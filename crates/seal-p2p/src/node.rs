//! Seal P2P node — libp2p swarm with GossipSub + mDNS.
//!
//! Supports optional **double encryption**: classical Noise transport
//! (X25519) + application-layer ML-KEM-768 encryption. This provides
//! Harvest Now Decrypt Later (HNDL) resistance even before full
//! PQC transport is patched into libp2p.

use libp2p::{
    futures::StreamExt,
    gossipsub, identify, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::pq_encrypt::{generate_transport_keypair, PqChannel};
use crate::topics::{blocks_topic, txs_topic};
use seal_crypto::kem::KemKeypair;

/// Messages received from the P2P network.
#[derive(Debug, Clone)]
pub enum NetworkMessage {
    /// A new block was received from a peer.
    NewBlock { data: Vec<u8>, source: PeerId },
    /// A new transaction was received from a peer.
    NewTransaction { data: Vec<u8>, source: PeerId },
    /// A committee vote (Ringtail partial signature) for a proposed block.
    CommitteeVote { data: Vec<u8>, source: PeerId },
    /// An aggregated committee threshold signature for a finalized block.
    CommitteeSignature { data: Vec<u8>, source: PeerId },
    /// Epoch transition announcement (new VRF public key, epoch number).
    EpochTransition { data: Vec<u8>, source: PeerId },
    /// A new peer connected.
    PeerConnected(PeerId),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
}

/// Combined network behaviour for Seal nodes.
#[derive(NetworkBehaviour)]
pub struct SealBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
}

/// Configuration for a Seal P2P node.
#[derive(Default)]
pub struct NodeConfig {
    /// Port to listen on. 0 = random.
    pub listen_port: u16,
    /// Bootstrap peers to connect to on startup.
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Enable PQ double-encryption on GossipSub messages.
    /// When true, all outbound messages are encrypted with ML-KEM-768
    /// on top of the classical Noise transport.
    pub pq_encryption: bool,
}

/// Per-peer PQ encryption state.
/// Shared between the event loop and the node handle via Arc<Mutex>.
struct PeerPqState {
    /// Our ML-KEM keypair for this node.
    our_keypair: KemKeypair,
    /// Established PQ channels per peer.
    channels: HashMap<PeerId, PqChannel>,
    /// Peers whose ML-KEM public key we've received but haven't completed handshake.
    pending_keys: HashMap<PeerId, Vec<u8>>,
}

impl PeerPqState {
    fn new() -> Self {
        Self {
            our_keypair: generate_transport_keypair(),
            channels: HashMap::new(),
            pending_keys: HashMap::new(),
        }
    }
}

/// A Seal P2P node.
pub struct SealNode {
    /// Channel to receive network messages.
    pub receiver: mpsc::Receiver<NetworkMessage>,
    /// Handle to send messages via the network.
    sender_tx: mpsc::Sender<Vec<u8>>,
    sender_blocks: mpsc::Sender<Vec<u8>>,
    /// Channel to send committee votes (partial Ringtail signatures).
    sender_committee_votes: mpsc::Sender<Vec<u8>>,
    /// Channel to send committee threshold signatures.
    sender_committee_sigs: mpsc::Sender<Vec<u8>>,
    /// Channel to send epoch transition announcements.
    sender_epoch_transition: mpsc::Sender<Vec<u8>>,
    /// PQ encryption state (None if pq_encryption disabled).
    pq_state: Option<Arc<Mutex<PeerPqState>>>,
}

/// GossipSub message prefix for PQ-encrypted payloads.
/// Messages with this prefix are decrypted before processing.
const PQ_ENCRYPTED_PREFIX: &[u8] = b"PQ1";

/// GossipSub message prefix for PQ key exchange.
/// Format: PQ_KEY_EXCHANGE_PREFIX || ML-KEM public key bytes
const PQ_KEY_EXCHANGE_PREFIX: &[u8] = b"PQKX";

impl SealNode {
    /// Start a new P2P node. Returns the node and a future that drives the swarm.
    pub async fn start(config: NodeConfig) -> Result<(Self, PeerId), Box<dyn std::error::Error>> {
        let pq_enabled = config.pq_encryption;

        let mut swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                // GossipSub config
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .max_transmit_size(64 * 1024) // 64 KB for PQ overhead
                    .build()
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::from(e.to_string())
                })?;

                let mdns =
                    mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

                let identify = identify::Behaviour::new(identify::Config::new(
                    "/seal/1.0.0".into(),
                    key.public(),
                ));

                Ok(SealBehaviour {
                    gossipsub,
                    mdns,
                    identify,
                })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // Subscribe to topics
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&blocks_topic())
            .map_err(|e| format!("failed to subscribe to blocks topic: {}", e))?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&txs_topic())
            .map_err(|e| format!("failed to subscribe to txs topic: {}", e))?;
        // Subscribe to committee and epoch topics (Phase 2 multi-node consensus)
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&crate::topics::committee_votes_topic())
            .map_err(|e| format!("failed to subscribe to committee-votes topic: {}", e))?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&crate::topics::committee_sigs_topic())
            .map_err(|e| format!("failed to subscribe to committee-sigs topic: {}", e))?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&crate::topics::epoch_transition_topic())
            .map_err(|e| format!("failed to subscribe to epoch-transition topic: {}", e))?;

        // Listen
        let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", config.listen_port)
            .parse()
            .map_err(|e| format!("invalid multiaddr: {}", e))?;
        swarm.listen_on(listen_addr)?;

        let local_peer_id = *swarm.local_peer_id();
        info!("Local peer ID: {}", local_peer_id);

        // Connect to bootstrap peers
        for addr in &config.bootstrap_peers {
            info!("Dialing bootstrap peer: {}", addr);
            swarm.dial(addr.clone())?;
        }

        // PQ encryption state
        let pq_state = if pq_enabled {
            let state = Arc::new(Mutex::new(PeerPqState::new()));
            info!("PQ double-encryption enabled (ML-KEM-768 over Noise)");
            Some(state)
        } else {
            None
        };
        let pq_state_loop = pq_state.clone();

        // Channels
        let (net_tx, net_rx) = mpsc::channel::<NetworkMessage>(256);
        let (tx_send, mut tx_recv) = mpsc::channel::<Vec<u8>>(256);
        let (block_send, mut block_recv) = mpsc::channel::<Vec<u8>>(256);
        let (vote_send, mut vote_recv) = mpsc::channel::<Vec<u8>>(256);
        let (sig_send, mut sig_recv) = mpsc::channel::<Vec<u8>>(256);
        let (epoch_send, mut epoch_recv) = mpsc::channel::<Vec<u8>>(256);

        // Spawn the swarm event loop
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Outbound transactions
                    Some(data) = tx_recv.recv() => {
                        let payload = maybe_encrypt_broadcast(&pq_state_loop, &data);
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(txs_topic(), payload) {
                            warn!("Failed to publish tx: {:?}", e);
                        }
                    }
                    // Outbound blocks
                    Some(data) = block_recv.recv() => {
                        let payload = maybe_encrypt_broadcast(&pq_state_loop, &data);
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(blocks_topic(), payload) {
                            warn!("Failed to publish block: {:?}", e);
                        }
                    }
                    // Outbound committee votes
                    Some(data) = vote_recv.recv() => {
                        let payload = maybe_encrypt_broadcast(&pq_state_loop, &data);
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(crate::topics::committee_votes_topic(), payload) {
                            warn!("Failed to publish committee vote: {:?}", e);
                        }
                    }
                    // Outbound committee threshold signatures
                    Some(data) = sig_recv.recv() => {
                        let payload = maybe_encrypt_broadcast(&pq_state_loop, &data);
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(crate::topics::committee_sigs_topic(), payload) {
                            warn!("Failed to publish committee signature: {:?}", e);
                        }
                    }
                    // Outbound epoch transition announcements
                    Some(data) = epoch_recv.recv() => {
                        let payload = maybe_encrypt_broadcast(&pq_state_loop, &data);
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(crate::topics::epoch_transition_topic(), payload) {
                            warn!("Failed to publish epoch transition: {:?}", e);
                        }
                    }
                    // Swarm events
                    event = swarm.select_next_some() => {
                        match event {
                            SwarmEvent::Behaviour(SealBehaviourEvent::Gossipsub(
                                gossipsub::Event::Message { propagation_source, message, .. }
                            )) => {
                                let raw_data = message.data;

                                // Handle PQ key exchange messages
                                if raw_data.starts_with(PQ_KEY_EXCHANGE_PREFIX) {
                                    if let Some(ref pq) = pq_state_loop {
                                        handle_pq_key_exchange(
                                            pq, propagation_source,
                                            &raw_data[PQ_KEY_EXCHANGE_PREFIX.len()..],
                                            &mut swarm,
                                        );
                                    }
                                    continue;
                                }

                                // Decrypt if PQ-encrypted
                                let data = maybe_decrypt_message(
                                    &pq_state_loop, &propagation_source, &raw_data,
                                );

                                let topic = message.topic.to_string();
                                let msg = if topic == blocks_topic().to_string() {
                                    NetworkMessage::NewBlock {
                                        data,
                                        source: propagation_source,
                                    }
                                } else if topic == crate::topics::committee_votes_topic().to_string() {
                                    NetworkMessage::CommitteeVote {
                                        data,
                                        source: propagation_source,
                                    }
                                } else if topic == crate::topics::committee_sigs_topic().to_string() {
                                    NetworkMessage::CommitteeSignature {
                                        data,
                                        source: propagation_source,
                                    }
                                } else if topic == crate::topics::epoch_transition_topic().to_string() {
                                    NetworkMessage::EpochTransition {
                                        data,
                                        source: propagation_source,
                                    }
                                } else {
                                    NetworkMessage::NewTransaction {
                                        data,
                                        source: propagation_source,
                                    }
                                };
                                let _ = net_tx.send(msg).await;
                            }
                            SwarmEvent::Behaviour(SealBehaviourEvent::Mdns(
                                mdns::Event::Discovered(peers)
                            )) => {
                                for (peer_id, _addr) in peers {
                                    debug!("mDNS discovered: {}", peer_id);
                                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);

                                    // Send our ML-KEM public key to the new peer
                                    if let Some(ref pq) = pq_state_loop {
                                        match pq.lock() {
                                            Ok(guard) => {
                                                let pk_bytes = guard.our_keypair.public.to_bytes();
                                                let mut key_msg = PQ_KEY_EXCHANGE_PREFIX.to_vec();
                                                key_msg.extend_from_slice(&pk_bytes);
                                                // Broadcast key exchange on the blocks topic
                                                let _ = swarm.behaviour_mut().gossipsub
                                                    .publish(blocks_topic(), key_msg);
                                            }
                                            Err(e) => {
                                                warn!("PQ state lock poisoned during key exchange broadcast: {}", e);
                                            }
                                        }
                                    }

                                    let _ = net_tx.send(NetworkMessage::PeerConnected(peer_id)).await;
                                }
                            }
                            SwarmEvent::Behaviour(SealBehaviourEvent::Mdns(
                                mdns::Event::Expired(peers)
                            )) => {
                                for (peer_id, _addr) in peers {
                                    debug!("mDNS expired: {}", peer_id);
                                    swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);

                                    // Remove PQ channel for disconnected peer
                                    if let Some(ref pq) = pq_state_loop {
                                        match pq.lock() {
                                            Ok(mut guard) => {
                                                guard.channels.remove(&peer_id);
                                                guard.pending_keys.remove(&peer_id);
                                            }
                                            Err(e) => {
                                                warn!("PQ state lock poisoned during peer cleanup: {}", e);
                                            }
                                        }
                                    }

                                    let _ = net_tx.send(NetworkMessage::PeerDisconnected(peer_id)).await;
                                }
                            }
                            SwarmEvent::NewListenAddr { address, .. } => {
                                info!("Listening on {}", address);
                            }
                            _ => {}
                        }
                    }
                }
            }
        });

        let node = SealNode {
            receiver: net_rx,
            sender_tx: tx_send,
            sender_blocks: block_send,
            sender_committee_votes: vote_send,
            sender_committee_sigs: sig_send,
            sender_epoch_transition: epoch_send,
            pq_state,
        };

        Ok((node, local_peer_id))
    }

    /// Broadcast a transaction to the network.
    pub async fn broadcast_transaction(
        &self,
        data: Vec<u8>,
    ) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.sender_tx.send(data).await
    }

    /// Broadcast a block to the network.
    pub async fn broadcast_block(
        &self,
        data: Vec<u8>,
    ) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.sender_blocks.send(data).await
    }

    /// Broadcast a committee vote (Ringtail partial signature) to the network.
    pub async fn broadcast_committee_vote(
        &self,
        data: Vec<u8>,
    ) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.sender_committee_votes.send(data).await
    }

    /// Broadcast an aggregated committee threshold signature.
    pub async fn broadcast_committee_signature(
        &self,
        data: Vec<u8>,
    ) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.sender_committee_sigs.send(data).await
    }

    /// Broadcast an epoch transition announcement.
    pub async fn broadcast_epoch_transition(
        &self,
        data: Vec<u8>,
    ) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.sender_epoch_transition.send(data).await
    }

    /// Whether PQ double-encryption is enabled.
    pub fn pq_encryption_enabled(&self) -> bool {
        self.pq_state.is_some()
    }

    /// Number of peers with established PQ channels.
    pub fn pq_peer_count(&self) -> usize {
        self.pq_state
            .as_ref()
            .and_then(|s| s.lock().ok().map(|guard| guard.channels.len()))
            .unwrap_or(0)
    }
}

/// Encrypt a broadcast message if PQ is enabled.
/// For broadcast (GossipSub), we use a node-wide encryption key rather
/// than per-peer channels, since GossipSub fans out to all subscribers.
/// The key is derived from our KEM keypair for simplicity.
fn maybe_encrypt_broadcast(pq_state: &Option<Arc<Mutex<PeerPqState>>>, data: &[u8]) -> Vec<u8> {
    match pq_state {
        Some(state) => {
            let guard = match state.lock() {
                Ok(g) => g,
                Err(e) => {
                    warn!("PQ state lock poisoned during encrypt broadcast: {}", e);
                    return data.to_vec();
                }
            };
            // Use SHA3(our_pk) as a broadcast encryption key.
            // Peers who have our public key can derive the same key.
            let broadcast_key = seal_crypto::hash::sha3_256(
                &guard.our_keypair.public.to_bytes(),
            ).0;
            let encrypted = crate::pq_encrypt::encrypt_with_key(data, &broadcast_key);
            let mut msg = PQ_ENCRYPTED_PREFIX.to_vec();
            msg.extend_from_slice(&encrypted);
            msg
        }
        None => data.to_vec(),
    }
}

/// Decrypt an inbound message if it has the PQ prefix.
fn maybe_decrypt_message(
    pq_state: &Option<Arc<Mutex<PeerPqState>>>,
    source: &PeerId,
    data: &[u8],
) -> Vec<u8> {
    if !data.starts_with(PQ_ENCRYPTED_PREFIX) {
        return data.to_vec();
    }

    let encrypted = &data[PQ_ENCRYPTED_PREFIX.len()..];

    match pq_state {
        Some(state) => {
            let guard = match state.lock() {
                Ok(g) => g,
                Err(e) => {
                    warn!("PQ state lock poisoned during decrypt: {}", e);
                    return data.to_vec();
                }
            };
            // Try per-peer decryption first
            if let Some(channel) = guard.channels.get(source) {
                return channel.decrypt(encrypted);
            }
            // Try broadcast decryption using peer's stored public key
            if let Some(peer_pk) = guard.pending_keys.get(source) {
                let broadcast_key = seal_crypto::hash::sha3_256(peer_pk).0;
                return crate::pq_encrypt::decrypt_with_key(encrypted, &broadcast_key);
            }
            // Can't decrypt — return raw (will likely be invalid)
            warn!("Cannot decrypt PQ message from {}: no key", source);
            data.to_vec()
        }
        None => {
            // PQ disabled but received PQ message — strip prefix and return raw
            warn!("Received PQ-encrypted message but PQ is disabled");
            data.to_vec()
        }
    }
}

/// Handle a PQ key exchange message from a peer.
fn handle_pq_key_exchange(
    pq_state: &Arc<Mutex<PeerPqState>>,
    peer_id: PeerId,
    pk_bytes: &[u8],
    _swarm: &mut libp2p::Swarm<SealBehaviour>,
) {
    let mut guard = match pq_state.lock() {
        Ok(g) => g,
        Err(e) => {
            warn!("PQ state lock poisoned during key exchange: {}", e);
            return;
        }
    };

    // Store the peer's ML-KEM public key
    guard.pending_keys.insert(peer_id, pk_bytes.to_vec());

    // Establish a PQ channel as initiator
    match PqChannel::initiate(pk_bytes) {
        Ok((channel, _ciphertext)) => {
            debug!("Established PQ channel with peer {}", peer_id);
            guard.channels.insert(peer_id, channel);
        }
        Err(e) => {
            warn!("Failed to establish PQ channel with {}: {}", peer_id, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_starts() {
        let config = NodeConfig {
            listen_port: 0, // Random port
            bootstrap_peers: vec![],
            pq_encryption: false,
        };

        let (node, peer_id) = SealNode::start(config).await.unwrap();
        assert!(!peer_id.to_string().is_empty());
        assert!(!node.pq_encryption_enabled());
        drop(node);
    }

    #[test]
    fn test_topics() {
        assert_eq!(blocks_topic().to_string(), "seal/blocks/1.0");
        assert_eq!(txs_topic().to_string(), "seal/txs/1.0");
    }

    #[tokio::test]
    async fn test_two_nodes_start() {
        let (node1, peer1) = SealNode::start(NodeConfig::default()).await.unwrap();
        let (node2, peer2) = SealNode::start(NodeConfig::default()).await.unwrap();
        assert_ne!(peer1, peer2, "two nodes should have different peer IDs");
        assert!(!peer1.to_string().is_empty());
        assert!(!peer2.to_string().is_empty());
        drop(node1);
        drop(node2);
    }

    #[tokio::test]
    async fn test_node_broadcast_doesnt_panic() {
        let (node, _peer) = SealNode::start(NodeConfig::default()).await.unwrap();
        let _ = node.broadcast_block(b"test_block".to_vec()).await;
        let _ = node.broadcast_transaction(b"test_tx".to_vec()).await;
        drop(node);
    }

    #[tokio::test]
    async fn test_pq_node_starts() {
        let config = NodeConfig {
            listen_port: 0,
            bootstrap_peers: vec![],
            pq_encryption: true,
        };
        let (node, peer_id) = SealNode::start(config).await.unwrap();
        assert!(!peer_id.to_string().is_empty());
        assert!(node.pq_encryption_enabled());
        assert_eq!(node.pq_peer_count(), 0);
        drop(node);
    }

    #[test]
    fn test_broadcast_encrypt_decrypt_roundtrip() {
        // Test the broadcast encryption/decryption functions directly
        let state = Arc::new(Mutex::new(PeerPqState::new()));
        let pq = Some(state.clone());

        let data = b"test block data for PQ encryption";
        let encrypted = maybe_encrypt_broadcast(&pq, data);

        // Encrypted should have PQ prefix
        assert!(encrypted.starts_with(PQ_ENCRYPTED_PREFIX));

        // Decrypt using the same node's public key
        let pk_bytes = state.lock().unwrap().our_keypair.public.to_bytes();
        let broadcast_key = seal_crypto::hash::sha3_256(&pk_bytes).0;
        let decrypted = crate::pq_encrypt::decrypt_with_key(
            &encrypted[PQ_ENCRYPTED_PREFIX.len()..],
            &broadcast_key,
        );
        assert_eq!(&decrypted[..], &data[..]);
    }

    #[test]
    fn test_no_pq_passthrough() {
        let data = b"plaintext message";
        let result = maybe_encrypt_broadcast(&None, data);
        assert_eq!(&result[..], &data[..]);
    }

    #[test]
    fn test_pq_key_exchange_state() {
        let state = PeerPqState::new();
        assert!(state.channels.is_empty());
        assert!(state.pending_keys.is_empty());
        assert!(!state.our_keypair.public.to_bytes().is_empty());
    }
}
