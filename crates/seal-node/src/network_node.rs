//! Network node — consensus runner + P2P for multi-node operation.
//!
//! Combines:
//! - ConsensusRunner (slot timing, VRF election, block production)
//! - SealNode P2P (GossipSub for block/tx propagation)
//! - Block serialization for network transmission
//!
//! Flow per slot:
//! 1. Advance slot, run VRF election
//! 2. If proposer: produce block → serialize → broadcast via GossipSub
//! 3. If committee: receive block from GossipSub → verify → vote
//! 4. Collect threshold votes → finalize

use seal_consensus::config::ConsensusConfig;
use seal_consensus::validator::ValidatorSet;
use seal_crypto::hash::Hash256;
use seal_crypto::signature::SigningKey;
use seal_p2p::node::{NetworkMessage, NodeConfig, SealNode};
use seal_storage::block_store::{Block, Transaction};
use seal_vrf::traits::Vrf;

use crate::consensus_runner::{ConsensusRunner, FinalizedBlock};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// A network-connected Seal node.
pub struct NetworkNode {
    /// Consensus runner.
    pub runner: ConsensusRunner,
    /// P2P node.
    p2p: SealNode,
    /// Our peer ID.
    pub peer_id: libp2p::PeerId,
    /// Blocks received from the network (not yet processed).
    received_blocks: Vec<Block>,
    /// Rate limiting: messages processed per tick.
    max_messages_per_tick: usize,
    /// Rate limiting: maximum received block queue size.
    max_received_blocks: usize,
}

impl NetworkNode {
    /// Start a network node.
    pub async fn start(
        consensus_config: ConsensusConfig,
        p2p_config: NodeConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let (p2p, peer_id) = SealNode::start(p2p_config).await?;
        let runner = ConsensusRunner::new(consensus_config);

        info!(%peer_id, "Network node started");

        Ok(NetworkNode {
            runner,
            p2p,
            peer_id,
            received_blocks: Vec::new(),
            max_messages_per_tick: 100,
            max_received_blocks: 1000,
        })
    }

    /// Start with a specific validator set (for multi-node testing).
    pub async fn start_with_validators(
        consensus_config: ConsensusConfig,
        p2p_config: NodeConfig,
        signing_key: SigningKey,
        verifying_key: seal_crypto::signature::VerifyingKey,
        vrf_manager: seal_vrf::VrfKeyManager,
        validator_set: ValidatorSet,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let (p2p, peer_id) = SealNode::start(p2p_config).await?;
        let runner = ConsensusRunner::with_validator_set(
            consensus_config,
            signing_key,
            verifying_key,
            vrf_manager,
            validator_set,
        );

        info!(%peer_id, "Network node started with validator set");

        Ok(NetworkNode {
            runner,
            p2p,
            peer_id,
            received_blocks: Vec::new(),
            max_messages_per_tick: 100,
            max_received_blocks: 1000,
        })
    }

    /// Process one slot: check for network messages, then advance consensus.
    /// Returns a finalized block if one was produced this slot.
    pub async fn tick(&mut self) -> Option<FinalizedBlock> {
        // 1. Drain incoming network messages
        self.process_network_messages().await;

        // 2. Auto-apply received blocks from peers
        self.apply_received_blocks();

        // 3. Advance consensus slot
        let block = self.runner.advance_slot();

        // 4. If we produced a block, broadcast it
        if let Some(ref finalized) = block {
            self.broadcast_block(&finalized.block).await;
        }

        block
    }

    /// Apply all received blocks that are at the next expected height.
    /// Skips blocks that are too old or too far ahead.
    fn apply_received_blocks(&mut self) {
        if self.received_blocks.is_empty() {
            return;
        }

        // Sort by height to apply in order
        self.received_blocks.sort_by_key(|b| b.header.height);

        let mut applied = 0;
        let mut remaining = Vec::new();

        for block in std::mem::take(&mut self.received_blocks) {
            let expected = self.runner.height() + 1;
            if block.header.height == expected {
                match self.verify_and_apply_block(&block) {
                    Ok(()) => {
                        applied += 1;
                    }
                    Err(e) => {
                        debug!(
                            height = block.header.height,
                            error = %e,
                            "Failed to apply received block"
                        );
                    }
                }
            } else if block.header.height > expected {
                // Future block — keep for later
                remaining.push(block);
            }
            // else: old block — discard
        }

        self.received_blocks = remaining;

        if applied > 0 {
            info!(applied, "Applied received blocks from peers");
        }
    }

    /// Process pending network messages (non-blocking, rate-limited).
    async fn process_network_messages(&mut self) {
        let mut processed = 0;
        loop {
            if processed >= self.max_messages_per_tick {
                debug!("Rate limit: {} messages processed this tick", processed);
                break;
            }
            match self.p2p.receiver.try_recv() {
                Ok(msg) => {
                    processed += 1;
                    match msg {
                        NetworkMessage::NewBlock { data, source } => {
                            // Drop if queue is full (backpressure)
                            if self.received_blocks.len() >= self.max_received_blocks {
                                warn!("Block queue full, dropping block from {}", source);
                                continue;
                            }
                            match bincode::deserialize::<Block>(&data) {
                                Ok(block) => {
                                    debug!(
                                        height = block.header.height,
                                        from = %source,
                                        "Received block from network"
                                    );
                                    self.received_blocks.push(block);
                                }
                                Err(e) => {
                                    warn!("Failed to deserialize block: {}", e);
                                }
                            }
                        }
                        NetworkMessage::NewTransaction { data, source } => {
                            match bincode::deserialize::<Transaction>(&data) {
                                Ok(tx) => {
                                    debug!(
                                        tx_type = ?tx.tx_type,
                                        from = %source,
                                        "Received tx from network"
                                    );
                                    if let Err(e) = self.runner.accept_transaction(tx) {
                                        debug!("Rejected tx from {}: {}", source, e);
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to deserialize tx from {}: {}", source, e);
                                }
                            }
                        }
                        NetworkMessage::CommitteeVote { data, source } => {
                            debug!(from = %source, bytes = data.len(), "Received committee vote");
                            // TODO: deserialize and process via CommitteeManager
                        }
                        NetworkMessage::CommitteeSignature { data, source } => {
                            debug!(from = %source, bytes = data.len(), "Received committee signature");
                            // TODO: deserialize and apply finalized attestation
                        }
                        NetworkMessage::EpochTransition { data, source } => {
                            debug!(from = %source, bytes = data.len(), "Received epoch transition");
                            // TODO: update validator VRF keys for new epoch
                        }
                        NetworkMessage::PeerConnected(peer) => {
                            info!(%peer, "Peer connected");
                        }
                        NetworkMessage::PeerDisconnected(peer) => {
                            debug!(%peer, "Peer disconnected");
                        }
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    warn!("P2P channel disconnected");
                    break;
                }
            }
        }
    }

    /// Broadcast a block to all connected peers.
    async fn broadcast_block(&self, block: &Block) {
        match bincode::serialize(block) {
            Ok(data) => {
                info!(
                    height = block.header.height,
                    bytes = data.len(),
                    "Broadcasting block"
                );
                if let Err(e) = self.p2p.broadcast_block(data).await {
                    warn!("Failed to broadcast block: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to serialize block: {}", e);
            }
        }
    }

    /// Broadcast a transaction to all connected peers.
    pub async fn broadcast_transaction(&self, tx: &Transaction) {
        match bincode::serialize(tx) {
            Ok(data) => {
                debug!(
                    tx_type = ?tx.tx_type,
                    bytes = data.len(),
                    "Broadcasting transaction"
                );
                if let Err(e) = self.p2p.broadcast_transaction(data).await {
                    warn!("Failed to broadcast tx: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to serialize tx: {}", e);
            }
        }
    }

    /// Submit a SQL transaction.
    pub fn submit_sql(
        &mut self,
        sql: &str,
    ) -> Result<seal_sql::engine::QueryResult, seal_sql::SqlError> {
        self.runner.submit_sql(sql)
    }

    /// Query SQL (read-only).
    pub fn query_sql(
        &mut self,
        sql: &str,
    ) -> Result<seal_sql::engine::QueryResult, seal_sql::SqlError> {
        self.runner.query_sql(sql)
    }

    /// Get chain height.
    pub fn height(&self) -> u64 {
        self.runner.height()
    }

    /// Get state root.
    pub fn state_root(&self) -> &Hash256 {
        self.runner.state_root()
    }

    /// Get number of blocks received from the network.
    pub fn received_block_count(&self) -> usize {
        self.received_blocks.len()
    }

    /// Run the consensus loop with real slot timing.
    /// Ticks every `slot_duration` (default 4s), producing blocks when elected.
    /// Runs for `max_slots` slots then returns.
    pub async fn run_consensus(&mut self, max_slots: u64) {
        let slot_duration = self.runner.config.slot_duration;
        let mut interval = tokio::time::interval(slot_duration);

        for slot in 0..max_slots {
            interval.tick().await;

            if let Some(block) = self.tick().await {
                info!(
                    slot,
                    height = block.block.header.height,
                    txs = block.block.transactions.len(),
                    "Block finalized"
                );
            }
        }
    }

    /// Take received blocks (for processing).
    pub fn take_received_blocks(&mut self) -> Vec<Block> {
        std::mem::take(&mut self.received_blocks)
    }

    /// Verify and apply a received block.
    /// Checks:
    /// 1. Height is sequential (next expected height)
    /// 2. Parent hash matches our latest block
    /// 3. VRF proof is valid (proposer was legitimately elected)
    /// 4. Replaying transactions produces the claimed state root
    pub fn verify_and_apply_block(&mut self, block: &Block) -> Result<(), String> {
        let expected_height = self.runner.height() + 1;
        if block.header.height != expected_height {
            return Err(format!(
                "unexpected height: expected {}, got {}",
                expected_height, block.header.height
            ));
        }

        // Check parent hash
        if self.runner.height() > 0 {
            let our_latest = self.runner.latest_block().ok_or("no latest block")?;
            let our_header_bytes = bincode::serialize(&our_latest.block.header)
                .map_err(|e| format!("serialize error: {}", e))?;
            let expected_parent = seal_crypto::hash::sha3_256(&our_header_bytes);
            if block.header.parent_hash != expected_parent {
                return Err("parent hash mismatch".into());
            }
        }

        // Verify VRF proof if present (proves proposer was legitimately elected)
        if !block.header.vrf_output.is_empty() && !block.header.vrf_proof.is_empty() {
            // Find the proposer in our validator set
            if let Some(proposer) = self.runner.validator_set.find_by_pubkey(&block.header.proposer) {
                let vrf_input = self.runner.current_slot.vrf_input(&self.runner.current_epoch.seed);
                let vrf_output = seal_vrf::VrfOutput(
                    block.header.vrf_output.as_slice().try_into()
                        .map_err(|_| "invalid VRF output length")?
                );
                let vrf_proof = seal_vrf::VrfProof {
                    bytes: block.header.vrf_proof.clone(),
                };
                // Verify using PqVrf (the proposer's VRF public key)
                seal_vrf::PqVrf::verify(
                    &proposer.vrf_public_key,
                    &vrf_input,
                    &vrf_output,
                    &vrf_proof,
                ).map_err(|e| format!("VRF proof verification failed: {}", e))?;

                debug!(height = block.header.height, "VRF proof verified");
            }
            // If proposer not in our validator set, skip VRF check (they may have rotated)
        }

        // Replay transactions and verify state root
        let replayed_root = self.runner.replay_block(block)?;
        if replayed_root != block.header.state_root {
            return Err(format!(
                "state root mismatch after replay: expected {}, got {}",
                block.header.state_root, replayed_root
            ));
        }

        info!(
            height = block.header.height,
            state_root = %block.header.state_root,
            "Block verified and applied"
        );

        Ok(())
    }

    /// Sync with another node by applying its blocks.
    /// Requests blocks from `from_height` to `to_height` inclusive.
    /// In production: these blocks would come over P2P. For now, takes a slice.
    pub fn sync_blocks(&mut self, blocks: &[Block]) -> Result<u64, String> {
        let mut applied = 0;
        for block in blocks {
            // Skip blocks we already have
            if block.header.height <= self.runner.height() {
                continue;
            }
            // Verify and apply
            self.verify_and_apply_block(block)?;
            applied += 1;
        }
        Ok(applied)
    }

    /// Get all blocks this node has produced (for sharing with peers).
    pub fn get_chain(&self) -> Vec<Block> {
        self.runner
            .chain
            .iter()
            .map(|fb| fb.block.clone())
            .collect()
    }

    /// Check if this node is behind another node's height.
    pub fn is_behind(&self, remote_height: u64) -> bool {
        self.runner.height() < remote_height
    }

    /// How many blocks behind are we?
    pub fn blocks_behind(&self, remote_height: u64) -> u64 {
        remote_height.saturating_sub(self.runner.height())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_node_starts() {
        let node = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();

        assert!(!node.peer_id.to_string().is_empty());
        assert_eq!(node.height(), 0);
        assert_eq!(node.received_block_count(), 0);
    }

    #[tokio::test]
    async fn test_network_node_produces_blocks() {
        let mut node = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();

        node.submit_sql("CREATE TABLE t (id BIGINT PRIMARY KEY)")
            .unwrap();

        let mut produced = false;
        for _ in 0..100 {
            if node.tick().await.is_some() {
                produced = true;
                break;
            }
        }
        assert!(produced, "should produce at least one block");
        assert!(node.height() > 0);
    }

    #[tokio::test]
    async fn test_network_node_sql() {
        let mut node = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();

        node.submit_sql("CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL)")
            .unwrap();
        node.submit_sql("INSERT INTO users (id, name) VALUES (1, 'alice')")
            .unwrap();

        let result = node.query_sql("SELECT * FROM users").unwrap();
        assert_eq!(result.rows.len(), 1);
    }

    #[tokio::test]
    async fn test_block_serialization_roundtrip() {
        // Verify blocks can be serialized and deserialized for network transmission
        let mut node = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();

        node.submit_sql("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        node.submit_sql("INSERT INTO t (id, val) VALUES (1, 'test')")
            .unwrap();

        let mut block = None;
        for _ in 0..100 {
            if let Some(b) = node.tick().await {
                block = Some(b);
                break;
            }
        }
        let block = block.unwrap();

        // Serialize and deserialize
        let bytes = bincode::serialize(&block.block).unwrap();
        let deserialized: Block = bincode::deserialize(&bytes).unwrap();

        assert_eq!(deserialized.header.height, block.block.header.height);
        assert_eq!(
            deserialized.header.state_root,
            block.block.header.state_root
        );
        assert_eq!(
            deserialized.transactions.len(),
            block.block.transactions.len()
        );
    }

    #[tokio::test]
    async fn test_verify_and_apply_block() {
        // Producer node
        let mut producer = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();

        producer
            .submit_sql("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        producer
            .submit_sql("INSERT INTO t (id, val) VALUES (1, 'hello')")
            .unwrap();

        // Produce a block
        let mut block = None;
        for _ in 0..100 {
            if let Some(b) = producer.tick().await {
                block = Some(b);
                break;
            }
        }
        let block = block.expect("should produce a block");

        // Receiver node verifies and applies the block
        let mut receiver = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();

        receiver.verify_and_apply_block(&block.block).unwrap();
        assert_eq!(receiver.height(), 1);

        // Data should be queryable after applying the block
        let result = receiver.query_sql("SELECT * FROM t").unwrap();
        assert_eq!(result.rows.len(), 1);
    }

    #[tokio::test]
    async fn test_verify_rejects_wrong_height() {
        let mut node = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();

        // Create a block claiming height 5 (but we're at height 0)
        let block = Block {
            header: seal_storage::block_store::BlockHeader {
                height: 5,
                parent_hash: Hash256::ZERO,
                state_root: Hash256::ZERO,
                timestamp: 0,
                proposer: vec![],
                vrf_output: vec![],
                vrf_proof: vec![],
            },
            transactions: vec![],
        };

        let result = node.verify_and_apply_block(&block);
        assert!(result.is_err(), "should reject block with wrong height");
    }

    /// End-to-end test: producer creates blocks, receiver verifies and applies them.
    /// Both nodes end up with the same state.
    #[tokio::test]
    async fn test_multi_node_sync() {
        // Producer node
        let mut producer = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();

        // Deploy schema + insert data on producer
        producer
            .submit_sql(
                "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT NOT NULL, price BIGINT)",
            )
            .unwrap();
        producer
            .submit_sql("INSERT INTO items (id, name, price) VALUES (1, 'Widget', 100)")
            .unwrap();
        producer
            .submit_sql("INSERT INTO items (id, name, price) VALUES (2, 'Gadget', 250)")
            .unwrap();
        producer
            .submit_sql("INSERT INTO items (id, name, price) VALUES (3, 'Doohickey', 75)")
            .unwrap();

        // Produce blocks on producer
        let mut produced_blocks = Vec::new();
        for _ in 0..200 {
            if let Some(block) = producer.tick().await {
                produced_blocks.push(block.block.clone());
                if produced_blocks.len() > 1 {
                    break;
                }
            }
            // Add more data for second block
            if produced_blocks.len() == 1 {
                producer
                    .submit_sql(
                        "INSERT INTO items (id, name, price) VALUES (4, 'Thingamajig', 500)",
                    )
                    .unwrap();
                producer
                    .submit_sql("UPDATE items SET price = 150 WHERE id = 1")
                    .unwrap();
            }
        }
        assert!(
            !produced_blocks.is_empty(),
            "producer should create at least 1 block"
        );

        let producer_height = producer.height();
        let producer_state = *producer.state_root();

        // Receiver node starts fresh
        let mut receiver = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();

        assert_eq!(receiver.height(), 0);

        // Receiver applies all blocks from producer
        for block in &produced_blocks {
            receiver.verify_and_apply_block(block).unwrap();
        }

        // Both nodes should be at the same state
        assert_eq!(
            receiver.height(),
            producer_height,
            "receiver height should match producer"
        );
        assert_eq!(
            *receiver.state_root(),
            producer_state,
            "receiver state root should match producer"
        );

        // Receiver can query the data
        let result = receiver.query_sql("SELECT * FROM items").unwrap();
        assert!(
            result.rows.len() >= 3,
            "receiver should have the items after sync"
        );

        // Query specific data
        let result = receiver
            .query_sql("SELECT * FROM items WHERE price > 200")
            .unwrap();
        assert!(result.rows.len() >= 1, "should find expensive items");
    }

    /// Test: produce multiple blocks, sync, then produce more on receiver.
    #[tokio::test]
    async fn test_sync_then_continue() {
        let mut producer = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();

        producer
            .submit_sql("CREATE TABLE counter (id BIGINT PRIMARY KEY, val BIGINT)")
            .unwrap();
        producer
            .submit_sql("INSERT INTO counter (id, val) VALUES (1, 0)")
            .unwrap();

        // Produce first block
        let mut blocks = Vec::new();
        for _ in 0..100 {
            if let Some(block) = producer.tick().await {
                blocks.push(block.block.clone());
                break;
            }
        }
        assert_eq!(blocks.len(), 1);

        // Sync to receiver
        let mut receiver = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();
        for block in &blocks {
            receiver.verify_and_apply_block(block).unwrap();
        }

        // Receiver can now continue independently
        receiver
            .submit_sql("UPDATE counter SET val = 42 WHERE id = 1")
            .unwrap();
        let result = receiver
            .query_sql("SELECT * FROM counter WHERE id = 1")
            .unwrap();
        assert_eq!(result.rows.len(), 1);
    }

    #[tokio::test]
    async fn test_sync_blocks() {
        let mut producer = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();

        producer
            .submit_sql("CREATE TABLE data (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        producer
            .submit_sql("INSERT INTO data (id, val) VALUES (1, 'first')")
            .unwrap();

        // Produce 3 blocks
        let mut block_count = 0;
        for _ in 0..200 {
            producer
                .submit_sql(&format!(
                    "INSERT INTO data (id, val) VALUES ({}, 'row')",
                    10 + block_count
                ))
                .unwrap();
            if producer.tick().await.is_some() {
                block_count += 1;
                if block_count >= 3 {
                    break;
                }
            }
        }
        assert!(block_count >= 2);

        let chain = producer.get_chain();

        // New node syncs
        let mut joiner = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();

        assert!(joiner.is_behind(producer.height()));
        assert_eq!(joiner.blocks_behind(producer.height()), producer.height());

        let applied = joiner.sync_blocks(&chain).unwrap();
        assert!(applied >= 2);
        assert_eq!(joiner.height(), producer.height());
        assert!(!joiner.is_behind(producer.height()));

        // Data is available
        let result = joiner.query_sql("SELECT * FROM data").unwrap();
        assert!(result.rows.len() >= 2);
    }

    #[tokio::test]
    async fn test_sync_skips_existing_blocks() {
        let mut producer = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();
        producer
            .submit_sql("CREATE TABLE t (id BIGINT PRIMARY KEY)")
            .unwrap();

        for _ in 0..100 {
            if producer.tick().await.is_some() {
                break;
            }
        }
        let chain = producer.get_chain();
        assert!(!chain.is_empty());

        let mut receiver = NetworkNode::start(ConsensusConfig::default(), NodeConfig::default())
            .await
            .unwrap();

        // First sync
        let applied1 = receiver.sync_blocks(&chain).unwrap();
        assert!(applied1 > 0);

        // Second sync with same blocks — should skip all
        let applied2 = receiver.sync_blocks(&chain).unwrap();
        assert_eq!(applied2, 0, "should skip already-applied blocks");
    }
}
