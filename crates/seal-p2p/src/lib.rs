//! P2P networking layer for Seal DAO.
//!
//! Uses libp2p with:
//! - **GossipSub** for block and transaction propagation
//! - **mDNS** for local peer discovery
//! - **Noise** protocol for encrypted transport (classical)
//! - **ML-KEM-768** double-encryption on top of Noise (PQ-secure)
//! - **ML-KEM-768 native transport** (replaces Noise key exchange)
//! - **Yamux** for stream multiplexing
//!
//! # Transport Security Layers
//!
//! Phase 1 (current): Double encryption via `pq_encrypt` module.
//!   Classical Noise underneath, ML-KEM-768 on top of GossipSub messages.
//!
//! Phase 2 (available): Native PQ transport via `pq_transport` module.
//!   ML-KEM replaces X25519 at the connection level. All protocols secured.
//!
//! Phase 3 (future): Hybrid ML-KEM + X25519 key agreement.
//!
//! Topics:
//! - `seal/blocks/1.0` — new block announcements
//! - `seal/txs/1.0` — new transaction broadcasts

pub mod node;
pub mod pq_encrypt;
pub mod pq_handshake;
pub mod pq_transport;
pub mod topics;

pub use node::SealNode;
pub use pq_encrypt::PqChannel;
pub use pq_handshake::{Initiator as PqInitiator, Responder as PqResponder};
pub use pq_transport::{PqTransportInitiator, PqTransportResponder, PqTransportSession};
pub use topics::{BLOCKS_TOPIC, TXS_TOPIC};
