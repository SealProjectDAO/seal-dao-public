//! P2P networking layer for Seal DAO.
//!
//! Uses libp2p with:
//! - **GossipSub** for block and transaction propagation
//! - **mDNS** for local peer discovery
//! - **Noise** protocol for encrypted transport (classical)
//! - **ML-KEM-768** double-encryption on top of Noise (PQ-secure)
//! - **ML-KEM-768 native transport** (replaces Noise key exchange)
//! - **Hybrid ML-KEM + X25519 transport** (defense in depth)
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
//! Phase 3 (available): Hybrid ML-KEM + X25519 key agreement.
//!   Session key = SHA3(ml_kem_ss || "hybrid-split-seal" || x25519_ss)
//!   Survives if either primitive is broken.
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
pub use pq_handshake::{
    HybridHandshakeMsg1, HybridHandshakeMsg2, HybridHandshakeMsg3, HybridHandshakeResult,
    HybridInitiator, HybridResponder, Initiator as PqInitiator, Responder as PqResponder,
};
pub use pq_transport::{
    KeyExchangeMode, PqTransportInitiator, PqTransportResponder, PqTransportSession,
};
pub use topics::{BLOCKS_TOPIC, TXS_TOPIC};
