//! Seal DAO node — integrates all crates into a working node.
//!
//! - PQC identity (ML-DSA keypair + address)
//! - SQL engine for executing queries
//! - VRF-based consensus (leader election + committee voting)
//! - Block production with ZK proofs
//! - P2P networking (GossipSub)
//! - Threshold committee signatures

pub mod bench;
pub mod committee;
pub mod consensus_runner;
pub mod delegation;
pub mod disk;
pub mod fees;
pub mod governance;
pub mod mempool;
pub mod metrics;
pub mod network_node;
pub mod persistent;
pub mod pq_rpc;
pub mod private_tables;
pub mod rpc;
pub mod state;
pub mod tee;
pub mod trace;
