//! On-disk state and block storage for Seal DAO.
//!
//! Uses `sled` as the embedded key-value store engine. Implements the
//! `NodeStore` trait from `seal-merkle` for persistent Merkle B-tree storage.
//!
//! Two stores:
//! - **State DB**: Content-addressed Merkle B-tree nodes (key = SHA3 hash, value = node bytes)
//! - **Block DB**: Blocks indexed by height (key = height as u64 BE, value = block bytes)

pub mod block_store;
pub mod disk_store;
pub mod pruning;

pub use block_store::BlockStore;
pub use disk_store::DiskNodeStore;
pub use pruning::{PruningConfig, PruningManager};
