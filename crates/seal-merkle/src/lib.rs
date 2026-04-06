#![allow(unexpected_cfgs)]
//! Merkle B-tree with SHA3 hashed references.
//!
//! The core state storage structure for Seal DAO. Every table is a Merkle B-tree
//! of rows keyed by primary key. The state root is the Merkle root of all tables,
//! committed in each block header.
//!
//! Design (from architecture-test-1 and architecture-test-2):
//! - Nodes are stored by their SHA3-256 hash (content-addressed)
//! - Interior nodes contain keys and child hashes
//! - Leaf nodes contain key-value pairs
//! - Any node can be verified against the root hash

pub mod node;
pub mod proof;
pub mod rbtree;
pub mod store;
pub mod tree;

pub use node::{Node, NodeRef};
pub use proof::MerkleProof;
pub use store::MemoryStore;
pub use tree::MerkleTree;

/// Errors returned by Merkle tree operations.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum MerkleError {
    /// A node reference was expected to contain a hash but was empty.
    #[error("expected a non-empty node reference")]
    EmptyNodeRef,

    /// A node hash was not found in the backing store.
    #[error("node not found in store")]
    NodeNotFound,

    /// A leaf node was expected to have at least one entry but was empty.
    #[error("expected non-empty leaf node")]
    EmptyLeaf,
}
