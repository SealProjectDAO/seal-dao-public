//! Content-addressed node storage.
//!
//! Nodes are stored by their SHA3-256 hash. This trait abstracts over
//! in-memory storage (for testing) and on-disk storage (for production).

use crate::node::Node;
use seal_crypto::hash::Hash256;
use std::collections::HashMap;

/// Trait for content-addressed node storage.
pub trait NodeStore {
    /// Retrieve a node by its hash.
    fn get(&self, hash: &Hash256) -> Option<Node>;

    /// Store a node, returning its content hash.
    fn put(&mut self, node: &Node) -> Hash256;

    /// Check if a node exists.
    fn contains(&self, hash: &Hash256) -> bool;
}

/// In-memory content-addressed store (for testing and prototyping).
#[derive(Default, Debug)]
pub struct MemoryStore {
    nodes: HashMap<Hash256, Node>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of nodes stored.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

impl NodeStore for MemoryStore {
    fn get(&self, hash: &Hash256) -> Option<Node> {
        self.nodes.get(hash).cloned()
    }

    fn put(&mut self, node: &Node) -> Hash256 {
        let hash = node.content_hash();
        self.nodes.insert(hash, node.clone());
        hash
    }

    fn contains(&self, hash: &Hash256) -> bool {
        self.nodes.contains_key(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Entry;

    #[test]
    fn test_memory_store_put_get() {
        let mut store = MemoryStore::new();
        let mut node = Node::new_leaf();
        node.entries.push(Entry {
            key: b"hello".to_vec(),
            value: b"world".to_vec(),
        });

        let hash = store.put(&node);
        assert!(store.contains(&hash));

        let retrieved = store.get(&hash).unwrap();
        assert_eq!(retrieved, node);
    }

    #[test]
    fn test_memory_store_deduplication() {
        let mut store = MemoryStore::new();
        let mut node = Node::new_leaf();
        node.entries.push(Entry {
            key: b"key".to_vec(),
            value: b"val".to_vec(),
        });

        let h1 = store.put(&node);
        let h2 = store.put(&node);
        assert_eq!(h1, h2);
        assert_eq!(store.len(), 1); // Only one copy stored
    }
}
