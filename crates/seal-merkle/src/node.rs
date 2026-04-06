//! Merkle B-tree node types.
//!
//! Nodes are content-addressed: stored and referenced by their SHA3-256 hash.
//! This gives us automatic deduplication and Merkle proofs.

use seal_crypto::hash::{Hash256, Sha3Hasher};
use serde::{Deserialize, Serialize};

/// Minimum degree of the B-tree (each node has at most 2*T - 1 keys).
/// T=4 gives nodes with 3-7 keys and 4-8 children.
pub const MIN_DEGREE: usize = 4;

/// Reference to a node, either by hash (for persisted nodes) or inline.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeRef {
    /// Hash pointer to a node in the store.
    Hash(Hash256),
    /// Empty (null pointer).
    Empty,
}

impl NodeRef {
    pub fn is_empty(&self) -> bool {
        matches!(self, NodeRef::Empty)
    }

    pub fn hash(&self) -> Option<&Hash256> {
        match self {
            NodeRef::Hash(h) => Some(h),
            NodeRef::Empty => None,
        }
    }
}

/// A key-value entry in the tree.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// A B-tree node (internal or leaf).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Node {
    /// Key-value entries stored in this node.
    pub entries: Vec<Entry>,
    /// Child node references (len = entries.len() + 1 for internal, 0 for leaf).
    pub children: Vec<NodeRef>,
}

impl Node {
    /// Create a new empty leaf node.
    pub fn new_leaf() -> Self {
        Node {
            entries: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Create a new internal node with one key and two children.
    pub fn new_internal(entry: Entry, left: NodeRef, right: NodeRef) -> Self {
        Node {
            entries: vec![entry],
            children: vec![left, right],
        }
    }

    /// Is this a leaf node (no children)?
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Number of entries in this node.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the node empty?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Is the node full (at max capacity)?
    pub fn is_full(&self) -> bool {
        self.entries.len() >= 2 * MIN_DEGREE - 1
    }

    /// Compute the content hash of this node.
    /// The hash covers all entries and child references, making it a Merkle hash.
    pub fn content_hash(&self) -> Hash256 {
        let mut hasher = Sha3Hasher::new();

        // Hash number of entries
        let n = self.entries.len() as u32;
        hasher.update(&n.to_le_bytes());

        // Hash each entry
        for entry in &self.entries {
            let key_len = entry.key.len() as u32;
            hasher.update(&key_len.to_le_bytes());
            hasher.update(&entry.key);
            let val_len = entry.value.len() as u32;
            hasher.update(&val_len.to_le_bytes());
            hasher.update(&entry.value);
        }

        // Hash children
        let nc = self.children.len() as u32;
        hasher.update(&nc.to_le_bytes());
        for child in &self.children {
            match child {
                NodeRef::Hash(h) => {
                    hasher.update(&[1u8]);
                    hasher.update(h.as_ref());
                }
                NodeRef::Empty => {
                    hasher.update(&[0u8]);
                }
            }
        }

        hasher.finalize()
    }

    /// Find the position where a key would be inserted (binary search).
    pub fn find_key_pos(&self, key: &[u8]) -> Result<usize, usize> {
        self.entries.binary_search_by(|e| e.key.as_slice().cmp(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::hash::sha3_256;

    #[test]
    fn test_leaf_node() {
        let node = Node::new_leaf();
        assert!(node.is_leaf());
        assert!(node.is_empty());
        assert!(!node.is_full());
    }

    #[test]
    fn test_content_hash_deterministic() {
        let mut node = Node::new_leaf();
        node.entries.push(Entry {
            key: b"key1".to_vec(),
            value: b"value1".to_vec(),
        });
        let h1 = node.content_hash();
        let h2 = node.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_content_hash_changes_with_data() {
        let mut node1 = Node::new_leaf();
        node1.entries.push(Entry {
            key: b"key1".to_vec(),
            value: b"value1".to_vec(),
        });

        let mut node2 = Node::new_leaf();
        node2.entries.push(Entry {
            key: b"key1".to_vec(),
            value: b"value2".to_vec(),
        });

        assert_ne!(node1.content_hash(), node2.content_hash());
    }

    #[test]
    fn test_internal_node() {
        let entry = Entry {
            key: b"mid".to_vec(),
            value: b"val".to_vec(),
        };
        let left = NodeRef::Hash(sha3_256(b"left"));
        let right = NodeRef::Hash(sha3_256(b"right"));
        let node = Node::new_internal(entry, left, right);

        assert!(!node.is_leaf());
        assert_eq!(node.len(), 1);
        assert_eq!(node.children.len(), 2);
    }

    #[test]
    fn test_find_key_pos() {
        let mut node = Node::new_leaf();
        node.entries.push(Entry {
            key: b"a".to_vec(),
            value: vec![],
        });
        node.entries.push(Entry {
            key: b"c".to_vec(),
            value: vec![],
        });
        node.entries.push(Entry {
            key: b"e".to_vec(),
            value: vec![],
        });

        assert_eq!(node.find_key_pos(b"a"), Ok(0));
        assert_eq!(node.find_key_pos(b"c"), Ok(1));
        assert_eq!(node.find_key_pos(b"e"), Ok(2));
        assert_eq!(node.find_key_pos(b"b"), Err(1));
        assert_eq!(node.find_key_pos(b"d"), Err(2));
    }
}
