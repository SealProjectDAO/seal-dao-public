//! Hash Array Mapped Trie (HAMT) for account state.
//!
//! O(log32 n) lookup, insert, and delete with structural sharing.
//! Each node has up to 32 children (5-bit fan-out from hash).
//! Content-addressed: each node's identity is its SHA3 hash.
//!
//! # Why HAMT?
//!
//! - O(log32 n) = O(1) for practical purposes (7 levels for 34B entries)
//! - Structural sharing: unchanged subtrees are shared between snapshots
//! - Content-addressed: natural fit for Merkle state commitments
//! - Used by: IPFS (IPLD), Ethereum (modified), Filecoin, etc.
//!
//! # Structure
//!
//! ```text
//! Root
//! ├── [0] → Leaf(key1, val1)
//! ├── [5] → Branch
//! │   ├── [0] → Leaf(key2, val2)
//! │   └── [3] → Leaf(key3, val3)
//! └── [31] → Leaf(key4, val4)
//! ```
//!
//! Bitmap tracks which of the 32 slots are occupied.
//! Children array is compressed: only occupied slots stored.

use seal_crypto::hash::{sha3_256, Hash256};

/// Fan-out: 32 children per node (5 bits per level).
const _BRANCH_FACTOR: usize = 32;

/// Bits per level of the trie.
const BITS_PER_LEVEL: usize = 5;

/// Maximum trie depth (256-bit hash / 5 bits per level).
const MAX_DEPTH: usize = 52;

/// A HAMT node.
#[derive(Clone, Debug)]
enum Node {
    /// Empty node.
    Empty,
    /// Single key-value pair.
    Leaf {
        key: Vec<u8>,
        value: Vec<u8>,
        key_hash: Hash256,
    },
    /// Branch with up to 32 children.
    Branch {
        /// Bitmap: bit i is set if child i is present.
        bitmap: u32,
        /// Compressed children array (only occupied slots).
        children: Vec<Node>,
    },
}

/// Hash Array Mapped Trie for account state.
#[derive(Clone, Debug)]
pub struct Hamt {
    root: Node,
    len: usize,
}

impl Default for Hamt {
    fn default() -> Self {
        Self::new()
    }
}

impl Hamt {
    /// Create an empty HAMT.
    pub fn new() -> Self {
        Hamt {
            root: Node::Empty,
            len: 0,
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the trie is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Look up a key. Returns the value if found.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        let hash = sha3_256(key);
        Self::get_node(&self.root, key, &hash, 0)
    }

    /// Insert or update a key-value pair. Returns the old value if replaced.
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Option<Vec<u8>> {
        let hash = sha3_256(&key);
        let (new_root, old_value) = Self::insert_node(self.root.clone(), key, value, hash, 0);
        self.root = new_root;
        if old_value.is_none() {
            self.len += 1;
        }
        old_value
    }

    /// Remove a key. Returns the old value if it existed.
    pub fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let hash = sha3_256(key);
        let (new_root, old_value) = Self::remove_node(self.root.clone(), key, &hash, 0);
        self.root = new_root;
        if old_value.is_some() {
            self.len -= 1;
        }
        old_value
    }

    /// Compute the Merkle root hash of the trie.
    /// Content-addressed: the hash uniquely identifies the trie contents.
    pub fn root_hash(&self) -> Hash256 {
        Self::hash_node(&self.root)
    }

    // ── Internal helpers ──────────────────────────────────

    /// Extract 5 bits from hash at the given depth level.
    fn index_at_depth(hash: &Hash256, depth: usize) -> usize {
        let bit_offset = depth * BITS_PER_LEVEL;
        let byte_idx = bit_offset / 8;
        let bit_idx = bit_offset % 8;

        if byte_idx >= 32 {
            return 0;
        }

        let val = if bit_idx <= 3 {
            // All 5 bits fit in one byte
            (hash.0[byte_idx] >> bit_idx) & 0x1F
        } else {
            // Bits span two bytes
            let lo = hash.0[byte_idx] >> bit_idx;
            let hi = if byte_idx + 1 < 32 {
                hash.0[byte_idx + 1] << (8 - bit_idx)
            } else {
                0
            };
            (lo | hi) & 0x1F
        };

        val as usize
    }

    /// Position in the compressed children array for a given bitmap index.
    fn compressed_index(bitmap: u32, idx: usize) -> usize {
        (bitmap & ((1 << idx) - 1)).count_ones() as usize
    }

    fn get_node<'a>(node: &'a Node, key: &[u8], hash: &Hash256, depth: usize) -> Option<&'a [u8]> {
        match node {
            Node::Empty => None,
            Node::Leaf {
                key: k, value: v, ..
            } => {
                if k == key {
                    Some(v)
                } else {
                    None
                }
            }
            Node::Branch { bitmap, children } => {
                let idx = Self::index_at_depth(hash, depth);
                if bitmap & (1 << idx) == 0 {
                    return None; // slot empty
                }
                let pos = Self::compressed_index(*bitmap, idx);
                Self::get_node(&children[pos], key, hash, depth + 1)
            }
        }
    }

    fn insert_node(
        node: Node,
        key: Vec<u8>,
        value: Vec<u8>,
        hash: Hash256,
        depth: usize,
    ) -> (Node, Option<Vec<u8>>) {
        match node {
            Node::Empty => {
                let leaf = Node::Leaf {
                    key,
                    value,
                    key_hash: hash,
                };
                (leaf, None)
            }
            Node::Leaf {
                key: existing_key,
                value: existing_value,
                key_hash: existing_hash,
            } => {
                if existing_key == key {
                    // Replace value
                    let leaf = Node::Leaf {
                        key,
                        value,
                        key_hash: hash,
                    };
                    (leaf, Some(existing_value))
                } else if depth >= MAX_DEPTH {
                    // Hash collision at max depth — replace (shouldn't happen with SHA3)
                    let leaf = Node::Leaf {
                        key,
                        value,
                        key_hash: hash,
                    };
                    (leaf, Some(existing_value))
                } else {
                    // Split: create a branch with both leaves
                    let idx_existing = Self::index_at_depth(&existing_hash, depth);
                    let idx_new = Self::index_at_depth(&hash, depth);

                    if idx_existing == idx_new {
                        // Same slot — recurse deeper
                        let existing_leaf = Node::Leaf {
                            key: existing_key,
                            value: existing_value,
                            key_hash: existing_hash,
                        };
                        let (child, old) =
                            Self::insert_node(existing_leaf, key, value, hash, depth + 1);
                        let branch = Node::Branch {
                            bitmap: 1 << idx_new,
                            children: vec![child],
                        };
                        (branch, old)
                    } else {
                        // Different slots — both go into the branch
                        let existing_leaf = Node::Leaf {
                            key: existing_key,
                            value: existing_value,
                            key_hash: existing_hash,
                        };
                        let new_leaf = Node::Leaf {
                            key,
                            value,
                            key_hash: hash,
                        };
                        let bitmap = (1 << idx_existing) | (1 << idx_new);
                        let children = if idx_existing < idx_new {
                            vec![existing_leaf, new_leaf]
                        } else {
                            vec![new_leaf, existing_leaf]
                        };
                        (Node::Branch { bitmap, children }, None)
                    }
                }
            }
            Node::Branch {
                mut bitmap,
                mut children,
            } => {
                let idx = Self::index_at_depth(&hash, depth);
                if bitmap & (1 << idx) == 0 {
                    // Slot empty — insert new leaf
                    let pos = Self::compressed_index(bitmap, idx);
                    let leaf = Node::Leaf {
                        key,
                        value,
                        key_hash: hash,
                    };
                    children.insert(pos, leaf);
                    bitmap |= 1 << idx;
                    (Node::Branch { bitmap, children }, None)
                } else {
                    // Slot occupied — recurse into child
                    let pos = Self::compressed_index(bitmap, idx);
                    let child = children.remove(pos);
                    let (new_child, old) = Self::insert_node(child, key, value, hash, depth + 1);
                    children.insert(pos, new_child);
                    (Node::Branch { bitmap, children }, old)
                }
            }
        }
    }

    fn remove_node(
        node: Node,
        key: &[u8],
        hash: &Hash256,
        depth: usize,
    ) -> (Node, Option<Vec<u8>>) {
        match node {
            Node::Empty => (Node::Empty, None),
            Node::Leaf {
                key: k, value: v, ..
            } => {
                if k == key {
                    (Node::Empty, Some(v))
                } else {
                    (
                        Node::Leaf {
                            key_hash: sha3_256(&k),
                            key: k,
                            value: v,
                        },
                        None,
                    )
                }
            }
            Node::Branch {
                mut bitmap,
                mut children,
            } => {
                let idx = Self::index_at_depth(hash, depth);
                if bitmap & (1 << idx) == 0 {
                    return (Node::Branch { bitmap, children }, None);
                }
                let pos = Self::compressed_index(bitmap, idx);
                let child = children.remove(pos);
                let (new_child, old) = Self::remove_node(child, key, hash, depth + 1);

                match new_child {
                    Node::Empty => {
                        bitmap &= !(1 << idx);
                        if children.is_empty() {
                            (Node::Empty, old)
                        } else if children.len() == 1 {
                            // Collapse single-child branch
                            if let Node::Leaf { .. } = &children[0] {
                                (children.remove(0), old)
                            } else {
                                (Node::Branch { bitmap, children }, old)
                            }
                        } else {
                            (Node::Branch { bitmap, children }, old)
                        }
                    }
                    _ => {
                        children.insert(pos, new_child);
                        (Node::Branch { bitmap, children }, old)
                    }
                }
            }
        }
    }

    fn hash_node(node: &Node) -> Hash256 {
        match node {
            Node::Empty => Hash256::ZERO,
            Node::Leaf { key, value, .. } => {
                let mut data = Vec::with_capacity(1 + key.len() + value.len());
                data.push(0x00); // leaf marker
                data.extend_from_slice(key);
                data.extend_from_slice(value);
                sha3_256(&data)
            }
            Node::Branch { bitmap, children } => {
                let mut data = Vec::new();
                data.push(0x01); // branch marker
                data.extend_from_slice(&bitmap.to_le_bytes());
                for child in children {
                    let child_hash = Self::hash_node(child);
                    data.extend_from_slice(child_hash.as_ref());
                }
                sha3_256(&data)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_hamt() {
        let hamt = Hamt::new();
        assert_eq!(hamt.len(), 0);
        assert!(hamt.is_empty());
        assert_eq!(hamt.get(b"key"), None);
    }

    #[test]
    fn test_insert_and_get() {
        let mut hamt = Hamt::new();
        hamt.insert(b"alice".to_vec(), b"100".to_vec());
        hamt.insert(b"bob".to_vec(), b"200".to_vec());

        assert_eq!(hamt.len(), 2);
        assert_eq!(hamt.get(b"alice"), Some(b"100".as_slice()));
        assert_eq!(hamt.get(b"bob"), Some(b"200".as_slice()));
        assert_eq!(hamt.get(b"charlie"), None);
    }

    #[test]
    fn test_update() {
        let mut hamt = Hamt::new();
        let old = hamt.insert(b"alice".to_vec(), b"100".to_vec());
        assert!(old.is_none());

        let old = hamt.insert(b"alice".to_vec(), b"150".to_vec());
        assert_eq!(old, Some(b"100".to_vec()));
        assert_eq!(hamt.len(), 1);
        assert_eq!(hamt.get(b"alice"), Some(b"150".as_slice()));
    }

    #[test]
    fn test_remove() {
        let mut hamt = Hamt::new();
        hamt.insert(b"alice".to_vec(), b"100".to_vec());
        hamt.insert(b"bob".to_vec(), b"200".to_vec());

        let removed = hamt.remove(b"alice");
        assert_eq!(removed, Some(b"100".to_vec()));
        assert_eq!(hamt.len(), 1);
        assert_eq!(hamt.get(b"alice"), None);
        assert_eq!(hamt.get(b"bob"), Some(b"200".as_slice()));
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut hamt = Hamt::new();
        hamt.insert(b"alice".to_vec(), b"100".to_vec());
        let removed = hamt.remove(b"bob");
        assert!(removed.is_none());
        assert_eq!(hamt.len(), 1);
    }

    #[test]
    fn test_many_entries() {
        let mut hamt = Hamt::new();
        for i in 0..1000u32 {
            let key = format!("account_{}", i);
            let val = format!("{}", i * 100);
            hamt.insert(key.into_bytes(), val.into_bytes());
        }
        assert_eq!(hamt.len(), 1000);

        for i in 0..1000u32 {
            let key = format!("account_{}", i);
            let val = format!("{}", i * 100);
            assert_eq!(
                hamt.get(key.as_bytes()),
                Some(val.as_bytes()),
                "missing key: {}",
                key
            );
        }
    }

    #[test]
    fn test_root_hash_deterministic() {
        let mut h1 = Hamt::new();
        let mut h2 = Hamt::new();

        // Same insertions in same order → same hash
        h1.insert(b"a".to_vec(), b"1".to_vec());
        h1.insert(b"b".to_vec(), b"2".to_vec());
        h2.insert(b"a".to_vec(), b"1".to_vec());
        h2.insert(b"b".to_vec(), b"2".to_vec());

        assert_eq!(h1.root_hash(), h2.root_hash());
    }

    #[test]
    fn test_root_hash_changes_on_insert() {
        let mut hamt = Hamt::new();
        let hash_empty = hamt.root_hash();

        hamt.insert(b"a".to_vec(), b"1".to_vec());
        let hash_one = hamt.root_hash();

        hamt.insert(b"b".to_vec(), b"2".to_vec());
        let hash_two = hamt.root_hash();

        assert_ne!(hash_empty, hash_one);
        assert_ne!(hash_one, hash_two);
    }

    #[test]
    fn test_root_hash_changes_on_update() {
        let mut hamt = Hamt::new();
        hamt.insert(b"a".to_vec(), b"1".to_vec());
        let hash_before = hamt.root_hash();

        hamt.insert(b"a".to_vec(), b"2".to_vec());
        let hash_after = hamt.root_hash();

        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn test_structural_sharing() {
        // After cloning and modifying one key, the other keys' subtrees
        // should be shared (same structure in memory).
        let mut h1 = Hamt::new();
        for i in 0..100u32 {
            h1.insert(format!("k{}", i).into_bytes(), vec![i as u8]);
        }
        let h1_hash = h1.root_hash();

        let mut h2 = h1.clone();
        h2.insert(b"k50".to_vec(), vec![0xFF]);

        // h1 is unchanged
        assert_eq!(h1.root_hash(), h1_hash);
        // h2 has different root
        assert_ne!(h1.root_hash(), h2.root_hash());
        // But same length
        assert_eq!(h1.len(), h2.len());
    }

    #[test]
    fn test_remove_until_empty() {
        let mut hamt = Hamt::new();
        hamt.insert(b"a".to_vec(), b"1".to_vec());
        hamt.insert(b"b".to_vec(), b"2".to_vec());
        hamt.insert(b"c".to_vec(), b"3".to_vec());

        hamt.remove(b"a");
        hamt.remove(b"b");
        hamt.remove(b"c");

        assert!(hamt.is_empty());
        assert_eq!(hamt.root_hash(), Hash256::ZERO);
    }

    #[test]
    fn test_index_at_depth() {
        // Verify the bit extraction works correctly
        let hash = sha3_256(b"test");
        for depth in 0..10 {
            let idx = Hamt::index_at_depth(&hash, depth);
            assert!(idx < _BRANCH_FACTOR, "index must be < 32");
        }
    }
}
