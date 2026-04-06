//! Property tests for the Merkle B-tree.
//!
//! Uses proptest to generate random operations and verify invariants hold.

use proptest::prelude::*;
use seal_merkle::store::MemoryStore;
use seal_merkle::tree::MerkleTree;

/// Generate a random key (1-8 bytes).
fn arb_key() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..8)
}

/// Generate a random value (0-32 bytes).
fn arb_value() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..32)
}

proptest! {
    /// Property: insert then get always returns the inserted value.
    #[test]
    fn prop_insert_get_roundtrip(key in arb_key(), value in arb_value()) {
        let mut tree = MerkleTree::new(MemoryStore::new());
        tree.insert(key.clone(), value.clone()).unwrap();
        prop_assert_eq!(tree.get(&key), Some(value));
    }

    /// Property: inserting the same key twice overwrites the value.
    #[test]
    fn prop_insert_overwrites(key in arb_key(), v1 in arb_value(), v2 in arb_value()) {
        let mut tree = MerkleTree::new(MemoryStore::new());
        tree.insert(key.clone(), v1).unwrap();
        tree.insert(key.clone(), v2.clone()).unwrap();
        prop_assert_eq!(tree.get(&key), Some(v2));
    }

    /// Property: deleting a key makes get return None.
    #[test]
    fn prop_delete_removes(key in arb_key(), value in arb_value()) {
        let mut tree = MerkleTree::new(MemoryStore::new());
        tree.insert(key.clone(), value).unwrap();
        tree.delete(&key).unwrap();
        prop_assert_eq!(tree.get(&key), None);
    }

    /// Property: root hash is deterministic (same ops → same root).
    #[test]
    fn prop_deterministic_root(
        keys in prop::collection::vec(arb_key(), 1..10),
        values in prop::collection::vec(arb_value(), 1..10),
    ) {
        let pairs: Vec<_> = keys.into_iter().zip(values.into_iter()).collect();

        let mut tree1 = MerkleTree::new(MemoryStore::new());
        let mut tree2 = MerkleTree::new(MemoryStore::new());

        for (k, v) in &pairs {
            tree1.insert(k.clone(), v.clone()).unwrap();
            tree2.insert(k.clone(), v.clone()).unwrap();
        }

        prop_assert_eq!(tree1.root_hash(), tree2.root_hash());
    }

    /// Property: entries are always returned in sorted order.
    #[test]
    fn prop_sorted_output(
        pairs in prop::collection::vec((arb_key(), arb_value()), 1..20),
    ) {
        let mut tree = MerkleTree::new(MemoryStore::new());
        for (k, v) in &pairs {
            tree.insert(k.clone(), v.clone()).unwrap();
        }

        let entries = tree.to_vec();
        for i in 1..entries.len() {
            prop_assert!(entries[i-1].0 < entries[i].0,
                "entries not sorted at position {}", i);
        }
    }
}
