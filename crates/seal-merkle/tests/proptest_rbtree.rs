//! Property tests for the persistent red-black tree.

use proptest::prelude::*;
use seal_merkle::rbtree::RBTree;

proptest! {
    /// Property: insert then get always returns the inserted value.
    #[test]
    fn prop_insert_get(key in 0i64..10000, value in 0i64..10000) {
        let tree = RBTree::new().insert(key, value);
        prop_assert_eq!(tree.get(&key), Some(&value));
    }

    /// Property: entries are always in sorted order after random inserts.
    #[test]
    fn prop_sorted_after_inserts(
        keys in prop::collection::vec(0i64..1000, 1..50),
    ) {
        let mut tree = RBTree::new();
        for &k in &keys {
            tree = tree.insert(k, k * 10);
        }
        let entries = tree.to_vec();
        for i in 1..entries.len() {
            prop_assert!(entries[i-1].0 < entries[i].0,
                "not sorted at {}: {} >= {}", i, entries[i-1].0, entries[i].0);
        }
    }

    /// Property: persistence — old tree unchanged after insert.
    #[test]
    fn prop_persistence(
        k1 in 0i64..1000,
        k2 in 1001i64..2000,
        v1 in 0i64..100,
        v2 in 0i64..100,
    ) {
        let tree1 = RBTree::new().insert(k1, v1);
        let tree2 = tree1.insert(k2, v2);

        // tree1 doesn't have k2
        prop_assert!(tree1.get(&k2).is_none());
        prop_assert_eq!(tree1.len(), 1);

        // tree2 has both
        prop_assert_eq!(tree2.get(&k1), Some(&v1));
        prop_assert_eq!(tree2.get(&k2), Some(&v2));
        prop_assert_eq!(tree2.len(), 2);
    }

    /// Property: range query returns exactly the keys in range.
    #[test]
    fn prop_range_correct(
        keys in prop::collection::vec(0i64..100, 1..30),
        lo in 20i64..40,
        hi in 60i64..80,
    ) {
        let mut tree = RBTree::new();
        for &k in &keys {
            tree = tree.insert(k, k);
        }

        let range = tree.range(&lo, &hi);
        for (k, _) in &range {
            prop_assert!(*k >= lo && *k <= hi,
                "key {} outside range [{}, {}]", k, lo, hi);
        }

        // All keys in range should be in the result
        let all = tree.to_vec();
        for (k, _) in &all {
            if *k >= lo && *k <= hi {
                prop_assert!(range.iter().any(|(rk, _)| rk == k),
                    "key {} in range but missing from result", k);
            }
        }
    }

    /// Property: overwrite preserves length.
    #[test]
    fn prop_overwrite_length(key in 0i64..1000, v1 in 0i64..100, v2 in 0i64..100) {
        let tree = RBTree::new().insert(key, v1).insert(key, v2);
        prop_assert_eq!(tree.len(), 1);
        prop_assert_eq!(tree.get(&key), Some(&v2));
    }
}
