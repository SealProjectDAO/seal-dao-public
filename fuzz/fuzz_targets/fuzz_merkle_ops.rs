//! Fuzz target: Merkle B-tree operations should never panic.
//!
//! Feeds arbitrary key-value pairs to the Merkle tree.
//! Insert, get, delete, and to_vec must never panic.
//! Also validates: insert then get returns the value (roundtrip).

#![no_main]
use libfuzzer_sys::fuzz_target;
use seal_merkle::store::MemoryStore;
use seal_merkle::tree::MerkleTree;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let mut tree = MerkleTree::new(MemoryStore::new());

    // Interpret data as a sequence of (op, key_len, key, value) commands
    let mut pos = 0;
    while pos + 3 < data.len() {
        let op = data[pos] % 4; // 0=insert, 1=get, 2=delete, 3=to_vec
        let key_len = (data[pos + 1] as usize % 8) + 1; // 1-8 byte keys
        pos += 2;

        if pos + key_len > data.len() {
            break;
        }

        let key = data[pos..pos + key_len].to_vec();
        pos += key_len;

        match op {
            0 => {
                // Insert: use remaining byte as value
                let val = if pos < data.len() {
                    let v = vec![data[pos]];
                    pos += 1;
                    v
                } else {
                    vec![0]
                };
                tree.insert(key.clone(), val.clone());
                // Roundtrip check: get should return what we just inserted
                let got = tree.get(&key);
                assert_eq!(got, Some(val), "insert-get roundtrip failed");
            }
            1 => {
                // Get: must not panic
                let _ = tree.get(&key);
            }
            2 => {
                // Delete: must not panic
                let _ = tree.delete(&key);
            }
            3 => {
                // to_vec: must not panic, must be sorted
                let entries = tree.to_vec();
                for i in 1..entries.len() {
                    assert!(
                        entries[i - 1].0 < entries[i].0,
                        "to_vec not sorted at position {}",
                        i
                    );
                }
            }
            _ => {}
        }
    }
});
