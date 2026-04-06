//! Persistent content-addressed node store backed by sled.

use seal_crypto::hash::Hash256;
use seal_merkle::node::Node;
use seal_merkle::store::NodeStore;
/// Persistent node store using sled embedded database.
pub struct DiskNodeStore {
    db: sled::Db,
}

impl DiskNodeStore {
    /// Open or create a store at the given path.
    pub fn open(path: &str) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        Ok(DiskNodeStore { db })
    }

    /// Open with a sled config.
    pub fn open_with_config(config: sled::Config) -> Result<Self, sled::Error> {
        let db = config.open()?;
        Ok(DiskNodeStore { db })
    }

    /// Number of entries in the store.
    pub fn len(&self) -> usize {
        self.db.len()
    }

    /// Is the store empty?
    pub fn is_empty(&self) -> bool {
        self.db.is_empty()
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<(), sled::Error> {
        self.db.flush().map(|_| ())
    }
}

impl NodeStore for DiskNodeStore {
    fn get(&self, hash: &Hash256) -> Option<Node> {
        let bytes = self.db.get(hash.as_bytes()).ok()??;
        bincode::deserialize(&bytes).ok()
    }

    fn put(&mut self, node: &Node) -> Hash256 {
        let hash = node.content_hash();
        let bytes = match bincode::serialize(node) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("disk_store: node serialization failed: {}", e);
                return hash;
            }
        };
        if let Err(e) = self.db.insert(hash.as_bytes(), bytes) {
            eprintln!("disk_store: sled insert failed: {}", e);
        }
        hash
    }

    fn contains(&self, hash: &Hash256) -> bool {
        self.db.contains_key(hash.as_bytes()).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_merkle::node::Entry;
    use seal_merkle::tree::MerkleTree;

    fn temp_store() -> DiskNodeStore {
        let dir = tempfile::tempdir().unwrap();
        DiskNodeStore::open(dir.path().to_str().unwrap()).unwrap()
    }

    #[test]
    fn test_put_and_get() {
        let mut store = temp_store();
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
    fn test_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap().to_string();

        let hash;
        {
            let mut store = DiskNodeStore::open(&path).unwrap();
            let mut node = Node::new_leaf();
            node.entries.push(Entry {
                key: b"persist".to_vec(),
                value: b"test".to_vec(),
            });
            hash = store.put(&node);
            store.flush().unwrap();
        }

        // Reopen and verify data persists
        let store = DiskNodeStore::open(&path).unwrap();
        let node = store.get(&hash).unwrap();
        assert_eq!(node.entries[0].key, b"persist");
        assert_eq!(node.entries[0].value, b"test");
    }

    #[test]
    fn test_merkle_tree_with_disk_store() {
        let store = temp_store();
        let mut tree = MerkleTree::new(store);

        let _ = tree.insert(b"key1".to_vec(), b"val1".to_vec());
        let _ = tree.insert(b"key2".to_vec(), b"val2".to_vec());
        let _ = tree.insert(b"key3".to_vec(), b"val3".to_vec());

        assert_eq!(tree.get(b"key1"), Some(b"val1".to_vec()));
        assert_eq!(tree.get(b"key2"), Some(b"val2".to_vec()));
        assert_eq!(tree.get(b"key3"), Some(b"val3".to_vec()));
        assert_eq!(tree.get(b"missing"), None);
    }

    #[test]
    fn test_deduplication() {
        let mut store = temp_store();
        let mut node = Node::new_leaf();
        node.entries.push(Entry {
            key: b"dup".to_vec(),
            value: b"test".to_vec(),
        });

        let h1 = store.put(&node);
        let h2 = store.put(&node);
        assert_eq!(h1, h2);
    }
}
