//! Disk persistence for seal-node using sled.
//!
//! Persists blocks, SQL state, and chain metadata to disk so the node
//! can restart without losing state.

use seal_crypto::hash::Hash256;
use seal_storage::block_store::Block;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

/// Persistent store backed by sled.
pub struct DiskStore {
    /// Block storage (height → serialized block).
    blocks: sled::Tree,
    /// Chain metadata (latest height, state root).
    meta: sled::Tree,
    /// SQL table data (table_name → serialized rows).
    tables: sled::Tree,
    /// SQL schemas (table_name → serialized schema).
    schemas: sled::Tree,
}

/// Chain metadata stored on disk.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChainMeta {
    pub height: u64,
    pub state_root: Hash256,
    pub chain_id: String,
}

impl DiskStore {
    /// Open or create a persistent store at the given path.
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let db = sled::open(path)?;
        let blocks = db.open_tree("blocks")?;
        let meta = db.open_tree("meta")?;
        let tables = db.open_tree("tables")?;
        let schemas = db.open_tree("schemas")?;

        info!("Disk store opened at {}", path.display());

        Ok(DiskStore {
            blocks,
            meta,
            tables,
            schemas,
        })
    }

    /// Store a block.
    pub fn put_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let key = block.header.height.to_be_bytes();
        let value = bincode::serialize(block)?;
        self.blocks.insert(key, value)?;
        Ok(())
    }

    /// Get a block by height.
    pub fn get_block(&self, height: u64) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let key = height.to_be_bytes();
        match self.blocks.get(key)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Get the latest block height stored.
    pub fn latest_height(&self) -> Result<u64, Box<dyn std::error::Error>> {
        match self.blocks.last()? {
            Some((key, _)) => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&key);
                Ok(u64::from_be_bytes(buf))
            }
            None => Ok(0),
        }
    }

    /// Store chain metadata.
    pub fn put_meta(&self, meta: &ChainMeta) -> Result<(), Box<dyn std::error::Error>> {
        let value = bincode::serialize(meta)?;
        self.meta.insert("chain", value)?;
        Ok(())
    }

    /// Load chain metadata.
    pub fn get_meta(&self) -> Result<Option<ChainMeta>, Box<dyn std::error::Error>> {
        match self.meta.get("chain")? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Store a SQL table's rows.
    pub fn put_table(
        &self,
        table_name: &str,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.tables.insert(table_name.as_bytes(), data)?;
        Ok(())
    }

    /// Load a SQL table's rows.
    pub fn get_table(&self, table_name: &str) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        match self.tables.get(table_name.as_bytes())? {
            Some(bytes) => Ok(Some(bytes.to_vec())),
            None => Ok(None),
        }
    }

    /// Store a table schema.
    pub fn put_schema(
        &self,
        table_name: &str,
        schema: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.schemas.insert(table_name.as_bytes(), schema)?;
        Ok(())
    }

    /// List all stored table names.
    pub fn table_names(&self) -> Vec<String> {
        self.tables
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter_map(|k| String::from_utf8(k.to_vec()).ok())
            .collect()
    }

    /// Get total number of stored blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.blocks.flush()?;
        self.meta.flush()?;
        self.tables.flush()?;
        self.schemas.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disk_store_meta_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = DiskStore::open(dir.path()).unwrap();

        let meta = ChainMeta {
            height: 42,
            state_root: Hash256([1u8; 32]),
            chain_id: "seal-testnet".into(),
        };

        store.put_meta(&meta).unwrap();
        let loaded = store.get_meta().unwrap().unwrap();
        assert_eq!(loaded.height, 42);
        assert_eq!(loaded.chain_id, "seal-testnet");
    }

    #[test]
    fn test_disk_store_table_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = DiskStore::open(dir.path()).unwrap();

        store.put_table("users", b"test data").unwrap();
        let loaded = store.get_table("users").unwrap().unwrap();
        assert_eq!(loaded, b"test data");
    }

    #[test]
    fn test_disk_store_table_names() {
        let dir = tempfile::tempdir().unwrap();
        let store = DiskStore::open(dir.path()).unwrap();

        store.put_table("users", b"a").unwrap();
        store.put_table("orders", b"b").unwrap();
        let names = store.table_names();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn test_disk_store_latest_height_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = DiskStore::open(dir.path()).unwrap();
        assert_eq!(store.latest_height().unwrap(), 0);
    }
}
