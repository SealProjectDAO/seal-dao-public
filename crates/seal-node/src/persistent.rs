//! Persistent node — consensus runner with on-disk block storage.
//!
//! Wraps ConsensusRunner with sled-backed BlockStore so blocks
//! survive node restarts. On startup, replays stored blocks to
//! reconstruct the state.

use crate::consensus_runner::{ConsensusRunner, FinalizedBlock};
use seal_consensus::config::ConsensusConfig;
use seal_crypto::hash::Hash256;
use seal_storage::block_store::BlockStore;

/// A persistent Seal node with on-disk storage.
pub struct PersistentNode {
    /// The consensus runner (in-memory state).
    pub runner: ConsensusRunner,
    /// On-disk block storage.
    block_store: BlockStore,
}

impl PersistentNode {
    /// Create a new persistent node, storing blocks at the given path.
    pub fn open(path: &str, config: ConsensusConfig) -> Result<Self, String> {
        let block_store = BlockStore::open(&format!("{}/blocks", path))
            .map_err(|e| format!("failed to open block store: {}", e))?;

        let mut runner = ConsensusRunner::new(config);

        // Replay any existing blocks to reconstruct state
        let mut height = 1u64;
        let mut replayed = 0;
        while let Some(block) = block_store.get_block(height) {
            runner
                .replay_block(&block)
                .map_err(|e| format!("replay failed at height {}: {}", height, e))?;
            height += 1;
            replayed += 1;
        }

        if replayed > 0 {
            tracing::info!(replayed, "Replayed blocks from disk");
        }

        Ok(PersistentNode {
            runner,
            block_store,
        })
    }

    /// Advance a slot. If a block is produced, persist it to disk.
    pub fn advance_slot(&mut self) -> Option<FinalizedBlock> {
        let block = self.runner.advance_slot()?;

        // Persist to disk
        if let Err(e) = self.block_store.put_block(&block.block) {
            tracing::error!("Failed to persist block: {}", e);
        }

        Some(block)
    }

    /// Submit SQL and queue as transaction.
    pub fn submit_sql(
        &mut self,
        sql: &str,
    ) -> Result<seal_sql::engine::QueryResult, seal_sql::SqlError> {
        self.runner.submit_sql(sql)
    }

    /// Query SQL (read-only).
    pub fn query_sql(
        &mut self,
        sql: &str,
    ) -> Result<seal_sql::engine::QueryResult, seal_sql::SqlError> {
        self.runner.query_sql(sql)
    }

    /// Get chain height.
    pub fn height(&self) -> u64 {
        self.runner.height()
    }

    /// Get state root.
    pub fn state_root(&self) -> &Hash256 {
        self.runner.state_root()
    }

    /// Get stored block height from disk.
    pub fn stored_height(&self) -> u64 {
        self.block_store.height()
    }

    /// Flush block store to disk.
    pub fn flush(&self) -> Result<(), String> {
        self.block_store
            .flush()
            .map_err(|e| format!("flush failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistent_node_basic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();

        let mut node = PersistentNode::open(path, ConsensusConfig::default()).unwrap();
        node.submit_sql("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        node.submit_sql("INSERT INTO t (id, val) VALUES (1, 'hello')")
            .unwrap();

        // Produce a block
        for _ in 0..100 {
            if node.advance_slot().is_some() {
                break;
            }
        }

        assert!(node.height() > 0);
        assert!(node.stored_height() > 0);
        assert_eq!(node.height(), node.stored_height());
    }

    #[test]
    fn test_persistent_node_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();

        let state_root;
        {
            // First run: create data and produce blocks
            let mut node = PersistentNode::open(path, ConsensusConfig::default()).unwrap();
            node.submit_sql("CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT)")
                .unwrap();
            node.submit_sql("INSERT INTO users (id, name) VALUES (1, 'alice')")
                .unwrap();

            for _ in 0..100 {
                if node.advance_slot().is_some() {
                    break;
                }
            }

            state_root = *node.state_root();
            node.flush().unwrap();
            assert!(node.height() > 0);
        }
        // Node dropped here — only disk state remains

        {
            // Second run: state should be reconstructed from blocks
            let mut node = PersistentNode::open(path, ConsensusConfig::default()).unwrap();
            assert!(node.height() > 0, "should have replayed blocks");

            // State root after replay should match
            assert_eq!(
                *node.state_root(),
                state_root,
                "state root after restart should match"
            );

            // Data should be queryable
            let result = node.query_sql("SELECT * FROM users").unwrap();
            assert_eq!(result.rows.len(), 1, "data should survive restart");
        }
    }

    #[test]
    fn test_persistent_node_empty_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();

        let node = PersistentNode::open(path, ConsensusConfig::default()).unwrap();
        assert_eq!(node.height(), 0);
        assert_eq!(node.stored_height(), 0);
    }
}
