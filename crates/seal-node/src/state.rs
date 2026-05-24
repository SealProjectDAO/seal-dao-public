//! Node state — integrates SQL engine + Merkle tree + block production.

use seal_crypto::address::SealAddress;
use seal_crypto::hash::{sha3_256, Hash256};
use seal_crypto::signature::{SigningKey, VerifyingKey};
use seal_sql::engine::Engine as SqlEngine;
use seal_sql::engine::QueryResult;
use seal_sql::error::SqlError;
use seal_storage::block_store::{Block, BlockHeader, Transaction, TxType};
use seal_vrf::pq_vrf::PqVrf;
use seal_vrf::traits::Vrf;
use seal_vrf::VrfKeypair;

/// A single-node Seal instance.
pub struct NodeState {
    /// PQC signing key (ML-DSA).
    signing_key: SigningKey,
    /// PQC verifying key (ML-DSA).
    pub verifying_key: VerifyingKey,
    /// Node address.
    pub address: SealAddress,
    /// VRF key pair.
    vrf_keypair: VrfKeypair,
    /// SQL execution engine.
    sql_engine: SqlEngine,
    /// Current block height.
    current_height: u64,
    /// Current state root (Merkle root of all tables).
    state_root: Hash256,
    /// Pending transactions.
    pending_txs: Vec<Transaction>,
    /// Produced blocks (for block explorer).
    blocks: Vec<Block>,
}

impl NodeState {
    /// Create a new node with a fresh PQC identity.
    pub fn new() -> Self {
        let (signing_key, verifying_key) = SigningKey::generate();
        let address = SealAddress::from_verifying_key(&verifying_key, true); // testnet
        let vrf_keypair = PqVrf::keygen();

        NodeState {
            signing_key,
            verifying_key,
            address,
            vrf_keypair,
            sql_engine: SqlEngine::new(),
            current_height: 0,
            state_root: Hash256::ZERO,
            pending_txs: Vec::new(),
            blocks: Vec::new(),
        }
    }

    /// Execute a SQL statement locally and add it as a pending transaction.
    pub fn execute_sql(&mut self, sql: &str) -> Result<QueryResult, SqlError> {
        let result = self.sql_engine.execute(sql)?;

        // Create a signed transaction for writes
        if sql.trim_start().to_uppercase().starts_with("SELECT") {
            // Reads are free — no transaction needed
            return Ok(result);
        }

        let tx = self
            .create_transaction(TxType::SqlExec, sql.as_bytes().to_vec())
            .map_err(|e| SqlError::Execution(format!("signing failed: {}", e)))?;
        self.pending_txs.push(tx);
        Ok(result)
    }

    /// Create a signed transaction.
    fn create_transaction(
        &self,
        tx_type: TxType,
        payload: Vec<u8>,
    ) -> Result<Transaction, seal_crypto::CryptoError> {
        let signature = self.signing_key.sign(&payload)?;
        Ok(Transaction {
            tx_type,
            payload,
            sender: self.verifying_key.to_bytes(),
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Produce a new block from pending transactions.
    pub fn produce_block(&mut self) -> Block {
        let parent_hash = if self.current_height == 0 {
            Hash256::ZERO
        } else {
            // Hash of previous block height (simplified)
            sha3_256(&self.current_height.to_le_bytes())
        };

        self.current_height += 1;

        // Compute state root from actual SQL engine state
        self.state_root = self.sql_engine.state_root();

        let block = Block {
            header: BlockHeader {
                height: self.current_height,
                parent_hash,
                state_root: self.state_root,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                proposer: self.verifying_key.to_bytes(),
                vrf_output: vec![],
                vrf_proof: vec![],
            },
            transactions: std::mem::take(&mut self.pending_txs),
        };
        self.blocks.push(block.clone());
        block
    }

    /// Get the current block height.
    pub fn height(&self) -> u64 {
        self.current_height
    }

    /// Get the current state root.
    pub fn state_root(&self) -> &Hash256 {
        &self.state_root
    }

    /// Get the node's address.
    pub fn node_address(&self) -> &SealAddress {
        &self.address
    }

    /// Get a block by height (1-indexed).
    pub fn get_block(&self, height: u64) -> Option<&Block> {
        if height == 0 || height as usize > self.blocks.len() {
            return None;
        }
        Some(&self.blocks[height as usize - 1])
    }

    /// List all table names.
    pub fn table_names(&self) -> Vec<&str> {
        self.sql_engine.table_names()
    }

    /// Get row count for a table.
    pub fn row_count(&self, table: &str) -> Option<usize> {
        self.sql_engine.row_count(table)
    }

    /// Evaluate the VRF for a given slot (for future consensus integration).
    pub fn vrf_eval(&self, slot: u64) -> (seal_vrf::VrfOutput, seal_vrf::VrfProof) {
        let input = format!("slot_{}", slot);
        match PqVrf::eval(&self.vrf_keypair.secret_key, input.as_bytes()) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("VRF eval failed for slot {}: {}", slot, e);
                // Return zero output as fallback — node will not win election with zero VRF output
                (
                    seal_vrf::VrfOutput([0u8; 32]),
                    seal_vrf::VrfProof { bytes: vec![] },
                )
            }
        }
    }

    /// Get the number of pending transactions.
    pub fn pending_tx_count(&self) -> usize {
        self.pending_txs.len()
    }
}

impl Default for NodeState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_creation() {
        let node = NodeState::new();
        assert_eq!(node.height(), 0);
        assert!(node.node_address().to_string().starts_with("sealt1"));
        assert_eq!(node.pending_tx_count(), 0);
    }

    #[test]
    fn test_create_table_and_insert() {
        let mut node = NodeState::new();

        node.execute_sql("CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL)")
            .unwrap();
        assert_eq!(node.pending_tx_count(), 1); // CREATE TABLE is a write

        node.execute_sql("INSERT INTO users (id, name) VALUES (1, 'alice')")
            .unwrap();
        assert_eq!(node.pending_tx_count(), 2);

        // SELECT is free (no transaction)
        let result = node.execute_sql("SELECT * FROM users").unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(node.pending_tx_count(), 2); // Still 2, SELECT didn't add
    }

    #[test]
    fn test_produce_block() {
        let mut node = NodeState::new();

        node.execute_sql("CREATE TABLE t (id BIGINT PRIMARY KEY)")
            .unwrap();
        node.execute_sql("INSERT INTO t (id) VALUES (1)").unwrap();
        node.execute_sql("INSERT INTO t (id) VALUES (2)").unwrap();
        assert_eq!(node.pending_tx_count(), 3);

        let block = node.produce_block();
        assert_eq!(block.header.height, 1);
        assert_eq!(block.transactions.len(), 3);
        assert_eq!(node.pending_tx_count(), 0); // Cleared after block
        assert_eq!(node.height(), 1);

        // Verify transactions are signed
        for tx in &block.transactions {
            assert!(!tx.signature.is_empty());
            assert!(!tx.sender.is_empty());
        }
    }

    #[test]
    fn test_multiple_blocks() {
        let mut node = NodeState::new();

        node.execute_sql("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        let block1 = node.produce_block();
        assert_eq!(block1.header.height, 1);

        node.execute_sql("INSERT INTO t (id, val) VALUES (1, 'a')")
            .unwrap();
        let block2 = node.produce_block();
        assert_eq!(block2.header.height, 2);
        assert_ne!(block1.header.state_root, block2.header.state_root);
    }

    #[test]
    fn test_vrf_evaluation() {
        let node = NodeState::new();
        // PqVrf uses ML-DSA with random nonce — outputs differ per eval.
        // Verify that eval produces a valid (non-zero) output.
        let (output1, _proof1) = node.vrf_eval(42);
        assert_ne!(output1.0, [0u8; 32], "VRF output should be non-zero");

        let (output2, _proof2) = node.vrf_eval(43);
        assert_ne!(output2.0, [0u8; 32]);
    }

    #[test]
    fn test_transaction_signing() {
        let mut node = NodeState::new();
        node.execute_sql("CREATE TABLE t (id BIGINT PRIMARY KEY)")
            .unwrap();
        let block = node.produce_block();

        // Verify the transaction was signed with the node's key
        let tx = &block.transactions[0];
        let vk = VerifyingKey::from_bytes(&tx.sender).unwrap();
        let sig = seal_crypto::signature::Signature::from_bytes(tx.signature.clone());
        assert!(vk.verify(&tx.payload, &sig).is_ok());
    }

    #[test]
    fn test_sql_read_write_separation() {
        let mut node = NodeState::new();
        node.execute_sql("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        node.execute_sql("INSERT INTO t (id, val) VALUES (1, 'hello')")
            .unwrap();

        // SELECT doesn't produce a transaction
        let before = node.pending_tx_count();
        node.execute_sql("SELECT * FROM t").unwrap();
        assert_eq!(node.pending_tx_count(), before);

        // UPDATE does produce a transaction
        node.execute_sql("UPDATE t SET val = 'world' WHERE id = 1")
            .unwrap();
        assert_eq!(node.pending_tx_count(), before + 1);
    }

    #[test]
    fn test_full_workflow() {
        let mut node = NodeState::new();

        // Deploy schema
        node.execute_sql(
            "CREATE TABLE posts (id BIGINT PRIMARY KEY, author TEXT NOT NULL, body TEXT)",
        )
        .unwrap();

        // Insert data
        for i in 0..10 {
            node.execute_sql(&format!(
                "INSERT INTO posts (id, author, body) VALUES ({}, 'user_{}', 'post #{}')",
                i,
                i % 3,
                i
            ))
            .unwrap();
        }

        // Produce block
        let block = node.produce_block();
        assert_eq!(block.header.height, 1);
        assert_eq!(block.transactions.len(), 11); // 1 CREATE + 10 INSERT

        // Query (free, local)
        let result = node
            .execute_sql("SELECT * FROM posts WHERE author = 'user_0'")
            .unwrap();
        assert_eq!(result.rows.len(), 4); // users 0, 3, 6, 9

        // More writes in next block
        node.execute_sql("DELETE FROM posts WHERE id = 0").unwrap();
        let block2 = node.produce_block();
        assert_eq!(block2.header.height, 2);
        assert_eq!(block2.transactions.len(), 1);
    }
}
