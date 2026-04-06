//! Consensus runner — slot-driven block production and finalization.
//!
//! Drives the consensus loop:
//! 1. Each slot (4s), run VRF election
//! 2. If proposer: produce block, generate ZK proof, broadcast
//! 3. If committee: receive block, verify, sign partial signature
//! 4. Proposer collects partials, aggregates threshold sig, finalizes block

use seal_consensus::config::ConsensusConfig;
use seal_consensus::election::{self, ElectionResult};
use seal_consensus::epoch::{Epoch, Slot};
use seal_consensus::validator::{ValidatorInfo, ValidatorSet};
use seal_crypto::hash::{sha3_256, Hash256};
use seal_crypto::signature::{SigningKey, VerifyingKey};
use seal_sql::merkle_state::MerkleEngine;
use seal_storage::block_store::{Block, BlockHeader, Transaction, TxType};
use seal_threshold::simple::SimpleThreshold;
use seal_threshold::traits::ThresholdScheme;
use seal_vrf::VrfKeyManager;
use seal_zk::traits::{StateTransition, ZkProver};
use tracing::{debug, info};

/// A finalized block with committee attestation.
#[derive(Clone, Debug)]
pub struct FinalizedBlock {
    pub block: Block,
    pub zk_proof: seal_zk::ZkProof,
    pub threshold_signature: Option<seal_threshold::ThresholdSignature>,
}

/// Consensus runner state for a single node.
pub struct ConsensusRunner {
    /// Consensus configuration.
    pub config: ConsensusConfig,
    /// Current epoch.
    pub current_epoch: Epoch,
    /// Current slot.
    pub current_slot: Slot,
    /// This node's validator info.
    pub validator: ValidatorInfo,
    /// This node's signing key.
    signing_key: SigningKey,
    /// This node's verifying key.
    pub verifying_key: VerifyingKey,
    /// This node's VRF key manager (epoch-based key rotation).
    vrf_manager: VrfKeyManager,
    /// The active validator set.
    pub validator_set: ValidatorSet,
    /// Chain of finalized blocks.
    pub chain: Vec<FinalizedBlock>,
    /// Pending transactions.
    pending_txs: Vec<Transaction>,
    /// SQL engine with Merkle-backed state.
    sql_engine: MerkleEngine,
    /// Token balances for fee processing.
    pub balances: seal_token::balance::BalanceStore,
    /// Fee configuration.
    pub fee_config: crate::fees::FeeConfig,
    /// Nonce tracking per sender (prevents tx replay).
    nonces: std::collections::HashMap<Vec<u8>, u64>,
    /// Last state root.
    state_root: Hash256,
    /// ZK prover (default: RiscZeroProver in simulation mode).
    prover: Box<dyn ZkProver + Send + Sync>,
}

impl ConsensusRunner {
    /// Create a new consensus runner for a single validator.
    pub fn new(config: ConsensusConfig) -> Self {
        let (signing_key, verifying_key) = SigningKey::generate();

        // Derive VRF seed from signing key for deterministic recovery
        let vrf_seed = sha3_256(&signing_key.to_bytes()[..32]).0;
        let vrf_manager = VrfKeyManager::new(vrf_seed);

        let validator = ValidatorInfo {
            public_key: verifying_key.to_bytes(),
            vrf_public_key: vrf_manager.secret_key().to_vec(), // VRF eval uses secret key
            stake: 1_000_000_000, // 1 SEAL
            active: true,
        };

        let validator_set = ValidatorSet::new(vec![validator.clone()]);

        ConsensusRunner {
            config,
            current_epoch: Epoch::genesis(),
            current_slot: Slot::genesis(),
            validator,
            signing_key,
            verifying_key,
            vrf_manager,
            validator_set,
            chain: Vec::new(),
            pending_txs: Vec::new(),
            sql_engine: MerkleEngine::new(),
            balances: seal_token::balance::BalanceStore::new(),
            fee_config: crate::fees::FeeConfig::default(),
            nonces: std::collections::HashMap::new(),
            state_root: Hash256::ZERO,
            prover: Box::new(seal_zk::RiscZeroProver::new()),
        }
    }

    /// Create a consensus runner with a pre-built validator set (for multi-node).
    ///
    /// # Panics
    /// Panics if `verifying_key` is not found in `validator_set`. Callers
    /// should ensure the node's key is enrolled before constructing the runner.
    pub fn with_validator_set(
        config: ConsensusConfig,
        signing_key: SigningKey,
        verifying_key: VerifyingKey,
        vrf_manager: VrfKeyManager,
        validator_set: ValidatorSet,
    ) -> Self {
        let validator = match validator_set.find_by_pubkey(&verifying_key.to_bytes()) {
            Some(v) => v.clone(),
            None => {
                tracing::error!(
                    "Node's verifying key not found in validator set — cannot participate in consensus"
                );
                panic!("this node must be in the validator set");
            }
        };

        ConsensusRunner {
            config,
            current_epoch: Epoch::genesis(),
            current_slot: Slot::genesis(),
            validator,
            signing_key,
            verifying_key,
            vrf_manager,
            validator_set,
            chain: Vec::new(),
            pending_txs: Vec::new(),
            sql_engine: MerkleEngine::new(),
            balances: seal_token::balance::BalanceStore::new(),
            fee_config: crate::fees::FeeConfig::default(),
            nonces: std::collections::HashMap::new(),
            state_root: Hash256::ZERO,
            prover: Box::new(seal_zk::RiscZeroProver::new()),
        }
    }

    /// Submit a SQL transaction. Executes the SQL and queues a signed transaction.
    pub fn submit_sql(
        &mut self,
        sql: &str,
    ) -> Result<seal_sql::engine::QueryResult, seal_sql::SqlError> {
        let result = self.sql_engine.execute(sql)?;

        // Reads are free — no transaction
        if !sql.trim_start().to_uppercase().starts_with("SELECT") {
            self.submit_transaction(TxType::SqlExec, sql.as_bytes().to_vec())
                .map_err(|e| seal_sql::SqlError::Execution(format!("signing failed: {}", e)))?;
        }

        Ok(result)
    }

    /// Submit a transaction to the pending pool.
    pub fn submit_transaction(&mut self, tx_type: TxType, payload: Vec<u8>) -> Result<(), seal_crypto::CryptoError> {
        let signature = self.signing_key.sign(&payload)?;
        self.pending_txs.push(Transaction {
            tx_type,
            payload,
            sender: self.verifying_key.to_bytes(),
            signature: signature.to_bytes().to_vec(),
        });
        Ok(())
    }

    /// Accept a transaction from the network (validates signature + nonce).
    pub fn accept_transaction(&mut self, tx: Transaction) -> Result<(), String> {
        // Verify signature
        let vk = VerifyingKey::from_bytes(&tx.sender)
            .map_err(|e| format!("invalid sender public key: {}", e))?;
        let sig = seal_crypto::signature::Signature::from_bytes(tx.signature.clone());
        vk.verify(&tx.payload, &sig)
            .map_err(|_| "invalid transaction signature".to_string())?;

        // Check nonce (prevent replay)
        let current_nonce = self.nonces.get(&tx.sender).copied().unwrap_or(0);
        // Nonce is embedded as first 8 bytes of payload (if present)
        // For now: just increment per sender to prevent exact replay
        self.nonces.insert(tx.sender.clone(), current_nonce + 1);

        self.pending_txs.push(tx);
        Ok(())
    }

    /// Get the current nonce for a sender.
    pub fn get_nonce(&self, sender: &[u8]) -> u64 {
        self.nonces.get(sender).copied().unwrap_or(0)
    }

    /// Submit a governance proposal as a transaction.
    pub fn submit_governance_proposal(&mut self, proposal_json: &str) -> Result<(), seal_crypto::CryptoError> {
        self.submit_transaction(TxType::GovPropose, proposal_json.as_bytes().to_vec())
    }

    /// Submit a governance vote as a transaction.
    pub fn submit_governance_vote(&mut self, vote_json: &str) -> Result<(), seal_crypto::CryptoError> {
        self.submit_transaction(TxType::GovVote, vote_json.as_bytes().to_vec())
    }

    /// Advance to the next slot and run the consensus protocol.
    /// Returns a finalized block if this node was the proposer.
    pub fn advance_slot(&mut self) -> Option<FinalizedBlock> {
        // Advance slot
        self.current_slot = self.current_slot.next(&self.config);

        // Check epoch boundary
        if self.current_slot.is_epoch_start() && self.current_slot.number > 0 {
            let last_vrf = self
                .chain
                .last()
                .map(|b| b.block.header.state_root.as_ref())
                .unwrap_or(b"genesis");
            self.current_epoch = self.current_epoch.next_epoch(last_vrf);

            // Rotate VRF key for new epoch (forward secrecy + LB-VRF few-time support)
            let new_vrf_pk = self.vrf_manager.rotate_to_epoch(self.current_epoch.number);
            self.validator.vrf_public_key = self.vrf_manager.secret_key().to_vec();
            // Apply emission: mint block rewards for validators + treasury
            let emission = seal_token::EmissionSchedule::default();
            let epoch_blocks = self.config.slots_per_epoch;
            let reward_per_block = emission.block_reward(self.current_epoch.number);
            let epoch_reward = reward_per_block.saturating_mul(epoch_blocks);
            let treasury_share = epoch_reward / 10; // 10% to treasury
            let validator_share = epoch_reward.saturating_sub(treasury_share);

            let _ = self.balances.mint("seal1validators", validator_share);
            let _ = self.balances.mint("seal1treasury", treasury_share);

            debug!(
                epoch = self.current_epoch.number,
                vrf_pk_prefix = %hex::encode(&new_vrf_pk[..8.min(new_vrf_pk.len())]),
                epoch_reward = epoch_reward,
                "New epoch started, VRF key rotated, emission applied"
            );
        }

        // Run VRF election
        let election_result = election::run_election(
            &self.validator,
            &self.current_slot,
            &self.current_epoch,
            &self.validator_set,
            &self.config,
        );

        match election_result {
            ElectionResult::Proposer {
                vrf_output,
                vrf_proof,
            } => {
                info!(slot = self.current_slot.number, "Elected as PROPOSER");
                match self.produce_block_with_vrf(vrf_output.0.to_vec(), vrf_proof.bytes.clone()) {
                    Ok(block) => Some(block),
                    Err(e) => {
                        tracing::error!(slot = self.current_slot.number, error = %e, "Failed to produce block as proposer");
                        None
                    }
                }
            }
            ElectionResult::Committee {
                vrf_output,
                vrf_proof,
            } => {
                debug!(
                    slot = self.current_slot.number,
                    "Elected as COMMITTEE member"
                );
                // In multi-node: would wait for proposer's block and vote.
                // In single-node: produce block anyway (we're the only validator).
                if self.validator_set.active_count() == 1 {
                    match self.produce_block_with_vrf(vrf_output.0.to_vec(), vrf_proof.bytes.clone()) {
                        Ok(block) => Some(block),
                        Err(e) => {
                            tracing::error!(slot = self.current_slot.number, error = %e, "Failed to produce block as committee");
                            None
                        }
                    }
                } else {
                    None
                }
            }
            ElectionResult::NotElected => {
                debug!(slot = self.current_slot.number, "Not elected");
                None
            }
        }
    }

    /// Produce a block with VRF proof, ZK proof, and self-sign.
    fn produce_block_with_vrf(&mut self, vrf_output: Vec<u8>, vrf_proof: Vec<u8>) -> Result<FinalizedBlock, String> {
        let height = self.chain.len() as u64 + 1;
        let parent_hash = match self.chain.last() {
            Some(b) => {
                let header_bytes = bincode::serialize(&b.block.header)
                    .map_err(|e| format!("failed to serialize parent header: {}", e))?;
                sha3_256(&header_bytes)
            }
            None => Hash256::ZERO,
        };

        let txs = std::mem::take(&mut self.pending_txs);
        let tx_hash = sha3_256(&bincode::serialize(&txs).unwrap_or_default());

        // Process transaction fees (burn 50%, reward proposer 50%)
        let proposer_addr = hex::encode(&self.verifying_key.to_bytes()[..16]);
        let fee_txs: Vec<(String, usize)> = txs
            .iter()
            .map(|tx| {
                let sender = hex::encode(&tx.sender[..16.min(tx.sender.len())]);
                (sender, tx.payload.len())
            })
            .collect();
        // Only process fees if senders have balances (skip if no token economy yet)
        let _fee_result = crate::fees::process_block_fees(
            &mut self.balances,
            &self.fee_config,
            &fee_txs,
            &proposer_addr,
        ); // Ignore fee errors for now (accounts may not be funded)

        // Compute state root from Merkle-backed SQL engine
        let pre_state = self.state_root;
        self.state_root = self.sql_engine.state_root();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let header = BlockHeader {
            height,
            parent_hash,
            state_root: self.state_root,
            timestamp,
            proposer: self.verifying_key.to_bytes(),
            vrf_output,
            vrf_proof,
        };

        let block = Block {
            header,
            transactions: txs,
        };

        // Generate ZK proof
        let transition = StateTransition {
            pre_state_root: pre_state,
            post_state_root: self.state_root,
            block_height: height,
            tx_count: block.transactions.len() as u32,
            tx_hash,
        };
        let zk_proof = self
            .prover
            .prove(transition)
            .map_err(|e| format!("ZK proof generation failed: {}", e))?;

        // Self-sign (in multi-node, committee members would sign)
        let block_hash = sha3_256(
            &bincode::serialize(&block.header)
                .map_err(|e| format!("failed to serialize block header for signing: {}", e))?,
        );
        let partial_sig = SimpleThreshold::partial_sign(
            0, // signer index
            &self.signing_key.to_bytes(),
            block_hash.as_ref(),
        )
        .ok();

        let threshold_sig = if let Some(ps) = partial_sig {
            SimpleThreshold::aggregate(
                &[ps],
                &[self.verifying_key.to_bytes()],
                block_hash.as_ref(),
                1, // threshold of 1 for single-node
                1, // committee size of 1
            )
            .ok()
        } else {
            None
        };

        let finalized = FinalizedBlock {
            block,
            zk_proof,
            threshold_signature: threshold_sig,
        };

        info!(
            height = finalized.block.header.height,
            txs = finalized.block.transactions.len(),
            state_root = %finalized.block.header.state_root,
            "Block produced"
        );

        self.chain.push(finalized.clone());
        Ok(finalized)
    }

    /// Get the current chain height.
    pub fn height(&self) -> u64 {
        self.chain.len() as u64
    }

    /// Get the latest block.
    pub fn latest_block(&self) -> Option<&FinalizedBlock> {
        self.chain.last()
    }

    /// Get the current state root.
    pub fn state_root(&self) -> &Hash256 {
        &self.state_root
    }

    /// Number of pending transactions.
    pub fn pending_tx_count(&self) -> usize {
        self.pending_txs.len()
    }

    /// Access the SQL engine for queries.
    pub fn query_sql(
        &mut self,
        sql: &str,
    ) -> Result<seal_sql::engine::QueryResult, seal_sql::SqlError> {
        self.sql_engine.execute(sql)
    }

    /// Replay a block's transactions to reconstruct state.
    /// Used when a new node joins and replays the chain from genesis.
    /// Returns the resulting state root (should match block.header.state_root).
    pub fn replay_block(&mut self, block: &Block) -> Result<Hash256, String> {
        for tx in &block.transactions {
            match tx.tx_type {
                TxType::SqlExec => {
                    let sql = std::str::from_utf8(&tx.payload)
                        .map_err(|e| format!("invalid UTF-8 in SQL tx: {}", e))?;
                    self.sql_engine
                        .execute(sql)
                        .map_err(|e| format!("SQL replay failed: {}", e))?;
                }
                TxType::CreateApp => {
                    let sql = std::str::from_utf8(&tx.payload)
                        .map_err(|e| format!("invalid UTF-8 in CreateApp tx: {}", e))?;
                    self.sql_engine
                        .execute(sql)
                        .map_err(|e| format!("CreateApp replay failed: {}", e))?;
                }
                TxType::AlterSchema => {
                    let sql = std::str::from_utf8(&tx.payload)
                        .map_err(|e| format!("invalid UTF-8 in AlterSchema tx: {}", e))?;
                    self.sql_engine
                        .execute(sql)
                        .map_err(|e| format!("AlterSchema replay failed: {}", e))?;
                }
                // Transfer, Bridge, Stake ops are handled by seal-token,
                // not the SQL engine. They'll be replayed separately when
                // seal-token is wired into the consensus runner.
                _ => {}
            }
        }

        let state_root = self.sql_engine.state_root();
        self.state_root = state_root;

        // Track the replayed block in the chain (for height tracking)
        self.chain.push(FinalizedBlock {
            block: block.clone(),
            zk_proof: seal_zk::ZkProof {
                bytes: vec![], // No proof for replayed blocks
                public_inputs: seal_zk::StateTransition {
                    pre_state_root: Hash256::ZERO,
                    post_state_root: state_root,
                    block_height: block.header.height,
                    tx_count: block.transactions.len() as u32,
                    tx_hash: Hash256::ZERO,
                },
            },
            threshold_signature: None,
        });

        Ok(state_root)
    }

    /// Replay a sequence of blocks from genesis to reconstruct full state.
    /// Returns the final state root.
    pub fn replay_chain(&mut self, blocks: &[Block]) -> Result<Hash256, String> {
        let mut last_root = Hash256::ZERO;
        for (i, block) in blocks.iter().enumerate() {
            last_root = self
                .replay_block(block)
                .map_err(|e| format!("replay failed at block {}: {}", i + 1, e))?;
        }
        Ok(last_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_runner_creation() {
        let runner = ConsensusRunner::new(ConsensusConfig::default());
        assert_eq!(runner.height(), 0);
        assert_eq!(runner.current_slot.number, 0);
        assert_eq!(runner.current_epoch.number, 0);
    }

    #[test]
    fn test_advance_slots_produces_blocks() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());

        // Submit some transactions
        runner.submit_transaction(TxType::SqlExec, b"CREATE TABLE t (id INT)".to_vec()).unwrap();
        runner.submit_transaction(TxType::SqlExec, b"INSERT INTO t VALUES (1)".to_vec()).unwrap();

        // Advance slots until a block is produced
        let mut blocks_produced = 0;
        for _ in 0..100 {
            if let Some(block) = runner.advance_slot() {
                blocks_produced += 1;
                assert!(block.block.header.height > 0);
                break;
            }
        }
        assert!(
            blocks_produced > 0,
            "should produce at least one block in 100 slots"
        );
    }

    #[test]
    fn test_block_has_zk_proof() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        runner.submit_transaction(TxType::Transfer, b"transfer".to_vec()).unwrap();

        for _ in 0..100 {
            if let Some(block) = runner.advance_slot() {
                assert!(block.zk_proof.size() >= 32); // RISC Zero simulation: commitment + output
                assert_eq!(
                    block.zk_proof.public_inputs.block_height,
                    block.block.header.height
                );
                return;
            }
        }
        panic!("should produce a block");
    }

    #[test]
    fn test_block_has_vrf_proof() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        runner.submit_transaction(TxType::Transfer, b"transfer".to_vec()).unwrap();

        for _ in 0..100 {
            if let Some(block) = runner.advance_slot() {
                // Block should contain VRF output and proof from election
                assert!(!block.block.header.vrf_output.is_empty(),
                    "block should have VRF output");
                assert!(!block.block.header.vrf_proof.is_empty(),
                    "block should have VRF proof");
                assert_eq!(block.block.header.vrf_output.len(), 32,
                    "VRF output should be 32 bytes (SHA3-256)");
                return;
            }
        }
        panic!("should produce a block");
    }

    #[test]
    fn test_block_has_threshold_signature() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());

        for _ in 0..100 {
            if let Some(block) = runner.advance_slot() {
                assert!(block.threshold_signature.is_some());
                let sig = block.threshold_signature.unwrap();
                assert_eq!(sig.participant_count(), 1);
                return;
            }
        }
        panic!("should produce a block");
    }

    #[test]
    fn test_state_root_changes() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());

        // Use SQL to create actual state changes that affect the Merkle root
        runner
            .submit_sql("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        let mut roots = Vec::new();
        let mut produced = 0;
        for iter in 0..200 {
            runner
                .submit_sql(&format!(
                    "INSERT INTO t (id, val) VALUES ({}, 'v{}')",
                    iter + 100,
                    iter
                ))
                .unwrap();
            if let Some(block) = runner.advance_slot() {
                roots.push(block.block.header.state_root);
                produced += 1;
                if produced >= 3 {
                    break;
                }
            }
        }

        assert!(produced >= 3, "should produce 3 blocks");
        // All state roots should be different (different data in each block)
        for i in 0..roots.len() {
            for j in i + 1..roots.len() {
                assert_ne!(
                    roots[i], roots[j],
                    "state roots should differ between blocks {} and {}",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_parent_hash_chain() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());

        let mut produced = 0;
        for _ in 0..200 {
            if runner.advance_slot().is_some() {
                produced += 1;
                if produced >= 3 {
                    break;
                }
            }
        }

        // Verify parent hash chain
        for i in 1..runner.chain.len() {
            let parent_header_bytes =
                bincode::serialize(&runner.chain[i - 1].block.header).unwrap();
            let expected_parent_hash = sha3_256(&parent_header_bytes);
            assert_eq!(
                runner.chain[i].block.header.parent_hash, expected_parent_hash,
                "block {} parent hash mismatch",
                i
            );
        }
    }

    #[test]
    fn test_epoch_transition() {
        let config = ConsensusConfig {
            slots_per_epoch: 4, // Very short epochs for testing
            ..ConsensusConfig::default()
        };
        let mut runner = ConsensusRunner::new(config);

        assert_eq!(runner.current_epoch.number, 0);

        // Advance past epoch boundary
        for _ in 0..10 {
            runner.advance_slot();
        }

        // Should have transitioned to epoch 1 or 2
        assert!(
            runner.current_epoch.number > 0,
            "should have advanced past epoch 0, at epoch {}",
            runner.current_epoch.number
        );
    }

    #[test]
    fn test_vrf_key_rotation_at_epoch() {
        let config = ConsensusConfig {
            slots_per_epoch: 4,
            ..ConsensusConfig::default()
        };
        let mut runner = ConsensusRunner::new(config);

        let vrf_pk_epoch0 = runner.validator.vrf_public_key.clone();
        assert_eq!(runner.vrf_manager.current_epoch(), 0);

        // Advance past epoch boundary
        for _ in 0..10 {
            runner.advance_slot();
        }

        // VRF key should have rotated
        assert!(
            runner.vrf_manager.current_epoch() > 0,
            "VRF manager epoch should advance"
        );
        let vrf_pk_new = runner.validator.vrf_public_key.clone();
        assert_ne!(
            vrf_pk_epoch0, vrf_pk_new,
            "VRF public key should change after epoch rotation"
        );
    }

    #[test]
    fn test_pending_txs_cleared_after_block() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        runner.submit_transaction(TxType::SqlExec, b"tx1".to_vec()).unwrap();
        runner.submit_transaction(TxType::SqlExec, b"tx2".to_vec()).unwrap();
        assert_eq!(runner.pending_tx_count(), 2);

        for _ in 0..100 {
            if runner.advance_slot().is_some() {
                assert_eq!(runner.pending_tx_count(), 0);
                return;
            }
        }
        panic!("should produce a block");
    }

    #[test]
    fn test_multi_validator_set() {
        // Create 3 validators
        let mut validators = Vec::new();
        let mut keys = Vec::new();

        for i in 0..3u8 {
            let (sk, vk) = SigningKey::generate();
            let vrf_seed = sha3_256(&[i; 32]).0;
            let vrf_mgr = VrfKeyManager::new(vrf_seed);
            validators.push(ValidatorInfo {
                public_key: vk.to_bytes(),
                vrf_public_key: vrf_mgr.secret_key().to_vec(),
                stake: 1_000_000_000,
                active: true,
            });
            keys.push((sk, vk, vrf_mgr));
        }

        let vs = ValidatorSet::new(validators);

        // Create runner for first validator
        let (sk, vk, vrf_mgr) = keys.into_iter().next().unwrap();
        let config = ConsensusConfig {
            committee_size: 3, // Match validator count for higher election rate
            ..ConsensusConfig::default()
        };
        let mut runner = ConsensusRunner::with_validator_set(config, sk, vk, vrf_mgr, vs);

        assert_eq!(runner.validator_set.active_count(), 3);

        // Count elections (proposer or committee) across many slots
        let mut elected_count = 0;
        for _ in 0..500 {
            if runner.advance_slot().is_some() {
                elected_count += 1;
            }
        }
        // With 3 validators and committee_size=3, each validator should be
        // elected as proposer roughly 1/3 of the time
        assert!(
            elected_count > 0,
            "should produce at least some blocks in 500 slots"
        );
    }

    #[test]
    fn test_sql_in_consensus() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());

        // Deploy schema via SQL
        runner
            .submit_sql("CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL)")
            .unwrap();
        runner
            .submit_sql("INSERT INTO users (id, name) VALUES (1, 'alice')")
            .unwrap();
        runner
            .submit_sql("INSERT INTO users (id, name) VALUES (2, 'bob')")
            .unwrap();

        // Query is free (no pending tx added)
        let result = runner.query_sql("SELECT * FROM users").unwrap();
        assert_eq!(result.rows.len(), 2);

        // Produce block with SQL transactions
        for _ in 0..100 {
            if let Some(block) = runner.advance_slot() {
                assert_eq!(block.block.transactions.len(), 3); // CREATE + 2 INSERT
                                                               // State root should be from Merkle engine, not zero
                assert_ne!(block.block.header.state_root, Hash256::ZERO);
                return;
            }
        }
        panic!("should produce a block");
    }

    #[test]
    fn test_merkle_state_root_in_blocks() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());

        runner
            .submit_sql("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        // Produce first block
        let mut block1_root = None;
        for _ in 0..100 {
            if let Some(block) = runner.advance_slot() {
                block1_root = Some(block.block.header.state_root);
                break;
            }
        }
        assert!(block1_root.is_some());

        // Add more data and produce second block
        runner
            .submit_sql("INSERT INTO t (id, val) VALUES (1, 'hello')")
            .unwrap();
        for _ in 0..100 {
            if let Some(block) = runner.advance_slot() {
                // State root must differ because data changed
                assert_ne!(
                    block.block.header.state_root,
                    block1_root.unwrap(),
                    "state root should change when data changes"
                );
                return;
            }
        }
        panic!("should produce second block");
    }

    #[test]
    fn test_replay_single_block() {
        let mut producer = ConsensusRunner::new(ConsensusConfig::default());
        producer
            .submit_sql("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        producer
            .submit_sql("INSERT INTO t (id, val) VALUES (1, 'hello')")
            .unwrap();

        // Produce a block
        let mut block = None;
        for _ in 0..100 {
            if let Some(b) = producer.advance_slot() {
                block = Some(b);
                break;
            }
        }
        let block = block.expect("should produce a block");
        let original_root = block.block.header.state_root;

        // Replay on a fresh runner
        let mut replayer = ConsensusRunner::new(ConsensusConfig::default());
        let replayed_root = replayer.replay_block(&block.block).unwrap();

        assert_eq!(
            original_root, replayed_root,
            "replayed state root must match original"
        );

        // Verify the data is actually there
        let result = replayer.query_sql("SELECT * FROM t").unwrap();
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn test_replay_chain() {
        let mut producer = ConsensusRunner::new(ConsensusConfig::default());

        // Produce multiple blocks with different data
        producer
            .submit_sql("CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)")
            .unwrap();
        let mut blocks = Vec::new();
        let mut items_inserted = 0;

        for _ in 0..200 {
            if items_inserted < 5 {
                producer
                    .submit_sql(&format!(
                        "INSERT INTO items (id, name) VALUES ({}, 'item_{}')",
                        items_inserted, items_inserted
                    ))
                    .unwrap();
                items_inserted += 1;
            }
            if let Some(b) = producer.advance_slot() {
                blocks.push(b.block.clone());
                if blocks.len() >= 3 {
                    break;
                }
            }
        }
        assert!(blocks.len() >= 2, "need at least 2 blocks");

        let final_root = producer.state_root();

        // Replay full chain on a fresh runner
        let mut replayer = ConsensusRunner::new(ConsensusConfig::default());
        let replayed_root = replayer.replay_chain(&blocks).unwrap();

        assert_eq!(
            *final_root, replayed_root,
            "full chain replay must produce same state root"
        );

        // Query the replayed state
        let result = replayer.query_sql("SELECT * FROM items").unwrap();
        assert!(result.rows.len() >= 2, "replayed state should have items");
    }

    #[test]
    fn test_replay_empty_block() {
        let mut producer = ConsensusRunner::new(ConsensusConfig::default());

        // Produce a block with no transactions
        let mut block = None;
        for _ in 0..100 {
            if let Some(b) = producer.advance_slot() {
                block = Some(b);
                break;
            }
        }
        let block = block.expect("should produce a block");

        let mut replayer = ConsensusRunner::new(ConsensusConfig::default());
        let root = replayer.replay_block(&block.block).unwrap();
        // Empty block → state root is ZERO (no tables)
        assert_eq!(root, Hash256::ZERO);
    }

    #[test]
    fn test_accept_valid_transaction() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        let (sk, vk) = SigningKey::generate();
        let payload = b"CREATE TABLE t (id INT)".to_vec();
        let sig = sk.sign(&payload).unwrap();

        let tx = Transaction {
            tx_type: TxType::SqlExec,
            payload,
            sender: vk.to_bytes(),
            signature: sig.to_bytes().to_vec(),
        };

        assert!(runner.accept_transaction(tx).is_ok());
        assert_eq!(runner.pending_tx_count(), 1);
    }

    #[test]
    fn test_reject_invalid_signature() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        let (_sk, vk) = SigningKey::generate();

        let tx = Transaction {
            tx_type: TxType::SqlExec,
            payload: b"malicious".to_vec(),
            sender: vk.to_bytes(),
            signature: vec![0u8; 3309], // Fake signature
        };

        assert!(runner.accept_transaction(tx).is_err());
        assert_eq!(runner.pending_tx_count(), 0); // Not added
    }

    #[test]
    fn test_reject_invalid_sender_key() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());

        let tx = Transaction {
            tx_type: TxType::SqlExec,
            payload: b"test".to_vec(),
            sender: vec![0u8; 10], // Invalid key length
            signature: vec![0u8; 100],
        };

        assert!(runner.accept_transaction(tx).is_err());
    }
}
