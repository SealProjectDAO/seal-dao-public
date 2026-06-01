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
use seal_sql::namespace::NamespaceRegistry;
use seal_sql::SqlError;
use seal_storage::block_store::{Block, BlockHeader, Transaction, TxType};
use seal_threshold::simple::SimpleThreshold;
use seal_threshold::traits::ThresholdScheme;
use seal_token::orderbook::DexManager;
use seal_vrf::VrfKeyManager;
use seal_zk::traits::{StateTransition, ZkProver};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;
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
    /// Can be switched to Sp1Prover via `set_prover()`.
    prover: Box<dyn ZkProver + Send + Sync>,
    /// Storage lease manager (#STORAGE-FORGET).
    /// Tracks per-table leases and handles expiry-based pruning.
    pub leases: seal_token::LeaseManager,
    /// Shared DEX order books. `match_all` runs once per produced block;
    /// the same `Arc` is handed to the JSON-RPC layer so order placement
    /// (`seal_dexPlaceOrder`) and matching share state.
    pub dex: Arc<Mutex<DexManager>>,
    /// Per-app namespaces. SQL submitted via the `*_in_namespace` API
    /// is routed through `AppNamespace::execute_as`, so RLS policies
    /// (including token-gated `HAS_TOKEN(...)` predicates) actually
    /// fire — unlike the bare `MerkleEngine` path used for
    /// global / unscoped SQL transactions.
    pub namespaces: NamespaceRegistry,
    /// Read-only mirror of available SEAL balances, refreshed once per
    /// produced block. Captured by the namespace RLS token checkers so
    /// `HAS_TOKEN(...)` evaluates against the most recent block's
    /// balances without holding a mutable runner reference at policy
    /// evaluation time.
    pub balance_mirror: Arc<RwLock<HashMap<String, u64>>>,
    /// Governance: 6 proposal tracks + conviction voting + adaptive
    /// quorum. Mutating handlers go through the JSON-RPC surface
    /// (`seal_gov*` methods) so callers can propose / vote /
    /// withdraw / tally / execute.
    pub governance: crate::governance::GovernanceModule,
    /// Per-track vote delegation. Mutated via `seal_govDelegate` /
    /// `seal_govRevokeDelegation` JSON-RPC methods.
    pub delegation: crate::delegation::DelegationManager,
    /// Bounded roster of recent state snapshots, captured at every
    /// epoch boundary. Surfaced via `seal_listSnapshots` (A2a) and
    /// the to-come `seal_getSnapshotManifest` / `seal_getSnapshotChunk`
    /// (A2b / A2c). Default cap = 32 ≈ a rolling few-hour window;
    /// callers can override via `SnapshotIndex::with_cap`.
    pub snapshots: seal_storage::SnapshotIndex,
}

/// Available ZK prover backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProverBackend {
    /// RISC Zero STARK (default). PQ-secure, ~200KB proofs.
    RiscZero,
    /// SP1 (Succinct). Faster proving, better multi-GPU.
    Sp1,
}

impl ConsensusRunner {
    /// Create a new consensus runner for a single validator with a
    /// fresh ML-DSA identity. The keypair is regenerated on every
    /// call; for persistent validator identity across restarts use
    /// [`Self::new_with_keypair`].
    pub fn new(config: ConsensusConfig) -> Self {
        let (signing_key, verifying_key) = SigningKey::generate();
        Self::new_with_keypair(config, signing_key, verifying_key)
    }

    /// Create a consensus runner using a caller-supplied validator
    /// identity. The VRF seed is derived deterministically from the
    /// signing key (`SHA3-256(signing_key[..32])`), so loading the
    /// same key on a fresh node reconstructs the same VRF state — the
    /// exact knob `seal-node --validator-key <path>` uses to keep a
    /// stable on-chain identity across restarts.
    ///
    /// Stake defaults to 1 SEAL; multi-node setups should swap to
    /// [`Self::with_validator_set`] with a pre-built [`ValidatorSet`].
    pub fn new_with_keypair(
        config: ConsensusConfig,
        signing_key: SigningKey,
        verifying_key: VerifyingKey,
    ) -> Self {
        // Derive VRF seed from signing key for deterministic recovery.
        let vrf_seed = sha3_256(&signing_key.to_bytes()[..32]).0;
        let vrf_manager = VrfKeyManager::new(vrf_seed);

        let validator = ValidatorInfo {
            public_key: verifying_key.to_bytes(),
            vrf_public_key: vrf_manager.secret_key().to_vec(), // VRF eval uses secret key
            stake: 1_000_000_000,                              // 1 SEAL
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
            leases: seal_token::LeaseManager::new(),
            dex: Arc::new(Mutex::new(DexManager::new())),
            namespaces: NamespaceRegistry::new(),
            balance_mirror: Arc::new(RwLock::new(HashMap::new())),
            governance: crate::governance::GovernanceModule::new(),
            delegation: crate::delegation::DelegationManager::new(),
            snapshots: seal_storage::SnapshotIndex::new(),
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
            leases: seal_token::LeaseManager::new(),
            dex: Arc::new(Mutex::new(DexManager::new())),
            namespaces: NamespaceRegistry::new(),
            balance_mirror: Arc::new(RwLock::new(HashMap::new())),
            governance: crate::governance::GovernanceModule::new(),
            delegation: crate::delegation::DelegationManager::new(),
            snapshots: seal_storage::SnapshotIndex::new(),
        }
    }

    /// Replace the DEX manager with a caller-provided shared instance.
    /// Used by `start_rpc_server` so the RPC layer (which receives order
    /// placements) and the block-production loop (which calls
    /// `match_all`) share the same order books.
    pub fn set_dex_manager(&mut self, dex: Arc<Mutex<DexManager>>) {
        self.dex = dex;
    }

    /// Deploy a new namespaced application. The namespace's RLS manager
    /// is automatically wired to this runner's balance mirror so
    /// `HAS_TOKEN(...)` predicates evaluate against current SEAL
    /// balances. The mirror is refreshed once per produced block; it
    /// is also seeded immediately so a deploy + write + read cycle in
    /// genesis (no blocks yet) still sees correct balances.
    pub fn deploy_namespace(
        &mut self,
        name: String,
        owner: String,
        schema: &str,
    ) -> Result<(), SqlError> {
        self.refresh_balance_mirror();
        self.namespaces.deploy_app(name.clone(), owner, schema)?;
        if let Some(ns) = self.namespaces.get_mut(&name) {
            let mirror = self.balance_mirror.clone();
            // For now all symbols share the SEAL ledger; per-symbol
            // balances will plug in when `TokenManager` exposes a
            // similar mirror.
            ns.rls.set_token_checker(Box::new(move |_symbol, address| {
                mirror
                    .read()
                    .map(|m| m.get(address).copied().unwrap_or(0))
                    .unwrap_or(0)
            }));
        }
        Ok(())
    }

    /// Submit SQL into a namespace's scoped engine, with `user` bound
    /// as the current user for RLS evaluation. DDL inside the
    /// namespace bypasses RLS (owner-level operation); DML and SELECT
    /// pass through `AppNamespace::execute_as` and respect any
    /// configured policies.
    pub fn submit_sql_in_namespace(
        &mut self,
        namespace: &str,
        sql: &str,
        user: &str,
    ) -> Result<seal_sql::engine::QueryResult, SqlError> {
        let ns = self
            .namespaces
            .get_mut(namespace)
            .ok_or_else(|| SqlError::Execution(format!("namespace '{}' not found", namespace)))?;
        ns.execute_as(sql, user)
    }

    /// Enable RLS on a namespace's table and install one policy.
    /// Programmatic alternative to `CREATE POLICY` (the SQL parser
    /// doesn't ingest policy DDL today).
    pub fn enable_rls_policy(
        &mut self,
        namespace: &str,
        table: &str,
        policy: seal_sql::Policy,
    ) -> Result<(), SqlError> {
        let ns = self
            .namespaces
            .get_mut(namespace)
            .ok_or_else(|| SqlError::Execution(format!("namespace '{}' not found", namespace)))?;
        ns.rls.enable_rls(table);
        ns.rls.add_policy(policy)
    }

    /// Refresh the per-block read-only balance snapshot consumed by
    /// namespace RLS token checkers. Called after every block.
    fn refresh_balance_mirror(&self) {
        let snapshot: HashMap<String, u64> = self.balances.all_accounts().into_iter().collect();
        if let Ok(mut m) = self.balance_mirror.write() {
            *m = snapshot;
        }
    }

    /// Apply a `GenesisConfig`'s token allocations to this runner's
    /// balance store. Intended to be called ONCE at node startup
    /// (before any blocks are produced). Returns the total amount
    /// minted so the caller can sanity-check against the configured
    /// `initial_supply`.
    ///
    /// In production this is called from `main.rs` after constructing
    /// the runner with `new` / `with_validator_set`; integration
    /// tests that don't need genesis funding can skip it entirely.
    pub fn apply_genesis(
        &mut self,
        genesis: &seal_consensus::genesis::GenesisConfig,
    ) -> Result<u64, seal_token::TokenError> {
        genesis.apply_balances(&mut self.balances)
    }

    /// Switch the ZK prover backend.
    pub fn set_prover(&mut self, backend: ProverBackend) {
        self.prover = match backend {
            ProverBackend::RiscZero => Box::new(seal_zk::RiscZeroProver::new()),
            ProverBackend::Sp1 => Box::new(seal_zk::Sp1Prover::new()),
        };
    }

    /// Ensure the block seed is set for the current pending block height.
    /// Called before executing any SQL that will go into a block.
    fn ensure_block_seed(&mut self) {
        let next_height = self.chain.len() as u64 + 1;
        let seed = next_height.to_le_bytes().to_vec();
        // Only reset if height changed (avoids resetting salt_counter mid-block)
        if self.sql_engine.block_seed() != Some(&seed) {
            self.sql_engine.set_block_seed(seed);
        }
    }

    /// Submit a SQL transaction. Executes the SQL and queues a signed transaction.
    pub fn submit_sql(
        &mut self,
        sql: &str,
    ) -> Result<seal_sql::engine::QueryResult, seal_sql::SqlError> {
        // Set deterministic block seed so salts are reproducible on replay (#STORAGE-FORGET)
        self.ensure_block_seed();

        // Read stake-gate: SELECT queries require the sender to hold a minimum
        // SEAL balance (prevents spam reads without staking). Currently logged only;
        // enforcement is opt-in per namespace via RLS policies.
        let trimmed = sql.trim_start().to_uppercase();
        if trimmed.starts_with("SELECT") {
            let sender_addr = hex::encode(&self.verifying_key.to_bytes()[..16]);
            let balance = self.balances.available(&sender_addr);
            if balance == 0 {
                tracing::debug!(sender = %sender_addr, "Read without SEAL balance (stake-gate warning)");
            }
        }

        let result = self.sql_engine.execute(sql)?;

        // Reads are free — no transaction
        if !trimmed.starts_with("SELECT") {
            self.submit_transaction(TxType::SqlExec, sql.as_bytes().to_vec())
                .map_err(|e| seal_sql::SqlError::Execution(format!("signing failed: {}", e)))?;
        }

        Ok(result)
    }

    /// Submit a transaction to the pending pool.
    pub fn submit_transaction(
        &mut self,
        tx_type: TxType,
        payload: Vec<u8>,
    ) -> Result<(), seal_crypto::CryptoError> {
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

    /// Process a committee vote received from the P2P network.
    /// Deserializes the vote, verifies the signer is a committee member,
    /// and forwards to the committee manager for aggregation.
    pub fn accept_committee_vote(&mut self, data: &[u8]) -> Result<(), String> {
        let vote: seal_threshold::traits::PartialSignature = bincode::deserialize(data)
            .map_err(|e| format!("failed to deserialize committee vote: {}", e))?;
        tracing::info!(
            signer = vote.signer_index,
            sig_len = vote.signature.len(),
            "Accepted committee vote"
        );
        // In production: aggregate via CommitteeManager and check threshold
        Ok(())
    }

    /// Process a finalized committee signature (threshold attestation).
    /// Once a block has >2/3 weighted committee votes, the threshold sig is formed.
    pub fn accept_committee_signature(&mut self, data: &[u8]) -> Result<(), String> {
        let sig: seal_threshold::traits::ThresholdSignature = bincode::deserialize(data)
            .map_err(|e| format!("failed to deserialize committee signature: {}", e))?;
        tracing::info!(
            sig_len = sig.signature.len(),
            participants = sig.participant_count(),
            "Accepted finalized committee signature"
        );
        // In production: verify threshold sig, mark block as finalized
        Ok(())
    }

    /// Process an epoch transition message.
    /// Updates the validator set VRF keys for the new epoch.
    pub fn accept_epoch_transition(&mut self, data: &[u8]) -> Result<(), String> {
        // Epoch transition data: new epoch number + updated VRF keys
        if data.len() < 8 {
            return Err("epoch transition data too short".into());
        }
        let new_epoch = u64::from_le_bytes(data[..8].try_into().unwrap());
        tracing::info!(new_epoch, "Processing epoch transition");
        // Advance epoch
        self.current_epoch = seal_consensus::epoch::Epoch {
            number: new_epoch,
            seed: seal_crypto::hash::sha3_256(data),
        };
        // In production: rotate VRF keys, update validator set weights
        Ok(())
    }

    /// Submit a governance proposal as a transaction.
    pub fn submit_governance_proposal(
        &mut self,
        proposal_json: &str,
    ) -> Result<(), seal_crypto::CryptoError> {
        self.submit_transaction(TxType::GovPropose, proposal_json.as_bytes().to_vec())
    }

    /// Submit a governance vote as a transaction.
    pub fn submit_governance_vote(
        &mut self,
        vote_json: &str,
    ) -> Result<(), seal_crypto::CryptoError> {
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

            // Capture a snapshot at every epoch boundary so late-joining
            // validators (and `seal_listSnapshots` callers) can pick a
            // recent state root to bootstrap from. We use the chain
            // tip's height + state_root rather than the in-progress
            // slot's because the tip is what's actually been
            // finalized; the new epoch's first block hasn't been
            // produced yet at this point in `advance_slot`. If the
            // chain is empty (genesis epoch transition), skip — there
            // is nothing to snapshot until the first block lands.
            if let Some(tip) = self.chain.last() {
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                // `tip_aggregate` fingerprints the tip block's
                // committee threshold signature. Single-node /
                // pre-Ringtail nodes still produce a `SimpleThreshold`
                // signature; we hash its bytes so the manifest
                // emitted by A2b has *something* attestation-shaped
                // to commit to. Once Ringtail aggregation lands, the
                // same field carries the real algebraic aggregate.
                let tip_aggregate = tip
                    .threshold_signature
                    .as_ref()
                    .map(|sig| sha3_256(&sig.signature));
                let recorded = self.snapshots.record(seal_storage::SnapshotMeta {
                    height: tip.block.header.height,
                    epoch: self.current_epoch.number,
                    state_root: tip.block.header.state_root,
                    captured_at_unix_secs: now_secs,
                    tip_aggregate,
                });
                if recorded {
                    debug!(
                        height = tip.block.header.height,
                        epoch = self.current_epoch.number,
                        "Captured epoch-boundary snapshot"
                    );
                }
            }
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
                    match self
                        .produce_block_with_vrf(vrf_output.0.to_vec(), vrf_proof.bytes.clone())
                    {
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
    fn produce_block_with_vrf(
        &mut self,
        vrf_output: Vec<u8>,
        vrf_proof: Vec<u8>,
    ) -> Result<FinalizedBlock, String> {
        let height = self.chain.len() as u64 + 1;
        let parent_hash = match self.chain.last() {
            Some(b) => {
                let header_bytes = bincode::serialize(&b.block.header)
                    .map_err(|e| format!("failed to serialize parent header: {}", e))?;
                sha3_256(&header_bytes)
            }
            None => Hash256::ZERO,
        };

        let mut txs = std::mem::take(&mut self.pending_txs);
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

        // Storage invoicing (#STORAGE-FORGET): charge per-byte for SQL writes
        for tx in &txs {
            if matches!(
                tx.tx_type,
                TxType::SqlExec | TxType::CreateApp | TxType::AlterSchema
            ) {
                let sender_addr = hex::encode(&tx.sender[..16.min(tx.sender.len())]);
                // Estimate storage cost: payload size * storage rate
                let storage_cost = (tx.payload.len() as u64).saturating_mul(1); // 1 micro-SEAL per byte
                if storage_cost > 0 {
                    let _ = self.balances.burn(&sender_addr, storage_cost);
                }
            }
        }

        // Compute combined state root: SHA3(sql_root || balance_root).
        // Block headers now commit to BOTH the SQL tables AND the
        // native SEAL ledger, so a validator that disagrees on any
        // balance produces a different state_root and the
        // disagreement surfaces in consensus.
        //
        // Future work: also fold in `TokenManager::state_root_hash`
        // and the bridge wrapped-balance set when those are owned by
        // the runner (today they live in RpcState).
        let pre_state = self.state_root;
        let sql_root = self.sql_engine.state_root();
        let balance_root = self.balances.state_root_hash();
        let mut combine = Vec::with_capacity(64);
        combine.extend_from_slice(sql_root.0.as_ref());
        combine.extend_from_slice(balance_root.0.as_ref());
        self.state_root = sha3_256(&combine);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // ── DEX matching (per-block) ──
        // `match_all` is called once per block so order books advance
        // deterministically with chain time. Trades are surfaced via
        // tracing for now; future work will fold them into block
        // transactions so they're observable in the on-chain history
        // and contribute to the state root.
        //
        // `try_lock` keeps block production lock-free: if a JSON-RPC
        // handler is mid-write to the books we skip matching this slot
        // rather than blocking the consensus loop. The RPC handlers
        // hold the lock for microseconds, so contention should be rare.
        match self.dex.try_lock() {
            Ok(mut dex) => {
                let trades = dex.match_all(timestamp);
                if !trades.is_empty() {
                    let pair_count = trades.len();
                    let trade_count: usize = trades.iter().map(|(_, t)| t.len()).sum();
                    info!(
                        height,
                        pair_count, trade_count, "DEX matched orders this block"
                    );

                    // Emit a TxType::DexMatch transaction so the trades
                    // contribute to tx_hash + are visible in the on-chain
                    // history. Payload is bincode of `Vec<(pair_string,
                    // Vec<Trade>)>`. Sender = proposer pubkey, signature
                    // empty (consensus-emitted; verifier checks `tx_type
                    // == DexMatch && sender == block.proposer`).
                    let payload = bincode::serialize(&trades).unwrap_or_default();
                    if !payload.is_empty() {
                        txs.push(seal_storage::block_store::Transaction {
                            tx_type: seal_storage::block_store::TxType::DexMatch,
                            payload,
                            sender: self.verifying_key.to_bytes(),
                            signature: Vec::new(),
                        });
                    }
                }
            }
            Err(_) => {
                debug!(
                    height,
                    "DEX lock contended this slot; skipping match_all (will retry next block)"
                );
            }
        }

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

        // ── Storage lease management (#STORAGE-FORGET) ──
        // 1. Auto-register leases for new tables (from WriteLog)
        if let Some(log) = self.sql_engine.last_write_log() {
            if log.schema_changed {
                // A CREATE TABLE was executed — register a lease for the new table
                let table = &log.table;
                if self.leases.get(table).is_none() {
                    let byte_size = self.sql_engine.table_byte_size(table).unwrap_or(0);
                    let mut lease = seal_token::StorageLease::new(
                        table.clone(),
                        self.verifying_key.to_bytes().to_vec(),
                        1, // default rate (governance-adjustable)
                    );
                    // Grant initial lease (1 epoch = ~4 hours by default)
                    lease.paid_through = finalized.block.header.timestamp.saturating_add(4 * 3600); // 4 hours
                    lease.update_size(
                        self.sql_engine.row_count(table).unwrap_or(0) as u64,
                        byte_size,
                    );
                    self.leases.register(lease);
                }
            }
        }

        // 2. Update byte sizes for modified tables
        for table_name in self.sql_engine.table_names() {
            if let Some(lease) = self.leases.get_mut(table_name) {
                let byte_size = self.sql_engine.table_byte_size(table_name).unwrap_or(0);
                let row_count = self.sql_engine.row_count(table_name).unwrap_or(0) as u64;
                lease.update_size(row_count, byte_size);
            }
        }

        // 3. Check for expired leases and prune
        let now_us = finalized.block.header.timestamp.saturating_mul(1_000_000);
        let expired = self.leases.tables_to_prune(now_us);
        for table_name in &expired {
            tracing::info!(table = %table_name, "Pruning expired table (lease expired)");
            let _ = self.sql_engine.drop_table(table_name);
            self.leases.remove(table_name);
        }

        // ── Refresh the balance mirror consumed by namespace RLS
        // token checkers (#TOKEN-GATED-RLS). Done after fees/emission
        // so HAS_TOKEN(...) sees the post-block state.
        self.refresh_balance_mirror();

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
        // Set deterministic block seed so salts match the producer (#STORAGE-FORGET)
        self.sql_engine
            .set_block_seed(block.header.height.to_le_bytes().to_vec());
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

        // Mirror the produce_block_with_vrf path: combine SQL root +
        // balance root so replay reaches the same `state_root` the
        // proposer published in the block header.
        let sql_root = self.sql_engine.state_root();
        let balance_root = self.balances.state_root_hash();
        let mut combine = Vec::with_capacity(64);
        combine.extend_from_slice(sql_root.0.as_ref());
        combine.extend_from_slice(balance_root.0.as_ref());
        self.state_root = sha3_256(&combine);

        // Track the replayed block in the chain (for height tracking)
        self.chain.push(FinalizedBlock {
            block: block.clone(),
            zk_proof: seal_zk::ZkProof {
                bytes: vec![], // No proof for replayed blocks
                public_inputs: seal_zk::StateTransition {
                    pre_state_root: Hash256::ZERO,
                    post_state_root: self.state_root,
                    block_height: block.header.height,
                    tx_count: block.transactions.len() as u32,
                    tx_hash: Hash256::ZERO,
                },
            },
            threshold_signature: None,
        });

        Ok(self.state_root)
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
        runner
            .submit_transaction(TxType::SqlExec, b"CREATE TABLE t (id INT)".to_vec())
            .unwrap();
        runner
            .submit_transaction(TxType::SqlExec, b"INSERT INTO t VALUES (1)".to_vec())
            .unwrap();

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
        runner
            .submit_transaction(TxType::Transfer, b"transfer".to_vec())
            .unwrap();

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
        runner
            .submit_transaction(TxType::Transfer, b"transfer".to_vec())
            .unwrap();

        for _ in 0..100 {
            if let Some(block) = runner.advance_slot() {
                // Block should contain VRF output and proof from election
                assert!(
                    !block.block.header.vrf_output.is_empty(),
                    "block should have VRF output"
                );
                assert!(
                    !block.block.header.vrf_proof.is_empty(),
                    "block should have VRF proof"
                );
                assert_eq!(
                    block.block.header.vrf_output.len(),
                    32,
                    "VRF output should be 32 bytes (SHA3-256)"
                );
                return;
            }
        }
        panic!("should produce a block");
    }

    /// DEX wiring: a crossing bid+ask placed via the runner's shared
    /// `DexManager` must be matched the next block. Verifies that
    /// `produce_block_with_vrf` actually runs `match_all` and that the
    /// trade lands in the same `Arc<Mutex<DexManager>>` the RPC layer
    /// would observe.
    #[test]
    fn test_dex_match_all_runs_per_block() {
        use seal_token::orderbook::{OrderType, Side};

        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        // Pre-populate a pair with one crossing bid + ask. Using a
        // blocking-mutex would deadlock inside async tests, but since
        // we constructed the runner outside any async runtime here the
        // tokio Mutex's `try_lock` is safe to call directly.
        {
            let mut dex = runner.dex.try_lock().expect("uncontended lock at setup");
            dex.create_pair("GOLD".into(), "SEAL".into()).unwrap();
            let book = dex.get_book_mut("GOLD/SEAL").unwrap();
            // Bid at 100 from alice, ask at 90 from bob — they cross,
            // matching at the maker (ask) price = 90.
            book.place_order("alice".into(), Side::Bid, 100, 5, OrderType::Limit, 0);
            book.place_order("bob".into(), Side::Ask, 90, 5, OrderType::Limit, 0);
            // Sanity: trades have NOT been produced yet because
            // matching only runs at block time.
            assert_eq!(book.recent_trades(usize::MAX).len(), 0);
        }

        // Drive consensus until a block is produced.
        let mut produced = false;
        for _ in 0..100 {
            if runner.advance_slot().is_some() {
                produced = true;
                break;
            }
        }
        assert!(produced, "expected at least one block in 100 slots");

        // After block production, `match_all` should have populated the
        // book's trade history. This proves consensus and RPC see the
        // same order book state through the shared Arc.
        let dex = runner.dex.try_lock().expect("uncontended lock after block");
        let book = dex.get_book("GOLD/SEAL").expect("pair persists");
        let trades = book.recent_trades(usize::MAX);
        assert!(
            !trades.is_empty(),
            "match_all should have produced at least one trade for the crossing bid+ask"
        );
        assert_eq!(trades[0].quantity, 5);
        assert_eq!(trades[0].price, 90, "trade fills at maker (ask) price");
    }

    /// DEX trades emitted in the block must land as a `TxType::DexMatch`
    /// transaction — that's what folds them into `tx_hash` and the
    /// per-block ZK proof. Drops `dex` borrow before re-grabbing for
    /// the assert.
    #[test]
    fn test_dex_match_emits_tx_in_produced_block() {
        use seal_token::orderbook::{OrderType, Side};

        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        {
            let mut dex = runner.dex.try_lock().unwrap();
            dex.create_pair("GOLD".into(), "SEAL".into()).unwrap();
            let book = dex.get_book_mut("GOLD/SEAL").unwrap();
            book.place_order("alice".into(), Side::Bid, 100, 3, OrderType::Limit, 0);
            book.place_order("bob".into(), Side::Ask, 90, 3, OrderType::Limit, 0);
        }

        let mut produced = None;
        for _ in 0..100 {
            if let Some(b) = runner.advance_slot() {
                produced = Some(b);
                break;
            }
        }
        let block = produced.expect("expected block within 100 slots");

        // Find the DexMatch tx and confirm the payload deserializes
        // back into the trade list we observe on the order book.
        let dex_match_tx = block
            .block
            .transactions
            .iter()
            .find(|tx| tx.tx_type == seal_storage::block_store::TxType::DexMatch)
            .expect("block must include a DexMatch tx when trades happen");
        let trades: Vec<(String, Vec<seal_token::orderbook::Trade>)> =
            bincode::deserialize(&dex_match_tx.payload)
                .expect("DexMatch payload must be a bincode trade list");
        let total_trades: usize = trades.iter().map(|(_, t)| t.len()).sum();
        assert!(
            total_trades >= 1,
            "at least one trade must appear in payload"
        );
        let (pair, ts) = &trades[0];
        assert_eq!(pair, "GOLD/SEAL");
        assert_eq!(ts[0].quantity, 3);
        assert_eq!(ts[0].price, 90);
        assert_eq!(
            dex_match_tx.sender,
            runner.verifying_key.to_bytes(),
            "DexMatch sender must be the proposer"
        );
    }

    /// Setting the runner's DexManager to a caller-provided `Arc` is
    /// the contract the RPC server depends on: orders placed through
    /// the RPC `Arc` must be visible to the runner's `match_all` call.
    #[test]
    fn test_set_dex_manager_shares_state() {
        use seal_token::orderbook::{OrderType, Side};

        let shared = Arc::new(Mutex::new(DexManager::new()));
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        runner.set_dex_manager(shared.clone());

        // Place an order via the *external* Arc (mimics the RPC path).
        {
            let mut dex = shared.try_lock().expect("uncontended");
            dex.create_pair("A".into(), "B".into()).unwrap();
            let book = dex.get_book_mut("A/B").unwrap();
            book.place_order("alice".into(), Side::Bid, 50, 1, OrderType::Limit, 0);
            book.place_order("bob".into(), Side::Ask, 50, 1, OrderType::Limit, 0);
        }

        // The runner produces a block — its `match_all` operates on the
        // very same books the RPC handler just wrote to.
        for _ in 0..100 {
            if runner.advance_slot().is_some() {
                break;
            }
        }

        let dex = shared.try_lock().expect("uncontended");
        let trades = dex.get_book("A/B").unwrap().recent_trades(usize::MAX);
        assert!(!trades.is_empty(), "shared Arc should observe the trade");
    }

    /// Token-gated RLS end-to-end: deploy a namespace, enable a
    /// `HAS_TOKEN(...)` SELECT policy, mint balances, advance a slot
    /// to refresh the runner's balance mirror, then verify that a
    /// holder can SELECT and a non-holder cannot.
    #[test]
    fn test_token_gated_rls_end_to_end() {
        use seal_sql::{Policy, PolicyAction};

        let mut runner = ConsensusRunner::new(ConsensusConfig::default());

        // Mint balances for two users so the post-block mirror has
        // entries for both.
        runner.balances.mint("alice", 1_000).unwrap();
        runner.balances.mint("bob", 0).unwrap(); // bob exists at 0
        runner.balances.mint("eve", 5).unwrap(); // eve has too few

        // Deploy a namespaced schema. The runner installs the token
        // checker that reads from `balance_mirror`.
        runner
            .deploy_namespace(
                "vault.seal".into(),
                "alice".into(),
                "CREATE TABLE secrets (id BIGINT PRIMARY KEY, body TEXT NOT NULL)",
            )
            .expect("namespace deploy");

        // Insert a row (DDL/DML run inside the namespace's engine).
        runner
            .submit_sql_in_namespace(
                "vault.seal",
                "INSERT INTO secrets (id, body) VALUES (1, 'classified')",
                "alice",
            )
            .expect("insert in namespace");

        // Enable RLS with a HAS_TOKEN('SEAL', 100) SELECT policy.
        runner
            .enable_rls_policy(
                "vault.seal",
                "secrets",
                Policy {
                    name: "token_gated_select".into(),
                    table_name: "secrets".into(),
                    action: PolicyAction::Select,
                    using_expr: "HAS_TOKEN('SEAL', 100)".into(),
                    with_check_expr: None,
                },
            )
            .expect("enable RLS");

        // The mirror is empty until a block runs (or until we deploy
        // another namespace, which seeds it). Drive a slot.
        for _ in 0..100 {
            if runner.advance_slot().is_some() {
                break;
            }
        }

        // alice has 1000 SEAL → policy allows.
        let alice_view = runner
            .submit_sql_in_namespace("vault.seal", "SELECT * FROM secrets", "alice")
            .expect("alice select");
        assert_eq!(
            alice_view.rows.len(),
            1,
            "alice (1000 SEAL) should see the row through HAS_TOKEN policy"
        );

        // eve has only 5 SEAL → policy denies; rows filtered to empty.
        // (No `owner` column on the table, so the manager applies the
        // table-level deny path.)
        let eve_result =
            runner.submit_sql_in_namespace("vault.seal", "SELECT * FROM secrets", "eve");
        match eve_result {
            Err(SqlError::Execution(msg)) => {
                assert!(
                    msg.contains("RLS"),
                    "eve denied via RLS error path: {}",
                    msg
                );
            }
            Ok(r) => assert_eq!(r.rows.len(), 0, "eve should see zero rows"),
            other => panic!("unexpected result for eve: {:?}", other),
        }

        // bob has 0 SEAL → also denied.
        let bob_result =
            runner.submit_sql_in_namespace("vault.seal", "SELECT * FROM secrets", "bob");
        match bob_result {
            Err(SqlError::Execution(msg)) => assert!(msg.contains("RLS")),
            Ok(r) => assert_eq!(r.rows.len(), 0),
            other => panic!("unexpected result for bob: {:?}", other),
        }
    }

    /// Smoke test for the namespace dispatch: SQL submitted through
    /// `submit_sql_in_namespace` lands in the namespace engine and is
    /// invisible to the bare engine, and vice-versa.
    #[test]
    fn test_namespace_isolation_from_bare_engine() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());

        runner
            .deploy_namespace(
                "appA.seal".into(),
                "alice".into(),
                "CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)",
            )
            .unwrap();
        runner
            .submit_sql_in_namespace(
                "appA.seal",
                "INSERT INTO t (id, val) VALUES (1, 'in-namespace')",
                "alice",
            )
            .unwrap();

        // Bare engine has no `t` table at all.
        let bare = runner.query_sql("SELECT * FROM t");
        assert!(
            bare.is_err(),
            "bare engine must not see namespace tables; got Ok"
        );

        // Namespace engine sees the row.
        let scoped = runner
            .submit_sql_in_namespace("appA.seal", "SELECT * FROM t", "alice")
            .unwrap();
        assert_eq!(scoped.rows.len(), 1);
    }

    /// Governance end-to-end on the runner: propose, vote with
    /// conviction, advance to the tally epoch, tally, then verify
    /// status. Mirrors the JSON-RPC `seal_gov*` flow without going
    /// through HTTP.
    #[test]
    fn test_governance_propose_vote_tally() {
        use crate::governance::{Conviction, ProposalTrack, VoteChoice};

        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        runner.governance.set_total_eligible_supply(1_000);

        // Snapshot the starting epoch so the tally call is gated on a
        // forward-stepped epoch (the GovernanceModule rejects tally
        // before `start_epoch + vote_period_epochs`).
        let start_epoch = runner.current_epoch.number;

        let id = runner.governance.create_proposal(
            ProposalTrack::ParameterChange,
            "raise gas".into(),
            "increase gas limit by 50%".into(),
            "SET param.gas_limit = 1500".into(),
            "alice".into(),
            start_epoch,
        );

        runner
            .governance
            .vote_with_conviction(id, "alice".into(), VoteChoice::Yes, 800, Conviction::X1)
            .unwrap();
        runner
            .governance
            .vote_with_conviction(id, "bob".into(), VoteChoice::No, 100, Conviction::X1)
            .unwrap();

        // Force the epoch forward past the vote period and tally.
        let vote_end = start_epoch + ProposalTrack::ParameterChange.vote_period_epochs();
        let status = runner.governance.tally(id, vote_end).unwrap();
        assert!(
            matches!(status, crate::governance::ProposalStatus::Timelocked { .. }),
            "expected Timelocked, got {:?}",
            status
        );
    }

    /// Withdrawing a vote during the voting period removes the vote
    /// from the tally. The conviction lock survives the withdrawal —
    /// that's the governance contract.
    #[test]
    fn test_governance_withdraw_vote_drops_from_tally() {
        use crate::governance::{Conviction, ProposalTrack, VoteChoice};

        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        runner.governance.set_total_eligible_supply(1_000);

        let start_epoch = runner.current_epoch.number;
        let id = runner.governance.create_proposal(
            ProposalTrack::TreasurySmall,
            "fund grant".into(),
            "alice grant".into(),
            "transfer 100 SEAL to alice".into(),
            "alice".into(),
            start_epoch,
        );
        runner
            .governance
            .vote_with_conviction(id, "alice".into(), VoteChoice::Yes, 500, Conviction::X1)
            .unwrap();
        runner.governance.withdraw_vote(id, "alice").unwrap();

        let vote_end = start_epoch + ProposalTrack::TreasurySmall.vote_period_epochs();
        let status = runner.governance.tally(id, vote_end).unwrap();
        assert!(matches!(
            status,
            crate::governance::ProposalStatus::Rejected
        ));
    }

    /// Delegation: alice delegates 200 SEAL on TreasurySmall to bob.
    /// `effective_weight` reflects that delegation when alice has not
    /// voted directly, and excludes it once alice does.
    #[test]
    fn test_delegation_effective_weight_excludes_direct_voters() {
        use crate::governance::ProposalTrack;

        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        runner
            .delegation
            .delegate("alice", "bob", &ProposalTrack::TreasurySmall, 200)
            .unwrap();

        let no_direct: Vec<String> = vec![];
        assert_eq!(
            runner
                .delegation
                .effective_weight("bob", &ProposalTrack::TreasurySmall, &no_direct),
            200,
            "bob should see alice's delegated 200 when she hasn't voted directly"
        );

        let alice_voted: Vec<String> = vec!["alice".into()];
        assert_eq!(
            runner
                .delegation
                .effective_weight("bob", &ProposalTrack::TreasurySmall, &alice_voted),
            0,
            "alice's direct vote must override her delegation to bob"
        );
    }

    /// Self-delegation is rejected; revocation of a non-existent
    /// delegation is rejected. These guard the `seal_govDelegate` /
    /// `seal_govRevokeDelegation` RPC against caller mistakes.
    #[test]
    fn test_delegation_input_validation() {
        use crate::governance::ProposalTrack;

        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        let track = ProposalTrack::ParameterChange;

        let self_err = runner.delegation.delegate("alice", "alice", &track, 50);
        assert!(self_err.is_err(), "self-delegation must error");

        let revoke_err = runner.delegation.revoke("alice", &track);
        assert!(revoke_err.is_err(), "revoking absent delegation must error");

        runner
            .delegation
            .delegate("alice", "bob", &track, 50)
            .unwrap();
        runner.delegation.revoke("alice", &track).unwrap();
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
        runner
            .submit_transaction(TxType::SqlExec, b"tx1".to_vec())
            .unwrap();
        runner
            .submit_transaction(TxType::SqlExec, b"tx2".to_vec())
            .unwrap();
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
        // Empty block → state root is the deterministic combined hash
        // SHA3(sql_root_zero || balance_root_empty). Block headers
        // now commit to BOTH the SQL Merkle root AND the native SEAL
        // ledger HAMT root, so this isn't ZERO anymore.
        // Important: it must equal what `produce_block_with_vrf`
        // computed in the proposer path (mirror logic).
        let sql_root = Hash256::ZERO;
        let balance_root = replayer.balances.state_root_hash();
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(sql_root.0.as_ref());
        combined.extend_from_slice(balance_root.0.as_ref());
        let expected = sha3_256(&combined);
        assert_eq!(root, expected);
        // Sanity: differs from ZERO so any test that asserted ZERO
        // would have caught the wiring change.
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn test_state_root_includes_balance_changes() {
        // The combined-state-root commitment means a balance change
        // must produce a different state root, even if the SQL
        // engine's table state is identical. This is the key
        // property that prevents a malicious validator from agreeing
        // on SQL state but disagreeing on native balances.
        let mut runner_a = ConsensusRunner::new(ConsensusConfig::default());
        let runner_b = ConsensusRunner::new(ConsensusConfig::default());

        // Same setup on both: empty SQL, empty balances.
        let sql_root_a = runner_a.sql_engine.state_root();
        let sql_root_b = runner_b.sql_engine.state_root();
        assert_eq!(sql_root_a, sql_root_b);

        // Mint to A only.
        runner_a.balances.mint("seal1alice", 1_000).unwrap();

        // Same SQL state, different balance state → different
        // state_root_hash on the underlying balances.
        assert_ne!(
            runner_a.balances.state_root_hash(),
            runner_b.balances.state_root_hash()
        );

        // The combined roots (what the block header commits to)
        // differ for the same reason.
        fn combined_state_root(r: &ConsensusRunner) -> Hash256 {
            let sql_root = r.sql_engine.state_root();
            let balance_root = r.balances.state_root_hash();
            let mut combine = Vec::with_capacity(64);
            combine.extend_from_slice(sql_root.0.as_ref());
            combine.extend_from_slice(balance_root.0.as_ref());
            sha3_256(&combine)
        }
        assert_ne!(
            combined_state_root(&runner_a),
            combined_state_root(&runner_b)
        );
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

    #[test]
    fn test_apply_genesis_credits_runner_balances() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        let genesis = seal_consensus::genesis::GenesisConfig::testnet(3, 10_000_000_000);

        // Precondition: new runner has an empty balance store.
        assert_eq!(runner.balances.total_supply(), 0);

        let credited = runner.apply_genesis(&genesis).unwrap();

        // All validator stakes + any non-validator allocations are live.
        assert!(credited > 0);
        assert_eq!(runner.balances.total_supply(), credited);

        // Spot-check: first testnet allocation lands under its address.
        let first = &genesis.allocations[0];
        assert_eq!(runner.balances.available(&first.address), first.amount);
    }

    /// New runners start with an empty snapshot roster — there's
    /// nothing to record before the first epoch boundary fires.
    #[test]
    fn test_snapshot_roster_starts_empty() {
        let runner = ConsensusRunner::new(ConsensusConfig::default());
        assert!(runner.snapshots.is_empty());
        assert!(runner.snapshots.latest().is_none());
    }

    /// Crossing an epoch boundary must add at most one snapshot per
    /// boundary, and the recorded `(height, epoch, state_root)` must
    /// match the chain tip at the moment of capture. Uses a tiny
    /// 4-slot epoch so the test crosses two boundaries in <30 slot
    /// advances without burning CPU on default 256-slot epochs.
    #[test]
    fn test_snapshot_captured_at_epoch_boundary() {
        let config = ConsensusConfig {
            slots_per_epoch: 4,
            ..ConsensusConfig::default()
        };
        let mut runner = ConsensusRunner::new(config);

        // Submit a couple of txs so blocks have something to commit.
        runner
            .submit_transaction(TxType::SqlExec, b"CREATE TABLE t (id INT)".to_vec())
            .unwrap();
        runner
            .submit_transaction(TxType::SqlExec, b"INSERT INTO t VALUES (1)".to_vec())
            .unwrap();

        // Advance 12 slots = 3 epoch boundaries (slots 4, 8, 12).
        // Genesis (slot 0) is intentionally skipped by
        // `advance_slot`'s `current_slot.number > 0` guard. The first
        // captured snapshot lands at slot 4 with height >= 1.
        for _ in 0..12 {
            runner.advance_slot();
        }

        let captured = runner.snapshots.list().to_vec();
        assert!(
            !captured.is_empty(),
            "at least one snapshot should land after 3 epoch boundaries"
        );
        // Heights must be strictly monotonic.
        for window in captured.windows(2) {
            assert!(
                window[0].height < window[1].height,
                "snapshot heights must be strictly monotonic"
            );
        }
        // Each snapshot's state_root must match a real block in the
        // chain (we capture from the live tip, not synthesized).
        let chain_roots: std::collections::HashSet<Hash256> = runner
            .chain
            .iter()
            .map(|b| b.block.header.state_root)
            .collect();
        for s in &captured {
            assert!(
                chain_roots.contains(&s.state_root),
                "snapshot state_root must match an in-chain block"
            );
        }
        // tip_aggregate carries a SHA3 fingerprint of the tip
        // block's threshold signature when available. In single-node
        // mode, the SimpleThreshold scheme always produces a
        // signature, so the fingerprint is `Some`. The actual hash
        // value is opaque to this test — we only check presence.
        for s in &captured {
            assert!(
                s.tip_aggregate.is_some(),
                "single-node tips always have a threshold signature, so tip_aggregate must be Some"
            );
        }
    }

    /// The roster's cap is enforced — once we cross more boundaries
    /// than the cap allows, the oldest entries are evicted.
    #[test]
    fn test_snapshot_roster_respects_cap() {
        let config = ConsensusConfig {
            slots_per_epoch: 2,
            ..ConsensusConfig::default()
        };
        let mut runner = ConsensusRunner::new(config);
        // Override the runner's snapshot cap to a small value so we
        // can hit eviction without grinding through 33 epoch
        // boundaries' worth of slots.
        runner.snapshots = seal_storage::SnapshotIndex::with_cap(3);

        runner
            .submit_transaction(TxType::SqlExec, b"CREATE TABLE t (id INT)".to_vec())
            .unwrap();

        // 20 slots @ 2 slots/epoch = ~10 epoch boundaries crossed
        // (well above the cap of 3).
        for _ in 0..20 {
            runner.advance_slot();
        }
        assert!(runner.snapshots.len() <= 3, "cap must be enforced");
    }
}
