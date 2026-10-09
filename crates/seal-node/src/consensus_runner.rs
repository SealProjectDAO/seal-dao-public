//! Consensus runner — slot-driven block production and finalization.
//!
//! Drives the consensus loop:
//! 1. Each slot (4s), run VRF election
//! 2. If proposer: produce block, generate ZK proof, broadcast
//! 3. If committee: receive block, verify, sign partial signature
//! 4. Proposer collects partials, aggregates threshold sig, finalizes block

use seal_consensus::config::ConsensusConfig;
use seal_consensus::election::{self, ElectionResult};
use seal_consensus::epoch::{Epoch, EpochTransitionMsg, Slot};
use seal_consensus::validator::{ValidatorInfo, ValidatorSet};
use seal_crypto::hash::{sha3_256, Hash256};
use seal_crypto::signature::{SigningKey, VerifyingKey};
use seal_sql::engine::Engine;
use seal_sql::merkle_state::MerkleEngine;
use seal_sql::namespace::NamespaceRegistry;
use seal_sql::SqlError;
use seal_storage::block_store::{Block, BlockHeader, Transaction, TxType};
use seal_threshold::simple::SimpleThreshold;
use seal_threshold::traits::ThresholdScheme;
use seal_token::orderbook::DexManager;
use seal_vrf::VrfKeyManager;
use seal_zk::traits::{StateTransition, ZkProof, ZkProver, ZkVerifier};
use seal_zk::ZkError;
use serde::{Deserialize, Serialize};
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

/// Canonical payload for money-movement transactions.
///
/// On-wire encoding (used by every money TxType):
/// `nonce (8 bytes, little-endian) || bincode(MoneyPayload)`.
///
/// `from`/`to` are bech32 Seal addresses — the same keys
/// `BalanceStore` uses — so chain replay can re-apply the movement
/// directly against the native SEAL ledger.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MoneyPayload {
    pub from: String,
    pub to: String,
    pub amount: u64,
}

/// Tx types whose payload uses the money encoding above.
fn is_money_tx_type(tx_type: &TxType) -> bool {
    matches!(
        tx_type,
        TxType::Transfer
            | TxType::TokenTransfer
            | TxType::BridgeIn
            | TxType::BridgeOut
            | TxType::StakeDeposit
            | TxType::StakeWithdraw
    )
}

/// Why an on-block transition failed. `failed_tx` names the transaction (by
/// index) that tripped it. Today only the tx-by-tx step (SQL write / native
/// transfer) can fail, so this is always `Some`; the field is an `Option` so
/// the producer's re-queue logic degrades gracefully if a non-tx step (e.g. a
/// future fallible emission/fee/lease) ever aborts the transition — in that
/// case `None` means "no single tx to blame", so the producer re-queues the
/// WHOLE pool rather than dropping one. The producer uses this to preserve the
/// txs that did NOT cause the failure when a block's transition aborts, so a
/// legitimate tx is not lost with the offending one (audit F1, second pass).
#[derive(Debug)]
pub struct TransitionError {
    pub message: String,
    pub failed_tx: Option<usize>,
}

impl TransitionError {
    /// A specific transaction failed.
    fn at(tx: usize, message: String) -> Self {
        Self {
            message,
            failed_tx: Some(tx),
        }
    }
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Encode a money-transaction payload: 8-byte LE nonce + bincode body.
pub fn encode_money_payload(nonce: u64, body: &MoneyPayload) -> Result<Vec<u8>, String> {
    let mut out = nonce.to_le_bytes().to_vec();
    out.extend(
        bincode::serialize(body)
            .map_err(|e| format!("failed to serialize MoneyPayload: {}", e))?,
    );
    Ok(out)
}

/// Decode a money-transaction payload back into `(nonce, body)`.
fn decode_money_tx(payload: &[u8]) -> Result<(u64, MoneyPayload), String> {
    if payload.len() < 8 {
        return Err("money transaction payload too short (missing 8-byte nonce)".into());
    }
    let nonce = u64::from_le_bytes(
        payload[..8]
            .try_into()
            .map_err(|_| "invalid nonce length".to_string())?,
    );
    let body = bincode::deserialize(&payload[8..])
        .map_err(|e| format!("invalid MoneyPayload in transaction: {}", e))?;
    Ok((nonce, body))
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
    /// Whether this node was enrolled in an *explicit* validator set
    /// (`with_validator_set`) rather than booting with the isolated
    /// single-validator set that `new` / `new_with_keypair` synthesize.
    ///
    /// Only an enrolled node can verify that a block's proposer is a
    /// registered validator: the membership check in
    /// `NetworkNode::verify_and_apply_block` fires only when this is
    /// `true`. A node that booted isolated (local single-validator dev,
    /// no shared set distributed) keeps the legacy self-attested
    /// proposer check so standalone operation does not regress. Full
    /// forger-resistance (audit finding F1) requires every peer to be
    /// enrolled in the same validator set — see the follow-up on
    /// validator-set bootstrap.
    pub enrolled: bool,
    /// Chain of finalized blocks.
    pub chain: Vec<FinalizedBlock>,
    /// Pending transactions.
    pending_txs: Vec<Transaction>,
    /// SQL engine with Merkle-backed state. This is the COMMITTED store: it is
    /// advanced only by `apply_block_transition` (producer + replayer), so the
    /// state root is a pure function of the block.
    sql_engine: MerkleEngine,
    /// Read-your-writes working set: the committed tables PLUS the pending SQL
    /// writes, kept in sync incrementally (one execute per submitted/received
    /// write, rebuilt from `sql_engine` when a block lands). `submit_sql` and
    /// `query_sql` read from here, so a node sees its own not-yet-blocked
    /// writes in O(1) per statement instead of re-executing the whole pending
    /// pool (which would be O(n²) for a batch of n writes).
    ///
    /// This is a bare [`Engine`], NOT a [`MerkleEngine`]: the working set only
    /// needs SQL rows for read-your-writes, never a state root, so it skips the
    /// O(n) per-write Merkle rebuild (and holds no redundant Merkle tree).
    preview_engine: Engine,
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
    /// ZK verifier (default: StubVerifier).
    /// Used to verify proofs submitted via `seal_submitProof`.
    verifier: Box<dyn ZkVerifier + Send + Sync>,
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
    /// The genesis configuration used to initialize this node, stored
    /// after `apply_genesis` so it can be queried via `seal_getGenesis`.
    pub genesis_config: Option<seal_consensus::genesis::GenesisConfig>,
    /// Per-track vote delegation. Mutated via `seal_govDelegate` /
    /// `seal_govRevokeDelegation` JSON-RPC methods.
    pub delegation: crate::delegation::DelegationManager,
    /// Bounded roster of recent state snapshots, captured at every
    /// epoch boundary. Surfaced via `seal_listSnapshots` (A2a) and
    /// the to-come `seal_getSnapshotManifest` / `seal_getSnapshotChunk`
    /// (A2b / A2c). Default cap = 32 ≈ a rolling few-hour window;
    /// callers can override via `SnapshotIndex::with_cap`.
    pub snapshots: seal_storage::SnapshotIndex,
    /// Signed epoch transition stashed when this node crosses an epoch
    /// boundary. Drained by `NetworkNode::tick` and broadcast over
    /// gossip — see `take_pending_epoch_transition`.
    pending_epoch_transition: Option<EpochTransitionMsg>,
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
            // Store the REAL public key: this field is gossiped to peers
            // and served over RPC (`vrf_public_key_hex`). Local election
            // eval uses `self.vrf_manager.secret_key()` directly (see
            // `advance_slot`); peers verify with this public key.
            vrf_public_key: vrf_manager.public_key().to_vec(),
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
            // Isolated single-validator set (this node only) — no shared
            // set to verify membership against, so the membership check
            // in `verify_and_apply_block` is disabled.
            enrolled: false,
            chain: Vec::new(),
            pending_txs: Vec::new(),
            sql_engine: MerkleEngine::new(),
            preview_engine: Engine::new(),
            balances: seal_token::balance::BalanceStore::new(),
            fee_config: crate::fees::FeeConfig::default(),
            nonces: std::collections::HashMap::new(),
            state_root: Hash256::ZERO,
            prover: Box::new(seal_zk::RiscZeroProver::new()),
            verifier: Box::new(seal_zk::StubVerifier),
            leases: seal_token::LeaseManager::new(),
            dex: Arc::new(Mutex::new(DexManager::new())),
            namespaces: NamespaceRegistry::new(),
            balance_mirror: Arc::new(RwLock::new(HashMap::new())),
            governance: crate::governance::GovernanceModule::new(),
            delegation: crate::delegation::DelegationManager::new(),
            snapshots: seal_storage::SnapshotIndex::new(),
            genesis_config: None,
            pending_epoch_transition: None,
        }
    }

    /// Create a consensus runner with a pre-built validator set (for multi-node).
    ///
    /// # Errors
    /// Returns `Err` if `verifying_key` is not found in `validator_set` —
    /// a node that is not enrolled cannot participate in consensus. Callers
    /// should ensure the node's key is enrolled before constructing the runner;
    /// this is an operator configuration error, not a recoverable runtime
    /// condition, so it is surfaced as a `String` rather than a panic.
    pub fn with_validator_set(
        config: ConsensusConfig,
        signing_key: SigningKey,
        verifying_key: VerifyingKey,
        vrf_manager: VrfKeyManager,
        validator_set: ValidatorSet,
    ) -> Result<Self, String> {
        let validator = match validator_set.find_by_pubkey(&verifying_key.to_bytes()) {
            Some(v) => v.clone(),
            None => {
                tracing::error!(
                    "Node's verifying key not found in validator set — cannot participate in consensus"
                );
                return Err(String::from(
                    "this node must be in the validator set",
                ));
            }
        };

        Ok(ConsensusRunner {
            config,
            current_epoch: Epoch::genesis(),
            current_slot: Slot::genesis(),
            validator,
            signing_key,
            verifying_key,
            vrf_manager,
            validator_set,
            // Explicit set supplied by the operator → this node can
            // verify proposer membership (see `enrolled` field docs).
            enrolled: true,
            chain: Vec::new(),
            pending_txs: Vec::new(),
            sql_engine: MerkleEngine::new(),
            preview_engine: Engine::new(),
            balances: seal_token::balance::BalanceStore::new(),
            fee_config: crate::fees::FeeConfig::default(),
            nonces: std::collections::HashMap::new(),
            state_root: Hash256::ZERO,
            prover: Box::new(seal_zk::RiscZeroProver::new()),
            verifier: Box::new(seal_zk::StubVerifier),
            leases: seal_token::LeaseManager::new(),
            dex: Arc::new(Mutex::new(DexManager::new())),
            namespaces: NamespaceRegistry::new(),
            balance_mirror: Arc::new(RwLock::new(HashMap::new())),
            governance: crate::governance::GovernanceModule::new(),
            delegation: crate::delegation::DelegationManager::new(),
            snapshots: seal_storage::SnapshotIndex::new(),
            genesis_config: None,
            pending_epoch_transition: None,
        })
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
    /// balance store. Must be called EXACTLY ONCE at node startup
    /// (before any blocks are produced). Returns the total amount
    /// minted so the caller can sanity-check against the configured
    /// `initial_supply`.
    ///
    /// Applying genesis twice on the same runner would double the total
    /// supply (each `apply_balances` call mints again), so once
    /// `genesis_config` is set a further call is refused with an error
    /// rather than silently double-minting.
    ///
    /// In production this is called from `main.rs` after constructing
    /// the runner with `new` / `with_validator_set`; integration
    /// tests that don't need genesis funding can skip it entirely.
    pub fn apply_genesis(
        &mut self,
        genesis: &seal_consensus::genesis::GenesisConfig,
    ) -> Result<u64, seal_token::TokenError> {
        // Idempotency guard: a second application on the same runner would
        // mint the allocations + validator stakes a second time and double
        // the supply. Genesis is applied exactly once, so once
        // `genesis_config` is `Some` we refuse further applications.
        if self.genesis_config.is_some() {
            return Err(seal_token::TokenError::Custom(
                "genesis already applied; refusing to double-mint".into(),
            ));
        }
        let credited = genesis.apply_balances(&mut self.balances)?;
        self.genesis_config = Some(genesis.clone());
        Ok(credited)
    }

    /// Switch the ZK prover backend (also resets verifier to match).
    pub fn set_prover(&mut self, backend: ProverBackend) {
        self.prover = match backend {
            ProverBackend::RiscZero => Box::new(seal_zk::RiscZeroProver::new()),
            ProverBackend::Sp1 => Box::new(seal_zk::Sp1Prover::new()),
        };
        self.verifier = Box::new(seal_zk::StubVerifier);
    }

    /// Verify a ZK proof of a state transition.
    pub fn verify_proof(&self, proof: &ZkProof) -> Result<(), ZkError> {
        self.verifier.verify(proof)
    }

    /// Submit a SQL transaction. The SQL is executed on the read-your-writes
    /// working set (`preview_engine`) so the caller gets the result, then the
    /// write is enqueued for a block. The COMMITTED engine (`sql_engine`) is
    /// advanced only by `apply_block_transition`, so the state root stays a pure
    /// function of (committed pre-state, block).
    ///
    /// The working set is the committed engine plus the pending SQL writes, kept
    /// in sync incrementally (one execute per submitted/received write; rebuilt
    /// from `sql_engine` when a block lands). This is O(1) per statement —
    /// re-executing the whole pending pool on every submit would be O(n²) for a
    /// batch of n writes.
    pub fn submit_sql(
        &mut self,
        sql: &str,
    ) -> Result<seal_sql::engine::QueryResult, seal_sql::SqlError> {
        let trimmed = sql.trim_start().to_uppercase();
        if trimmed.starts_with("SELECT") {
            // Read stake-gate: SELECT queries require the sender to hold a
            // minimum SEAL balance (prevents spam reads without staking).
            // Currently logged only; enforcement is opt-in per namespace via RLS.
            let sender_addr = hex::encode(&self.verifying_key.to_bytes()[..16]);
            if self.balances.available(&sender_addr) == 0 {
                tracing::debug!(sender = %sender_addr, "Read without SEAL balance (stake-gate warning)");
            }
            // Reads are free — execute on the working set, no transaction enqueued.
            return self.preview_engine.execute(sql);
        }

        // Write: execute on the working set (advances it for read-your-writes)
        // and capture the result, then enqueue. The committed engine is
        // untouched until the on-block transition applies it.
        let result = self.preview_engine.execute(sql)?;
        self.submit_transaction(TxType::SqlExec, sql.as_bytes().to_vec())
            .map_err(|e| seal_sql::SqlError::Execution(format!("signing failed: {}", e)))?;
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
    ///
    /// Money-movement transactions carry an 8-byte little-endian nonce
    /// as the first bytes of their payload. The nonce must equal the
    /// sender's next-expected value — that comparison is what prevents
    /// a received money transaction from being replayed (the same
    /// payload with the same nonce is rejected once consumed). Other
    /// transaction types have no on-wire nonce; for them the counter
    /// below only orders per-sender transactions.
    pub fn accept_transaction(&mut self, tx: Transaction) -> Result<(), String> {
        // Verify signature
        let vk = VerifyingKey::from_bytes(&tx.sender)
            .map_err(|e| format!("invalid sender public key: {}", e))?;
        let sig = seal_crypto::signature::Signature::from_bytes(tx.signature.clone());
        vk.verify(&tx.payload, &sig)
            .map_err(|_| "invalid transaction signature".to_string())?;

        // Nonce check (prevents replay). Only money-movement txs carry an
        // on-wire nonce and consume a slot from the per-sender counter. The
        // on-block transition rebuilds this counter for money txs only
        // (`apply_block_transition_impl`), so a fresh/restarted node
        // reconstructs it from the chain's money txs alone. F9: we used to
        // advance the counter for EVERY tx type here, so a sender who mixed SQL
        // writes with transfers got a counter that diverged between a running
        // node (bumped at accept for the SQL writes) and a fresh node (rebuilt
        // from money txs only) — the two disagreed on the next expected transfer
        // nonce until a Transfer from that sender landed in a block. Advance
        // only for money txs, matching the transition. Non-money txs (SQL, DDL,
        // DexMatch) carry no on-wire nonce and are applied in block order by the
        // transition, not sequenced per-sender.
        if is_money_tx_type(&tx.tx_type) {
            let (nonce, _body) = decode_money_tx(&tx.payload)?;
            let next_nonce = self.nonces.get(&tx.sender).copied().unwrap_or(0);
            if nonce != next_nonce {
                return Err(format!(
                    "nonce mismatch: expected {}, got {}",
                    next_nonce, nonce
                ));
            }
            let next_after = next_nonce
                .checked_add(1)
                .ok_or_else(|| "nonce counter overflow".to_string())?;
            self.nonces.insert(tx.sender.clone(), next_after);
        }

        // Read-your-writes: apply a received SQL write to the working set so a
        // query issued after this sees it, before it lands in a block. A write
        // that FAILS on the working set is rejected outright (audit F1,
        // second pass): otherwise a correctly-signed malformed write (e.g.
        // `INSERT INTO nonexistent`) passes the signature/nonce checks, is
        // gossiped, and is drained by the next producer into an on-block
        // transition that aborts mid-block — destroying the pool's other
        // transactions with it. Rejection here is the same outcome the
        // transition would reach, so it cannot desync the committed state.
        if matches!(
            tx.tx_type,
            TxType::SqlExec | TxType::CreateApp | TxType::AlterSchema
        ) {
            let sql = std::str::from_utf8(&tx.payload)
                .map_err(|e| format!("invalid UTF-8 in SQL tx: {}", e))?;
            if let Err(e) = self.preview_engine.execute(sql) {
                return Err(format!("SQL write rejected at accept: {}", e));
            }
        }

        self.pending_txs.push(tx);
        Ok(())
    }

    /// Enqueue a signed money-movement transaction stamped with this
    /// node's next nonce.
    ///
    /// The nonce is consumed at enqueue time, not at block inclusion:
    /// any later network copy of the same movement fails the
    /// `accept_transaction` check because the counter has already
    /// advanced past it. This is what makes `seal_transfer` replay-safe
    /// — the RPC handler moves the balance immediately and then calls
    /// this, so the movement is recorded on-chain exactly once.
    ///
    /// Returns the nonce that was stamped.
    pub fn submit_money_tx(
        &mut self,
        tx_type: TxType,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Result<u64, String> {
        if !is_money_tx_type(&tx_type) {
            return Err("submit_money_tx requires a money-movement TxType".into());
        }
        let body = MoneyPayload {
            from: from.to_string(),
            to: to.to_string(),
            amount,
        };
        let sender = self.verifying_key.to_bytes();
        let nonce = self.get_nonce(&sender);
        let payload = encode_money_payload(nonce, &body)?;
        let signature = self
            .signing_key
            .sign(&payload)
            .map_err(|e| format!("signing failed: {}", e))?;
        let next_after = nonce
            .checked_add(1)
            .ok_or_else(|| "nonce counter overflow".to_string())?;
        self.nonces.insert(sender.clone(), next_after);
        self.pending_txs.push(Transaction {
            tx_type,
            payload,
            sender,
            signature: signature.to_bytes().to_vec(),
        });
        Ok(nonce)
    }

    /// Get the current nonce for a sender.
    pub fn get_nonce(&self, sender: &[u8]) -> u64 {
        self.nonces.get(sender).copied().unwrap_or(0)
    }

    /// The sender's available balance after applying all pending (not-yet-blocked)
    /// money-movement transactions. Used to reject overdrafts at submit time
    /// WITHOUT mutating the committed ledger: the on-block transition
    /// (`apply_block_transition`) is the single place that applies transfers,
    /// identically for the producer and every replayer (F3).
    pub fn available_with_pending(&self, sender: &str) -> u64 {
        let mut preview = self.balances.clone();
        for tx in &self.pending_txs {
            if tx.tx_type == TxType::Transfer {
                if let Ok((_nonce, body)) = decode_money_tx(&tx.payload) {
                    let _ = preview.transfer(&body.from, &body.to, body.amount);
                }
            }
        }
        preview.available(sender)
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
    ///
    /// The message (bincode `EpochTransitionMsg`) must:
    /// 1. target exactly our next epoch (no skips, no repeats),
    /// 2. be anchored to our state — `prev_seed` equals our current
    ///    epoch seed and `vrf_output` equals our last finalized
    ///    block's state root,
    /// 3. derive its claimed `seed` from (prev_seed, vrf_output) via
    ///    `Epoch::next_epoch`,
    /// 4. be signed over its canonical bytes by an ACTIVE member of
    ///    the current validator set.
    ///
    /// Checks 1-3 make the message content fully determined by local
    /// chain state; check 4 is what binds an accountable validator to
    /// it. (Audit B.8: previously any peer could inject an arbitrary
    /// epoch number and rewrite the epoch seed, unsigned.)
    pub fn accept_epoch_transition(&mut self, data: &[u8]) -> Result<(), String> {
        let msg: EpochTransitionMsg = bincode::deserialize(data)
            .map_err(|e| format!("epoch transition decode: {}", e))?;

        let expected_epoch = self
            .current_epoch
            .number
            .checked_add(1)
            .ok_or_else(|| "epoch number overflow".to_string())?;
        if msg.epoch != expected_epoch {
            return Err(format!(
                "epoch transition: expected epoch {}, got {}",
                expected_epoch, msg.epoch
            ));
        }
        if msg.prev_seed != self.current_epoch.seed {
            return Err(
                "epoch transition: prev_seed does not match our current epoch seed"
                    .to_string(),
            );
        }
        // The VRF input must be the same one our own `advance_slot`
        // would use at this boundary — the chain tip's state root
        // (b"genesis" on an empty chain).
        let local_vrf = self
            .chain
            .last()
            .map(|b| b.block.header.state_root.as_ref())
            .unwrap_or(b"genesis");
        if msg.vrf_output != local_vrf {
            return Err(
                "epoch transition: vrf_output does not match our chain tip".to_string(),
            );
        }
        let derived = self.current_epoch.next_epoch(&msg.vrf_output);
        if msg.seed != derived.seed {
            return Err(
                "epoch transition: seed does not match prev_seed + vrf_output".to_string(),
            );
        }
        let info = self
            .validator_set
            .find_by_pubkey(&msg.signer)
            .ok_or_else(|| "epoch transition: signer is not in the validator set".to_string())?;
        if !info.active {
            return Err("epoch transition: signer is not an active validator".to_string());
        }
        let vk = VerifyingKey::from_bytes(&msg.signer)
            .map_err(|e| format!("epoch transition: invalid signer key: {}", e))?;
        let sig = seal_crypto::signature::Signature::from_bytes(msg.signature.clone());
        vk.verify(&sha3_256(&msg.canonical_bytes()).0, &sig)
            .map_err(|_| "epoch transition: invalid signature".to_string())?;

        info!(new_epoch = msg.epoch, "Processing epoch transition");
        self.current_epoch = derived;
        Ok(())
    }

    /// Drain the signed epoch transition stashed by `advance_slot` at
    /// the most recent epoch boundary, if any. `NetworkNode::tick`
    /// calls this after advancing the slot and broadcasts the result.
    pub fn take_pending_epoch_transition(&mut self) -> Option<EpochTransitionMsg> {
        self.pending_epoch_transition.take()
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

            // Idempotency guard (double-advance fix). The epoch is a pure
            // function of the absolute slot: `slot / slots_per_epoch`. Only
            // advance it — and emit the peer announcement — if we have not
            // already been advanced to this epoch by an accepted transition
            // from a peer. `accept_epoch_transition` sets `current_epoch` but
            // does NOT rotate the VRF key or apply emission, so those below
            // still run regardless. Without this guard, a lagging node that
            // accepts a peer's N-1 -> N transition and then crosses its own
            // boundary advances a second time (to N+1) and its leader-election
            // seed diverges from the rest of the network.
            let target_epoch = self
                .config
                .decompose_slot(self.current_slot.number)
                .0;
            if self.current_epoch.number < target_epoch {
                let prev_seed = self.current_epoch.seed;
                self.current_epoch = self.current_epoch.next_epoch(last_vrf);

                // Build + sign the epoch transition announcement for
                // peers (audit B.8). Peers re-derive the same seed from
                // (prev_seed, vrf_output) and verify this signature
                // before accepting it — see `accept_epoch_transition`.
                // `NetworkNode::tick` drains + broadcasts the result.
                let mut transition = EpochTransitionMsg {
                    epoch: self.current_epoch.number,
                    prev_seed,
                    vrf_output: last_vrf.to_vec(),
                    seed: self.current_epoch.seed,
                    signer: self.verifying_key.to_bytes(),
                    signature: Vec::new(),
                };
                match self
                    .signing_key
                    .sign(&sha3_256(&transition.canonical_bytes()).0)
                {
                    Ok(sig) => transition.signature = sig.to_bytes().to_vec(),
                    Err(e) => tracing::error!(
                        "epoch transition signing failed: {} — broadcasting unsigned (peers will reject)",
                        e
                    ),
                }
                self.pending_epoch_transition = Some(transition);
            }

            // Rotate VRF key for new epoch (forward secrecy + LB-VRF few-time support)
            let new_vrf_pk = self.vrf_manager.rotate_to_epoch(self.current_epoch.number);
            // Public key only — the secret stays local (eval in
            // `advance_slot` reads it from the manager directly).
            self.validator.vrf_public_key = self.vrf_manager.public_key().to_vec();
            // The epoch emission (mint to validator + treasury) lives in
            // `apply_block_transition`, so the producer and every replayer mint
            // the same amount on the same block (the F3 emission leg). Only the
            // VRF key rotation stays here — that is protocol state, not balance
            // state, so it is node-local and does not affect the state root.
            debug!(
                epoch = self.current_epoch.number,
                vrf_pk_prefix = %hex::encode(&new_vrf_pk[..8.min(new_vrf_pk.len())]),
                "New epoch started, VRF key rotated (emission applied on-block)"
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

        // Run VRF election. Local eval uses this node's own VRF secret
        // (from the manager, current epoch); the gossiped
        // `validator.vrf_public_key` is the public key peers verify
        // with — the two must not be mixed.
        let election_result = election::run_election(
            &self.validator,
            &self.current_slot,
            &self.current_epoch,
            &self.validator_set,
            &self.config,
            self.vrf_manager.secret_key(),
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

        // Pre-block committed state root, captured BEFORE the on-block
        // transition mutates the committed stores (used as the ZK transition's
        // `pre_state_root`).
        let pre_state = self.state_root;

        // Block timestamp, captured once and shared by the on-block transition
        // (storage-lease grant/prune, audit F3), the DEX match, and the header.
        // Computed before the transition because the lease step now runs inside
        // it and needs the grant timestamp.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Apply the block's on-block transition — SQL writes, native transfers,
        // fee burn, per-byte storage burn, the epoch emission, and the storage
        // lease grant/prune — to the committed pre-state. This is the F3 fix:
        // the state root is now a pure function of (committed pre-state,
        // block), applied identically by the producer and every replayer,
        // independent of which node submitted each tx. Previously a non-origin
        // proposer stamped a root its replayers rejected, because its committed
        // store had not applied the gossiped txs.
        let proposer_bytes = self.verifying_key.to_bytes();
        if let Err(te) = self.apply_block_transition(&txs, height, timestamp, &proposer_bytes) {
            // A single bad tx must not destroy the whole pool (audit F1, second
            // pass). The transition is atomic — on error it has already rolled
            // the committed state (SQL, balances, nonces, leases) back to the
            // pre-block snapshot — so re-queuing the transactions that were NOT
            // the offender is safe: they are still valid against the unchanged
            // pre-state and will be picked up by a later block. Only the
            // offending tx is dropped; it fails deterministically on every node
            // and would otherwise stall production by failing the same way in
            // every future slot.
            let bad = te.failed_tx;
            let rescued: Vec<Transaction> = txs
                .into_iter()
                .enumerate()
                .filter(|(i, _)| Some(*i) != bad)
                .map(|(_, tx)| tx)
                .collect();
            tracing::warn!(
                height,
                failed_tx = ?bad,
                rescued = rescued.len(),
                "on-block transition failed; re-queued surviving txs, dropped the offender"
            );
            self.pending_txs = rescued;
            return Err(format!("on-block transition failed: {}", te));
        }

        // Compute combined state root: SHA3(sql_root || balance_root) over the
        // post-transition committed state. Block headers commit to BOTH the SQL
        // tables AND the native SEAL ledger, so a validator that disagrees on
        // any balance produces a different state_root and the disagreement
        // surfaces in consensus.
        //
        // Future work: also fold in `TokenManager::state_root_hash` and the
        // bridge wrapped-balance set when those are owned by the runner (today
        // they live in RpcState).
        let sql_root = self.sql_engine.state_root();
        let balance_root = self.balances.state_root_hash();
        let mut combine = Vec::with_capacity(64);
        combine.extend_from_slice(sql_root.0.as_ref());
        combine.extend_from_slice(balance_root.0.as_ref());
        self.state_root = sha3_256(&combine);

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

        // `txs` here already includes the per-block `DexMatch` (appended just
        // above, after the state root), so this root binds the match — and
        // every other transaction — to the signed header. Verifiers recompute
        // it from the received block and reject any post-sign tampering.
        let tx_root = seal_storage::block_store::transactions_root(&txs);

        let mut header = BlockHeader {
            height,
            parent_hash,
            state_root: self.state_root,
            timestamp,
            proposer: self.verifying_key.to_bytes(),
            vrf_output,
            vrf_proof,
            proposer_signature: Vec::new(),
            tx_root,
        };

        // Sign the canonical (empty-sig) serialization of the header.
        // Verifiers zero `proposer_signature`, re-serialize, and check
        // the signature against `header.proposer`.
        let sign_bytes = bincode::serialize(&header)
            .map_err(|e| format!("failed to serialize block header for signing: {}", e))?;
        let proposer_sig = self
            .signing_key
            .sign(&sign_bytes)
            .map_err(|e| format!("proposer signature failed: {}", e))?;
        header.proposer_signature = proposer_sig.to_bytes().to_vec();

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

        // Self-sign (in multi-node, committee members would sign) —
        // over the same canonical empty-sig header bytes as
        // `proposer_signature`, so both attestations bind identical
        // content.
        let block_hash = sha3_256(&sign_bytes);
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

        // (Storage lease management — registration, size updates, and expiry
        //  pruning — moved into `apply_block_transition` so the producer and
        //  every replayer grant/prune identically; audit F3.)

        // Rebuild the read-your-writes working set from the (now post-block)
        // committed engine: the on-block transition applied the pending SQL to
        // `sql_engine` and `pending_txs` was drained at the top of produce, so a
        // fresh `preview_engine` == committed + (empty pending) is back in sync.
        self.preview_engine = self.sql_engine.engine().clone();

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
        // Read-your-writes: run the query on the working set (committed +
        // pending SQL), so a node sees its own not-yet-blocked writes. The
        // committed engine is untouched — it is only advanced by the on-block
        // transition — keeping the state root a pure function of the block.
        self.preview_engine.execute(sql)
    }

    /// Apply a block's on-block transition to the committed pre-state: the
    /// SQL writes, native transfers, fee burn, and per-byte storage burn a
    /// block commits, as ONE deterministic pure function of
    /// `(committed pre-state, the block's ordered transactions)`.
    ///
    /// Both the block producer and the block replayer call this, so every node
    /// that finalizes a block derives the same post-state and therefore the
    /// same `state_root`. This is the F3 fix: the state root no longer depends
    /// on which node happened to apply a gossiped tx to its own live store.
    ///
    /// `proposer` is the block's `header.proposer` (NOT `self.verifying_key`)
    /// so the producer and every replayer credit the same account's fee share.
    /// `txs` is the pre-DexMatch transaction list: the producer appends its
    /// per-block DEX-matching event to `block.transactions` *after* this
    /// transition, so `DexMatch` (and token/bridge/stake/gov, whose state
    /// lives in `RpcState`) are runner-level no-ops here.
    ///
    /// Does NOT recompute `self.state_root` — callers read
    /// `sql_engine.state_root()` / `balances.state_root_hash()` afterwards, so
    /// producer and replayer compute the identical combined root.
    pub fn apply_block_transition(
        &mut self,
        txs: &[Transaction],
        height: u64,
        timestamp: u64,
        proposer: &[u8],
    ) -> Result<(), TransitionError> {
        // Audit F1: snapshot the committed state this transition mutates and
        // roll back cleanly if any step fails. Without this, a mid-transition
        // error (a malformed SQL write, or an unfunded transfer that passed
        // `accept_transaction`'s signature/nonce check) would leave earlier
        // txs' effects baked into the committed engine with no block produced —
        // a root the producer stamps that no replayer can reach. Cloning is
        // O(n); fine at prototype scale. The returned `TransitionError` also
        // names the offending tx (if any) so the producer can preserve the
        // rest of the pool (audit F1, second pass).
        let (sql_engine, balances, nonces, leases) = (
            self.sql_engine.clone(),
            self.balances.clone(),
            self.nonces.clone(),
            self.leases.clone(),
        );
        let result = self.apply_block_transition_impl(txs, height, timestamp, proposer);
        if result.is_err() {
            self.sql_engine = sql_engine;
            self.balances = balances;
            self.nonces = nonces;
            self.leases = leases;
        }
        result
    }

    /// The on-block transition itself. [`apply_block_transition`] is the public
    /// entry point that wraps this in a snapshot/rollback so a failing block
    /// leaves the committed state untouched (audit F1).
    ///
    /// `timestamp` is the block header's timestamp (seconds since epoch),
    /// shared by the producer and every replayer from the block, and drives the
    /// deterministic storage-lease grant/prune (audit F3).
    fn apply_block_transition_impl(
        &mut self,
        txs: &[Transaction],
        height: u64,
        timestamp: u64,
        proposer: &[u8],
    ) -> Result<(), TransitionError> {
        // 1. Deterministic block seed so Merkle salts match the producer.
        self.sql_engine
            .set_block_seed(height.to_le_bytes().to_vec());

        // 2. Re-execute SQL writes and re-apply native transfers, in order. The
        //    loop is indexed so a failure reports WHICH tx tripped it — the
        //    producer drops that tx and keeps the rest of the pool (audit F1,
        //    second pass) instead of losing every pending transaction.
        for (i, tx) in txs.iter().enumerate() {
            match tx.tx_type {
                TxType::SqlExec | TxType::CreateApp | TxType::AlterSchema => {
                    let sql = std::str::from_utf8(&tx.payload)
                        .map_err(|e| TransitionError::at(i, format!("invalid UTF-8 in SQL tx: {}", e)))?;
                    self.sql_engine
                        .execute(sql)
                        .map_err(|e| TransitionError::at(i, format!("SQL apply failed: {}", e)))?;
                }
                TxType::Transfer => {
                    let (nonce, body) = decode_money_tx(&tx.payload)
                        .map_err(|e| TransitionError::at(i, format!("Transfer apply: {}", e)))?;
                    self.balances
                        .transfer(&body.from, &body.to, body.amount)
                        .map_err(|e| TransitionError::at(i, format!("Transfer apply failed: {}", e)))?;
                    // Rebuild the per-sender nonce counter (idempotent; keyed
                    // by `tx.sender` exactly as accept_transaction /
                    // submit_money_tx do) so a restarted replayer continues
                    // from the last on-chain nonce.
                    let expected = nonce
                        .checked_add(1)
                        .ok_or_else(|| {
                            TransitionError::at(i, "Transfer apply: nonce counter overflow".to_string())
                        })?;
                    let current = self.nonces.get(&tx.sender).copied().unwrap_or(0);
                    if expected > current {
                        self.nonces.insert(tx.sender.clone(), expected);
                    }
                }
                // DexMatch (appended by the producer after this transition) and
                // token/bridge/stake/gov (state in RpcState) are no-ops, so the
                // state-root computation stays stable.
                _ => {}
            }
        }

        // 3. Fees: burn the per-byte fee from each sender and credit the block
        //    proposer the non-burned share. A pure function of
        //    (txs, fee_config, proposer), applied identically by the producer
        //    and every replayer. Fee errors (unfunded senders) are ignored,
        //    matching the producing path.
        let proposer_addr = hex::encode(&proposer[..16.min(proposer.len())]);
        let fee_txs: Vec<(String, usize)> = txs
            .iter()
            // DexMatch is consensus-emitted by the proposer (not a user tx), so
            // it is never fee-charged — matching the producing path, which
            // appends it to the block AFTER this transition runs.
            .filter(|tx| !matches!(tx.tx_type, TxType::DexMatch))
            .map(|tx| {
                let sender = hex::encode(&tx.sender[..16.min(tx.sender.len())]);
                (sender, tx.payload.len())
            })
            .collect();
        let _ = crate::fees::process_block_fees(
            &mut self.balances,
            &self.fee_config,
            &fee_txs,
            &proposer_addr,
        );

        // 4. Storage burn: per-byte for SQL writes, charged to the sender.
        for tx in txs {
            if matches!(
                tx.tx_type,
                TxType::SqlExec | TxType::CreateApp | TxType::AlterSchema
            ) {
                let sender_addr = hex::encode(&tx.sender[..16.min(tx.sender.len())]);
                // 1 micro-SEAL per byte of written payload.
                let storage_cost = (tx.payload.len() as u64).saturating_mul(1);
                if storage_cost > 0 {
                    let _ = self.balances.burn(&sender_addr, storage_cost);
                }
            }
        }

        // 5. Deterministic epoch emission: mint the epoch's full reward to the
        //    validator + treasury accounts when this block closes its epoch.
        //    A pure function of (height, slots_per_epoch, the emission
        //    schedule), applied identically by the producer and every replayer.
        //    This is where the per-epoch mint moved from `advance_slot`, so a
        //    replayer's ledger agrees with the proposer's (the F3 emission leg).
        //    Height `H` closes epoch `H / slots_per_epoch` exactly when
        //    `H % slots_per_epoch == 0` (the first such height, 1, is genesis
        //    epoch 0, which mints nothing — matching the old `slot.number > 0`).
        let slots_per_epoch = self.config.slots_per_epoch.max(1);
        if height > 0 && height % slots_per_epoch == 0 {
            let emission = seal_token::EmissionSchedule::default();
            let epoch = height / slots_per_epoch;
            // Mint the schedule's per-epoch emission — the annual rate divided
            // by EPOCHS_PER_YEAR — which is independent of the epoch's slot
            // count (audit F8). The old code minted `block_reward ×
            // slots_per_epoch`, but block_reward is calibrated for a
            // BLOCKS_PER_EPOCH=128-block epoch, so with the shipped 256-slot
            // epoch (SPEC §consensus) that emitted exactly 2× the intended
            // annual rate. `epoch_reward` matches the schedule's own
            // total_emitted, so producer and replayer stay in sync.
            let epoch_reward = emission.epoch_reward(epoch);
            let treasury_share = epoch_reward / 10; // 10% to treasury
            let validator_share = epoch_reward.saturating_sub(treasury_share);
            let _ = self.balances.mint("seal1validators", validator_share);
            let _ = self.balances.mint("seal1treasury", treasury_share);
        }

        // 6. Storage lease management (#STORAGE-FORGET), now part of the shared
        //    transition so the producer and every replayer grant and prune
        //    identically (audit F3). Previously this ran producer-only, *after*
        //    the state root was stamped, so a producer could prune a table its
        //    replayers kept — a fork. It is keyed on the block's `timestamp`
        //    (not node-local time) so the grant/prune is a pure function of the
        //    block, and the lease owner is the block's `proposer` (deterministic
        //    across nodes), not `self.verifying_key` (which would differ per
        //    node). `paid_through` is stored in microseconds per the
        //    `StorageLease` contract; the initial grant is 4 hours out.
        if let Some(log) = self.sql_engine.last_write_log() {
            if log.schema_changed {
                let table = &log.table;
                if self.leases.get(table).is_none() {
                    let byte_size = self.sql_engine.table_byte_size(table).unwrap_or(0);
                    let mut lease = seal_token::StorageLease::new(
                        table.clone(),
                        proposer.to_vec(),
                        1, // default rate (governance-adjustable)
                    );
                    lease.paid_through = timestamp
                        .saturating_mul(1_000_000)
                        .saturating_add(4 * 3600 * 1_000_000); // +4h, in microseconds
                    lease.update_size(
                        self.sql_engine.row_count(table).unwrap_or(0) as u64,
                        byte_size,
                    );
                    self.leases.register(lease);
                }
            }
        }

        for table_name in self.sql_engine.table_names() {
            if let Some(lease) = self.leases.get_mut(table_name) {
                let byte_size = self.sql_engine.table_byte_size(table_name).unwrap_or(0);
                let row_count = self.sql_engine.row_count(table_name).unwrap_or(0) as u64;
                lease.update_size(row_count, byte_size);
            }
        }

        let now_us = timestamp.saturating_mul(1_000_000);
        let expired = self.leases.tables_to_prune(now_us);
        for table_name in &expired {
            tracing::info!(table = %table_name, "Pruning expired table (lease expired)");
            let _ = self.sql_engine.drop_table(table_name);
            self.leases.remove(table_name);
        }

        Ok(())
    }

    /// Replay a block's transactions to reconstruct state.
    /// Used when a new node joins and replays the chain from genesis.
    /// Returns the resulting state root.
    ///
    /// **Low-level primitive — does NOT verify the header root.** This method
    /// reconstructs the post-block state and APPENDS the block to
    /// [`ConsensusRunner::chain`] WITHOUT comparing the recomputed root against
    /// `block.header.state_root`. Production code that commits an
    /// externally-supplied block MUST use [`Self::apply_block_verified`]
    /// instead, which snapshots, replays, and only commits on a root match
    /// (rolling back on mismatch) — see audit F2 (second pass), where the
    /// restart/disk-replay paths silently committed root-mismatched blocks
    /// because they called this directly. It is kept unchecked so tests can
    /// inspect intermediate state (e.g. balance-root equality) against
    /// hand-built blocks.
    ///
    /// **F3 (fixed):** replay now runs the same `apply_block_transition` the
    /// producer runs, so fees, per-byte storage burn, native transfers, and the
    /// epoch emission are all applied on replay. The replayer reaches the
    /// identical `state_root` the proposer published, so the old
    /// produce-only fee/storage/emission drift is gone. (Token/bridge/stake
    /// movement still lives in `RpcState` and is a runner-level no-op here —
    /// a documented follow-up.)
    pub fn replay_block(&mut self, block: &Block) -> Result<Hash256, String> {
        // Apply the SAME on-block transition the producer runs, keyed on the
        // block's header (height for the seed/emission, proposer for the fee
        // credit). This is the F3 fix: the replayer now applies fees, storage
        // burn, and the epoch emission too (previously replay re-ran none of
        // them, so the replayer's ledger diverged from the proposer's). The
        // transition is a pure function of (committed pre-state, block), so the
        // replayer reaches the identical state_root the proposer published.
        //
        // `block.transactions` includes the proposer's consensus-emitted
        // DexMatch tx; the transition no-ops it (SQL/transfer arms), skips it in
        // the fee loop, and it is not a SQL type, so the storage burn skips it —
        // exactly matching the producer, which appends DexMatch after its
        // transition runs over the pre-DexMatch list.
        self.apply_block_transition(
            &block.transactions,
            block.header.height,
            block.header.timestamp,
            &block.header.proposer,
        )
        .map_err(|e| format!("replay transition failed: {}", e))?;

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

        // Rebuild the read-your-writes working set from the (now post-block)
        // committed engine — replay just applied the block's SQL to `sql_engine`
        // and the replayer has no pending pool of its own, so the fresh working
        // set is exactly the committed state.
        self.preview_engine = self.sql_engine.engine().clone();

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

    /// Snapshot every committed field a block replay can change, so a node can
    /// verify a replayed block's root *before* committing it (audit F2) and
    /// roll back cleanly if it does not match. `chain_len` is captured (not the
    /// whole chain) so rollback truncates the one block a replay appended in
    /// O(1) instead of cloning every finalized block.
    fn snapshot_committed(&self) -> CommittedSnapshot {
        CommittedSnapshot {
            sql_engine: self.sql_engine.clone(),
            balances: self.balances.clone(),
            nonces: self.nonces.clone(),
            leases: self.leases.clone(),
            state_root: self.state_root,
            preview_engine: self.preview_engine.clone(),
            chain_len: self.chain.len(),
        }
    }

    /// Restore a [`CommittedSnapshot`], rolling back a replay that failed its
    /// root check (audit F2). The chain is truncated back to the snapshot's
    /// length, undoing the block the failed replay appended, so a rejected
    /// block leaves the node exactly where it was.
    fn restore_committed(&mut self, snap: CommittedSnapshot) {
        self.sql_engine = snap.sql_engine;
        self.balances = snap.balances;
        self.nonces = snap.nonces;
        self.leases = snap.leases;
        self.state_root = snap.state_root;
        self.preview_engine = snap.preview_engine;
        self.chain.truncate(snap.chain_len);
    }

    /// Remove a block's transactions from the pending pool (audit F5). A
    /// gossiped tx is enqueued by `accept_transaction` on every node that
    /// receives it; once that tx lands in a finalized block, the copies in each
    /// node's pool must be dropped, or the next block re-includes them and the
    /// transition re-applies them (it rebuilds but never *checks* the nonce),
    /// double-debiting a transfer. Matched on the transaction's full
    /// (type, sender, payload) — the same bytes that were gossiped and then
    /// finalized.
    pub fn prune_applied_txs(&mut self, block: &Block) {
        self.pending_txs.retain(|p| {
            !block.transactions.iter().any(|b| {
                b.tx_type == p.tx_type
                    && b.sender == p.sender
                    && b.payload == p.payload
            })
        });
    }

    /// Replay a received block and commit it only if its replayed state root
    /// matches the header (audit F2), then drop the finalized txs from the
    /// pending pool (audit F5). This is the verify-before-commit wrapper the
    /// network path uses: [`replay_block`] runs the transition (mutating the
    /// committed state) and appends the block, and *only then* is the root
    /// compared. Because the header signature covers the header only (no tx
    /// root), a peer can forward a validly-signed block with injected or removed
    /// transactions — every header check passes, the replay applies the forged
    /// txs, and the mismatch is seen only after the block is committed. Snapshot
    /// first and roll back on any failure so a rejected block leaves the node
    /// exactly where it was (no advanced height, no mutated ledger).
    pub fn apply_block_verified(&mut self, block: &Block) -> Result<Hash256, String> {
        let snapshot = self.snapshot_committed();
        let replayed_root = match self.replay_block(block) {
            Ok(root) => root,
            Err(e) => {
                self.restore_committed(snapshot);
                return Err(e);
            }
        };
        if replayed_root != block.header.state_root {
            self.restore_committed(snapshot);
            return Err(format!(
                "state root mismatch after replay: expected {}, got {}",
                block.header.state_root, replayed_root
            ));
        }
        self.prune_applied_txs(block);
        Ok(replayed_root)
    }
}

/// Snapshot of the committed state a block replay can change (see
/// [`ConsensusRunner::snapshot_committed`]). Used to verify a replayed block's
/// root before committing it and roll back on mismatch (audit F2).
#[derive(Clone)]
struct CommittedSnapshot {
    sql_engine: MerkleEngine,
    balances: seal_token::balance::BalanceStore,
    nonces: HashMap<Vec<u8>, u64>,
    leases: seal_token::LeaseManager,
    state_root: Hash256,
    preview_engine: Engine,
    chain_len: usize,
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

    /// Regression (2026-09-27 inspection): `validator.vrf_public_key`
    /// must hold the REAL VRF public key, not the secret — it is
    /// gossiped to peers and served over RPC (`vrf_public_key_hex`).
    /// Proven by verifying a local eval output against it: if the
    /// field held the secret, the public-key `verify` would fail.
    #[test]
    fn test_vrf_public_key_is_verifiable_public_key() {
        use seal_vrf::pq_vrf::PqVrf;
        use seal_vrf::traits::Vrf;

        let runner = ConsensusRunner::new(ConsensusConfig::default());
        let vrf_input = runner.current_slot.vrf_input(&runner.current_epoch.seed);
        let (output, proof) = PqVrf::eval(runner.vrf_manager.secret_key(), &vrf_input)
            .expect("local eval with the manager's secret");
        assert!(
            PqVrf::verify(&runner.validator.vrf_public_key, &vrf_input, &output, &proof)
                .is_ok(),
            "validator.vrf_public_key must verify local eval output (peers verify with it)"
        );
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

    /// F8 — CONFIRMED BUG, now fixed (this test fails on the pre-fix code). The
    /// emission leg used to mint `block_reward × slots_per_epoch` per epoch,
    /// but `block_reward` is calibrated for a `BLOCKS_PER_EPOCH = 128`-block
    /// epoch. With the shipped 256-slot epoch (SPEC §consensus) that emitted
    /// exactly 2× the schedule's intended annual rate. The per-epoch emission
    /// is an ANNUAL rate applied per epoch =
    /// `initial_supply × rate_bp / (10_000 × EPOCHS_PER_YEAR)`, independent of
    /// the epoch's slot count. This drives the real transition to an epoch
    /// boundary and asserts the minted total equals that figure for several
    /// slot counts — the old code scaled with `slots_per_epoch`, so it was
    /// wrong for every epoch length other than `BLOCKS_PER_EPOCH`.
    #[test]
    fn test_emission_per_epoch_matches_schedule_annual_rate() {
        let schedule = seal_token::EmissionSchedule::default();
        // The first epoch boundary is height == slots; the epoch index there is 1.
        let expected = schedule.epoch_reward(1);

        // The per-epoch mint must be the SAME for every slot count.
        for slots in [4u64, 8, 128, 256] {
            let mut config = ConsensusConfig::default();
            config.slots_per_epoch = slots;
            let mut runner = ConsensusRunner::new(config);
            let before = runner.balances.total_supply();
            runner
                .apply_block_transition(&[], slots, 0, &[0u8; 32])
                .expect("empty-block transition must not fail");
            let minted = runner.balances.total_supply() - before;
            assert_eq!(
                minted, expected,
                "per-epoch emission must not depend on slots_per_epoch (slots={slots})"
            );
        }

        // Frequency check: a non-epoch-boundary height mints nothing.
        let mut config2 = ConsensusConfig::default();
        config2.slots_per_epoch = 4;
        let mut runner2 = ConsensusRunner::new(config2);
        let before2 = runner2.balances.total_supply();
        runner2
            .apply_block_transition(&[], 3, 0, &[0u8; 32])
            .expect("ok");
        assert_eq!(
            runner2.balances.total_supply() - before2,
            0,
            "no emission on a non-epoch-boundary height"
        );
    }

    /// M1 — dedup behavior, pinned here. `prune_applied_txs` matches a pool tx
    /// against the block on (type, sender, payload) — deliberately NOT the
    /// signature (a randomized ML-DSA sig can't be a stable key; omitting it is
    /// what lets a re-gossiped copy — same payload, new sig — still dedup).
    /// For MONEY txs this is correct: the nonce is in the payload, so two
    /// distinct transfers from the same sender never share (type, sender,
    /// payload). For SQL txs the payload is bare text, so a byte-identical
    /// resubmission of the SAME statement (a client retry, or an idempotent
    /// write) correctly dedups. Residual limitation (reviewer-confirmed, LOW):
    /// two *independent* byte-identical NON-idempotent SQL writes from the same
    /// sender would be over-pruned once one finalizes — rare, and fully closing
    /// it needs a per-SQL-tx nonce / client idempotency key (deferred). This
    /// pins the money-tx behavior: a finalized transfer is pruned, its
    /// byte-identical duplicate is pruned with it, and a distinct
    /// (different-nonce) transfer from the same sender is kept.
    #[test]
    fn test_prune_applied_txs_removes_finalized_keeps_distinct() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        let (sk, vk) = SigningKey::generate();
        let t0 = money_transfer_tx(&sk, &vk, 0, "seal1a", "seal1b", 5);
        let t0_dup = t0.clone();
        let t1 = money_transfer_tx(&sk, &vk, 1, "seal1a", "seal1b", 7); // distinct: nonce 1
        runner.pending_txs.push(t0.clone());
        runner.pending_txs.push(t0_dup);
        runner.pending_txs.push(t1.clone());

        // The block finalizes only the nonce-0 transfer.
        let block = Block {
            header: BlockHeader {
                height: 1,
                parent_hash: Hash256::ZERO,
                state_root: Hash256::ZERO,
                timestamp: 0,
                proposer: vec![],
                vrf_output: vec![],
                vrf_proof: vec![],
                proposer_signature: vec![],
                tx_root: Hash256::ZERO,
            },
            transactions: vec![t0.clone()],
        };

        runner.prune_applied_txs(&block);

        assert_eq!(
            runner.pending_txs.len(),
            1,
            "only the distinct (nonce-1) transfer survives the prune"
        );
        assert_eq!(runner.pending_txs[0].payload, t1.payload);
    }

    #[test]
    fn test_block_has_zk_proof() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        // Use the canonical money encoding so the produced block stays
        // replayable (replay_block decodes Transfer payloads).
        runner
            .submit_money_tx(TxType::Transfer, "seal1alice", "seal1bob", 1)
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
            .submit_money_tx(TxType::Transfer, "seal1alice", "seal1bob", 1)
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
            .vote_with_conviction(id, "alice".into(), VoteChoice::Yes, 800, Conviction::X1, None)
            .unwrap();
        runner
            .governance
            .vote_with_conviction(id, "bob".into(), VoteChoice::No, 100, Conviction::X1, None)
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
            .vote_with_conviction(id, "alice".into(), VoteChoice::Yes, 500, Conviction::X1, None)
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

    /// F3 — the epoch-emission leg of the shared on-block transition. When a
    /// block closes its epoch, the deterministic emission is minted to the
    /// validator + treasury accounts. Pre-fix this mint lived in `advance_slot`
    /// (produce-only, node-local timing), so a replayer's ledger diverged from
    /// the proposer's. Post-fix both the producer and every replayer run the
    /// same `apply_block_transition`, so the mint — and the resulting state
    /// root — is identical.
    ///
    /// Validated here at the runner level (produce vs replay) with a 1-slot
    /// epoch so the emission fires on the very first block. Cross-node
    /// agreement is proven by the `NetworkNode` F3 tests, which drive the same
    /// transition over the network path.
    #[test]
    fn test_f3_emission_applied_identically_on_produce_and_replay() {
        let config = ConsensusConfig {
            slots_per_epoch: 1,
            ..ConsensusConfig::default()
        };
        let mut producer = ConsensusRunner::new(config.clone());
        let mut replayer = ConsensusRunner::new(config);

        // Produce the first block (height 1), which closes epoch 0 and mints
        // the epoch's emission. Empty VRF fields: the producer stores them in
        // the header and `replay_block` does not re-verify them, so this
        // bypasses the election without touching the on-block transition.
        let fb = producer
            .produce_block_with_vrf(Vec::new(), Vec::new())
            .expect("produce the epoch-closing block");
        let replayed_root = replayer
            .replay_block(&fb.block)
            .expect("replay the epoch-closing block");

        // THE F3 emission assertion: the replayer reproduces the producer's
        // state root (which now folds in the emission).
        assert_eq!(
            replayed_root,
            *producer.state_root(),
            "emission must not fork producer and replayer state roots (F3)"
        );

        // The emission was minted, identically, on both nodes.
        assert!(
            producer.balances.available("seal1validators") > 0,
            "epoch emission should mint to the validator account"
        );
        assert!(
            producer.balances.available("seal1treasury") > 0,
            "epoch emission should mint to the treasury account"
        );
        assert_eq!(
            producer.balances.available("seal1validators"),
            replayer.balances.available("seal1validators"),
            "validator emission must match on producer and replayer"
        );
        assert_eq!(
            producer.balances.available("seal1treasury"),
            replayer.balances.available("seal1treasury"),
            "treasury emission must match on producer and replayer"
        );
        // The replayer minted the same new supply as the producer.
        assert_eq!(
            producer.balances.total_supply(),
            replayer.balances.total_supply(),
            "total supply (emission mint) must match on producer and replayer"
        );
    }

    /// Audit F1 — a failing on-block transition rolls the committed state back
    /// to its pre-transition snapshot instead of baking in the txs that
    /// succeeded before the abort. The producer drains its pending pool *before*
    /// running the transition; without the snapshot/rollback, one bad tx
    /// (malformed SQL, or a transfer from an account that turned out to be
    /// insolvent) would leave the earlier txs' effects in the committed engine
    /// with no block produced — a state root the producer stamps that no
    /// replayer can reach.
    #[test]
    fn test_f1_failing_transition_rolls_back_committed_state() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        let root_before = *runner.state_root();

        // A good write (creates a table) followed by an aborting write (`INSERT`
        // into a table that does not exist). The good write mutates the engine
        // first; the bad one must trigger a full rollback.
        let sender = vec![1u8; 32];
        let txs = vec![
            Transaction {
                tx_type: TxType::SqlExec,
                payload: b"CREATE TABLE f1t (id BIGINT PRIMARY KEY)".to_vec(),
                sender: sender.clone(),
                signature: vec![],
            },
            Transaction {
                tx_type: TxType::SqlExec,
                payload: b"INSERT INTO missing (id) VALUES (1)".to_vec(),
                sender,
                signature: vec![],
            },
        ];

        let result = runner.apply_block_transition(&txs, 1, 1_000_000, &[1u8; 32]);
        assert!(
            result.is_err(),
            "the aborting write must fail the transition"
        );

        // THE F1 assertion: the good write's table was rolled back — it is not in
        // the committed engine, and the committed root is unchanged.
        assert_eq!(
            *runner.state_root(),
            root_before,
            "a failed transition must leave the committed state root unchanged (F1)"
        );
        let tables: Vec<String> = runner
            .sql_engine
            .table_names()
            .into_iter()
            .map(|t| t.to_string())
            .collect();
        assert!(
            !tables.iter().any(|t| t == "f1t"),
            "the good write's table must be rolled back after a failed transition (F1): {tables:?}"
        );
    }

    /// Audit F2 — a block whose replayed state root does not match the header is
    /// rejected *before* it is committed: the node's height, ledger, and chain
    /// are all restored to their pre-replay state. This closes the path where a
    /// peer forwards a validly-signed block with injected or removed
    /// transactions (the header signature covers the header only, not the txs):
    /// pre-fix the replay mutated the ledger and appended the block, and the
    /// mismatch was seen only afterwards and swallowed at debug level, leaving
    /// the node on a state no other node has.
    #[test]
    fn test_f2_rejected_block_rolls_back_node_state() {
        let mut producer = ConsensusRunner::new(ConsensusConfig::default());
        let mut replayer = ConsensusRunner::new(ConsensusConfig::default());

        // A write that mutates state, so "unchanged" is observable.
        producer
            .submit_transaction(
                TxType::SqlExec,
                b"CREATE TABLE f2t (id BIGINT PRIMARY KEY)".to_vec(),
            )
            .unwrap();
        let mut fb = None;
        for _ in 0..100 {
            if let Some(b) = producer.advance_slot() {
                fb = Some(b);
                break;
            }
        }
        let fb = fb.expect("produce a block with the write");

        // Tamper with the stamped root (flip a byte) so the replayer's honest
        // replay no longer matches the header.
        let mut forged = fb.block.clone();
        let mut root_arr = forged.header.state_root.0;
        root_arr[0] ^= 0xff;
        forged.header.state_root = Hash256(root_arr);

        let root_before = *replayer.state_root();
        let chain_len_before = replayer.chain.len();

        let result = replayer.apply_block_verified(&forged);
        assert!(
            result.is_err(),
            "a block whose root does not match must be rejected (F2)"
        );

        // THE F2 assertion: the rejected block left the replayer exactly where
        // it was — root, chain length, and ledger all unchanged.
        assert_eq!(
            *replayer.state_root(),
            root_before,
            "a rejected block must not change the node's state root (F2)"
        );
        assert_eq!(
            replayer.chain.len(),
            chain_len_before,
            "a rejected block must not advance the node's chain (F2)"
        );
        let tables: Vec<String> = replayer
            .sql_engine
            .table_names()
            .into_iter()
            .map(|t| t.to_string())
            .collect();
        assert!(
            !tables.iter().any(|t| t == "f2t"),
            "a rejected block's write must not land in the committed engine (F2): {tables:?}"
        );
    }

    /// Audit F5 — a tx that lands in a finalized block is pruned from the node's
    /// pending pool, so it is not re-included (and re-applied) in the next block.
    /// `accept_transaction` enqueues every gossiped tx on every node; once that tx
    /// lands in a block, the copies in each node's pool must be dropped, or the
    /// next block re-includes them and the transition re-applies them (it rebuilds
    /// the nonce counter but never *checks* it) — double-debiting a transfer.
    #[test]
    fn test_f5_applied_tx_pruned_from_pending_pool() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());

        // Produce a block containing one write (drains the pool).
        runner
            .submit_transaction(
                TxType::SqlExec,
                b"CREATE TABLE f5t (id BIGINT PRIMARY KEY)".to_vec(),
            )
            .unwrap();
        let mut fb = None;
        for _ in 0..100 {
            if let Some(b) = runner.advance_slot() {
                fb = Some(b);
                break;
            }
        }
        let fb = fb.expect("produce a block with the first write");

        // Re-enqueue a copy of the finalized tx (as a gossiped duplicate would
        // sit in the pool) plus a distinct, not-yet-finalized tx.
        let finalized = fb.block.transactions[0].clone();
        runner
            .submit_transaction(TxType::SqlExec, finalized.payload.clone())
            .unwrap();
        runner
            .submit_transaction(
                TxType::SqlExec,
                b"CREATE TABLE f5t2 (id BIGINT PRIMARY KEY)".to_vec(),
            )
            .unwrap();
        assert_eq!(runner.pending_tx_count(), 2);

        runner.prune_applied_txs(&fb.block);

        // Only the duplicate of the finalized tx is pruned; the distinct one
        // stays in the pool for a future block.
        assert_eq!(
            runner.pending_tx_count(),
            1,
            "the finalized tx's duplicate must be pruned (F5)"
        );
        assert_eq!(
            runner.pending_txs[0].payload,
            b"CREATE TABLE f5t2 (id BIGINT PRIMARY KEY)".to_vec(),
            "the non-finalized tx must remain in the pool (F5)"
        );
    }

    /// Audit F1 (second pass) — a failing on-block transition must NOT destroy
    /// the producer's whole pending pool. `produce_block_with_vrf` drains the
    /// pool into a local before running the transition; pre-fix, a mid-transition
    /// error simply dropped that local, so one bad tx (a correctly-signed SQL
    /// write that fails against the committed state) wiped every other pending
    /// transaction with it — sustained gossip of such tx is network-wide
    /// censorship at zero cost to the attacker. Now the surviving
    /// (non-offending) txs are re-queued for a later block and only the offender
    /// is dropped (it fails deterministically on every node and would stall
    /// production by failing the same way in every future slot).
    #[test]
    fn test_f1_second_pass_pool_preserved_on_failed_transition() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        let root_before = *runner.state_root();

        // A good write followed by an aborting one. Both are pushed via
        // `submit_transaction` (sign + enqueue, no preview) so the aborting
        // write reaches the pool — mirroring a gossiped tx that slips past an
        // older node's accept-time preview.
        runner
            .submit_transaction(
                TxType::SqlExec,
                b"CREATE TABLE f1p (id BIGINT PRIMARY KEY)".to_vec(),
            )
            .unwrap();
        runner
            .submit_transaction(
                TxType::SqlExec,
                b"INSERT INTO missing (id) VALUES (1)".to_vec(),
            )
            .unwrap();
        assert_eq!(runner.pending_tx_count(), 2);

        // First slot: the aborting write (index 1) fails the transition. The
        // good write (index 0) must be preserved; the offender dropped.
        let first = runner.produce_block_with_vrf(Vec::new(), Vec::new());
        assert!(
            first.is_err(),
            "the aborting write must fail block production"
        );
        assert_eq!(
            runner.pending_tx_count(),
            1,
            "the good tx must be re-queued after a failed transition (F1 second pass)"
        );
        assert_eq!(
            runner.pending_txs[0].payload,
            b"CREATE TABLE f1p (id BIGINT PRIMARY KEY)".to_vec(),
            "the surviving tx must be the good write, not the offender"
        );
        // The rollback left the committed state untouched.
        assert_eq!(
            *runner.state_root(),
            root_before,
            "a failed transition must not change the committed state root (F1)"
        );

        // Next slot: the pool is now just the good write, so it lands in a block
        // and the (gone) offender no longer poisons production.
        let second = runner.produce_block_with_vrf(Vec::new(), Vec::new());
        assert!(
            second.is_ok(),
            "the surviving good tx must be produced on the next slot"
        );
        let block = second.unwrap().block;
        assert!(
            block
                .transactions
                .iter()
                .any(|t| t.payload == b"CREATE TABLE f1p (id BIGINT PRIMARY KEY)".to_vec()),
            "the block must contain the re-queued good write"
        );
        assert!(
            !block
                .transactions
                .iter()
                .any(|t| t.payload == b"INSERT INTO missing (id) VALUES (1)".to_vec()),
            "the dropped offender must not appear in the block"
        );
    }

    /// Audit F2 (second pass) — the restart/disk-replay path verifies each
    /// block's root before committing it. A stored block whose replayed state
    /// root differs from its header (disk corruption or an adversarial edit)
    /// stops the replay and leaves the node at the last consistent height — NOT
    /// on a state that mixes a higher balance snapshot with a lower SQL state
    /// (the pre-fix self-fork: the next produced block would stamp
    /// `sha3(sql_root ‖ balance_root)` over two different heights, un-reproducible
    /// by any peer). This mirrors main.rs's replay loop, which now calls
    /// `apply_block_verified` per block instead of the unchecked `replay_block`.
    #[test]
    fn test_f2_second_pass_restart_replay_stops_on_corrupt_block() {
        // Build a legit 2-block chain on a producer.
        let mut producer = ConsensusRunner::new(ConsensusConfig::default());
        producer
            .submit_transaction(
                TxType::SqlExec,
                b"CREATE TABLE c1 (id BIGINT PRIMARY KEY)".to_vec(),
            )
            .unwrap();
        let mut b1 = None;
        for _ in 0..100 {
            if let Some(b) = producer.advance_slot() {
                b1 = Some(b);
                break;
            }
        }
        let b1 = b1.expect("produce block 1");
        producer
            .submit_transaction(
                TxType::SqlExec,
                b"CREATE TABLE c2 (id BIGINT PRIMARY KEY)".to_vec(),
            )
            .unwrap();
        let mut b2 = None;
        for _ in 0..100 {
            if let Some(b) = producer.advance_slot() {
                b2 = Some(b);
                break;
            }
        }
        let b2 = b2.expect("produce block 2");

        // Corrupt block 2's stamped root (flip a byte) so its honest replay no
        // longer matches the header.
        let mut bad_b2 = b2.block.clone();
        let mut root_arr = bad_b2.header.state_root.0;
        root_arr[0] ^= 0xff;
        bad_b2.header.state_root = Hash256(root_arr);

        // Replay the way main.rs's restart loop does: verify-before-commit per
        // block, stopping at the first failure.
        let mut node = ConsensusRunner::new(ConsensusConfig::default());
        let mut replayed = 0u64;
        let mut complete = true;
        for block in [&b1.block, &bad_b2] {
            if node.apply_block_verified(block).is_err() {
                complete = false;
                break;
            }
            replayed += 1;
        }

        assert!(!complete, "the corrupted block must stop the restart replay");
        assert_eq!(replayed, 1, "only the first (valid) block should replay");
        assert_eq!(
            node.height(),
            1,
            "the node must sit at the last consistent height, not past the corruption"
        );

        // Self-consistent: the node is exactly at block 1's verified root and did
        // NOT commit the corrupted block 2's state.
        assert_eq!(
            *node.state_root(),
            b1.block.header.state_root,
            "the node must sit exactly at the last verified block's root (F2 second pass)"
        );
        let tables: Vec<String> = node
            .sql_engine
            .table_names()
            .into_iter()
            .map(|t| t.to_string())
            .collect();
        assert!(
            tables.contains(&"c1".to_string()),
            "block 1's table must be present: {tables:?}"
        );
        assert!(
            !tables.contains(&"c2".to_string()),
            "the corrupted block 2's table must NOT be committed: {tables:?}"
        );
    }

    // --- Epoch transition signing (audit B.8) -------------------------

    /// Build a signed `EpochTransitionMsg` exactly the way
    /// `advance_slot` does at a boundary: canonical bytes signed by
    /// the transitioning validator.
    fn signed_epoch_transition(
        sk: &SigningKey,
        vk: &VerifyingKey,
        epoch: u64,
        prev_seed: Hash256,
        vrf_output: Vec<u8>,
        seed: Hash256,
    ) -> EpochTransitionMsg {
        let msg = EpochTransitionMsg {
            epoch,
            prev_seed,
            vrf_output,
            seed,
            signer: vk.to_bytes(),
            signature: Vec::new(),
        };
        let sig = sk
            .sign(&sha3_256(&msg.canonical_bytes()).0)
            .expect("test signing");
        EpochTransitionMsg {
            signature: sig.to_bytes().to_vec(),
            ..msg
        }
    }

    /// Receiver runner B with validator A enrolled in its set — the
    /// minimal topology in which B can legitimately accept one of A's
    /// transitions. Both start at the genesis epoch with an empty
    /// chain, so A's 0→1 transition (vrf_output = b"genesis") anchors
    /// to B's state.
    fn epoch_transition_topology() -> (
        SigningKey,
        VerifyingKey,
        ConsensusRunner,
    ) {
        let (sk_a, vk_a) = SigningKey::generate();
        let (sk_b, vk_b) = SigningKey::generate();
        let validator_a = ValidatorInfo {
            public_key: vk_a.to_bytes(),
            vrf_public_key: vec![0xAA; 32],
            stake: 1_000_000_000,
            active: true,
        };
        let validator_b = ValidatorInfo {
            public_key: vk_b.to_bytes(),
            vrf_public_key: vec![0xBB; 32],
            stake: 1_000_000_000,
            active: true,
        };
        let set = ValidatorSet::new(vec![validator_a, validator_b]);
        let runner_b = ConsensusRunner::with_validator_set(
            ConsensusConfig::default(),
            sk_b,
            vk_b,
            VrfKeyManager::new(sha3_256(b"runner_b_seed").0),
            set,
        )
        .expect("test node is enrolled in its own validator set");
        (sk_a, vk_a, runner_b)
    }

    #[test]
    fn test_accept_epoch_transition_valid() {
        let (sk_a, vk_a, mut runner_b) = epoch_transition_topology();
        let epoch0 = Epoch::genesis();
        let epoch1 = epoch0.next_epoch(b"genesis");
        let msg = signed_epoch_transition(
            &sk_a,
            &vk_a,
            epoch1.number,
            epoch0.seed,
            b"genesis".to_vec(),
            epoch1.seed,
        );
        let data = bincode::serialize(&msg).expect("serialize");
        assert!(runner_b.accept_epoch_transition(&data).is_ok());
        assert_eq!(runner_b.current_epoch, epoch1);
    }

    #[test]
    fn test_accept_epoch_transition_rejects_stale_and_future() {
        let (sk_a, vk_a, mut runner_b) = epoch_transition_topology();
        let epoch0 = Epoch::genesis();
        let epoch1 = epoch0.next_epoch(b"genesis");

        // Stale: epoch 0 against a receiver still in epoch 0.
        let stale = EpochTransitionMsg {
            epoch: 0,
            prev_seed: epoch0.seed,
            seed: epoch0.seed,
            ..signed_epoch_transition(&sk_a, &vk_a, 1, epoch0.seed, b"genesis".to_vec(), epoch1.seed)
        };
        let data = bincode::serialize(&stale).expect("serialize");
        assert!(runner_b.accept_epoch_transition(&data).is_err());
        assert_eq!(runner_b.current_epoch.number, 0);

        // Future: epoch 2 skips over epoch 1.
        let future = signed_epoch_transition(
            &sk_a,
            &vk_a,
            2,
            epoch1.seed,
            b"genesis".to_vec(),
            epoch1.next_epoch(b"genesis").seed,
        );
        let data = bincode::serialize(&future).expect("serialize");
        assert!(runner_b.accept_epoch_transition(&data).is_err());
        assert_eq!(runner_b.current_epoch.number, 0);
    }

    #[test]
    fn test_accept_epoch_transition_rejects_wrong_seed() {
        let (sk_a, vk_a, mut runner_b) = epoch_transition_topology();
        let epoch0 = Epoch::genesis();
        let epoch1 = epoch0.next_epoch(b"genesis");
        // Seed does not match prev_seed + vrf_output (signed over the
        // tampered value — the derivation check catches it before the
        // signature check even runs).
        let msg = signed_epoch_transition(
            &sk_a,
            &vk_a,
            epoch1.number,
            epoch0.seed,
            b"genesis".to_vec(),
            sha3_256(b"tampered_seed"),
        );
        let data = bincode::serialize(&msg).expect("serialize");
        assert!(runner_b.accept_epoch_transition(&data).is_err());
        assert_eq!(runner_b.current_epoch.number, 0);
    }

    #[test]
    fn test_accept_epoch_transition_rejects_non_validator_signer() {
        let (_sk_a, _vk_a, mut runner_b) = epoch_transition_topology();
        let (sk_c, vk_c) = SigningKey::generate(); // not in the validator set
        let epoch0 = Epoch::genesis();
        let epoch1 = epoch0.next_epoch(b"genesis");
        let msg = signed_epoch_transition(
            &sk_c,
            &vk_c,
            epoch1.number,
            epoch0.seed,
            b"genesis".to_vec(),
            epoch1.seed,
        );
        let data = bincode::serialize(&msg).expect("serialize");
        assert!(runner_b.accept_epoch_transition(&data).is_err());
        assert_eq!(runner_b.current_epoch.number, 0);
    }

    #[test]
    fn test_accept_epoch_transition_rejects_inactive_signer() {
        let (sk_a, vk_a, mut runner_b) = epoch_transition_topology();
        // Deactivate signer A, then try to accept its transition.
        runner_b
            .validator_set
            .validators
            .iter_mut()
            .find(|v| v.public_key == vk_a.to_bytes())
            .expect("A is enrolled")
            .active = false;
        let epoch0 = Epoch::genesis();
        let epoch1 = epoch0.next_epoch(b"genesis");
        let msg = signed_epoch_transition(
            &sk_a,
            &vk_a,
            epoch1.number,
            epoch0.seed,
            b"genesis".to_vec(),
            epoch1.seed,
        );
        let data = bincode::serialize(&msg).expect("serialize");
        assert!(runner_b.accept_epoch_transition(&data).is_err());
        assert_eq!(runner_b.current_epoch.number, 0);
    }

    #[test]
    fn test_accept_epoch_transition_rejects_tampered_signature() {
        let (sk_a, vk_a, mut runner_b) = epoch_transition_topology();
        let epoch0 = Epoch::genesis();
        let epoch1 = epoch0.next_epoch(b"genesis");
        let mut msg = signed_epoch_transition(
            &sk_a,
            &vk_a,
            epoch1.number,
            epoch0.seed,
            b"genesis".to_vec(),
            epoch1.seed,
        );
        assert!(!msg.signature.is_empty());
        msg.signature[0] ^= 0xFF; // flip a bit in the ML-DSA signature
        let data = bincode::serialize(&msg).expect("serialize");
        assert!(runner_b.accept_epoch_transition(&data).is_err());
        assert_eq!(runner_b.current_epoch.number, 0);
    }

    #[test]
    fn test_accept_epoch_transition_rejects_garbage_bytes() {
        let (_sk_a, _vk_a, mut runner_b) = epoch_transition_topology();
        // The old wire format (raw 8-byte epoch) must no longer parse.
        let old_format = 1u64.to_le_bytes().to_vec();
        assert!(runner_b.accept_epoch_transition(&old_format).is_err());
        assert!(runner_b.accept_epoch_transition(b"").is_err());
        assert_eq!(runner_b.current_epoch.number, 0);
    }

    /// Producer side: crossing a boundary in `advance_slot` must stash
    /// a transition whose signature verifies against the runner's own
    /// verifying key, with fields matching the local epoch derivation.
    #[test]
    fn test_advance_slot_stashes_signed_epoch_transition() {
        let config = ConsensusConfig {
            slots_per_epoch: 4,
            ..ConsensusConfig::default()
        };
        let mut runner = ConsensusRunner::new(config);
        let prev_epoch = runner.current_epoch.clone();
        // Slot 4 is the first slot of epoch 1.
        for _ in 0..4 {
            runner.advance_slot();
        }
        assert_eq!(runner.current_epoch.number, 1);
        let msg = runner
            .take_pending_epoch_transition()
            .expect("boundary must stash a transition");
        assert_eq!(msg.epoch, 1);
        assert_eq!(msg.prev_seed, prev_epoch.seed);
        assert_eq!(msg.seed, runner.current_epoch.seed);
        assert_eq!(msg.signer, runner.verifying_key.to_bytes());
        let vk = VerifyingKey::from_bytes(&msg.signer).expect("own vk");
        let sig = seal_crypto::signature::Signature::from_bytes(msg.signature.clone());
        assert!(
            vk.verify(&sha3_256(&msg.canonical_bytes()).0, &sig).is_ok(),
            "stashed transition must carry a valid signature over its canonical bytes"
        );
        // Drained: a second take returns None.
        assert!(runner.take_pending_epoch_transition().is_none());
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
                vrf_public_key: vrf_mgr.public_key().to_vec(),
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
        let mut runner =
            ConsensusRunner::with_validator_set(config, sk, vk, vrf_mgr, vs)
                .expect("test node is enrolled in its own validator set");

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

    /// Build a Transfer tx signed by `sk` stamped with `nonce`.
    fn money_transfer_tx(
        sk: &SigningKey,
        vk: &VerifyingKey,
        nonce: u64,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Transaction {
        let payload = encode_money_payload(
            nonce,
            &MoneyPayload {
                from: from.into(),
                to: to.into(),
                amount,
            },
        )
        .unwrap();
        let sig = sk.sign(&payload).unwrap();
        Transaction {
            tx_type: TxType::Transfer,
            payload,
            sender: vk.to_bytes(),
            signature: sig.to_bytes().to_vec(),
        }
    }

    /// Regression (2026-09-27 inspection): money transactions must
    /// present nonces in order; replays and out-of-order submissions
    /// are rejected.
    #[test]
    fn test_money_tx_nonce_sequencing() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        let (sk, vk) = SigningKey::generate();

        // Nonce 0 is accepted.
        assert!(runner
            .accept_transaction(money_transfer_tx(&sk, &vk, 0, "seal1a", "seal1b", 5))
            .is_ok());
        // Replaying the identical transaction is rejected: nonce 0
        // was already consumed.
        assert!(runner
            .accept_transaction(money_transfer_tx(&sk, &vk, 0, "seal1a", "seal1b", 5))
            .is_err());
        // Skipping ahead (nonce 2 before 1) is rejected.
        assert!(runner
            .accept_transaction(money_transfer_tx(&sk, &vk, 2, "seal1a", "seal1b", 5))
            .is_err());
        // Nonce 1 is the next expected value and is accepted.
        assert!(runner
            .accept_transaction(money_transfer_tx(&sk, &vk, 1, "seal1a", "seal1b", 5))
            .is_ok());
    }

    /// F9 regression: a non-money tx (a SQL write) must NOT advance the
    /// per-sender nonce counter. The counter sequences + replay-protects money
    /// txs, and the on-block transition rebuilds it for money txs only — so a
    /// running node and a fresh/restarted node agree on it only if `accept`
    /// does not bump it for SQL writes. Before the fix, a SQL write from S
    /// consumed a slot here but the transition never did, so a fresh node
    /// (rebuilt from the chain's money txs) computed a LOWER counter than a
    /// running node for a sender who mixed SQL + transfers: the running node
    /// accepted a transfer the fresh node rejected (and vice versa) until a
    /// Transfer from S landed in a block.
    #[test]
    fn test_non_money_tx_does_not_advance_nonce() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        let (sk, vk) = SigningKey::generate();
        let sender = vk.to_bytes();

        // A SQL write from S, signed by S (accept preview-executes it, so use
        // a valid statement).
        let sql = b"CREATE TABLE f9t (id BIGINT PRIMARY KEY)";
        let sig = sk.sign(sql).unwrap();
        let tx = Transaction {
            tx_type: TxType::SqlExec,
            payload: sql.to_vec(),
            sender: sender.clone(),
            signature: sig.to_bytes().to_vec(),
        };
        assert!(runner.accept_transaction(tx).is_ok());

        // The SQL write must not have consumed a nonce slot: S's next money tx
        // is still expected at nonce 0, exactly as a fresh node (which rebuilds
        // the counter from money txs only) would expect.
        assert_eq!(
            runner.get_nonce(&sender),
            0,
            "a non-money tx must not advance the per-sender nonce counter"
        );

        // …and a transfer at nonce 0 from S is accepted (not rejected as a
        // "nonce mismatch" caused by the SQL write having consumed slot 0).
        assert!(runner
            .accept_transaction(money_transfer_tx(&sk, &vk, 0, "seal1a", "seal1b", 5))
            .is_ok());
    }

    /// A money transaction whose payload is shorter than the 8-byte
    /// nonce prefix cannot be decoded and must be rejected.
    #[test]
    fn test_money_tx_rejects_short_payload() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        let (sk, vk) = SigningKey::generate();
        let payload = b"short".to_vec();
        let sig = sk.sign(&payload).unwrap();
        let tx = Transaction {
            tx_type: TxType::Transfer,
            payload,
            sender: vk.to_bytes(),
            signature: sig.to_bytes().to_vec(),
        };
        assert!(runner.accept_transaction(tx).is_err());
    }

    /// The producer applies a `seal_transfer`-style movement live and
    /// records it as a nonce-stamped tx; a replayer starting from the
    /// pre-movement state must reach the identical balance set by
    /// replaying the block.
    #[test]
    fn test_replay_block_applies_transfer() {
        let mut producer = ConsensusRunner::new(ConsensusConfig::default());
        producer.balances.mint("seal1alice", 1_000).unwrap();
        // Live movement (what handle_transfer does first)…
        producer.balances.transfer("seal1alice", "seal1bob", 300).unwrap();
        // …recorded on-chain (what handle_transfer does second).
        producer
            .submit_money_tx(TxType::Transfer, "seal1alice", "seal1bob", 300)
            .unwrap();

        let mut replayer = ConsensusRunner::new(ConsensusConfig::default());
        replayer.balances.mint("seal1alice", 1_000).unwrap();

        let tx = producer.pending_txs[0].clone();
        let block = Block {
            header: BlockHeader {
                height: 1,
                parent_hash: Hash256::ZERO,
                state_root: Hash256::ZERO,
                timestamp: 0,
                proposer: vec![],
                vrf_output: vec![],
                vrf_proof: vec![],
                proposer_signature: vec![],
                tx_root: Hash256::ZERO,
            },
            transactions: vec![tx],
        };

        replayer.replay_block(&block).unwrap();

        assert_eq!(replayer.balances.available("seal1alice"), 700);
        assert_eq!(replayer.balances.available("seal1bob"), 300);
        // The whole point: replayer and producer now commit to the
        // same ledger state.
        assert_eq!(
            producer.balances.state_root_hash(),
            replayer.balances.state_root_hash()
        );
    }

    /// F2 regression: a node that produced a native-transfer block and
    /// then restarts must reconstruct the identical ledger. main.rs now
    /// seeds the genesis pool *before* replay, so the transfer's debit
    /// finds its funded source account. This test mirrors that boot order
    /// (seed genesis, then replay) and asserts the restarted node reaches
    /// the same balances, the same conserved `total_supply` (no
    /// double-mint), the same state root, and a rebuilt nonce counter so
    /// the next transfer continues from nonce 1 rather than re-issuing 0.
    #[test]
    fn test_restart_transfer_chain_replays_without_divergence() {
        // First run: seed genesis, move funds live, record on chain.
        let mut producer = ConsensusRunner::new(ConsensusConfig::default());
        producer.balances.mint("seal1alice", 1_000).unwrap();
        producer.balances.transfer("seal1alice", "seal1bob", 300).unwrap();
        producer
            .submit_money_tx(TxType::Transfer, "seal1alice", "seal1bob", 300)
            .unwrap();
        let sender = producer.verifying_key.to_bytes();
        let producer_supply = producer.balances.total_supply();
        let producer_alice = producer.balances.available("seal1alice");
        let producer_bob = producer.balances.available("seal1bob");
        let producer_nonce = producer.nonces.get(&sender).copied();
        let tx = producer.pending_txs[0].clone();
        let block = Block {
            header: BlockHeader {
                height: 1,
                parent_hash: Hash256::ZERO,
                state_root: Hash256::ZERO,
                timestamp: 0,
                proposer: vec![],
                vrf_output: vec![],
                vrf_proof: vec![],
                proposer_signature: vec![],
                tx_root: Hash256::ZERO,
            },
            transactions: vec![tx],
        };

        // Restart: fresh ledger, seed genesis first (the main.rs fix),
        // then replay the historical transfer block.
        let mut replayer = ConsensusRunner::new(ConsensusConfig::default());
        replayer.balances.mint("seal1alice", 1_000).unwrap();
        assert!(
            replayer.replay_block(&block).is_ok(),
            "transfer chain must replay once genesis is seeded"
        );

        // No double-mint: the pool was seeded once and the transfer is
        // supply-conserving, so the restarted supply equals the first run's.
        assert_eq!(
            replayer.balances.total_supply(),
            producer_supply,
            "restart must not re-mint genesis"
        );
        // Ledger is byte-identical to the producer's.
        assert_eq!(replayer.balances.available("seal1alice"), producer_alice);
        assert_eq!(replayer.balances.available("seal1bob"), producer_bob);
        assert_eq!(
            producer.balances.state_root_hash(),
            replayer.balances.state_root_hash()
        );
        // Nonce counter rebuilt: the restarted node continues from nonce 1,
        // matching the producer, instead of re-issuing nonce 0.
        assert_eq!(
            replayer.nonces.get(&sender).copied(),
            producer_nonce,
            "nonce counter must be rebuilt during replay"
        );
    }

    /// F2 negative control: replaying a native-transfer block into an
    /// EMPTY ledger (genesis not seeded) must fail on the first debit —
    /// the source account does not exist. This is the divergence the
    /// pre-replay genesis seed in main.rs prevents.
    #[test]
    fn test_replay_transfer_into_empty_ledger_fails() {
        let mut producer = ConsensusRunner::new(ConsensusConfig::default());
        producer.balances.mint("seal1alice", 1_000).unwrap();
        producer.balances.transfer("seal1alice", "seal1bob", 300).unwrap();
        producer
            .submit_money_tx(TxType::Transfer, "seal1alice", "seal1bob", 300)
            .unwrap();
        let tx = producer.pending_txs[0].clone();
        let block = Block {
            header: BlockHeader {
                height: 1,
                parent_hash: Hash256::ZERO,
                state_root: Hash256::ZERO,
                timestamp: 0,
                proposer: vec![],
                vrf_output: vec![],
                vrf_proof: vec![],
                proposer_signature: vec![],
                tx_root: Hash256::ZERO,
            },
            transactions: vec![tx],
        };

        // Empty ledger — no genesis seed. The debit has no funded source.
        let mut replayer = ConsensusRunner::new(ConsensusConfig::default());
        let result = replayer.replay_block(&block);
        assert!(
            result.is_err(),
            "replaying a transfer into an empty ledger must fail (F2): {:?}",
            result
        );
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

    #[test]
    fn test_genesis_config_stored_after_apply() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());

        // Precondition: no genesis config set.
        assert!(runner.genesis_config.is_none());

        let genesis = seal_consensus::genesis::GenesisConfig::testnet(3, 10_000_000_000);
        runner.apply_genesis(&genesis).unwrap();

        // Post-condition: genesis config is stored and queryable.
        let stored = runner.genesis_config.as_ref().expect("genesis config should be stored");
        assert_eq!(stored.chain_id, "seal-testnet");
        assert_eq!(stored.validators.len(), 3);
        assert_eq!(stored.allocations.len(), 1); // testnet single faucet allocation
        assert_eq!(stored.initial_supply, 1_000_000_000_000_000_000); // hard-coded in testnet()
    }

    /// Regression (audit item 6): applying genesis twice on the same runner
    /// must not double the supply. The first call mints and sets
    /// `genesis_config`; the second must be refused with an error and leave
    /// the total supply unchanged.
    #[test]
    fn test_apply_genesis_refuses_double_apply() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        let genesis = seal_consensus::genesis::GenesisConfig::testnet(3, 10_000_000_000);

        let first = runner.apply_genesis(&genesis).unwrap();
        let supply_after_first = runner.balances.total_supply();
        assert_eq!(supply_after_first, first);

        // A second application is refused and must not mint again.
        let second = runner.apply_genesis(&genesis);
        assert!(second.is_err(), "second apply_genesis must be refused");
        assert_eq!(
            runner.balances.total_supply(),
            supply_after_first,
            "total supply must not double on a refused re-apply"
        );
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
