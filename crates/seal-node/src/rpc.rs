//! JSON-RPC 2.0 server for seal-node.
//!
//! Features:
//! - ML-DSA signature authentication on mutating requests
//! - RLS enforcement on SQL queries
//! - Namespace-aware query routing
//! - MPC aggregate and ZK proof endpoints
//! - Chain state inspection

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use seal_crypto::address::SealAddress;
use seal_crypto::hash::sha3_256;
use seal_crypto::signature::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::governance::{CouncilMember, TechnicalCouncil};
use crate::network_node::NetworkNode;
use crate::pq_rpc::PqRpcManager;
use crate::private_tables::{PrivateTableManager, PrivateTableType};
use seal_bridge::{
    BridgeManager, BridgeObserverSet, Chain, SolanaObserver, StellarObserver, WrappedToken,
};
use seal_token::orderbook::DexManager;
use seal_token::tokens::TokenManager;

/// RPC server configuration.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    /// Namespaces this node serves (empty = serve all).
    pub served_namespaces: HashSet<String>,
    /// Whether to require authentication for reads.
    pub require_auth_for_reads: bool,
    /// Maximum SQL query length in bytes.
    pub max_query_length: usize,
    /// Maximum requests per IP per minute.
    pub max_requests_per_minute: u64,
    /// Dev-only faucet. When enabled, `seal_faucet` mints a bounded
    /// amount of SEAL to any address with no signature. Intended for
    /// single-node devnet use; refuses to mint past `dev_faucet_cap`
    /// per address in a 24h window. MUST NEVER be enabled on mainnet.
    pub dev_faucet: bool,
    /// Max SEAL (base units) a single address can pull from the dev
    /// faucet in one 24h window. Defaults to 1000 SEAL (10^12 units
    /// at 9-decimal precision).
    pub dev_faucet_cap: u64,
    /// Encode caller-derived addresses with the testnet HRP
    /// (`sealt1…`) rather than mainnet (`seal1…`). Must match the
    /// wallet's testnet flag (see `Wallet::from_seed(_, testnet)`);
    /// otherwise the server derives a different address from the
    /// same verifying key than the wallet displays, and any signed
    /// transfer debits a ghost account with zero balance. Default
    /// is true — single-node devnet work uses testnet keys.
    pub testnet: bool,
    /// Set of bech32m Seal addresses authorized to call admin-gated
    /// RPCs (`seal_addBridgeObserver`,
    /// `seal_bridgeCouncilAdd/Remove`, `seal_bridgePauseChain/Unpause`).
    /// Empty set = "open mode": admin-gated methods are reachable by
    /// any signed caller, matching the alpha-testnet bootstrap
    /// behaviour. Populated set = "gated mode": admin-gated methods
    /// require both a valid signature *and* an address in this set.
    /// Mainnet must populate this (genesis config); testnet usually
    /// leaves it empty. See `requires_admin_auth` for the method
    /// list and `is_admin` for the check.
    pub admin_addresses: HashSet<String>,
    /// Recipient-new-account policy override. When `false` (default,
    /// "block mode"), `seal_transfer` / `seal_transferToken` reject
    /// transfers to addresses with no prior ledger entry unless the
    /// caller passes `confirm_new_recipient: true` in the params
    /// ("confirm mode" — explicit per-request opt-in). When `true`
    /// ("allow mode"), the check is skipped entirely — for bridge or
    /// faucet nodes that legitimately mint to fresh accounts. Set
    /// via `--allow-new-recipients` in `seal-node`. The check covers
    /// both the native SEAL ledger and per-token ledgers in
    /// `TokenManager`.
    pub allow_new_recipients: bool,
    /// Minimum amount (in base units) that a transfer to a *new*
    /// recipient must carry. 0 = disabled. Independent of
    /// `allow_new_recipients`: a faucet/bridge node typically sets
    /// `allow_new_recipients = true` *and* a non-zero
    /// `min_opening_balance` so it can create fresh accounts but
    /// only with a minimum funding amount, raising the per-account
    /// cost of dust-spam attacks against the HAMT-backed
    /// `BalanceStore`.
    ///
    /// Applies to native SEAL (`seal_transfer`) and to custom
    /// tokens (`seal_transferToken`). The native check runs against
    /// `BalanceStore::has_account`; the per-token check runs
    /// against `TokenManager::has_token_account` (so a fresh
    /// recipient for one token is independent of any other).
    pub min_opening_balance: u64,
    /// Per-method-group requests-per-minute caps (P8/§4.1 mainnet
    /// gate). The grouping classifier lives in `rpc_group_for_method`.
    /// Defaults: expensive=20/min (writes + bridge withdraws),
    /// admin=5/min (gated bootstrap RPCs), default=120/min (reads).
    /// `max_requests_per_minute` above is the legacy single-bucket
    /// global cap; if either bucket trips, the request is rejected.
    pub rpm_default: u64,
    pub rpm_expensive: u64,
    pub rpm_admin: u64,
    /// Bridge withdrawal fee (P8/§4.2 mainnet gate). Burned from
    /// the caller's native SEAL balance on every successful
    /// seal_bridgeWithdraw before the wrapped-token burn. 0 = off
    /// (testnet default). Mainnet sets this via the
    /// `--bridge-withdrawal-fee` CLI flag.
    pub bridge_withdrawal_fee: u64,
    /// Admin M-of-N multisig threshold (P8/§4.3 mainnet gate).
    /// 0 or 1 = single-signature mode (backwards-compatible with
    /// pre-P8 behaviour: one signed request from any
    /// `admin_addresses` member passes). When set to ≥ 2, every
    /// admin-gated RPC additionally requires an `admin_signatures`
    /// array in the params containing at least `admin_threshold`
    /// valid signatures from *distinct* addresses in the admin set
    /// — see `verify_admin_multisig`. Defaults to 0 so existing
    /// configs aren't broken.
    pub admin_threshold: usize,
}

impl Default for RpcConfig {
    fn default() -> Self {
        RpcConfig {
            served_namespaces: HashSet::new(),
            require_auth_for_reads: false,
            max_query_length: 64 * 1024, // 64 KB
            max_requests_per_minute: 120,
            dev_faucet: false,
            dev_faucet_cap: 1_000 * 1_000_000_000,
            testnet: true,
            admin_addresses: HashSet::new(),
            allow_new_recipients: false,
            min_opening_balance: 0,
            rpm_default: 120,
            rpm_expensive: 20,
            rpm_admin: 5,
            bridge_withdrawal_fee: 0,
            admin_threshold: 0,
        }
    }
}

/// Enforce the recipient-new-account policy. Returns Ok if the
/// transfer should proceed, Err with a JSON-RPC error otherwise.
///
/// - If `config.allow_new_recipients` is true → always proceed
///   (allow mode; bridge/faucet nodes set this).
/// - Else if the caller passes `confirm_new_recipient: true` →
///   proceed (confirm mode; per-request opt-in).
/// - Else if the recipient already has a ledger entry → proceed
///   (block mode happy path; recipient is not a new account).
/// - Else reject with -32007 ("recipient is a new account; pass
///   `confirm_new_recipient: true` to acknowledge").
///
/// `recipient_known` is the result of `BalanceStore::has_account`
/// (or `TokenManager::has_token_account`) on the recipient address.
fn check_recipient_policy(
    config: &RpcConfig,
    params: &serde_json::Value,
    recipient_known: bool,
    recipient_addr: &str,
) -> Result<(), (i32, String)> {
    if config.allow_new_recipients {
        return Ok(());
    }
    let confirmed = params
        .get("confirm_new_recipient")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if confirmed || recipient_known {
        return Ok(());
    }
    Err((
        -32007,
        format!(
            "recipient {recipient_addr} is a new account with no prior ledger entry; \
             re-submit with confirm_new_recipient=true to acknowledge, or run the \
             node with --allow-new-recipients"
        ),
    ))
}

/// Enforce the min-opening-balance policy. Returns Ok if the
/// transfer should proceed, Err with a JSON-RPC error otherwise.
///
/// Active only when `config.min_opening_balance > 0` AND the
/// recipient is not already on the ledger. Existing recipients are
/// always exempt regardless of amount — the rule targets
/// per-account creation cost, not per-transfer.
///
/// Independent of `check_recipient_policy`: a faucet node typically
/// sets `allow_new_recipients = true` (so the recipient policy is
/// always Ok) AND a non-zero `min_opening_balance` (so dust drips
/// to fresh addresses still fail). Both checks run on every
/// transfer; either can reject independently.
fn check_min_opening_balance(
    config: &RpcConfig,
    recipient_known: bool,
    amount: u64,
    recipient_addr: &str,
) -> Result<(), (i32, String)> {
    if config.min_opening_balance == 0 || recipient_known {
        return Ok(());
    }
    if amount < config.min_opening_balance {
        return Err((
            -32008,
            format!(
                "recipient {recipient_addr} is new and amount {amount} is below the \
                 min-opening-balance threshold {threshold}; raise the amount or send \
                 to an existing account",
                threshold = config.min_opening_balance,
            ),
        ));
    }
    Ok(())
}

/// Per-IP, per-method-group rate limiter (P8/§4.1 mainnet gate).
///
/// Pre-P8 this was a single bucket per IP — expensive paths
/// (`seal_submitSql`, `seal_bridgeWithdraw`) and admin RPCs could
/// starve cheap reads (and vice-versa). The grouped variant keys
/// each bucket by `(ip, RpcGroup)` so SQL writes don't crowd out
/// admin calls.
///
/// The grouping is coarse on purpose — 3 buckets is enough to
/// separate the cost classes without turning rate-limit tuning into
/// a per-method config sprawl. See `rpc_group_for_method` for the
/// classifier.
#[derive(Default)]
pub struct RateLimiter {
    /// Requests per (IP, group) in the current window.
    requests: std::collections::HashMap<(std::net::IpAddr, RpcGroup), (u64, std::time::Instant)>,
}

/// Coarse classification of an RPC method for rate-limit grouping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RpcGroup {
    /// Cheap reads + chain-state queries. High quota.
    Default,
    /// Expensive writes / mutations. Lower quota.
    Expensive,
    /// Bridge-bootstrap + governance-gated calls. Lowest quota.
    Admin,
}

/// Map a JSON-RPC method name to its rate-limit group.
pub fn rpc_group_for_method(method: &str) -> RpcGroup {
    if requires_admin_auth(method) {
        return RpcGroup::Admin;
    }
    match method {
        "seal_submitSql"
        | "seal_bridgeWithdraw"
        | "seal_bridgeMarkExecuted"
        | "seal_transfer"
        | "seal_transferToken"
        | "seal_mintToken"
        | "seal_burnToken"
        | "seal_createToken"
        | "seal_createPair"
        | "seal_placeOrder"
        | "seal_govPropose"
        | "seal_govVote" => RpcGroup::Expensive,
        _ => RpcGroup::Default,
    }
}

impl RateLimiter {
    /// Check if a request from this IP for `group` should be allowed.
    /// Returns false if the IP has exceeded `max_per_minute` for that
    /// group in the current 60-second window.
    pub fn check(&mut self, ip: std::net::IpAddr, group: RpcGroup, max_per_minute: u64) -> bool {
        let now = std::time::Instant::now();
        let entry = self.requests.entry((ip, group)).or_insert((0, now));

        // Reset window if more than 60s have passed
        if now.duration_since(entry.1).as_secs() >= 60 {
            *entry = (1, now);
            return true;
        }

        entry.0 += 1;
        entry.0 <= max_per_minute
    }

    /// Clean up expired entries (call periodically).
    pub fn cleanup(&mut self) {
        let now = std::time::Instant::now();
        self.requests
            .retain(|_, (_, ts)| now.duration_since(*ts).as_secs() < 120);
    }
}

/// Registered namespace info (in-memory, backed by on-chain state).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceEntry {
    pub name: String,
    pub owner: String,
    pub schema_hash: String,
    pub visibility: String,
    pub replication: u64,
}

/// Shared state for RPC handlers.
#[derive(Clone)]
pub struct RpcState {
    pub node: Arc<Mutex<NetworkNode>>,
    pub config: Arc<RpcConfig>,
    pub private_tables: Arc<Mutex<PrivateTableManager>>,
    pub pq_rpc: Arc<PqRpcManager>,
    pub token_manager: Arc<Mutex<TokenManager>>,
    pub dex: Arc<Mutex<DexManager>>,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    /// Registered namespaces (persisted via on-chain transactions).
    pub namespaces: Arc<Mutex<Vec<NamespaceEntry>>>,
    /// Node metrics for /health, /metrics, /status endpoints.
    pub metrics: Arc<crate::metrics::NodeMetrics>,
    /// Node start time (for uptime calculation).
    pub start_time: std::time::Instant,
    /// Cross-chain bridge manager: tracks deposits, withdrawals and
    /// wrapped balances for SOL/XLM/USDC. Populated by `seal_pollBridges`.
    pub bridge: Arc<Mutex<BridgeManager>>,
    /// Observer set for configured source chains. Extended at runtime
    /// via `seal_addBridgeObserver`.
    pub observers: Arc<Mutex<BridgeObserverSet>>,
    /// Technical Council: members can veto proposals and, via 2/3
    /// supermajority, trigger bridge emergency pauses. Empty at
    /// startup; bootstrap with `seal_bridgeCouncilAdd` on testnet.
    pub council: Arc<Mutex<TechnicalCouncil>>,
    /// Per-address drip tracker for `seal_faucet`. Maps address →
    /// (total_minted_in_window, window_start). Window length is 24 h.
    pub faucet_drips: Arc<Mutex<std::collections::HashMap<String, (u64, std::time::Instant)>>>,
    /// Data directory — the rotate-committee-key handler writes the
    /// new key here so it survives node restart (otherwise the CLI
    /// flag wins on reboot and reverts the rotation). `None` when
    /// the node runs in `--no-network` mode without a disk store.
    pub data_dir: Option<std::path::PathBuf>,
    /// Multi-validator Ringtail signing orchestrator (P1#5 layer 4 —
    /// ADR-002). `Some` only when the operator opted into Ringtail
    /// mode via `--bridge-ringtail-*` CLI flags AND the
    /// `ringtail-singleton` feature is on. `None` on the HMAC
    /// committee-of-1 default path. `seal_bridgeRingtailStatus`
    /// reads `session_count()` from this when present.
    #[cfg(feature = "ringtail-singleton")]
    pub ringtail_orchestrator:
        Option<Arc<Mutex<seal_bridge::ringtail_orchestrator::RingtailBridgeOrchestrator>>>,
}

/// JSON-RPC 2.0 request with optional authentication.
#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    pub id: serde_json::Value,
    /// ML-DSA signature over SHA3(method || params_json), hex-encoded.
    #[serde(default)]
    pub signature: Option<String>,
    /// Sender's ML-DSA verifying key, hex-encoded.
    #[serde(default)]
    pub sender: Option<String>,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: serde_json::Value,
}

/// JSON-RPC 2.0 error.
#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcResponse {
    fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        RpcResponse {
            jsonrpc: "2.0".into(),
            result: Some(result),
            error: None,
            id,
        }
    }

    fn err(id: serde_json::Value, code: i64, message: String) -> Self {
        RpcResponse {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(RpcError { code, message }),
            id,
        }
    }
}

/// Authenticated caller identity.
struct Caller {
    /// Seal address derived from public key.
    address: String,
}

/// Start the JSON-RPC server.
///
/// `bridge` is owned by the caller (typically `seal-node` main) so the
/// network event loop, the optional multi-validator Ringtail
/// orchestrator, and any signing-signal subscriber can share the
/// same Arc — every mutation must be visible across all three
/// surfaces. Pre-set the committee key on the BridgeManager before
/// calling this function.
///
/// `ringtail_orchestrator` is the optional P1#5 layer 4 orchestrator
/// (ADR-002): `Some` when the operator passed `--bridge-ringtail-*`
/// flags AND the `ringtail-singleton` feature is on. Threading it
/// here lets `seal_bridgeRingtailStatus` report session count and
/// future per-method handlers (e.g. operator-driven manual session
/// flush) reach into the orchestrator without re-plumbing.
#[allow(clippy::too_many_arguments)]
pub async fn start_rpc_server(
    node: Arc<Mutex<NetworkNode>>,
    config: RpcConfig,
    port: u16,
    external: bool,
    bridge: Arc<Mutex<BridgeManager>>,
    data_dir: Option<std::path::PathBuf>,
    bridge_poll_interval_secs: u64,
    #[cfg(feature = "ringtail-singleton")] ringtail_orchestrator: Option<
        Arc<Mutex<seal_bridge::ringtail_orchestrator::RingtailBridgeOrchestrator>>,
    >,
) {
    let max_rpm = config.max_requests_per_minute;
    // Share the consensus runner's `DexManager` with the RPC layer so
    // order placements (`seal_dexPlaceOrder`) land in the same books
    // that block production matches each slot via `match_all`.
    let dex = node.lock().await.runner.dex.clone();
    let state = RpcState {
        node,
        config: Arc::new(config),
        private_tables: Arc::new(Mutex::new(PrivateTableManager::new())),
        pq_rpc: Arc::new(PqRpcManager::new()),
        token_manager: Arc::new(Mutex::new(TokenManager::new())),
        dex,
        rate_limiter: Arc::new(Mutex::new(RateLimiter::default())),
        namespaces: Arc::new(Mutex::new(Vec::new())),
        metrics: Arc::new(crate::metrics::NodeMetrics::new()),
        start_time: std::time::Instant::now(),
        bridge,
        observers: Arc::new(Mutex::new(BridgeObserverSet::new())),
        council: Arc::new(Mutex::new(TechnicalCouncil::new())),
        faucet_drips: Arc::new(Mutex::new(std::collections::HashMap::new())),
        data_dir,
        #[cfg(feature = "ringtail-singleton")]
        ringtail_orchestrator,
    };

    use axum::http::header;
    use axum::http::{HeaderValue, Method};

    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin("*".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE]);

    let app = Router::new()
        .route("/", post(handle_rpc))
        .route("/health", get(handle_health))
        .route("/metrics", get(handle_metrics))
        .route("/status", get(handle_status))
        .layer(cors)
        .with_state(state.clone());

    // Default: bind to localhost only — unencrypted RPC must never be exposed to the
    // network in production. Pass `external = true` (--rpc-external flag) only in
    // containerised test environments where the port is bridged to a Docker network.
    let bind_ip = if external {
        [0, 0, 0, 0]
    } else {
        [127, 0, 0, 1]
    };
    let addr = SocketAddr::from((bind_ip, port));
    info!(
        "RPC server listening on http://{} ({}, {} req/min)",
        addr,
        if external {
            "all interfaces"
        } else {
            "localhost only"
        },
        max_rpm
    );

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Failed to bind RPC server on port {}: {}", port, e);
            return;
        }
    };

    // Optional background bridge-auto-poll. Disabled when interval=0;
    // typical testnet value is 10-30s. Each tick runs the same
    // poll_bridges_once path that seal_pollBridges exposes, so the
    // observation cadence is uniform whether driven by cron + RPC
    // or by this in-process task. Errors are logged and the task
    // continues — a transient source-chain RPC hiccup shouldn't
    // wedge the loop.
    if bridge_poll_interval_secs > 0 {
        let bg_state = state.clone();
        let period = std::time::Duration::from_secs(bridge_poll_interval_secs);
        info!(
            "Bridge auto-poll enabled (interval = {}s)",
            bridge_poll_interval_secs
        );
        tokio::spawn(async move {
            // Phase the first poll one period in so observers can be
            // registered (via seal_addBridgeObserver) before the
            // first run rather than the loop spamming "no observers"
            // on every fresh boot.
            let mut ticker = tokio::time::interval(period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await; // immediate first tick
            loop {
                ticker.tick().await;
                match poll_bridges_once(&bg_state, true).await {
                    Ok((observed, new, dup, processed)) => {
                        if observed > 0 || new > 0 || processed > 0 {
                            debug!(
                                "bridge auto-poll: observed={} new={} duplicate={} processed={}",
                                observed, new, dup, processed
                            );
                        }
                    }
                    Err((code, msg)) => {
                        warn!("bridge auto-poll error ({}): {}", code, msg);
                    }
                }
            }
        });
    }

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        warn!("RPC server error: {}", e);
    }
}

// ─── Authentication ─────────────────────────────────

/// Verify ML-DSA signature on a request. Returns the caller's address
/// in the canonical bech32m form produced by
/// `SealAddress::from_verifying_key` — the same derivation every
/// wallet (`crates/seal-wallet`) uses, so the address a transfer
/// debits matches the address the wallet displays. `testnet`
/// selects the HRP (`sealt1…` vs `seal1…`).
fn authenticate(req: &RpcRequest, testnet: bool) -> Result<Caller, (i32, String)> {
    let sig_hex = req
        .signature
        .as_ref()
        .ok_or((-32003, "missing 'signature' field".into()))?;
    let sender_hex = req
        .sender
        .as_ref()
        .ok_or((-32003, "missing 'sender' field".into()))?;

    // Decode verifying key
    let vk_bytes = hex::decode(sender_hex).map_err(|_| (-32003, "invalid sender hex".into()))?;
    let vk = VerifyingKey::from_bytes(&vk_bytes)
        .map_err(|_| (-32003, "invalid sender public key".into()))?;

    // Decode signature
    let sig_bytes = hex::decode(sig_hex).map_err(|_| (-32003, "invalid signature hex".into()))?;
    let sig = Signature::from_bytes(sig_bytes);

    // Reconstruct signed message: SHA3(method || params_json)
    let params_json = serde_json::to_string(&req.params).unwrap_or_default();
    let message = format!("{}{}", req.method, params_json);
    let message_hash = sha3_256(message.as_bytes());
    debug!("auth message: {}", message);
    debug!("auth hash: {}", hex::encode(message_hash.as_ref()));

    // Verify
    vk.verify(message_hash.as_ref(), &sig)
        .map_err(|_| (-32003, "signature verification failed".into()))?;

    // Derive address the same way the wallet does: full 32-byte
    // SHA3-256 of the vk, bech32m-encoded with the correct HRP.
    let address = SealAddress::from_verifying_key(&vk, testnet).to_string_encoding();

    Ok(Caller { address })
}

/// Check if a method requires authentication.
fn requires_auth(method: &str) -> bool {
    matches!(
        method,
        "seal_submitSql"
            | "seal_deployNamespace"
            | "seal_transfer"
            | "seal_createToken"
            | "seal_mintToken"
            | "seal_transferToken"
            | "seal_burnToken"
            | "seal_freezeAccount"
            | "seal_unfreezeAccount"
            | "seal_setTokenFrozen"
            | "seal_setMintAuthority"
            | "seal_setFreezeAuthority"
            | "seal_setFeeAuthority"
            | "seal_renounceMintAuthority"
            | "seal_renounceFreezeAuthority"
            | "seal_renounceFeeAuthority"
            | "seal_setTransferFee"
            | "seal_setFeeRecipient"
            | "seal_createPair"
            | "seal_placeOrder"
            | "seal_cancelOrder"
            | "seal_createPrivateTable"
            // (seal_setVisibility / seal_enableRls / seal_addPolicy used
            //  to live here, but no handler was ever wired — the canonical
            //  path is SQL DDL: `ALTER TABLE … ENABLE ROW LEVEL SECURITY`
            //  and `CREATE POLICY …` via seal_submitSql, which is already
            //  auth-gated. Listing them here would force callers through
            //  the auth check only to get -32601 method not found.)
            // Bridge mutations require a signed sender so we know whose
            // wrapped balance to burn when they initiate a withdrawal.
            | "seal_bridgeWithdraw"
            // Relayer mark-executed: validator pubkey signs the
            // request; the handler additionally checks the caller's
            // address is in the active validator set (P1#3 per-
            // validator custody model).
            | "seal_bridgeMarkExecuted"
            // Governance mutations bind the caller's ML-DSA address as
            // proposer / voter / delegator. Reads stay open.
            | "seal_govPropose"
            | "seal_govVote"
            | "seal_govWithdrawVote"
            | "seal_govDelegate"
            | "seal_govRevokeDelegation"
    )
}

/// Methods that, in addition to `requires_auth`, require the caller's
/// derived address to be in `RpcConfig::admin_addresses`. These are
/// the bridge-bootstrap RPCs that can otherwise grant the caller
/// chain-level privilege (registering an observer, seating council
/// members, pausing/unpausing a chain). The 2/3 council check on
/// pause/unpause already prevents unilateral action, but admin
/// gating closes the "anyone can drive RPC traffic" gap so the call
/// is at least bound to a known operator key.
///
/// Open-mode (empty `admin_addresses`) preserves the alpha-testnet
/// behaviour: any signed caller can hit these. Mainnet must populate
/// the set via genesis config / `--admin-address` CLI flag.
fn requires_admin_auth(method: &str) -> bool {
    matches!(
        method,
        "seal_addBridgeObserver"
            | "seal_bridgeCouncilAdd"
            | "seal_bridgeCouncilRemove"
            | "seal_bridgePauseChain"
            | "seal_bridgeUnpauseChain"
            | "seal_bridgeRotateCommitteeKey"
    )
}

/// Returns true if `address` is permitted to call admin-gated
/// methods under `config`. Open-mode (no admin addresses configured)
/// permits any signed caller to preserve testnet bootstrap; gated
/// mode requires explicit membership.
fn is_admin(address: &str, config: &RpcConfig) -> bool {
    config.admin_addresses.is_empty() || config.admin_addresses.contains(address)
}

/// Verify that the request carries at least `config.admin_threshold`
/// valid signatures from distinct admin-set members (P8/§4.3
/// mainnet multisig). The primary signer (already
/// authenticate()'d into `caller_address`) counts as one signature;
/// the rest live in an `admin_signatures` param array of
/// `{sender: hex, signature: hex}` objects, each over the same
/// message digest as the primary except with the `admin_signatures`
/// field itself stripped from params (so cosigners aren't signing
/// each other's bytes).
fn verify_admin_multisig(
    method: &str,
    params: &serde_json::Value,
    caller_address: &str,
    config: &RpcConfig,
) -> Result<(), String> {
    // Build the canonical signing message: params with the
    // admin_signatures field removed (or null), then serialize as
    // JSON. Both the primary signer and every cosigner sign this
    // same shape — keeps cosigners' signatures byte-stable across
    // submission attempts.
    let mut canon_params = params.clone();
    if let Some(obj) = canon_params.as_object_mut() {
        obj.remove("admin_signatures");
    }
    let params_json = serde_json::to_string(&canon_params).unwrap_or_default();
    let message = format!("{}{}", method, params_json);
    let message_hash = sha3_256(message.as_bytes());

    // Collect distinct verified-cosigner addresses. The primary
    // signer counts as one — they already passed authenticate().
    let mut verified: std::collections::HashSet<String> = std::collections::HashSet::new();
    verified.insert(caller_address.to_string());

    let empty_cosigners: Vec<serde_json::Value> = Vec::new();
    let cosigners = params
        .get("admin_signatures")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_cosigners);
    for entry in cosigners {
        let sender_hex = match entry.get("sender").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue, // malformed entry → skipped, not fatal
        };
        let sig_hex = match entry.get("signature").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };
        let vk_bytes = match hex::decode(sender_hex) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let vk = match VerifyingKey::from_bytes(&vk_bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let sig = Signature::from_bytes(sig_bytes);
        if vk.verify(message_hash.as_ref(), &sig).is_err() {
            continue;
        }
        let addr = SealAddress::from_verifying_key(&vk, config.testnet).to_string_encoding();
        if !is_admin(&addr, config) {
            continue;
        }
        verified.insert(addr);
    }

    if verified.len() < config.admin_threshold {
        return Err(format!(
            "{} requires {}-of-{} admin multisig; got {} distinct admin signature(s)",
            method,
            config.admin_threshold,
            config.admin_addresses.len(),
            verified.len(),
        ));
    }
    Ok(())
}

// ─── Request Handler ────────────────────────────────

async fn handle_rpc(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    State(state): State<RpcState>,
    Json(req): Json<RpcRequest>,
) -> (StatusCode, Json<RpcResponse>) {
    let id = req.id.clone();

    // Rate limiting — per-method-group bucket (P8/§4.1). The global
    // legacy `max_requests_per_minute` continues to apply via the
    // `Default` group cap (which defaults to the same 120/min).
    {
        let group = rpc_group_for_method(&req.method);
        let cap = match group {
            RpcGroup::Default => state.config.rpm_default,
            RpcGroup::Expensive => state.config.rpm_expensive,
            RpcGroup::Admin => state.config.rpm_admin,
        };
        let mut limiter = state.rate_limiter.lock().await;
        if !limiter.check(addr.ip(), group, cap) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(RpcResponse::err(
                    id,
                    -32005,
                    format!(
                        "rate limit exceeded for {:?} group ({} req/min)",
                        group, cap
                    ),
                )),
            );
        }
    }

    // Input validation
    if let Some(sql) = req.params.get("sql").and_then(|v| v.as_str()) {
        if sql.len() > state.config.max_query_length {
            return (
                StatusCode::OK,
                Json(RpcResponse::err(id, -32000, "query too large".into())),
            );
        }
    }

    // Authenticate if required. Admin-gated methods only force auth
    // when `admin_addresses` is populated — open mode preserves the
    // alpha-testnet bootstrap flow where `bridge-e2e.sh` and similar
    // scripts call these RPCs without signing.
    let admin_method = requires_admin_auth(&req.method);
    let admin_gated = admin_method && !state.config.admin_addresses.is_empty();
    let needs_signature = requires_auth(&req.method) || admin_gated;
    let caller = if needs_signature {
        match authenticate(&req, state.config.testnet) {
            Ok(c) => Some(c),
            Err((code, msg)) => {
                return (StatusCode::OK, Json(RpcResponse::err(id, code as i64, msg)))
            }
        }
    } else if req.signature.is_some() {
        // Optional auth on reads — verify if provided
        authenticate(&req, state.config.testnet).ok()
    } else {
        None
    };

    let caller_addr = caller.as_ref().map(|c| c.address.as_str());

    // When `admin_addresses` is populated, every admin-gated method
    // additionally requires the caller's derived address to be in
    // that set. The auth step above already failed any
    // missing/invalid signature; here we only need the membership
    // check.
    if admin_gated {
        let address = caller_addr.unwrap_or("");
        if !is_admin(address, &state.config) {
            return (
                StatusCode::OK,
                Json(RpcResponse::err(
                    id,
                    -32004,
                    format!(
                        "{} requires admin authorization (address {} not in admin set)",
                        req.method, address
                    ),
                )),
            );
        }
        // P8/§4.3 — admin M-of-N multisig. The caller's own signature
        // already passed authenticate(); when threshold >= 2 we
        // additionally require `admin_threshold - 1` cosigners in
        // `admin_signatures` to push the count to >= threshold.
        if state.config.admin_threshold >= 2 {
            if let Err(msg) =
                verify_admin_multisig(&req.method, &req.params, address, &state.config)
            {
                return (StatusCode::OK, Json(RpcResponse::err(id, -32004, msg)));
            }
        }
    }

    let response = match req.method.as_str() {
        // SQL operations
        "seal_submitSql" => {
            handle_submit_sql(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_querySql" => {
            handle_query_sql(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }

        // Namespace management (auth required)
        "seal_deployNamespace" => {
            handle_deploy_namespace(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }

        // Chain state (no auth)
        "seal_getHeight" => handle_get_height(&state).await,
        "seal_getStateRoot" => handle_get_state_root(&state).await,
        "seal_getBlock" => handle_get_block(&state, &req.params).await,
        "seal_getPeers" => handle_get_peers(&state).await,
        "seal_getNamespaces" => handle_get_namespaces(&state).await,
        "seal_listNamespacesByOwner" => handle_list_namespaces_by_owner(&state, &req.params).await,
        "seal_listValidators" => handle_list_validators(&state).await,
        "seal_getValidatorByAddress" => handle_get_validator_by_address(&state, &req.params).await,
        "seal_listSnapshots" => handle_list_snapshots(&state, &req.params).await,
        "seal_getSnapshotManifest" => handle_get_snapshot_manifest(&state, &req.params).await,
        "seal_getSnapshotChunk" => handle_get_snapshot_chunk(&state, &req.params).await,
        "seal_getNodeInfo" => handle_get_node_info(&state).await,

        // Private tables
        "seal_createPrivateTable" => {
            handle_create_private_table(&state, &req.params, caller_addr.unwrap_or("anonymous"))
                .await
        }
        "seal_listPrivateTables" => handle_list_private_tables(&state).await,
        "seal_listPrivateTablesByOwner" => {
            handle_list_private_tables_by_owner(&state, &req.params).await
        }
        "seal_listLeases" => handle_list_leases(&state, &req.params).await,
        "seal_listLeasesByOwner" => handle_list_leases_by_owner(&state, &req.params).await,

        // MPC / ZK (auth optional but recommended)
        "seal_mpcAggregate" => {
            handle_mpc_aggregate(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_zkProve" => {
            handle_zk_prove(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }

        // Token operations
        "seal_getBalance" => handle_get_balance(&state, &req.params).await,
        "seal_faucet" => handle_faucet(&state, &req.params).await,
        "seal_transfer" => {
            handle_transfer(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_createToken" => {
            handle_create_token(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_mintToken" => {
            handle_mint_token(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_transferToken" => {
            handle_transfer_token(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_burnToken" => {
            handle_burn_token(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_freezeAccount" => {
            handle_freeze_account(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_unfreezeAccount" => {
            handle_unfreeze_account(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_isFrozen" => handle_is_frozen(&state, &req.params).await,
        "seal_listFrozenAccounts" => handle_list_frozen_accounts(&state, &req.params).await,
        "seal_listFrozenSymbolsForAddress" => {
            handle_list_frozen_symbols_for_address(&state, &req.params).await
        }
        "seal_setTokenFrozen" => {
            handle_set_token_frozen(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_setMintAuthority" => {
            handle_set_authority(
                &state,
                &req.params,
                caller_addr.unwrap_or("anonymous"),
                Authority::Mint,
            )
            .await
        }
        "seal_setFreezeAuthority" => {
            handle_set_authority(
                &state,
                &req.params,
                caller_addr.unwrap_or("anonymous"),
                Authority::Freeze,
            )
            .await
        }
        "seal_setFeeAuthority" => {
            handle_set_authority(
                &state,
                &req.params,
                caller_addr.unwrap_or("anonymous"),
                Authority::Fee,
            )
            .await
        }
        "seal_renounceMintAuthority" => {
            handle_renounce_authority(
                &state,
                &req.params,
                caller_addr.unwrap_or("anonymous"),
                Authority::Mint,
            )
            .await
        }
        "seal_renounceFreezeAuthority" => {
            handle_renounce_authority(
                &state,
                &req.params,
                caller_addr.unwrap_or("anonymous"),
                Authority::Freeze,
            )
            .await
        }
        "seal_renounceFeeAuthority" => {
            handle_renounce_authority(
                &state,
                &req.params,
                caller_addr.unwrap_or("anonymous"),
                Authority::Fee,
            )
            .await
        }
        "seal_getTokenBalance" => handle_get_token_balance(&state, &req.params).await,
        "seal_getToken" => handle_get_token(&state, &req.params).await,
        "seal_listTokens" => handle_list_tokens(&state).await,
        "seal_listTokensByCreator" => handle_list_tokens_by_creator(&state, &req.params).await,
        "seal_listTokensByMintAuthority" => {
            handle_list_tokens_by_mint_authority(&state, &req.params).await
        }
        "seal_listTokensByFreezeAuthority" => {
            handle_list_tokens_by_freeze_authority(&state, &req.params).await
        }
        "seal_listTokensByFeeAuthority" => {
            handle_list_tokens_by_fee_authority(&state, &req.params).await
        }
        "seal_setTransferFee" => {
            handle_set_transfer_fee(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_setFeeRecipient" => {
            handle_set_fee_recipient(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_getTransferFee" => handle_get_transfer_fee(&state, &req.params).await,

        // DEX
        "seal_createPair" => {
            handle_create_pair(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_placeOrder" => {
            handle_place_order(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_cancelOrder" => handle_cancel_order(&state, &req.params).await,
        "seal_getOrderBook" => handle_get_order_book(&state, &req.params).await,
        "seal_listPairs" => handle_list_pairs(&state).await,
        "seal_listTrades" => handle_list_trades(&state, &req.params).await,
        "seal_listOrdersByOwner" => handle_list_orders_by_owner(&state, &req.params).await,
        "seal_listTradesByOwner" => handle_list_trades_by_owner(&state, &req.params).await,

        // PQ transport
        "seal_pqHandshake" => handle_pq_handshake(&state, &req.params).await,

        // Cross-chain bridge
        "seal_getBridgeDeposits" => handle_get_bridge_deposits(&state, &req.params).await,
        "seal_listBridgeDepositsByRecipient" => {
            handle_list_bridge_deposits_by_recipient(&state, &req.params).await
        }
        "seal_listBridgeWithdrawals" => handle_list_bridge_withdrawals(&state, &req.params).await,
        "seal_listBridgeWithdrawalsByInitiator" => {
            handle_list_bridge_withdrawals_by_initiator(&state, &req.params).await
        }
        "seal_getBridgeWithdrawal" => handle_get_bridge_withdrawal(&state, &req.params).await,
        "seal_getBridgeStatus" => handle_get_bridge_status(&state).await,
        "seal_getBridgeWrappedBalance" => {
            handle_get_bridge_wrapped_balance(&state, &req.params).await
        }
        "seal_listBridgeWrappedBalances" => {
            handle_list_bridge_wrapped_balances(&state, &req.params).await
        }
        "seal_bridgeWithdraw" => {
            handle_bridge_withdraw(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_bridgeMarkExecuted" => {
            handle_bridge_mark_executed(&state, &req.params, caller_addr.unwrap_or("anonymous"))
                .await
        }
        "seal_addBridgeObserver" => handle_add_bridge_observer(&state, &req.params).await,
        "seal_listBridgeObservers" => handle_list_bridge_observers(&state).await,
        "seal_pollBridges" => handle_poll_bridges(&state).await,

        // Bridge emergency pause (Technical Council 2/3 vote)
        "seal_bridgePauseChain" => handle_bridge_pause_chain(&state, &req.params).await,
        "seal_bridgeUnpauseChain" => handle_bridge_unpause_chain(&state, &req.params).await,
        "seal_bridgeListPaused" => handle_bridge_list_paused(&state).await,
        "seal_bridgeRotateCommitteeKey" => {
            handle_bridge_rotate_committee_key(&state, &req.params).await
        }
        "seal_bridgeGetCommitteeKeyStatus" => handle_bridge_get_committee_key_status(&state).await,
        "seal_bridgeRingtailStatus" => handle_bridge_ringtail_status(&state).await,
        "seal_getBridgeWithdrawalFee" => handle_get_bridge_withdrawal_fee(&state).await,
        "seal_listAdminAddresses" => handle_list_admin_addresses(&state).await,
        "seal_bridgeCouncilAdd" => handle_bridge_council_add(&state, &req.params).await,
        "seal_bridgeCouncilRemove" => handle_bridge_council_remove(&state, &req.params).await,
        "seal_bridgeCouncilList" => handle_bridge_council_list(&state).await,
        "seal_getCouncilMemberByAddress" => {
            handle_get_council_member_by_address(&state, &req.params).await
        }

        // Governance: 6 proposal tracks + conviction voting + delegation.
        "seal_govPropose" => {
            handle_gov_propose(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_govVote" => {
            handle_gov_vote(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_govWithdrawVote" => {
            handle_gov_withdraw_vote(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_govTally" => handle_gov_tally(&state, &req.params).await,
        "seal_govExecute" => handle_gov_execute(&state, &req.params).await,
        "seal_govGetProposal" => handle_gov_get_proposal(&state, &req.params).await,
        "seal_govListProposals" => handle_gov_list_proposals(&state).await,
        "seal_govGetVotes" => handle_gov_get_votes(&state, &req.params).await,
        "seal_govDelegate" => {
            handle_gov_delegate(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_govRevokeDelegation" => {
            handle_gov_revoke_delegation(&state, &req.params, caller_addr.unwrap_or("anonymous"))
                .await
        }
        "seal_govEffectiveWeight" => handle_gov_effective_weight(&state, &req.params).await,
        "seal_govListProposalsByProposer" => {
            handle_gov_list_proposals_by_proposer(&state, &req.params).await
        }
        "seal_govListVotesByVoter" => handle_gov_list_votes_by_voter(&state, &req.params).await,
        "seal_govListLocksByVoter" => handle_gov_list_locks_by_voter(&state, &req.params).await,
        "seal_govListDelegationsFrom" => {
            handle_gov_list_delegations_from(&state, &req.params).await
        }
        "seal_govListDelegationsTo" => handle_gov_list_delegations_to(&state, &req.params).await,

        _ => Err((-32601, format!("method not found: {}", req.method))),
    };

    match response {
        Ok(result) => (StatusCode::OK, Json(RpcResponse::ok(id, result))),
        Err((code, msg)) => (StatusCode::OK, Json(RpcResponse::err(id, code as i64, msg))),
    }
}

// ─── SQL Handlers ───────────────────────────────────

async fn handle_submit_sql(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let sql = params
        .get("sql")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'sql' param".into()))?;

    let namespace = params.get("namespace").and_then(|v| v.as_str());

    // Check namespace routing
    if let Some(ns) = namespace {
        if !state.config.served_namespaces.is_empty()
            && !state.config.served_namespaces.contains(ns)
        {
            return Err((
                -32004,
                format!("namespace '{}' not served by this node", ns),
            ));
        }
    }

    let mut node = state.node.lock().await;
    // Namespace-scoped path: routes through `AppNamespace::execute_as`,
    // which evaluates RLS policies (including HAS_TOKEN) against the
    // caller. Falls through to the bare engine for unscoped SQL.
    let result = match namespace {
        Some(ns) => node
            .runner
            .submit_sql_in_namespace(ns, sql, caller)
            .map_err(|e| (-32000, format!("SQL error: {}", e)))?,
        None => node
            .submit_sql(sql)
            .map_err(|e| (-32000, format!("SQL error: {}", e)))?,
    };
    Ok(serde_json::json!({
        "rows_affected": result.rows_affected,
        "columns": result.columns,
        "rows": result.rows.iter().map(|r| &r.values).collect::<Vec<_>>(),
        "sender": caller,
    }))
}

async fn handle_query_sql(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let sql = params
        .get("sql")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'sql' param".into()))?;

    let namespace = params.get("namespace").and_then(|v| v.as_str());

    // Check namespace routing
    if let Some(ns) = namespace {
        if !state.config.served_namespaces.is_empty()
            && !state.config.served_namespaces.contains(ns)
        {
            return Err((
                -32004,
                format!("namespace '{}' not served by this node", ns),
            ));
        }
    }

    let mut node = state.node.lock().await;
    let result = match namespace {
        Some(ns) => node
            .runner
            .submit_sql_in_namespace(ns, sql, caller)
            .map_err(|e| (-32000, format!("SQL error: {}", e)))?,
        None => node
            .query_sql(sql)
            .map_err(|e| (-32000, format!("SQL error: {}", e)))?,
    };
    Ok(serde_json::json!({
        "columns": result.columns,
        "rows": result.rows.iter().map(|r| &r.values).collect::<Vec<_>>(),
        "caller": caller,
    }))
}

// ─── Namespace Handlers ─────────────────────────────

async fn handle_deploy_namespace(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'name' param".into()))?;
    let schema = params
        .get("schema")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'schema' param".into()))?;
    let visibility = params
        .get("visibility")
        .and_then(|v| v.as_str())
        .unwrap_or("private");
    let replication = params
        .get("replication")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);

    // Persist namespace to on-chain state via transaction
    let entry = NamespaceEntry {
        name: name.to_string(),
        owner: caller.to_string(),
        schema_hash: hex::encode(sha3_256(schema.as_bytes()).0),
        visibility: visibility.to_string(),
        replication,
    };
    {
        let mut ns = state.namespaces.lock().await;
        // Prevent duplicate registration
        if ns.iter().any(|e| e.name == name) {
            return Err((-32602, format!("namespace '{}' already exists", name)));
        }
        ns.push(entry.clone());
    }
    // Deploy into the runner's namespace registry (RLS-enabled scoped
    // engine) AND submit the schema bytes as a CreateApp transaction
    // so the deploy is visible to peers and replayed from history.
    {
        let mut node = state.node.lock().await;
        node.runner
            .deploy_namespace(name.to_string(), caller.to_string(), schema)
            .map_err(|e| (-32000, format!("namespace deploy failed: {}", e)))?;
        let _ = node.runner.submit_transaction(
            seal_storage::block_store::TxType::CreateApp,
            format!("{}\n{}", name, schema).into_bytes(),
        );
    }
    Ok(serde_json::json!({
        "namespace": entry.name,
        "owner": entry.owner,
        "schema_hash": entry.schema_hash,
        "visibility": entry.visibility,
        "replication": entry.replication,
        "status": "deployed",
    }))
}

async fn handle_get_namespaces(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let ns = state.namespaces.lock().await;
    Ok(serde_json::json!({
        "namespaces": *ns,
    }))
}

/// `seal_listNamespacesByOwner`: every registered namespace
/// whose `owner` field matches `address`. Per-owner gap-closer
/// completing the namespace surface alongside the
/// `seal_listTokensByCreator` / `seal_listPrivateTablesByOwner`
/// / `seal_listLeasesByOwner` cluster. Until this RPC any
/// caller asking "which namespaces have I deployed?" pulled the
/// full `seal_getNamespaces` set and filtered client-side. The
/// owner is set at `seal_deployNamespace` time and never
/// rotates today, so the view is lifetime-stable. Sorted
/// lexicographically by namespace name for diff-stable polling.
/// Empty list for addresses that have deployed no namespaces.
async fn handle_list_namespaces_by_owner(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let ns = state.namespaces.lock().await;
    let mut filtered: Vec<&NamespaceEntry> = ns.iter().filter(|e| e.owner == address).collect();
    filtered.sort_by(|a, b| a.name.cmp(&b.name));
    let namespaces: Vec<serde_json::Value> = filtered
        .iter()
        .map(|e| {
            serde_json::json!({
                "name": e.name,
                "owner": e.owner,
                "schema_hash": e.schema_hash,
                "visibility": e.visibility,
                "replication": e.replication,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "namespaces": namespaces,
        "count": namespaces.len(),
    }))
}

/// `seal_listValidators`: snapshot of the active validator set.
/// Unsigned read — the only operator visibility before this was
/// the `validators: <count>` field on /status. Returns each
/// validator's public-key hex, VRF public-key hex, stake, and
/// active flag, plus the total_stake aggregate. Inactive
/// validators (slashed / unbonding) are included so callers can
/// see the full set; filter client-side if you only want active.
async fn handle_list_validators(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let node = state.node.lock().await;
    let vs = &node.runner.validator_set;
    let validators: Vec<serde_json::Value> = vs
        .validators
        .iter()
        .map(|v| {
            serde_json::json!({
                "public_key_hex": hex::encode(&v.public_key),
                "vrf_public_key_hex": hex::encode(&v.vrf_public_key),
                "stake": v.stake,
                "active": v.active,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "validators": validators,
        "active_count": vs.active_count(),
        "total_stake": vs.total_stake,
        "total_count": vs.validators.len(),
    }))
}

/// `seal_getValidatorByAddress`: per-address validator-status
/// lookup. Until this RPC, a wallet asking "am I a validator?"
/// pulled the full `seal_listValidators` set and ran
/// `SHA3-256(public_key_hex) == address_hash` client-side. New
/// `ValidatorSet::find_by_address_hash` does the same scan
/// server-side. Returns the validator's pubkey hex / VRF pubkey
/// hex / stake / active flag, or `validator: null` if the address
/// is not in the set. Unsigned read; the underlying state is
/// already publicly visible via `seal_listValidators`.
async fn handle_get_validator_by_address(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let parsed = SealAddress::from_string_encoding(address)
        .map_err(|e| (-32602, format!("invalid 'address': {e}")))?;
    let addr_hash: [u8; 32] = *parsed.as_bytes();
    let node = state.node.lock().await;
    let vs = &node.runner.validator_set;
    let validator = vs.find_by_address_hash(&addr_hash).map(|v| {
        serde_json::json!({
            "public_key_hex": hex::encode(&v.public_key),
            "vrf_public_key_hex": hex::encode(&v.vrf_public_key),
            "stake": v.stake,
            "active": v.active,
        })
    });
    Ok(serde_json::json!({
        "address": address,
        "validator": validator,
    }))
}

/// `seal_listSnapshots`: read-only roster of recent state snapshots.
///
/// Captured at every epoch boundary by `ConsensusRunner::advance_slot`
/// — see `crates/seal-node/src/consensus_runner.rs` and
/// `crates/seal-storage/src/snapshot_index.rs`. Late-joining
/// validators hit this endpoint first to pick a base from which to
/// fetch chunks via `seal_getSnapshotManifest` (A2b) and
/// `seal_getSnapshotChunk` (A2c). Explorer / wallet clients use it
/// to surface "where the chain has been recently".
///
/// Optional `limit` param caps the response size client-side: e.g.
/// `{ "limit": 5 }` returns at most the 5 newest snapshots. Without
/// `limit`, all retained entries are returned (default cap = 32).
/// Snapshots are returned newest-first so callers reaching for "the
/// freshest one to bootstrap from" don't have to reverse the list.
///
/// Unsigned read — the underlying state roots are already public via
/// `seal_getStateRoot`.
async fn handle_list_snapshots(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let limit = params
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize);
    let node = state.node.lock().await;
    // Clone the bounded roster (default cap = 32) so we can drop the
    // runner lock before allocating the JSON. The roster is small —
    // the clone cost is negligible compared to holding the lock
    // across `serde_json::to_string`.
    let entries: Vec<seal_storage::SnapshotMeta> = node.runner.snapshots.list().to_vec();
    drop(node);
    // Newest-first: the late-joiner heuristic is to take the first
    // returned entry, so flipping the slice here saves every caller a
    // reverse iteration.
    let total = entries.len();
    let snapshots: Vec<serde_json::Value> = entries
        .iter()
        .rev()
        .take(limit.unwrap_or(usize::MAX))
        .map(|m| {
            let mut obj = serde_json::json!({
                "height": m.height,
                "epoch": m.epoch,
                "state_root_hex": hex::encode(m.state_root.0),
                "captured_at_unix_secs": m.captured_at_unix_secs,
            });
            // Tip aggregate is filled by A2b; include only when
            // present so the response shape doesn't lie about
            // attestation availability for A2a-only nodes.
            if let Some(agg) = m.tip_aggregate {
                obj["tip_aggregate_hex"] = serde_json::Value::String(hex::encode(agg.0));
            }
            obj
        })
        .collect();
    Ok(serde_json::json!({
        "snapshots": snapshots,
        "count": snapshots.len(),
        "total_retained": total,
    }))
}

/// `seal_getSnapshotManifest`: full chunk-list manifest for one
/// snapshot in the roster.
///
/// Returns `{ height, epoch, state_root_hex, tip_block_hash_hex,
/// tip_aggregate_hex, total_bytes, manifest_hash_hex,
/// chunks: [{ index, chunk_hash_hex, byte_size }, ...] }`. The
/// caller's flow is:
///
///   1. Pick a `(height, state_root)` from `seal_listSnapshots`.
///   2. Call this RPC with the chosen `height`.
///   3. Spot-check `state_root_hex` against the value from step 1.
///   4. For each chunk, pull bytes via `seal_getSnapshotChunk` (A2c);
///      re-hash and verify against `chunk_hash_hex`.
///
/// **Refuses pruned manifests** (per the plan): if the snapshot is
/// no longer in the roster (evicted by cap) or its `state_root` no
/// longer matches the live state (the host has moved on past the
/// snapshot point), this RPC returns an error rather than serving
/// a manifest that can't be reproduced. Late-joiners detect this
/// and fall back to a fresher snapshot from the roster.
///
/// Manifest source-of-truth in the prototype runner is the live
/// `BalanceStore` HAMT — that's the canonical state surface a
/// late-joiner needs to reach the snapshot's `state_root`. Once
/// the token-state HAMT is wired into the snapshot stream as a
/// second source, this handler will emit two top-level chunk lists
/// (or a single concatenation, depending on what
/// `seal_getSnapshotChunk` ends up paginating over).
async fn handle_get_snapshot_manifest(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let height = params
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'height' param".into()))?;

    let node = state.node.lock().await;
    // Look up the snapshot in the roster. `find_by_height` is a
    // linear scan over the bounded ring (default cap = 32), so this
    // is fast.
    let meta = node
        .runner
        .snapshots
        .find_by_height(height)
        .cloned()
        .ok_or((
            -32004,
            format!("snapshot at height {height} not retained (pruned or never captured)"),
        ))?;
    // Refuse stale manifests: if the live state has moved past the
    // snapshot point, the live HAMT no longer reproduces this
    // snapshot's root. Operationally, this only happens when the
    // caller raced an epoch boundary — they should re-list and pick
    // a fresher entry.
    let live_state_root = node.runner.balances.state_root_hash();
    if live_state_root != meta.state_root {
        return Err((
            -32005,
            format!(
                "snapshot at height {height} has been pruned: live state_root {} no longer matches snapshot state_root {}",
                hex::encode(live_state_root.0),
                hex::encode(meta.state_root.0)
            ),
        ));
    }
    // Tip block hash: header hash of the block at the snapshot's
    // height. With pruning, the block may have been retired from
    // the in-memory chain — guard against that and surface "block
    // pruned" rather than panic.
    let tip_block_header_hash = node
        .runner
        .chain
        .iter()
        .find(|fb| fb.block.header.height == height)
        .map(|fb| {
            let header_bytes = bincode::serialize(&fb.block.header).unwrap_or_default();
            seal_crypto::hash::sha3_256(&header_bytes)
        });
    let tip_block_header_hash = tip_block_header_hash.ok_or((
        -32006,
        format!("block at height {height} not in memory; can't build tip header hash"),
    ))?;

    // Build chunks deterministically. The `BalanceStore::snapshot_dump`
    // contract sorts entries by key, so the chunker just preserves
    // that order.
    let entries = node.runner.balances.snapshot_dump();
    drop(node);

    let chunks = seal_storage::chunk_entries(entries);
    let (chunk_refs, total_bytes) = seal_storage::manifest_from_chunks(&chunks);
    let manifest_hash = seal_storage::manifest_fingerprint(&chunk_refs);

    let chunks_json: Vec<serde_json::Value> = chunk_refs
        .iter()
        .map(|r| {
            serde_json::json!({
                "index": r.index,
                "chunk_hash_hex": hex::encode(r.chunk_hash.0),
                "byte_size": r.byte_size,
            })
        })
        .collect();

    let mut out = serde_json::json!({
        "height": meta.height,
        "epoch": meta.epoch,
        "state_root_hex": hex::encode(meta.state_root.0),
        "tip_block_hash_hex": hex::encode(tip_block_header_hash.0),
        "manifest_hash_hex": hex::encode(manifest_hash.0),
        "total_bytes": total_bytes,
        "chunk_count": chunks_json.len(),
        "chunks": chunks_json,
    });
    if let Some(agg) = meta.tip_aggregate {
        out["tip_aggregate_hex"] = serde_json::Value::String(hex::encode(agg.0));
    }
    Ok(out)
}

/// `seal_getSnapshotChunk`: fetch one chunk of a snapshot's encoded
/// state stream by `(height, chunk_index)`.
///
/// Returns `{ height, chunk_index, byte_size, chunk_hash_hex,
/// bytes_b64 }`. The caller is expected to:
///
///   1. Pull the manifest first via `seal_getSnapshotManifest` to
///      learn the chunk count + each chunk's expected hash.
///   2. Iterate `chunk_index = 0..chunk_count`, calling this RPC.
///   3. Re-hash each fetched payload with SHA3-256 and check
///      against the manifest's `chunk_hash_hex`. A mismatch means
///      the host has moved on past the snapshot point (rare race)
///      and the caller should re-fetch the manifest from a fresher
///      snapshot.
///   4. Concatenate the chunk bytes in index order to reconstruct
///      the snapshot stream, then decode the
///      `(key_len:u32 LE)(value_len:u32 LE)(key)(value)` records
///      into HAMT leaves to seed the local `BalanceStore`.
///
/// Wire format details live in `crates/seal-storage/src/snapshot_chunks.rs`
/// (the source of truth for both the chunker and the upcoming
/// late-joiner stream-decoder in A2d).
///
/// Hard 4 MiB cap per chunk (matches `MAX_CHUNK_BYTES`); base64
/// encoding adds ~33% transit overhead — well within HTTP
/// acceptable. The same pruned-manifest error codes from A2b apply
/// (`-32004` / `-32005` / `-32006`) plus `-32007` for an
/// out-of-range `chunk_index`.
async fn handle_get_snapshot_chunk(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let height = params
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'height' param".into()))?;
    let chunk_index = params
        .get("chunk_index")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'chunk_index' param".into()))? as u32;

    let node = state.node.lock().await;
    let meta = node
        .runner
        .snapshots
        .find_by_height(height)
        .cloned()
        .ok_or((
            -32004,
            format!("snapshot at height {height} not retained (pruned or never captured)"),
        ))?;
    let live_state_root = node.runner.balances.state_root_hash();
    if live_state_root != meta.state_root {
        return Err((
            -32005,
            format!(
                "snapshot at height {height} has been pruned: live state_root {} no longer matches snapshot state_root {}",
                hex::encode(live_state_root.0),
                hex::encode(meta.state_root.0)
            ),
        ));
    }
    let entries = node.runner.balances.snapshot_dump();
    drop(node);

    let chunks = seal_storage::chunk_entries(entries);
    let target = chunks.get(chunk_index as usize).ok_or((
        -32007,
        format!(
            "chunk_index {} out of range (snapshot has {} chunks)",
            chunk_index,
            chunks.len()
        ),
    ))?;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let bytes_b64 = STANDARD.encode(&target.bytes);
    Ok(serde_json::json!({
        "height": height,
        "chunk_index": target.r#ref.index,
        "byte_size": target.r#ref.byte_size,
        "chunk_hash_hex": hex::encode(target.r#ref.chunk_hash.0),
        "bytes_b64": bytes_b64,
    }))
}

// ─── Chain State Handlers ───────────────────────────

async fn handle_get_height(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let node = state.node.lock().await;
    Ok(serde_json::json!({ "height": node.height() }))
}

async fn handle_get_state_root(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let node = state.node.lock().await;
    // Constituent roots so external observers can pinpoint which
    // half of the combined state diverged when two nodes disagree.
    // The combined `state_root` is what block headers carry.
    let combined = node.state_root().to_string();
    let balance_root = hex::encode(node.runner.balances.state_root_hash().0);
    drop(node);
    let token_root = hex::encode(state.token_manager.lock().await.state_root_hash().0);
    Ok(serde_json::json!({
        "state_root": combined,
        "components": {
            "balance_root_hex": balance_root,
            "token_root_hex": token_root,
        },
    }))
}

async fn handle_get_block(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let height = params
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'height' param".into()))?;

    let node = state.node.lock().await;
    let chain = node.get_chain();
    let block = chain
        .iter()
        .find(|b| b.header.height == height)
        .ok_or((-32001, format!("block {} not found", height)))?;

    Ok(serde_json::json!({
        "height": block.header.height,
        "parent_hash": block.header.parent_hash.to_string(),
        "state_root": block.header.state_root.to_string(),
        "timestamp": block.header.timestamp,
        "tx_count": block.transactions.len(),
    }))
}

async fn handle_get_peers(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let node = state.node.lock().await;
    Ok(serde_json::json!({
        "received_blocks": node.received_block_count(),
    }))
}

// ─── MPC / ZK Handlers ─────────────────────────────

async fn handle_mpc_aggregate(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let function = params
        .get("function")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'function' param (sum, count, avg)".into()))?;
    let table = params
        .get("table")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'table' param".into()))?;
    let column = params
        .get("column")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'column' param".into()))?;

    // Execute SQL to get the column values, then compute locally.
    // In production, this would use SPDZ protocol across multiple nodes.
    let sql = match function {
        "sum" => format!("SELECT {} FROM {}", column, table),
        "count" => format!("SELECT {} FROM {}", column, table),
        "avg" => format!("SELECT {} FROM {}", column, table),
        _ => return Err((-32602, format!("unsupported function: {}", function))),
    };

    let mut node = state.node.lock().await;
    let result = node
        .query_sql(&sql)
        .map_err(|e| (-32000, format!("SQL error: {}", e)))?;

    // Extract numeric values from the column
    let values: Vec<i64> = result
        .rows
        .iter()
        .filter_map(|row| {
            row.values.iter().find_map(|v| match v {
                seal_sql::types::SealValue::BigInt(n) => Some(*n),
                seal_sql::types::SealValue::Integer(n) => Some(*n as i64),
                seal_sql::types::SealValue::SmallInt(n) => Some(*n as i64),
                _ => None,
            })
        })
        .collect();

    let (agg_result, count) = match function {
        "sum" => (values.iter().sum::<i64>(), values.len()),
        "count" => (values.len() as i64, values.len()),
        "avg" => {
            if values.is_empty() {
                (0, 0)
            } else {
                (
                    values.iter().sum::<i64>() / values.len() as i64,
                    values.len(),
                )
            }
        }
        _ => unreachable!(),
    };

    // Also compute via SPDZ to demonstrate the protocol
    let spdz_result = if !values.is_empty() && function == "sum" {
        use seal_mpc::spdz::{spdz_sum, SpdzParty};
        let party = SpdzParty::new(0, 42, 1, b"seal-mpc-seed");
        let shares: Vec<_> = values
            .iter()
            .map(|v| {
                let (s1, _s2) = party.share_value(*v as u64, 0);
                s1
            })
            .collect();
        let sum_share = spdz_sum(&party, &shares);
        Some(sum_share.value)
    } else {
        None
    };

    Ok(serde_json::json!({
        "function": function,
        "table": table,
        "column": column,
        "result": agg_result,
        "row_count": count,
        "protocol": if spdz_result.is_some() { "spdz" } else { "local" },
        "spdz_share": spdz_result,
        "caller": caller,
    }))
}

async fn handle_zk_prove(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let statement = params
        .get("statement")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'statement' param".into()))?;
    let table = params
        .get("table")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'table' param".into()))?;

    // Parse simple statements like "balance > 1000" or "count > 0"
    let node = state.node.lock().await;
    let state_root = node.state_root().to_string();
    let height = node.height();
    drop(node);

    // Generate a proof commitment: SHA3(statement || state_root || height)
    let proof_input = format!("{}:{}:{}", statement, state_root, height);
    let proof_hash = sha3_256(proof_input.as_bytes());

    // Execute the statement as SQL to get the actual result
    // e.g., "balance > 1000" → SELECT COUNT(*) FROM table WHERE balance > 1000
    let check_sql = format!("SELECT * FROM {} WHERE {}", table, statement);
    let mut node = state.node.lock().await;
    let satisfied = match node.query_sql(&check_sql) {
        Ok(result) => !result.rows.is_empty(),
        Err(_) => false,
    };

    // Generate a ZK proof using the stub prover (wraps into ZkProof structure)
    use seal_zk::stub::StubProver;
    use seal_zk::traits::{StateTransition, ZkProver};

    let pre_root = sha3_256(format!("pre:{}:{}", table, statement).as_bytes());
    let post_root = sha3_256(format!("post:{}:{}:{}", table, statement, satisfied).as_bytes());
    let transition = StateTransition {
        pre_state_root: pre_root,
        post_state_root: post_root,
        block_height: height,
        tx_count: 1,
        tx_hash: proof_hash,
    };

    let prover = StubProver;
    let zk_proof = prover
        .prove(transition)
        .map_err(|e| (-32000, format!("proof generation failed: {}", e)))?;

    Ok(serde_json::json!({
        "statement": statement,
        "table": table,
        "satisfied": satisfied,
        "proof": hex::encode(&zk_proof.bytes),
        "proof_size": zk_proof.size(),
        "state_root": state_root,
        "block_height": height,
        "prover": "stub (SHA3 commitment — production: STARK via RISC Zero or SP1)",
        "caller": caller,
    }))
}

// ─── Private Table Handlers ─────────────────────────

async fn handle_create_private_table(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'name' param".into()))?;
    let schema = params
        .get("schema")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'schema' param".into()))?;
    let table_type = match params.get("type").and_then(|v| v.as_str()).unwrap_or("app") {
        "user" => PrivateTableType::UserPrivate,
        "regulated" => PrivateTableType::RegulatedPrivate,
        _ => PrivateTableType::AppPrivate,
    };

    let mut mgr = state.private_tables.lock().await;
    let meta = mgr.register(name.to_string(), caller.to_string(), table_type, schema);

    Ok(serde_json::json!({
        "name": meta.name,
        "owner": meta.owner,
        "type": format!("{:?}", meta.table_type),
        "schema_hash": meta.schema_hash.to_string(),
        "status": "created",
    }))
}

async fn handle_list_private_tables(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let mgr = state.private_tables.lock().await;
    let tables: Vec<serde_json::Value> = mgr
        .table_names()
        .iter()
        .filter_map(|name| {
            mgr.get_meta(name).map(|m| {
                serde_json::json!({
                    "name": m.name,
                    "owner": m.owner,
                    "type": format!("{:?}", m.table_type),
                    "row_count": m.row_count,
                })
            })
        })
        .collect();

    Ok(serde_json::json!({ "tables": tables }))
}

/// `seal_listPrivateTablesByOwner`: every private table whose
/// `owner` field matches `address`. Per-owner enumeration
/// paralleling `seal_listTokensByCreator`. Until this RPC the
/// only path was `seal_listPrivateTables` + client-side filter,
/// which forces every wallet/explorer to scan the global
/// metadata set. Sorted lexicographically by table name.
/// Empty list for owners with no tables — not an error.
async fn handle_list_private_tables_by_owner(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let mgr = state.private_tables.lock().await;
    let tables: Vec<serde_json::Value> = mgr
        .tables_by_owner(address)
        .iter()
        .map(|m| {
            serde_json::json!({
                "name": m.name,
                "owner": m.owner,
                "type": format!("{:?}", m.table_type),
                "row_count": m.row_count,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "tables": tables,
        "count": tables.len(),
    }))
}

/// `seal_listLeases`: snapshot of every active storage lease.
/// Unsigned read; the only operator surface is the `/metrics`
/// `seal_leases_active` count, which doesn't tell you *which*
/// tables are leased or when they expire. This RPC fills that
/// gap. Owner is emitted as raw verifying-key hex (the lease
/// stores the full ML-DSA pubkey, not the bech32m address);
/// callers comparing to a `seal1...` address derive
/// `SHA3-256(owner_pubkey_hex)` and bech32m-encode. Sorted by
/// table name. Optional `expired_only: true` filters to leases
/// that have expired (paid_through < now) but are still within
/// the grace period.
async fn handle_list_leases(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let expired_only = params
        .get("expired_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let node = state.node.lock().await;
    let now_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        * 1_000_000;
    let leases: Vec<serde_json::Value> = node
        .runner
        .leases
        .all_leases()
        .into_iter()
        .filter(|l| !expired_only || l.is_expired(now_us))
        .map(|l| {
            serde_json::json!({
                "table": l.table,
                "owner_pubkey_hex": hex::encode(&l.owner),
                "paid_through_us": l.paid_through,
                "row_count": l.row_count,
                "byte_size": l.byte_size,
                "rate": l.rate,
                "governance_hold": l.governance_hold,
                "expired": l.is_expired(now_us),
            })
        })
        .collect();
    Ok(serde_json::json!({
        "leases": leases,
        "count": leases.len(),
        "now_us": now_us,
    }))
}

/// `seal_listLeasesByOwner`: every storage lease whose owner
/// derives to the supplied bech32m `address`. The lease stores
/// the raw ML-DSA verifying-key bytes; bech32m encodes
/// `SHA3-256(verifying_key)`. The handler decodes the address
/// to its 32-byte hash form and the manager hashes each lease's
/// pubkey for comparison — testnet/mainnet-agnostic since both
/// encodings of the same key share the same hash. Per-owner
/// gap-closer paralleling the `seal_listTokensByCreator` /
/// `seal_listPrivateTablesByOwner` cluster: until this RPC the
/// only operator surface for "what tables am I paying lease
/// for?" was `seal_listLeases` + manual pubkey-hex matching.
/// Sorted lexicographically by table name. Optional
/// `expired_only: true` filter mirrors `seal_listLeases`.
async fn handle_list_leases_by_owner(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let parsed = SealAddress::from_string_encoding(address)
        .map_err(|e| (-32602, format!("invalid 'address': {e}")))?;
    let address_hash: [u8; 32] = *parsed.as_bytes();
    let expired_only = params
        .get("expired_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let node = state.node.lock().await;
    let now_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        * 1_000_000;
    let leases: Vec<serde_json::Value> = node
        .runner
        .leases
        .leases_by_owner_hash(&address_hash)
        .into_iter()
        .filter(|l| !expired_only || l.is_expired(now_us))
        .map(|l| {
            serde_json::json!({
                "table": l.table,
                "owner_pubkey_hex": hex::encode(&l.owner),
                "paid_through_us": l.paid_through,
                "row_count": l.row_count,
                "byte_size": l.byte_size,
                "rate": l.rate,
                "governance_hold": l.governance_hold,
                "expired": l.is_expired(now_us),
            })
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "leases": leases,
        "count": leases.len(),
        "now_us": now_us,
    }))
}

// ─── Token Handlers ─────────────────────────────────

async fn handle_get_balance(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    SealAddress::from_string_encoding(address)
        .map_err(|e| (-32602, format!("invalid 'address': {e}")))?;
    let node = state.node.lock().await;
    let balance = node.runner.balances.available(address);
    Ok(serde_json::json!({
        "address": address,
        "balance": balance,
        "total_supply": node.runner.balances.total_supply(),
    }))
}

/// Dev-only faucet: mint SEAL to any address with no signature, up to
/// `dev_faucet_cap` per address per rolling 24 h window. Gated on
/// `RpcConfig::dev_faucet`; rejects otherwise so a mainnet node that
/// somehow still carries the method name cannot be drained.
async fn handle_faucet(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    if !state.config.dev_faucet {
        return Err((
            -32601,
            "seal_faucet disabled (start the node with --dev-faucet)".into(),
        ));
    }
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    SealAddress::from_string_encoding(address)
        .map_err(|e| (-32602, format!("invalid 'address': {e}")))?;
    let default_drip: u64 = 100 * 1_000_000_000; // 100 SEAL
    let amount = params
        .get("amount")
        .and_then(|v| v.as_u64())
        .unwrap_or(default_drip);

    // Enforce per-address cap over a 24 h window.
    let cap = state.config.dev_faucet_cap;
    let window = std::time::Duration::from_secs(24 * 60 * 60);
    let now = std::time::Instant::now();
    {
        let mut drips = state.faucet_drips.lock().await;
        let entry = drips.entry(address.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) >= window {
            *entry = (0, now);
        }
        let next_total = entry.0.saturating_add(amount);
        if next_total > cap {
            return Err((
                -32000,
                format!(
                    "faucet cap reached: {} / {} used in current 24h window",
                    entry.0, cap
                ),
            ));
        }
        entry.0 = next_total;
    }

    let mut node = state.node.lock().await;
    node.runner
        .balances
        .mint(address, amount)
        .map_err(|e| (-32000, format!("mint failed: {e}")))?;
    let new_balance = node.runner.balances.available(address);
    Ok(serde_json::json!({
        "address": address,
        "amount": amount,
        "balance": new_balance,
        "status": "minted",
    }))
}

async fn handle_transfer(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let to = params
        .get("to")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'to' param".into()))?;
    let amount = params
        .get("amount")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'amount' param".into()))?;

    // Reject malformed recipients before the ledger `entry().or_default()`
    // silently creates a ghost account and burns the funds. `SealAddress`
    // runs the full bech32m check (HRP + checksum + 32-byte payload),
    // so placeholders like "sealt1recipient…" (with an ellipsis) fail here.
    SealAddress::from_string_encoding(to)
        .map_err(|e| (-32602, format!("invalid 'to' address: {e}")))?;

    let mut node = state.node.lock().await;
    let recipient_known = node.runner.balances.has_account(to);
    check_recipient_policy(&state.config, params, recipient_known, to)?;
    check_min_opening_balance(&state.config, recipient_known, amount, to)?;
    node.runner
        .balances
        .transfer(caller, to, amount)
        .map_err(|e| (-32000, format!("transfer failed: {}", e)))?;

    Ok(serde_json::json!({
        "from": caller,
        "to": to,
        "amount": amount,
        "status": "confirmed",
    }))
}

async fn handle_create_token(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'name' param".into()))?;
    let decimals = params.get("decimals").and_then(|v| v.as_u64()).unwrap_or(9) as u8;
    let max_supply = params
        .get("max_supply")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let mut mgr = state.token_manager.lock().await;
    let info = mgr
        .create_token(
            symbol.into(),
            name.into(),
            decimals,
            max_supply,
            caller.into(),
        )
        .map_err(|e| (-32000, format!("{}", e)))?;

    Ok(serde_json::json!({
        "symbol": info.symbol,
        "name": info.name,
        "decimals": info.decimals,
        "max_supply": info.max_supply,
        "creator": info.creator,
        "status": "created",
    }))
}

async fn handle_mint_token(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let to = params
        .get("to")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'to' param".into()))?;
    let amount = params
        .get("amount")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'amount' param".into()))?;
    SealAddress::from_string_encoding(to)
        .map_err(|e| (-32602, format!("invalid 'to' address: {e}")))?;

    let mut mgr = state.token_manager.lock().await;
    mgr.mint(symbol, to, amount, caller)
        .map_err(|e| (-32000, format!("{}", e)))?;

    Ok(serde_json::json!({
        "symbol": symbol,
        "to": to,
        "amount": amount,
        "status": "minted",
    }))
}

async fn handle_transfer_token(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let to = params
        .get("to")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'to' param".into()))?;
    let amount = params
        .get("amount")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'amount' param".into()))?;
    SealAddress::from_string_encoding(to)
        .map_err(|e| (-32602, format!("invalid 'to' address: {e}")))?;

    let mut mgr = state.token_manager.lock().await;
    let recipient_known = mgr.has_token_account(symbol, to);
    check_recipient_policy(&state.config, params, recipient_known, to)?;
    check_min_opening_balance(&state.config, recipient_known, amount, to)?;
    mgr.transfer(symbol, caller, to, amount)
        .map_err(|e| (-32000, format!("{}", e)))?;

    Ok(serde_json::json!({
        "symbol": symbol,
        "from": caller,
        "to": to,
        "amount": amount,
        "status": "transferred",
    }))
}

/// Burn caller-held tokens. Decreases both the caller's per-token
/// balance and the token's `total_supply`. Authority for the burn
/// is "any holder of their own balance" — there's no separate
/// burn-authority concept, the signed `caller` *is* the from-address.
/// (A separate `seal_burnTokenAdmin` for an authority-only burn is
/// trackable as a follow-up but isn't in scope here.)
async fn handle_burn_token(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let amount = params
        .get("amount")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'amount' param".into()))?;
    if amount == 0 {
        return Err((-32602, "amount must be > 0".into()));
    }

    let mut mgr = state.token_manager.lock().await;
    let new_supply = match mgr.get_token(symbol) {
        Some(info) => info.total_supply.saturating_sub(amount),
        None => {
            return Err((
                -32602,
                format!("unknown token '{symbol}' — see seal_listTokens"),
            ))
        }
    };
    mgr.burn(symbol, caller, amount)
        .map_err(|e| (-32000, format!("{}", e)))?;

    Ok(serde_json::json!({
        "symbol": symbol,
        "from": caller,
        "amount": amount,
        "total_supply": new_supply,
        "status": "burned",
    }))
}

/// Freeze an address for a token. Caller must be the token's
/// `freeze_authority` (set at creation; cannot be rotated yet —
/// trackable as a follow-up). Frozen accounts can't initiate
/// transfers; the freeze flag is checked in `TokenManager::transfer`.
async fn handle_freeze_account(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    SealAddress::from_string_encoding(address)
        .map_err(|e| (-32602, format!("invalid 'address': {e}")))?;

    let mut mgr = state.token_manager.lock().await;
    mgr.freeze_account(symbol, address, caller)
        .map_err(|e| (-32000, format!("{}", e)))?;
    Ok(serde_json::json!({
        "symbol": symbol,
        "address": address,
        "status": "frozen",
    }))
}

/// Unfreeze an address for a token. Caller must be the token's
/// `freeze_authority`. No-op (Ok) if the address wasn't frozen —
/// the manager's `unfreeze_account` only errors on auth, not on
/// idempotency.
async fn handle_unfreeze_account(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    SealAddress::from_string_encoding(address)
        .map_err(|e| (-32602, format!("invalid 'address': {e}")))?;

    let mut mgr = state.token_manager.lock().await;
    mgr.unfreeze_account(symbol, address, caller)
        .map_err(|e| (-32000, format!("{}", e)))?;
    Ok(serde_json::json!({
        "symbol": symbol,
        "address": address,
        "status": "unfrozen",
    }))
}

enum Authority {
    Mint,
    Freeze,
    Fee,
}

/// Rotate a token authority (mint or freeze). Caller must be the
/// current holder of the rotation target (matches the manager-level
/// auth gate). The new authority is validated as a Seal address
/// before the manager call so a typo can't quietly orphan the
/// token. Renounce-to-zero is intentionally not supported here —
/// pass an unfundable address if you want to drop the authority,
/// or follow up with a separate `seal_renounce*Authority` RPC.
async fn handle_set_authority(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
    which: Authority,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let new_authority = params
        .get("new_authority")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'new_authority' param".into()))?;
    SealAddress::from_string_encoding(new_authority)
        .map_err(|e| (-32602, format!("invalid 'new_authority': {e}")))?;

    let mut mgr = state.token_manager.lock().await;
    let result = match which {
        Authority::Mint => mgr.set_mint_authority(symbol, new_authority, caller),
        Authority::Freeze => mgr.set_freeze_authority(symbol, new_authority, caller),
        Authority::Fee => mgr.set_fee_authority(symbol, new_authority, caller),
    };
    result.map_err(|e| (-32000, format!("{}", e)))?;

    let kind = match which {
        Authority::Mint => "mint",
        Authority::Freeze => "freeze",
        Authority::Fee => "fee",
    };
    Ok(serde_json::json!({
        "symbol": symbol,
        "authority": kind,
        "new_authority": new_authority,
        "status": "rotated",
    }))
}

/// Irrevocably renounce the mint or freeze authority. Caller must
/// be the current authority. After this call the manager-stored
/// authority is `""`, which no real Seal address can match — every
/// future mint/freeze attempt rejects. There's no inverse.
async fn handle_renounce_authority(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
    which: Authority,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;

    let mut mgr = state.token_manager.lock().await;
    let result = match which {
        Authority::Mint => mgr.renounce_mint_authority(symbol, caller),
        Authority::Freeze => mgr.renounce_freeze_authority(symbol, caller),
        Authority::Fee => mgr.renounce_fee_authority(symbol, caller),
    };
    result.map_err(|e| (-32000, format!("{}", e)))?;

    let kind = match which {
        Authority::Mint => "mint",
        Authority::Freeze => "freeze",
        Authority::Fee => "fee",
    };
    Ok(serde_json::json!({
        "symbol": symbol,
        "authority": kind,
        "status": "renounced",
    }))
}

/// Read whether an address is frozen for a given token. Unsigned —
/// pure read, no auth.
async fn handle_is_frozen(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    SealAddress::from_string_encoding(address)
        .map_err(|e| (-32602, format!("invalid 'address': {e}")))?;
    let mgr = state.token_manager.lock().await;
    Ok(serde_json::json!({
        "symbol": symbol,
        "address": address,
        "frozen": mgr.is_frozen(symbol, address),
    }))
}

/// Set the token-level global freeze flag. When true, every
/// transfer of `symbol` rejects regardless of per-account state —
/// the "kill switch" companion to per-account freeze. Caller must
/// be the token's `freeze_authority`. Idempotent.
async fn handle_set_token_frozen(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let frozen = params
        .get("frozen")
        .and_then(|v| v.as_bool())
        .ok_or((-32602, "missing 'frozen' param (must be JSON bool)".into()))?;
    let mut mgr = state.token_manager.lock().await;
    mgr.set_token_frozen(symbol, frozen, caller)
        .map_err(|e| (-32000, format!("{}", e)))?;
    Ok(serde_json::json!({
        "symbol": symbol,
        "frozen": frozen,
        "status": if frozen { "globally_frozen" } else { "globally_unfrozen" },
    }))
}

/// List every address currently frozen for `symbol`. Unsigned read.
/// Result is sorted lexicographically so a polling client can
/// diff against the previous snapshot. Empty list for unknown
/// tokens (consistent with `is_frozen` returning false in the same
/// case). Capped at `LIST_FROZEN_MAX` entries — the cap is large
/// enough that ops-realistic freeze counts (manual abuse response)
/// never hit it; if a future use case needs more we'll add cursor
/// pagination.
async fn handle_list_frozen_accounts(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    const LIST_FROZEN_MAX: usize = 10_000;
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let mgr = state.token_manager.lock().await;
    let mut frozen = mgr.list_frozen(symbol);
    let total = frozen.len();
    frozen.sort();
    let truncated = total > LIST_FROZEN_MAX;
    if truncated {
        frozen.truncate(LIST_FROZEN_MAX);
    }
    Ok(serde_json::json!({
        "symbol": symbol,
        "frozen": frozen,
        "count": total,
        "truncated": truncated,
    }))
}

/// Snapshot of every token symbol where `address` is currently
/// frozen. Inverse of `seal_listFrozenAccounts` (which scans by
/// symbol). Useful for wallets answering "am I blocked from
/// transferring anywhere?" without iterating every known token.
/// Sorted lexicographically; empty list for unfrozen addresses.
async fn handle_list_frozen_symbols_for_address(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let mgr = state.token_manager.lock().await;
    let symbols = mgr.frozen_symbols_for(address);
    Ok(serde_json::json!({
        "address": address,
        "symbols": symbols,
        "count": symbols.len(),
    }))
}

async fn handle_get_token_balance(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    SealAddress::from_string_encoding(address)
        .map_err(|e| (-32602, format!("invalid 'address': {e}")))?;

    let mgr = state.token_manager.lock().await;
    // Reject unknown tokens explicitly — previously this returned
    // `{balance: 0, total_supply: 0}` for any symbol, making the
    // response indistinguishable from "token exists, address has
    // zero balance". `seal_listTokens` is the authoritative
    // enumeration for what exists.
    let info = mgr.get_token(symbol).ok_or((
        -32602,
        format!("unknown token '{symbol}' — see seal_listTokens"),
    ))?;
    let balance = mgr.balance(symbol, address);

    Ok(serde_json::json!({
        "symbol": symbol,
        "address": address,
        "balance": balance,
        "total_supply": info.total_supply,
    }))
}

/// Read full TokenInfo for one symbol. Same shape as a single
/// element of `seal_listTokens`, including the renounce-aware
/// `mint_authority` / `freeze_authority` fields (null when
/// renounced). Returns `-32602` for unknown symbols — matches
/// the convention from `seal_getTokenBalance`.
async fn handle_get_token(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let mgr = state.token_manager.lock().await;
    let info = mgr.get_token(symbol).ok_or((
        -32602,
        format!("unknown token '{symbol}' — see seal_listTokens"),
    ))?;
    let mint_auth = if info.mint_authority.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(info.mint_authority.clone())
    };
    let freeze_auth = if info.freeze_authority.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(info.freeze_authority.clone())
    };
    let fee_auth = if info.fee_authority.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(info.fee_authority.clone())
    };
    Ok(serde_json::json!({
        "symbol": info.symbol,
        "name": info.name,
        "decimals": info.decimals,
        "total_supply": info.total_supply,
        "max_supply": info.max_supply,
        "creator": info.creator,
        "transfer_fee_bps": info.transfer_fee_bps,
        "fee_recipient": info.fee_recipient,
        "mint_authority": mint_auth,
        "freeze_authority": freeze_auth,
        "fee_authority": fee_auth,
        "frozen": info.frozen,
    }))
}

async fn handle_list_tokens(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let mgr = state.token_manager.lock().await;
    let tokens: Vec<serde_json::Value> = mgr
        .list_tokens()
        .iter()
        .map(|t| {
            // `mint_authority` / `freeze_authority` may be the empty
            // string after a renounce — emit an explicit `null` then so
            // clients can render "renounced" rather than printing an
            // empty bech32m field that looks like a missing key.
            let mint_auth = if t.mint_authority.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(t.mint_authority.clone())
            };
            let freeze_auth = if t.freeze_authority.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(t.freeze_authority.clone())
            };
            let fee_auth = if t.fee_authority.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(t.fee_authority.clone())
            };
            serde_json::json!({
                "symbol": t.symbol,
                "name": t.name,
                "decimals": t.decimals,
                "total_supply": t.total_supply,
                "max_supply": t.max_supply,
                "creator": t.creator,
                "transfer_fee_bps": t.transfer_fee_bps,
                "fee_recipient": t.fee_recipient,
                "mint_authority": mint_auth,
                "freeze_authority": freeze_auth,
                "fee_authority": fee_auth,
                "frozen": t.frozen,
            })
        })
        .collect();
    Ok(serde_json::json!({ "tokens": tokens }))
}

/// `seal_listTokensByCreator`: every token whose immutable
/// `creator` field matches `address`. Per-owner enumeration
/// paralleling `seal_listFrozenSymbolsForAddress`,
/// `seal_listOrdersByOwner`, and the governance per-voter
/// cluster — the natural "what tokens did I create?" question.
/// `creator` is the original deployer and never rotates; the
/// authority-current counterpart is `seal_listTokensByMintAuthority`
/// (covers the post-rotation case where the deployer is no longer
/// in control). Sorted lexicographically by symbol for diff-
/// friendly polling. Empty list for addresses that have never
/// created a token — not an error.
async fn handle_list_tokens_by_creator(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let mgr = state.token_manager.lock().await;
    let tokens: Vec<serde_json::Value> = mgr
        .tokens_by_creator(address)
        .iter()
        .map(|t| {
            let mint_auth = if t.mint_authority.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(t.mint_authority.clone())
            };
            let freeze_auth = if t.freeze_authority.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(t.freeze_authority.clone())
            };
            let fee_auth = if t.fee_authority.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(t.fee_authority.clone())
            };
            serde_json::json!({
                "symbol": t.symbol,
                "name": t.name,
                "decimals": t.decimals,
                "total_supply": t.total_supply,
                "max_supply": t.max_supply,
                "creator": t.creator,
                "transfer_fee_bps": t.transfer_fee_bps,
                "fee_recipient": t.fee_recipient,
                "mint_authority": mint_auth,
                "freeze_authority": freeze_auth,
                "fee_authority": fee_auth,
                "frozen": t.frozen,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "tokens": tokens,
        "count": tokens.len(),
    }))
}

/// `seal_listTokensByMintAuthority`: every token whose **current**
/// `mint_authority` matches `address`. Authority-current
/// counterpart to `seal_listTokensByCreator`: after a
/// `seal_setMintAuthority` rotation the outgoing authority
/// disappears from this view and the incoming one starts
/// appearing. After `seal_renounceMintAuthority` the token stops
/// appearing for any address — no one can mint it. Useful for
/// answering "which tokens can I mint right now?" — a question
/// the creator-view can't answer once authorities have rotated.
/// Sorted lexicographically by symbol. Unsigned read; the
/// underlying state is publicly visible via `seal_listTokens`.
async fn handle_list_tokens_by_mint_authority(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let mgr = state.token_manager.lock().await;
    let tokens: Vec<serde_json::Value> = mgr
        .tokens_by_mint_authority(address)
        .iter()
        .map(|t| {
            let freeze_auth = if t.freeze_authority.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(t.freeze_authority.clone())
            };
            let fee_auth = if t.fee_authority.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(t.fee_authority.clone())
            };
            serde_json::json!({
                "symbol": t.symbol,
                "name": t.name,
                "decimals": t.decimals,
                "total_supply": t.total_supply,
                "max_supply": t.max_supply,
                "creator": t.creator,
                "freeze_authority": freeze_auth,
                "fee_authority": fee_auth,
                "frozen": t.frozen,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "tokens": tokens,
        "count": tokens.len(),
    }))
}

/// `seal_listTokensByFreezeAuthority`: every token whose
/// **current** `freeze_authority` matches `address`. Mirror of
/// `seal_listTokensByMintAuthority` for the freeze-authority
/// surface — answers "which tokens can I freeze right now?".
/// Compliance and operational separation often pair a long-
/// lived deployer/mint authority with a short-lived freeze
/// authority on a dedicated key, so the by-freeze view diverges
/// from the by-mint view independently. Sorted lexicographically
/// by symbol. Unsigned read; the underlying state is publicly
/// visible via `seal_listTokens`.
async fn handle_list_tokens_by_freeze_authority(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let mgr = state.token_manager.lock().await;
    let tokens: Vec<serde_json::Value> = mgr
        .tokens_by_freeze_authority(address)
        .iter()
        .map(|t| {
            let mint_auth = if t.mint_authority.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(t.mint_authority.clone())
            };
            let fee_auth = if t.fee_authority.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(t.fee_authority.clone())
            };
            serde_json::json!({
                "symbol": t.symbol,
                "name": t.name,
                "decimals": t.decimals,
                "total_supply": t.total_supply,
                "max_supply": t.max_supply,
                "creator": t.creator,
                "mint_authority": mint_auth,
                "fee_authority": fee_auth,
                "frozen": t.frozen,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "tokens": tokens,
        "count": tokens.len(),
    }))
}

/// `seal_listTokensByFeeAuthority`: every token whose **current**
/// `fee_authority` matches `address`. Third leg of the
/// authority-current trio (mint / freeze / fee) — answers
/// "which tokens' transfer-fee schedule can I edit right now?".
/// Treasury-style operators sometimes hold the fee-authority key
/// independently of mint and freeze, so this view diverges from
/// both after a `seal_setFeeAuthority` rotation; after
/// `seal_renounceFeeAuthority` the symbol stops appearing for any
/// address (transfer fee is then immutable). Sorted
/// lexicographically by symbol. Unsigned read; the underlying
/// state is publicly visible via `seal_listTokens`.
async fn handle_list_tokens_by_fee_authority(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let mgr = state.token_manager.lock().await;
    let tokens: Vec<serde_json::Value> = mgr
        .tokens_by_fee_authority(address)
        .iter()
        .map(|t| {
            let mint_auth = if t.mint_authority.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(t.mint_authority.clone())
            };
            let freeze_auth = if t.freeze_authority.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(t.freeze_authority.clone())
            };
            serde_json::json!({
                "symbol": t.symbol,
                "name": t.name,
                "decimals": t.decimals,
                "total_supply": t.total_supply,
                "max_supply": t.max_supply,
                "creator": t.creator,
                "mint_authority": mint_auth,
                "freeze_authority": freeze_auth,
                "transfer_fee_bps": t.transfer_fee_bps,
                "frozen": t.frozen,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "tokens": tokens,
        "count": tokens.len(),
    }))
}

/// Set the transfer fee (in basis points, 1 bp = 0.01%) on a custom
/// token. Caller must be the token's current `fee_authority`
/// (defaults to creator on `seal_createToken`, rotateable via
/// `seal_setFeeAuthority`, renounceable via
/// `seal_renounceFeeAuthority`). Range 0..=10000 (0%..=100%).
async fn handle_set_transfer_fee(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let fee_bps = params
        .get("fee_bps")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'fee_bps' param".into()))?;

    let mut mgr = state.token_manager.lock().await;
    mgr.set_transfer_fee(symbol, fee_bps, caller)
        .map_err(|e| (-32000, format!("{}", e)))?;

    Ok(serde_json::json!({
        "symbol": symbol,
        "fee_bps": fee_bps,
        "status": "updated",
    }))
}

/// Update where transfer fees are routed. Caller must be the
/// token's current `fee_authority` — same gate as
/// `seal_setTransferFee`. The new recipient is validated as a
/// Seal address before the manager call so a typo can't silently
/// route fees to a dead address. Empty / null `new_recipient` is
/// rejected at the manager layer.
async fn handle_set_fee_recipient(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let new_recipient = params
        .get("new_recipient")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'new_recipient' param".into()))?;
    SealAddress::from_string_encoding(new_recipient)
        .map_err(|e| (-32602, format!("invalid 'new_recipient': {e}")))?;

    let mut mgr = state.token_manager.lock().await;
    mgr.set_fee_recipient(symbol, new_recipient, caller)
        .map_err(|e| (-32000, format!("{}", e)))?;

    Ok(serde_json::json!({
        "symbol": symbol,
        "new_recipient": new_recipient,
        "status": "updated",
    }))
}

/// Read the current transfer fee for a token. Free query; no auth.
async fn handle_get_transfer_fee(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;

    let mgr = state.token_manager.lock().await;
    let info = mgr
        .get_token(symbol)
        .ok_or((-32000, format!("token '{}' not found", symbol)))?;

    Ok(serde_json::json!({
        "symbol": info.symbol,
        "fee_bps": info.transfer_fee_bps,
    }))
}

// ─── DEX Handlers ───────────────────────────────────

async fn handle_create_pair(
    state: &RpcState,
    params: &serde_json::Value,
    _caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let base = params
        .get("base")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'base' param".into()))?;
    let quote = params
        .get("quote")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'quote' param".into()))?;

    let mut dex = state.dex.lock().await;
    dex.create_pair(base.into(), quote.into())
        .map_err(|e| (-32000, format!("{}", e)))?;

    Ok(serde_json::json!({
        "pair": format!("{}/{}", base, quote),
        "status": "created",
    }))
}

async fn handle_place_order(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let pair = params
        .get("pair")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'pair' param".into()))?;
    let side = match params.get("side").and_then(|v| v.as_str()) {
        Some("bid" | "buy") => seal_token::orderbook::Side::Bid,
        Some("ask" | "sell") => seal_token::orderbook::Side::Ask,
        _ => return Err((-32602, "missing 'side' param (bid/ask)".into())),
    };
    let price = params
        .get("price")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'price' param".into()))?;
    let quantity = params
        .get("quantity")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'quantity' param".into()))?;

    let mut dex = state.dex.lock().await;
    let book = dex
        .get_book_mut(pair)
        .ok_or((-32000, format!("pair '{}' not found", pair)))?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let order_id = book.place_order(
        caller.into(),
        side,
        price,
        quantity,
        seal_token::orderbook::OrderType::Limit,
        timestamp,
    );

    // Auto-match after placing
    let trades = book.match_orders(timestamp);

    Ok(serde_json::json!({
        "order_id": order_id,
        "pair": pair,
        "trades": trades.len(),
        "open_orders": book.open_order_count(),
    }))
}

async fn handle_cancel_order(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let pair = params
        .get("pair")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'pair' param".into()))?;
    let order_id = params
        .get("order_id")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'order_id' param".into()))?;

    let mut dex = state.dex.lock().await;
    let book = dex
        .get_book_mut(pair)
        .ok_or((-32000, format!("pair '{}' not found", pair)))?;
    book.cancel_order(order_id)
        .map_err(|e| (-32000, format!("{}", e)))?;

    Ok(serde_json::json!({ "cancelled": order_id }))
}

async fn handle_get_order_book(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let pair = params
        .get("pair")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'pair' param".into()))?;
    let depth = params.get("depth").and_then(|v| v.as_u64()).unwrap_or(10) as usize;

    let dex = state.dex.lock().await;
    let book = dex
        .get_book(pair)
        .ok_or((-32000, format!("pair '{}' not found", pair)))?;
    let (bids, asks) = book.depth(depth);

    Ok(serde_json::json!({
        "pair": pair,
        "bids": bids.iter().map(|(p, q)| serde_json::json!({"price": p, "quantity": q})).collect::<Vec<_>>(),
        "asks": asks.iter().map(|(p, q)| serde_json::json!({"price": p, "quantity": q})).collect::<Vec<_>>(),
        "last_price": book.pair.last_price,
        "open_orders": book.open_order_count(),
    }))
}

async fn handle_list_pairs(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let dex = state.dex.lock().await;
    let pairs: Vec<serde_json::Value> = dex
        .list_pairs()
        .iter()
        .map(|p| {
            serde_json::json!({
                "pair": format!("{}/{}", p.base, p.quote),
                "last_price": p.last_price,
                "volume_24h": p.volume_24h,
                "trade_count": p.trade_count,
            })
        })
        .collect();
    Ok(serde_json::json!({ "pairs": pairs }))
}

/// Maximum number of trades a single `seal_listTrades` call can
/// return. Larger requests are silently capped to this. The rolling
/// per-book window in `OrderBook::trades` is `MAX_TRADE_HISTORY`
/// (10_000); this cap protects RPC consumers from accidental full
/// dumps.
const LIST_TRADES_MAX_LIMIT: usize = 1000;

/// `seal_listTrades` — paginate over the per-pair rolling trade
/// window. Params:
///
/// - `pair`: required, e.g. "GOLD/SEAL"
/// - `since_id`: optional u64; only trades with `id > since_id` are
///   returned. Default 0 = whole window.
/// - `limit`: optional, default 100, capped at `LIST_TRADES_MAX_LIMIT`.
///
/// Returns trades in chronological (oldest-first) order so a caller
/// polling with `since_id = last_id` gets a forward-stream.
async fn handle_list_trades(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let pair = params
        .get("pair")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'pair' param".into()))?;
    let since_id = params.get("since_id").and_then(|v| v.as_u64()).unwrap_or(0);
    let limit = params
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|n| (n as usize).min(LIST_TRADES_MAX_LIMIT))
        .unwrap_or(100);

    let dex = state.dex.lock().await;
    let trades = dex
        .list_trades_for(pair, since_id, limit)
        .ok_or((-32000, format!("pair '{}' not found", pair)))?;

    let last_id = trades.last().map(|t| t.id).unwrap_or(since_id);
    let json_trades: Vec<serde_json::Value> = trades
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "maker_order_id": t.maker_order_id,
                "taker_order_id": t.taker_order_id,
                "price": t.price,
                "quantity": t.quantity,
                "maker": t.maker,
                "taker": t.taker,
                "side": match t.side {
                    seal_token::orderbook::Side::Bid => "bid",
                    seal_token::orderbook::Side::Ask => "ask",
                },
                "timestamp": t.timestamp,
            })
        })
        .collect();

    Ok(serde_json::json!({
        "pair": pair,
        "trades": json_trades,
        "count": json_trades.len(),
        "last_id": last_id,
    }))
}

/// List every open order belonging to `address` across every
/// trading pair. Unsigned read; the address is a query param,
/// not the signer. Pure aggregation over `DexManager::orders_by_owner`.
/// Sorted by `(pair, order_id)` so polling clients can diff a
/// previous snapshot. Empty list for unknown owners — not an
/// error path. Useful for "what orders do I have open?" UX
/// without scanning every pair.
async fn handle_list_orders_by_owner(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;

    let dex = state.dex.lock().await;
    let orders = dex.orders_by_owner(address);
    let json_orders: Vec<serde_json::Value> = orders
        .iter()
        .map(|(pair, o)| {
            serde_json::json!({
                "pair": pair,
                "id": o.id,
                "side": match o.side {
                    seal_token::orderbook::Side::Bid => "bid",
                    seal_token::orderbook::Side::Ask => "ask",
                },
                "price": o.price,
                "quantity": o.quantity,
                "remaining": o.remaining,
                "timestamp": o.timestamp,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "orders": json_orders,
        "count": json_orders.len(),
    }))
}

/// List every retained trade where `address` was either maker or
/// taker, across every pair. Sorted descending by timestamp so
/// the natural use case ("show my last N fills") is the prefix
/// of the result. Bounded by each pair's `MAX_TRADE_HISTORY`
/// (10 000 entries); older trades are dropped — clients that
/// need full history watch the per-block `TxType::DexMatch`
/// payloads instead. Optional `limit` caps the response.
async fn handle_list_trades_by_owner(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let limit = params
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|n| (n as usize).min(LIST_TRADES_MAX_LIMIT))
        .unwrap_or(100);

    let dex = state.dex.lock().await;
    let mut trades = dex.trades_by_owner(address);
    trades.truncate(limit);
    let json_trades: Vec<serde_json::Value> = trades
        .iter()
        .map(|(pair, t)| {
            serde_json::json!({
                "pair": pair,
                "id": t.id,
                "maker_order_id": t.maker_order_id,
                "taker_order_id": t.taker_order_id,
                "price": t.price,
                "quantity": t.quantity,
                "maker": t.maker,
                "taker": t.taker,
                "side": match t.side {
                    seal_token::orderbook::Side::Bid => "bid",
                    seal_token::orderbook::Side::Ask => "ask",
                },
                "timestamp": t.timestamp,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "trades": json_trades,
        "count": json_trades.len(),
    }))
}

// ─── PQ Transport Handler ───────────────────────────

async fn handle_pq_handshake(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let client_pk = params
        .get("client_public_key")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'client_public_key' param".into()))?;

    let req = crate::pq_rpc::HandshakeRequest {
        client_public_key: client_pk.to_string(),
    };

    match state.pq_rpc.handshake(&req) {
        Ok(resp) => Ok(serde_json::json!({
            "session_id": resp.session_id,
            "ciphertext": resp.ciphertext,
            "server_public_key": resp.server_public_key,
        })),
        Err(e) => Err((-32000, format!("PQ handshake failed: {}", e))),
    }
}

// ─── Bridge Handlers ────────────────────────────────

/// Parse a "chain" string param into a `Chain` enum, case-insensitive.
fn parse_chain(s: &str) -> Result<Chain, (i32, String)> {
    match s.to_ascii_lowercase().as_str() {
        "solana" | "sol" => Ok(Chain::Solana),
        "stellar" | "xlm" => Ok(Chain::Stellar),
        other => Err((-32602, format!("unknown chain: {}", other))),
    }
}

/// Parse a "token" string param into a `WrappedToken`.
fn parse_wrapped_token(s: &str) -> Result<WrappedToken, (i32, String)> {
    match s.to_ascii_uppercase().as_str() {
        "WSOL" | "SOL" => Ok(WrappedToken::WSOL),
        "WXLM" | "XLM" => Ok(WrappedToken::WXLM),
        "WUSDC" | "USDC" => Ok(WrappedToken::WUSDC),
        other => Err((-32602, format!("unknown wrapped token: {}", other))),
    }
}

/// `seal_getBridgeDeposits`: returns all observed deposits, optionally
/// filtered by source chain. Read-only — no auth required.
///
/// Params: `[chain?]` where `chain` is "Solana", "Stellar", or omitted.
async fn handle_get_bridge_deposits(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    // Accept either named ({"chain":"Solana"}) or positional (["Solana"]).
    // Named is the canonical / documented form; positional is kept so the
    // long-standing `bridge-e2e.sh` `'["Solana"]'` invocation keeps working.
    let chain_str = params
        .get("chain")
        .and_then(|v| v.as_str())
        .or_else(|| params.get(0).and_then(|v| v.as_str()));
    let chain_filter = match chain_str {
        Some(c) => Some(parse_chain(c)?),
        None => None,
    };
    let bridge = state.bridge.lock().await;
    let deposits = bridge.list_deposits(chain_filter.as_ref());
    Ok(serde_json::to_value(deposits).unwrap_or(serde_json::json!([])))
}

/// `seal_listBridgeDepositsByRecipient`: every observed deposit
/// targeting `address` as the on-Seal recipient. Per-owner gap-
/// closer paralleling `seal_listBridgeWrappedBalances` (which
/// covers the post-mint side). Until this RPC, a wallet asking
/// "what crossed the bridge to me?" pulled the global
/// `seal_getBridgeDeposits` stream and filtered `seal_address`
/// client-side. Sorted by deposit ID for diff-stable polling.
/// Empty list for recipients with no deposits — not an error.
/// Unsigned read; the underlying state is also publicly visible
/// via `seal_getBridgeDeposits`.
async fn handle_list_bridge_deposits_by_recipient(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let lookup_key = normalize_seal_address_to_hex(address)
        .ok_or((-32602, format!("invalid 'address': {address}")))?;
    let bridge = state.bridge.lock().await;
    let deposits = bridge.list_deposits_by_recipient(&lookup_key);
    Ok(serde_json::json!({
        "address": address,
        "deposits": deposits,
        "count": deposits.len(),
    }))
}

/// `seal_listBridgeWithdrawals`: global list of every withdrawal,
/// optionally filtered by destination chain. Accepts named (`{chain:"Solana"}`)
/// or positional (`["Solana"]`) params; omitting the filter returns
/// every withdrawal on every chain.
///
/// This is the surface operators reach for to find pending claims —
/// each entry carries `nonce` and `committee_signature_hex`, which
/// together with `amount` and `dest_address` are the four arguments
/// `unlock_tokens(amount, nonce, signature)` on the destination chain
/// expects. `committee_signature_hex: null` means "not yet signed";
/// the claim can't proceed until the Ringtail signing pipeline (or
/// the committee-of-1 testnet path) attaches a MAC.
async fn handle_list_bridge_withdrawals(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let chain_str = params
        .get("chain")
        .and_then(|v| v.as_str())
        .or_else(|| params.get(0).and_then(|v| v.as_str()));
    let chain_filter = match chain_str {
        Some(c) => Some(parse_chain(c)?),
        None => None,
    };
    let bridge = state.bridge.lock().await;
    let all = bridge.list_withdrawals();
    let withdrawals: Vec<_> = match chain_filter {
        Some(c) => all.into_iter().filter(|w| w.dest_chain == c).collect(),
        None => all,
    };
    Ok(serde_json::json!({
        "count": withdrawals.len(),
        "withdrawals": withdrawals,
    }))
}

/// `seal_getBridgeWithdrawal`: fetch a single withdrawal record by
/// id. Same envelope as `seal_listBridgeWithdrawals` returns per
/// element. Returns `{withdrawal: null}` if the id isn't recognized
/// (not an error — lets a polling client wait for the record to
/// surface).
async fn handle_get_bridge_withdrawal(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let id = params
        .get("withdrawal_id")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'withdrawal_id' param".into()))?;
    let bridge = state.bridge.lock().await;
    let withdrawal = bridge.get_withdrawal(id);
    Ok(serde_json::json!({
        "withdrawal_id": id,
        "withdrawal": withdrawal,
    }))
}

/// `seal_bridgeMarkExecuted`: flip `executed = true` on the named
/// withdrawal after a validator relayer has confirmed the destination
/// -chain `unlock_*` ix landed.
///
/// Auth model (P1#3 per-validator custody): the request must be
/// signed by an ML-DSA key whose derived address belongs to an
/// active validator. Open-mode (empty validator set during early
/// bootstrap) falls back to "any signed caller" so the alpha-testnet
/// scripts still work; once the set is populated the check tightens.
///
/// Idempotent at the bridge layer: every validator may race to submit
/// the unlock ix and follow with this RPC; only the first call
/// decrements `total_locked`. The response distinguishes the two
/// cases via `was_already_executed` so the relayer log shows whether
/// it raced.
///
/// Params:
///   - `withdrawal_id`: the wd_<chain>_<n> id from
///     seal_bridgeWithdraw / seal_listBridgeWithdrawals.
///   - `dest_chain_tx_hash` (optional, ≤ 128 chars): the destination-
///     chain transaction hash for audit trail. Logged but not
///     persisted to the withdrawal record (operators recover this
///     from chain explorers; adding storage would bloat
///     BridgeWithdrawal across every replica).
async fn handle_bridge_mark_executed(
    state: &RpcState,
    params: &serde_json::Value,
    caller_addr: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let withdrawal_id = params
        .get("withdrawal_id")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'withdrawal_id' param".into()))?;
    let dest_chain_tx_hash = params
        .get("dest_chain_tx_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if let Some(ref h) = dest_chain_tx_hash {
        if h.len() > 128 {
            return Err((
                -32602,
                format!("'dest_chain_tx_hash' too long: {} chars (max 128)", h.len()),
            ));
        }
    }

    // Validator-set membership check. caller_addr is the bech32m
    // `sealt1…` / `seal1…` form the auth layer derived from the
    // request signature. Decode to the 32-byte address hash and look
    // it up in the active validator set; reject if the address is
    // present-but-inactive (slashed / unbonding) or missing entirely.
    // Open-mode (active_count == 0) skips the membership check so
    // the testnet bootstrap path before genesis still works.
    let parsed = SealAddress::from_string_encoding(caller_addr)
        .map_err(|e| (-32602, format!("invalid caller address: {e}")))?;
    let addr_hash: [u8; 32] = *parsed.as_bytes();
    {
        let node = state.node.lock().await;
        let vs = &node.runner.validator_set;
        if vs.active_count() > 0 {
            let active = vs
                .find_by_address_hash(&addr_hash)
                .map(|v| v.active)
                .unwrap_or(false);
            if !active {
                return Err((
                    -32004,
                    format!(
                        "seal_bridgeMarkExecuted requires active validator authorization \
                         (address {} not in active set)",
                        caller_addr
                    ),
                ));
            }
        }
    }

    // Snapshot the prior executed flag so the response can report
    // whether this call mutated or raced. BridgeManager::execute_
    // withdrawal is idempotent, so we don't gate the call on the
    // snapshot — we just look it up first for the response.
    let was_already_executed = {
        let bridge = state.bridge.lock().await;
        bridge.get_withdrawal(withdrawal_id).map(|w| w.executed)
    };
    let was_already_executed = match was_already_executed {
        Some(b) => b,
        None => {
            return Err((-32602, format!("unknown withdrawal_id: {}", withdrawal_id)));
        }
    };

    {
        let mut bridge = state.bridge.lock().await;
        bridge
            .execute_withdrawal(withdrawal_id)
            .map_err(|e| (-32000, format!("execute_withdrawal failed: {:?}", e)))?;
    }

    info!(
        "bridge mark-executed: id={} caller={} was_already_executed={} tx_hash={:?}",
        withdrawal_id, caller_addr, was_already_executed, dest_chain_tx_hash
    );
    Ok(serde_json::json!({
        "withdrawal_id": withdrawal_id,
        "executed": true,
        "was_already_executed": was_already_executed,
        "dest_chain_tx_hash": dest_chain_tx_hash,
    }))
}

/// `seal_listBridgeWithdrawalsByInitiator`: every withdrawal whose
/// burner-on-Seal matches `address`. Per-owner gap-closer mirroring
/// `seal_listBridgeDepositsByRecipient` for the outbound side.
/// Until this RPC, a wallet asking "what did I send out via the
/// bridge?" pulled the global withdrawal stream and filtered
/// `seal_address` client-side. Sorted by withdrawal ID for diff-
/// stable polling. Empty list for initiators with no withdrawals —
/// not an error. Unsigned read; the underlying state is publicly
/// visible (the bridge is a transparent system).
async fn handle_list_bridge_withdrawals_by_initiator(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let lookup_key = normalize_seal_address_to_hex(address)
        .ok_or((-32602, format!("invalid 'address': {address}")))?;
    let bridge = state.bridge.lock().await;
    let withdrawals = bridge.list_withdrawals_by_initiator(&lookup_key);
    Ok(serde_json::json!({
        "address": address,
        "withdrawals": withdrawals,
        "count": withdrawals.len(),
    }))
}

/// `seal_getBridgeStatus`: aggregate view — total locked and minted
/// per wrapped token, plus the invariant check (minted <= locked).
async fn handle_get_bridge_status(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let bridge = state.bridge.lock().await;
    let tokens = [WrappedToken::WSOL, WrappedToken::WXLM, WrappedToken::WUSDC];
    let per_token: Vec<_> = tokens
        .iter()
        .map(|t| {
            serde_json::json!({
                "token": t.symbol(),
                "locked": bridge.total_locked(t),
                "minted": bridge.total_minted(t),
            })
        })
        .collect();
    let paused: Vec<serde_json::Value> = bridge
        .list_paused_chains()
        .into_iter()
        .map(|(c, r)| serde_json::json!({ "chain": c.to_string(), "reason": r }))
        .collect();
    Ok(serde_json::json!({
        "invariant_holds": bridge.check_invariant(),
        "required_confirmations": bridge.required_confirmations,
        "per_token": per_token,
        "paused_chains": paused,
    }))
}

/// Normalize a seal-address input to the 32-byte hex form the bridge
/// manager keys wrapped-balance entries on. Accepts either:
///   - a bech32m `sealt1…` / `seal1…` address — decoded via
///     `SealAddress::from_string_encoding`, then `as_bytes()` →
///     32-byte SHA3-256 of the verifying key → hex
///   - already-hex 64-char input — passed through unchanged
///
/// Returns `None` for malformed input (caller should reject with
/// `-32602`).
fn normalize_seal_address_to_hex(addr: &str) -> Option<String> {
    // Hex round-trip — 64 chars of [0-9a-fA-F].
    if addr.len() == 64 && addr.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(addr.to_ascii_lowercase());
    }
    use seal_crypto::address::SealAddress;
    SealAddress::from_string_encoding(addr)
        .ok()
        .map(|sa| hex::encode(sa.as_bytes()))
}

/// `seal_getBridgeWrappedBalance`: wrapped-token balance for a
/// seal address.
///
/// Params: `{"address": "sealt1…" | "<32-byte-hex>", "token": "WSOL"}`.
/// Either the bech32m form or the raw 32-byte hex form is accepted;
/// the handler normalizes to hex (the form `BridgeManager` keys on).
async fn handle_get_bridge_wrapped_balance(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let lookup_key = normalize_seal_address_to_hex(address)
        .ok_or((-32602, format!("invalid 'address': {address}")))?;
    let token = params
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'token' param".into()))?;
    let token = parse_wrapped_token(token)?;
    let bridge = state.bridge.lock().await;
    let balance = bridge.wrapped_balance(&lookup_key, &token);
    Ok(serde_json::json!({ "address": address, "token": token.symbol(), "balance": balance }))
}

/// `seal_listBridgeWrappedBalances`: every non-zero wrapped-token
/// balance for `address`. Companion to `seal_getBridgeWrappedBalance`
/// (which requires the caller to know the symbol up-front);
/// scans `WrappedToken::all_variants()` and emits only the
/// non-zero entries so the response stays compact for the
/// common case (most addresses hold zero or one wrapped token).
/// Unsigned read; the address is a query param, not a signer.
async fn handle_list_bridge_wrapped_balances(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let lookup_key = normalize_seal_address_to_hex(address)
        .ok_or((-32602, format!("invalid 'address': {address}")))?;
    let bridge = state.bridge.lock().await;
    let entries: Vec<serde_json::Value> = seal_bridge::WrappedToken::all_variants()
        .iter()
        .filter_map(|t| {
            let balance = bridge.wrapped_balance(&lookup_key, t);
            if balance == 0 {
                None
            } else {
                Some(serde_json::json!({
                    "token": t.symbol(),
                    "chain": format!("{:?}", t.chain()),
                    "balance": balance,
                }))
            }
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "balances": entries,
        "count": entries.len(),
    }))
}

/// `seal_bridgeWithdraw`: burn wrapped tokens for the caller and
/// create a withdrawal record for the committee to sign.
///
/// Params: `{"dest_chain": "Solana", "dest_address": "...", "token": "WSOL", "amount": 1000000}`.
/// Auth: required.
async fn handle_bridge_withdraw(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    if caller == "anonymous" {
        return Err((-32000, "seal_bridgeWithdraw requires authentication".into()));
    }
    let dest_chain = params
        .get("dest_chain")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'dest_chain' param".into()))?;
    let dest_address = params
        .get("dest_address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'dest_address' param".into()))?;
    let token = params
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'token' param".into()))?;
    let amount = params
        .get("amount")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing or invalid 'amount' param".into()))?;

    let dest_chain = parse_chain(dest_chain)?;
    let token = parse_wrapped_token(token)?;
    // BridgeManager keys wrapped balances on the 32-byte hex form
    // (SHA3-256 of the verifying key). The authenticated `caller`
    // arrives as the bech32m address (`SealAddress::string_encoding`).
    // Normalize so the burn lands against the same key the observer
    // credited at mint time.
    let lookup_key = normalize_seal_address_to_hex(caller)
        .ok_or((-32602, format!("invalid caller address: {caller}")))?;

    // P8/§4.2 — bridge withdrawal fee. Burn from the caller's
    // native SEAL balance BEFORE touching the wrapped ledger. If
    // the fee burn fails (insufficient balance), we fail the
    // entire RPC with -32000 and the wrapped balance is untouched.
    // If the fee burn succeeds and the wrapped burn fails (e.g.
    // InsufficientWrapped), we refund — the fee is for service
    // rendered, not a slashing tool.
    let fee = state.config.bridge_withdrawal_fee;
    if fee > 0 {
        let mut node = state.node.lock().await;
        node.runner
            .balances
            .burn(caller, fee)
            .map_err(|e| (-32000, format!("withdrawal-fee burn failed: {e}")))?;
        drop(node);
    }

    let mut bridge = state.bridge.lock().await;
    let withdrawal_id_result =
        bridge.initiate_withdrawal(&lookup_key, dest_chain, dest_address, token, amount);
    let withdrawal_id = match withdrawal_id_result {
        Ok(id) => id,
        Err(e) => {
            drop(bridge);
            // Refund the fee since the withdrawal didn't actually
            // get queued. Re-mint via BalanceStore::mint to keep
            // total_supply consistent (burn dropped supply by
            // `fee`; mint puts it back).
            if fee > 0 {
                let mut node = state.node.lock().await;
                if let Err(re) = node.runner.balances.mint(caller, fee) {
                    warn!(
                        caller, fee, err = ?re,
                        "withdrawal-fee refund failed — caller is owed {fee} SEAL", fee = fee
                    );
                }
            }
            return Err((-32000, format!("withdraw failed: {e}")));
        }
    };
    Ok(serde_json::json!({
        "withdrawal_id": withdrawal_id,
        "caller": caller,
        "fee_burned": fee,
    }))
}

/// `seal_addBridgeObserver`: register a chain observer so subsequent
/// `seal_pollBridges` calls see its events. No auth for testnet; in
/// production this will be admin-gated once the bridge param-store
/// lands. Params:
///   `{"chain": "Solana", "rpc_url": "http://localhost:8899",
///     "program_id": "SealBridge11...",
///     "poll_interval_secs": 5  (optional)}`
/// For Stellar: `"horizon_url"` instead of `"rpc_url"`,
/// `"contract_id"` instead of `"program_id"`, and an optional
/// `"soroban_rpc_url"` (defaults to deriving from `horizon_url` by
/// swapping port 8000 → 8003).
///
/// `poll_interval_secs` is honored by the in-process auto-poll loop
/// (`--bridge-poll-interval-secs`) only. The explicit
/// `seal_pollBridges` RPC ignores it (polls every observer on every
/// call). Zero or absent means "match the global tick rate" —
/// preserves prior behavior.
async fn handle_add_bridge_observer(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let chain = params
        .get("chain")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'chain' param".into()))?;
    let chain = parse_chain(chain)?;
    let poll_interval_secs = params
        .get("poll_interval_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let mut set = state.observers.lock().await;
    match chain {
        Chain::Solana => {
            let rpc_url = params
                .get("rpc_url")
                .and_then(|v| v.as_str())
                .ok_or((-32602, "missing 'rpc_url' for Solana observer".into()))?;
            let program_id = params
                .get("program_id")
                .and_then(|v| v.as_str())
                .ok_or((-32602, "missing 'program_id' for Solana observer".into()))?;
            let mut obs = SolanaObserver::new(rpc_url, program_id);
            if let Some(usdc_mint) = params.get("usdc_mint").and_then(|v| v.as_str()) {
                obs = obs.with_usdc_mint(usdc_mint);
            }
            set.add_observer_with_interval(Box::new(obs), poll_interval_secs);
        }
        Chain::Stellar => {
            let horizon_url = params
                .get("horizon_url")
                .and_then(|v| v.as_str())
                .ok_or((-32602, "missing 'horizon_url' for Stellar observer".into()))?;
            let contract_id = params
                .get("contract_id")
                .and_then(|v| v.as_str())
                .ok_or((-32602, "missing 'contract_id' for Stellar observer".into()))?;
            let mut obs = StellarObserver::new(horizon_url, contract_id);
            if let Some(soroban_url) = params.get("soroban_rpc_url").and_then(|v| v.as_str()) {
                obs = obs.with_soroban_rpc(soroban_url);
            }
            set.add_observer_with_interval(Box::new(obs), poll_interval_secs);
        }
    }
    Ok(serde_json::json!({
        "chain": chain.to_string(),
        "ok": true,
        "poll_interval_secs": poll_interval_secs,
    }))
}

/// `seal_listBridgeObservers`: debug-level view of configured chains.
/// Returns `{count, intervals: [{chain, poll_interval_secs}, ...]}`
/// — operators confirm a `seal_addBridgeObserver` call landed the
/// `poll_interval_secs` value they passed.
async fn handle_list_bridge_observers(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
    let set = state.observers.lock().await;
    let intervals: Vec<serde_json::Value> = set
        .poll_intervals()
        .into_iter()
        .map(|(c, secs)| {
            serde_json::json!({
                "chain": c.to_string(),
                "poll_interval_secs": secs,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "count": set.observer_count(),
        "intervals": intervals,
    }))
}

/// Shared body for `seal_pollBridges` and the optional background
/// auto-poll task. `scheduled = true` only polls observers whose
/// per-observer `poll_interval_secs` has elapsed (skips chains that
/// configured a slower cadence than the global tick); `false` polls
/// every observer unconditionally (the explicit RPC contract).
/// Returns (observed, new, duplicate, processed) counters.
pub(crate) async fn poll_bridges_once(
    state: &RpcState,
    scheduled: bool,
) -> Result<(usize, u64, u64, u64), (i32, String)> {
    // The observer trait uses blocking I/O (reqwest::blocking). We
    // must not call it with an async mutex held because the mutex
    // would then span a sync HTTP fetch that could stall for
    // seconds. Take ownership of the observer set under the lock, do
    // the poll outside, restore it. `BridgeObserverSet` isn't Clone,
    // so we `mem::take` and put it back.
    //
    // PANIC SAFETY: a panic inside the spawn_blocking closure (e.g. a
    // malformed RPC response that trips an `expect()` in the
    // observer) used to wipe `state.observers` — the closure dropped
    // its copy, the `.await?` propagated the JoinError, and the
    // `*observers = observer_set` restore never ran. Observed live on
    // bridge-e2e.sh: registration returned ok:true, `count` flipped
    // back to 0 after the first auto-poll tick, and every subsequent
    // `seal_addBridgeObserver` looked accepted-but-lost.
    //
    // The fix below catches the panic *inside* the closure with
    // `catch_unwind`, so the closure always returns Ok with the
    // observer set intact. We re-raise the panic info as a regular
    // RPC error after restoring the set.
    let mut observers = state.observers.lock().await;
    let observer_set = std::mem::take(&mut *observers);
    let (observer_set, poll_result) = tokio::task::spawn_blocking(move || {
        let mut set = observer_set;
        // AssertUnwindSafe: BridgeObserverSet has internal mutability
        // (cursors), so it isn't UnwindSafe by default. After a
        // panic the cursor on the offending observer may be
        // inconsistent — but the alternative (losing the entire
        // observer set) is much worse, so we accept the trade-off.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if scheduled {
                set.poll_due(std::time::Instant::now())
            } else {
                set.poll_all()
            }
        }));
        let result = match result {
            Ok(inner) => inner.map_err(|e| format!("observer poll error: {}", e)),
            Err(panic_payload) => {
                // Extract a readable message from the panic payload —
                // it can be either `&'static str` or `String`
                // depending on how the panic was raised.
                let msg = panic_payload
                    .downcast_ref::<&'static str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "observer poll panicked (unknown payload)".to_string());
                Err(msg)
            }
        };
        (set, result)
    })
    .await
    .map_err(|e| (-32000, format!("bridge poll task join error: {}", e)))?;
    *observers = observer_set;
    drop(observers);
    let deposits = poll_result.map_err(|e| (-32000, format!("bridge poll failed: {}", e)))?;

    let mut new_count = 0u64;
    let mut duplicate_count = 0u64;
    let mut processed_count = 0u64;
    {
        let mut bridge = state.bridge.lock().await;
        for d in deposits.iter() {
            let id = d.id.clone();
            match bridge.observe_deposit(d.clone()) {
                Ok(()) => new_count += 1,
                Err(seal_bridge::BridgeError::DepositAlreadyProcessed(_)) => {
                    duplicate_count += 1;
                    continue;
                }
                Err(e) => {
                    warn!("bridge observe_deposit error: {}", e);
                    continue;
                }
            }
            // Testnet committee-of-1 auto-confirm + auto-process.
            // Multi-validator testnet should swap this for a separate
            // confirmation RPC that quorum drives. For now, every
            // observed deposit advances to `required_confirmations` in
            // one step so the wrapped balance is immediately mintable.
            if let Err(e) = bridge.confirm_deposit(&id) {
                warn!("bridge confirm_deposit({}) error: {}", id, e);
                continue;
            }
            match bridge.process_deposit(&id) {
                Ok(_) => processed_count += 1,
                Err(e) => {
                    warn!("bridge process_deposit({}) error: {}", id, e);
                }
            }
        }
    }
    Ok((deposits.len(), new_count, duplicate_count, processed_count))
}

/// `seal_pollBridges`: run one observation round across all
/// configured observers. Each returned deposit is fed into
/// `BridgeManager::observe_deposit`; already-observed deposit IDs
/// are ignored (the returned `new`/`duplicate` counts reflect that).
///
/// In production a background task (enabled via
/// `--bridge-poll-interval-secs`) calls this every N seconds. For
/// `bridge-e2e.sh` and local debugging we still expose it as an
/// explicit RPC so the test can observe at a known point.
async fn handle_poll_bridges(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    // Explicit RPC ignores per-observer schedules — bridge-e2e.sh
    // and operator debugging expect "poll every observer right now".
    let (observed, new_count, duplicate_count, processed_count) =
        poll_bridges_once(state, false).await?;
    Ok(serde_json::json!({
        "observed": observed,
        "new": new_count,
        "duplicate": duplicate_count,
        "processed": processed_count,
    }))
}

// ─── Bridge emergency pause (Technical Council 2/3) ──

/// Parse a JSON array of strings into `Vec<String>`.
fn parse_string_array(v: &serde_json::Value, field: &str) -> Result<Vec<String>, (i32, String)> {
    v.as_array()
        .ok_or_else(|| (-32602, format!("'{}' must be an array of strings", field)))?
        .iter()
        .map(|e| {
            e.as_str()
                .map(String::from)
                .ok_or_else(|| (-32602, format!("'{}' entries must be strings", field)))
        })
        .collect()
}

/// `seal_bridgePauseChain`: halt deposits, processing, and
/// withdrawals on the named chain until `seal_bridgeUnpauseChain`
/// is called. Requires a 2/3 supermajority of the Technical Council.
///
/// Params:
///   `{"chain": "Solana", "reason": "signing key rotation",
///     "approvers": ["pk1", "pk2", ...]}`
///
/// The approvers list is the set of council members who voted yes.
/// Supermajority uses ceiling arithmetic: an 11-member council
/// needs 8 approvers, a 7-member council needs 5.
async fn handle_bridge_pause_chain(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let chain_str = params
        .get("chain")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'chain' param".into()))?;
    let chain = parse_chain(chain_str)?;
    let reason = params
        .get("reason")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'reason' param".into()))?;
    let approvers_val = params
        .get("approvers")
        .ok_or((-32602, "missing 'approvers' param".into()))?;
    let approvers = parse_string_array(approvers_val, "approvers")?;

    let council = state.council.lock().await;
    if council.member_count() == 0 {
        return Err((
            -32000,
            "technical council is empty; bootstrap via seal_bridgeCouncilAdd first".into(),
        ));
    }
    if !council.has_two_thirds_approval(&approvers) {
        let required = council.two_thirds_threshold();
        let valid = council.count_valid_approvers(&approvers);
        return Err((
            -32000,
            format!(
                "insufficient council approval for pause: need {} of {}, got {} valid",
                required,
                council.member_count(),
                valid
            ),
        ));
    }
    drop(council);

    let mut bridge = state.bridge.lock().await;
    bridge.pause_chain(chain.clone(), reason.to_string());
    info!("bridge chain paused: {} — {}", chain, reason);
    Ok(serde_json::json!({
        "chain": chain.to_string(),
        "paused": true,
        "reason": reason,
    }))
}

/// `seal_bridgeUnpauseChain`: resume a previously-paused chain.
/// Requires 2/3 council approval. Params: same shape as
/// `seal_bridgePauseChain` minus `reason`.
async fn handle_bridge_unpause_chain(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let chain_str = params
        .get("chain")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'chain' param".into()))?;
    let chain = parse_chain(chain_str)?;
    let approvers_val = params
        .get("approvers")
        .ok_or((-32602, "missing 'approvers' param".into()))?;
    let approvers = parse_string_array(approvers_val, "approvers")?;

    let council = state.council.lock().await;
    if council.member_count() == 0 {
        return Err((
            -32000,
            "technical council is empty; bootstrap via seal_bridgeCouncilAdd first".into(),
        ));
    }
    if !council.has_two_thirds_approval(&approvers) {
        let required = council.two_thirds_threshold();
        let valid = council.count_valid_approvers(&approvers);
        return Err((
            -32000,
            format!(
                "insufficient council approval for unpause: need {} of {}, got {} valid",
                required,
                council.member_count(),
                valid
            ),
        ));
    }
    drop(council);

    let mut bridge = state.bridge.lock().await;
    bridge
        .unpause_chain(&chain)
        .map_err(|e| (-32000, e.to_string()))?;
    info!("bridge chain unpaused: {}", chain);
    Ok(serde_json::json!({
        "chain": chain.to_string(),
        "paused": false,
    }))
}

/// `seal_bridgeListPaused`: no-auth read of the currently-paused
/// chains with their pause reasons. Dashboards and relay clients
/// poll this to decide whether to skip submissions.
async fn handle_bridge_list_paused(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let bridge = state.bridge.lock().await;
    let paused: Vec<serde_json::Value> = bridge
        .list_paused_chains()
        .into_iter()
        .map(|(c, r)| serde_json::json!({ "chain": c.to_string(), "reason": r }))
        .collect();
    Ok(serde_json::json!({ "paused": paused }))
}

/// `seal_bridgeRotateCommitteeKey`: rotate the host-side committee
/// MAC key without restarting `seal-node`. Requires a 2/3 supermajority
/// of the Technical Council and admin auth, matching
/// `seal_bridgePauseChain`. Operators MUST follow this with the
/// matching `rotate_committee_key` ix on each chain's bridge program
/// — until they do, `seal_bridgeGetCommitteeKeyStatus`'s fingerprint
/// will not match the on-chain `committee_key_hash` and new
/// withdrawals will be unclaimable.
///
/// Params:
///   `{"new_key_hex": "64-hex", "approvers": ["pk1", "pk2", ...]}`
async fn handle_bridge_rotate_committee_key(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let new_key_hex = params
        .get("new_key_hex")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'new_key_hex' param".into()))?;
    if new_key_hex.len() != 64 {
        return Err((
            -32602,
            format!(
                "new_key_hex must be 64 hex chars (32 bytes); got {}",
                new_key_hex.len()
            ),
        ));
    }
    let new_key_bytes = hex::decode(new_key_hex)
        .map_err(|e| (-32602, format!("new_key_hex hex decode failed: {e}")))?;
    let mut new_key = [0u8; 32];
    new_key.copy_from_slice(&new_key_bytes);

    let approvers_val = params
        .get("approvers")
        .ok_or((-32602, "missing 'approvers' param".into()))?;
    let approvers = parse_string_array(approvers_val, "approvers")?;

    let council = state.council.lock().await;
    if council.member_count() == 0 {
        return Err((
            -32000,
            "technical council is empty; bootstrap via seal_bridgeCouncilAdd first".into(),
        ));
    }
    if !council.has_two_thirds_approval(&approvers) {
        let required = council.two_thirds_threshold();
        let valid = council.count_valid_approvers(&approvers);
        return Err((
            -32000,
            format!(
                "insufficient council approval for committee-key rotation: need {} of {}, got {} valid",
                required,
                council.member_count(),
                valid
            ),
        ));
    }
    drop(council);

    let mut bridge = state.bridge.lock().await;
    bridge.set_committee_key(new_key);
    let fingerprint_sha3 = bridge
        .committee_key_fingerprint()
        .map(hex::encode)
        .unwrap_or_default();
    let fingerprint_sha2 = bridge
        .committee_key_fingerprint_sha256()
        .map(hex::encode)
        .unwrap_or_default();
    drop(bridge);
    // Persist to disk so the rotation survives node restart. Without
    // this, on the next boot the CLI flag (or its docker-compose
    // value) would win and silently revert the rotation. Atomic
    // tmp+rename so a crash mid-write can't leave a truncated file.
    let persist_result: Result<(), String> = match &state.data_dir {
        Some(dir) => {
            let final_path = dir.join("bridge-committee-key.hex");
            let tmp_path = dir.join("bridge-committee-key.hex.tmp");
            match std::fs::write(&tmp_path, new_key_hex.as_bytes())
                .and_then(|_| std::fs::rename(&tmp_path, &final_path))
            {
                Ok(()) => Ok(()),
                Err(e) => Err(format!("{}: {}", final_path.display(), e)),
            }
        }
        None => Err("no data_dir configured; rotation is in-memory only".into()),
    };
    let persisted = match &persist_result {
        Ok(()) => true,
        Err(e) => {
            // Don't fail the RPC — the in-memory rotation already
            // succeeded, signed withdrawals from this process will
            // use the new key. The operator just needs to re-apply
            // the rotation after a restart (or fix the data-dir
            // permission). Surface the reason in both the log and
            // the response so it's discoverable.
            error!(
                "bridge committee key rotated in-memory but failed to persist: {}",
                e
            );
            false
        }
    };
    info!(
        "bridge committee key rotated: sha3=0x{} sha2=0x{} persisted={}",
        fingerprint_sha3, fingerprint_sha2, persisted
    );
    let mut resp = serde_json::json!({
        "rotated": true,
        "persisted": persisted,
        "fingerprint_sha3_hex": fingerprint_sha3,
        "fingerprint_sha2_hex": fingerprint_sha2,
    });
    if let Err(e) = persist_result {
        resp["persist_error"] = serde_json::Value::String(e);
    }
    Ok(resp)
}

/// `seal_bridgeGetCommitteeKeyStatus`: no-auth read returning whether
/// a committee key is installed plus two fingerprints over it. The
/// raw key is never exposed.
///
/// - `fingerprint_sha3_hex` — SHA3-256, the host's PQ-native hash.
/// - `fingerprint_sha2_hex` — SHA-256, the cross-chain comparison
///   hash. Solana's `sol_sha256` syscall and Stellar's
///   `env.crypto().sha256()` are both SHA-256, so an on-chain
///   `committee_key_hash` getter (added later) returns the same
///   bytes and operators can diff against this field directly.
async fn handle_bridge_get_committee_key_status(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
    let bridge = state.bridge.lock().await;
    let fingerprint_sha3 = bridge.committee_key_fingerprint().map(hex::encode);
    let fingerprint_sha2 = bridge.committee_key_fingerprint_sha256().map(hex::encode);
    Ok(serde_json::json!({
        "set": fingerprint_sha3.is_some(),
        "fingerprint_sha3_hex": fingerprint_sha3,
        "fingerprint_sha2_hex": fingerprint_sha2,
    }))
}

/// `seal_bridgeRingtailStatus`: no-auth read returning the bridge's
/// multi-validator Ringtail wiring state. Mirrors the shape of
/// `seal_bridgeGetCommitteeKeyStatus` so dashboards can show both
/// at a glance.
///
/// Fields:
///   `singleton_keypair_installed` — whether a 1-of-1 Ringtail
///   keypair is set via `BridgeManager::set_committee_ringtail_keypair`
///   (P1#5 layer 3). When true, new withdrawals carry a 2088-byte
///   hex-encoded Ringtail signature instead of the 32-byte HMAC.
///   `signing_signal_subscriber` — whether the multi-validator
///   orchestrator (P1#5 layer 4) is subscribed to the withdrawal-
///   ready-for-signing channel. Today wires manually in seal-node
///   bring-up; future operator runbooks gate it on this flag.
///
/// Returns `singleton_keypair_installed: false` when the seal-bridge
/// `ringtail-singleton` feature is OFF — the field exists on every
/// build so dashboards can scrape it uniformly.
/// `seal_listAdminAddresses`: no-auth read of the configured
/// admin set + multisig threshold. Cosigners use this to verify
/// they're in the set before signing; wallets pre-flight an
/// admin call by checking the threshold. Addresses are public
/// bech32m so there's no secrecy concern.
async fn handle_list_admin_addresses(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let mut addresses: Vec<String> = state.config.admin_addresses.iter().cloned().collect();
    addresses.sort();
    Ok(serde_json::json!({
        "addresses": addresses,
        "count": addresses.len(),
        "threshold": state.config.admin_threshold,
        "mode": if state.config.admin_addresses.is_empty() {
            "open"
        } else if state.config.admin_threshold >= 2 {
            "multisig"
        } else {
            "single-sig"
        },
    }))
}

/// `seal_getBridgeWithdrawalFee`: no-auth read returning the SEAL
/// fee charged on every successful `seal_bridgeWithdraw` (P8/§4.2).
/// Wallets call this before the burn so they can show users the
/// "you'll pay X SEAL in fees" line; dashboards consume it to
/// catch fee-config drift between validators in a committee.
async fn handle_get_bridge_withdrawal_fee(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
    Ok(serde_json::json!({
        "fee_base_units": state.config.bridge_withdrawal_fee,
        "fee_seal": (state.config.bridge_withdrawal_fee as f64) / 1_000_000_000.0,
    }))
}

async fn handle_bridge_ringtail_status(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
    #[cfg(feature = "ringtail-singleton")]
    let (installed, subscribed, orchestrator_active, session_count) = {
        let bridge = state.bridge.lock().await;
        let (active, count) = match &state.ringtail_orchestrator {
            Some(orch) => (true, orch.lock().await.session_count()),
            None => (false, 0usize),
        };
        (
            bridge.has_ringtail_keypair(),
            bridge.has_signing_signal_subscriber(),
            active,
            count,
        )
    };
    #[cfg(not(feature = "ringtail-singleton"))]
    let (installed, subscribed, orchestrator_active, session_count) = {
        let _ = state;
        (false, false, false, 0usize)
    };
    Ok(serde_json::json!({
        "singleton_keypair_installed": installed,
        "signing_signal_subscriber": subscribed,
        "orchestrator_active": orchestrator_active,
        "session_count": session_count,
        "feature_compiled_in": cfg!(feature = "ringtail-singleton"),
    }))
}

/// `seal_bridgeCouncilAdd`: seat a council member. Alpha-testnet
/// bootstrap endpoint — production will replace this with Token
/// House election output. No auth by design; operators running
/// beyond alpha should front this RPC with access controls.
///
/// Params:
///   `{"pubkey": "hex...", "name": "Alice",
///     "term_start_epoch": 0, "term_end_epoch": 26280}`
async fn handle_bridge_council_add(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let pubkey = params
        .get("pubkey")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'pubkey' param".into()))?;
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'name' param".into()))?;
    let term_start_epoch = params
        .get("term_start_epoch")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let term_end_epoch = params
        .get("term_end_epoch")
        .and_then(|v| v.as_u64())
        .unwrap_or(26280);
    let member = CouncilMember {
        pubkey: pubkey.to_string(),
        name: name.to_string(),
        term_start_epoch,
        term_end_epoch,
    };
    let mut council = state.council.lock().await;
    council.add_member(member).map_err(|e| (-32000, e))?;
    Ok(serde_json::json!({
        "pubkey": pubkey,
        "member_count": council.member_count(),
    }))
}

/// `seal_bridgeCouncilRemove`: unseat a council member. Alpha-testnet
/// bootstrap endpoint; see caveats on `seal_bridgeCouncilAdd`.
async fn handle_bridge_council_remove(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let pubkey = params
        .get("pubkey")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'pubkey' param".into()))?;
    let mut council = state.council.lock().await;
    council.remove_member(pubkey).map_err(|e| (-32000, e))?;
    Ok(serde_json::json!({
        "pubkey": pubkey,
        "member_count": council.member_count(),
    }))
}

/// `seal_bridgeCouncilList`: seated council members, sorted by
/// pubkey. Includes the 2/3 supermajority threshold so CLI clients
/// can tell users how many signatures they need.
async fn handle_bridge_council_list(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let council = state.council.lock().await;
    let members: Vec<serde_json::Value> = council
        .list_members()
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "pubkey": m.pubkey,
                "name": m.name,
                "term_start_epoch": m.term_start_epoch,
                "term_end_epoch": m.term_end_epoch,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "members": members,
        "member_count": council.member_count(),
        "two_thirds_threshold": council.two_thirds_threshold(),
    }))
}

/// `seal_getCouncilMemberByAddress`: per-address Technical Council
/// membership lookup paralleling `seal_getValidatorByAddress`.
/// Until this RPC, a wallet asking "am I on the council?" pulled
/// the full `seal_bridgeCouncilList` and ran
/// `SHA3-256(hex_decode(pubkey)) == address_hash` client-side.
/// New `TechnicalCouncil::find_by_address_hash` does the same scan
/// server-side. Returns the member's pubkey hex / name / term-
/// start / term-end epochs, or `member: null` if the address is
/// not on the council. Unsigned read; the underlying state is
/// already publicly visible via `seal_bridgeCouncilList`.
async fn handle_get_council_member_by_address(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let parsed = SealAddress::from_string_encoding(address)
        .map_err(|e| (-32602, format!("invalid 'address': {e}")))?;
    let addr_hash: [u8; 32] = *parsed.as_bytes();
    let council = state.council.lock().await;
    let member = council.find_by_address_hash(&addr_hash).map(|m| {
        serde_json::json!({
            "pubkey": m.pubkey,
            "name": m.name,
            "term_start_epoch": m.term_start_epoch,
            "term_end_epoch": m.term_end_epoch,
        })
    });
    Ok(serde_json::json!({
        "address": address,
        "member": member,
    }))
}

// ─── Governance Handlers ────────────────────────────
//
// All proposal-mutating methods require authentication so the
// proposer / voter / delegator address is bound to the caller's
// ML-DSA key. Read methods (`seal_govGetProposal`,
// `seal_govListProposals`, `seal_govGetVotes`, `seal_govEffectiveWeight`)
// are open.

fn parse_track(s: &str) -> Result<crate::governance::ProposalTrack, (i32, String)> {
    use crate::governance::ProposalTrack::*;
    match s.to_ascii_lowercase().as_str() {
        "parameter" | "parameter_change" | "parameterchange" => Ok(ParameterChange),
        "protocol" | "protocol_upgrade" | "protocolupgrade" => Ok(ProtocolUpgrade),
        "treasury_small" | "treasurysmall" => Ok(TreasurySmall),
        "treasury_large" | "treasurylarge" => Ok(TreasuryLarge),
        "emergency" => Ok(Emergency),
        "constitutional" => Ok(Constitutional),
        other => Err((-32602, format!("unknown track '{}'", other))),
    }
}

fn parse_conviction(s: &str) -> Result<crate::governance::Conviction, (i32, String)> {
    use crate::governance::Conviction::*;
    match s.to_ascii_lowercase().as_str() {
        "none" | "0" => Ok(None),
        "x1" | "1" => Ok(X1),
        "x2" | "2" => Ok(X2),
        "x3" | "3" => Ok(X3),
        "x4" | "4" => Ok(X4),
        "x5" | "5" => Ok(X5),
        "x6" | "6" => Ok(X6),
        other => Err((-32602, format!("unknown conviction '{}'", other))),
    }
}

fn parse_choice(s: &str) -> Result<crate::governance::VoteChoice, (i32, String)> {
    use crate::governance::VoteChoice::*;
    match s.to_ascii_lowercase().as_str() {
        "yes" | "aye" => Ok(Yes),
        "no" | "nay" => Ok(No),
        "abstain" => Ok(Abstain),
        other => Err((-32602, format!("unknown vote choice '{}'", other))),
    }
}

async fn handle_gov_propose(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let track_s = params
        .get("track")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'track'".into()))?;
    let track = parse_track(track_s)?;
    let title = params
        .get("title")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'title'".into()))?
        .to_string();
    let description = params
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let payload = params
        .get("payload")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut node = state.node.lock().await;
    let current_epoch = node.runner.current_epoch.number;
    let id = node.runner.governance.create_proposal(
        track.clone(),
        title,
        description,
        payload,
        caller.to_string(),
        current_epoch,
    );
    Ok(serde_json::json!({
        "proposal_id": id,
        "track": format!("{:?}", track),
        "start_epoch": current_epoch,
    }))
}

async fn handle_gov_vote(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let proposal_id = params
        .get("proposal_id")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'proposal_id'".into()))?;
    let choice = parse_choice(
        params
            .get("choice")
            .and_then(|v| v.as_str())
            .ok_or((-32602, "missing 'choice'".into()))?,
    )?;
    let stake = params
        .get("stake")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'stake'".into()))?;
    let conviction = parse_conviction(
        params
            .get("conviction")
            .and_then(|v| v.as_str())
            .unwrap_or("x1"),
    )?;

    let mut node = state.node.lock().await;
    node.runner
        .governance
        .vote_with_conviction(proposal_id, caller.to_string(), choice, stake, conviction)
        .map_err(|e| (-32000, e))?;
    Ok(serde_json::json!({ "ok": true }))
}

async fn handle_gov_withdraw_vote(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let proposal_id = params
        .get("proposal_id")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'proposal_id'".into()))?;
    let mut node = state.node.lock().await;
    node.runner
        .governance
        .withdraw_vote(proposal_id, caller)
        .map_err(|e| (-32000, e))?;
    Ok(serde_json::json!({ "ok": true }))
}

async fn handle_gov_tally(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let proposal_id = params
        .get("proposal_id")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'proposal_id'".into()))?;
    let mut node = state.node.lock().await;
    let current_epoch = node.runner.current_epoch.number;
    let status = node
        .runner
        .governance
        .tally(proposal_id, current_epoch)
        .map_err(|e| (-32000, e))?;
    Ok(serde_json::json!({
        "proposal_id": proposal_id,
        "status": format!("{:?}", status),
    }))
}

async fn handle_gov_execute(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let proposal_id = params
        .get("proposal_id")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'proposal_id'".into()))?;
    let mut node = state.node.lock().await;
    let current_epoch = node.runner.current_epoch.number;
    let payload = node
        .runner
        .governance
        .execute(proposal_id, current_epoch)
        .map_err(|e| (-32000, e))?;
    Ok(serde_json::json!({
        "proposal_id": proposal_id,
        "executed_payload": payload,
    }))
}

async fn handle_gov_get_proposal(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let proposal_id = params
        .get("proposal_id")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'proposal_id'".into()))?;
    let node = state.node.lock().await;
    let p = node
        .runner
        .governance
        .get_proposal(proposal_id)
        .ok_or((-32004, format!("proposal {} not found", proposal_id)))?;
    Ok(serde_json::json!({
        "id": p.id,
        "track": format!("{:?}", p.track),
        "title": p.title,
        "description": p.description,
        "payload": p.payload,
        "proposer": p.proposer,
        "start_epoch": p.start_epoch,
        "status": format!("{:?}", p.status),
    }))
}

async fn handle_gov_list_proposals(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let node = state.node.lock().await;
    let out: Vec<_> = node
        .runner
        .governance
        .list_proposals()
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "track": format!("{:?}", p.track),
                "title": p.title,
                "proposer": p.proposer,
                "start_epoch": p.start_epoch,
                "status": format!("{:?}", p.status),
            })
        })
        .collect();
    Ok(serde_json::json!({ "proposals": out }))
}

async fn handle_gov_get_votes(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let proposal_id = params
        .get("proposal_id")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'proposal_id'".into()))?;
    let node = state.node.lock().await;
    let votes = node.runner.governance.get_votes(proposal_id).cloned();
    let out: Vec<_> = votes
        .unwrap_or_default()
        .into_iter()
        .map(|v| {
            serde_json::json!({
                "voter": v.voter,
                "choice": format!("{:?}", v.choice),
                "stake": v.stake,
                "weight": v.weight,
                "conviction": format!("{:?}", v.conviction),
                "unlock_epoch": v.unlock_epoch,
            })
        })
        .collect();
    Ok(serde_json::json!({ "votes": out }))
}

async fn handle_gov_delegate(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let delegate = params
        .get("delegate")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'delegate'".into()))?;
    let track = parse_track(
        params
            .get("track")
            .and_then(|v| v.as_str())
            .ok_or((-32602, "missing 'track'".into()))?,
    )?;
    let weight = params
        .get("weight")
        .and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'weight'".into()))?;

    let mut node = state.node.lock().await;
    node.runner
        .delegation
        .delegate(caller, delegate, &track, weight)
        .map_err(|e| (-32000, e))?;
    Ok(serde_json::json!({ "ok": true }))
}

async fn handle_gov_revoke_delegation(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let track = parse_track(
        params
            .get("track")
            .and_then(|v| v.as_str())
            .ok_or((-32602, "missing 'track'".into()))?,
    )?;
    let mut node = state.node.lock().await;
    node.runner
        .delegation
        .revoke(caller, &track)
        .map_err(|e| (-32000, e))?;
    Ok(serde_json::json!({ "ok": true }))
}

async fn handle_gov_effective_weight(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let voter = params
        .get("voter")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'voter'".into()))?;
    let track = parse_track(
        params
            .get("track")
            .and_then(|v| v.as_str())
            .ok_or((-32602, "missing 'track'".into()))?,
    )?;
    let direct_voters: Vec<String> = params
        .get("direct_voters")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let node = state.node.lock().await;
    let w = node
        .runner
        .delegation
        .effective_weight(voter, &track, &direct_voters);
    Ok(serde_json::json!({ "voter": voter, "delegated_weight": w }))
}

/// Proposals authored by `address`. Same shape as
/// `seal_govListProposals` but filtered server-side. Useful for
/// "what have I proposed?" UX. Empty list for non-proposers.
async fn handle_gov_list_proposals_by_proposer(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let node = state.node.lock().await;
    let out: Vec<_> = node
        .runner
        .governance
        .proposals_by_proposer(address)
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "track": format!("{:?}", p.track),
                "title": p.title,
                "proposer": p.proposer,
                "start_epoch": p.start_epoch,
                "status": format!("{:?}", p.status),
            })
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "proposals": out,
        "count": out.len(),
    }))
}

/// Votes cast by `address` across every proposal. Each entry
/// carries the proposal_id so the caller can dereference via
/// `seal_govGetProposal` for title + track. Sorted ascending
/// by proposal_id.
async fn handle_gov_list_votes_by_voter(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let node = state.node.lock().await;
    let out: Vec<_> = node
        .runner
        .governance
        .votes_by_voter(address)
        .into_iter()
        .map(|(pid, v)| {
            serde_json::json!({
                "proposal_id": pid,
                "choice": format!("{:?}", v.choice),
                "stake": v.stake,
                "conviction": format!("{:?}", v.conviction),
                "weight": v.weight,
                "unlock_epoch": v.unlock_epoch,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "votes": out,
        "count": out.len(),
    }))
}

/// Active conviction locks for `address` — tokens locked through
/// past votes that haven't yet reached `unlock_epoch`. Sorted
/// ascending by `unlock_epoch` so "next to unlock" is the first
/// entry. Useful for "when do my tokens unlock?" UX.
async fn handle_gov_list_locks_by_voter(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let node = state.node.lock().await;
    let out: Vec<_> = node
        .runner
        .governance
        .locks_by_voter(address)
        .into_iter()
        .map(|l| {
            serde_json::json!({
                "proposal_id": l.proposal_id,
                "amount": l.amount,
                "unlock_epoch": l.unlock_epoch,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "locks": out,
        "count": out.len(),
    }))
}

/// Outgoing delegations from `address` — one entry per track
/// they've delegated on. Useful for "who am I delegating to?"
/// UX. Sorted by track for stable snapshots.
async fn handle_gov_list_delegations_from(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let node = state.node.lock().await;
    let out: Vec<_> = node
        .runner
        .delegation
        .delegations_from(address)
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "delegator": d.delegator,
                "delegate": d.delegate,
                "track": format!("{:?}", d.track),
                "weight": d.weight,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "delegations": out,
        "count": out.len(),
    }))
}

/// Incoming delegations to `address` — who has delegated voting
/// weight to this address, on which tracks. Useful for delegate
/// candidates evaluating their support; the count + weight sums
/// also feed UX like "you're at X% of the 4% delegate cap on
/// track Y".
async fn handle_gov_list_delegations_to(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let node = state.node.lock().await;
    let out: Vec<_> = node
        .runner
        .delegation
        .delegations_to(address)
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "delegator": d.delegator,
                "delegate": d.delegate,
                "track": format!("{:?}", d.track),
                "weight": d.weight,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "address": address,
        "delegations": out,
        "count": out.len(),
    }))
}

async fn handle_get_node_info(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let node = state.node.lock().await;
    let height = node.height();
    let epoch = node.runner.current_epoch.number;
    let validators = node.runner.validator_set.active_count();
    let leases = node.runner.leases.count();
    drop(node);

    let uptime = state.start_time.elapsed().as_secs();
    let peers = state
        .metrics
        .peers_connected
        .load(std::sync::atomic::Ordering::Relaxed);

    Ok(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "height": height,
        "epoch": epoch,
        "peers": peers,
        "validators": validators,
        "leases_active": leases,
        "uptime_secs": uptime,
    }))
}

// ─── Monitoring Endpoints ────────────────────────────────────

/// GET /health — liveness probe for load balancers and uptime monitors.
/// Returns enough signal that a testnet operator can answer
/// "is my node ready to vote?" from this endpoint alone:
///   - `status`: "ok" / "starting" / "stalled" based on height growth.
///   - `validator_pubkey_hex`, `validator_address`: the on-chain
///     identity this process is signing as (empty when no
///     `--validator-key` was supplied — node is a passive observer).
///   - `is_validator`: pubkey is seated in the active validator set.
///   - `blocks_pending`: depth of the received-but-not-yet-applied
///     P2P block queue. Steady-state ~0 on a healthy node; sustained
///     non-zero indicates the applier loop is lagging.
async fn handle_health(State(state): State<RpcState>) -> impl IntoResponse {
    let node = state.node.lock().await;
    let height = node.height();
    let pending_blocks = node.received_block_count();
    let our_pubkey: Vec<u8> = node.runner.verifying_key.to_bytes();
    let is_validator = node
        .runner
        .validator_set
        .find_by_pubkey(&our_pubkey)
        .map(|v| v.active)
        .unwrap_or(false);
    drop(node);

    let uptime = state.start_time.elapsed().as_secs();
    let peers = state
        .metrics
        .peers_connected
        .load(std::sync::atomic::Ordering::Relaxed);
    let blocks_produced = state
        .metrics
        .blocks_produced
        .load(std::sync::atomic::Ordering::Relaxed);

    // `status` is a coarse traffic-light:
    //   - "starting" for the first 30 s when there's no point asking
    //     about sync state yet.
    //   - "stalled" if uptime > 60 s and height is 0 (chain hasn't
    //     advanced past genesis even though we should have peers).
    //   - "ok" otherwise.
    let status = if uptime < 30 {
        "starting"
    } else if height == 0 && peers > 0 {
        "stalled"
    } else {
        "ok"
    };

    // Derive the bech32m address from the SHA3-256 of the pubkey.
    // Prefix tracks the node's mainnet/testnet flag so the address in
    // /health matches the one the operator's wallet shows.
    let address_hash = seal_crypto::hash::sha3_256(&our_pubkey).0;
    let validator_address =
        seal_crypto::address::SealAddress::from_hash(address_hash, state.config.testnet)
            .to_string_encoding();

    Json(serde_json::json!({
        "status": status,
        "height": height,
        "peers": peers,
        "uptime_secs": uptime,
        "validator_pubkey_hex": hex::encode(&our_pubkey),
        "validator_address": validator_address,
        "is_validator": is_validator,
        "blocks_produced": blocks_produced,
        "blocks_pending": pending_blocks,
    }))
}

/// GET /metrics — Prometheus exposition format for Grafana/Prometheus scraping.
async fn handle_metrics(State(state): State<RpcState>) -> impl IntoResponse {
    let node = state.node.lock().await;
    let height = node.height();
    let leases = node.runner.leases.count();
    let account_count = node.runner.balances.account_count();
    let total_supply = node.runner.balances.total_supply();
    // PLAN #8 stepping-stone: HAMT-based content-addressed root over
    // the entire balance ledger. Two nodes that agree on this hash
    // agree on every (addr, available, staked) triple. Exposed as a
    // bare hex string so dashboards can diff snapshots without
    // parsing the underlying serialization. Cost is sub-ms for a
    // few-K-account testnet (rebuilds the HAMT each call).
    let balance_root_hex = hex::encode(node.runner.balances.state_root_hash().0);
    drop(node);
    let mgr = state.token_manager.lock().await;
    let token_count = mgr.list_tokens().len();
    let frozen_count = mgr.total_frozen_accounts();
    let frozen_tokens = mgr.total_frozen_tokens();
    let token_root_hex = hex::encode(mgr.state_root_hash().0);
    drop(mgr);

    let uptime = state.start_time.elapsed().as_secs();
    // Refresh the bridge-Ringtail in-flight gauge from the
    // orchestrator's live session_count before serialising — atomic
    // store so to_prometheus reads the latest value. 0 when no
    // orchestrator is wired (HMAC committee-of-1 default path).
    #[cfg(feature = "ringtail-singleton")]
    {
        let session_count = match &state.ringtail_orchestrator {
            Some(orch) => orch.lock().await.session_count() as u64,
            None => 0,
        };
        state
            .metrics
            .bridge_ringtail_sessions
            .store(session_count, std::sync::atomic::Ordering::Relaxed);
    }
    let mut out = state.metrics.to_prometheus();

    // Add gauges that come from node state. `seal_account_count`
    // counts ACTIVE accounts only — drained-to-zero accounts are
    // eagerly pruned from the HAMT (commit `<this>`), so the
    // gauge reflects organic adoption rather than historical
    // dust-fanout. Companion to `--min-opening-balance`: that
    // prevents dust accounts from being created cheaply, the
    // eager prune prevents them from sticking around. The previous
    // pre-prune behavior used this gauge as an attack signal; with
    // prune in place it's a healthier "is this network growing"
    // metric instead. `seal_total_supply_micro` tracks SEAL
    // emission + burn end-to-end.
    out.push_str(&format!(
        "# HELP seal_chain_height Current chain height\n\
         # TYPE seal_chain_height gauge\n\
         seal_chain_height {}\n\
         # HELP seal_uptime_seconds Node uptime in seconds\n\
         # TYPE seal_uptime_seconds gauge\n\
         seal_uptime_seconds {}\n\
         # HELP seal_leases_active Number of active storage leases\n\
         # TYPE seal_leases_active gauge\n\
         seal_leases_active {}\n\
         # HELP seal_account_count Number of SEAL accounts in the native ledger\n\
         # TYPE seal_account_count gauge\n\
         seal_account_count {}\n\
         # HELP seal_total_supply_micro Total SEAL supply (minted - burned, micro-SEAL)\n\
         # TYPE seal_total_supply_micro gauge\n\
         seal_total_supply_micro {}\n\
         # HELP seal_tokens_registered Number of custom tokens created via seal_createToken\n\
         # TYPE seal_tokens_registered gauge\n\
         seal_tokens_registered {}\n\
         # HELP seal_frozen_accounts Total (symbol, address) frozen-account entries across all tokens\n\
         # TYPE seal_frozen_accounts gauge\n\
         seal_frozen_accounts {}\n\
         # HELP seal_frozen_tokens Number of tokens currently in the global-frozen kill-switch state\n\
         # TYPE seal_frozen_tokens gauge\n\
         seal_frozen_tokens {}\n",
        height, uptime, leases, account_count, total_supply, token_count, frozen_count, frozen_tokens,
    ));

    // HAMT state-root hashes — exposed as label-only metrics
    // (`info` style) since Prometheus gauges are numeric. Dashboards
    // can `count by (root_hex) (seal_balance_state_root)` to detect
    // node disagreement.
    out.push_str(&format!(
        "# HELP seal_balance_state_root HAMT root over the native SEAL ledger (hex label)\n\
         # TYPE seal_balance_state_root gauge\n\
         seal_balance_state_root{{root_hex=\"{}\"}} 1\n\
         # HELP seal_token_state_root HAMT root over per-token ledgers (hex label)\n\
         # TYPE seal_token_state_root gauge\n\
         seal_token_state_root{{root_hex=\"{}\"}} 1\n",
        balance_root_hex, token_root_hex,
    ));

    // Bridge metrics — operators alerting on testnet need a single
    // place to see whether the committee key is loaded, whether any
    // chain is paused, and how full the deposit/withdrawal queues
    // are. Label-info-style fingerprint lets dashboards drift-detect
    // against on-chain `committee_key_hash` values without exposing
    // the key itself.
    let bridge = state.bridge.lock().await;
    let committee_key_set = if bridge.has_committee_key() { 1 } else { 0 };
    let paused_count = bridge.paused_chain_count();
    let total_deposits = bridge.deposit_count();
    let pending_deposits = bridge.pending_deposit_count();
    let total_withdrawals = bridge.withdrawal_count();
    let fingerprint_sha2 = bridge
        .committee_key_fingerprint_sha256()
        .map(hex::encode)
        .unwrap_or_default();
    // Persistence check: does <data_dir>/bridge-committee-key.hex
    // exist and match the in-memory key? Lets operators alert on
    // rotate-then-disk-write-failure where the in-memory rotation
    // succeeded but the next restart will revert to the CLI flag.
    let committee_key_persisted: u8 = match &state.data_dir {
        Some(dir) if bridge.has_committee_key() => {
            let path = dir.join("bridge-committee-key.hex");
            match std::fs::read_to_string(&path) {
                Ok(contents) => match hex::decode(contents.trim()) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut candidate = [0u8; 32];
                        candidate.copy_from_slice(&bytes);
                        if bridge.committee_key_eq(&candidate) {
                            1
                        } else {
                            0
                        }
                    }
                    _ => 0,
                },
                Err(_) => 0,
            }
        }
        _ => 0,
    };
    // Per-token locked/minted snapshots — the bridge safety
    // invariant is `total_minted(t) <= total_locked(t)` per token,
    // so a per-(token,side) gauge lets the violation alert pinpoint
    // which asset broke. `seal_bridge_invariant_violated` is the
    // pre-baked any-token flag.
    let mut token_metrics: Vec<(&'static str, u64, u64)> =
        Vec::with_capacity(seal_bridge::WrappedToken::all_variants().len());
    for token in seal_bridge::WrappedToken::all_variants() {
        token_metrics.push((
            token.symbol(),
            bridge.total_locked(token),
            bridge.total_minted(token),
        ));
    }
    let invariant_violated = if bridge.check_invariant() { 0 } else { 1 };
    drop(bridge);

    out.push_str(&format!(
        "# HELP seal_bridge_committee_key_set 1 if BridgeManager has a committee MAC key installed, else 0\n\
         # TYPE seal_bridge_committee_key_set gauge\n\
         seal_bridge_committee_key_set {}\n\
         # HELP seal_bridge_paused_chains Number of source chains currently paused by council vote\n\
         # TYPE seal_bridge_paused_chains gauge\n\
         seal_bridge_paused_chains {}\n\
         # HELP seal_bridge_deposits_total Total deposit records (observed + processed)\n\
         # TYPE seal_bridge_deposits_total gauge\n\
         seal_bridge_deposits_total {}\n\
         # HELP seal_bridge_deposits_pending Deposits observed but not yet processed (waiting for confirmations or paused)\n\
         # TYPE seal_bridge_deposits_pending gauge\n\
         seal_bridge_deposits_pending {}\n\
         # HELP seal_bridge_withdrawals_total Total withdrawal records initiated against the host\n\
         # TYPE seal_bridge_withdrawals_total gauge\n\
         seal_bridge_withdrawals_total {}\n\
         # HELP seal_bridge_committee_key_fingerprint SHA-256 of the host's installed committee key (label-info; empty pre-key)\n\
         # TYPE seal_bridge_committee_key_fingerprint gauge\n\
         seal_bridge_committee_key_fingerprint{{sha2_hex=\"{}\"}} {}\n\
         # HELP seal_bridge_committee_key_persisted 1 if <data_dir>/bridge-committee-key.hex matches the in-memory key; 0 means a rotation succeeded in-memory but the on-disk file is missing/stale and the next restart will revert\n\
         # TYPE seal_bridge_committee_key_persisted gauge\n\
         seal_bridge_committee_key_persisted {}\n\
         # HELP seal_bridge_invariant_violated 1 if total_minted > total_locked on any wrapped token (bridge safety break), else 0\n\
         # TYPE seal_bridge_invariant_violated gauge\n",
        committee_key_set,
        paused_count,
        total_deposits,
        pending_deposits,
        total_withdrawals,
        fingerprint_sha2,
        committee_key_set,
        committee_key_persisted,
    ));
    out.push_str(&format!(
        "seal_bridge_invariant_violated {}\n\
         # HELP seal_bridge_total_locked Total source-chain tokens locked in the bridge vault (per wrapped token)\n\
         # TYPE seal_bridge_total_locked gauge\n\
         # HELP seal_bridge_total_minted Total wrapped tokens minted on Seal (per wrapped token)\n\
         # TYPE seal_bridge_total_minted gauge\n",
        invariant_violated,
    ));
    for (sym, locked, minted) in &token_metrics {
        out.push_str(&format!(
            "seal_bridge_total_locked{{token=\"{}\"}} {}\n\
             seal_bridge_total_minted{{token=\"{}\"}} {}\n",
            sym, locked, sym, minted,
        ));
    }

    // P8 mainnet-gate exposition — gauges so dashboards can alert on
    // misconfigured nodes (admin_threshold drifting between
    // validators in a committee, or rate-limit caps changed under
    // operator's nose by a stale systemd unit).
    out.push_str(&format!(
        "# HELP seal_bridge_withdrawal_fee_base_units Configured per-withdrawal SEAL fee (P8/§4.2)\n\
         # TYPE seal_bridge_withdrawal_fee_base_units gauge\n\
         seal_bridge_withdrawal_fee_base_units {}\n\
         # HELP seal_admin_threshold M-of-N admin multisig threshold (0 or 1 = single-sig; P8/§4.3)\n\
         # TYPE seal_admin_threshold gauge\n\
         seal_admin_threshold {}\n\
         # HELP seal_admin_addresses_count Number of addresses in the admin set\n\
         # TYPE seal_admin_addresses_count gauge\n\
         seal_admin_addresses_count {}\n\
         # HELP seal_rpc_rate_limit_per_minute Per-method-group RPC rate limit (req/min; P8/§4.1)\n\
         # TYPE seal_rpc_rate_limit_per_minute gauge\n\
         seal_rpc_rate_limit_per_minute{{group=\"default\"}} {}\n\
         seal_rpc_rate_limit_per_minute{{group=\"expensive\"}} {}\n\
         seal_rpc_rate_limit_per_minute{{group=\"admin\"}} {}\n",
        state.config.bridge_withdrawal_fee,
        state.config.admin_threshold,
        state.config.admin_addresses.len(),
        state.config.rpm_default,
        state.config.rpm_expensive,
        state.config.rpm_admin,
    ));

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        out,
    )
}

/// GET /status — rich JSON status for dashboards and status pages.
async fn handle_status(State(state): State<RpcState>) -> impl IntoResponse {
    let node = state.node.lock().await;
    let height = node.height();
    let state_root = format!("{}", node.runner.state_root());
    let epoch = node.runner.current_epoch.number;
    let slot = node.runner.current_slot.number;
    let validators = node.runner.validator_set.active_count();
    let leases = node.runner.leases.count();
    drop(node);

    let uptime = state.start_time.elapsed().as_secs();
    let m = &state.metrics;
    let ord = std::sync::atomic::Ordering::Relaxed;

    // Surface the same bridge state /metrics exposes, but in
    // structured JSON for dashboards that prefer /status over
    // scraping Prometheus exposition. Same lock pattern as
    // handle_metrics — short critical section, drop before
    // building the response.
    let bridge = state.bridge.lock().await;
    let bridge_committee_key_set = bridge.has_committee_key();
    let bridge_fingerprint_sha2 = bridge.committee_key_fingerprint_sha256().map(hex::encode);
    let bridge_paused_chains = bridge.paused_chain_count();
    let bridge_deposits_total = bridge.deposit_count();
    let bridge_deposits_pending = bridge.pending_deposit_count();
    let bridge_withdrawals_total = bridge.withdrawal_count();
    let bridge_invariant_holds = bridge.check_invariant();
    drop(bridge);

    Json(serde_json::json!({
        "node": "seal-node",
        "version": env!("CARGO_PKG_VERSION"),
        "chain_id": "seal-testnet-1",
        "height": height,
        "state_root": state_root,
        "epoch": epoch,
        "slot": slot,
        "peers": m.peers_connected.load(ord),
        "uptime_secs": uptime,
        "validators": validators,
        "leases_active": leases,
        "metrics": {
            "blocks_produced": m.blocks_produced.load(ord),
            "blocks_received": m.blocks_received.load(ord),
            "txs_submitted": m.txs_submitted.load(ord),
            "txs_accepted": m.txs_accepted.load(ord),
            "sql_queries": m.sql_queries.load(ord),
            "sql_writes": m.sql_writes.load(ord),
            "fees_collected": m.fees_collected.load(ord),
            "fees_burned": m.fees_burned.load(ord),
        },
        "bridge": {
            "committee_key_set": bridge_committee_key_set,
            "committee_key_fingerprint_sha2_hex": bridge_fingerprint_sha2,
            "paused_chains": bridge_paused_chains,
            "deposits_total": bridge_deposits_total,
            "deposits_pending": bridge_deposits_pending,
            "withdrawals_total": bridge_withdrawals_total,
            "invariant_holds": bridge_invariant_holds,
            "withdrawal_fee_base_units": state.config.bridge_withdrawal_fee,
        },
        // P8 mainnet-gate config snapshot — exposed so operators
        // running `seal status` against a remote node can verify the
        // gate values without SSHing in to inspect the systemd unit.
        // Drift across validators in a committee is a real
        // misconfiguration signal.
        "p8_gates": {
            "admin_threshold": state.config.admin_threshold,
            "admin_addresses_count": state.config.admin_addresses.len(),
            "rate_limits_per_minute": {
                "default": state.config.rpm_default,
                "expensive": state.config.rpm_expensive,
                "admin": state.config.rpm_admin,
            },
        }
    }))
}

// ─── Tests ──────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_response_ok() {
        let resp = RpcResponse::ok(serde_json::json!(1), serde_json::json!({"height": 42}));
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn rate_limiter_isolates_groups_per_ip() {
        // P8/§4.1 — expensive-bucket exhaustion must NOT block
        // cheap-read traffic from the same IP.
        let mut lim = RateLimiter::default();
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        // Fill the expensive bucket.
        for _ in 0..20 {
            assert!(lim.check(ip, RpcGroup::Expensive, 20));
        }
        // 21st expensive request trips.
        assert!(!lim.check(ip, RpcGroup::Expensive, 20));
        // Default bucket still has its full 120-quota — proves the
        // bucket key is (ip, group), not just (ip).
        for _ in 0..120 {
            assert!(lim.check(ip, RpcGroup::Default, 120));
        }
        // Admin is also independent.
        for _ in 0..5 {
            assert!(lim.check(ip, RpcGroup::Admin, 5));
        }
        assert!(!lim.check(ip, RpcGroup::Admin, 5));
    }

    #[test]
    fn admin_multisig_threshold_2_rejects_single_sig() {
        // P8/§4.3 — with threshold 2, the primary signer alone
        // isn't enough; verify_admin_multisig must report the
        // shortfall in the error.
        let mut admin_set = HashSet::new();
        admin_set.insert("seal1adminA".to_string());
        admin_set.insert("seal1adminB".to_string());
        let cfg = RpcConfig {
            admin_addresses: admin_set,
            admin_threshold: 2,
            ..RpcConfig::default()
        };
        let params = serde_json::json!({"foo": "bar"});
        let err = verify_admin_multisig("seal_bridgePauseChain", &params, "seal1adminA", &cfg)
            .expect_err("primary-only must fail at threshold 2");
        assert!(err.contains("2-of-2 admin multisig"), "err: {err}");
        assert!(err.contains("got 1"), "err: {err}");
    }

    #[test]
    fn admin_multisig_threshold_2_accepts_valid_cosig() {
        // Build a real ML-DSA cosigner, derive its address, drop
        // it into admin_addresses, then sign the canonical message
        // (method || params_without_admin_signatures_json) and
        // confirm verify_admin_multisig hits threshold.
        use seal_crypto::signature::SigningKey;
        let (sk, vk) = SigningKey::generate();
        let cosigner_addr = SealAddress::from_verifying_key(&vk, true).to_string_encoding();

        let mut admin_set = HashSet::new();
        admin_set.insert("seal1primary".to_string());
        admin_set.insert(cosigner_addr.clone());
        let cfg = RpcConfig {
            admin_addresses: admin_set,
            admin_threshold: 2,
            testnet: true,
            ..RpcConfig::default()
        };

        let mut params = serde_json::json!({"chain": "Solana"});
        let params_json = serde_json::to_string(&params).unwrap();
        let message = format!("seal_bridgePauseChain{}", params_json);
        let message_hash = sha3_256(message.as_bytes());
        let sig = sk.sign(message_hash.as_ref()).expect("sign");

        params.as_object_mut().unwrap().insert(
            "admin_signatures".into(),
            serde_json::json!([
                {
                    "sender": hex::encode(vk.to_bytes()),
                    "signature": hex::encode(sig.to_bytes()),
                }
            ]),
        );

        verify_admin_multisig("seal_bridgePauseChain", &params, "seal1primary", &cfg)
            .expect("primary + 1 valid cosig at threshold 2 must pass");
    }

    #[test]
    fn admin_multisig_dedups_repeated_cosigner() {
        // Same cosigner submitted twice must count as one — the
        // dedup set is keyed on derived address. Otherwise an
        // attacker with one stolen admin key could forge an M-of-N
        // by replaying the same signature M times.
        use seal_crypto::signature::SigningKey;
        let (sk, vk) = SigningKey::generate();
        let cosigner_addr = SealAddress::from_verifying_key(&vk, true).to_string_encoding();

        let mut admin_set = HashSet::new();
        admin_set.insert("seal1primary".to_string());
        admin_set.insert(cosigner_addr.clone());
        let cfg = RpcConfig {
            admin_addresses: admin_set,
            admin_threshold: 3,
            testnet: true,
            ..RpcConfig::default()
        };

        let mut params = serde_json::json!({"chain": "Solana"});
        let params_json = serde_json::to_string(&params).unwrap();
        let message = format!("seal_bridgePauseChain{}", params_json);
        let message_hash = sha3_256(message.as_bytes());
        let sig = sk.sign(message_hash.as_ref()).expect("sign");
        let sig_hex = hex::encode(sig.to_bytes());
        let vk_hex = hex::encode(vk.to_bytes());

        params.as_object_mut().unwrap().insert(
            "admin_signatures".into(),
            serde_json::json!([
                {"sender": vk_hex.clone(), "signature": sig_hex.clone()},
                {"sender": vk_hex, "signature": sig_hex},
            ]),
        );

        let err = verify_admin_multisig("seal_bridgePauseChain", &params, "seal1primary", &cfg)
            .expect_err("repeated cosigner must NOT push count to 3");
        assert!(err.contains("got 2"), "err: {err}");
    }

    #[test]
    fn rpc_config_default_carries_zero_bridge_fee() {
        // P8/§4.2 — fee is opt-in. The default must stay 0 so
        // testnet operators don't suddenly start paying for what
        // they got for free in the previous release.
        let c = RpcConfig::default();
        assert_eq!(c.bridge_withdrawal_fee, 0);
    }

    #[test]
    fn rpc_group_classifier_buckets_correctly() {
        // Admin set.
        assert_eq!(
            rpc_group_for_method("seal_addBridgeObserver"),
            RpcGroup::Admin
        );
        assert_eq!(
            rpc_group_for_method("seal_bridgePauseChain"),
            RpcGroup::Admin
        );
        assert_eq!(
            rpc_group_for_method("seal_bridgeRotateCommitteeKey"),
            RpcGroup::Admin
        );
        // Expensive set.
        assert_eq!(rpc_group_for_method("seal_submitSql"), RpcGroup::Expensive);
        assert_eq!(
            rpc_group_for_method("seal_bridgeWithdraw"),
            RpcGroup::Expensive
        );
        assert_eq!(rpc_group_for_method("seal_govPropose"), RpcGroup::Expensive);
        // Default.
        assert_eq!(rpc_group_for_method("seal_querySql"), RpcGroup::Default);
        assert_eq!(rpc_group_for_method("seal_getHeight"), RpcGroup::Default);
        assert_eq!(
            rpc_group_for_method("seal_bridgeRingtailStatus"),
            RpcGroup::Default
        );
    }

    #[test]
    fn test_rpc_response_err() {
        let resp = RpcResponse::err(serde_json::json!(1), -32601, "not found".into());
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[test]
    fn test_requires_auth() {
        assert!(requires_auth("seal_submitSql"));
        assert!(requires_auth("seal_deployNamespace"));
        assert!(!requires_auth("seal_querySql"));
        assert!(!requires_auth("seal_getHeight"));
        // Token mutations
        assert!(requires_auth("seal_mintToken"));
        assert!(requires_auth("seal_transferToken"));
        assert!(requires_auth("seal_burnToken"));
        assert!(requires_auth("seal_freezeAccount"));
        assert!(requires_auth("seal_unfreezeAccount"));
        assert!(requires_auth("seal_setTokenFrozen"));
        assert!(requires_auth("seal_setMintAuthority"));
        assert!(requires_auth("seal_setFreezeAuthority"));
        assert!(requires_auth("seal_setFeeAuthority"));
        assert!(requires_auth("seal_renounceMintAuthority"));
        assert!(requires_auth("seal_renounceFreezeAuthority"));
        assert!(requires_auth("seal_renounceFeeAuthority"));
        assert!(requires_auth("seal_setFeeRecipient"));
        // Bridge relayer mark-executed (P1#3 per-validator custody)
        // is a regular auth-gated method — the handler enforces the
        // additional validator-set membership check.
        assert!(requires_auth("seal_bridgeMarkExecuted"));
        // Reads stay open
        assert!(!requires_auth("seal_listTokens"));
        assert!(!requires_auth("seal_listTokensByCreator"));
        assert!(!requires_auth("seal_listTokensByMintAuthority"));
        assert!(!requires_auth("seal_listTokensByFreezeAuthority"));
        assert!(!requires_auth("seal_listTokensByFeeAuthority"));
        assert!(!requires_auth("seal_listPrivateTables"));
        assert!(!requires_auth("seal_listPrivateTablesByOwner"));
        assert!(!requires_auth("seal_listLeases"));
        assert!(!requires_auth("seal_listLeasesByOwner"));
        assert!(!requires_auth("seal_getNamespaces"));
        assert!(!requires_auth("seal_listNamespacesByOwner"));
        assert!(!requires_auth("seal_getBridgeDeposits"));
        assert!(!requires_auth("seal_listBridgeDepositsByRecipient"));
        assert!(!requires_auth("seal_listBridgeWithdrawals"));
        assert!(!requires_auth("seal_listBridgeWithdrawalsByInitiator"));
        assert!(!requires_auth("seal_getBridgeWithdrawal"));
        assert!(!requires_auth("seal_getValidatorByAddress"));
        assert!(!requires_auth("seal_getCouncilMemberByAddress"));
        assert!(!requires_auth("seal_getTokenBalance"));
        assert!(!requires_auth("seal_isFrozen"));
        // Admin-gated methods are NOT in `requires_auth` itself —
        // their auth requirement only kicks in when admin_addresses
        // is populated, so the alpha-testnet bootstrap (bridge-e2e.sh
        // sending unsigned RPCs) keeps working.
        assert!(!requires_auth("seal_addBridgeObserver"));
        assert!(!requires_auth("seal_bridgeCouncilAdd"));
        assert!(!requires_auth("seal_bridgePauseChain"));
    }

    #[test]
    fn test_requires_admin_auth() {
        // Admin-gated methods.
        assert!(requires_admin_auth("seal_addBridgeObserver"));
        assert!(requires_admin_auth("seal_bridgeCouncilAdd"));
        assert!(requires_admin_auth("seal_bridgeCouncilRemove"));
        assert!(requires_admin_auth("seal_bridgePauseChain"));
        assert!(requires_admin_auth("seal_bridgeUnpauseChain"));
        assert!(requires_admin_auth("seal_bridgeRotateCommitteeKey"));
        // Read methods stay out of the admin gate.
        assert!(!requires_admin_auth("seal_bridgeListPaused"));
        assert!(!requires_admin_auth("seal_bridgeCouncilList"));
        assert!(!requires_admin_auth("seal_listBridgeObservers"));
        assert!(!requires_admin_auth("seal_bridgeGetCommitteeKeyStatus"));
        // Bridge withdrawal is a regular signed-caller method, not
        // admin-gated — anyone with wrapped tokens can withdraw.
        assert!(!requires_admin_auth("seal_bridgeWithdraw"));
    }

    #[test]
    fn test_is_admin_open_mode() {
        // Empty admin_addresses = open mode: any caller passes,
        // including the unsigned-fallback empty string.
        let config = RpcConfig::default();
        assert!(is_admin("seal1alice", &config));
        assert!(is_admin("seal1bob", &config));
        assert!(is_admin("", &config));
    }

    #[test]
    fn test_is_admin_gated_mode() {
        // Populated admin_addresses = gated mode: only members pass.
        let mut config = RpcConfig::default();
        config.admin_addresses.insert("seal1alice".into());
        config.admin_addresses.insert("seal1bob".into());
        assert!(is_admin("seal1alice", &config));
        assert!(is_admin("seal1bob", &config));
        // Non-members rejected.
        assert!(!is_admin("seal1eve", &config));
        // Empty caller (unsigned fallback) rejected.
        assert!(!is_admin("", &config));
    }

    // ── Recipient-new-account policy ──────────────────────────

    #[test]
    fn test_recipient_policy_block_default_rejects_new() {
        let config = RpcConfig::default();
        assert!(!config.allow_new_recipients);
        let params = serde_json::json!({});
        let err = check_recipient_policy(&config, &params, false, "seal1new").unwrap_err();
        assert_eq!(err.0, -32007);
        assert!(err.1.contains("seal1new"));
        assert!(err.1.contains("confirm_new_recipient"));
    }

    #[test]
    fn test_recipient_policy_block_accepts_existing() {
        let config = RpcConfig::default();
        let params = serde_json::json!({});
        // recipient_known=true → existing account, no confirm needed.
        check_recipient_policy(&config, &params, true, "seal1known").unwrap();
    }

    #[test]
    fn test_recipient_policy_confirm_unblocks_new() {
        let config = RpcConfig::default();
        let params = serde_json::json!({"confirm_new_recipient": true});
        check_recipient_policy(&config, &params, false, "seal1new").unwrap();
    }

    #[test]
    fn test_recipient_policy_confirm_false_still_blocks() {
        let config = RpcConfig::default();
        let params = serde_json::json!({"confirm_new_recipient": false});
        assert!(check_recipient_policy(&config, &params, false, "seal1new").is_err());
    }

    #[test]
    fn test_recipient_policy_allow_mode_skips_check() {
        let config = RpcConfig {
            allow_new_recipients: true,
            ..RpcConfig::default()
        };
        let params = serde_json::json!({});
        // Even with new recipient and no confirm, allow mode lets it through.
        check_recipient_policy(&config, &params, false, "seal1new").unwrap();
    }

    #[test]
    fn test_recipient_policy_non_bool_confirm_treated_as_false() {
        let config = RpcConfig::default();
        // String "true" is not a JSON bool — must be rejected, not coerced.
        let params = serde_json::json!({"confirm_new_recipient": "true"});
        assert!(check_recipient_policy(&config, &params, false, "seal1new").is_err());
    }

    // ── min-opening-balance policy ────────────────────────────────

    #[test]
    fn test_min_opening_balance_disabled_by_default() {
        let config = RpcConfig::default();
        assert_eq!(config.min_opening_balance, 0);
        // Threshold 0 → always Ok.
        check_min_opening_balance(&config, false, 1, "seal1new").unwrap();
        check_min_opening_balance(&config, false, 0, "seal1new").unwrap();
        check_min_opening_balance(&config, true, 0, "seal1known").unwrap();
    }

    #[test]
    fn test_min_opening_balance_known_recipient_always_ok() {
        let config = RpcConfig {
            min_opening_balance: 100_000,
            ..RpcConfig::default()
        };
        // Existing recipients are exempt regardless of amount.
        check_min_opening_balance(&config, true, 1, "seal1known").unwrap();
        check_min_opening_balance(&config, true, 0, "seal1known").unwrap();
    }

    #[test]
    fn test_min_opening_balance_rejects_below_threshold() {
        let config = RpcConfig {
            min_opening_balance: 100_000,
            ..RpcConfig::default()
        };
        // Fresh recipient + amount 99_999 → reject.
        let err = check_min_opening_balance(&config, false, 99_999, "seal1new").unwrap_err();
        assert_eq!(err.0, -32008);
        assert!(err.1.contains("99999"));
        assert!(err.1.contains("100000"));
        assert!(err.1.contains("seal1new"));
    }

    #[test]
    fn test_min_opening_balance_accepts_exact_threshold() {
        let config = RpcConfig {
            min_opening_balance: 100_000,
            ..RpcConfig::default()
        };
        // Exact threshold passes (the check is strict-less-than).
        check_min_opening_balance(&config, false, 100_000, "seal1new").unwrap();
        check_min_opening_balance(&config, false, 100_001, "seal1new").unwrap();
    }

    #[test]
    fn test_min_opening_balance_independent_of_allow_new_recipients() {
        // Faucet/bridge node: allow_new_recipients=true *and* a
        // non-zero min_opening_balance. Both checks run; min-opening
        // can still reject a fresh recipient even with allow=true.
        let config = RpcConfig {
            allow_new_recipients: true,
            min_opening_balance: 100_000,
            ..RpcConfig::default()
        };
        // recipient_policy passes (allow mode), but min_opening
        // rejects on its own.
        let params = serde_json::json!({});
        check_recipient_policy(&config, &params, false, "seal1new").unwrap();
        let err = check_min_opening_balance(&config, false, 1, "seal1new").unwrap_err();
        assert_eq!(err.0, -32008);
    }

    #[test]
    fn test_rpc_config_default() {
        let config = RpcConfig::default();
        assert!(config.served_namespaces.is_empty());
        assert!(!config.require_auth_for_reads);
        assert_eq!(config.max_query_length, 64 * 1024);
    }

    #[test]
    fn test_namespace_routing() {
        let mut config = RpcConfig::default();
        config.served_namespaces.insert("blog.seal".into());
        assert!(config.served_namespaces.contains("blog.seal"));
        assert!(!config.served_namespaces.contains("market.seal"));
    }

    // ── Bridge RPC helpers ─────────────────────────────────────

    #[test]
    fn test_parse_chain_accepts_case_insensitive_aliases() {
        assert_eq!(parse_chain("Solana").unwrap(), Chain::Solana);
        assert_eq!(parse_chain("solana").unwrap(), Chain::Solana);
        assert_eq!(parse_chain("SOL").unwrap(), Chain::Solana);
        assert_eq!(parse_chain("Stellar").unwrap(), Chain::Stellar);
        assert_eq!(parse_chain("xlm").unwrap(), Chain::Stellar);
    }

    #[test]
    fn test_parse_chain_rejects_unknown() {
        let err = parse_chain("ethereum").unwrap_err();
        assert_eq!(err.0, -32602);
        assert!(err.1.contains("ethereum"));
    }

    #[test]
    fn test_parse_wrapped_token_covers_every_variant() {
        assert_eq!(parse_wrapped_token("WSOL").unwrap(), WrappedToken::WSOL);
        assert_eq!(parse_wrapped_token("SOL").unwrap(), WrappedToken::WSOL);
        assert_eq!(parse_wrapped_token("wxlm").unwrap(), WrappedToken::WXLM);
        assert_eq!(parse_wrapped_token("XLM").unwrap(), WrappedToken::WXLM);
        assert_eq!(parse_wrapped_token("wusdc").unwrap(), WrappedToken::WUSDC);
        assert_eq!(parse_wrapped_token("USDC").unwrap(), WrappedToken::WUSDC);
    }

    #[test]
    fn test_parse_wrapped_token_rejects_unknown() {
        assert!(parse_wrapped_token("WETH").is_err());
    }

    // ── Bridge pause helpers ──────────────────────────────────

    #[test]
    fn test_parse_string_array_happy_path() {
        let v = serde_json::json!(["m0", "m1", "m2"]);
        let parsed = parse_string_array(&v, "approvers").unwrap();
        assert_eq!(parsed, vec!["m0", "m1", "m2"]);
    }

    #[test]
    fn test_parse_string_array_rejects_non_array() {
        let v = serde_json::json!("nope");
        let err = parse_string_array(&v, "approvers").unwrap_err();
        assert_eq!(err.0, -32602);
        assert!(err.1.contains("approvers"));
    }

    #[test]
    fn test_parse_string_array_rejects_non_string_entry() {
        let v = serde_json::json!(["ok", 42]);
        let err = parse_string_array(&v, "approvers").unwrap_err();
        assert_eq!(err.0, -32602);
        assert!(err.1.contains("entries"));
    }

    #[test]
    fn test_parse_string_array_accepts_empty() {
        let v = serde_json::json!([]);
        let parsed = parse_string_array(&v, "approvers").unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_bridge_pause_council_quorum_logic() {
        // Integration-style: build a council, check that 2/3 of its
        // members is enough to approve a pause, fewer is not. Mirrors
        // the code path inside handle_bridge_pause_chain without
        // needing an RpcState.
        let mut tc = TechnicalCouncil::new();
        for i in 0..9 {
            tc.add_member(CouncilMember {
                pubkey: format!("pk_{}", i),
                name: format!("M{}", i),
                term_start_epoch: 0,
                term_end_epoch: 26280,
            })
            .unwrap();
        }
        // 9 members → 2/3 = 6.
        assert_eq!(tc.two_thirds_threshold(), 6);
        // 5 approvers → insufficient.
        let five: Vec<String> = (0..5).map(|i| format!("pk_{}", i)).collect();
        assert!(!tc.has_two_thirds_approval(&five));
        // 6 approvers → approved.
        let six: Vec<String> = (0..6).map(|i| format!("pk_{}", i)).collect();
        assert!(tc.has_two_thirds_approval(&six));
    }
}
