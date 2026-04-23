//! JSON-RPC 2.0 server for seal-node.
//!
//! Features:
//! - ML-DSA signature authentication on mutating requests
//! - RLS enforcement on SQL queries
//! - Namespace-aware query routing
//! - MPC aggregate and ZK proof endpoints
//! - Chain state inspection

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::{get, post}, Json, Router};
use seal_crypto::address::SealAddress;
use seal_crypto::hash::sha3_256;
use seal_crypto::signature::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

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
        }
    }
}

/// Per-IP rate limiter.
#[derive(Default)]
pub struct RateLimiter {
    /// Requests per IP in the current window.
    requests: std::collections::HashMap<std::net::IpAddr, (u64, std::time::Instant)>,
}

impl RateLimiter {
    /// Check if a request from this IP should be allowed.
    /// Returns false if rate limit exceeded.
    pub fn check(&mut self, ip: std::net::IpAddr, max_per_minute: u64) -> bool {
        let now = std::time::Instant::now();
        let entry = self.requests.entry(ip).or_insert((0, now));

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
pub async fn start_rpc_server(node: Arc<Mutex<NetworkNode>>, config: RpcConfig, port: u16) {
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
        // BridgeManager default requires 1 confirmation so the e2e
        // round-trip doesn't need 32 Solana slots of patience. Set to
        // 32 in production via config once we're past alpha.
        bridge: Arc::new(Mutex::new(BridgeManager::new(1))),
        observers: Arc::new(Mutex::new(BridgeObserverSet::new())),
        council: Arc::new(Mutex::new(TechnicalCouncil::new())),
        faucet_drips: Arc::new(Mutex::new(std::collections::HashMap::new())),
    };

    use axum::http::{HeaderValue, Method};
    use axum::http::header;

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
        .with_state(state);

    // Bind to localhost only — unencrypted RPC must never be exposed to the network.
    // Remote access requires PQ-encrypted transport (ML-KEM handshake on P2P layer).
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("RPC server listening on http://{} (localhost only, {} req/min)", addr, max_rpm);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Failed to bind RPC server on port {}: {}", port, e);
            return;
        }
    };

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    ).await {
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
    let vk_bytes =
        hex::decode(sender_hex).map_err(|_| (-32003, "invalid sender hex".into()))?;
    let vk = VerifyingKey::from_bytes(&vk_bytes)
        .map_err(|_| (-32003, "invalid sender public key".into()))?;

    // Decode signature
    let sig_bytes =
        hex::decode(sig_hex).map_err(|_| (-32003, "invalid signature hex".into()))?;
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
            | "seal_setTransferFee"
            | "seal_createPair"
            | "seal_placeOrder"
            | "seal_cancelOrder"
            | "seal_createPrivateTable"
            | "seal_setVisibility"
            | "seal_enableRls"
            | "seal_addPolicy"
            // Bridge mutations require a signed sender so we know whose
            // wrapped balance to burn when they initiate a withdrawal.
            | "seal_bridgeWithdraw"
            // Governance mutations bind the caller's ML-DSA address as
            // proposer / voter / delegator. Reads stay open.
            | "seal_govPropose"
            | "seal_govVote"
            | "seal_govWithdrawVote"
            | "seal_govDelegate"
            | "seal_govRevokeDelegation"
    )
}

// ─── Request Handler ────────────────────────────────

async fn handle_rpc(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    State(state): State<RpcState>,
    Json(req): Json<RpcRequest>,
) -> (StatusCode, Json<RpcResponse>) {
    let id = req.id.clone();

    // Rate limiting
    {
        let mut limiter = state.rate_limiter.lock().await;
        if !limiter.check(addr.ip(), state.config.max_requests_per_minute) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(RpcResponse::err(id, -32005, "rate limit exceeded".into())),
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

    // Authenticate if required
    let caller = if requires_auth(&req.method) {
        match authenticate(&req, state.config.testnet) {
            Ok(c) => Some(c),
            Err((code, msg)) => {
                return (
                    StatusCode::OK,
                    Json(RpcResponse::err(id, code as i64, msg)),
                )
            }
        }
    } else if req.signature.is_some() {
        // Optional auth on reads — verify if provided
        authenticate(&req, state.config.testnet).ok()
    } else {
        None
    };

    let caller_addr = caller.as_ref().map(|c| c.address.as_str());

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
        "seal_getNodeInfo" => handle_get_node_info(&state).await,

        // Private tables
        "seal_createPrivateTable" => {
            handle_create_private_table(&state, &req.params, caller_addr.unwrap_or("anonymous"))
                .await
        }
        "seal_listPrivateTables" => handle_list_private_tables(&state).await,

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
        "seal_getTokenBalance" => handle_get_token_balance(&state, &req.params).await,
        "seal_listTokens" => handle_list_tokens(&state).await,
        "seal_setTransferFee" => {
            handle_set_transfer_fee(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_getTransferFee" => handle_get_transfer_fee(&state, &req.params).await,

        // DEX
        "seal_createPair" => {
            handle_create_pair(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_placeOrder" => {
            handle_place_order(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_cancelOrder" => {
            handle_cancel_order(&state, &req.params).await
        }
        "seal_getOrderBook" => handle_get_order_book(&state, &req.params).await,
        "seal_listPairs" => handle_list_pairs(&state).await,

        // PQ transport
        "seal_pqHandshake" => handle_pq_handshake(&state, &req.params).await,

        // Cross-chain bridge
        "seal_getBridgeDeposits" => handle_get_bridge_deposits(&state, &req.params).await,
        "seal_getBridgeStatus" => handle_get_bridge_status(&state).await,
        "seal_getBridgeWrappedBalance" => {
            handle_get_bridge_wrapped_balance(&state, &req.params).await
        }
        "seal_bridgeWithdraw" => {
            handle_bridge_withdraw(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_addBridgeObserver" => handle_add_bridge_observer(&state, &req.params).await,
        "seal_listBridgeObservers" => handle_list_bridge_observers(&state).await,
        "seal_pollBridges" => handle_poll_bridges(&state).await,

        // Bridge emergency pause (Technical Council 2/3 vote)
        "seal_bridgePauseChain" => handle_bridge_pause_chain(&state, &req.params).await,
        "seal_bridgeUnpauseChain" => handle_bridge_unpause_chain(&state, &req.params).await,
        "seal_bridgeListPaused" => handle_bridge_list_paused(&state).await,
        "seal_bridgeCouncilAdd" => handle_bridge_council_add(&state, &req.params).await,
        "seal_bridgeCouncilRemove" => handle_bridge_council_remove(&state, &req.params).await,
        "seal_bridgeCouncilList" => handle_bridge_council_list(&state).await,

        // Governance: 6 proposal tracks + conviction voting + delegation.
        "seal_govPropose" => {
            handle_gov_propose(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_govVote" => {
            handle_gov_vote(&state, &req.params, caller_addr.unwrap_or("anonymous")).await
        }
        "seal_govWithdrawVote" => {
            handle_gov_withdraw_vote(&state, &req.params, caller_addr.unwrap_or("anonymous"))
                .await
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
            handle_gov_revoke_delegation(
                &state,
                &req.params,
                caller_addr.unwrap_or("anonymous"),
            )
            .await
        }
        "seal_govEffectiveWeight" => handle_gov_effective_weight(&state, &req.params).await,

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
            return Err((-32004, format!("namespace '{}' not served by this node", ns)));
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
            return Err((-32004, format!("namespace '{}' not served by this node", ns)));
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

async fn handle_get_namespaces(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
    let ns = state.namespaces.lock().await;
    Ok(serde_json::json!({
        "namespaces": *ns,
    }))
}

// ─── Chain State Handlers ───────────────────────────

async fn handle_get_height(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let node = state.node.lock().await;
    Ok(serde_json::json!({ "height": node.height() }))
}

async fn handle_get_state_root(state: &RpcState) -> Result<serde_json::Value, (i32, String)> {
    let node = state.node.lock().await;
    Ok(serde_json::json!({ "state_root": node.state_root().to_string() }))
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
                (values.iter().sum::<i64>() / values.len() as i64, values.len())
            }
        }
        _ => unreachable!(),
    };

    // Also compute via SPDZ to demonstrate the protocol
    let spdz_result = if !values.is_empty() && function == "sum" {
        use seal_mpc::spdz::{SpdzParty, spdz_sum};
        let party = SpdzParty::new(0, 42, 1, b"seal-mpc-seed");
        let shares: Vec<_> = values.iter().map(|v| {
            let (s1, _s2) = party.share_value(*v as u64, 0);
            s1
        }).collect();
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
    use seal_zk::traits::{ZkProver, StateTransition};

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
    let zk_proof = prover.prove(transition)
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

async fn handle_list_private_tables(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
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

// ─── Token Handlers ─────────────────────────────────

async fn handle_get_balance(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params.get("address").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
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
    // Basic shape check — full bech32m validation lives behind the
    // broader address-validation todo. We at least reject obvious
    // placeholder strings so `seal1...` can't drain the drip cap.
    // Accept both mainnet (`seal1…`) and testnet (`sealt1…`) HRPs
    // per crates/seal-crypto/src/address.rs.
    let has_valid_hrp = address.starts_with("seal1") || address.starts_with("sealt1");
    if !has_valid_hrp || address.len() < 10 || address.contains('.') {
        return Err((-32602, "invalid address".into()));
    }
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
        let entry = drips
            .entry(address.to_string())
            .or_insert((0, now));
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
    let to = params.get("to").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'to' param".into()))?;
    let amount = params.get("amount").and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'amount' param".into()))?;

    // Reject malformed recipients before the ledger `entry().or_default()`
    // silently creates a ghost account and burns the funds. `SealAddress`
    // runs the full bech32m check (HRP + checksum + 32-byte payload),
    // so placeholders like "sealt1recipient…" (with an ellipsis) fail here.
    SealAddress::from_string_encoding(to).map_err(|e| {
        (-32602, format!("invalid 'to' address: {e}"))
    })?;

    let mut node = state.node.lock().await;
    node.runner.balances.transfer(caller, to, amount)
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
    let symbol = params.get("symbol").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let name = params.get("name").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'name' param".into()))?;
    let decimals = params.get("decimals").and_then(|v| v.as_u64()).unwrap_or(9) as u8;
    let max_supply = params.get("max_supply").and_then(|v| v.as_u64()).unwrap_or(0);

    let mut mgr = state.token_manager.lock().await;
    let info = mgr.create_token(symbol.into(), name.into(), decimals, max_supply, caller.into())
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
    let symbol = params.get("symbol").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let to = params.get("to").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'to' param".into()))?;
    let amount = params.get("amount").and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'amount' param".into()))?;

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
    let symbol = params.get("symbol").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let to = params.get("to").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'to' param".into()))?;
    let amount = params.get("amount").and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'amount' param".into()))?;

    let mut mgr = state.token_manager.lock().await;
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

async fn handle_get_token_balance(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params.get("symbol").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let address = params.get("address").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    SealAddress::from_string_encoding(address).map_err(|e| {
        (-32602, format!("invalid 'address': {e}"))
    })?;

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

async fn handle_list_tokens(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
    let mgr = state.token_manager.lock().await;
    let tokens: Vec<serde_json::Value> = mgr.list_tokens().iter().map(|t| {
        serde_json::json!({
            "symbol": t.symbol,
            "name": t.name,
            "decimals": t.decimals,
            "total_supply": t.total_supply,
            "max_supply": t.max_supply,
            "creator": t.creator,
            "transfer_fee_bps": t.transfer_fee_bps,
        })
    }).collect();
    Ok(serde_json::json!({ "tokens": tokens }))
}

/// Set the transfer fee (in basis points, 1 bp = 0.01%) on a custom
/// token. Only the token creator may call this; `TokenManager` enforces
/// the caller check. Range 0..=10000 (0%..=100%).
async fn handle_set_transfer_fee(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params.get("symbol").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;
    let fee_bps = params.get("fee_bps").and_then(|v| v.as_u64())
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

/// Read the current transfer fee for a token. Free query; no auth.
async fn handle_get_transfer_fee(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let symbol = params.get("symbol").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'symbol' param".into()))?;

    let mgr = state.token_manager.lock().await;
    let info = mgr.get_token(symbol)
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
    let base = params.get("base").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'base' param".into()))?;
    let quote = params.get("quote").and_then(|v| v.as_str())
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
    let pair = params.get("pair").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'pair' param".into()))?;
    let side = match params.get("side").and_then(|v| v.as_str()) {
        Some("bid" | "buy") => seal_token::orderbook::Side::Bid,
        Some("ask" | "sell") => seal_token::orderbook::Side::Ask,
        _ => return Err((-32602, "missing 'side' param (bid/ask)".into())),
    };
    let price = params.get("price").and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'price' param".into()))?;
    let quantity = params.get("quantity").and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'quantity' param".into()))?;

    let mut dex = state.dex.lock().await;
    let book = dex.get_book_mut(pair)
        .ok_or((-32000, format!("pair '{}' not found", pair)))?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let order_id = book.place_order(
        caller.into(), side, price, quantity,
        seal_token::orderbook::OrderType::Limit, timestamp,
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
    let pair = params.get("pair").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'pair' param".into()))?;
    let order_id = params.get("order_id").and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'order_id' param".into()))?;

    let mut dex = state.dex.lock().await;
    let book = dex.get_book_mut(pair)
        .ok_or((-32000, format!("pair '{}' not found", pair)))?;
    book.cancel_order(order_id)
        .map_err(|e| (-32000, format!("{}", e)))?;

    Ok(serde_json::json!({ "cancelled": order_id }))
}

async fn handle_get_order_book(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let pair = params.get("pair").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'pair' param".into()))?;
    let depth = params.get("depth").and_then(|v| v.as_u64()).unwrap_or(10) as usize;

    let dex = state.dex.lock().await;
    let book = dex.get_book(pair)
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

async fn handle_list_pairs(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
    let dex = state.dex.lock().await;
    let pairs: Vec<serde_json::Value> = dex.list_pairs().iter().map(|p| {
        serde_json::json!({
            "pair": format!("{}/{}", p.base, p.quote),
            "last_price": p.last_price,
            "volume_24h": p.volume_24h,
            "trade_count": p.trade_count,
        })
    }).collect();
    Ok(serde_json::json!({ "pairs": pairs }))
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
    let chain_filter = if let Some(c) = params.get(0).and_then(|v| v.as_str()) {
        Some(parse_chain(c)?)
    } else {
        None
    };
    let bridge = state.bridge.lock().await;
    let deposits = bridge.list_deposits(chain_filter.as_ref());
    Ok(serde_json::to_value(deposits).unwrap_or(serde_json::json!([])))
}

/// `seal_getBridgeStatus`: aggregate view — total locked and minted
/// per wrapped token, plus the invariant check (minted <= locked).
async fn handle_get_bridge_status(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
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

/// `seal_getBridgeWrappedBalance`: wrapped-token balance for a
/// seal address.
///
/// Params: `{"address": "seal1…", "token": "WSOL"}`.
async fn handle_get_bridge_wrapped_balance(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let address = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'address' param".into()))?;
    let token = params
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'token' param".into()))?;
    let token = parse_wrapped_token(token)?;
    let bridge = state.bridge.lock().await;
    let balance = bridge.wrapped_balance(address, &token);
    Ok(serde_json::json!({ "address": address, "token": token.symbol(), "balance": balance }))
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
    let mut bridge = state.bridge.lock().await;
    let withdrawal_id = bridge
        .initiate_withdrawal(caller, dest_chain, dest_address, token, amount)
        .map_err(|e| (-32000, format!("withdraw failed: {}", e)))?;
    Ok(serde_json::json!({
        "withdrawal_id": withdrawal_id,
        "caller": caller,
    }))
}

/// `seal_addBridgeObserver`: register a chain observer so subsequent
/// `seal_pollBridges` calls see its events. No auth for testnet; in
/// production this will be admin-gated once the bridge param-store
/// lands. Params:
///   `{"chain": "Solana", "rpc_url": "http://localhost:8899",
///     "program_id": "SealBridge11..." }`
/// For Stellar: `"horizon_url"` instead of `"rpc_url"`, and
/// `"contract_id"` instead of `"program_id"`.
async fn handle_add_bridge_observer(
    state: &RpcState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (i32, String)> {
    let chain = params
        .get("chain")
        .and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'chain' param".into()))?;
    let chain = parse_chain(chain)?;
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
            set.add_observer(Box::new(SolanaObserver::new(rpc_url, program_id)));
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
            set.add_observer(Box::new(StellarObserver::new(horizon_url, contract_id)));
        }
    }
    Ok(serde_json::json!({ "chain": chain.to_string(), "ok": true }))
}

/// `seal_listBridgeObservers`: debug-level view of configured chains.
async fn handle_list_bridge_observers(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
    let set = state.observers.lock().await;
    Ok(serde_json::json!({ "count": set.observer_count() }))
}

/// `seal_pollBridges`: run one observation round across all
/// configured observers. Each returned deposit is fed into
/// `BridgeManager::observe_deposit`; already-observed deposit IDs
/// are ignored (the returned `new`/`duplicate` counts reflect that).
///
/// In production a background task calls this every ~10 s. For
/// `bridge-e2e.sh` and local debugging we expose it as an explicit
/// RPC so the test can observe at a known point.
async fn handle_poll_bridges(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
    // The observer trait uses blocking I/O (reqwest::blocking). We
    // must not call it with an async mutex held because the mutex
    // would then span a sync HTTP fetch that could stall for
    // seconds. Take a clone of the observer set under the lock, drop
    // the lock, then poll outside it. `BridgeObserverSet` isn't
    // Clone, so use a scoped lock + `poll_all` that owns the lock
    // briefly; for the simple one-shot poll the blocking time
    // against localhost RPC is small enough to be acceptable.
    let mut observers = state.observers.lock().await;
    // Run the sync poll on a blocking task so the async runtime
    // doesn't lose a worker thread for seconds while the HTTP
    // fetches complete. We need a &mut borrow across an await
    // point, so pass ownership to spawn_blocking via std::mem::take.
    let observer_set = std::mem::take(&mut *observers);
    let (observer_set, poll_result) = tokio::task::spawn_blocking(move || {
        let mut set = observer_set;
        let result = set.poll_all();
        (set, result)
    })
    .await
    .map_err(|e| (-32000, format!("bridge poll task panicked: {}", e)))?;
    *observers = observer_set;
    drop(observers);
    let deposits = poll_result
        .map_err(|e| (-32000, format!("bridge poll failed: {}", e)))?;

    let mut new_count = 0u64;
    let mut duplicate_count = 0u64;
    {
        let mut bridge = state.bridge.lock().await;
        for d in deposits.iter() {
            match bridge.observe_deposit(d.clone()) {
                Ok(()) => new_count += 1,
                Err(seal_bridge::BridgeError::DepositAlreadyProcessed(_)) => {
                    duplicate_count += 1;
                }
                Err(e) => {
                    warn!("bridge observe_deposit error: {}", e);
                }
            }
        }
    }
    Ok(serde_json::json!({
        "observed": deposits.len(),
        "new": new_count,
        "duplicate": duplicate_count,
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
async fn handle_bridge_list_paused(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
    let bridge = state.bridge.lock().await;
    let paused: Vec<serde_json::Value> = bridge
        .list_paused_chains()
        .into_iter()
        .map(|(c, r)| serde_json::json!({ "chain": c.to_string(), "reason": r }))
        .collect();
    Ok(serde_json::json!({ "paused": paused }))
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
    council
        .add_member(member)
        .map_err(|e| (-32000, e))?;
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
    council
        .remove_member(pubkey)
        .map_err(|e| (-32000, e))?;
    Ok(serde_json::json!({
        "pubkey": pubkey,
        "member_count": council.member_count(),
    }))
}

/// `seal_bridgeCouncilList`: seated council members, sorted by
/// pubkey. Includes the 2/3 supermajority threshold so CLI clients
/// can tell users how many signatures they need.
async fn handle_bridge_council_list(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
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

async fn handle_gov_list_proposals(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
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

async fn handle_get_node_info(
    state: &RpcState,
) -> Result<serde_json::Value, (i32, String)> {
    let node = state.node.lock().await;
    let height = node.height();
    let epoch = node.runner.current_epoch.number;
    let validators = node.runner.validator_set.active_count();
    let leases = node.runner.leases.count();
    drop(node);

    let uptime = state.start_time.elapsed().as_secs();
    let peers = state.metrics.peers_connected.load(std::sync::atomic::Ordering::Relaxed);

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
async fn handle_health(State(state): State<RpcState>) -> impl IntoResponse {
    let node = state.node.lock().await;
    let height = node.height();
    drop(node);

    let uptime = state.start_time.elapsed().as_secs();
    let peers = state.metrics.peers_connected.load(std::sync::atomic::Ordering::Relaxed);

    Json(serde_json::json!({
        "status": "ok",
        "height": height,
        "peers": peers,
        "uptime_secs": uptime,
    }))
}

/// GET /metrics — Prometheus exposition format for Grafana/Prometheus scraping.
async fn handle_metrics(State(state): State<RpcState>) -> impl IntoResponse {
    let node = state.node.lock().await;
    let height = node.height();
    let leases = node.runner.leases.count();
    drop(node);

    let uptime = state.start_time.elapsed().as_secs();
    let mut out = state.metrics.to_prometheus();

    // Add gauges that come from node state
    out.push_str(&format!(
        "# HELP seal_chain_height Current chain height\n\
         # TYPE seal_chain_height gauge\n\
         seal_chain_height {}\n\
         # HELP seal_uptime_seconds Node uptime in seconds\n\
         # TYPE seal_uptime_seconds gauge\n\
         seal_uptime_seconds {}\n\
         # HELP seal_leases_active Number of active storage leases\n\
         # TYPE seal_leases_active gauge\n\
         seal_leases_active {}\n",
        height, uptime, leases,
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
        }
    }))
}
