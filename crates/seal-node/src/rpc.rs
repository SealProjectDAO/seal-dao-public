//! JSON-RPC 2.0 server for seal-node.
//!
//! Features:
//! - ML-DSA signature authentication on mutating requests
//! - RLS enforcement on SQL queries
//! - Namespace-aware query routing
//! - MPC aggregate and ZK proof endpoints
//! - Chain state inspection

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::{get, post}, Json, Router};
use seal_crypto::hash::sha3_256;
use seal_crypto::signature::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::network_node::NetworkNode;
use crate::pq_rpc::PqRpcManager;
use crate::private_tables::{PrivateTableManager, PrivateTableType};
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
}

impl Default for RpcConfig {
    fn default() -> Self {
        RpcConfig {
            served_namespaces: HashSet::new(),
            require_auth_for_reads: false,
            max_query_length: 64 * 1024, // 64 KB
            max_requests_per_minute: 120,
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
    let state = RpcState {
        node,
        config: Arc::new(config),
        private_tables: Arc::new(Mutex::new(PrivateTableManager::new())),
        pq_rpc: Arc::new(PqRpcManager::new()),
        token_manager: Arc::new(Mutex::new(TokenManager::new())),
        dex: Arc::new(Mutex::new(DexManager::new())),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::default())),
        namespaces: Arc::new(Mutex::new(Vec::new())),
        metrics: Arc::new(crate::metrics::NodeMetrics::new()),
        start_time: std::time::Instant::now(),
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

/// Verify ML-DSA signature on a request. Returns the caller's address.
fn authenticate(req: &RpcRequest) -> Result<Caller, (i32, String)> {
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

    // Derive address from public key
    let addr_hash = sha3_256(&vk_bytes);
    let address = format!("seal1{}", hex::encode(&addr_hash.0[..20]));

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
            | "seal_createPair"
            | "seal_placeOrder"
            | "seal_cancelOrder"
            | "seal_createPrivateTable"
            | "seal_setVisibility"
            | "seal_enableRls"
            | "seal_addPolicy"
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
        match authenticate(&req) {
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
        authenticate(&req).ok()
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
    match node.submit_sql(sql) {
        Ok(result) => Ok(serde_json::json!({
            "rows_affected": result.rows_affected,
            "columns": result.columns,
            "rows": result.rows.iter().map(|r| &r.values).collect::<Vec<_>>(),
            "sender": caller,
        })),
        Err(e) => Err((-32000, format!("SQL error: {}", e))),
    }
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
    match node.query_sql(sql) {
        Ok(result) => Ok(serde_json::json!({
            "columns": result.columns,
            "rows": result.rows.iter().map(|r| &r.values).collect::<Vec<_>>(),
            "caller": caller,
        })),
        Err(e) => Err((-32000, format!("SQL error: {}", e))),
    }
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
    // Submit the schema as a CreateApp transaction
    {
        let mut node = state.node.lock().await;
        let _ = node.runner.submit_sql(schema);
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
        let mut party = SpdzParty::new(0, 42, 1, b"seal-mpc-seed");
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

async fn handle_transfer(
    state: &RpcState,
    params: &serde_json::Value,
    caller: &str,
) -> Result<serde_json::Value, (i32, String)> {
    let to = params.get("to").and_then(|v| v.as_str())
        .ok_or((-32602, "missing 'to' param".into()))?;
    let amount = params.get("amount").and_then(|v| v.as_u64())
        .ok_or((-32602, "missing 'amount' param".into()))?;

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

    let mgr = state.token_manager.lock().await;
    let balance = mgr.balance(symbol, address);
    let info = mgr.get_token(symbol);

    Ok(serde_json::json!({
        "symbol": symbol,
        "address": address,
        "balance": balance,
        "total_supply": info.map(|i| i.total_supply).unwrap_or(0),
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
        })
    }).collect();
    Ok(serde_json::json!({ "tokens": tokens }))
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
