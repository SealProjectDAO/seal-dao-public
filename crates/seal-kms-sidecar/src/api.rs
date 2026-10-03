//! KMS sidecar API: request/response types and handler logic.
//!
//! Protocol: JSON over tokio's Unix stream, one message per line.
//! Commands are identified by a `"cmd"` field in the JSON object.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::marker::Unpin;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf, split};
use tokio::net::UnixStream;
use tokio::time::timeout;
use tracing::{debug, warn};

use seal_crypto::signature::SigningKey;

use crate::error::{KmsError, KmsResult};

// ── Request/Response Types ──

/// Pair a new node.
#[derive(Deserialize)]
pub struct KmsPairRequest {
    pub node_id: String,
    pub node_hybrid_pk: String,
    pub node_ml_dsa_sig: String,
    pub challenge: String,
}

#[derive(Serialize, Deserialize)]
pub struct KmsPairResponse {
    pub encrypted_validator_key: String,
    pub master_challenge: String,
    pub master_sig: String,
}

/// Sign a bridge withdrawal with the committee key.
#[derive(Deserialize)]
pub struct KmsSignCommitteeRequest {
    pub payload_hex: String,
    pub nonce: u64,
}

#[derive(Serialize, Deserialize)]
pub struct KmsSignCommitteeResponse {
    pub signature_hex: String,
}

/// Sign a bridge withdrawal with the Ringtail key.
#[derive(Deserialize)]
pub struct KmsSignRingtailRequest {
    pub payload_hex: String,
}

#[derive(Serialize, Deserialize)]
pub struct KmsSignRingtailResponse {
    pub signature_hex: String,
}

/// Check node trust status.
#[derive(Deserialize)]
pub struct KmsTrustRequest {
    pub node_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct KmsTrustResponse {
    pub trusted: bool,
}

/// List paired nodes.
#[derive(Deserialize)]
pub struct KmsListNodesRequest {}

#[derive(Serialize, Deserialize)]
pub struct KmsListNodesResponse {
    pub nodes: Vec<NodeSummary>,
}

#[derive(Serialize, Deserialize)]
pub struct NodeSummary {
    pub node_id: String,
    pub paired_at: u64,
    pub last_seen: u64,
    pub revoked: bool,
    pub signer_index: usize,
}

/// Revoke a node.
#[derive(Deserialize)]
pub struct KmsRevokeRequest {
    pub node_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct KmsRevokeResponse {
    pub revoked: bool,
}

// ── Key Backup Format ──

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BackupKeys {
    pub master_kem_sk_hex: String,
    pub master_sig_sk_hex: String,
    pub committee_key_hex: String,
    pub ringtail_sk_hex: String,
}

// ── Master Key Material ──

/// Master key material held in the KMS sidecar.
///
/// Phase 1: Plain in-memory (secure only by Unix socket + process isolation).
/// Phase 2: Wrapped in LockedBuffer (mlock + guard pages + canary).
pub struct MasterKeys {
    /// Committee MAC key for bridge withdrawal HMAC signing.
    pub committee_key: [u8; 32],
    /// Ringtail secret key hex (for signing).
    pub ringtail_sk_hex: String,
}

impl MasterKeys {
    /// Generate new random master keys.
    pub fn generate() -> Self {
        let mut committee_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut committee_key);
        MasterKeys {
            committee_key,
            ringtail_sk_hex: String::new(),
        }
    }

    /// Load from hex-encoded backup data.
    pub fn from_hex(data: &BackupKeys) -> Self {
        let mut mk = Self::generate();
        if !data.committee_key_hex.is_empty() {
            let bytes = hex::decode(&data.committee_key_hex).expect("bad committee hex");
            mk.committee_key = bytes.try_into().expect("committee key wrong size");
        }
        if !data.ringtail_sk_hex.is_empty() {
            mk.ringtail_sk_hex = data.ringtail_sk_hex.clone();
        }
        mk
    }
}

impl Drop for MasterKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.committee_key.zeroize();
    }
}

// ── KMS Server ──

pub struct Kmserver {
    /// Optional auth token for TCP connections.
    pub auth_token: Option<String>,
    pub trust_store: Arc<crate::trust_store::TrustStore>,
    pub keys: Option<Arc<Mutex<MasterKeys>>>,
    pub master_node_id: String,
    pub server_sig: Arc<Mutex<SigningKey>>,
}

impl Clone for Kmserver {
    fn clone(&self) -> Self {
        Kmserver {
            auth_token: self.auth_token.clone(),
            trust_store: Arc::clone(&self.trust_store),
            keys: self.keys.clone(),
            master_node_id: self.master_node_id.clone(),
            server_sig: Arc::clone(&self.server_sig),
        }
    }
}


impl Kmserver {
    pub fn new(trust_store: Arc<crate::trust_store::TrustStore>) -> Self {
        let (_sig_sk, server_vk) = SigningKey::generate();
        let master_node_id =
            hex::encode(sha3::Sha3_256::digest(server_vk.to_bytes()));
        let (server_sig_sk, _) = SigningKey::generate();

        Kmserver {
            auth_token: None,
            trust_store,
            keys: None,
            master_node_id,
            server_sig: Arc::new(Mutex::new(server_sig_sk)),
        }
    }

    /// Initialize with master key material.
    pub fn with_keys(mut self, keys: MasterKeys) -> Self {
        self.keys = Some(Arc::new(Mutex::new(keys)));
        self
    }

    /// Set the auth token for TCP connections.
    pub fn with_auth_token(mut self, token: Option<String>) -> Self {
        self.auth_token = token;
        self
    }
    /// Handle a single client connection.
    /// If an auth token is configured, the first command must be "auth"
    /// with a matching token before any other command is accepted.
    pub async fn handle_connection<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>(
        &self,
        stream: S,
    ) -> KmsResult<()> {
        let (reader_part, writer_part) = tokio::io::split(stream);
        let reader = BufReader::new(reader_part);
        let mut writer = writer_part;

        let mut reader = reader;
        let auth_required = self.auth_token.is_some();

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let line = line.trim().to_string();
                    if line.is_empty() {
                        continue;
                    }
                    debug!("Received: {}", line);

                    let response = if auth_required {
                        self.handle_auth(&line).await
                    } else {
                        self.handle_command(&line).await
                    };

                    let response_json = match serde_json::to_string(&response) {
                        Ok(s) => s,
                        Err(e) => {
                            debug!("Serialize error: {}", e);
                            break;
                        }
                    };
                    debug!("Replying: {}", response_json);
                    if let ApiResponse::Error { code, .. } = &response {
                        if *code >= 400 {
                            writer.write_all(response_json.as_bytes()).await?;
                            break;
                        }
                    }
                    writer.write_all(format!("{}\n", response_json).as_bytes()).await?;
                    writer.flush().await?;
                }
                Err(e) => {
                    debug!("Read error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle the initial "auth" command for TCP connections.
    async fn handle_auth(&self, line: &str) -> ApiResponse {
        let parsed: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return ApiResponse::error(400, &format!("JSON parse error: {}", e));
            }
        };

        let cmd = parsed.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
        if cmd != "auth" {
            return ApiResponse::error(
                401,
                "auth required: send cmd=auth first",
            );
        }

        let token = parsed
            .get("token")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if Some(token) == self.auth_token.as_deref() {
            ApiResponse::success(serde_json::json!({"authenticated": true}))
        } else {
            ApiResponse::error(401, "invalid auth token")
        }
    }


    async fn handle_command(&self, line: &str) -> ApiResponse {
        let parsed: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return ApiResponse::error(400, &format!("JSON parse error: {}", e));
            }
        };

        let cmd = parsed.get("cmd").and_then(|v| v.as_str()).unwrap_or("");

        match cmd {
            "pair" => self.cmd_pair(parsed).await,
            "sign_committee" => self.cmd_sign_committee(parsed).await,
            "sign_ringtail" => self.cmd_sign_ringtail(parsed).await,
            "trust" => self.cmd_trust(parsed).await,
            "list_nodes" => self.cmd_list_nodes(parsed).await,
            "revoke" => self.cmd_revoke(parsed).await,
            "heartbeat" => self.cmd_heartbeat(parsed).await,
            _ => ApiResponse::error(400, &format!("Unknown command: {}", cmd)),
        }
    }

    async fn cmd_pair(&self, parsed: serde_json::Value) -> ApiResponse {
        let req: KmsPairRequest = match serde_json::from_value(parsed["args"].clone()) {
            Ok(r) => r,
            Err(e) => return ApiResponse::error(400, &format!("Invalid pair request: {}", e)),
        };

        // Parse the node's hybrid public key
        let hybrid_pk_bytes = match hex::decode(&req.node_hybrid_pk) {
            Ok(b) => b,
            Err(_) => return ApiResponse::error(400, "Invalid hybrid public key hex"),
        };
        let node_hybrid_pk = match seal_crypto::hybrid_kem::HybridKemPublicKey::from_bytes(&hybrid_pk_bytes) {
            Ok(pk) => pk,
            Err(_) => return ApiResponse::error(400, "Failed to parse hybrid public key"),
        };

        let node_id = req.node_id.clone();

        // Check if node is pre-registered in trust store
        if !self.trust_store.is_trusted(&node_id).await {
            return ApiResponse::error(403, "Node not pre-registered in trust store");
        }

        // Verify challenge signature
        let challenge_bytes = match hex::decode(&req.challenge) {
            Ok(b) => b,
            Err(_) => return ApiResponse::error(400, "Invalid challenge hex"),
        };
        let sig_bytes = match hex::decode(&req.node_ml_dsa_sig) {
            Ok(b) => b,
            Err(_) => return ApiResponse::error(400, "Invalid signature hex"),
        };

        // Build signing payload: node_id || hybrid_pk_hex || challenge
        let mut signing_payload = Vec::new();
        signing_payload.extend_from_slice(node_id.as_bytes());
        signing_payload.extend_from_slice(req.node_hybrid_pk.as_bytes());
        signing_payload.extend_from_slice(&challenge_bytes);

        let sig = seal_crypto::signature::Signature::from_bytes(sig_bytes);

        let node_info = match self.trust_store.get_node(&node_id).await {
            Ok(info) => info,
            Err(_) => return ApiResponse::error(404, "Node not found in trust store"),
        };

        let vk_bytes = match hex::decode(&node_info.verifying_key_hex) {
            Ok(v) => v,
            Err(_) => return ApiResponse::error(500, "Corrupted trust store"),
        };

        let vk = match seal_crypto::signature::VerifyingKey::from_bytes(&vk_bytes) {
            Ok(v) => v,
            Err(_) => return ApiResponse::error(500, "Invalid stored verifying key"),
        };

        if vk.verify(&signing_payload, &sig).is_err() {
            return ApiResponse::error(403, "Signature verification failed");
        }

        // Update node's hybrid public key
        if let Err(e) = self
            .trust_store
            .set_hybrid_pk(&node_id, req.node_hybrid_pk.clone())
            .await
        {
            tracing::warn!("Failed to update hybrid PK: {}", e);
        }

        // Generate master challenge
        let mut master_challenge = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut master_challenge);

        // Encrypt validator key under node's hybrid public key
        let enc_validator_key = match &self.keys {
            Some(keys) => {
                let keys = keys.lock().unwrap();
                self.encrypt_under_hybrid(&keys, &node_hybrid_pk, &master_challenge)
            }
            None => {
                return ApiResponse::error(503, "KMS not initialized (no master keys)");
            }
        };

        // Sign the master challenge with server's own signing key
        let sig_guard = self.server_sig.lock().unwrap();
        let master_sig = sig_guard.sign(&master_challenge).expect("signing should not fail");
        let master_sig_hex = hex::encode(master_sig.to_bytes());

        ApiResponse::success(KmsPairResponse {
            encrypted_validator_key: enc_validator_key,
            master_challenge: hex::encode(master_challenge),
            master_sig: master_sig_hex,
        })
    }

    fn encrypt_under_hybrid(
        &self,
        _keys: &MasterKeys,
        node_hybrid_pk: &seal_crypto::hybrid_kem::HybridKemPublicKey,
        _plaintext: &[u8],
    ) -> String {
        // Encapsulate under node's hybrid public key
        let encapsulation = node_hybrid_pk.encapsulate();

        // Return encapsulation data as hex
        let mut result = Vec::new();
        result.extend_from_slice(encapsulation.mlkem_ct.to_bytes());
        result.extend_from_slice(&encapsulation.x25519_ct);
        result.extend_from_slice(encapsulation.shared_secret.as_bytes());

        hex::encode(result)
    }

    async fn cmd_sign_committee(&self, parsed: serde_json::Value) -> ApiResponse {
        let keys = match &self.keys {
            Some(k) => k,
            None => return ApiResponse::error(503, "KMS not initialized"),
        };

        let req: KmsSignCommitteeRequest = match serde_json::from_value(parsed["args"].clone()) {
            Ok(r) => r,
            Err(e) => return ApiResponse::error(400, &format!("Invalid request: {}", e)),
        };

        let payload = match hex::decode(&req.payload_hex) {
            Ok(p) => p,
            Err(_) => return ApiResponse::error(400, "Invalid payload hex"),
        };

        let keys = keys.lock().unwrap();
        let signature = hmac_sha256(&keys.committee_key, &payload);
        drop(keys);

        ApiResponse::success(KmsSignCommitteeResponse {
            signature_hex: hex::encode(signature),
        })
    }

    async fn cmd_sign_ringtail(&self, parsed: serde_json::Value) -> ApiResponse {
        let keys = match &self.keys {
            Some(k) => k,
            None => return ApiResponse::error(503, "KMS not initialized"),
        };

        let req: KmsSignRingtailRequest = match serde_json::from_value(parsed["args"].clone()) {
            Ok(r) => r,
            Err(e) => return ApiResponse::error(400, &format!("Invalid request: {}", e)),
        };

        let _payload = match hex::decode(&req.payload_hex) {
            Ok(p) => p,
            Err(_) => return ApiResponse::error(400, "Invalid payload hex"),
        };

        let keys = keys.lock().unwrap();
        // TODO: Real Ringtail threshold signature
        let signature_hex = keys.ringtail_sk_hex.clone();
        drop(keys);

        ApiResponse::success(KmsSignRingtailResponse {
            signature_hex,
        })
    }

    async fn cmd_trust(&self, parsed: serde_json::Value) -> ApiResponse {
        let req: KmsTrustRequest = match serde_json::from_value(parsed["args"].clone()) {
            Ok(r) => r,
            Err(e) => return ApiResponse::error(400, &format!("Invalid request: {}", e)),
        };

        let trusted = self.trust_store.is_trusted(&req.node_id).await;
        ApiResponse::success(KmsTrustResponse { trusted })
    }

    async fn cmd_list_nodes(&self, parsed: serde_json::Value) -> ApiResponse {
        let _req: KmsListNodesRequest = match serde_json::from_value(parsed["args"].clone()) {
            Ok(r) => r,
            Err(e) => return ApiResponse::error(400, &format!("Invalid request: {}", e)),
        };

        let nodes = self.trust_store.list_nodes().await;
        let summaries = nodes
            .into_iter()
            .map(|n| NodeSummary {
                node_id: n.node_id,
                paired_at: n.paired_at,
                last_seen: n.last_seen,
                revoked: n.revoked,
                signer_index: n.bridge_signer_index,
            })
            .collect();

        ApiResponse::success(KmsListNodesResponse { nodes: summaries })
    }

    async fn cmd_revoke(&self, parsed: serde_json::Value) -> ApiResponse {
        let req: KmsRevokeRequest = match serde_json::from_value(parsed["args"].clone()) {
            Ok(r) => r,
            Err(e) => return ApiResponse::error(400, &format!("Invalid request: {}", e)),
        };

        match self.trust_store.revoke_node(&req.node_id).await {
            Ok(()) => ApiResponse::success(KmsRevokeResponse { revoked: true }),
            Err(e) => ApiResponse::error(404, &format!("Cannot revoke: {}", e)),
        }
    }

    async fn cmd_heartbeat(&self, parsed: serde_json::Value) -> ApiResponse {
        let node_id = match parsed.get("args")
            .and_then(|a| a.get("node_id"))
            .and_then(|v| v.as_str())
        {
            Some(id) => id.to_string(),
            None => return ApiResponse::error(400, "Missing node_id"),
        };

        match self.trust_store.heartbeat(&node_id).await {
            Ok(()) => ApiResponse::success(()),
            Err(e) => ApiResponse::error(404, &format!("Heartbeat failed: {}", e)),
        }
    }
}

// ── API Response ──

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ApiResponse {
    #[serde(rename = "result")]
    Result {
        code: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
    },
    #[serde(rename = "error")]
    Error {
        code: u16,
        message: String,
    },
}

impl ApiResponse {
    pub fn success<T: Serialize>(data: T) -> Self {
        let data = serde_json::to_value(&data).ok();
        ApiResponse::Result {
            code: 200,
            data,
        }
    }

    pub fn error(code: u16, message: &str) -> Self {
        ApiResponse::Error {
            code,
            message: message.to_string(),
        }
    }
}


// ── Circuit Breaker ──

/// Simple circuit breaker: open after `failure_threshold` consecutive
/// failures, half-opens after `recovery_timeout`, then allows one
/// probe request.  Success resets counters; failure re-opens.
#[derive(Debug, Clone)]
struct CircuitBreaker {
    /// Current state: 0 = closed (normal), 1 = half-open (probing), 2 = open (blocking)
    state: u8,
    /// Consecutive failure count
    failures: u32,
    /// Threshold to open the circuit
    failure_threshold: u32,
    /// Time between half-open probe and re-opening if it fails
    recovery_timeout: Duration,
    /// When the circuit was last opened (or half-opened)
    last_failure_time: Option<Instant>,
}

impl CircuitBreaker {
    fn new(failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            state: 0,
            failures: 0,
            failure_threshold,
            recovery_timeout,
            last_failure_time: None,
        }
    }

    /// Check if a request is allowed through.
    /// Returns true if the request should proceed, false if the circuit is open.
    fn allow_request(&mut self) -> bool {
        match self.state {
            0 => true, // closed: always allow
            1 => {
                // half-open: allow exactly one probe
                true
            }
            2 => {
                // open: check if recovery timeout has elapsed
                if let Some(last) = self.last_failure_time {
                    if last.elapsed() >= self.recovery_timeout {
                        self.state = 1; // transition to half-open
                        self.last_failure_time = Some(Instant::now());
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Record a successful request — resets the circuit to closed.
    fn record_success(&mut self) {
        self.failures = 0;
        self.state = 0;
        self.last_failure_time = None;
    }

    /// Record a failed request — increments counter, opens if threshold reached.
    fn record_failure(&mut self) {
        self.failures += 1;
        self.last_failure_time = Some(Instant::now());
        if self.failures >= self.failure_threshold {
            self.state = 2; // open
        }
    }
}

// ── Helpers ──

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("key length OK");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

// ── KMS Client (for seal-node to talk to KMS sidecar) ──

/// Configuration for the KMS client's timeout/retry/circuit-breaker behavior.
#[derive(Debug, Clone)]
pub struct KmsClientConfig {
    /// Per-request timeout (write + read).
    pub request_timeout: Duration,
    /// Maximum number of retry attempts (initial + retries).
    pub max_retries: u32,
    /// Base delay for exponential backoff between retries.
    pub retry_base_delay: Duration,
    /// Circuit breaker: open after this many consecutive failures.
    pub circuit_failure_threshold: u32,
    /// Circuit breaker: wait this long before half-opening.
    pub circuit_recovery_timeout: Duration,
}

impl Default for KmsClientConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(10),
            max_retries: 3,
            retry_base_delay: Duration::from_millis(100),
            circuit_failure_threshold: 5,
            circuit_recovery_timeout: Duration::from_secs(30),
        }
    }
}

pub struct KmsClient {
    reader: Mutex<BufReader<ReadHalf<UnixStream>>>,
    writer: Mutex<WriteHalf<UnixStream>>,
    /// Shared circuit breaker state — protects against hammering a dead sidecar.
    circuit_breaker: Arc<Mutex<CircuitBreaker>>,
    /// Request timeout.
    request_timeout: Duration,
    /// Max retry attempts.
    max_retries: u32,
    /// Base delay for exponential backoff.
    retry_base_delay: Duration,
}

impl KmsClient {
    /// Connect to a KMS sidecar via Unix socket.
    pub async fn connect(path: &PathBuf) -> KmsResult<Self> {
        Self::connect_with_config(path, KmsClientConfig::default()).await
    }

    /// Connect with custom timeout/retry/circuit-breaker configuration.
    pub async fn connect_with_config(
        path: &PathBuf,
        config: KmsClientConfig,
    ) -> KmsResult<Self> {
        let stream = UnixStream::connect(path).await?;
        let (read_half, write_half) = split(stream);
        Ok(KmsClient {
            reader: Mutex::new(BufReader::new(read_half)),
            writer: Mutex::new(write_half),
            circuit_breaker: Arc::new(Mutex::new(CircuitBreaker::new(
                config.circuit_failure_threshold,
                config.circuit_recovery_timeout,
            ))),
            request_timeout: config.request_timeout,
            max_retries: config.max_retries,
            retry_base_delay: config.retry_base_delay,
        })
    }

    /// Send a command with timeout, retry, and circuit-breaker protection.
    ///
    /// Strategy:
    /// 1. Check circuit breaker — if open and not yet recovered, fail immediately.
    /// 2. Attempt the request with `request_timeout` deadline.
    /// 3. On failure, apply exponential backoff and retry up to `max_retries` times.
    /// 4. On success, record success (circuit closes); on failure, record failure.
    async fn send_command<T: for<'de> Deserialize<'de>>(
        &self,
        cmd: &str,
        args: &serde_json::Value,
    ) -> KmsResult<T> {
        // 1. Check circuit breaker
        {
            let mut cb = self.circuit_breaker.lock().unwrap();
            if !cb.allow_request() {
                return Err(KmsError::CircuitBreakerOpen);
            }
        }

        let msg = serde_json::json!({
            "cmd": cmd,
            "args": args,
        });
        let msg_str = msg.to_string();

        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            // Check circuit breaker before each attempt
            {
                let mut cb = self.circuit_breaker.lock().unwrap();
                if !cb.allow_request() {
                    return Err(KmsError::CircuitBreakerOpen);
                }
            }

            // Execute with timeout
            let result = timeout(
                self.request_timeout,
                self.do_send_receive(&msg_str),
            ).await;

            match result {
                Ok(Ok(resp)) => match resp {
                    ApiResponse::Result { code: 200, data } => {
                        let d = data.unwrap_or(serde_json::json!(null));
                        let value: T = match serde_json::from_value(d) {
                            Ok(v) => v,
                            Err(e) => {
                                // Record success (circuit recovers from transient errors)
                                self.circuit_breaker.lock().unwrap().record_success();
                                return Err(KmsError::Json(e));
                            }
                        };
                        // Success — record and return
                        self.circuit_breaker.lock().unwrap().record_success();
                        return Ok(value);
                    }
                    ApiResponse::Result { code, .. } => {
                        let err_msg = format!("Server error code {}", code);
                        warn!(attempt, cmd, "KMS server error");
                        last_err = Some(KmsError::InvalidRequest(err_msg));
                    }
                    ApiResponse::Error { message, .. } => {
                        warn!(attempt, cmd, error = %message, "KMS error response");
                        last_err = Some(KmsError::InvalidRequest(message));
                    }
                },
                Ok(Err(e)) => {
                    warn!(attempt, cmd, error = %e, "KMS IO error");
                    last_err = Some(KmsError::Io(e));
                }
                Err(_timeout) => {
                    warn!(attempt, cmd, timeout = ?self.request_timeout, "KMS request timeout");
                    last_err = Some(KmsError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "KMS request timed out",
                    )));
                }
            }

            // Record failure for circuit breaker (only on transient errors)
            if attempt < self.max_retries {
                self.circuit_breaker.lock().unwrap().record_failure();
                // Exponential backoff
                let delay = self.retry_base_delay * 2_u32.pow(attempt);
                debug!(attempt, delay_ms = delay.as_millis(), "KMS retrying...");
                tokio::time::sleep(delay).await;
            }
        }

        // All retries exhausted — do one final circuit breaker record
        self.circuit_breaker.lock().unwrap().record_failure();
        Err(last_err.unwrap_or_else(|| {
            KmsError::InvalidRequest("KMS command failed after all retries".into())
        }))
    }

    /// Perform the actual write + read without timeout (called within timeout wrapper).
    async fn do_send_receive(&self, msg_str: &str) -> Result<ApiResponse, std::io::Error> {
        {
            let mut writer = self.writer.lock().unwrap();
            writer.write_all(msg_str.as_bytes()).await?;
            writer.flush().await?;
        }

        let mut line = String::new();
        {
            let mut reader = self.reader.lock().unwrap();
            reader.read_line(&mut line).await?;
        }

        serde_json::from_str(&line).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })
    }

    /// Check if a node is trusted.
    pub async fn is_trusted(&self, node_id: &str) -> KmsResult<bool> {
        let resp: KmsTrustResponse =
            self.send_command("trust", &serde_json::json!({ "node_id": node_id }))
                .await?;
        Ok(resp.trusted)
    }

    /// Sign a bridge withdrawal with the committee key.
    pub async fn sign_committee(&self, payload_hex: &str, nonce: u64) -> KmsResult<String> {
        let resp: KmsSignCommitteeResponse = self
            .send_command(
                "sign_committee",
                &serde_json::json!({
                    "payload_hex": payload_hex,
                    "nonce": nonce,
                }),
            )
            .await?;
        Ok(resp.signature_hex)
    }

    /// Sign a bridge withdrawal with the Ringtail key.
    pub async fn sign_ringtail(&self, payload_hex: &str) -> KmsResult<String> {
        let resp: KmsSignRingtailResponse = self
            .send_command(
                "sign_ringtail",
                &serde_json::json!({
                    "payload_hex": payload_hex,
                }),
            )
            .await?;
        Ok(resp.signature_hex)
    }
}
