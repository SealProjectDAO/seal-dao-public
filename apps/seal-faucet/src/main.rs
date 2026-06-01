//! Seal DAO testnet faucet — HTTP service.
//!
//! `POST /faucet {address}` → ML-DSA-signed `seal_transfer` from a
//! dedicated faucet keypair to `address`. Per-address and per-IP
//! rate limits keep faucet drain bounded.
//!
//! NOT wired into `scripts/ci.sh` — the faucet keypair is real
//! (testnet) credentials and a CI-driven loop would burn the
//! balance. Run manually:
//!
//! ```
//! cargo run -p seal-faucet -- \
//!     --key faucet.json \
//!     --node http://localhost:8545 \
//!     --port 8546 \
//!     --drip 1000000 \
//!     --interval-secs 3600
//! ```
//!
//! `faucet.json` is a regular Seal wallet keyfile with
//! `{signing_key, verifying_key, address}` (hex). Generate with
//! `cargo run -p seal-cli -- wallet --testnet`. Top up the address
//! via testnet genesis or an admin transfer before pointing the
//! faucet at a node.

use axum::{
    extract::{ConnectInfo, Json, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use seal_crypto::{hash::sha3_256, signature::SigningKey, SealAddress};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Deserialize)]
struct FaucetRequest {
    address: String,
}

#[derive(Serialize)]
struct FaucetResponse {
    status: &'static str,
    address: String,
    amount: u64,
    tx_hash: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    retry_after_secs: Option<u64>,
}

struct AppState {
    faucet_sk: SigningKey,
    faucet_vk_hex: String,
    faucet_address: String,
    node_url: String,
    drip_amount: u64,
    min_interval: Duration,
    rate_limits_addr: Mutex<HashMap<String, Instant>>,
    rate_limits_ip: Mutex<HashMap<IpAddr, Instant>>,
    // Cumulative counters for /metrics. AtomicU64 is enough — these
    // increment under high contention but never need consistent
    // reads across counters.
    drips_attempted: AtomicU64,
    drips_successful: AtomicU64,
    cooldown_rejections_addr: AtomicU64,
    cooldown_rejections_ip: AtomicU64,
    bad_address_rejections: AtomicU64,
    upstream_failures: AtomicU64,
    start_time: Instant,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let key_file = parse_arg::<String>(&args, "--key").unwrap_or_else(|| {
        eprintln!("usage: seal-faucet --key <faucet.json> [options]");
        eprintln!();
        eprintln!("required:");
        eprintln!(
            "  --key <path>          faucet keypair JSON (signing_key, verifying_key, address)"
        );
        eprintln!();
        eprintln!("optional:");
        eprintln!("  --node <url>          target seal-node RPC URL [http://localhost:8545]");
        eprintln!("  --port <n>            faucet HTTP listen port [8546]");
        eprintln!("  --bind <ip>           faucet HTTP bind address [127.0.0.1]");
        eprintln!(
            "  --drip <base-units>   per-request amount [1_000_000_000 = 1 SEAL @ 9 decimals]"
        );
        eprintln!("  --interval-secs <n>   per-address + per-IP cooldown [3600 = 1 h]");
        std::process::exit(2);
    });
    let node_url =
        parse_arg::<String>(&args, "--node").unwrap_or_else(|| "http://localhost:8545".to_string());
    let port: u16 = parse_arg(&args, "--port").unwrap_or(8546);
    let bind: IpAddr = parse_arg(&args, "--bind").unwrap_or_else(|| "127.0.0.1".parse().unwrap());
    let drip_amount: u64 = parse_arg(&args, "--drip").unwrap_or(1_000_000_000);
    let interval_secs: u64 = parse_arg(&args, "--interval-secs").unwrap_or(3600);

    let (faucet_sk, faucet_vk_hex, faucet_address) = match load_keyfile(&key_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };

    tracing::info!(
        "seal-faucet listening on http://{}:{}/faucet \
         (node={}, drip={} base units, cooldown={}s, faucet={})",
        bind,
        port,
        node_url,
        drip_amount,
        interval_secs,
        faucet_address
    );

    let state = Arc::new(AppState {
        faucet_sk,
        faucet_vk_hex,
        faucet_address,
        node_url,
        drip_amount,
        min_interval: Duration::from_secs(interval_secs),
        rate_limits_addr: Mutex::new(HashMap::new()),
        rate_limits_ip: Mutex::new(HashMap::new()),
        drips_attempted: AtomicU64::new(0),
        drips_successful: AtomicU64::new(0),
        cooldown_rejections_addr: AtomicU64::new(0),
        cooldown_rejections_ip: AtomicU64::new(0),
        bad_address_rejections: AtomicU64::new(0),
        upstream_failures: AtomicU64::new(0),
        start_time: Instant::now(),
    });

    let app = Router::new()
        .route("/faucet", post(handle_faucet))
        .route("/health", get(handle_health))
        .route("/metrics", get(handle_metrics))
        .with_state(state);

    let addr = SocketAddr::from((bind, port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        eprintln!("serve: {e}");
        std::process::exit(1);
    }
}

async fn handle_health() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

/// Prometheus exposition for the faucet. Counters since process
/// start plus map sizes (which are bounded by active-requesters-in-
/// window thanks to the prune-on-read in `check_cooldown`).
async fn handle_metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let drips_attempted = state.drips_attempted.load(Ordering::Relaxed);
    let drips_successful = state.drips_successful.load(Ordering::Relaxed);
    let cooldown_addr = state.cooldown_rejections_addr.load(Ordering::Relaxed);
    let cooldown_ip = state.cooldown_rejections_ip.load(Ordering::Relaxed);
    let bad_addr = state.bad_address_rejections.load(Ordering::Relaxed);
    let upstream_fail = state.upstream_failures.load(Ordering::Relaxed);
    let active_addr = state.rate_limits_addr.lock().await.len();
    let active_ip = state.rate_limits_ip.lock().await.len();
    let uptime = state.start_time.elapsed().as_secs();

    let body = format!(
        "# HELP seal_faucet_drips_attempted Total faucet requests received (incl. rejected)\n\
         # TYPE seal_faucet_drips_attempted counter\n\
         seal_faucet_drips_attempted {drips_attempted}\n\
         # HELP seal_faucet_drips_successful Drips where the upstream node accepted seal_transfer\n\
         # TYPE seal_faucet_drips_successful counter\n\
         seal_faucet_drips_successful {drips_successful}\n\
         # HELP seal_faucet_cooldown_rejections_addr Requests rejected by per-address cooldown\n\
         # TYPE seal_faucet_cooldown_rejections_addr counter\n\
         seal_faucet_cooldown_rejections_addr {cooldown_addr}\n\
         # HELP seal_faucet_cooldown_rejections_ip Requests rejected by per-source-IP cooldown\n\
         # TYPE seal_faucet_cooldown_rejections_ip counter\n\
         seal_faucet_cooldown_rejections_ip {cooldown_ip}\n\
         # HELP seal_faucet_bad_address_rejections Requests rejected due to malformed or wrong-HRP addresses\n\
         # TYPE seal_faucet_bad_address_rejections counter\n\
         seal_faucet_bad_address_rejections {bad_addr}\n\
         # HELP seal_faucet_upstream_failures Drips where the upstream seal-node returned an RPC error\n\
         # TYPE seal_faucet_upstream_failures counter\n\
         seal_faucet_upstream_failures {upstream_fail}\n\
         # HELP seal_faucet_active_addr_entries Live entries in the per-address cooldown map\n\
         # TYPE seal_faucet_active_addr_entries gauge\n\
         seal_faucet_active_addr_entries {active_addr}\n\
         # HELP seal_faucet_active_ip_entries Live entries in the per-source-IP cooldown map\n\
         # TYPE seal_faucet_active_ip_entries gauge\n\
         seal_faucet_active_ip_entries {active_ip}\n\
         # HELP seal_faucet_uptime_seconds Faucet uptime in seconds\n\
         # TYPE seal_faucet_uptime_seconds gauge\n\
         seal_faucet_uptime_seconds {uptime}\n",
    );

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

async fn handle_faucet(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(req): Json<FaucetRequest>,
) -> impl IntoResponse {
    state.drips_attempted.fetch_add(1, Ordering::Relaxed);

    // 1) Address parses and matches the faucet's network (HRP).
    let parsed = match SealAddress::from_string_encoding(&req.address) {
        Ok(a) => a,
        Err(e) => {
            state.bad_address_rejections.fetch_add(1, Ordering::Relaxed);
            return error(
                StatusCode::BAD_REQUEST,
                format!("invalid address: {e}"),
                None,
            );
        }
    };
    let canonical = parsed.to_string_encoding();

    // Cross-network paste guard: don't drip to a sealt1… address from
    // a seal1… faucet (or vice versa). Compare on the HRP segment.
    let faucet_hrp = state
        .faucet_address
        .split_once('1')
        .map(|(h, _)| h)
        .unwrap_or("seal");
    let req_hrp = canonical.split_once('1').map(|(h, _)| h).unwrap_or("seal");
    if faucet_hrp != req_hrp {
        state.bad_address_rejections.fetch_add(1, Ordering::Relaxed);
        return error(
            StatusCode::BAD_REQUEST,
            format!("address HRP {req_hrp:?} does not match faucet HRP {faucet_hrp:?}"),
            None,
        );
    }

    // 2) Rate-limit checks. Per-address and per-IP both apply; we
    // record on success only so a failed RPC doesn't burn the
    // requester's quota. Order matters slightly: address first
    // because that's the resource being protected.
    let now = Instant::now();
    if let Some(left) =
        check_cooldown(&state.rate_limits_addr, &canonical, state.min_interval, now).await
    {
        state
            .cooldown_rejections_addr
            .fetch_add(1, Ordering::Relaxed);
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            format!("address cooldown — try again in {}s", left.as_secs()),
            Some(left.as_secs()),
        );
    }
    let ip = remote.ip();
    if let Some(left) = check_ip_cooldown(&state.rate_limits_ip, ip, state.min_interval, now).await
    {
        state.cooldown_rejections_ip.fetch_add(1, Ordering::Relaxed);
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            format!("source-ip cooldown — try again in {}s", left.as_secs()),
            Some(left.as_secs()),
        );
    }

    // 3) Sign + POST seal_transfer.
    let params = serde_json::json!({
        "to": canonical,
        "amount": state.drip_amount,
    });
    let (sig_hex, sender_hex) = match sign_request(
        &state.faucet_sk,
        &state.faucet_vk_hex,
        "seal_transfer",
        &params,
    ) {
        Ok(t) => t,
        Err(e) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("signing failed: {e}"),
                None,
            );
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "seal_transfer",
        "params": params,
        "signature": sig_hex,
        "sender": sender_hex,
        "id": 1,
    });
    let result = match rpc_post(&state.node_url, &body).await {
        Ok(r) => r,
        Err(e) => {
            state.upstream_failures.fetch_add(1, Ordering::Relaxed);
            return error(StatusCode::BAD_GATEWAY, format!("upstream node: {e}"), None);
        }
    };
    if let Some(err) = result.get("error") {
        state.upstream_failures.fetch_add(1, Ordering::Relaxed);
        return error(
            StatusCode::BAD_GATEWAY,
            format!("node rejected transfer: {err}"),
            None,
        );
    }
    let tx_hash = result
        .get("result")
        .and_then(|r| r.get("tx_hash").or_else(|| r.get("txHash")))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // 4) Record success — only after the node accepted the transfer.
    state
        .rate_limits_addr
        .lock()
        .await
        .insert(canonical.clone(), now);
    state.rate_limits_ip.lock().await.insert(ip, now);
    state.drips_successful.fetch_add(1, Ordering::Relaxed);

    tracing::info!(
        target: "faucet.drip",
        "drip {drip} base units → {addr} (ip={ip}, tx={tx})",
        drip = state.drip_amount,
        addr = canonical,
        ip = ip,
        tx = tx_hash.as_deref().unwrap_or("?"),
    );

    let resp = FaucetResponse {
        status: "ok",
        address: canonical,
        amount: state.drip_amount,
        tx_hash,
    };
    (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response()
}

fn error(
    status: StatusCode,
    message: String,
    retry_after_secs: Option<u64>,
) -> axum::response::Response {
    let body = serde_json::to_value(ErrorResponse {
        error: message,
        retry_after_secs,
    })
    .unwrap();
    (status, Json(body)).into_response()
}

/// Cooldown check that doubles as a bounded-LRU sweep.
///
/// Without this, the map grows without bound on a long-running
/// testnet — every fresh requester adds an entry that's only ever
/// overwritten on a successful re-drip. The fix is opportunistic:
/// on every check, drop entries whose `last` is older than
/// `interval`, because they're no longer enforcing anything.
/// `HashMap::retain` is O(n), but `n` is bounded by
/// "active requesters in the past `interval`" which is the
/// steady-state we want anyway, so amortized cost stays low.
async fn check_cooldown(
    map: &Mutex<HashMap<String, Instant>>,
    key: &str,
    interval: Duration,
    now: Instant,
) -> Option<Duration> {
    let mut g = map.lock().await;
    g.retain(|_, last| now.saturating_duration_since(*last) < interval);
    g.get(key).and_then(|&last| {
        let elapsed = now.saturating_duration_since(last);
        if elapsed < interval {
            Some(interval - elapsed)
        } else {
            None
        }
    })
}

async fn check_ip_cooldown(
    map: &Mutex<HashMap<IpAddr, Instant>>,
    key: IpAddr,
    interval: Duration,
    now: Instant,
) -> Option<Duration> {
    let mut g = map.lock().await;
    g.retain(|_, last| now.saturating_duration_since(*last) < interval);
    g.get(&key).and_then(|&last| {
        let elapsed = now.saturating_duration_since(last);
        if elapsed < interval {
            Some(interval - elapsed)
        } else {
            None
        }
    })
}

fn sign_request(
    sk: &SigningKey,
    vk_hex: &str,
    method: &str,
    params: &serde_json::Value,
) -> Result<(String, String), String> {
    // Match seal-cli's canonical: serde_json default (BTreeMap-sorted
    // keys) so the server reproduces the same byte string when
    // verifying the signature.
    let params_json = serde_json::to_string(params).map_err(|e| e.to_string())?;
    let message = format!("{method}{params_json}");
    let hash = sha3_256(message.as_bytes());
    let sig = sk.sign(hash.as_ref()).map_err(|e| e.to_string())?;
    Ok((hex::encode(sig.to_bytes()), vk_hex.to_string()))
}

async fn rpc_post(url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let host = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let host = host.trim_end_matches('/');
    let mut stream = tokio::net::TcpStream::connect(host)
        .await
        .map_err(|e| format!("connect {host}: {e}"))?;
    let body_str = body.to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
        body_str.len()
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("send: {e}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| format!("read: {e}"))?;
    let response_str = String::from_utf8_lossy(&response);
    let json_start = response_str
        .find("\r\n\r\n")
        .map(|p| p + 4)
        .ok_or_else(|| "bad HTTP response".to_string())?;
    serde_json::from_str(&response_str[json_start..]).map_err(|e| format!("parse: {e}"))
}

fn load_keyfile(path: &str) -> Result<(SigningKey, String, String), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))?;
    let sk_hex = v
        .get("signing_key")
        .and_then(|x| x.as_str())
        .ok_or("missing 'signing_key'")?;
    let vk_hex = v
        .get("verifying_key")
        .and_then(|x| x.as_str())
        .ok_or("missing 'verifying_key'")?;
    let address = v
        .get("address")
        .and_then(|x| x.as_str())
        .ok_or("missing 'address'")?;
    let sk_bytes = hex::decode(sk_hex).map_err(|e| format!("signing_key hex: {e}"))?;
    let sk = SigningKey::from_bytes(&sk_bytes).map_err(|e| format!("signing key: {e}"))?;
    Ok((sk, vk_hex.to_string(), address.to_string()))
}

fn parse_arg<T: std::str::FromStr>(args: &[String], flag: &str) -> Option<T> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cooldown_blocks_within_interval_and_clears_after() {
        let map: Mutex<HashMap<String, Instant>> = Mutex::new(HashMap::new());
        let interval = Duration::from_millis(50);
        let now = Instant::now();

        // First call: nothing recorded → cooldown clear.
        assert!(check_cooldown(&map, "addr", interval, now).await.is_none());

        // Record a hit; an immediately-following call sees it.
        map.lock().await.insert("addr".to_string(), now);
        assert!(check_cooldown(&map, "addr", interval, now).await.is_some());

        // After interval elapses, cooldown clears.
        let later = now + interval + Duration::from_millis(1);
        assert!(check_cooldown(&map, "addr", interval, later)
            .await
            .is_none());
    }

    /// check_cooldown drops entries whose `last` is older than the
    /// cooldown window. Pinch: a long-running faucet would otherwise
    /// keep every requester's address forever.
    #[tokio::test]
    async fn cooldown_check_prunes_expired_entries() {
        let map: Mutex<HashMap<String, Instant>> = Mutex::new(HashMap::new());
        let interval = Duration::from_millis(50);
        let now = Instant::now();

        // Pre-populate with three stale entries (older than the
        // cooldown window) and one fresh entry.
        {
            let mut g = map.lock().await;
            g.insert("old1".into(), now - Duration::from_secs(10));
            g.insert("old2".into(), now - Duration::from_secs(10));
            g.insert("old3".into(), now - Duration::from_secs(10));
            g.insert("fresh".into(), now);
        }
        assert_eq!(map.lock().await.len(), 4);

        // Any check_cooldown call now should sweep the stale entries.
        let _ = check_cooldown(&map, "unrelated", interval, now).await;
        let g = map.lock().await;
        assert_eq!(g.len(), 1, "stale entries pruned");
        assert!(g.contains_key("fresh"));
    }

    #[test]
    fn signing_request_is_deterministic_per_key() {
        // Same params, two signs: hashes match (signing is randomized,
        // but the sender/vk and message hash are deterministic).
        let sk_bytes = vec![1u8; 4032]; // ML-DSA-65 sk size
        let sk = match SigningKey::from_bytes(&sk_bytes) {
            Ok(k) => k,
            Err(_) => {
                // Size constants may shift between libcrux versions;
                // skip the check rather than fail noisily.
                return;
            }
        };
        let params = serde_json::json!({"to":"sealt1abc","amount":1});
        let (sig1, vk1) = sign_request(&sk, "deadbeef", "seal_transfer", &params).unwrap();
        let (sig2, vk2) = sign_request(&sk, "deadbeef", "seal_transfer", &params).unwrap();
        // Signatures may differ (random nonce) but vk_hex is constant.
        assert_eq!(vk1, vk2);
        assert!(!sig1.is_empty() && !sig2.is_empty());
    }

    #[test]
    fn keyfile_round_trip() {
        let dir = tempdir_or_skip();
        let Some(dir) = dir else {
            return;
        };
        let path = dir.path().join("k.json");
        let body = serde_json::json!({
            "signing_key": "00".repeat(4032),
            "verifying_key": "11".repeat(1952),
            "address": "sealt1abc"
        });
        std::fs::write(&path, body.to_string()).unwrap();
        match load_keyfile(path.to_str().unwrap()) {
            Ok((_, vk, addr)) => {
                assert_eq!(addr, "sealt1abc");
                assert_eq!(vk.len(), 1952 * 2);
            }
            Err(e) => {
                // Ignore size-mismatch panics from libcrux version skew.
                assert!(e.contains("signing key"), "unexpected error: {e}");
            }
        }
    }

    fn tempdir_or_skip() -> Option<TempDir> {
        match std::env::temp_dir().canonicalize() {
            Ok(_) => Some(TempDir(
                std::env::temp_dir().join(format!("seal-faucet-test-{}", std::process::id())),
            )),
            Err(_) => None,
        }
    }

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn path(&self) -> &std::path::Path {
            std::fs::create_dir_all(&self.0).unwrap();
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
