//! Seal DAO testnet validator-registration portal — HTTP service.
//!
//! `POST /register {pubkey_hex, vrf_pubkey_hex, name, contact,
//! signature_hex}` → ML-DSA-verifies the signature against the
//! supplied `pubkey_hex`, dedupes on pubkey, persists the entry as
//! a JSONL line. `GET /registrations` returns the public roster
//! (omits `contact` to keep operator emails / Telegram handles
//! private). Per-IP rate limit on POST.
//!
//! Companion runbook: `docs/TESTNET-REGISTRATION.md`.
//!
//! NOT wired into `scripts/ci.sh` — this is a long-running HTTP
//! service. Run manually:
//!
//! ```
//! cargo run -p seal-registration -- \
//!     --port 8547 \
//!     --bind 0.0.0.0 \
//!     --store registrations.jsonl \
//!     --interval-secs 60
//! ```
//!
//! The signed message is `register || pubkey_hex || vrf_pubkey_hex
//! || name || contact`, hashed with SHA3-256. Signers can produce
//! it with `seal-cli register-validator --name … --contact …
//! --vrf-pubkey-hex … --key wallet.json --portal http://host:port`
//! once that subcommand lands; for now the request body is hand-
//! constructed (the README shows a curl recipe).

use axum::{
    extract::{ConnectInfo, Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use seal_crypto::hash::sha3_256;
use seal_crypto::signature::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct RegistrationRecord {
    pubkey_hex: String,
    vrf_pubkey_hex: String,
    name: String,
    contact: String,
    /// Server-side wall-clock seconds since the Unix epoch when the
    /// portal accepted the registration. Useful for ordering
    /// concurrent submissions in the roster but is NOT signed.
    accepted_at_unix_secs: u64,
}

#[derive(Deserialize)]
struct RegisterRequest {
    pubkey_hex: String,
    vrf_pubkey_hex: String,
    name: String,
    contact: String,
    /// ML-DSA signature over
    /// `SHA3(b"register" || pubkey_hex || vrf_pubkey_hex || name ||
    /// contact)`, hex-encoded. Verified against the supplied
    /// `pubkey_hex` — anyone can submit any operator's payload, but
    /// without that operator's signing key the signature won't
    /// verify.
    signature_hex: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    status: &'static str,
    pubkey_hex: String,
    name: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    retry_after_secs: Option<u64>,
}

/// Public-roster view: same as the on-disk JSONL but without the
/// `contact` field. The internal contact info is operator-private.
#[derive(Serialize)]
struct PublicRecord {
    pubkey_hex: String,
    vrf_pubkey_hex: String,
    name: String,
    accepted_at_unix_secs: u64,
}

struct AppState {
    /// Path to the append-only JSONL store.
    store_path: PathBuf,
    /// In-memory cache of all registrations, keyed by `pubkey_hex`
    /// for O(1) dedupe checks. Populated from disk on startup;
    /// kept in sync on every successful POST.
    registrations: Mutex<HashMap<String, RegistrationRecord>>,
    /// Per-IP cooldown to keep a single source from spamming the
    /// signature-verify path (which costs a few ms each). Default
    /// 60 s.
    rate_limits_ip: Mutex<HashMap<IpAddr, Instant>>,
    min_interval: Duration,
    /// Process-lifetime counters for /metrics. AtomicU64 lets the
    /// hot path stay lock-free; consistent reads across counters
    /// are not required for Prometheus scrape semantics.
    registrations_attempted: AtomicU64,
    registrations_accepted: AtomicU64,
    duplicate_registrations: AtomicU64,
    cooldown_rejections_ip: AtomicU64,
    bad_request_rejections: AtomicU64,
    signature_verify_failures: AtomicU64,
    persist_failures: AtomicU64,
    lookup_hits: AtomicU64,
    lookup_misses: AtomicU64,
    start_time: Instant,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let port: u16 = parse_arg(&args, "--port").unwrap_or(8547);
    let bind: IpAddr = parse_arg(&args, "--bind").unwrap_or_else(|| "127.0.0.1".parse().unwrap());
    let store_path: PathBuf = parse_arg::<String>(&args, "--store")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("registrations.jsonl"));
    let interval_secs: u64 = parse_arg(&args, "--interval-secs").unwrap_or(60);

    let registrations = match load_jsonl(&store_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error reading {}: {e}", store_path.display());
            std::process::exit(2);
        }
    };

    tracing::info!(
        "seal-registration listening on http://{}:{}/register \
         (store={}, existing={}, ip-cooldown={}s)",
        bind,
        port,
        store_path.display(),
        registrations.len(),
        interval_secs
    );

    let state = Arc::new(AppState {
        store_path,
        registrations: Mutex::new(registrations),
        rate_limits_ip: Mutex::new(HashMap::new()),
        min_interval: Duration::from_secs(interval_secs),
        registrations_attempted: AtomicU64::new(0),
        registrations_accepted: AtomicU64::new(0),
        duplicate_registrations: AtomicU64::new(0),
        cooldown_rejections_ip: AtomicU64::new(0),
        bad_request_rejections: AtomicU64::new(0),
        signature_verify_failures: AtomicU64::new(0),
        persist_failures: AtomicU64::new(0),
        lookup_hits: AtomicU64::new(0),
        lookup_misses: AtomicU64::new(0),
        start_time: Instant::now(),
    });

    let app = Router::new()
        .route("/register", post(handle_register))
        .route("/registrations", get(handle_list))
        .route("/registration/:pubkey_hex", get(handle_lookup))
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

/// Prometheus exposition for the registration portal. Mirrors the
/// faucet pattern: counters since process start + size gauges on
/// the bounded in-memory maps.
async fn handle_metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let attempted = state.registrations_attempted.load(Ordering::Relaxed);
    let accepted = state.registrations_accepted.load(Ordering::Relaxed);
    let dupes = state.duplicate_registrations.load(Ordering::Relaxed);
    let cooldown = state.cooldown_rejections_ip.load(Ordering::Relaxed);
    let bad_req = state.bad_request_rejections.load(Ordering::Relaxed);
    let sig_fail = state.signature_verify_failures.load(Ordering::Relaxed);
    let persist_fail = state.persist_failures.load(Ordering::Relaxed);
    let hits = state.lookup_hits.load(Ordering::Relaxed);
    let misses = state.lookup_misses.load(Ordering::Relaxed);
    let validators = state.registrations.lock().await.len();
    let active_ip = state.rate_limits_ip.lock().await.len();
    let uptime = state.start_time.elapsed().as_secs();

    let body = format!(
        "# HELP seal_registration_attempts Total POST /register requests received\n\
         # TYPE seal_registration_attempts counter\n\
         seal_registration_attempts {attempted}\n\
         # HELP seal_registration_accepted New unique registrations persisted\n\
         # TYPE seal_registration_accepted counter\n\
         seal_registration_accepted {accepted}\n\
         # HELP seal_registration_duplicates Idempotent re-submits of an already-registered pubkey\n\
         # TYPE seal_registration_duplicates counter\n\
         seal_registration_duplicates {dupes}\n\
         # HELP seal_registration_cooldown_rejections_ip Requests rejected by per-source-IP cooldown\n\
         # TYPE seal_registration_cooldown_rejections_ip counter\n\
         seal_registration_cooldown_rejections_ip {cooldown}\n\
         # HELP seal_registration_bad_request_rejections Requests rejected for field-shape (length, hex, missing fields)\n\
         # TYPE seal_registration_bad_request_rejections counter\n\
         seal_registration_bad_request_rejections {bad_req}\n\
         # HELP seal_registration_signature_failures ML-DSA verify failures (signature does not match pubkey_hex)\n\
         # TYPE seal_registration_signature_failures counter\n\
         seal_registration_signature_failures {sig_fail}\n\
         # HELP seal_registration_persist_failures JSONL append failures (disk full / permission)\n\
         # TYPE seal_registration_persist_failures counter\n\
         seal_registration_persist_failures {persist_fail}\n\
         # HELP seal_registration_lookup_hits Per-pubkey GET /registration/:pubkey requests that found a record\n\
         # TYPE seal_registration_lookup_hits counter\n\
         seal_registration_lookup_hits {hits}\n\
         # HELP seal_registration_lookup_misses Per-pubkey GET /registration/:pubkey requests with no matching record\n\
         # TYPE seal_registration_lookup_misses counter\n\
         seal_registration_lookup_misses {misses}\n\
         # HELP seal_registration_validators_total Unique validator pubkeys in the portal\n\
         # TYPE seal_registration_validators_total gauge\n\
         seal_registration_validators_total {validators}\n\
         # HELP seal_registration_active_ip_entries Live entries in the per-source-IP cooldown map\n\
         # TYPE seal_registration_active_ip_entries gauge\n\
         seal_registration_active_ip_entries {active_ip}\n\
         # HELP seal_registration_uptime_seconds Registration portal uptime in seconds\n\
         # TYPE seal_registration_uptime_seconds gauge\n\
         seal_registration_uptime_seconds {uptime}\n",
    );

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

/// Build the canonical message bytes for the registration
/// signature. Public so the seal-cli companion subcommand (and any
/// curl recipe) can produce the exact byte string the portal will
/// hash + verify.
fn registration_message(req: &RegisterRequest) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        b"register".len()
            + req.pubkey_hex.len()
            + req.vrf_pubkey_hex.len()
            + req.name.len()
            + req.contact.len(),
    );
    buf.extend_from_slice(b"register");
    buf.extend_from_slice(req.pubkey_hex.as_bytes());
    buf.extend_from_slice(req.vrf_pubkey_hex.as_bytes());
    buf.extend_from_slice(req.name.as_bytes());
    buf.extend_from_slice(req.contact.as_bytes());
    buf
}

async fn handle_register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    state
        .registrations_attempted
        .fetch_add(1, Ordering::Relaxed);

    // 1) Per-IP rate limit. Burns a few ms per signature-verify so
    // the cooldown is a defense-in-depth against amplification.
    let now = Instant::now();
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

    // 2) Field-shape validation. Empty name / contact / pubkey
    // would survive the signature check (you can sign an empty
    // string) but should still be rejected — a registration with
    // no name is useless to operators reading the roster.
    if req.name.trim().is_empty()
        || req.contact.trim().is_empty()
        || req.pubkey_hex.is_empty()
        || req.vrf_pubkey_hex.is_empty()
        || req.signature_hex.is_empty()
    {
        state.bad_request_rejections.fetch_add(1, Ordering::Relaxed);
        return error(
            StatusCode::BAD_REQUEST,
            "name / contact / pubkey_hex / vrf_pubkey_hex / signature_hex must all be non-empty"
                .into(),
            None,
        );
    }
    // Soft length caps so a malicious submitter can't blow up the
    // JSONL store with a multi-MB name.
    if req.name.len() > 200 || req.contact.len() > 400 {
        state.bad_request_rejections.fetch_add(1, Ordering::Relaxed);
        return error(
            StatusCode::BAD_REQUEST,
            "name (≤200) / contact (≤400) field too long".into(),
            None,
        );
    }

    // 3) Verify the signature against the supplied pubkey. Anyone
    // can submit any payload, but without the corresponding signing
    // key the signature won't verify.
    let pubkey_bytes = match hex::decode(&req.pubkey_hex) {
        Ok(b) => b,
        Err(e) => {
            state.bad_request_rejections.fetch_add(1, Ordering::Relaxed);
            return error(StatusCode::BAD_REQUEST, format!("pubkey_hex: {e}"), None);
        }
    };
    let vk = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(v) => v,
        Err(e) => {
            state.bad_request_rejections.fetch_add(1, Ordering::Relaxed);
            return error(StatusCode::BAD_REQUEST, format!("pubkey: {e}"), None);
        }
    };
    let sig_bytes = match hex::decode(&req.signature_hex) {
        Ok(b) => b,
        Err(e) => {
            state.bad_request_rejections.fetch_add(1, Ordering::Relaxed);
            return error(StatusCode::BAD_REQUEST, format!("signature_hex: {e}"), None);
        }
    };
    let sig = Signature::from_bytes(sig_bytes);
    let message = registration_message(&req);
    let hash = sha3_256(&message);
    if vk.verify(hash.as_ref(), &sig).is_err() {
        state
            .signature_verify_failures
            .fetch_add(1, Ordering::Relaxed);
        return error(
            StatusCode::UNAUTHORIZED,
            "signature does not verify against pubkey_hex".into(),
            None,
        );
    }

    // 4) Dedupe on pubkey. Already-registered keys are a quiet 200
    // (idempotent re-submit), not an error — operators sometimes
    // re-register after losing their local state and shouldn't see
    // a noisy failure.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let record = RegistrationRecord {
        pubkey_hex: req.pubkey_hex.clone(),
        vrf_pubkey_hex: req.vrf_pubkey_hex.clone(),
        name: req.name.clone(),
        contact: req.contact.clone(),
        accepted_at_unix_secs: now_secs,
    };
    let already_present = {
        let map = state.registrations.lock().await;
        map.contains_key(&req.pubkey_hex)
    };
    if !already_present {
        // Persist BEFORE updating the in-memory cache so a partial
        // append + crash leaves the disk store as the source of
        // truth.
        if let Err(e) = append_jsonl(&state.store_path, &record) {
            state.persist_failures.fetch_add(1, Ordering::Relaxed);
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("persist: {e}"),
                None,
            );
        }
        state
            .registrations
            .lock()
            .await
            .insert(req.pubkey_hex.clone(), record);
        state.registrations_accepted.fetch_add(1, Ordering::Relaxed);
    } else {
        state
            .duplicate_registrations
            .fetch_add(1, Ordering::Relaxed);
    }
    state.rate_limits_ip.lock().await.insert(ip, now);

    tracing::info!(
        target: "registration.accept",
        "register pubkey={} name={:?} (ip={}, dupe={})",
        req.pubkey_hex,
        req.name,
        ip,
        already_present
    );

    let resp = RegisterResponse {
        status: if already_present {
            "already-registered"
        } else {
            "ok"
        },
        pubkey_hex: req.pubkey_hex,
        name: req.name,
    };
    (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response()
}

/// `GET /registration/:pubkey_hex` — per-pubkey lookup. Returns the
/// public record on hit (200), `{"error":"not found"}` on miss
/// (404). Operators use this to confirm their POST /register made
/// it into the roster without grep'ing the full `/registrations`
/// list. Pubkey is matched case-insensitively.
async fn handle_lookup(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> impl IntoResponse {
    let key = pubkey_hex.to_ascii_lowercase();
    let snapshot = {
        let map = state.registrations.lock().await;
        map.get(&key).cloned()
    };
    match snapshot {
        Some(r) => {
            state.lookup_hits.fetch_add(1, Ordering::Relaxed);
            let public = PublicRecord {
                pubkey_hex: r.pubkey_hex,
                vrf_pubkey_hex: r.vrf_pubkey_hex,
                name: r.name,
                accepted_at_unix_secs: r.accepted_at_unix_secs,
            };
            (StatusCode::OK, Json(serde_json::to_value(public).unwrap())).into_response()
        }
        None => {
            state.lookup_misses.fetch_add(1, Ordering::Relaxed);
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "not found"})),
            )
                .into_response()
        }
    }
}

async fn handle_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Scoped lock so we don't hold across JSON serialization.
    let snapshot: Vec<RegistrationRecord> = {
        let map = state.registrations.lock().await;
        map.values().cloned().collect()
    };
    let mut public: Vec<PublicRecord> = snapshot
        .into_iter()
        .map(|r| PublicRecord {
            pubkey_hex: r.pubkey_hex,
            vrf_pubkey_hex: r.vrf_pubkey_hex,
            name: r.name,
            accepted_at_unix_secs: r.accepted_at_unix_secs,
        })
        .collect();
    // Stable order for callers that diff the roster between
    // requests: oldest first by accepted_at, ties broken by
    // pubkey_hex.
    public.sort_by(|a, b| {
        a.accepted_at_unix_secs
            .cmp(&b.accepted_at_unix_secs)
            .then_with(|| a.pubkey_hex.cmp(&b.pubkey_hex))
    });
    let count = public.len();
    Json(serde_json::json!({
        "registrations": public,
        "count": count,
    }))
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

/// Cooldown check that doubles as a bounded-LRU sweep. Same
/// approach the faucet uses — drop entries older than `interval`
/// on every call so the map stays bounded by active requesters
/// in the past window. `HashMap::retain` is O(n) but `n` is the
/// active-set, which is the size we'd want anyway.
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

fn append_jsonl(path: &PathBuf, record: &RegistrationRecord) -> Result<(), String> {
    use std::io::Write;
    let line = serde_json::to_string(record).map_err(|e| e.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    writeln!(file, "{}", line).map_err(|e| format!("write: {e}"))?;
    Ok(())
}

fn load_jsonl(path: &PathBuf) -> Result<HashMap<String, RegistrationRecord>, String> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
    let mut out = HashMap::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let r: RegistrationRecord =
            serde_json::from_str(line).map_err(|e| format!("line {}: {e}", i + 1))?;
        // Last-write wins — duplicates in the JSONL would be a
        // corrupted store but we tolerate it gracefully.
        out.insert(r.pubkey_hex.clone(), r);
    }
    Ok(out)
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
    use seal_crypto::signature::SigningKey;

    fn signed_request(name: &str, contact: &str) -> (RegisterRequest, SigningKey, VerifyingKey) {
        let (sk, vk) = SigningKey::generate();
        let pubkey_hex = hex::encode(vk.to_bytes());
        let vrf_pubkey_hex = hex::encode([0xab; 32]);
        let mut req = RegisterRequest {
            pubkey_hex,
            vrf_pubkey_hex,
            name: name.into(),
            contact: contact.into(),
            signature_hex: String::new(),
        };
        let msg = registration_message(&req);
        let hash = sha3_256(&msg);
        let sig = sk.sign(hash.as_ref()).unwrap();
        req.signature_hex = hex::encode(sig.to_bytes());
        (req, sk, vk)
    }

    #[test]
    fn registration_message_is_canonical() {
        let req = RegisterRequest {
            pubkey_hex: "deadbeef".into(),
            vrf_pubkey_hex: "1234".into(),
            name: "alpha".into(),
            contact: "alpha@example.com".into(),
            signature_hex: "irrelevant".into(),
        };
        let msg = registration_message(&req);
        // Concatenation order: tag || pubkey_hex || vrf_pubkey_hex
        // || name || contact. Any reorder must produce a different
        // byte string.
        assert!(msg.starts_with(b"register"));
        assert!(msg.windows(8).any(|w| w == b"deadbeef"));
        assert!(msg.windows(5).any(|w| w == b"alpha"));
        // Name "alpha" must come BEFORE contact "alpha@example.com"
        // — flipping that order is the most likely future regression
        // and would silently invalidate every existing signature.
        let name_pos = msg.windows(5).position(|w| w == b"alpha").unwrap();
        let contact_pos = msg
            .windows(17)
            .position(|w| w == b"alpha@example.com")
            .unwrap();
        assert!(name_pos < contact_pos);
    }

    #[test]
    fn signature_verifies_for_authentic_request() {
        let (req, _sk, vk) = signed_request("validator-1", "ops@example.com");
        let msg = registration_message(&req);
        let hash = sha3_256(&msg);
        let sig = Signature::from_bytes(hex::decode(&req.signature_hex).unwrap());
        vk.verify(hash.as_ref(), &sig)
            .expect("signature must verify");
    }

    #[test]
    fn signature_fails_when_message_is_tampered() {
        let (mut req, _sk, vk) = signed_request("validator-2", "ops@example.com");
        // Mutate the name (a real-world tamper attempt would replace
        // the public roster's display name with the attacker's
        // chosen string while keeping the signature).
        req.name = "validator-attacker".into();
        let msg = registration_message(&req);
        let hash = sha3_256(&msg);
        let sig = Signature::from_bytes(hex::decode(&req.signature_hex).unwrap());
        assert!(vk.verify(hash.as_ref(), &sig).is_err());
    }

    #[test]
    fn signature_fails_when_pubkey_is_substituted() {
        // Sign with key A but submit pubkey B — the signature
        // verifies against A's vk only, so this must fail at the
        // portal's verify step.
        let (req, _sk_a, _vk_a) = signed_request("validator-3", "ops@example.com");
        let (_sk_b, vk_b) = SigningKey::generate();
        let msg = registration_message(&req);
        let hash = sha3_256(&msg);
        let sig = Signature::from_bytes(hex::decode(&req.signature_hex).unwrap());
        assert!(vk_b.verify(hash.as_ref(), &sig).is_err());
    }

    #[tokio::test]
    async fn cooldown_blocks_within_interval_and_clears_after() {
        let map: Mutex<HashMap<IpAddr, Instant>> = Mutex::new(HashMap::new());
        let interval = Duration::from_millis(50);
        let now = Instant::now();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        // First call: nothing recorded → cooldown clear.
        assert!(check_ip_cooldown(&map, ip, interval, now).await.is_none());
        // Record a hit; an immediately-following call sees it.
        map.lock().await.insert(ip, now);
        assert!(check_ip_cooldown(&map, ip, interval, now).await.is_some());
        // After interval elapses, cooldown clears.
        let later = now + interval + Duration::from_millis(1);
        assert!(check_ip_cooldown(&map, ip, interval, later).await.is_none());
    }

    /// check_ip_cooldown prunes stale entries so the rate-limit map
    /// stays bounded by active sources in the window. Matters for
    /// long-running testnet registration portals — without this the
    /// map would grow forever.
    #[tokio::test]
    async fn cooldown_check_prunes_expired_entries() {
        let map: Mutex<HashMap<IpAddr, Instant>> = Mutex::new(HashMap::new());
        let interval = Duration::from_millis(50);
        let now = Instant::now();
        let old: Vec<IpAddr> = vec![
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "10.0.0.3".parse().unwrap(),
        ];
        let fresh: IpAddr = "10.0.0.4".parse().unwrap();
        {
            let mut g = map.lock().await;
            for ip in &old {
                g.insert(*ip, now - Duration::from_secs(10));
            }
            g.insert(fresh, now);
        }
        assert_eq!(map.lock().await.len(), 4);
        let _ = check_ip_cooldown(&map, "8.8.8.8".parse().unwrap(), interval, now).await;
        let g = map.lock().await;
        assert_eq!(g.len(), 1, "stale entries pruned");
        assert!(g.contains_key(&fresh));
    }

    #[test]
    fn append_and_load_jsonl_round_trip() {
        let dir =
            std::env::temp_dir().join(format!("seal-registration-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("reg.jsonl");
        let _ = std::fs::remove_file(&path);

        let r1 = RegistrationRecord {
            pubkey_hex: "aa".repeat(1952),
            vrf_pubkey_hex: "bb".repeat(32),
            name: "alpha".into(),
            contact: "alpha@example.com".into(),
            accepted_at_unix_secs: 1700000000,
        };
        let r2 = RegistrationRecord {
            pubkey_hex: "cc".repeat(1952),
            vrf_pubkey_hex: "dd".repeat(32),
            name: "beta".into(),
            contact: "beta@example.com".into(),
            accepted_at_unix_secs: 1700000001,
        };
        append_jsonl(&path, &r1).unwrap();
        append_jsonl(&path, &r2).unwrap();
        let loaded = load_jsonl(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.get(&r1.pubkey_hex).unwrap(), &r1);
        assert_eq!(loaded.get(&r2.pubkey_hex).unwrap(), &r2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_jsonl_missing_file_yields_empty_map() {
        let path = std::env::temp_dir().join("seal-registration-nonexistent.jsonl");
        let _ = std::fs::remove_file(&path);
        let loaded = load_jsonl(&path).unwrap();
        assert!(loaded.is_empty());
    }
}
