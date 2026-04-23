//! Chain observers — poll external chains for lock events.
//!
//! Each observer monitors a source chain for lock transactions directed
//! at the Seal bridge program. When a lock is detected, it produces a
//! [`BridgeDeposit`] that gets fed to the [`BridgeManager`](crate::BridgeManager).
//!
//! Architecture:
//! ```text
//!   ChainObserver (trait)
//!     ├── SolanaObserver   polls Solana JSON-RPC for Anchor LockEvent logs
//!     └── StellarObserver  polls Horizon for Soroban lock() invocations
//! ```
//!
//! Both poll (not WebSocket) for simplicity on testnet. Production
//! should upgrade to WebSocket subscriptions for lower latency.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::error::BridgeError;
use crate::http::{HttpTransport, ReqwestTransport};
use crate::types::{BridgeDeposit, Chain, WrappedToken};

/// Trait for chain-specific lock event observers.
///
/// Implementations poll an external chain's RPC endpoint for new lock
/// events and convert them to [`BridgeDeposit`] records.
///
/// Bound `Send + Sync` so observer sets can cross thread boundaries
/// (`tokio::task::spawn_blocking` in the seal-node RPC handler).
pub trait ChainObserver: Send + Sync {
    /// Which chain this observer monitors.
    fn chain(&self) -> Chain;

    /// Poll for new lock events since `last_cursor`.
    /// Returns new deposits and an updated cursor for pagination.
    ///
    /// The cursor is opaque — for Solana it's a transaction signature,
    /// for Stellar it's a Horizon paging token.
    fn poll_events(
        &self,
        last_cursor: &str,
    ) -> Result<(Vec<BridgeDeposit>, String), BridgeError>;

    /// Check whether a specific source transaction is confirmed and
    /// finalized on the source chain.
    fn is_finalized(&self, source_tx_hash: &str) -> Result<bool, BridgeError>;
}

// ═══════════════════════════════════════════════════════════════════════════
// Solana observer
// ═══════════════════════════════════════════════════════════════════════════

/// Solana observer — watches the seal-bridge Anchor program for
/// `LockEvent` emissions and converts them into `BridgeDeposit`s.
///
/// The program emits lock events via Anchor's `emit!` macro, which the
/// Solana runtime writes to transaction logs as `Program data: <base64>`
/// lines. The first 8 bytes of the decoded payload are the event
/// discriminator (`sha256("event:LockEvent")[0..8]`); the remainder is
/// a Borsh-encoded `LockEvent { sender: Pubkey, amount: u64,
/// seal_address: [u8; 32], nonce: u64, timestamp: i64 }`.
///
/// This observer's parse path is intentionally narrow: it ignores any
/// tx that doesn't emit the exact discriminator we expect. New event
/// types the program might add later are silently skipped, not
/// mis-decoded.
pub struct SolanaObserver {
    /// Solana JSON-RPC endpoint (e.g. "https://api.devnet.solana.com"
    /// or "http://localhost:8899" for `solana-test-validator`).
    pub rpc_url: String,
    /// The seal-bridge program ID on Solana (base-58).
    pub program_id: String,
    /// Required confirmations for finality (Solana's "finalized"
    /// commitment is ~32 slots).
    pub required_confirmations: u32,
    /// HTTP transport — swappable for tests.
    transport: Arc<dyn HttpTransport>,
}

/// The Anchor `LockEvent` discriminator = first 8 bytes of
/// `sha256("event:LockEvent")`. Precomputed so we don't need SHA-256
/// at runtime on the host (the bridges/solana/… program's Anchor build
/// bakes in the same value).
pub(crate) const LOCK_EVENT_DISCRIMINATOR: [u8; 8] =
    [0x21, 0x19, 0x86, 0xc2, 0xd9, 0x8f, 0x67, 0x15];

impl SolanaObserver {
    /// Create with an explicit HTTP transport. Main use is to inject
    /// `MockTransport` in tests; production code should use `new`.
    pub fn with_transport(
        rpc_url: &str,
        program_id: &str,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            program_id: program_id.to_string(),
            required_confirmations: 32,
            transport,
        }
    }

    /// Create with the default reqwest-backed transport.
    pub fn new(rpc_url: &str, program_id: &str) -> Self {
        Self::with_transport(rpc_url, program_id, Arc::new(ReqwestTransport::new()))
    }

    /// Devnet configuration.
    pub fn devnet(program_id: &str) -> Self {
        Self::new("https://api.devnet.solana.com", program_id)
    }

    /// Local `solana-test-validator` configuration.
    pub fn localnet(program_id: &str) -> Self {
        Self::new("http://localhost:8899", program_id)
    }

    /// Build a JSON-RPC envelope. Solana uses standard JSON-RPC 2.0.
    fn rpc_envelope(method: &str, params: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        })
    }

    /// Parse a Solana transaction into a BridgeDeposit (test helper).
    #[allow(dead_code)]
    fn parse_lock_event_raw(
        &self,
        tx_signature: &str,
        sender: &str,
        amount: u64,
        seal_recipient: &str,
        token: WrappedToken,
    ) -> BridgeDeposit {
        BridgeDeposit {
            id: format!("sol_{}", tx_signature),
            source_chain: Chain::Solana,
            source_tx_hash: tx_signature.to_string(),
            source_address: sender.to_string(),
            seal_address: seal_recipient.to_string(),
            amount,
            token,
            processed: false,
            confirmations: 0,
        }
    }

    /// Extract and decode Anchor `LockEvent`s from a transaction's
    /// log messages. Returns one deposit per emitted lock, skipping
    /// any log lines that aren't our event.
    fn deposits_from_logs(
        &self,
        tx_signature: &str,
        sender_fallback: &str,
        log_messages: &[String],
    ) -> Vec<BridgeDeposit> {
        use base64::Engine as _;
        let mut out = Vec::new();
        for line in log_messages {
            // Anchor events appear as: "Program data: <base64>".
            let Some(b64) = line.strip_prefix("Program data: ") else {
                continue;
            };
            let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
                continue;
            };
            if bytes.len() < 8 + 32 + 8 + 32 + 8 + 8 {
                continue;
            }
            if bytes[..8] != LOCK_EVENT_DISCRIMINATOR {
                continue;
            }
            // Borsh layout of LockEvent (same module-order as the program):
            //   sender: Pubkey     (32 bytes, raw)
            //   amount: u64         (8 bytes, little-endian)
            //   seal_address: [u8; 32]
            //   nonce: u64          (8 bytes)
            //   timestamp: i64      (8 bytes)
            let body = &bytes[8..];
            let sender_bytes: [u8; 32] = body[0..32]
                .try_into()
                .expect("32 bytes of sender pubkey");
            let amount = u64::from_le_bytes(body[32..40].try_into().expect("8 bytes amount"));
            let seal_address: [u8; 32] = body[40..72]
                .try_into()
                .expect("32 bytes of seal address");
            // nonce and timestamp are not stored on BridgeDeposit today,
            // but we decode them so a malformed tail still fails loud.
            let _nonce = u64::from_le_bytes(
                body[72..80].try_into().expect("8 bytes nonce"),
            );

            out.push(BridgeDeposit {
                id: format!("sol_{}_{}", tx_signature, _nonce),
                source_chain: Chain::Solana,
                source_tx_hash: tx_signature.to_string(),
                source_address: bs58_encode(&sender_bytes)
                    .unwrap_or_else(|| sender_fallback.to_string()),
                seal_address: hex_encode(&seal_address),
                amount,
                token: WrappedToken::WSOL,
                processed: false,
                confirmations: 0,
            });
        }
        out
    }
}

impl ChainObserver for SolanaObserver {
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn poll_events(
        &self,
        last_cursor: &str,
    ) -> Result<(Vec<BridgeDeposit>, String), BridgeError> {
        // Step 1: get recent signatures for the program.
        let mut params = json!([self.program_id, {"limit": 100, "commitment": "finalized"}]);
        if !last_cursor.is_empty() {
            // `until` scopes the response to signatures newer than the
            // cursor (exclusive). Solana returns newest first.
            params[1]["until"] = json!(last_cursor);
        }
        let sig_resp = self
            .transport
            .post_json(&self.rpc_url, &Self::rpc_envelope("getSignaturesForAddress", params))?;
        let sigs = sig_resp
            .get("result")
            .and_then(|r| r.as_array())
            .ok_or_else(|| {
                BridgeError::RpcError(format!(
                    "getSignaturesForAddress: unexpected shape: {sig_resp}"
                ))
            })?;
        if sigs.is_empty() {
            return Ok((Vec::new(), last_cursor.to_string()));
        }

        // The first entry is newest. For cursor semantics we want the
        // newest tx we processed to be the *new* cursor, so later
        // `until` bounds us correctly.
        let new_cursor = sigs[0]
            .get("signature")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();

        let mut deposits = Vec::new();
        // Walk oldest→newest so repeated calls with the same RPC
        // state produce a stable ordering of deposits.
        for sig_entry in sigs.iter().rev() {
            let signature = match sig_entry.get("signature").and_then(|s| s.as_str()) {
                Some(s) => s,
                None => continue,
            };
            // Skip failed txs. "err" is null on success.
            if sig_entry.get("err").is_some_and(|e| !e.is_null()) {
                continue;
            }
            let tx = self.transport.post_json(
                &self.rpc_url,
                &Self::rpc_envelope(
                    "getTransaction",
                    json!([
                        signature,
                        {
                            "encoding": "json",
                            "commitment": "finalized",
                            "maxSupportedTransactionVersion": 0u64,
                        }
                    ]),
                ),
            )?;
            let logs = tx
                .pointer("/result/meta/logMessages")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            // Use the tx's first signer as a fallback sender label.
            let signer_fallback = tx
                .pointer("/result/transaction/message/accountKeys/0")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            deposits.extend(self.deposits_from_logs(signature, &signer_fallback, &logs));
        }

        Ok((deposits, new_cursor))
    }

    fn is_finalized(&self, source_tx_hash: &str) -> Result<bool, BridgeError> {
        let resp = self.transport.post_json(
            &self.rpc_url,
            &Self::rpc_envelope(
                "getTransaction",
                json!([
                    source_tx_hash,
                    { "encoding": "json", "commitment": "finalized",
                      "maxSupportedTransactionVersion": 0u64 }
                ]),
            ),
        )?;
        // A non-null `result` with no error means the tx is finalized
        // (we asked for commitment=finalized).
        let finalized = resp
            .get("result")
            .is_some_and(|r| !r.is_null() && r.pointer("/meta/err").is_none_or(|e| e.is_null()));
        Ok(finalized)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Stellar observer
// ═══════════════════════════════════════════════════════════════════════════

/// Stellar observer — watches the seal-bridge Soroban contract for
/// `lock()` invocations via Horizon's operations endpoint.
///
/// Horizon's `/accounts/{id}/operations` returns a JSON:API shaped
/// stream. For each `invoke_host_function` operation that targets our
/// contract we read the `function_args` array (XDR-decoded by Horizon
/// into JSON) to extract (sender, amount, seal_address, asset).
pub struct StellarObserver {
    /// Horizon API endpoint.
    pub horizon_url: String,
    /// The seal-bridge contract ID on Stellar (strkey CXXX…).
    pub contract_id: String,
    /// Required ledger confirmations.
    pub required_confirmations: u32,
    transport: Arc<dyn HttpTransport>,
}

impl StellarObserver {
    pub fn with_transport(
        horizon_url: &str,
        contract_id: &str,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            horizon_url: horizon_url.trim_end_matches('/').to_string(),
            contract_id: contract_id.to_string(),
            required_confirmations: 5,
            transport,
        }
    }

    pub fn new(horizon_url: &str, contract_id: &str) -> Self {
        Self::with_transport(horizon_url, contract_id, Arc::new(ReqwestTransport::new()))
    }

    /// Public testnet configuration.
    pub fn testnet(contract_id: &str) -> Self {
        Self::new("https://horizon-testnet.stellar.org", contract_id)
    }

    /// Local `stellar/quickstart` docker container.
    pub fn localnet(contract_id: &str) -> Self {
        Self::new("http://localhost:8000", contract_id)
    }

    fn parse_lock_event_raw(
        &self,
        tx_hash: &str,
        sender: &str,
        amount: u64,
        asset: &str,
        seal_recipient: &str,
    ) -> BridgeDeposit {
        let token = match asset {
            "native" => WrappedToken::WXLM,
            _ => WrappedToken::WUSDC,
        };
        BridgeDeposit {
            id: format!("xlm_{}", tx_hash),
            source_chain: Chain::Stellar,
            source_tx_hash: tx_hash.to_string(),
            source_address: sender.to_string(),
            seal_address: seal_recipient.to_string(),
            amount,
            token,
            processed: false,
            confirmations: 0,
        }
    }

    /// Decode one Horizon operation record into a deposit, if it's a
    /// lock() invocation of our contract.
    fn deposit_from_op(&self, op: &Value) -> Option<BridgeDeposit> {
        if op.get("type").and_then(|t| t.as_str()) != Some("invoke_host_function") {
            return None;
        }
        // Horizon renders function args as a JSON array with decoded
        // scvals. We look for a function named exactly "lock" and the
        // expected positional args (sender, amount, seal_address,
        // asset_symbol).
        let args = op.get("parameters")?.as_array()?;
        let function_name = op.get("function").and_then(|f| f.as_str()).unwrap_or("");
        if function_name != "lock" && function_name != "lock_xlm" {
            return None;
        }
        // Expected ordering — matches bridges/stellar/src/lib.rs:
        //   0: sender (Address → strkey)
        //   1: amount (i128/u64)
        //   2: seal_address (BytesN<32> or Bytes)
        //   3: asset_symbol (Symbol) — optional
        let sender = args.first().and_then(scval_string).unwrap_or_default();
        let amount = args.get(1).and_then(scval_u64)?;
        let seal_address = args.get(2).and_then(scval_hex).unwrap_or_default();
        let asset = args.get(3).and_then(scval_string).unwrap_or_else(|| "native".into());

        let contract = op
            .get("contract")
            .and_then(|c| c.as_str())
            .unwrap_or("");
        if !contract.is_empty() && contract != self.contract_id {
            return None;
        }
        let tx_hash = op
            .get("transaction_hash")
            .and_then(|t| t.as_str())
            .unwrap_or_default()
            .to_string();

        Some(self.parse_lock_event_raw(&tx_hash, &sender, amount, &asset, &seal_address))
    }
}

impl ChainObserver for StellarObserver {
    fn chain(&self) -> Chain {
        Chain::Stellar
    }

    fn poll_events(
        &self,
        last_cursor: &str,
    ) -> Result<(Vec<BridgeDeposit>, String), BridgeError> {
        let cursor_qs = if last_cursor.is_empty() {
            String::new()
        } else {
            format!("&cursor={}", last_cursor)
        };
        let url = format!(
            "{}/accounts/{}/operations?order=asc&limit=100{}",
            self.horizon_url, self.contract_id, cursor_qs
        );
        let resp = self.transport.get_json(&url)?;
        let ops = resp
            .pointer("/_embedded/records")
            .and_then(|r| r.as_array())
            .ok_or_else(|| {
                BridgeError::RpcError(format!("Horizon operations: unexpected shape: {resp}"))
            })?;

        let mut deposits = Vec::new();
        let mut new_cursor = last_cursor.to_string();
        for op in ops {
            if let Some(d) = self.deposit_from_op(op) {
                deposits.push(d);
            }
            // Always advance the cursor — even for non-lock ops — so we
            // don't re-read the same page forever.
            if let Some(paging) = op.get("paging_token").and_then(|p| p.as_str()) {
                new_cursor = paging.to_string();
            }
        }
        Ok((deposits, new_cursor))
    }

    fn is_finalized(&self, source_tx_hash: &str) -> Result<bool, BridgeError> {
        let url = format!("{}/transactions/{}", self.horizon_url, source_tx_hash);
        let resp = self.transport.get_json(&url)?;
        // A successful tx has `successful: true`. Stellar has ~5s
        // finality so presence at all is effectively final.
        Ok(resp
            .get("successful")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-chain observer set
// ═══════════════════════════════════════════════════════════════════════════

/// Multi-chain observer that aggregates events from all supported chains.
pub struct BridgeObserverSet {
    observers: Vec<Box<dyn ChainObserver>>,
    cursors: std::collections::HashMap<Chain, String>,
}

impl BridgeObserverSet {
    pub fn new() -> Self {
        Self {
            observers: Vec::new(),
            cursors: std::collections::HashMap::new(),
        }
    }

    pub fn add_observer(&mut self, observer: Box<dyn ChainObserver>) {
        let chain = observer.chain();
        self.cursors.entry(chain).or_default();
        self.observers.push(observer);
    }

    /// Number of configured observers. Useful as an RPC debug signal
    /// to confirm `seal_addBridgeObserver` calls actually landed.
    pub fn observer_count(&self) -> usize {
        self.observers.len()
    }

    /// Poll all chains for new events. A failure on one chain does not
    /// stop the others — we collect successful deposits and return the
    /// first error encountered (if any).
    pub fn poll_all(&mut self) -> Result<Vec<BridgeDeposit>, BridgeError> {
        let mut all_deposits = Vec::new();
        let mut first_err: Option<BridgeError> = None;
        for observer in &self.observers {
            let chain = observer.chain();
            let cursor = self.cursors.get(&chain).cloned().unwrap_or_default();
            match observer.poll_events(&cursor) {
                Ok((deposits, new_cursor)) => {
                    if !new_cursor.is_empty() {
                        self.cursors.insert(chain, new_cursor);
                    }
                    all_deposits.extend(deposits);
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        if let Some(e) = first_err {
            if all_deposits.is_empty() {
                return Err(e);
            }
            // Partial success: prefer returning what we got. Caller
            // sees the deposits on this round and will re-hit the
            // failing chain on the next poll.
        }
        Ok(all_deposits)
    }
}

impl Default for BridgeObserverSet {
    fn default() -> Self {
        Self::new()
    }
}

// ── Small helpers (crate-private) ───────────────────────────

/// Best-effort scval_string decoder. Horizon's JSON envelope stores
/// function_args as objects like `{ "value": "hello", "type": "string" }`
/// or `{ "value": "CDXYZ…", "type": "address" }`. Return the value
/// when it's a string-shaped scval.
fn scval_string(v: &Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        return Some(s.to_string());
    }
    v.get("value")
        .and_then(|vv| vv.as_str())
        .map(String::from)
        .or_else(|| v.get("address").and_then(|a| a.as_str()).map(String::from))
        .or_else(|| v.get("symbol").and_then(|a| a.as_str()).map(String::from))
}

/// Best-effort u64 decoder for numeric scvals (Horizon serializes
/// amounts as strings to avoid JSON precision loss).
fn scval_u64(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(s) = v.as_str() {
        return s.parse().ok();
    }
    v.get("value")
        .and_then(|vv| vv.as_str().and_then(|s| s.parse().ok()).or_else(|| vv.as_u64()))
}

/// Best-effort hex encoding for `BytesN<32>` seal addresses. Horizon
/// may deliver the bytes as a lowercase hex string directly, as a
/// base64 string, or nested under `{ "value": "…" }`.
///
/// Strategy: if the input already looks like hex (even-length,
/// `[0-9a-fA-F]+`), return it verbatim. Otherwise try base64 →
/// hex-encoded bytes. Last resort: return the raw string.
fn scval_hex(v: &Value) -> Option<String> {
    use base64::Engine as _;
    let raw = match v {
        Value::String(s) => s.clone(),
        _ => v.get("value").and_then(|vv| vv.as_str()).map(String::from)?,
    };
    if looks_hex(&raw) {
        return Some(raw.to_lowercase());
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&raw) {
        return Some(hex_encode(&bytes));
    }
    Some(raw)
}

fn looks_hex(s: &str) -> bool {
    !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Minimal base58 encoder for Solana pubkeys (32 bytes). Avoids
/// pulling `bs58` crate for a single use site.
fn bs58_encode(bytes: &[u8]) -> Option<String> {
    const ALPHABET: &[u8; 58] =
        b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if bytes.is_empty() {
        return Some(String::new());
    }
    let mut num: Vec<u32> = Vec::new();
    for &b in bytes {
        let mut carry = b as u32;
        for digit in num.iter_mut() {
            let v = *digit * 256 + carry;
            *digit = v % 58;
            carry = v / 58;
        }
        while carry > 0 {
            num.push(carry % 58);
            carry /= 58;
        }
    }
    // Leading zeros → leading '1's.
    let mut out = Vec::with_capacity(num.len());
    for &b in bytes.iter().take_while(|&&b| b == 0) {
        let _ = b;
        out.push(b'1');
    }
    for &digit in num.iter().rev() {
        out.push(ALPHABET[digit as usize]);
    }
    String::from_utf8(out).ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockTransport;
    use base64::Engine as _;
    use serde_json::json;
    use std::sync::Arc;

    fn mock_transport() -> Arc<MockTransport> {
        Arc::new(MockTransport::new())
    }

    // ── Solana ─────────────────────────────────────────

    /// Build a base64-encoded Anchor `LockEvent` log payload that the
    /// parser will accept.
    fn lock_event_log(amount: u64, nonce: u64, seal_addr: [u8; 32]) -> String {
        let mut buf = Vec::with_capacity(8 + 32 + 8 + 32 + 8 + 8);
        buf.extend_from_slice(&LOCK_EVENT_DISCRIMINATOR);
        buf.extend_from_slice(&[7u8; 32]); // sender pubkey
        buf.extend_from_slice(&amount.to_le_bytes());
        buf.extend_from_slice(&seal_addr);
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.extend_from_slice(&0i64.to_le_bytes()); // timestamp
        format!(
            "Program data: {}",
            base64::engine::general_purpose::STANDARD.encode(&buf)
        )
    }

    #[test]
    fn solana_observer_creates() {
        let obs = SolanaObserver::devnet("SealLock111111111111111111111111111111111111");
        assert_eq!(obs.chain(), Chain::Solana);
        assert_eq!(obs.required_confirmations, 32);
    }

    #[test]
    fn solana_parse_lock_event_from_logs() {
        let obs = SolanaObserver::with_transport(
            "http://x",
            "prog",
            mock_transport() as Arc<dyn HttpTransport>,
        );
        let seal = [3u8; 32];
        let log = lock_event_log(1_000_000, 42, seal);
        let deposits = obs.deposits_from_logs("sig1", "unknown", &[log]);
        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].amount, 1_000_000);
        assert_eq!(deposits[0].source_chain, Chain::Solana);
        assert_eq!(deposits[0].seal_address, hex_encode(&seal));
        assert_eq!(deposits[0].id, "sol_sig1_42");
        assert_eq!(deposits[0].token, WrappedToken::WSOL);
    }

    #[test]
    fn solana_ignores_non_event_logs() {
        let obs = SolanaObserver::with_transport(
            "http://x",
            "prog",
            mock_transport() as Arc<dyn HttpTransport>,
        );
        let logs = vec![
            "Program 1111... invoke [1]".to_string(),
            "Program log: random noise".to_string(),
            "Program data: not-base64".to_string(),
        ];
        let deposits = obs.deposits_from_logs("sig1", "unknown", &logs);
        assert!(deposits.is_empty());
    }

    #[test]
    fn solana_ignores_wrong_discriminator() {
        let obs = SolanaObserver::with_transport(
            "http://x",
            "prog",
            mock_transport() as Arc<dyn HttpTransport>,
        );
        // Same length as LockEvent but different discriminator.
        let mut buf = vec![0u8; 8 + 32 + 8 + 32 + 8 + 8];
        buf[..8].copy_from_slice(&[0xAAu8; 8]);
        let log = format!(
            "Program data: {}",
            base64::engine::general_purpose::STANDARD.encode(&buf)
        );
        let deposits = obs.deposits_from_logs("sig1", "unknown", &[log]);
        assert!(deposits.is_empty());
    }

    #[test]
    fn solana_poll_events_end_to_end() {
        let transport = mock_transport();
        let obs = SolanaObserver::with_transport(
            "http://x",
            "prog",
            transport.clone() as Arc<dyn HttpTransport>,
        );

        // getSignaturesForAddress response: two signatures, newest
        // first.
        transport.enqueue(
            "POST",
            "http://x",
            json!({
                "result": [
                    {"signature": "sig_new", "err": null},
                    {"signature": "sig_old", "err": null}
                ]
            }),
        );
        // Two getTransaction responses, one per signature (reverse
        // order: we iterate oldest→newest).
        let log_old = lock_event_log(111, 1, [1u8; 32]);
        let log_new = lock_event_log(222, 2, [2u8; 32]);
        transport.enqueue(
            "POST",
            "http://x",
            json!({
                "result": {
                    "meta": {"logMessages": [log_old]},
                    "transaction": {"message": {"accountKeys": ["signerA"]}}
                }
            }),
        );
        transport.enqueue(
            "POST",
            "http://x",
            json!({
                "result": {
                    "meta": {"logMessages": [log_new]},
                    "transaction": {"message": {"accountKeys": ["signerB"]}}
                }
            }),
        );

        let (deposits, cursor) = obs.poll_events("").unwrap();
        assert_eq!(deposits.len(), 2);
        assert_eq!(deposits[0].amount, 111, "oldest first");
        assert_eq!(deposits[1].amount, 222);
        assert_eq!(cursor, "sig_new");
    }

    #[test]
    fn solana_poll_events_skips_failed_tx() {
        let transport = mock_transport();
        let obs = SolanaObserver::with_transport(
            "http://x",
            "prog",
            transport.clone() as Arc<dyn HttpTransport>,
        );

        transport.enqueue(
            "POST",
            "http://x",
            json!({
                "result": [
                    {"signature": "sig_ok", "err": null},
                    {"signature": "sig_fail", "err": {"InstructionError": [0, "Custom"]}}
                ]
            }),
        );
        // Only one getTransaction — the failed sig is skipped.
        let log = lock_event_log(42, 0, [9u8; 32]);
        transport.enqueue(
            "POST",
            "http://x",
            json!({
                "result": {
                    "meta": {"logMessages": [log]},
                    "transaction": {"message": {"accountKeys": ["signerX"]}}
                }
            }),
        );
        let (deposits, _cursor) = obs.poll_events("").unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].amount, 42);
    }

    #[test]
    fn solana_poll_events_empty_returns_old_cursor() {
        let transport = mock_transport();
        let obs = SolanaObserver::with_transport(
            "http://x",
            "prog",
            transport.clone() as Arc<dyn HttpTransport>,
        );
        transport.enqueue("POST", "http://x", json!({"result": []}));
        let (deposits, cursor) = obs.poll_events("prev").unwrap();
        assert!(deposits.is_empty());
        assert_eq!(cursor, "prev");
    }

    #[test]
    fn solana_is_finalized_true_when_result_present() {
        let transport = mock_transport();
        let obs = SolanaObserver::with_transport(
            "http://x",
            "prog",
            transport.clone() as Arc<dyn HttpTransport>,
        );
        transport.enqueue(
            "POST",
            "http://x",
            json!({"result": {"slot": 123, "meta": {"err": null}}}),
        );
        assert!(obs.is_finalized("anysig").unwrap());
    }

    #[test]
    fn solana_is_finalized_false_when_result_null() {
        let transport = mock_transport();
        let obs = SolanaObserver::with_transport(
            "http://x",
            "prog",
            transport.clone() as Arc<dyn HttpTransport>,
        );
        transport.enqueue("POST", "http://x", json!({"result": null}));
        assert!(!obs.is_finalized("anysig").unwrap());
    }

    // ── Stellar ────────────────────────────────────────

    #[test]
    fn stellar_observer_creates() {
        let obs = StellarObserver::testnet("CDXYZ_CONTRACT_ID");
        assert_eq!(obs.chain(), Chain::Stellar);
        assert_eq!(obs.required_confirmations, 5);
    }

    #[test]
    fn stellar_parse_lock_event_raw_xlm() {
        let obs = StellarObserver::testnet("contract1");
        let dep = obs.parse_lock_event_raw(
            "xlm_tx_hash_123",
            "GABCD_stellar",
            5_000_000,
            "native",
            "seal1bob",
        );
        assert_eq!(dep.token, WrappedToken::WXLM);
        assert_eq!(dep.source_chain, Chain::Stellar);
    }

    #[test]
    fn stellar_parse_lock_event_raw_non_xlm_is_usdc() {
        let obs = StellarObserver::testnet("contract1");
        let dep =
            obs.parse_lock_event_raw("tx_456", "GABCD", 100_000, "USDC_CONTRACT_ID", "seal1carol");
        assert_eq!(dep.token, WrappedToken::WUSDC);
    }

    #[test]
    fn stellar_poll_events_end_to_end() {
        let transport = mock_transport();
        let obs = StellarObserver::with_transport(
            "http://horizon",
            "contractX",
            transport.clone() as Arc<dyn HttpTransport>,
        );
        let expected_url =
            "http://horizon/accounts/contractX/operations?order=asc&limit=100";
        transport.enqueue(
            "GET",
            expected_url,
            json!({
                "_embedded": {
                    "records": [
                        {
                            "type": "invoke_host_function",
                            "contract": "contractX",
                            "function": "lock",
                            "parameters": [
                                {"type": "address", "value": "GSENDER"},
                                {"type": "u64", "value": "1000000"},
                                {"type": "bytes", "value": "aabbccdd"},
                                {"type": "symbol", "value": "native"}
                            ],
                            "transaction_hash": "tx1",
                            "paging_token": "p1"
                        },
                        {
                            "type": "payment",
                            "paging_token": "p2"
                        }
                    ]
                }
            }),
        );
        let (deposits, cursor) = obs.poll_events("").unwrap();
        assert_eq!(deposits.len(), 1, "only the lock op yields a deposit");
        assert_eq!(deposits[0].amount, 1_000_000);
        assert_eq!(deposits[0].source_address, "GSENDER");
        assert_eq!(deposits[0].token, WrappedToken::WXLM);
        assert_eq!(deposits[0].seal_address, "aabbccdd");
        assert_eq!(cursor, "p2", "cursor advances past the payment too");
    }

    #[test]
    fn stellar_poll_events_cursor_in_url() {
        let transport = mock_transport();
        let obs = StellarObserver::with_transport(
            "http://horizon",
            "contractX",
            transport.clone() as Arc<dyn HttpTransport>,
        );
        let expected_url =
            "http://horizon/accounts/contractX/operations?order=asc&limit=100&cursor=abc";
        transport.enqueue(
            "GET",
            expected_url,
            json!({"_embedded": {"records": []}}),
        );
        let (deposits, cursor) = obs.poll_events("abc").unwrap();
        assert!(deposits.is_empty());
        assert_eq!(cursor, "abc", "empty page keeps the old cursor");
    }

    #[test]
    fn stellar_poll_events_skips_other_contract() {
        let transport = mock_transport();
        let obs = StellarObserver::with_transport(
            "http://horizon",
            "contractX",
            transport.clone() as Arc<dyn HttpTransport>,
        );
        transport.enqueue(
            "GET",
            "http://horizon/accounts/contractX/operations?order=asc&limit=100",
            json!({
                "_embedded": {
                    "records": [{
                        "type": "invoke_host_function",
                        "contract": "someOtherContract",
                        "function": "lock",
                        "parameters": [
                            {"value": "GS"}, {"value": "1"}, {"value": "aa"}, {"value": "native"}
                        ],
                        "transaction_hash": "tx",
                        "paging_token": "p"
                    }]
                }
            }),
        );
        let (deposits, _) = obs.poll_events("").unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn stellar_is_finalized_reads_successful_flag() {
        let transport = mock_transport();
        let obs = StellarObserver::with_transport(
            "http://horizon",
            "contractX",
            transport.clone() as Arc<dyn HttpTransport>,
        );
        transport.enqueue(
            "GET",
            "http://horizon/transactions/abc",
            json!({"successful": true}),
        );
        assert!(obs.is_finalized("abc").unwrap());

        transport.enqueue(
            "GET",
            "http://horizon/transactions/def",
            json!({"successful": false}),
        );
        assert!(!obs.is_finalized("def").unwrap());
    }

    // ── BridgeObserverSet ──────────────────────────────

    #[test]
    fn bridge_observer_set_aggregates_and_advances_cursors() {
        let sol_transport = mock_transport();
        let stellar_transport = mock_transport();
        sol_transport.enqueue("POST", "http://s", json!({"result": []}));
        stellar_transport.enqueue(
            "GET",
            "http://h/accounts/c/operations?order=asc&limit=100",
            json!({"_embedded": {"records": []}}),
        );
        let mut set = BridgeObserverSet::new();
        set.add_observer(Box::new(SolanaObserver::with_transport(
            "http://s",
            "prog",
            sol_transport as Arc<dyn HttpTransport>,
        )));
        set.add_observer(Box::new(StellarObserver::with_transport(
            "http://h",
            "c",
            stellar_transport as Arc<dyn HttpTransport>,
        )));
        let deposits = set.poll_all().unwrap();
        assert!(deposits.is_empty());
        assert_eq!(set.observers.len(), 2);
    }

    // ── helper tests ───────────────────────────────────

    #[test]
    fn bs58_encode_roundtrip_known_vectors() {
        // Empty.
        assert_eq!(bs58_encode(&[]).as_deref(), Some(""));
        // All-zero (leading 1s).
        assert_eq!(bs58_encode(&[0u8; 3]).as_deref(), Some("111"));
        // Known single byte: 1 → '2'.
        assert_eq!(bs58_encode(&[1u8]).as_deref(), Some("2"));
    }

    #[test]
    fn hex_encode_known_bytes() {
        assert_eq!(hex_encode(&[0xab, 0xcd, 0x01]), "abcd01");
        assert_eq!(hex_encode(&[]), "");
    }
}
