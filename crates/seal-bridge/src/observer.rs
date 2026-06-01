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
    fn poll_events(&self, last_cursor: &str) -> Result<(Vec<BridgeDeposit>, String), BridgeError>;

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
    /// Optional USDC mint (base-58 Pubkey). When the on-chain
    /// `LockEvent.mint` matches, the observer routes the deposit to
    /// `WrappedToken::WUSDC`. Anything else routes to `WSOL`.
    /// Configured via `seal_addBridgeObserver` `usdc_mint` param so
    /// operators can flip the canonical devnet USDC mint
    /// (`Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr`) without a
    /// node rebuild.
    pub usdc_mint: Option<String>,
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
    [0x4c, 0x25, 0x06, 0xba, 0x0e, 0x2a, 0xfd, 0x0f];

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
            usdc_mint: None,
            required_confirmations: 32,
            transport,
        }
    }

    /// Create with the default reqwest-backed transport.
    pub fn new(rpc_url: &str, program_id: &str) -> Self {
        Self::with_transport(rpc_url, program_id, Arc::new(ReqwestTransport::new()))
    }

    /// Builder: attach a USDC mint pubkey. Locks of this mint route to
    /// `WrappedToken::WUSDC`; everything else routes to `WSOL`.
    pub fn with_usdc_mint(mut self, mint: impl Into<String>) -> Self {
        self.usdc_mint = Some(mint.into());
        self
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
            // LockEvent layouts:
            //   v1 (legacy): disc(8) + sender(32) + amount(8) +
            //                seal_address(32) + nonce(8) + timestamp(8)
            //              = 96 bytes total.
            //   v2 (current): disc(8) + sender(32) + amount(8) +
            //                 seal_address(32) + mint(32) + nonce(8) +
            //                 timestamp(8) = 128 bytes total.
            // Accept both so operators who haven't redeployed the
            // Anchor program (v1) still see locks observed. A v1 lock
            // always routes to WSOL because the on-chain event
            // doesn't carry the mint pubkey.
            const V1_LEN: usize = 8 + 32 + 8 + 32 + 8 + 8;
            const V2_LEN: usize = 8 + 32 + 8 + 32 + 32 + 8 + 8;
            if bytes.len() != V1_LEN && bytes.len() != V2_LEN {
                continue;
            }
            if bytes[..8] != LOCK_EVENT_DISCRIMINATOR {
                continue;
            }
            let body = &bytes[8..];
            let sender_bytes: [u8; 32] = body[0..32].try_into().expect("32 bytes of sender pubkey");
            let amount = u64::from_le_bytes(body[32..40].try_into().expect("8 bytes amount"));
            let seal_address: [u8; 32] = body[40..72].try_into().expect("32 bytes of seal address");

            // Branch on layout: in v2, mint sits between
            // seal_address and nonce; in v1 there's no mint at all.
            let (mint_bytes, _nonce) = if bytes.len() == V2_LEN {
                let m: [u8; 32] = body[72..104].try_into().expect("32 bytes of mint pubkey");
                let n = u64::from_le_bytes(body[104..112].try_into().expect("8 bytes nonce"));
                (Some(m), n)
            } else {
                let n = u64::from_le_bytes(body[72..80].try_into().expect("8 bytes nonce"));
                (None, n)
            };

            // Route to WUSDC iff v2 carried a mint AND it matches the
            // operator-configured USDC pubkey; otherwise WSOL.
            let token = match (&self.usdc_mint, mint_bytes.and_then(|m| bs58_encode(&m))) {
                (Some(want), Some(got)) if &got == want => WrappedToken::WUSDC,
                _ => WrappedToken::WSOL,
            };

            out.push(BridgeDeposit {
                id: format!("sol_{}_{}", tx_signature, _nonce),
                source_chain: Chain::Solana,
                source_tx_hash: tx_signature.to_string(),
                source_address: bs58_encode(&sender_bytes)
                    .unwrap_or_else(|| sender_fallback.to_string()),
                seal_address: hex_encode(&seal_address),
                amount,
                token,
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

    fn poll_events(&self, last_cursor: &str) -> Result<(Vec<BridgeDeposit>, String), BridgeError> {
        // Step 1: get recent signatures for the program.
        // "confirmed" (not "finalized") so the observer catches txs within
        // seconds on a local test-validator where finalization lags ~32 slots
        // (~13s). For mainnet, bump to "finalized" for full reorg safety.
        let mut params = json!([self.program_id, {"limit": 100, "commitment": "confirmed"}]);
        if !last_cursor.is_empty() {
            // `until` scopes the response to signatures newer than the
            // cursor (exclusive). Solana returns newest first.
            params[1]["until"] = json!(last_cursor);
        }
        let sig_resp = self.transport.post_json(
            &self.rpc_url,
            &Self::rpc_envelope("getSignaturesForAddress", params),
        )?;
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
                            "commitment": "confirmed",
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
            .is_some_and(|r| !r.is_null() && r.pointer("/meta/err").map_or(true, |e| e.is_null()));
        Ok(finalized)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Stellar observer
// ═══════════════════════════════════════════════════════════════════════════

/// Stellar observer — watches the seal-bridge Soroban contract for
/// `lock` events via Soroban RPC `getEvents`.
///
/// Uses the Soroban RPC endpoint (typically port 8003) rather than
/// Horizon (port 8000). Horizon's `/accounts/{contract}/operations`
/// endpoint indexes operations by the transaction SOURCE account, not
/// the called contract — so it returns zero results for
/// `invoke_host_function` calls that target our bridge contract.
/// The Soroban RPC `getEvents` method provides a contract-scoped event
/// stream that is correct for this purpose.
///
/// Event format emitted by `lock_xlm` in the Soroban contract:
///   topic: `(symbol_short!("lock"),)` — one XDR ScVal::Symbol
///   value: XDR ScVal::Map of the `LockInfo` contracttype struct with
///          fields: amount (i128), nonce (u64), seal_address (BytesN<32>),
///          sender (Address), timestamp (u64).
pub struct StellarObserver {
    /// Horizon API endpoint (used only for `is_finalized`).
    pub horizon_url: String,
    /// Soroban RPC endpoint (used for `getEvents`).
    pub soroban_rpc_url: String,
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
        let horizon = horizon_url.trim_end_matches('/').to_string();
        let soroban_rpc = derive_soroban_rpc_url(&horizon);
        Self {
            horizon_url: horizon,
            soroban_rpc_url: soroban_rpc,
            contract_id: contract_id.to_string(),
            required_confirmations: 5,
            transport,
        }
    }

    pub fn new(horizon_url: &str, contract_id: &str) -> Self {
        Self::with_transport(horizon_url, contract_id, Arc::new(ReqwestTransport::new()))
    }

    /// Override the Soroban RPC URL (builder method).
    pub fn with_soroban_rpc(mut self, soroban_rpc_url: &str) -> Self {
        self.soroban_rpc_url = soroban_rpc_url.trim_end_matches('/').to_string();
        self
    }

    /// Public testnet configuration.
    pub fn testnet(contract_id: &str) -> Self {
        Self::new("https://horizon-testnet.stellar.org", contract_id)
            .with_soroban_rpc("https://soroban-testnet.stellar.org")
    }

    /// Local `stellar/quickstart` docker container.
    pub fn localnet(contract_id: &str) -> Self {
        Self::new("http://localhost:8000", contract_id).with_soroban_rpc("http://localhost:8003")
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

    /// Decode one Soroban RPC event into a deposit, if it's one of
    /// our recognized lock events (`lock` for XLM, `lockusdc` for USDC).
    fn deposit_from_event(&self, event: &Value) -> Option<BridgeDeposit> {
        // Skip events that are not from our contract.
        let contract = event
            .get("contractId")
            .and_then(|c| c.as_str())
            .unwrap_or("");
        if !contract.is_empty() && contract != self.contract_id {
            return None;
        }
        // Skip events that were not part of a successful contract call.
        if !event
            .get("inSuccessfulContractCall")
            .and_then(|v| v.as_bool())
            .unwrap_or(true)
        {
            return None;
        }
        // Detect which lock variant: Symbol("lock") → XLM, Symbol("lockusdc") → USDC.
        let topics = event.get("topic").and_then(|t| t.as_array())?;
        let first_topic = topics.first().and_then(|t| t.as_str())?;
        let asset_tag = if is_lock_symbol(first_topic) {
            "native"
        } else if is_lockusdc_symbol(first_topic) {
            "USDC"
        } else {
            return None;
        };
        let tx_hash = event
            .get("txHash")
            .and_then(|t| t.as_str())
            .unwrap_or_default();
        // Parse the XDR-encoded LockInfo value.
        let value_b64 = event.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let (amount, seal_address, sender) =
            parse_lock_info_xdr(value_b64).unwrap_or((0, String::new(), String::new()));
        Some(self.parse_lock_event_raw(tx_hash, &sender, amount, asset_tag, &seal_address))
    }
}

impl ChainObserver for StellarObserver {
    fn chain(&self) -> Chain {
        Chain::Stellar
    }

    fn poll_events(&self, last_cursor: &str) -> Result<(Vec<BridgeDeposit>, String), BridgeError> {
        // Build a Soroban RPC getEvents request body.
        // Omit "topics" entirely — stellar-rpc 25.x rejects the string "*"
        // as a wildcard (only JSON null is valid, and omitting the field is
        // cleaner). deposit_from_event() filters to lock events by XDR topic.
        // Pull all contract events without a contractIds filter — stellar-rpc
        // 25.x silently returns 0 results when the filter matches a contract
        // address that was deployed *after* the RPC's first-seen retention
        // window, even when the index clearly contains events with that
        // contractId (verified by an unfiltered query returning the event).
        // Filtering client-side via `deposit_from_event` keeps the load on
        // the host (a few hundred bytes per ledger) and bypasses the
        // server-side bug. Same `filters: [{type:"contract"}]` keeps
        // non-contract events out.
        // Page size — Soroban RPC accepts up to 10 000 per page. The
        // observer drains until it catches up to latestLedger so a fresh
        // observer registered after the chain has been running for a
        // while doesn't need 130+ `seal_pollBridges` calls to walk
        // through 13 000 ledgers of events.
        const PAGE_LIMIT: u64 = 10_000;
        let build_body = |start_ledger: Option<u64>, cursor: Option<&str>| -> Value {
            let mut params = json!({
                "filters": [{"type": "contract"}],
                "pagination": { "limit": PAGE_LIMIT }
            });
            if let Some(l) = start_ledger {
                params["startLedger"] = json!(l);
            }
            if let Some(c) = cursor {
                params["pagination"]["cursor"] = json!(c);
            }
            json!({"jsonrpc": "2.0", "id": 1, "method": "getEvents", "params": params})
        };

        let mut deposits = Vec::new();
        let mut current_cursor = last_cursor.to_string();
        // Across-poll cursor must be event-precise so consecutive
        // `poll_events` calls don't re-observe events. We initialize
        // it to the input cursor (in case no new events land this
        // poll), and overwrite as we see events below.
        let mut last_event_id: Option<String> = if last_cursor.is_empty() {
            None
        } else {
            Some(last_cursor.to_string())
        };
        // Safety cap on pages per poll — at PAGE_LIMIT=10k and ~1
        // event/ledger this drains ~100k ledgers in 10 calls; production
        // shouldn't need more than a handful even after long observer
        // downtime. The cap exists so a misconfigured RPC that keeps
        // returning full pages can't burn the seal-node forever.
        for _page in 0..20 {
            // Build the request body for this page.
            //
            // Initial cursor + startLedger handling (first call only):
            // try startLedger=2; if rejected with "must be within
            // range: N - …", parse N and retry with that. stellar-rpc
            // 25.x doesn't populate `error.data.oldestLedger`.
            let resp = if current_cursor.is_empty() {
                let r = self
                    .transport
                    .post_json(&self.soroban_rpc_url, &build_body(Some(2), None))?;
                if r.pointer("/result/events").is_some() {
                    r
                } else if let Some(oldest) = extract_oldest_ledger(&r) {
                    // First retry: stellar-rpc told us the lower bound.
                    let r2 = self
                        .transport
                        .post_json(&self.soroban_rpc_url, &build_body(Some(oldest), None))?;
                    if r2.pointer("/result/events").is_some() {
                        r2
                    } else if let Some(latest) =
                        fetch_latest_ledger(&*self.transport, &self.soroban_rpc_url)
                    {
                        // P7#2: ultimate fallback — if the retry still
                        // fails (e.g., the lower bound jumped between
                        // calls because of pruning), call
                        // getLatestLedger and pick a window 24 h back.
                        // 17280 ≈ 24 h of 5-second ledgers; the bridge
                        // doesn't need older history than that for fresh
                        // observers, and starting too close to the tip
                        // risks missing pending events.
                        let start = latest.saturating_sub(17_280).max(2);
                        self.transport
                            .post_json(&self.soroban_rpc_url, &build_body(Some(start), None))?
                    } else {
                        r2
                    }
                } else if let Some(latest) =
                    fetch_latest_ledger(&*self.transport, &self.soroban_rpc_url)
                {
                    // First-call rejection but no oldest-ledger hint —
                    // jump to latest-24h as a best-effort starting point.
                    let start = latest.saturating_sub(17_280).max(2);
                    self.transport
                        .post_json(&self.soroban_rpc_url, &build_body(Some(start), None))?
                } else {
                    r
                }
            } else {
                self.transport.post_json(
                    &self.soroban_rpc_url,
                    &build_body(None, Some(&current_cursor)),
                )?
            };

            let events = resp
                .pointer("/result/events")
                .and_then(|e| e.as_array())
                .ok_or_else(|| {
                    BridgeError::RpcError(format!(
                        "Soroban getEvents: unexpected response shape: {resp}"
                    ))
                })?;

            // Track the LATEST event id seen — this becomes the
            // `last_cursor` returned to the caller, so the NEXT
            // `poll_events` call resumes precisely past every event
            // we observed (no skips, no duplicates across polls).
            for event in events {
                if let Some(id) = event.get("id").and_then(|p| p.as_str()) {
                    last_event_id = Some(id.to_string());
                }
                if let Some(d) = self.deposit_from_event(event) {
                    deposits.push(d);
                }
            }
            // Soroban RPC paginates by ledger-window, not event-count:
            // `pagination.limit` caps the max ledgers scanned per call,
            // not events returned. So `events.len() < PAGE_LIMIT` is
            // NOT a "caught up" signal — sparse ranges return few
            // events while the cursor still advances by a fixed window.
            // Use the server-reported `result.cursor` as the
            // authoritative pagination state within the drain (it
            // jumps over empty windows in one hop); fall back to the
            // last event id between polls so we don't miss anything.
            let server_cursor = resp
                .pointer("/result/cursor")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let Some(sc) = server_cursor else {
                break;
            };
            current_cursor = sc.clone();
            // Stop when the cursor crosses the latestLedger boundary.
            let latest = resp
                .pointer("/result/latestLedger")
                .and_then(|v| v.as_u64())
                .unwrap_or(u64::MAX);
            if cursor_ledger(&sc).unwrap_or(0) >= latest {
                break;
            }
            // Defense in depth: if we hit the loop cap with a full
            // page, the observer is lagging the chain. The next poll
            // resumes from the last event id (event-precise) and
            // continues draining.
        }
        // Return the per-event cursor for the next poll — using the
        // server cursor here would skip over any newly-arrived events
        // in the window between calls (the server cursor jumps by
        // ledger-window, not event-by-event).
        let resume_cursor = last_event_id.unwrap_or(current_cursor);
        Ok((deposits, resume_cursor))
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

/// Parse the ledger field out of a Soroban cursor. Cursors are
/// strings of the form `LLLLLLLLLLLLLLLLLLL-TTTTTTTTTT` where
/// `LLL…` is `ledger << 32 | tx_index << 12 | op_index` (per soroban-rpc
/// 25.x). For the page-drain "are we caught up?" check we only need
/// the ledger; right-shift the parsed u64 by 32.
fn cursor_ledger(cursor: &str) -> Option<u64> {
    let head = cursor.split_once('-').map(|(h, _)| h).unwrap_or(cursor);
    head.parse::<u64>().ok().map(|n| n >> 32)
}

/// Extract the oldest ledger that the Soroban RPC will accept from a
/// `startLedger` rejection. We accept three wire formats so a stellar-
/// rpc upgrade across the 25.x line doesn't take the observer down:
///
/// 1. Object: `{"error":{"data":{"oldestLedger":N}}}`
///    — documented shape; future versions are expected to populate it.
/// 2. Message regex: `{"error":{"message":"startLedger must be within
///    the ledger range: 7 - 715"}}` — emitted by stellar-rpc 25.x as
///    of 2026-05.
/// 3. String `data`: `{"error":{"data":"oldestLedger is 7"}}` — seen
///    on stellar-rpc 25.0 nightly builds; preserved here in case it
///    re-appears after a rebuild.
fn extract_oldest_ledger(resp: &Value) -> Option<u64> {
    // 1. documented object shape
    if let Some(n) = resp
        .pointer("/error/data/oldestLedger")
        .and_then(|v| v.as_u64())
    {
        return Some(n);
    }
    // 3. string `data` shape (P7#1 fallback).
    if let Some(s) = resp.pointer("/error/data").and_then(|v| v.as_str()) {
        if let Some(n) = parse_first_u64_after(s, "oldestLedger") {
            return Some(n);
        }
    }
    // 2. message regex
    let msg = resp.pointer("/error/message").and_then(|v| v.as_str())?;
    let tail = msg.split_once("range:").map(|(_, t)| t)?;
    let digits: String = tail
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// Find the first run of ASCII digits in `s` after a literal anchor.
/// Used by the string-`data` `oldestLedger` parser; defensive against
/// "oldestLedger is N", "oldestLedger=N", "oldestLedger: N".
fn parse_first_u64_after(s: &str, anchor: &str) -> Option<u64> {
    let tail = s.split_once(anchor).map(|(_, t)| t)?;
    let digits: String = tail
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// Call Soroban RPC `getLatestLedger` and return the current sequence,
/// or `None` if the call fails or the response shape is unexpected.
/// Used as a last-resort starting-point fallback when both the first
/// `startLedger=2` attempt and the `oldestLedger`-hinted retry fail —
/// e.g., a fresh chain where the lower bound jumps between calls.
fn fetch_latest_ledger(transport: &dyn crate::http::HttpTransport, url: &str) -> Option<u64> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLatestLedger",
        "params": {}
    });
    let resp = transport.post_json(url, &body).ok()?;
    // Soroban returns {"result":{"sequence":N,"id":"...","protocolVersion":22}}
    resp.pointer("/result/sequence").and_then(|v| v.as_u64())
}

/// Derive the Soroban RPC URL from a Horizon URL.
/// The quickstart container exposes Soroban RPC on port 8003 while
/// Horizon is on port 8000; we simply swap the port.
fn derive_soroban_rpc_url(horizon_url: &str) -> String {
    // Common case: http://host:8000 → http://host:8003
    if horizon_url.contains(":8000") {
        return horizon_url.replace(":8000", ":8003");
    }
    // Stellar public endpoints — Horizon and Soroban RPC have different hosts.
    if horizon_url.contains("horizon-testnet.stellar.org") {
        return "https://soroban-testnet.stellar.org".to_string();
    }
    if horizon_url.contains("horizon.stellar.org") {
        return "https://soroban-rpc.stellar.org".to_string();
    }
    // Generic fallback: append :8003 to whatever host is given.
    format!("{horizon_url}:8003")
}

/// Check whether a base64-encoded XDR ScVal topic is `Symbol("lock")`.
///
/// `symbol_short!("lock")` in the Soroban contract produces
/// `ScVal::Symbol("lock")`. Its XDR encoding is:
///   4B discriminant: SCV_SYMBOL = 15 = [0x00, 0x00, 0x00, 0x0F]
///   4B string length: 4 = [0x00, 0x00, 0x00, 0x04]
///   4B string bytes: "lock" = [0x6c, 0x6f, 0x63, 0x6b]
/// → base64: "AAAADwAAAARsb2Nr"
fn is_lock_symbol(b64: &str) -> bool {
    use base64::Engine as _;
    let bytes = match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    bytes.len() >= 12
        && bytes[0..4] == [0, 0, 0, 15]   // SCV_SYMBOL = 15
        && bytes[4..8] == [0, 0, 0, 4]    // string length = 4
        && bytes[8..12] == b"lock"[..] // "lock"
}

/// Check whether a base64-encoded XDR ScVal topic is `Symbol("lockusdc")`.
///
/// `symbol_short!("lockusdc")` in the Soroban contract produces
/// `ScVal::Symbol("lockusdc")`. XDR encoding:
///   4B discriminant: SCV_SYMBOL = 15
///   4B string length: 8
///   8B string bytes: "lockusdc"
/// → base64: "AAAADwAAAAhsb2NrdXNkYw=="
fn is_lockusdc_symbol(b64: &str) -> bool {
    use base64::Engine as _;
    let bytes = match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    bytes.len() >= 16
        && bytes[0..4] == [0, 0, 0, 15]   // SCV_SYMBOL = 15
        && bytes[4..8] == [0, 0, 0, 8]    // string length = 8
        && bytes[8..16] == b"lockusdc"[..] // "lockusdc"
}

/// Parse a base64-encoded XDR `ScVal::Map` emitted by `lock_xlm`
/// (the `LockInfo` contracttype struct). Returns `(amount, seal_address_hex, sender_hex)`.
///
/// The `#[contracttype]` macro serializes struct fields in alphabetical
/// order by field name. For `LockInfo` that order is:
///   amount (i128), nonce (u64), seal_address (BytesN<32>),
///   sender (Address), timestamp (u64).
///
/// We dispatch by key name so the order doesn't affect correctness.
fn parse_lock_info_xdr(b64: &str) -> Option<(u64, String, String)> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let mut r = XdrCursor::new(&bytes);

    // ScVal::Map discriminant = 17, followed by an XDR option marker
    // for `Option<ScMap>` (1 = Some, 0 = None). soroban-sdk always emits
    // a Some-wrapped map for `#[contracttype]` structs; Some is therefore
    // the only shape we accept.
    if r.read_u32()? != 17 {
        return None;
    }
    if r.read_u32()? != 1 {
        return None;
    }
    let count = r.read_u32()? as usize;

    let mut amount = 0u64;
    let mut seal_address = String::new();
    let mut sender = String::new();

    for _ in 0..count {
        // Key: ScVal::Symbol (discriminant = 15)
        if r.read_u32()? != 15 {
            return None;
        }
        let key_len = r.read_u32()? as usize;
        let key_bytes = r.read_bytes_padded(key_len)?;
        let key = std::str::from_utf8(key_bytes).ok()?.to_string();

        // Value: dispatch by field name
        let val_disc = r.read_u32()?;
        match (key.as_str(), val_disc) {
            ("amount", 10) => {
                // SCV_I128: Int128Parts { hi: i64 (8B BE), lo: u64 (8B BE) }
                let _hi = r.read_u64()?;
                amount = r.read_u64()?;
            }
            ("nonce" | "timestamp", 5) => {
                // SCV_U64
                let _ = r.read_u64()?;
            }
            ("seal_address", 13) => {
                // SCV_BYTES: u32 length + bytes (padded to 4-byte boundary)
                let len = r.read_u32()? as usize;
                let data = r.read_bytes_padded(len)?;
                seal_address = hex_encode(data);
            }
            ("sender", 18) => {
                // SCV_ADDRESS: ScAddressType (u32) + payload
                match r.read_u32()? {
                    0 => {
                        // SC_ADDRESS_TYPE_ACCOUNT: PublicKey (4B disc + 32B key)
                        let _pk_disc = r.read_u32()?;
                        let key = r.read_exact(32)?;
                        sender = hex_encode(key);
                    }
                    1 => {
                        // SC_ADDRESS_TYPE_CONTRACT: 32B hash
                        let hash = r.read_exact(32)?;
                        sender = hex_encode(hash);
                    }
                    _ => return None,
                }
            }
            _ => break, // unknown field — stop to avoid XDR misalignment
        }
    }

    Some((amount, seal_address, sender))
}

/// Minimal cursor-based XDR reader. Used only by `parse_lock_info_xdr`.
struct XdrCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> XdrCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Some(v)
    }

    fn read_u64(&mut self) -> Option<u64> {
        if self.pos + 8 > self.data.len() {
            return None;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Some(u64::from_be_bytes(b))
    }

    fn read_exact(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return None;
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }

    fn read_bytes_padded(&mut self, len: usize) -> Option<&'a [u8]> {
        let padded = (len + 3) & !3;
        if self.pos + padded > self.data.len() {
            return None;
        }
        let s = &self.data[self.pos..self.pos + len];
        self.pos += padded;
        Some(s)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-chain observer set
// ═══════════════════════════════════════════════════════════════════════════

/// Multi-chain observer that aggregates events from all supported chains.
/// Per-observer scheduling metadata. `poll_interval` of zero means
/// "always due" — preserves the prior behavior of `poll_all`.
struct ObserverEntry {
    observer: Box<dyn ChainObserver>,
    poll_interval: std::time::Duration,
    last_polled: Option<std::time::Instant>,
}

pub struct BridgeObserverSet {
    observers: Vec<ObserverEntry>,
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
        self.add_observer_with_interval(observer, 0);
    }

    /// Register an observer with a per-chain poll interval (seconds).
    /// `interval_secs = 0` falls back to the global auto-poll tick —
    /// matches the prior unconditional `add_observer` behavior.
    /// Different chains can run at different rates (Solana 5 s, Stellar
    /// 30 s) so a slow source-chain RPC doesn't drag the fast one's
    /// observation cadence.
    pub fn add_observer_with_interval(
        &mut self,
        observer: Box<dyn ChainObserver>,
        interval_secs: u64,
    ) {
        let chain = observer.chain();
        self.cursors.entry(chain).or_default();
        self.observers.push(ObserverEntry {
            observer,
            poll_interval: std::time::Duration::from_secs(interval_secs),
            last_polled: None,
        });
    }

    /// Number of configured observers. Useful as an RPC debug signal
    /// to confirm `seal_addBridgeObserver` calls actually landed.
    pub fn observer_count(&self) -> usize {
        self.observers.len()
    }

    /// Configured intervals for each observer's chain (label-info for
    /// /metrics + debug). Zero means "always poll on every tick".
    pub fn poll_intervals(&self) -> Vec<(Chain, u64)> {
        self.observers
            .iter()
            .map(|e| (e.observer.chain(), e.poll_interval.as_secs()))
            .collect()
    }

    /// Poll every observer unconditionally (used by the
    /// `seal_pollBridges` RPC for explicit-tick tests in
    /// `bridge-e2e.sh`). For the scheduled auto-poll path use
    /// `poll_due(now)`.
    pub fn poll_all(&mut self) -> Result<Vec<BridgeDeposit>, BridgeError> {
        self.poll_filtered(|_| true)
    }

    /// Poll only observers whose configured interval has elapsed
    /// since their last poll (or which have never been polled).
    /// Observers with `poll_interval = 0` are treated as always-due,
    /// preserving the prior global-tick behavior. The background
    /// auto-poll task drives this on every tick.
    pub fn poll_due(&mut self, now: std::time::Instant) -> Result<Vec<BridgeDeposit>, BridgeError> {
        self.poll_filtered(|e| match (e.poll_interval.as_secs(), e.last_polled) {
            (0, _) => true,
            (_, None) => true,
            (_, Some(last)) => now.saturating_duration_since(last) >= e.poll_interval,
        })
    }

    fn poll_filtered<F: Fn(&ObserverEntry) -> bool>(
        &mut self,
        predicate: F,
    ) -> Result<Vec<BridgeDeposit>, BridgeError> {
        let mut all_deposits = Vec::new();
        let mut first_err: Option<BridgeError> = None;
        let now = std::time::Instant::now();
        for entry in &mut self.observers {
            if !predicate(entry) {
                continue;
            }
            let chain = entry.observer.chain();
            let cursor = self.cursors.get(&chain).cloned().unwrap_or_default();
            match entry.observer.poll_events(&cursor) {
                Ok((deposits, new_cursor)) => {
                    if !new_cursor.is_empty() {
                        self.cursors.insert(chain, new_cursor);
                    }
                    all_deposits.extend(deposits);
                    entry.last_polled = Some(now);
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                    // Don't mark last_polled on error so the next tick
                    // retries immediately rather than waiting another
                    // interval.
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

/// Minimal base58 encoder for Solana pubkeys (32 bytes). Avoids
/// pulling `bs58` crate for a single use site.
fn bs58_encode(bytes: &[u8]) -> Option<String> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
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
    /// parser will accept. Default mint is all-zeros (= WSOL); use
    /// `lock_event_log_with_mint` to inject a specific mint pubkey.
    fn lock_event_log(amount: u64, nonce: u64, seal_addr: [u8; 32]) -> String {
        lock_event_log_with_mint(amount, nonce, seal_addr, [0u8; 32])
    }

    fn lock_event_log_with_mint(
        amount: u64,
        nonce: u64,
        seal_addr: [u8; 32],
        mint: [u8; 32],
    ) -> String {
        let mut buf = Vec::with_capacity(8 + 32 + 8 + 32 + 32 + 8 + 8);
        buf.extend_from_slice(&LOCK_EVENT_DISCRIMINATOR);
        buf.extend_from_slice(&[7u8; 32]); // sender pubkey
        buf.extend_from_slice(&amount.to_le_bytes());
        buf.extend_from_slice(&seal_addr);
        buf.extend_from_slice(&mint);
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.extend_from_slice(&0i64.to_le_bytes()); // timestamp
        format!(
            "Program data: {}",
            base64::engine::general_purpose::STANDARD.encode(&buf)
        )
    }

    /// v1 layout — no `mint` field. Used to pin the legacy path so
    /// nodes running ahead of an Anchor redeploy still observe locks.
    fn lock_event_log_v1(amount: u64, nonce: u64, seal_addr: [u8; 32]) -> String {
        let mut buf = Vec::with_capacity(8 + 32 + 8 + 32 + 8 + 8);
        buf.extend_from_slice(&LOCK_EVENT_DISCRIMINATOR);
        buf.extend_from_slice(&[7u8; 32]);
        buf.extend_from_slice(&amount.to_le_bytes());
        buf.extend_from_slice(&seal_addr);
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.extend_from_slice(&0i64.to_le_bytes());
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
    fn solana_routes_usdc_when_mint_matches() {
        // Pick a known mint, encode it base58, hand it to the observer
        // as `usdc_mint`, then emit a LockEvent whose `mint` field is
        // those same bytes. The deposit must land in WUSDC.
        let usdc_bytes = [9u8; 32];
        let usdc_b58 = bs58_encode(&usdc_bytes).expect("bs58 encode");
        let obs = SolanaObserver::with_transport(
            "http://x",
            "prog",
            mock_transport() as Arc<dyn HttpTransport>,
        )
        .with_usdc_mint(usdc_b58);
        let seal = [3u8; 32];
        let log = lock_event_log_with_mint(7_000_000, 1, seal, usdc_bytes);
        let deposits = obs.deposits_from_logs("sigU", "unknown", &[log]);
        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].token, WrappedToken::WUSDC);
        assert_eq!(deposits[0].amount, 7_000_000);
    }

    #[test]
    fn solana_accepts_legacy_v1_lock_event() {
        // Old Anchor program emits 96-byte events (no mint). The
        // observer must still pick those up so an operator who
        // hasn't redeployed yet doesn't lose every Solana lock.
        let obs = SolanaObserver::with_transport(
            "http://x",
            "prog",
            mock_transport() as Arc<dyn HttpTransport>,
        )
        .with_usdc_mint(bs58_encode(&[9u8; 32]).unwrap());
        let seal = [3u8; 32];
        let log = lock_event_log_v1(2_000_000, 11, seal);
        let deposits = obs.deposits_from_logs("sigV1", "unknown", &[log]);
        assert_eq!(deposits.len(), 1);
        // No mint in v1 → falls back to WSOL regardless of usdc_mint.
        assert_eq!(deposits[0].token, WrappedToken::WSOL);
        assert_eq!(deposits[0].amount, 2_000_000);
        assert_eq!(deposits[0].id, "sol_sigV1_11");
    }

    #[test]
    fn solana_falls_back_to_wsol_when_mint_unknown() {
        // Configure a USDC mint but emit an event whose mint doesn't
        // match — must fall back to WSOL.
        let obs = SolanaObserver::with_transport(
            "http://x",
            "prog",
            mock_transport() as Arc<dyn HttpTransport>,
        )
        .with_usdc_mint(bs58_encode(&[9u8; 32]).unwrap());
        let log = lock_event_log_with_mint(5_000_000, 0, [3u8; 32], [42u8; 32]);
        let deposits = obs.deposits_from_logs("sigW", "unknown", &[log]);
        assert_eq!(deposits.len(), 1);
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

    /// Build XDR bytes for a `LockInfo` contracttype struct (the event
    /// value emitted by `lock_xlm`). Fields are in alphabetical order,
    /// which is how the soroban-sdk `#[contracttype]` macro serializes
    /// them: amount, nonce, seal_address, sender, timestamp.
    fn lock_info_xdr(amount: u64, seal_addr: &[u8; 32], sender_key: &[u8; 32]) -> String {
        let mut buf: Vec<u8> = Vec::new();
        // ScVal::Map (discriminant = 17), wrapped in Option<ScMap>::Some.
        buf.extend_from_slice(&17u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes()); // Some
        buf.extend_from_slice(&5u32.to_be_bytes()); // 5 fields
                                                    // amount (i128 = SCV_I128 = 10): hi=0, lo=amount
        push_sym(&mut buf, "amount");
        buf.extend_from_slice(&10u32.to_be_bytes());
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.extend_from_slice(&amount.to_be_bytes());
        // nonce (u64 = SCV_U64 = 5)
        push_sym(&mut buf, "nonce");
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.extend_from_slice(&0u64.to_be_bytes());
        // seal_address (Bytes = SCV_BYTES = 13, 32 bytes, no padding needed)
        push_sym(&mut buf, "seal_address");
        buf.extend_from_slice(&13u32.to_be_bytes());
        buf.extend_from_slice(&32u32.to_be_bytes());
        buf.extend_from_slice(seal_addr);
        // sender (Address = SCV_ADDRESS = 18, account type, ED25519 key)
        push_sym(&mut buf, "sender");
        buf.extend_from_slice(&18u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // SC_ADDRESS_TYPE_ACCOUNT
        buf.extend_from_slice(&0u32.to_be_bytes()); // PUBLIC_KEY_TYPE_ED25519
        buf.extend_from_slice(sender_key);
        // timestamp (u64 = SCV_U64 = 5)
        push_sym(&mut buf, "timestamp");
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.extend_from_slice(&0u64.to_be_bytes());
        base64::engine::general_purpose::STANDARD.encode(&buf)
    }

    /// Push an XDR ScVal::Symbol key to `buf` (padded to 4-byte boundary).
    fn push_sym(buf: &mut Vec<u8>, s: &str) {
        buf.extend_from_slice(&15u32.to_be_bytes()); // SCV_SYMBOL = 15
        buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
        buf.extend_from_slice(s.as_bytes());
        let rem = (4 - s.len() % 4) % 4;
        buf.extend(std::iter::repeat(0u8).take(rem));
    }

    /// The base64 XDR encoding of `Symbol("lock")` (SCV_SYMBOL=15, len=4, "lock").
    const LOCK_TOPIC_B64: &str = "AAAADwAAAARsb2Nr";

    #[test]
    fn stellar_observer_creates() {
        let obs = StellarObserver::testnet("CDXYZ_CONTRACT_ID");
        assert_eq!(obs.chain(), Chain::Stellar);
        assert_eq!(obs.required_confirmations, 5);
        assert_eq!(obs.soroban_rpc_url, "https://soroban-testnet.stellar.org");
    }

    #[test]
    fn stellar_observer_derives_soroban_rpc_from_port_8000() {
        let obs = StellarObserver::with_transport(
            "http://stellar:8000",
            "c",
            mock_transport() as Arc<dyn HttpTransport>,
        );
        assert_eq!(obs.soroban_rpc_url, "http://stellar:8003");
    }

    #[test]
    fn stellar_cursor_ledger_parses_pagination_cursor() {
        // Real cursor captured from a local stellar/quickstart soroban-rpc
        // (page 1 of a getEvents drain). Pinned so the parser doesn't
        // regress; the exact decode (`n >> 32`) is what the drain loop
        // uses to detect cursor crossing latestLedger.
        let c = "0000042979737731071-4294967295";
        assert_eq!(cursor_ledger(c), Some(10006));
        // Page 2 cursor — larger, higher ledger.
        assert_eq!(cursor_ledger("0000085925115723775-4294967295"), Some(20005));
        // Edge cases: malformed, missing dash, empty.
        assert_eq!(cursor_ledger(""), None);
        assert_eq!(cursor_ledger("not-a-number"), None);
        // No dash → treat full string as the head.
        assert_eq!(cursor_ledger("4294967296"), Some(1));
    }

    #[test]
    fn stellar_extract_oldest_ledger_parses_message_and_data() {
        // stellar-rpc 25.x: range encoded in message, no `data` field.
        let r = json!({"error":{"code":-32600,"message":"startLedger must be within the ledger range: 7 - 715"}});
        assert_eq!(extract_oldest_ledger(&r), Some(7));
        // Future shape with structured data — also supported.
        let r = json!({"error":{"data":{"oldestLedger":42}}});
        assert_eq!(extract_oldest_ledger(&r), Some(42));
        // Result-shaped response: no oldest ledger to extract.
        let r = json!({"result":{"events":[]}});
        assert_eq!(extract_oldest_ledger(&r), None);
    }

    /// stellar-rpc 25.0 nightly builds occasionally returned the
    /// oldest-ledger hint as a plain string in `error.data` rather
    /// than the documented object. We tolerate "oldestLedger is N",
    /// "oldestLedger: N", and "oldestLedger=N" so an upgrade across
    /// the 25.x line doesn't take the observer down (P7#1).
    #[test]
    fn stellar_extract_oldest_ledger_handles_string_data_shape() {
        let r = json!({"error":{"data":"oldestLedger is 99"}});
        assert_eq!(extract_oldest_ledger(&r), Some(99));
        let r = json!({"error":{"data":"oldestLedger=12345"}});
        assert_eq!(extract_oldest_ledger(&r), Some(12345));
        let r = json!({"error":{"data":"oldestLedger: 7"}});
        assert_eq!(extract_oldest_ledger(&r), Some(7));
        // Unrelated string shouldn't false-match.
        let r = json!({"error":{"data":"some other error"}});
        assert_eq!(extract_oldest_ledger(&r), None);
    }

    /// `fetch_latest_ledger` calls Soroban RPC and extracts the
    /// `result.sequence` field. Used as the last-resort fallback
    /// when both the first `startLedger=2` attempt and the
    /// `oldestLedger`-hinted retry fail (P7#2).
    #[test]
    fn stellar_fetch_latest_ledger_parses_sequence() {
        let transport = mock_transport();
        transport.enqueue(
            "POST",
            "http://h:8003",
            json!({"result":{"sequence":54321,"id":"abc","protocolVersion":22}}),
        );
        let got = fetch_latest_ledger(&*transport.clone(), "http://h:8003");
        assert_eq!(got, Some(54321));
        // Error response → None.
        transport.enqueue(
            "POST",
            "http://h:8003",
            json!({"error":{"code":-32000,"message":"down"}}),
        );
        let got = fetch_latest_ledger(&*transport.clone(), "http://h:8003");
        assert_eq!(got, None);
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
    fn stellar_is_lock_symbol_correct() {
        assert!(is_lock_symbol(LOCK_TOPIC_B64), "Symbol(lock) must match");
        assert!(
            !is_lock_symbol("AAAADwAAAAd1bmxvY2s="),
            "Symbol(unlock) must not match"
        );
        assert!(!is_lock_symbol("invalid"), "garbage must not match");
    }

    /// `symbol_short!("lockusdc")` XDR base64 — pinned so a future
    /// refactor of either the contract event name OR the host parser
    /// breaks visibly. Construct by hand to avoid pulling soroban-sdk
    /// into seal-bridge just for the byte sequence.
    #[test]
    fn stellar_is_lockusdc_symbol_correct() {
        // SCV_SYMBOL(15) + len(8) + "lockusdc"
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&15u32.to_be_bytes());
        bytes.extend_from_slice(&8u32.to_be_bytes());
        bytes.extend_from_slice(b"lockusdc");
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        assert!(is_lockusdc_symbol(&b64), "Symbol(lockusdc) must match");
        // The plain XLM lock topic must NOT match.
        assert!(
            !is_lockusdc_symbol(LOCK_TOPIC_B64),
            "Symbol(lock) must not match the USDC topic"
        );
        assert!(!is_lockusdc_symbol("invalid"), "garbage must not match");
    }

    #[test]
    fn stellar_parse_lock_info_xdr_roundtrip() {
        let seal = [0xABu8; 32];
        let sender_key = [0x07u8; 32];
        let b64 = lock_info_xdr(1_000_000, &seal, &sender_key);
        let (amount, seal_hex, sender_hex) = parse_lock_info_xdr(&b64).unwrap();
        assert_eq!(amount, 1_000_000);
        assert_eq!(seal_hex, hex_encode(&seal));
        assert_eq!(sender_hex, hex_encode(&sender_key));
    }

    /// Wire-format pin: the bytes captured from a real stellar-rpc 25.x
    /// `getEvents` response for a `lock_xlm` invocation. amount=10_000_000,
    /// nonce=0, seal_address=deadbeefcafe…00, sender G-account with the
    /// ed25519 key bc35..88bb. Locks the `Option<ScMap>` Some-marker that
    /// the test helper used to miss.
    #[test]
    fn stellar_parse_lock_info_xdr_real_wire_bytes() {
        let captured = "AAAAEQAAAAEAAAAFAAAADwAAAAZhbW91bnQAAAAAAAoAAAAAAAAAAAAAAAAA\
                        mJaAAAAADwAAAAVub25jZQAAAAAAAAUAAAAAAAAAAAAAAA8AAAAMc2VhbF9h\
                        ZGRyZXNzAAAADQAAACDerb7vyv4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                        AAAAAA8AAAAGc2VuZGVyAAAAAAASAAAAAAAAAAC8NUKG1gqzNW1ZOIJdMnd9\
                        YMbTb7m4mHu8eHlPFSmIuwAAAA8AAAAJdGltZXN0YW1wAAAAAAAABQAAAABq\
                        BXOL";
        let b64: String = captured.split_whitespace().collect();
        let (amount, seal_hex, sender_hex) =
            parse_lock_info_xdr(&b64).expect("real Soroban LockInfo XDR must parse");
        assert_eq!(amount, 10_000_000);
        assert!(
            seal_hex.starts_with("deadbeefcafe"),
            "seal_address prefix mismatch: {seal_hex}"
        );
        assert_eq!(sender_hex.len(), 64, "sender ed25519 key is 32 bytes hex");
    }

    #[test]
    fn stellar_poll_events_end_to_end() {
        let transport = mock_transport();
        let obs = StellarObserver::with_transport(
            "http://horizon",
            "contractX",
            transport.clone() as Arc<dyn HttpTransport>,
        );
        // with_transport derives soroban_rpc_url as "http://horizon:8003"
        let seal = [0x11u8; 32];
        let sender_key = [0x22u8; 32];
        let value_b64 = lock_info_xdr(1_000_000, &seal, &sender_key);
        transport.enqueue(
            "POST",
            "http://horizon:8003",
            json!({
                "result": {
                    "events": [
                        {
                            "contractId": "contractX",
                            "id": "event1",
                            "topic": [LOCK_TOPIC_B64],
                            "value": value_b64,
                            "inSuccessfulContractCall": true,
                            "txHash": "tx1"
                        },
                        {
                            "contractId": "contractX",
                            "id": "event2",
                            "topic": ["AAAADwAAAAd1bmxvY2s="],  // unlock — not a lock event
                            "value": "",
                            "inSuccessfulContractCall": true,
                            "txHash": "tx2"
                        }
                    ]
                }
            }),
        );
        let (deposits, cursor) = obs.poll_events("").unwrap();
        assert_eq!(deposits.len(), 1, "only the lock event yields a deposit");
        assert_eq!(deposits[0].amount, 1_000_000);
        assert_eq!(deposits[0].seal_address, hex_encode(&seal));
        assert_eq!(deposits[0].token, WrappedToken::WXLM);
        assert_eq!(cursor, "event2", "cursor advances past non-lock events too");
    }

    #[test]
    fn stellar_poll_events_cursor_passed_to_rpc() {
        let transport = mock_transport();
        let obs = StellarObserver::with_transport(
            "http://horizon",
            "contractX",
            transport.clone() as Arc<dyn HttpTransport>,
        );
        transport.enqueue(
            "POST",
            "http://horizon:8003",
            json!({"result": {"events": []}}),
        );
        let (deposits, cursor) = obs.poll_events("abc").unwrap();
        assert!(deposits.is_empty());
        assert_eq!(cursor, "abc", "empty page keeps the old cursor");
    }

    #[test]
    fn stellar_poll_events_retries_on_oldest_ledger_error() {
        let transport = mock_transport();
        let obs = StellarObserver::with_transport(
            "http://horizon",
            "contractX",
            transport.clone() as Arc<dyn HttpTransport>,
        );
        let seal = [0x55u8; 32];
        let sender_key = [0x66u8; 32];
        let value_b64 = lock_info_xdr(500_000, &seal, &sender_key);
        // First response: startLedger=2 rejected — stellar-rpc 25.x encodes
        // the live range in the error message text (no `data` field).
        transport.enqueue(
            "POST",
            "http://horizon:8003",
            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"startLedger must be within the ledger range: 100 - 715"}}),
        );
        // Second response: retry with startLedger=100 — returns one lock event.
        transport.enqueue(
            "POST",
            "http://horizon:8003",
            json!({
                "result": {
                    "events": [{
                        "contractId": "contractX",
                        "id": "ev100",
                        "topic": [LOCK_TOPIC_B64],
                        "value": value_b64,
                        "inSuccessfulContractCall": true,
                        "txHash": "txRetry"
                    }]
                }
            }),
        );
        let (deposits, cursor) = obs.poll_events("").unwrap();
        assert_eq!(deposits.len(), 1, "retry must yield the lock event");
        assert_eq!(deposits[0].amount, 500_000);
        assert_eq!(cursor, "ev100");
    }

    #[test]
    fn stellar_poll_events_skips_other_contract() {
        let transport = mock_transport();
        let obs = StellarObserver::with_transport(
            "http://horizon",
            "contractX",
            transport.clone() as Arc<dyn HttpTransport>,
        );
        let seal = [0x33u8; 32];
        let sender_key = [0x44u8; 32];
        let value_b64 = lock_info_xdr(999, &seal, &sender_key);
        transport.enqueue(
            "POST",
            "http://horizon:8003",
            json!({
                "result": {
                    "events": [{
                        "contractId": "someOtherContract",
                        "id": "ev1",
                        "topic": [LOCK_TOPIC_B64],
                        "value": value_b64,
                        "inSuccessfulContractCall": true,
                        "txHash": "tx"
                    }]
                }
            }),
        );
        let (deposits, _) = obs.poll_events("").unwrap();
        assert!(
            deposits.is_empty(),
            "event from different contract must be ignored"
        );
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

    /// `poll_due` skips observers whose configured interval hasn't
    /// elapsed since their last poll, but always-due (`interval=0`)
    /// observers and never-polled observers fire on every call.
    /// Matches the auto-poll loop's contract: Solana at 5 s + Stellar
    /// at 30 s should fire Stellar once for every six Solana ticks.
    #[test]
    fn poll_due_respects_per_observer_interval() {
        use std::time::{Duration, Instant};
        let sol_transport = mock_transport();
        let stellar_transport = mock_transport();
        // Both observers will get pinged each "due" call.
        for _ in 0..4 {
            sol_transport.enqueue("POST", "http://s", json!({"result": []}));
        }
        for _ in 0..2 {
            stellar_transport.enqueue("POST", "http://h:8003", json!({"result": {"events": []}}));
        }
        let mut set = BridgeObserverSet::new();
        set.add_observer_with_interval(
            Box::new(SolanaObserver::with_transport(
                "http://s",
                "prog",
                sol_transport.clone() as Arc<dyn HttpTransport>,
            )),
            0, // always-due
        );
        set.add_observer_with_interval(
            Box::new(StellarObserver::with_transport(
                "http://h",
                "c",
                stellar_transport.clone() as Arc<dyn HttpTransport>,
            )),
            10, // 10 s interval
        );

        let t0 = Instant::now();
        // First poll: never-polled stellar fires + always-due solana.
        set.poll_due(t0).unwrap();
        // 1 s later: only solana (stellar last_polled was t0, interval 10 s).
        set.poll_due(t0 + Duration::from_secs(1)).unwrap();
        // 5 s later: still only solana.
        set.poll_due(t0 + Duration::from_secs(5)).unwrap();
        // 11 s later: both — stellar is due again.
        set.poll_due(t0 + Duration::from_secs(11)).unwrap();

        // Reveal: 4 solana polls, 2 stellar polls. Confirmed by the
        // enqueue counts above — if we'd called either observer more
        // times than queued responses, the mock would have returned
        // an unexpected-request error and poll_due would have failed.
        let intervals = set.poll_intervals();
        assert_eq!(intervals.len(), 2);
        let sol = intervals.iter().find(|(c, _)| *c == Chain::Solana).unwrap();
        let xlm = intervals
            .iter()
            .find(|(c, _)| *c == Chain::Stellar)
            .unwrap();
        assert_eq!(sol.1, 0);
        assert_eq!(xlm.1, 10);
    }

    #[test]
    fn bridge_observer_set_aggregates_and_advances_cursors() {
        let sol_transport = mock_transport();
        let stellar_transport = mock_transport();
        sol_transport.enqueue("POST", "http://s", json!({"result": []}));
        // StellarObserver::with_transport("http://h", ...) derives soroban_rpc_url
        // as "http://h:8003" (no ":8000" in the URL → fallback appends ":8003").
        stellar_transport.enqueue("POST", "http://h:8003", json!({"result": {"events": []}}));
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
