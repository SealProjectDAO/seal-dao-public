//! Bridge manager — tracks deposits, withdrawals, and wrapped token balances.
//!
//! INVARIANT (to be proven in TLA+):
//!   TotalMinted(token) <= TotalLocked(token)
//!   i.e., we never mint more wrapped tokens than are locked on the source chain.

use crate::error::BridgeError;
use crate::types::*;
use std::collections::HashMap;

/// Manages bridge state: deposits, withdrawals, and wrapped balances.
#[derive(Default)]
pub struct BridgeManager {
    /// Pending and processed deposits.
    deposits: HashMap<String, BridgeDeposit>,
    /// Pending and executed withdrawals.
    withdrawals: HashMap<String, BridgeWithdrawal>,
    /// Wrapped token balances per SEAL address: (address, token) -> amount.
    wrapped_balances: HashMap<(String, WrappedToken), u64>,
    /// Total locked per token (on source chains).
    total_locked: HashMap<WrappedToken, u64>,
    /// Total minted per token (on Seal).
    total_minted: HashMap<WrappedToken, u64>,
    /// Required confirmations before processing a deposit.
    pub required_confirmations: u32,
    /// Paused chains: chain -> human-readable reason. An entry in this
    /// map blocks new deposits, deposit processing, and withdrawals
    /// involving that chain until `unpause_chain` is called. Settled
    /// wrapped-balance reads are unaffected.
    paused_chains: HashMap<Chain, String>,
    /// Monotonic withdrawal counter. Combined with `seal_address` and
    /// `dest_chain` produces a globally-unique withdrawal id; assigned
    /// as `nonce` so the on-chain unlock instruction can detect
    /// replays. Persists for the life of the BridgeManager instance.
    withdrawal_counter: u64,
    /// Committee MAC key shared with the on-chain bridge programs.
    /// Both `bridges/solana/programs/seal-bridge/src/lib.rs` and
    /// `bridges/stellar/src/lib.rs` store the same 32 bytes (set via
    /// each program's `initialize`/`rotate_committee_key`); the host
    /// signs unlock payloads with HMAC-SHA-256 using this key.
    /// `None` until configured by the operator — withdrawal records
    /// land with `committee_signature_hex = None` and the on-chain
    /// claim can't proceed.
    committee_key: Option<[u8; 32]>,
    /// Ringtail singleton keypair for the PQ-signed unlock path
    /// (P1#5). When set, `initiate_withdrawal` produces a Ringtail
    /// signature instead of an HMAC. Boxed because `PublicParams`
    /// carries ~16 KB of matrix bytes; sk_collapsed_bytes is small
    /// (one polynomial = 2048 B).
    ///
    /// Operator opts in via `set_committee_ringtail_keypair`; the
    /// HMAC path remains the default so existing tests + bring-up
    /// scripts keep working untouched.
    #[cfg(feature = "ringtail-singleton")]
    committee_ringtail_keypair: Option<Box<crate::ringtail::RingtailKeypair>>,
    /// Optional outbound notification channel — fires once per
    /// successful `initiate_withdrawal` to signal that the
    /// withdrawal is ready for committee signing. Subscribed by the
    /// future P1#5 multi-validator orchestrator (see ADR-002); other
    /// signing modes (HMAC, Ringtail singleton) ignore this channel
    /// and attach signatures inline. None by default — subscribers
    /// opt in via `set_signing_signal_sender`.
    ///
    /// Flagged `cfg(feature = "ringtail-singleton")` to keep the
    /// default dep graph free of the tokio dep this would otherwise
    /// pull in. Single-signer paths don't use this channel.
    #[cfg(feature = "ringtail-singleton")]
    signing_signal_tx: Option<tokio::sync::mpsc::Sender<crate::types::WithdrawalReadyForSigning>>,
}

impl BridgeManager {
    pub fn new(required_confirmations: u32) -> Self {
        BridgeManager {
            required_confirmations,
            ..Default::default()
        }
    }

    /// Install the 32-byte committee MAC key. This MUST match the
    /// value passed to each bridge program's `initialize` (or set
    /// via `rotate_committee_key`); without it `initiate_withdrawal`
    /// records a withdrawal with `committee_signature_hex = None`
    /// and the on-chain unlock claim can't be authenticated.
    ///
    /// Rotating this key invalidates every prior un-claimed
    /// withdrawal signature — operators should drain pending claims
    /// before rotating.
    pub fn set_committee_key(&mut self, key: [u8; 32]) {
        self.committee_key = Some(key);
    }

    /// Whether `set_committee_key` has been called.
    pub fn has_committee_key(&self) -> bool {
        self.committee_key.is_some()
    }

    /// Install a Ringtail singleton keypair (P1#5). When set, every
    /// new withdrawal's `committee_signature_hex` is the hex of a
    /// 2088-byte Ringtail singleton signature (vs the 64-char HMAC
    /// from the default path).
    ///
    /// Mutually exclusive with `set_committee_key` in practice — if
    /// both are set, Ringtail wins. Operators flip from HMAC →
    /// Ringtail by installing the keypair AND deploying bridge
    /// programs with the `ringtail-verify` feature on.
    #[cfg(feature = "ringtail-singleton")]
    pub fn set_committee_ringtail_keypair(&mut self, keypair: crate::ringtail::RingtailKeypair) {
        self.committee_ringtail_keypair = Some(Box::new(keypair));
    }

    /// Whether a Ringtail keypair is installed. `false` until the
    /// operator opts into the PQ-signed unlock path.
    #[cfg(feature = "ringtail-singleton")]
    pub fn has_ringtail_keypair(&self) -> bool {
        self.committee_ringtail_keypair.is_some()
    }

    /// Subscribe to "withdrawal ready for signing" notifications
    /// (P1#5 layer 4 trigger). The future multi-validator orchestrator
    /// (see ADR-002) holds the receiver and calls `start_signing`
    /// whenever a message lands.
    ///
    /// Single-signer paths (HMAC default, Ringtail singleton) do NOT
    /// need this — they attach signatures inline inside
    /// `initiate_withdrawal`. Calling `set_signing_signal_sender`
    /// alongside those modes is harmless but wasteful (the channel
    /// fires per withdrawal but no consumer reads it).
    #[cfg(feature = "ringtail-singleton")]
    pub fn set_signing_signal_sender(
        &mut self,
        tx: tokio::sync::mpsc::Sender<crate::types::WithdrawalReadyForSigning>,
    ) {
        self.signing_signal_tx = Some(tx);
    }

    /// Whether a signing-signal subscriber is registered. Used by
    /// /metrics to gauge orchestrator wire-up.
    #[cfg(feature = "ringtail-singleton")]
    pub fn has_signing_signal_subscriber(&self) -> bool {
        self.signing_signal_tx.is_some()
    }

    /// SHA3-256 fingerprint over the installed committee key, or
    /// `None` when no key is set. SHA3 is the host's PQ-native default.
    /// The raw key itself is intentionally never exposed by RPC.
    pub fn committee_key_fingerprint(&self) -> Option<[u8; 32]> {
        self.committee_key
            .as_ref()
            .map(|k| seal_crypto::hash::sha3_256(k).0)
    }

    /// Constant-time check: does `candidate` match the in-memory
    /// committee key? Returns `false` if no key is installed.
    /// Used by the persistence-detection metric to compare the
    /// on-disk file's contents against the in-memory state without
    /// leaking byte-by-byte timing.
    pub fn committee_key_eq(&self, candidate: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        match &self.committee_key {
            Some(k) => k.ct_eq(candidate).into(),
            None => false,
        }
    }

    /// SHA2-256 fingerprint over the installed committee key, or
    /// `None` when no key is set. Operators use this for cross-chain
    /// drift detection: Solana's `sol_sha256` syscall and Stellar's
    /// `env.crypto().sha256()` are SHA2-256, so a `committee_key_hash`
    /// view added on-chain returns the same bytes. The raw key itself
    /// is intentionally never exposed by RPC.
    pub fn committee_key_fingerprint_sha256(&self) -> Option<[u8; 32]> {
        use sha2::{Digest, Sha256};
        self.committee_key.as_ref().map(|k| {
            let mut h = Sha256::new();
            h.update(k);
            let out = h.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&out);
            arr
        })
    }

    /// Record a new deposit observed on a source chain.
    pub fn observe_deposit(&mut self, deposit: BridgeDeposit) -> Result<(), BridgeError> {
        self.ensure_chain_active(&deposit.source_chain)?;
        if self.deposits.contains_key(&deposit.id) {
            return Err(BridgeError::DepositAlreadyProcessed(deposit.id));
        }
        self.deposits.insert(deposit.id.clone(), deposit);
        Ok(())
    }

    /// Add a validator confirmation to a deposit.
    pub fn confirm_deposit(&mut self, deposit_id: &str) -> Result<u32, BridgeError> {
        let deposit = self
            .deposits
            .get_mut(deposit_id)
            .ok_or_else(|| BridgeError::DepositNotFound(deposit_id.into()))?;
        if deposit.processed {
            return Err(BridgeError::DepositAlreadyProcessed(deposit_id.into()));
        }
        deposit.confirmations += 1;
        Ok(deposit.confirmations)
    }

    /// Process a confirmed deposit: mint wrapped tokens on Seal.
    /// Only succeeds if confirmations >= required_confirmations.
    pub fn process_deposit(&mut self, deposit_id: &str) -> Result<u64, BridgeError> {
        let deposit = self
            .deposits
            .get(deposit_id)
            .ok_or_else(|| BridgeError::DepositNotFound(deposit_id.into()))?;

        self.ensure_chain_active(&deposit.source_chain)?;

        if deposit.processed {
            return Err(BridgeError::DepositAlreadyProcessed(deposit_id.into()));
        }
        if deposit.confirmations < self.required_confirmations {
            return Err(BridgeError::WithdrawalNotConfirmed);
        }

        let amount = deposit.amount;
        let token = deposit.token.clone();
        let seal_addr = deposit.seal_address.clone();

        // Update locked total
        *self.total_locked.entry(token.clone()).or_insert(0) += amount;

        // Mint wrapped tokens
        *self.total_minted.entry(token.clone()).or_insert(0) += amount;
        *self.wrapped_balances.entry((seal_addr, token)).or_insert(0) += amount;

        // Mark as processed
        self.deposits
            .get_mut(deposit_id)
            .ok_or_else(|| BridgeError::DepositNotFound(deposit_id.into()))?
            .processed = true;

        Ok(amount)
    }

    /// Initiate a withdrawal: burn wrapped tokens, create withdrawal record.
    pub fn initiate_withdrawal(
        &mut self,
        seal_address: &str,
        dest_chain: Chain,
        dest_address: &str,
        token: WrappedToken,
        amount: u64,
    ) -> Result<String, BridgeError> {
        self.ensure_chain_active(&dest_chain)?;
        // Format-validate the destination address up front. Without this,
        // a malformed dest_address (typo, ellipsis placeholder, address
        // for the wrong chain) would burn the caller's wrapped tokens
        // and produce an unprocessable withdrawal record. See
        // `validate_dest_address` for the per-chain shape rules.
        validate_dest_address(&dest_chain, dest_address)
            .map_err(BridgeError::InvalidDestAddress)?;
        // Check wrapped balance
        let balance = self
            .wrapped_balances
            .get(&(seal_address.to_string(), token.clone()))
            .copied()
            .unwrap_or(0);
        if balance < amount {
            return Err(BridgeError::InsufficientWrapped {
                need: amount,
                have: balance,
            });
        }

        // Burn wrapped tokens
        *self
            .wrapped_balances
            .get_mut(&(seal_address.to_string(), token.clone()))
            .ok_or(BridgeError::InsufficientWrapped {
                need: amount,
                have: 0,
            })? -= amount;
        *self
            .total_minted
            .get_mut(&token)
            .ok_or(BridgeError::MintExceedsLocked)? -= amount;

        // Assign monotonic nonce + globally-unique id. Old code used
        // `wd_{seal_address}_{amount}` which collides on the second
        // withdrawal-of-equal-amount from the same caller.
        let nonce = self.withdrawal_counter;
        self.withdrawal_counter = self
            .withdrawal_counter
            .checked_add(1)
            .ok_or(BridgeError::MintExceedsLocked)?;
        let id = format!("wd_{}_{}", chain_tag(&dest_chain), nonce);

        // Sign the on-chain unlock claim. Three states, picked in
        // priority order:
        //   1. Ringtail singleton keypair installed → 2088-byte
        //      lattice signature (P1#5 PQ-signed path). Hex-encoded
        //      to fit the same field as the HMAC.
        //   2. HMAC committee key installed → 32-byte symmetric MAC
        //      (committee-of-1 default).
        //   3. Neither installed → withdrawal lands with `None` and
        //      the operator must drive signing out-of-band.
        let committee_signature_hex =
            self.compute_committee_signature(&dest_chain, dest_address, amount, nonce);

        let withdrawal = BridgeWithdrawal {
            id: id.clone(),
            nonce,
            dest_chain: dest_chain.clone(),
            dest_address: dest_address.to_string(),
            seal_address: seal_address.to_string(),
            amount,
            token,
            committee_signature_hex,
            executed: false,
        };
        self.withdrawals.insert(id.clone(), withdrawal);

        // Notify any signing-signal subscriber (multi-validator
        // Ringtail orchestrator). try_send avoids blocking the burn
        // path on a slow consumer; the channel buffer is 256 so
        // saturation only happens under genuine orchestrator
        // failure, in which case dropping is fine — the orchestrator
        // can re-poll BridgeManager for any withdrawal it missed.
        #[cfg(feature = "ringtail-singleton")]
        if let Some(tx) = &self.signing_signal_tx {
            let signal = crate::types::WithdrawalReadyForSigning {
                withdrawal_id: id.clone(),
                dest_chain,
                dest_address: dest_address.to_string(),
                amount,
                nonce,
            };
            // Best-effort: log + continue on failure.
            if let Err(e) = tx.try_send(signal) {
                eprintln!("[seal-bridge] signing-signal channel send failed for {id}: {e}");
            }
        }

        Ok(id)
    }

    /// Pick the right signing primitive based on what the operator
    /// has installed. Ringtail wins over HMAC; neither installed →
    /// `None`. Hex-encodes the result so the wire format
    /// (`committee_signature_hex`) carries either flavour.
    fn compute_committee_signature(
        &self,
        dest_chain: &Chain,
        dest_address: &str,
        amount: u64,
        nonce: u64,
    ) -> Option<String> {
        #[cfg(feature = "ringtail-singleton")]
        {
            if let Some(kp) = self.committee_ringtail_keypair.as_ref() {
                match crate::ringtail::compute_committee_ringtail_sig(
                    dest_chain,
                    &kp.public_params,
                    &kp.sk_collapsed_bytes,
                    dest_address,
                    amount,
                    nonce,
                ) {
                    Ok(bytes) => return Some(hex::encode(bytes)),
                    Err(e) => {
                        // Don't fall back to HMAC silently — that would
                        // produce a signature the on-chain ringtail-
                        // verify branch would reject. Surface the
                        // failure as `None` so the operator notices in
                        // the withdrawal record. eprintln rather than
                        // tracing so the bridge crate doesn't acquire a
                        // log-framework dep just for one warn line.
                        eprintln!(
                            "[seal-bridge] ringtail singleton sign failed: {} \
                             — withdrawal lands without signature",
                            e
                        );
                        return None;
                    }
                }
            }
        }
        self.committee_key
            .as_ref()
            .map(|k| compute_committee_mac(dest_chain, k, dest_address, amount, nonce))
    }

    /// Attach a committee MAC to an existing withdrawal. Called when
    /// the Ringtail signing pipeline produces an aggregate after the
    /// fact (multi-validator path). Idempotent — overwrites any prior
    /// signature on the same withdrawal_id so a re-signed withdrawal
    /// can replace one that was signed with a now-stale committee
    /// key.
    pub fn attach_committee_signature(
        &mut self,
        withdrawal_id: &str,
        signature_hex: String,
    ) -> Result<(), BridgeError> {
        let w = self
            .withdrawals
            .get_mut(withdrawal_id)
            .ok_or_else(|| BridgeError::DepositNotFound(withdrawal_id.into()))?;
        w.committee_signature_hex = Some(signature_hex);
        Ok(())
    }

    /// Read a single withdrawal record by id.
    pub fn get_withdrawal(&self, withdrawal_id: &str) -> Option<&BridgeWithdrawal> {
        self.withdrawals.get(withdrawal_id)
    }

    /// Mark a withdrawal as executed on the destination chain.
    ///
    /// **Idempotent.** Multiple per-validator relayers (P1#3 custody
    /// model) may race to call this after submitting the on-chain
    /// `unlock_tokens` / `unlock_xlm` claim. The first call flips
    /// `executed = true` and decrements `total_locked`; subsequent
    /// calls return `Ok(())` without touching counters so the
    /// destination-chain `AlreadyClaimed` response surfaces as a
    /// success-ish no-op all the way up the stack.
    pub fn execute_withdrawal(&mut self, withdrawal_id: &str) -> Result<(), BridgeError> {
        let withdrawal = self
            .withdrawals
            .get_mut(withdrawal_id)
            .ok_or_else(|| BridgeError::DepositNotFound(withdrawal_id.into()))?;

        if withdrawal.executed {
            return Ok(());
        }

        let token = withdrawal.token.clone();
        let amount = withdrawal.amount;
        withdrawal.executed = true;
        *self
            .total_locked
            .get_mut(&token)
            .ok_or(BridgeError::MintExceedsLocked)? -= amount;
        Ok(())
    }

    /// Get wrapped token balance for an address.
    pub fn wrapped_balance(&self, address: &str, token: &WrappedToken) -> u64 {
        self.wrapped_balances
            .get(&(address.to_string(), token.clone()))
            .copied()
            .unwrap_or(0)
    }

    /// Total locked on source chains for a token.
    pub fn total_locked(&self, token: &WrappedToken) -> u64 {
        self.total_locked.get(token).copied().unwrap_or(0)
    }

    /// Total minted on Seal for a token.
    pub fn total_minted(&self, token: &WrappedToken) -> u64 {
        self.total_minted.get(token).copied().unwrap_or(0)
    }

    /// INVARIANT CHECK: minted <= locked for all tokens.
    /// This is the core bridge safety property.
    pub fn check_invariant(&self) -> bool {
        for token in [WrappedToken::WSOL, WrappedToken::WXLM, WrappedToken::WUSDC] {
            if self.total_minted(&token) > self.total_locked(&token) {
                return false;
            }
        }
        true
    }

    /// List all observed deposits, optionally filtered by source
    /// chain. Sorted by deposit ID for deterministic output across
    /// repeat calls — useful for testnet polling where the caller
    /// (e.g. `bridge-e2e.sh`) compares snapshots.
    pub fn list_deposits(&self, chain: Option<&Chain>) -> Vec<BridgeDeposit> {
        let mut out: Vec<BridgeDeposit> = self
            .deposits
            .values()
            .filter(|d| chain.map_or(true, |c| &d.source_chain == c))
            .cloned()
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Snapshot of every observed deposit whose `seal_address`
    /// (the recipient on Seal) matches the supplied address.
    /// Sorted by deposit ID — same diff-stable order as
    /// `list_deposits`. Empty Vec for recipients with no
    /// deposits. Backs `seal_listBridgeDepositsByRecipient`. Per-
    /// owner gap-closer paralleling
    /// `seal_listBridgeWrappedBalances`: a wallet asking "what
    /// crossed the bridge to me?" used to pull the global deposit
    /// stream and filter client-side.
    pub fn list_deposits_by_recipient(&self, seal_address: &str) -> Vec<BridgeDeposit> {
        let mut out: Vec<BridgeDeposit> = self
            .deposits
            .values()
            .filter(|d| d.seal_address == seal_address)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// List all withdrawals (executed or pending), sorted by ID.
    pub fn list_withdrawals(&self) -> Vec<BridgeWithdrawal> {
        let mut out: Vec<BridgeWithdrawal> = self.withdrawals.values().cloned().collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Snapshot of every withdrawal whose `seal_address` (the burner
    /// on Seal) matches the supplied address. Sorted by withdrawal
    /// ID — same diff-stable order as `list_withdrawals`. Empty Vec
    /// for initiators with no withdrawals. Backs
    /// `seal_listBridgeWithdrawalsByInitiator`. Per-owner gap-closer
    /// paralleling `list_deposits_by_recipient`: a wallet asking
    /// "what did I send out via the bridge?" used to pull the global
    /// withdrawal stream and filter client-side.
    pub fn list_withdrawals_by_initiator(&self, seal_address: &str) -> Vec<BridgeWithdrawal> {
        let mut out: Vec<BridgeWithdrawal> = self
            .withdrawals
            .values()
            .filter(|w| w.seal_address == seal_address)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    // ─── Emergency pause (Technical Council 2/3 vote) ────────────

    /// Pause a bridge chain: block new deposits, deposit processing,
    /// and withdrawals involving this chain. Council authorization is
    /// enforced by the caller (RPC layer) — this method is the state
    /// mutation only. Calling `pause_chain` on an already-paused
    /// chain updates the reason.
    pub fn pause_chain(&mut self, chain: Chain, reason: String) {
        self.paused_chains.insert(chain, reason);
    }

    /// Unpause a previously-paused chain. Returns an error if the
    /// chain was not paused.
    pub fn unpause_chain(&mut self, chain: &Chain) -> Result<(), BridgeError> {
        if self.paused_chains.remove(chain).is_none() {
            return Err(BridgeError::ChainNotPaused(chain.to_string()));
        }
        Ok(())
    }

    /// Is the chain currently paused?
    pub fn is_chain_paused(&self, chain: &Chain) -> bool {
        self.paused_chains.contains_key(chain)
    }

    /// Human-readable pause reason, if paused.
    pub fn pause_reason(&self, chain: &Chain) -> Option<&str> {
        self.paused_chains.get(chain).map(String::as_str)
    }

    /// Cheap len-based counts for Prometheus exposition — avoids
    /// allocating + sorting the full `list_*` Vec for every scrape.
    pub fn deposit_count(&self) -> usize {
        self.deposits.len()
    }
    pub fn pending_deposit_count(&self) -> usize {
        self.deposits.values().filter(|d| !d.processed).count()
    }
    pub fn withdrawal_count(&self) -> usize {
        self.withdrawals.len()
    }
    pub fn paused_chain_count(&self) -> usize {
        self.paused_chains.len()
    }

    /// Sorted list of `(chain, reason)` pairs for every paused chain.
    /// Deterministic so RPC callers (dashboards, status pages) can
    /// compare snapshots across repeat calls.
    pub fn list_paused_chains(&self) -> Vec<(Chain, String)> {
        let mut out: Vec<(Chain, String)> = self
            .paused_chains
            .iter()
            .map(|(c, r)| (c.clone(), r.clone()))
            .collect();
        out.sort_by(|a, b| a.0.to_string().cmp(&b.0.to_string()));
        out
    }

    fn ensure_chain_active(&self, chain: &Chain) -> Result<(), BridgeError> {
        if let Some(reason) = self.paused_chains.get(chain) {
            return Err(BridgeError::ChainPaused {
                chain: chain.to_string(),
                reason: reason.clone(),
            });
        }
        Ok(())
    }
}

/// Domain tag baked into the Solana bridge program; must match
/// `BRIDGE_DOMAIN_TAG` in `bridges/solana/programs/seal-bridge/src/lib.rs`.
pub(crate) const BRIDGE_DOMAIN_TAG_SOLANA: &[u8] = b"seal-bridge-solana-v1";

/// Domain tag baked into the Stellar bridge contract; must match
/// `BRIDGE_DOMAIN_TAG` in `bridges/stellar/src/lib.rs`. Distinct from
/// the Solana tag so a signature for one chain can't be replayed on
/// the other.
pub(crate) const BRIDGE_DOMAIN_TAG_STELLAR: &[u8] = b"seal-bridge-stellar-v1";

/// Short chain identifier used in withdrawal IDs.
fn chain_tag(chain: &Chain) -> &'static str {
    match chain {
        Chain::Solana => "sol",
        Chain::Stellar => "xlm",
    }
}

/// Decode a Solana destination address (base58 ed25519 pubkey) into
/// the 32-byte form the on-chain unlock instruction hashes. Used by
/// the committee-MAC computation; for ill-formed addresses falls
/// back to a SHA3-truncated digest of the raw bytes so the
/// withdrawal still records a deterministic (but unhelpful) MAC —
/// `validate_dest_address` already rejected malformed inputs up
/// front, this is purely defense in depth.
pub(crate) fn solana_recipient_bytes(dest_address: &str) -> [u8; 32] {
    // bs58 0.4 is in vendor/ but seal-bridge doesn't depend on it
    // directly; this minimal decode is enough for the test/fuzz
    // shapes a base58-validated address can take (32 raw bytes).
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut num: Vec<u8> = vec![0];
    for c in dest_address.as_bytes() {
        let Some(digit) = alphabet.iter().position(|&a| a == *c) else {
            // Malformed character — return SHA3 fallback (still
            // deterministic; just won't authenticate against the
            // on-chain key). validate_dest_address rejects this
            // before we get here.
            return seal_crypto::hash::sha3_256(dest_address.as_bytes()).0;
        };
        let mut carry = digit;
        for byte in num.iter_mut() {
            carry += (*byte as usize) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Leading '1' chars encode leading zero bytes.
    let leading_zeros = dest_address.bytes().take_while(|b| *b == b'1').count();
    let mut bytes = vec![0u8; leading_zeros];
    bytes.extend(num.iter().rev().skip_while(|b| **b == 0));
    if bytes.is_empty() {
        bytes.push(0);
    }
    // Pad / truncate to 32. Real Solana pubkeys decode to exactly 32;
    // anything else is rejected upstream.
    let mut out = [0u8; 32];
    if bytes.len() <= 32 {
        let start = 32 - bytes.len();
        out[start..].copy_from_slice(&bytes);
    } else {
        out.copy_from_slice(&bytes[bytes.len() - 32..]);
    }
    out
}

/// Decode a Stellar StrKey address (`G…` for ed25519 account,
/// `C…` for contract) into its 32-byte payload + version byte.
/// Returns `None` for malformed inputs (wrong length, bad base32,
/// unknown version, CRC mismatch). The version byte tells the
/// caller which `ScAddressType` discriminant to emit.
fn stellar_strkey_decode(addr: &str) -> Option<(u8, [u8; 32])> {
    // StrKey format per SEP-23:
    //   - 56 base32 chars (no padding)
    //   - decodes to 35 bytes: 1 version + 32 payload + 2 CRC16-XMODEM
    if addr.len() != 56 {
        return None;
    }
    let decoded = data_encoding::BASE32_NOPAD.decode(addr.as_bytes()).ok()?;
    if decoded.len() != 35 {
        return None;
    }
    let version = decoded[0];
    let mut payload = [0u8; 32];
    payload.copy_from_slice(&decoded[1..33]);
    let supplied_crc = u16::from_le_bytes([decoded[33], decoded[34]]);
    let expected_crc = crc16_xmodem(&decoded[..33]);
    if supplied_crc != expected_crc {
        return None;
    }
    Some((version, payload))
}

/// CRC16-XMODEM (polynomial 0x1021, initial value 0) — the checksum
/// algorithm StrKey uses. Inlined to avoid pulling another crate;
/// the loop is tiny and covered by `strkey_decode_round_trip` below.
fn crc16_xmodem(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in bytes {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Build the XDR serialization of `ScVal::Address(ScAddress::…)` that
/// `Soroban-sdk`'s `Address::to_xdr(env)` produces. The on-chain
/// `verify_proof` HMACs over exactly these bytes plus the trailing
/// amount/nonce/domain.
///
/// XDR layout (all 4-byte aligned, big-endian discriminants):
///   - SCV_ADDRESS = 18 (4 bytes)
///   - ScAddressType (4 bytes): 0 for account, 1 for contract
///   - Account: PUBLIC_KEY_TYPE_ED25519 = 0 (4 bytes) + 32 ed25519 bytes
///   - Contract: 32 hash bytes (no inner discriminant)
pub(crate) fn stellar_address_to_xdr(addr: &str) -> Option<Vec<u8>> {
    const STRKEY_VERSION_ACCOUNT_G: u8 = 6 << 3; // 0x30 — base32 char 'G'
    const STRKEY_VERSION_CONTRACT_C: u8 = 2 << 3; // 0x10 — base32 char 'C'

    let (version, payload) = stellar_strkey_decode(addr)?;
    let mut out = Vec::with_capacity(48);
    // SCV_ADDRESS discriminant
    out.extend_from_slice(&18u32.to_be_bytes());
    match version {
        STRKEY_VERSION_ACCOUNT_G => {
            // SC_ADDRESS_TYPE_ACCOUNT = 0
            out.extend_from_slice(&0u32.to_be_bytes());
            // PUBLIC_KEY_TYPE_ED25519 = 0
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&payload);
        }
        STRKEY_VERSION_CONTRACT_C => {
            // SC_ADDRESS_TYPE_CONTRACT = 1
            out.extend_from_slice(&1u32.to_be_bytes());
            out.extend_from_slice(&payload);
        }
        _ => return None,
    }
    Some(out)
}

/// Compute the committee MAC the on-chain unlock instruction expects.
///
/// Solana: `HMAC-SHA-256(committee_key, recipient(32) || amount_le(8)
/// || nonce_le(8) || "seal-bridge-solana-v1")`.
///
/// Stellar: `HMAC-SHA-256(committee_key, recipient_xdr || amount_be_16
/// || nonce_be_8 || "seal-bridge-stellar-v1")`. The Stellar XDR address
/// serialization isn't implemented host-side yet — for Stellar
/// withdrawals the returned hex is currently a marker `(stellar-xdr-todo)`
/// so the RPC surface stays uniform while the encoding bring-up lands.
fn compute_committee_mac(
    chain: &Chain,
    committee_key: &[u8; 32],
    dest_address: &str,
    amount: u64,
    nonce: u64,
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    match chain {
        Chain::Solana => {
            let recipient = solana_recipient_bytes(dest_address);
            let mut mac = HmacSha256::new_from_slice(committee_key)
                .expect("HMAC-SHA-256 accepts any byte length key");
            mac.update(&recipient);
            mac.update(&amount.to_le_bytes());
            mac.update(&nonce.to_le_bytes());
            mac.update(BRIDGE_DOMAIN_TAG_SOLANA);
            hex::encode(mac.finalize().into_bytes())
        }
        Chain::Stellar => {
            // The Stellar program HMACs over the XDR serialization of
            // an `ScVal::Address(...)`. Reconstruct that off-chain:
            //   - decode the G… / C… StrKey to its 32-byte payload
            //   - prefix with SCV_ADDRESS (= 18) + ScAddressType
            //     discriminant (0 = account / 1 = contract) + (for
            //     accounts) PublicKey discriminant (0 = ed25519).
            // Then the contract layout is `recipient_xdr || amount_be_16
            // || nonce_be_8 || domain_tag`.
            let Some(recipient_xdr) = stellar_address_to_xdr(dest_address) else {
                // validate_dest_address would have already rejected this,
                // so this branch is defense-in-depth.
                return format!("stellar-decode-failed:{nonce:016x}");
            };
            let mut mac = HmacSha256::new_from_slice(committee_key)
                .expect("HMAC-SHA-256 accepts any byte length key");
            mac.update(&recipient_xdr);
            // i128 big-endian, 16 bytes — Stellar amounts are i128 on
            // the contract side. We hold u64 host-side; widen with
            // leading zeros so the BE bytes match.
            let amount_be_16 = {
                let mut b = [0u8; 16];
                b[8..].copy_from_slice(&amount.to_be_bytes());
                b
            };
            mac.update(&amount_be_16);
            mac.update(&nonce.to_be_bytes());
            mac.update(BRIDGE_DOMAIN_TAG_STELLAR);
            hex::encode(mac.finalize().into_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Format-valid synthetic destination addresses for withdrawal
    // tests. The Solana value is the System Program (32 chars, all
    // base58); the Stellar values are 56-char strkeys with 'G'/'C'
    // prefix and base32 alphabet. Real bs58/strkey checksum
    // validation is a follow-up — see `validate_dest_address`.
    const SOL_ADDR_A: &str = "11111111111111111111111111111111";
    const SOL_ADDR_B: &str = "So11111111111111111111111111111111111111112";
    const STELLAR_ADDR_A: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    #[allow(dead_code)]
    const STELLAR_ADDR_B: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn make_deposit(id: &str, amount: u64) -> BridgeDeposit {
        BridgeDeposit {
            id: id.to_string(),
            source_chain: Chain::Solana,
            source_tx_hash: format!("tx_{}", id),
            source_address: "sol_addr_1".into(),
            seal_address: "seal1alice".into(),
            amount,
            token: WrappedToken::WSOL,
            processed: false,
            confirmations: 0,
        }
    }

    #[test]
    fn test_deposit_confirm_process() {
        let mut bridge = BridgeManager::new(3);
        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();

        // Confirm 3 times
        assert_eq!(bridge.confirm_deposit("d1").unwrap(), 1);
        assert_eq!(bridge.confirm_deposit("d1").unwrap(), 2);
        assert_eq!(bridge.confirm_deposit("d1").unwrap(), 3);

        // Process
        let minted = bridge.process_deposit("d1").unwrap();
        assert_eq!(minted, 1000);
        assert_eq!(
            bridge.wrapped_balance("seal1alice", &WrappedToken::WSOL),
            1000
        );
        assert!(bridge.check_invariant());
    }

    #[test]
    fn test_process_before_confirmed_fails() {
        let mut bridge = BridgeManager::new(3);
        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();
        bridge.confirm_deposit("d1").unwrap(); // Only 1 of 3
        assert!(bridge.process_deposit("d1").is_err());
    }

    #[test]
    fn test_duplicate_deposit_rejected() {
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();
        assert!(bridge.observe_deposit(make_deposit("d1", 2000)).is_err());
    }

    #[test]
    fn test_withdrawal() {
        let mut bridge = BridgeManager::new(1);

        // Deposit first
        bridge.observe_deposit(make_deposit("d1", 5000)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        // Withdraw
        let wd_id = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                2000,
            )
            .unwrap();

        assert_eq!(
            bridge.wrapped_balance("seal1alice", &WrappedToken::WSOL),
            3000
        );
        assert!(bridge.check_invariant()); // minted=3000, locked=5000 → OK

        // Execute on source chain
        bridge.execute_withdrawal(&wd_id).unwrap();
        assert_eq!(bridge.total_locked(&WrappedToken::WSOL), 3000); // 5000 - 2000
        assert!(bridge.check_invariant());
    }

    #[cfg(feature = "ringtail-singleton")]
    #[tokio::test]
    async fn signing_signal_fires_once_per_withdrawal() {
        // ADR-002 trigger surface: every initiate_withdrawal must
        // emit one WithdrawalReadyForSigning to the subscribed
        // channel. Verifies the orchestrator can drive
        // start_signing without polling BridgeManager.
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 5000)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::types::WithdrawalReadyForSigning>(8);
        bridge.set_signing_signal_sender(tx);
        assert!(bridge.has_signing_signal_subscriber());

        let wd_id = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                1000,
            )
            .unwrap();

        let signal = rx.recv().await.expect("signal must arrive");
        assert_eq!(signal.withdrawal_id, wd_id);
        assert_eq!(signal.dest_chain, Chain::Solana);
        assert_eq!(signal.dest_address, SOL_ADDR_A);
        assert_eq!(signal.amount, 1000);

        // Without a subscriber, initiate_withdrawal stays purely sync
        // and lossless (existing tests cover this — no need to
        // re-test here).
    }

    #[test]
    fn execute_withdrawal_is_idempotent() {
        // Per-validator relayer model (P1#3): every validator may
        // race to submit `unlock_tokens` / `unlock_xlm` and follow up
        // with seal_bridgeMarkExecuted. Without idempotency the
        // second relayer would double-decrement total_locked and
        // crash the invariant.
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 5000)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();
        let wd_id = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                2000,
            )
            .unwrap();

        // First mark-executed: flip + decrement.
        bridge.execute_withdrawal(&wd_id).unwrap();
        assert_eq!(bridge.total_locked(&WrappedToken::WSOL), 3000);
        assert!(bridge.get_withdrawal(&wd_id).unwrap().executed);

        // Second mark-executed: must not double-decrement.
        bridge.execute_withdrawal(&wd_id).unwrap();
        assert_eq!(
            bridge.total_locked(&WrappedToken::WSOL),
            3000,
            "second execute_withdrawal must be a no-op"
        );
        assert!(bridge.check_invariant());

        // Third call too — racing relayer fleet pattern.
        bridge.execute_withdrawal(&wd_id).unwrap();
        bridge.execute_withdrawal(&wd_id).unwrap();
        assert_eq!(bridge.total_locked(&WrappedToken::WSOL), 3000);
    }

    #[test]
    fn test_withdrawal_insufficient_balance() {
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 100)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        assert!(matches!(
            bridge.initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                200
            ),
            Err(BridgeError::InsufficientWrapped {
                need: 200,
                have: 100
            })
        ));
    }

    #[test]
    fn test_invariant_holds_through_operations() {
        let mut bridge = BridgeManager::new(1);

        // Multiple deposits
        for i in 0..5 {
            let mut dep = make_deposit(&format!("d{}", i), 1000);
            dep.seal_address = format!("seal1user{}", i % 2);
            bridge.observe_deposit(dep).unwrap();
            bridge.confirm_deposit(&format!("d{}", i)).unwrap();
            bridge.process_deposit(&format!("d{}", i)).unwrap();
            assert!(
                bridge.check_invariant(),
                "invariant failed after deposit {}",
                i
            );
        }

        // Partial withdrawals
        bridge
            .initiate_withdrawal(
                "seal1user0",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                500,
            )
            .unwrap();
        assert!(bridge.check_invariant());

        bridge
            .initiate_withdrawal(
                "seal1user1",
                Chain::Solana,
                SOL_ADDR_B,
                WrappedToken::WSOL,
                1000,
            )
            .unwrap();
        assert!(bridge.check_invariant());

        // Total: minted = 5000 - 500 - 1000 = 3500, locked = 5000 → OK
        assert_eq!(bridge.total_minted(&WrappedToken::WSOL), 3500);
        assert_eq!(bridge.total_locked(&WrappedToken::WSOL), 5000);
    }

    #[test]
    fn test_stellar_bridge() {
        let mut bridge = BridgeManager::new(1);
        let dep = BridgeDeposit {
            id: "xlm_d1".into(),
            source_chain: Chain::Stellar,
            source_tx_hash: "stellar_tx_1".into(),
            source_address: "G_stellar_addr".into(),
            seal_address: "seal1bob".into(),
            amount: 2000,
            token: WrappedToken::WXLM,
            processed: false,
            confirmations: 0,
        };
        bridge.observe_deposit(dep).unwrap();
        bridge.confirm_deposit("xlm_d1").unwrap();
        bridge.process_deposit("xlm_d1").unwrap();

        assert_eq!(
            bridge.wrapped_balance("seal1bob", &WrappedToken::WXLM),
            2000
        );
        assert!(bridge.check_invariant());
    }

    #[test]
    fn test_list_deposits_sorted_and_filtered() {
        let mut bridge = BridgeManager::new(1);
        // Insert in reverse-sort order so we exercise list_deposits'
        // sort contract.
        bridge
            .observe_deposit(make_deposit("sol_zzz", 100))
            .unwrap();
        bridge
            .observe_deposit(make_deposit("sol_aaa", 200))
            .unwrap();
        let mut xlm_dep = make_deposit("xlm_mid", 300);
        xlm_dep.source_chain = Chain::Stellar;
        xlm_dep.token = WrappedToken::WXLM;
        bridge.observe_deposit(xlm_dep).unwrap();

        let all = bridge.list_deposits(None);
        assert_eq!(all.len(), 3);
        // Sorted by ID ascending.
        assert_eq!(all[0].id, "sol_aaa");
        assert_eq!(all[1].id, "sol_zzz");
        assert_eq!(all[2].id, "xlm_mid");

        let sol_only = bridge.list_deposits(Some(&Chain::Solana));
        assert_eq!(sol_only.len(), 2);
        assert!(sol_only.iter().all(|d| d.source_chain == Chain::Solana));

        let xlm_only = bridge.list_deposits(Some(&Chain::Stellar));
        assert_eq!(xlm_only.len(), 1);
        assert_eq!(xlm_only[0].id, "xlm_mid");
    }

    #[test]
    fn test_pause_blocks_new_deposits() {
        let mut bridge = BridgeManager::new(1);
        bridge.pause_chain(Chain::Solana, "suspicious activity".into());
        let err = bridge.observe_deposit(make_deposit("d1", 100)).unwrap_err();
        assert!(matches!(err, BridgeError::ChainPaused { .. }));
        assert_eq!(
            bridge.pause_reason(&Chain::Solana),
            Some("suspicious activity")
        );
        // Stellar is unaffected.
        let mut xlm = make_deposit("xlm_d", 200);
        xlm.source_chain = Chain::Stellar;
        xlm.token = WrappedToken::WXLM;
        assert!(bridge.observe_deposit(xlm).is_ok());
    }

    #[test]
    fn test_pause_blocks_processing_of_observed_deposit() {
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 100)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        // Pause after observe but before process — processing still blocked.
        bridge.pause_chain(Chain::Solana, "investigating".into());
        let err = bridge.process_deposit("d1").unwrap_err();
        assert!(matches!(err, BridgeError::ChainPaused { .. }));
    }

    #[test]
    fn test_pause_blocks_new_withdrawals() {
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        bridge.pause_chain(Chain::Solana, "emergency".into());
        let err = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                100,
            )
            .unwrap_err();
        assert!(matches!(err, BridgeError::ChainPaused { .. }));
    }

    #[test]
    fn test_unpause_restores_operation() {
        let mut bridge = BridgeManager::new(1);
        bridge.pause_chain(Chain::Solana, "maintenance".into());
        bridge.unpause_chain(&Chain::Solana).unwrap();
        assert!(!bridge.is_chain_paused(&Chain::Solana));
        // Post-unpause deposits work again.
        assert!(bridge.observe_deposit(make_deposit("d1", 50)).is_ok());
    }

    #[test]
    fn test_unpause_nonpaused_errors() {
        let mut bridge = BridgeManager::new(1);
        let err = bridge.unpause_chain(&Chain::Solana).unwrap_err();
        assert!(matches!(err, BridgeError::ChainNotPaused(_)));
    }

    #[test]
    fn test_list_paused_chains_sorted() {
        let mut bridge = BridgeManager::new(1);
        bridge.pause_chain(Chain::Stellar, "horizon flapping".into());
        bridge.pause_chain(Chain::Solana, "key rotation mid-flight".into());
        let listed = bridge.list_paused_chains();
        assert_eq!(listed.len(), 2);
        // "Solana" < "Stellar" lexicographically.
        assert_eq!(listed[0].0, Chain::Solana);
        assert_eq!(listed[1].0, Chain::Stellar);
    }

    #[test]
    fn test_pause_does_not_affect_wrapped_balance_reads() {
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        bridge.pause_chain(Chain::Solana, "any".into());
        // Reads keep working so dashboards and users can still see state.
        assert_eq!(
            bridge.wrapped_balance("seal1alice", &WrappedToken::WSOL),
            1000
        );
        assert_eq!(bridge.total_locked(&WrappedToken::WSOL), 1000);
        assert_eq!(bridge.total_minted(&WrappedToken::WSOL), 1000);
        assert!(bridge.check_invariant());
    }

    #[test]
    fn test_pause_updates_reason() {
        let mut bridge = BridgeManager::new(1);
        bridge.pause_chain(Chain::Solana, "reason A".into());
        bridge.pause_chain(Chain::Solana, "reason B".into());
        assert_eq!(bridge.pause_reason(&Chain::Solana), Some("reason B"));
    }

    #[test]
    fn test_list_withdrawals_sorted() {
        let mut bridge = BridgeManager::new(1);
        let mut dep = make_deposit("sol_d", 1000);
        dep.confirmations = 1;
        bridge.observe_deposit(dep).unwrap();
        bridge.process_deposit("sol_d").unwrap();

        // Two withdrawals with different amounts produce different IDs.
        let id_a = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                400,
            )
            .unwrap();
        let id_b = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                300,
            )
            .unwrap();

        let ws = bridge.list_withdrawals();
        assert_eq!(ws.len(), 2);
        // Sorted ascending — depends on format but must be stable.
        let ids: Vec<_> = ws.iter().map(|w| w.id.as_str()).collect();
        assert!(ids.contains(&id_a.as_str()));
        assert!(ids.contains(&id_b.as_str()));
        assert!(ws[0].id <= ws[1].id);
    }

    #[test]
    fn test_list_deposits_by_recipient() {
        let mut bridge = BridgeManager::new(1);
        // Three deposits, two for alice and one for bob.
        let mut d1 = make_deposit("d_alice_1", 100);
        d1.seal_address = "seal1alice".into();
        let mut d2 = make_deposit("d_bob_1", 200);
        d2.seal_address = "seal1bob".into();
        let mut d3 = make_deposit("d_alice_2", 300);
        d3.seal_address = "seal1alice".into();
        bridge.observe_deposit(d1).unwrap();
        bridge.observe_deposit(d2).unwrap();
        bridge.observe_deposit(d3).unwrap();
        // Alice: ["d_alice_1", "d_alice_2"], sorted by ID.
        let alice_deps = bridge.list_deposits_by_recipient("seal1alice");
        let alice: Vec<&str> = alice_deps.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(alice, vec!["d_alice_1", "d_alice_2"]);
        // Bob: ["d_bob_1"].
        let bob_deps = bridge.list_deposits_by_recipient("seal1bob");
        let bob: Vec<&str> = bob_deps.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(bob, vec!["d_bob_1"]);
        // Unknown recipient: empty Vec, not error.
        assert!(bridge.list_deposits_by_recipient("seal1nobody").is_empty());
    }

    #[test]
    fn test_list_withdrawals_by_initiator() {
        let mut bridge = BridgeManager::new(1);
        // Fund alice and bob via deposits, so they can each initiate
        // withdrawals.
        let mut da = make_deposit("d_alice", 1000);
        da.seal_address = "seal1alice".into();
        da.confirmations = 1;
        let mut db = make_deposit("d_bob", 500);
        db.seal_address = "seal1bob".into();
        db.confirmations = 1;
        bridge.observe_deposit(da).unwrap();
        bridge.observe_deposit(db).unwrap();
        bridge.process_deposit("d_alice").unwrap();
        bridge.process_deposit("d_bob").unwrap();

        // Two withdrawals for alice (different amounts → distinct
        // IDs), one for bob. ID format is `wd_<addr>_<amount>`, so
        // sorting by ID groups by initiator naturally.
        let a1 = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                400,
            )
            .unwrap();
        let a2 = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                300,
            )
            .unwrap();
        let b1 = bridge
            .initiate_withdrawal(
                "seal1bob",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                200,
            )
            .unwrap();

        let alice_ws = bridge.list_withdrawals_by_initiator("seal1alice");
        let alice_ids: Vec<&str> = alice_ws.iter().map(|w| w.id.as_str()).collect();
        assert_eq!(alice_ids.len(), 2);
        assert!(alice_ids.contains(&a1.as_str()));
        assert!(alice_ids.contains(&a2.as_str()));
        // Sorted ascending by ID.
        assert!(alice_ws[0].id <= alice_ws[1].id);

        let bob_ws = bridge.list_withdrawals_by_initiator("seal1bob");
        assert_eq!(bob_ws.len(), 1);
        assert_eq!(bob_ws[0].id, b1);

        // Unknown initiator: empty Vec, not error.
        assert!(bridge
            .list_withdrawals_by_initiator("seal1nobody")
            .is_empty());
    }

    // ── dest_address format validation ──────────────────────────

    #[test]
    fn test_withdrawal_rejects_malformed_solana_address() {
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        // Ellipsis placeholder — the foot-gun this validator catches.
        let err = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                "sol1recipient…",
                WrappedToken::WSOL,
                100,
            )
            .unwrap_err();
        assert!(matches!(err, BridgeError::InvalidDestAddress(_)));
        // Funds must NOT be burned on a rejected withdrawal.
        assert_eq!(
            bridge.wrapped_balance("seal1alice", &WrappedToken::WSOL),
            1000
        );
    }

    #[test]
    fn test_withdrawal_rejects_too_short_address() {
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        let err = bridge
            .initiate_withdrawal("seal1alice", Chain::Solana, "abc", WrappedToken::WSOL, 100)
            .unwrap_err();
        assert!(matches!(err, BridgeError::InvalidDestAddress(_)));
    }

    #[test]
    fn test_withdrawal_accepts_valid_stellar_address() {
        let mut bridge = BridgeManager::new(1);
        // Deposit XLM first.
        let mut dep = make_deposit("xlm_d1", 2000);
        dep.source_chain = Chain::Stellar;
        dep.token = WrappedToken::WXLM;
        bridge.observe_deposit(dep).unwrap();
        bridge.confirm_deposit("xlm_d1").unwrap();
        bridge.process_deposit("xlm_d1").unwrap();

        let _wd_id = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Stellar,
                STELLAR_ADDR_A,
                WrappedToken::WXLM,
                500,
            )
            .expect("format-valid Stellar strkey accepted");
    }

    #[test]
    fn test_withdrawal_rejects_solana_address_for_stellar_chain() {
        let mut bridge = BridgeManager::new(1);
        let mut dep = make_deposit("xlm_d1", 2000);
        dep.source_chain = Chain::Stellar;
        dep.token = WrappedToken::WXLM;
        bridge.observe_deposit(dep).unwrap();
        bridge.confirm_deposit("xlm_d1").unwrap();
        bridge.process_deposit("xlm_d1").unwrap();

        // SOL_ADDR_A is 32 chars — not 56, and doesn't start with G/C.
        let err = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Stellar,
                SOL_ADDR_A,
                WrappedToken::WXLM,
                500,
            )
            .unwrap_err();
        assert!(matches!(err, BridgeError::InvalidDestAddress(_)));
    }

    #[test]
    fn test_validate_dest_address_unit() {
        // Direct unit-tests for the validator (no BridgeManager state).
        assert!(validate_dest_address(&Chain::Solana, SOL_ADDR_A).is_ok());
        assert!(validate_dest_address(&Chain::Solana, SOL_ADDR_B).is_ok());
        assert!(validate_dest_address(&Chain::Stellar, STELLAR_ADDR_A).is_ok());
        assert!(validate_dest_address(&Chain::Stellar, STELLAR_ADDR_B).is_ok());

        // Solana foot-guns.
        assert!(validate_dest_address(&Chain::Solana, "").is_err());
        assert!(validate_dest_address(&Chain::Solana, "tooshort").is_err());
        // Length OK but contains base58-forbidden '0'.
        assert!(validate_dest_address(&Chain::Solana, "00000000000000000000000000000000").is_err());
        // 'O' is also forbidden in base58.
        assert!(validate_dest_address(&Chain::Solana, "OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO").is_err());

        // Stellar foot-guns.
        assert!(validate_dest_address(&Chain::Stellar, "").is_err());
        // Right length, wrong prefix.
        let bad_prefix = format!("X{}", &STELLAR_ADDR_A[1..]);
        assert!(validate_dest_address(&Chain::Stellar, &bad_prefix).is_err());
        // Right shape, lowercase letter (not in base32 alphabet).
        let lowercased = STELLAR_ADDR_A.to_lowercase();
        assert!(validate_dest_address(&Chain::Stellar, &lowercased).is_err());
        // Length 55 (one short).
        assert!(validate_dest_address(&Chain::Stellar, &STELLAR_ADDR_A[..55]).is_err());
    }

    // ── Withdrawal nonce + committee-MAC tests ───────────────────

    /// Two withdrawals for the same amount from the same caller must
    /// get different ids + different nonces — the pre-fix code used
    /// `wd_{seal_address}_{amount}` which silently overwrote on
    /// replay. Pins the new counter-based scheme.
    #[test]
    fn second_withdrawal_does_not_overwrite_first() {
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 2000)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        let id1 = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                500,
            )
            .unwrap();
        let id2 = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                500,
            )
            .unwrap();
        assert_ne!(id1, id2, "ids must be distinct");
        let w1 = bridge.get_withdrawal(&id1).unwrap();
        let w2 = bridge.get_withdrawal(&id2).unwrap();
        assert_ne!(w1.nonce, w2.nonce, "nonces must be distinct");
        // Counter increments monotonically — second nonce is greater.
        assert!(w2.nonce > w1.nonce);
    }

    /// Without `set_committee_key`, a withdrawal lands with no
    /// signature attached. The RPC layer surfaces this as a
    /// `committee_signature_hex: null` field; operators interpret
    /// it as "not yet signed".
    #[test]
    fn withdrawal_has_no_signature_without_committee_key() {
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        let id = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                100,
            )
            .unwrap();
        let w = bridge.get_withdrawal(&id).unwrap();
        assert!(w.committee_signature_hex.is_none());
    }

    /// Once a committee key is configured, every subsequent
    /// withdrawal carries a deterministic HMAC that the on-chain
    /// `verify_committee_sig` reproduces from the same inputs. The
    /// canonical bytes are `recipient(32) || amount_le(8) ||
    /// nonce_le(8) || "seal-bridge-solana-v1"`.
    #[test]
    fn solana_withdrawal_mac_matches_canonical_hmac() {
        let mut bridge = BridgeManager::new(1);
        let committee_key = [0x11u8; 32];
        bridge.set_committee_key(committee_key);

        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        let id = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                100,
            )
            .unwrap();
        let w = bridge.get_withdrawal(&id).unwrap();
        let sig_hex = w
            .committee_signature_hex
            .as_ref()
            .expect("MAC must be present");
        // Re-derive what `bridges/solana/programs/seal-bridge::verify_committee_sig`
        // computes on-chain. Equal hex ⇒ on-chain verify accepts.
        let expected =
            compute_committee_mac(&Chain::Solana, &committee_key, SOL_ADDR_A, 100, w.nonce);
        assert_eq!(sig_hex, &expected);
        // HMAC-SHA-256 is always 32 bytes = 64 hex chars.
        assert_eq!(sig_hex.len(), 64);
    }

    /// Stellar StrKey decode + XDR serialization, pinned against a
    /// known G-address. The payload is the ed25519 pubkey the
    /// `seal-bridge-deployer` test key resolves to under the
    /// bridge-e2e setup — same value `bridges/stellar/src/lib.rs`
    /// would XDR-encode if asked via `to_xdr(env)`.
    #[test]
    fn stellar_strkey_decode_known_g_address() {
        // GC6DKQUG2YFLGNLNLE4IEXJSO56WBRWTN643RGD3XR4HSTYVFGELW7TF —
        // 56 chars, known-good StrKey. Decodes to a 32-byte ed25519.
        let addr = "GC6DKQUG2YFLGNLNLE4IEXJSO56WBRWTN643RGD3XR4HSTYVFGELW7TF";
        let (version, payload) = stellar_strkey_decode(addr).expect("decode");
        assert_eq!(version, 6 << 3, "G-version byte");
        // Round-trip via the XDR builder: 4 (SCV_ADDRESS) + 4 (account)
        // + 4 (ed25519 disc) + 32 (payload) = 44 bytes.
        let xdr = stellar_address_to_xdr(addr).expect("xdr");
        assert_eq!(xdr.len(), 44);
        assert_eq!(&xdr[..4], &18u32.to_be_bytes());
        assert_eq!(&xdr[4..8], &0u32.to_be_bytes());
        assert_eq!(&xdr[8..12], &0u32.to_be_bytes());
        assert_eq!(&xdr[12..], &payload);
    }

    /// Reject CRC-tampered, length-wrong, and unknown-prefix StrKeys.
    #[test]
    fn stellar_strkey_decode_rejects_malformed() {
        // Wrong length.
        assert!(stellar_strkey_decode("GTOOSHORT").is_none());
        // Right length, garbage base32.
        assert!(stellar_strkey_decode(&"G".repeat(56)).is_none());
        // Right length + base32 alphabet but CRC will mismatch for
        // arbitrary 'G…A' fill.
        let bad = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB";
        assert!(stellar_strkey_decode(bad).is_none());
    }

    /// Stellar withdrawal MAC: confirm the canonical bytes match the
    /// contract's `verify_proof` layout — XDR address + i128_be
    /// amount + u64_be nonce + Stellar domain tag.
    #[test]
    fn stellar_withdrawal_mac_matches_canonical_hmac() {
        let mut bridge = BridgeManager::new(1);
        let committee_key = [0x11u8; 32];
        bridge.set_committee_key(committee_key);
        // Stellar deposit so wrapped-XLM balance exists to burn.
        let deposit = BridgeDeposit {
            id: "x1".into(),
            source_chain: Chain::Stellar,
            source_tx_hash: "tx".into(),
            source_address: "g_addr".into(),
            seal_address: "seal1alice".into(),
            amount: 1000,
            token: WrappedToken::WXLM,
            processed: false,
            confirmations: 0,
        };
        bridge.observe_deposit(deposit).unwrap();
        bridge.confirm_deposit("x1").unwrap();
        bridge.process_deposit("x1").unwrap();

        let stellar_dest = "GC6DKQUG2YFLGNLNLE4IEXJSO56WBRWTN643RGD3XR4HSTYVFGELW7TF";
        let id = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Stellar,
                stellar_dest,
                WrappedToken::WXLM,
                100,
            )
            .unwrap();
        let w = bridge.get_withdrawal(&id).unwrap();
        let sig = w.committee_signature_hex.as_ref().expect("MAC present");
        // 32-byte HMAC, hex-encoded.
        assert_eq!(sig.len(), 64, "HMAC-SHA-256 hex");
        // Re-derive to confirm determinism.
        let expected =
            compute_committee_mac(&Chain::Stellar, &committee_key, stellar_dest, 100, w.nonce);
        assert_eq!(sig, &expected);
    }

    /// `attach_committee_signature` overwrites an existing signature
    /// — needed when the multi-validator Ringtail aggregate lands
    /// later, replacing the committee-of-1 testnet MAC.
    #[test]
    fn attach_committee_signature_overwrites() {
        let mut bridge = BridgeManager::new(1);
        bridge.set_committee_key([0x22u8; 32]);
        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();
        let id = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                100,
            )
            .unwrap();

        bridge
            .attach_committee_signature(&id, "deadbeef".into())
            .unwrap();
        assert_eq!(
            bridge
                .get_withdrawal(&id)
                .unwrap()
                .committee_signature_hex
                .as_deref(),
            Some("deadbeef")
        );
    }

    /// Fingerprint is unset until `set_committee_key`, then matches
    /// SHA3-256 over the raw key. Different keys produce different
    /// fingerprints (sanity check that we hash the key rather than
    /// returning a constant).
    #[test]
    fn committee_key_fingerprint_tracks_installed_key() {
        let mut bridge = BridgeManager::new(1);
        assert!(bridge.committee_key_fingerprint().is_none());

        let key_a = [0x11u8; 32];
        bridge.set_committee_key(key_a);
        let fp_a = bridge.committee_key_fingerprint().expect("set");
        assert_eq!(fp_a, seal_crypto::hash::sha3_256(&key_a).0);

        let key_b = [0x22u8; 32];
        bridge.set_committee_key(key_b);
        let fp_b = bridge.committee_key_fingerprint().expect("set");
        assert_eq!(fp_b, seal_crypto::hash::sha3_256(&key_b).0);
        assert_ne!(fp_a, fp_b, "fingerprint must change with key");
    }

    /// committee_key_eq returns true only for an exact match against
    /// the in-memory key, and false (without leaking timing) when
    /// no key is installed or the candidate differs.
    #[test]
    fn committee_key_eq_returns_true_only_on_exact_match() {
        let mut bridge = BridgeManager::new(1);
        let key = [0x55u8; 32];
        // Pre-set: no key installed → eq is always false.
        assert!(!bridge.committee_key_eq(&key));

        bridge.set_committee_key(key);
        assert!(bridge.committee_key_eq(&key));
        // Different byte at any position → false.
        let mut tampered = key;
        tampered[7] ^= 0x01;
        assert!(!bridge.committee_key_eq(&tampered));
        // All-zero never matches the installed key.
        assert!(!bridge.committee_key_eq(&[0u8; 32]));
    }

    /// Cheap counts (`deposit_count`, `pending_deposit_count`,
    /// `withdrawal_count`, `paused_chain_count`) match the lengths
    /// of their respective list endpoints. They exist to back
    /// `/metrics` without paying the sort/clone cost of `list_*`
    /// once per scrape.
    #[test]
    fn cheap_counts_match_list_lengths() {
        let mut bridge = BridgeManager::new(1);
        bridge.set_committee_key([0x44u8; 32]);
        assert_eq!(bridge.deposit_count(), 0);
        assert_eq!(bridge.pending_deposit_count(), 0);
        assert_eq!(bridge.withdrawal_count(), 0);
        assert_eq!(bridge.paused_chain_count(), 0);

        bridge.observe_deposit(make_deposit("d1", 100)).unwrap();
        bridge.observe_deposit(make_deposit("d2", 200)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();
        assert_eq!(bridge.deposit_count(), 2);
        assert_eq!(bridge.deposit_count(), bridge.list_deposits(None).len());
        assert_eq!(bridge.pending_deposit_count(), 1, "d2 still pending");

        let _wid = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                SOL_ADDR_A,
                WrappedToken::WSOL,
                50,
            )
            .unwrap();
        assert_eq!(bridge.withdrawal_count(), 1);
        assert_eq!(bridge.withdrawal_count(), bridge.list_withdrawals().len());

        bridge.pause_chain(Chain::Stellar, "drill".into());
        assert_eq!(bridge.paused_chain_count(), 1);
        assert_eq!(
            bridge.paused_chain_count(),
            bridge.list_paused_chains().len()
        );
    }

    /// SHA2 fingerprint matches a freshly-computed Sha256 over the
    /// raw key and is distinct from the SHA3 fingerprint (different
    /// hash families). Both must be unset before `set_committee_key`.
    #[test]
    fn committee_key_fingerprint_sha256_matches_reference() {
        use sha2::{Digest, Sha256};
        let mut bridge = BridgeManager::new(1);
        assert!(bridge.committee_key_fingerprint_sha256().is_none());
        assert!(bridge.committee_key_fingerprint().is_none());

        let key = [0x33u8; 32];
        bridge.set_committee_key(key);

        let fp2 = bridge.committee_key_fingerprint_sha256().expect("set");
        let expected: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(key);
            let out = h.finalize();
            let mut a = [0u8; 32];
            a.copy_from_slice(&out);
            a
        };
        assert_eq!(fp2, expected);

        let fp3 = bridge.committee_key_fingerprint().expect("set");
        assert_ne!(
            fp2, fp3,
            "SHA2 and SHA3 fingerprints must differ on the same key"
        );
    }
}

// Kani verification harnesses
//
// NOTE: BridgeManager uses HashMap which CBMC cannot model. These harnesses
// verify arithmetic invariants without constructing BridgeManager.
#[cfg(kani)]
mod kani_proofs {
    /// Prove: mint + lock arithmetic preserves minted <= locked.
    /// Models the core invariant without HashMap.
    #[kani::proof]
    fn deposit_preserves_invariant() {
        let locked: u64 = kani::any();
        let minted: u64 = kani::any();
        let amount: u64 = kani::any();
        kani::assume(minted <= locked); // precondition: invariant holds
        kani::assume(amount <= 1_000_000);

        // Deposit: both locked and minted increase by the same amount
        let new_locked = locked.saturating_add(amount);
        let new_minted = minted.saturating_add(amount);
        assert!(new_minted <= new_locked); // postcondition: invariant preserved
    }

    /// Prove: withdrawal preserves minted <= locked when withdraw <= minted.
    #[kani::proof]
    fn withdrawal_preserves_invariant() {
        let locked: u64 = kani::any();
        let minted: u64 = kani::any();
        let withdraw: u64 = kani::any();
        kani::assume(minted <= locked);
        kani::assume(withdraw <= minted);

        // Withdrawal: both locked and minted decrease by withdraw amount
        let new_locked = locked.saturating_sub(withdraw);
        let new_minted = minted.saturating_sub(withdraw);
        assert!(new_minted <= new_locked);
    }

    /// Prove: deposit amount cannot cause overflow with saturating_add.
    #[kani::proof]
    fn deposit_no_overflow() {
        let balance: u64 = kani::any();
        let amount: u64 = kani::any();
        let result = balance.saturating_add(amount);
        assert!(result >= balance);
        assert!(result >= amount.min(balance));
    }
}
