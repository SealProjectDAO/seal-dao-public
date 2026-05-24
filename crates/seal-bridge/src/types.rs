//! Bridge types.

use serde::{Deserialize, Serialize};

/// Per-chain destination-address format validation. Catches the
/// foot-gun cases (typo, ellipsis, wrong-chain-pasted-by-mistake)
/// before `BridgeManager::initiate_withdrawal` burns wrapped tokens
/// against an unprocessable record. This is **format-only**, not a
/// full cryptographic check:
///
/// - Solana: base58 alphabet + 32 ≤ len ≤ 44 (32-byte pubkey
///   base58-encodes to 43-44 chars; lower bound covers the
///   all-zeros edge case).
/// - Stellar: strkey shape — first char G (account) or C
///   (contract), total length 56, uppercase base32 alphabet
///   `[A-Z2-7]` (no padding).
///
/// Real checksum verification (bs58 → 32-byte Pubkey, Stellar
/// strkey CRC16) is a follow-up — vendoring bs58/stellar-strkey as
/// direct deps requires a separate vendor refresh.
pub fn validate_dest_address(chain: &Chain, addr: &str) -> Result<(), String> {
    match chain {
        Chain::Solana => validate_solana_address(addr),
        Chain::Stellar => validate_stellar_address(addr),
    }
}

fn validate_solana_address(addr: &str) -> Result<(), String> {
    let len = addr.len();
    if !(32..=44).contains(&len) {
        return Err(format!(
            "Solana address must be 32-44 chars (base58 of a 32-byte pubkey); got {len}"
        ));
    }
    // Base58 alphabet: ASCII alphanumerics minus '0', 'O', 'I', 'l'.
    for c in addr.chars() {
        let ok = c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l';
        if !ok {
            return Err(format!(
                "Solana address contains non-base58 character {c:?}"
            ));
        }
    }
    Ok(())
}

fn validate_stellar_address(addr: &str) -> Result<(), String> {
    if addr.len() != 56 {
        return Err(format!(
            "Stellar strkey must be 56 chars; got {}",
            addr.len()
        ));
    }
    let first = addr.chars().next().expect("len 56 implies non-empty");
    if first != 'G' && first != 'C' {
        return Err(format!(
            "Stellar strkey must start with 'G' (account) or 'C' (contract); got {first:?}"
        ));
    }
    // Base32 (RFC 4648 uppercase, no padding): A-Z and 2-7.
    for c in addr.chars() {
        let ok = matches!(c, 'A'..='Z' | '2'..='7');
        if !ok {
            return Err(format!(
                "Stellar strkey contains non-base32 character {c:?}"
            ));
        }
    }
    Ok(())
}

/// Supported external chains.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Chain {
    Solana,
    Stellar,
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::Solana => write!(f, "Solana"),
            Chain::Stellar => write!(f, "Stellar"),
        }
    }
}

/// A wrapped token on the Seal chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WrappedToken {
    WSOL,  // Wrapped SOL
    WXLM,  // Wrapped XLM
    WUSDC, // Wrapped USDC (from either chain)
}

impl WrappedToken {
    pub fn chain(&self) -> Chain {
        match self {
            WrappedToken::WSOL => Chain::Solana,
            WrappedToken::WXLM => Chain::Stellar,
            WrappedToken::WUSDC => Chain::Solana, // Default USDC source
        }
    }

    pub fn symbol(&self) -> &str {
        match self {
            WrappedToken::WSOL => "wSOL",
            WrappedToken::WXLM => "wXLM",
            WrappedToken::WUSDC => "wUSDC",
        }
    }

    /// Every wrapped-token variant. Useful for any caller that
    /// wants to enumerate all balances for an address without
    /// hardcoding the variant list (e.g. the explorer Account
    /// Lookup, the wallet TUI). Order is stable: WSOL, WXLM,
    /// WUSDC.
    pub fn all_variants() -> &'static [WrappedToken] {
        &[WrappedToken::WSOL, WrappedToken::WXLM, WrappedToken::WUSDC]
    }
}

/// A deposit from an external chain into Seal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeDeposit {
    /// Unique deposit ID.
    pub id: String,
    /// Source chain.
    pub source_chain: Chain,
    /// Source chain transaction hash.
    pub source_tx_hash: String,
    /// Depositor's address on the source chain.
    pub source_address: String,
    /// Recipient's SEAL address.
    pub seal_address: String,
    /// Amount locked on source chain (in source chain's smallest unit).
    pub amount: u64,
    /// Token being bridged.
    pub token: WrappedToken,
    /// Whether the deposit has been processed (minted on Seal).
    pub processed: bool,
    /// Number of validator confirmations.
    pub confirmations: u32,
}

/// Notification emitted when a new withdrawal is ready for committee
/// signing — i.e. after `initiate_withdrawal` inserts the record but
/// before the committee MAC has been attached.
///
/// Wraps the inputs the future P1#5 multi-validator Ringtail
/// orchestrator (ADR-002) needs to call `start_signing(...)` on the
/// orchestrator. Single-signer (HMAC + Ringtail-singleton) paths
/// don't subscribe to this — they attach the signature inline inside
/// `initiate_withdrawal`.
#[derive(Clone, Debug)]
pub struct WithdrawalReadyForSigning {
    pub withdrawal_id: String,
    pub dest_chain: Chain,
    pub dest_address: String,
    pub amount: u64,
    pub nonce: u64,
}

/// A withdrawal from Seal to an external chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeWithdrawal {
    /// Unique withdrawal ID.
    pub id: String,
    /// Monotonic nonce assigned at burn time. The on-chain unlock
    /// instruction (`bridges/solana/.../unlock_tokens` /
    /// `bridges/stellar/.../unlock_xlm`) requires the matching nonce
    /// alongside the committee MAC; the bridge state on each chain
    /// rejects replays of the same nonce.
    pub nonce: u64,
    /// Destination chain.
    pub dest_chain: Chain,
    /// Destination address on the external chain.
    pub dest_address: String,
    /// SEAL address burning the wrapped tokens.
    pub seal_address: String,
    /// Amount to unlock on destination chain.
    pub amount: u64,
    /// Token being withdrawn.
    pub token: WrappedToken,
    /// Committee MAC (hex) authenticating the unlock to the destination
    /// chain. `None` until the committee has signed; populated by
    /// `BridgeManager::attach_committee_signature` once the Ringtail
    /// pipeline produces an aggregate (or, on a committee-of-1
    /// testnet, immediately on burn). The bridge programs verify
    /// this as `HMAC-SHA-256(committee_key, payload)`.
    pub committee_signature_hex: Option<String>,
    /// Whether the withdrawal has been executed on the destination chain.
    pub executed: bool,
}

#[cfg(test)]
mod validator_tests {
    use super::*;
    use proptest::prelude::*;

    // ── Property tests for the format-only validator ───────────
    //
    // The validator takes untrusted user-supplied strings; the
    // overarching property is "never panics, always returns Ok or
    // Err." The Solana/Stellar-specific properties below pin the
    // alphabet and length rules so a future edit can't silently
    // widen the validator and accept malformed addresses.

    proptest! {
        /// `validate_dest_address` accepts arbitrary input without
        /// panicking — the only invariant the calling
        /// `BridgeManager::initiate_withdrawal` relies on is that a
        /// malformed input produces a clean `Err`, never a process
        /// crash. Solana and Stellar branches both exercised.
        #[test]
        fn never_panics_on_arbitrary_input_solana(s in ".*") {
            let _ = validate_dest_address(&Chain::Solana, &s);
        }

        #[test]
        fn never_panics_on_arbitrary_input_stellar(s in ".*") {
            let _ = validate_dest_address(&Chain::Stellar, &s);
        }

        /// Any string outside the [32, 44] length window must be
        /// rejected for Solana, regardless of alphabet.
        #[test]
        fn solana_rejects_out_of_window_length(s in "[a-zA-Z0-9]{0,200}") {
            let len = s.len();
            if !(32..=44).contains(&len) {
                prop_assert!(
                    validate_dest_address(&Chain::Solana, &s).is_err(),
                    "Solana validator accepted an out-of-window length {len}: {s:?}"
                );
            }
        }

        /// Stellar rejects anything not exactly 56 chars.
        #[test]
        fn stellar_rejects_non_56_length(s in "[A-Z2-7]{0,200}") {
            if s.len() != 56 {
                prop_assert!(
                    validate_dest_address(&Chain::Stellar, &s).is_err(),
                    "Stellar validator accepted a non-56 length {}: {s:?}", s.len()
                );
            }
        }

        /// Solana rejects any input containing the four base58-forbidden
        /// characters '0', 'O', 'I', 'l' — even if length is in window.
        #[test]
        fn solana_rejects_forbidden_chars(prefix in "[a-zA-Z1-9]{16,22}",
                                          forbidden in "[0OIl]",
                                          suffix in "[a-zA-Z1-9]{15,21}") {
            let s = format!("{}{}{}", prefix, forbidden, suffix);
            // Ensure we land inside the Solana length window.
            if (32..=44).contains(&s.len()) {
                prop_assert!(
                    validate_dest_address(&Chain::Solana, &s).is_err(),
                    "Solana validator accepted forbidden char {forbidden:?} in {s:?}"
                );
            }
        }

        /// Stellar rejects any input whose first character isn't G or C,
        /// even with a perfect 56-char length and base32 alphabet.
        /// Prefix regex `[ABDEFH-Z2-7]` = A-Z minus C and G, plus 2-7.
        #[test]
        fn stellar_rejects_non_g_or_c_prefix(prefix in "[ABDEFH-Z2-7]",
                                             rest in "[A-Z2-7]{55}") {
            let s = format!("{}{}", prefix, rest);
            prop_assert_eq!(s.len(), 56);
            prop_assert!(
                validate_dest_address(&Chain::Stellar, &s).is_err(),
                "Stellar validator accepted non-G/C prefix {prefix:?}: {s:?}"
            );
        }

        /// Stellar rejects any 56-char string containing a lowercase
        /// letter — base32 alphabet is uppercase-only.
        #[test]
        fn stellar_rejects_lowercase(prefix in "[GC]",
                                     before in "[A-Z2-7]{0,54}",
                                     low in "[a-z]") {
            let pad = "A".repeat(55 - before.len());
            let s = format!("{}{}{}{}", prefix, before, low, pad);
            // s.len() == 1 + before.len() + 1 + (55 - before.len()) = 57.
            // Trim to 56 to satisfy the length check.
            let s: String = s.chars().take(56).collect();
            prop_assert_eq!(s.len(), 56);
            prop_assert!(
                validate_dest_address(&Chain::Stellar, &s).is_err(),
                "Stellar validator accepted lowercase {low:?} in {s:?}"
            );
        }
    }
}
