//! Destination-chain submission helpers for the relayer.
//!
//! These wrap the same CLIs the bridge-testnet-demo.sh reverse modes
//! invoke (`stellar contract invoke ... unlock_xlm` for Stellar) so
//! the on-chain wire format stays in lockstep between manual operator
//! flows and automated relayer flows. We shell out rather than embed
//! a Rust SDK because:
//!   1. The CLIs are already in the operator's PATH (prereq for the
//!      manual reverse path), and
//!   2. Pulling stellar-rs / soroban-rs into the relayer binary would
//!      add ~50 MB of compiled code and a separate XDR-versioning
//!      surface to manage on every Soroban protocol bump.
//!
//! Submission returns the destination-chain transaction hash so the
//! relayer can pass it into `seal_bridgeMarkExecuted` for the audit
//! log.

use crate::{SolanaConfig, StellarConfig, WithdrawalRecord};
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug)]
pub enum SubmitError {
    /// Operator hasn't configured this chain on this relayer instance.
    /// The withdrawal is silently left for another relayer to pick up.
    NotConfigured,
    /// Unsupported token for the chain (e.g. WSOL on Stellar).
    UnsupportedToken { chain: String, token: String },
    /// CLI exit code != 0. The relayer logs the stderr text and
    /// retries on the next poll interval.
    CommandFailed { code: i32, stderr: String },
    /// Anything below the CLI level (fork/exec failure, signature
    /// decoding, etc).
    Io(String),
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitError::NotConfigured => write!(f, "chain not configured for this relayer"),
            SubmitError::UnsupportedToken { chain, token } => {
                write!(f, "unsupported token {token} on {chain}")
            }
            SubmitError::CommandFailed { code, stderr } => {
                write!(f, "CLI exit {code}: {stderr}")
            }
            SubmitError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

pub struct Submission {
    pub tx_hash: Option<String>,
}

/// Submit `unlock_xlm` or `unlock_usdc` on the configured Stellar
/// network. `committee_signature_hex` is the 64-char hex form from
/// `seal_getBridgeWithdrawal`.
pub async fn submit_stellar(
    cfg: &StellarConfig,
    w: &WithdrawalRecord,
    committee_signature_hex: &str,
) -> Result<Submission, SubmitError> {
    let unlock_fn = match w.token.as_str() {
        "WXLM" => "unlock_xlm",
        "WUSDC" => "unlock_usdc",
        other => {
            return Err(SubmitError::UnsupportedToken {
                chain: "Stellar".into(),
                token: other.into(),
            });
        }
    };

    let mut cmd = Command::new("stellar");
    cmd.current_dir(&cfg.contract_dir)
        .arg("contract")
        .arg("invoke")
        .arg("--id")
        .arg(&cfg.contract_id)
        .arg("--source")
        .arg(&cfg.source)
        .arg("--network")
        .arg(&cfg.network)
        .arg("--")
        .arg(unlock_fn)
        .arg("--recipient")
        .arg(&w.dest_address)
        .arg("--amount")
        .arg(w.amount.to_string())
        .arg("--nonce")
        .arg(w.nonce.to_string())
        .arg("--proof")
        .arg(committee_signature_hex)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd
        .output()
        .await
        .map_err(|e| SubmitError::Io(format!("spawn stellar: {e}")))?;
    if !output.status.success() {
        return Err(SubmitError::CommandFailed {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr)
                .lines()
                .take(20)
                .collect::<Vec<_>>()
                .join("\n"),
        });
    }
    let tx_hash = parse_stellar_tx_hash(&output.stdout, &output.stderr);
    Ok(Submission { tx_hash })
}

/// Submit `unlock_tokens` on the configured Solana cluster via
/// `anchor run unlock-tokens`. Per-token (mint, vault_ata) lookup
/// against the relayer's SolanaConfig; recipient ATA is derived via
/// `spl-token address --token <mint> --owner <recipient>`. If the
/// derived ATA isn't yet initialized on-chain, the Anchor program
/// rejects the unlock and we surface CommandFailed for the operator
/// to investigate (the user must initialize their own ATA — auto-
/// init by the relayer opens a SOL-drain DoS).
pub async fn submit_solana(
    cfg: &SolanaConfig,
    w: &WithdrawalRecord,
    committee_signature_hex: &str,
) -> Result<Submission, SubmitError> {
    let (mint, vault_ata) = match w.token.as_str() {
        "WSOL" => match (&cfg.mint_wsol, &cfg.vault_ata_wsol) {
            (Some(m), Some(v)) => (m.clone(), v.clone()),
            _ => return Err(SubmitError::NotConfigured),
        },
        "WUSDC" => match (&cfg.mint_wusdc, &cfg.vault_ata_wusdc) {
            (Some(m), Some(v)) => (m.clone(), v.clone()),
            _ => return Err(SubmitError::NotConfigured),
        },
        other => {
            return Err(SubmitError::UnsupportedToken {
                chain: "Solana".into(),
                token: other.into(),
            });
        }
    };

    // Derive recipient ATA pubkey via spl-token (deterministic; does
    // not contact the chain).
    let recipient_ata = derive_solana_ata(&mint, &w.dest_address).await?;

    let mut cmd = Command::new("anchor");
    cmd.current_dir(&cfg.anchor_dir)
        .arg("run")
        .arg("unlock-tokens")
        .arg("--")
        .arg("--amount")
        .arg(w.amount.to_string())
        .arg("--nonce")
        .arg(w.nonce.to_string())
        .arg("--signature")
        .arg(committee_signature_hex)
        .arg("--recipient")
        .arg(&w.dest_address)
        .arg("--recipient-ata")
        .arg(&recipient_ata)
        .arg("--vault-ata")
        .arg(&vault_ata)
        .arg("--authority")
        .arg(&cfg.authority)
        .arg("--program-id")
        .arg(&cfg.program_id)
        .arg("--provider.cluster")
        .arg(&cfg.cluster)
        .arg("--provider.wallet")
        .arg(&cfg.wallet)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd
        .output()
        .await
        .map_err(|e| SubmitError::Io(format!("spawn anchor: {e}")))?;
    if !output.status.success() {
        return Err(SubmitError::CommandFailed {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr)
                .lines()
                .take(20)
                .collect::<Vec<_>>()
                .join("\n"),
        });
    }
    let tx_hash = parse_solana_tx_hash(&output.stdout, &output.stderr);
    Ok(Submission { tx_hash })
}

async fn derive_solana_ata(mint: &str, owner: &str) -> Result<String, SubmitError> {
    // `spl-token address --token <mint> --owner <owner> --verbose`
    // prints multiple lines; the one we want is
    // "Associated token address: <pubkey>".
    let output = Command::new("spl-token")
        .arg("address")
        .arg("--token")
        .arg(mint)
        .arg("--owner")
        .arg(owner)
        .arg("--verbose")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| SubmitError::Io(format!("spawn spl-token: {e}")))?;
    if !output.status.success() {
        return Err(SubmitError::CommandFailed {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Associated token address:") {
            return Ok(rest.trim().to_string());
        }
    }
    Err(SubmitError::Io(format!(
        "spl-token address did not emit 'Associated token address:' line; stdout was:\n{}",
        text
    )))
}

/// Anchor's `unlock-tokens` script prints `Tx: <signature>` to stdout
/// after successful submission (per bridges/solana/scripts/
/// unlock-tokens.ts). We also accept "Signature: <sig>" for forward-
/// compat with anchor 0.32+ output.
fn parse_solana_tx_hash(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );
    for line in text.lines() {
        let trimmed = line.trim();
        for prefix in ["Tx:", "Signature:", "tx:", "signature:"] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                let tok = rest.trim();
                if !tok.is_empty() {
                    // Solana sigs are base58, 87-88 chars. Be lenient
                    // — just take the first whitespace-bounded token.
                    let first = tok.split_whitespace().next().unwrap_or("");
                    if !first.is_empty() {
                        return Some(first.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Extract the transaction hash from `stellar contract invoke` output.
/// The CLI prints the hash to stderr in a "Transaction hash is …"
/// line; stdout carries the contract's return value (usually `null`
/// for void-returning unlocks). Best-effort — if neither stream
/// matches the expected pattern we fall back to None and the caller
/// still treats the submission as successful (exit code was 0).
fn parse_stellar_tx_hash(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );
    for line in text.lines() {
        // Match e.g. "Transaction hash is abc123def…" or "tx hash: abc".
        let lower = line.to_ascii_lowercase();
        if lower.contains("transaction hash") || lower.contains("tx hash") {
            // Grab the last whitespace-delimited token that looks
            // hex-ish.
            for tok in line.split_whitespace().rev() {
                let tok = tok.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
                if tok.len() >= 16 && tok.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(tok.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tx_hash_from_stderr_line() {
        let stderr = b"some other line\n\
                       Transaction hash is abc123def456789012345678901234567890abcdef\n\
                       trailing\n";
        let h = parse_stellar_tx_hash(b"", stderr).expect("hash should parse");
        assert!(h.starts_with("abc123def456"));
    }

    #[test]
    fn parse_tx_hash_handles_no_match() {
        assert_eq!(parse_stellar_tx_hash(b"null\n", b"all good\n"), None);
    }

    #[test]
    fn parse_tx_hash_lowercase_alt_label() {
        let line = b"tx hash: cafebabedeadbeefcafebabedeadbeefcafebabe\n";
        let h = parse_stellar_tx_hash(line, b"").expect("hash should parse");
        assert_eq!(h, "cafebabedeadbeefcafebabedeadbeefcafebabe");
    }

    #[test]
    fn parse_solana_tx_hash_handles_anchor_output() {
        let stdout = b"Unlocking 100 -> abc123... nonce=42\n\
                       Tx: 2VgsBcWtFa5j3qcSCYrXpgWVMUuMnCMv1NLzZmgw3SsKbnGTzj4PrShG3vR5MTr5LpMtcHpa6JFD8Vu1S9Vh51bU\n";
        let h = parse_solana_tx_hash(stdout, b"").expect("sig should parse");
        assert!(h.starts_with("2VgsBcWtFa5j3qcSCY"));
    }

    #[test]
    fn parse_solana_tx_hash_accepts_signature_label() {
        let stdout = b"Signature: 3xyz\n";
        let h = parse_solana_tx_hash(stdout, b"").expect("sig should parse");
        assert_eq!(h, "3xyz");
    }

    #[test]
    fn parse_solana_tx_hash_no_match() {
        assert_eq!(parse_solana_tx_hash(b"nothing here\n", b""), None);
    }
}
