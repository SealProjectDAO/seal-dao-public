//! Seal DAO bridge relayer — submits destination-chain unlock
//! claims for committee-signed bridge withdrawals.
//!
//! # Custody model
//!
//! Per-validator (decided 2026-05-16): every Seal validator runs its
//! own relayer instance and holds its own funded Solana ed25519 key +
//! Stellar G-key. The single-relayer alternative would be a SPOF.
//!
//! # Loop
//!
//! 1. Poll `seal_listBridgeWithdrawals` for entries where
//!    `committee_signature_hex` is set and `executed == false`.
//! 2. For each such withdrawal, compute a deterministic back-off
//!    delay based on `SHA3-256(validator_pubkey || withdrawal_id)`
//!    mod `--max-backoff-secs`. Different validators get different
//!    delays for the same withdrawal so they don't all submit at
//!    once; whichever has the smallest delay wins the gas.
//! 3. After sleeping, re-fetch the withdrawal: if it's still
//!    un-executed, submit the unlock on the destination chain (or
//!    log it in `--dry-run` mode) and call `seal_bridgeMarkExecuted`
//!    to flip the flag. Idempotent at the bridge layer, so a race-
//!    losing submission still surfaces as success.
//! 4. Persist the highest withdrawal-id seen + executed to the
//!    cursor file so restarts don't re-process the entire log.
//!
//! # Chain submission (next commit)
//!
//! This scaffold lands the loop with `--dry-run` only — actual
//! `anchor run unlock-tokens` / `stellar contract invoke -- unlock_xlm`
//! submission is wired in a follow-up commit (P1#3 #4). The dry-run
//! mode is useful in production today to verify the loop sees the
//! right withdrawals before flipping on real submission.
//!
//! # Usage
//!
//! ```
//! cargo run -p seal-relayer -- \
//!     --key validator.json \
//!     --node http://localhost:8545 \
//!     --cursor-file /var/lib/seal/relayer-cursor.json \
//!     --interval-secs 10 \
//!     --max-backoff-secs 30 \
//!     --dry-run
//! ```

use seal_crypto::signature::SigningKey;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::path::PathBuf;
use std::time::Duration;

mod chains;
mod metrics;
mod rpc;

use crate::metrics::Metrics;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[derive(Debug, Clone)]
struct Config {
    key_path: String,
    node_url: String,
    cursor_path: PathBuf,
    interval: Duration,
    max_backoff: Duration,
    dry_run: bool,
    /// `--metrics-bind <ip:port>`. None disables the metrics
    /// endpoint entirely (default).
    metrics_bind: Option<std::net::SocketAddr>,
    /// Stellar chain submission config. None → reject any WXLM/WUSDC
    /// withdrawal on the Stellar chain (operator decided not to relay
    /// Stellar from this instance). Some(_) → shell out to
    /// `stellar contract invoke ... unlock_xlm` / `unlock_usdc`.
    stellar: Option<StellarConfig>,
    /// Solana chain submission config. See `parse_solana_config`.
    solana: Option<SolanaConfig>,
}

#[derive(Debug, Clone)]
struct StellarConfig {
    contract_id: String,
    network: String,
    source: String,
    contract_dir: PathBuf,
}

#[derive(Debug, Clone)]
struct SolanaConfig {
    program_id: String,
    cluster: String,
    wallet: String,
    authority: String,
    anchor_dir: PathBuf,
    /// SPL mint pubkey for WSOL-routed locks; None disables WSOL on
    /// this relayer instance (operator runs a separate one if needed).
    mint_wsol: Option<String>,
    /// Vault ATA owned by the bridge_state PDA for the WSOL mint.
    vault_ata_wsol: Option<String>,
    mint_wusdc: Option<String>,
    vault_ata_wusdc: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct Cursor {
    /// Highest numeric nonce of a withdrawal we've processed (regardless
    /// of which validator actually relayed it). On startup we still
    /// poll the full list and dedup by `executed = true`, but the
    /// cursor lets us short-circuit the common case and reduces log
    /// noise for old withdrawals.
    last_seen_nonce: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct WithdrawalRecord {
    id: String,
    nonce: u64,
    dest_chain: String,
    dest_address: String,
    #[serde(rename = "seal_address")]
    _seal_address: String,
    amount: u64,
    token: String,
    committee_signature_hex: Option<String>,
    executed: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            print_usage();
            std::process::exit(2);
        }
    };

    let (sk, vk_hex, address) = match rpc::load_keyfile(&cfg.key_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: keyfile {}: {}", cfg.key_path, e);
            std::process::exit(2);
        }
    };
    let vk_bytes = match hex::decode(&vk_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: verifying_key hex: {e}");
            std::process::exit(2);
        }
    };

    tracing::info!(
        node_url = %cfg.node_url,
        address = %address,
        interval_secs = cfg.interval.as_secs(),
        max_backoff_secs = cfg.max_backoff.as_secs(),
        cursor_file = %cfg.cursor_path.display(),
        dry_run = cfg.dry_run,
        "seal-relayer starting"
    );

    let mut cursor = Cursor::load(&cfg.cursor_path);
    tracing::info!(last_seen_nonce = cursor.last_seen_nonce, "cursor loaded");

    let metrics = Arc::new(Metrics::new(cfg.dry_run));
    if let Some(bind) = cfg.metrics_bind {
        metrics::spawn(metrics.clone(), bind);
    }

    loop {
        metrics.passes_total.fetch_add(1, Ordering::Relaxed);
        match run_pass(&cfg, &sk, &vk_hex, &vk_bytes, &mut cursor, &metrics).await {
            Ok(processed) => {
                if processed > 0 {
                    tracing::info!(processed, "relayer pass complete");
                    if let Err(e) = cursor.save(&cfg.cursor_path) {
                        tracing::warn!(error = %e, "cursor save failed");
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "relayer pass failed"),
        }
        tokio::time::sleep(cfg.interval).await;
    }
}

async fn run_pass(
    cfg: &Config,
    sk: &SigningKey,
    vk_hex: &str,
    vk_bytes: &[u8],
    cursor: &mut Cursor,
    metrics: &Metrics,
) -> Result<u64, String> {
    let withdrawals = rpc::list_bridge_withdrawals(&cfg.node_url).await?;
    let mut processed: u64 = 0;

    for w in withdrawals {
        if w.executed || w.committee_signature_hex.is_none() {
            continue;
        }
        if w.nonce <= cursor.last_seen_nonce && cursor.last_seen_nonce > 0 {
            // Already processed in a prior pass; skip silently.
            continue;
        }
        metrics.withdrawals_seen.fetch_add(1, Ordering::Relaxed);

        // Per-validator deterministic back-off. SHA3-256(vk || id) %
        // max_backoff_secs distributes validators across the window
        // so they don't all submit at once. Lowest-delay validator
        // pays the gas; everyone else's RPC sees `executed = true`
        // already and folds into a no-op via the idempotent
        // bridge-mark-executed.
        let backoff = compute_backoff(vk_bytes, &w.id, cfg.max_backoff);
        tracing::info!(
            withdrawal_id = %w.id,
            nonce = w.nonce,
            dest_chain = %w.dest_chain,
            dest_address = %w.dest_address,
            amount = w.amount,
            token = %w.token,
            backoff_secs = backoff.as_secs(),
            "withdrawal queued for relay"
        );
        tokio::time::sleep(backoff).await;

        // Re-fetch — another validator may have already submitted
        // while we slept. Saves gas on the common race-loser path.
        let live = match rpc::get_bridge_withdrawal(&cfg.node_url, &w.id).await? {
            Some(rec) => rec,
            None => {
                tracing::warn!(withdrawal_id = %w.id, "withdrawal disappeared mid-pass");
                continue;
            }
        };
        if live.executed {
            tracing::info!(
                withdrawal_id = %w.id,
                "skipped — already executed by another relayer"
            );
            if live.nonce > cursor.last_seen_nonce {
                cursor.last_seen_nonce = live.nonce;
            }
            processed += 1;
            continue;
        }

        if cfg.dry_run {
            tracing::info!(
                withdrawal_id = %w.id,
                dest_chain = %w.dest_chain,
                token = %w.token,
                "DRY RUN — would submit unlock on destination chain"
            );
            metrics.dry_run_skipped.fetch_add(1, Ordering::Relaxed);
            if w.nonce > cursor.last_seen_nonce {
                cursor.last_seen_nonce = w.nonce;
            }
            processed += 1;
            continue;
        }

        let sig_hex = match live.committee_signature_hex.as_deref() {
            Some(s) => s,
            None => {
                tracing::warn!(
                    withdrawal_id = %w.id,
                    "committee signature missing on re-fetch — skip"
                );
                continue;
            }
        };

        let dest_tx_hash = match dispatch_submission(cfg, &live, sig_hex).await {
            Ok(s) => {
                metrics.submissions_total.fetch_add(1, Ordering::Relaxed);
                s.tx_hash
            }
            Err(chains::SubmitError::NotConfigured) => {
                metrics
                    .skipped_not_configured
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    withdrawal_id = %w.id,
                    dest_chain = %live.dest_chain,
                    "skip — this relayer is not configured for chain"
                );
                continue;
            }
            Err(chains::SubmitError::UnsupportedToken { chain, token }) => {
                tracing::warn!(
                    withdrawal_id = %w.id,
                    chain = %chain,
                    token = %token,
                    "skip — unsupported token for chain"
                );
                continue;
            }
            Err(e) => {
                metrics.submission_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    withdrawal_id = %w.id,
                    error = %e,
                    "chain submission failed — retrying on next pass"
                );
                continue;
            }
        };

        match rpc::bridge_mark_executed(&cfg.node_url, sk, vk_hex, &w.id, dest_tx_hash.as_deref())
            .await
        {
            Ok(was_already) => {
                if was_already {
                    metrics
                        .mark_executed_already
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    metrics.mark_executed_total.fetch_add(1, Ordering::Relaxed);
                }
                tracing::info!(
                    withdrawal_id = %w.id,
                    was_already_executed = was_already,
                    dest_tx_hash = ?dest_tx_hash,
                    "withdrawal claim submitted + marked executed"
                );
                if w.nonce > cursor.last_seen_nonce {
                    cursor.last_seen_nonce = w.nonce;
                }
                processed += 1;
            }
            Err(e) => {
                metrics
                    .mark_executed_failures
                    .fetch_add(1, Ordering::Relaxed);
                // On-chain claim succeeded but Seal-side mark failed.
                // The on-chain side is replay-protected (AlreadyClaimed
                // on the second try), so this isn't a duplicate-pay
                // risk — log loudly and let the next pass retry the
                // mark-executed step (which is itself idempotent).
                tracing::warn!(
                    withdrawal_id = %w.id,
                    dest_tx_hash = ?dest_tx_hash,
                    error = %e,
                    "claim landed on-chain but mark-executed failed — will retry"
                );
            }
        }
    }
    Ok(processed)
}

async fn dispatch_submission(
    cfg: &Config,
    w: &WithdrawalRecord,
    committee_signature_hex: &str,
) -> Result<chains::Submission, chains::SubmitError> {
    match w.dest_chain.as_str() {
        "Stellar" => {
            let stellar_cfg = cfg
                .stellar
                .as_ref()
                .ok_or(chains::SubmitError::NotConfigured)?;
            chains::submit_stellar(stellar_cfg, w, committee_signature_hex).await
        }
        "Solana" => {
            let solana_cfg = cfg
                .solana
                .as_ref()
                .ok_or(chains::SubmitError::NotConfigured)?;
            chains::submit_solana(solana_cfg, w, committee_signature_hex).await
        }
        other => Err(chains::SubmitError::UnsupportedToken {
            chain: other.into(),
            token: w.token.clone(),
        }),
    }
}

/// Compute the deterministic per-validator back-off delay.
///
/// `SHA3-256(vk_bytes || withdrawal_id_bytes)` mod `max_secs`.
/// Pure function; tested.
fn compute_backoff(vk_bytes: &[u8], withdrawal_id: &str, max: Duration) -> Duration {
    let max_secs = max.as_secs().max(1);
    let mut h = Sha3_256::new();
    h.update(vk_bytes);
    h.update(withdrawal_id.as_bytes());
    let digest = h.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    let n = u64::from_le_bytes(bytes) % max_secs;
    Duration::from_secs(n)
}

impl Cursor {
    fn load(path: &PathBuf) -> Self {
        match std::fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
            Err(_) => Cursor::default(),
        }
    }
    fn save(&self, path: &PathBuf) -> Result<(), String> {
        let tmp = path.with_extension("json.tmp");
        let raw =
            serde_json::to_string_pretty(self).map_err(|e| format!("serialize cursor: {e}"))?;
        std::fs::write(&tmp, raw).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), path.display()))?;
        Ok(())
    }
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = std::env::args().collect();
    let key_path = parse_arg_string(&args, "--key").ok_or("--key is required")?;
    let node_url =
        parse_arg_string(&args, "--node").unwrap_or_else(|| "http://localhost:8545".to_string());
    let cursor_path = PathBuf::from(
        parse_arg_string(&args, "--cursor-file")
            .unwrap_or_else(|| "/var/lib/seal/relayer-cursor.json".to_string()),
    );
    let interval = Duration::from_secs(parse_arg::<u64>(&args, "--interval-secs").unwrap_or(10));
    let max_backoff =
        Duration::from_secs(parse_arg::<u64>(&args, "--max-backoff-secs").unwrap_or(30));
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let metrics_bind = parse_arg::<std::net::SocketAddr>(&args, "--metrics-bind");

    // Stellar chain submission is opt-in: all four --stellar-* args
    // must be present together, or the relayer leaves Stellar
    // withdrawals for another instance. Mixed states are rejected at
    // parse time so the operator catches typos at startup instead of
    // when the first WXLM withdrawal lands.
    let stellar = parse_stellar_config(&args)?;
    let solana = parse_solana_config(&args)?;

    Ok(Config {
        key_path,
        node_url,
        cursor_path,
        interval,
        max_backoff,
        dry_run,
        metrics_bind,
        stellar,
        solana,
    })
}

fn parse_solana_config(args: &[String]) -> Result<Option<SolanaConfig>, String> {
    let program_id = parse_arg_string(args, "--solana-program-id");
    let cluster = parse_arg_string(args, "--solana-cluster");
    let wallet = parse_arg_string(args, "--solana-wallet");
    let authority = parse_arg_string(args, "--solana-authority");
    let anchor_dir = parse_arg_string(args, "--anchor-program-dir");
    let mint_wsol = parse_arg_string(args, "--solana-mint-wsol");
    let vault_ata_wsol = parse_arg_string(args, "--solana-vault-ata-wsol");
    let mint_wusdc = parse_arg_string(args, "--solana-mint-wusdc");
    let vault_ata_wusdc = parse_arg_string(args, "--solana-vault-ata-wusdc");
    let any = program_id.is_some()
        || cluster.is_some()
        || wallet.is_some()
        || authority.is_some()
        || anchor_dir.is_some()
        || mint_wsol.is_some()
        || vault_ata_wsol.is_some()
        || mint_wusdc.is_some()
        || vault_ata_wusdc.is_some();
    if !any {
        return Ok(None);
    }
    let cluster = cluster.unwrap_or_else(|| "devnet".to_string());
    let anchor_dir = PathBuf::from(anchor_dir.unwrap_or_else(|| "bridges/solana".to_string()));
    let program_id =
        program_id.ok_or("--solana-program-id is required when any --solana-* flag is set")?;
    let wallet = wallet.ok_or("--solana-wallet is required when any --solana-* flag is set")?;
    let authority =
        authority.ok_or("--solana-authority is required when any --solana-* flag is set")?;
    // Per-token mint + vault must come paired. Half-config of a mint
    // is a typo, not a deliberate choice.
    if mint_wsol.is_some() != vault_ata_wsol.is_some() {
        return Err("--solana-mint-wsol and --solana-vault-ata-wsol must be set together".into());
    }
    if mint_wusdc.is_some() != vault_ata_wusdc.is_some() {
        return Err("--solana-mint-wusdc and --solana-vault-ata-wusdc must be set together".into());
    }
    if mint_wsol.is_none() && mint_wusdc.is_none() {
        return Err("at least one of --solana-mint-wsol / --solana-mint-wusdc must be set".into());
    }
    Ok(Some(SolanaConfig {
        program_id,
        cluster,
        wallet,
        authority,
        anchor_dir,
        mint_wsol,
        vault_ata_wsol,
        mint_wusdc,
        vault_ata_wusdc,
    }))
}

fn parse_stellar_config(args: &[String]) -> Result<Option<StellarConfig>, String> {
    let contract_id = parse_arg_string(args, "--stellar-contract-id");
    let network = parse_arg_string(args, "--stellar-network");
    let source = parse_arg_string(args, "--stellar-source");
    let contract_dir = parse_arg_string(args, "--stellar-contract-dir");
    let any =
        contract_id.is_some() || network.is_some() || source.is_some() || contract_dir.is_some();
    if !any {
        return Ok(None);
    }
    // Defaults that mirror docs/BRIDGE-TESTNET.md so the common case
    // is "--stellar-source <id>" + "--stellar-contract-id <id>" only.
    let network = network.unwrap_or_else(|| "testnet".to_string());
    let contract_dir = PathBuf::from(contract_dir.unwrap_or_else(|| "bridges/stellar".to_string()));
    let contract_id =
        contract_id.ok_or("--stellar-contract-id is required when any --stellar-* flag is set")?;
    let source = source.ok_or("--stellar-source is required when any --stellar-* flag is set")?;
    Ok(Some(StellarConfig {
        contract_id,
        network,
        source,
        contract_dir,
    }))
}

fn print_usage() {
    eprintln!();
    eprintln!("usage: seal-relayer --key <validator.json> [options]");
    eprintln!();
    eprintln!("required:");
    eprintln!("  --key <path>              validator keypair JSON (signs seal_bridgeMarkExecuted)");
    eprintln!();
    eprintln!("optional:");
    eprintln!("  --node <url>              seal-node RPC URL [http://localhost:8545]");
    eprintln!("  --cursor-file <path>      durable cursor [/var/lib/seal/relayer-cursor.json]");
    eprintln!("  --interval-secs <n>       seconds between polls [10]");
    eprintln!("  --max-backoff-secs <n>    max per-validator back-off window [30]");
    eprintln!(
        "  --dry-run                 log intended chain submissions without actually submitting"
    );
    eprintln!(
        "  --metrics-bind <ip:port>  enable Prometheus /metrics endpoint (default: disabled)"
    );
    eprintln!();
    eprintln!("stellar (opt-in — set ALL or NONE):");
    eprintln!("  --stellar-contract-id <id>   Soroban contract id");
    eprintln!("  --stellar-source <id>        stellar keys identity (funded G-key)");
    eprintln!("  --stellar-network <name>     stellar network alias [testnet]");
    eprintln!("  --stellar-contract-dir <p>   Soroban contract working dir [bridges/stellar]");
    eprintln!();
    eprintln!("solana (opt-in — set the four core flags + ≥1 token mint pair):");
    eprintln!("  --solana-program-id <id>     Anchor program id");
    eprintln!("  --solana-cluster <name>      anchor provider cluster [devnet]");
    eprintln!("  --solana-wallet <path>       funded relayer keypair JSON");
    eprintln!("  --solana-authority <pubkey>  bridge_state.authority pubkey");
    eprintln!("  --anchor-program-dir <p>     Anchor workspace dir [bridges/solana]");
    eprintln!("  --solana-mint-wsol <pubkey>      WSOL SPL mint  (pair with vault-ata)");
    eprintln!("  --solana-vault-ata-wsol <pubkey> WSOL vault ATA (PDA-owned)");
    eprintln!("  --solana-mint-wusdc <pubkey>     WUSDC SPL mint (pair with vault-ata)");
    eprintln!("  --solana-vault-ata-wusdc <pubkey> WUSDC vault ATA (PDA-owned)");
}

fn parse_arg_string(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn parse_arg<T: std::str::FromStr>(args: &[String], flag: &str) -> Option<T> {
    parse_arg_string(args, flag).and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_backoff_is_deterministic_and_bounded() {
        let vk = b"validator-pubkey-stub-32-bytes!!";
        assert_eq!(vk.len(), 32);
        let max = Duration::from_secs(30);
        // Same inputs → same output.
        let a = compute_backoff(vk, "wd_sol_42", max);
        let b = compute_backoff(vk, "wd_sol_42", max);
        assert_eq!(a, b);
        // Always within [0, max).
        for id in ["wd_sol_1", "wd_xlm_2", "wd_sol_99999", "wd_xlm_0"] {
            let d = compute_backoff(vk, id, max);
            assert!(d < max, "{id}: backoff {:?} exceeded max", d);
        }
    }

    #[test]
    fn compute_backoff_differs_per_validator() {
        // Two different validators on the same withdrawal id should
        // (almost always) get distinct delays. SHA3-256 collision
        // probability over 8 bytes is negligible, so a single
        // example is enough.
        let max = Duration::from_secs(30);
        let a = compute_backoff(&[0xAA; 32], "wd_sol_42", max);
        let b = compute_backoff(&[0xBB; 32], "wd_sol_42", max);
        assert_ne!(a, b);
    }

    #[test]
    fn compute_backoff_zero_max_returns_zero() {
        let d = compute_backoff(&[0; 32], "wd_sol_1", Duration::from_secs(0));
        assert_eq!(d, Duration::from_secs(0));
    }

    #[test]
    fn cursor_roundtrip() {
        let tmp = std::env::temp_dir().join("seal-relayer-cursor-test.json");
        let _ = std::fs::remove_file(&tmp);

        // Missing → default.
        let c = Cursor::load(&tmp);
        assert_eq!(c.last_seen_nonce, 0);

        // Save + reload.
        let c = Cursor {
            last_seen_nonce: 42,
        };
        c.save(&tmp).unwrap();
        let c2 = Cursor::load(&tmp);
        assert_eq!(c2.last_seen_nonce, 42);

        let _ = std::fs::remove_file(&tmp);
    }
}
