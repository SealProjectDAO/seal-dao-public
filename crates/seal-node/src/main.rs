//! Seal DAO Node
//!
//! Usage:
//!   cargo run -p seal-node                                              # 10 slots, mDNS discovery
//!   cargo run -p seal-node -- --slots 0                                 # Run forever
//!   cargo run -p seal-node -- --slots 0 --port 4001                     # Listen on port 4001
//!   cargo run -p seal-node -- --slots 0 --bootstrap-peers /dns4/ajax/tcp/4001
//!   cargo run -p seal-node -- --slots 0 --rpc-port 8545                 # Enable JSON-RPC (localhost only)
//!   cargo run -p seal-node -- --slots 0 --rpc-port 8545 --rpc-external  # Enable JSON-RPC on all interfaces
//!   cargo run -p seal-node -- --no-network                              # Local only
//!   cargo run -p seal-node -- --bootstrap-from-snapshot http://peer:8545 # Late-join via state-sync
//!   cargo run -p seal-node -- --validator-key validator-keys.json       # Persistent on-chain identity

use libp2p::Multiaddr;
use seal_consensus::config::ConsensusConfig;
use seal_node::disk::DiskStore;
use seal_node::network_node::NetworkNode;
use seal_node::rpc::{self, RpcConfig};
use seal_node::snapshot_bootstrap::{bootstrap_from_peer, HttpSnapshotRpc};
use seal_p2p::node::NodeConfig;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let no_network = args.iter().any(|a| a == "--no-network");
    let dev_faucet = args.iter().any(|a| a == "--dev-faucet");
    // Node defaults to testnet addresses (sealt1…) so the HRP matches
    // what `cargo run -p seal-cli -- wallet` creates by default. Pass
    // `--mainnet` for a `seal1…`-HRP node. Mixing the two across
    // wallet and node makes authenticated transfers silently debit a
    // ghost account.
    let mainnet = args.iter().any(|a| a == "--mainnet");
    if mainnet && dev_faucet {
        eprintln!(
            "error: --dev-faucet refused under --mainnet (unsigned mint to arbitrary addresses \
             must never reach a production chain)"
        );
        std::process::exit(2);
    }
    let slots = parse_arg(&args, "--slots").unwrap_or(10);
    let port = parse_arg::<u16>(&args, "--port").unwrap_or(4001);
    let rpc_port = parse_arg::<u16>(&args, "--rpc-port").unwrap_or(0);
    let rpc_external = args.iter().any(|a| a == "--rpc-external");
    let mut bootstrap_peers = parse_multi_arg(&args, "--bootstrap-peers");
    // `--bootstrap-peers-file <path>` reads newline-delimited
    // multiaddrs and appends them to the bootstrap list. Lines
    // starting with `#` and empty lines are skipped. Easier to
    // swap than re-passing N `--bootstrap-peers` flags when the
    // testnet seed list rotates.
    if let Some(path) = parse_arg::<String>(&args, "--bootstrap-peers-file") {
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let mut loaded = 0;
                for (lineno, raw) in contents.lines().enumerate() {
                    let line = raw.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    match line.parse::<Multiaddr>() {
                        Ok(ma) => {
                            bootstrap_peers.push(ma);
                            loaded += 1;
                        }
                        Err(e) => {
                            eprintln!(
                                "warning: {}:{} bad multiaddr {line:?}: {e}",
                                path,
                                lineno + 1
                            );
                        }
                    }
                }
                println!("Bootstrap peers file {path}: loaded {loaded} addresses");
            }
            Err(e) => {
                eprintln!("error: --bootstrap-peers-file {path}: {e}");
                std::process::exit(2);
            }
        }
    }
    let serve_namespaces = parse_multi_string(&args, "--serve");
    let data_dir = parse_arg::<String>(&args, "--data-dir").unwrap_or_else(|| "seal-data".into());
    // `--admin-address sealt1xyz` (repeatable) populates the
    // `RpcConfig::admin_addresses` set. When non-empty, admin-gated
    // RPCs (`seal_addBridgeObserver`, `seal_bridgeCouncilAdd/Remove`,
    // `seal_bridgePauseChain/Unpause`) require both a valid signature
    // and a caller address in this set. Empty (default) preserves
    // alpha-testnet bootstrap where any unsigned caller can hit them.
    let admin_addresses = parse_multi_string(&args, "--admin-address");
    if mainnet && admin_addresses.is_empty() {
        eprintln!(
            "warning: --mainnet without any --admin-address — bridge bootstrap RPCs \
             (seal_addBridgeObserver, seal_bridgeCouncil*, seal_bridgePauseChain) are \
             callable by any unsigned client. Set --admin-address sealt1… (repeat for each \
             operator key) to gate them."
        );
    }
    // `--allow-new-recipients` flips the recipient-new-account policy
    // from block (default) to allow. Bridge and faucet nodes set this
    // because they legitimately mint to fresh addresses; regular
    // wallet-facing nodes leave it off so accidental transfers to
    // typo'd addresses are caught at submit time.
    let allow_new_recipients = args.iter().any(|a| a == "--allow-new-recipients");
    // `--min-opening-balance <base-units>` requires fresh recipients
    // be funded with at least this many base units. 0 = disabled.
    // Independent of `--allow-new-recipients`: a faucet node
    // typically sets both — allow=true (fresh accounts ok) AND
    // min_opening_balance > 0 (so dust drips fail). The check runs
    // for native SEAL and per-token transfers alike.
    let min_opening_balance: u64 = parse_arg(&args, "--min-opening-balance").unwrap_or(0);
    // `--bootstrap-from-snapshot <peer-rpc-url>` runs the state-sync
    // late-joiner client at startup *before* the genesis-mint or
    // disk-replay paths. On success the node's BalanceStore is
    // populated from the peer's most recent snapshot — the operator
    // sees the snapshot's height/epoch/state_root and can confirm
    // it matches the peer's `seal_listSnapshots` output. Designed
    // for testnet validators joining after genesis.
    let bootstrap_snapshot_peer: Option<String> = parse_arg(&args, "--bootstrap-from-snapshot");

    // `--validator-key <path>` loads a `seal keygen` JSON keyfile
    // (`{signing_key, verifying_key, address, network, type}`) and
    // uses it as the validator's on-chain identity. Without the flag
    // the node generates a fresh keypair at every start — fine for
    // local dev, broken for testnet where operators need a stable
    // identity across reboots.
    // `--bridge-committee-key <64-hex-char>` configures the 32-byte
    // MAC key the seal-node uses to sign bridge unlock payloads. MUST
    // match the value the on-chain bridge programs were initialized
    // with (Anchor's `BridgeState::committee_key` on Solana,
    // `seal_bridge_key` storage key on Stellar); without alignment
    // every unlock claim is rejected with InvalidSignature on-chain.
    // Without the flag, withdrawal records land with
    // `committee_signature_hex = None` and the claim must be driven
    // through the future Ringtail multi-validator pipeline.
    let bridge_committee_key_hex: Option<String> = parse_arg(&args, "--bridge-committee-key");
    let mut bridge_committee_key: Option<[u8; 32]> = match bridge_committee_key_hex.as_deref() {
        Some(hex_str) => match hex::decode(hex_str) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                println!(
                    "Bridge committee key loaded ({} chars hex, matches on-chain MAC verifier)",
                    hex_str.len()
                );
                Some(k)
            }
            Ok(bytes) => {
                eprintln!(
                    "error: --bridge-committee-key expects 32 bytes (64 hex chars), got {} bytes",
                    bytes.len()
                );
                std::process::exit(2);
            }
            Err(e) => {
                eprintln!("error: --bridge-committee-key hex decode failed: {e}");
                std::process::exit(2);
            }
        },
        None => None,
    };
    // Persisted rotation takes precedence over the CLI flag so
    // `seal_bridgeRotateCommitteeKey` survives node restart. The
    // file lives in <data_dir>/bridge-committee-key.hex and is
    // written atomically by the rotate handler. Format: single
    // 64-char hex string; trailing whitespace is tolerated.
    let persisted_path = std::path::PathBuf::from(&data_dir).join("bridge-committee-key.hex");
    if persisted_path.is_file() {
        match std::fs::read_to_string(&persisted_path) {
            Ok(contents) => {
                let trimmed = contents.trim();
                match hex::decode(trimmed) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(&bytes);
                        if bridge_committee_key.map_or(false, |cli| cli != k) {
                            println!(
                                "Persisted bridge committee key at {} overrides --bridge-committee-key",
                                persisted_path.display()
                            );
                        } else {
                            println!(
                                "Persisted bridge committee key loaded from {}",
                                persisted_path.display()
                            );
                        }
                        bridge_committee_key = Some(k);
                    }
                    Ok(_) | Err(_) => {
                        eprintln!(
                            "warning: {} exists but is not a valid 32-byte hex string; falling back to CLI flag",
                            persisted_path.display()
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "warning: cannot read {}: {}; falling back to CLI flag",
                    persisted_path.display(),
                    e
                );
            }
        }
    }

    let validator_key_path: Option<String> = parse_arg(&args, "--validator-key");
    let validator_keypair = match validator_key_path.as_deref() {
        Some(path) => match load_validator_keypair(path, mainnet) {
            Ok(kp) => {
                println!(
                    "Validator identity loaded from {} (address {})",
                    path, kp.address
                );
                Some((kp.signing_key, kp.verifying_key))
            }
            Err(e) => {
                eprintln!("error: --validator-key {path}: {e}");
                std::process::exit(2);
            }
        },
        None => None,
    };

    // `--expect-committee-key-sha2 <64-hex>` is an opt-in startup
    // assertion: operators bake the last-known on-chain
    // committee_key_hash into the systemd unit, and seal-node warns
    // loudly if the locally-loaded key doesn't match. Catches
    // file-vs-flag drift in 5 s rather than after a withdrawal
    // fails on-chain.
    let expect_committee_key_sha2: Option<String> =
        parse_arg(&args, "--expect-committee-key-sha2").map(|s: String| s.to_ascii_lowercase());
    // `--bridge-poll-interval-secs <n>` (default 0 = off) drives an
    // in-process background poll loop that calls seal_pollBridges
    // every N seconds. Replaces the operator's cron-hits-RPC pattern.
    // Typical testnet value: 10-30. Set to 0 (default) to leave
    // polling driven entirely by external schedulers.
    let bridge_poll_interval_secs: u64 =
        parse_arg(&args, "--bridge-poll-interval-secs").unwrap_or(0);

    // `--bridge-withdrawal-fee <u64>` (P8/§4.2). SEAL base units
    // burned from caller's balance on every successful
    // seal_bridgeWithdraw. Refunded if the wrapped burn fails (e.g.
    // InsufficientWrapped). Default 0 = no fee (testnet acceptable);
    // mainnet typically sets ~0.01 SEAL = 10_000_000 base units.
    let bridge_withdrawal_fee: u64 = parse_arg(&args, "--bridge-withdrawal-fee").unwrap_or(0);

    // `--admin-threshold <n>` (P8/§4.3). M-of-N multisig
    // requirement for every admin-gated RPC. 0 or 1 = legacy
    // single-sig mode (caller in admin set is enough). >= 2
    // requires `admin_signatures: [{sender, signature}, ...]` in
    // the request params with at least `threshold - 1` additional
    // valid signatures from distinct admin set members.
    let admin_threshold: usize = parse_arg(&args, "--admin-threshold").unwrap_or(0);

    // Per-IP-per-group rate limiter knobs. Defaults
    // (default=120, expensive=20, admin=5) per minute are aimed at
    // shared-network production behavior; for a test stack that
    // bursts council seating + rotations + observer registration
    // back-to-back, admin=5 trips the rate limit on otherwise-valid
    // call sequences. docker-compose.testnet.yml bumps this to a
    // dev-appropriate value via `--rpm-admin`; leave the production
    // default alone when this flag isn't passed.
    let rpm_admin_override: Option<u64> = parse_arg(&args, "--rpm-admin");
    let rpm_default_override: Option<u64> = parse_arg(&args, "--rpm-default");
    let rpm_expensive_override: Option<u64> = parse_arg(&args, "--rpm-expensive");

    // `--bridge-kms-config <path>` (P8/§4.4). Optional JSON config
    // that loads the committee MAC key (and, when ringtail-singleton
    // is on, the Ringtail keypair) via the
    // `seal_bridge::keysource::CommitteeKeySource` /
    // `RingtailKeySource` trait. Falls back to direct CLI flags
    // when not supplied. The file shape:
    //   { "committee_mac_path": "/var/lib/seal/committee-mac.hex",
    //     "ringtail_keypair_path": "/var/lib/seal/ringtail.json" }
    // Either field may be absent. Future HSM/KMS adapters slot in
    // by implementing the same traits.
    let bridge_kms_config: Option<String> = parse_arg(&args, "--bridge-kms-config");
    if let Some(path) = &bridge_kms_config {
        match std::fs::read_to_string(path) {
            Ok(s) => match serde_json::from_str::<serde_json::Value>(&s) {
                Ok(v) => {
                    use seal_bridge::keysource::{CommitteeKeySource, FileKeySource};
                    let mac_path = v
                        .get("committee_mac_path")
                        .and_then(|x| x.as_str())
                        .map(std::path::PathBuf::from);
                    let kp_path = v
                        .get("ringtail_keypair_path")
                        .and_then(|x| x.as_str())
                        .map(std::path::PathBuf::from);
                    let src = FileKeySource::new(mac_path.clone(), kp_path);
                    if mac_path.is_some() {
                        match src.read_committee_mac() {
                            Ok(key) => {
                                bridge_committee_key = Some(key);
                                eprintln!(
                                    "[bridge-kms] loaded committee MAC via FileKeySource ({})",
                                    path
                                );
                            }
                            Err(e) => {
                                eprintln!("error: --bridge-kms-config committee MAC: {e}");
                                std::process::exit(2);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: --bridge-kms-config parse {}: {e}", path);
                    std::process::exit(2);
                }
            },
            Err(e) => {
                eprintln!("error: --bridge-kms-config read {}: {e}", path);
                std::process::exit(2);
            }
        }
    }

    // P1#5 layer 4 — multi-validator Ringtail orchestrator config.
    // All six flags must be present together or the orchestrator
    // path stays off (HMAC committee-of-1 default). The 6th flag
    // (--bridge-ringtail-prune-secs) and 7th
    // (--bridge-ringtail-max-idle-secs) have defaults (300/600).
    // Behind --features ringtail-singleton so the default build
    // stays lean.
    #[cfg(feature = "ringtail-singleton")]
    let ringtail_orchestrator_config = parse_ringtail_orchestrator_config(&args);

    // Pre-flight: collect every condition that makes the node
    // functional-but-mis-configured. None of these are fatal — the
    // node still starts — but they're easy to miss in a copy-pasted
    // systemd unit, and they all bite quietly in production
    // (silently-unsignable bridge withdrawals, open admin RPCs,
    // ephemeral validator identity). Print them as one block before
    // `Seal DAO Node` so they're the last thing the operator sees
    // before the noisy startup spam.
    let mut warnings: Vec<String> = Vec::new();
    if bridge_committee_key.is_none() {
        warnings.push(
            "no --bridge-committee-key and no <data_dir>/bridge-committee-key.hex present: \
             seal_bridgeWithdraw will land withdrawals with committee_signature_hex=null, \
             and the on-chain unlock claim cannot proceed until a key is installed via \
             seal_bridgeRotateCommitteeKey (council-gated)."
                .into(),
        );
    }
    if let (Some(key), Some(expected_hex)) = (&bridge_committee_key, &expect_committee_key_sha2) {
        if expected_hex.len() != 64 {
            warnings.push(format!(
                "--expect-committee-key-sha2 should be 64 hex chars (32 bytes); got {} \
                 — not enforcing",
                expected_hex.len()
            ));
        } else {
            // Round-trip through BridgeManager so this matches what
            // the /metrics + RPC surfaces report, byte-for-byte.
            let mut mgr = seal_bridge::BridgeManager::new(1);
            mgr.set_committee_key(*key);
            let actual_hex = mgr
                .committee_key_fingerprint_sha256()
                .map(hex::encode)
                .unwrap_or_default();
            if actual_hex != *expected_hex {
                warnings.push(format!(
                    "--expect-committee-key-sha2 mismatch: loaded key has sha2={} but \
                     expected={}. Either the on-chain key rotated and the systemd unit \
                     wasn't updated, OR the on-disk persistence file has drifted from \
                     the on-chain state. seal_bridgeRotateCommitteeKey can re-align both.",
                    actual_hex, expected_hex
                ));
            }
        }
    }
    if rpc_external && admin_addresses.is_empty() {
        warnings.push(
            "--rpc-external is set but no --admin-address: the bridge-bootstrap RPCs \
             (seal_addBridgeObserver, seal_bridgeCouncilAdd/Remove, seal_bridgePauseChain, \
             seal_bridgeRotateCommitteeKey) are reachable by any signed-or-unsigned caller \
             on every network interface. Add --admin-address sealt1… (repeat per operator) \
             before exposing this node."
                .into(),
        );
    }
    if validator_key_path.is_none() && rpc_port > 0 {
        warnings.push(
            "no --validator-key: seal-node generates a fresh ML-DSA identity at every start. \
             Acceptable for local dev; for testnet validators pass --validator-key <path> so \
             the on-chain pubkey stays stable across restarts (otherwise /health.is_validator \
             will flip-flop between false and 'newly-registered')."
                .into(),
        );
    }
    if mainnet && bootstrap_peers.is_empty() {
        warnings.push(
            "--mainnet with empty bootstrap-peer list: this node will only discover peers via \
             mDNS, which is LAN-local. Pass --bootstrap-peers or --bootstrap-peers-file."
                .into(),
        );
    }
    if !warnings.is_empty() {
        eprintln!();
        eprintln!("=== Pre-flight warnings ({}) ===", warnings.len());
        for w in &warnings {
            eprintln!("- {}", w);
        }
        eprintln!();
    }

    // P1#5 layer 4 — surface the Ringtail orchestrator config at
    // startup so operators can see at-a-glance whether they're in
    // HMAC committee-of-1 mode or multi-validator PQ mode. Actual
    // orchestrator construction + Arc-threading into RpcState +
    // network loop happens in follow-up commits per ADR-002.
    #[cfg(feature = "ringtail-singleton")]
    if let Some(cfg) = &ringtail_orchestrator_config {
        eprintln!(
            "[bridge] Ringtail orchestrator config loaded — party_id={} threshold={} committee_size={} (multi-validator mode)",
            cfg.party_id, cfg.threshold, cfg.committee_size,
        );
    }

    println!("=== Seal DAO Node ===\n");

    if no_network {
        run_local().await;
    } else {
        run_networked(
            slots,
            port,
            rpc_port,
            rpc_external,
            bootstrap_peers,
            serve_namespaces,
            data_dir,
            dev_faucet,
            mainnet,
            admin_addresses,
            allow_new_recipients,
            min_opening_balance,
            bootstrap_snapshot_peer,
            validator_keypair,
            bridge_committee_key,
            bridge_poll_interval_secs,
            bridge_withdrawal_fee,
            admin_threshold,
            rpm_admin_override,
            rpm_default_override,
            rpm_expensive_override,
            #[cfg(feature = "ringtail-singleton")]
            ringtail_orchestrator_config,
        )
        .await;
    }
}

/// Validator keypair loaded from a `seal keygen` JSON file, with the
/// derived bech32m address surfaced for logging.
struct LoadedValidatorKey {
    signing_key: seal_crypto::signature::SigningKey,
    verifying_key: seal_crypto::signature::VerifyingKey,
    address: String,
}

// Custom Debug that redacts the signing key — `SigningKey` deliberately
// does not implement `Debug` (secret material should never accidentally
// land in a log message), so we surface only the public address.
impl std::fmt::Debug for LoadedValidatorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedValidatorKey")
            .field("address", &self.address)
            .field("signing_key", &"<redacted>")
            .field("verifying_key", &"<redacted>")
            .finish()
    }
}

/// Parse a `seal keygen --output <path>` JSON file into the on-chain
/// keypair the consensus runner needs. The keyfile carries the
/// hex-encoded `signing_key` and `verifying_key`; the `network` and
/// `address` fields are checked against the running node's HRP so a
/// `sealt1…` (testnet) keyfile on a `--mainnet` node fails loud
/// rather than silently signing on the wrong chain.
fn load_validator_keypair(path: &str, mainnet: bool) -> Result<LoadedValidatorKey, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read: {e}"))?;
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse: {e}"))?;

    let sk_hex = json
        .get("signing_key")
        .and_then(|v| v.as_str())
        .ok_or("missing 'signing_key' field")?;
    let vk_hex = json
        .get("verifying_key")
        .and_then(|v| v.as_str())
        .ok_or("missing 'verifying_key' field")?;

    let sk_bytes = hex::decode(sk_hex).map_err(|e| format!("signing_key hex: {e}"))?;
    let vk_bytes = hex::decode(vk_hex).map_err(|e| format!("verifying_key hex: {e}"))?;

    let signing_key = seal_crypto::signature::SigningKey::from_bytes(&sk_bytes)
        .map_err(|e| format!("invalid signing_key: {e:?}"))?;
    let verifying_key = seal_crypto::signature::VerifyingKey::from_bytes(&vk_bytes)
        .map_err(|e| format!("invalid verifying_key: {e:?}"))?;

    // Cross-check the keyfile's HRP against the running node so a
    // testnet identity can't be used on a mainnet node by mistake.
    if let Some(file_network) = json.get("network").and_then(|v| v.as_str()) {
        let expect = if mainnet { "mainnet" } else { "testnet" };
        if file_network != expect {
            return Err(format!(
                "network mismatch: keyfile is for '{file_network}' but node is running \
                 in '{expect}' mode (toggle --mainnet to match)"
            ));
        }
    }

    let address = seal_crypto::address::SealAddress::from_verifying_key(&verifying_key, !mainnet)
        .to_string_encoding();

    Ok(LoadedValidatorKey {
        signing_key,
        verifying_key,
        address,
    })
}

fn parse_arg<T: std::str::FromStr>(args: &[String], flag: &str) -> Option<T> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
}

/// Build the bridge Ringtail orchestrator config from CLI flags.
/// Returns `None` if the operator hasn't opted in (any of the
/// required flags missing); returns `Some(config)` only when the
/// full set is present + valid. Per-flag validation lives inside
/// `seal_bridge::ringtail_orchestrator::RingtailBridgeOrchestrator
/// ::new` — this function just assembles the inputs and fails fast
/// with a clear message on parse-level errors (bad hex, missing
/// file).
#[cfg(feature = "ringtail-singleton")]
fn parse_ringtail_orchestrator_config(
    args: &[String],
) -> Option<seal_bridge::ringtail_orchestrator::OrchestratorConfig> {
    let keypair_path: Option<String> = parse_arg(args, "--bridge-ringtail-keypair-file");
    let mac_key_hex: Option<String> = parse_arg(args, "--bridge-ringtail-mac-key-hex");
    let party_id: Option<usize> = parse_arg(args, "--bridge-ringtail-party-id");
    let threshold: Option<usize> = parse_arg(args, "--bridge-ringtail-threshold");
    let committee_size: Option<usize> = parse_arg(args, "--bridge-ringtail-committee-size");

    // Each --bridge-ringtail-* family is opt-in; if NONE is present
    // the orchestrator stays off (HMAC default path). Half-config
    // is rejected with a fatal error so operators catch typos at
    // boot instead of when the first withdrawal lands.
    let any = keypair_path.is_some()
        || mac_key_hex.is_some()
        || party_id.is_some()
        || threshold.is_some()
        || committee_size.is_some();
    if !any {
        return None;
    }
    let keypair_path = keypair_path
        .unwrap_or_else(|| {
            eprintln!("error: --bridge-ringtail-keypair-file is required when any --bridge-ringtail-* flag is set");
            std::process::exit(2);
        });
    let mac_key_hex = mac_key_hex.unwrap_or_else(|| {
        eprintln!("error: --bridge-ringtail-mac-key-hex is required when any --bridge-ringtail-* flag is set");
        std::process::exit(2);
    });
    if mac_key_hex.len() != 64 {
        eprintln!(
            "error: --bridge-ringtail-mac-key-hex must be 64 hex chars (32 bytes); got {}",
            mac_key_hex.len()
        );
        std::process::exit(2);
    }
    let mac_key = hex::decode(&mac_key_hex).unwrap_or_else(|e| {
        eprintln!("error: --bridge-ringtail-mac-key-hex hex decode failed: {e}");
        std::process::exit(2);
    });
    let party_id = party_id.unwrap_or_else(|| {
        eprintln!("error: --bridge-ringtail-party-id <n> is required");
        std::process::exit(2);
    });
    let threshold = threshold.unwrap_or_else(|| {
        eprintln!("error: --bridge-ringtail-threshold <n> is required");
        std::process::exit(2);
    });
    let committee_size = committee_size.unwrap_or_else(|| {
        eprintln!("error: --bridge-ringtail-committee-size <n> is required");
        std::process::exit(2);
    });

    let keypair =
        seal_bridge::ringtail::RingtailKeypair::load_from_file(std::path::Path::new(&keypair_path))
            .unwrap_or_else(|e| {
                eprintln!("error: load --bridge-ringtail-keypair-file: {e}");
                std::process::exit(2);
            });

    Some(seal_bridge::ringtail_orchestrator::OrchestratorConfig {
        party_id,
        sk_collapsed_bytes: keypair.sk_collapsed_bytes,
        public_params: keypair.public_params,
        mac_key,
        threshold,
        committee_size,
    })
}

fn parse_multi_string(args: &[String], flag: &str) -> HashSet<String> {
    let mut result = HashSet::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if let Some(val) = args.get(i + 1) {
                result.insert(val.clone());
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    result
}

fn parse_multi_arg(args: &[String], flag: &str) -> Vec<Multiaddr> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if let Some(val) = args.get(i + 1) {
                if let Ok(addr) = val.parse() {
                    result.push(addr);
                } else {
                    eprintln!("Invalid multiaddr: {}", val);
                }
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    result
}

// CLI-arg passthrough; not real coupling. Silenced rather than
// shoehorned into a struct because the call site is the sole `main`
// dispatch and adding a struct just to satisfy lint hurts readability.
#[allow(clippy::too_many_arguments)]
async fn run_networked(
    slots: u64,
    port: u16,
    rpc_port: u16,
    rpc_external: bool,
    bootstrap_peers: Vec<Multiaddr>,
    serve_namespaces: HashSet<String>,
    data_dir: String,
    dev_faucet: bool,
    mainnet: bool,
    admin_addresses: HashSet<String>,
    allow_new_recipients: bool,
    min_opening_balance: u64,
    bootstrap_snapshot_peer: Option<String>,
    validator_keypair: Option<(
        seal_crypto::signature::SigningKey,
        seal_crypto::signature::VerifyingKey,
    )>,
    bridge_committee_key: Option<[u8; 32]>,
    bridge_poll_interval_secs: u64,
    bridge_withdrawal_fee: u64,
    admin_threshold: usize,
    rpm_admin_override: Option<u64>,
    rpm_default_override: Option<u64>,
    rpm_expensive_override: Option<u64>,
    #[cfg(feature = "ringtail-singleton")] ringtail_orchestrator_config: Option<
        seal_bridge::ringtail_orchestrator::OrchestratorConfig,
    >,
) {
    let config = ConsensusConfig::default();
    let slot_duration = config.slot_duration;

    let node_config = NodeConfig {
        listen_port: port,
        bootstrap_peers,
        pq_encryption: false,
    };

    // Pin the validator identity from --validator-key if supplied;
    // otherwise NetworkNode::start generates a fresh keypair (good
    // enough for local dev, restart-unsafe for testnet — see TESTNET.md
    // "Identity persistence").
    let start_result = match validator_keypair {
        Some((sk, vk)) => NetworkNode::start_with_keypair(config, node_config, sk, vk).await,
        None => NetworkNode::start(config, node_config).await,
    };
    let mut node = match start_result {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Failed to start network node: {}", e);
            return;
        }
    };

    let peer_id = node.peer_id;

    // State-sync late-joiner path takes priority over genesis mint:
    // a node that's joining an existing testnet shouldn't overlay
    // the genesis allocations on top of the snapshot it just
    // received from a peer. If `--bootstrap-from-snapshot` was
    // passed, run the client; on success, skip the genesis-mint
    // block. On failure (peer unreachable, snapshot pruned mid-
    // stream, hash mismatch), bail out with a clear error rather
    // than silently falling back to genesis — silently mixing
    // genesis + partial snapshot would diverge state from peers.
    let bootstrapped_from_snapshot = if let Some(peer_url) = bootstrap_snapshot_peer.as_ref() {
        println!("Bootstrap-from-snapshot: connecting to {peer_url}…");
        let rpc_client = HttpSnapshotRpc {
            peer_url: peer_url.clone(),
        };
        match bootstrap_from_peer(&rpc_client) {
            Ok(outcome) => {
                println!(
                    "Bootstrap-from-snapshot: replayed {} bytes across {} chunk(s)",
                    outcome.total_bytes, outcome.chunk_count
                );
                println!(
                    "  height = {}, epoch = {}, state_root = {}",
                    outcome.height, outcome.epoch, outcome.state_root_hex
                );
                node.runner.balances = outcome.balances;
                println!(
                    "Bootstrap-from-snapshot: balances populated, {} account(s) live",
                    node.runner.balances.account_count()
                );
                true
            }
            Err(e) => {
                eprintln!(
                    "Bootstrap-from-snapshot failed: {e}\n\
                     Refusing to fall back to genesis — that would diverge state from peers.\n\
                     Pick a different peer or omit --bootstrap-from-snapshot to start from genesis."
                );
                std::process::exit(3);
            }
        }
    } else {
        false
    };

    // Initialize genesis balances (30/20/15/15/10/10 distribution).
    // Only when we're not late-joining via state-sync.
    if !bootstrapped_from_snapshot {
        use seal_token::params;
        let balances = &mut node.runner.balances;
        let _ = balances.mint("seal1validators", params::genesis::VALIDATOR_POOL);
        let _ = balances.mint("seal1treasury", params::genesis::COMMUNITY_TREASURY);
        let _ = balances.mint("seal1team", params::genesis::TEAM_ALLOCATION);
        let _ = balances.mint("seal1ecosystem", params::genesis::ECOSYSTEM_FUND);
        let _ = balances.mint("seal1public", params::genesis::PUBLIC_DISTRIBUTION);
        let _ = balances.mint("seal1reserve", params::genesis::RESERVE);
        println!(
            "Genesis: {} SEAL minted ({} accounts)",
            balances.total_supply() / 1_000_000_000,
            balances.account_count()
        );
    }

    let node = Arc::new(Mutex::new(node));

    println!("Peer ID: {}", peer_id);
    println!("P2P port: {}", port);
    if rpc_port > 0 {
        if rpc_external {
            println!(
                "RPC: http://0.0.0.0:{} (all interfaces — test/bridge mode)",
                rpc_port
            );
        } else {
            println!("RPC: http://127.0.0.1:{} (localhost only)", rpc_port);
        }
    }
    if !serve_namespaces.is_empty() {
        println!("Serving: {:?}", serve_namespaces);
    }
    println!("Data dir: {}", data_dir);
    println!("Listening for peers via mDNS...");
    if slots == 0 {
        println!("Running indefinitely (Ctrl+C to stop)\n");
    } else {
        println!("Running for {} slots\n", slots);
    }

    // Build BridgeManager once and share it across (a) the RPC layer,
    // (b) the multi-validator Ringtail orchestrator's network loop,
    // and (c) the signing-signal start_signing tokio task. All three
    // need to mutate the same instance; passing it via Arc<Mutex<…>>
    // from here keeps ownership obvious and avoids any "which bridge
    // is this RPC writing to?" foot-gun.
    //
    // The default required_confirmations = 1 lets bridge-e2e.sh
    // round-trip without waiting 32 Solana slots; tune up via a
    // future --bridge-confirmations flag.
    let mut bridge = seal_bridge::BridgeManager::new(1);
    if let Some(k) = bridge_committee_key {
        bridge.set_committee_key(k);
    }
    let bridge = Arc::new(Mutex::new(bridge));
    // Hand the bridge Arc to the NetworkNode so the receive loop's
    // Round2Complete + race-loser-Aggregate paths can call
    // attach_committee_signature without a separate plumbing dance.
    node.lock().await.attach_bridge(Arc::clone(&bridge));

    // P1#5 layer 4 — construct the multi-validator Ringtail
    // orchestrator (when the operator opted in) AND wire the
    // signing-signal channel so every new pending withdrawal kicks
    // off Round1 broadcasting via the orchestrator. Held in an
    // Arc<Mutex<…>> so the RPC layer (session count read) and the
    // network loop (envelope routing) can both reach it.
    #[cfg(feature = "ringtail-singleton")]
    let ringtail_orchestrator = match ringtail_orchestrator_config {
        Some(cfg) => match seal_bridge::ringtail_orchestrator::RingtailBridgeOrchestrator::new(cfg)
        {
            Ok(orch) => Some(Arc::new(Mutex::new(orch))),
            Err(e) => {
                eprintln!("error: build Ringtail orchestrator: {e}");
                std::process::exit(2);
            }
        },
        None => None,
    };
    // §3 of the no-excuse-bordel plan — restart-resume of in-flight
    // signing sessions. Open the on-disk store under
    // `<data_dir>/ringtail-sessions/` and replay every persisted
    // snapshot into the orchestrator. Each snapshot carries enough
    // state (session round1/round2 messages + the validator's own
    // round1 randomness) that the protocol can resume from where it
    // left off.
    #[cfg(feature = "ringtail-singleton")]
    let ringtail_session_store = if ringtail_orchestrator.is_some() {
        match seal_bridge::ringtail_store::RingtailSessionStore::open(
            PathBuf::from(&data_dir).join("ringtail-sessions"),
        ) {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                eprintln!(
                    "error: open ringtail session store at {}/ringtail-sessions: {e}",
                    data_dir
                );
                std::process::exit(2);
            }
        }
    } else {
        None
    };
    #[cfg(feature = "ringtail-singleton")]
    if let (Some(orch), Some(store)) = (
        ringtail_orchestrator.as_ref(),
        ringtail_session_store.as_ref(),
    ) {
        match store.load_all() {
            Ok(snaps) => {
                let restored = snaps.len();
                let mut o = orch.lock().await;
                for snap in snaps {
                    if let Err(e) = o.restore_session(snap.clone()) {
                        eprintln!(
                            "[bridge-ringtail] restore_session({}) failed: {e}",
                            snap.withdrawal_id
                        );
                    }
                }
                if restored > 0 {
                    eprintln!(
                        "[bridge-ringtail] restored {restored} in-flight signing session(s) from {:?}",
                        store.dir()
                    );
                }
            }
            Err(e) => {
                eprintln!("[bridge-ringtail] load_all session store: {e}");
            }
        }
    }
    #[cfg(feature = "ringtail-singleton")]
    if let Some(orch) = ringtail_orchestrator.as_ref() {
        node.lock()
            .await
            .attach_ringtail_orchestrator(Arc::clone(orch));
    }
    #[cfg(feature = "ringtail-singleton")]
    if let Some(store) = ringtail_session_store.as_ref() {
        node.lock()
            .await
            .attach_ringtail_session_store(Arc::clone(store));
    }

    // P1#5 layer 4 — periodic prune of abandoned signing sessions.
    // Defaults match ADR-002: tick every 300s, drop sessions idle
    // beyond 600s. Operators override via `--bridge-ringtail-prune-
    // secs <n>` and `--bridge-ringtail-max-idle-secs <n>`. Cheap
    // (HashMap walk over a typically-empty map) so a tight default
    // interval is fine.
    #[cfg(feature = "ringtail-singleton")]
    if let Some(orch) = ringtail_orchestrator.as_ref() {
        use tracing::warn as log_warn;
        let prune_secs: u64 = parse_arg(
            &std::env::args().collect::<Vec<_>>(),
            "--bridge-ringtail-prune-secs",
        )
        .unwrap_or(300);
        let max_idle_secs: u64 = parse_arg(
            &std::env::args().collect::<Vec<_>>(),
            "--bridge-ringtail-max-idle-secs",
        )
        .unwrap_or(600);
        let task_orch = Arc::clone(orch);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(prune_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await; // phase first tick one period in
            loop {
                ticker.tick().await;
                let dropped = task_orch
                    .lock()
                    .await
                    .prune_stale_sessions(std::time::Duration::from_secs(max_idle_secs));
                if !dropped.is_empty() {
                    log_warn!(
                        count = dropped.len(),
                        max_idle_secs = max_idle_secs,
                        "pruned stale bridge-ringtail signing sessions",
                    );
                }
            }
        });
    }

    // P1#5 layer 4 — wire the signing-signal channel from BridgeManager
    // to the orchestrator. Every successful `seal_bridgeWithdraw` emits
    // a `WithdrawalReadyForSigning` onto this channel; the task below
    // pulls each one off, kicks `start_signing` on the orchestrator,
    // and broadcasts the resulting Round1 envelope over gossipsub so
    // the rest of the validator set can join the signing round.
    //
    // Buffer size 256 matches `BridgeManager::set_signing_signal_sender`
    // semantics: try_send is used on the burn path so a saturated
    // channel surfaces as an eprintln (we don't want the burn to block
    // on a stuck orchestrator). Under normal load the queue stays
    // empty — 256 is just a paranoia buffer for a withdrawal storm.
    #[cfg(feature = "ringtail-singleton")]
    if let Some(orch) = ringtail_orchestrator.as_ref() {
        use tracing::{info as log_info, warn as log_warn};
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<seal_bridge::WithdrawalReadyForSigning>(256);
        bridge.lock().await.set_signing_signal_sender(tx);
        let task_orch = Arc::clone(orch);
        let task_store = ringtail_session_store.as_ref().map(Arc::clone);
        // Cloneable mpsc broadcaster — see NetworkNode::ringtail_broadcaster
        // for why we don't hold an Arc<Mutex<NetworkNode>> here.
        let broadcaster = node.lock().await.ringtail_broadcaster();
        log_info!("[bridge-ringtail] signing-signal channel + start_signing task armed");
        tokio::spawn(async move {
            while let Some(signal) = rx.recv().await {
                let wd_id = signal.withdrawal_id.clone();
                let (env_opt, snap) = {
                    let mut o = task_orch.lock().await;
                    let env = match o.start_signing(
                        signal.withdrawal_id.clone(),
                        signal.dest_chain.clone(),
                        &signal.dest_address,
                        signal.amount,
                        signal.nonce,
                    ) {
                        Ok(Some(env)) => Some(env),
                        Ok(None) => {
                            // Idempotent re-entry — orchestrator
                            // already has a session for this id.
                            None
                        }
                        Err(e) => {
                            log_warn!(
                                error = %e,
                                wd_id = %wd_id,
                                "start_signing failed",
                            );
                            None
                        }
                    };
                    let snap = o.export_session(&wd_id);
                    (env, snap)
                };
                // Persist the newly-opened session so a restart
                // immediately after start_signing doesn't lose the
                // committed Round1 randomness.
                if let (Some(store), Some(snap)) = (task_store.as_ref(), snap) {
                    if let Err(e) = store.save(&snap) {
                        log_warn!(error = %e, wd_id = %wd_id, "persist start_signing snapshot");
                    }
                }
                if let Some(env) = env_opt {
                    match serde_json::to_vec(&env) {
                        Ok(bytes) => {
                            if let Err(e) = broadcaster.round1(bytes).await {
                                log_warn!(
                                    error = %e,
                                    wd_id = %wd_id,
                                    "broadcast bridge-ringtail Round1 envelope",
                                );
                            }
                        }
                        Err(e) => log_warn!(
                            error = %e,
                            wd_id = %wd_id,
                            "serialize bridge-ringtail Round1 envelope",
                        ),
                    }
                }
            }
            log_warn!(
                "[bridge-ringtail] signing-signal channel closed; start_signing task exiting"
            );
        });
    }

    // Start RPC server if enabled
    if rpc_port > 0 {
        if dev_faucet {
            println!(
                "Dev faucet enabled: POST seal_faucet {{\"address\":\"seal1…\"}} — do NOT enable on mainnet."
            );
        }
        if !admin_addresses.is_empty() {
            println!(
                "Admin gating: {} address(es) authorized for bridge bootstrap RPCs",
                admin_addresses.len()
            );
        }
        if allow_new_recipients {
            println!(
                "Recipient policy: allow-mode (transfers to new accounts pass without confirm_new_recipient)"
            );
        }
        if min_opening_balance > 0 {
            println!(
                "Min opening balance: {} base units (transfers to new accounts must fund at least this much)",
                min_opening_balance
            );
        }
        let rpc_node = Arc::clone(&node);
        let rpc_bridge = Arc::clone(&bridge);
        #[cfg(feature = "ringtail-singleton")]
        let rpc_orchestrator = ringtail_orchestrator.as_ref().map(Arc::clone);
        // Capture the rpm defaults once so we can mix per-field
        // overrides with the rest of RpcConfig::default() in the
        // struct expression below.
        let rpm_defaults = RpcConfig::default();
        let rpc_config = RpcConfig {
            served_namespaces: serve_namespaces,
            dev_faucet,
            testnet: !mainnet,
            admin_addresses,
            allow_new_recipients,
            min_opening_balance,
            bridge_withdrawal_fee,
            admin_threshold,
            rpm_default: rpm_default_override.unwrap_or(rpm_defaults.rpm_default),
            rpm_expensive: rpm_expensive_override.unwrap_or(rpm_defaults.rpm_expensive),
            rpm_admin: rpm_admin_override.unwrap_or(rpm_defaults.rpm_admin),
            ..RpcConfig::default()
        };
        let rpc_data_dir = PathBuf::from(&data_dir);
        tokio::spawn(async move {
            rpc::start_rpc_server(
                rpc_node,
                rpc_config,
                rpc_port,
                rpc_external,
                rpc_bridge,
                Some(rpc_data_dir),
                bridge_poll_interval_secs,
                #[cfg(feature = "ringtail-singleton")]
                rpc_orchestrator,
            )
            .await;
        });
    }

    // Open disk store for persistence. If prior blocks exist we replay
    // them FIRST and skip the demo seed — otherwise the seed's
    // `CREATE TABLE users` collides with block 1's already-recorded
    // schema, and the replay dies at block 1 with
    // `SQL replay failed: table already exists: users`.
    let (disk_store, had_prior_chain) = match DiskStore::open(&PathBuf::from(&data_dir)) {
        Ok(store) => {
            let stored_height = store.latest_height().unwrap_or(0);
            let mut replayed_any = false;
            if stored_height > 0 {
                println!("Found {} blocks on disk, replaying...", stored_height);
                let mut n = node.lock().await;
                let mut replayed = 0u64;
                for h in 1..=stored_height {
                    match store.get_block(h) {
                        Ok(Some(block)) => match n.runner.replay_block(&block) {
                            Ok(_) => replayed += 1,
                            Err(e) => {
                                eprintln!("Replay failed at block {}: {}", h, e);
                                break;
                            }
                        },
                        Ok(None) => {
                            eprintln!("Block {} missing from disk, stopping replay", h);
                            break;
                        }
                        Err(e) => {
                            eprintln!("Failed to read block {}: {}", h, e);
                            break;
                        }
                    }
                }
                if replayed > 0 {
                    println!(
                        "Replayed {} blocks, height={}, state={}",
                        replayed,
                        n.height(),
                        n.state_root()
                    );
                    replayed_any = true;
                }
                drop(n);
            }
            (Some(store), replayed_any)
        }
        Err(e) => {
            eprintln!("Warning: disk persistence disabled ({})", e);
            (None, false)
        }
    };

    // Demo seed: only on a fresh chain. Block 1 records this tx; on
    // subsequent runs the replay above reconstitutes the same state.
    if !had_prior_chain {
        let mut n = node.lock().await;
        if let Err(e) = n.submit_sql(
            "CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL, balance BIGINT)",
        ) {
            eprintln!("Failed to create table: {}", e);
            return;
        }
        if let Err(e) =
            n.submit_sql("INSERT INTO users (id, name, balance) VALUES (1, 'alice', 1000)")
        {
            eprintln!("Failed to insert user alice: {}", e);
            return;
        }
        if let Err(e) = n.submit_sql("INSERT INTO users (id, name, balance) VALUES (2, 'bob', 500)")
        {
            eprintln!("Failed to insert user bob: {}", e);
            return;
        }
        println!("Deployed schema + inserted 2 users");
    }

    // Run consensus
    println!("\n--- Running consensus ---");
    let mut slot: u64 = 0;
    loop {
        if slots > 0 && slot >= slots {
            break;
        }
        {
            let mut n = node.lock().await;
            if let Some(block) = n.tick().await {
                println!(
                    "Slot {}: Block #{} produced ({} txs, state: {})",
                    slot,
                    block.block.header.height,
                    block.block.transactions.len(),
                    block.block.header.state_root,
                );
                // Persist block to disk
                if let Some(ref store) = disk_store {
                    if let Err(e) = store.put_block(&block.block) {
                        eprintln!("Warning: failed to persist block: {}", e);
                    }
                }
            }
        }
        tokio::time::sleep(slot_duration).await;
        slot = slot.wrapping_add(1);
    }

    // Query (only when slots are finite)
    let n = node.lock().await;
    println!("\n--- Query results ---");
    // Need to drop and reacquire for mutable access
    drop(n);
    let mut n = node.lock().await;
    match n.query_sql("SELECT * FROM users") {
        Ok(result) => {
            println!("users: {} rows", result.rows.len());
            for row in &result.rows {
                println!("  {:?}", row.values);
            }
        }
        Err(e) => {
            eprintln!("Failed to query users: {}", e);
        }
    }

    println!("\nChain height: {}", n.height());
    println!("State root: {}", n.state_root());
    println!("Received blocks from peers: {}", n.received_block_count());
    println!("\n=== Done ===");
}

async fn run_local() {
    use seal_node::state::NodeState;

    let mut node = NodeState::new();
    println!(
        "Node address: {} (local mode, no P2P)\n",
        node.node_address()
    );

    if let Err(e) = node.execute_sql(
        "CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL, balance BIGINT)",
    ) {
        eprintln!("Failed to create table: {}", e);
        return;
    }
    if let Err(e) =
        node.execute_sql("INSERT INTO users (id, name, balance) VALUES (1, 'alice', 1000)")
    {
        eprintln!("Failed to insert user alice: {}", e);
        return;
    }
    if let Err(e) = node.execute_sql("INSERT INTO users (id, name, balance) VALUES (2, 'bob', 500)")
    {
        eprintln!("Failed to insert user bob: {}", e);
        return;
    }

    let block = node.produce_block();
    println!(
        "Block #{}: {} txs, state: {}",
        block.header.height,
        block.transactions.len(),
        block.header.state_root
    );

    match node.execute_sql("SELECT * FROM users") {
        Ok(result) => println!("users: {} rows", result.rows.len()),
        Err(e) => eprintln!("Failed to query users: {}", e),
    }

    println!("\n=== Done ===");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write a synthetic keyfile that matches `seal keygen --output`.
    fn write_keyfile(dir: &std::path::Path, name: &str, network: &str) -> std::path::PathBuf {
        let (sk, vk) = seal_crypto::signature::SigningKey::generate();
        let testnet = network == "testnet";
        let address = seal_crypto::address::SealAddress::from_verifying_key(&vk, testnet)
            .to_string_encoding();
        let body = serde_json::json!({
            "type": "ml-dsa-65",
            "network": network,
            "address": address,
            "signing_key": hex::encode(sk.to_bytes()),
            "verifying_key": hex::encode(vk.to_bytes()),
        });
        let path = dir.join(name);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(body.to_string().as_bytes())
            .unwrap();
        path
    }

    #[test]
    fn load_validator_keypair_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keyfile(dir.path(), "key.json", "testnet");
        let loaded = load_validator_keypair(path.to_str().unwrap(), false).unwrap();
        assert!(loaded.address.starts_with("sealt1"));
        // The address derived from the loaded verifying_key must match
        // the keyfile's stored address (the round-trip we're really pinning).
        let recomputed =
            seal_crypto::address::SealAddress::from_verifying_key(&loaded.verifying_key, true)
                .to_string_encoding();
        assert_eq!(loaded.address, recomputed);
    }

    #[test]
    fn load_validator_keypair_rejects_hrp_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keyfile(dir.path(), "key.json", "testnet");
        // mainnet=true → expect 'mainnet' in the keyfile, get 'testnet'.
        let err = load_validator_keypair(path.to_str().unwrap(), true).unwrap_err();
        assert!(
            err.contains("network mismatch"),
            "expected HRP mismatch error, got: {err}"
        );
    }

    #[test]
    fn load_validator_keypair_rejects_missing_file() {
        let err =
            load_validator_keypair("/tmp/seal-no-such-file-xyz-12345.json", false).unwrap_err();
        assert!(err.starts_with("read:"), "expected read error, got: {err}");
    }

    #[test]
    fn load_validator_keypair_rejects_missing_signing_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partial.json");
        std::fs::write(&path, r#"{"verifying_key":"00"}"#).unwrap();
        let err = load_validator_keypair(path.to_str().unwrap(), false).unwrap_err();
        assert!(err.contains("'signing_key'"));
    }
}
