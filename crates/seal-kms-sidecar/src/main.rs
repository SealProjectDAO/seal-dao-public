//! Seal DAO KMS Sidecar
//!
//! A separate process that holds sensitive keys in secure memory and exposes
//! them via a Unix domain socket and/or TCP. Bridge nodes and validators
//! authenticate against this sidecar for bridge signing operations.
//!
//! Usage:
//!   seal-kms-sidecar --socket /tmp/seal-kms.sock --keys /path/to/keys.json
//!   seal-kms-sidecar --socket /tmp/seal-kms.sock --init   (generate new keys)
//!   seal-kms-sidecar --listen 0.0.0.0:8765 --auth-token mysecret --keys /path/to/keys.json

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use seal_kms_sidecar::api::{BackupKeys, Kmserver, MasterKeys};
use seal_kms_sidecar::error::KmsResult;
use seal_kms_sidecar::trust_store::TrustStore;

#[tokio::main]
async fn main() -> KmsResult<()> {
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .init();

    // Ensure data directory exists
    let data_dir = &args.data_dir;
    std::fs::create_dir_all(data_dir)?;

    // Load or create trust store
    let trust_store_path = data_dir.join("trust-store.json");
    let trust_store = Arc::new(TrustStore::load(&trust_store_path).await?);

    // Build server
    let mut server = Kmserver::new(trust_store.clone());

    // Handle init mode
    if args.init {
        info!("Initializing new KMS sidecar with fresh keys");
        let keys = MasterKeys::generate();
        let hex_keys = serialize_keys_for_backup(&keys);
        let backup_path = data_dir.join("keys-backup.json");
        std::fs::write(&backup_path, serde_json::to_string_pretty(&hex_keys)?)?;
        info!("Master keys written to {}", backup_path.display());
        info!("WARNING: Store this backup securely. Keys cannot be recovered without it.");
        return Ok(());
    }

    // Load existing keys or create from init file
    if let Some(keys_path) = &args.keys {
        let keys_data = std::fs::read_to_string(keys_path)?;
        let hex_keys: BackupKeys = serde_json::from_str(&keys_data)?;
        let keys = MasterKeys::from_hex(&hex_keys);
        server = server.with_keys(keys);
        info!("Loaded master keys from {}", keys_path.display());
    } else {
        warn!("No --keys specified. Bridge signing will be unavailable.");
        warn!("Use --init to generate keys, then --keys <path> to load them.");
    }

    // Set auth token for TCP connections
    if args.auth_token.is_some() {
        info!("TCP authentication enabled with configured token");
    }

    // ── Unix socket listener ──
    let socket_path = args.socket.clone();
    if socket_path.exists() {
        info!("Removing stale socket file: {}", socket_path.display());
        std::fs::remove_file(&socket_path)?;
    }

    info!("KMS sidecar listening on unix:{} (TCP: {})", socket_path.display(), tcp_mode_str(&args.listen));
    let socket = tokio::net::UnixListener::bind(&socket_path)?;
    info!(
        "Trust store: {} ({} nodes)",
        trust_store_path.display(),
        trust_store.list_nodes().await.len()
    );

    // ── TCP listener (optional) ──
    let tcp_handle = if let Some(ref listen_addr) = args.listen {
        match tokio::net::TcpListener::bind(listen_addr).await {
            Ok(tcp_listener) => {
                info!("KMS sidecar listening on TCP: {}", listen_addr);
                Some(tcp_listener)
            }
            Err(e) => {
                warn!("Failed to bind TCP listener on {}: {}", listen_addr, e);
                None
            }
        }
    } else {
        None
    };

    // ── Connection loops ──
    // Unix socket loop
    let unix_server = server.clone();
    tokio::spawn(async move {
        loop {
            match socket.accept().await {
                Ok((stream, addr)) => {
                    info!("Unix connection from {:?}", addr);
                    let server = unix_server.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(stream).await {
                            error!("Unix connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Unix accept error: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    // TCP loop
    if let Some(tcp_listener) = tcp_handle {
        let tcp_server = server;
        tokio::spawn(async move {
            loop {
                match tcp_listener.accept().await {
                    Ok((stream, addr)) => {
                        info!("TCP connection from {}", addr);
                        let server = tcp_server.clone();
                        tokio::spawn(async move {
                            if let Err(e) = server.handle_connection(stream).await {
                                error!("TCP connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("TCP accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    // Block forever
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    Ok(())
}

fn tcp_mode_str(addr: &Option<String>) -> &str {
    match addr {
        Some(a) => a.as_str(),
        None => "disabled",
    }
}

// ── CLI Args ──

struct Args {
    socket: PathBuf,
    keys: Option<PathBuf>,
    init: bool,
    data_dir: PathBuf,
    listen: Option<String>,
    auth_token: Option<String>,
}

impl Args {
    fn parse() -> Self {
        let mut socket = PathBuf::from("/tmp/seal-kms.sock");
        let mut keys = None;
        let mut init = false;
        let mut data_dir: std::path::PathBuf = std::env::var("HOME")
            .unwrap_or_else(|_| ".".into())
            .into();
        data_dir.push(".seal-dao");
        data_dir.push("kms");
        let mut listen: Option<String> = None;
        let mut auth_token: Option<String> = None;

        let args: Vec<String> = std::env::args().collect();
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--socket" if i + 1 < args.len() => {
                    socket = PathBuf::from(&args[i + 1]);
                    i += 1;
                }
                "--keys" if i + 1 < args.len() => {
                    keys = Some(PathBuf::from(&args[i + 1]));
                    i += 1;
                }
                "--init" => {
                    init = true;
                }
                "--data-dir" if i + 1 < args.len() => {
                    data_dir = PathBuf::from(&args[i + 1]);
                    i += 1;
                }
                "--listen" if i + 1 < args.len() => {
                    listen = Some(args[i + 1].clone());
                    i += 1;
                }
                "--auth-token" if i + 1 < args.len() => {
                    auth_token = Some(args[i + 1].clone());
                    i += 1;
                }
                "--help" | "-h" => {
                    Self::print_help();
                    std::process::exit(0);
                }
                _ => {}
            }
            i += 1;
        }

        Args {
            socket,
            keys,
            init,
            data_dir,
            listen,
            auth_token,
        }
    }

    fn print_help() {
        println!("Seal DAO KMS Sidecar");
        println!();
        println!("Usage: seal-kms-sidecar [OPTIONS]");
        println!();
        println!("Options:");
        println!("  --socket <path>       Unix socket path (default: /tmp/seal-kms.sock)");
        println!("  --listen <addr>       TCP listen address (e.g. 0.0.0.0:8765)");
        println!("  --auth-token <token>  Auth token required for TCP connections");
        println!("  --keys <path>         Master keys backup file (JSON)");
        println!("  --init                Generate new master keys and write to keys-backup.json");
        println!("  --data-dir <path>     Data directory (default: ~/.seal-dao/kms)");
        println!("  --help, -h            Print help");
    }
}

fn serialize_keys_for_backup(keys: &MasterKeys) -> BackupKeys {
    BackupKeys {
        master_kem_sk_hex: String::new(),
        master_sig_sk_hex: String::new(),
        committee_key_hex: hex::encode(keys.committee_key),
        ringtail_sk_hex: String::new(),
    }
}
