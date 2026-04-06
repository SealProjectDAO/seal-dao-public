//! Tauri commands — native Rust crypto operations for the wallet UI.
//!
//! Each function here becomes a Tauri IPC command that the Svelte frontend
//! can call. All crypto (ML-DSA signing, SHA3 hashing, key derivation)
//! happens in Rust — the frontend never sees private keys.
//!
//! State is managed via a thread-local wallet instance. In production,
//! this would use Tauri's managed state with proper locking.

use seal_wallet::keystore::Wallet;
use seal_wallet::mnemonic::Seed;
use std::cell::RefCell;

thread_local! {
    /// Current wallet state. In production, use Tauri's managed state.
    static WALLET: RefCell<Option<WalletState>> = const { RefCell::new(None) };
}

struct WalletState {
    wallet: Wallet,
    /// Seed bytes stored separately (Seed doesn't impl Clone).
    seed_bytes: [u8; 32],
}

// --- Wallet lifecycle ---

/// Create a new random wallet. Returns WalletInfo as JSON.
// #[tauri::command]
pub fn create_wallet(testnet: bool) -> Result<String, String> {
    let seed = Seed::generate();
    let seed_hex = seed.to_hex();
    let seed_bytes = hex::decode(&seed_hex).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed_bytes);

    let wallet = Wallet::from_seed(seed, testnet);
    let info = wallet.info();
    let json = serde_json::to_string_pretty(&info)
        .map_err(|e| format!("serialization failed: {}", e))?;

    WALLET.with(|w| {
        *w.borrow_mut() = Some(WalletState {
            wallet,
            seed_bytes: arr,
        });
    });

    Ok(json)
}

/// Import a wallet from a hex mnemonic string. Returns WalletInfo as JSON.
// #[tauri::command]
pub fn import_wallet(mnemonic_hex: String, testnet: bool) -> Result<String, String> {
    let seed = Seed::from_hex(&mnemonic_hex).map_err(|e| format!("invalid mnemonic: {}", e))?;
    let seed_hex = seed.to_hex();
    let seed_bytes_vec = hex::decode(&seed_hex).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed_bytes_vec);

    let wallet = Wallet::from_seed(seed, testnet);
    let info = wallet.info();
    let json = serde_json::to_string_pretty(&info)
        .map_err(|e| format!("serialization failed: {}", e))?;

    WALLET.with(|w| {
        *w.borrow_mut() = Some(WalletState {
            wallet,
            seed_bytes: arr,
        });
    });

    Ok(json)
}

/// Import a wallet from a BIP-39 24-word mnemonic.
// #[tauri::command]
pub fn import_wallet_bip39(words: String, testnet: bool) -> Result<String, String> {
    let word_list: Vec<String> = words.split_whitespace().map(String::from).collect();
    let entropy = seal_wallet::bip39::mnemonic_to_entropy(&word_list)
        .map_err(|e| format!("invalid BIP-39 mnemonic: {}", e))?;

    let seed = Seed::from_bytes(entropy);
    let seed_hex = seed.to_hex();
    let seed_bytes_vec = hex::decode(&seed_hex).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed_bytes_vec);

    let wallet = Wallet::from_seed(seed, testnet);
    let info = wallet.info();
    let json = serde_json::to_string_pretty(&info)
        .map_err(|e| format!("serialization failed: {}", e))?;

    WALLET.with(|w| {
        *w.borrow_mut() = Some(WalletState {
            wallet,
            seed_bytes: arr,
        });
    });

    Ok(json)
}

// --- Wallet info ---

/// Get current wallet info as JSON.
// #[tauri::command]
pub fn get_wallet_info() -> Result<String, String> {
    with_wallet(|state| {
        serde_json::to_string_pretty(&state.wallet.info())
            .map_err(|e| format!("serialization failed: {}", e))
    })
}

/// Get the wallet's Seal address (bech32m).
// #[tauri::command]
pub fn get_address() -> Result<String, String> {
    with_wallet(|state| Ok(state.wallet.info().seal_address))
}

/// Get balance (placeholder — needs node connection).
// #[tauri::command]
pub fn get_balance() -> Result<String, String> {
    Ok(serde_json::json!({
        "seal": 0,
        "wSOL": 0,
        "wXLM": 0,
        "wUSDC": 0,
    })
    .to_string())
}

// --- Mnemonic export ---

/// Export the wallet seed as a hex mnemonic (64 hex chars).
// #[tauri::command]
pub fn export_mnemonic() -> Result<String, String> {
    with_wallet(|state| Ok(hex::encode(state.seed_bytes)))
}

/// Export the wallet seed as a BIP-39 24-word mnemonic.
// #[tauri::command]
pub fn export_mnemonic_bip39() -> Result<String, String> {
    with_wallet(|state| {
        let words = seal_wallet::bip39::entropy_to_mnemonic(&state.seed_bytes);
        Ok(words.join(" "))
    })
}

/// Export the wallet seed as a simple 32-word mnemonic.
// #[tauri::command]
pub fn export_mnemonic_words() -> Result<String, String> {
    with_wallet(|state| {
        let seed = Seed::from_bytes(state.seed_bytes);
        Ok(seed.to_words().join(" "))
    })
}

// --- Crypto operations ---

/// Sign a message with the wallet's ML-DSA key.
/// Returns the signature as hex.
// #[tauri::command]
pub fn sign_message(message: String) -> Result<String, String> {
    with_wallet(|state| {
        let sig = state.wallet.sign(message.as_bytes())
            .map_err(|e| format!("signing failed: {}", e))?;
        Ok(hex::encode(sig.to_bytes()))
    })
}

/// Verify a signature against a message using this wallet's public key.
/// Returns true if valid.
// #[tauri::command]
pub fn verify_signature(message: String, signature_hex: String) -> Result<bool, String> {
    with_wallet(|state| {
        let sig_bytes = hex::decode(&signature_hex)
            .map_err(|e| format!("invalid hex signature: {}", e))?;
        let sig = seal_crypto::signature::Signature::from_bytes(sig_bytes);
        let vk_bytes = hex::decode(&state.wallet.info().seal_pubkey_hex)
            .map_err(|e| format!("invalid pubkey hex: {}", e))?;
        let vk = seal_crypto::signature::VerifyingKey::from_bytes(&vk_bytes)
            .map_err(|e| format!("invalid verifying key: {}", e))?;
        Ok(vk.verify(message.as_bytes(), &sig).is_ok())
    })
}

// --- Persistent storage ---

/// Save wallet to an encrypted file.
// #[tauri::command]
pub fn save_wallet(path: String, password: String) -> Result<(), String> {
    with_wallet(|state| {
        seal_wallet::storage::save_wallet_encrypted(&state.wallet, &path, &password)
            .map_err(|e| format!("save failed: {}", e))
    })
}

/// Load wallet from an encrypted file.
// #[tauri::command]
pub fn load_wallet(path: String, password: String) -> Result<String, String> {
    let wallet = seal_wallet::storage::load_wallet_encrypted(&path, &password)
        .map_err(|e| format!("load failed: {}", e))?;

    let info = wallet.info();
    let json = serde_json::to_string_pretty(&info)
        .map_err(|e| format!("serialization failed: {}", e))?;

    // Note: when loading from encrypted storage, we don't recover the original seed.
    // The wallet is functional for signing but the seed can't be re-exported.
    // To preserve the seed, save it separately or use mnemonic import.
    WALLET.with(|w| {
        *w.borrow_mut() = Some(WalletState {
            wallet,
            seed_bytes: [0u8; 32], // Seed unknown after encrypted load
        });
    });

    Ok(json)
}

// --- Node RPC ---

/// Connect to a Seal node and return chain height.
// #[tauri::command]
pub fn rpc_get_height(node_url: String) -> Result<String, String> {
    rpc_call(&node_url, "seal_getHeight", "{}")
}

/// Execute read-only SQL on a connected node.
// #[tauri::command]
pub fn rpc_query(node_url: String, sql: String) -> Result<String, String> {
    let params = format!("{{\"sql\":\"{}\"}}", sql.replace('"', "\\\""));
    rpc_call(&node_url, "seal_querySql", &params)
}

/// Send a signed SQL transaction to a node.
// #[tauri::command]
pub fn rpc_send(node_url: String, sql: String) -> Result<String, String> {
    with_wallet(|state| {
        let params_json = format!("{{\"sql\":\"{}\"}}", sql.replace('"', "\\\""));
        let message = format!("seal_submitSql{}", params_json);
        let message_hash = seal_crypto::hash::sha3_256(message.as_bytes());

        let sig = state.wallet.sign(message_hash.as_ref())
            .map_err(|e| format!("signing failed: {}", e))?;

        let vk = state.wallet.verifying_key();
        let body = format!(
            "{{\"jsonrpc\":\"2.0\",\"method\":\"seal_submitSql\",\"params\":{},\"signature\":\"{}\",\"sender\":\"{}\",\"id\":1}}",
            params_json,
            hex::encode(sig.to_bytes()),
            hex::encode(vk.to_bytes())
        );

        rpc_post(&node_url, &body)
    })
}

/// Get MPC aggregate from a node.
// #[tauri::command]
pub fn rpc_mpc_aggregate(node_url: String, function: String, table: String, column: String) -> Result<String, String> {
    let params = format!(
        "{{\"function\":\"{}\",\"table\":\"{}\",\"column\":\"{}\"}}",
        function, table, column
    );
    rpc_call(&node_url, "seal_mpcAggregate", &params)
}

/// Get ZK proof from a node.
// #[tauri::command]
pub fn rpc_zk_prove(node_url: String, statement: String, table: String) -> Result<String, String> {
    let params = format!(
        "{{\"statement\":\"{}\",\"table\":\"{}\"}}",
        statement.replace('"', "\\\""), table
    );
    rpc_call(&node_url, "seal_zkProve", &params)
}

fn rpc_call(url: &str, method: &str, params: &str) -> Result<String, String> {
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"{}\",\"params\":{},\"id\":1}}",
        method, params
    );
    rpc_post(url, &body)
}

fn rpc_post(url: &str, body: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    let addr = url.trim_start_matches("http://");
    let mut stream = std::net::TcpStream::connect(addr)
        .map_err(|e| format!("connect to {}: {}", url, e))?;
    let req = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    );
    stream.write_all(req.as_bytes()).map_err(|e| format!("send: {}", e))?;
    let mut response = String::new();
    stream.read_to_string(&mut response).map_err(|e| format!("read: {}", e))?;
    let json_start = response.find("\r\n\r\n").map(|p| p + 4).ok_or("invalid HTTP response")?;
    Ok(response[json_start..].to_string())
}

// --- Helpers ---

fn with_wallet<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce(&WalletState) -> Result<T, String>,
{
    WALLET.with(|w| {
        let borrow = w.borrow();
        match borrow.as_ref() {
            Some(state) => f(state),
            None => Err("no wallet loaded — create or import first".into()),
        }
    })
}
