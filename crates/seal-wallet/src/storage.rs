//! Persistent wallet storage — save/load wallet to disk.
//!
//! Two modes:
//! - **Plaintext**: `save_wallet` / `load_wallet` — for development
//! - **Encrypted**: `save_wallet_encrypted` / `load_wallet_encrypted` —
//!   encrypts seed with password-derived key (SHA3-based KDF + XOR)
//!
//! Production should ALWAYS use encrypted mode.

use crate::error::WalletError;
use crate::keystore::Wallet;
use crate::mnemonic::Seed;
use seal_crypto::hash::sha3_256;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Serializable wallet data (plaintext).
#[derive(Serialize, Deserialize)]
struct WalletFile {
    mnemonic: String,
    signing_key_hex: String,
    testnet: bool,
}

/// Serializable encrypted wallet data.
#[derive(Serialize, Deserialize)]
struct EncryptedWalletFile {
    /// Encrypted seed (XOR with password-derived key), hex-encoded.
    encrypted_seed_hex: String,
    /// Salt for key derivation (random 32 bytes), hex-encoded.
    salt_hex: String,
    /// SHA3(derived_key || seed) — to verify correct password.
    check_hash_hex: String,
    /// Number of KDF iterations.
    kdf_iterations: u32,
    testnet: bool,
}

/// Derive an encryption key from a password and salt using iterated SHA3.
/// This is a simplified PBKDF — production would use Argon2 or scrypt.
fn derive_key(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = sha3_256(&[password, salt].concat()).0;
    for _ in 0..iterations {
        key = sha3_256(&key).0;
    }
    key
}

/// XOR two 32-byte arrays.
fn xor_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

const DEFAULT_KDF_ITERATIONS: u32 = 100_000;

// --- Plaintext storage (development) ---

/// Save a wallet to a plaintext JSON file.
pub fn save_wallet(wallet: &Wallet, path: &str) -> Result<(), WalletError> {
    let data = WalletFile {
        mnemonic: wallet.mnemonic(),
        signing_key_hex: hex::encode(wallet.signing_key_bytes()),
        testnet: wallet.address().is_testnet(),
    };
    let json = serde_json::to_string_pretty(&data)
        .map_err(|e| WalletError::Serialization(e.to_string()))?;
    std::fs::write(path, json)
        .map_err(|e| WalletError::Serialization(format!("write failed: {}", e)))?;
    Ok(())
}

/// Load a wallet from a plaintext JSON file.
pub fn load_wallet(path: &str) -> Result<Wallet, WalletError> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| WalletError::Serialization(format!("read failed: {}", e)))?;
    let data: WalletFile =
        serde_json::from_str(&json).map_err(|e| WalletError::Serialization(e.to_string()))?;
    let seed = Seed::from_hex(&data.mnemonic)?;
    Ok(Wallet::from_seed(seed, data.testnet))
}

// --- Encrypted storage (production) ---

/// Save a wallet encrypted with a password.
pub fn save_wallet_encrypted(
    wallet: &Wallet,
    path: &str,
    password: &str,
) -> Result<(), WalletError> {
    let seed_bytes =
        hex::decode(wallet.mnemonic()).map_err(|e| WalletError::Serialization(e.to_string()))?;
    let seed_arr: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| WalletError::Serialization("seed not 32 bytes".into()))?;

    // Generate random salt
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);

    // Derive key from password
    let key = derive_key(password.as_bytes(), &salt, DEFAULT_KDF_ITERATIONS);

    // Encrypt seed (XOR)
    let encrypted = xor_bytes(&seed_arr, &key);

    // Compute check hash (to verify password on load)
    let check = sha3_256(&[&key[..], &seed_arr[..]].concat());

    let data = EncryptedWalletFile {
        encrypted_seed_hex: hex::encode(encrypted),
        salt_hex: hex::encode(salt),
        check_hash_hex: hex::encode(check.0),
        kdf_iterations: DEFAULT_KDF_ITERATIONS,
        testnet: wallet.address().is_testnet(),
    };

    let json = serde_json::to_string_pretty(&data)
        .map_err(|e| WalletError::Serialization(e.to_string()))?;
    std::fs::write(path, json)
        .map_err(|e| WalletError::Serialization(format!("write failed: {}", e)))?;
    Ok(())
}

/// Load a wallet from an encrypted file.
pub fn load_wallet_encrypted(path: &str, password: &str) -> Result<Wallet, WalletError> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| WalletError::Serialization(format!("read failed: {}", e)))?;
    let data: EncryptedWalletFile =
        serde_json::from_str(&json).map_err(|e| WalletError::Serialization(e.to_string()))?;

    let encrypted = hex::decode(&data.encrypted_seed_hex)
        .map_err(|e| WalletError::Serialization(e.to_string()))?;
    let salt =
        hex::decode(&data.salt_hex).map_err(|e| WalletError::Serialization(e.to_string()))?;
    let expected_check =
        hex::decode(&data.check_hash_hex).map_err(|e| WalletError::Serialization(e.to_string()))?;

    let enc_arr: [u8; 32] = encrypted
        .try_into()
        .map_err(|_| WalletError::Serialization("bad encrypted seed length".into()))?;
    let salt_arr: [u8; 32] = salt
        .try_into()
        .map_err(|_| WalletError::Serialization("bad salt length".into()))?;

    // Derive key
    let key = derive_key(password.as_bytes(), &salt_arr, data.kdf_iterations);

    // Decrypt seed
    let seed_bytes = xor_bytes(&enc_arr, &key);

    // Verify password (check hash)
    let check = sha3_256(&[&key[..], &seed_bytes[..]].concat());
    if check.0[..] != expected_check[..] {
        return Err(WalletError::InvalidPassword);
    }

    let seed = Seed::from_bytes(seed_bytes);
    Ok(Wallet::from_seed(seed, data.testnet))
}

/// Check if a wallet file exists.
pub fn wallet_exists(path: &str) -> bool {
    Path::new(path).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = format!("{}/wallet.json", dir.path().to_str().unwrap());

        let wallet = Wallet::generate(true);
        let original_address = wallet.info().seal_address.clone();
        let original_sk = wallet.signing_key_bytes();

        save_wallet(&wallet, &path).unwrap();
        assert!(wallet_exists(&path));

        let loaded = load_wallet(&path).unwrap();
        assert_eq!(loaded.info().seal_address, original_address);
        assert_eq!(loaded.signing_key_bytes(), original_sk);
    }

    #[test]
    fn test_load_nonexistent() {
        assert!(load_wallet("/nonexistent/path/wallet.json").is_err());
    }

    #[test]
    fn test_sign_after_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = format!("{}/wallet.json", dir.path().to_str().unwrap());

        let wallet = Wallet::generate(true);
        let message = b"persistent wallet test";
        let sig = wallet.sign(message).unwrap();

        save_wallet(&wallet, &path).unwrap();
        let loaded = load_wallet(&path).unwrap();

        assert!(loaded.verifying_key().verify(message, &sig).is_ok());
        let new_sig = loaded.sign(b"new message").unwrap();
        assert!(loaded
            .verifying_key()
            .verify(b"new message", &new_sig)
            .is_ok());
    }

    #[test]
    fn test_encrypted_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = format!("{}/wallet.enc.json", dir.path().to_str().unwrap());

        let wallet = Wallet::generate(true);
        let original_address = wallet.info().seal_address.clone();
        let password = "my_secure_password_123";

        save_wallet_encrypted(&wallet, &path, password).unwrap();
        let loaded = load_wallet_encrypted(&path, password).unwrap();

        assert_eq!(loaded.info().seal_address, original_address);
    }

    #[test]
    fn test_encrypted_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = format!("{}/wallet.enc.json", dir.path().to_str().unwrap());

        let wallet = Wallet::generate(true);
        save_wallet_encrypted(&wallet, &path, "correct_password").unwrap();

        let result = load_wallet_encrypted(&path, "wrong_password");
        assert!(matches!(result, Err(WalletError::InvalidPassword)));
    }

    #[test]
    fn test_encrypted_sign_after_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = format!("{}/wallet.enc.json", dir.path().to_str().unwrap());

        let wallet = Wallet::generate(true);
        let message = b"encrypted wallet test";
        let sig = wallet.sign(message).unwrap();

        save_wallet_encrypted(&wallet, &path, "passphrase").unwrap();
        let loaded = load_wallet_encrypted(&path, "passphrase").unwrap();

        // Signature from original verifies with loaded key
        assert!(loaded.verifying_key().verify(message, &sig).is_ok());
    }
}
