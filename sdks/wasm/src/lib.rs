//! WASM bindings for Seal DAO.
//!
//! Exposes core seal-crypto and seal-sql functionality to JavaScript/TypeScript
//! via wasm-bindgen. Build with:
//!
//! ```bash
//! wasm-pack build --target web
//! ```
//!
//! Exported functions:
//! - `sha3_256` — SHA3-256 hash (FIPS 202)
//! - `sign` — ML-DSA-65 signature (FIPS 204)
//! - `verify` — ML-DSA-65 signature verification
//! - `sql_parse` — Parse and validate PostgreSQL-compatible SQL

use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Internal implementations (testable on all targets)
// ---------------------------------------------------------------------------

/// Compute SHA3-256 hash of the input bytes. Returns 32 bytes.
fn sha3_256_impl(data: &[u8]) -> Vec<u8> {
    let hash = seal_crypto::sha3_256(data);
    hash.as_bytes().to_vec()
}

/// Sign a message using ML-DSA-65. Returns the detached signature (3309 bytes).
fn sign_impl(signing_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let sk = seal_crypto::SigningKey::from_bytes(signing_key_bytes)
        .map_err(|e| format!("Invalid signing key: {e}"))?;
    let sig = sk
        .sign(message)
        .map_err(|e| format!("Signing failed: {e}"))?;
    Ok(sig.to_bytes().to_vec())
}

/// Verify an ML-DSA-65 signature. Returns true if valid.
fn verify_impl(
    verifying_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, String> {
    let vk = seal_crypto::VerifyingKey::from_bytes(verifying_key_bytes)
        .map_err(|e| format!("Invalid verifying key: {e}"))?;
    let sig = seal_crypto::Signature::from_bytes(signature_bytes.to_vec());
    match vk.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Parse SQL and return a JSON array of statement strings.
fn sql_parse_impl(sql: &str) -> Result<String, String> {
    let statements =
        seal_sql::parse_sql(sql).map_err(|e| format!("SQL parse error: {e}"))?;

    let ast_strings: Vec<String> = statements.iter().map(|s| format!("{s}")).collect();
    serde_json::to_string(&ast_strings)
        .map_err(|e| format!("JSON serialization error: {e}"))
}

/// Generate a new ML-DSA-65 keypair from a random 32-byte seed.
/// Returns JSON with seed_hex, mnemonic (24 BIP-39 words), signing_key, verifying_key, address.
fn generate_keypair_impl(testnet: bool) -> String {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    let (sk, vk) = seal_crypto::SigningKey::generate_from_seed(seed);
    let addr_hash = seal_crypto::sha3_256(&vk.to_bytes());
    let prefix = if testnet { "sealt1" } else { "seal1" };
    let address = format!("{}{}", prefix, hex::encode(&addr_hash.as_bytes()[..20]));
    let mnemonic = seal_wallet::bip39::entropy_to_mnemonic(&seed).join(" ");
    serde_json::json!({
        "seed_hex": hex::encode(seed),
        "mnemonic": mnemonic,
        "signing_key": hex::encode(sk.to_bytes()),
        "verifying_key": hex::encode(vk.to_bytes()),
        "address": address,
    }).to_string()
}

// ---------------------------------------------------------------------------
// wasm_bindgen exports (thin wrappers that convert errors to JsValue)
// ---------------------------------------------------------------------------

/// Compute SHA3-256 hash of the input bytes.
///
/// Returns a 32-byte hash digest as a `Uint8Array`.
///
/// # Example (JavaScript)
/// ```js
/// import { sha3_256 } from "seal-dao-wasm";
/// const hash = sha3_256(new TextEncoder().encode("hello"));
/// console.log(hash); // Uint8Array(32)
/// ```
#[wasm_bindgen]
pub fn sha3_256(data: &[u8]) -> Vec<u8> {
    sha3_256_impl(data)
}

/// Sign a message using ML-DSA-65 (FIPS 204).
///
/// Takes a signing key (4032 bytes) and a message, returns the detached
/// signature (3309 bytes) as a `Uint8Array`.
///
/// # Errors
///
/// Returns an error string if the signing key is invalid.
#[wasm_bindgen]
pub fn sign(signing_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    sign_impl(signing_key_bytes, message).map_err(|e| JsValue::from_str(&e))
}

/// Verify an ML-DSA-65 signature (FIPS 204).
///
/// Takes a verifying key (1952 bytes), a message, and a signature (3309 bytes).
/// Returns `true` if the signature is valid, `false` otherwise.
///
/// # Errors
///
/// Returns an error string if the verifying key is malformed.
#[wasm_bindgen]
pub fn verify(
    verifying_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, JsValue> {
    verify_impl(verifying_key_bytes, message, signature_bytes)
        .map_err(|e| JsValue::from_str(&e))
}

/// Parse and validate a PostgreSQL-compatible SQL statement.
///
/// Returns a JSON string containing the parsed statement strings on success,
/// or an error message if the SQL is invalid. This uses the same parser as
/// the Seal node.
///
/// Supported statements: SELECT, INSERT, UPDATE, DELETE, CREATE TABLE,
/// CREATE POLICY, CREATE INDEX, ALTER TABLE.
///
/// # Example (JavaScript)
/// ```js
/// import { sql_parse } from "seal-dao-wasm";
/// const ast = sql_parse("SELECT * FROM users WHERE id = 1");
/// console.log(ast); // JSON string
/// ```
///
/// # Errors
///
/// Returns an error string if the SQL cannot be parsed.
/// Generate a new ML-DSA-65 keypair.
///
/// Returns a JSON string with signing_key (hex), verifying_key (hex), and address.
#[wasm_bindgen]
pub fn generate_keypair(testnet: bool) -> String {
    generate_keypair_impl(testnet)
}

/// Import a wallet from a BIP-39 mnemonic (24 words).
/// Returns the same JSON as generate_keypair.
#[wasm_bindgen]
pub fn import_from_mnemonic(words: &str, testnet: bool) -> Result<String, JsValue> {
    let word_list: Vec<String> = words.split_whitespace().map(String::from).collect();
    let seed = seal_wallet::bip39::mnemonic_to_entropy(&word_list)
        .map_err(|e| JsValue::from_str(&e))?;
    let (sk, vk) = seal_crypto::SigningKey::generate_from_seed(seed);
    let addr_hash = seal_crypto::sha3_256(&vk.to_bytes());
    let prefix = if testnet { "sealt1" } else { "seal1" };
    let address = format!("{}{}", prefix, hex::encode(&addr_hash.as_bytes()[..20]));
    let mnemonic = seal_wallet::bip39::entropy_to_mnemonic(&seed).join(" ");
    Ok(serde_json::json!({
        "seed_hex": hex::encode(seed),
        "mnemonic": mnemonic,
        "signing_key": hex::encode(sk.to_bytes()),
        "verifying_key": hex::encode(vk.to_bytes()),
        "address": address,
    }).to_string())
}

/// Import a wallet from a hex seed (64 chars).
#[wasm_bindgen]
pub fn import_from_hex(seed_hex: &str, testnet: bool) -> Result<String, JsValue> {
    let seed_bytes = hex::decode(seed_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid hex: {}", e)))?;
    if seed_bytes.len() != 32 {
        return Err(JsValue::from_str("seed must be 32 bytes (64 hex chars)"));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let (sk, vk) = seal_crypto::SigningKey::generate_from_seed(seed);
    let addr_hash = seal_crypto::sha3_256(&vk.to_bytes());
    let prefix = if testnet { "sealt1" } else { "seal1" };
    let address = format!("{}{}", prefix, hex::encode(&addr_hash.as_bytes()[..20]));
    let mnemonic = seal_wallet::bip39::entropy_to_mnemonic(&seed).join(" ");
    Ok(serde_json::json!({
        "seed_hex": hex::encode(seed),
        "mnemonic": mnemonic,
        "signing_key": hex::encode(sk.to_bytes()),
        "verifying_key": hex::encode(vk.to_bytes()),
        "address": address,
    }).to_string())
}

#[wasm_bindgen]
pub fn sql_parse(sql: &str) -> Result<String, JsValue> {
    sql_parse_impl(sql).map_err(|e| JsValue::from_str(&e))
}

// ---------------------------------------------------------------------------
// Tests (use internal impls to run on native targets)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_returns_32_bytes() {
        let hash = sha3_256_impl(b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha3_256_deterministic() {
        let a = sha3_256_impl(b"seal dao");
        let b = sha3_256_impl(b"seal dao");
        assert_eq!(a, b);
    }

    #[test]
    fn test_sha3_256_different_inputs() {
        let a = sha3_256_impl(b"seal dao");
        let b = sha3_256_impl(b"seal dao!");
        assert_ne!(a, b);
    }

    #[test]
    fn test_sql_parse_valid() {
        let result = sql_parse_impl("SELECT * FROM users WHERE id = 1");
        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("SELECT"));
    }

    #[test]
    fn test_sql_parse_create_table() {
        let result = sql_parse_impl("CREATE TABLE test (id BIGINT PRIMARY KEY, name TEXT)");
        assert!(result.is_ok());
    }

    #[test]
    fn test_sql_parse_invalid() {
        let result = sql_parse_impl("THIS IS NOT SQL");
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_invalid_key() {
        let result = sign_impl(b"too short", b"message");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signing key"));
    }

    #[test]
    fn test_verify_invalid_key() {
        let result = verify_impl(b"too short", b"message", b"fake sig");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid verifying key"));
    }
}
