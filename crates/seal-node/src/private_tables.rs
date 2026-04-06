//! Private table storage with encryption at rest.
//!
//! Three types of private tables:
//! - **App-private**: schema enforced on-chain, data on user's node, encrypted
//! - **User-private**: user-defined schema, fully opaque to network
//! - **Regulated-private**: schema enforced, access via ZK proofs only
//!
//! All private data is encrypted with AES-256-GCM. The encryption key is
//! derived from the owner's ML-KEM keypair via HKDF.

use seal_crypto::hash::{sha3_256, Hash256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Private table type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivateTableType {
    /// App-defined schema, user-owned data, app can aggregate via MPC.
    AppPrivate,
    /// User-defined schema, fully opaque.
    UserPrivate,
    /// App-defined schema, access via ZK proofs only. Never reveals raw data.
    RegulatedPrivate,
}

/// Metadata for a private table (stored on-chain).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateTableMeta {
    /// Table name.
    pub name: String,
    /// Owner's seal address.
    pub owner: String,
    /// Privacy type.
    pub table_type: PrivateTableType,
    /// Schema hash (SHA3 of CREATE TABLE statement). Enforced for app/regulated.
    pub schema_hash: Hash256,
    /// Commitment to encrypted data (SHA3 of ciphertext).
    pub data_commitment: Hash256,
    /// Number of rows (committed via Pedersen for regulated, plaintext for app).
    pub row_count: u64,
    /// Replication factor (how many of owner's nodes store copies).
    pub replication: u32,
}

/// Encrypted table data (stored on owner's nodes only).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedTable {
    /// Table name.
    pub name: String,
    /// Encrypted rows (AES-256-GCM).
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption.
    pub nonce: [u8; 12],
    /// Data commitment for on-chain verification.
    pub commitment: Hash256,
}

/// Manages private tables for a node.
#[derive(Default)]
pub struct PrivateTableManager {
    /// On-chain metadata (visible to all).
    metadata: HashMap<String, PrivateTableMeta>,
    /// Encrypted data (only on owner's nodes).
    encrypted_data: HashMap<String, EncryptedTable>,
}

impl PrivateTableManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new private table.
    pub fn register(
        &mut self,
        name: String,
        owner: String,
        table_type: PrivateTableType,
        schema_sql: &str,
    ) -> PrivateTableMeta {
        let schema_hash = sha3_256(schema_sql.as_bytes());

        let meta = PrivateTableMeta {
            name: name.clone(),
            owner,
            table_type,
            schema_hash,
            data_commitment: Hash256([0u8; 32]),
            row_count: 0,
            replication: 1,
        };

        self.metadata.insert(name, meta.clone());
        meta
    }

    /// Store encrypted data for a private table.
    pub fn store_encrypted(
        &mut self,
        name: &str,
        plaintext: &[u8],
        encryption_key: &[u8; 32],
    ) -> Result<Hash256, String> {
        let _meta = self
            .metadata
            .get(name)
            .ok_or_else(|| format!("private table '{}' not registered", name))?;

        // Encrypt with AES-256-GCM (simplified — uses XOR for now, real impl needs aes-gcm crate)
        let nonce = generate_nonce();
        let ciphertext = xor_encrypt(plaintext, encryption_key, &nonce);
        let commitment = sha3_256(&ciphertext);

        let encrypted = EncryptedTable {
            name: name.to_string(),
            ciphertext,
            nonce,
            commitment,
        };

        self.encrypted_data.insert(name.to_string(), encrypted);

        // Update on-chain metadata
        if let Some(meta) = self.metadata.get_mut(name) {
            meta.data_commitment = commitment;
        }

        Ok(commitment)
    }

    /// Decrypt and return data (only for owner).
    pub fn decrypt(
        &self,
        name: &str,
        caller: &str,
        encryption_key: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let meta = self
            .metadata
            .get(name)
            .ok_or_else(|| format!("private table '{}' not found", name))?;

        if meta.owner != caller {
            return Err("access denied: not the table owner".into());
        }

        let encrypted = self
            .encrypted_data
            .get(name)
            .ok_or_else(|| "encrypted data not on this node".to_string())?;

        let plaintext = xor_encrypt(&encrypted.ciphertext, encryption_key, &encrypted.nonce);
        Ok(plaintext)
    }

    /// Get metadata for a private table (public — anyone can see metadata).
    pub fn get_meta(&self, name: &str) -> Option<&PrivateTableMeta> {
        self.metadata.get(name)
    }

    /// Check if a table is private.
    pub fn is_private(&self, name: &str) -> bool {
        self.metadata.contains_key(name)
    }

    /// List all private table names.
    pub fn table_names(&self) -> Vec<&str> {
        self.metadata.keys().map(|s| s.as_str()).collect()
    }

    /// Verify that encrypted data matches its on-chain commitment.
    pub fn verify_commitment(&self, name: &str) -> Result<bool, String> {
        let meta = self
            .metadata
            .get(name)
            .ok_or_else(|| format!("table '{}' not found", name))?;
        let encrypted = self
            .encrypted_data
            .get(name)
            .ok_or_else(|| "encrypted data not on this node".to_string())?;

        let actual = sha3_256(&encrypted.ciphertext);
        Ok(actual == meta.data_commitment)
    }
}

/// Simple XOR-based encryption (placeholder for AES-256-GCM).
/// In production, replace with `aes-gcm` crate.
fn xor_encrypt(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(data.len());
    let seed: Vec<u8> = key.iter().chain(nonce.iter()).copied().collect();
    let mut hash = sha3_256(&seed);
    while keystream.len() < data.len() {
        keystream.extend_from_slice(&hash.0);
        hash = sha3_256(&hash.0);
    }
    data.iter()
        .zip(keystream.iter())
        .map(|(d, k)| d ^ k)
        .collect()
}

fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let hash = sha3_256(&timestamp.to_le_bytes());
    nonce.copy_from_slice(&hash.0[..12]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_private_table() {
        let mut mgr = PrivateTableManager::new();
        let meta = mgr.register(
            "user_prefs".into(),
            "seal1alice".into(),
            PrivateTableType::AppPrivate,
            "CREATE TABLE user_prefs (user_id TEXT, theme TEXT)",
        );
        assert_eq!(meta.name, "user_prefs");
        assert_eq!(meta.owner, "seal1alice");
        assert!(mgr.is_private("user_prefs"));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut mgr = PrivateTableManager::new();
        mgr.register(
            "secret".into(),
            "seal1alice".into(),
            PrivateTableType::UserPrivate,
            "CREATE TABLE secret (id BIGINT, data TEXT)",
        );

        let key = [42u8; 32];
        let plaintext = b"sensitive data here";

        mgr.store_encrypted("secret", plaintext, &key).unwrap();
        let decrypted = mgr.decrypt("secret", "seal1alice", &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_owner_denied() {
        let mut mgr = PrivateTableManager::new();
        mgr.register(
            "secret".into(),
            "seal1alice".into(),
            PrivateTableType::UserPrivate,
            "CREATE TABLE secret (id BIGINT)",
        );

        let key = [42u8; 32];
        mgr.store_encrypted("secret", b"data", &key).unwrap();
        assert!(mgr.decrypt("secret", "seal1bob", &key).is_err());
    }

    #[test]
    fn test_commitment_verification() {
        let mut mgr = PrivateTableManager::new();
        mgr.register(
            "t".into(),
            "seal1alice".into(),
            PrivateTableType::AppPrivate,
            "CREATE TABLE t (id BIGINT)",
        );

        let key = [7u8; 32];
        mgr.store_encrypted("t", b"rows", &key).unwrap();
        assert!(mgr.verify_commitment("t").unwrap());
    }

    #[test]
    fn test_table_types() {
        let mut mgr = PrivateTableManager::new();
        mgr.register("a".into(), "o".into(), PrivateTableType::AppPrivate, "");
        mgr.register("b".into(), "o".into(), PrivateTableType::UserPrivate, "");
        mgr.register("c".into(), "o".into(), PrivateTableType::RegulatedPrivate, "");

        assert_eq!(mgr.get_meta("a").unwrap().table_type, PrivateTableType::AppPrivate);
        assert_eq!(mgr.get_meta("b").unwrap().table_type, PrivateTableType::UserPrivate);
        assert_eq!(mgr.get_meta("c").unwrap().table_type, PrivateTableType::RegulatedPrivate);
    }
}
