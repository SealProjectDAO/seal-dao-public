//! Private table storage with encryption at rest.
//!
//! Three types of private tables:
//! - **App-private**: schema enforced on-chain, data on user's node, encrypted
//! - **User-private**: user-defined schema, fully opaque to network
//! - **Regulated-private**: schema enforced, access via ZK proofs only
//!
//! All private data is encrypted with AES-256-GCM (authenticated encryption).
//! Nonces are 96-bit random values generated from the OS RNG. Keys are wrapped
//! in [`EncryptionKey`] which zeroes the material on drop.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use seal_crypto::hash::{sha3_256, Hash256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
///
/// AES-256-GCM ciphertext. The 16-byte authentication tag is appended to the
/// ciphertext body by the `aes-gcm` crate, so `ciphertext.len() == plaintext.len() + 16`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedTable {
    /// Table name.
    pub name: String,
    /// Ciphertext || auth tag (AES-256-GCM).
    pub ciphertext: Vec<u8>,
    /// 96-bit nonce used for encryption. MUST be unique per (key, message).
    pub nonce: [u8; 12],
    /// Data commitment (SHA3 of `nonce || ciphertext`) for on-chain verification.
    pub commitment: Hash256,
}

/// An AES-256-GCM key that zeroes itself on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey([u8; 32]);

impl EncryptionKey {
    /// Wrap 32 bytes of key material. The caller is responsible for how the
    /// bytes are derived (HKDF from an ML-KEM shared secret, random, etc).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh random key from the OS RNG.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    fn as_aes_key(&self) -> &Key<Aes256Gcm> {
        Key::<Aes256Gcm>::from_slice(&self.0)
    }
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

    /// Encrypt and store data for a private table.
    ///
    /// Generates a fresh 96-bit random nonce, seals `plaintext` with
    /// AES-256-GCM, stores `nonce || ciphertext || tag`, and updates the
    /// on-chain commitment to `SHA3(nonce || ciphertext || tag)`. Including
    /// the nonce in the commitment binds the ciphertext to the nonce used
    /// during sealing, so replaying the same ciphertext under a different
    /// nonce fails the commitment check.
    pub fn store_encrypted(
        &mut self,
        name: &str,
        plaintext: &[u8],
        key: &EncryptionKey,
    ) -> Result<Hash256, String> {
        self.metadata
            .get(name)
            .ok_or_else(|| format!("private table '{}' not registered", name))?;

        let cipher = Aes256Gcm::new(key.as_aes_key());
        let nonce_ga = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce_ga, plaintext)
            .map_err(|e| format!("AES-256-GCM encrypt failed: {e}"))?;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_ga.as_slice());

        let commitment = commit(&nonce, &ciphertext);
        let encrypted = EncryptedTable {
            name: name.to_string(),
            ciphertext,
            nonce,
            commitment,
        };

        self.encrypted_data.insert(name.to_string(), encrypted);

        if let Some(meta) = self.metadata.get_mut(name) {
            meta.data_commitment = commitment;
        }

        Ok(commitment)
    }

    /// Decrypt and return data (only for owner). Returns an error if either
    /// the auth tag fails (tampered ciphertext) or the caller is not the
    /// registered owner.
    pub fn decrypt(
        &self,
        name: &str,
        caller: &str,
        key: &EncryptionKey,
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

        let cipher = Aes256Gcm::new(key.as_aes_key());
        let nonce = Nonce::from_slice(&encrypted.nonce);
        cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| format!("AES-256-GCM decrypt failed: {e}"))
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

        let actual = commit(&encrypted.nonce, &encrypted.ciphertext);
        Ok(actual == meta.data_commitment)
    }
}

fn commit(nonce: &[u8; 12], ciphertext: &[u8]) -> Hash256 {
    let mut buf = Vec::with_capacity(12 + ciphertext.len());
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(ciphertext);
    sha3_256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice_key() -> EncryptionKey {
        EncryptionKey::from_bytes([42u8; 32])
    }

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

        let key = alice_key();
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

        let key = alice_key();
        mgr.store_encrypted("secret", b"data", &key).unwrap();
        assert!(mgr.decrypt("secret", "seal1bob", &key).is_err());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let mut mgr = PrivateTableManager::new();
        mgr.register(
            "t".into(),
            "o".into(),
            PrivateTableType::UserPrivate,
            "",
        );
        let key = alice_key();
        mgr.store_encrypted("t", b"rows", &key).unwrap();

        let wrong_key = EncryptionKey::from_bytes([7u8; 32]);
        let err = mgr.decrypt("t", "o", &wrong_key).unwrap_err();
        assert!(err.contains("decrypt failed"));
    }

    #[test]
    fn test_tampered_ciphertext_rejected_by_auth_tag() {
        let mut mgr = PrivateTableManager::new();
        mgr.register("t".into(), "o".into(), PrivateTableType::UserPrivate, "");
        let key = alice_key();
        mgr.store_encrypted("t", b"rows", &key).unwrap();

        // Flip one byte in the ciphertext — AES-GCM must reject it.
        mgr.encrypted_data
            .get_mut("t")
            .unwrap()
            .ciphertext[0] ^= 0x01;
        assert!(mgr.decrypt("t", "o", &key).is_err());
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

        let key = alice_key();
        mgr.store_encrypted("t", b"rows", &key).unwrap();
        assert!(mgr.verify_commitment("t").unwrap());

        // Mutating the stored ciphertext must invalidate the commitment.
        mgr.encrypted_data.get_mut("t").unwrap().ciphertext[0] ^= 0xFF;
        assert!(!mgr.verify_commitment("t").unwrap());
    }

    #[test]
    fn test_nonces_are_distinct_per_store() {
        let mut mgr = PrivateTableManager::new();
        mgr.register("a".into(), "o".into(), PrivateTableType::UserPrivate, "");
        mgr.register("b".into(), "o".into(), PrivateTableType::UserPrivate, "");

        let key = EncryptionKey::random();
        mgr.store_encrypted("a", b"same", &key).unwrap();
        mgr.store_encrypted("b", b"same", &key).unwrap();

        let a_nonce = mgr.encrypted_data["a"].nonce;
        let b_nonce = mgr.encrypted_data["b"].nonce;
        assert_ne!(a_nonce, b_nonce, "each seal must use a fresh nonce");

        // Same plaintext + same key + different nonce ⇒ different ciphertexts.
        let a_ct = &mgr.encrypted_data["a"].ciphertext;
        let b_ct = &mgr.encrypted_data["b"].ciphertext;
        assert_ne!(a_ct, b_ct);
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
