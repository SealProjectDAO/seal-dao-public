//! Secure memory wrappers for key material.
//!
//! Phase 1: In-memory secure storage with zeroize on drop.
//! Phase 2: rust-secure-memory LockedBuffer integration (mlock + guard pages + canary sentinels).

use rand::RngCore;
use std::mem::ManuallyDrop;
use zeroize::Zeroize;

/// Secure in-memory storage for a byte array.
///
/// Phase 1: Simple Vec wrapper with zeroize on Drop.
/// Phase 2: Wraps rust_secure_memory::LockedBuffer for mlock + guard pages.
pub struct SecureBuffer {
    bytes: ManuallyDrop<Vec<u8>>,
    len: usize,
}

impl SecureBuffer {
    pub fn new(size: usize) -> Self {
        let mut bytes = vec![0u8; size];
        // Fill with randomness to avoid zeroed memory patterns
        rand::thread_rng().fill_bytes(&mut bytes);
        SecureBuffer {
            bytes: ManuallyDrop::new(bytes),
            len: 0,
        }
    }

    pub fn store(&mut self, data: &[u8]) {
        assert!(data.len() <= self.bytes.len(), "data exceeds buffer size");
        self.bytes[..data.len()].copy_from_slice(data);
        self.len = data.len();
        // Zero out remaining bytes
        self.bytes[data.len()..].zeroize();
    }

    pub fn load(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }

    /// Zero out the buffer without freeing the allocation.
    pub fn clear(&mut self) {
        self.bytes[..self.len].zeroize();
        self.len = 0;
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.bytes[..self.len].zeroize();
        // ManuallyDrop prevents double-free; vec drop is skipped
        unsafe { ManuallyDrop::drop(&mut self.bytes) };
    }
}

/// Key store: holds all master key material securely.
pub struct KeyStore {
    /// Master ML-KEM secret key (2400 bytes).
    pub master_kem_sk: SecureBuffer,
    /// Master ML-DSA signing key (4032 bytes).
    pub master_sig_sk: SecureBuffer,
    /// Committee MAC key (32 bytes).
    pub committee_key: SecureBuffer,
    /// Ringtail secret key (size varies by scheme).
    pub ringtail_sk: SecureBuffer,
}

impl KeyStore {
    /// Create a new empty key store.
    pub fn new() -> Self {
        KeyStore {
            master_kem_sk: SecureBuffer::new(2400),
            master_sig_sk: SecureBuffer::new(4032),
            committee_key: SecureBuffer::new(32),
            ringtail_sk: SecureBuffer::new(1024), // generous upper bound
        }
    }

    /// Load master keys from a file (Phase 1: read raw bytes).
    /// Phase 2: decrypt from age-encrypted file.
    pub fn load_from_hex(
        kem_hex: &str,
        sig_hex: &str,
        committee_hex: &str,
        ringtail_hex: &str,
    ) -> Self {
        let mut store = Self::new();

        let kem_bytes = hex::decode(kem_hex).expect("invalid ML-KEM key hex");
        store.master_kem_sk.store(&kem_bytes);

        let sig_bytes = hex::decode(sig_hex).expect("invalid ML-DSA key hex");
        store.master_sig_sk.store(&sig_bytes);

        let committee_bytes = hex::decode(committee_hex).expect("invalid committee key hex");
        store.committee_key.store(&committee_bytes);

        let ringtail_bytes = hex::decode(ringtail_hex).expect("invalid Ringtail key hex");
        store.ringtail_sk.store(&ringtail_bytes);

        store
    }

    /// Generate new random keys.
    pub fn generate() -> Self {
        let mut store = Self::new();
        let mut rng = rand::thread_rng();

        // ML-KEM-768 secret key: 2400 bytes
        let mut kem_bytes = vec![0u8; 2400];
        rng.fill_bytes(&mut kem_bytes);
        store.master_kem_sk.store(&kem_bytes);

        // ML-DSA-65 signing key: 4032 bytes
        let mut sig_bytes = vec![0u8; 4032];
        rng.fill_bytes(&mut sig_bytes);
        store.master_sig_sk.store(&sig_bytes);

        // Committee key: 32 bytes
        let mut committee = [0u8; 32];
        rng.fill_bytes(&mut committee);
        store.committee_key.store(&committee);

        // Ringtail: placeholder
        let mut ringtail_bytes = vec![0u8; 128];
        rng.fill_bytes(&mut ringtail_bytes);
        store.ringtail_sk.store(&ringtail_bytes);

        store
    }

    /// Serialize all keys to hex (for backup/persistence).
    pub fn to_hex(&self) -> (String, String, String, String) {
        (
            hex::encode(self.master_kem_sk.load()),
            hex::encode(self.master_sig_sk.load()),
            hex::encode(self.committee_key.load()),
            hex::encode(self.ringtail_sk.load()),
        )
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_store_load() {
        let mut buf = SecureBuffer::new(32);
        let data = b"hello world";
        buf.store(data);
        assert_eq!(buf.load(), data);
    }

    #[test]
    fn test_secure_buffer_clear() {
        let mut buf = SecureBuffer::new(32);
        let data = b"hello world";
        buf.store(data);
        buf.clear();
        assert!(buf.load().is_empty());
    }

    #[test]
    fn test_secure_buffer_over_size() {
        let mut buf = SecureBuffer::new(5);
        let data = b"this is too long";
        assert!(data.len() > 5);
        // Should not panic (assert in production, but test verifies)
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            buf.store(data);
        }))
        .expect_err("should panic on oversized data");
    }

    #[test]
    fn test_keystore_hex_roundtrip() {
        let store = KeyStore::generate();
        let (kem, sig, comm, ring) = store.to_hex();
        let store2 = KeyStore::load_from_hex(&kem, &sig, &comm, &ring);
        assert_eq!(store2.master_kem_sk.load(), store.master_kem_sk.load());
        assert_eq!(store2.committee_key.load(), store.committee_key.load());
    }
}
