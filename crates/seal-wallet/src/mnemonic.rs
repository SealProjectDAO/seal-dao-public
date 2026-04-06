//! Mnemonic seed generation and key derivation.
//!
//! Simplified mnemonic: 32 random bytes encoded as hex (64 chars).
//! Production would use BIP-39 wordlist, but the entropy source is the same.
//!
//! From a single seed we derive:
//! - SEAL PQC keys (ML-DSA) via SHA3(seed || "seal/pqc/0")
//! - Ed25519 keys (for Solana/Stellar) via SHA3(seed || "seal/ed25519/0")

use rand::RngCore;
use seal_crypto::hash::sha3_256;
use zeroize::Zeroize;

/// A 32-byte seed from which all keys are derived.
pub struct Seed {
    bytes: [u8; 32],
}

impl Seed {
    /// Generate a new random seed.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Seed { bytes }
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Seed { bytes }
    }

    /// Export as hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Export as 32 mnemonic words (human-readable backup).
    pub fn to_words(&self) -> Vec<String> {
        crate::wordlist::bytes_to_words(&self.bytes)
    }

    /// Export as formatted mnemonic (4 words per line).
    pub fn to_mnemonic_display(&self) -> String {
        crate::wordlist::format_mnemonic(&self.to_words())
    }

    /// Import from mnemonic words.
    pub fn from_words(words: &[String]) -> Result<Self, crate::WalletError> {
        let bytes = crate::wordlist::words_to_bytes(words)
            .map_err(|e| crate::WalletError::InvalidMnemonic(e))?;
        Ok(Seed { bytes })
    }

    /// Export as human-readable grouped hex (8 groups of 8 chars).
    pub fn to_display(&self) -> String {
        let hex = self.to_hex();
        hex.as_bytes()
            .chunks(8)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Import from hex string (with or without spaces).
    pub fn from_hex(s: &str) -> Result<Self, crate::WalletError> {
        let s = s.replace(' ', ""); // Strip spaces for grouped format
        let bytes =
            hex::decode(s).map_err(|e| crate::WalletError::InvalidMnemonic(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(crate::WalletError::InvalidMnemonic(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Seed { bytes: arr })
    }

    /// Derive a child key for a given path string.
    /// Returns 32 bytes of key material.
    pub fn derive(&self, path: &str) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&self.bytes);
        data.extend_from_slice(path.as_bytes());
        sha3_256(&data).0
    }

    /// Derive the PQC seed (for ML-DSA key generation).
    pub fn pqc_seed(&self) -> [u8; 32] {
        self.derive("seal/pqc/0")
    }

    /// Derive the Ed25519 seed (for Solana/Stellar).
    pub fn ed25519_seed(&self) -> [u8; 32] {
        self.derive("seal/ed25519/0")
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_generation() {
        let s1 = Seed::generate();
        let s2 = Seed::generate();
        assert_ne!(s1.bytes, s2.bytes); // Overwhelmingly likely
    }

    #[test]
    fn test_seed_hex_roundtrip() {
        let seed = Seed::generate();
        let hex_str = seed.to_hex();
        assert_eq!(hex_str.len(), 64);
        let seed2 = Seed::from_hex(&hex_str).unwrap();
        assert_eq!(seed.bytes, seed2.bytes);
    }

    #[test]
    fn test_seed_derivation_deterministic() {
        let seed = Seed::from_bytes([42u8; 32]);
        let d1 = seed.derive("path/a");
        let d2 = seed.derive("path/a");
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_seed_derivation_different_paths() {
        let seed = Seed::from_bytes([42u8; 32]);
        let pqc = seed.pqc_seed();
        let ed = seed.ed25519_seed();
        assert_ne!(pqc, ed);
    }

    #[test]
    fn test_invalid_hex() {
        assert!(Seed::from_hex("not_hex").is_err());
        assert!(Seed::from_hex("aabb").is_err()); // Too short
    }
}
