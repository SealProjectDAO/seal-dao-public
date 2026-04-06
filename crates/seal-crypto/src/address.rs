//! Seal address derivation and encoding.
//!
//! Addresses are derived from ML-DSA public keys:
//!   `seal1<bech32m-encoded-sha3-256-of-public-key>`
//!
//! - Mainnet prefix: `seal1`
//! - Testnet prefix: `sealt1`

use crate::hash::sha3_256;
use crate::signature::VerifyingKey;
use crate::CryptoError;
use serde::{Deserialize, Serialize};

/// A Seal network address, derived from a PQC public key.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SealAddress {
    /// Raw SHA3-256 hash of the public key (32 bytes).
    hash: [u8; 32],
    /// Whether this is a testnet address.
    testnet: bool,
}

impl SealAddress {
    /// Derive an address from a verifying (public) key.
    pub fn from_verifying_key(vk: &VerifyingKey, testnet: bool) -> Self {
        let pk_bytes = vk.to_bytes();
        let hash = sha3_256(&pk_bytes);
        SealAddress {
            hash: hash.0,
            testnet,
        }
    }

    /// Create an address from raw hash bytes.
    pub fn from_hash(hash: [u8; 32], testnet: bool) -> Self {
        SealAddress { hash, testnet }
    }

    /// Get the raw hash bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Check if this is a testnet address.
    pub fn is_testnet(&self) -> bool {
        self.testnet
    }

    /// Get the human-readable prefix.
    pub fn prefix(&self) -> &str {
        if self.testnet {
            "sealt1"
        } else {
            "seal1"
        }
    }

    /// Encode as a bech32m string: `seal1<bech32m>` or `sealt1<bech32m>`
    pub fn to_string_encoding(&self) -> String {
        let hrp = if self.testnet { "sealt" } else { "seal" };
        crate::bech32m::encode(hrp, &self.hash)
    }

    /// Parse from a bech32m-encoded string.
    pub fn from_string_encoding(s: &str) -> Result<Self, CryptoError> {
        let (hrp, bytes) = crate::bech32m::decode(s)
            .map_err(|e| CryptoError::InvalidAddress(format!("bech32m: {}", e)))?;

        let testnet = match hrp.as_str() {
            "seal" => false,
            "sealt" => true,
            _ => {
                return Err(CryptoError::InvalidAddress(
                    "prefix must be 'seal' or 'sealt'".into(),
                ))
            }
        };

        if bytes.len() < 32 {
            return Err(CryptoError::InvalidAddress(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(SealAddress { hash, testnet })
    }
}

impl std::fmt::Debug for SealAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_encoding())
    }
}

impl std::fmt::Display for SealAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_encoding())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::SigningKey;

    #[test]
    fn test_address_from_key() {
        let (_sk, vk) = SigningKey::generate();
        let addr = SealAddress::from_verifying_key(&vk, false);
        assert!(addr.to_string_encoding().starts_with("seal1"));
        assert_eq!(addr.as_bytes().len(), 32);
    }

    #[test]
    fn test_address_testnet() {
        let (_sk, vk) = SigningKey::generate();
        let addr = SealAddress::from_verifying_key(&vk, true);
        assert!(addr.to_string_encoding().starts_with("sealt1"));
        assert!(addr.is_testnet());
    }

    #[test]
    fn test_address_deterministic() {
        let (_sk, vk) = SigningKey::generate();
        let a1 = SealAddress::from_verifying_key(&vk, false);
        let a2 = SealAddress::from_verifying_key(&vk, false);
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_address_different_keys() {
        let (_, vk1) = SigningKey::generate();
        let (_, vk2) = SigningKey::generate();
        let a1 = SealAddress::from_verifying_key(&vk1, false);
        let a2 = SealAddress::from_verifying_key(&vk2, false);
        assert_ne!(a1, a2);
    }

    #[test]
    fn test_address_roundtrip() {
        let (_, vk) = SigningKey::generate();
        let addr = SealAddress::from_verifying_key(&vk, false);
        let encoded = addr.to_string_encoding();
        let decoded = SealAddress::from_string_encoding(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_address_invalid_prefix() {
        assert!(SealAddress::from_string_encoding("eth10xabc").is_err());
    }
}
