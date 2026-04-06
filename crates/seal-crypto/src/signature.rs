//! ML-DSA-65 (Dilithium) digital signatures (FIPS 204).
//!
//! Now using **libcrux** — formally verified with hax + F* by Cryspen.
//! Properties verified: panic freedom, functional correctness against
//! NIST FIPS 204 spec, secret independence.
//!
//! Key improvement: `generate_from_seed(seed: [u8; 32])` enables
//! deterministic keygen from a mnemonic seed.
//!
//! ML-DSA-65: security level 3, sig ~3,309 bytes, pk ~1,952 bytes.

use libcrux_ml_dsa::ml_dsa_65;

// Type aliases matching libcrux's ml_dsa_65 module
type MLDSA65SigningKey = libcrux_ml_dsa::ml_dsa_65::MLDSA65SigningKey;
type MLDSA65VerificationKey = libcrux_ml_dsa::ml_dsa_65::MLDSA65VerificationKey;
type MLDSA65Signature = libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::CryptoError;

/// Size constants for ML-DSA-65.
pub const SIGNING_KEY_SIZE: usize = 4032;
pub const VERIFYING_KEY_SIZE: usize = 1952;
pub const SIGNATURE_SIZE: usize = 3309;

/// ML-DSA-65 signing key (secret). Zeroized on drop.
pub struct SigningKey {
    /// Raw signing key bytes (4032 bytes for ML-DSA-65).
    bytes: Vec<u8>,
}

impl SigningKey {
    /// Generate a new random signing key pair.
    pub fn generate() -> (Self, VerifyingKey) {
        let mut randomness = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut randomness);
        Self::generate_from_seed(randomness)
    }

    /// Generate a key pair deterministically from a 32-byte seed.
    /// Same seed always produces the same key pair.
    /// This enables mnemonic-based wallet recovery.
    pub fn generate_from_seed(seed: [u8; 32]) -> (Self, VerifyingKey) {
        let keypair = ml_dsa_65::generate_key_pair(seed);
        let sk_bytes = keypair.signing_key.as_ref().to_vec();
        let vk_bytes = keypair.verification_key.as_ref().to_vec();
        (
            SigningKey { bytes: sk_bytes },
            VerifyingKey { bytes: vk_bytes },
        )
    }

    /// Sign a message, producing a detached signature.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, CryptoError> {
        let sk_arr: [u8; SIGNING_KEY_SIZE] = self
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidSecretKey)?;
        let sk = MLDSA65SigningKey::new(sk_arr);
        let mut randomness = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut randomness);
        let context = b"";
        let sig = ml_dsa_65::sign(&sk, message, context, randomness)
            .map_err(|_| CryptoError::InvalidSecretKey)?;
        Ok(Signature {
            bytes: sig.as_ref().to_vec(),
        })
    }

    /// Sign with deterministic randomness (for VRF).
    /// Derives signing randomness from SHA3(sk || message) so the
    /// same (key, message) always produces the same signature.
    pub fn sign_deterministic(&self, message: &[u8]) -> Result<Signature, CryptoError> {
        let sk_arr: [u8; SIGNING_KEY_SIZE] = self
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidSecretKey)?;
        let sk = MLDSA65SigningKey::new(sk_arr);
        // Derive randomness deterministically from sk + message
        let randomness = crate::hash::sha3_256(
            &[&self.bytes[..32], message].concat(),
        ).0;
        let context = b"";
        let sig = ml_dsa_65::sign(&sk, message, context, randomness)
            .map_err(|_| CryptoError::InvalidSecretKey)?;
        Ok(Signature {
            bytes: sig.as_ref().to_vec(),
        })
    }

    /// Serialize the secret key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Deserialize from secret key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SIGNING_KEY_SIZE {
            return Err(CryptoError::InvalidSecretKey);
        }
        Ok(SigningKey {
            bytes: bytes.to_vec(),
        })
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// ML-DSA-65 verifying key (public).
#[derive(Clone)]
pub struct VerifyingKey {
    bytes: Vec<u8>,
}

impl VerifyingKey {
    /// Verify a detached signature against a message.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        let vk_arr: [u8; VERIFYING_KEY_SIZE] = self
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey("wrong length".into()))?;
        let vk = MLDSA65VerificationKey::new(vk_arr);
        let sig_arr: [u8; SIGNATURE_SIZE] = signature
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let sig = MLDSA65Signature::new(sig_arr);
        let context = b"";
        ml_dsa_65::verify(&vk, message, context, &sig).map_err(|_| CryptoError::InvalidSignature)
    }

    /// Serialize the public key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Deserialize from public key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != VERIFYING_KEY_SIZE {
            return Err(CryptoError::InvalidPublicKey(format!(
                "expected {} bytes, got {}",
                VERIFYING_KEY_SIZE,
                bytes.len()
            )));
        }
        Ok(VerifyingKey {
            bytes: bytes.to_vec(),
        })
    }

    /// Get the size of a serialized public key.
    pub fn byte_size() -> usize {
        VERIFYING_KEY_SIZE
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for VerifyingKey {}

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VerifyingKey({}...)", hex::encode(&self.bytes[..8]))
    }
}

/// ML-DSA-65 detached signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    bytes: Vec<u8>,
}

impl Signature {
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Signature { bytes }
    }

    /// Get the size of a signature.
    pub fn byte_size() -> usize {
        SIGNATURE_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let (sk, vk) = SigningKey::generate();
        let message = b"seal dao transaction";
        let sig = sk.sign(message).unwrap();
        assert!(vk.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_verify_wrong_message() {
        let (sk, vk) = SigningKey::generate();
        let sig = sk.sign(b"correct message").unwrap();
        assert!(vk.verify(b"wrong message", &sig).is_err());
    }

    #[test]
    fn test_verify_wrong_key() {
        let (sk, _vk) = SigningKey::generate();
        let (_, vk2) = SigningKey::generate();
        let sig = sk.sign(b"message").unwrap();
        assert!(vk2.verify(b"message", &sig).is_err());
    }

    #[test]
    fn test_key_serialization_roundtrip() {
        let (sk, vk) = SigningKey::generate();
        let message = b"roundtrip test";
        let sig = sk.sign(message).unwrap();

        // Serialize and deserialize public key
        let vk_bytes = vk.to_bytes();
        let vk2 = VerifyingKey::from_bytes(&vk_bytes).unwrap();
        assert!(vk2.verify(message, &sig).is_ok());

        // Serialize and deserialize secret key
        let sk_bytes = sk.to_bytes();
        let sk2 = SigningKey::from_bytes(&sk_bytes).unwrap();
        let sig2 = sk2.sign(message).unwrap();
        assert!(vk.verify(message, &sig2).is_ok());
    }

    #[test]
    fn test_signature_sizes() {
        assert_eq!(Signature::byte_size(), 3309);
        assert_eq!(VerifyingKey::byte_size(), 1952);
    }

    #[test]
    fn test_seed_deterministic_keygen() {
        let seed = [42u8; 32];
        let (sk1, vk1) = SigningKey::generate_from_seed(seed);
        let (sk2, vk2) = SigningKey::generate_from_seed(seed);

        // Same seed → same keys
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());
        assert_eq!(vk1.to_bytes(), vk2.to_bytes());

        // Different seed → different keys
        let (sk3, vk3) = SigningKey::generate_from_seed([99u8; 32]);
        assert_ne!(sk1.to_bytes(), sk3.to_bytes());
        assert_ne!(vk1.to_bytes(), vk3.to_bytes());
    }

    #[test]
    fn test_seed_deterministic_sign_verify() {
        let seed = [7u8; 32];
        let (sk, vk) = SigningKey::generate_from_seed(seed);
        let message = b"deterministic keygen works!";
        let sig = sk.sign(message).unwrap();
        assert!(vk.verify(message, &sig).is_ok());

        // Restore from same seed
        let (_sk2, vk2) = SigningKey::generate_from_seed(seed);
        // Same key, should verify the original signature
        assert!(vk2.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_sign_verify_arbitrary_messages() {
        let (sk, vk) = SigningKey::generate();
        let test_messages: Vec<Vec<u8>> = vec![
            vec![],
            vec![0],
            vec![0xff; 1],
            vec![0; 100],
            (0..=255).collect(),
            vec![0xab; 10000],
            b"seal dao transaction".to_vec(),
        ];

        for msg in &test_messages {
            let sig = sk.sign(msg).unwrap();
            assert!(
                vk.verify(msg, &sig).is_ok(),
                "sign-verify failed for message of len {}",
                msg.len()
            );
        }
    }
}
