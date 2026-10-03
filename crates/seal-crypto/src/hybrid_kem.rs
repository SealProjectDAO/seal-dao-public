//! Hybrid KEM: ML-KEM-768 (post-quantum) + X25519 (classical).
//!
//! Both primitives are used in key exchange; the final shared secret is
//! SHA3(MLKEM-SS || "hybrid-split-seal" || X25519-SS), so compromise of
//! either primitive alone does not expose the session key.
//!
//! Used for: KMS node pairing, hybrid PQ-Noise handshake.

use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::edwards::EdwardsPoint;
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::kem::{KemCiphertext, KemKeypair};
use crate::CryptoError;
use zeroize::Zeroize;

/// X25519 secret material (32 bytes, stored raw for serialization compatibility).
/// Clamping is applied on use via [`x25519_clamp`].
#[derive(Clone, Copy)]
pub struct X25519Secret(pub [u8; 32]);

/// X25519 public key material (32 bytes).
#[derive(Clone, Copy)]
pub struct X25519Public(pub [u8; 32]);

/// Clamp raw x25519 scalar bytes per RFC 7748 Section 5.
fn x25519_clamp(bytes: &mut [u8; 32]) {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
}

/// Compute X25519 shared secret from clamped secret bytes and public key bytes.
fn x25519_shared_secret(secret_clamped: [u8; 32], their_pk: &[u8; 32]) -> [u8; 32] {
    let their_point = MontgomeryPoint(*their_pk);
    let result = their_point.mul_clamped(secret_clamped);
    result.0
}

/// Derive X25519 public key bytes from raw secret bytes (clamped).
fn x25519_public_key(secret: &[u8; 32]) -> [u8; 32] {
    let mut clamped = *secret;
    x25519_clamp(&mut clamped);
    let point = EdwardsPoint::mul_base_clamped(clamped);
    let montgomery = point.to_montgomery();
    montgomery.0
}

/// Hybrid KEM keypair: ML-KEM-768 + X25519.
pub struct HybridKemKeypair {
    pub mlkem: KemKeypair,
    pub x25519: X25519Secret,
}

impl HybridKemKeypair {
    /// Generate a new random hybrid keypair.
    pub fn generate() -> Self {
        let mlkem = KemKeypair::generate();
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        HybridKemKeypair {
            mlkem,
            x25519: X25519Secret(secret),
        }
    }

    /// Derive the public key for transmission.
    pub fn public_key(&self) -> HybridKemPublicKey {
        let pk_bytes = x25519_public_key(&self.x25519.0);
        HybridKemPublicKey {
            mlkem: self.mlkem.public.clone(),
            x25519: X25519PublicKey::from(pk_bytes),
        }
    }
}

impl Drop for HybridKemKeypair {
    fn drop(&mut self) {
        // ML-KEM secret key is zeroized by KemSecretKey::drop.
        self.x25519.0.zeroize();
    }
}

/// Hybrid KEM public key (1216 bytes total: 1184 + 32).
#[derive(Clone)]
pub struct HybridKemPublicKey {
    pub mlkem: crate::kem::KemPublicKey,
    pub x25519: X25519PublicKey,
}

impl HybridKemPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1184 + 32);
        bytes.extend_from_slice(&self.mlkem.to_bytes());
        bytes.extend_from_slice(self.x25519.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 1216 {
            return Err(CryptoError::InvalidPublicKey(format!(
                "expected 1216 bytes, got {}",
                bytes.len()
            )));
        }
        let (mlkem_bytes, x25519_bytes) = bytes.split_at(1184);
        Ok(HybridKemPublicKey {
            mlkem: crate::kem::KemPublicKey::from_bytes(mlkem_bytes)?,
            x25519: X25519PublicKey::from(<[u8; 32]>::try_from(x25519_bytes).map_err(|_| {
                CryptoError::InvalidPublicKey("X25519 public key must be 32 bytes".into())
            })?),
        })
    }
}

impl std::fmt::Debug for HybridKemPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridKemPublicKey({}mlkem, {}x25519)", self.to_bytes().len(), 32)
    }
}

/// Hybrid shared secret (32 bytes, zeroized on drop).
#[derive(Clone)]
pub struct HybridKemSharedSecret {
    bytes: [u8; 32],
}

impl HybridKemSharedSecret {
    /// Derive the hybrid shared secret from the ML-KEM and X25519 shared secrets.
    pub fn from_ss(mlkem_ss: &[u8], x25519_ss: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(mlkem_ss);
        hasher.update(b"hybrid-split-seal");
        hasher.update(x25519_ss);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        HybridKemSharedSecret { bytes: out }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl std::fmt::Debug for HybridKemSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridKemSharedSecret(<redacted>)")
    }
}

impl Drop for HybridKemSharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl PartialEq for HybridKemSharedSecret {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for HybridKemSharedSecret {}

/// Result of encapsulating under a hybrid public key.
pub struct HybridEncapsulation {
    /// The derived shared secret (plaintext, only valid on decapsulator side).
    pub shared_secret: HybridKemSharedSecret,
    /// ML-KEM ciphertext (1088 bytes).
    pub mlkem_ct: KemCiphertext,
    /// X25519 ciphertext (32 bytes — actually the responder's ephemeral public key).
    pub x25519_ct: [u8; 32],
}

impl HybridKemPublicKey {
    /// Encapsulate: generate a hybrid shared secret + ciphertext.
    ///
    /// Returns (shared_secret, mlkem_ciphertext, x25519_ct).
    /// The shared secret is derived from both primitives via SHA3.
    pub fn encapsulate(&self) -> HybridEncapsulation {
        // ML-KEM encapsulation
        let (mlkem_ss, mlkem_ct) = self.mlkem.encapsulate();

        // X25519 key agreement (generate ephemeral keypair)
        let x25519_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let x25519_pk = X25519PublicKey::from(&x25519_secret);
        let x25519_ss = x25519_secret.diffie_hellman(&self.x25519);

        // Hybrid: SHA3(MLKEM-SS || "hybrid-split-seal" || X25519-SS)
        let shared_secret =
            HybridKemSharedSecret::from_ss(mlkem_ss.as_bytes(), x25519_ss.as_bytes());

        HybridEncapsulation {
            shared_secret,
            mlkem_ct,
            x25519_ct: x25519_pk.as_bytes().to_owned(),
        }
    }
}

impl HybridKemKeypair {
    /// Decapsulate: recover the hybrid shared secret from the encapsulation.
    pub fn decapsulate(&self, encapsulation: &HybridEncapsulation) -> Result<HybridKemSharedSecret, CryptoError> {
        self.decapsulate_from_ct(&encapsulation.mlkem_ct, &encapsulation.x25519_ct)
    }

    /// Decapsulate directly from ML-KEM ciphertext and X25519 ephemeral public key bytes.
    /// This is the handshake-friendly variant that doesn't require constructing
    /// a full `HybridEncapsulation` struct.
    pub fn decapsulate_from_ct(&self, mlkem_ct: &KemCiphertext, x25519_ct: &[u8; 32]) -> Result<HybridKemSharedSecret, CryptoError> {
        // ML-KEM decapsulation
        let mlkem_ss = self.mlkem.secret.decapsulate(mlkem_ct)?;

        // X25519 key agreement using raw clamped bytes
        let mut clamped = self.x25519.0;
        x25519_clamp(&mut clamped);
        let x25519_ss = x25519_shared_secret(clamped, x25519_ct);

        // Derive hybrid shared secret
        Ok(HybridKemSharedSecret::from_ss(mlkem_ss.as_bytes(), &x25519_ss))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_encapsulate_decapsulate() {
        let keypair = HybridKemKeypair::generate();
        let encapsulation = keypair.public_key().encapsulate();
        let ss = keypair.decapsulate(&encapsulation).unwrap();
        assert_eq!(ss.as_bytes(), encapsulation.shared_secret.as_bytes());
    }

    #[test]
    fn test_hybrid_public_key_sizes() {
        let keypair = HybridKemKeypair::generate();
        let pk = keypair.public_key();
        assert_eq!(pk.to_bytes().len(), 1216);
    }

    #[test]
    fn test_hybrid_shared_secret_size() {
        let keypair = HybridKemKeypair::generate();
        let encapsulation = keypair.public_key().encapsulate();
        assert_eq!(encapsulation.shared_secret.as_bytes().len(), 32);
    }

    #[test]
    fn test_hybrid_cross_verify() {
        let a_kp = HybridKemKeypair::generate();
        let b_kp = HybridKemKeypair::generate();

        let a_enc = a_kp.public_key().encapsulate();
        let a_ss = a_kp.decapsulate(&a_enc).unwrap();

        let b_enc = b_kp.public_key().encapsulate();
        let b_ss = b_kp.decapsulate(&b_enc).unwrap();

        assert_eq!(a_ss.as_bytes(), a_enc.shared_secret.as_bytes());
        assert_eq!(b_ss.as_bytes(), b_enc.shared_secret.as_bytes());
    }

    #[test]
    fn test_hybrid_from_bytes_roundtrip() {
        let keypair = HybridKemKeypair::generate();
        let pk = keypair.public_key();
        let bytes = pk.to_bytes();
        let pk2 = HybridKemPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn test_hybrid_wrong_size_rejected() {
        assert!(HybridKemPublicKey::from_bytes(&[0u8; 1215]).is_err());
        assert!(HybridKemPublicKey::from_bytes(&[0u8; 1217]).is_err());
    }

    #[test]
    fn test_x25519_clamp() {
        let mut bytes = [0xFFu8; 32];
        x25519_clamp(&mut bytes);
        assert_eq!(bytes[0], 0xF8); // bottom 3 bits cleared
        assert_eq!(bytes[31], 0x7F); // bit 255 cleared, bit 254 already set in 0x7F
    }

    #[test]
    fn test_x25519_shared_secret_non_trivial() {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let pk = x25519_public_key(&secret);
        let mut clamped = secret;
        x25519_clamp(&mut clamped);
        let ss = x25519_shared_secret(clamped, &pk);
        assert_eq!(ss.len(), 32);
        assert!(ss != [0u8; 32]);
    }

    #[test]
    fn test_decapsulate_from_ct() {
        let keypair = HybridKemKeypair::generate();
        let encaps = keypair.public_key().encapsulate();

        // decapsulate_from_ct should produce the same result as decapsulate
        let ss_from_ct = keypair
            .decapsulate_from_ct(&encaps.mlkem_ct, &encaps.x25519_ct)
            .unwrap();
        let ss_from_enc = keypair.decapsulate(&encaps).unwrap();

        assert_eq!(ss_from_ct.as_bytes(), ss_from_enc.as_bytes());
        assert_eq!(ss_from_ct.as_bytes(), encaps.shared_secret.as_bytes());
    }
}
