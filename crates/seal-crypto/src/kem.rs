//! ML-KEM-768 (Kyber) key encapsulation (FIPS 203).
//!
//! Now using **libcrux** — formally verified with hax + F* by Cryspen.
//!
//! Used for:
//! - Encrypted P2P communications (TLS/QUIC handshake)
//! - Secure key exchange between nodes

use libcrux_ml_kem::mlkem768;
use rand::RngCore;
use zeroize::Zeroize;

use crate::CryptoError;

/// ML-KEM-768 key pair for key encapsulation.
pub struct KemKeypair {
    pub public: KemPublicKey,
    pub secret: KemSecretKey,
}

impl KemKeypair {
    /// Generate a new random KEM key pair.
    pub fn generate() -> Self {
        let mut randomness = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut randomness);
        let keypair = mlkem768::generate_key_pair(randomness);
        KemKeypair {
            public: KemPublicKey {
                bytes: keypair.pk().as_ref().to_vec(),
            },
            secret: KemSecretKey {
                bytes: keypair.sk().as_ref().to_vec(),
            },
        }
    }
}

/// ML-KEM-768 public key (encapsulation key).
#[derive(Clone)]
pub struct KemPublicKey {
    bytes: Vec<u8>,
}

impl KemPublicKey {
    /// Encapsulate: generate a shared secret and ciphertext.
    pub fn encapsulate(&self) -> (KemSharedSecret, KemCiphertext) {
        let pk = mlkem768::MlKem768PublicKey::from(
            <[u8; 1184]>::try_from(self.bytes.as_slice()).unwrap(),
        );
        let mut randomness = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut randomness);
        let (ct, ss) = mlkem768::encapsulate(&pk, randomness);
        (
            KemSharedSecret {
                bytes: ss.as_ref().to_vec(),
            },
            KemCiphertext {
                bytes: ct.as_ref().to_vec(),
            },
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 1184 {
            return Err(CryptoError::InvalidPublicKey(format!(
                "expected 1184 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(KemPublicKey {
            bytes: bytes.to_vec(),
        })
    }
}

impl std::fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KemPublicKey({}...)", hex::encode(&self.bytes[..8]))
    }
}

/// ML-KEM-768 secret key (decapsulation key). Zeroized on drop.
pub struct KemSecretKey {
    bytes: Vec<u8>,
}

impl KemSecretKey {
    /// Decapsulate: recover the shared secret from a ciphertext.
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> Result<KemSharedSecret, CryptoError> {
        let sk = mlkem768::MlKem768PrivateKey::from(
            <[u8; 2400]>::try_from(self.bytes.as_slice())
                .map_err(|_| CryptoError::InvalidSecretKey)?,
        );
        let ct = mlkem768::MlKem768Ciphertext::from(
            <[u8; 1088]>::try_from(ciphertext.bytes.as_slice())
                .map_err(|_| CryptoError::InvalidCiphertext)?,
        );
        let ss = mlkem768::decapsulate(&sk, &ct);
        Ok(KemSharedSecret {
            bytes: ss.as_ref().to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 2400 {
            return Err(CryptoError::InvalidSecretKey);
        }
        Ok(KemSecretKey {
            bytes: bytes.to_vec(),
        })
    }
}

impl Drop for KemSecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Ciphertext produced by KEM encapsulation.
#[derive(Clone, Debug)]
pub struct KemCiphertext {
    bytes: Vec<u8>,
}

impl KemCiphertext {
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        KemCiphertext { bytes }
    }
}

/// Shared secret produced by KEM encapsulation/decapsulation.
pub struct KemSharedSecret {
    pub(crate) bytes: Vec<u8>,
}

impl std::fmt::Debug for KemSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KemSharedSecret(<redacted>)")
    }
}

impl KemSharedSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for KemSharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl PartialEq for KemSharedSecret {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for KemSharedSecret {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_encapsulate_decapsulate() {
        let keypair = KemKeypair::generate();
        let (ss_enc, ciphertext) = keypair.public.encapsulate();
        let ss_dec = keypair.secret.decapsulate(&ciphertext).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_kem_shared_secret_size() {
        let kp = KemKeypair::generate();
        let (ss, _ct) = kp.public.encapsulate();
        assert_eq!(ss.as_bytes().len(), 32);
    }

    #[test]
    fn test_kem_key_sizes() {
        let kp = KemKeypair::generate();
        assert_eq!(kp.public.to_bytes().len(), 1184);
        assert_eq!(kp.secret.to_bytes().len(), 2400);
    }
}
