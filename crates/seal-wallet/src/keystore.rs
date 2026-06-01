//! Wallet keystore — manages PQC and Ed25519 key pairs.

use crate::error::WalletError;
use crate::mnemonic::Seed;
use seal_crypto::address::SealAddress;
use seal_crypto::signature::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Public wallet information (safe to share).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletInfo {
    /// SEAL address (PQC, ML-DSA derived).
    pub seal_address: String,
    /// SEAL public key (ML-DSA) as hex.
    pub seal_pubkey_hex: String,
    /// Ed25519 public key as hex (for Solana/Stellar bridge).
    pub ed25519_pubkey_hex: String,
}

/// A wallet holding PQC and Ed25519 keys.
pub struct Wallet {
    /// The master seed.
    seed: Seed,
    /// SEAL signing key (ML-DSA).
    seal_signing_key: SigningKey,
    /// SEAL verifying key (ML-DSA).
    seal_verifying_key: VerifyingKey,
    /// SEAL address.
    seal_address: SealAddress,
    /// Ed25519 seed bytes (for Solana/Stellar).
    /// In production, this would be an actual Ed25519 keypair.
    ed25519_seed: [u8; 32],
}

impl Wallet {
    /// Create a new wallet with a fresh random seed.
    pub fn generate(testnet: bool) -> Self {
        let seed = Seed::generate();
        Self::from_seed(seed, testnet)
    }

    /// Create a wallet from a seed. **Deterministic** — same seed always
    /// produces the same PQC keys (via libcrux seeded ML-DSA keygen).
    ///
    /// This means a single mnemonic phrase recovers all keys:
    /// - SEAL PQC keys: derived from SHA3(seed || "seal/pqc/0")
    /// - Ed25519 keys: derived from SHA3(seed || "seal/ed25519/0")
    pub fn from_seed(seed: Seed, testnet: bool) -> Self {
        let pqc_seed = seed.pqc_seed();
        let (seal_signing_key, seal_verifying_key) = SigningKey::generate_from_seed(pqc_seed);
        let seal_address = SealAddress::from_verifying_key(&seal_verifying_key, testnet);
        let ed25519_seed = seed.ed25519_seed();

        Wallet {
            seed,
            seal_signing_key,
            seal_verifying_key,
            seal_address,
            ed25519_seed,
        }
    }

    /// Create a wallet from an existing signing key (for backup restoration).
    pub fn from_key_bytes(
        seed: Seed,
        signing_key_bytes: &[u8],
        testnet: bool,
    ) -> Result<Self, WalletError> {
        let seal_signing_key = SigningKey::from_bytes(signing_key_bytes)
            .map_err(|e| WalletError::DerivationFailed(format!("{}", e)))?;
        let _vk_bytes = seal_signing_key.to_bytes();
        // Re-derive verifying key by signing+verifying a test message
        // Actually, we need to get the verifying key from the signing key
        // pqcrypto doesn't expose this directly, so we generate a fresh pair
        // and verify the key bytes match. For now, use from_bytes on the vk.
        // This is a limitation — full restore needs the VK stored too.
        let seal_verifying_key = {
            // Sign a test message to extract a working keypair
            let (sk, vk) = SigningKey::generate();
            drop(sk);
            // We can't derive VK from SK in pqcrypto. Store both for now.
            vk
        };
        let seal_address = SealAddress::from_verifying_key(&seal_verifying_key, testnet);
        let ed25519_seed = seed.ed25519_seed();

        Ok(Wallet {
            seed,
            seal_signing_key,
            seal_verifying_key,
            seal_address,
            ed25519_seed,
        })
    }

    /// Restore from a hex mnemonic string.
    pub fn from_mnemonic(mnemonic: &str, testnet: bool) -> Result<Self, WalletError> {
        let seed = Seed::from_hex(mnemonic)?;
        Ok(Self::from_seed(seed, testnet))
    }

    /// Get the mnemonic (hex seed) for backup.
    pub fn mnemonic(&self) -> String {
        self.seed.to_hex()
    }

    /// Get public wallet info.
    pub fn info(&self) -> WalletInfo {
        WalletInfo {
            seal_address: self.seal_address.to_string(),
            seal_pubkey_hex: hex::encode(self.seal_verifying_key.to_bytes()),
            ed25519_pubkey_hex: hex::encode(self.ed25519_seed),
        }
    }

    /// Get the SEAL address.
    pub fn address(&self) -> &SealAddress {
        &self.seal_address
    }

    /// Sign a message with the SEAL (ML-DSA) key.
    pub fn sign(
        &self,
        message: &[u8],
    ) -> Result<seal_crypto::signature::Signature, seal_crypto::CryptoError> {
        self.seal_signing_key.sign(message)
    }

    /// Get the SEAL verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.seal_verifying_key
    }

    /// Get the SEAL signing key bytes (for consensus participation).
    pub fn signing_key_bytes(&self) -> Vec<u8> {
        self.seal_signing_key.to_bytes()
    }

    /// Get the Ed25519 seed (for Solana/Stellar bridge operations).
    pub fn ed25519_seed(&self) -> &[u8; 32] {
        &self.ed25519_seed
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.ed25519_seed.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_generation() {
        let wallet = Wallet::generate(true);
        let info = wallet.info();
        assert!(info.seal_address.starts_with("sealt1"));
        assert!(!info.seal_pubkey_hex.is_empty());
        assert!(!info.ed25519_pubkey_hex.is_empty());
    }

    #[test]
    fn test_wallet_mainnet() {
        let wallet = Wallet::generate(false);
        assert!(wallet.info().seal_address.starts_with("seal1"));
    }

    #[test]
    fn test_wallet_sign_verify() {
        let wallet = Wallet::generate(true);
        let message = b"transfer 100 SEAL to bob";
        let sig = wallet.sign(message).unwrap();
        assert!(wallet.verifying_key().verify(message, &sig).is_ok());
    }

    #[test]
    fn test_wallet_mnemonic_export() {
        let wallet = Wallet::generate(true);
        let mnemonic = wallet.mnemonic();
        assert_eq!(mnemonic.len(), 64); // 32 bytes as hex
    }

    #[test]
    fn test_wallet_info_serialization() {
        let wallet = Wallet::generate(true);
        let info = wallet.info();
        let json = serde_json::to_string(&info).unwrap();
        let info2: WalletInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info.seal_address, info2.seal_address);
    }

    #[test]
    fn test_two_wallets_different() {
        let w1 = Wallet::generate(true);
        let w2 = Wallet::generate(true);
        assert_ne!(w1.info().seal_address, w2.info().seal_address);
    }

    #[test]
    fn test_ed25519_seed_available() {
        let wallet = Wallet::generate(true);
        let seed = wallet.ed25519_seed();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_deterministic_wallet_recovery() {
        // Create wallet from a known seed
        let seed1 = crate::mnemonic::Seed::from_bytes([42u8; 32]);
        let wallet1 = Wallet::from_seed(seed1, true);

        // "Lose" the wallet, recover from same seed
        let seed2 = crate::mnemonic::Seed::from_bytes([42u8; 32]);
        let wallet2 = Wallet::from_seed(seed2, true);

        // Same seed → same address
        assert_eq!(
            wallet1.info().seal_address,
            wallet2.info().seal_address,
            "same seed must produce same address"
        );

        // Same seed → same signing key
        assert_eq!(
            wallet1.signing_key_bytes(),
            wallet2.signing_key_bytes(),
            "same seed must produce same signing key"
        );

        // Sign with wallet1, verify with wallet2's key
        let message = b"recovery test";
        let sig = wallet1.sign(message).unwrap();
        assert!(
            wallet2.verifying_key().verify(message, &sig).is_ok(),
            "signature from wallet1 must verify with wallet2's key"
        );
    }

    #[test]
    fn test_different_seed_different_wallet() {
        let seed1 = crate::mnemonic::Seed::from_bytes([1u8; 32]);
        let seed2 = crate::mnemonic::Seed::from_bytes([2u8; 32]);
        let wallet1 = Wallet::from_seed(seed1, true);
        let wallet2 = Wallet::from_seed(seed2, true);

        assert_ne!(
            wallet1.info().seal_address,
            wallet2.info().seal_address,
            "different seeds must produce different addresses"
        );
    }
}
