//! VRF key rotation — epoch-based key management.
//!
//! LB-VRF is a "few-time" VRF: using the same key for too many
//! evaluations leaks information about the secret key. To mitigate:
//! each validator rotates their VRF key pair every epoch.
//!
//! Key derivation chain:
//!   master_seed (from wallet mnemonic)
//!     → epoch_seed = SHA3(master_seed || epoch_number)
//!     → VRF key pair = keygen_from_seed(epoch_seed)
//!
//! This is deterministic: same (master_seed, epoch) → same VRF key.
//! Recovery from mnemonic works across all epochs.
//!
//! PqVrf (ML-DSA based) is many-time and doesn't strictly need rotation,
//! but we rotate anyway for forward secrecy: compromising one epoch's
//! key doesn't compromise other epochs.

use crate::traits::{Vrf, VrfKeypair};
use seal_crypto::hash::sha3_256;
use zeroize::Zeroize;

/// Manages VRF key rotation across epochs.
pub struct VrfKeyManager {
    /// Master seed (32 bytes, from wallet mnemonic).
    /// Zeroized on drop.
    master_seed: [u8; 32],
    /// Current epoch number.
    current_epoch: u64,
    /// Current epoch's VRF key pair.
    current_keypair: VrfKeypair,
}

impl VrfKeyManager {
    /// Create a new key manager from a master seed.
    /// Initializes at epoch 0.
    pub fn new(master_seed: [u8; 32]) -> Self {
        let keypair = derive_epoch_keypair(&master_seed, 0);
        Self {
            master_seed,
            current_epoch: 0,
            current_keypair: keypair,
        }
    }

    /// Rotate to a new epoch. Derives a new VRF key pair.
    /// Returns the new public key (for announcing to the network).
    pub fn rotate_to_epoch(&mut self, epoch: u64) -> Vec<u8> {
        if epoch == self.current_epoch {
            return self.current_keypair.public_key.clone();
        }
        self.current_keypair = derive_epoch_keypair(&self.master_seed, epoch);
        self.current_epoch = epoch;
        self.current_keypair.public_key.clone()
    }

    /// Get the current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Get the current VRF secret key (for eval).
    pub fn secret_key(&self) -> &[u8] {
        &self.current_keypair.secret_key
    }

    /// Get the current VRF public key (for announcing).
    pub fn public_key(&self) -> &[u8] {
        &self.current_keypair.public_key
    }

    /// Derive the public key for a specific epoch (for verification).
    /// This doesn't change the current epoch.
    pub fn public_key_for_epoch(&self, epoch: u64) -> Vec<u8> {
        let kp = derive_epoch_keypair(&self.master_seed, epoch);
        kp.public_key
    }

    /// Evaluate the VRF for the current epoch.
    pub fn eval(&self, input: &[u8]) -> Result<(crate::traits::VrfOutput, crate::traits::VrfProof), crate::VrfError> {
        crate::pq_vrf::PqVrf::eval(&self.current_keypair.secret_key, input)
    }
}

impl Drop for VrfKeyManager {
    fn drop(&mut self) {
        self.master_seed.zeroize();
    }
}

/// Derive a VRF key pair for a specific epoch from a master seed.
///
/// epoch_seed = SHA3(master_seed || "seal_vrf_epoch" || epoch_number)
/// keypair = PqVrf::keygen_from_seed(epoch_seed)
fn derive_epoch_keypair(master_seed: &[u8; 32], epoch: u64) -> VrfKeypair {
    let mut input = Vec::with_capacity(32 + 14 + 8);
    input.extend_from_slice(master_seed);
    input.extend_from_slice(b"seal_vrf_epoch");
    input.extend_from_slice(&epoch.to_le_bytes());
    let epoch_seed = sha3_256(&input);
    crate::pq_vrf::keygen_from_seed(epoch_seed.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Vrf;

    #[test]
    fn test_key_manager_creates() {
        let seed = [42u8; 32];
        let mgr = VrfKeyManager::new(seed);
        assert_eq!(mgr.current_epoch(), 0);
        assert!(!mgr.public_key().is_empty());
        assert!(!mgr.secret_key().is_empty());
    }

    #[test]
    fn test_deterministic_derivation() {
        let seed = [42u8; 32];
        let mgr1 = VrfKeyManager::new(seed);
        let mgr2 = VrfKeyManager::new(seed);
        // Same seed → same epoch 0 keys
        assert_eq!(mgr1.public_key(), mgr2.public_key());
    }

    #[test]
    fn test_different_epochs_different_keys() {
        let seed = [42u8; 32];
        let mut mgr = VrfKeyManager::new(seed);
        let pk0 = mgr.public_key().to_vec();
        mgr.rotate_to_epoch(1);
        let pk1 = mgr.public_key().to_vec();
        assert_ne!(pk0, pk1, "different epochs should have different keys");
    }

    #[test]
    fn test_rotate_and_eval() {
        let seed = [7u8; 32];
        let mut mgr = VrfKeyManager::new(seed);
        mgr.rotate_to_epoch(5);

        let (output, proof) = mgr.eval(b"slot_42").unwrap();

        // Verify with the epoch's public key
        let pk = mgr.public_key();
        assert!(crate::pq_vrf::PqVrf::verify(pk, b"slot_42", &output, &proof).is_ok());
    }

    #[test]
    fn test_public_key_for_epoch() {
        let seed = [99u8; 32];
        let mgr = VrfKeyManager::new(seed);

        // public_key_for_epoch should match what we'd get if we rotated
        let pk_future = mgr.public_key_for_epoch(10);

        let mut mgr2 = VrfKeyManager::new(seed);
        mgr2.rotate_to_epoch(10);
        assert_eq!(pk_future, mgr2.public_key());
    }

    #[test]
    fn test_rotate_same_epoch_noop() {
        let seed = [42u8; 32];
        let mut mgr = VrfKeyManager::new(seed);
        let pk0 = mgr.public_key().to_vec();
        mgr.rotate_to_epoch(0); // Same epoch
        assert_eq!(pk0, mgr.public_key());
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let mgr1 = VrfKeyManager::new([1u8; 32]);
        let mgr2 = VrfKeyManager::new([2u8; 32]);
        assert_ne!(mgr1.public_key(), mgr2.public_key());
    }

    #[test]
    fn test_eval_deterministic_within_epoch() {
        let seed = [42u8; 32];
        let mgr = VrfKeyManager::new(seed);
        let (o1, p1) = mgr.eval(b"same_input").unwrap();
        let (o2, p2) = mgr.eval(b"same_input").unwrap();
        assert_eq!(o1, o2);
        assert_eq!(p1.bytes, p2.bytes);
    }

    #[test]
    fn test_cross_epoch_verification() {
        let seed = [42u8; 32];
        let mut mgr = VrfKeyManager::new(seed);

        // Eval at epoch 0
        let pk0 = mgr.public_key().to_vec();
        let (output0, proof0) = mgr.eval(b"slot_0").unwrap();

        // Rotate to epoch 1
        mgr.rotate_to_epoch(1);

        // Can still verify epoch 0's proof using epoch 0's public key
        assert!(crate::pq_vrf::PqVrf::verify(&pk0, b"slot_0", &output0, &proof0).is_ok());

        // Epoch 1's key can't verify epoch 0's proof
        let pk1 = mgr.public_key();
        assert!(crate::pq_vrf::PqVrf::verify(pk1, b"slot_0", &output0, &proof0).is_err());
    }
}
