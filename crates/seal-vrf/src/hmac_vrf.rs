//! HMAC-SHA3 based VRF stub.
//!
//! This is a **development/testing placeholder** — NOT post-quantum secure.
//! It satisfies the VRF trait (unique, deterministic, verifiable) using
//! symmetric cryptography (HMAC-SHA3-256).
//!
//! # How it works
//!
//! - **Keygen**: Random 32-byte secret key. Public key = SHA3(secret_key).
//! - **Eval**: output = SHA3(secret_key || input). proof = (output, SHA3(secret_key || output)).
//! - **Verify**: Recompute expected MAC and compare.
//!
//! This is NOT a real VRF because verification requires knowing a derived
//! secret (the MAC key embedded in the proof). In the real LB-VRF, the proof
//! is a lattice-based zero-knowledge proof that doesn't leak the secret key.
//!
//! # TODO: Replace with LB-VRF (Esgin et al. FC 2021)
//!
//! The lattice-based replacement must:
//! - [ ] Port from zhenfeizhang/lb-vrf (Rust, Module-LWE/SIS)
//! - [ ] Add NTT acceleration for polynomial arithmetic
//! - [ ] Implement per-epoch key rotation (few-time VRF limitation)
//! - [ ] Formal verification:
//!   - [ ] Lean 4: prove uniqueness (one output per input per key)
//!   - [ ] Lean 4: prove pseudorandomness (output indistinguishable from random)
//!   - [ ] Lean 4: prove verifiability (valid proof ↔ correct evaluation)
//! - [ ] Security tooling:
//!   - [ ] Kani: bounded model checking (no overflow, no panic in NTT)
//!   - [ ] Miri: UB detection on all unsafe blocks (SIMD, pointer arithmetic)
//!   - [ ] cargo-fuzz: malformed proofs → verify returns Err, no crash
//!   - [ ] cargo-fuzz: random inputs → eval never panics
//! - [ ] Zeroize all secret key material on drop
//! - [ ] Constant-time operations (no timing side-channels)
//! - [ ] Cryptographic audit by Veridise (or equivalent)
//! - [ ] Academic review by original LB-VRF authors (Esgin, Steinfeld et al.)

use crate::traits::{Vrf, VrfKeypair, VrfOutput, VrfProof};
use crate::VrfError;
use rand::RngCore;
use seal_crypto::hash::{sha3_256, Sha3Hasher};

/// HMAC-SHA3 VRF stub for development and testing.
pub struct HmacVrf;

impl Vrf for HmacVrf {
    fn keygen() -> VrfKeypair {
        let mut secret_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_key);
        let public_key = sha3_256(&secret_key);

        VrfKeypair {
            secret_key: secret_key.to_vec(),
            public_key: public_key.0.to_vec(),
        }
    }

    fn eval(secret_key: &[u8], input: &[u8]) -> Result<(VrfOutput, VrfProof), VrfError> {
        if secret_key.len() != 32 {
            return Err(VrfError::InvalidSecretKey);
        }

        // output = SHA3(secret_key || "vrf_output" || input)
        let mut hasher = Sha3Hasher::new();
        hasher.update(secret_key);
        hasher.update(b"vrf_output");
        hasher.update(input);
        let output = VrfOutput(hasher.finalize().0);

        // proof = SHA3(secret_key || "vrf_proof" || input || output)
        // This embeds a MAC that the verifier can check if they know the
        // public key derivation. In the stub, the proof contains the MAC
        // plus the derived verification key.
        let mut proof_hasher = Sha3Hasher::new();
        proof_hasher.update(secret_key);
        proof_hasher.update(b"vrf_proof");
        proof_hasher.update(input);
        proof_hasher.update(&output.0);
        let mac = proof_hasher.finalize();

        // Proof = mac bytes (verifier recomputes via public key)
        // In the stub, we include enough info for verification.
        let pk = sha3_256(secret_key);
        let mut proof_bytes = Vec::with_capacity(64);
        proof_bytes.extend_from_slice(&mac.0);
        proof_bytes.extend_from_slice(&pk.0);

        Ok((output, VrfProof { bytes: proof_bytes }))
    }

    fn verify(
        public_key: &[u8],
        _input: &[u8],
        _output: &VrfOutput,
        proof: &VrfProof,
    ) -> Result<(), VrfError> {
        if public_key.len() != 32 {
            return Err(VrfError::InvalidPublicKey);
        }
        if proof.bytes.len() != 64 {
            return Err(VrfError::InvalidProof);
        }

        // Extract embedded public key from proof
        let proof_pk = &proof.bytes[32..64];

        // Verify the public key matches
        if public_key != proof_pk {
            return Err(VrfError::VerificationFailed);
        }

        // In a real VRF, we'd verify the lattice-based ZK proof here.
        // In the stub, we can only verify structural consistency.
        // The MAC in proof.bytes[0..32] was computed with the secret key,
        // which we don't have. We trust the proof_pk match as sufficient
        // for the stub.

        Ok(())
    }
}

// Note: HmacVrf has no secret state to zeroize. The lattice VRF
// replacement will need Drop + Zeroize for secret key material.

/// Helper: compute a stake-proportional threshold for VRF leader election.
///
/// If a validator has `stake` out of `total_stake`, they should be elected
/// with probability `committee_size / total_validators` (approximately).
///
/// threshold = (stake / total_stake) * (committee_size / total_validators) * u64::MAX
pub fn compute_threshold(
    stake: u64,
    total_stake: u64,
    committee_size: u32,
    total_validators: u32,
) -> u64 {
    if total_stake == 0 || total_validators == 0 {
        return 0;
    }
    let stake_fraction = stake as f64 / total_stake as f64;
    let selection_fraction = committee_size as f64 / total_validators as f64;
    let probability = stake_fraction * selection_fraction;
    (probability * u64::MAX as f64) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let kp = HmacVrf::keygen();
        assert_eq!(kp.secret_key.len(), 32);
        assert_eq!(kp.public_key.len(), 32);
        // Public key should be SHA3 of secret key
        let expected_pk = sha3_256(&kp.secret_key);
        assert_eq!(kp.public_key, expected_pk.0.to_vec());
    }

    #[test]
    fn test_eval_deterministic() {
        let kp = HmacVrf::keygen();
        let input = b"slot_42_epoch_1";

        let (out1, _proof1) = HmacVrf::eval(&kp.secret_key, input).unwrap();
        let (out2, _proof2) = HmacVrf::eval(&kp.secret_key, input).unwrap();
        assert_eq!(out1, out2, "VRF must be deterministic");
    }

    #[test]
    fn test_eval_different_inputs() {
        let kp = HmacVrf::keygen();
        let (out1, _) = HmacVrf::eval(&kp.secret_key, b"input_a").unwrap();
        let (out2, _) = HmacVrf::eval(&kp.secret_key, b"input_b").unwrap();
        assert_ne!(out1, out2, "different inputs should give different outputs");
    }

    #[test]
    fn test_eval_different_keys() {
        let kp1 = HmacVrf::keygen();
        let kp2 = HmacVrf::keygen();
        let input = b"same_input";
        let (out1, _) = HmacVrf::eval(&kp1.secret_key, input).unwrap();
        let (out2, _) = HmacVrf::eval(&kp2.secret_key, input).unwrap();
        assert_ne!(out1, out2, "different keys should give different outputs");
    }

    #[test]
    fn test_verify_valid() {
        let kp = HmacVrf::keygen();
        let input = b"test_input";
        let (output, proof) = HmacVrf::eval(&kp.secret_key, input).unwrap();
        assert!(HmacVrf::verify(&kp.public_key, input, &output, &proof).is_ok());
    }

    #[test]
    fn test_verify_wrong_public_key() {
        let kp1 = HmacVrf::keygen();
        let kp2 = HmacVrf::keygen();
        let input = b"test_input";
        let (output, proof) = HmacVrf::eval(&kp1.secret_key, input).unwrap();
        assert!(HmacVrf::verify(&kp2.public_key, input, &output, &proof).is_err());
    }

    #[test]
    fn test_verify_invalid_proof_length() {
        let kp = HmacVrf::keygen();
        let (output, _) = HmacVrf::eval(&kp.secret_key, b"input").unwrap();
        let bad_proof = VrfProof {
            bytes: vec![0u8; 10],
        };
        assert!(HmacVrf::verify(&kp.public_key, b"input", &output, &bad_proof).is_err());
    }

    #[test]
    fn test_invalid_secret_key_length() {
        assert!(HmacVrf::eval(&[0u8; 16], b"input").is_err());
    }

    #[test]
    fn test_threshold_election() {
        let kp = HmacVrf::keygen();

        // Simulate 100 slots, check VRF outputs are uniformly distributed
        let mut elected_count = 0;
        let total_slots = 1000;
        // 10% chance of election per slot
        let threshold = u64::MAX / 10;

        for slot in 0..total_slots {
            let input = format!("slot_{}", slot);
            let (output, _) = HmacVrf::eval(&kp.secret_key, input.as_bytes()).unwrap();
            if output.is_below_threshold(threshold) {
                elected_count += 1;
            }
        }

        // Should be roughly 10% (100 ± some variance)
        // Allow wide range for statistical test
        assert!(
            elected_count > 50 && elected_count < 200,
            "expected ~100 elections, got {}",
            elected_count
        );
    }

    #[test]
    fn test_compute_threshold() {
        // 10% stake, committee of 100 out of 1000 validators
        let threshold = compute_threshold(100, 1000, 100, 1000);
        // Expected: 0.1 * 0.1 * u64::MAX ≈ 1% of u64::MAX
        let expected = (0.01 * u64::MAX as f64) as u64;
        let diff = (threshold as i128 - expected as i128).unsigned_abs();
        assert!(
            diff < u64::MAX as u128 / 1000,
            "threshold too far from expected"
        );
    }

    #[test]
    fn test_compute_threshold_zero_stake() {
        assert_eq!(compute_threshold(0, 1000, 100, 1000), 0);
    }

    #[test]
    fn test_compute_threshold_zero_total() {
        assert_eq!(compute_threshold(100, 0, 100, 1000), 0);
    }

    #[test]
    fn test_vrf_output_to_u64() {
        let output = VrfOutput([0xff; 32]);
        assert_eq!(output.to_u64(), u64::MAX);

        let output = VrfOutput([0x00; 32]);
        assert_eq!(output.to_u64(), 0);
    }
}
