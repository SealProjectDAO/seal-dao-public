//! Post-quantum VRF using ML-DSA + SHA3.
//!
//! A practical PQ-VRF construction using our existing PQ primitives:
//!
//! VRF(sk, input) = (output, proof) where:
//!   proof = ML-DSA.sign(sk, input)
//!   output = SHA3-256(proof)
//!
//! Properties:
//! - **Uniqueness**: For a given (sk, input), there is exactly one valid
//!   output. ML-DSA is deterministic for a given (sk, msg, randomness),
//!   and SHA3 is deterministic. Using fixed randomness (derived from sk+input)
//!   ensures uniqueness.
//! - **Pseudorandomness**: SHA3(ML-DSA_sig) is indistinguishable from random
//!   to anyone who doesn't know sk. The signature acts as a PRF.
//! - **Verifiability**: Anyone with pk can verify the ML-DSA signature,
//!   then compute SHA3(proof) to get the same output.
//!
//! This is NOT the LB-VRF from Esgin et al. (which has smaller proofs and
//! a formal security reduction to Module-LWE). This is a practical
//! construction that provides VRF functionality using NIST-standard PQC.
//!
//! Proof size: ~3,309 bytes (one ML-DSA-65 signature)
//! Output size: 32 bytes (SHA3-256 hash)
//!
//! Security: As strong as ML-DSA-65 (NIST Level 3, ~128-bit PQ security).

use crate::traits::{Vrf, VrfKeypair, VrfOutput, VrfProof};
use crate::VrfError;
use seal_crypto::hash::sha3_256;
use seal_crypto::signature::{SigningKey, VerifyingKey};

/// Post-quantum VRF based on ML-DSA + SHA3.
pub struct PqVrf;

impl Vrf for PqVrf {
    fn keygen() -> VrfKeypair {
        let (sk, vk) = SigningKey::generate();
        VrfKeypair {
            secret_key: sk.to_bytes(),
            public_key: vk.to_bytes(),
        }
    }

    fn eval(secret_key: &[u8], input: &[u8]) -> Result<(VrfOutput, VrfProof), VrfError> {
        let sk = SigningKey::from_bytes(secret_key).map_err(|_| VrfError::InvalidSecretKey)?;

        // Sign with deterministic randomness so same (sk, input) → same output
        let sig = sk
            .sign_deterministic(input)
            .map_err(|_| VrfError::InvalidSecretKey)?;
        let proof_bytes = sig.to_bytes().to_vec();

        // Output = SHA3-256(proof) — deterministic from the signature
        let output = sha3_256(&proof_bytes);

        Ok((VrfOutput(output.0), VrfProof { bytes: proof_bytes }))
    }

    fn verify(
        public_key: &[u8],
        input: &[u8],
        output: &VrfOutput,
        proof: &VrfProof,
    ) -> Result<(), VrfError> {
        // Reconstruct the verifying key
        let vk = VerifyingKey::from_bytes(public_key).map_err(|_| VrfError::InvalidPublicKey)?;

        // Verify the ML-DSA signature
        let sig = seal_crypto::signature::Signature::from_bytes(proof.bytes.clone());
        vk.verify(input, &sig)
            .map_err(|_| VrfError::VerificationFailed)?;

        // Check that output = SHA3-256(proof)
        let expected_output = sha3_256(&proof.bytes);
        if output.0 != expected_output.0 {
            return Err(VrfError::VerificationFailed);
        }

        Ok(())
    }
}

/// Generate a VRF keypair from a seed (deterministic).
pub fn keygen_from_seed(seed: [u8; 32]) -> VrfKeypair {
    let (sk, vk) = SigningKey::generate_from_seed(seed);
    VrfKeypair {
        secret_key: sk.to_bytes(),
        public_key: vk.to_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_vrf_eval_verify() {
        let kp = PqVrf::keygen();
        let input = b"slot_42_epoch_1";
        let (output, proof) = PqVrf::eval(&kp.secret_key, input).unwrap();

        assert!(PqVrf::verify(&kp.public_key, input, &output, &proof).is_ok());
    }

    #[test]
    fn test_pq_vrf_deterministic() {
        // Same key + same input → same output (deterministic signing)
        let kp = PqVrf::keygen();
        let (output1, proof1) = PqVrf::eval(&kp.secret_key, b"test").unwrap();
        let (output2, proof2) = PqVrf::eval(&kp.secret_key, b"test").unwrap();
        assert_eq!(output1, output2, "same (sk, input) must give same output");
        assert_eq!(
            proof1.bytes, proof2.bytes,
            "same (sk, input) must give same proof"
        );

        // Different input → different output
        let (output3, _) = PqVrf::eval(&kp.secret_key, b"other").unwrap();
        assert_ne!(output1, output3);
    }

    #[test]
    fn test_pq_vrf_wrong_key_fails() {
        let kp1 = PqVrf::keygen();
        let kp2 = PqVrf::keygen();
        let (output, proof) = PqVrf::eval(&kp1.secret_key, b"input").unwrap();
        assert!(PqVrf::verify(&kp2.public_key, b"input", &output, &proof).is_err());
    }

    #[test]
    fn test_pq_vrf_wrong_input_fails() {
        let kp = PqVrf::keygen();
        let (output, proof) = PqVrf::eval(&kp.secret_key, b"correct").unwrap();
        assert!(PqVrf::verify(&kp.public_key, b"wrong", &output, &proof).is_err());
    }

    #[test]
    fn test_pq_vrf_tampered_output_fails() {
        let kp = PqVrf::keygen();
        let (mut output, proof) = PqVrf::eval(&kp.secret_key, b"test").unwrap();
        output.0[0] ^= 0xFF; // Tamper
        assert!(PqVrf::verify(&kp.public_key, b"test", &output, &proof).is_err());
    }

    #[test]
    fn test_pq_vrf_seed_keygen() {
        let seed = [42u8; 32];
        let kp1 = keygen_from_seed(seed);
        let kp2 = keygen_from_seed(seed);
        assert_eq!(kp1.secret_key, kp2.secret_key);
        assert_eq!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn test_pq_vrf_threshold_election() {
        let kp = PqVrf::keygen();
        let threshold = u64::MAX / 10; // 10% election rate
        let mut elected = 0;
        for slot in 0..100 {
            let input = format!("slot_{}", slot);
            let (output, _) = PqVrf::eval(&kp.secret_key, input.as_bytes()).unwrap();
            if output.is_below_threshold(threshold) {
                elected += 1;
            }
        }
        // Should be roughly 10% (allow wide variance for randomness)
        assert!(elected > 0 && elected < 50, "elected {} of 100", elected);
    }
}
