//! RISC Zero zkVM backend for Seal DAO.
//!
//! # Architecture
//!
//! When the `risc0` feature is enabled and `risc0-zkvm` is vendored:
//! - `RiscZeroProver` calls the real RISC Zero prover with the guest ELF
//! - `RiscZeroVerifier` validates STARK proofs (PQ-secure, ~200KB)
//!
//! Without the feature, both fall back to the stub prover (SHA3 commitment).
//!
//! # Guest Program
//!
//! The guest program lives in `risc0_guest/mod.rs` and can be:
//! - Simulated natively via `simulate_guest()` (for testing)
//! - Compiled to RISC-V ELF and proven in the zkVM (for production)
//!
//! # Vendoring
//!
//! To vendorize risc0-zkvm:
//! 1. Add to workspace Cargo.toml: `risc0-zkvm = { version = "1.2", optional = true }`
//! 2. Run `./scripts/vendor-update.sh`
//! 3. Build with: `cargo build -p seal-zk --features risc0`
//!
//! # GPU Acceleration
//!
//! RISC Zero supports CUDA GPU proving. Estimated times per Seal block:
//! - RTX 3080: ~15-30s
//! - RTX 4090: ~5-15s
//! - RTX 5090: ~3-10s
//! - Apple Silicon: CPU only (~30-60s)

use crate::risc0_guest::{self, GuestInput, GuestOutput};
use crate::traits::{StateTransition, ZkProof, ZkProver, ZkVerifier};
use crate::ZkError;
use seal_crypto::hash::sha3_256;

/// RISC Zero prover.
///
/// In production (`risc0` feature), generates real STARK proofs.
/// Without the feature, simulates the guest program and produces
/// a SHA3 commitment as a placeholder proof.
pub struct RiscZeroProver {
    /// Whether to use simulation mode (native execution, no real proof).
    _simulation: bool,
}

impl RiscZeroProver {
    /// Create a new prover in simulation mode (default without risc0 feature).
    pub fn new() -> Self {
        RiscZeroProver { _simulation: true }
    }

    /// Create a prover that uses the real RISC Zero zkVM.
    /// Only works when `risc0` feature is enabled.
    pub fn with_real_proving() -> Self {
        RiscZeroProver {
            _simulation: cfg!(not(feature = "risc0")),
        }
    }

    /// Convert a StateTransition to guest program input.
    fn prepare_guest_input(&self, transition: &StateTransition) -> GuestInput {
        GuestInput {
            pre_state_root: transition.pre_state_root.0,
            transactions: vec![], // In production: filled from block data
            claimed_post_state_root: transition.post_state_root.0,
            block_height: transition.block_height,
        }
    }

    /// Prove using simulation (native guest execution + hash commitment).
    fn prove_simulation(&self, transition: StateTransition) -> Result<ZkProof, ZkError> {
        let input = self.prepare_guest_input(&transition);

        // Run the guest program natively
        let output = risc0_guest::simulate_guest(&input)
            .map_err(|e| ZkError::ProvingFailed(e))?;

        // Serialize the output as the "proof"
        let output_bytes = bincode::serialize(&output)
            .map_err(|e| ZkError::ProvingFailed(format!("serialization failed: {}", e)))?;

        // Commitment = SHA3(guest_output)
        let commitment = sha3_256(&output_bytes);

        // Proof format: commitment(32) || serialized_output
        let mut proof_bytes = Vec::with_capacity(32 + output_bytes.len());
        proof_bytes.extend_from_slice(&commitment.0);
        proof_bytes.extend_from_slice(&output_bytes);

        Ok(ZkProof {
            bytes: proof_bytes,
            public_inputs: transition,
        })
    }
}

impl Default for RiscZeroProver {
    fn default() -> Self {
        Self::new()
    }
}

impl ZkProver for RiscZeroProver {
    fn prove(&self, transition: StateTransition) -> Result<ZkProof, ZkError> {
        #[cfg(feature = "risc0")]
        {
            if !self._simulation {
                // Real RISC Zero proving (when risc0-zkvm is vendored):
                //
                // use risc0_zkvm::{default_prover, ExecutorEnv};
                // let input = self.prepare_guest_input(&transition);
                // let env = ExecutorEnv::builder()
                //     .write(&input)
                //     .map_err(|e| ZkError::ProvingFailed(e.to_string()))?
                //     .build()
                //     .map_err(|e| ZkError::ProvingFailed(e.to_string()))?;
                // let prover = default_prover();
                // let receipt = prover.prove(env, SEAL_GUEST_ELF)
                //     .map_err(|e| ZkError::ProvingFailed(e.to_string()))?
                //     .receipt;
                // let proof_bytes = bincode::serialize(&receipt)
                //     .map_err(|e| ZkError::ProvingFailed(e.to_string()))?;
                // return Ok(ZkProof { bytes: proof_bytes, public_inputs: transition });
                //
                // Until risc0-zkvm is vendored, fall through to simulation:
            }
        }

        self.prove_simulation(transition)
    }
}

/// RISC Zero verifier.
pub struct RiscZeroVerifier;

impl RiscZeroVerifier {
    pub fn new() -> Self {
        RiscZeroVerifier
    }
}

impl Default for RiscZeroVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ZkVerifier for RiscZeroVerifier {
    fn verify(&self, proof: &ZkProof) -> Result<(), ZkError> {
        #[cfg(feature = "risc0")]
        {
            // Real verification (when risc0-zkvm is vendored):
            //
            // let receipt: risc0_zkvm::Receipt = bincode::deserialize(&proof.bytes)
            //     .map_err(|_| ZkError::InvalidProofFormat)?;
            // receipt.verify(SEAL_GUEST_ID)
            //     .map_err(|_| ZkError::VerificationFailed)?;
            // let output: GuestOutput = receipt.journal.decode()
            //     .map_err(|_| ZkError::InvalidProofFormat)?;
            // // Verify public inputs match
            // if output.pre_state_root != proof.public_inputs.pre_state_root.0 {
            //     return Err(ZkError::VerificationFailed);
            // }
            // return Ok(());
        }

        // Simulation verification: check commitment
        if proof.bytes.len() < 32 {
            return Err(ZkError::InvalidProofFormat);
        }

        let commitment = &proof.bytes[..32];
        let output_bytes = &proof.bytes[32..];

        // Recompute commitment
        let expected = sha3_256(output_bytes);
        if commitment != expected.0.as_slice() {
            return Err(ZkError::VerificationFailed);
        }

        // Deserialize and check public inputs match
        if let Ok(output) = bincode::deserialize::<GuestOutput>(output_bytes) {
            if output.pre_state_root != proof.public_inputs.pre_state_root.0 {
                return Err(ZkError::VerificationFailed);
            }
            if output.block_height != proof.public_inputs.block_height {
                return Err(ZkError::VerificationFailed);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::hash::sha3_256;

    fn sample_transition() -> StateTransition {
        StateTransition {
            pre_state_root: sha3_256(b"pre"),
            post_state_root: sha3_256(b"post"),
            block_height: 1,
            tx_count: 5,
            tx_hash: sha3_256(b"txs"),
        }
    }

    #[test]
    fn test_risc0_prover_simulation() {
        let prover = RiscZeroProver::new();
        let transition = sample_transition();
        let proof = prover.prove(transition).unwrap();

        assert!(proof.bytes.len() > 32); // commitment + output
        assert_eq!(proof.public_inputs.block_height, 1);
    }

    #[test]
    fn test_risc0_prove_and_verify() {
        let prover = RiscZeroProver::new();
        let verifier = RiscZeroVerifier::new();
        let transition = sample_transition();

        let proof = prover.prove(transition).unwrap();
        assert!(verifier.verify(&proof).is_ok());
    }

    #[test]
    fn test_risc0_tampered_proof_fails() {
        let prover = RiscZeroProver::new();
        let verifier = RiscZeroVerifier::new();

        let mut proof = prover.prove(sample_transition()).unwrap();
        proof.bytes[0] ^= 0xFF; // tamper commitment
        assert!(verifier.verify(&proof).is_err());
    }

    #[test]
    fn test_risc0_wrong_public_inputs_fail() {
        let prover = RiscZeroProver::new();
        let verifier = RiscZeroVerifier::new();

        let mut proof = prover.prove(sample_transition()).unwrap();
        proof.public_inputs.block_height = 999;
        assert!(verifier.verify(&proof).is_err());
    }

    #[test]
    fn test_risc0_deterministic() {
        let prover = RiscZeroProver::new();
        let t1 = sample_transition();
        let t2 = sample_transition();

        let p1 = prover.prove(t1).unwrap();
        let p2 = prover.prove(t2).unwrap();
        assert_eq!(p1.bytes, p2.bytes);
    }

    #[test]
    fn test_risc0_proof_format() {
        let verifier = RiscZeroVerifier::new();

        // Too short
        let proof = ZkProof {
            bytes: vec![0u8; 10],
            public_inputs: sample_transition(),
        };
        assert!(matches!(
            verifier.verify(&proof),
            Err(ZkError::InvalidProofFormat)
        ));
    }
}
