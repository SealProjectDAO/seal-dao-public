//! Stub ZK prover/verifier — hash commitment placeholder.
//!
//! Produces a SHA3 hash of the state transition as a "proof".
//! NOT a real ZK proof — verifier must trust the prover.
//!
//! # TODO: Replace with RISC Zero
//!
//! - [ ] Add risc0-zkvm dependency
//! - [ ] Write guest program (Rust) that:
//!   - Replays SQL write ops against Merkle state
//!   - Verifies pre_state_root → post_state_root
//!   - Verifies all transaction signatures (ML-DSA)
//!   - Verifies access control policies
//! - [ ] Host code generates STARK proof via RISC Zero prover
//! - [ ] Verifier checks STARK proof natively (no Groth16 wrapper for PQ)
//! - [ ] Benchmark: target <10s per block proof generation
//! - [ ] Alternatives: SP1, OpenVM (same RISC-V ISA, same Rust guest)

use crate::traits::{StateTransition, ZkProof, ZkProver, ZkVerifier};
use crate::ZkError;
use seal_crypto::hash::Sha3Hasher;

/// Stub prover: produces SHA3 commitment as "proof".
pub struct StubProver;

impl ZkProver for StubProver {
    fn prove(&self, transition: StateTransition) -> Result<ZkProof, ZkError> {
        // "Proof" = SHA3(pre_root || post_root || height || tx_hash)
        let mut hasher = Sha3Hasher::new();
        hasher.update(transition.pre_state_root.as_ref());
        hasher.update(transition.post_state_root.as_ref());
        hasher.update(&transition.block_height.to_le_bytes());
        hasher.update(&transition.tx_count.to_le_bytes());
        hasher.update(transition.tx_hash.as_ref());
        let commitment = hasher.finalize();

        Ok(ZkProof {
            bytes: commitment.0.to_vec(),
            public_inputs: transition,
        })
    }
}

/// Stub verifier: recomputes the hash commitment and checks it matches.
pub struct StubVerifier;

impl ZkVerifier for StubVerifier {
    fn verify(&self, proof: &ZkProof) -> Result<(), ZkError> {
        if proof.bytes.len() != 32 {
            return Err(ZkError::InvalidProofFormat);
        }

        // Recompute commitment
        let t = &proof.public_inputs;
        let mut hasher = Sha3Hasher::new();
        hasher.update(t.pre_state_root.as_ref());
        hasher.update(t.post_state_root.as_ref());
        hasher.update(&t.block_height.to_le_bytes());
        hasher.update(&t.tx_count.to_le_bytes());
        hasher.update(t.tx_hash.as_ref());
        let expected = hasher.finalize();

        if proof.bytes == expected.0 {
            Ok(())
        } else {
            Err(ZkError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::hash::sha3_256;

    fn sample_transition() -> StateTransition {
        StateTransition {
            pre_state_root: sha3_256(b"pre_state"),
            post_state_root: sha3_256(b"post_state"),
            block_height: 42,
            tx_count: 10,
            tx_hash: sha3_256(b"tx_list_hash"),
        }
    }

    #[test]
    fn test_prove_and_verify() {
        let prover = StubProver;
        let verifier = StubVerifier;
        let transition = sample_transition();

        let proof = prover.prove(transition).unwrap();
        assert_eq!(proof.size(), 32); // SHA3-256 commitment
        assert!(verifier.verify(&proof).is_ok());
    }

    #[test]
    fn test_proof_deterministic() {
        let prover = StubProver;
        let t1 = sample_transition();
        let t2 = sample_transition();

        let p1 = prover.prove(t1).unwrap();
        let p2 = prover.prove(t2).unwrap();
        assert_eq!(p1.bytes, p2.bytes);
    }

    #[test]
    fn test_tampered_proof_fails() {
        let prover = StubProver;
        let verifier = StubVerifier;

        let mut proof = prover.prove(sample_transition()).unwrap();
        proof.bytes[0] ^= 0xFF; // Tamper
        assert!(verifier.verify(&proof).is_err());
    }

    #[test]
    fn test_wrong_public_inputs_fail() {
        let prover = StubProver;
        let verifier = StubVerifier;

        let mut proof = prover.prove(sample_transition()).unwrap();
        proof.public_inputs.block_height = 999; // Change public input
        assert!(verifier.verify(&proof).is_err());
    }

    #[test]
    fn test_different_transitions_different_proofs() {
        let prover = StubProver;
        let t1 = sample_transition();
        let mut t2 = sample_transition();
        t2.block_height = 43;

        let p1 = prover.prove(t1).unwrap();
        let p2 = prover.prove(t2).unwrap();
        assert_ne!(p1.bytes, p2.bytes);
    }

    #[test]
    fn test_invalid_proof_format() {
        let verifier = StubVerifier;
        let proof = ZkProof {
            bytes: vec![0u8; 10], // Wrong size
            public_inputs: sample_transition(),
        };
        assert!(matches!(
            verifier.verify(&proof),
            Err(ZkError::InvalidProofFormat)
        ));
    }
}
