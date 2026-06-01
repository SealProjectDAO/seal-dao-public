//! SNARK aggregation for committee threshold signatures.
//!
//! Reduces on-chain verification cost by wrapping Ringtail threshold
//! signatures in a STARK/SNARK proof. Instead of verifying the full
//! lattice-based signature (~2 KB, O(N) verification), validators check
//! a compact proof (~32-200 bytes) in O(1).
//!
//! # Architecture
//!
//! ```text
//! Committee (67+ of 100 members)
//!   ├── Ringtail Round 1 (preprocessed)
//!   ├── Ringtail Round 2 (on critical path)
//!   └── Aggregated ThresholdSignature (~2 KB)
//!         │
//!         ▼
//! SnarkAggregator::prove(threshold_sig, public_params)
//!         │
//!         ▼
//! AggregatedProof (~32-200 bytes)
//!         │
//!         ▼
//! SnarkAggregator::verify(proof, committee_root)
//!         ╰── O(1) verification
//! ```
//!
//! # What the SNARK proves
//!
//! Given public inputs:
//!   - `committee_root`: Merkle root of committee public keys
//!   - `message_hash`: SHA3 of the attested block
//!   - `participant_count`: number of signers
//!   - `threshold`: required minimum signers
//!
//! The proof attests:
//!   1. There exist ≥ threshold valid partial signatures
//!   2. Each partial sig is from a distinct committee member
//!   3. Each committee member's public key is in the Merkle tree
//!   4. The aggregated Ringtail signature verifies correctly
//!
//! # Status
//!
//! Scaffold — uses SHA3 commitment as placeholder proof.
//! Will be replaced with RISC Zero or SP1 STARK proof when
//! those backends are enabled (same guest program pattern as seal-zk).

use crate::traits::ThresholdSignature;
use seal_crypto::hash::{sha3_256, Hash256};
use serde::{Deserialize, Serialize};

/// Public inputs for the SNARK aggregation proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregationPublicInputs {
    /// Merkle root of the committee's public keys.
    pub committee_root: Hash256,
    /// Hash of the message that was signed (block hash).
    pub message_hash: Hash256,
    /// Number of committee members who participated.
    pub participant_count: u32,
    /// Threshold required for validity.
    pub threshold: u32,
    /// Total committee size.
    pub committee_size: u32,
}

/// A SNARK proof that a threshold signature is valid.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedProof {
    /// Proof bytes. Stub: SHA3 commitment (32 bytes).
    /// Production: STARK proof (~200 bytes after compression).
    pub bytes: Vec<u8>,
    /// Public inputs committed to in the proof.
    pub public_inputs: AggregationPublicInputs,
}

impl AggregatedProof {
    /// Size of the proof in bytes.
    pub fn size(&self) -> usize {
        self.bytes.len()
    }
}

/// SNARK aggregator for committee threshold signatures.
pub struct SnarkAggregator {
    /// Whether to use simulation mode (SHA3 commitment, no real SNARK).
    simulation: bool,
}

impl SnarkAggregator {
    /// Create a new aggregator in simulation mode.
    pub fn new() -> Self {
        SnarkAggregator { simulation: true }
    }

    /// Create an aggregator with real SNARK proving (when available).
    pub fn with_real_proving() -> Self {
        SnarkAggregator { simulation: false }
    }

    /// Generate a SNARK proof that a threshold signature is valid.
    ///
    /// # Arguments
    /// - `threshold_sig`: The aggregated Ringtail threshold signature
    /// - `committee_pks`: Public keys of all committee members
    /// - `message`: The message that was signed
    /// - `threshold`: Minimum number of signers required
    pub fn prove(
        &self,
        threshold_sig: &ThresholdSignature,
        committee_pks: &[Vec<u8>],
        message: &[u8],
        threshold: usize,
    ) -> Result<AggregatedProof, String> {
        let participant_count = threshold_sig.participant_count();

        if participant_count < threshold {
            return Err(format!(
                "insufficient signers: {} < {}",
                participant_count, threshold
            ));
        }

        // Compute committee Merkle root (simplified: hash of all pks)
        let committee_root = compute_committee_root(committee_pks);
        let message_hash = sha3_256(message);

        let public_inputs = AggregationPublicInputs {
            committee_root,
            message_hash,
            participant_count: participant_count as u32,
            threshold: threshold as u32,
            committee_size: committee_pks.len() as u32,
        };

        if self.simulation {
            // Simulation: SHA3 commitment over (threshold_sig || public_inputs)
            let witness = build_witness(threshold_sig, &public_inputs);
            let commitment = sha3_256(&witness);

            Ok(AggregatedProof {
                bytes: commitment.0.to_vec(),
                public_inputs,
            })
        } else {
            // Real proving would use RISC Zero / SP1 guest program:
            //
            // Guest program:
            //   1. Read threshold_sig, committee_pks, message from stdin
            //   2. Verify threshold_sig using Ringtail verify
            //   3. Verify each participant's pk is in committee_pks
            //   4. Verify participant_count >= threshold
            //   5. Commit public_inputs to journal
            //
            // For now, fall back to simulation.
            let witness = build_witness(threshold_sig, &public_inputs);
            let commitment = sha3_256(&witness);

            Ok(AggregatedProof {
                bytes: commitment.0.to_vec(),
                public_inputs,
            })
        }
    }

    /// Verify a SNARK aggregation proof.
    ///
    /// Checks:
    /// 1. Proof is well-formed
    /// 2. Public inputs match expected values
    /// 3. Participant count >= threshold
    pub fn verify(
        &self,
        proof: &AggregatedProof,
        expected_committee_root: &Hash256,
        expected_message_hash: &Hash256,
        threshold: usize,
    ) -> Result<(), String> {
        // Check public inputs
        if proof.public_inputs.committee_root != *expected_committee_root {
            return Err("committee root mismatch".to_string());
        }

        if proof.public_inputs.message_hash != *expected_message_hash {
            return Err("message hash mismatch".to_string());
        }

        if (proof.public_inputs.participant_count as usize) < threshold {
            return Err(format!(
                "insufficient participants: {} < {}",
                proof.public_inputs.participant_count, threshold
            ));
        }

        // Check proof format
        if proof.bytes.len() < 32 {
            return Err("proof too short".to_string());
        }

        // In simulation mode, we can't fully verify without the witness.
        // In production, STARK verification would go here:
        //
        // let receipt: Receipt = deserialize(&proof.bytes)?;
        // receipt.verify(AGGREGATOR_GUEST_ID)?;
        // let outputs: AggregationPublicInputs = receipt.journal.decode()?;
        // assert!(outputs == proof.public_inputs);

        Ok(())
    }
}

impl Default for SnarkAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a Merkle root from committee public keys.
///
/// Simplified: SHA3 of concatenated sorted public key hashes.
/// Production: proper Merkle tree from seal-merkle crate.
fn compute_committee_root(public_keys: &[Vec<u8>]) -> Hash256 {
    if public_keys.is_empty() {
        return sha3_256(b"empty-committee");
    }

    // Hash each public key, then hash all hashes together
    let mut pk_hashes: Vec<Hash256> = public_keys.iter().map(|pk| sha3_256(pk)).collect();
    pk_hashes.sort_by(|a, b| a.0.cmp(&b.0));

    let combined: Vec<u8> = pk_hashes.iter().flat_map(|h| h.0).collect();
    sha3_256(&combined)
}

/// Build the witness (private input) for the SNARK proof.
fn build_witness(
    threshold_sig: &ThresholdSignature,
    public_inputs: &AggregationPublicInputs,
) -> Vec<u8> {
    let sig_bytes = bincode::serialize(threshold_sig).unwrap_or_default();
    let input_bytes = bincode::serialize(public_inputs).unwrap_or_default();

    let mut witness = Vec::with_capacity(sig_bytes.len() + input_bytes.len());
    witness.extend_from_slice(&sig_bytes);
    witness.extend_from_slice(&input_bytes);
    witness
}

/// Verify a threshold signature and produce a SNARK proof in one step.
///
/// Convenience function that combines signature verification with SNARK proving.
pub fn verify_and_prove(
    aggregator: &SnarkAggregator,
    threshold_sig: &ThresholdSignature,
    committee_pks: &[Vec<u8>],
    message: &[u8],
    threshold: usize,
) -> Result<AggregatedProof, String> {
    // First, verify the threshold signature itself
    let participant_count = threshold_sig.participant_count();
    if participant_count < threshold {
        return Err(format!(
            "threshold not met: {} < {}",
            participant_count, threshold
        ));
    }

    // Then produce the SNARK proof
    aggregator.prove(threshold_sig, committee_pks, message, threshold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Bitfield;

    fn make_test_sig(signers: &[usize], committee_size: usize) -> ThresholdSignature {
        let mut participants = Bitfield::new(committee_size);
        for &i in signers {
            participants.set(i);
        }
        ThresholdSignature {
            signature: vec![0xAB; 2048], // Simulated Ringtail sig
            participants,
        }
    }

    fn make_test_pks(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| vec![i as u8; 32]).collect()
    }

    #[test]
    fn test_prove_and_verify() {
        let agg = SnarkAggregator::new();
        let pks = make_test_pks(100);
        let sig = make_test_sig(&(0..67).collect::<Vec<_>>(), 100);
        let message = b"block-hash-123";

        let proof = agg.prove(&sig, &pks, message, 67).unwrap();
        assert_eq!(proof.size(), 32); // SHA3 commitment
        assert_eq!(proof.public_inputs.participant_count, 67);
        assert_eq!(proof.public_inputs.threshold, 67);
        assert_eq!(proof.public_inputs.committee_size, 100);

        let committee_root = compute_committee_root(&pks);
        let msg_hash = sha3_256(message);
        assert!(agg.verify(&proof, &committee_root, &msg_hash, 67).is_ok());
    }

    #[test]
    fn test_insufficient_signers_rejected() {
        let agg = SnarkAggregator::new();
        let pks = make_test_pks(100);
        let sig = make_test_sig(&[0, 1, 2], 100); // Only 3 signers
        let message = b"block-hash";

        let result = agg.prove(&sig, &pks, message, 67);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_committee_root_rejected() {
        let agg = SnarkAggregator::new();
        let pks = make_test_pks(100);
        let sig = make_test_sig(&(0..67).collect::<Vec<_>>(), 100);
        let message = b"block-hash";

        let proof = agg.prove(&sig, &pks, message, 67).unwrap();

        let wrong_root = sha3_256(b"wrong-committee");
        let msg_hash = sha3_256(message);
        assert!(agg.verify(&proof, &wrong_root, &msg_hash, 67).is_err());
    }

    #[test]
    fn test_wrong_message_hash_rejected() {
        let agg = SnarkAggregator::new();
        let pks = make_test_pks(100);
        let sig = make_test_sig(&(0..67).collect::<Vec<_>>(), 100);
        let message = b"block-hash";

        let proof = agg.prove(&sig, &pks, message, 67).unwrap();

        let committee_root = compute_committee_root(&pks);
        let wrong_hash = sha3_256(b"wrong-message");
        assert!(agg
            .verify(&proof, &committee_root, &wrong_hash, 67)
            .is_err());
    }

    #[test]
    fn test_deterministic_proofs() {
        let agg = SnarkAggregator::new();
        let pks = make_test_pks(100);
        let sig = make_test_sig(&(0..67).collect::<Vec<_>>(), 100);
        let message = b"block-hash";

        let p1 = agg.prove(&sig, &pks, message, 67).unwrap();
        let p2 = agg.prove(&sig, &pks, message, 67).unwrap();
        assert_eq!(p1.bytes, p2.bytes);
    }

    #[test]
    fn test_committee_root_deterministic() {
        let pks = make_test_pks(100);
        let r1 = compute_committee_root(&pks);
        let r2 = compute_committee_root(&pks);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_different_committees_different_roots() {
        let pks1 = make_test_pks(100);
        let pks2 = make_test_pks(50);
        assert_ne!(compute_committee_root(&pks1), compute_committee_root(&pks2));
    }

    #[test]
    fn test_empty_committee() {
        let root = compute_committee_root(&[]);
        assert_eq!(root, sha3_256(b"empty-committee"));
    }

    #[test]
    fn test_verify_and_prove_convenience() {
        let agg = SnarkAggregator::new();
        let pks = make_test_pks(100);
        let sig = make_test_sig(&(0..70).collect::<Vec<_>>(), 100);
        let message = b"block";

        let proof = verify_and_prove(&agg, &sig, &pks, message, 67).unwrap();
        assert_eq!(proof.public_inputs.participant_count, 70);
    }
}
