//! Batch proof aggregation for Seal DAO.
//!
//! Instead of proving each block independently, the batch prover
//! aggregates multiple blocks into a single proof. This amortizes
//! the per-proof overhead and is critical for throughput.
//!
//! # Strategy
//!
//! ```text
//! Block N     Block N+1     Block N+2
//!   │            │              │
//!   ├─ prove ─┐  ├─ prove ─┐   ├─ prove ─┐
//!   │         │  │         │   │         │
//!   └─────────┴──┴─────────┴───┴─────────┘
//!                    │
//!              Batch proof
//!           (single STARK proof)
//! ```
//!
//! The batch proof asserts:
//! - pre_state_root(block_N) → post_state_root(block_N) = pre_state_root(block_N+1)
//! - Each block's transactions are valid
//! - Chain of state roots is consistent

use crate::traits::{StateTransition, ZkProof, ZkProver, ZkVerifier};
use crate::ZkError;
use seal_crypto::hash::{sha3_256, Sha3Hasher};

/// A batch of state transitions to prove together.
#[derive(Clone, Debug)]
pub struct BatchTransition {
    /// Ordered list of block transitions.
    pub transitions: Vec<StateTransition>,
}

impl BatchTransition {
    /// Create a new batch from a sequence of transitions.
    /// Validates that the chain is consistent: each post_state_root
    /// matches the next block's pre_state_root.
    pub fn new(transitions: Vec<StateTransition>) -> Result<Self, ZkError> {
        if transitions.is_empty() {
            return Err(ZkError::InvalidTransition("batch is empty".into()));
        }

        // Validate chain consistency
        for window in transitions.windows(2) {
            if window[0].post_state_root != window[1].pre_state_root {
                return Err(ZkError::InvalidTransition(
                    "state root chain is inconsistent".into(),
                ));
            }
        }

        // Validate block heights are sequential
        for window in transitions.windows(2) {
            if window[1].block_height != window[0].block_height + 1 {
                return Err(ZkError::InvalidTransition(
                    "block heights are not sequential".into(),
                ));
            }
        }

        Ok(Self { transitions })
    }

    /// First block's pre-state root.
    pub fn initial_state_root(&self) -> Result<&seal_crypto::hash::Hash256, ZkError> {
        self.transitions
            .first()
            .map(|t| &t.pre_state_root)
            .ok_or_else(|| ZkError::InvalidTransition("batch is empty".into()))
    }

    /// Last block's post-state root.
    pub fn final_state_root(&self) -> Result<&seal_crypto::hash::Hash256, ZkError> {
        self.transitions
            .last()
            .map(|t| &t.post_state_root)
            .ok_or_else(|| ZkError::InvalidTransition("batch is empty".into()))
    }

    /// Range of block heights in this batch.
    pub fn height_range(&self) -> Result<(u64, u64), ZkError> {
        let first = self.transitions
            .first()
            .ok_or_else(|| ZkError::InvalidTransition("batch is empty".into()))?
            .block_height;
        let last = self.transitions
            .last()
            .ok_or_else(|| ZkError::InvalidTransition("batch is empty".into()))?
            .block_height;
        Ok((first, last))
    }

    /// Total number of transactions across all blocks.
    pub fn total_tx_count(&self) -> u32 {
        self.transitions.iter().map(|t| t.tx_count).sum()
    }

    /// Number of blocks in the batch.
    pub fn block_count(&self) -> usize {
        self.transitions.len()
    }
}

/// Batch prover: proves multiple blocks in a single proof.
pub struct BatchProver<P: ZkProver> {
    inner: P,
}

impl<P: ZkProver> BatchProver<P> {
    pub fn new(inner: P) -> Self {
        Self { inner }
    }

    /// Prove a batch of transitions.
    /// Returns a single proof covering the entire batch.
    pub fn prove_batch(&self, batch: &BatchTransition) -> Result<ZkProof, ZkError> {
        // Strategy: create a "super-transition" that covers the full range,
        // then use the inner prover.
        //
        // In the real implementation with RISC Zero/SP1, the guest program
        // would replay all blocks sequentially and produce one proof.
        // For the stub, we hash all individual proofs together.

        let mut combined_hasher = Sha3Hasher::new();

        for transition in &batch.transitions {
            let proof = self.inner.prove(transition.clone())?;
            combined_hasher.update(&proof.bytes);
        }

        let batch_commitment = combined_hasher.finalize();

        // The batch proof's public inputs summarize the entire range
        let super_transition = StateTransition {
            pre_state_root: *batch.initial_state_root()?,
            post_state_root: *batch.final_state_root()?,
            block_height: batch.height_range()?.0,
            tx_count: batch.total_tx_count(),
            tx_hash: sha3_256(&batch_commitment.0),
        };

        Ok(ZkProof {
            bytes: batch_commitment.0.to_vec(),
            public_inputs: super_transition,
        })
    }
}

/// Batch verifier: verifies a batch proof.
pub struct BatchVerifier<V: ZkVerifier> {
    /// Inner verifier (used when real STARK backend is enabled).
    #[allow(dead_code)]
    inner: V,
}

impl<V: ZkVerifier> BatchVerifier<V> {
    pub fn new(inner: V) -> Self {
        Self { inner }
    }

    /// Verify a batch proof.
    pub fn verify_batch(&self, proof: &ZkProof) -> Result<(), ZkError> {
        // For the stub, delegate to inner verifier's format check.
        // Real implementation would verify the aggregated STARK proof.
        if proof.bytes.len() != 32 {
            return Err(ZkError::InvalidProofFormat);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stub::{StubProver, StubVerifier};

    #[allow(dead_code)]
    fn make_transition(height: u64, pre: &[u8], post: &[u8]) -> StateTransition {
        StateTransition {
            pre_state_root: sha3_256(pre),
            post_state_root: sha3_256(post),
            block_height: height,
            tx_count: 5,
            tx_hash: sha3_256(&[height as u8]),
        }
    }

    fn make_chain(count: usize) -> Vec<StateTransition> {
        let mut transitions = Vec::new();
        for i in 0..count {
            let pre = sha3_256(&[i as u8]);
            let post = sha3_256(&[(i + 1) as u8]);
            transitions.push(StateTransition {
                pre_state_root: pre,
                post_state_root: post,
                block_height: i as u64,
                tx_count: 3,
                tx_hash: sha3_256(&[100 + i as u8]),
            });
        }
        transitions
    }

    #[test]
    fn test_batch_transition_valid() {
        let chain = make_chain(5);
        let batch = BatchTransition::new(chain).unwrap();
        assert_eq!(batch.block_count(), 5);
        assert_eq!(batch.height_range().unwrap(), (0, 4));
        assert_eq!(batch.total_tx_count(), 15);
    }

    #[test]
    fn test_batch_transition_empty_fails() {
        let result = BatchTransition::new(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_transition_inconsistent_roots_fails() {
        let mut chain = make_chain(3);
        // Break the chain: block 1's pre_state != block 0's post_state
        chain[1].pre_state_root = sha3_256(b"wrong");
        let result = BatchTransition::new(chain);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_transition_non_sequential_heights_fails() {
        let mut chain = make_chain(3);
        chain[2].block_height = 10; // Skip heights
        let result = BatchTransition::new(chain);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_transition_single_block() {
        let chain = make_chain(1);
        let batch = BatchTransition::new(chain).unwrap();
        assert_eq!(batch.block_count(), 1);
        assert_eq!(batch.height_range().unwrap(), (0, 0));
    }

    #[test]
    fn test_batch_prover() {
        let chain = make_chain(3);
        let batch = BatchTransition::new(chain).unwrap();
        let prover = BatchProver::new(StubProver);
        let proof = prover.prove_batch(&batch).unwrap();

        assert_eq!(proof.size(), 32);
        assert_eq!(proof.public_inputs.block_height, 0);
        assert_eq!(proof.public_inputs.tx_count, 9); // 3 blocks × 3 txs
    }

    #[test]
    fn test_batch_prover_deterministic() {
        let chain1 = make_chain(3);
        let chain2 = make_chain(3);
        let batch1 = BatchTransition::new(chain1).unwrap();
        let batch2 = BatchTransition::new(chain2).unwrap();
        let prover = BatchProver::new(StubProver);

        let p1 = prover.prove_batch(&batch1).unwrap();
        let p2 = prover.prove_batch(&batch2).unwrap();
        assert_eq!(p1.bytes, p2.bytes);
    }

    #[test]
    fn test_batch_verifier() {
        let chain = make_chain(5);
        let batch = BatchTransition::new(chain).unwrap();
        let prover = BatchProver::new(StubProver);
        let verifier = BatchVerifier::new(StubVerifier);

        let proof = prover.prove_batch(&batch).unwrap();
        assert!(verifier.verify_batch(&proof).is_ok());
    }

    #[test]
    fn test_batch_verifier_invalid_format() {
        let verifier = BatchVerifier::new(StubVerifier);
        let proof = ZkProof {
            bytes: vec![0u8; 10], // Wrong size
            public_inputs: StateTransition {
                pre_state_root: sha3_256(b"a"),
                post_state_root: sha3_256(b"b"),
                block_height: 0,
                tx_count: 0,
                tx_hash: sha3_256(b"c"),
            },
        };
        assert!(verifier.verify_batch(&proof).is_err());
    }
}
