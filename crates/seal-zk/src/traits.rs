//! ZK proof trait definitions.

use crate::ZkError;
use seal_crypto::hash::Hash256;
use serde::{Deserialize, Serialize};

/// A state transition to be proven.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateTransition {
    /// State root before the transition.
    pub pre_state_root: Hash256,
    /// State root after the transition.
    pub post_state_root: Hash256,
    /// Block height.
    pub block_height: u64,
    /// Number of transactions in the block.
    pub tx_count: u32,
    /// Hash of the transaction list.
    pub tx_hash: Hash256,
}

/// A zero-knowledge proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkProof {
    /// Proof bytes.
    /// Stub: SHA3 commitment (~32 bytes).
    /// RISC Zero: STARK proof (~200 KB).
    pub bytes: Vec<u8>,
    /// The public inputs (state transition).
    pub public_inputs: StateTransition,
}

impl ZkProof {
    /// Size of the proof in bytes.
    pub fn size(&self) -> usize {
        self.bytes.len()
    }
}

/// Trait for ZK proof generation.
pub trait ZkProver {
    /// Generate a proof that a state transition is valid.
    fn prove(&self, transition: StateTransition) -> Result<ZkProof, ZkError>;
}

/// Trait for ZK proof verification.
pub trait ZkVerifier {
    /// Verify a ZK proof.
    fn verify(&self, proof: &ZkProof) -> Result<(), ZkError>;
}
