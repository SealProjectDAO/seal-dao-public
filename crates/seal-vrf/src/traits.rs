//! VRF trait definition.
//!
//! Any VRF implementation (HMAC stub or lattice-based) must satisfy:
//!
//! 1. **Uniqueness**: For a given (secret_key, input), there is exactly one
//!    valid output. No two different outputs can pass verification.
//!
//! 2. **Pseudorandomness**: The output is indistinguishable from random to
//!    anyone who doesn't know the secret key.
//!
//! 3. **Verifiability**: Given (public_key, input, output, proof), anyone
//!    can verify that output was correctly computed.
//!
//! These properties must be proven formally (Lean 4) for the lattice
//! implementation before mainnet.

use crate::VrfError;
use serde::{Deserialize, Serialize};

/// VRF output: a pseudorandom value (32 bytes).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrfOutput(pub [u8; 32]);

impl VrfOutput {
    /// Interpret the output as a u64 for threshold comparison.
    /// Used in leader election: elected if output_u64 < threshold(stake).
    pub fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.0[..8].try_into().unwrap())
    }

    /// Check if this output is below a threshold (for leader election).
    /// threshold is in [0, u64::MAX], proportional to stake.
    pub fn is_below_threshold(&self, threshold: u64) -> bool {
        self.to_u64() < threshold
    }
}

impl AsRef<[u8]> for VrfOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for VrfOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VrfOutput({})", hex::encode(&self.0[..8]))
    }
}

/// VRF proof: proves that the output was correctly computed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VrfProof {
    pub bytes: Vec<u8>,
}

/// VRF key pair (public + secret).
pub struct VrfKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// The VRF trait. Implementations must satisfy uniqueness, pseudorandomness,
/// and verifiability.
pub trait Vrf {
    /// Generate a new VRF key pair.
    fn keygen() -> VrfKeypair;

    /// Evaluate the VRF: compute (output, proof) for a given input.
    ///
    /// # Properties (to be formally verified):
    /// - Deterministic: same (sk, input) always produces same (output, proof)
    /// - Unique: no other output can pass verify for this (pk, input)
    fn eval(secret_key: &[u8], input: &[u8]) -> Result<(VrfOutput, VrfProof), VrfError>;

    /// Verify a VRF output and proof against a public key and input.
    ///
    /// Returns Ok(()) if the proof is valid, Err otherwise.
    fn verify(
        public_key: &[u8],
        input: &[u8],
        output: &VrfOutput,
        proof: &VrfProof,
    ) -> Result<(), VrfError>;
}
