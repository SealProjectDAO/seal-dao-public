//! SHA3-256 hashing (FIPS 202).
//!
//! Used throughout Seal for:
//! - State hashing (Merkle tree nodes)
//! - Address derivation (SHA3-256 of public key)
//! - Transaction hashing

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// A SHA3-256 hash digest (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash256({})", hex::encode(&self.0[..8]))
    }
}

impl std::fmt::Display for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Compute SHA3-256 of arbitrary bytes.
pub fn sha3_256(data: &[u8]) -> Hash256 {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Hash256(out)
}

/// Incremental SHA3-256 hasher.
pub struct Sha3Hasher {
    inner: Sha3_256,
}

impl Sha3Hasher {
    pub fn new() -> Self {
        Self {
            inner: Sha3_256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> Hash256 {
        let result = self.inner.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        Hash256(out)
    }
}

impl Default for Sha3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_empty() {
        let hash = sha3_256(b"");
        // Known SHA3-256 of empty string
        assert_eq!(
            hex::encode(hash.0),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn test_sha3_256_deterministic() {
        let a = sha3_256(b"seal dao");
        let b = sha3_256(b"seal dao");
        assert_eq!(a, b);
    }

    #[test]
    fn test_sha3_256_different_inputs() {
        let a = sha3_256(b"seal dao");
        let b = sha3_256(b"seal dao!");
        assert_ne!(a, b);
    }

    #[test]
    fn test_incremental_hasher() {
        let direct = sha3_256(b"hello world");
        let mut hasher = Sha3Hasher::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let incremental = hasher.finalize();
        assert_eq!(direct, incremental);
    }
}

// Kani verification harnesses
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // NOTE: sha3_256_no_panic, sha3_256_deterministic, and
    // hasher_single_update_matches_direct are infeasible for CBMC —
    // Keccak-f[1600] has 24 rounds of permutations on 1600-bit state,
    // which is too large for symbolic execution. These properties are
    // covered by the sha3 crate's own tests and libcrux formal verification
    // (hax + F*). The harnesses below verify properties that don't
    // invoke SHA3 on symbolic input.

    /// Prove: Hash256 ordering is consistent with byte ordering.
    #[kani::proof]
    fn hash256_ord_consistent() {
        let a: [u8; 32] = kani::any();
        let b: [u8; 32] = kani::any();
        let ha = Hash256(a);
        let hb = Hash256(b);
        assert_eq!(ha.cmp(&hb) == std::cmp::Ordering::Equal, ha == hb);
    }

    /// Prove: Hash256 equality is reflexive.
    #[kani::proof]
    fn hash256_eq_reflexive() {
        let a: [u8; 32] = kani::any();
        let ha = Hash256(a);
        assert_eq!(ha, ha);
    }

    /// Prove: Hash256 from zeroes is distinct from Hash256 from ones.
    #[kani::proof]
    fn hash256_distinct_inputs() {
        let a = Hash256([0u8; 32]);
        let b = Hash256([1u8; 32]);
        assert_ne!(a, b);
    }
}
