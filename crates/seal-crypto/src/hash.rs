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

/// Compute a binary Merkle root over a list of opaque items.
///
/// This is a generic, order-sensitive commitment: the root depends on both
/// the contents *and* the order of `items`, so it is a tamper-evident digest
/// of a sequence. Used to bind a block's transaction list to its signed
/// header (`BlockHeader.tx_root`) — see `audits/2026-10-08-dexmatch-txroot-design.md`.
///
/// Construction (canonical, deterministic):
/// - leaf `i`        = `sha3_256(items[i])`
/// - internal node   = `sha3_256(left ‖ right)` over the two 32-byte child hashes
/// - an odd node in a level is promoted unchanged to the next level
/// - empty input     = `sha3_256(b"")` (a fixed, non-zero constant)
///
/// Every producer and replayer computes the same root from the same
/// transaction bytes, so a post-signature injection, removal, or reorder of a
/// transaction changes the recomputed root and fails the header check.
pub fn merkle_root(items: &[Vec<u8>]) -> Hash256 {
    if items.is_empty() {
        return sha3_256(b"");
    }
    let mut level: Vec<Hash256> = items.iter().map(|item| sha3_256(item)).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(level[i].0.as_ref());
                combined.extend_from_slice(level[i + 1].0.as_ref());
                next.push(sha3_256(&combined));
                i += 2;
            } else {
                // Odd node: promote as-is.
                next.push(level[i]);
                i += 1;
            }
        }
        level = next;
    }
    level[0]
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
    fn test_merkle_root_empty_is_fixed_nonzero() {
        let root = merkle_root(&[]);
        assert_eq!(root, sha3_256(b""));
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn test_merkle_root_single_item_is_leaf_hash() {
        let root = merkle_root(&[b"only".to_vec()]);
        assert_eq!(root, sha3_256(b"only"));
    }

    #[test]
    fn test_merkle_root_deterministic_and_order_sensitive() {
        let a = merkle_root(&[b"x".to_vec(), b"y".to_vec(), b"z".to_vec()]);
        let b = merkle_root(&[b"x".to_vec(), b"y".to_vec(), b"z".to_vec()]);
        assert_eq!(a, b, "same sequence must give the same root");
        let swapped = merkle_root(&[b"y".to_vec(), b"x".to_vec(), b"z".to_vec()]);
        assert_ne!(a, swapped, "order must affect the root");
    }

    #[test]
    fn test_merkle_root_changes_when_a_leaf_changes() {
        let base = merkle_root(&[b"x".to_vec(), b"y".to_vec(), b"z".to_vec()]);
        let tampered = merkle_root(&[b"x".to_vec(), b"Y".to_vec(), b"z".to_vec()]);
        assert_ne!(base, tampered, "mutating one item must change the root");
    }

    #[test]
    fn test_merkle_root_odd_leaf_promotion() {
        // 3 leaves: [x,y] paired, z promoted. Root = H(H(x||y) || z) with
        // the promotion meaning the promoted node is its own leaf hash.
        let hz = sha3_256(b"z");
        let hxy = sha3_256(&{
            let mut c = Vec::new();
            c.extend_from_slice(sha3_256(b"x").0.as_ref());
            c.extend_from_slice(sha3_256(b"y").0.as_ref());
            c
        });
        let expected = sha3_256(&{
            let mut c = Vec::new();
            c.extend_from_slice(hxy.0.as_ref());
            c.extend_from_slice(hz.0.as_ref());
            c
        });
        assert_eq!(merkle_root(&[b"x".to_vec(), b"y".to_vec(), b"z".to_vec()]), expected);
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
