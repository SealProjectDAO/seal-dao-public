//! Threshold signature trait definitions.

use crate::ThresholdError;
use serde::{Deserialize, Serialize};

/// A bitfield tracking which committee members participated.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bitfield {
    /// One bit per committee member. Bit i is set if member i signed.
    bytes: Vec<u8>,
    /// Total number of members.
    size: usize,
}

impl Bitfield {
    /// Create a new bitfield for `size` members, all unset.
    pub fn new(size: usize) -> Self {
        let byte_count = size.div_ceil(8);
        Bitfield {
            bytes: vec![0u8; byte_count],
            size,
        }
    }

    /// Set bit at index.
    pub fn set(&mut self, index: usize) {
        if index < self.size {
            self.bytes[index / 8] |= 1 << (index % 8);
        }
    }

    /// Check if bit at index is set.
    pub fn is_set(&self, index: usize) -> bool {
        if index >= self.size {
            return false;
        }
        (self.bytes[index / 8] >> (index % 8)) & 1 == 1
    }

    /// Count the number of set bits.
    pub fn count(&self) -> usize {
        self.bytes.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Total members.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Raw bytes (for serialization into blocks).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A partial signature from a single committee member.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialSignature {
    /// Index of the signer in the committee.
    pub signer_index: usize,
    /// The individual signature bytes.
    pub signature: Vec<u8>,
}

/// A threshold signature (aggregated from partial signatures).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdSignature {
    /// The aggregated signature bytes.
    /// In SimpleThreshold: concatenated individual sigs.
    /// In Ringtail: single ~13.4 KB threshold sig.
    pub signature: Vec<u8>,
    /// Bitfield of participating signers.
    pub participants: Bitfield,
}

impl ThresholdSignature {
    /// Number of participants.
    pub fn participant_count(&self) -> usize {
        self.participants.count()
    }
}

/// Trait for threshold signature schemes.
pub trait ThresholdScheme {
    /// Create a partial signature for a message.
    fn partial_sign(
        signer_index: usize,
        secret_key: &[u8],
        message: &[u8],
    ) -> Result<PartialSignature, ThresholdError>;

    /// Aggregate partial signatures into a threshold signature.
    /// Requires at least `threshold` valid partial signatures.
    fn aggregate(
        partial_sigs: &[PartialSignature],
        public_keys: &[Vec<u8>],
        message: &[u8],
        threshold: usize,
        committee_size: usize,
    ) -> Result<ThresholdSignature, ThresholdError>;

    /// Verify a threshold signature.
    fn verify(
        threshold_sig: &ThresholdSignature,
        public_keys: &[Vec<u8>],
        message: &[u8],
        threshold: usize,
    ) -> Result<(), ThresholdError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitfield_basic() {
        let mut bf = Bitfield::new(100);
        assert_eq!(bf.count(), 0);
        assert_eq!(bf.size(), 100);
        assert!(!bf.is_set(0));

        bf.set(0);
        bf.set(50);
        bf.set(99);
        assert!(bf.is_set(0));
        assert!(bf.is_set(50));
        assert!(bf.is_set(99));
        assert!(!bf.is_set(1));
        assert_eq!(bf.count(), 3);
    }

    #[test]
    fn test_bitfield_all_set() {
        let mut bf = Bitfield::new(8);
        for i in 0..8 {
            bf.set(i);
        }
        assert_eq!(bf.count(), 8);
        assert_eq!(bf.as_bytes(), &[0xFF]);
    }

    #[test]
    fn test_bitfield_size() {
        // 100 members = 13 bytes
        let bf = Bitfield::new(100);
        assert_eq!(bf.as_bytes().len(), 13);
    }

    #[test]
    fn test_bitfield_out_of_range() {
        let bf = Bitfield::new(10);
        assert!(!bf.is_set(100)); // Out of range returns false
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove: set then is_set returns true for any valid index.
    #[kani::proof]
    #[kani::unwind(2)]
    fn bitfield_set_then_is_set() {
        let size: usize = kani::any();
        kani::assume(size > 0 && size <= 256);
        let idx: usize = kani::any();
        kani::assume(idx < size);

        let mut bf = Bitfield::new(size);
        bf.set(idx);
        assert!(bf.is_set(idx));
    }

    /// Prove: setting one bit doesn't affect other bits.
    #[kani::proof]
    #[kani::unwind(2)]
    fn bitfield_set_independent() {
        let size: usize = kani::any();
        kani::assume(size >= 2 && size <= 64);
        let idx1: usize = kani::any();
        let idx2: usize = kani::any();
        kani::assume(idx1 < size && idx2 < size && idx1 != idx2);

        let mut bf = Bitfield::new(size);
        bf.set(idx1);
        // idx2 should still be unset
        assert!(!bf.is_set(idx2));
    }

    /// Prove: count after setting N distinct bits equals N.
    #[kani::proof]
    #[kani::unwind(4)]
    fn bitfield_count_correct() {
        let size: usize = kani::any();
        kani::assume(size >= 3 && size <= 16);

        let mut bf = Bitfield::new(size);
        assert_eq!(bf.count(), 0);

        let idx: usize = kani::any();
        kani::assume(idx < size);
        bf.set(idx);
        assert_eq!(bf.count(), 1);
    }

    /// Prove: out-of-range is_set never panics and returns false.
    #[kani::proof]
    #[kani::unwind(2)]
    fn bitfield_out_of_range_safe() {
        let size: usize = kani::any();
        kani::assume(size > 0 && size <= 64);
        let idx: usize = kani::any();
        kani::assume(idx >= size);

        let bf = Bitfield::new(size);
        assert!(!bf.is_set(idx));
    }
}
