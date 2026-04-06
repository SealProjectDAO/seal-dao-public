//! Epoch and slot management.

use crate::config::ConsensusConfig;
use seal_crypto::hash::{sha3_256, Hash256};
use serde::{Deserialize, Serialize};

/// Represents an epoch in the consensus protocol.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Epoch {
    /// Epoch number (0-indexed).
    pub number: u64,
    /// Randomness seed for this epoch (derived from previous epoch's VRF outputs).
    pub seed: Hash256,
}

impl Epoch {
    /// Create the genesis epoch.
    pub fn genesis() -> Self {
        Epoch {
            number: 0,
            seed: sha3_256(b"seal_genesis_seed"),
        }
    }

    /// Derive the next epoch's seed from this epoch's seed and a finalized VRF output.
    pub fn next_epoch(&self, vrf_output: &[u8]) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(self.seed.as_ref());
        data.extend_from_slice(vrf_output);
        data.extend_from_slice(&(self.number + 1).to_le_bytes());

        Epoch {
            number: self.number + 1,
            seed: sha3_256(&data),
        }
    }
}

/// Represents a slot within an epoch.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Slot {
    /// Absolute slot number (epoch * slots_per_epoch + slot_in_epoch).
    pub number: u64,
    /// Epoch this slot belongs to.
    pub epoch: u64,
    /// Slot position within the epoch (0..slots_per_epoch-1).
    pub slot_in_epoch: u64,
}

impl Slot {
    /// Create a slot from an absolute slot number.
    pub fn from_absolute(absolute: u64, config: &ConsensusConfig) -> Self {
        let (epoch, slot_in_epoch) = config.decompose_slot(absolute);
        Slot {
            number: absolute,
            epoch,
            slot_in_epoch,
        }
    }

    /// Create the genesis slot.
    pub fn genesis() -> Self {
        Slot {
            number: 0,
            epoch: 0,
            slot_in_epoch: 0,
        }
    }

    /// Get the next slot.
    pub fn next(&self, config: &ConsensusConfig) -> Self {
        Self::from_absolute(self.number + 1, config)
    }

    /// Is this the first slot of an epoch?
    pub fn is_epoch_start(&self) -> bool {
        self.slot_in_epoch == 0
    }

    /// Is this the last slot of an epoch?
    pub fn is_epoch_end(&self, config: &ConsensusConfig) -> bool {
        self.slot_in_epoch == config.slots_per_epoch - 1
    }

    /// Compute the VRF input for this slot (epoch_seed || slot_number).
    pub fn vrf_input(&self, epoch_seed: &Hash256) -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(epoch_seed.as_ref());
        input.extend_from_slice(&self.number.to_le_bytes());
        input
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_epoch() {
        let epoch = Epoch::genesis();
        assert_eq!(epoch.number, 0);
        assert_ne!(epoch.seed, Hash256::ZERO);
    }

    #[test]
    fn test_next_epoch() {
        let epoch0 = Epoch::genesis();
        let epoch1 = epoch0.next_epoch(b"vrf_output_from_epoch_0");
        assert_eq!(epoch1.number, 1);
        assert_ne!(epoch1.seed, epoch0.seed);
    }

    #[test]
    fn test_epoch_seed_deterministic() {
        let epoch0 = Epoch::genesis();
        let epoch1a = epoch0.next_epoch(b"same_vrf");
        let epoch1b = epoch0.next_epoch(b"same_vrf");
        assert_eq!(epoch1a.seed, epoch1b.seed);
    }

    #[test]
    fn test_epoch_seed_different_vrf() {
        let epoch0 = Epoch::genesis();
        let epoch1a = epoch0.next_epoch(b"vrf_a");
        let epoch1b = epoch0.next_epoch(b"vrf_b");
        assert_ne!(epoch1a.seed, epoch1b.seed);
    }

    #[test]
    fn test_slot_genesis() {
        let slot = Slot::genesis();
        assert_eq!(slot.number, 0);
        assert_eq!(slot.epoch, 0);
        assert_eq!(slot.slot_in_epoch, 0);
        assert!(slot.is_epoch_start());
    }

    #[test]
    fn test_slot_next() {
        let config = ConsensusConfig::default();
        let slot = Slot::genesis();
        let next = slot.next(&config);
        assert_eq!(next.number, 1);
        assert_eq!(next.epoch, 0);
        assert_eq!(next.slot_in_epoch, 1);
    }

    #[test]
    fn test_slot_epoch_boundary() {
        let config = ConsensusConfig::default();
        let slot = Slot::from_absolute(255, &config);
        assert_eq!(slot.epoch, 0);
        assert_eq!(slot.slot_in_epoch, 255);
        assert!(slot.is_epoch_end(&config));
        assert!(!slot.is_epoch_start());

        let next = slot.next(&config);
        assert_eq!(next.epoch, 1);
        assert_eq!(next.slot_in_epoch, 0);
        assert!(next.is_epoch_start());
    }

    #[test]
    fn test_vrf_input_unique_per_slot() {
        let seed = sha3_256(b"test_seed");
        let slot1 = Slot::from_absolute(1, &ConsensusConfig::default());
        let slot2 = Slot::from_absolute(2, &ConsensusConfig::default());
        assert_ne!(slot1.vrf_input(&seed), slot2.vrf_input(&seed));
    }

    #[test]
    fn test_vrf_input_unique_per_epoch() {
        let seed1 = sha3_256(b"seed_1");
        let seed2 = sha3_256(b"seed_2");
        let slot = Slot::from_absolute(5, &ConsensusConfig::default());
        assert_ne!(slot.vrf_input(&seed1), slot.vrf_input(&seed2));
    }
}
