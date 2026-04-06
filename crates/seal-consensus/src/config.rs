//! Consensus configuration parameters (matching SPEC.md §2.7).

use std::time::Duration;

/// Consensus parameters. All values tunable via governance.
#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    /// Duration of a single slot.
    pub slot_duration: Duration,
    /// Number of slots per epoch.
    pub slots_per_epoch: u64,
    /// Target committee size per slot.
    pub committee_size: u32,
    /// Finality threshold (fraction, e.g. 0.67 = 2/3).
    pub finality_threshold: f64,
    /// Minimum stake required to be a validator (in micro-SEAL).
    pub min_stake: u64,
    /// Maximum block size in bytes.
    pub max_block_size: usize,
    /// Maximum transactions per block.
    pub max_txs_per_block: usize,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        ConsensusConfig {
            slot_duration: Duration::from_secs(4),
            slots_per_epoch: 256,
            committee_size: 100,
            finality_threshold: 0.67,
            min_stake: 1_000_000_000,        // 1 SEAL
            max_block_size: 2 * 1024 * 1024, // 2 MB
            max_txs_per_block: 1000,
        }
    }
}

impl ConsensusConfig {
    /// Epoch duration.
    pub fn epoch_duration(&self) -> Duration {
        self.slot_duration * self.slots_per_epoch as u32
    }

    /// Compute the absolute slot number from epoch and slot-within-epoch.
    pub fn absolute_slot(&self, epoch: u64, slot_in_epoch: u64) -> u64 {
        epoch * self.slots_per_epoch + slot_in_epoch
    }

    /// Decompose an absolute slot into (epoch, slot_in_epoch).
    pub fn decompose_slot(&self, absolute_slot: u64) -> (u64, u64) {
        (
            absolute_slot / self.slots_per_epoch,
            absolute_slot % self.slots_per_epoch,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ConsensusConfig::default();
        assert_eq!(config.slot_duration, Duration::from_secs(4));
        assert_eq!(config.slots_per_epoch, 256);
        assert_eq!(config.committee_size, 100);
    }

    #[test]
    fn test_epoch_duration() {
        let config = ConsensusConfig::default();
        assert_eq!(config.epoch_duration(), Duration::from_secs(4 * 256));
    }

    #[test]
    fn test_slot_decomposition() {
        let config = ConsensusConfig::default();
        assert_eq!(config.absolute_slot(0, 0), 0);
        assert_eq!(config.absolute_slot(0, 255), 255);
        assert_eq!(config.absolute_slot(1, 0), 256);
        assert_eq!(config.absolute_slot(2, 10), 522);

        assert_eq!(config.decompose_slot(0), (0, 0));
        assert_eq!(config.decompose_slot(255), (0, 255));
        assert_eq!(config.decompose_slot(256), (1, 0));
        assert_eq!(config.decompose_slot(522), (2, 10));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove: decompose(absolute(epoch, slot)) = (epoch, slot)
    /// i.e., slot composition is a perfect roundtrip.
    #[kani::proof]
    fn slot_roundtrip() {
        let config = ConsensusConfig::default();
        let epoch: u64 = kani::any();
        let slot: u64 = kani::any();
        kani::assume(epoch < 1000);
        kani::assume(slot < config.slots_per_epoch);

        let abs = config.absolute_slot(epoch, slot);
        let (e, s) = config.decompose_slot(abs);
        assert_eq!(e, epoch);
        assert_eq!(s, slot);
    }

    /// Prove: absolute_slot never overflows for reasonable inputs.
    #[kani::proof]
    fn absolute_slot_no_overflow() {
        let config = ConsensusConfig::default();
        let epoch: u64 = kani::any();
        let slot: u64 = kani::any();
        kani::assume(epoch < u64::MAX / config.slots_per_epoch);
        kani::assume(slot < config.slots_per_epoch);

        let abs = config.absolute_slot(epoch, slot);
        assert!(abs >= epoch); // Sanity: absolute slot >= epoch number
    }
}
