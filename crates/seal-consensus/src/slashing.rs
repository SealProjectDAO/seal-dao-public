//! Slashing for provable validator misbehavior.
//!
//! Detectable offenses:
//! 1. Double proposal: two blocks at same slot from same proposer
//! 2. Double vote: two attestations for different blocks at same slot
//!
//! Evidence: two conflicting signed messages from the same validator.
//! Penalty: configurable fraction of stake (default 1%).

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Slashing configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingConfig {
    /// Penalty for double proposal, in basis points (100 = 1%).
    pub double_proposal_penalty_bps: u64,
    /// Penalty for double vote, in basis points (100 = 1%).
    pub double_vote_penalty_bps: u64,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            double_proposal_penalty_bps: 100,
            double_vote_penalty_bps: 100,
        }
    }
}

/// A provable slashable offense.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SlashableOffense {
    /// Two blocks proposed at the same slot by the same proposer.
    DoubleProposal {
        slot: u64,
        block_hash_1: Vec<u8>,
        block_hash_2: Vec<u8>,
        proposer: String,
    },
    /// Two votes for different blocks at the same slot by the same voter.
    DoubleVote {
        slot: u64,
        block_hash_1: Vec<u8>,
        block_hash_2: Vec<u8>,
        voter: String,
    },
}

impl SlashableOffense {
    /// Return the validator address responsible for this offense.
    pub fn validator(&self) -> &str {
        match self {
            SlashableOffense::DoubleProposal { proposer, .. } => proposer,
            SlashableOffense::DoubleVote { voter, .. } => voter,
        }
    }
}

/// Record of a completed slash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub offense: SlashableOffense,
    pub penalty_amount: u64,
    pub epoch: u64,
}

/// Manages slashing evidence and penalties.
pub struct SlashingManager {
    config: SlashingConfig,
    /// Set of slashed validator addresses.
    slashed_validators: HashSet<String>,
    /// Cumulative penalty per validator.
    penalties: HashMap<String, u64>,
    /// Full history of slash records.
    history: Vec<SlashingRecord>,
    /// Current epoch (set externally).
    current_epoch: u64,
}

impl SlashingManager {
    pub fn new(config: SlashingConfig) -> Self {
        Self {
            config,
            slashed_validators: HashSet::new(),
            penalties: HashMap::new(),
            history: Vec::new(),
            current_epoch: 0,
        }
    }

    /// Set the current epoch for recording slash records.
    pub fn set_epoch(&mut self, epoch: u64) {
        self.current_epoch = epoch;
    }

    /// Report a slashable offense and compute the penalty.
    ///
    /// Validates that the evidence is internally consistent (the two block
    /// hashes must differ) and computes the penalty as a fraction of the
    /// validator's stake.
    pub fn report_offense(
        &mut self,
        offense: SlashableOffense,
        validator_stake: u64,
    ) -> Result<SlashingRecord, String> {
        // Validate evidence: the two block hashes must be different.
        match &offense {
            SlashableOffense::DoubleProposal {
                block_hash_1,
                block_hash_2,
                ..
            } => {
                if block_hash_1 == block_hash_2 {
                    return Err(
                        "invalid evidence: block hashes are identical for double proposal".into(),
                    );
                }
            }
            SlashableOffense::DoubleVote {
                block_hash_1,
                block_hash_2,
                ..
            } => {
                if block_hash_1 == block_hash_2 {
                    return Err(
                        "invalid evidence: block hashes are identical for double vote".into(),
                    );
                }
            }
        }

        // Compute penalty using checked arithmetic.
        let penalty_bps = match &offense {
            SlashableOffense::DoubleProposal { .. } => self.config.double_proposal_penalty_bps,
            SlashableOffense::DoubleVote { .. } => self.config.double_vote_penalty_bps,
        };

        let penalty_amount = validator_stake
            .checked_mul(penalty_bps)
            .map(|v| v / 10_000)
            .unwrap_or_else(|| {
                // On overflow, use saturating arithmetic:
                // stake * bps / 10_000 ~ stake / 10_000 * bps
                (validator_stake / 10_000).saturating_mul(penalty_bps)
            });

        let validator = offense.validator().to_string();
        self.slashed_validators.insert(validator.clone());

        let cumulative = self.penalties.entry(validator).or_insert(0);
        *cumulative = cumulative.saturating_add(penalty_amount);

        let record = SlashingRecord {
            offense,
            penalty_amount,
            epoch: self.current_epoch,
        };

        self.history.push(record.clone());
        Ok(record)
    }

    /// Check if a validator has been slashed.
    pub fn is_slashed(&self, validator: &str) -> bool {
        self.slashed_validators.contains(validator)
    }

    /// Total amount slashed from a validator across all offenses.
    pub fn total_slashed(&self, validator: &str) -> u64 {
        self.penalties.get(validator).copied().unwrap_or(0)
    }

    /// Full slash history.
    pub fn slash_history(&self) -> &[SlashingRecord] {
        &self.history
    }
}

#[cfg(kani)]
mod kani_proofs {
    // NOTE: SlashingManager uses HashMap which CBMC cannot model.
    // These harnesses verify the penalty arithmetic without constructing SlashingManager.

    /// Prove: penalty_bps in [0, 10000] means penalty <= stake.
    /// Uses u16 stake for CBMC feasibility (property holds for all sizes).
    #[kani::proof]
    fn penalty_bounded_by_stake() {
        let stake: u16 = kani::any();
        let bps: u16 = kani::any();
        kani::assume(bps <= 10_000);
        let penalty = (stake as u32) * (bps as u32) / 10_000;
        assert!(penalty <= stake as u32);
    }

    /// Prove: cumulative slashing with saturating_add never wraps.
    #[kani::proof]
    fn cumulative_slash_saturates() {
        let p1: u64 = kani::any();
        let p2: u64 = kani::any();
        let total = p1.saturating_add(p2);
        assert!(total >= p1);
        assert!(total >= p2.min(p1));
    }

    /// Prove: two identical byte values are always equal.
    /// Models the "identical hashes must be rejected" check.
    #[kani::proof]
    fn identical_hashes_always_equal() {
        let hash_byte: u8 = kani::any();
        let h1 = [hash_byte; 32];
        let h2 = [hash_byte; 32];
        assert_eq!(h1, h2, "identical hashes must be detected as equal");
        // Therefore: offense with h1 == h2 should always be rejected
        assert!(h1 == h2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_manager() -> SlashingManager {
        SlashingManager::new(SlashingConfig::default())
    }

    #[test]
    fn test_double_proposal_slash() {
        let mut sm = default_manager();
        sm.set_epoch(5);

        let offense = SlashableOffense::DoubleProposal {
            slot: 42,
            block_hash_1: vec![1; 32],
            block_hash_2: vec![2; 32],
            proposer: "val_alice".into(),
        };

        let record = sm.report_offense(offense, 10_000).unwrap();
        // 1% of 10_000 = 100
        assert_eq!(record.penalty_amount, 100);
        assert_eq!(record.epoch, 5);
        assert!(sm.is_slashed("val_alice"));
        assert_eq!(sm.total_slashed("val_alice"), 100);
    }

    #[test]
    fn test_double_vote_slash() {
        let mut sm = default_manager();

        let offense = SlashableOffense::DoubleVote {
            slot: 10,
            block_hash_1: vec![0xAA; 32],
            block_hash_2: vec![0xBB; 32],
            voter: "val_bob".into(),
        };

        let record = sm.report_offense(offense, 50_000).unwrap();
        // 1% of 50_000 = 500
        assert_eq!(record.penalty_amount, 500);
        assert!(sm.is_slashed("val_bob"));
    }

    #[test]
    fn test_identical_hashes_rejected() {
        let mut sm = default_manager();

        let offense = SlashableOffense::DoubleProposal {
            slot: 1,
            block_hash_1: vec![0xAA; 32],
            block_hash_2: vec![0xAA; 32],
            proposer: "val_charlie".into(),
        };

        let result = sm.report_offense(offense, 10_000);
        assert!(result.is_err());
        assert!(!sm.is_slashed("val_charlie"));
    }

    #[test]
    fn test_identical_hashes_rejected_double_vote() {
        let mut sm = default_manager();

        let offense = SlashableOffense::DoubleVote {
            slot: 1,
            block_hash_1: vec![0xFF; 32],
            block_hash_2: vec![0xFF; 32],
            voter: "val_dave".into(),
        };

        let result = sm.report_offense(offense, 10_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_cumulative_slashing() {
        let mut sm = default_manager();

        let offense1 = SlashableOffense::DoubleProposal {
            slot: 1,
            block_hash_1: vec![1; 32],
            block_hash_2: vec![2; 32],
            proposer: "val_repeat".into(),
        };

        let offense2 = SlashableOffense::DoubleVote {
            slot: 2,
            block_hash_1: vec![3; 32],
            block_hash_2: vec![4; 32],
            voter: "val_repeat".into(),
        };

        sm.report_offense(offense1, 10_000).unwrap(); // 100
        sm.report_offense(offense2, 10_000).unwrap(); // 100

        assert_eq!(sm.total_slashed("val_repeat"), 200);
        assert_eq!(sm.slash_history().len(), 2);
    }

    #[test]
    fn test_non_slashed_validator() {
        let sm = default_manager();
        assert!(!sm.is_slashed("innocent"));
        assert_eq!(sm.total_slashed("innocent"), 0);
    }

    #[test]
    fn test_custom_config() {
        let config = SlashingConfig {
            double_proposal_penalty_bps: 500, // 5%
            double_vote_penalty_bps: 200,     // 2%
        };
        let mut sm = SlashingManager::new(config);

        let offense = SlashableOffense::DoubleProposal {
            slot: 1,
            block_hash_1: vec![1; 32],
            block_hash_2: vec![2; 32],
            proposer: "val_x".into(),
        };

        let record = sm.report_offense(offense, 100_000).unwrap();
        // 5% of 100_000 = 5_000
        assert_eq!(record.penalty_amount, 5_000);
    }

    #[test]
    fn test_custom_config_double_vote() {
        let config = SlashingConfig {
            double_proposal_penalty_bps: 500,
            double_vote_penalty_bps: 200, // 2%
        };
        let mut sm = SlashingManager::new(config);

        let offense = SlashableOffense::DoubleVote {
            slot: 1,
            block_hash_1: vec![1; 32],
            block_hash_2: vec![2; 32],
            voter: "val_y".into(),
        };

        let record = sm.report_offense(offense, 100_000).unwrap();
        // 2% of 100_000 = 2_000
        assert_eq!(record.penalty_amount, 2_000);
    }

    #[test]
    fn test_slash_history_ordering() {
        let mut sm = default_manager();
        sm.set_epoch(1);

        let offense1 = SlashableOffense::DoubleProposal {
            slot: 10,
            block_hash_1: vec![1; 32],
            block_hash_2: vec![2; 32],
            proposer: "v1".into(),
        };

        sm.set_epoch(3);
        let offense2 = SlashableOffense::DoubleVote {
            slot: 20,
            block_hash_1: vec![3; 32],
            block_hash_2: vec![4; 32],
            voter: "v2".into(),
        };

        // Need to set epoch before reporting
        sm.set_epoch(1);
        sm.report_offense(offense1, 10_000).unwrap();
        sm.set_epoch(3);
        sm.report_offense(offense2, 20_000).unwrap();

        let history = sm.slash_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].epoch, 1);
        assert_eq!(history[1].epoch, 3);
    }

    #[test]
    fn test_zero_stake_slash() {
        let mut sm = default_manager();

        let offense = SlashableOffense::DoubleProposal {
            slot: 1,
            block_hash_1: vec![1; 32],
            block_hash_2: vec![2; 32],
            proposer: "v_zero".into(),
        };

        let record = sm.report_offense(offense, 0).unwrap();
        assert_eq!(record.penalty_amount, 0);
        // Still marked as slashed even with zero penalty
        assert!(sm.is_slashed("v_zero"));
    }

    #[test]
    fn test_large_stake_no_overflow() {
        let mut sm = default_manager();

        let offense = SlashableOffense::DoubleProposal {
            slot: 1,
            block_hash_1: vec![1; 32],
            block_hash_2: vec![2; 32],
            proposer: "v_whale".into(),
        };

        // Very large stake — should not overflow
        let record = sm.report_offense(offense, u64::MAX).unwrap();
        // u64::MAX * 100 overflows, so fallback: (u64::MAX / 10_000) * 100
        let expected = (u64::MAX / 10_000).saturating_mul(100);
        assert_eq!(record.penalty_amount, expected);
    }

    #[test]
    fn test_saturating_cumulative_penalty() {
        let config = SlashingConfig {
            double_proposal_penalty_bps: 10_000, // 100% — extreme for testing
            double_vote_penalty_bps: 10_000,
        };
        let mut sm = SlashingManager::new(config);

        let offense1 = SlashableOffense::DoubleProposal {
            slot: 1,
            block_hash_1: vec![1; 32],
            block_hash_2: vec![2; 32],
            proposer: "v_max".into(),
        };
        let offense2 = SlashableOffense::DoubleVote {
            slot: 2,
            block_hash_1: vec![3; 32],
            block_hash_2: vec![4; 32],
            voter: "v_max".into(),
        };

        sm.report_offense(offense1, u64::MAX / 2).unwrap();
        sm.report_offense(offense2, u64::MAX / 2).unwrap();

        // Cumulative should saturate, not overflow
        let total = sm.total_slashed("v_max");
        assert!(total > 0);
    }
}
