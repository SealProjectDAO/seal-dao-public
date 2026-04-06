//! TLA+ trace recorder for consensus conformance testing.
//!
//! Records state transitions from the ConsensusRunner in a format that
//! can be validated against the SealConsensus.tla specification.
//!
//! # How It Works
//!
//! 1. The `TraceRecorder` captures key state transitions:
//!    - Propose: a validator proposes a block at a height
//!    - Vote: a committee member votes for a block
//!    - Finalize: a block is finalized at a height
//!    - SkipSlot: no block produced at a slot
//!
//! 2. After running the consensus, the trace is exported as JSON.
//!
//! 3. The trace checker (scripts/check-trace.py or Rust) validates:
//!    - Agreement: at most one block finalized per height
//!    - No equivocation: no validator votes for two blocks at same height
//!    - Monotonic height: heights never decrease
//!    - Progress: heights keep increasing
//!
//! # Usage
//!
//! ```ignore
//! let mut recorder = TraceRecorder::new();
//! // ... run consensus, call recorder.record_*() at each step ...
//! let result = recorder.validate();
//! assert!(result.is_ok());
//! recorder.export_json("trace.json");
//! ```

use seal_crypto::hash::Hash256;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A single state transition event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TraceEvent {
    /// A validator proposed a block at a height.
    Propose {
        height: u64,
        proposer: String,
        block_hash: String,
    },
    /// A committee member voted for a block at a height.
    Vote {
        height: u64,
        voter: String,
        block_hash: String,
    },
    /// A block was finalized at a height.
    Finalize {
        height: u64,
        block_hash: String,
        vote_count: usize,
    },
    /// A slot was skipped (no block produced).
    SkipSlot {
        slot: u64,
        epoch: u64,
    },
    /// Epoch transition.
    EpochTransition {
        from_epoch: u64,
        to_epoch: u64,
    },
}

/// Records a sequence of consensus events for conformance testing.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceRecorder {
    /// Ordered list of events.
    events: Vec<TraceEvent>,
    /// Current slot number.
    current_slot: u64,
}

impl TraceRecorder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a proposal event.
    pub fn record_propose(&mut self, height: u64, proposer: &str, block_hash: &Hash256) {
        self.events.push(TraceEvent::Propose {
            height,
            proposer: proposer.to_string(),
            block_hash: hex::encode(&block_hash.0[..8]),
        });
    }

    /// Record a vote event.
    pub fn record_vote(&mut self, height: u64, voter: &str, block_hash: &Hash256) {
        self.events.push(TraceEvent::Vote {
            height,
            voter: voter.to_string(),
            block_hash: hex::encode(&block_hash.0[..8]),
        });
    }

    /// Record a finalization event.
    pub fn record_finalize(&mut self, height: u64, block_hash: &Hash256, vote_count: usize) {
        self.events.push(TraceEvent::Finalize {
            height,
            block_hash: hex::encode(&block_hash.0[..8]),
            vote_count,
        });
    }

    /// Record a skipped slot.
    pub fn record_skip(&mut self, slot: u64, epoch: u64) {
        self.events.push(TraceEvent::SkipSlot { slot, epoch });
    }

    /// Record an epoch transition.
    pub fn record_epoch_transition(&mut self, from_epoch: u64, to_epoch: u64) {
        self.events.push(TraceEvent::EpochTransition {
            from_epoch,
            to_epoch,
        });
    }

    /// Set current slot (for context).
    pub fn set_slot(&mut self, slot: u64) {
        self.current_slot = slot;
    }

    /// Number of events recorded.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Get all events.
    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    /// Export trace as JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Validate the trace against TLA+ safety properties.
    ///
    /// Checks:
    /// 1. Agreement: at most one block finalized per height
    /// 2. No equivocation: no validator votes for two different blocks at same height
    /// 3. Monotonic finalization: heights are finalized in order
    pub fn validate(&self) -> Result<TraceValidation, Vec<String>> {
        let mut errors = Vec::new();

        // Track finalized blocks per height
        let mut finalized: HashMap<u64, String> = HashMap::new();
        // Track votes: (height, voter) -> block_hash
        let mut voter_choices: HashMap<(u64, String), String> = HashMap::new();
        // Track finalization order
        let mut last_finalized_height: u64 = 0;

        let mut propose_count = 0u64;
        let mut vote_count = 0u64;
        let mut finalize_count = 0u64;
        let mut skip_count = 0u64;

        for event in &self.events {
            match event {
                TraceEvent::Propose { height, .. } => {
                    propose_count += 1;
                    // Proposals don't violate safety by themselves
                    let _ = height;
                }

                TraceEvent::Vote {
                    height,
                    voter,
                    block_hash,
                } => {
                    vote_count += 1;
                    let key = (*height, voter.clone());
                    if let Some(existing) = voter_choices.get(&key) {
                        if existing != block_hash {
                            errors.push(format!(
                                "EQUIVOCATION: {} voted for {} and {} at height {}",
                                voter, existing, block_hash, height
                            ));
                        }
                    } else {
                        voter_choices.insert(key, block_hash.clone());
                    }
                }

                TraceEvent::Finalize {
                    height,
                    block_hash,
                    ..
                } => {
                    finalize_count += 1;

                    // Agreement check
                    if let Some(existing) = finalized.get(height) {
                        if existing != block_hash {
                            errors.push(format!(
                                "AGREEMENT VIOLATION: height {} finalized as {} and {}",
                                height, existing, block_hash
                            ));
                        }
                    } else {
                        finalized.insert(*height, block_hash.clone());
                    }

                    // Monotonic height check
                    if *height < last_finalized_height {
                        errors.push(format!(
                            "MONOTONIC VIOLATION: finalized height {} after {}",
                            height, last_finalized_height
                        ));
                    }
                    last_finalized_height = *height;
                }

                TraceEvent::SkipSlot { .. } => {
                    skip_count += 1;
                }

                TraceEvent::EpochTransition { .. } => {}
            }
        }

        let validation = TraceValidation {
            total_events: self.events.len(),
            proposals: propose_count,
            votes: vote_count,
            finalizations: finalize_count,
            skips: skip_count,
            unique_heights_finalized: finalized.len(),
            errors: errors.clone(),
        };

        if errors.is_empty() {
            Ok(validation)
        } else {
            Err(errors)
        }
    }
}

/// Result of trace validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceValidation {
    pub total_events: usize,
    pub proposals: u64,
    pub votes: u64,
    pub finalizations: u64,
    pub skips: u64,
    pub unique_heights_finalized: usize,
    pub errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::hash::sha3_256;

    #[test]
    fn test_empty_trace_valid() {
        let recorder = TraceRecorder::new();
        let result = recorder.validate();
        assert!(result.is_ok());
        let v = result.unwrap();
        assert_eq!(v.total_events, 0);
    }

    #[test]
    fn test_valid_trace() {
        let mut recorder = TraceRecorder::new();
        let block_hash = sha3_256(b"block1");

        recorder.record_propose(1, "v1", &block_hash);
        recorder.record_vote(1, "v1", &block_hash);
        recorder.record_vote(1, "v2", &block_hash);
        recorder.record_vote(1, "v3", &block_hash);
        recorder.record_finalize(1, &block_hash, 3);

        let result = recorder.validate();
        assert!(result.is_ok());
        let v = result.unwrap();
        assert_eq!(v.proposals, 1);
        assert_eq!(v.votes, 3);
        assert_eq!(v.finalizations, 1);
    }

    #[test]
    fn test_agreement_violation_detected() {
        let mut recorder = TraceRecorder::new();
        let block1 = sha3_256(b"block1");
        let block2 = sha3_256(b"block2");

        recorder.record_finalize(1, &block1, 3);
        recorder.record_finalize(1, &block2, 3); // Same height, different block!

        let result = recorder.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].contains("AGREEMENT VIOLATION"));
    }

    #[test]
    fn test_equivocation_detected() {
        let mut recorder = TraceRecorder::new();
        let block1 = sha3_256(b"block1");
        let block2 = sha3_256(b"block2");

        recorder.record_vote(1, "v1", &block1);
        recorder.record_vote(1, "v1", &block2); // Same voter, same height, different block!

        let result = recorder.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].contains("EQUIVOCATION"));
    }

    #[test]
    fn test_monotonic_violation_detected() {
        let mut recorder = TraceRecorder::new();
        let block = sha3_256(b"block");

        recorder.record_finalize(5, &block, 3);
        recorder.record_finalize(3, &block, 3); // Going backwards!

        let result = recorder.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].contains("MONOTONIC VIOLATION"));
    }

    #[test]
    fn test_multi_height_valid_trace() {
        let mut recorder = TraceRecorder::new();

        for h in 1..=5 {
            let block = sha3_256(&[h as u8]);
            recorder.record_propose(h, &format!("v{}", h % 3 + 1), &block);
            recorder.record_vote(h, "v1", &block);
            recorder.record_vote(h, "v2", &block);
            recorder.record_finalize(h, &block, 2);
        }

        let result = recorder.validate();
        assert!(result.is_ok());
        let v = result.unwrap();
        assert_eq!(v.unique_heights_finalized, 5);
        assert_eq!(v.proposals, 5);
        assert_eq!(v.votes, 10);
    }

    #[test]
    fn test_trace_with_skips() {
        let mut recorder = TraceRecorder::new();
        let block = sha3_256(b"block");

        recorder.record_skip(1, 0);
        recorder.record_skip(2, 0);
        recorder.record_propose(1, "v1", &block);
        recorder.record_finalize(1, &block, 3);

        let result = recorder.validate();
        assert!(result.is_ok());
        let v = result.unwrap();
        assert_eq!(v.skips, 2);
    }

    #[test]
    fn test_trace_json_export() {
        let mut recorder = TraceRecorder::new();
        let block = sha3_256(b"test");
        recorder.record_propose(1, "v1", &block);
        recorder.record_finalize(1, &block, 1);

        let json = recorder.to_json();
        assert!(json.contains("Propose"));
        assert!(json.contains("Finalize"));
    }

    #[test]
    fn test_duplicate_finalization_same_block_ok() {
        let mut recorder = TraceRecorder::new();
        let block = sha3_256(b"block");

        // Same block finalized twice at same height (idempotent) — should be OK
        recorder.record_finalize(1, &block, 3);
        recorder.record_finalize(1, &block, 3);

        let result = recorder.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_epoch_transitions_recorded() {
        let mut recorder = TraceRecorder::new();
        recorder.record_epoch_transition(0, 1);
        recorder.record_epoch_transition(1, 2);

        assert_eq!(recorder.event_count(), 2);
        let result = recorder.validate();
        assert!(result.is_ok());
    }
}
