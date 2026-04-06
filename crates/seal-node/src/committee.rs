//! Committee signing manager for multi-node consensus.
//!
//! When a validator is elected as a committee member for a slot:
//! 1. Receive the proposed block from the proposer (via GossipSub blocks topic)
//! 2. Validate the block (VRF proof, parent hash, state root)
//! 3. Produce a Ringtail partial signature on the block hash
//! 4. Broadcast the partial sig to the committee-votes topic
//!
//! The proposer (or any aggregator) collects partial signatures and:
//! 1. Aggregates them into a threshold signature once >= threshold received
//! 2. Broadcasts the finalized block + threshold sig on committee-sigs topic
//! 3. The block is considered finalized when threshold is reached

use seal_crypto::hash::{sha3_256, Hash256};
use seal_threshold::ringtail::RingtailThreshold;
use seal_threshold::traits::{PartialSignature, ThresholdScheme, ThresholdSignature};
use seal_threshold::ThresholdError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// A committee vote: a partial Ringtail signature on a block hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeVote {
    /// Block height this vote is for.
    pub height: u64,
    /// Block hash (SHA3-256 of serialized block header).
    pub block_hash: [u8; 32],
    /// Signer index within the committee.
    pub signer_index: usize,
    /// The Ringtail partial signature.
    pub partial_signature: Vec<u8>,
    /// The signer's public key (for identification).
    pub signer_pubkey: Vec<u8>,
}

/// A finalization message: aggregated threshold signature for a block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeAttestation {
    /// Block height.
    pub height: u64,
    /// Block hash.
    pub block_hash: [u8; 32],
    /// The aggregated Ringtail threshold signature.
    pub threshold_signature: Vec<u8>,
    /// Bitfield of participating signers.
    pub participants: Vec<u8>,
    /// Number of signers.
    pub signer_count: usize,
}

/// Epoch transition announcement broadcast at epoch boundaries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochAnnouncement {
    /// New epoch number.
    pub epoch: u64,
    /// The validator's new VRF public key for this epoch.
    pub vrf_public_key: Vec<u8>,
    /// The validator's signing public key (for identification).
    pub validator_pubkey: Vec<u8>,
}

/// Manages committee vote collection and aggregation for a specific block height.
struct VoteCollector {
    /// Block hash we're collecting votes for.
    block_hash: [u8; 32],
    /// Collected partial signatures, keyed by signer_index.
    votes: HashMap<usize, PartialSignature>,
    /// Public keys of signers (indexed by signer_index).
    public_keys: Vec<Vec<u8>>,
    /// Required threshold for finalization.
    threshold: usize,
    /// Committee size.
    committee_size: usize,
}

impl VoteCollector {
    fn new(
        block_hash: [u8; 32],
        public_keys: Vec<Vec<u8>>,
        threshold: usize,
        committee_size: usize,
    ) -> Self {
        Self {
            block_hash,
            votes: HashMap::new(),
            public_keys,
            threshold,
            committee_size,
        }
    }

    /// Add a vote. Returns true if threshold is now reached.
    fn add_vote(&mut self, vote: &CommitteeVote) -> bool {
        if vote.block_hash != self.block_hash {
            debug!("Vote block_hash mismatch, ignoring");
            return false;
        }
        if self.votes.contains_key(&vote.signer_index) {
            debug!(signer = vote.signer_index, "Duplicate vote, ignoring");
            return false;
        }

        let partial = PartialSignature {
            signer_index: vote.signer_index,
            signature: vote.partial_signature.clone(),
        };
        self.votes.insert(vote.signer_index, partial);

        debug!(
            signer = vote.signer_index,
            votes = self.votes.len(),
            threshold = self.threshold,
            "Vote collected"
        );

        self.votes.len() >= self.threshold
    }

    /// Aggregate collected votes into a threshold signature.
    fn aggregate(&self) -> Result<ThresholdSignature, ThresholdError> {
        let partial_sigs: Vec<PartialSignature> = self.votes.values().cloned().collect();

        RingtailThreshold::aggregate(
            &partial_sigs,
            &self.public_keys,
            &self.block_hash,
            self.threshold,
            self.committee_size,
        )
    }
}

/// Manages the committee signing protocol across multiple block heights.
pub struct CommitteeManager {
    /// Vote collectors, keyed by block height.
    collectors: HashMap<u64, VoteCollector>,
    /// Our committee signer index (None if not a committee member this slot).
    our_signer_index: Option<usize>,
    /// Our signing key (for producing partial signatures).
    our_signing_key: Vec<u8>,
    /// Required threshold (fraction of committee).
    finality_threshold_percent: u64,
    /// Maximum heights to track simultaneously (prevent memory leak).
    max_pending_heights: usize,
}

impl CommitteeManager {
    pub fn new(signing_key: Vec<u8>, finality_threshold_percent: u64) -> Self {
        Self {
            collectors: HashMap::new(),
            our_signer_index: None,
            our_signing_key: signing_key,
            finality_threshold_percent,
            max_pending_heights: 64,
        }
    }

    /// Set our committee index for the current slot.
    pub fn set_committee_index(&mut self, index: Option<usize>) {
        self.our_signer_index = index;
    }

    /// Initialize vote collection for a new block.
    pub fn start_collection(
        &mut self,
        height: u64,
        block_hash: [u8; 32],
        committee_pubkeys: Vec<Vec<u8>>,
        committee_size: usize,
    ) {
        // Evict old heights
        if self.collectors.len() >= self.max_pending_heights {
            let min_height = self.collectors.keys().copied().min().unwrap_or(0);
            self.collectors.remove(&min_height);
        }

        let threshold = ((committee_size as u64)
            .saturating_mul(self.finality_threshold_percent)
            / 100) as usize;
        let threshold = threshold.max(1);

        self.collectors.insert(
            height,
            VoteCollector::new(block_hash, committee_pubkeys, threshold, committee_size),
        );

        debug!(
            height,
            threshold,
            committee_size,
            "Started vote collection for block"
        );
    }

    /// Produce our committee vote for a block (if we're a committee member).
    pub fn produce_vote(
        &self,
        height: u64,
        block_hash: [u8; 32],
        signer_pubkey: Vec<u8>,
    ) -> Option<CommitteeVote> {
        let signer_index = self.our_signer_index?;

        match RingtailThreshold::partial_sign(signer_index, &self.our_signing_key, &block_hash) {
            Ok(partial) => Some(CommitteeVote {
                height,
                block_hash,
                signer_index,
                partial_signature: partial.signature,
                signer_pubkey,
            }),
            Err(e) => {
                warn!("Failed to produce committee vote: {:?}", e);
                None
            }
        }
    }

    /// Process a received committee vote.
    /// Returns Some(CommitteeAttestation) if threshold is now reached.
    pub fn process_vote(&mut self, vote: &CommitteeVote) -> Option<CommitteeAttestation> {
        let collector = self.collectors.get_mut(&vote.height)?;

        if !collector.add_vote(vote) {
            return None; // threshold not yet reached
        }

        // Threshold reached — aggregate
        info!(
            height = vote.height,
            votes = collector.votes.len(),
            "Threshold reached, aggregating committee signature"
        );

        match collector.aggregate() {
            Ok(threshold_sig) => {
                let signer_count = threshold_sig.participant_count();
                let participants = threshold_sig.participants.as_bytes().to_vec();
                let attestation = CommitteeAttestation {
                    height: vote.height,
                    block_hash: vote.block_hash,
                    threshold_signature: threshold_sig.signature,
                    participants,
                    signer_count,
                };

                // Clean up this height's collector
                self.collectors.remove(&vote.height);

                Some(attestation)
            }
            Err(e) => {
                warn!(height = vote.height, "Failed to aggregate: {:?}", e);
                None
            }
        }
    }

    /// Check if we have a finalized attestation for a given height.
    pub fn is_height_pending(&self, height: u64) -> bool {
        self.collectors.contains_key(&height)
    }

    /// Number of heights currently being tracked.
    pub fn pending_count(&self) -> usize {
        self.collectors.len()
    }
}

/// Fork choice rule: heaviest attestation wins.
///
/// Given multiple candidate blocks at the same height, prefer the one
/// with the most committee attestation weight.
pub struct ForkChoice {
    /// Candidate blocks at each height: (block_hash, attestation_count).
    candidates: HashMap<u64, Vec<([u8; 32], usize)>>,
}

impl ForkChoice {
    pub fn new() -> Self {
        Self {
            candidates: HashMap::new(),
        }
    }

    /// Record a candidate block at a height with its attestation count.
    pub fn add_candidate(&mut self, height: u64, block_hash: [u8; 32], attestation_count: usize) {
        let entry = self.candidates.entry(height).or_default();
        // Update if same hash, or add new
        if let Some(existing) = entry.iter_mut().find(|(h, _)| *h == block_hash) {
            existing.1 = existing.1.max(attestation_count);
        } else {
            entry.push((block_hash, attestation_count));
        }
    }

    /// Get the winning block hash for a height (highest attestation count).
    /// Ties broken by block hash (deterministic).
    pub fn winner(&self, height: u64) -> Option<[u8; 32]> {
        self.candidates.get(&height).and_then(|candidates| {
            candidates
                .iter()
                .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)))
                .map(|(hash, _)| *hash)
        })
    }

    /// Prune heights below a given finalized height.
    pub fn prune_below(&mut self, finalized_height: u64) {
        self.candidates.retain(|h, _| *h >= finalized_height);
    }
}

impl Default for ForkChoice {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove: fork choice with a single candidate always returns that candidate.
    #[kani::proof]
    fn fork_choice_single_deterministic() {
        let mut fc = ForkChoice::new();
        let hash: [u8; 32] = [kani::any(); 32];
        let count: usize = kani::any();
        kani::assume(count > 0 && count < 1000);
        let height: u64 = kani::any();
        kani::assume(height < 1_000_000);

        fc.add_candidate(height, hash, count);
        assert_eq!(fc.winner(height), Some(hash));
    }

    /// Prove: fork choice always prefers higher attestation count.
    #[kani::proof]
    fn fork_choice_heavier_wins() {
        let mut fc = ForkChoice::new();
        let hash_a = [1u8; 32];
        let hash_b = [2u8; 32];
        let count_a: usize = kani::any();
        let count_b: usize = kani::any();
        kani::assume(count_a < count_b);
        kani::assume(count_b < 10_000);

        fc.add_candidate(1, hash_a, count_a);
        fc.add_candidate(1, hash_b, count_b);

        assert_eq!(fc.winner(1), Some(hash_b));
    }

    /// Prove: prune_below removes all heights below threshold.
    #[kani::proof]
    fn fork_choice_prune_removes_old() {
        let mut fc = ForkChoice::new();
        let threshold: u64 = kani::any();
        kani::assume(threshold > 0 && threshold < 100);

        // Add candidate below threshold
        fc.add_candidate(threshold - 1, [1u8; 32], 5);
        fc.prune_below(threshold);
        assert_eq!(fc.winner(threshold - 1), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_threshold::ntt::HandRolledOps;
    use seal_threshold::ringtail::RingOps;

    #[test]
    fn test_committee_vote_production() {
        let ring = HandRolledOps::new();
        let sk = ring.sample_gaussian(6.108);
        let sk_bytes = ring.to_bytes(&sk);

        let mut mgr = CommitteeManager::new(sk_bytes.clone(), 67);
        mgr.set_committee_index(Some(0));

        let block_hash = sha3_256(b"test block").0;
        let vote = mgr.produce_vote(1, block_hash, vec![1, 2, 3]);

        assert!(vote.is_some());
        let v = vote.unwrap();
        assert_eq!(v.height, 1);
        assert_eq!(v.block_hash, block_hash);
        assert_eq!(v.signer_index, 0);
        assert!(!v.partial_signature.is_empty());
    }

    #[test]
    fn test_committee_vote_collection_and_aggregation() {
        let ring = HandRolledOps::new();
        let block_hash = sha3_256(b"test block at height 42").0;

        // Create 3 committee members
        let keys: Vec<Vec<u8>> = (0..3).map(|_| {
            let sk = ring.sample_gaussian(6.108);
            ring.to_bytes(&sk)
        }).collect();

        let mut mgr = CommitteeManager::new(keys[0].clone(), 67);

        // Start collection for 3-member committee, threshold = 67% of 3 = 2
        mgr.start_collection(42, block_hash, keys.clone(), 3);

        // Each member produces a vote
        let mut result = None;
        for i in 0..3 {
            let mut voter = CommitteeManager::new(keys[i].clone(), 67);
            voter.set_committee_index(Some(i));
            let vote = voter.produce_vote(42, block_hash, vec![i as u8]).unwrap();

            result = mgr.process_vote(&vote);
            if result.is_some() {
                break;
            }
        }

        // Should have aggregated after 2 votes (67% of 3)
        assert!(result.is_some());
        let attestation = result.unwrap();
        assert_eq!(attestation.height, 42);
        assert_eq!(attestation.block_hash, block_hash);
        assert!(attestation.signer_count >= 2);
    }

    #[test]
    fn test_duplicate_vote_ignored() {
        let ring = HandRolledOps::new();
        let sk = ring.sample_gaussian(6.108);
        let sk_bytes = ring.to_bytes(&sk);
        let block_hash = sha3_256(b"block").0;

        let mut mgr = CommitteeManager::new(sk_bytes.clone(), 67);
        mgr.start_collection(1, block_hash, vec![sk_bytes.clone()], 3);

        let mut voter = CommitteeManager::new(sk_bytes.clone(), 67);
        voter.set_committee_index(Some(0));
        let vote = voter.produce_vote(1, block_hash, vec![]).unwrap();

        // First vote — accepted
        let r1 = mgr.process_vote(&vote);
        assert!(r1.is_none()); // threshold not reached yet

        // Same vote again — should be ignored (duplicate signer_index)
        let r2 = mgr.process_vote(&vote);
        assert!(r2.is_none());
    }

    #[test]
    fn test_not_committee_member_no_vote() {
        let mgr = CommitteeManager::new(vec![0; 256], 67);
        // our_signer_index is None (not a committee member)
        let vote = mgr.produce_vote(1, [0u8; 32], vec![]);
        assert!(vote.is_none());
    }

    #[test]
    fn test_fork_choice_single_candidate() {
        let mut fc = ForkChoice::new();
        let hash = [1u8; 32];
        fc.add_candidate(1, hash, 5);

        assert_eq!(fc.winner(1), Some(hash));
        assert_eq!(fc.winner(2), None);
    }

    #[test]
    fn test_fork_choice_heavier_wins() {
        let mut fc = ForkChoice::new();
        let hash_a = [1u8; 32];
        let hash_b = [2u8; 32];

        fc.add_candidate(5, hash_a, 3);
        fc.add_candidate(5, hash_b, 7);

        assert_eq!(fc.winner(5), Some(hash_b)); // more attestations
    }

    #[test]
    fn test_fork_choice_tie_broken_by_hash() {
        let mut fc = ForkChoice::new();
        let hash_a = [1u8; 32];
        let hash_b = [2u8; 32];

        fc.add_candidate(5, hash_a, 5);
        fc.add_candidate(5, hash_b, 5);

        // Tie: higher hash wins (deterministic)
        assert_eq!(fc.winner(5), Some(hash_b));
    }

    #[test]
    fn test_fork_choice_prune() {
        let mut fc = ForkChoice::new();
        fc.add_candidate(1, [1u8; 32], 3);
        fc.add_candidate(5, [5u8; 32], 7);
        fc.add_candidate(10, [10u8; 32], 4);

        fc.prune_below(5);

        assert_eq!(fc.winner(1), None); // pruned
        assert_eq!(fc.winner(5), Some([5u8; 32]));
        assert_eq!(fc.winner(10), Some([10u8; 32]));
    }

    #[test]
    fn test_epoch_announcement_serialization() {
        let announcement = EpochAnnouncement {
            epoch: 42,
            vrf_public_key: vec![1, 2, 3, 4],
            validator_pubkey: vec![5, 6, 7, 8],
        };

        let bytes = bincode::serialize(&announcement).unwrap();
        let deserialized: EpochAnnouncement = bincode::deserialize(&bytes).unwrap();

        assert_eq!(deserialized.epoch, 42);
        assert_eq!(deserialized.vrf_public_key, vec![1, 2, 3, 4]);
        assert_eq!(deserialized.validator_pubkey, vec![5, 6, 7, 8]);
    }
}
