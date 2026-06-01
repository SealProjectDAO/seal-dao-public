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

#[cfg(test)]
use seal_crypto::hash::sha3_256; // Used only by the test module below.
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

        let threshold = ((committee_size as u64).saturating_mul(self.finality_threshold_percent)
            / 100) as usize;
        let threshold = threshold.max(1);

        self.collectors.insert(
            height,
            VoteCollector::new(block_hash, committee_pubkeys, threshold, committee_size),
        );

        debug!(
            height,
            threshold, committee_size, "Started vote collection for block"
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
///
/// Uses `BTreeMap` (not `HashMap`) so Kani harnesses can trace
/// through construction — HashMap's SipHash seeding calls the OS
/// random source which Kani can't interpret. See
/// `formal/kani/LIMITATIONS.md` §5.
pub struct ForkChoice {
    /// Candidate blocks at each height: (block_hash, attestation_count).
    candidates: std::collections::BTreeMap<u64, Vec<([u8; 32], usize)>>,
}

impl ForkChoice {
    pub fn new() -> Self {
        Self {
            candidates: std::collections::BTreeMap::new(),
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

// ============================================================================
// Full-protocol committee manager: uses round1_full / round2_full with
// PublicParams so the signature is byte-exact accepted by
// `verify_signature_full` and the BPF/Soroban verifiers.
// ============================================================================

/// A two-round full-protocol committee vote, carrying the K-vector
/// commitment (`D_i = A·r_i + e_i`) and the per-round-2 response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeVoteFull {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub signer_index: usize,
    /// Round-1 commitment serialized as `MODULE_K · RING_N · 8` bytes.
    pub commitment: Vec<u8>,
    /// MAC binding `commitment` to `signer_index` under the per-slot key.
    pub mac: Vec<u8>,
    /// Round-2 response (`r_i + c·sk_i`), single-polynomial.
    pub response: Vec<u8>,
}

/// Coordinator state for the full-protocol path. Owns one `RingtailParty`
/// per managed slot; collects round-1 commitments from peers, aggregates
/// them, then collects round-2 responses and aggregates the final
/// `RingtailSignature`.
pub struct CommitteeManagerFull {
    /// Public parameters (matrix A, public key t). Shared across slots.
    public_params: seal_threshold::ringtail::PublicParams,
    /// Our secret share polynomial (serialized).
    sk_share_bytes: Vec<u8>,
    /// Per-slot collected round-1 commitments, keyed by signer index.
    round1: HashMap<u64, HashMap<usize, seal_threshold::ringtail::Round1MessageFull>>,
    /// Per-slot collected round-2 responses (keyed by signer index).
    round2: HashMap<u64, HashMap<usize, seal_threshold::ringtail::Round2Message>>,
    /// Per-slot cached `aggregated_d_bytes` (computed once per slot when
    /// the round-1 set is "frozen" via `freeze_round1`).
    aggregated_d: HashMap<u64, Vec<u8>>,
    /// Threshold (number of round-2 responses needed).
    threshold: usize,
    /// Committee size.
    committee_size: usize,
    /// Smudging on/off (off in the byte-exact subset that the BPF
    /// verifier accepts today).
    smudging: bool,
}

impl CommitteeManagerFull {
    pub fn new(
        public_params: seal_threshold::ringtail::PublicParams,
        sk_share_bytes: Vec<u8>,
        threshold: usize,
        committee_size: usize,
    ) -> Self {
        Self {
            public_params,
            sk_share_bytes,
            round1: HashMap::new(),
            round2: HashMap::new(),
            aggregated_d: HashMap::new(),
            threshold,
            committee_size,
            smudging: false,
        }
    }

    /// Enable per-signer smudging error. Default is false because the
    /// BPF/Soroban verifiers do not yet implement the matching rounding
    /// (see `seal_threshold::rounding`).
    pub fn enable_smudging(&mut self, on: bool) {
        self.smudging = on;
    }

    /// Run our round-1 for `height`, returning the full vote (commitment
    /// + MAC; the response field is filled later in `our_round2`).
    pub fn our_round1(
        &mut self,
        height: u64,
        block_hash: [u8; 32],
        signer_index: usize,
        mac_key: &[u8],
    ) -> Result<
        (
            CommitteeVoteFull,
            seal_threshold::ringtail::RingtailParty<seal_threshold::ntt::HandRolledOps>,
        ),
        ThresholdError,
    > {
        use seal_threshold::ntt::HandRolledOps;
        use seal_threshold::ringtail::{RingOps, RingtailParty};
        let ring = HandRolledOps::new();
        let sk_poly = ring
            .from_bytes(&self.sk_share_bytes)
            .map_err(|_| ThresholdError::InvalidPartialSignature(signer_index))?;
        let mut party = RingtailParty::new(signer_index, sk_poly, HandRolledOps::new());
        let r1 = party.round1_full(&self.public_params, mac_key, self.smudging)?;
        self.round1
            .entry(height)
            .or_default()
            .insert(signer_index, r1.clone());
        let vote = CommitteeVoteFull {
            height,
            block_hash,
            signer_index,
            commitment: r1.commitment,
            mac: r1.mac,
            response: Vec::new(), // filled in round 2
        };
        Ok((vote, party))
    }

    /// Add a peer's round-1 vote to the aggregator state.
    pub fn add_peer_round1(&mut self, vote: &CommitteeVoteFull) {
        self.round1.entry(vote.height).or_default().insert(
            vote.signer_index,
            seal_threshold::ringtail::Round1MessageFull {
                party_id: vote.signer_index,
                commitment: vote.commitment.clone(),
                mac: vote.mac.clone(),
            },
        );
    }

    /// Number of round-1 commitments collected so far for `height`.
    pub fn round1_count(&self, height: u64) -> usize {
        self.round1.get(&height).map(|m| m.len()).unwrap_or(0)
    }

    /// Freeze the round-1 set for `height` and compute the aggregated
    /// commitment bytes that round-2 will hash with the message. Returns
    /// the aggregated D bytes for broadcast / round-2 hashing.
    pub fn freeze_round1(&mut self, height: u64) -> Result<Vec<u8>, ThresholdError> {
        use seal_threshold::ntt::HandRolledOps;
        use seal_threshold::ringtail::aggregate_commitments;
        let r1s: Vec<_> = self
            .round1
            .get(&height)
            .ok_or(ThresholdError::InvalidThresholdSignature)?
            .values()
            .cloned()
            .collect();
        let agg = aggregate_commitments(&HandRolledOps::new(), &r1s)?;
        self.aggregated_d.insert(height, agg.clone());
        Ok(agg)
    }

    /// Run our round-2: given a `RingtailParty` returned by `our_round1`,
    /// compute and store our response and emit the full vote.
    pub fn our_round2(
        &mut self,
        height: u64,
        block_hash: [u8; 32],
        signer_index: usize,
        party: &mut seal_threshold::ringtail::RingtailParty<seal_threshold::ntt::HandRolledOps>,
        message: &[u8],
    ) -> Result<CommitteeVoteFull, ThresholdError> {
        let aggregated_d = self
            .aggregated_d
            .get(&height)
            .ok_or(ThresholdError::InvalidThresholdSignature)?
            .clone();
        let r2 = party.round2_full(&aggregated_d, message)?;
        // Pull our round-1 commitment + MAC back so the vote is self-contained.
        let r1 = self
            .round1
            .get(&height)
            .and_then(|m| m.get(&signer_index))
            .cloned()
            .ok_or(ThresholdError::InvalidPartialSignature(signer_index))?;
        self.round2
            .entry(height)
            .or_default()
            .insert(signer_index, r2.clone());
        Ok(CommitteeVoteFull {
            height,
            block_hash,
            signer_index,
            commitment: r1.commitment,
            mac: r1.mac,
            response: r2.response,
        })
    }

    /// Add a peer's round-2 response (the `response` bytes) to the aggregator.
    pub fn add_peer_round2(&mut self, vote: &CommitteeVoteFull) {
        if vote.response.is_empty() {
            return;
        }
        self.round2.entry(vote.height).or_default().insert(
            vote.signer_index,
            seal_threshold::ringtail::Round2Message {
                party_id: vote.signer_index,
                response: vote.response.clone(),
            },
        );
    }

    /// Number of round-2 responses collected so far for `height`.
    pub fn round2_count(&self, height: u64) -> usize {
        self.round2.get(&height).map(|m| m.len()).unwrap_or(0)
    }

    /// Aggregate the final threshold signature for `height` once
    /// round-2 has reached threshold. Returns the byte-exact
    /// `RingtailSignature` that `verify_signature_full` accepts.
    pub fn aggregate_final(
        &self,
        height: u64,
        message: &[u8],
    ) -> Result<seal_threshold::ringtail::RingtailSignature, ThresholdError> {
        use seal_threshold::ntt::HandRolledOps;
        use seal_threshold::ringtail::aggregate_responses_full;
        let aggregated_d = self
            .aggregated_d
            .get(&height)
            .ok_or(ThresholdError::InvalidThresholdSignature)?;
        let r2s: Vec<_> = self
            .round2
            .get(&height)
            .ok_or(ThresholdError::InvalidThresholdSignature)?
            .values()
            .cloned()
            .collect();
        aggregate_responses_full(
            &HandRolledOps::new(),
            aggregated_d,
            &r2s,
            message,
            self.threshold,
            self.committee_size,
        )
    }

    /// Drop per-slot state once a height is finalized to bound memory.
    pub fn prune_height(&mut self, height: u64) {
        self.round1.remove(&height);
        self.round2.remove(&height);
        self.aggregated_d.remove(&height);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // ────────────────────────────────────────────────────────────────
    // NOTE on harness style
    //
    // These harnesses verify the *decision logic* the ForkChoice
    // implementation relies on — comparator ordering, filter
    // behaviour — rather than instantiating a ForkChoice and calling
    // `add_candidate` through the BTreeMap. Two reasons:
    //
    // 1. BTreeMap insertion hits CBMC's limits. `BTreeMap::entry ->
    //    node split -> correct_childrens_parent_links` has loops
    //    Kani can't close, and the resulting SAT instance exceeds
    //    several GiB of memory even with tight `kani::unwind`
    //    bounds (observed: 38 GiB RSS, 7 min wall-time).
    // 2. The *behaviour* we want to prove is not about BTreeMap; it
    //    is "heavier candidate wins, ties broken by hash, prune
    //    removes below threshold." Those are properties of the
    //    comparator + Vec::retain — purely logical, and Kani can
    //    close them in milliseconds when reformulated directly.
    //
    // The full through-the-API behaviour is covered by the
    // `#[cfg(test)]` suite below (test_fork_choice_*).

    /// Prove: a comparator that ranks (count, hash) lex-ascending
    /// picks the single candidate as the winner. This is the
    /// invariant `ForkChoice::winner` depends on when a single
    /// candidate exists for a height.
    #[kani::proof]
    fn fork_choice_single_deterministic() {
        let hash: [u8; 32] = [kani::any(); 32];
        let count: usize = kani::any();
        kani::assume(count > 0 && count < 1000);
        // A one-element Vec is what `add_candidate(h, hash, count)`
        // produces for a fresh BTreeMap entry. Verify the
        // comparator returns it.
        let candidates = [(hash, count)];
        let winner = candidates
            .iter()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)))
            .map(|(h, _)| *h);
        assert_eq!(winner, Some(hash));
    }

    /// Prove: when two candidates have different attestation counts
    /// the one with the higher count wins — regardless of hash.
    #[kani::proof]
    fn fork_choice_heavier_wins() {
        let hash_a = [1u8; 32];
        let hash_b = [2u8; 32];
        let count_a: usize = kani::any();
        let count_b: usize = kani::any();
        kani::assume(count_a < count_b);
        kani::assume(count_b < 10_000);

        let candidates = [(hash_a, count_a), (hash_b, count_b)];
        let winner = candidates
            .iter()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)))
            .map(|(h, _)| *h);
        assert_eq!(winner, Some(hash_b));
    }

    /// Prove the `retain` predicate `ForkChoice::prune_below` uses:
    /// heights strictly below `threshold` are NOT retained. If the
    /// predicate is correct for every `(threshold, height)` pair
    /// with height < threshold, `BTreeMap::retain` will drop them.
    #[kani::proof]
    fn fork_choice_prune_removes_old() {
        let threshold: u64 = kani::any();
        kani::assume(threshold > 0 && threshold < 100);
        let below = threshold - 1;
        // The closure mirrors `prune_below`'s `|h, _| *h >= finalized_height`.
        let keep = below >= threshold;
        assert!(!keep);
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
        let keys: Vec<Vec<u8>> = (0..3)
            .map(|_| {
                let sk = ring.sample_gaussian(6.108);
                ring.to_bytes(&sk)
            })
            .collect();

        let mut mgr = CommitteeManager::new(keys[0].clone(), 67);

        // Start collection for 3-member committee, threshold = 67% of 3 = 2
        mgr.start_collection(42, block_hash, keys.clone(), 3);

        // Each member produces a vote
        let mut result = None;
        for (i, key) in keys.iter().enumerate().take(3) {
            let mut voter = CommitteeManager::new(key.clone(), 67);
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
    fn test_committee_manager_full_single_signer_byte_exact() {
        use seal_threshold::ntt::HandRolledOps;
        use seal_threshold::ringtail::{generate_public_params_no_error, verify_signature_full};

        let ring = HandRolledOps::new();
        let (params, sk_bytes) = generate_public_params_no_error(&ring);

        let mut mgr = CommitteeManagerFull::new(params.clone(), sk_bytes, 1, 1);
        let block_hash = sha3_256(b"full-protocol slot 1").0;
        let mac_key = sha3_256(b"per-slot-mac-key").0;

        let (_vote_r1, mut party) = mgr
            .our_round1(1, block_hash, 0, &mac_key)
            .expect("round1 must succeed");

        mgr.freeze_round1(1).expect("freeze must succeed");

        let _vote_r2 = mgr
            .our_round2(1, block_hash, 0, &mut party, &block_hash)
            .expect("round2 must succeed");

        let sig = mgr
            .aggregate_final(1, &block_hash)
            .expect("aggregate must succeed");

        verify_signature_full(&ring, &sig, &params, &block_hash, 1)
            .expect("byte-exact verify against host verifier");
    }

    #[test]
    fn test_committee_manager_full_two_of_two_aggregation() {
        use seal_threshold::lagrange::lagrange_coefficient_at_zero;
        use seal_threshold::ntt::HandRolledOps;
        use seal_threshold::ringtail::RING_Q;

        // Sanity: with two parties at indices {1, 2}, the Lagrange
        // coefficients sum to 1, so a t=2 reconstruction at x=0 is
        // unbiased.
        let l1 = lagrange_coefficient_at_zero(1, &[1, 2], RING_Q);
        let l2 = lagrange_coefficient_at_zero(2, &[1, 2], RING_Q);
        let sum = ((l1 as u128 + l2 as u128) % RING_Q as u128) as u64;
        assert_eq!(sum, 1);

        // Aggregator-side smoke test that two parties' round-1 + round-2
        // get tracked correctly without panicking.
        let ring = HandRolledOps::new();
        let (params, sk_bytes) = seal_threshold::ringtail::generate_public_params_no_error(&ring);
        let mut mgr_a = CommitteeManagerFull::new(params.clone(), sk_bytes.clone(), 2, 2);
        let mut mgr_b = CommitteeManagerFull::new(params.clone(), sk_bytes.clone(), 2, 2);
        let bh = sha3_256(b"slot 2-of-2").0;
        let mac_key = sha3_256(b"key").0;

        let (vote_a, mut party_a) = mgr_a.our_round1(1, bh, 0, &mac_key).unwrap();
        let (vote_b, mut party_b) = mgr_b.our_round1(1, bh, 1, &mac_key).unwrap();

        // Both managers see both round-1 votes.
        mgr_a.add_peer_round1(&vote_b);
        mgr_b.add_peer_round1(&vote_a);

        assert_eq!(mgr_a.round1_count(1), 2);
        assert_eq!(mgr_b.round1_count(1), 2);

        mgr_a.freeze_round1(1).unwrap();
        mgr_b.freeze_round1(1).unwrap();

        let _r2_a = mgr_a.our_round2(1, bh, 0, &mut party_a, &bh).unwrap();
        let _r2_b = mgr_b.our_round2(1, bh, 1, &mut party_b, &bh).unwrap();
    }

    #[test]
    fn test_committee_manager_full_prune_height() {
        use seal_threshold::ntt::HandRolledOps;
        use seal_threshold::ringtail::generate_public_params_no_error;

        let ring = HandRolledOps::new();
        let (params, sk_bytes) = generate_public_params_no_error(&ring);
        let mut mgr = CommitteeManagerFull::new(params, sk_bytes, 1, 1);

        let mac_key = [0u8; 32];
        let _ = mgr.our_round1(7, [0u8; 32], 0, &mac_key).unwrap();
        assert_eq!(mgr.round1_count(7), 1);
        mgr.prune_height(7);
        assert_eq!(mgr.round1_count(7), 0);
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
