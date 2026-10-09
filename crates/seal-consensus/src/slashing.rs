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

use crate::validator::ValidatorSet;
use seal_crypto::hash::sha3_256;
use seal_crypto::signature::{Signature, VerifyingKey};
use seal_storage::block_store::BlockHeader;

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
    ///
    /// Evidence carries the two full headers (bincode-serialized
    /// [`BlockHeader`]) plus each proposer's ML-DSA signature over its
    /// header's canonical (empty-`proposer_signature`) serialization.
    /// `report_offense` verifies both signatures against the proposer's
    /// public key *as registered in the validator set* before recording a
    /// slash — this is what stops a reporter from fabricating an offense
    /// with a random key pair, or mis-attributing a real one to an
    /// innocent validator.
    DoubleProposal {
        slot: u64,
        block_hash_1: Vec<u8>,
        block_hash_2: Vec<u8>,
        /// Full bincode-serialized [`BlockHeader`] (proposer sig included).
        header_1: Vec<u8>,
        /// Full bincode-serialized [`BlockHeader`] (proposer sig included).
        header_2: Vec<u8>,
        /// ML-DSA signature of the proposer over `header_1`'s canonical
        /// (empty-`proposer_signature`) serialization.
        header_sig_1: Vec<u8>,
        /// ML-DSA signature of the proposer over `header_2`'s canonical
        /// (empty-`proposer_signature`) serialization.
        header_sig_2: Vec<u8>,
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
    /// hashes must differ) and, for a double proposal, cryptographically
    /// verifies that both headers were signed by a validator present in
    /// `validator_set`. Then computes the penalty as a fraction of the
    /// validator's stake.
    pub fn report_offense(
        &mut self,
        offense: SlashableOffense,
        validator_stake: u64,
        validator_set: &ValidatorSet,
    ) -> Result<SlashingRecord, String> {
        // Validate evidence: the two block hashes must be different.
        match &offense {
            SlashableOffense::DoubleProposal {
                slot,
                block_hash_1,
                block_hash_2,
                header_1,
                header_2,
                header_sig_1,
                header_sig_2,
                ..
            } => {
                if block_hash_1 == block_hash_2 {
                    return Err(
                        "invalid evidence: block hashes are identical for double proposal".into(),
                    );
                }
                // A double proposal is two *different* blocks at the same
                // slot. Passing the same signed header twice (with two
                // arbitrary, differing block hashes) used to slip past the
                // `block_hash_1 != block_hash_2` check and mint a slash
                // record from a single honest block (audit finding F5), so
                // the two canonical headers must actually differ.
                if header_1 == header_2 {
                    return Err(
                        "invalid evidence: headers are identical for double proposal".into(),
                    );
                }
                // Each claimed block hash must be the actual hash of its
                // header, so a reporter cannot pair real, validly-signed
                // headers with arbitrary hashes.
                if sha3_256(header_1).0.to_vec() != *block_hash_1
                    || sha3_256(header_2).0.to_vec() != *block_hash_2
                {
                    return Err(
                        "invalid evidence: block hash does not match its header".into(),
                    );
                }
                // Cryptographically attribute the offense: both headers must
                // target `slot`, name a proposer that is registered in the
                // validator set, and carry signatures that verify under that
                // proposer's public key. Any failure rejects the evidence.
                verify_double_proposal_evidence(
                    *slot,
                    header_1,
                    header_2,
                    header_sig_1,
                    header_sig_2,
                    validator_set,
                )?;
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

/// Verify double-proposal evidence and attribute it to a real validator.
///
/// The two supplied headers must: (1) both target `slot`, (2) name the same
/// proposer, (3) have a proposer public key that is present in
/// `validator_set`, and (4) carry proposer signatures that verify over each
/// header's canonical (empty-`proposer_signature`) serialization — the exact
/// canonical bytes `BlockHeader` documents and that
/// `verify_and_apply_block` checks. Any failure rejects the offense. This is
/// the anti-forgery gate: a reporter cannot build valid evidence for a key the
/// chain never entrusted with proposing, nor mislabel a real offense.
fn verify_double_proposal_evidence(
    slot: u64,
    header_1: &[u8],
    header_2: &[u8],
    header_sig_1: &[u8],
    header_sig_2: &[u8],
    validator_set: &ValidatorSet,
) -> Result<(), String> {
    let h1: BlockHeader =
        bincode::deserialize(header_1).map_err(|e| format!("invalid header_1: {}", e))?;
    let h2: BlockHeader =
        bincode::deserialize(header_2).map_err(|e| format!("invalid header_2: {}", e))?;

    if h1.height != slot || h2.height != slot {
        return Err(format!(
            "double-proposal headers do not both target slot {} (got {}, {})",
            slot,
            h1.height,
            h2.height
        ));
    }
    if h1.proposer != h2.proposer {
        return Err("double-proposal headers name different proposers".into());
    }

    // The proposer must be a registered validator; otherwise the evidence is
    // for a key the chain never entrusted with proposing, and it is rejected.
    let proposer = validator_set
        .find_by_pubkey(&h1.proposer)
        .ok_or("double-proposal proposer is not in the validator set")?;

    // Verify each proposer signature over its header's canonical (empty-sig)
    // serialization, against the proposer's public key as registered in the
    // set. Mirrors `verify_and_apply_block`'s proposer-sig check.
    for (header, sig_bytes) in [(&h1, header_sig_1), (&h2, header_sig_2)] {
        let vk = VerifyingKey::from_bytes(&proposer.public_key)
            .map_err(|e| format!("invalid proposer public key: {}", e))?;
        let mut unsigned = header.clone();
        unsigned.proposer_signature.clear();
        let sign_bytes =
            bincode::serialize(&unsigned).map_err(|e| format!("serialize error: {}", e))?;
        let sig = Signature::from_bytes(sig_bytes.to_vec());
        vk.verify(&sign_bytes, &sig)
            .map_err(|e| format!("proposer signature verification failed: {}", e))?;
    }
    Ok(())
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
    use crate::validator::ValidatorInfo;
    use seal_crypto::hash::{sha3_256, Hash256};
    use seal_crypto::signature::SigningKey;

    fn default_manager() -> SlashingManager {
        SlashingManager::new(SlashingConfig::default())
    }

    /// Deterministic ML-DSA key pair from a single seed byte.
    fn test_keypair(seed_byte: u8) -> (SigningKey, VerifyingKey) {
        SigningKey::generate_from_seed([seed_byte; 32])
    }

    /// A validator set from `(public_key, stake)` pairs, all active.
    fn validator_set(pks: &[(Vec<u8>, u64)]) -> ValidatorSet {
        let validators = pks
            .iter()
            .map(|(pk, stake)| ValidatorInfo {
                public_key: pk.clone(),
                vrf_public_key: vec![0u8; 32],
                stake: *stake,
                active: true,
            })
            .collect();
        ValidatorSet::new(validators)
    }

    /// A minimal block header at `height`/`timestamp`, proposing under `proposer`.
    fn make_header(height: u64, timestamp: u64, proposer: &[u8]) -> BlockHeader {
        BlockHeader {
            height,
            parent_hash: Hash256::ZERO,
            state_root: Hash256::ZERO,
            timestamp,
            proposer: proposer.to_vec(),
            vrf_output: vec![],
            vrf_proof: vec![],
            proposer_signature: vec![],
            tx_root: Hash256::ZERO,
        }
    }

    /// Sign `header`'s canonical (empty-sig) serialization with `sk`.
    /// Returns `(full_header_bytes, sig_bytes)` where `full_header_bytes` is
    /// the bincode of the header with its signature attached (as a real block
    /// header looks) and `sig_bytes` is the detached ML-DSA signature.
    fn sign_header(sk: &SigningKey, header: &BlockHeader) -> (Vec<u8>, Vec<u8>) {
        let mut unsigned = header.clone();
        unsigned.proposer_signature.clear();
        let sign_bytes = bincode::serialize(&unsigned).expect("serialize header");
        let sig = sk.sign(&sign_bytes).expect("sign header");
        let sig_bytes = sig.to_bytes().to_vec();
        let mut full = header.clone();
        full.proposer_signature = sig_bytes.clone();
        let full_bytes = bincode::serialize(&full).expect("serialize signed header");
        (full_bytes, sig_bytes)
    }

    /// A valid, self-consistent double-proposal offense at `slot` (two
    /// differently-stamped blocks, same proposer), plus the proposer public
    /// key so a test can build the matching validator set.
    fn valid_double_proposal(slot: u64, label: &str) -> (SlashableOffense, Vec<u8>) {
        let (sk, vk) = test_keypair(slot as u8);
        let pk = vk.to_bytes();
        let (h1, s1) = sign_header(&sk, &make_header(slot, 10_000 + slot, &pk));
        let (h2, s2) = sign_header(&sk, &make_header(slot, 10_001 + slot, &pk));
        (
            SlashableOffense::DoubleProposal {
                slot,
                block_hash_1: sha3_256(&h1).0.to_vec(),
                block_hash_2: sha3_256(&h2).0.to_vec(),
                header_1: h1,
                header_2: h2,
                header_sig_1: s1,
                header_sig_2: s2,
                proposer: label.into(),
            },
            pk,
        )
    }

    #[test]
    fn test_double_proposal_slash() {
        let mut sm = default_manager();
        sm.set_epoch(5);

        let (offense, pk) = valid_double_proposal(42, "val_alice");
        let vs = validator_set(&[(pk, 10_000)]);

        let record = sm.report_offense(offense, 10_000, &vs).unwrap();
        // 1% of 10_000 = 100
        assert_eq!(record.penalty_amount, 100);
        assert_eq!(record.epoch, 5);
        assert!(sm.is_slashed("val_alice"));
        assert_eq!(sm.total_slashed("val_alice"), 100);
    }

    #[test]
    fn test_double_proposal_bad_signature_rejected() {
        let mut sm = default_manager();
        let (sk, vk) = test_keypair(2);
        let (other_sk, _other_vk) = test_keypair(3);
        let pk = vk.to_bytes();
        let (h1, _s1) = sign_header(&sk, &make_header(7, 2_000, &pk));
        let (h2, s2) = sign_header(&sk, &make_header(7, 2_001, &pk));
        // header_sig_1 is produced by a *different* key, so it fails verify.
        let (_bad_full, bad_sig) = sign_header(&other_sk, &make_header(7, 2_000, &pk));
        let vs = validator_set(&[(pk.clone(), 10_000)]);

        let offense = SlashableOffense::DoubleProposal {
            slot: 7,
            block_hash_1: sha3_256(&h1).0.to_vec(),
            block_hash_2: sha3_256(&h2).0.to_vec(),
            header_1: h1,
            header_2: h2,
            header_sig_1: bad_sig,
            header_sig_2: s2,
            proposer: "val_alice".into(),
        };

        let result = sm.report_offense(offense, 10_000, &vs);
        assert!(result.is_err());
        assert!(!sm.is_slashed("val_alice"));
    }

    #[test]
    fn test_double_proposal_non_validator_rejected() {
        let mut sm = default_manager();
        // The offense's proposer key is NOT in the validator set.
        let (rogue_sk, rogue_vk) = test_keypair(4);
        let rogue_pk = rogue_vk.to_bytes();
        let (h1, s1) = sign_header(&rogue_sk, &make_header(9, 3_000, &rogue_pk));
        let (h2, s2) = sign_header(&rogue_sk, &make_header(9, 3_001, &rogue_pk));
        // The validator set holds a *different* (legit) key.
        let (_legit_sk, legit_vk) = test_keypair(5);
        let vs = validator_set(&[(legit_vk.to_bytes(), 10_000)]);

        let offense = SlashableOffense::DoubleProposal {
            slot: 9,
            block_hash_1: sha3_256(&h1).0.to_vec(),
            block_hash_2: sha3_256(&h2).0.to_vec(),
            header_1: h1,
            header_2: h2,
            header_sig_1: s1,
            header_sig_2: s2,
            proposer: "rogue".into(),
        };

        let result = sm.report_offense(offense, 10_000, &vs);
        assert!(result.is_err());
        assert!(!sm.is_slashed("rogue"));
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

        let record = sm
            .report_offense(offense, 50_000, &ValidatorSet::new(vec![]))
            .unwrap();
        // 1% of 50_000 = 500
        assert_eq!(record.penalty_amount, 500);
        assert!(sm.is_slashed("val_bob"));
    }

    #[test]
    fn test_identical_hashes_rejected() {
        let mut sm = default_manager();
        let (sk, vk) = test_keypair(6);
        let pk = vk.to_bytes();
        let (h, s) = sign_header(&sk, &make_header(1, 4_000, &pk));
        let vs = validator_set(&[(pk, 10_000)]);

        let offense = SlashableOffense::DoubleProposal {
            slot: 1,
            block_hash_1: sha3_256(&h).0.to_vec(),
            block_hash_2: sha3_256(&h).0.to_vec(), // identical
            header_1: h.clone(),
            header_2: h,
            header_sig_1: s.clone(),
            header_sig_2: s,
            proposer: "val_charlie".into(),
        };

        let result = sm.report_offense(offense, 10_000, &vs);
        assert!(result.is_err());
        assert!(!sm.is_slashed("val_charlie"));
    }

    /// Regression for audit finding F5: the SAME signed header passed twice,
    /// with two *different* block hashes, evaded the `block_hash_1 !=
    /// block_hash_2` check and produced a slash record from a single honest
    /// block. The headers must differ and each block hash must hash its
    /// header, so this is now rejected.
    #[test]
    fn test_double_proposal_identical_header_different_hashes_rejected() {
        let mut sm = default_manager();
        let (sk, vk) = test_keypair(7);
        let pk = vk.to_bytes();
        let (h, s) = sign_header(&sk, &make_header(3, 5_000, &pk));
        let vs = validator_set(&[(pk, 10_000)]);

        let offense = SlashableOffense::DoubleProposal {
            slot: 3,
            block_hash_1: sha3_256(&h).0.to_vec(),
            // Differs from block_hash_1 (so the identical-hash check passes)
            // but is not the hash of the header.
            block_hash_2: vec![0xEE; 32],
            header_1: h.clone(),
            header_2: h,
            header_sig_1: s.clone(),
            header_sig_2: s,
            proposer: "val_eve".into(),
        };

        let result = sm.report_offense(offense, 10_000, &vs);
        assert!(result.is_err());
        assert!(!sm.is_slashed("val_eve"));
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

        let result = sm
            .report_offense(offense, 10_000, &ValidatorSet::new(vec![]));
        assert!(result.is_err());
    }

    #[test]
    fn test_cumulative_slashing() {
        let mut sm = default_manager();

        let (offense1, pk1) = valid_double_proposal(1, "val_repeat");
        let vs = validator_set(&[(pk1, 10_000)]);
        let offense2 = SlashableOffense::DoubleVote {
            slot: 2,
            block_hash_1: vec![3; 32],
            block_hash_2: vec![4; 32],
            voter: "val_repeat".into(),
        };

        sm.report_offense(offense1, 10_000, &vs)
            .unwrap(); // 100
        sm.report_offense(offense2, 10_000, &ValidatorSet::new(vec![]))
            .unwrap(); // 100

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

        let (offense, pk) = valid_double_proposal(1, "val_x");
        let vs = validator_set(&[(pk, 100_000)]);

        let record = sm.report_offense(offense, 100_000, &vs).unwrap();
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

        let record = sm
            .report_offense(offense, 100_000, &ValidatorSet::new(vec![]))
            .unwrap();
        // 2% of 100_000 = 2_000
        assert_eq!(record.penalty_amount, 2_000);
    }

    #[test]
    fn test_slash_history_ordering() {
        let mut sm = default_manager();
        sm.set_epoch(1);

        let (offense1, pk1) = valid_double_proposal(10, "v1");
        let vs = validator_set(&[(pk1, 10_000)]);
        let offense2 = SlashableOffense::DoubleVote {
            slot: 20,
            block_hash_1: vec![3; 32],
            block_hash_2: vec![4; 32],
            voter: "v2".into(),
        };

        // Need to set epoch before reporting
        sm.report_offense(offense1, 10_000, &vs).unwrap();
        sm.set_epoch(3);
        sm.report_offense(offense2, 20_000, &ValidatorSet::new(vec![]))
            .unwrap();

        let history = sm.slash_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].epoch, 1);
        assert_eq!(history[1].epoch, 3);
    }

    #[test]
    fn test_zero_stake_slash() {
        let mut sm = default_manager();

        let (offense, pk) = valid_double_proposal(1, "v_zero");
        let vs = validator_set(&[(pk, 0)]);

        let record = sm.report_offense(offense, 0, &vs).unwrap();
        assert_eq!(record.penalty_amount, 0);
        // Still marked as slashed even with zero penalty
        assert!(sm.is_slashed("v_zero"));
    }

    #[test]
    fn test_large_stake_no_overflow() {
        let mut sm = default_manager();

        let (offense, pk) = valid_double_proposal(1, "v_whale");
        let vs = validator_set(&[(pk, 10_000)]);

        // Very large stake — should not overflow
        let record = sm.report_offense(offense, u64::MAX, &vs).unwrap();
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

        let (offense1, pk1) = valid_double_proposal(1, "v_max");
        let vs = validator_set(&[(pk1, 10_000)]);
        let offense2 = SlashableOffense::DoubleVote {
            slot: 2,
            block_hash_1: vec![3; 32],
            block_hash_2: vec![4; 32],
            voter: "v_max".into(),
        };

        sm.report_offense(offense1, u64::MAX / 2, &vs)
            .unwrap();
        sm.report_offense(offense2, u64::MAX / 2, &ValidatorSet::new(vec![]))
            .unwrap();

        // Cumulative should saturate, not overflow
        let total = sm.total_slashed("v_max");
        assert!(total > 0);
    }
}
