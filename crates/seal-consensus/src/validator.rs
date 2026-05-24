//! Validator set management.

use seal_crypto::hash::sha3_256;
use serde::{Deserialize, Serialize};

/// Information about a single validator.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorInfo {
    /// Validator's public key (ML-DSA, for signing).
    pub public_key: Vec<u8>,
    /// Validator's VRF public key (for leader election).
    pub vrf_public_key: Vec<u8>,
    /// Staked amount (micro-SEAL).
    pub stake: u64,
    /// Whether the validator is active (not slashed, not unbonding).
    pub active: bool,
}

/// The active validator set for an epoch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// All validators, ordered by public key for determinism.
    pub validators: Vec<ValidatorInfo>,
    /// Total stake across all active validators.
    pub total_stake: u64,
}

impl ValidatorSet {
    /// Create a new validator set.
    pub fn new(mut validators: Vec<ValidatorInfo>) -> Self {
        // Sort by public key for deterministic ordering
        validators.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        let total_stake = validators
            .iter()
            .filter(|v| v.active)
            .map(|v| v.stake)
            .sum();
        ValidatorSet {
            validators,
            total_stake,
        }
    }

    /// Number of active validators.
    pub fn active_count(&self) -> usize {
        self.validators.iter().filter(|v| v.active).count()
    }

    /// Find a validator by public key.
    pub fn find_by_pubkey(&self, pubkey: &[u8]) -> Option<&ValidatorInfo> {
        self.validators.iter().find(|v| v.public_key == pubkey)
    }

    /// Find a validator whose `SHA3-256(public_key)` matches the
    /// supplied 32-byte address-hash. Backs the per-address validator-
    /// status lookup (`seal_getValidatorByAddress`): an address
    /// encodes `bech32m(SHA3-256(pubkey))` and is the only on-Seal
    /// identifier a wallet/UI can hand to an RPC, so the lookup runs
    /// in the address-hash space rather than the raw-pubkey space.
    /// Linear scan — fine for the typical sub-thousand validator
    /// set; if it ever grows large enough to matter, replace with a
    /// hash-keyed index built once per epoch.
    pub fn find_by_address_hash(&self, address_hash: &[u8; 32]) -> Option<&ValidatorInfo> {
        self.validators
            .iter()
            .find(|v| sha3_256(&v.public_key).0 == *address_hash)
    }

    /// Compute the VRF threshold for a given validator.
    /// threshold = (stake / total_stake) * (committee_size / active_count) * u64::MAX
    pub fn vrf_threshold(&self, validator: &ValidatorInfo, committee_size: u32) -> u64 {
        if self.total_stake == 0 || self.active_count() == 0 || !validator.active {
            return 0;
        }
        let stake_fraction = validator.stake as f64 / self.total_stake as f64;
        let selection_fraction = committee_size as f64 / self.active_count() as f64;
        let probability = (stake_fraction * selection_fraction).min(1.0);
        (probability * u64::MAX as f64) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator(id: u8, stake: u64) -> ValidatorInfo {
        ValidatorInfo {
            public_key: vec![id; 32],
            vrf_public_key: vec![id + 100; 32],
            stake,
            active: true,
        }
    }

    #[test]
    fn test_validator_set_creation() {
        let vs = ValidatorSet::new(vec![
            make_validator(1, 100),
            make_validator(2, 200),
            make_validator(3, 300),
        ]);
        assert_eq!(vs.active_count(), 3);
        assert_eq!(vs.total_stake, 600);
    }

    #[test]
    fn test_validator_set_sorted() {
        let vs = ValidatorSet::new(vec![
            make_validator(3, 300),
            make_validator(1, 100),
            make_validator(2, 200),
        ]);
        assert_eq!(vs.validators[0].public_key, vec![1u8; 32]);
        assert_eq!(vs.validators[1].public_key, vec![2u8; 32]);
        assert_eq!(vs.validators[2].public_key, vec![3u8; 32]);
    }

    #[test]
    fn test_find_by_pubkey() {
        let vs = ValidatorSet::new(vec![make_validator(1, 100), make_validator(2, 200)]);
        assert!(vs.find_by_pubkey(&[1u8; 32]).is_some());
        assert!(vs.find_by_pubkey(&[99u8; 32]).is_none());
    }

    #[test]
    fn test_find_by_address_hash() {
        let vs = ValidatorSet::new(vec![make_validator(1, 100), make_validator(2, 200)]);
        // Recompute the address-hash for validator 1's pubkey and look it up.
        let v1_addr = sha3_256(&[1u8; 32]).0;
        let found = vs.find_by_address_hash(&v1_addr).expect("v1 found");
        assert_eq!(found.public_key, vec![1u8; 32]);
        assert_eq!(found.stake, 100);
        // An unrelated address-hash returns None.
        let unrelated = sha3_256(b"not-a-validator-key").0;
        assert!(vs.find_by_address_hash(&unrelated).is_none());
    }

    #[test]
    fn test_vrf_threshold_proportional() {
        let vs = ValidatorSet::new(vec![make_validator(1, 100), make_validator(2, 300)]);
        let t1 = vs.vrf_threshold(&vs.validators[0], 2);
        let t2 = vs.vrf_threshold(&vs.validators[1], 2);
        // Validator 2 has 3x stake, should have ~3x threshold
        assert!(t2 > t1);
        let ratio = t2 as f64 / t1 as f64;
        assert!(
            (ratio - 3.0).abs() < 0.1,
            "ratio should be ~3.0, got {}",
            ratio
        );
    }

    #[test]
    fn test_vrf_threshold_inactive() {
        let mut v = make_validator(1, 100);
        v.active = false;
        let vs = ValidatorSet::new(vec![v.clone(), make_validator(2, 200)]);
        assert_eq!(vs.vrf_threshold(&v, 100), 0);
    }

    #[test]
    fn test_active_count_excludes_inactive() {
        let mut v = make_validator(1, 100);
        v.active = false;
        let vs = ValidatorSet::new(vec![v, make_validator(2, 200)]);
        assert_eq!(vs.active_count(), 1);
        assert_eq!(vs.total_stake, 200); // Only active stake
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove: vrf_threshold for inactive validator is always 0.
    #[kani::proof]
    fn inactive_threshold_zero() {
        let stake: u64 = kani::any();
        let committee_size: u32 = kani::any();
        kani::assume(committee_size > 0);

        let mut v = ValidatorInfo {
            public_key: vec![1; 32],
            vrf_public_key: vec![2; 32],
            stake,
            active: false,
        };

        let vs = ValidatorSet::new(vec![v.clone()]);
        assert_eq!(vs.vrf_threshold(&v, committee_size), 0);
    }

    /// Prove: vrf_threshold never exceeds u64::MAX (no overflow).
    #[kani::proof]
    fn threshold_no_overflow() {
        let stake: u64 = kani::any();
        let total_other: u64 = kani::any();
        let committee_size: u32 = kani::any();
        kani::assume(stake <= 1_000_000_000_000); // Reasonable stake bound
        kani::assume(total_other <= 1_000_000_000_000);
        kani::assume(committee_size > 0 && committee_size <= 10000);

        let v = ValidatorInfo {
            public_key: vec![1; 32],
            vrf_public_key: vec![2; 32],
            stake,
            active: true,
        };

        let vs = ValidatorSet::new(vec![v.clone()]);
        // This should not panic (overflow would panic)
        let _threshold = vs.vrf_threshold(&v, committee_size);
    }
}
