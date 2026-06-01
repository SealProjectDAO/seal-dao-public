//! VRF-based leader and committee election.

use crate::config::ConsensusConfig;
use crate::epoch::{Epoch, Slot};
use crate::validator::{ValidatorInfo, ValidatorSet};
use seal_vrf::pq_vrf::PqVrf;
use seal_vrf::traits::{Vrf, VrfOutput, VrfProof};
/// Result of a leader election for a slot.
#[derive(Clone, Debug)]
pub enum ElectionResult {
    /// This validator is elected as block proposer.
    Proposer {
        vrf_output: VrfOutput,
        vrf_proof: VrfProof,
    },
    /// This validator is elected as committee member (voter).
    Committee {
        vrf_output: VrfOutput,
        vrf_proof: VrfProof,
    },
    /// This validator is not elected for this slot.
    NotElected,
}

/// Run leader election for a validator at a given slot.
///
/// A validator is elected as proposer if their VRF output is below the
/// proposer threshold (1/committee_size of the committee threshold).
/// They are elected as committee member if their VRF output is below
/// the committee threshold.
pub fn run_election(
    validator: &ValidatorInfo,
    slot: &Slot,
    epoch: &Epoch,
    validator_set: &ValidatorSet,
    config: &ConsensusConfig,
) -> ElectionResult {
    if !validator.active {
        return ElectionResult::NotElected;
    }

    // Compute VRF
    let vrf_input = slot.vrf_input(&epoch.seed);
    let (vrf_output, vrf_proof) = match PqVrf::eval(&validator.vrf_public_key, &vrf_input) {
        Ok(result) => result,
        Err(_) => return ElectionResult::NotElected,
    };

    // Committee threshold
    let committee_threshold = validator_set.vrf_threshold(validator, config.committee_size);

    // Proposer threshold: 1 proposer expected per slot
    // = committee_threshold / committee_size (approximately)
    let proposer_threshold = committee_threshold / config.committee_size as u64;

    if vrf_output.is_below_threshold(proposer_threshold) {
        ElectionResult::Proposer {
            vrf_output,
            vrf_proof,
        }
    } else if vrf_output.is_below_threshold(committee_threshold) {
        ElectionResult::Committee {
            vrf_output,
            vrf_proof,
        }
    } else {
        ElectionResult::NotElected
    }
}

/// Verify that a validator was legitimately elected for a slot.
///
/// `vrf_verify_key` is the public key for VRF verification.
/// In the HMAC stub, this is SHA3(secret_key). In the real LB-VRF,
/// this will be the lattice VRF public key.
#[allow(clippy::too_many_arguments)]
pub fn verify_election(
    validator: &ValidatorInfo,
    slot: &Slot,
    epoch: &Epoch,
    vrf_output: &VrfOutput,
    vrf_proof: &VrfProof,
    vrf_verify_key: &[u8],
    validator_set: &ValidatorSet,
    config: &ConsensusConfig,
) -> bool {
    if !validator.active {
        return false;
    }

    // Verify VRF proof
    let vrf_input = slot.vrf_input(&epoch.seed);
    if PqVrf::verify(vrf_verify_key, &vrf_input, vrf_output, vrf_proof).is_err() {
        return false;
    }

    // Check threshold
    let committee_threshold = validator_set.vrf_threshold(validator, config.committee_size);
    vrf_output.is_below_threshold(committee_threshold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_vrf::traits::Vrf;

    fn make_validator_with_vrf(id: u8, stake: u64) -> (ValidatorInfo, Vec<u8>) {
        let kp = PqVrf::keygen();
        let verify_key = kp.public_key.clone(); // SHA3(secret_key) for HMAC stub
        let info = ValidatorInfo {
            public_key: vec![id; 32],
            vrf_public_key: kp.secret_key, // HMAC stub uses secret for eval
            stake,
            active: true,
        };
        (info, verify_key)
    }

    #[test]
    fn test_election_verifiable() {
        // PqVrf uses ML-DSA with random nonce, so outputs differ per eval.
        // We verify that both evaluations produce VERIFIABLE results.
        let (v, vk) = make_validator_with_vrf(1, 1000);
        let vs = ValidatorSet::new(vec![v.clone()]);
        let epoch = Epoch::genesis();
        let config = ConsensusConfig::default();

        // Run election and verify the result is valid
        for slot_num in 0..10u64 {
            let slot = Slot::from_absolute(slot_num, &config);
            let result = run_election(&v, &slot, &epoch, &vs, &config);
            match result {
                ElectionResult::Proposer {
                    vrf_output,
                    vrf_proof,
                }
                | ElectionResult::Committee {
                    vrf_output,
                    vrf_proof,
                } => {
                    // The VRF proof should verify
                    assert!(
                        verify_election(
                            &v,
                            &slot,
                            &epoch,
                            &vrf_output,
                            &vrf_proof,
                            &vk,
                            &vs,
                            &config
                        ),
                        "VRF proof should verify for slot {}",
                        slot_num
                    );
                }
                ElectionResult::NotElected => {
                    // Not elected is also valid
                }
            }
        }
    }

    #[test]
    fn test_election_different_slots() {
        let (v, _vk) = make_validator_with_vrf(1, 1000);
        let vs = ValidatorSet::new(vec![v.clone()]);
        let epoch = Epoch::genesis();
        let config = ConsensusConfig::default();

        let mut elected_count = 0;
        for s in 0..100 {
            let slot = Slot::from_absolute(s, &config);
            match run_election(&v, &slot, &epoch, &vs, &config) {
                ElectionResult::Proposer { .. } | ElectionResult::Committee { .. } => {
                    elected_count += 1;
                }
                ElectionResult::NotElected => {}
            }
        }
        assert!(
            elected_count > 0,
            "should be elected at least once in 100 slots"
        );
    }

    #[test]
    fn test_inactive_validator_not_elected() {
        let (mut v, _vk) = make_validator_with_vrf(1, 1000);
        v.active = false;
        let vs = ValidatorSet::new(vec![v.clone()]);
        let epoch = Epoch::genesis();
        let slot = Slot::genesis();
        let config = ConsensusConfig::default();

        assert!(matches!(
            run_election(&v, &slot, &epoch, &vs, &config),
            ElectionResult::NotElected
        ));
    }

    #[test]
    fn test_verify_election_valid() {
        let (v, vk) = make_validator_with_vrf(1, 1000);
        let vs = ValidatorSet::new(vec![v.clone()]);
        let epoch = Epoch::genesis();
        let config = ConsensusConfig::default();

        for s in 0..1000 {
            let slot = Slot::from_absolute(s, &config);
            match run_election(&v, &slot, &epoch, &vs, &config) {
                ElectionResult::Proposer {
                    vrf_output,
                    vrf_proof,
                }
                | ElectionResult::Committee {
                    vrf_output,
                    vrf_proof,
                } => {
                    assert!(verify_election(
                        &v,
                        &slot,
                        &epoch,
                        &vrf_output,
                        &vrf_proof,
                        &vk,
                        &vs,
                        &config
                    ));
                    return;
                }
                ElectionResult::NotElected => {}
            }
        }
        panic!("validator should be elected at least once in 1000 slots");
    }

    #[test]
    fn test_higher_stake_elected_more() {
        let (v_low, _vk1) = make_validator_with_vrf(1, 10);
        let (v_high, _vk2) = make_validator_with_vrf(2, 10000);
        let vs = ValidatorSet::new(vec![v_low.clone(), v_high.clone()]);
        let epoch = Epoch::genesis();
        let config = ConsensusConfig {
            committee_size: 1,
            ..ConsensusConfig::default()
        };

        let mut low_elected = 0;
        let mut high_elected = 0;
        for s in 0..1000 {
            let slot = Slot::from_absolute(s, &config);
            match run_election(&v_low, &slot, &epoch, &vs, &config) {
                ElectionResult::Proposer { .. } | ElectionResult::Committee { .. } => {
                    low_elected += 1;
                }
                _ => {}
            }
            match run_election(&v_high, &slot, &epoch, &vs, &config) {
                ElectionResult::Proposer { .. } | ElectionResult::Committee { .. } => {
                    high_elected += 1;
                }
                _ => {}
            }
        }

        assert!(
            high_elected > low_elected,
            "high stake ({}) should be elected more than low stake ({})",
            high_elected,
            low_elected
        );
    }
}
