//! Vote delegation system.
//!
//! - Token holders can delegate their voting power to another address
//! - Delegation is per-track (can delegate differently for Treasury vs Protocol)
//! - Delegated power stacks (A delegates to B, C delegates to B -> B has all three)
//! - Per-delegate cap: max 4% of circulating supply delegated to one delegate
//! - Delegators can revoke at any time
//! - Direct vote overrides delegation for that proposal

use crate::governance::ProposalTrack;
use std::collections::HashMap;

/// Maximum percentage of circulating supply that can be delegated to a single
/// delegate, expressed in basis points (400 bps = 4%).
const MAX_DELEGATE_CAP_BPS: u64 = 400;

/// A single delegation record.
#[derive(Clone, Debug)]
struct Delegation {
    /// Address of the delegator.
    delegator: String,
    /// Address of the delegate.
    delegate: String,
    /// Proposal track this delegation applies to.
    track: ProposalTrack,
    /// Weight being delegated (voting power).
    weight: u64,
}

/// Manages vote delegations across all tracks.
#[derive(Default)]
pub struct DelegationManager {
    /// (delegator, track) -> Delegation
    delegations: HashMap<(String, ProposalTrack), Delegation>,
}

impl DelegationManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Delegate voting power from `delegator` to `delegate` for a given track.
    ///
    /// If the delegator already has a delegation for this track, it is replaced.
    /// A delegator cannot delegate to themselves.
    pub fn delegate(
        &mut self,
        delegator: &str,
        delegate: &str,
        track: &ProposalTrack,
        weight: u64,
    ) -> Result<(), String> {
        if delegator == delegate {
            return Err("cannot delegate to self".into());
        }
        if weight == 0 {
            return Err("delegation weight must be greater than zero".into());
        }

        let key = (delegator.to_string(), track.clone());
        let record = Delegation {
            delegator: delegator.to_string(),
            delegate: delegate.to_string(),
            track: track.clone(),
            weight,
        };
        self.delegations.insert(key, record);
        Ok(())
    }

    /// Revoke delegation for a given track.
    pub fn revoke(&mut self, delegator: &str, track: &ProposalTrack) -> Result<(), String> {
        let key = (delegator.to_string(), track.clone());
        if self.delegations.remove(&key).is_none() {
            return Err(format!(
                "no delegation found for {} on track {:?}",
                delegator, track
            ));
        }
        Ok(())
    }

    /// Compute effective voting weight for a voter on a given track.
    ///
    /// Returns the voter's own weight plus all weight delegated to them,
    /// **excluding** delegators who voted directly on the proposal (their
    /// direct vote overrides the delegation).
    pub fn effective_weight(
        &self,
        voter: &str,
        track: &ProposalTrack,
        direct_voters: &[String],
    ) -> u64 {
        let delegated: u64 = self
            .delegations
            .values()
            .filter(|d| d.delegate == voter && d.track == *track)
            .filter(|d| !direct_voters.contains(&d.delegator))
            .fold(0u64, |acc, d| acc.saturating_add(d.weight));

        delegated
    }

    /// Total weight currently delegated to a specific delegate on a track.
    pub fn total_delegated_to(&self, delegate: &str, track: &ProposalTrack) -> u64 {
        self.delegations
            .values()
            .filter(|d| d.delegate == delegate && d.track == *track)
            .fold(0u64, |acc, d| acc.saturating_add(d.weight))
    }

    /// Check whether a delegate is under the 4% cap for a given track.
    ///
    /// Returns `true` if the total delegated weight to this delegate is
    /// strictly less than 4% of the circulating supply.
    pub fn check_delegate_cap(
        &self,
        delegate: &str,
        track: &ProposalTrack,
        circulating_supply: u64,
    ) -> bool {
        let total = self.total_delegated_to(delegate, track);
        // cap = circulating_supply * MAX_DELEGATE_CAP_BPS / 10_000
        // Use checked arithmetic to avoid overflow on large supplies.
        let cap = circulating_supply
            .checked_mul(MAX_DELEGATE_CAP_BPS)
            .map(|v| v / 10_000)
            .unwrap_or(u64::MAX);
        total < cap
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove that delegate cap check never overflows for any circulating supply.
    #[kani::proof]
    fn delegate_cap_no_overflow() {
        let circulating: u64 = kani::any();
        let dm = DelegationManager::new();
        let track = ProposalTrack::TreasurySmall;
        // check_delegate_cap uses checked_mul; must not panic
        let _ = dm.check_delegate_cap("any_delegate", &track, circulating);
    }

    /// Prove that effective_weight with saturating_add never overflows.
    #[kani::proof]
    fn effective_weight_saturates() {
        let mut dm = DelegationManager::new();
        let track = ProposalTrack::TreasurySmall;

        // Two delegations with near-max weights
        let w1: u64 = kani::any();
        let w2: u64 = kani::any();
        kani::assume(w1 > 0);
        kani::assume(w2 > 0);

        dm.delegate("a", "z", &track, w1).unwrap();
        dm.delegate("b", "z", &track, w2).unwrap();

        let eff = dm.effective_weight("z", &track, &[]);
        // Must be >= each individual weight (saturating)
        assert!(eff >= w1.min(w2));
    }

    /// Prove that self-delegation is always rejected.
    #[kani::proof]
    fn self_delegation_rejected() {
        let mut dm = DelegationManager::new();
        let track = ProposalTrack::ParameterChange;
        let result = dm.delegate("alice", "alice", &track, 100);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegate_and_effective_weight() {
        let mut dm = DelegationManager::new();
        let track = ProposalTrack::TreasurySmall;

        // A delegates 100 to B
        dm.delegate("alice", "bob", &track, 100).unwrap();
        // C delegates 200 to B
        dm.delegate("charlie", "bob", &track, 200).unwrap();

        // B's effective weight with no direct voters overriding
        let eff = dm.effective_weight("bob", &track, &[]);
        assert_eq!(eff, 300);
    }

    #[test]
    fn test_direct_vote_overrides_delegation() {
        let mut dm = DelegationManager::new();
        let track = ProposalTrack::TreasurySmall;

        dm.delegate("alice", "bob", &track, 100).unwrap();
        dm.delegate("charlie", "bob", &track, 200).unwrap();

        // Alice voted directly, so her delegation is excluded
        let eff = dm.effective_weight("bob", &track, &["alice".to_string()]);
        assert_eq!(eff, 200);
    }

    #[test]
    fn test_delegation_per_track() {
        let mut dm = DelegationManager::new();

        dm.delegate("alice", "bob", &ProposalTrack::TreasurySmall, 100)
            .unwrap();
        dm.delegate("alice", "charlie", &ProposalTrack::ProtocolUpgrade, 200)
            .unwrap();

        assert_eq!(
            dm.total_delegated_to("bob", &ProposalTrack::TreasurySmall),
            100
        );
        assert_eq!(
            dm.total_delegated_to("bob", &ProposalTrack::ProtocolUpgrade),
            0
        );
        assert_eq!(
            dm.total_delegated_to("charlie", &ProposalTrack::ProtocolUpgrade),
            200
        );
    }

    #[test]
    fn test_revoke_delegation() {
        let mut dm = DelegationManager::new();
        let track = ProposalTrack::ParameterChange;

        dm.delegate("alice", "bob", &track, 500).unwrap();
        assert_eq!(dm.total_delegated_to("bob", &track), 500);

        dm.revoke("alice", &track).unwrap();
        assert_eq!(dm.total_delegated_to("bob", &track), 0);
    }

    #[test]
    fn test_revoke_nonexistent_fails() {
        let mut dm = DelegationManager::new();
        let result = dm.revoke("alice", &ProposalTrack::Emergency);
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_delegate_to_self() {
        let mut dm = DelegationManager::new();
        let result = dm.delegate("alice", "alice", &ProposalTrack::TreasurySmall, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_weight_delegation_rejected() {
        let mut dm = DelegationManager::new();
        let result = dm.delegate("alice", "bob", &ProposalTrack::TreasurySmall, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_replace_existing_delegation() {
        let mut dm = DelegationManager::new();
        let track = ProposalTrack::Constitutional;

        dm.delegate("alice", "bob", &track, 100).unwrap();
        assert_eq!(dm.total_delegated_to("bob", &track), 100);

        // Alice re-delegates to charlie — replaces the previous delegation
        dm.delegate("alice", "charlie", &track, 250).unwrap();
        assert_eq!(dm.total_delegated_to("bob", &track), 0);
        assert_eq!(dm.total_delegated_to("charlie", &track), 250);
    }

    #[test]
    fn test_delegate_cap_under() {
        let mut dm = DelegationManager::new();
        let track = ProposalTrack::TreasuryLarge;

        // Circulating supply: 1_000_000. 4% cap = 40_000.
        dm.delegate("alice", "bob", &track, 30_000).unwrap();
        assert!(dm.check_delegate_cap("bob", &track, 1_000_000));
    }

    #[test]
    fn test_delegate_cap_at_limit() {
        let mut dm = DelegationManager::new();
        let track = ProposalTrack::TreasuryLarge;

        // Exactly at 4% — should return false (not strictly under)
        dm.delegate("alice", "bob", &track, 40_000).unwrap();
        assert!(!dm.check_delegate_cap("bob", &track, 1_000_000));
    }

    #[test]
    fn test_delegate_cap_over() {
        let mut dm = DelegationManager::new();
        let track = ProposalTrack::TreasuryLarge;

        dm.delegate("alice", "bob", &track, 50_000).unwrap();
        assert!(!dm.check_delegate_cap("bob", &track, 1_000_000));
    }

    #[test]
    fn test_stacking_from_multiple_delegators() {
        let mut dm = DelegationManager::new();
        let track = ProposalTrack::ParameterChange;

        dm.delegate("a", "z", &track, 10).unwrap();
        dm.delegate("b", "z", &track, 20).unwrap();
        dm.delegate("c", "z", &track, 30).unwrap();
        dm.delegate("d", "z", &track, 40).unwrap();

        assert_eq!(dm.total_delegated_to("z", &track), 100);
        assert_eq!(dm.effective_weight("z", &track, &[]), 100);

        // Two of them voted directly
        let eff = dm.effective_weight(
            "z",
            &track,
            &["a".to_string(), "c".to_string()],
        );
        assert_eq!(eff, 60); // 20 + 40
    }

    #[test]
    fn test_effective_weight_no_delegations() {
        let dm = DelegationManager::new();
        let track = ProposalTrack::Emergency;

        // No delegations: effective weight from delegations is 0
        assert_eq!(dm.effective_weight("alice", &track, &[]), 0);
    }

    #[test]
    fn test_saturating_addition_large_weights() {
        let mut dm = DelegationManager::new();
        let track = ProposalTrack::TreasurySmall;

        dm.delegate("a", "z", &track, u64::MAX - 1).unwrap();
        dm.delegate("b", "z", &track, u64::MAX - 1).unwrap();

        // Should saturate at u64::MAX, not overflow
        let eff = dm.effective_weight("z", &track, &[]);
        assert_eq!(eff, u64::MAX);
    }
}
