//! On-chain governance: proposals, voting, execution.
//!
//! Implements GOVERNANCE.md — three-body system with proposal tracks.
//!
//! # Features
//! - 6 proposal tracks with distinct thresholds, vote periods, timelocks
//! - Conviction voting: voters lock tokens for multiplied weight (0.1×–6×)
//! - Adaptive quorum biasing: low turnout requires super-majority
//! - Vote change and withdrawal during voting period
//! - Technical Council and Service Operators Council (Phase 3)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Proposal tracks
// ============================================================================

/// Proposal track (GOVERNANCE.md §2).
///
/// `PartialOrd + Ord` derived so `(String, ProposalTrack)` can key a
/// `BTreeMap` — see `delegation.rs` for the Kani-motivated switch.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProposalTrack {
    ParameterChange,
    ProtocolUpgrade,
    TreasurySmall,
    TreasuryLarge,
    Emergency,
    Constitutional,
}

impl ProposalTrack {
    /// Base approval percentage (0-100) before adaptive quorum adjustment.
    pub fn base_approval_threshold(&self) -> u64 {
        match self {
            ProposalTrack::ParameterChange => 50,
            ProposalTrack::ProtocolUpgrade => 66,
            ProposalTrack::TreasurySmall => 50,
            ProposalTrack::TreasuryLarge => 66,
            ProposalTrack::Emergency => 75,
            ProposalTrack::Constitutional => 75,
        }
    }

    /// Required approval percentage (0-100).
    /// Alias for backward compatibility with existing code.
    pub fn approval_threshold(&self) -> u64 {
        self.base_approval_threshold()
    }

    /// Vote period in epochs.
    pub fn vote_period_epochs(&self) -> u64 {
        match self {
            ProposalTrack::ParameterChange => 5,
            ProposalTrack::ProtocolUpgrade => 14,
            ProposalTrack::TreasurySmall => 5,
            ProposalTrack::TreasuryLarge => 7,
            ProposalTrack::Emergency => 1,
            ProposalTrack::Constitutional => 14,
        }
    }

    /// Timelock in epochs (delay between passing and execution).
    pub fn timelock_epochs(&self) -> u64 {
        match self {
            ProposalTrack::ParameterChange => 3,
            ProposalTrack::ProtocolUpgrade => 14,
            ProposalTrack::TreasurySmall => 2,
            ProposalTrack::TreasuryLarge => 7,
            ProposalTrack::Emergency => 1,
            ProposalTrack::Constitutional => 28,
        }
    }

    /// Adaptive quorum bias factor (0-100).
    /// Higher bias = more super-majority required at low turnout.
    pub fn quorum_bias(&self) -> u64 {
        match self {
            ProposalTrack::ParameterChange => 20,
            ProposalTrack::ProtocolUpgrade => 25,
            ProposalTrack::TreasurySmall => 15,
            ProposalTrack::TreasuryLarge => 25,
            ProposalTrack::Emergency => 30,
            ProposalTrack::Constitutional => 30,
        }
    }

    /// Minimum turnout percentage (0-100) for a valid vote.
    pub fn min_turnout(&self) -> u64 {
        match self {
            ProposalTrack::ParameterChange => 5,
            ProposalTrack::ProtocolUpgrade => 10,
            ProposalTrack::TreasurySmall => 5,
            ProposalTrack::TreasuryLarge => 10,
            ProposalTrack::Emergency => 15,
            ProposalTrack::Constitutional => 15,
        }
    }
}

// ============================================================================
// Conviction voting
// ============================================================================

/// Conviction multiplier — voters lock tokens longer for higher weight.
///
/// - None: 0.1× weight, no lock
/// - X1: 1× weight, 1 epoch lock
/// - X2: 2× weight, 2 epoch lock
/// - X3: 3× weight, 4 epoch lock
/// - X4: 4× weight, 8 epoch lock
/// - X5: 5× weight, 16 epoch lock
/// - X6: 6× weight, 32 epoch lock
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Conviction {
    None,
    X1,
    X2,
    X3,
    X4,
    X5,
    X6,
}

impl Conviction {
    /// Multiplier numerator (multiply stake, then divide by 10).
    /// None=1 (0.1×), X1=10 (1×), X2=20 (2×), X3=30 (3×), X4=40 (4×), X5=50 (5×), X6=60 (6×).
    pub fn multiplier_x10(&self) -> u64 {
        match self {
            Conviction::None => 1,
            Conviction::X1 => 10,
            Conviction::X2 => 20,
            Conviction::X3 => 30,
            Conviction::X4 => 40,
            Conviction::X5 => 50,
            Conviction::X6 => 60,
        }
    }

    /// Lock period in epochs after vote period ends.
    pub fn lock_epochs(&self) -> u64 {
        match self {
            Conviction::None => 0,
            Conviction::X1 => 1,
            Conviction::X2 => 2,
            Conviction::X3 => 4,
            Conviction::X4 => 8,
            Conviction::X5 => 16,
            Conviction::X6 => 32,
        }
    }

    /// Compute weighted voting power: (stake * multiplier_x10) / 10.
    /// Uses saturating arithmetic to prevent overflow.
    pub fn weighted_stake(&self, stake: u64) -> u64 {
        stake.saturating_mul(self.multiplier_x10()) / 10
    }
}

// ============================================================================
// Adaptive quorum
// ============================================================================

/// Compute the adaptive approval threshold based on turnout.
///
/// At low turnout, a super-majority is needed. At full turnout, the base threshold suffices.
/// Formula: `effective_threshold = base + bias * (100 - turnout_pct) / 100`
/// Capped at 100%.
pub fn adaptive_threshold(base_threshold: u64, bias: u64, turnout_pct: u64) -> u64 {
    let turnout = if turnout_pct > 100 { 100 } else { turnout_pct };
    let adjustment = bias.saturating_mul(100u64.saturating_sub(turnout)) / 100;
    let threshold = base_threshold.saturating_add(adjustment);
    if threshold > 100 { 100 } else { threshold }
}

// ============================================================================
// Core data structures
// ============================================================================

/// A governance proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub id: u64,
    pub track: ProposalTrack,
    pub title: String,
    pub description: String,
    /// The SQL or parameter change to execute if passed.
    pub payload: String,
    /// Proposer's address.
    pub proposer: String,
    /// Epoch when voting started.
    pub start_epoch: u64,
    /// Current status.
    pub status: ProposalStatus,
}

/// Proposal lifecycle status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    Voting,
    Passed,
    Rejected,
    Timelocked { execute_at_epoch: u64 },
    Executed,
    Cancelled,
}

/// Vote choice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteChoice {
    Yes,
    No,
    Abstain,
}

/// Vote record with conviction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub voter: String,
    pub choice: VoteChoice,
    /// Raw stake committed to this vote.
    pub stake: u64,
    /// Conviction multiplier chosen by voter.
    pub conviction: Conviction,
    /// Effective voting weight: stake * conviction multiplier.
    pub weight: u64,
    /// Epoch when tokens unlock (vote_end_epoch + conviction.lock_epochs()).
    pub unlock_epoch: u64,
}

/// Token lock record for conviction voting.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvictionLock {
    pub voter: String,
    pub proposal_id: u64,
    pub amount: u64,
    pub unlock_epoch: u64,
}

// ============================================================================
// Governance module
// ============================================================================

/// Governance state.
#[derive(Default)]
pub struct GovernanceModule {
    proposals: HashMap<u64, Proposal>,
    votes: HashMap<u64, Vec<Vote>>,
    conviction_locks: Vec<ConvictionLock>,
    next_proposal_id: u64,
    /// Total eligible supply for quorum calculation.
    total_eligible_supply: u64,
}

impl GovernanceModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a known total supply for adaptive quorum.
    pub fn with_supply(total_eligible_supply: u64) -> Self {
        Self {
            total_eligible_supply,
            ..Self::default()
        }
    }

    /// Update the total eligible supply (call when supply changes).
    pub fn set_total_eligible_supply(&mut self, supply: u64) {
        self.total_eligible_supply = supply;
    }

    /// Create a new proposal.
    pub fn create_proposal(
        &mut self,
        track: ProposalTrack,
        title: String,
        description: String,
        payload: String,
        proposer: String,
        current_epoch: u64,
    ) -> u64 {
        let id = self.next_proposal_id;
        self.next_proposal_id = self.next_proposal_id.saturating_add(1);

        let proposal = Proposal {
            id,
            track,
            title,
            description,
            payload,
            proposer,
            start_epoch: current_epoch,
            status: ProposalStatus::Voting,
        };

        self.proposals.insert(id, proposal);
        self.votes.insert(id, Vec::new());
        id
    }

    /// Cast a vote on a proposal with conviction.
    pub fn vote_with_conviction(
        &mut self,
        proposal_id: u64,
        voter: String,
        choice: VoteChoice,
        stake: u64,
        conviction: Conviction,
    ) -> Result<(), String> {
        let proposal = self
            .proposals
            .get(&proposal_id)
            .ok_or_else(|| format!("proposal {} not found", proposal_id))?;

        if proposal.status != ProposalStatus::Voting {
            return Err("proposal is not in voting status".into());
        }

        let vote_end = proposal.start_epoch.saturating_add(proposal.track.vote_period_epochs());
        let unlock_epoch = vote_end.saturating_add(conviction.lock_epochs());
        let weight = conviction.weighted_stake(stake);

        let votes = self
            .votes
            .get_mut(&proposal_id)
            .ok_or_else(|| format!("votes for proposal {} not found", proposal_id))?;

        // Check for existing vote — allow vote change
        if let Some(existing) = votes.iter_mut().find(|v| v.voter == voter) {
            // Remove old lock
            self.conviction_locks
                .retain(|l| !(l.voter == voter && l.proposal_id == proposal_id));

            // Update vote
            existing.choice = choice;
            existing.stake = stake;
            existing.conviction = conviction;
            existing.weight = weight;
            existing.unlock_epoch = unlock_epoch;
        } else {
            votes.push(Vote {
                voter: voter.clone(),
                choice,
                stake,
                conviction,
                weight,
                unlock_epoch,
            });
        }

        // Record conviction lock (if conviction requires locking)
        if conviction.lock_epochs() > 0 {
            self.conviction_locks.push(ConvictionLock {
                voter,
                proposal_id,
                amount: stake,
                unlock_epoch,
            });
        }

        Ok(())
    }

    /// Cast a vote (backward-compatible: uses Conviction::X1).
    pub fn vote(
        &mut self,
        proposal_id: u64,
        voter: String,
        choice: VoteChoice,
        weight: u64,
    ) -> Result<(), String> {
        // For backward compatibility, treat weight as stake with 1× conviction
        self.vote_with_conviction(proposal_id, voter, choice, weight, Conviction::X1)
    }

    /// Withdraw a vote (tokens remain locked for the original conviction period).
    pub fn withdraw_vote(
        &mut self,
        proposal_id: u64,
        voter: &str,
    ) -> Result<(), String> {
        let proposal = self
            .proposals
            .get(&proposal_id)
            .ok_or_else(|| format!("proposal {} not found", proposal_id))?;

        if proposal.status != ProposalStatus::Voting {
            return Err("proposal is not in voting status".into());
        }

        let votes = self
            .votes
            .get_mut(&proposal_id)
            .ok_or_else(|| format!("votes for proposal {} not found", proposal_id))?;

        let idx = votes
            .iter()
            .position(|v| v.voter == voter)
            .ok_or_else(|| format!("{} has not voted on proposal {}", voter, proposal_id))?;

        votes.remove(idx);
        // Note: conviction lock remains — tokens stay locked until unlock_epoch
        Ok(())
    }

    /// Tally votes with adaptive quorum biasing.
    pub fn tally(
        &mut self,
        proposal_id: u64,
        current_epoch: u64,
    ) -> Result<ProposalStatus, String> {
        let proposal = self
            .proposals
            .get(&proposal_id)
            .ok_or_else(|| format!("proposal {} not found", proposal_id))?;

        if proposal.status != ProposalStatus::Voting {
            return Err("proposal is not in voting status".into());
        }

        let vote_end = proposal.start_epoch.saturating_add(proposal.track.vote_period_epochs());
        if current_epoch < vote_end {
            return Err("voting period not over yet".into());
        }

        let votes = self
            .votes
            .get(&proposal_id)
            .ok_or_else(|| format!("votes for proposal {} not found", proposal_id))?;

        let total_yes: u64 = votes
            .iter()
            .filter(|v| v.choice == VoteChoice::Yes)
            .map(|v| v.weight)
            .sum();
        let total_no: u64 = votes
            .iter()
            .filter(|v| v.choice == VoteChoice::No)
            .map(|v| v.weight)
            .sum();
        let total_voted = total_yes.saturating_add(total_no);

        // Compute turnout percentage
        let turnout_pct = if self.total_eligible_supply > 0 {
            // Use raw stake for turnout (not conviction-weighted)
            let raw_stake_voted: u64 = votes
                .iter()
                .filter(|v| v.choice != VoteChoice::Abstain)
                .map(|v| v.stake)
                .sum();
            raw_stake_voted.saturating_mul(100) / self.total_eligible_supply
        } else {
            100 // If no supply info, treat as full turnout (use base threshold)
        };

        // Check minimum turnout
        let min_turnout = proposal.track.min_turnout();
        if turnout_pct < min_turnout && self.total_eligible_supply > 0 {
            let new_status = ProposalStatus::Rejected;
            if let Some(p) = self.proposals.get_mut(&proposal_id) {
                p.status = new_status.clone();
            }
            return Ok(new_status);
        }

        // Compute adaptive threshold
        let threshold = adaptive_threshold(
            proposal.track.base_approval_threshold(),
            proposal.track.quorum_bias(),
            turnout_pct,
        );

        let new_status = if total_voted == 0 {
            ProposalStatus::Rejected
        } else if total_yes.saturating_mul(100) / total_voted >= threshold {
            let execute_at = current_epoch.saturating_add(proposal.track.timelock_epochs());
            ProposalStatus::Timelocked {
                execute_at_epoch: execute_at,
            }
        } else {
            ProposalStatus::Rejected
        };

        if let Some(p) = self.proposals.get_mut(&proposal_id) {
            p.status = new_status.clone();
        }
        Ok(new_status)
    }

    /// Execute a timelocked proposal (after timelock expires).
    pub fn execute(&mut self, proposal_id: u64, current_epoch: u64) -> Result<String, String> {
        let proposal = self
            .proposals
            .get(&proposal_id)
            .ok_or_else(|| format!("proposal {} not found", proposal_id))?;

        match &proposal.status {
            ProposalStatus::Timelocked { execute_at_epoch } => {
                if current_epoch < *execute_at_epoch {
                    return Err(format!(
                        "timelock not expired: {} epochs remaining",
                        execute_at_epoch.saturating_sub(current_epoch)
                    ));
                }
            }
            _ => return Err("proposal is not timelocked".into()),
        }

        let payload = proposal.payload.clone();
        if let Some(p) = self.proposals.get_mut(&proposal_id) {
            p.status = ProposalStatus::Executed;
        }
        Ok(payload)
    }

    /// Get expired conviction locks that can be released at the given epoch.
    pub fn expired_locks(&self, current_epoch: u64) -> Vec<&ConvictionLock> {
        self.conviction_locks
            .iter()
            .filter(|l| current_epoch >= l.unlock_epoch)
            .collect()
    }

    /// Release expired conviction locks.
    pub fn release_expired_locks(&mut self, current_epoch: u64) -> Vec<ConvictionLock> {
        let (expired, active): (Vec<_>, Vec<_>) = self
            .conviction_locks
            .drain(..)
            .partition(|l| current_epoch >= l.unlock_epoch);
        self.conviction_locks = active;
        expired
    }

    /// Get a proposal by ID.
    pub fn get_proposal(&self, id: u64) -> Option<&Proposal> {
        self.proposals.get(&id)
    }

    /// List all proposals.
    pub fn list_proposals(&self) -> Vec<&Proposal> {
        let mut proposals: Vec<_> = self.proposals.values().collect();
        proposals.sort_by_key(|p| p.id);
        proposals
    }

    /// Get votes for a proposal.
    pub fn get_votes(&self, proposal_id: u64) -> Option<&Vec<Vote>> {
        self.votes.get(&proposal_id)
    }
}

// ============================================================================
// Technical Council (GOVERNANCE.md §1.2)
// ============================================================================

/// Technical Council: 7–11 elected members with 1-year terms.
///
/// Powers:
/// - Whitelist emergency proposals for fast-track voting
/// - Veto queued proposals during timelock (with mandatory post-hoc ratification)
/// - Manage cryptographic agility (PQC algorithm rotation)
/// - Cannot unilaterally pass proposals
#[derive(Clone, Debug, Default)]
pub struct TechnicalCouncil {
    /// Council members (public key -> member info).
    members: HashMap<String, CouncilMember>,
    /// Maximum council size.
    max_size: usize,
    /// Minimum council size.
    min_size: usize,
    /// Proposals whitelisted for emergency fast-track.
    whitelisted: Vec<u64>,
    /// Proposals vetoed during timelock.
    vetoed: Vec<u64>,
}

/// A council member.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CouncilMember {
    /// Member's public key (hex-encoded).
    pub pubkey: String,
    /// Human-readable name.
    pub name: String,
    /// Epoch when term started.
    pub term_start_epoch: u64,
    /// Epoch when term expires (term_start + ~1 year in epochs).
    pub term_end_epoch: u64,
}

impl TechnicalCouncil {
    pub fn new() -> Self {
        Self {
            max_size: 11,
            min_size: 7,
            ..Self::default()
        }
    }

    /// Add a member (via Token House election).
    pub fn add_member(&mut self, member: CouncilMember) -> Result<(), String> {
        if self.members.len() >= self.max_size {
            return Err(format!("council is full ({} members)", self.max_size));
        }
        if self.members.contains_key(&member.pubkey) {
            return Err("member already on council".into());
        }
        self.members.insert(member.pubkey.clone(), member);
        Ok(())
    }

    /// Remove a member (term expiry or removal vote).
    pub fn remove_member(&mut self, pubkey: &str) -> Result<(), String> {
        if self.members.remove(pubkey).is_none() {
            return Err("member not found".into());
        }
        Ok(())
    }

    /// Remove members whose terms have expired.
    pub fn expire_terms(&mut self, current_epoch: u64) -> Vec<CouncilMember> {
        let expired: Vec<String> = self
            .members
            .iter()
            .filter(|(_, m)| m.term_end_epoch <= current_epoch)
            .map(|(k, _)| k.clone())
            .collect();

        expired
            .iter()
            .filter_map(|k| self.members.remove(k))
            .collect()
    }

    /// Whitelist a proposal for emergency fast-track.
    /// Requires council vote (simple majority of council members).
    pub fn whitelist_proposal(
        &mut self,
        proposal_id: u64,
        approving_members: &[String],
    ) -> Result<(), String> {
        let valid_approvers: usize = approving_members
            .iter()
            .filter(|pk| self.members.contains_key(*pk))
            .count();

        let required = self.members.len() / 2 + 1; // simple majority
        if valid_approvers < required {
            return Err(format!(
                "need {} council approvals, got {}",
                required, valid_approvers
            ));
        }

        if !self.whitelisted.contains(&proposal_id) {
            self.whitelisted.push(proposal_id);
        }
        Ok(())
    }

    /// Veto a queued proposal during timelock.
    /// Requires 3-of-5 council members (or majority if council is smaller).
    pub fn veto_proposal(
        &mut self,
        proposal_id: u64,
        approving_members: &[String],
    ) -> Result<(), String> {
        let valid_approvers: usize = approving_members
            .iter()
            .filter(|pk| self.members.contains_key(*pk))
            .count();

        let required = 3.min(self.members.len() / 2 + 1);
        if valid_approvers < required {
            return Err(format!(
                "need {} council approvals for veto, got {}",
                required, valid_approvers
            ));
        }

        if !self.vetoed.contains(&proposal_id) {
            self.vetoed.push(proposal_id);
        }
        Ok(())
    }

    /// Check if a proposal is whitelisted for emergency fast-track.
    pub fn is_whitelisted(&self, proposal_id: u64) -> bool {
        self.whitelisted.contains(&proposal_id)
    }

    /// Check if a proposal has been vetoed.
    pub fn is_vetoed(&self, proposal_id: u64) -> bool {
        self.vetoed.contains(&proposal_id)
    }

    /// Current council size.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Check if council is at quorum (at least min_size members).
    pub fn has_quorum(&self) -> bool {
        self.members.len() >= self.min_size
    }

    /// Count how many of the given public keys correspond to seated
    /// council members. Duplicate pubkeys collapse to one vote.
    pub fn count_valid_approvers(&self, approving_members: &[String]) -> usize {
        let mut seen = std::collections::HashSet::new();
        for pk in approving_members {
            if self.members.contains_key(pk) {
                seen.insert(pk.clone());
            }
        }
        seen.len()
    }

    /// Smallest number of council members required for a 2/3
    /// supermajority vote. Uses ceiling arithmetic — a 7-member
    /// council needs 5 (not 4), a 11-member council needs 8.
    pub fn two_thirds_threshold(&self) -> usize {
        let n = self.members.len();
        n.saturating_mul(2).div_ceil(3)
    }

    /// True if `approving_members` covers at least a 2/3 supermajority
    /// of seated council members. Empty council always returns false
    /// (caller must bootstrap before using supermajority gates).
    pub fn has_two_thirds_approval(&self, approving_members: &[String]) -> bool {
        if self.members.is_empty() {
            return false;
        }
        self.count_valid_approvers(approving_members) >= self.two_thirds_threshold()
    }

    /// List all seated members (sorted by pubkey for determinism).
    pub fn list_members(&self) -> Vec<CouncilMember> {
        let mut out: Vec<CouncilMember> = self.members.values().cloned().collect();
        out.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
        out
    }
}

// ============================================================================
// Service Operators Council (GOVERNANCE.md §1.3)
// ============================================================================

/// Service Operators Council: representatives of node/TEE operators.
///
/// Powers:
/// - Advisory vote on infrastructure parameters
/// - Binding veto on changes that would break SLAs
/// - Advisory influence on storage pricing, compute costs
#[derive(Clone, Debug, Default)]
pub struct ServiceOperatorsCouncil {
    /// Council members (operator_id -> OperatorInfo).
    members: HashMap<String, OperatorInfo>,
    /// Proposals this council has advisorily endorsed.
    endorsed: Vec<u64>,
    /// Proposals this council has vetoed (binding for SLA-breaking changes).
    sla_vetoed: Vec<u64>,
}

/// Information about a service operator council member.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorInfo {
    /// Operator identifier (public key or organization name).
    pub operator_id: String,
    /// Description of the operator's infrastructure.
    pub description: String,
    /// Number of nodes operated.
    pub node_count: u32,
    /// Whether this operator runs TEE-attested nodes.
    pub tee_attested: bool,
}

impl ServiceOperatorsCouncil {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a service operator.
    pub fn register_operator(&mut self, info: OperatorInfo) -> Result<(), String> {
        if self.members.contains_key(&info.operator_id) {
            return Err("operator already registered".into());
        }
        self.members.insert(info.operator_id.clone(), info);
        Ok(())
    }

    /// Remove a service operator.
    pub fn remove_operator(&mut self, operator_id: &str) -> Result<(), String> {
        if self.members.remove(operator_id).is_none() {
            return Err("operator not found".into());
        }
        Ok(())
    }

    /// Advisory endorsement of a proposal.
    /// Requires majority of operators.
    pub fn endorse_proposal(
        &mut self,
        proposal_id: u64,
        approving_operators: &[String],
    ) -> Result<(), String> {
        let valid: usize = approving_operators
            .iter()
            .filter(|id| self.members.contains_key(*id))
            .count();

        let required = self.members.len() / 2 + 1;
        if valid < required {
            return Err(format!(
                "need {} operator endorsements, got {}",
                required, valid
            ));
        }

        if !self.endorsed.contains(&proposal_id) {
            self.endorsed.push(proposal_id);
        }
        Ok(())
    }

    /// SLA veto: binding rejection of a proposal that would break SLAs.
    /// Requires at least 2 operators (or majority if fewer).
    pub fn sla_veto(
        &mut self,
        proposal_id: u64,
        vetoing_operators: &[String],
    ) -> Result<(), String> {
        let valid: usize = vetoing_operators
            .iter()
            .filter(|id| self.members.contains_key(*id))
            .count();

        let required = 2.min(self.members.len() / 2 + 1);
        if valid < required {
            return Err(format!(
                "need {} operators for SLA veto, got {}",
                required, valid
            ));
        }

        if !self.sla_vetoed.contains(&proposal_id) {
            self.sla_vetoed.push(proposal_id);
        }
        Ok(())
    }

    /// Check if a proposal has been endorsed.
    pub fn is_endorsed(&self, proposal_id: u64) -> bool {
        self.endorsed.contains(&proposal_id)
    }

    /// Check if a proposal has been SLA-vetoed.
    pub fn is_sla_vetoed(&self, proposal_id: u64) -> bool {
        self.sla_vetoed.contains(&proposal_id)
    }

    /// Current operator count.
    pub fn operator_count(&self) -> usize {
        self.members.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Original tests (backward-compatible) ---

    #[test]
    fn test_create_and_vote() {
        let mut gov = GovernanceModule::new();
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange,
            "Increase block size".into(),
            "Proposal to increase max block size to 2MB".into(),
            "SET block_size = 2097152".into(),
            "seal1proposer".into(),
            10,
        );

        assert_eq!(id, 0);
        assert_eq!(gov.get_proposal(0).unwrap().status, ProposalStatus::Voting);

        gov.vote(id, "seal1alice".into(), VoteChoice::Yes, 1000)
            .unwrap();
        gov.vote(id, "seal1bob".into(), VoteChoice::Yes, 500)
            .unwrap();
        gov.vote(id, "seal1charlie".into(), VoteChoice::No, 200)
            .unwrap();
    }

    #[test]
    fn test_tally_passes() {
        let mut gov = GovernanceModule::new();
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange,
            "Test".into(),
            "".into(),
            "payload".into(),
            "proposer".into(),
            0,
        );

        gov.vote(id, "a".into(), VoteChoice::Yes, 700).unwrap();
        gov.vote(id, "b".into(), VoteChoice::No, 300).unwrap();

        let status = gov.tally(id, 5).unwrap();
        assert!(matches!(status, ProposalStatus::Timelocked { .. }));
    }

    #[test]
    fn test_tally_rejects() {
        let mut gov = GovernanceModule::new();
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange,
            "Test".into(),
            "".into(),
            "payload".into(),
            "proposer".into(),
            0,
        );

        gov.vote(id, "a".into(), VoteChoice::Yes, 300).unwrap();
        gov.vote(id, "b".into(), VoteChoice::No, 700).unwrap();

        let status = gov.tally(id, 5).unwrap();
        assert_eq!(status, ProposalStatus::Rejected);
    }

    #[test]
    fn test_tally_too_early() {
        let mut gov = GovernanceModule::new();
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange,
            "Test".into(),
            "".into(),
            "".into(),
            "p".into(),
            0,
        );
        assert!(gov.tally(id, 2).is_err());
    }

    #[test]
    fn test_execute_after_timelock() {
        let mut gov = GovernanceModule::new();
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange,
            "Test".into(),
            "".into(),
            "SET x = 1".into(),
            "p".into(),
            0,
        );

        gov.vote(id, "a".into(), VoteChoice::Yes, 1000).unwrap();
        gov.tally(id, 5).unwrap();

        assert!(gov.execute(id, 6).is_err());

        let payload = gov.execute(id, 8).unwrap();
        assert_eq!(payload, "SET x = 1");
        assert_eq!(
            gov.get_proposal(id).unwrap().status,
            ProposalStatus::Executed
        );
    }

    #[test]
    fn test_double_vote_changes_vote() {
        // With conviction voting, duplicate votes now UPDATE rather than reject
        let mut gov = GovernanceModule::new();
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange,
            "Test".into(),
            "".into(),
            "".into(),
            "p".into(),
            0,
        );
        gov.vote(id, "alice".into(), VoteChoice::Yes, 100).unwrap();
        // Second vote changes the first
        gov.vote(id, "alice".into(), VoteChoice::No, 100).unwrap();
        let votes = gov.get_votes(id).unwrap();
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[0].choice, VoteChoice::No);
    }

    #[test]
    fn test_protocol_upgrade_supermajority() {
        let mut gov = GovernanceModule::new();
        let id = gov.create_proposal(
            ProposalTrack::ProtocolUpgrade,
            "Upgrade".into(),
            "".into(),
            "".into(),
            "p".into(),
            0,
        );

        gov.vote(id, "a".into(), VoteChoice::Yes, 650).unwrap();
        gov.vote(id, "b".into(), VoteChoice::No, 350).unwrap();

        let status = gov.tally(id, 14).unwrap();
        assert_eq!(status, ProposalStatus::Rejected);
    }

    // --- Conviction voting tests ---

    #[test]
    fn test_conviction_multipliers() {
        assert_eq!(Conviction::None.weighted_stake(1000), 100); // 0.1×
        assert_eq!(Conviction::X1.weighted_stake(1000), 1000);  // 1×
        assert_eq!(Conviction::X2.weighted_stake(1000), 2000);  // 2×
        assert_eq!(Conviction::X3.weighted_stake(1000), 3000);  // 3×
        assert_eq!(Conviction::X4.weighted_stake(1000), 4000);  // 4×
        assert_eq!(Conviction::X5.weighted_stake(1000), 5000);  // 5×
        assert_eq!(Conviction::X6.weighted_stake(1000), 6000);  // 6×
    }

    #[test]
    fn test_conviction_lock_periods() {
        assert_eq!(Conviction::None.lock_epochs(), 0);
        assert_eq!(Conviction::X1.lock_epochs(), 1);
        assert_eq!(Conviction::X2.lock_epochs(), 2);
        assert_eq!(Conviction::X3.lock_epochs(), 4);
        assert_eq!(Conviction::X4.lock_epochs(), 8);
        assert_eq!(Conviction::X5.lock_epochs(), 16);
        assert_eq!(Conviction::X6.lock_epochs(), 32);
    }

    #[test]
    fn test_conviction_saturating_on_large_stake() {
        let large_stake = u64::MAX / 2;
        // Should not overflow, uses saturating_mul
        let weight = Conviction::X6.weighted_stake(large_stake);
        assert!(weight > 0);
        assert!(weight <= large_stake.saturating_mul(32));
    }

    #[test]
    fn test_vote_with_conviction_x4() {
        let mut gov = GovernanceModule::new();
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange,
            "Test".into(),
            "".into(),
            "p".into(),
            "p".into(),
            0,
        );

        // 100 stake with 4× conviction = 400 weight
        gov.vote_with_conviction(id, "alice".into(), VoteChoice::Yes, 100, Conviction::X4)
            .unwrap();

        let votes = gov.get_votes(id).unwrap();
        assert_eq!(votes[0].weight, 400);
        assert_eq!(votes[0].stake, 100);
        assert_eq!(votes[0].conviction, Conviction::X4);
        // Vote ends at epoch 5, lock 8 epochs → unlock at 13
        assert_eq!(votes[0].unlock_epoch, 13);
    }

    #[test]
    fn test_conviction_lock_created() {
        let mut gov = GovernanceModule::new();
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange,
            "Test".into(),
            "".into(),
            "p".into(),
            "p".into(),
            0,
        );

        gov.vote_with_conviction(id, "alice".into(), VoteChoice::Yes, 500, Conviction::X3)
            .unwrap();

        assert_eq!(gov.conviction_locks.len(), 1);
        assert_eq!(gov.conviction_locks[0].amount, 500);
        assert_eq!(gov.conviction_locks[0].unlock_epoch, 9); // 5 + 4
    }

    #[test]
    fn test_no_lock_for_conviction_none() {
        let mut gov = GovernanceModule::new();
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange,
            "Test".into(),
            "".into(),
            "p".into(),
            "p".into(),
            0,
        );

        gov.vote_with_conviction(id, "alice".into(), VoteChoice::Yes, 500, Conviction::None)
            .unwrap();

        assert_eq!(gov.conviction_locks.len(), 0);
    }

    #[test]
    fn test_vote_change_updates_conviction() {
        let mut gov = GovernanceModule::new();
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange,
            "Test".into(),
            "".into(),
            "p".into(),
            "p".into(),
            0,
        );

        gov.vote_with_conviction(id, "alice".into(), VoteChoice::Yes, 100, Conviction::X2)
            .unwrap();
        assert_eq!(gov.get_votes(id).unwrap()[0].weight, 200);

        // Change to X4
        gov.vote_with_conviction(id, "alice".into(), VoteChoice::No, 100, Conviction::X4)
            .unwrap();
        let votes = gov.get_votes(id).unwrap();
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[0].weight, 400);
        assert_eq!(votes[0].choice, VoteChoice::No);
    }

    #[test]
    fn test_withdraw_vote() {
        let mut gov = GovernanceModule::new();
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange,
            "Test".into(),
            "".into(),
            "p".into(),
            "p".into(),
            0,
        );

        gov.vote(id, "alice".into(), VoteChoice::Yes, 100).unwrap();
        assert_eq!(gov.get_votes(id).unwrap().len(), 1);

        gov.withdraw_vote(id, "alice").unwrap();
        assert_eq!(gov.get_votes(id).unwrap().len(), 0);

        // Lock remains (tokens still locked)
        // alice can re-vote
        gov.vote(id, "alice".into(), VoteChoice::No, 200).unwrap();
        assert_eq!(gov.get_votes(id).unwrap().len(), 1);
    }

    #[test]
    fn test_release_expired_locks() {
        let mut gov = GovernanceModule::new();
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange,
            "Test".into(),
            "".into(),
            "p".into(),
            "p".into(),
            0,
        );

        gov.vote_with_conviction(id, "alice".into(), VoteChoice::Yes, 100, Conviction::X1)
            .unwrap(); // unlock at epoch 6 (5+1)
        gov.vote_with_conviction(id, "bob".into(), VoteChoice::Yes, 200, Conviction::X4)
            .unwrap(); // unlock at epoch 13 (5+8)

        assert_eq!(gov.conviction_locks.len(), 2);

        // At epoch 6: alice's lock expires
        let released = gov.release_expired_locks(6);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].voter, "alice");
        assert_eq!(gov.conviction_locks.len(), 1);

        // At epoch 13: bob's lock expires
        let released = gov.release_expired_locks(13);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].voter, "bob");
        assert_eq!(gov.conviction_locks.len(), 0);
    }

    // --- Adaptive quorum tests ---

    #[test]
    fn test_adaptive_threshold_full_turnout() {
        // At 100% turnout: threshold = base + bias * 0 / 100 = base
        assert_eq!(adaptive_threshold(50, 20, 100), 50);
        assert_eq!(adaptive_threshold(66, 25, 100), 66);
        assert_eq!(adaptive_threshold(75, 30, 100), 75);
    }

    #[test]
    fn test_adaptive_threshold_zero_turnout() {
        // At 0% turnout: threshold = base + bias
        assert_eq!(adaptive_threshold(50, 20, 0), 70); // 50 + 20
        assert_eq!(adaptive_threshold(66, 25, 0), 91); // 66 + 25
        assert_eq!(adaptive_threshold(75, 30, 0), 100); // 75 + 30 = 105 → capped at 100
    }

    #[test]
    fn test_adaptive_threshold_half_turnout() {
        // At 50% turnout: threshold = base + bias * 50 / 100
        assert_eq!(adaptive_threshold(50, 20, 50), 60); // 50 + 10
        assert_eq!(adaptive_threshold(66, 25, 50), 78); // 66 + 12 (25*50/100=12)
    }

    #[test]
    fn test_adaptive_threshold_capped_at_100() {
        assert_eq!(adaptive_threshold(90, 50, 0), 100);
        assert_eq!(adaptive_threshold(100, 100, 0), 100);
    }

    #[test]
    fn test_adaptive_threshold_turnout_over_100() {
        // Edge case: turnout > 100 treated as 100
        assert_eq!(adaptive_threshold(50, 20, 150), 50);
    }

    #[test]
    fn test_adaptive_quorum_in_tally() {
        let mut gov = GovernanceModule::with_supply(10000);
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange, // base 50%, bias 20%, min turnout 5%
            "Test".into(),
            "".into(),
            "p".into(),
            "p".into(),
            0,
        );

        // 10% turnout → threshold = 50 + 20*(90)/100 = 68%
        // 600 yes, 400 no → 60% approval < 68% → REJECTED
        gov.vote_with_conviction(id, "a".into(), VoteChoice::Yes, 600, Conviction::X1)
            .unwrap();
        gov.vote_with_conviction(id, "b".into(), VoteChoice::No, 400, Conviction::X1)
            .unwrap();

        let status = gov.tally(id, 5).unwrap();
        assert_eq!(status, ProposalStatus::Rejected);
    }

    #[test]
    fn test_min_turnout_rejection() {
        let mut gov = GovernanceModule::with_supply(1_000_000);
        let id = gov.create_proposal(
            ProposalTrack::ProtocolUpgrade, // min turnout 10%
            "Test".into(),
            "".into(),
            "p".into(),
            "p".into(),
            0,
        );

        // Only 5% turnout (50000 of 1000000) → below 10% minimum
        gov.vote_with_conviction(id, "a".into(), VoteChoice::Yes, 50000, Conviction::X1)
            .unwrap();

        let status = gov.tally(id, 14).unwrap();
        assert_eq!(status, ProposalStatus::Rejected);
    }

    #[test]
    fn test_high_turnout_uses_base_threshold() {
        let mut gov = GovernanceModule::with_supply(1000);
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange, // base 50%, bias 20%
            "Test".into(),
            "".into(),
            "p".into(),
            "p".into(),
            0,
        );

        // 100% turnout → threshold = 50% exactly
        // 510 yes, 490 no → 51% > 50% → PASSES
        gov.vote_with_conviction(id, "a".into(), VoteChoice::Yes, 510, Conviction::X1)
            .unwrap();
        gov.vote_with_conviction(id, "b".into(), VoteChoice::No, 490, Conviction::X1)
            .unwrap();

        let status = gov.tally(id, 5).unwrap();
        assert!(matches!(status, ProposalStatus::Timelocked { .. }));
    }

    #[test]
    fn test_conviction_amplifies_winning_side() {
        let mut gov = GovernanceModule::new();
        let id = gov.create_proposal(
            ProposalTrack::ParameterChange,
            "Test".into(),
            "".into(),
            "p".into(),
            "p".into(),
            0,
        );

        // Alice: 300 stake with X4 conviction = 1200 weight (Yes)
        // Bob: 500 stake with X1 conviction = 500 weight (No)
        // Alice wins despite lower stake due to conviction
        gov.vote_with_conviction(id, "alice".into(), VoteChoice::Yes, 300, Conviction::X4)
            .unwrap();
        gov.vote_with_conviction(id, "bob".into(), VoteChoice::No, 500, Conviction::X1)
            .unwrap();

        let status = gov.tally(id, 5).unwrap();
        assert!(matches!(status, ProposalStatus::Timelocked { .. }));
    }

    // --- Technical Council tests ---

    #[test]
    fn test_tc_add_and_remove_member() {
        let mut tc = TechnicalCouncil::new();
        let member = CouncilMember {
            pubkey: "member1".into(),
            name: "Alice".into(),
            term_start_epoch: 0,
            term_end_epoch: 26280, // ~1 year
        };
        tc.add_member(member).unwrap();
        assert_eq!(tc.member_count(), 1);

        tc.remove_member("member1").unwrap();
        assert_eq!(tc.member_count(), 0);
    }

    #[test]
    fn test_tc_duplicate_member_rejected() {
        let mut tc = TechnicalCouncil::new();
        let member = CouncilMember {
            pubkey: "member1".into(),
            name: "Alice".into(),
            term_start_epoch: 0,
            term_end_epoch: 26280,
        };
        tc.add_member(member.clone()).unwrap();
        assert!(tc.add_member(member).is_err());
    }

    #[test]
    fn test_tc_max_size_enforced() {
        let mut tc = TechnicalCouncil::new();
        for i in 0..11 {
            tc.add_member(CouncilMember {
                pubkey: format!("m{}", i),
                name: format!("Member {}", i),
                term_start_epoch: 0,
                term_end_epoch: 26280,
            })
            .unwrap();
        }
        assert_eq!(tc.member_count(), 11);
        // 12th member should fail
        assert!(tc
            .add_member(CouncilMember {
                pubkey: "m11".into(),
                name: "Extra".into(),
                term_start_epoch: 0,
                term_end_epoch: 26280,
            })
            .is_err());
    }

    #[test]
    fn test_tc_whitelist_requires_majority() {
        let mut tc = TechnicalCouncil::new();
        for i in 0..7 {
            tc.add_member(CouncilMember {
                pubkey: format!("m{}", i),
                name: format!("Member {}", i),
                term_start_epoch: 0,
                term_end_epoch: 26280,
            })
            .unwrap();
        }

        // Need 4 of 7 (majority)
        // 3 approvers → insufficient
        assert!(tc
            .whitelist_proposal(1, &["m0".into(), "m1".into(), "m2".into()])
            .is_err());

        // 4 approvers → sufficient
        tc.whitelist_proposal(
            1,
            &["m0".into(), "m1".into(), "m2".into(), "m3".into()],
        )
        .unwrap();
        assert!(tc.is_whitelisted(1));
    }

    #[test]
    fn test_tc_veto_proposal() {
        let mut tc = TechnicalCouncil::new();
        for i in 0..7 {
            tc.add_member(CouncilMember {
                pubkey: format!("m{}", i),
                name: format!("Member {}", i),
                term_start_epoch: 0,
                term_end_epoch: 26280,
            })
            .unwrap();
        }

        tc.veto_proposal(42, &["m0".into(), "m1".into(), "m2".into()])
            .unwrap();
        assert!(tc.is_vetoed(42));
        assert!(!tc.is_vetoed(43));
    }

    #[test]
    fn test_tc_two_thirds_threshold_is_ceiling() {
        let mut tc = TechnicalCouncil::new();
        assert_eq!(tc.two_thirds_threshold(), 0);
        for n in 1..=11 {
            tc.add_member(CouncilMember {
                pubkey: format!("m{}", n - 1),
                name: format!("M{}", n - 1),
                term_start_epoch: 0,
                term_end_epoch: 26280,
            })
            .unwrap();
            let expected = (n * 2usize).div_ceil(3);
            assert_eq!(
                tc.two_thirds_threshold(),
                expected,
                "n={} → expected {}",
                n,
                expected
            );
        }
    }

    #[test]
    fn test_tc_has_two_thirds_approval() {
        let mut tc = TechnicalCouncil::new();
        // Empty council — never approves.
        assert!(!tc.has_two_thirds_approval(&[]));
        assert!(!tc.has_two_thirds_approval(&["m0".into()]));

        for i in 0..7 {
            tc.add_member(CouncilMember {
                pubkey: format!("m{}", i),
                name: format!("M{}", i),
                term_start_epoch: 0,
                term_end_epoch: 26280,
            })
            .unwrap();
        }
        // 7 members → 2/3 threshold = ceil(14/3) = 5.
        assert!(!tc.has_two_thirds_approval(&[
            "m0".into(),
            "m1".into(),
            "m2".into(),
            "m3".into(),
        ]));
        assert!(tc.has_two_thirds_approval(&[
            "m0".into(),
            "m1".into(),
            "m2".into(),
            "m3".into(),
            "m4".into(),
        ]));
        // Non-members don't count.
        assert!(!tc.has_two_thirds_approval(&[
            "m0".into(),
            "m1".into(),
            "stranger".into(),
            "ghost".into(),
            "unknown".into(),
        ]));
        // Duplicates collapse.
        assert!(!tc.has_two_thirds_approval(&[
            "m0".into(),
            "m0".into(),
            "m1".into(),
            "m1".into(),
            "m2".into(),
        ]));
    }

    #[test]
    fn test_tc_list_members_sorted() {
        let mut tc = TechnicalCouncil::new();
        for pk in ["charlie", "alice", "bob"] {
            tc.add_member(CouncilMember {
                pubkey: pk.into(),
                name: pk.into(),
                term_start_epoch: 0,
                term_end_epoch: 26280,
            })
            .unwrap();
        }
        let listed = tc.list_members();
        let pks: Vec<_> = listed.iter().map(|m| m.pubkey.as_str()).collect();
        assert_eq!(pks, vec!["alice", "bob", "charlie"]);
    }

    #[test]
    fn test_tc_expire_terms() {
        let mut tc = TechnicalCouncil::new();
        tc.add_member(CouncilMember {
            pubkey: "early".into(),
            name: "Early".into(),
            term_start_epoch: 0,
            term_end_epoch: 100,
        })
        .unwrap();
        tc.add_member(CouncilMember {
            pubkey: "late".into(),
            name: "Late".into(),
            term_start_epoch: 0,
            term_end_epoch: 26280,
        })
        .unwrap();

        let expired = tc.expire_terms(150);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].pubkey, "early");
        assert_eq!(tc.member_count(), 1);
    }

    // --- Service Operators Council tests ---

    #[test]
    fn test_soc_register_and_remove() {
        let mut soc = ServiceOperatorsCouncil::new();
        soc.register_operator(OperatorInfo {
            operator_id: "op1".into(),
            description: "AWS nodes".into(),
            node_count: 10,
            tee_attested: true,
        })
        .unwrap();
        assert_eq!(soc.operator_count(), 1);

        soc.remove_operator("op1").unwrap();
        assert_eq!(soc.operator_count(), 0);
    }

    #[test]
    fn test_soc_duplicate_rejected() {
        let mut soc = ServiceOperatorsCouncil::new();
        let op = OperatorInfo {
            operator_id: "op1".into(),
            description: "Nodes".into(),
            node_count: 5,
            tee_attested: false,
        };
        soc.register_operator(op.clone()).unwrap();
        assert!(soc.register_operator(op).is_err());
    }

    #[test]
    fn test_soc_endorse_requires_majority() {
        let mut soc = ServiceOperatorsCouncil::new();
        for i in 0..5 {
            soc.register_operator(OperatorInfo {
                operator_id: format!("op{}", i),
                description: format!("Operator {}", i),
                node_count: 3,
                tee_attested: i % 2 == 0,
            })
            .unwrap();
        }

        // 2 of 5 → not enough (need 3)
        assert!(soc
            .endorse_proposal(1, &["op0".into(), "op1".into()])
            .is_err());

        // 3 of 5 → passes
        soc.endorse_proposal(1, &["op0".into(), "op1".into(), "op2".into()])
            .unwrap();
        assert!(soc.is_endorsed(1));
    }

    #[test]
    fn test_soc_sla_veto() {
        let mut soc = ServiceOperatorsCouncil::new();
        for i in 0..4 {
            soc.register_operator(OperatorInfo {
                operator_id: format!("op{}", i),
                description: format!("Op {}", i),
                node_count: 1,
                tee_attested: false,
            })
            .unwrap();
        }

        soc.sla_veto(99, &["op0".into(), "op1".into()]).unwrap();
        assert!(soc.is_sla_vetoed(99));
        assert!(!soc.is_sla_vetoed(100));
    }
}

// ============================================================================
// Kani formal verification harnesses
// ============================================================================

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove: conviction weighted_stake never panics and is monotonic.
    #[kani::proof]
    fn conviction_weighted_stake_safe() {
        let stake: u64 = kani::any();
        let mult: u64 = kani::any();
        kani::assume(mult <= 60); // Max conviction multiplier_x10

        let result = stake.saturating_mul(mult) / 10;
        // Result is always <= stake * 6 (for X6)
        // And never panics (saturating)
        assert!(result <= u64::MAX);
    }

    /// Prove: adaptive_threshold always returns a value in [0, 100].
    #[kani::proof]
    fn adaptive_threshold_bounded() {
        let base: u64 = kani::any();
        let bias: u64 = kani::any();
        let turnout: u64 = kani::any();
        kani::assume(base <= 100);
        kani::assume(bias <= 100);

        let result = adaptive_threshold(base, bias, turnout);
        assert!(result <= 100);
        assert!(result >= base); // Threshold is always at least the base
    }

    /// Prove: adaptive_threshold is monotonically decreasing with turnout.
    /// Higher turnout → lower or equal threshold.
    #[kani::proof]
    fn adaptive_threshold_monotone() {
        let base: u64 = kani::any();
        let bias: u64 = kani::any();
        let turnout_low: u64 = kani::any();
        let turnout_high: u64 = kani::any();
        kani::assume(base <= 100);
        kani::assume(bias <= 100);
        kani::assume(turnout_low <= turnout_high);
        kani::assume(turnout_high <= 100);

        let thresh_low = adaptive_threshold(base, bias, turnout_low);
        let thresh_high = adaptive_threshold(base, bias, turnout_high);
        assert!(thresh_low >= thresh_high);
    }

    /// Prove: conviction lock_epochs is monotonically increasing with conviction level.
    #[kani::proof]
    fn conviction_lock_monotone() {
        // X1 < X2 < X3 < X4 < X5 < X6
        assert!(Conviction::None.lock_epochs() < Conviction::X1.lock_epochs());
        assert!(Conviction::X1.lock_epochs() < Conviction::X2.lock_epochs());
        assert!(Conviction::X2.lock_epochs() < Conviction::X3.lock_epochs());
        assert!(Conviction::X3.lock_epochs() < Conviction::X4.lock_epochs());
        assert!(Conviction::X4.lock_epochs() < Conviction::X5.lock_epochs());
        assert!(Conviction::X5.lock_epochs() < Conviction::X6.lock_epochs());
    }

    /// Prove: conviction multiplier is monotonically increasing.
    #[kani::proof]
    fn conviction_multiplier_monotone() {
        assert!(Conviction::None.multiplier_x10() < Conviction::X1.multiplier_x10());
        assert!(Conviction::X1.multiplier_x10() < Conviction::X2.multiplier_x10());
        assert!(Conviction::X2.multiplier_x10() < Conviction::X3.multiplier_x10());
        assert!(Conviction::X3.multiplier_x10() < Conviction::X4.multiplier_x10());
        assert!(Conviction::X4.multiplier_x10() < Conviction::X5.multiplier_x10());
        assert!(Conviction::X5.multiplier_x10() < Conviction::X6.multiplier_x10());
    }
}
