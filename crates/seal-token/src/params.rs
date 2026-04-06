//! Finalized token economics parameters (SPEC.md §16, GOVERNANCE.md §3).
//!
//! All monetary constants for the Seal network.
//! These are the authoritative values — other modules should reference these.

/// Denomination: 1 SEAL = 10^9 micro-SEAL.
pub const MICRO_SEAL_PER_SEAL: u64 = 1_000_000_000;

/// Initial supply at genesis: 1 billion SEAL.
pub const INITIAL_SUPPLY_SEAL: u64 = 1_000_000_000;

/// Initial supply in micro-SEAL (10^18).
pub const INITIAL_SUPPLY: u64 = INITIAL_SUPPLY_SEAL * MICRO_SEAL_PER_SEAL;

/// Maximum supply cap: 10 billion SEAL (10^19 micro-SEAL).
/// Emission stops when this cap is reached.
pub const MAX_SUPPLY_SEAL: u64 = 10_000_000_000;

/// Maximum supply in micro-SEAL.
pub const MAX_SUPPLY: u64 = MAX_SUPPLY_SEAL * MICRO_SEAL_PER_SEAL;

/// Minimum validator stake: 1,000 SEAL.
pub const VALIDATOR_MIN_STAKE_SEAL: u64 = 1_000;

/// Minimum validator stake in micro-SEAL (10^12).
pub const VALIDATOR_MIN_STAKE: u64 = VALIDATOR_MIN_STAKE_SEAL * MICRO_SEAL_PER_SEAL;

/// Proposal deposit: 100 SEAL (burned if proposal is vetoed).
pub const PROPOSAL_DEPOSIT_SEAL: u64 = 100;

/// Proposal deposit in micro-SEAL.
pub const PROPOSAL_DEPOSIT: u64 = PROPOSAL_DEPOSIT_SEAL * MICRO_SEAL_PER_SEAL;

/// Treasury allocation: 10% of each epoch's emission goes to treasury.
pub const TREASURY_ALLOCATION_PERCENT: u64 = 10;

/// Per-delegate cap: max 4% of circulating supply delegated to one delegate.
pub const MAX_DELEGATE_CAP_PERCENT: u64 = 4;

/// Maximum base fee per byte (ceiling for EIP-1559 adjustment).
pub const MAX_BASE_FEE: u64 = 10_000; // micro-SEAL per byte

/// Minimum base fee per byte (floor).
pub const MIN_BASE_FEE: u64 = 1;

/// Default burn percentage of transaction fees.
pub const DEFAULT_BURN_PERCENT: u64 = 50;

/// Genesis allocations.
/// Percentages are applied to INITIAL_SUPPLY_SEAL first, then scaled to micro-SEAL.
pub mod genesis {
    use super::*;

    /// Validator staking pool: 30% of initial supply.
    pub const VALIDATOR_POOL_PERCENT: u64 = 30;
    pub const VALIDATOR_POOL: u64 =
        (INITIAL_SUPPLY_SEAL * VALIDATOR_POOL_PERCENT / 100) * MICRO_SEAL_PER_SEAL;

    /// Community treasury: 20% of initial supply.
    pub const COMMUNITY_TREASURY_PERCENT: u64 = 20;
    pub const COMMUNITY_TREASURY: u64 =
        (INITIAL_SUPPLY_SEAL * COMMUNITY_TREASURY_PERCENT / 100) * MICRO_SEAL_PER_SEAL;

    /// Core team (4-year vest, 6-month cliff): 15% of initial supply.
    pub const TEAM_PERCENT: u64 = 15;
    pub const TEAM_ALLOCATION: u64 =
        (INITIAL_SUPPLY_SEAL * TEAM_PERCENT / 100) * MICRO_SEAL_PER_SEAL;

    /// Ecosystem fund: 15% of initial supply.
    pub const ECOSYSTEM_PERCENT: u64 = 15;
    pub const ECOSYSTEM_FUND: u64 =
        (INITIAL_SUPPLY_SEAL * ECOSYSTEM_PERCENT / 100) * MICRO_SEAL_PER_SEAL;

    /// Public distribution (testnet rewards, airdrops): 10% of initial supply.
    pub const PUBLIC_PERCENT: u64 = 10;
    pub const PUBLIC_DISTRIBUTION: u64 =
        (INITIAL_SUPPLY_SEAL * PUBLIC_PERCENT / 100) * MICRO_SEAL_PER_SEAL;

    /// Reserve (emergency, future use): 10% of initial supply.
    pub const RESERVE_PERCENT: u64 = 10;
    pub const RESERVE: u64 =
        (INITIAL_SUPPLY_SEAL * RESERVE_PERCENT / 100) * MICRO_SEAL_PER_SEAL;
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove: genesis allocations sum to exactly INITIAL_SUPPLY (no tokens lost or created).
    #[kani::proof]
    fn genesis_allocations_sum_to_initial_supply() {
        let total = genesis::VALIDATOR_POOL
            + genesis::COMMUNITY_TREASURY
            + genesis::TEAM_ALLOCATION
            + genesis::ECOSYSTEM_FUND
            + genesis::PUBLIC_DISTRIBUTION
            + genesis::RESERVE;
        assert_eq!(total, INITIAL_SUPPLY);
    }

    /// Prove: percentage allocations sum to 100%.
    #[kani::proof]
    fn genesis_percentages_sum_to_100() {
        let total = genesis::VALIDATOR_POOL_PERCENT
            + genesis::COMMUNITY_TREASURY_PERCENT
            + genesis::TEAM_PERCENT
            + genesis::ECOSYSTEM_PERCENT
            + genesis::PUBLIC_PERCENT
            + genesis::RESERVE_PERCENT;
        assert_eq!(total, 100);
    }

    /// Prove: INITIAL_SUPPLY < MAX_SUPPLY.
    #[kani::proof]
    fn initial_less_than_max() {
        assert!(INITIAL_SUPPLY < MAX_SUPPLY);
    }

    /// Prove: VALIDATOR_MIN_STAKE > 0 and < INITIAL_SUPPLY.
    #[kani::proof]
    fn validator_min_stake_reasonable() {
        assert!(VALIDATOR_MIN_STAKE > 0);
        assert!(VALIDATOR_MIN_STAKE < INITIAL_SUPPLY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_denomination() {
        assert_eq!(MICRO_SEAL_PER_SEAL, 1_000_000_000);
        assert_eq!(1 * MICRO_SEAL_PER_SEAL, 1_000_000_000); // 1 SEAL
    }

    #[test]
    fn test_initial_supply() {
        assert_eq!(INITIAL_SUPPLY, 1_000_000_000_000_000_000);
        assert_eq!(INITIAL_SUPPLY_SEAL, 1_000_000_000);
    }

    #[test]
    fn test_max_supply() {
        assert_eq!(MAX_SUPPLY, 10_000_000_000_000_000_000);
        assert!(MAX_SUPPLY > INITIAL_SUPPLY);
    }

    #[test]
    fn test_validator_min_stake() {
        assert_eq!(VALIDATOR_MIN_STAKE, 1_000_000_000_000); // 1000 SEAL in micro
        assert_eq!(VALIDATOR_MIN_STAKE_SEAL, 1_000);
    }

    #[test]
    fn test_genesis_allocations_sum() {
        let total = genesis::VALIDATOR_POOL
            + genesis::COMMUNITY_TREASURY
            + genesis::TEAM_ALLOCATION
            + genesis::ECOSYSTEM_FUND
            + genesis::PUBLIC_DISTRIBUTION
            + genesis::RESERVE;
        assert_eq!(total, INITIAL_SUPPLY, "genesis allocations must sum to initial supply");
    }

    #[test]
    fn test_genesis_percentages() {
        let total = genesis::VALIDATOR_POOL_PERCENT
            + genesis::COMMUNITY_TREASURY_PERCENT
            + genesis::TEAM_PERCENT
            + genesis::ECOSYSTEM_PERCENT
            + genesis::PUBLIC_PERCENT
            + genesis::RESERVE_PERCENT;
        assert_eq!(total, 100);
    }

    #[test]
    fn test_individual_allocations() {
        assert_eq!(genesis::VALIDATOR_POOL, 300_000_000_000_000_000); // 30%
        assert_eq!(genesis::COMMUNITY_TREASURY, 200_000_000_000_000_000); // 20%
        assert_eq!(genesis::TEAM_ALLOCATION, 150_000_000_000_000_000); // 15%
        assert_eq!(genesis::ECOSYSTEM_FUND, 150_000_000_000_000_000); // 15%
        assert_eq!(genesis::PUBLIC_DISTRIBUTION, 100_000_000_000_000_000); // 10%
        assert_eq!(genesis::RESERVE, 100_000_000_000_000_000); // 10%
    }
}
