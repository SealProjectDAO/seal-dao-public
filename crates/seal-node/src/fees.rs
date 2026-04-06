//! Transaction fee calculation and distribution.
//!
//! Fee model (SPEC.md §10.2, §10.4):
//! - Each SQL write transaction has a fee proportional to payload size
//! - 50% of base fee is burned (deflationary pressure)
//! - 50% goes to the block proposer
//! - SELECTs are free (no on-chain cost)

use seal_token::balance::BalanceStore;
use seal_token::error::TokenError;

/// Fee parameters with EIP-1559-style dynamic base fee adjustment.
pub struct FeeConfig {
    /// Base fee per byte of transaction payload (in micro-SEAL).
    pub base_fee_per_byte: u64,
    /// Fraction of fee to burn (0-100, representing percentage).
    pub burn_percent: u64,
    /// Target block utilization percentage (0-100). Default: 50%.
    pub target_block_utilization: u64,
    /// Maximum base fee change per block in percent (0-100). Default: 12 (~12.5%).
    pub max_fee_change_percent: u64,
    /// Minimum base fee per byte (floor).
    pub min_base_fee: u64,
    /// Maximum base fee per byte (ceiling).
    pub max_base_fee: u64,
}

impl Default for FeeConfig {
    fn default() -> Self {
        FeeConfig {
            base_fee_per_byte: 10, // 10 micro-SEAL per byte
            burn_percent: 50,      // 50% burned, 50% to proposer
            target_block_utilization: 50, // 50% target
            max_fee_change_percent: 12,   // max ~12.5% change per block
            min_base_fee: 1,              // floor: 1 micro-SEAL/byte
            max_base_fee: 10000,          // ceiling: 10000 micro-SEAL/byte
        }
    }
}

impl FeeConfig {
    /// Calculate the fee for a transaction.
    pub fn calculate_fee(&self, payload_size: usize) -> u64 {
        self.base_fee_per_byte.saturating_mul(payload_size as u64)
    }

    /// Calculate the burn amount from a fee.
    pub fn burn_amount(&self, fee: u64) -> u64 {
        fee.saturating_mul(self.burn_percent) / 100
    }

    /// Calculate the proposer reward from a fee.
    pub fn proposer_reward(&self, fee: u64) -> u64 {
        fee - self.burn_amount(fee)
    }

    /// Adjust the base fee based on block utilization (EIP-1559-style).
    ///
    /// If `block_utilization_percent` > target, increase base fee.
    /// If below target, decrease base fee.
    /// Change is capped by `max_fee_change_percent` and clamped to [min, max].
    pub fn adjust_base_fee(&mut self, block_utilization_percent: u64) {
        let utilization = block_utilization_percent.min(100);
        let target = self.target_block_utilization;

        if utilization > target {
            // Increase: proportional to how far above target
            // delta = base_fee * max_change% * (util - target) / (100 - target) / 100
            let excess = utilization.saturating_sub(target);
            let range = 100u64.saturating_sub(target).max(1);
            let max_increase = self
                .base_fee_per_byte
                .saturating_mul(self.max_fee_change_percent)
                / 100;
            let increase = max_increase.saturating_mul(excess) / range;
            // Ensure at least 1 micro-SEAL increase when above target
            let increase = increase.max(1);
            self.base_fee_per_byte = self.base_fee_per_byte.saturating_add(increase);
        } else if utilization < target {
            // Decrease: proportional to how far below target
            let deficit = target.saturating_sub(utilization);
            let range = target.max(1);
            let max_decrease = self
                .base_fee_per_byte
                .saturating_mul(self.max_fee_change_percent)
                / 100;
            let decrease = max_decrease.saturating_mul(deficit) / range;
            // Ensure at least 1 micro-SEAL decrease when below target
            let decrease = decrease.max(1);
            self.base_fee_per_byte = self.base_fee_per_byte.saturating_sub(decrease);
        }
        // utilization == target: no change

        // Clamp to [min, max]
        self.base_fee_per_byte = self.base_fee_per_byte.clamp(self.min_base_fee, self.max_base_fee);
    }
}

/// Process fees for a block's transactions.
/// Returns (total_fees, total_burned, proposer_reward).
///
/// If `emission_reward` is Some, the emission amount is minted to the proposer
/// in addition to their fee share.
pub fn process_block_fees(
    balances: &mut BalanceStore,
    fee_config: &FeeConfig,
    transactions: &[(String, usize)], // (sender_address, payload_size)
    proposer_address: &str,
) -> Result<(u64, u64, u64), TokenError> {
    process_block_fees_with_emission(balances, fee_config, transactions, proposer_address, None)
}

/// Process fees with an optional emission reward added to the proposer's take.
/// Returns (total_fees, total_burned, proposer_total_reward).
pub fn process_block_fees_with_emission(
    balances: &mut BalanceStore,
    fee_config: &FeeConfig,
    transactions: &[(String, usize)], // (sender_address, payload_size)
    proposer_address: &str,
    emission_reward: Option<u64>,
) -> Result<(u64, u64, u64), TokenError> {
    let mut total_fees = 0u64;
    let mut total_burned = 0u64;

    for (sender, payload_size) in transactions {
        let fee = fee_config.calculate_fee(*payload_size);
        if fee == 0 {
            continue;
        }

        // Deduct fee from sender
        balances.burn(sender, fee)?;
        total_fees = total_fees.saturating_add(fee);

        let burn = fee_config.burn_amount(fee);
        total_burned = total_burned.saturating_add(burn);
    }

    // Reward proposer with the non-burned portion + emission reward
    let fee_reward = total_fees.saturating_sub(total_burned);
    let emission = emission_reward.unwrap_or(0);
    let proposer_total = fee_reward.saturating_add(emission);

    if proposer_total > 0 {
        balances.mint(proposer_address, proposer_total)?;
    }

    Ok((total_fees, total_burned, proposer_total))
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove that burn_amount + proposer_reward == fee (no tokens lost).
    #[kani::proof]
    fn fee_split_conserves_total() {
        let config = FeeConfig::default();
        let fee: u64 = kani::any();
        kani::assume(fee < u64::MAX / 100); // avoid saturation edge cases
        let burned = config.burn_amount(fee);
        let reward = config.proposer_reward(fee);
        assert_eq!(burned + reward, fee, "burn + reward must equal total fee");
    }

    /// Prove that adjust_base_fee always produces a value in [min_base_fee, max_base_fee].
    #[kani::proof]
    fn base_fee_clamped_after_adjustment() {
        let mut config = FeeConfig::default();
        config.base_fee_per_byte = kani::any();
        let utilization: u64 = kani::any();
        kani::assume(utilization <= 100);
        config.adjust_base_fee(utilization);
        assert!(config.base_fee_per_byte >= config.min_base_fee);
        assert!(config.base_fee_per_byte <= config.max_base_fee);
    }

    /// Prove that calculate_fee never panics (uses saturating_mul).
    #[kani::proof]
    fn calculate_fee_no_panic() {
        let config = FeeConfig::default();
        let size: usize = kani::any();
        kani::assume(size < 10_000_000); // reasonable transaction size
        let fee = config.calculate_fee(size);
        assert!(fee <= config.base_fee_per_byte.saturating_mul(size as u64));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_calculation() {
        let config = FeeConfig::default();
        assert_eq!(config.calculate_fee(100), 1000); // 100 bytes × 10 = 1000
        assert_eq!(config.calculate_fee(0), 0);
    }

    #[test]
    fn test_burn_and_reward_split() {
        let config = FeeConfig::default();
        let fee = 1000;
        assert_eq!(config.burn_amount(fee), 500); // 50%
        assert_eq!(config.proposer_reward(fee), 500); // 50%
    }

    #[test]
    fn test_process_block_fees() {
        let mut balances = BalanceStore::new();
        balances.mint("alice", 10000).unwrap();
        balances.mint("bob", 10000).unwrap();
        let config = FeeConfig::default();

        let txs = vec![
            ("alice".to_string(), 50), // fee = 500
            ("bob".to_string(), 100),  // fee = 1000
        ];

        let (total, burned, reward) =
            process_block_fees(&mut balances, &config, &txs, "proposer").unwrap();

        assert_eq!(total, 1500);
        assert_eq!(burned, 750); // 50% of 1500
        assert_eq!(reward, 750); // 50% of 1500

        // Alice paid 500 (burned), Bob paid 1000 (burned)
        assert_eq!(balances.available("alice"), 9500);
        assert_eq!(balances.available("bob"), 9000);
        // Proposer received reward
        assert_eq!(balances.available("proposer"), 750);
    }

    #[test]
    fn test_fees_insufficient_balance() {
        let mut balances = BalanceStore::new();
        balances.mint("poor", 5).unwrap(); // Only 5 micro-SEAL
        let config = FeeConfig::default();

        let txs = vec![("poor".to_string(), 100)]; // fee = 1000, balance = 5

        assert!(process_block_fees(&mut balances, &config, &txs, "proposer").is_err());
    }

    #[test]
    fn test_fees_supply_conservation() {
        let mut balances = BalanceStore::new();
        balances.mint("alice", 100000).unwrap();
        balances.mint("bob", 100000).unwrap();
        let initial_supply = balances.total_supply();
        let config = FeeConfig::default();

        let txs = vec![("alice".to_string(), 100), ("bob".to_string(), 200)];

        let (total, _burned, reward) =
            process_block_fees(&mut balances, &config, &txs, "proposer").unwrap();

        // Supply should decrease by burned amount
        // total fees deducted via burn (decreases supply), reward minted (increases)
        // net: supply decreases by burned amount
        let expected_supply = initial_supply - total + reward;
        assert_eq!(balances.total_supply(), expected_supply);
    }

    // --- Dynamic fee adjustment tests ---

    #[test]
    fn test_adjust_base_fee_high_utilization() {
        let mut config = FeeConfig::default();
        let original = config.base_fee_per_byte;
        // 80% utilization > 50% target → fee should increase
        config.adjust_base_fee(80);
        assert!(
            config.base_fee_per_byte > original,
            "base fee should increase when utilization is above target"
        );
    }

    #[test]
    fn test_adjust_base_fee_low_utilization() {
        let mut config = FeeConfig::default();
        let original = config.base_fee_per_byte;
        // 20% utilization < 50% target → fee should decrease
        config.adjust_base_fee(20);
        assert!(
            config.base_fee_per_byte < original,
            "base fee should decrease when utilization is below target"
        );
    }

    #[test]
    fn test_adjust_base_fee_at_target() {
        let mut config = FeeConfig::default();
        let original = config.base_fee_per_byte;
        // Exactly at target → no change
        config.adjust_base_fee(50);
        assert_eq!(
            config.base_fee_per_byte, original,
            "base fee should not change when utilization equals target"
        );
    }

    #[test]
    fn test_adjust_base_fee_respects_min() {
        let mut config = FeeConfig {
            base_fee_per_byte: 1,
            min_base_fee: 1,
            ..Default::default()
        };
        // Repeated low utilization should not go below min
        for _ in 0..100 {
            config.adjust_base_fee(0);
        }
        assert_eq!(
            config.base_fee_per_byte, config.min_base_fee,
            "base fee should not go below min_base_fee"
        );
    }

    #[test]
    fn test_adjust_base_fee_respects_max() {
        let mut config = FeeConfig {
            base_fee_per_byte: 9990,
            max_base_fee: 10000,
            ..Default::default()
        };
        // Repeated high utilization should not exceed max
        for _ in 0..100 {
            config.adjust_base_fee(100);
        }
        assert!(
            config.base_fee_per_byte <= config.max_base_fee,
            "base fee should not exceed max_base_fee"
        );
    }

    #[test]
    fn test_adjust_base_fee_full_utilization_increase() {
        let mut config = FeeConfig::default();
        let original = config.base_fee_per_byte;
        // 100% utilization → maximum increase
        config.adjust_base_fee(100);
        let max_increase = original * config.max_fee_change_percent / 100;
        assert!(config.base_fee_per_byte <= original + max_increase + 1);
        assert!(config.base_fee_per_byte > original);
    }

    #[test]
    fn test_adjust_base_fee_zero_utilization_decrease() {
        let mut config = FeeConfig {
            base_fee_per_byte: 100,
            ..Default::default()
        };
        let original = config.base_fee_per_byte;
        // 0% utilization → maximum decrease
        config.adjust_base_fee(0);
        assert!(config.base_fee_per_byte < original);
    }

    // --- Emission reward in process_block_fees ---

    #[test]
    fn test_process_block_fees_with_emission_reward() {
        let mut balances = BalanceStore::new();
        balances.mint("alice", 10000).unwrap();
        let config = FeeConfig::default();

        let txs = vec![("alice".to_string(), 50)]; // fee = 500

        let (total, burned, reward) =
            process_block_fees_with_emission(&mut balances, &config, &txs, "proposer", Some(1000))
                .unwrap();

        assert_eq!(total, 500);
        assert_eq!(burned, 250);
        // proposer gets: fee_reward (250) + emission (1000) = 1250
        assert_eq!(reward, 1250);
        assert_eq!(balances.available("proposer"), 1250);
    }

    #[test]
    fn test_process_block_fees_with_no_emission() {
        let mut balances = BalanceStore::new();
        balances.mint("alice", 10000).unwrap();
        let config = FeeConfig::default();

        let txs = vec![("alice".to_string(), 50)]; // fee = 500

        let (total, burned, reward) =
            process_block_fees_with_emission(&mut balances, &config, &txs, "proposer", None)
                .unwrap();

        assert_eq!(total, 500);
        assert_eq!(burned, 250);
        assert_eq!(reward, 250);
    }

    #[test]
    fn test_process_block_fees_emission_only_no_txs() {
        let mut balances = BalanceStore::new();
        let config = FeeConfig::default();

        let txs: Vec<(String, usize)> = vec![];

        let (total, burned, reward) =
            process_block_fees_with_emission(&mut balances, &config, &txs, "proposer", Some(5000))
                .unwrap();

        assert_eq!(total, 0);
        assert_eq!(burned, 0);
        assert_eq!(reward, 5000);
        assert_eq!(balances.available("proposer"), 5000);
    }
}
