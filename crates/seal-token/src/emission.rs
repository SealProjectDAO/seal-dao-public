//! Token emission schedule (SPEC.md §16).
//!
//! Emission rates (annual, applied per-block):
//! - Year 0–4: linearly decreasing from 10% to 5%
//! - Year 4–8: linearly decreasing from 5% to 2%
//! - Year 8+:  2% floor (tail emission for validator security)
//!
//! Net inflation = emission_rate - burn_rate.
//! As usage grows, burn > emission → deflationary.
//! When usage is low, tail emission maintains validator incentives.

/// Epochs per year, assuming ~20-minute epochs (3 per hour).
pub const EPOCHS_PER_YEAR: u64 = 365 * 24 * 3; // 26_280

/// Blocks per epoch.
pub const BLOCKS_PER_EPOCH: u64 = 128;

/// Default initial supply: 1 billion SEAL in micro-SEAL (10^9 * 10^9).
pub const DEFAULT_INITIAL_SUPPLY: u64 = 1_000_000_000_000_000_000;

/// Maximum supply cap: 10 billion SEAL in micro-SEAL.
pub const MAX_SUPPLY: u64 = 10_000_000_000_000_000_000;

/// Emission rate boundaries (in basis points, 1 bp = 0.01%).
/// 10% = 1000 bp, 5% = 500 bp, 2% = 200 bp.
const RATE_YEAR_0_BP: u64 = 1000; // 10%
const RATE_YEAR_4_BP: u64 = 500; // 5%
const RATE_YEAR_8_BP: u64 = 200; // 2%

/// Token emission schedule.
#[derive(Debug, Clone)]
pub struct EmissionSchedule {
    /// Initial supply at genesis (micro-SEAL).
    pub initial_supply: u64,
}

impl Default for EmissionSchedule {
    fn default() -> Self {
        EmissionSchedule {
            initial_supply: DEFAULT_INITIAL_SUPPLY,
        }
    }
}

impl EmissionSchedule {
    /// Create a new emission schedule with the given initial supply.
    pub fn new(initial_supply: u64) -> Self {
        EmissionSchedule { initial_supply }
    }

    /// Annual emission rate for a given epoch, in basis points (0.01%).
    ///
    /// Year 0–4: linear from 1000 bp (10%) down to 500 bp (5%)
    /// Year 4–8: linear from 500 bp (5%) down to 200 bp (2%)
    /// Year 8+:  200 bp (2%) floor
    pub fn epoch_emission_rate_bp(&self, epoch: u64) -> u64 {
        let year = epoch / EPOCHS_PER_YEAR;

        if year < 4 {
            // Linear interpolation: 1000 → 500 over 4 years
            // rate = 1000 - (year * (1000-500) / 4) = 1000 - year * 125
            // Use epoch-granular interpolation for smoothness.
            let epoch_in_phase = epoch; // epochs from start
            let phase_epochs = 4u64.saturating_mul(EPOCHS_PER_YEAR);
            // rate = 1000 - (epoch_in_phase * 500 / phase_epochs)
            let decrease = epoch_in_phase
                .saturating_mul(RATE_YEAR_0_BP - RATE_YEAR_4_BP)
                / phase_epochs;
            RATE_YEAR_0_BP.saturating_sub(decrease)
        } else if year < 8 {
            // Linear interpolation: 500 → 200 over years 4–8
            let epoch_in_phase = epoch.saturating_sub(4u64.saturating_mul(EPOCHS_PER_YEAR));
            let phase_epochs = 4u64.saturating_mul(EPOCHS_PER_YEAR);
            let decrease = epoch_in_phase
                .saturating_mul(RATE_YEAR_4_BP - RATE_YEAR_8_BP)
                / phase_epochs;
            RATE_YEAR_4_BP.saturating_sub(decrease)
        } else {
            // Floor: 2%
            RATE_YEAR_8_BP
        }
    }

    /// Annual emission rate as a floating-point percentage (e.g. 10.0 for 10%).
    pub fn epoch_emission_rate(&self, epoch: u64) -> f64 {
        self.epoch_emission_rate_bp(epoch) as f64 / 100.0
    }

    /// Compute per-block emission reward for a given epoch.
    ///
    /// reward = (initial_supply * rate_bp) / (10_000 * blocks_per_year)
    ///
    /// We use u128 intermediates to avoid overflow on the multiplication.
    pub fn block_reward(&self, epoch: u64) -> u64 {
        let rate_bp = self.epoch_emission_rate_bp(epoch);
        let blocks_per_year = EPOCHS_PER_YEAR.saturating_mul(BLOCKS_PER_EPOCH); // 3_363_840

        // Use u128 to avoid overflow: initial_supply * rate_bp could exceed u64
        let numerator = (self.initial_supply as u128).saturating_mul(rate_bp as u128);
        let denominator = 10_000u128.saturating_mul(blocks_per_year as u128);

        if denominator == 0 {
            return 0;
        }

        let reward = numerator / denominator;

        // Clamp to u64
        if reward > u64::MAX as u128 {
            u64::MAX
        } else {
            reward as u64
        }
    }

    /// Cumulative emission through the end of `through_epoch` (inclusive).
    ///
    /// Sums block rewards for each epoch from 0 through `through_epoch`,
    /// multiplied by BLOCKS_PER_EPOCH.
    ///
    /// For efficiency, we compute phase-by-phase rather than epoch-by-epoch.
    pub fn total_emitted(&self, through_epoch: u64) -> u64 {
        let mut total: u128 = 0;

        // We iterate epoch by epoch up to through_epoch (inclusive).
        // For very large epoch counts this could be slow, but in practice
        // 8 years = ~210k epochs which is fine.
        for ep in 0..=through_epoch {
            let reward_per_block = self.block_reward(ep) as u128;
            total = total.saturating_add(reward_per_block.saturating_mul(BLOCKS_PER_EPOCH as u128));
        }

        if total > u64::MAX as u128 {
            u64::MAX
        } else {
            total as u64
        }
    }

    /// Check if the current supply is below the maximum supply cap.
    pub fn is_below_max_supply(&self, current_supply: u64) -> bool {
        current_supply < MAX_SUPPLY
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove that for any epoch, the emission rate is always in [200, 1000] bp.
    #[kani::proof]
    fn emission_rate_bounded() {
        let epoch: u64 = kani::any();
        let schedule = EmissionSchedule::default();
        let rate = schedule.epoch_emission_rate_bp(epoch);
        assert!(rate >= 200, "rate must be >= 200 bp (2% floor)");
        assert!(rate <= 1000, "rate must be <= 1000 bp (10% ceiling)");
    }

    /// Prove that block_reward never panics (no overflow) for any epoch
    /// and any initial_supply up to u64::MAX.
    #[kani::proof]
    fn block_reward_no_overflow() {
        let epoch: u64 = kani::any();
        let initial_supply: u64 = kani::any();
        let schedule = EmissionSchedule::new(initial_supply);
        // If this completes without panic, the function is overflow-safe.
        let _reward = schedule.block_reward(epoch);
    }

    /// Prove that the emission rate is monotonically non-increasing:
    /// for any epoch_a < epoch_b, rate(epoch_a) >= rate(epoch_b).
    /// Bounded to epochs < 10 * EPOCHS_PER_YEAR to keep verification tractable.
    #[kani::proof]
    fn emission_rate_monotone_decreasing() {
        let epoch_a: u64 = kani::any();
        let epoch_b: u64 = kani::any();

        // Bound epochs to keep Kani tractable (10 years of epochs).
        let bound = 10 * EPOCHS_PER_YEAR;
        kani::assume(epoch_a < bound);
        kani::assume(epoch_b < bound);
        kani::assume(epoch_a < epoch_b);

        let schedule = EmissionSchedule::default();
        let rate_a = schedule.epoch_emission_rate_bp(epoch_a);
        let rate_b = schedule.epoch_emission_rate_bp(epoch_b);

        assert!(
            rate_a >= rate_b,
            "emission rate must be monotonically non-increasing"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_initial_supply() {
        let schedule = EmissionSchedule::default();
        assert_eq!(schedule.initial_supply, DEFAULT_INITIAL_SUPPLY);
    }

    #[test]
    fn test_epoch_emission_rate_year_0() {
        let schedule = EmissionSchedule::default();
        // At epoch 0, rate should be 10% (1000 bp)
        assert_eq!(schedule.epoch_emission_rate_bp(0), 1000);
        // As f64
        let rate = schedule.epoch_emission_rate(0);
        assert!((rate - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_epoch_emission_rate_year_4() {
        let schedule = EmissionSchedule::default();
        // At the start of year 4, rate should be 5% (500 bp)
        let epoch_year_4 = 4 * EPOCHS_PER_YEAR;
        assert_eq!(schedule.epoch_emission_rate_bp(epoch_year_4), 500);
        let rate = schedule.epoch_emission_rate(epoch_year_4);
        assert!((rate - 5.0).abs() < 0.01);
    }

    #[test]
    fn test_epoch_emission_rate_year_8() {
        let schedule = EmissionSchedule::default();
        // At the start of year 8, rate should be 2% (200 bp)
        let epoch_year_8 = 8 * EPOCHS_PER_YEAR;
        assert_eq!(schedule.epoch_emission_rate_bp(epoch_year_8), 200);
    }

    #[test]
    fn test_epoch_emission_rate_year_10() {
        let schedule = EmissionSchedule::default();
        // After year 8, rate stays at 2% floor
        let epoch_year_10 = 10 * EPOCHS_PER_YEAR;
        assert_eq!(schedule.epoch_emission_rate_bp(epoch_year_10), 200);
    }

    #[test]
    fn test_rate_decreases_smoothly_phase1() {
        let schedule = EmissionSchedule::default();
        // Rate should strictly decrease (or stay same) through phase 1
        let mut prev_rate = schedule.epoch_emission_rate_bp(0);
        for ep in (1..4 * EPOCHS_PER_YEAR).step_by(1000) {
            let rate = schedule.epoch_emission_rate_bp(ep);
            assert!(rate <= prev_rate, "rate should decrease: epoch {ep}");
            prev_rate = rate;
        }
    }

    #[test]
    fn test_rate_decreases_smoothly_phase2() {
        let schedule = EmissionSchedule::default();
        let start = 4 * EPOCHS_PER_YEAR;
        let mut prev_rate = schedule.epoch_emission_rate_bp(start);
        for ep in (start + 1..8 * EPOCHS_PER_YEAR).step_by(1000) {
            let rate = schedule.epoch_emission_rate_bp(ep);
            assert!(rate <= prev_rate, "rate should decrease: epoch {ep}");
            prev_rate = rate;
        }
    }

    #[test]
    fn test_block_reward_nonzero() {
        let schedule = EmissionSchedule::default();
        // Block reward at epoch 0 should be positive
        let reward = schedule.block_reward(0);
        assert!(reward > 0, "block reward should be positive at epoch 0");
    }

    #[test]
    fn test_block_reward_decreases_over_time() {
        let schedule = EmissionSchedule::default();
        let reward_year0 = schedule.block_reward(0);
        let reward_year4 = schedule.block_reward(4 * EPOCHS_PER_YEAR);
        let reward_year8 = schedule.block_reward(8 * EPOCHS_PER_YEAR);

        assert!(reward_year0 > reward_year4, "reward should decrease year 0 → 4");
        assert!(reward_year4 > reward_year8, "reward should decrease year 4 → 8");
    }

    #[test]
    fn test_block_reward_floor() {
        let schedule = EmissionSchedule::default();
        // After year 8, reward should remain constant (2% floor)
        let reward_year8 = schedule.block_reward(8 * EPOCHS_PER_YEAR);
        let reward_year12 = schedule.block_reward(12 * EPOCHS_PER_YEAR);
        assert_eq!(reward_year8, reward_year12);
    }

    #[test]
    fn test_total_emitted_increases() {
        let schedule = EmissionSchedule::default();
        let emitted_100 = schedule.total_emitted(100);
        let emitted_200 = schedule.total_emitted(200);
        assert!(emitted_200 > emitted_100, "cumulative emission should increase");
    }

    #[test]
    fn test_total_emitted_epoch_0() {
        let schedule = EmissionSchedule::default();
        let emitted = schedule.total_emitted(0);
        // Should equal exactly block_reward(0) * BLOCKS_PER_EPOCH
        let expected = schedule.block_reward(0) * BLOCKS_PER_EPOCH;
        assert_eq!(emitted, expected);
    }

    #[test]
    fn test_is_below_max_supply() {
        let schedule = EmissionSchedule::default();
        assert!(schedule.is_below_max_supply(DEFAULT_INITIAL_SUPPLY));
        assert!(schedule.is_below_max_supply(MAX_SUPPLY - 1));
        assert!(!schedule.is_below_max_supply(MAX_SUPPLY));
        assert!(!schedule.is_below_max_supply(u64::MAX));
    }

    #[test]
    fn test_block_reward_checked_arithmetic() {
        // Ensure no panic with extreme values
        let schedule = EmissionSchedule::new(u64::MAX);
        let reward = schedule.block_reward(0);
        // Should not panic; reward is clamped
        assert!(reward > 0);
    }

    #[test]
    fn test_midpoint_year_2_rate() {
        let schedule = EmissionSchedule::default();
        // At year 2 (midpoint of phase 1), rate should be ~7.5% (750 bp)
        let epoch_year_2 = 2 * EPOCHS_PER_YEAR;
        let rate = schedule.epoch_emission_rate_bp(epoch_year_2);
        // Allow small rounding: should be close to 750
        assert!(
            (rate as i64 - 750).unsigned_abs() <= 1,
            "year 2 rate should be ~750 bp, got {rate}"
        );
    }

    #[test]
    fn test_midpoint_year_6_rate() {
        let schedule = EmissionSchedule::default();
        // At year 6 (midpoint of phase 2), rate should be ~3.5% (350 bp)
        let epoch_year_6 = 6 * EPOCHS_PER_YEAR;
        let rate = schedule.epoch_emission_rate_bp(epoch_year_6);
        assert!(
            (rate as i64 - 350).unsigned_abs() <= 1,
            "year 6 rate should be ~350 bp, got {rate}"
        );
    }

    #[test]
    fn test_constants() {
        assert_eq!(EPOCHS_PER_YEAR, 26_280);
        assert_eq!(BLOCKS_PER_EPOCH, 128);
        assert_eq!(DEFAULT_INITIAL_SUPPLY, 1_000_000_000_000_000_000);
    }
}
