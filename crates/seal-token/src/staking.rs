//! Staking and unbonding management.
//!
//! Validators stake SEAL tokens to participate in consensus.
//! Unstaking has a 14-day unbonding period (21 epochs).

use crate::balance::BalanceStore;
use crate::error::TokenError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unbonding period in epochs (14 days at ~17 min/epoch ≈ 1185 epochs,
/// simplified to 21 for testnet).
pub const UNBONDING_EPOCHS: u64 = 21;

/// Staking info for a validator.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakeInfo {
    /// Amount staked.
    pub staked: u64,
    /// Amount currently unbonding.
    pub unbonding: u64,
    /// Epoch when unbonding completes (0 if not unbonding).
    pub unbonding_complete_epoch: u64,
}

/// Manages staking operations.
#[derive(Clone, Debug, Default)]
pub struct StakingManager {
    stakes: HashMap<String, StakeInfo>,
}

impl StakingManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stake tokens for a validator.
    pub fn stake(
        &mut self,
        balance_store: &mut BalanceStore,
        address: &str,
        amount: u64,
    ) -> Result<(), TokenError> {
        // Move from available to staked in balance
        let bal = balance_store
            .get_mut(address)
            .ok_or_else(|| TokenError::AccountNotFound(address.into()))?;
        bal.stake(amount)?;

        // Track in staking manager
        let info = self.stakes.entry(address.to_string()).or_insert(StakeInfo {
            staked: 0,
            unbonding: 0,
            unbonding_complete_epoch: 0,
        });
        info.staked = info
            .staked
            .checked_add(amount)
            .ok_or(TokenError::Overflow)?;

        Ok(())
    }

    /// Begin unstaking (start unbonding period).
    pub fn begin_unstake(
        &mut self,
        address: &str,
        amount: u64,
        current_epoch: u64,
    ) -> Result<(), TokenError> {
        let info = self
            .stakes
            .get_mut(address)
            .ok_or_else(|| TokenError::AccountNotFound(address.into()))?;

        if amount > info.staked {
            return Err(TokenError::InsufficientStake {
                need: amount,
                have: info.staked,
            });
        }

        info.staked -= amount;
        info.unbonding = info
            .unbonding
            .checked_add(amount)
            .ok_or(TokenError::Overflow)?;
        info.unbonding_complete_epoch = current_epoch + UNBONDING_EPOCHS;

        Ok(())
    }

    /// Complete unstaking after unbonding period.
    pub fn complete_unstake(
        &mut self,
        balance_store: &mut BalanceStore,
        address: &str,
        current_epoch: u64,
    ) -> Result<u64, TokenError> {
        let info = self
            .stakes
            .get_mut(address)
            .ok_or_else(|| TokenError::AccountNotFound(address.into()))?;

        if info.unbonding == 0 {
            return Ok(0);
        }

        if current_epoch < info.unbonding_complete_epoch {
            return Err(TokenError::UnbondingNotComplete {
                remaining_epochs: info.unbonding_complete_epoch - current_epoch,
            });
        }

        let amount = info.unbonding;
        info.unbonding = 0;
        info.unbonding_complete_epoch = 0;

        // Move from staked to available in balance
        let bal = balance_store
            .get_mut(address)
            .ok_or_else(|| TokenError::AccountNotFound(address.into()))?;
        bal.unstake(amount)?;

        Ok(amount)
    }

    /// Get staking info for an address.
    pub fn get_stake(&self, address: &str) -> Option<&StakeInfo> {
        self.stakes.get(address)
    }

    /// Total staked across all validators.
    pub fn total_staked(&self) -> u64 {
        self.stakes.values().map(|s| s.staked + s.unbonding).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stake_and_unstake() {
        let mut balances = BalanceStore::new();
        balances.mint("alice", 10000).unwrap();
        let mut staking = StakingManager::new();

        // Stake
        staking.stake(&mut balances, "alice", 3000).unwrap();
        assert_eq!(balances.available("alice"), 7000);
        assert_eq!(staking.get_stake("alice").unwrap().staked, 3000);

        // Begin unstake at epoch 10
        staking.begin_unstake("alice", 1000, 10).unwrap();
        assert_eq!(staking.get_stake("alice").unwrap().staked, 2000);
        assert_eq!(staking.get_stake("alice").unwrap().unbonding, 1000);

        // Try to complete too early (epoch 20, need 31)
        assert!(staking
            .complete_unstake(&mut balances, "alice", 20)
            .is_err());

        // Complete at epoch 31
        let released = staking
            .complete_unstake(&mut balances, "alice", 31)
            .unwrap();
        assert_eq!(released, 1000);
        assert_eq!(balances.available("alice"), 8000);
    }

    #[test]
    fn test_stake_insufficient_balance() {
        let mut balances = BalanceStore::new();
        balances.mint("bob", 100).unwrap();
        let mut staking = StakingManager::new();

        assert!(staking.stake(&mut balances, "bob", 200).is_err());
    }

    #[test]
    fn test_total_staked() {
        let mut balances = BalanceStore::new();
        balances.mint("a", 10000).unwrap();
        balances.mint("b", 10000).unwrap();
        let mut staking = StakingManager::new();

        staking.stake(&mut balances, "a", 5000).unwrap();
        staking.stake(&mut balances, "b", 3000).unwrap();
        assert_eq!(staking.total_staked(), 8000);
    }

    #[test]
    fn test_staking_preserves_total_supply() {
        let mut balances = BalanceStore::new();
        balances.mint("validator", 10000).unwrap();
        let initial_supply = balances.total_supply();
        let mut staking = StakingManager::new();

        staking.stake(&mut balances, "validator", 5000).unwrap();
        assert_eq!(balances.total_supply(), initial_supply);

        staking.begin_unstake("validator", 2000, 0).unwrap();
        staking
            .complete_unstake(&mut balances, "validator", UNBONDING_EPOCHS)
            .unwrap();
        assert_eq!(balances.total_supply(), initial_supply);
    }
}
