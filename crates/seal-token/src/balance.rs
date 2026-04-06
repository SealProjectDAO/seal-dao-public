//! Balance tracking per address.
//!
//! All amounts are in micro-SEAL (1 SEAL = 10^9 micro-SEAL).
//! Arithmetic uses checked operations — no overflow/underflow possible.

use crate::error::TokenError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Balance of a single account.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Balance {
    /// Available (spendable) balance in micro-SEAL.
    pub available: u64,
    /// Staked (locked) balance in micro-SEAL.
    pub staked: u64,
    /// Total balance (available + staked).
    pub total: u64,
}

impl Balance {
    pub fn new(available: u64) -> Self {
        Balance {
            available,
            staked: 0,
            total: available,
        }
    }

    /// Credit (add) an amount. Returns error on overflow.
    pub fn credit(&mut self, amount: u64) -> Result<(), TokenError> {
        self.available = self
            .available
            .checked_add(amount)
            .ok_or(TokenError::Overflow)?;
        self.total = self.total.checked_add(amount).ok_or(TokenError::Overflow)?;
        Ok(())
    }

    /// Debit (subtract) from available balance.
    pub fn debit(&mut self, amount: u64) -> Result<(), TokenError> {
        if amount > self.available {
            return Err(TokenError::InsufficientBalance {
                need: amount,
                have: self.available,
            });
        }
        self.available -= amount;
        self.total -= amount;
        Ok(())
    }

    /// Move amount from available to staked.
    pub fn stake(&mut self, amount: u64) -> Result<(), TokenError> {
        if amount > self.available {
            return Err(TokenError::InsufficientBalance {
                need: amount,
                have: self.available,
            });
        }
        self.available -= amount;
        self.staked = self
            .staked
            .checked_add(amount)
            .ok_or(TokenError::Overflow)?;
        // total unchanged
        Ok(())
    }

    /// Move amount from staked to available (unstake).
    pub fn unstake(&mut self, amount: u64) -> Result<(), TokenError> {
        if amount > self.staked {
            return Err(TokenError::InsufficientStake {
                need: amount,
                have: self.staked,
            });
        }
        self.staked -= amount;
        self.available = self
            .available
            .checked_add(amount)
            .ok_or(TokenError::Overflow)?;
        // total unchanged
        Ok(())
    }
}

/// Store of all account balances.
#[derive(Clone, Debug, Default)]
pub struct BalanceStore {
    accounts: HashMap<String, Balance>,
    total_supply: u64,
    total_burned: u64,
}

impl BalanceStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint tokens to an address (increases total supply).
    pub fn mint(&mut self, address: &str, amount: u64) -> Result<(), TokenError> {
        self.total_supply = self
            .total_supply
            .checked_add(amount)
            .ok_or(TokenError::Overflow)?;
        let balance = self.accounts.entry(address.to_string()).or_default();
        balance.credit(amount)
    }

    /// Burn tokens from an address (decreases total supply).
    pub fn burn(&mut self, address: &str, amount: u64) -> Result<(), TokenError> {
        let balance = self
            .accounts
            .get_mut(address)
            .ok_or_else(|| TokenError::AccountNotFound(address.into()))?;
        balance.debit(amount)?;
        self.total_supply -= amount; // Safe: debit succeeded so amount <= total
        self.total_burned = self
            .total_burned
            .checked_add(amount)
            .ok_or(TokenError::Overflow)?;
        Ok(())
    }

    /// Get balance for an address.
    pub fn get(&self, address: &str) -> Option<&Balance> {
        self.accounts.get(address)
    }

    /// Get available balance, defaulting to 0.
    pub fn available(&self, address: &str) -> u64 {
        self.accounts.get(address).map(|b| b.available).unwrap_or(0)
    }

    /// Total supply (minted - burned).
    pub fn total_supply(&self) -> u64 {
        self.total_supply
    }

    /// Total ever burned.
    pub fn total_burned(&self) -> u64 {
        self.total_burned
    }

    /// Number of accounts.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Transfer tokens between addresses.
    pub fn transfer(&mut self, from: &str, to: &str, amount: u64) -> Result<(), TokenError> {
        if amount == 0 {
            return Err(TokenError::Custom("amount must be > 0".into()));
        }
        let from_balance = self
            .accounts
            .get_mut(from)
            .ok_or_else(|| TokenError::AccountNotFound(from.into()))?;
        from_balance.debit(amount)?;
        let to_balance = self.accounts.entry(to.to_string()).or_default();
        to_balance.credit(amount)
    }

    /// List all accounts with non-zero balance.
    pub fn all_accounts(&self) -> Vec<(&str, u64)> {
        self.accounts
            .iter()
            .filter(|(_, b)| b.available > 0)
            .map(|(addr, b)| (addr.as_str(), b.available))
            .collect()
    }

    /// Get mutable balance (internal).
    pub(crate) fn get_mut(&mut self, address: &str) -> Option<&mut Balance> {
        self.accounts.get_mut(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balance_credit_debit() {
        let mut b = Balance::new(1000);
        assert_eq!(b.available, 1000);

        b.credit(500).unwrap();
        assert_eq!(b.available, 1500);
        assert_eq!(b.total, 1500);

        b.debit(300).unwrap();
        assert_eq!(b.available, 1200);
        assert_eq!(b.total, 1200);
    }

    #[test]
    fn test_balance_insufficient() {
        let mut b = Balance::new(100);
        assert_eq!(
            b.debit(200),
            Err(TokenError::InsufficientBalance {
                need: 200,
                have: 100
            })
        );
    }

    #[test]
    fn test_balance_overflow() {
        let mut b = Balance::new(u64::MAX);
        assert_eq!(b.credit(1), Err(TokenError::Overflow));
    }

    #[test]
    fn test_stake_unstake() {
        let mut b = Balance::new(1000);
        b.stake(400).unwrap();
        assert_eq!(b.available, 600);
        assert_eq!(b.staked, 400);
        assert_eq!(b.total, 1000); // Total unchanged

        b.unstake(200).unwrap();
        assert_eq!(b.available, 800);
        assert_eq!(b.staked, 200);
        assert_eq!(b.total, 1000);
    }

    #[test]
    fn test_mint_and_burn() {
        let mut store = BalanceStore::new();
        store.mint("alice", 1000).unwrap();
        store.mint("bob", 500).unwrap();

        assert_eq!(store.total_supply(), 1500);
        assert_eq!(store.available("alice"), 1000);

        store.burn("alice", 300).unwrap();
        assert_eq!(store.total_supply(), 1200);
        assert_eq!(store.total_burned(), 300);
        assert_eq!(store.available("alice"), 700);
    }

    #[test]
    fn test_burn_nonexistent() {
        let mut store = BalanceStore::new();
        assert!(store.burn("nobody", 100).is_err());
    }

    #[test]
    fn test_supply_conservation() {
        let mut store = BalanceStore::new();
        store.mint("a", 1000).unwrap();
        store.mint("b", 2000).unwrap();
        store.burn("a", 500).unwrap();

        // total_supply = minted - burned = 3000 - 500 = 2500
        assert_eq!(store.total_supply(), 2500);
        // Sum of all balances should equal total_supply
        let sum: u64 = ["a", "b"]
            .iter()
            .map(|addr| store.get(addr).map(|b| b.total).unwrap_or(0))
            .sum();
        assert_eq!(sum, store.total_supply());
    }
}

// Kani verification harnesses
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove: credit followed by debit of same amount preserves balance.
    #[kani::proof]
    fn credit_debit_roundtrip() {
        let initial: u64 = kani::any();
        kani::assume(initial <= u64::MAX / 2); // Prevent overflow
        let amount: u64 = kani::any();
        kani::assume(amount <= u64::MAX / 2);

        let mut b = Balance::new(initial);
        if b.credit(amount).is_ok() {
            assert!(b.debit(amount).is_ok());
            assert_eq!(b.available, initial);
            assert_eq!(b.total, initial);
        }
    }

    /// Prove: stake + unstake preserves total balance.
    #[kani::proof]
    fn stake_unstake_preserves_total() {
        let initial: u64 = kani::any();
        let stake_amount: u64 = kani::any();
        kani::assume(stake_amount <= initial);

        let mut b = Balance::new(initial);
        b.stake(stake_amount).unwrap();
        assert_eq!(b.total, initial); // Total unchanged after stake

        b.unstake(stake_amount).unwrap();
        assert_eq!(b.total, initial); // Total unchanged after unstake
        assert_eq!(b.available, initial);
        assert_eq!(b.staked, 0);
    }

    /// Prove: debit never causes underflow (checked arithmetic).
    #[kani::proof]
    fn debit_no_underflow() {
        let initial: u64 = kani::any();
        let amount: u64 = kani::any();

        let mut b = Balance::new(initial);
        match b.debit(amount) {
            Ok(()) => {
                // Debit succeeded → new balance is valid
                assert!(b.available <= initial);
                assert_eq!(b.available, initial - amount);
            }
            Err(TokenError::InsufficientBalance { .. }) => {
                // Debit failed → balance unchanged
                assert_eq!(b.available, initial);
            }
            _ => panic!("unexpected error"),
        }
    }
}
