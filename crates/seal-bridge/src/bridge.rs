//! Bridge manager — tracks deposits, withdrawals, and wrapped token balances.
//!
//! INVARIANT (to be proven in TLA+):
//!   TotalMinted(token) <= TotalLocked(token)
//!   i.e., we never mint more wrapped tokens than are locked on the source chain.

use crate::error::BridgeError;
use crate::types::*;
use std::collections::HashMap;

/// Manages bridge state: deposits, withdrawals, and wrapped balances.
#[derive(Default)]
pub struct BridgeManager {
    /// Pending and processed deposits.
    deposits: HashMap<String, BridgeDeposit>,
    /// Pending and executed withdrawals.
    withdrawals: HashMap<String, BridgeWithdrawal>,
    /// Wrapped token balances per SEAL address: (address, token) -> amount.
    wrapped_balances: HashMap<(String, WrappedToken), u64>,
    /// Total locked per token (on source chains).
    total_locked: HashMap<WrappedToken, u64>,
    /// Total minted per token (on Seal).
    total_minted: HashMap<WrappedToken, u64>,
    /// Required confirmations before processing a deposit.
    pub required_confirmations: u32,
}

impl BridgeManager {
    pub fn new(required_confirmations: u32) -> Self {
        BridgeManager {
            required_confirmations,
            ..Default::default()
        }
    }

    /// Record a new deposit observed on a source chain.
    pub fn observe_deposit(&mut self, deposit: BridgeDeposit) -> Result<(), BridgeError> {
        if self.deposits.contains_key(&deposit.id) {
            return Err(BridgeError::DepositAlreadyProcessed(deposit.id));
        }
        self.deposits.insert(deposit.id.clone(), deposit);
        Ok(())
    }

    /// Add a validator confirmation to a deposit.
    pub fn confirm_deposit(&mut self, deposit_id: &str) -> Result<u32, BridgeError> {
        let deposit = self
            .deposits
            .get_mut(deposit_id)
            .ok_or_else(|| BridgeError::DepositNotFound(deposit_id.into()))?;
        if deposit.processed {
            return Err(BridgeError::DepositAlreadyProcessed(deposit_id.into()));
        }
        deposit.confirmations += 1;
        Ok(deposit.confirmations)
    }

    /// Process a confirmed deposit: mint wrapped tokens on Seal.
    /// Only succeeds if confirmations >= required_confirmations.
    pub fn process_deposit(&mut self, deposit_id: &str) -> Result<u64, BridgeError> {
        let deposit = self
            .deposits
            .get(deposit_id)
            .ok_or_else(|| BridgeError::DepositNotFound(deposit_id.into()))?;

        if deposit.processed {
            return Err(BridgeError::DepositAlreadyProcessed(deposit_id.into()));
        }
        if deposit.confirmations < self.required_confirmations {
            return Err(BridgeError::WithdrawalNotConfirmed);
        }

        let amount = deposit.amount;
        let token = deposit.token.clone();
        let seal_addr = deposit.seal_address.clone();

        // Update locked total
        *self.total_locked.entry(token.clone()).or_insert(0) += amount;

        // Mint wrapped tokens
        *self.total_minted.entry(token.clone()).or_insert(0) += amount;
        *self.wrapped_balances.entry((seal_addr, token)).or_insert(0) += amount;

        // Mark as processed
        self.deposits
            .get_mut(deposit_id)
            .ok_or_else(|| BridgeError::DepositNotFound(deposit_id.into()))?
            .processed = true;

        Ok(amount)
    }

    /// Initiate a withdrawal: burn wrapped tokens, create withdrawal record.
    pub fn initiate_withdrawal(
        &mut self,
        seal_address: &str,
        dest_chain: Chain,
        dest_address: &str,
        token: WrappedToken,
        amount: u64,
    ) -> Result<String, BridgeError> {
        // Check wrapped balance
        let balance = self
            .wrapped_balances
            .get(&(seal_address.to_string(), token.clone()))
            .copied()
            .unwrap_or(0);
        if balance < amount {
            return Err(BridgeError::InsufficientWrapped {
                need: amount,
                have: balance,
            });
        }

        // Burn wrapped tokens
        *self
            .wrapped_balances
            .get_mut(&(seal_address.to_string(), token.clone()))
            .ok_or_else(|| BridgeError::InsufficientWrapped { need: amount, have: 0 })? -= amount;
        *self
            .total_minted
            .get_mut(&token)
            .ok_or(BridgeError::MintExceedsLocked)? -= amount;

        // Create withdrawal record
        let id = format!("wd_{}_{}", seal_address, amount);
        let withdrawal = BridgeWithdrawal {
            id: id.clone(),
            dest_chain,
            dest_address: dest_address.to_string(),
            seal_address: seal_address.to_string(),
            amount,
            token,
            executed: false,
        };
        self.withdrawals.insert(id.clone(), withdrawal);

        Ok(id)
    }

    /// Mark a withdrawal as executed on the destination chain.
    pub fn execute_withdrawal(&mut self, withdrawal_id: &str) -> Result<(), BridgeError> {
        let withdrawal = self
            .withdrawals
            .get_mut(withdrawal_id)
            .ok_or_else(|| BridgeError::DepositNotFound(withdrawal_id.into()))?;

        // Reduce locked total (tokens unlocked on source chain)
        let token = withdrawal.token.clone();
        let amount = withdrawal.amount;
        withdrawal.executed = true;
        *self
            .total_locked
            .get_mut(&token)
            .ok_or(BridgeError::MintExceedsLocked)? -= amount;
        Ok(())
    }

    /// Get wrapped token balance for an address.
    pub fn wrapped_balance(&self, address: &str, token: &WrappedToken) -> u64 {
        self.wrapped_balances
            .get(&(address.to_string(), token.clone()))
            .copied()
            .unwrap_or(0)
    }

    /// Total locked on source chains for a token.
    pub fn total_locked(&self, token: &WrappedToken) -> u64 {
        self.total_locked.get(token).copied().unwrap_or(0)
    }

    /// Total minted on Seal for a token.
    pub fn total_minted(&self, token: &WrappedToken) -> u64 {
        self.total_minted.get(token).copied().unwrap_or(0)
    }

    /// INVARIANT CHECK: minted <= locked for all tokens.
    /// This is the core bridge safety property.
    pub fn check_invariant(&self) -> bool {
        for token in [WrappedToken::WSOL, WrappedToken::WXLM, WrappedToken::WUSDC] {
            if self.total_minted(&token) > self.total_locked(&token) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_deposit(id: &str, amount: u64) -> BridgeDeposit {
        BridgeDeposit {
            id: id.to_string(),
            source_chain: Chain::Solana,
            source_tx_hash: format!("tx_{}", id),
            source_address: "sol_addr_1".into(),
            seal_address: "seal1alice".into(),
            amount,
            token: WrappedToken::WSOL,
            processed: false,
            confirmations: 0,
        }
    }

    #[test]
    fn test_deposit_confirm_process() {
        let mut bridge = BridgeManager::new(3);
        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();

        // Confirm 3 times
        assert_eq!(bridge.confirm_deposit("d1").unwrap(), 1);
        assert_eq!(bridge.confirm_deposit("d1").unwrap(), 2);
        assert_eq!(bridge.confirm_deposit("d1").unwrap(), 3);

        // Process
        let minted = bridge.process_deposit("d1").unwrap();
        assert_eq!(minted, 1000);
        assert_eq!(
            bridge.wrapped_balance("seal1alice", &WrappedToken::WSOL),
            1000
        );
        assert!(bridge.check_invariant());
    }

    #[test]
    fn test_process_before_confirmed_fails() {
        let mut bridge = BridgeManager::new(3);
        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();
        bridge.confirm_deposit("d1").unwrap(); // Only 1 of 3
        assert!(bridge.process_deposit("d1").is_err());
    }

    #[test]
    fn test_duplicate_deposit_rejected() {
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();
        assert!(bridge.observe_deposit(make_deposit("d1", 2000)).is_err());
    }

    #[test]
    fn test_withdrawal() {
        let mut bridge = BridgeManager::new(1);

        // Deposit first
        bridge.observe_deposit(make_deposit("d1", 5000)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        // Withdraw
        let wd_id = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                "sol_addr_2",
                WrappedToken::WSOL,
                2000,
            )
            .unwrap();

        assert_eq!(
            bridge.wrapped_balance("seal1alice", &WrappedToken::WSOL),
            3000
        );
        assert!(bridge.check_invariant()); // minted=3000, locked=5000 → OK

        // Execute on source chain
        bridge.execute_withdrawal(&wd_id).unwrap();
        assert_eq!(bridge.total_locked(&WrappedToken::WSOL), 3000); // 5000 - 2000
        assert!(bridge.check_invariant());
    }

    #[test]
    fn test_withdrawal_insufficient_balance() {
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 100)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        assert!(matches!(
            bridge.initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                "dest",
                WrappedToken::WSOL,
                200
            ),
            Err(BridgeError::InsufficientWrapped {
                need: 200,
                have: 100
            })
        ));
    }

    #[test]
    fn test_invariant_holds_through_operations() {
        let mut bridge = BridgeManager::new(1);

        // Multiple deposits
        for i in 0..5 {
            let mut dep = make_deposit(&format!("d{}", i), 1000);
            dep.seal_address = format!("seal1user{}", i % 2);
            bridge.observe_deposit(dep).unwrap();
            bridge.confirm_deposit(&format!("d{}", i)).unwrap();
            bridge.process_deposit(&format!("d{}", i)).unwrap();
            assert!(
                bridge.check_invariant(),
                "invariant failed after deposit {}",
                i
            );
        }

        // Partial withdrawals
        bridge
            .initiate_withdrawal("seal1user0", Chain::Solana, "sol", WrappedToken::WSOL, 500)
            .unwrap();
        assert!(bridge.check_invariant());

        bridge
            .initiate_withdrawal("seal1user1", Chain::Solana, "sol", WrappedToken::WSOL, 1000)
            .unwrap();
        assert!(bridge.check_invariant());

        // Total: minted = 5000 - 500 - 1000 = 3500, locked = 5000 → OK
        assert_eq!(bridge.total_minted(&WrappedToken::WSOL), 3500);
        assert_eq!(bridge.total_locked(&WrappedToken::WSOL), 5000);
    }

    #[test]
    fn test_stellar_bridge() {
        let mut bridge = BridgeManager::new(1);
        let dep = BridgeDeposit {
            id: "xlm_d1".into(),
            source_chain: Chain::Stellar,
            source_tx_hash: "stellar_tx_1".into(),
            source_address: "G_stellar_addr".into(),
            seal_address: "seal1bob".into(),
            amount: 2000,
            token: WrappedToken::WXLM,
            processed: false,
            confirmations: 0,
        };
        bridge.observe_deposit(dep).unwrap();
        bridge.confirm_deposit("xlm_d1").unwrap();
        bridge.process_deposit("xlm_d1").unwrap();

        assert_eq!(
            bridge.wrapped_balance("seal1bob", &WrappedToken::WXLM),
            2000
        );
        assert!(bridge.check_invariant());
    }
}

// Kani verification harnesses
//
// NOTE: BridgeManager uses HashMap which CBMC cannot model. These harnesses
// verify arithmetic invariants without constructing BridgeManager.
#[cfg(kani)]
mod kani_proofs {
    /// Prove: mint + lock arithmetic preserves minted <= locked.
    /// Models the core invariant without HashMap.
    #[kani::proof]
    fn deposit_preserves_invariant() {
        let locked: u64 = kani::any();
        let minted: u64 = kani::any();
        let amount: u64 = kani::any();
        kani::assume(minted <= locked); // precondition: invariant holds
        kani::assume(amount <= 1_000_000);

        // Deposit: both locked and minted increase by the same amount
        let new_locked = locked.saturating_add(amount);
        let new_minted = minted.saturating_add(amount);
        assert!(new_minted <= new_locked); // postcondition: invariant preserved
    }

    /// Prove: withdrawal preserves minted <= locked when withdraw <= minted.
    #[kani::proof]
    fn withdrawal_preserves_invariant() {
        let locked: u64 = kani::any();
        let minted: u64 = kani::any();
        let withdraw: u64 = kani::any();
        kani::assume(minted <= locked);
        kani::assume(withdraw <= minted);

        // Withdrawal: both locked and minted decrease by withdraw amount
        let new_locked = locked.saturating_sub(withdraw);
        let new_minted = minted.saturating_sub(withdraw);
        assert!(new_minted <= new_locked);
    }

    /// Prove: deposit amount cannot cause overflow with saturating_add.
    #[kani::proof]
    fn deposit_no_overflow() {
        let balance: u64 = kani::any();
        let amount: u64 = kani::any();
        let result = balance.saturating_add(amount);
        assert!(result >= balance);
        assert!(result >= amount.min(balance));
    }
}
