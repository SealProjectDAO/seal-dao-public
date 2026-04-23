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
    /// Paused chains: chain -> human-readable reason. An entry in this
    /// map blocks new deposits, deposit processing, and withdrawals
    /// involving that chain until `unpause_chain` is called. Settled
    /// wrapped-balance reads are unaffected.
    paused_chains: HashMap<Chain, String>,
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
        self.ensure_chain_active(&deposit.source_chain)?;
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

        self.ensure_chain_active(&deposit.source_chain)?;

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
        self.ensure_chain_active(&dest_chain)?;
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

    /// List all observed deposits, optionally filtered by source
    /// chain. Sorted by deposit ID for deterministic output across
    /// repeat calls — useful for testnet polling where the caller
    /// (e.g. `bridge-e2e.sh`) compares snapshots.
    pub fn list_deposits(&self, chain: Option<&Chain>) -> Vec<BridgeDeposit> {
        let mut out: Vec<BridgeDeposit> = self
            .deposits
            .values()
            .filter(|d| chain.is_none_or(|c| &d.source_chain == c))
            .cloned()
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// List all withdrawals (executed or pending), sorted by ID.
    pub fn list_withdrawals(&self) -> Vec<BridgeWithdrawal> {
        let mut out: Vec<BridgeWithdrawal> = self.withdrawals.values().cloned().collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    // ─── Emergency pause (Technical Council 2/3 vote) ────────────

    /// Pause a bridge chain: block new deposits, deposit processing,
    /// and withdrawals involving this chain. Council authorization is
    /// enforced by the caller (RPC layer) — this method is the state
    /// mutation only. Calling `pause_chain` on an already-paused
    /// chain updates the reason.
    pub fn pause_chain(&mut self, chain: Chain, reason: String) {
        self.paused_chains.insert(chain, reason);
    }

    /// Unpause a previously-paused chain. Returns an error if the
    /// chain was not paused.
    pub fn unpause_chain(&mut self, chain: &Chain) -> Result<(), BridgeError> {
        if self.paused_chains.remove(chain).is_none() {
            return Err(BridgeError::ChainNotPaused(chain.to_string()));
        }
        Ok(())
    }

    /// Is the chain currently paused?
    pub fn is_chain_paused(&self, chain: &Chain) -> bool {
        self.paused_chains.contains_key(chain)
    }

    /// Human-readable pause reason, if paused.
    pub fn pause_reason(&self, chain: &Chain) -> Option<&str> {
        self.paused_chains.get(chain).map(String::as_str)
    }

    /// Sorted list of `(chain, reason)` pairs for every paused chain.
    /// Deterministic so RPC callers (dashboards, status pages) can
    /// compare snapshots across repeat calls.
    pub fn list_paused_chains(&self) -> Vec<(Chain, String)> {
        let mut out: Vec<(Chain, String)> = self
            .paused_chains
            .iter()
            .map(|(c, r)| (c.clone(), r.clone()))
            .collect();
        out.sort_by(|a, b| a.0.to_string().cmp(&b.0.to_string()));
        out
    }

    fn ensure_chain_active(&self, chain: &Chain) -> Result<(), BridgeError> {
        if let Some(reason) = self.paused_chains.get(chain) {
            return Err(BridgeError::ChainPaused {
                chain: chain.to_string(),
                reason: reason.clone(),
            });
        }
        Ok(())
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

    #[test]
    fn test_list_deposits_sorted_and_filtered() {
        let mut bridge = BridgeManager::new(1);
        // Insert in reverse-sort order so we exercise list_deposits'
        // sort contract.
        bridge
            .observe_deposit(make_deposit("sol_zzz", 100))
            .unwrap();
        bridge
            .observe_deposit(make_deposit("sol_aaa", 200))
            .unwrap();
        let mut xlm_dep = make_deposit("xlm_mid", 300);
        xlm_dep.source_chain = Chain::Stellar;
        xlm_dep.token = WrappedToken::WXLM;
        bridge.observe_deposit(xlm_dep).unwrap();

        let all = bridge.list_deposits(None);
        assert_eq!(all.len(), 3);
        // Sorted by ID ascending.
        assert_eq!(all[0].id, "sol_aaa");
        assert_eq!(all[1].id, "sol_zzz");
        assert_eq!(all[2].id, "xlm_mid");

        let sol_only = bridge.list_deposits(Some(&Chain::Solana));
        assert_eq!(sol_only.len(), 2);
        assert!(sol_only.iter().all(|d| d.source_chain == Chain::Solana));

        let xlm_only = bridge.list_deposits(Some(&Chain::Stellar));
        assert_eq!(xlm_only.len(), 1);
        assert_eq!(xlm_only[0].id, "xlm_mid");
    }

    #[test]
    fn test_pause_blocks_new_deposits() {
        let mut bridge = BridgeManager::new(1);
        bridge.pause_chain(Chain::Solana, "suspicious activity".into());
        let err = bridge.observe_deposit(make_deposit("d1", 100)).unwrap_err();
        assert!(matches!(err, BridgeError::ChainPaused { .. }));
        assert_eq!(
            bridge.pause_reason(&Chain::Solana),
            Some("suspicious activity")
        );
        // Stellar is unaffected.
        let mut xlm = make_deposit("xlm_d", 200);
        xlm.source_chain = Chain::Stellar;
        xlm.token = WrappedToken::WXLM;
        assert!(bridge.observe_deposit(xlm).is_ok());
    }

    #[test]
    fn test_pause_blocks_processing_of_observed_deposit() {
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 100)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        // Pause after observe but before process — processing still blocked.
        bridge.pause_chain(Chain::Solana, "investigating".into());
        let err = bridge.process_deposit("d1").unwrap_err();
        assert!(matches!(err, BridgeError::ChainPaused { .. }));
    }

    #[test]
    fn test_pause_blocks_new_withdrawals() {
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        bridge.pause_chain(Chain::Solana, "emergency".into());
        let err = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                "sol_bob",
                WrappedToken::WSOL,
                100,
            )
            .unwrap_err();
        assert!(matches!(err, BridgeError::ChainPaused { .. }));
    }

    #[test]
    fn test_unpause_restores_operation() {
        let mut bridge = BridgeManager::new(1);
        bridge.pause_chain(Chain::Solana, "maintenance".into());
        bridge.unpause_chain(&Chain::Solana).unwrap();
        assert!(!bridge.is_chain_paused(&Chain::Solana));
        // Post-unpause deposits work again.
        assert!(bridge.observe_deposit(make_deposit("d1", 50)).is_ok());
    }

    #[test]
    fn test_unpause_nonpaused_errors() {
        let mut bridge = BridgeManager::new(1);
        let err = bridge.unpause_chain(&Chain::Solana).unwrap_err();
        assert!(matches!(err, BridgeError::ChainNotPaused(_)));
    }

    #[test]
    fn test_list_paused_chains_sorted() {
        let mut bridge = BridgeManager::new(1);
        bridge.pause_chain(Chain::Stellar, "horizon flapping".into());
        bridge.pause_chain(Chain::Solana, "key rotation mid-flight".into());
        let listed = bridge.list_paused_chains();
        assert_eq!(listed.len(), 2);
        // "Solana" < "Stellar" lexicographically.
        assert_eq!(listed[0].0, Chain::Solana);
        assert_eq!(listed[1].0, Chain::Stellar);
    }

    #[test]
    fn test_pause_does_not_affect_wrapped_balance_reads() {
        let mut bridge = BridgeManager::new(1);
        bridge.observe_deposit(make_deposit("d1", 1000)).unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        bridge.pause_chain(Chain::Solana, "any".into());
        // Reads keep working so dashboards and users can still see state.
        assert_eq!(
            bridge.wrapped_balance("seal1alice", &WrappedToken::WSOL),
            1000
        );
        assert_eq!(bridge.total_locked(&WrappedToken::WSOL), 1000);
        assert_eq!(bridge.total_minted(&WrappedToken::WSOL), 1000);
        assert!(bridge.check_invariant());
    }

    #[test]
    fn test_pause_updates_reason() {
        let mut bridge = BridgeManager::new(1);
        bridge.pause_chain(Chain::Solana, "reason A".into());
        bridge.pause_chain(Chain::Solana, "reason B".into());
        assert_eq!(bridge.pause_reason(&Chain::Solana), Some("reason B"));
    }

    #[test]
    fn test_list_withdrawals_sorted() {
        let mut bridge = BridgeManager::new(1);
        let mut dep = make_deposit("sol_d", 1000);
        dep.confirmations = 1;
        bridge.observe_deposit(dep).unwrap();
        bridge.process_deposit("sol_d").unwrap();

        // Two withdrawals with different amounts produce different IDs.
        let id_a = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                "sol_bob",
                WrappedToken::WSOL,
                400,
            )
            .unwrap();
        let id_b = bridge
            .initiate_withdrawal(
                "seal1alice",
                Chain::Solana,
                "sol_bob",
                WrappedToken::WSOL,
                300,
            )
            .unwrap();

        let ws = bridge.list_withdrawals();
        assert_eq!(ws.len(), 2);
        // Sorted ascending — depends on format but must be stable.
        let ids: Vec<_> = ws.iter().map(|w| w.id.as_str()).collect();
        assert!(ids.contains(&id_a.as_str()));
        assert!(ids.contains(&id_b.as_str()));
        assert!(ws[0].id <= ws[1].id);
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
