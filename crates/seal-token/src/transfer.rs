//! Token transfers with checked arithmetic.

use crate::balance::BalanceStore;
use crate::error::TokenError;

/// Result of a transfer operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferResult {
    pub from_balance: u64,
    pub to_balance: u64,
    pub amount: u64,
}

/// Execute a transfer between two accounts.
pub fn transfer(
    store: &mut BalanceStore,
    from: &str,
    to: &str,
    amount: u64,
) -> Result<TransferResult, TokenError> {
    if amount == 0 {
        let from_bal = store.available(from);
        let to_bal = store.available(to);
        return Ok(TransferResult {
            from_balance: from_bal,
            to_balance: to_bal,
            amount: 0,
        });
    }

    // Debit sender
    let from_balance = store
        .get_mut(from)
        .ok_or_else(|| TokenError::AccountNotFound(from.into()))?;
    from_balance.debit(amount)?;
    let from_bal = from_balance.available;

    // Credit receiver (create account if needed)
    if store.get_mut(to).is_none() {
        store.mint(to, 0)?;
    }
    store
        .get_mut(to)
        .ok_or_else(|| TokenError::AccountNotFound(to.into()))?
        .credit(amount)?;
    let to_bal = store.available(to);

    Ok(TransferResult {
        from_balance: from_bal,
        to_balance: to_bal,
        amount,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_transfer() {
        let mut store = BalanceStore::new();
        store.mint("alice", 1000).unwrap();
        store.mint("bob", 500).unwrap();

        let result = transfer(&mut store, "alice", "bob", 300).unwrap();
        assert_eq!(result.from_balance, 700);
        assert_eq!(result.to_balance, 800);
        assert_eq!(result.amount, 300);

        // Total supply unchanged
        assert_eq!(store.total_supply(), 1500);
    }

    #[test]
    fn test_transfer_insufficient() {
        let mut store = BalanceStore::new();
        store.mint("alice", 100).unwrap();
        store.mint("bob", 0).unwrap();

        assert!(transfer(&mut store, "alice", "bob", 200).is_err());
        // Balances unchanged on failure
        assert_eq!(store.available("alice"), 100);
        assert_eq!(store.available("bob"), 0);
    }

    #[test]
    fn test_transfer_zero() {
        let mut store = BalanceStore::new();
        store.mint("alice", 100).unwrap();
        store.mint("bob", 50).unwrap();

        let result = transfer(&mut store, "alice", "bob", 0).unwrap();
        assert_eq!(result.amount, 0);
        assert_eq!(store.available("alice"), 100);
    }

    #[test]
    fn test_transfer_from_nonexistent() {
        let mut store = BalanceStore::new();
        store.mint("bob", 100).unwrap();
        assert!(transfer(&mut store, "nobody", "bob", 50).is_err());
    }

    #[test]
    fn test_transfer_preserves_total_supply() {
        let mut store = BalanceStore::new();
        store.mint("a", 1000).unwrap();
        store.mint("b", 2000).unwrap();
        store.mint("c", 3000).unwrap();
        let initial_supply = store.total_supply();

        transfer(&mut store, "a", "b", 500).unwrap();
        transfer(&mut store, "b", "c", 1000).unwrap();
        transfer(&mut store, "c", "a", 200).unwrap();

        assert_eq!(store.total_supply(), initial_supply);
    }
}
