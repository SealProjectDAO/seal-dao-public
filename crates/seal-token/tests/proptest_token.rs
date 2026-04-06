//! Property tests for token operations.

use proptest::prelude::*;
use seal_token::balance::{Balance, BalanceStore};

proptest! {
    /// Property: credit + debit of same amount = original balance.
    #[test]
    fn prop_credit_debit_roundtrip(initial in 0u64..1_000_000, amount in 0u64..1_000_000) {
        let mut b = Balance::new(initial);
        if b.credit(amount).is_ok() {
            prop_assert!(b.debit(amount).is_ok());
            prop_assert_eq!(b.available, initial);
        }
    }

    /// Property: stake + unstake = original balance.
    #[test]
    fn prop_stake_unstake_roundtrip(initial in 0u64..1_000_000, amount in 0u64..1_000_000) {
        prop_assume!(amount <= initial);
        let mut b = Balance::new(initial);
        b.stake(amount).unwrap();
        prop_assert_eq!(b.total, initial); // Total unchanged
        b.unstake(amount).unwrap();
        prop_assert_eq!(b.available, initial);
        prop_assert_eq!(b.staked, 0);
    }

    /// Property: mint then burn of same amount = original supply.
    #[test]
    fn prop_mint_burn_roundtrip(amount in 1u64..1_000_000) {
        let mut store = BalanceStore::new();
        store.mint("addr", amount).unwrap();
        prop_assert_eq!(store.total_supply(), amount);
        store.burn("addr", amount).unwrap();
        prop_assert_eq!(store.total_supply(), 0);
    }

    /// Property: transfer preserves total supply.
    #[test]
    fn prop_transfer_conserves(
        a_amount in 1u64..1_000_000,
        b_amount in 0u64..1_000_000,
        transfer in 0u64..1_000_000,
    ) {
        prop_assume!(transfer <= a_amount);
        let mut store = BalanceStore::new();
        store.mint("a", a_amount).unwrap();
        store.mint("b", b_amount).unwrap();
        let initial_supply = store.total_supply();

        let _ = seal_token::transfer::transfer(&mut store, "a", "b", transfer);

        prop_assert_eq!(store.total_supply(), initial_supply);
    }

    /// Property: debit never makes available negative (wrapping).
    #[test]
    fn prop_debit_safe(initial in 0u64..u64::MAX, amount in 0u64..u64::MAX) {
        let mut b = Balance::new(initial);
        match b.debit(amount) {
            Ok(()) => prop_assert!(amount <= initial),
            Err(_) => prop_assert!(amount > initial),
        }
    }
}
