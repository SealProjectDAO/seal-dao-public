//! Balance tracking per address.
//!
//! All amounts are in micro-SEAL (1 SEAL = 10^9 micro-SEAL).
//! Arithmetic uses checked operations — no overflow/underflow possible.
//!
//! As of PLAN #8 (2026-05-08), `BalanceStore` is HAMT-backed: the
//! account map is a content-addressed `Hamt` storing bincode-serialized
//! `Balance` records. The Merkle root commits to the entire ledger and
//! is cached so block production gets O(1) `state_root_hash()` instead
//! of the previous O(n log32 n) on-the-fly rebuild.

use crate::error::TokenError;
use crate::hamt::Hamt;
use seal_crypto::hash::Hash256;
use serde::{Deserialize, Serialize};
use std::cell::Cell;

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

/// Store of all account balances. HAMT-backed (content-addressed,
/// log32-depth lookups, structural sharing on clone) with a cached
/// Merkle root that invalidates on any mutation.
#[derive(Clone, Debug, Default)]
pub struct BalanceStore {
    accounts: Hamt,
    total_supply: u64,
    total_burned: u64,
    /// Lazily-computed root hash. Invalidated on every mutation; the
    /// next `state_root_hash()` call recomputes and re-caches. `Cell`
    /// gives interior mutability so the recompute happens through
    /// `&self` without exposing it to callers.
    root_cache: Cell<Option<Hash256>>,
}

impl BalanceStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize a `Balance` for HAMT storage. Bincode 1's encoding
    /// of a fixed-size 3 × u64 struct is 24 bytes and never fails.
    fn encode_balance(bal: &Balance) -> Vec<u8> {
        bincode::serialize(bal).expect("Balance is fixed-size u64 fields, bincode never fails")
    }

    /// Deserialize a HAMT-stored balance. Panics on corrupt data —
    /// the only way that happens is a bug in this module, not user
    /// input, so propagating an error wouldn't help recovery.
    fn decode_balance(bytes: &[u8]) -> Balance {
        bincode::deserialize(bytes)
            .expect("HAMT-stored balance must be bincode of Balance; bug if not")
    }

    /// Read a balance by address. Owned because the value is
    /// deserialized from the HAMT's stored bytes; we can't return
    /// a borrow into the trie.
    fn fetch(&self, address: &str) -> Option<Balance> {
        self.accounts
            .get(address.as_bytes())
            .map(Self::decode_balance)
    }

    /// Write a balance back to the HAMT. Invalidates the cached
    /// root.
    /// Eager dust-prune threshold. A balance with both `available`
    /// and `staked` at zero contributes nothing — keeping it in
    /// the HAMT inflates the leaf count, the state-root rebuild
    /// cost, and the dust-fanout attack surface (an attacker that
    /// can spam-create accounts then drain them was previously
    /// leaving behind permanent record entries). Companion to
    /// `--min-opening-balance` (commit `c042b406b`): that prevents
    /// dust accounts from being created cheaply, this prevents
    /// existing accounts from sticking around after their balance
    /// is gone. Staked-only accounts (available=0, staked>0) are
    /// preserved — they have value locked.
    fn is_empty(bal: &Balance) -> bool {
        bal.available == 0 && bal.staked == 0
    }

    fn put(&mut self, address: &str, bal: &Balance) {
        if Self::is_empty(bal) {
            self.accounts.remove(address.as_bytes());
        } else {
            self.accounts
                .insert(address.as_bytes().to_vec(), Self::encode_balance(bal));
        }
        self.root_cache.set(None);
    }

    /// Read-modify-write helper: fetch the existing balance,
    /// run `f` against it, write the result back. Errors if the
    /// account doesn't exist. Used by burn / transfer / staking
    /// where the account is required.
    pub(crate) fn update<F>(&mut self, address: &str, f: F) -> Result<(), TokenError>
    where
        F: FnOnce(&mut Balance) -> Result<(), TokenError>,
    {
        let mut bal = self
            .fetch(address)
            .ok_or_else(|| TokenError::AccountNotFound(address.into()))?;
        f(&mut bal)?;
        self.put(address, &bal);
        Ok(())
    }

    /// Same as `update` but creates a default (zero) balance if the
    /// account doesn't exist yet. Used by mint and the recipient
    /// side of a transfer.
    pub(crate) fn update_or_create<F>(&mut self, address: &str, f: F) -> Result<(), TokenError>
    where
        F: FnOnce(&mut Balance) -> Result<(), TokenError>,
    {
        let mut bal = self.fetch(address).unwrap_or_default();
        f(&mut bal)?;
        self.put(address, &bal);
        Ok(())
    }

    /// Mint tokens to an address (increases total supply).
    pub fn mint(&mut self, address: &str, amount: u64) -> Result<(), TokenError> {
        self.total_supply = self
            .total_supply
            .checked_add(amount)
            .ok_or(TokenError::Overflow)?;
        self.update_or_create(address, |b| b.credit(amount))
    }

    /// Burn tokens from an address (decreases total supply).
    pub fn burn(&mut self, address: &str, amount: u64) -> Result<(), TokenError> {
        self.update(address, |b| b.debit(amount))?;
        self.total_supply -= amount; // Safe: debit succeeded so amount <= total
        self.total_burned = self
            .total_burned
            .checked_add(amount)
            .ok_or(TokenError::Overflow)?;
        Ok(())
    }

    /// Get balance for an address. Returns an owned `Balance` because
    /// the underlying storage is a HAMT and we can't borrow into a
    /// deserialized value.
    pub fn get(&self, address: &str) -> Option<Balance> {
        self.fetch(address)
    }

    /// Get available balance, defaulting to 0.
    pub fn available(&self, address: &str) -> u64 {
        self.fetch(address).map(|b| b.available).unwrap_or(0)
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

    /// Whether `address` has an active entry in the ledger.
    /// Accounts with both `available == 0` and `staked == 0` are
    /// eagerly pruned (see `put`), so `has_account` returns false
    /// for either "never existed" or "drained to zero". Used by the
    /// recipient-new-account policy in `seal-node`
    /// (`RpcConfig::allow_new_recipients`); the policy treats
    /// pruned-to-zero and never-seen the same — that's the
    /// dust-spam mitigation working.
    pub fn has_account(&self, address: &str) -> bool {
        self.accounts.contains_key(address.as_bytes())
    }

    /// Content-addressed Merkle root of the entire balance set.
    ///
    /// Cached after first call; recomputed lazily on the next call
    /// after any mutation (mint / burn / transfer / update). The
    /// cache makes block production's per-block `state_root` a
    /// constant-time read instead of an O(n log32 n) tree-rebuild.
    pub fn state_root_hash(&self) -> Hash256 {
        if let Some(h) = self.root_cache.get() {
            return h;
        }
        let h = self.accounts.root_hash();
        self.root_cache.set(Some(h));
        h
    }

    /// Transfer tokens between addresses.
    pub fn transfer(&mut self, from: &str, to: &str, amount: u64) -> Result<(), TokenError> {
        if amount == 0 {
            return Err(TokenError::Custom("amount must be > 0".into()));
        }
        self.update(from, |b| b.debit(amount))?;
        self.update_or_create(to, |b| b.credit(amount))
    }

    /// List all accounts with non-zero available balance. The HAMT
    /// iteration order is hash-bucket-sorted (deterministic but not
    /// lexicographic); callers that need a specific ordering should
    /// sort the returned `Vec` themselves.
    pub fn all_accounts(&self) -> Vec<(String, u64)> {
        self.accounts
            .iter()
            .filter_map(|(k, v)| {
                let bal = Self::decode_balance(v);
                if bal.available == 0 {
                    return None;
                }
                let addr = std::str::from_utf8(k).ok()?.to_string();
                Some((addr, bal.available))
            })
            .collect()
    }

    /// Dump every HAMT leaf as raw `(key, encoded_balance)` bytes,
    /// sorted lexicographically by key. Used by the state-sync
    /// snapshot path (`seal_getSnapshotManifest` / chunk) — the
    /// chunker is order-preserving, so this routine is the source of
    /// the deterministic order. Sort order = byte-wise key, which is
    /// stable across nodes regardless of HAMT layout.
    pub fn snapshot_dump(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out: Vec<(Vec<u8>, Vec<u8>)> = self
            .accounts
            .iter()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Reconstruct a `BalanceStore` from a snapshot stream (the
    /// inverse of `snapshot_dump` + `chunk_entries`). Caller is the
    /// state-sync late-joiner path: it pulls chunks from a peer,
    /// decodes them via `seal_storage::decode_chunks`, and feeds
    /// the resulting `(key, encoded_balance)` records here.
    ///
    /// `total_supply` is rebuilt from the per-account
    /// `available + staked` sums; `total_burned` is reset to zero.
    /// The latter is non-state derived data that doesn't live in
    /// the HAMT — a snapshot doesn't carry it. For testnet this
    /// is acceptable: the late-joiner sees an unbiased "since
    /// snapshot" burn counter, which matches "since I joined" in
    /// operator UX. Mainnet will need a separate
    /// totals-attestation channel before this is safe to ship.
    ///
    /// Returns `Err` if any record fails to decode (corrupt /
    /// truncated chunks already get caught earlier by
    /// `decode_chunk_bytes`, but a malicious peer could still
    /// hand-craft an invalid bincode payload — surface that as
    /// an error rather than panic).
    pub fn restore_from_snapshot(entries: Vec<(Vec<u8>, Vec<u8>)>) -> Result<Self, String> {
        let mut store = Self::default();
        for (key, value) in entries {
            // Validate the encoded balance round-trips through
            // bincode before inserting into the HAMT. A
            // failure here is "the peer lied"; bail out cleanly so
            // the late-joiner can fall back to a different peer
            // rather than ending up with a half-populated store.
            let bal: Balance = match bincode::deserialize(&value) {
                Ok(b) => b,
                Err(e) => {
                    return Err(format!(
                        "snapshot entry for key {:?} has malformed bincode: {e}",
                        std::str::from_utf8(&key).unwrap_or("<binary>")
                    ));
                }
            };
            // Drop dust accounts — `put` would skip them anyway,
            // but doing it here means we don't waste the HAMT
            // insert for entries that the snapshot stream
            // shouldn't have included in the first place. (A
            // well-behaved encoder strips them via
            // `BalanceStore::put`, but we don't trust the peer.)
            if Self::is_empty(&bal) {
                continue;
            }
            let supply_delta = bal.available.saturating_add(bal.staked);
            store.total_supply = store.total_supply.saturating_add(supply_delta);
            store.accounts.insert(key, value);
        }
        store.root_cache.set(None);
        Ok(store)
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
    fn test_eager_prune_on_full_drain() {
        let mut store = BalanceStore::new();
        store.mint("alice", 1000).unwrap();
        assert!(store.has_account("alice"));
        assert_eq!(store.account_count(), 1);
        // Burn the entire balance.
        store.burn("alice", 1000).unwrap();
        // Account is gone — pruned to keep the HAMT tight.
        assert!(!store.has_account("alice"));
        assert_eq!(store.account_count(), 0);
        // Subsequent burn errors with AccountNotFound (the entry's
        // truly gone, not just zero).
        assert!(store.burn("alice", 1).is_err());
    }

    #[test]
    fn test_no_prune_when_staked() {
        let mut store = BalanceStore::new();
        store.mint("alice", 1000).unwrap();
        store.update("alice", |b| b.stake(1000)).unwrap();
        // available=0, staked=1000 — NOT pruned (alice still has value).
        assert!(store.has_account("alice"));
        assert_eq!(store.get("alice").unwrap().available, 0);
        assert_eq!(store.get("alice").unwrap().staked, 1000);
        // Unstake all — now available=1000, staked=0, still not empty.
        store.update("alice", |b| b.unstake(1000)).unwrap();
        assert!(store.has_account("alice"));
        // Burn the available — now fully empty, pruned.
        store.burn("alice", 1000).unwrap();
        assert!(!store.has_account("alice"));
    }

    #[test]
    fn test_eager_prune_on_full_transfer() {
        let mut store = BalanceStore::new();
        store.mint("alice", 1000).unwrap();
        store.transfer("alice", "bob", 1000).unwrap();
        // Sender drained to zero → pruned. Recipient is created.
        assert!(!store.has_account("alice"));
        assert!(store.has_account("bob"));
        assert_eq!(store.account_count(), 1);
        // Once pruned, alice looks fresh on the next deposit — same
        // semantics as never having existed. This is intentional;
        // the `--min-opening-balance` policy applies on the way back
        // in (recipient-new-account check in seal-node rpc).
        store.transfer("bob", "alice", 1).unwrap();
        assert!(store.has_account("alice"));
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

    // ── HAMT state-root-hash tests ─────────────────────────────

    #[test]
    fn state_root_hash_empty_is_deterministic() {
        let a = BalanceStore::new();
        let b = BalanceStore::new();
        assert_eq!(a.state_root_hash(), b.state_root_hash());
    }

    #[test]
    fn state_root_hash_is_insertion_order_independent() {
        let mut a = BalanceStore::new();
        a.mint("seal1alice", 1_000).unwrap();
        a.mint("seal1bob", 2_000).unwrap();
        a.mint("seal1carol", 3_000).unwrap();

        let mut b = BalanceStore::new();
        b.mint("seal1carol", 3_000).unwrap();
        b.mint("seal1alice", 1_000).unwrap();
        b.mint("seal1bob", 2_000).unwrap();

        assert_eq!(a.state_root_hash(), b.state_root_hash());
    }

    #[test]
    fn state_root_hash_changes_on_balance_diff() {
        let mut a = BalanceStore::new();
        a.mint("seal1alice", 1_000).unwrap();
        let h_before = a.state_root_hash();
        a.mint("seal1alice", 1).unwrap();
        assert_ne!(h_before, a.state_root_hash());
    }

    #[test]
    fn state_root_hash_changes_on_new_account() {
        let mut a = BalanceStore::new();
        a.mint("seal1alice", 1_000).unwrap();
        let h_before = a.state_root_hash();
        a.mint("seal1bob", 1).unwrap();
        assert_ne!(h_before, a.state_root_hash());
    }

    #[test]
    fn state_root_hash_distinguishes_addresses() {
        let mut a = BalanceStore::new();
        a.mint("seal1alice", 1_000).unwrap();

        let mut b = BalanceStore::new();
        b.mint("seal1bob", 1_000).unwrap();

        assert_ne!(a.state_root_hash(), b.state_root_hash());
    }

    #[test]
    fn state_root_hash_distinguishes_available_vs_staked() {
        let mut a = BalanceStore::new();
        a.mint("seal1alice", 1_000).unwrap();
        let h_all_available = a.state_root_hash();

        let mut b = BalanceStore::new();
        b.mint("seal1alice", 1_000).unwrap();
        b.update("seal1alice", |bal| bal.stake(500)).unwrap();
        assert_ne!(h_all_available, b.state_root_hash());
    }

    // ── Cache invalidation tests ──────────────────────────────

    #[test]
    fn root_cache_returns_same_value_on_repeated_calls() {
        let mut store = BalanceStore::new();
        store.mint("seal1alice", 1_000).unwrap();
        let h1 = store.state_root_hash();
        let h2 = store.state_root_hash();
        let h3 = store.state_root_hash();
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }

    #[test]
    fn root_cache_invalidates_on_mint() {
        let mut store = BalanceStore::new();
        store.mint("seal1alice", 1_000).unwrap();
        let h_before = store.state_root_hash();
        store.mint("seal1bob", 500).unwrap();
        assert_ne!(h_before, store.state_root_hash());
    }

    #[test]
    fn root_cache_invalidates_on_burn() {
        let mut store = BalanceStore::new();
        store.mint("seal1alice", 1_000).unwrap();
        let h_before = store.state_root_hash();
        store.burn("seal1alice", 100).unwrap();
        assert_ne!(h_before, store.state_root_hash());
    }

    #[test]
    fn root_cache_invalidates_on_transfer() {
        let mut store = BalanceStore::new();
        store.mint("seal1alice", 1_000).unwrap();
        store.mint("seal1bob", 0).unwrap();
        let h_before = store.state_root_hash();
        store.transfer("seal1alice", "seal1bob", 100).unwrap();
        assert_ne!(h_before, store.state_root_hash());
    }

    /// `snapshot_dump` returns sorted-by-key raw HAMT leaves.
    /// The state-sync chunker is order-preserving, so this routine
    /// must impose a deterministic byte-wise key order or two
    /// nodes serializing the same state will produce different
    /// manifest hashes.
    #[test]
    fn snapshot_dump_is_lexicographically_sorted() {
        let mut store = BalanceStore::new();
        // Mint in an order that's definitely NOT lexicographic so a
        // bug that just returned HAMT-iter order would be caught.
        store.mint("seal1charlie", 300).unwrap();
        store.mint("seal1alice", 100).unwrap();
        store.mint("seal1bob", 200).unwrap();
        let dump = store.snapshot_dump();
        assert_eq!(dump.len(), 3);
        let keys: Vec<&[u8]> = dump.iter().map(|(k, _)| k.as_slice()).collect();
        assert_eq!(
            keys,
            vec![&b"seal1alice"[..], &b"seal1bob"[..], &b"seal1charlie"[..]]
        );
        // Each value must round-trip through decode_balance.
        for (_, v) in &dump {
            let bal = BalanceStore::decode_balance(v);
            assert!(bal.available > 0);
        }
    }

    /// `snapshot_dump` of an empty store yields an empty vec — the
    /// chunker handles this case (no chunks emitted).
    #[test]
    fn snapshot_dump_empty_store() {
        let store = BalanceStore::new();
        assert!(store.snapshot_dump().is_empty());
    }

    /// `restore_from_snapshot` is the inverse of `snapshot_dump` —
    /// dump → restore must yield a store whose state_root and
    /// per-account balances match the original. This is the
    /// load-bearing invariant for the late-joiner bootstrap path
    /// (A2d).
    #[test]
    fn snapshot_dump_then_restore_round_trip() {
        let mut original = BalanceStore::new();
        original.mint("seal1alice", 1_000).unwrap();
        original.mint("seal1bob", 2_500).unwrap();
        // Stake some of bob's balance so the encoded record has a
        // non-zero `staked` field too.
        original.update("seal1bob", |b| b.stake(500)).unwrap();
        original.mint("seal1carol", 3_000).unwrap();

        let dump = original.snapshot_dump();
        let restored = BalanceStore::restore_from_snapshot(dump).unwrap();

        // State roots must match — same HAMT contents ⇒ same root.
        assert_eq!(original.state_root_hash(), restored.state_root_hash());
        // Total supply matches (available + staked summed).
        assert_eq!(original.total_supply(), restored.total_supply());
        // Per-account balances match.
        assert_eq!(original.get("seal1alice"), restored.get("seal1alice"));
        assert_eq!(original.get("seal1bob"), restored.get("seal1bob"));
        assert_eq!(original.get("seal1carol"), restored.get("seal1carol"));
    }

    /// Restoring from a stream that includes a malformed bincode
    /// blob fails cleanly rather than panicking.
    #[test]
    fn snapshot_restore_rejects_malformed_bincode() {
        let bad = vec![(b"seal1eve".to_vec(), vec![0xff, 0xee])];
        let err = BalanceStore::restore_from_snapshot(bad).unwrap_err();
        assert!(err.contains("malformed bincode"));
    }

    /// Restoring an empty stream yields an empty store — useful
    /// for the late-joiner edge case where the peer's snapshot is
    /// genesis-equivalent.
    #[test]
    fn snapshot_restore_empty_yields_empty_store() {
        let restored = BalanceStore::restore_from_snapshot(vec![]).unwrap();
        assert_eq!(restored.account_count(), 0);
        assert_eq!(restored.total_supply(), 0);
    }

    /// Dust entries (available=0, staked=0) in a malicious / stale
    /// stream get filtered on restore — the encoder's
    /// `BalanceStore::put` strips them, but we don't trust the
    /// peer to have run the encoder.
    #[test]
    fn snapshot_restore_drops_dust_entries() {
        let zero_balance = bincode::serialize(&Balance::default()).unwrap();
        let restored =
            BalanceStore::restore_from_snapshot(vec![(b"seal1ghost".to_vec(), zero_balance)])
                .unwrap();
        assert_eq!(restored.account_count(), 0);
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
