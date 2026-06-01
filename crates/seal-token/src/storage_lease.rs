//! Storage lease tracking for the right-to-be-forgotten (#STORAGE-FORGET).
//!
//! Every public/shared table has a storage lease paid in SEAL tokens.
//! When the lease expires, validators prune the table's rows and salts
//! from active state. The Merkle roots in old blocks remain but become
//! opaque (no data, no salts, no reconstruction possible).
//!
//! Serving data from an expired lease is a slashable offense unless
//! a governance vote grants an exemption (e.g., legal/regulatory holds).
//!
//! See QA.md #STORAGE-FORGET for the full design.

use crate::error::TokenError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A storage lease for a single table.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageLease {
    /// Fully qualified table name (e.g., "my_app.seal:users").
    pub table: String,
    /// Owner's Seal address (pays the lease).
    pub owner: Vec<u8>,
    /// Lease is paid through this timestamp (microseconds since epoch).
    pub paid_through: u64,
    /// Current row count (updated on each write).
    pub row_count: u64,
    /// Current byte size of the table data.
    pub byte_size: u64,
    /// Per-byte-epoch rate in micro-SEAL (governance-adjustable).
    pub rate: u64,
    /// Whether a governance exemption prevents pruning even after expiry.
    pub governance_hold: bool,
}

/// Grace period before expired leases are pruned (in microseconds).
/// Default: 30 days. Adjustable by governance.
pub const DEFAULT_GRACE_PERIOD_US: u64 = 30 * 24 * 3600 * 1_000_000;

impl StorageLease {
    /// Create a new lease with the given parameters.
    pub fn new(table: String, owner: Vec<u8>, rate: u64) -> Self {
        Self {
            table,
            owner,
            paid_through: 0,
            row_count: 0,
            byte_size: 0,
            rate,
            governance_hold: false,
        }
    }

    /// Extend the lease by paying for `duration_us` microseconds of storage.
    /// Returns the cost in micro-SEAL.
    pub fn extend(&mut self, duration_us: u64) -> Result<u64, TokenError> {
        let cost = self.compute_cost(duration_us)?;
        self.paid_through = self
            .paid_through
            .checked_add(duration_us)
            .ok_or(TokenError::Overflow)?;
        Ok(cost)
    }

    /// Compute the cost for a given duration based on current byte_size and rate.
    /// cost = byte_size * rate * (duration_us / EPOCH_US)
    /// Simplified: cost = byte_size * rate * duration_us / 1_000_000
    pub fn compute_cost(&self, duration_us: u64) -> Result<u64, TokenError> {
        // Avoid overflow: (byte_size * rate) checked, then * duration / divisor
        let base = self
            .byte_size
            .checked_mul(self.rate)
            .ok_or(TokenError::Overflow)?;
        // Scale by duration (in seconds for simplicity)
        let duration_s = duration_us / 1_000_000;
        base.checked_mul(duration_s.max(1))
            .ok_or(TokenError::Overflow)
    }

    /// Check if the lease is expired at the given timestamp.
    pub fn is_expired(&self, now_us: u64) -> bool {
        now_us > self.paid_through
    }

    /// Check if the lease is past the grace period and should be pruned.
    pub fn should_prune(&self, now_us: u64, grace_period_us: u64) -> bool {
        if self.governance_hold {
            return false;
        }
        now_us > self.paid_through.saturating_add(grace_period_us)
    }

    /// Update the table size metrics.
    pub fn update_size(&mut self, row_count: u64, byte_size: u64) {
        self.row_count = row_count;
        self.byte_size = byte_size;
    }
}

/// Manages storage leases for all tables.
#[derive(Debug, Default)]
pub struct LeaseManager {
    /// Table name → StorageLease.
    leases: HashMap<String, StorageLease>,
    /// Grace period in microseconds (governance-adjustable).
    pub grace_period_us: u64,
}

impl LeaseManager {
    pub fn new() -> Self {
        Self {
            leases: HashMap::new(),
            grace_period_us: DEFAULT_GRACE_PERIOD_US,
        }
    }

    /// Register a new lease for a table.
    pub fn register(&mut self, lease: StorageLease) {
        self.leases.insert(lease.table.clone(), lease);
    }

    /// Get a lease by table name.
    pub fn get(&self, table: &str) -> Option<&StorageLease> {
        self.leases.get(table)
    }

    /// Get a mutable lease by table name.
    pub fn get_mut(&mut self, table: &str) -> Option<&mut StorageLease> {
        self.leases.get_mut(table)
    }

    /// Return all tables whose leases are past the grace period and should be pruned.
    pub fn tables_to_prune(&self, now_us: u64) -> Vec<String> {
        self.leases
            .iter()
            .filter(|(_, lease)| lease.should_prune(now_us, self.grace_period_us))
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Remove a lease (after pruning the table data).
    pub fn remove(&mut self, table: &str) -> Option<StorageLease> {
        self.leases.remove(table)
    }

    /// Number of active leases.
    pub fn count(&self) -> usize {
        self.leases.len()
    }

    /// Snapshot of every active lease, sorted by table name so a
    /// polling client can diff a previous snapshot. Used by the
    /// `seal_listLeases` RPC for the explorer Storage panel and
    /// operator dashboards.
    pub fn all_leases(&self) -> Vec<&StorageLease> {
        let mut out: Vec<&StorageLease> = self.leases.values().collect();
        out.sort_by(|a, b| a.table.cmp(&b.table));
        out
    }

    /// Snapshot of every lease whose owner derives to
    /// `address_hash` (the 32-byte SHA3-256 of the owner's
    /// ML-DSA verifying-key). Sorted lexicographically by table
    /// name — same diff-stable order as `all_leases`. Empty Vec
    /// for owners with no leases. Backs `seal_listLeasesByOwner`.
    /// The hash form is what's testnet/mainnet-agnostic: both
    /// `seal1...` and `sealt1...` encodings of the same key
    /// produce identical bytes here, so a wallet doesn't need
    /// to know which network the lease was registered on.
    pub fn leases_by_owner_hash(&self, address_hash: &[u8; 32]) -> Vec<&StorageLease> {
        let mut out: Vec<&StorageLease> = self
            .leases
            .values()
            .filter(|l| {
                // The lease stores the raw verifying-key bytes;
                // a bech32m address encodes SHA3(verifying_key).
                // Hash the lease's pubkey and compare.
                let h = seal_crypto::sha3_256(&l.owner);
                h.0 == *address_hash
            })
            .collect();
        out.sort_by(|a, b| a.table.cmp(&b.table));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_creation() {
        let lease = StorageLease::new("app.seal:users".into(), vec![1; 32], 100);
        assert_eq!(lease.paid_through, 0);
        assert_eq!(lease.rate, 100);
        assert!(!lease.governance_hold);
    }

    #[test]
    fn test_lease_extend() {
        let mut lease = StorageLease::new("app.seal:users".into(), vec![1; 32], 1);
        lease.update_size(100, 10_000);
        let cost = lease.extend(30 * 24 * 3600 * 1_000_000).unwrap(); // 30 days
        assert!(cost > 0);
        assert!(lease.paid_through > 0);
    }

    #[test]
    fn test_lease_expiry() {
        let mut lease = StorageLease::new("app.seal:users".into(), vec![1; 32], 1);
        lease.paid_through = 1_000_000; // 1 second

        assert!(!lease.is_expired(500_000));
        assert!(lease.is_expired(2_000_000));
    }

    #[test]
    fn test_lease_prune_with_grace() {
        let mut lease = StorageLease::new("app.seal:users".into(), vec![1; 32], 1);
        lease.paid_through = 1_000_000;
        let grace = 5_000_000; // 5 seconds

        // Expired but within grace period
        assert!(!lease.should_prune(3_000_000, grace));
        // Past grace period
        assert!(lease.should_prune(7_000_000, grace));
    }

    #[test]
    fn test_governance_hold_prevents_prune() {
        let mut lease = StorageLease::new("app.seal:users".into(), vec![1; 32], 1);
        lease.paid_through = 1_000_000;
        lease.governance_hold = true;

        // Even way past grace, governance hold prevents pruning
        assert!(!lease.should_prune(999_000_000, 5_000_000));
    }

    #[test]
    fn test_lease_manager() {
        let mut mgr = LeaseManager::new();
        mgr.grace_period_us = 5_000_000;

        let mut lease1 = StorageLease::new("app1:t1".into(), vec![1; 32], 1);
        lease1.paid_through = 100_000_000; // far future
        let mut lease2 = StorageLease::new("app2:t2".into(), vec![2; 32], 1);
        lease2.paid_through = 1_000_000; // already expired

        mgr.register(lease1);
        mgr.register(lease2);

        assert_eq!(mgr.count(), 2);

        // At time 20M: lease2 is past grace (1M + 5M < 20M), lease1 still active (100M)
        let to_prune = mgr.tables_to_prune(20_000_000);
        assert_eq!(to_prune.len(), 1);
        assert_eq!(to_prune[0], "app2:t2");
    }

    #[test]
    fn test_lease_manager_all_leases_sorted() {
        let mut mgr = LeaseManager::new();
        // Insert in non-alphabetical order — accessor must sort.
        mgr.register(StorageLease::new("zoo:cats".into(), vec![1; 32], 1));
        mgr.register(StorageLease::new("alpha:dogs".into(), vec![2; 32], 1));
        mgr.register(StorageLease::new("middle:fish".into(), vec![3; 32], 1));
        let all = mgr.all_leases();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].table, "alpha:dogs");
        assert_eq!(all[1].table, "middle:fish");
        assert_eq!(all[2].table, "zoo:cats");
        // Empty manager → empty Vec, no panic.
        let empty = LeaseManager::new();
        assert!(empty.all_leases().is_empty());
    }

    #[test]
    fn test_lease_manager_leases_by_owner_hash() {
        let mut mgr = LeaseManager::new();
        // Two distinct owner-key fixtures. SHA3-256 of each gives
        // the address-hash that the RPC compares against.
        let alice_key = vec![1u8; 32];
        let bob_key = vec![2u8; 32];
        let alice_hash = seal_crypto::sha3_256(&alice_key).0;
        let bob_hash = seal_crypto::sha3_256(&bob_key).0;
        // Alice owns two tables, bob owns one. Insert in non-
        // alphabetical order — accessor must sort by table name.
        mgr.register(StorageLease::new("zoo:cats".into(), alice_key.clone(), 1));
        mgr.register(StorageLease::new("alpha:dogs".into(), alice_key.clone(), 1));
        mgr.register(StorageLease::new("middle:fish".into(), bob_key.clone(), 1));
        // Alice: ["alpha:dogs", "zoo:cats"], sorted.
        let alice: Vec<&str> = mgr
            .leases_by_owner_hash(&alice_hash)
            .iter()
            .map(|l| l.table.as_str())
            .collect();
        assert_eq!(alice, vec!["alpha:dogs", "zoo:cats"]);
        // Bob: ["middle:fish"].
        let bob: Vec<&str> = mgr
            .leases_by_owner_hash(&bob_hash)
            .iter()
            .map(|l| l.table.as_str())
            .collect();
        assert_eq!(bob, vec!["middle:fish"]);
        // Unknown owner-hash: empty Vec, not error.
        let unknown_hash = [0u8; 32];
        assert!(mgr.leases_by_owner_hash(&unknown_hash).is_empty());
    }
}
