//! In-memory roster of recent state snapshots.
//!
//! A *snapshot* is a fixed `(height, epoch, state_root)` triple captured
//! at an epoch boundary. Late-joining validators (and explorer / wallet
//! clients reconstructing recent history) hit this roster first to pick
//! a base from which to fetch chunks via `seal_getSnapshotManifest` /
//! `seal_getSnapshotChunk` (Tier-1 #3 steps B and C, separate sub-tasks).
//!
//! This module is intentionally minimal: it owns a bounded ring of
//! `SnapshotMeta` entries, sorted by height (oldest first), with a
//! configurable cap. Capture is driven externally — `ConsensusRunner`
//! calls `record(...)` once per epoch boundary in `advance_slot`. We
//! deliberately do **not** persist this roster to disk: a node that
//! restarts repopulates its roster from the live chain after a few
//! epochs, and the snapshot fetch RPCs are a best-effort accelerator,
//! not a chain-of-record. Persistence would just add a recovery /
//! version-skew failure mode for no benefit.
//!
//! See `formal/README.md` for the matching invariants the late-joiner
//! bootstrap path (sub-task A2d) will rely on.

use seal_crypto::hash::Hash256;

/// One entry in the snapshot roster.
///
/// `tip_aggregate` is filled in by sub-task A2b
/// (`seal_getSnapshotManifest`) once the tip's Ringtail aggregate
/// signature is available. For A2a it's `None` — the listing surface
/// only commits to `(height, epoch, state_root, captured_at_unix_secs)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotMeta {
    pub height: u64,
    pub epoch: u64,
    pub state_root: Hash256,
    /// Wall-clock seconds since the Unix epoch at the moment the runner
    /// captured the snapshot. Useful for explorer UX; not load-bearing
    /// for consensus.
    pub captured_at_unix_secs: u64,
    /// Tip Ringtail aggregate (filled by A2b). `None` for A2a-only
    /// captures so the wire format doesn't lock in a forward-compat
    /// hole.
    pub tip_aggregate: Option<Hash256>,
}

/// Bounded roster of recent snapshots.
///
/// Entries are stored oldest-first. Inserting beyond `cap` evicts the
/// oldest entry. Inserts must be strictly height-monotonic — the
/// caller is the consensus runner, which only advances forward, so
/// any non-monotonic call is a programmer error and is rejected.
#[derive(Clone, Debug)]
pub struct SnapshotIndex {
    entries: Vec<SnapshotMeta>,
    cap: usize,
}

/// Default maximum number of snapshots retained in memory.
///
/// 32 ≈ a day of epoch-boundary captures at 32-slot epochs / 4 s slots /
/// (32 × 4) s = 128 s per epoch ⇒ ~675 epochs/day. We keep the most
/// recent 32 to give late joiners a few-hour rolling window without
/// burning RAM on long-lived hot validators. Operators can override
/// via `SnapshotIndex::with_cap`.
pub const DEFAULT_SNAPSHOT_CAP: usize = 32;

impl SnapshotIndex {
    /// Construct a roster with the default 32-entry cap.
    pub fn new() -> Self {
        Self::with_cap(DEFAULT_SNAPSHOT_CAP)
    }

    /// Construct a roster with a custom cap. A cap of zero disables
    /// the roster (every `record` is a no-op). A cap of `usize::MAX`
    /// turns the roster into archive mode — never evicts.
    pub fn with_cap(cap: usize) -> Self {
        Self {
            entries: Vec::with_capacity(cap.min(DEFAULT_SNAPSHOT_CAP * 4)),
            cap,
        }
    }

    /// Record a new snapshot. Strictly height-monotonic: a record with
    /// `height` not greater than the newest entry is dropped (returns
    /// `false`). On success returns `true`.
    pub fn record(&mut self, meta: SnapshotMeta) -> bool {
        if self.cap == 0 {
            return false;
        }
        if let Some(last) = self.entries.last() {
            if meta.height <= last.height {
                return false;
            }
        }
        self.entries.push(meta);
        if self.entries.len() > self.cap {
            let excess = self.entries.len() - self.cap;
            self.entries.drain(..excess);
        }
        true
    }

    /// Number of snapshots currently in the roster.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the roster is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Newest snapshot, if any.
    pub fn latest(&self) -> Option<&SnapshotMeta> {
        self.entries.last()
    }

    /// All snapshots, oldest first. The returned slice has the same
    /// lifetime as `&self`, so callers must clone if they want to
    /// outlive the borrow (`seal_listSnapshots` does just that).
    pub fn list(&self) -> &[SnapshotMeta] {
        &self.entries
    }

    /// Look up a specific snapshot by height. Linear scan over the
    /// bounded roster — `cap` is small (default 32), so this is fast
    /// enough that a sorted-bsearch isn't worth the complexity.
    pub fn find_by_height(&self, height: u64) -> Option<&SnapshotMeta> {
        self.entries.iter().find(|m| m.height == height)
    }

    /// Cap (max retained entries).
    pub fn cap(&self) -> usize {
        self.cap
    }
}

impl Default for SnapshotIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::hash::sha3_256;

    fn meta_at(height: u64, epoch: u64) -> SnapshotMeta {
        SnapshotMeta {
            height,
            epoch,
            state_root: sha3_256(&height.to_le_bytes()),
            captured_at_unix_secs: 1_700_000_000 + height,
            tip_aggregate: None,
        }
    }

    #[test]
    fn empty_index_has_no_latest() {
        let idx = SnapshotIndex::new();
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
        assert!(idx.latest().is_none());
        assert!(idx.list().is_empty());
    }

    #[test]
    fn record_appends_in_order() {
        let mut idx = SnapshotIndex::with_cap(8);
        for h in 1..=4 {
            assert!(idx.record(meta_at(h * 32, h)));
        }
        assert_eq!(idx.len(), 4);
        assert_eq!(idx.latest().unwrap().height, 128);
        assert_eq!(idx.list().first().unwrap().height, 32);
        assert_eq!(idx.list().last().unwrap().height, 128);
    }

    #[test]
    fn cap_evicts_oldest() {
        let mut idx = SnapshotIndex::with_cap(3);
        for h in 1..=5 {
            assert!(idx.record(meta_at(h * 32, h)));
        }
        assert_eq!(idx.len(), 3);
        let kept_heights: Vec<u64> = idx.list().iter().map(|m| m.height).collect();
        assert_eq!(kept_heights, vec![3 * 32, 4 * 32, 5 * 32]);
    }

    #[test]
    fn non_monotonic_record_is_rejected() {
        let mut idx = SnapshotIndex::with_cap(8);
        assert!(idx.record(meta_at(64, 2)));
        // Same height — must be rejected.
        assert!(!idx.record(meta_at(64, 2)));
        // Lower height — also rejected.
        assert!(!idx.record(meta_at(32, 1)));
        // Forward — accepted again.
        assert!(idx.record(meta_at(96, 3)));
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn zero_cap_disables_recording() {
        let mut idx = SnapshotIndex::with_cap(0);
        assert!(!idx.record(meta_at(64, 2)));
        assert!(idx.is_empty());
    }

    #[test]
    fn find_by_height_hits_and_misses() {
        let mut idx = SnapshotIndex::with_cap(8);
        for h in 1..=4 {
            idx.record(meta_at(h * 32, h));
        }
        assert!(idx.find_by_height(32).is_some());
        assert_eq!(idx.find_by_height(96).unwrap().epoch, 3);
        // Missing.
        assert!(idx.find_by_height(33).is_none());
        // Beyond the latest.
        assert!(idx.find_by_height(1024).is_none());
    }

    #[test]
    fn default_cap_matches_constant() {
        let idx = SnapshotIndex::new();
        assert_eq!(idx.cap(), DEFAULT_SNAPSHOT_CAP);
    }

    #[test]
    fn snapshot_meta_eq_uses_all_fields() {
        let a = meta_at(64, 2);
        let mut b = a.clone();
        assert_eq!(a, b);
        b.tip_aggregate = Some(sha3_256(b"agg"));
        assert_ne!(a, b);
    }
}
