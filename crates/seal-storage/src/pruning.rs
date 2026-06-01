//! State pruning for Seal DAO nodes.
//!
//! Full nodes keep only the last N state snapshots (Merkle roots).
//! Older Merkle tree nodes not reachable from any retained root are pruned.
//! Archive nodes disable pruning and keep all history.
//!
//! # Strategy
//!
//! ```text
//! Height 1    Height 2    Height 3    Height 4    Height 5
//!   root1       root2       root3       root4       root5
//!    │           │           │           │           │
//!    ├── a       ├── a'      ├── a''     ├── a''     ├── a'''
//!    ├── b       ├── b       ├── b       ├── b'      ├── b'
//!    └── c       └── c       └── c       └── c       └── c'
//!
//! With retain_count=2, after height 5:
//!   - Roots 4,5 retained
//!   - Nodes only reachable from roots 1,2,3 are pruned
//!   - Shared nodes (b' reachable from both root4 and root5) kept
//! ```
//!
//! # How It Works
//!
//! 1. Mark: traverse all retained roots, mark reachable node hashes
//! 2. Sweep: delete all nodes not in the marked set
//!
//! This is a classic mark-and-sweep GC adapted for content-addressed storage.

use seal_crypto::hash::Hash256;
use std::collections::HashSet;

/// Pruning configuration.
#[derive(Clone, Debug)]
pub struct PruningConfig {
    /// Number of recent state roots to retain.
    /// Set to 0 or usize::MAX for archive mode (no pruning).
    pub retain_count: usize,
    /// Minimum height gap between pruning runs.
    pub prune_interval: u64,
    /// Whether this node is an archive node (never prunes).
    pub archive_mode: bool,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            retain_count: 256,  // keep last 256 state snapshots (~1 epoch)
            prune_interval: 64, // prune every 64 blocks
            archive_mode: false,
        }
    }
}

impl PruningConfig {
    /// Create an archive node config (never prunes).
    pub fn archive() -> Self {
        Self {
            retain_count: usize::MAX,
            prune_interval: u64::MAX,
            archive_mode: true,
        }
    }

    /// Create a light pruning config (keep last N roots).
    pub fn light(retain_count: usize) -> Self {
        Self {
            retain_count,
            prune_interval: retain_count as u64 / 4,
            archive_mode: false,
        }
    }
}

/// Tracks state roots for pruning decisions.
#[derive(Debug)]
pub struct PruningManager {
    config: PruningConfig,
    /// Retained state roots (most recent last).
    retained_roots: Vec<(u64, Hash256)>,
    /// Height of last pruning run.
    last_prune_height: u64,
    /// Total nodes pruned (cumulative).
    total_pruned: u64,
}

impl PruningManager {
    pub fn new(config: PruningConfig) -> Self {
        Self {
            config,
            retained_roots: Vec::new(),
            last_prune_height: 0,
            total_pruned: 0,
        }
    }

    /// Record a new state root at a given height.
    pub fn add_state_root(&mut self, height: u64, root: Hash256) {
        self.retained_roots.push((height, root));

        // Trim to retain_count
        if !self.config.archive_mode && self.retained_roots.len() > self.config.retain_count {
            let excess = self.retained_roots.len() - self.config.retain_count;
            self.retained_roots.drain(..excess);
        }
    }

    /// Check if pruning should run at this height.
    pub fn should_prune(&self, current_height: u64) -> bool {
        if self.config.archive_mode {
            return false;
        }
        // Need at least retain_count roots before pruning makes sense
        if self.retained_roots.len() < self.config.retain_count {
            return false;
        }
        current_height.saturating_sub(self.last_prune_height) >= self.config.prune_interval
    }

    /// Get the set of roots that must be retained.
    pub fn retained_roots(&self) -> &[(u64, Hash256)] {
        &self.retained_roots
    }

    /// Get the oldest retained height.
    pub fn oldest_retained_height(&self) -> Option<u64> {
        self.retained_roots.first().map(|(h, _)| *h)
    }

    /// Get the newest retained height.
    pub fn newest_retained_height(&self) -> Option<u64> {
        self.retained_roots.last().map(|(h, _)| *h)
    }

    /// Perform a mark phase: collect all node hashes reachable from retained roots.
    ///
    /// `traverse_fn` is called for each retained root and should return
    /// all node hashes reachable from that root.
    pub fn mark_reachable<F>(&self, mut traverse_fn: F) -> HashSet<Hash256>
    where
        F: FnMut(&Hash256) -> Vec<Hash256>,
    {
        let mut reachable = HashSet::new();

        for (_, root) in &self.retained_roots {
            if reachable.contains(root) {
                continue; // already traversed (shared subtree)
            }
            let nodes = traverse_fn(root);
            reachable.insert(*root);
            for node_hash in nodes {
                reachable.insert(node_hash);
            }
        }

        reachable
    }

    /// Record that pruning was performed.
    pub fn record_prune(&mut self, height: u64, nodes_pruned: u64) {
        self.last_prune_height = height;
        self.total_pruned = self.total_pruned.saturating_add(nodes_pruned);
    }

    /// Total nodes pruned since creation.
    pub fn total_pruned(&self) -> u64 {
        self.total_pruned
    }

    /// Number of currently retained roots.
    pub fn retained_count(&self) -> usize {
        self.retained_roots.len()
    }

    /// Whether this manager is in archive mode.
    pub fn is_archive(&self) -> bool {
        self.config.archive_mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::hash::sha3_256;

    fn root_at(height: u64) -> Hash256 {
        sha3_256(&height.to_le_bytes())
    }

    #[test]
    fn test_default_config() {
        let config = PruningConfig::default();
        assert_eq!(config.retain_count, 256);
        assert!(!config.archive_mode);
    }

    #[test]
    fn test_archive_config() {
        let config = PruningConfig::archive();
        assert!(config.archive_mode);
        assert_eq!(config.retain_count, usize::MAX);
    }

    #[test]
    fn test_add_state_root() {
        let mut mgr = PruningManager::new(PruningConfig::light(3));

        for h in 1..=5 {
            mgr.add_state_root(h, root_at(h));
        }

        // Only last 3 retained
        assert_eq!(mgr.retained_count(), 3);
        assert_eq!(mgr.oldest_retained_height(), Some(3));
        assert_eq!(mgr.newest_retained_height(), Some(5));
    }

    #[test]
    fn test_archive_mode_retains_all() {
        let mut mgr = PruningManager::new(PruningConfig::archive());

        for h in 1..=100 {
            mgr.add_state_root(h, root_at(h));
        }

        assert_eq!(mgr.retained_count(), 100);
        assert_eq!(mgr.oldest_retained_height(), Some(1));
    }

    #[test]
    fn test_should_prune() {
        let mut mgr = PruningManager::new(PruningConfig {
            retain_count: 2,
            prune_interval: 5,
            archive_mode: false,
        });

        for h in 1..=10 {
            mgr.add_state_root(h, root_at(h));
        }

        // Should prune: we have excess roots and haven't pruned yet
        assert!(mgr.should_prune(10));

        // Record pruning at height 10
        mgr.record_prune(10, 50);
        assert_eq!(mgr.total_pruned(), 50);

        // Not enough gap since last prune
        assert!(!mgr.should_prune(12));

        // Enough gap
        assert!(mgr.should_prune(15));
    }

    #[test]
    fn test_archive_never_prunes() {
        let mut mgr = PruningManager::new(PruningConfig::archive());

        for h in 1..=1000 {
            mgr.add_state_root(h, root_at(h));
        }

        assert!(!mgr.should_prune(1000));
        assert!(mgr.is_archive());
    }

    #[test]
    fn test_mark_reachable() {
        let mut mgr = PruningManager::new(PruningConfig::light(2));

        let root1 = sha3_256(b"root1");
        let root2 = sha3_256(b"root2");
        mgr.add_state_root(1, root1);
        mgr.add_state_root(2, root2);

        // Simulate traversal: each root reaches 3 nodes
        let node_a = sha3_256(b"a");
        let node_b = sha3_256(b"b"); // shared between both roots
        let node_c = sha3_256(b"c");
        let node_d = sha3_256(b"d");

        let reachable = mgr.mark_reachable(|root| {
            if *root == root1 {
                vec![node_a, node_b]
            } else if *root == root2 {
                vec![node_b, node_c, node_d] // node_b is shared
            } else {
                vec![]
            }
        });

        // root1, root2, a, b, c, d = 6 reachable
        assert!(reachable.contains(&root1));
        assert!(reachable.contains(&root2));
        assert!(reachable.contains(&node_a));
        assert!(reachable.contains(&node_b));
        assert!(reachable.contains(&node_c));
        assert!(reachable.contains(&node_d));
        assert_eq!(reachable.len(), 6);
    }

    #[test]
    fn test_pruning_stats() {
        let mut mgr = PruningManager::new(PruningConfig::default());
        assert_eq!(mgr.total_pruned(), 0);

        mgr.record_prune(100, 500);
        assert_eq!(mgr.total_pruned(), 500);

        mgr.record_prune(200, 300);
        assert_eq!(mgr.total_pruned(), 800);
    }

    #[test]
    fn test_light_config() {
        let config = PruningConfig::light(100);
        assert_eq!(config.retain_count, 100);
        assert_eq!(config.prune_interval, 25);
        assert!(!config.archive_mode);
    }
}
