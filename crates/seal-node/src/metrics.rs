//! Simple node metrics for monitoring.

use std::sync::atomic::{AtomicU64, Ordering};

/// Node-level metrics counters.
pub struct NodeMetrics {
    pub blocks_produced: AtomicU64,
    pub blocks_received: AtomicU64,
    pub blocks_verified: AtomicU64,
    pub blocks_rejected: AtomicU64,
    pub txs_submitted: AtomicU64,
    pub txs_accepted: AtomicU64,
    pub txs_rejected: AtomicU64,
    pub sql_queries: AtomicU64,
    pub sql_writes: AtomicU64,
    pub peers_connected: AtomicU64,
    pub fees_collected: AtomicU64,
    pub fees_burned: AtomicU64,
}

impl NodeMetrics {
    pub fn new() -> Self {
        NodeMetrics {
            blocks_produced: AtomicU64::new(0),
            blocks_received: AtomicU64::new(0),
            blocks_verified: AtomicU64::new(0),
            blocks_rejected: AtomicU64::new(0),
            txs_submitted: AtomicU64::new(0),
            txs_accepted: AtomicU64::new(0),
            txs_rejected: AtomicU64::new(0),
            sql_queries: AtomicU64::new(0),
            sql_writes: AtomicU64::new(0),
            peers_connected: AtomicU64::new(0),
            fees_collected: AtomicU64::new(0),
            fees_burned: AtomicU64::new(0),
        }
    }

    pub fn increment(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, counter: &AtomicU64, value: u64) {
        counter.fetch_add(value, Ordering::Relaxed);
    }

    /// Print a summary of all metrics.
    pub fn summary(&self) -> String {
        format!(
            "Blocks: produced={}, received={}, verified={}, rejected={}\n\
             Txs: submitted={}, accepted={}, rejected={}\n\
             SQL: queries={}, writes={}\n\
             Network: peers={}\n\
             Fees: collected={}, burned={}",
            self.blocks_produced.load(Ordering::Relaxed),
            self.blocks_received.load(Ordering::Relaxed),
            self.blocks_verified.load(Ordering::Relaxed),
            self.blocks_rejected.load(Ordering::Relaxed),
            self.txs_submitted.load(Ordering::Relaxed),
            self.txs_accepted.load(Ordering::Relaxed),
            self.txs_rejected.load(Ordering::Relaxed),
            self.sql_queries.load(Ordering::Relaxed),
            self.sql_writes.load(Ordering::Relaxed),
            self.peers_connected.load(Ordering::Relaxed),
            self.fees_collected.load(Ordering::Relaxed),
            self.fees_burned.load(Ordering::Relaxed),
        )
    }
}

impl Default for NodeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_increment() {
        let m = NodeMetrics::new();
        m.increment(&m.blocks_produced);
        m.increment(&m.blocks_produced);
        m.increment(&m.blocks_produced);
        assert_eq!(m.blocks_produced.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_metrics_add() {
        let m = NodeMetrics::new();
        m.add(&m.fees_collected, 1000);
        m.add(&m.fees_burned, 500);
        assert_eq!(m.fees_collected.load(Ordering::Relaxed), 1000);
        assert_eq!(m.fees_burned.load(Ordering::Relaxed), 500);
    }

    #[test]
    fn test_metrics_summary() {
        let m = NodeMetrics::new();
        m.increment(&m.blocks_produced);
        m.add(&m.txs_submitted, 10);
        let summary = m.summary();
        assert!(summary.contains("produced=1"));
        assert!(summary.contains("submitted=10"));
    }
}
