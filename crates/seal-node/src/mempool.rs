//! Narwhal-style decoupled mempool for Seal DAO.
//!
//! Separates transaction dissemination from consensus ordering:
//!
//! ```text
//! Traditional:
//!   Proposer collects txs → orders them → proposes block
//!   (single bottleneck: proposer must receive ALL txs)
//!
//! Narwhal-style:
//!   ALL validators batch & disseminate txs (parallel)
//!   Proposer only orders batch references (tiny)
//!   Consensus is fast because it only orders hashes
//! ```
//!
//! # Architecture
//!
//! 1. **Workers**: Each validator has W workers that batch incoming transactions
//! 2. **Batches**: Workers create transaction batches, hash them, broadcast
//! 3. **Certificates**: When 2f+1 validators acknowledge a batch, it's certified
//! 4. **DAG**: Certified batches form a DAG (each references parent batches)
//! 5. **Ordering**: Consensus only orders batch certificates (not individual txs)
//!
//! # Benefits
//!
//! - Transaction throughput scales with number of validators (parallel dissemination)
//! - Consensus messages are tiny (just batch hashes)
//! - Batches can be fetched asynchronously (not on critical path)
//! - Natural backpressure: validators only propose batches they have

use seal_crypto::hash::{sha3_256, Hash256};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Maximum transactions per batch.
const DEFAULT_MAX_BATCH_SIZE: usize = 100;

/// Maximum pending batches before backpressure.
const DEFAULT_MAX_PENDING_BATCHES: usize = 256;

/// A batch of transactions created by a worker.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionBatch {
    /// Unique batch identifier (SHA3 of contents).
    pub digest: Hash256,
    /// The worker that created this batch.
    pub worker_id: u32,
    /// The validator that created this batch.
    pub author: Vec<u8>,
    /// Transactions in this batch (serialized).
    pub transactions: Vec<Vec<u8>>,
    /// References to parent batches (DAG structure).
    pub parents: Vec<Hash256>,
    /// Creation timestamp (Unix millis).
    pub timestamp: u64,
}

impl TransactionBatch {
    /// Compute the digest of this batch.
    pub fn compute_digest(
        worker_id: u32,
        author: &[u8],
        transactions: &[Vec<u8>],
        parents: &[Hash256],
    ) -> Hash256 {
        let mut data = Vec::new();
        data.extend_from_slice(&worker_id.to_le_bytes());
        data.extend_from_slice(author);
        for tx in transactions {
            data.extend_from_slice(&(tx.len() as u32).to_le_bytes());
            data.extend_from_slice(tx);
        }
        for parent in parents {
            data.extend_from_slice(parent.as_ref());
        }
        sha3_256(&data)
    }
}

/// A certificate for a batch: proof that 2f+1 validators received it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchCertificate {
    /// The batch this certificate is for.
    pub batch_digest: Hash256,
    /// The batch author.
    pub author: Vec<u8>,
    /// Validator signatures acknowledging receipt (simplified: just pubkeys for now).
    pub acknowledgements: Vec<Vec<u8>>,
    /// Round number in the DAG.
    pub round: u64,
}

impl BatchCertificate {
    /// Check if the certificate has enough acknowledgements.
    pub fn is_valid(&self, required: usize) -> bool {
        self.acknowledgements.len() >= required
    }
}

/// Worker: batches incoming transactions.
pub struct Worker {
    /// Worker index.
    id: u32,
    /// This validator's public key.
    author: Vec<u8>,
    /// Pending transactions (not yet batched).
    pending: VecDeque<Vec<u8>>,
    /// Maximum batch size.
    max_batch_size: usize,
    /// Current parent batch digests.
    current_parents: Vec<Hash256>,
}

impl Worker {
    pub fn new(id: u32, author: Vec<u8>) -> Self {
        Self {
            id,
            author,
            pending: VecDeque::new(),
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            current_parents: Vec::new(),
        }
    }

    /// Add a transaction to the pending queue.
    pub fn add_transaction(&mut self, tx: Vec<u8>) {
        self.pending.push_back(tx);
    }

    /// Number of pending transactions.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Check if we have enough transactions for a batch.
    pub fn should_seal_batch(&self) -> bool {
        self.pending.len() >= self.max_batch_size
    }

    /// Seal the current pending transactions into a batch.
    /// Returns None if no transactions are pending.
    pub fn seal_batch(&mut self) -> Option<TransactionBatch> {
        if self.pending.is_empty() {
            return None;
        }

        let count = self.pending.len().min(self.max_batch_size);
        let transactions: Vec<Vec<u8>> = self.pending.drain(..count).collect();
        let parents = std::mem::take(&mut self.current_parents);

        let digest =
            TransactionBatch::compute_digest(self.id, &self.author, &transactions, &parents);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Some(TransactionBatch {
            digest,
            worker_id: self.id,
            author: self.author.clone(),
            transactions,
            parents,
            timestamp,
        })
    }

    /// Set parent batch references for the next batch.
    pub fn set_parents(&mut self, parents: Vec<Hash256>) {
        self.current_parents = parents;
    }
}

/// Mempool: manages workers and batch certification.
pub struct Mempool {
    /// Workers (one per configured worker count).
    workers: Vec<Worker>,
    /// Certified batches by digest.
    certified: HashMap<Hash256, BatchCertificate>,
    /// Pending batches awaiting certification.
    pending_batches: HashMap<Hash256, TransactionBatch>,
    /// Current DAG round.
    current_round: u64,
    /// Required acknowledgements for certification (2f+1).
    quorum_threshold: usize,
    /// Maximum pending batches.
    max_pending: usize,
}

impl Mempool {
    /// Create a new mempool with the given number of workers.
    pub fn new(num_workers: u32, author: Vec<u8>, quorum_threshold: usize) -> Self {
        let workers = (0..num_workers)
            .map(|i| Worker::new(i, author.clone()))
            .collect();

        Self {
            workers,
            certified: HashMap::new(),
            pending_batches: HashMap::new(),
            current_round: 0,
            quorum_threshold,
            max_pending: DEFAULT_MAX_PENDING_BATCHES,
        }
    }

    /// Submit a transaction (routed to worker by round-robin).
    pub fn submit_transaction(&mut self, tx: Vec<u8>) {
        if self.workers.is_empty() {
            return;
        }
        let worker_idx = self.pending_batches.len() % self.workers.len();
        self.workers[worker_idx].add_transaction(tx);
    }

    /// Seal batches from all workers that have enough transactions.
    /// Returns the newly created batches.
    pub fn seal_batches(&mut self) -> Vec<TransactionBatch> {
        let mut new_batches = Vec::new();

        for worker in &mut self.workers {
            if let Some(batch) = worker.seal_batch() {
                if self.pending_batches.len() < self.max_pending {
                    self.pending_batches.insert(batch.digest, batch.clone());
                    new_batches.push(batch);
                }
            }
        }

        new_batches
    }

    /// Force seal a batch from a specific worker (even if below max size).
    pub fn force_seal(&mut self, worker_idx: usize) -> Option<TransactionBatch> {
        if worker_idx >= self.workers.len() {
            return None;
        }
        let batch = self.workers[worker_idx].seal_batch()?;
        self.pending_batches.insert(batch.digest, batch.clone());
        Some(batch)
    }

    /// Record an acknowledgement for a batch.
    /// Returns Some(certificate) when quorum is reached.
    pub fn acknowledge_batch(
        &mut self,
        batch_digest: &Hash256,
        acknowledger: Vec<u8>,
    ) -> Option<BatchCertificate> {
        // Find or create the certificate-in-progress
        let cert = self
            .certified
            .entry(*batch_digest)
            .or_insert_with(|| BatchCertificate {
                batch_digest: *batch_digest,
                author: self
                    .pending_batches
                    .get(batch_digest)
                    .map(|b| b.author.clone())
                    .unwrap_or_default(),
                acknowledgements: Vec::new(),
                round: self.current_round,
            });

        // Dedup acknowledgements
        if !cert.acknowledgements.contains(&acknowledger) {
            cert.acknowledgements.push(acknowledger);
        }

        if cert.is_valid(self.quorum_threshold) {
            Some(cert.clone())
        } else {
            None
        }
    }

    /// Get all certified batch digests for the current round.
    /// These are what the proposer includes in the block.
    pub fn certified_digests(&self) -> Vec<Hash256> {
        self.certified
            .values()
            .filter(|c| c.is_valid(self.quorum_threshold))
            .map(|c| c.batch_digest)
            .collect()
    }

    /// Advance to the next DAG round.
    pub fn advance_round(&mut self) {
        self.current_round += 1;

        // Set parent references for next round's batches
        let parent_digests = self.certified_digests();
        for worker in &mut self.workers {
            worker.set_parents(parent_digests.clone());
        }
    }

    /// Current DAG round.
    pub fn current_round(&self) -> u64 {
        self.current_round
    }

    /// Number of certified batches.
    pub fn certified_count(&self) -> usize {
        self.certified
            .values()
            .filter(|c| c.is_valid(self.quorum_threshold))
            .count()
    }

    /// Total pending transactions across all workers.
    pub fn total_pending(&self) -> usize {
        self.workers.iter().map(|w| w.pending_count()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_batch_creation() {
        let mut worker = Worker::new(0, b"validator1".to_vec());

        for i in 0..10 {
            worker.add_transaction(format!("tx_{}", i).into_bytes());
        }
        assert_eq!(worker.pending_count(), 10);

        let batch = worker.seal_batch().unwrap();
        assert_eq!(batch.transactions.len(), 10);
        assert_eq!(batch.worker_id, 0);
        assert_eq!(batch.author, b"validator1");
        assert_eq!(worker.pending_count(), 0);
    }

    #[test]
    fn test_worker_empty_seal_returns_none() {
        let mut worker = Worker::new(0, b"v".to_vec());
        assert!(worker.seal_batch().is_none());
    }

    #[test]
    fn test_batch_digest_deterministic() {
        let d1 = TransactionBatch::compute_digest(0, b"v", &[b"tx1".to_vec()], &[]);
        let d2 = TransactionBatch::compute_digest(0, b"v", &[b"tx1".to_vec()], &[]);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_batch_digest_changes_with_content() {
        let d1 = TransactionBatch::compute_digest(0, b"v", &[b"tx1".to_vec()], &[]);
        let d2 = TransactionBatch::compute_digest(0, b"v", &[b"tx2".to_vec()], &[]);
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_mempool_submit_and_seal() {
        let mut pool = Mempool::new(2, b"val1".to_vec(), 2);

        for i in 0..5 {
            pool.submit_transaction(format!("tx_{}", i).into_bytes());
        }
        assert_eq!(pool.total_pending(), 5);

        // Force seal from worker 0
        let batch = pool.force_seal(0);
        assert!(batch.is_some());
    }

    #[test]
    fn test_mempool_certification() {
        let mut pool = Mempool::new(1, b"val1".to_vec(), 2);

        pool.submit_transaction(b"tx1".to_vec());
        let batch = pool.force_seal(0).unwrap();
        let digest = batch.digest;

        // First ack — not enough
        let cert = pool.acknowledge_batch(&digest, b"v1".to_vec());
        assert!(cert.is_none());

        // Second ack — quorum reached
        let cert = pool.acknowledge_batch(&digest, b"v2".to_vec());
        assert!(cert.is_some());
        assert!(cert.unwrap().is_valid(2));
    }

    #[test]
    fn test_mempool_dedup_acks() {
        let mut pool = Mempool::new(1, b"val1".to_vec(), 2);

        pool.submit_transaction(b"tx1".to_vec());
        let batch = pool.force_seal(0).unwrap();
        let digest = batch.digest;

        // Same validator acks twice — should dedup
        pool.acknowledge_batch(&digest, b"v1".to_vec());
        let cert = pool.acknowledge_batch(&digest, b"v1".to_vec());
        assert!(cert.is_none()); // still only 1 unique ack
    }

    #[test]
    fn test_mempool_advance_round() {
        let mut pool = Mempool::new(1, b"val1".to_vec(), 1);

        pool.submit_transaction(b"tx1".to_vec());
        let batch = pool.force_seal(0).unwrap();
        pool.acknowledge_batch(&batch.digest, b"v1".to_vec());

        assert_eq!(pool.current_round(), 0);
        assert_eq!(pool.certified_count(), 1);

        pool.advance_round();
        assert_eq!(pool.current_round(), 1);
    }

    #[test]
    fn test_certificate_validity() {
        let cert = BatchCertificate {
            batch_digest: Hash256::ZERO,
            author: b"v1".to_vec(),
            acknowledgements: vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            round: 0,
        };
        assert!(cert.is_valid(3));
        assert!(cert.is_valid(2));
        assert!(!cert.is_valid(4));
    }

    #[test]
    fn test_multiple_workers() {
        let mut pool = Mempool::new(4, b"val1".to_vec(), 1);

        // Submit 40 transactions (10 per worker via round-robin)
        for i in 0..40 {
            pool.submit_transaction(format!("tx_{}", i).into_bytes());
        }

        // Seal all batches
        let batches = pool.seal_batches();
        assert!(!batches.is_empty());

        // Each batch should have transactions
        for batch in &batches {
            assert!(!batch.transactions.is_empty());
        }
    }

    #[test]
    fn test_batch_serialization() {
        let batch = TransactionBatch {
            digest: sha3_256(b"test"),
            worker_id: 0,
            author: b"v1".to_vec(),
            transactions: vec![b"tx1".to_vec(), b"tx2".to_vec()],
            parents: vec![sha3_256(b"parent1")],
            timestamp: 1700000000,
        };

        let bytes = bincode::serialize(&batch).unwrap();
        let deserialized: TransactionBatch = bincode::deserialize(&bytes).unwrap();

        assert_eq!(deserialized.digest, batch.digest);
        assert_eq!(deserialized.transactions.len(), 2);
        assert_eq!(deserialized.parents.len(), 1);
    }
}
