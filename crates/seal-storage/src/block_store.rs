//! Block storage — append-only log of blocks indexed by height.

use seal_crypto::hash::Hash256;
use serde::{Deserialize, Serialize};

/// Block header with VRF election proof.
///
/// **Canonical signing bytes**: `proposer_signature` is an ML-DSA
/// signature over `bincode(header)` with `proposer_signature` set to
/// empty. Producers sign the empty-sig serialization; verifiers zero
/// the field, re-serialize, and verify against `proposer`. (This field
/// was added after the fact, so persisted data from before it must be
/// wiped — see CHANGELOG.)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BlockHeader {
    pub height: u64,
    pub parent_hash: Hash256,
    pub state_root: Hash256,
    pub timestamp: u64,
    pub proposer: Vec<u8>, // Public key of proposer
    /// VRF output proving this proposer was legitimately elected.
    /// Verifiers check: VRF.verify(proposer_vrf_pk, slot_input, vrf_output, vrf_proof).
    #[serde(default)]
    pub vrf_output: Vec<u8>,
    /// VRF proof (ML-DSA signature for PqVrf, ~3.3 KB).
    #[serde(default)]
    pub vrf_proof: Vec<u8>,
    /// ML-DSA signature of the proposer over the canonical (empty-sig)
    /// serialization of this header. Verifiers reject blocks with an
    /// empty signature.
    pub proposer_signature: Vec<u8>,
    /// Merkle root over `Block.transactions` (order-sensitive). Added so the
    /// transaction set is bound to the *signed* header: without it a relayer
    /// could inject/remove/modify a no-op tx (DexMatch, token/bridge/stake) in
    /// a validly-signed block and every node would commit it, because no-op txs
    /// affect neither `state_root` nor the header signature. Producers compute
    /// this *after* appending the per-block `DexMatch` so the match is covered;
    /// verifiers recompute it from the received transactions and reject on
    /// mismatch. Adding this field changes the canonical signing bytes, so
    /// pre-upgrade headers are invalid — wipe the data dir on upgrade (see
    /// `audits/2026-10-08-dexmatch-txroot-design.md`).
    pub tx_root: Hash256,
}

/// Merkle root over a transaction list (order-sensitive). This is the value
/// committed to as `BlockHeader.tx_root`. Producers, the legacy `state.rs`
/// producer, and every replayer call the same function on the same bytes, so
/// they always agree; a post-signature change to any transaction changes the
/// recomputed root and fails the header check.
pub fn transactions_root(txs: &[Transaction]) -> Hash256 {
    let mut leaves = Vec::with_capacity(txs.len());
    for tx in txs {
        // A tx that cannot serialize is a distinct, stable leaf; in practice a
        // produced/stored block only contains serializable txs, so this arm is
        // a fail-safe against a panic (no `.unwrap()` in production).
        match bincode::serialize(tx) {
            Ok(bytes) => leaves.push(bytes),
            Err(_) => leaves.push(Vec::new()),
        }
    }
    seal_crypto::hash::merkle_root(&leaves)
}

/// A block containing header and transactions.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

/// A transaction (simplified for Phase 0).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub tx_type: TxType,
    pub payload: Vec<u8>,
    pub sender: Vec<u8>,    // Public key
    pub signature: Vec<u8>, // ML-DSA signature
}

/// Transaction types matching SPEC.md §4.4.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum TxType {
    CreateApp,
    SqlExec,
    AlterSchema,
    Transfer,
    BridgeIn,
    BridgeOut,
    StakeDeposit,
    StakeWithdraw,
    GovPropose,
    GovVote,
    TokenCreate,
    TokenMint,
    TokenTransfer,
    /// Per-block DEX matching event. Payload is a bincode-serialized
    /// list of `(maker_order_id, taker_order_id, market, price, qty,
    /// timestamp)` tuples produced by `DexManager::match_all`. Emitting
    /// this as a transaction (rather than out-of-band metadata) is
    /// what brings DEX trades into the state root + the block-level
    /// ZK proof of execution.
    DexMatch,
}

/// Persistent block storage using sled.
pub struct BlockStore {
    db: sled::Db,
}

impl BlockStore {
    pub fn open(path: &str) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        Ok(BlockStore { db })
    }

    /// Store a block at its height.
    pub fn put_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let key = block.header.height.to_be_bytes();
        let bytes = bincode::serialize(block)?;
        self.db.insert(key, bytes)?;
        Ok(())
    }

    /// Get a block by height.
    pub fn get_block(&self, height: u64) -> Option<Block> {
        let key = height.to_be_bytes();
        let bytes = self.db.get(key).ok()??;
        bincode::deserialize(&bytes).ok()
    }

    /// Get the latest (highest) block.
    pub fn latest_block(&self) -> Option<Block> {
        let (_, bytes) = self.db.last().ok()??;
        bincode::deserialize(&bytes).ok()
    }

    /// Get the current chain height.
    pub fn height(&self) -> u64 {
        self.latest_block().map(|b| b.header.height).unwrap_or(0)
    }

    /// Flush to disk.
    pub fn flush(&self) -> Result<(), sled::Error> {
        self.db.flush().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_block_store() -> BlockStore {
        let dir = tempfile::tempdir().unwrap();
        BlockStore::open(dir.path().to_str().unwrap()).unwrap()
    }

    fn make_block(height: u64) -> Block {
        Block {
            header: BlockHeader {
                height,
                parent_hash: Hash256::ZERO,
                state_root: Hash256::ZERO,
                timestamp: 1000 + height,
                proposer: vec![0u8; 32],
                vrf_output: vec![],
                vrf_proof: vec![],
                proposer_signature: vec![],
                tx_root: Hash256::ZERO,
            },
            transactions: vec![],
        }
    }

    #[test]
    fn test_put_and_get_block() {
        let store = temp_block_store();
        let block = make_block(1);
        store.put_block(&block).unwrap();

        let retrieved = store.get_block(1).unwrap();
        assert_eq!(retrieved, block);
    }

    #[test]
    fn test_latest_block() {
        let store = temp_block_store();
        store.put_block(&make_block(1)).unwrap();
        store.put_block(&make_block(2)).unwrap();
        store.put_block(&make_block(3)).unwrap();

        let latest = store.latest_block().unwrap();
        assert_eq!(latest.header.height, 3);
    }

    #[test]
    fn test_height() {
        let store = temp_block_store();
        assert_eq!(store.height(), 0);

        store.put_block(&make_block(1)).unwrap();
        assert_eq!(store.height(), 1);

        store.put_block(&make_block(5)).unwrap();
        assert_eq!(store.height(), 5);
    }

    #[test]
    fn test_get_nonexistent_block() {
        let store = temp_block_store();
        assert!(store.get_block(999).is_none());
    }

    #[test]
    fn test_block_with_transactions() {
        let store = temp_block_store();
        let block = Block {
            header: BlockHeader {
                height: 1,
                parent_hash: Hash256::ZERO,
                state_root: Hash256::ZERO,
                timestamp: 1000,
                proposer: vec![1u8; 32],
                vrf_output: vec![],
                vrf_proof: vec![],
                proposer_signature: vec![],
                tx_root: Hash256::ZERO,
            },
            transactions: vec![
                Transaction {
                    tx_type: TxType::SqlExec,
                    payload: b"INSERT INTO t (id) VALUES (1)".to_vec(),
                    sender: vec![2u8; 32],
                    signature: vec![3u8; 100],
                },
                Transaction {
                    tx_type: TxType::Transfer,
                    payload: b"transfer_data".to_vec(),
                    sender: vec![4u8; 32],
                    signature: vec![5u8; 100],
                },
            ],
        };

        store.put_block(&block).unwrap();
        let retrieved = store.get_block(1).unwrap();
        assert_eq!(retrieved.transactions.len(), 2);
        assert_eq!(retrieved.transactions[0].tx_type, TxType::SqlExec);
        assert_eq!(retrieved.transactions[1].tx_type, TxType::Transfer);
    }
}
