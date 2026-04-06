//! GossipSub topic definitions for Seal DAO P2P network.

use libp2p::gossipsub::IdentTopic;

// ============================================================================
// Core topics (Phase 1)
// ============================================================================

/// Topic string for new block announcements.
pub const BLOCKS_TOPIC_STR: &str = "seal/blocks/1.0";

/// Topic string for new transaction broadcasts.
pub const TXS_TOPIC_STR: &str = "seal/txs/1.0";

// ============================================================================
// Committee signing topics (Phase 2 — multi-node consensus)
// ============================================================================

/// Topic string for committee partial signatures (Ringtail Round 2 responses).
/// Committee members publish their partial signatures after verifying a proposed block.
pub const COMMITTEE_VOTES_TOPIC_STR: &str = "seal/committee-votes/1.0";

/// Topic string for aggregated committee threshold signatures.
/// The combiner publishes the finalized block with threshold signature.
pub const COMMITTEE_SIGS_TOPIC_STR: &str = "seal/committee-sigs/1.0";

/// Topic string for epoch transition messages.
/// Broadcast at epoch boundaries: new epoch seed, validator set snapshot, VRF key rotation.
pub const EPOCH_TRANSITION_TOPIC_STR: &str = "seal/epoch-transition/1.0";

// ============================================================================
// Mempool topics (Phase 4 — Narwhal-style decoupled mempool)
// ============================================================================

/// Topic string for mempool batch announcements (Narwhal-style DAG vertices).
pub const MEMPOOL_BATCH_TOPIC_STR: &str = "seal/mempool-batch/1.0";

// ============================================================================
// Topic constructors
// ============================================================================

pub fn blocks_topic() -> IdentTopic {
    IdentTopic::new(BLOCKS_TOPIC_STR)
}

pub fn txs_topic() -> IdentTopic {
    IdentTopic::new(TXS_TOPIC_STR)
}

pub fn committee_votes_topic() -> IdentTopic {
    IdentTopic::new(COMMITTEE_VOTES_TOPIC_STR)
}

pub fn committee_sigs_topic() -> IdentTopic {
    IdentTopic::new(COMMITTEE_SIGS_TOPIC_STR)
}

pub fn epoch_transition_topic() -> IdentTopic {
    IdentTopic::new(EPOCH_TRANSITION_TOPIC_STR)
}

pub fn mempool_batch_topic() -> IdentTopic {
    IdentTopic::new(MEMPOOL_BATCH_TOPIC_STR)
}

// ============================================================================
// Static topic references (backward compatibility)
// ============================================================================

#[allow(non_upper_case_globals)]
pub static BLOCKS_TOPIC: fn() -> IdentTopic = blocks_topic;

#[allow(non_upper_case_globals)]
pub static TXS_TOPIC: fn() -> IdentTopic = txs_topic;

/// All topics a full validator node should subscribe to.
pub fn all_validator_topics() -> Vec<IdentTopic> {
    vec![
        blocks_topic(),
        txs_topic(),
        committee_votes_topic(),
        committee_sigs_topic(),
        epoch_transition_topic(),
    ]
}

/// Topics for a light client (blocks only).
pub fn light_client_topics() -> Vec<IdentTopic> {
    vec![blocks_topic()]
}
