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
// Bridge multi-validator Ringtail signing topics (P1#5 layer 4)
// ============================================================================
//
// Three topics drive the multi-validator unlock-signing protocol:
//
//   round1 — every validator broadcasts its Round1MessageFull
//            (commitment for a specific withdrawal_id)
//   round2 — every validator broadcasts its Round2Message
//            (partial response, computed once it sees the aggregated D)
//   sigs   — once any validator has threshold partials, it broadcasts
//            the aggregated 2088-byte Ringtail signature so the rest of
//            the validator set can attach it to the local withdrawal
//            record without re-aggregating
//
// All three carry a session id (`wd_<chain>_<n>`) in their envelope so
// receivers route messages to the right ongoing signing session. The
// envelope structs live in the bridge crate alongside the
// aggregate_committee_ringtail_sig primitive (commit 024bdf85d) — the
// topics here are the wire layer.

/// Topic string for bridge unlock signing — Round 1 commitments.
pub const BRIDGE_RINGTAIL_ROUND1_TOPIC_STR: &str = "seal/bridge-ringtail-round1/1.0";

/// Topic string for bridge unlock signing — Round 2 partial responses.
pub const BRIDGE_RINGTAIL_ROUND2_TOPIC_STR: &str = "seal/bridge-ringtail-round2/1.0";

/// Topic string for finalized aggregated bridge unlock signatures.
pub const BRIDGE_RINGTAIL_SIGS_TOPIC_STR: &str = "seal/bridge-ringtail-sigs/1.0";

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

pub fn bridge_ringtail_round1_topic() -> IdentTopic {
    IdentTopic::new(BRIDGE_RINGTAIL_ROUND1_TOPIC_STR)
}

pub fn bridge_ringtail_round2_topic() -> IdentTopic {
    IdentTopic::new(BRIDGE_RINGTAIL_ROUND2_TOPIC_STR)
}

pub fn bridge_ringtail_sigs_topic() -> IdentTopic {
    IdentTopic::new(BRIDGE_RINGTAIL_SIGS_TOPIC_STR)
}

// ============================================================================
// Static topic references (backward compatibility)
// ============================================================================

#[allow(non_upper_case_globals)]
pub static BLOCKS_TOPIC: fn() -> IdentTopic = blocks_topic;

#[allow(non_upper_case_globals)]
pub static TXS_TOPIC: fn() -> IdentTopic = txs_topic;

/// All topics a full validator node should subscribe to.
///
/// Bridge-ringtail topics are listed here so validators auto-receive
/// signing-protocol traffic once the host orchestration lands.
/// Subscribing to them today is harmless (no publishers exist yet);
/// flipping on the orchestrator in a future commit doesn't require
/// touching this list.
pub fn all_validator_topics() -> Vec<IdentTopic> {
    vec![
        blocks_topic(),
        txs_topic(),
        committee_votes_topic(),
        committee_sigs_topic(),
        epoch_transition_topic(),
        bridge_ringtail_round1_topic(),
        bridge_ringtail_round2_topic(),
        bridge_ringtail_sigs_topic(),
    ]
}

/// Topics for a light client (blocks only).
pub fn light_client_topics() -> Vec<IdentTopic> {
    vec![blocks_topic()]
}
