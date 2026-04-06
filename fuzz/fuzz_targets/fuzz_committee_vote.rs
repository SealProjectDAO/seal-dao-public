//! Fuzz target: CommitteeVote deserialization should never panic.
//!
//! Feeds arbitrary bytes to bincode deserialization of CommitteeVote
//! and CommitteeAttestation. Must return Ok or Err — never panic.

#![no_main]
use libfuzzer_sys::fuzz_target;
use seal_node::committee::{CommitteeVote, CommitteeAttestation, EpochAnnouncement};

fuzz_target!(|data: &[u8]| {
    // Try to deserialize as each committee message type
    // Must NEVER panic
    let _ = bincode::deserialize::<CommitteeVote>(data);
    let _ = bincode::deserialize::<CommitteeAttestation>(data);
    let _ = bincode::deserialize::<EpochAnnouncement>(data);
});
