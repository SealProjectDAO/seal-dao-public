//! Fuzz target: Ringtail signature verification should never panic.
//!
//! Feeds arbitrary bytes as signature components to verify_signature().
//! Must return Ok or Err — never panic or exhibit undefined behavior.

#![no_main]
use libfuzzer_sys::fuzz_target;
use seal_threshold::ringtail::{verify_signature, RingtailSignature, RING_N};
use seal_threshold::traits::Bitfield;
use seal_threshold::ntt::HandRolledOps;
use seal_threshold::ringtail::RingOps;

fuzz_target!(|data: &[u8]| {
    // We need at least RING_N * 8 bytes for z + 32 bytes for challenge + 1 for threshold
    let min_len = RING_N * 8 + 32 + 1;
    if data.len() < min_len {
        return;
    }

    let z_bytes = data[..RING_N * 8].to_vec();
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&data[RING_N * 8..RING_N * 8 + 32]);
    let threshold = (data[RING_N * 8 + 32] as usize % 10).max(1);

    // Create a bitfield with some participants set
    let mut participants = Bitfield::new(10);
    for i in 0..threshold.min(10) {
        participants.set(i);
    }

    let sig = RingtailSignature {
        z: z_bytes,
        challenge,
        participants,
    };

    let ring = HandRolledOps::new();

    // This must NEVER panic
    let _ = verify_signature(&ring, &sig, &[], b"fuzz message", threshold);
});
