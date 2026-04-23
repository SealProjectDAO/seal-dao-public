//! Fuzz target: Ringtail signing path (partial_sign + aggregate) must
//! never panic regardless of input byte shape for (sk_share, message,
//! pub_key). Complements `fuzz_ringtail_verify.rs`, which only exercises
//! the verify side.
//!
//! The partial_sign / aggregate / verify pipeline has more surface —
//! from_bytes decoding, Shamir reconstruction, NTT, norm checks — and
//! is where correctness bugs are more likely to show up as panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use seal_threshold::ntt::HandRolledOps;
use seal_threshold::ringtail::{RING_N, RingOps, RingtailThreshold, distribute_key_shares};
use seal_threshold::traits::ThresholdScheme;

fuzz_target!(|data: &[u8]| {
    // Layout: [message_len(1) | message | tail]. If tail is >=RING_N*8
    // bytes, use it as the master secret polynomial; otherwise sample
    // one from the ring (keeping the fuzz loop fast).
    if data.is_empty() {
        return;
    }
    let msg_len = (data[0] as usize).min(data.len().saturating_sub(1));
    let (msg_slice, tail) = data[1..].split_at(msg_len.min(data[1..].len()));

    let ring = HandRolledOps::new();
    let master = if tail.len() >= RING_N * 8 {
        match ring.from_bytes(&tail[..RING_N * 8]) {
            Ok(p) => p,
            Err(_) => return,
        }
    } else {
        ring.sample_gaussian(6.108)
    };

    // Pick a small committee so the fuzz iteration stays cheap.
    let (n, t) = (5usize, 3usize);
    let shares = distribute_key_shares(&ring, &master, n, t);

    // partial_sign on each share must not panic on arbitrary message bytes.
    let partials: Vec<_> = (0..t)
        .filter_map(|i| RingtailThreshold::partial_sign(shares[i].0, &shares[i].1, msg_slice).ok())
        .collect();
    if partials.len() < t {
        return;
    }

    let pub_keys: Vec<Vec<u8>> = shares.iter().map(|(_, s)| s.clone()).collect();

    // aggregate + verify must not panic (may return Err on invalid inputs).
    if let Ok(sig) = RingtailThreshold::aggregate(&partials, &pub_keys, msg_slice, t, n) {
        let _ = RingtailThreshold::verify(&sig, &pub_keys, msg_slice, t);
    }
});
