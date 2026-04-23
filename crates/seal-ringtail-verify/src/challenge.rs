//! Sparse challenge polynomial expansion.
//!
//! Ringtail's challenge c is a degree-(N-1) polynomial with TAU = 60
//! non-zero coefficients, each ±1. It's derived deterministically from a
//! 32-byte SHA3-256 hash by probing positions via `SHA3(hash || counter)`
//! and accepting the first TAU collision-free positions.
//!
//! This has to match `seal-threshold::ringtail::expand_challenge`
//! byte-for-byte — the cross-check test under `std-crosscheck` enforces
//! that.

use sha3::{Digest, Sha3_256};
use crate::field::{RING_N, RING_Q};

/// Number of non-zero coefficients in the challenge polynomial.
pub const TAU: usize = 60;

/// Expand a 32-byte challenge hash into a sparse ±1 polynomial in R_q.
///
/// Coefficients are stored in the standard coefficient representation:
/// +1 as 1, -1 as RING_Q - 1.
pub fn expand(challenge_hash: &[u8; 32], out: &mut [u64; RING_N]) {
    for c in out.iter_mut() {
        *c = 0;
    }

    let mut placed = 0usize;
    let mut counter: u32 = 0;
    // Track occupied positions with a byte array — RING_N = 256 so this
    // is 256 B on the stack, well inside BPF's 4 KB frame limit.
    let mut positions_set = [false; RING_N];

    while placed < TAU {
        let mut hasher = Sha3_256::new();
        hasher.update(challenge_hash);
        hasher.update(counter.to_le_bytes());
        let h = hasher.finalize();

        counter = counter.saturating_add(1);

        // Match the host signer: u16-LE of (h[0], h[1]) mod RING_N.
        let pos = (u16::from_le_bytes([h[0], h[1]]) as usize) % RING_N;
        if positions_set[pos] {
            continue;
        }
        positions_set[pos] = true;

        // h[2] lowest bit picks the sign.
        let sign = h[2] & 1;
        out[pos] = if sign == 0 { 1 } else { RING_Q - 1 };
        placed += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_is_deterministic() {
        let hash = [7u8; 32];
        let mut a = [0u64; RING_N];
        let mut b = [0u64; RING_N];
        expand(&hash, &mut a);
        expand(&hash, &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn expand_has_exactly_tau_nonzero_coefficients() {
        let hash = [0x5Au8; 32];
        let mut poly = [0u64; RING_N];
        expand(&hash, &mut poly);
        let nonzero = poly.iter().filter(|&&c| c != 0).count();
        assert_eq!(nonzero, TAU);
    }

    #[test]
    fn expand_coefficients_are_plus_or_minus_one() {
        let hash = [0xC3u8; 32];
        let mut poly = [0u64; RING_N];
        expand(&hash, &mut poly);
        let plus_one = RING_Q - (RING_Q - 1); // 1
        let minus_one = RING_Q - 1;
        for &c in &poly {
            assert!(c == 0 || c == plus_one || c == minus_one,
                    "coefficient {} is not 0, +1, or -1 mod q", c);
        }
    }

    #[test]
    fn expand_differs_for_different_inputs() {
        let mut a = [0u64; RING_N];
        let mut b = [0u64; RING_N];
        expand(&[1u8; 32], &mut a);
        expand(&[2u8; 32], &mut b);
        assert_ne!(a, b);
    }
}
