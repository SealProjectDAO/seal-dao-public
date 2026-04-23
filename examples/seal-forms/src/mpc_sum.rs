//! MPC additive-share aggregation for numeric answers.
//!
//! Goal: a respondent answers a numeric question (e.g. "how many
//! hours did you spend?") in a way that lets the form owner — or any
//! committee — learn the *aggregate* across all respondents without
//! ever seeing any individual's value.
//!
//! Construction: additive secret sharing in `Z_p` for `p = 2^61 - 1`
//! (a Mersenne prime small enough to fit in a `u64`, large enough
//! that one survey's worth of answers won't overflow). For each
//! response:
//!
//! 1. Respondent picks `n` MPC parties they trust. They generate
//!    `n` random shares `s_1, ..., s_n` in `Z_p` such that
//!    `s_1 + s_2 + ... + s_n ≡ answer (mod p)`.
//! 2. Each share is encapsulated for the corresponding party's
//!    ML-KEM public key (so only that party can decrypt their own
//!    share — not enough to recover the answer).
//! 3. The on-chain row stores all `n` encapsulated shares. The
//!    `aggregator` summons each party's local share, sums them, and
//!    publishes the aggregate.
//!
//! This module ships the share-construction + final-sum primitives.
//! The wire format and the per-party decryption are intentionally
//! decoupled from `seal-crypto::kem` so unit tests can exercise the
//! arithmetic without spinning up KEM keypairs.

use seal_crypto::hash::sha3_256;
use serde::{Deserialize, Serialize};

/// Field modulus: 2^61 - 1, the largest Mersenne prime that fits in
/// a `u64`. Picked so:
///
/// * Sums of up to ~2^60 / 2^32 ≈ 2^28 ≈ 270M survey answers stay
///   well below the modulus even when each answer is up to 2^32.
/// * Modular reduction is two adds (`(x & MASK) + (x >> 61)`).
/// * Adversaries can't distinguish the share distribution from
///   uniform on `Z_p` with information-theoretic security.
pub const FIELD_MODULUS: u64 = (1u64 << 61) - 1;

/// One additive share for one MPC party.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareBundle {
    /// 0-based party index (matches the form's MPC committee roster).
    pub party_index: usize,
    /// Share value in `Z_p` (less than `FIELD_MODULUS`).
    pub share: u64,
}

/// Modular addition mod `FIELD_MODULUS`.
#[inline]
pub fn add_mod(a: u64, b: u64) -> u64 {
    let s = a as u128 + b as u128;
    (s % FIELD_MODULUS as u128) as u64
}

/// Modular subtraction mod `FIELD_MODULUS`.
#[inline]
pub fn sub_mod(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        FIELD_MODULUS - (b - a)
    }
}

/// Split `answer mod p` into `n` additive shares.
///
/// Uses a deterministic SHA3-derived randomness stream seeded with
/// `seed`; production code should pass a fresh CSPRNG seed per
/// answer. Returns `n` shares whose sum is `answer mod FIELD_MODULUS`.
pub fn split(answer: u64, n: usize, seed: &[u8]) -> Vec<ShareBundle> {
    assert!(n >= 2, "MPC sum needs at least 2 parties");
    let answer_mod = answer % FIELD_MODULUS;
    let mut shares: Vec<u64> = Vec::with_capacity(n);
    let mut running_sum: u64 = 0;
    // The first n-1 shares come from the seeded stream; the last one
    // is whatever closes the books (answer - sum_so_far) mod p.
    for i in 0..(n - 1) {
        let mut buf = Vec::with_capacity(seed.len() + 8);
        buf.extend_from_slice(seed);
        buf.extend_from_slice(&(i as u64).to_le_bytes());
        let h = sha3_256(&buf).0;
        // Take 8 bytes, reduce mod p.
        let mut s8 = [0u8; 8];
        s8.copy_from_slice(&h[..8]);
        let raw = u64::from_le_bytes(s8) & ((1u64 << 61) - 1);
        let s = raw % FIELD_MODULUS;
        running_sum = add_mod(running_sum, s);
        shares.push(s);
    }
    let last = sub_mod(answer_mod, running_sum);
    shares.push(last);

    shares
        .into_iter()
        .enumerate()
        .map(|(party_index, share)| ShareBundle { party_index, share })
        .collect()
}

/// Reconstruct the answer from a complete share set.
///
/// This is what each party's local subsystem feeds into the
/// aggregator: the aggregator sums *across responses for that
/// party*, then sums *across parties* to get the survey total. This
/// helper does the second step (sum across parties for one
/// response) — it's also the unit-test oracle.
pub fn reconstruct(shares: &[ShareBundle]) -> u64 {
    shares.iter().fold(0u64, |acc, s| add_mod(acc, s.share))
}

/// Aggregate every party's running total into the survey total.
///
/// `per_party_totals[i]` is the sum (in `Z_p`) of all of party `i`'s
/// share contributions across the survey. The survey total in `Z_p`
/// is just their sum.
pub fn survey_total(per_party_totals: &[u64]) -> u64 {
    per_party_totals.iter().fold(0u64, |acc, &t| add_mod(acc, t))
}

/// Per-party local aggregation: sum the party's share across many
/// `ShareBundle`s, returning the running total in `Z_p`.
pub fn aggregate_for_party(party_index: usize, bundles: &[ShareBundle]) -> u64 {
    bundles
        .iter()
        .filter(|b| b.party_index == party_index)
        .fold(0u64, |acc, b| add_mod(acc, b.share))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_then_reconstruct_recovers_answer() {
        let answer: u64 = 12345;
        let shares = split(answer, 5, b"seed-A");
        assert_eq!(shares.len(), 5);
        assert_eq!(reconstruct(&shares), answer);
    }

    #[test]
    fn shares_sum_to_answer_mod_p() {
        let answer: u64 = FIELD_MODULUS - 7;
        let shares = split(answer, 3, b"seed-B");
        assert_eq!(reconstruct(&shares), answer);
    }

    #[test]
    fn no_individual_share_equals_answer() {
        // Information-theoretic privacy property: each share alone
        // is uniformly distributed and reveals nothing about the
        // answer. Statistical sanity: with 4 shares and a fixed
        // small answer (7) and a fixed seed, no single share equals 7.
        let shares = split(7, 4, b"seed-C");
        for s in &shares {
            assert_ne!(s.share, 7, "share leaks the answer");
        }
    }

    #[test]
    fn split_with_two_parties_works() {
        let shares = split(99, 2, b"seed-D");
        assert_eq!(shares.len(), 2);
        assert_eq!(reconstruct(&shares), 99);
    }

    #[test]
    fn survey_total_equals_sum_of_per_party_totals() {
        // Three respondents, two parties.
        let r1 = split(10, 2, b"r1");
        let r2 = split(20, 2, b"r2");
        let r3 = split(30, 2, b"r3");

        let bundles: Vec<ShareBundle> =
            r1.iter().chain(r2.iter()).chain(r3.iter()).cloned().collect();

        let p0 = aggregate_for_party(0, &bundles);
        let p1 = aggregate_for_party(1, &bundles);
        let total = survey_total(&[p0, p1]);
        assert_eq!(total, 60);
    }

    #[test]
    fn aggregate_for_missing_party_returns_zero() {
        let bundles = split(100, 3, b"q");
        assert_eq!(aggregate_for_party(99, &bundles), 0);
    }

    #[test]
    fn split_panics_for_lone_party() {
        let r = std::panic::catch_unwind(|| split(1, 1, b"x"));
        assert!(r.is_err(), "split with n<2 must panic");
    }
}
