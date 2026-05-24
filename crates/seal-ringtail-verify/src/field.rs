//! 48-bit prime field arithmetic for Ringtail.
//!
//! q = 0x1000000004A01 is the Ringtail NTT-friendly prime: 48 bits wide,
//! (q - 1) divisible by 2N = 512. All polynomial coefficients live in
//! [0, q). Multiplication uses a `u128` intermediate since q fits in 48
//! bits but `q * q` needs 96. BPF emulates `u128` in software — every
//! `u128` mul is roughly 4 native `u64` muls plus shifts.

/// Ring dimension. Polynomials have 256 coefficients.
pub const RING_N: usize = 256;

/// 48-bit NTT-friendly prime: `(q - 1) % 512 == 0`, so a primitive 512-th
/// root of unity exists mod q — which is what the negacyclic NTT needs.
pub const RING_Q: u64 = 0x1000000004A01;

/// Aggregate signature norm bound (reject if ||z|| > B_agg).
/// Matches `seal-threshold::AGGREGATE_NORM_BOUND`.
pub const AGGREGATE_NORM_BOUND: u64 = 1u64 << 60;

/// Module dimension: the matrix A is K x L and the public-key vector t
/// is K-long. Only K matters for the verify loop.
pub const MODULE_K: usize = 8;

/// `(a + b) mod q`. Both inputs assumed already reduced.
#[inline]
pub const fn mod_add(a: u64, b: u64) -> u64 {
    // a, b < q < 2^48, so a + b < 2^49 — fits in u64 without overflow.
    let s = a + b;
    if s >= RING_Q {
        s - RING_Q
    } else {
        s
    }
}

/// `(a - b) mod q`. Both inputs assumed already reduced.
#[inline]
pub const fn mod_sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        RING_Q - b + a
    }
}

/// `(a * b) mod q`. Both inputs assumed already reduced (< q < 2^48).
/// The product fits in 96 bits so a single `u128 % q` is correct.
#[inline]
pub fn mod_mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % RING_Q as u128) as u64
}

/// `base^exp mod q`. Square-and-multiply. Used only at precompute-table
/// build time (not on the verify hot path, so the `%` cost is fine).
pub fn mod_pow(mut base: u64, mut exp: u64) -> u64 {
    let mut r: u64 = 1;
    base %= RING_Q;
    while exp > 0 {
        if exp & 1 == 1 {
            r = mod_mul(r, base);
        }
        exp >>= 1;
        base = mod_mul(base, base);
    }
    r
}

/// `1 / a mod q` via Fermat: `a^(q-2)`. Only used at precompute time.
#[inline]
pub fn mod_inv(a: u64) -> u64 {
    mod_pow(a, RING_Q - 2)
}

/// Centered-representative absolute value: treat `c ∈ [0, q)` as a signed
/// integer in `(-q/2, q/2]` and return `|c|`. Branchless so the per-
/// coefficient time doesn't depend on the sign.
#[inline]
pub fn centered_abs(c: u64) -> u64 {
    let flipped = RING_Q - c; // safe for c in [0, q)
    let is_negative = ((c > RING_Q / 2) as u64).wrapping_neg(); // 0 or !0
                                                                // select flipped if is_negative, else c
    (flipped & is_negative) | (c & !is_negative)
}

/// Squared L2 norm of a polynomial's centered representation.
///
/// We return the sum of squared centered magnitudes — the caller compares
/// this against `bound * bound` to avoid computing a square root. Sums
/// fit in `u128`: each coefficient's squared magnitude is at most
/// `(q/2)^2 ≈ 2^94`, and we have 256 of them, so the total is < 2^102.
pub fn norm_sq(poly: &[u64]) -> u128 {
    let mut acc: u128 = 0;
    for &c in poly {
        let a = centered_abs(c) as u128;
        acc += a * a;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mod_add_basic() {
        assert_eq!(mod_add(1, 2), 3);
        assert_eq!(mod_add(RING_Q - 1, 1), 0);
        assert_eq!(mod_add(RING_Q - 5, 10), 5);
    }

    #[test]
    fn mod_sub_basic() {
        assert_eq!(mod_sub(5, 3), 2);
        assert_eq!(mod_sub(0, 1), RING_Q - 1);
    }

    #[test]
    fn mod_mul_matches_reference() {
        // Known products.
        assert_eq!(mod_mul(2, 3), 6);
        assert_eq!(mod_mul(RING_Q - 1, RING_Q - 1), 1); // (-1)^2 = 1

        // Large operands that force the u128 path.
        let a: u64 = (1u64 << 40) + 123;
        let b: u64 = (1u64 << 45) + 9876;
        let expected = ((a as u128 * b as u128) % RING_Q as u128) as u64;
        assert_eq!(mod_mul(a, b), expected);
    }

    #[test]
    fn mod_pow_then_mul_is_identity() {
        // a * a^(q-2) == 1 mod q
        let a: u64 = 123456789 % RING_Q;
        let inv = mod_inv(a);
        assert_eq!(mod_mul(a, inv), 1);
    }

    #[test]
    fn centered_abs_crosses_midpoint() {
        assert_eq!(centered_abs(0), 0);
        assert_eq!(centered_abs(5), 5);
        // One past the midpoint is "negative" — absolute value is q - c.
        let one_negative = RING_Q / 2 + 1;
        assert_eq!(centered_abs(one_negative), RING_Q - one_negative);
        assert_eq!(centered_abs(RING_Q - 1), 1);
    }

    #[test]
    fn norm_sq_all_zero_is_zero() {
        let p = [0u64; RING_N];
        assert_eq!(norm_sq(&p), 0);
    }

    #[test]
    fn norm_sq_pure_plus_one() {
        // All coefficients are 1 (which reads as centered +1). Norm^2 = N.
        let p = [1u64; RING_N];
        assert_eq!(norm_sq(&p), RING_N as u128);
    }

    #[test]
    fn norm_sq_pure_minus_one() {
        // All coefficients are q - 1 (centered -1). Norm^2 = N.
        let p = [RING_Q - 1; RING_N];
        assert_eq!(norm_sq(&p), RING_N as u128);
    }
}
