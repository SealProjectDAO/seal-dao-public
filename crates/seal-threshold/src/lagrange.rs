//! Lagrange interpolation over Z_q for t-of-n threshold reconstruction.
//!
//! Given a set of indexed points (x_j, y_j) with j ∈ S, the Lagrange
//! basis at evaluation point x = 0 is:
//!
//!   λ_j(0) = ∏_{k ∈ S, k ≠ j} (-x_k) · (x_j - x_k)^{-1} mod q
//!
//! Reconstruction at 0 (the secret point in Shamir over R_q):
//!
//!   y(0) = Σ_{j ∈ S} y_j · λ_j(0) mod q
//!
//! For Ringtail t-of-n: a partial response z_j carries `c · sk_j` where
//! sk_j = f(j) is the secret shared at index j (1-based, 0 reserved for
//! the secret). Combining via Lagrange yields `c · f(0) = c · sk_master`,
//! so the aggregated z still satisfies the verifier's `A · z - c · t`
//! check when `t = A · sk_master`.
//!
//! Per-coefficient (scalar Z_q) interpolation is used here. To combine
//! polynomial-valued shares, apply the same scalar coefficient to every
//! coefficient of the share polynomial — that is the Shamir-over-R_q
//! convention this crate already uses (`shamir_reconstruct` in `ntt.rs`).

use crate::ringtail::RING_Q;

/// Modular addition mod q.
#[inline]
fn add_mod(a: u64, b: u64, q: u64) -> u64 {
    let s = a as u128 + b as u128;
    (s % q as u128) as u64
}

/// Modular subtraction mod q.
#[inline]
fn sub_mod(a: u64, b: u64, q: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        q - (b - a)
    }
}

/// Modular multiplication mod q.
#[inline]
fn mul_mod(a: u64, b: u64, q: u64) -> u64 {
    ((a as u128 * b as u128) % q as u128) as u64
}

/// Modular exponentiation: base^exp mod q.
fn pow_mod(mut base: u64, mut exp: u64, q: u64) -> u64 {
    let mut acc = 1u64;
    base %= q;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = mul_mod(acc, base, q);
        }
        exp >>= 1;
        base = mul_mod(base, base, q);
    }
    acc
}

/// Modular inverse via Fermat (q must be prime).
fn inv_mod(a: u64, q: u64) -> u64 {
    pow_mod(a, q - 2, q)
}

/// Compute λ_j(0) for one party j given the participant index set.
///
/// `j_index` is the participant's Shamir index (the 1-based x-coordinate
/// it was assigned at share-distribution time). `participant_indices` is
/// the full set of indices that contributed shares to this aggregation,
/// including `j_index` itself.
///
/// Returns the scalar coefficient in [0, q). Panics on duplicate index.
pub fn lagrange_coefficient_at_zero(j_index: usize, participant_indices: &[usize], q: u64) -> u64 {
    assert!(
        participant_indices.contains(&j_index),
        "j_index must be in the participant set"
    );
    let xj = (j_index as u64) % q;
    let mut numerator = 1u64;
    let mut denominator = 1u64;
    for &k in participant_indices {
        if k == j_index {
            continue;
        }
        let xk = (k as u64) % q;
        // numerator *= (-x_k) mod q
        numerator = mul_mod(numerator, sub_mod(0, xk, q), q);
        // denominator *= (x_j - x_k) mod q
        denominator = mul_mod(denominator, sub_mod(xj, xk, q), q);
    }
    mul_mod(numerator, inv_mod(denominator, q), q)
}

/// Compute all Lagrange coefficients λ_j(0) for j ∈ participant_indices,
/// in the same order as the input.
pub fn lagrange_coefficients_at_zero(participant_indices: &[usize], q: u64) -> Vec<u64> {
    participant_indices
        .iter()
        .map(|&j| lagrange_coefficient_at_zero(j, participant_indices, q))
        .collect()
}

/// Apply a scalar Lagrange coefficient to every coefficient of a
/// polynomial (represented as `Vec<u64>` mod RING_Q). Pure scalar mul,
/// no NTT — Shamir reconstruction is linear in the shared point.
pub fn scale_poly(poly: &[u64], scalar: u64) -> Vec<u64> {
    poly.iter().map(|&c| mul_mod(c, scalar, RING_Q)).collect()
}

/// Add two polynomials coefficient-wise mod RING_Q.
pub fn add_poly(a: &[u64], b: &[u64]) -> Vec<u64> {
    assert_eq!(a.len(), b.len(), "polynomials must have equal length");
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| add_mod(*x, *y, RING_Q))
        .collect()
}

/// Reconstruct f(0) from `(index, share_poly)` pairs using Lagrange
/// interpolation over R_q (per-coefficient). Returns the reconstructed
/// polynomial. Caller is responsible for ensuring `shares.len() >= t`.
pub fn lagrange_combine_shares(shares: &[(usize, Vec<u64>)]) -> Vec<u64> {
    let indices: Vec<usize> = shares.iter().map(|(i, _)| *i).collect();
    let coeffs = lagrange_coefficients_at_zero(&indices, RING_Q);

    let len = shares.first().map(|(_, p)| p.len()).unwrap_or(0);
    let mut acc = vec![0u64; len];
    for ((_, share_poly), lambda) in shares.iter().zip(coeffs.iter()) {
        let scaled = scale_poly(share_poly, *lambda);
        acc = add_poly(&acc, &scaled);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lagrange_coefficient_singleton_is_one() {
        // With only one participant, λ_j(0) = 1 (empty product).
        let lambda = lagrange_coefficient_at_zero(7, &[7], RING_Q);
        assert_eq!(lambda, 1);
    }

    #[test]
    fn lagrange_coefficients_sum_to_one() {
        // Lagrange interpolation of the constant polynomial f(x) = 1
        // recovers 1 at any evaluation point, so Σ λ_j(0) = 1 mod q.
        let indices = vec![1usize, 2, 3, 5, 8];
        let coeffs = lagrange_coefficients_at_zero(&indices, RING_Q);
        let sum: u64 = coeffs.iter().fold(0u64, |acc, &c| add_mod(acc, c, RING_Q));
        assert_eq!(sum, 1, "Σ λ_j(0) must equal 1 mod q");
    }

    #[test]
    fn lagrange_reconstructs_constant() {
        // Polynomial f(x) = c (constant). Each share share_j = c. Then
        // f(0) = c, and Σ c · λ_j = c.
        let secret = vec![12345u64; 4];
        let shares = vec![
            (1usize, secret.clone()),
            (2usize, secret.clone()),
            (3usize, secret.clone()),
        ];
        let reconstructed = lagrange_combine_shares(&shares);
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn lagrange_reconstructs_linear_polynomial() {
        // f(x) = a*x + b, secret is f(0) = b. With three shares we
        // should recover b regardless of which two we pick.
        let a: u64 = 7;
        let b: u64 = 42;
        let eval = |x: u64| add_mod(mul_mod(a, x % RING_Q, RING_Q), b, RING_Q);
        let shares: Vec<(usize, Vec<u64>)> =
            (1..=4).map(|i| (i, vec![eval(i as u64); 1])).collect();

        // Subset {1,2,3}
        let r1 = lagrange_combine_shares(&shares[..3]);
        assert_eq!(r1, vec![b]);

        // Subset {2,3,4}
        let r2 = lagrange_combine_shares(&shares[1..4]);
        assert_eq!(r2, vec![b]);
    }

    #[test]
    fn lagrange_coefficient_two_party() {
        // For indices {1, 2}:
        //   λ_1(0) = (0 - 2)/(1 - 2) = -2/-1 = 2
        //   λ_2(0) = (0 - 1)/(2 - 1) = -1/1 = -1 = q - 1
        let lambda1 = lagrange_coefficient_at_zero(1, &[1, 2], RING_Q);
        let lambda2 = lagrange_coefficient_at_zero(2, &[1, 2], RING_Q);
        assert_eq!(lambda1, 2);
        assert_eq!(lambda2, RING_Q - 1);
        // And λ_1 + λ_2 = 1 mod q.
        assert_eq!(add_mod(lambda1, lambda2, RING_Q), 1);
    }

    #[test]
    fn add_poly_is_componentwise_mod_q() {
        let a = vec![RING_Q - 1, 5, 10];
        let b = vec![2, RING_Q - 3, 0];
        let s = add_poly(&a, &b);
        // (q-1 + 2) mod q = 1
        // (5 + q-3) mod q = 2
        // (10 + 0) = 10
        assert_eq!(s, vec![1, 2, 10]);
    }
}
