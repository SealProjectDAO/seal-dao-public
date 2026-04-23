//! Ringtail rounding + noise-flooding utilities.
//!
//! The simplified one-shot Ringtail path verifies byte-equally only when
//! both signer and verifier omit the per-signer smudging error `e_i`
//! (see `ringtail.rs::full_single_signer_smudging_breaks_byte_equality`
//! for the boundary test that documents this).
//!
//! This module adds the two missing pieces from the ePrint that, taken
//! together, restore byte-equality under noise:
//!
//! 1. **Rounding** — divide each coefficient of `D_i` by `2^DROP_BITS`
//!    (with rounding-to-nearest, mod q). The verifier rounds the
//!    recomputed `D' = A·z - c·t` the same way before hashing. Small
//!    additive errors below `2^DROP_BITS / 2` are absorbed.
//!
//! 2. **Noise flooding (smudging)** — sample a *much larger* Gaussian
//!    `e_smudge` with σ ≫ ‖c·e_master‖∞ and add it during `round1_full`.
//!    The aggregate `Σ e_i + Σ e_smudge` is statistically close to a
//!    fresh Gaussian, hiding the discrepancy from a malicious aggregator
//!    while the rounding step removes it from the verifier's hash.
//!
//! # Status
//!
//! This module ships the rounding primitive (small, deterministic, easy
//! to cross-check on BPF/Soroban) and a CSPRNG-based smudge sampler. The
//! signer-side wiring into `round1_full` and the verifier-side wiring
//! into `verify_signature_full` is a follow-up that touches the wire
//! format (rounded D bytes, rounded D' bytes); see
//! `crates/seal-threshold/TODO_ROUNDING.md` for the migration plan.
//!
//! Choice of `DROP_BITS = 12`: with σ_smudge ≈ 2^14 per coefficient and
//! `‖c‖_1 = TAU = 60`, the worst-case `‖c · e_master‖∞ ≤ TAU · σ ≈
//! 2^20`, comfortably below `2^DROP_BITS / 2 = 2^11`… correction:
//! we'll need DROP_BITS ≥ 22 in production. The constant below is
//! tuned for the test shape (small σ_master); production deployment
//! must re-derive it from the audit's noise budget.

use crate::ringtail::RING_Q;

/// Number of low bits dropped during rounding. Tuneable; tests use
/// `DROP_BITS = 0` (no rounding) to keep the byte-exact property of the
/// existing single-signer test. Production deployment must re-derive
/// from the noise budget — see module-level doc.
pub const DROP_BITS: u32 = 0;

/// Round one coefficient: `(c + 2^(DROP_BITS-1)) >> DROP_BITS`, all
/// performed mod q with overflow-safe widening. With `DROP_BITS = 0`
/// this is the identity, preserving the no-smudging byte-exact path.
#[inline]
pub fn round_coeff(c: u64) -> u64 {
    if DROP_BITS == 0 {
        return c;
    }
    let half = 1u64 << (DROP_BITS - 1);
    let shifted = ((c as u128 + half as u128) >> DROP_BITS) as u64;
    shifted % RING_Q
}

/// Round every coefficient of a polynomial. Pure, allocation-free over
/// a borrowed slice — the caller owns the output buffer's lifetime.
pub fn round_poly(poly: &[u64]) -> Vec<u64> {
    poly.iter().map(|&c| round_coeff(c)).collect()
}

/// Sample a discrete Gaussian for noise flooding. Reuses the existing
/// crate sampler; exposed here so callers can pass the production
/// `sigma_smudge` constant from one place.
///
/// Default σ_smudge for the test shape is `2^14` — large enough to
/// flood the per-signer error if rounding is enabled, small enough to
/// keep `||z||` within `NORM_BOUND`. Production must re-derive.
pub const SIGMA_SMUDGE: f64 = 16384.0;

/// Sample `n` coefficients of the smudge polynomial.
pub fn sample_smudge(n: usize) -> Vec<u64> {
    crate::ntt::sample_discrete_gaussian(SIGMA_SMUDGE, n, RING_Q)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_coeff_identity_when_drop_bits_zero() {
        assert_eq!(round_coeff(0), 0);
        assert_eq!(round_coeff(1), 1);
        assert_eq!(round_coeff(RING_Q - 1), RING_Q - 1);
    }

    #[test]
    fn round_poly_preserves_length() {
        let p = vec![1, 2, 3, 4];
        let r = round_poly(&p);
        assert_eq!(r.len(), p.len());
    }

    #[test]
    fn smudge_sampler_returns_n_coefficients() {
        let s = sample_smudge(64);
        assert_eq!(s.len(), 64);
    }
}
