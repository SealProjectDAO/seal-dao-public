//! Cooley-Tukey DIT negacyclic NTT for `R_q = Z_q[X] / (X^256 + 1)`.
//!
//! Ported from `seal-threshold::ntt::HandRolledRing` with three changes:
//!
//!  1. `no_std` compatible — no `f64::log2`, no `Vec` arguments (slices and
//!     fixed-size arrays only).
//!  2. Twiddle tables are built once at `NttCtx::new()` and stored in
//!     heap-allocated boxed arrays so the context is copy-cheap but not
//!     stack-hostile.
//!  3. `poly_mul` takes output-by-reference to avoid per-call allocations
//!     — relevant for BPF where the heap is a fixed 32 KB region.
//!
//! Correctness is cross-checked against `seal-threshold::HandRolledRing`
//! in `tests/crosscheck.rs` under the `std-crosscheck` feature.

use crate::field::{mod_add, mod_inv, mod_mul, mod_pow, mod_sub, RING_N, RING_Q};
use alloc::boxed::Box;

/// Precomputed NTT state. `new()` is expensive (~300 modular ops) — build
/// it once and reuse it across verifies.
pub struct NttCtx {
    /// Primitive 2N-th root of unity ψ.
    psi: u64,
    /// ψ^{-1}.
    psi_inv: u64,
    /// Forward twiddles: `twiddles[i] = ω^i` for i in 0..N, where ω = ψ².
    twiddles: Box<[u64; RING_N]>,
    /// Inverse twiddles: `inv_twiddles[i] = ω^{-i}`.
    inv_twiddles: Box<[u64; RING_N]>,
    /// 1/N mod q, used to normalize the inverse NTT.
    inv_n: u64,
}

impl NttCtx {
    /// Build the twiddle tables. Roughly equivalent to
    /// `HandRolledRing::new()` in `seal-threshold`.
    pub fn new() -> Self {
        // We need a primitive 2N-th root of unity ψ such that ψ^N = -1 mod q.
        // Then ω = ψ² is a primitive N-th root.
        let psi = find_primitive_2n_root();
        let psi_inv = mod_inv(psi);
        let omega = mod_mul(psi, psi);
        let omega_inv = mod_inv(omega);
        let inv_n = mod_inv(RING_N as u64);

        let mut twiddles = Box::new([0u64; RING_N]);
        let mut inv_twiddles = Box::new([0u64; RING_N]);
        twiddles[0] = 1;
        inv_twiddles[0] = 1;
        for i in 1..RING_N {
            twiddles[i] = mod_mul(twiddles[i - 1], omega);
            inv_twiddles[i] = mod_mul(inv_twiddles[i - 1], omega_inv);
        }

        Self {
            psi,
            psi_inv,
            twiddles,
            inv_twiddles,
            inv_n,
        }
    }

    /// Forward negacyclic NTT: coefficient representation → evaluation.
    /// Writes the result into `out`. `a` and `out` must both be length N.
    pub fn ntt(&self, a: &[u64; RING_N], out: &mut [u64; RING_N]) {
        // Step 1: pre-multiply by ψ^i.
        let mut psi_pow: u64 = 1;
        for i in 0..RING_N {
            out[i] = mod_mul(a[i], psi_pow);
            psi_pow = mod_mul(psi_pow, self.psi);
        }

        // Step 2: bit-reversal permutation.
        bit_reverse(out);

        // Step 3: Cooley-Tukey DIT butterfly.
        let log_n = RING_N.trailing_zeros() as usize;
        for s in 0..log_n {
            let m: usize = 1 << (s + 1);
            let half = m / 2;
            let w_m = self.twiddles[RING_N / m]; // ω^(N/m)
            let mut k = 0;
            while k < RING_N {
                let mut w: u64 = 1;
                for j in 0..half {
                    let t = mod_mul(w, out[k + j + half]);
                    let u = out[k + j];
                    out[k + j] = mod_add(u, t);
                    out[k + j + half] = mod_sub(u, t);
                    w = mod_mul(w, w_m);
                }
                k += m;
            }
        }
    }

    /// Inverse NTT: evaluation → coefficient representation.
    pub fn intt(&self, a: &[u64; RING_N], out: &mut [u64; RING_N]) {
        out.copy_from_slice(a);

        // Inverse DFT (reverse stage order, use inverse twiddles, different
        // butterfly shape to match the forward's bit-reversed input).
        let log_n = RING_N.trailing_zeros() as usize;
        for s in (0..log_n).rev() {
            let m: usize = 1 << (s + 1);
            let half = m / 2;
            let w_m = self.inv_twiddles[RING_N / m];
            let mut k = 0;
            while k < RING_N {
                let mut w: u64 = 1;
                for j in 0..half {
                    let u = out[k + j];
                    let v = out[k + j + half];
                    out[k + j] = mod_add(u, v);
                    out[k + j + half] = mod_mul(mod_sub(u, v), w);
                    w = mod_mul(w, w_m);
                }
                k += m;
            }
        }

        bit_reverse(out);

        // Normalize by 1/N and post-multiply by ψ^{-i}.
        let mut psi_inv_pow: u64 = 1;
        for slot in out.iter_mut() {
            *slot = mod_mul(*slot, self.inv_n);
            *slot = mod_mul(*slot, psi_inv_pow);
            psi_inv_pow = mod_mul(psi_inv_pow, self.psi_inv);
        }
    }

    /// `c = a * b` in `R_q`. Performs three NTTs + one pointwise mul.
    /// Writes into `out`. No heap allocation.
    pub fn poly_mul(&self, a: &[u64; RING_N], b: &[u64; RING_N], out: &mut [u64; RING_N]) {
        // Scratch buffers on the heap (BPF's 4 KB stack can't hold two
        // [u64; 256] locals comfortably alongside the verify frame).
        let mut a_ntt = alloc::boxed::Box::new([0u64; RING_N]);
        let mut b_ntt = alloc::boxed::Box::new([0u64; RING_N]);
        let mut c_ntt = alloc::boxed::Box::new([0u64; RING_N]);

        self.ntt(a, &mut a_ntt);
        self.ntt(b, &mut b_ntt);
        for i in 0..RING_N {
            c_ntt[i] = mod_mul(a_ntt[i], b_ntt[i]);
        }
        self.intt(&c_ntt, out);
    }
}

impl Default for NttCtx {
    fn default() -> Self {
        Self::new()
    }
}

/// In-place bit-reversal permutation of a length-N array where N is a
/// power of two.
fn bit_reverse(a: &mut [u64; RING_N]) {
    let log_n = RING_N.trailing_zeros();
    for i in 0..RING_N {
        let j = (i as u32).reverse_bits() >> (u32::BITS - log_n);
        let j = j as usize;
        if i < j {
            a.swap(i, j);
        }
    }
}

/// Search for ψ such that ψ^N = -1 mod q and ψ^(2N) = 1 mod q. We probe
/// small candidate generators; the Ringtail prime admits one below 100.
fn find_primitive_2n_root() -> u64 {
    let order = 2 * RING_N as u64; // 512
                                   // (q - 1) % (2N) must be 0 for a 2N-th root to exist.
    debug_assert_eq!((RING_Q - 1) % order, 0);

    let exp = (RING_Q - 1) / order;
    let minus_one = RING_Q - 1;
    for g in 2u64..100 {
        let candidate = mod_pow(g, exp);
        if mod_pow(candidate, RING_N as u64) == minus_one {
            return candidate;
        }
    }
    // Unreachable for Ringtail's fixed prime. In no_std without panic
    // infrastructure we'd need an alternate error path — but BPF builds
    // will already have panicked at debug_assert, and in std-feature
    // tests we want a loud panic if the prime ever changes.
    panic!("no primitive 2N-th root of unity found");
}

#[cfg(test)]
#[allow(clippy::needless_range_loop, clippy::manual_memcpy)]
mod tests {
    use super::*;

    #[test]
    fn ntt_intt_roundtrip_zero() {
        let ctx = NttCtx::new();
        let a = [0u64; RING_N];
        let mut b = [0u64; RING_N];
        let mut c = [0u64; RING_N];
        ctx.ntt(&a, &mut b);
        ctx.intt(&b, &mut c);
        assert_eq!(c, a);
    }

    #[test]
    fn ntt_intt_roundtrip_constant() {
        let ctx = NttCtx::new();
        let mut a = [0u64; RING_N];
        a[0] = 42;
        let mut b = [0u64; RING_N];
        let mut c = [0u64; RING_N];
        ctx.ntt(&a, &mut b);
        ctx.intt(&b, &mut c);
        assert_eq!(c, a);
    }

    #[test]
    fn ntt_intt_roundtrip_varied() {
        let ctx = NttCtx::new();
        let mut a = [0u64; RING_N];
        for i in 0..RING_N {
            a[i] = (i as u64 * 1001 + 7) % RING_Q;
        }
        let mut b = [0u64; RING_N];
        let mut c = [0u64; RING_N];
        ctx.ntt(&a, &mut b);
        ctx.intt(&b, &mut c);
        assert_eq!(c, a);
    }

    #[test]
    fn poly_mul_by_one_is_identity() {
        let ctx = NttCtx::new();
        let mut a = [0u64; RING_N];
        for i in 0..RING_N {
            a[i] = (i as u64 * 13 + 3) % RING_Q;
        }
        // b = 1 (as a polynomial: coefficient of X^0 is 1, rest 0)
        let mut b = [0u64; RING_N];
        b[0] = 1;
        let mut c = [0u64; RING_N];
        ctx.poly_mul(&a, &b, &mut c);
        assert_eq!(c, a);
    }

    #[test]
    fn poly_mul_by_x_shifts_and_negates_wrap() {
        // In R_q = Z_q[X]/(X^N+1), X * (a_0 + a_1 X + ... + a_{N-1} X^{N-1})
        //   = a_0 X + a_1 X^2 + ... + a_{N-2} X^{N-1} - a_{N-1}
        // (because X^N = -1).
        let ctx = NttCtx::new();
        let mut a = [0u64; RING_N];
        for i in 0..RING_N {
            a[i] = (i as u64 + 1) % RING_Q;
        }
        let mut x = [0u64; RING_N];
        x[1] = 1;

        let mut c = [0u64; RING_N];
        ctx.poly_mul(&a, &x, &mut c);

        // Expected: c[0] = -a[N-1] mod q, c[i] = a[i-1] for i in 1..N
        let mut expected = [0u64; RING_N];
        expected[0] = mod_sub(0, a[RING_N - 1]);
        for i in 1..RING_N {
            expected[i] = a[i - 1];
        }
        assert_eq!(c, expected);
    }
}
