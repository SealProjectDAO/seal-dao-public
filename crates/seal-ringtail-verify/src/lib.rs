//! Ringtail signature verifier, ported to `no_std` + `alloc` for Solana BPF.
//!
//! This crate is the on-chain counterpart of
//! `seal-threshold::verify_signature_full`. It exists because `seal-threshold`
//! depends on `std`, `rand`, `subtle`, and `zeroize` in ways that don't build
//! for the `sbf-solana-solana` target.
//!
//! # What's ported
//!
//! - 48-bit prime modular arithmetic (`RING_Q = 0x1000000004A01`)
//! - Cooley-Tukey DIT NTT over `R_q = Z_q[X] / (X^256 + 1)` (negacyclic)
//! - Sparse challenge polynomial expansion (`TAU = 60` non-zero ±1 coeffs)
//! - The verify predicate itself: participant count, aggregate norm bound,
//!   `A*z - c*t` recomputation, challenge hash equality
//!
//! # What's not here
//!
//! - No signing. No key generation. No randomness. No RingOps trait — verify
//!   only needs the concrete `RING_Q`/`RING_N` parameters.
//! - No SPDZ / MPC. This is strictly the lattice-signature verification.
//!
//! # Byte compatibility
//!
//! The wire format for `z` is 256 little-endian `u64` coefficients (2048 B).
//! `matrix_a[i][0]` and `public_key_t[i]` are serialized the same way.
//! `challenge` is a 32-byte SHA3-256 digest. These match the host-side
//! signer byte-for-byte; see tests in `tests/crosscheck.rs` (gated on the
//! `std-crosscheck` feature).

#![cfg_attr(not(feature = "std-crosscheck"), no_std)]

extern crate alloc;

pub mod field;
pub mod ntt;
pub mod challenge;
pub mod verify;

pub use field::{RING_N, RING_Q, AGGREGATE_NORM_BOUND};
pub use verify::{verify, VerifyError, Signature, PublicParams};
