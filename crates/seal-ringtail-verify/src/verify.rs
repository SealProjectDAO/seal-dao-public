//! The verify function itself.
//!
//! Mirrors `seal-threshold::ringtail::verify_signature_full` one-to-one,
//! including the "one-shot" simplification where `A[i][0]` and `t_i` are
//! the only matrix/vector entries that matter — because this verifier
//! only supports the single-polynomial response form the signer already
//! emits, not the general L-dimensional Ringtail response.

use alloc::boxed::Box;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_256};

use crate::challenge::expand;
use crate::field::{
    mod_sub, norm_sq, AGGREGATE_NORM_BOUND, MODULE_K, RING_N, RING_Q,
};
use crate::ntt::NttCtx;

/// Ringtail signature in a form suitable for on-chain verification.
///
/// Byte layout of `z`: 256 LE-u64 coefficients = 2048 bytes (must match
/// `seal-threshold::RingOps::to_bytes`).
pub struct Signature<'a> {
    /// Serialized response polynomial z (2048 bytes, LE-u64 coefficients).
    pub z: &'a [u8],
    /// 32-byte challenge hash: SHA3-256(D || message).
    pub challenge: &'a [u8; 32],
    /// Number of distinct committee members whose shares contributed.
    pub participant_count: usize,
}

/// Public parameters needed for verification.
///
/// `matrix_a` has K rows, one polynomial each (the verifier only uses
/// the first column of the signer-side K×L matrix). `public_key_t` is a
/// K-vector of polynomials. Each polynomial is 2048 bytes.
pub struct PublicParams<'a> {
    pub matrix_a: [&'a [u8]; MODULE_K],
    pub public_key_t: [&'a [u8]; MODULE_K],
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    InsufficientSigners { needed: usize, have: usize },
    BadLength,
    NormTooLarge,
    TrivialChallenge,
    ChallengeMismatch,
}

/// Verify a Ringtail threshold signature against the public parameters.
///
/// Pass a reused `NttCtx` — building the twiddle tables is ~300 mod_muls
/// and not something to repeat per call in a loop. For one-shot on-chain
/// verify, construct the context inside the call.
pub fn verify(
    ctx: &NttCtx,
    signature: &Signature,
    public_params: &PublicParams,
    message: &[u8],
    threshold: usize,
) -> Result<(), VerifyError> {
    // 1. Participant count.
    if signature.participant_count < threshold {
        return Err(VerifyError::InsufficientSigners {
            needed: threshold,
            have: signature.participant_count,
        });
    }

    // 2. Deserialize z.
    let mut z = Box::new([0u64; RING_N]);
    deserialize_poly(signature.z, &mut z)?;

    // 3. Norm bound: compare squared norm to squared bound.
    let bound_sq = (AGGREGATE_NORM_BOUND as u128) * (AGGREGATE_NORM_BOUND as u128);
    if norm_sq(&z[..]) > bound_sq {
        return Err(VerifyError::NormTooLarge);
    }

    // 4. Non-trivial challenge.
    if signature.challenge.iter().all(|&b| b == 0) {
        return Err(VerifyError::TrivialChallenge);
    }

    // 5. Expand challenge polynomial.
    let mut c_poly = Box::new([0u64; RING_N]);
    expand(signature.challenge, &mut c_poly);

    // 6. Recompute D' = A[i][0] * z - c * t_i for each row i; collect
    //    the serialized bytes of each D'_i.
    //
    //    Byte ordering and per-polynomial byte count must match the host
    //    signer exactly, otherwise the recomputed challenge won't equal
    //    `signature.challenge`.
    let mut d_prime_bytes: Vec<u8> = Vec::with_capacity(MODULE_K * RING_N * 8 + message.len());
    let mut a_z = Box::new([0u64; RING_N]);
    let mut c_t = Box::new([0u64; RING_N]);
    for i in 0..MODULE_K {
        let mut a_row = Box::new([0u64; RING_N]);
        let mut t_i = Box::new([0u64; RING_N]);
        deserialize_poly(public_params.matrix_a[i], &mut a_row)?;
        deserialize_poly(public_params.public_key_t[i], &mut t_i)?;

        ctx.poly_mul(&a_row, &z, &mut a_z);
        ctx.poly_mul(&c_poly, &t_i, &mut c_t);

        // D'_i = a_z - c_t
        for j in 0..RING_N {
            let v = mod_sub(a_z[j], c_t[j]);
            d_prime_bytes.extend_from_slice(&v.to_le_bytes());
        }
    }

    // 7. Append message and hash.
    d_prime_bytes.extend_from_slice(message);
    let mut hasher = Sha3_256::new();
    hasher.update(&d_prime_bytes);
    let recomputed = hasher.finalize();

    // 8. Challenge equality (constant-time not strictly required — a
    //    mismatch is a public fact — but cheap anyway).
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= recomputed[i] ^ signature.challenge[i];
    }
    if diff != 0 {
        return Err(VerifyError::ChallengeMismatch);
    }

    Ok(())
}

fn deserialize_poly(bytes: &[u8], out: &mut [u64; RING_N]) -> Result<(), VerifyError> {
    if bytes.len() < RING_N * 8 {
        return Err(VerifyError::BadLength);
    }
    for i in 0..RING_N {
        let off = i * 8;
        let arr: [u8; 8] = bytes[off..off + 8]
            .try_into()
            .map_err(|_| VerifyError::BadLength)?;
        // Host signer does `from_bytes % RING_Q` to reduce. Mirror it so
        // canonical and non-canonical encodings of the same coefficient
        // produce the same internal value.
        out[i] = u64::from_le_bytes(arr) % RING_Q;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // An all-zero signature should fail on the trivial-challenge check,
    // assuming participant count and length are fine but challenge is
    // all zero.
    #[test]
    fn rejects_trivial_challenge() {
        let z = [0u8; RING_N * 8];
        let challenge = [0u8; 32];
        let sig = Signature { z: &z, challenge: &challenge, participant_count: 67 };
        let a_bytes = [0u8; RING_N * 8];
        let t_bytes = [0u8; RING_N * 8];
        let pp = PublicParams {
            matrix_a: [&a_bytes[..]; MODULE_K],
            public_key_t: [&t_bytes[..]; MODULE_K],
        };
        let ctx = NttCtx::new();
        let err = verify(&ctx, &sig, &pp, b"msg", 67).unwrap_err();
        assert_eq!(err, VerifyError::TrivialChallenge);
    }

    #[test]
    fn rejects_insufficient_signers() {
        let z = [0u8; RING_N * 8];
        let challenge = [1u8; 32];
        let sig = Signature { z: &z, challenge: &challenge, participant_count: 50 };
        let a_bytes = [0u8; RING_N * 8];
        let t_bytes = [0u8; RING_N * 8];
        let pp = PublicParams {
            matrix_a: [&a_bytes[..]; MODULE_K],
            public_key_t: [&t_bytes[..]; MODULE_K],
        };
        let ctx = NttCtx::new();
        let err = verify(&ctx, &sig, &pp, b"msg", 67).unwrap_err();
        assert_eq!(err, VerifyError::InsufficientSigners { needed: 67, have: 50 });
    }

    #[test]
    fn rejects_bad_length() {
        let z = [0u8; 100]; // too short
        let challenge = [1u8; 32];
        let sig = Signature { z: &z, challenge: &challenge, participant_count: 67 };
        let a_bytes = [0u8; RING_N * 8];
        let t_bytes = [0u8; RING_N * 8];
        let pp = PublicParams {
            matrix_a: [&a_bytes[..]; MODULE_K],
            public_key_t: [&t_bytes[..]; MODULE_K],
        };
        let ctx = NttCtx::new();
        let err = verify(&ctx, &sig, &pp, b"msg", 67).unwrap_err();
        assert_eq!(err, VerifyError::BadLength);
    }
}
