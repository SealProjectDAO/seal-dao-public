//! Byte-for-byte compatibility with `seal-threshold`'s `verify_signature_full`.
//!
//! # Scope
//!
//! End-to-end cross-check (sign with `seal-threshold`, verify with this
//! crate) now works via `sign_single_full` + `generate_public_params_no_error`,
//! which together implement the paper-shaped commitment `D_i = A·r_i + e_i`
//! and a public key without the trapdoor error term. The smudging-on
//! variant is still expected to fail (Ringtail rounding is a follow-up
//! track), so the cross-check uses the smudging-off mode where challenge
//! recomputation is byte-exact.
//!
//! Tests below exercise:
//!  - end-to-end accept of a real `sign_single_full` signature (host + BPF),
//!  - tamper-rejection (challenge flip, message change),
//!  - module-constant equality so the two crates can't silently drift on
//!    `RING_N`, `RING_Q`, or `MODULE_K`.

use seal_ringtail_verify::{field::{MODULE_K, RING_N, RING_Q}, ntt::NttCtx, verify::{PublicParams, Signature}, VerifyError};
use seal_threshold::ringtail::{
    expand_challenge, generate_public_params, generate_public_params_no_error,
    sign_single_full, verify_signature_full, PublicParams as HostParams,
    RingtailSignature as HostSignature, RingOps, MODULE_L,
};
use seal_threshold::ntt::HandRolledOps;
use seal_threshold::traits::Bitfield;
use sha3::{Digest, Sha3_256};

/// Build a (public_params, signature) tuple that satisfies `verify_signature_full`.
///
/// Strategy: pick arbitrary z with small coefficients, compute each D'_i as
/// the host verifier would, hash D'_0 || ... || D'_{K-1} || message to get
/// the "challenge", and return the tuple. Because the host signer byte
/// format for matrix/key/poly is `LE-u64 per coefficient`, the resulting
/// `HostSignature` will pass `verify_signature_full`.
fn build_valid_sig(
    ring: &HandRolledOps,
    message: &[u8],
    z_poly: Vec<u64>,
) -> (HostParams, HostSignature, Vec<u8>) {
    // Build public params the normal way (random matrix A, secret s, t = A*s + e).
    let (params, _secret) = generate_public_params(ring);

    // Fake the challenge: any 32-byte non-zero hash. Expand it into c.
    let seed_challenge: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"crosscheck-seed");
        h.update(message);
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    };
    let c_poly = expand_challenge(ring, &seed_challenge);

    // Compute D'_i = A[i][0]*z - c*t_i for each i, serialize.
    let mut d_prime_bytes: Vec<u8> = Vec::new();
    let k = params.matrix_a.len().min(params.public_key_t.len());
    for i in 0..k {
        let a_i0 = ring.from_bytes(&params.matrix_a[i][0]).unwrap();
        let t_i = ring.from_bytes(&params.public_key_t[i]).unwrap();
        let a_z = ring.mul(&a_i0, &z_poly);
        let c_t = ring.mul(&c_poly, &t_i);
        let d_i = ring.sub(&a_z, &c_t);
        d_prime_bytes.extend_from_slice(&ring.to_bytes(&d_i));
    }
    d_prime_bytes.extend_from_slice(message);

    // The signature's challenge is the hash of that stream — so the verifier
    // recomputes the same bytes and gets the same hash.
    let mut h = Sha3_256::new();
    h.update(&d_prime_bytes);
    let challenge: [u8; 32] = h.finalize().into();

    let mut participants = Bitfield::new(100);
    for i in 0..67 {
        participants.set(i);
    }

    let sig = HostSignature {
        z: ring.to_bytes(&z_poly),
        challenge,
        participants,
    };

    (params, sig, d_prime_bytes)
}

/// End-to-end cross-check using `sign_single_full` (the full-protocol
/// signer with `D_i = A·r_i + e_i`-shaped commitment), `e_i = 0` smudging,
/// and `t = A·s` keygen. The host verifier and the BPF verifier must
/// both accept the produced signature byte-for-byte from the same inputs.
#[test]
fn valid_signature_accepted_by_both() {
    let ring = HandRolledOps::new();
    let message = b"cross-chain unlock: recipient=abc amount=100";

    let (params, sk_bytes) = generate_public_params_no_error(&ring);
    let sig = sign_single_full(&params, &sk_bytes, message, false /* no smudging */)
        .expect("sign_single_full should succeed");

    // Host-side verify must pass.
    verify_signature_full(&ring, &sig, &params, message, 1)
        .expect("host verifier rejected sign_single_full output");

    // BPF-compat verifier must also pass with identical inputs.
    let ctx = NttCtx::new();
    let matrix_a_bytes: Vec<&[u8]> = params.matrix_a.iter().map(|row| row[0].as_slice()).collect();
    let t_bytes: Vec<&[u8]> = params.public_key_t.iter().map(|p| p.as_slice()).collect();

    let bpf_sig = Signature {
        z: &sig.z,
        challenge: &sig.challenge,
        participant_count: sig.participants.count(),
    };
    let bpf_pp = PublicParams {
        matrix_a: [
            matrix_a_bytes[0], matrix_a_bytes[1], matrix_a_bytes[2], matrix_a_bytes[3],
            matrix_a_bytes[4], matrix_a_bytes[5], matrix_a_bytes[6], matrix_a_bytes[7],
        ],
        public_key_t: [
            t_bytes[0], t_bytes[1], t_bytes[2], t_bytes[3],
            t_bytes[4], t_bytes[5], t_bytes[6], t_bytes[7],
        ],
    };

    seal_ringtail_verify::verify(&ctx, &bpf_sig, &bpf_pp, message, 1)
        .expect("BPF-compat verifier rejected a signature the host accepted");
}

/// End-to-end cross-check, multi-party (n-of-n with shared secret 2·sk
/// inside `t`, mirroring the seal-threshold internal test). Confirms
/// the BPF verifier accepts a real two-party aggregate that the host
/// verifier accepts.
#[test]
fn valid_signature_accepted_by_both_n_of_n() {
    use seal_threshold::ringtail::{
        aggregate_commitments, aggregate_responses_full, RingtailParty, MODULE_K as HOST_K,
    };

    let ring = HandRolledOps::new();
    let sk = ring.sample_gaussian(6.108);
    let two_sk = ring.add(&sk, &sk);

    // Build params with t = A·(2·sk).
    let mut matrix_a_col0_polys = Vec::with_capacity(HOST_K);
    let mut matrix_a_bytes_h: Vec<Vec<Vec<u8>>> = Vec::with_capacity(HOST_K);
    for _ in 0..HOST_K {
        let col0 = ring.sample_uniform();
        let mut row_bytes = Vec::with_capacity(MODULE_L);
        row_bytes.push(ring.to_bytes(&col0));
        for _ in 1..MODULE_L {
            row_bytes.push(ring.to_bytes(&ring.sample_uniform()));
        }
        matrix_a_col0_polys.push(col0);
        matrix_a_bytes_h.push(row_bytes);
    }
    let public_key_t_bytes_h: Vec<Vec<u8>> = matrix_a_col0_polys
        .iter()
        .map(|a| ring.to_bytes(&ring.mul(a, &two_sk)))
        .collect();
    let host_params = HostParams {
        matrix_a: matrix_a_bytes_h,
        public_key_t: public_key_t_bytes_h,
    };

    let mut p0 = RingtailParty::new(0, sk.clone(), HandRolledOps::new());
    let mut p1 = RingtailParty::new(1, sk.clone(), HandRolledOps::new());
    let mac_key = b"shared-mac-key";
    let r1_0 = p0.round1_full(&host_params, mac_key, false).unwrap();
    let r1_1 = p1.round1_full(&host_params, mac_key, false).unwrap();

    let aggregated = aggregate_commitments(&ring, &[r1_0.clone(), r1_1.clone()]).unwrap();
    let message = b"BPF cross-check 2-of-2";
    let r2_0 = p0.round2_full(&aggregated, message).unwrap();
    let r2_1 = p1.round2_full(&aggregated, message).unwrap();
    let sig =
        aggregate_responses_full(&ring, &aggregated, &[r2_0, r2_1], message, 2, 2).unwrap();

    // Host verifier accepts.
    verify_signature_full(&ring, &sig, &host_params, message, 2)
        .expect("host verifier must accept 2-of-2 full-protocol sig");

    // BPF verifier accepts the same bytes.
    let ctx = NttCtx::new();
    let matrix_a_bytes: Vec<&[u8]> =
        host_params.matrix_a.iter().map(|row| row[0].as_slice()).collect();
    let t_bytes: Vec<&[u8]> = host_params.public_key_t.iter().map(|p| p.as_slice()).collect();
    let bpf_sig = Signature {
        z: &sig.z,
        challenge: &sig.challenge,
        participant_count: sig.participants.count(),
    };
    let bpf_pp = PublicParams {
        matrix_a: [
            matrix_a_bytes[0], matrix_a_bytes[1], matrix_a_bytes[2], matrix_a_bytes[3],
            matrix_a_bytes[4], matrix_a_bytes[5], matrix_a_bytes[6], matrix_a_bytes[7],
        ],
        public_key_t: [
            t_bytes[0], t_bytes[1], t_bytes[2], t_bytes[3],
            t_bytes[4], t_bytes[5], t_bytes[6], t_bytes[7],
        ],
    };
    seal_ringtail_verify::verify(&ctx, &bpf_sig, &bpf_pp, message, 2)
        .expect("BPF verifier must accept the same 2-of-2 sig");
}

/// Flipping one bit of the challenge produces a mismatch.
#[test]
fn tampered_challenge_rejected_by_both() {
    let ring = HandRolledOps::new();
    let message = b"cross-chain unlock: recipient=abc amount=100";
    let z_poly: Vec<u64> = (0..RING_N).map(|i| (i as u64) % 100).collect();
    let (params, mut sig, _) = build_valid_sig(&ring, message, z_poly);

    sig.challenge[0] ^= 1;

    // Host rejects.
    assert!(verify_signature_full(&ring, &sig, &params, message, 67).is_err());

    // BPF verifier also rejects.
    let ctx = NttCtx::new();
    let matrix_a_bytes: Vec<&[u8]> = params.matrix_a.iter().map(|row| row[0].as_slice()).collect();
    let t_bytes: Vec<&[u8]> = params.public_key_t.iter().map(|p| p.as_slice()).collect();

    let bpf_sig = Signature {
        z: &sig.z,
        challenge: &sig.challenge,
        participant_count: sig.participants.count(),
    };
    let bpf_pp = PublicParams {
        matrix_a: [
            matrix_a_bytes[0], matrix_a_bytes[1], matrix_a_bytes[2], matrix_a_bytes[3],
            matrix_a_bytes[4], matrix_a_bytes[5], matrix_a_bytes[6], matrix_a_bytes[7],
        ],
        public_key_t: [
            t_bytes[0], t_bytes[1], t_bytes[2], t_bytes[3],
            t_bytes[4], t_bytes[5], t_bytes[6], t_bytes[7],
        ],
    };

    let err = seal_ringtail_verify::verify(&ctx, &bpf_sig, &bpf_pp, message, 67).unwrap_err();
    assert_eq!(err, VerifyError::ChallengeMismatch);
}

/// Different message → challenge recomputation disagrees → BPF verify rejects.
#[test]
fn wrong_message_rejected_by_bpf() {
    let ring = HandRolledOps::new();
    let message = b"msg A";
    let z_poly: Vec<u64> = (0..RING_N).map(|i| (i as u64) % 100).collect();
    let (params, sig, _) = build_valid_sig(&ring, message, z_poly);

    // Verify with a different message.
    let ctx = NttCtx::new();
    let matrix_a_bytes: Vec<&[u8]> = params.matrix_a.iter().map(|row| row[0].as_slice()).collect();
    let t_bytes: Vec<&[u8]> = params.public_key_t.iter().map(|p| p.as_slice()).collect();

    let bpf_sig = Signature {
        z: &sig.z,
        challenge: &sig.challenge,
        participant_count: sig.participants.count(),
    };
    let bpf_pp = PublicParams {
        matrix_a: [
            matrix_a_bytes[0], matrix_a_bytes[1], matrix_a_bytes[2], matrix_a_bytes[3],
            matrix_a_bytes[4], matrix_a_bytes[5], matrix_a_bytes[6], matrix_a_bytes[7],
        ],
        public_key_t: [
            t_bytes[0], t_bytes[1], t_bytes[2], t_bytes[3],
            t_bytes[4], t_bytes[5], t_bytes[6], t_bytes[7],
        ],
    };

    let err = seal_ringtail_verify::verify(&ctx, &bpf_sig, &bpf_pp, b"msg B", 67).unwrap_err();
    assert_eq!(err, VerifyError::ChallengeMismatch);
}

/// Documents that the current `AGGREGATE_NORM_BOUND = 2^60` is not reachable
/// by a single-polynomial z with 256 coefficients mod a 48-bit q. The bound
/// was calibrated for 100-party aggregate responses (`~2^56`), so for any
/// single z with |coeff| < q/2 ≈ 2^47, `sqrt(256 * (q/2)^2) = 8q ≈ 2^51`
/// is the maximum possible, well under the bound. `#[ignore]` until either
/// the bound is tightened or the test is re-purposed for multi-party
/// aggregate-response inputs.
#[ignore = "AGGREGATE_NORM_BOUND unreachable for single-poly z; test needs aggregate"]
#[test]
fn oversized_z_rejected_by_norm_check() {
    let ring = HandRolledOps::new();
    let message = b"m";
    // All coefficients just under q — centered-abs is ~q/2, squared and
    // summed over 256 coefficients easily blows past (2^60)^2.
    let z_poly: Vec<u64> = vec![RING_Q / 2 - 1; RING_N];

    let (params, sig, _) = build_valid_sig(&ring, message, z_poly);

    let ctx = NttCtx::new();
    let matrix_a_bytes: Vec<&[u8]> = params.matrix_a.iter().map(|row| row[0].as_slice()).collect();
    let t_bytes: Vec<&[u8]> = params.public_key_t.iter().map(|p| p.as_slice()).collect();

    let bpf_sig = Signature {
        z: &sig.z,
        challenge: &sig.challenge,
        participant_count: sig.participants.count(),
    };
    let bpf_pp = PublicParams {
        matrix_a: [
            matrix_a_bytes[0], matrix_a_bytes[1], matrix_a_bytes[2], matrix_a_bytes[3],
            matrix_a_bytes[4], matrix_a_bytes[5], matrix_a_bytes[6], matrix_a_bytes[7],
        ],
        public_key_t: [
            t_bytes[0], t_bytes[1], t_bytes[2], t_bytes[3],
            t_bytes[4], t_bytes[5], t_bytes[6], t_bytes[7],
        ],
    };

    let err = seal_ringtail_verify::verify(&ctx, &bpf_sig, &bpf_pp, message, 67).unwrap_err();
    assert_eq!(err, VerifyError::NormTooLarge);
}

/// Sanity: MODULE_K must match across the two crates. A divergence here
/// would silently misuse the fixed-size array API in `PublicParams`.
#[test]
fn module_k_matches_host() {
    assert_eq!(MODULE_K, seal_threshold::ringtail::MODULE_K);
    assert_eq!(RING_N, seal_threshold::ringtail::RING_N);
    assert_eq!(RING_Q, seal_threshold::ringtail::RING_Q);
    // L differs — the BPF verifier only uses the first column (L=1 slot).
    let _ = MODULE_L; // ensure the import is alive
}
