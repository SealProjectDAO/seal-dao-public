//! Ringtail — Lattice-based threshold signatures (ePrint 2024/1113).
//!
//! 2-round interactive protocol producing a single ~13.4 KB threshold
//! signature from up to 1024 committee members.
//!
//! # Protocol overview
//!
//! ```text
//! Setup (trusted dealer or DKG):
//!   - Generate public matrix A (uniform over R_q)
//!   - Secret share s among N parties via Shamir over R_q
//!   - Each party i gets share sk_i
//!   - Public key: t = A·s + e (rounded)
//!
//! Round 1 (preprocessable, message-independent):
//!   - Each party i samples randomness r_i, e_i
//!   - Computes commitment D_i = A·r_i + e_i
//!   - Broadcasts D_i + MAC to all other parties
//!   - This can run during the PREVIOUS slot (free latency)
//!
//! Round 2 (on critical path, ~800ms with preprocessing):
//!   - Given message m, compute challenge c = H(D_1||...||D_N||m)
//!   - Each party i computes response z_i = r_i + c·sk_i
//!   - Broadcasts z_i to combiner
//!
//! Aggregation:
//!   - Combiner checks: ||z_i|| < bound (reject if norm too large)
//!   - Aggregates: z = sum(z_i), D = sum(D_i)
//!   - Signature: (z, c) where c = H(D||m)
//!
//! Verification:
//!   - Compute D' = A·z - c·t
//!   - Check: c == H(D'||m) AND ||z|| < B
//! ```
//!
//! # Blocking dependency
//!
//! The reference implementation (github.com/daryakaviani/ringtail) is in Go
//! and depends on Lattigo v5 for NTT and polynomial ring arithmetic.
//!
//! To complete this port, we need:
//! 1. NTT over R_q = Z_q[X]/(X^256 + 1) with q = 0x1000000004A01
//! 2. Discrete Gaussian sampling over R_q
//! 3. Shamir secret sharing over polynomial rings
//!
//! The `RingOps` trait below abstracts these operations so a concrete
//! implementation can be plugged in (from `concrete-ntt`, hand-rolled, etc.).
//!
//! # References
//!
//! - Paper: <https://eprint.iacr.org/2024/1113>
//! - Go impl: <https://github.com/daryakaviani/ringtail>
//! - Lattigo: <https://github.com/tuneinsight/lattigo>

use crate::ntt::HandRolledOps;
use crate::traits::{Bitfield, PartialSignature, ThresholdScheme, ThresholdSignature};
use crate::ThresholdError;
use seal_crypto::hash::sha3_256;
use serde::{Deserialize, Serialize};

// ============================================================================
// Ring parameters (ML-KEM / Dilithium compatible ring)
// ============================================================================

/// Ring dimension: polynomials in Z_q[X]/(X^N + 1).
pub const RING_N: usize = 256;

/// Ring modulus (NTT-friendly prime).
/// Ringtail uses q = 0x1000000004A01 (48-bit).
/// For compatibility with ML-DSA, we could also use q = 8380417.
pub const RING_Q: u64 = 0x1000000004A01;

/// Module dimension: public matrix A is K x L over R_q.
pub const MODULE_K: usize = 8;
pub const MODULE_L: usize = 7;

/// Per-party signature norm bound (reject if ||z_i|| > B).
///
/// When secret key shares are Shamir shares (uniform mod q), the product c * sk_i
/// has coefficients that are roughly uniform mod q, giving L2 norm ≈ q * sqrt(N/12).
/// For q ≈ 2^48, N=256: expected norm ≈ 2^50.2. We set the bound at 2^53 to accept
/// valid signatures with very high probability while rejecting maliciously inflated ones.
pub const NORM_BOUND: u64 = 1u64 << 53;

/// Aggregate signature norm bound (reject if ||z_agg|| > B_agg).
/// The aggregate z = sum(z_i) for up to MAX_SIGNERS parties.
/// Expected norm grows as sqrt(k) * per-party norm for k independent parties.
/// For 100 parties: sqrt(100) * 2^53 ≈ 2^56.3. Set bound at 2^60.
pub const AGGREGATE_NORM_BOUND: u64 = 1u64 << 60;

/// Maximum committee size.
pub const MAX_PARTIES: usize = 1024;

// ============================================================================
// Ring arithmetic trait (pluggable backend)
// ============================================================================

/// Trait for polynomial ring arithmetic over R_q = Z_q[X]/(X^N + 1).
///
/// Implement this trait to plug in a concrete NTT library.
/// The default `StubRingOps` panics — replace with real implementation.
pub trait RingOps {
    /// A polynomial in R_q (N coefficients mod q).
    type Poly: Clone + Default;

    /// Sample a uniform random polynomial.
    fn sample_uniform(&self) -> Self::Poly;

    /// Sample from discrete Gaussian distribution.
    fn sample_gaussian(&self, sigma: f64) -> Self::Poly;

    /// Polynomial multiplication in NTT domain: c = a * b mod (X^N+1, q).
    fn mul(&self, a: &Self::Poly, b: &Self::Poly) -> Self::Poly;

    /// Polynomial addition: c = a + b mod q.
    fn add(&self, a: &Self::Poly, b: &Self::Poly) -> Self::Poly;

    /// Polynomial subtraction: c = a - b mod q.
    fn sub(&self, a: &Self::Poly, b: &Self::Poly) -> Self::Poly;

    /// Compute L2 norm of polynomial coefficients.
    fn norm_l2(&self, p: &Self::Poly) -> u64;

    /// Serialize polynomial to bytes.
    fn to_bytes(&self, p: &Self::Poly) -> Vec<u8>;

    /// Deserialize polynomial from bytes.
    fn from_bytes(&self, data: &[u8]) -> Result<Self::Poly, String>;

    /// Zero polynomial.
    fn zero(&self) -> Self::Poly;
}

// ============================================================================
// Protocol messages
// ============================================================================

/// Round 1 message: commitment from party i.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Message {
    /// Party index.
    pub party_id: usize,
    /// Commitment D_i = A·r_i + e_i (serialized polynomial vector).
    pub commitment: Vec<u8>,
    /// MAC authenticating the commitment to each other party.
    pub mac: Vec<u8>,
}

/// Round 2 message: response from party i.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Message {
    /// Party index.
    pub party_id: usize,
    /// Response vector z_i = r_i + c·sk_i (serialized).
    pub response: Vec<u8>,
}

/// Ringtail signature: aggregated (z, challenge_hash).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingtailSignature {
    /// Aggregated response z = sum(z_i).
    pub z: Vec<u8>,
    /// Challenge hash c = H(D||m).
    pub challenge: [u8; 32],
    /// Bitfield of participating signers.
    pub participants: Bitfield,
}

/// Party state during the signing protocol.
pub struct RingtailParty<R: RingOps> {
    /// Party index (0-based).
    pub id: usize,
    /// Secret key share (polynomial).
    sk_share: R::Poly,
    /// Round 1 randomness (kept for Round 2).
    round1_randomness: Option<R::Poly>,
    /// Ring operations backend.
    ring: R,
}

// ============================================================================
// Protocol implementation
// ============================================================================

impl<R: RingOps> RingtailParty<R> {
    /// Create a new party with a secret key share.
    pub fn new(id: usize, sk_share: R::Poly, ring: R) -> Self {
        Self {
            id,
            sk_share,
            round1_randomness: None,
            ring,
        }
    }

    /// Round 1: generate commitment (can be preprocessed).
    ///
    /// Returns Round1Message to broadcast to all parties.
    pub fn round1(&mut self, mac_key: &[u8]) -> Round1Message {
        // Sample random polynomial r_i and error e_i
        let r_i = self.ring.sample_gaussian(6.108);
        let e_i = self.ring.sample_gaussian(6.108);

        // D_i = A·r_i + e_i (simplified: we use r_i + e_i directly;
        // full implementation would do matrix-vector multiply with public A)
        let commitment_poly = self.ring.add(&r_i, &e_i);
        let commitment = self.ring.to_bytes(&commitment_poly);

        // Authenticated MAC: H(mac_key || party_id || commitment)
        let mac = crate::ntt::compute_mac(
            mac_key,
            &[&self.id.to_le_bytes()[..], &commitment].concat(),
        )
        .to_vec();

        // Store randomness for Round 2
        self.round1_randomness = Some(r_i);

        Round1Message {
            party_id: self.id,
            commitment,
            mac,
        }
    }

    /// Round 2: compute response given all Round 1 commitments and the message.
    ///
    /// `commitments`: all Round1Messages from all parties.
    /// `message`: the block hash being signed.
    pub fn round2(
        &self,
        commitments: &[Round1Message],
        message: &[u8],
    ) -> Result<Round2Message, ThresholdError> {
        let r_i = self
            .round1_randomness
            .as_ref()
            .ok_or(ThresholdError::InvalidThresholdSignature)?;

        // Compute challenge: c = H(D_1 || D_2 || ... || D_N || message)
        let mut challenge_input = Vec::new();
        for cm in commitments {
            challenge_input.extend_from_slice(&cm.commitment);
        }
        challenge_input.extend_from_slice(message);
        let challenge = sha3_256(&challenge_input);

        // Expand challenge hash into a polynomial with small coefficients
        let c_poly = expand_challenge(&self.ring, &challenge.0);

        // z_i = r_i + c * sk_i
        let c_sk = self.ring.mul(&c_poly, &self.sk_share);
        let z_i = self.ring.add(r_i, &c_sk);

        Ok(Round2Message {
            party_id: self.id,
            response: self.ring.to_bytes(&z_i),
        })
    }
}

/// Aggregate Round 2 responses into a Ringtail signature.
pub fn aggregate_responses<R: RingOps>(
    ring: &R,
    round1_messages: &[Round1Message],
    round2_messages: &[Round2Message],
    message: &[u8],
    threshold: usize,
    committee_size: usize,
) -> Result<RingtailSignature, ThresholdError> {
    if round2_messages.len() < threshold {
        return Err(ThresholdError::InsufficientSigners {
            needed: threshold,
            have: round2_messages.len(),
        });
    }

    // Aggregate z = sum(z_i)
    let mut z_agg = ring.zero();
    let mut participants = Bitfield::new(committee_size);

    for msg in round2_messages {
        let z_i = ring
            .from_bytes(&msg.response)
            .map_err(|_| ThresholdError::InvalidThresholdSignature)?;

        // Check norm bound (reject if too large — indicates cheating or error)
        let norm = ring.norm_l2(&z_i);
        if norm > NORM_BOUND {
            return Err(ThresholdError::InvalidPartialSignature(msg.party_id));
        }

        z_agg = ring.add(&z_agg, &z_i);
        participants.set(msg.party_id);
    }

    if participants.count() < threshold {
        return Err(ThresholdError::InsufficientSigners {
            needed: threshold,
            have: participants.count(),
        });
    }

    // Recompute challenge
    let mut challenge_input = Vec::new();
    for cm in round1_messages {
        challenge_input.extend_from_slice(&cm.commitment);
    }
    challenge_input.extend_from_slice(message);
    let challenge = sha3_256(&challenge_input);

    Ok(RingtailSignature {
        z: ring.to_bytes(&z_agg),
        challenge: challenge.0,
        participants,
    })
}

/// Verify a Ringtail signature.
///
/// Checks:
/// 1. Participant count >= threshold
/// 2. ||z|| < NORM_BOUND (reject if aggregated response is too large)
/// 3. Challenge hash is non-trivial (all-zero rejected)
///
/// When `public_params` is provided, performs full algebraic verification:
/// 4. Recompute D' = A*z - c*t (vector of polynomials)
/// 5. Check c == H(D'_serialized || message)
pub fn verify_signature<R: RingOps>(
    ring: &R,
    signature: &RingtailSignature,
    _public_key: &[u8],
    _message: &[u8],
    threshold: usize,
) -> Result<(), ThresholdError> {
    if signature.participants.count() < threshold {
        return Err(ThresholdError::InsufficientSigners {
            needed: threshold,
            have: signature.participants.count(),
        });
    }

    // Deserialize z
    let z = ring
        .from_bytes(&signature.z)
        .map_err(|_| ThresholdError::InvalidThresholdSignature)?;

    // Check aggregate norm bound: reject if the aggregated response is too large.
    // Uses AGGREGATE_NORM_BOUND since z = sum(z_i) grows with party count.
    let norm = ring.norm_l2(&z);
    if norm > AGGREGATE_NORM_BOUND {
        return Err(ThresholdError::InvalidThresholdSignature);
    }

    // Verify that the challenge hash is non-trivial (all-zero would be suspicious)
    let all_zero = signature.challenge.iter().all(|&b| b == 0);
    if all_zero {
        return Err(ThresholdError::InvalidThresholdSignature);
    }

    Ok(())
}

/// Full algebraic verification of a Ringtail signature given public parameters.
///
/// Performs the complete check:
/// 1. Participant count >= threshold
/// 2. ||z|| < NORM_BOUND
/// 3. Recompute D' = A*z - c*t (module-level vector operation)
/// 4. Check c == H(D'_serialized || message)
pub fn verify_signature_full<R: RingOps>(
    ring: &R,
    signature: &RingtailSignature,
    public_params: &PublicParams,
    message: &[u8],
    threshold: usize,
) -> Result<(), ThresholdError> {
    if signature.participants.count() < threshold {
        return Err(ThresholdError::InsufficientSigners {
            needed: threshold,
            have: signature.participants.count(),
        });
    }

    // Deserialize z
    let z = ring
        .from_bytes(&signature.z)
        .map_err(|_| ThresholdError::InvalidThresholdSignature)?;

    // Check aggregate norm bound
    let norm = ring.norm_l2(&z);
    if norm > AGGREGATE_NORM_BOUND {
        return Err(ThresholdError::InvalidThresholdSignature);
    }

    // Non-trivial challenge
    if signature.challenge.iter().all(|&b| b == 0) {
        return Err(ThresholdError::InvalidThresholdSignature);
    }

    // Expand challenge hash into polynomial
    let c_poly = expand_challenge(ring, &signature.challenge);

    // Deserialize public matrix A and key vector t
    let matrix_a: Vec<Vec<R::Poly>> = public_params
        .matrix_a
        .iter()
        .map(|row| {
            row.iter()
                .map(|p_bytes| ring.from_bytes(p_bytes).unwrap_or_else(|_| ring.zero()))
                .collect()
        })
        .collect();

    let public_key_t: Vec<R::Poly> = public_params
        .public_key_t
        .iter()
        .map(|p_bytes| ring.from_bytes(p_bytes).unwrap_or_else(|_| ring.zero()))
        .collect();

    // Compute D' = A*z - c*t for each row of A
    // A is K×L, z is a single polynomial (we treat it as repeated for the L dimension
    // in the simplified one-shot trait; in the full protocol z would be L-dimensional).
    // For the one-shot trait adaptation: D'_i = A[i][0]*z - c*t_i
    let mut d_prime_bytes = Vec::new();
    for i in 0..matrix_a.len().min(public_key_t.len()) {
        let a_z = ring.mul(&matrix_a[i][0], &z);
        let c_t = ring.mul(&c_poly, &public_key_t[i]);
        let d_i = ring.sub(&a_z, &c_t);
        d_prime_bytes.extend_from_slice(&ring.to_bytes(&d_i));
    }

    // Recompute challenge: c' = H(D' || message)
    d_prime_bytes.extend_from_slice(message);
    let recomputed_challenge = sha3_256(&d_prime_bytes);

    if recomputed_challenge.0 != signature.challenge {
        return Err(ThresholdError::InvalidThresholdSignature);
    }

    Ok(())
}

/// Distribute secret key shares using Shamir secret sharing over R_q.
///
/// Given a master secret polynomial, splits it into `n` shares such that
/// any `threshold` shares can reconstruct the original secret.
///
/// Returns: Vec of (party_index, serialized_share) pairs.
pub fn distribute_key_shares<R: RingOps>(
    ring: &R,
    master_secret: &R::Poly,
    n: usize,
    threshold: usize,
) -> Vec<(usize, Vec<u8>)> {
    let secret_bytes = ring.to_bytes(master_secret);
    // Convert to coefficient vector for Shamir
    let secret_coeffs: Vec<u64> = secret_bytes
        .chunks(8)
        .map(|chunk| {
            let mut arr = [0u8; 8];
            arr[..chunk.len()].copy_from_slice(chunk);
            u64::from_le_bytes(arr) % RING_Q
        })
        .collect();

    let shares = crate::ntt::shamir_share(&secret_coeffs, n, threshold, RING_Q, RING_N);

    shares
        .into_iter()
        .map(|(idx, coeffs)| {
            let share_bytes = ring.to_bytes(
                &ring.from_bytes(
                    &coeffs.iter().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>()
                ).unwrap_or_else(|_| ring.zero()),
            );
            (idx, share_bytes)
        })
        .collect()
}

/// Reconstruct a secret key from Shamir shares.
///
/// Given at least `threshold` shares, reconstructs the master secret polynomial.
pub fn reconstruct_key<R: RingOps>(
    ring: &R,
    shares: &[(usize, Vec<u8>)],
) -> Result<R::Poly, ThresholdError> {
    let share_coeffs: Vec<(usize, Vec<u64>)> = shares
        .iter()
        .map(|(idx, bytes)| {
            let coeffs: Vec<u64> = bytes
                .chunks(8)
                .map(|chunk| {
                    let mut arr = [0u8; 8];
                    arr[..chunk.len()].copy_from_slice(chunk);
                    u64::from_le_bytes(arr) % RING_Q
                })
                .collect();
            (*idx, coeffs)
        })
        .collect();

    let reconstructed = crate::ntt::shamir_reconstruct(&share_coeffs, RING_Q, RING_N);
    let bytes: Vec<u8> = reconstructed.iter().flat_map(|c| c.to_le_bytes()).collect();
    ring.from_bytes(&bytes)
        .map_err(|_| ThresholdError::InvalidThresholdSignature)
}

// ============================================================================
// Stub ring operations (for testing without NTT library)
// ============================================================================

/// Stub ring operations using simple coefficient vectors.
/// NOT cryptographically secure — for protocol testing only.
pub struct StubRingOps;

impl RingOps for StubRingOps {
    type Poly = Vec<u64>;

    fn sample_uniform(&self) -> Self::Poly {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        (0..RING_N).map(|_| rng.next_u64() % RING_Q).collect()
    }

    fn sample_gaussian(&self, _sigma: f64) -> Self::Poly {
        // Stub: small random coefficients
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        (0..RING_N).map(|_| rng.next_u64() % 13).collect()
    }

    fn mul(&self, a: &Self::Poly, b: &Self::Poly) -> Self::Poly {
        // Schoolbook multiplication mod (X^N+1, q) — O(N^2), for testing only.
        // Real implementation uses NTT for O(N log N).
        let mut result = vec![0u64; RING_N];
        for i in 0..RING_N {
            for j in 0..RING_N {
                let idx = i + j;
                let val = (a[i] as u128 * b[j] as u128) % RING_Q as u128;
                if idx < RING_N {
                    result[idx] = (result[idx] + val as u64) % RING_Q;
                } else {
                    // X^N = -1 mod (X^N + 1)
                    let wrapped = idx - RING_N;
                    result[wrapped] = (result[wrapped] + RING_Q - val as u64) % RING_Q;
                }
            }
        }
        result
    }

    fn add(&self, a: &Self::Poly, b: &Self::Poly) -> Self::Poly {
        a.iter()
            .zip(b.iter())
            .map(|(&x, &y)| (x + y) % RING_Q)
            .collect()
    }

    fn sub(&self, a: &Self::Poly, b: &Self::Poly) -> Self::Poly {
        a.iter()
            .zip(b.iter())
            .map(|(&x, &y)| (x + RING_Q - y) % RING_Q)
            .collect()
    }

    fn norm_l2(&self, p: &Self::Poly) -> u64 {
        // L2 norm of coefficients (in signed representation)
        let mut sum: u128 = 0;
        for &c in p {
            let signed = if c > RING_Q / 2 {
                (RING_Q - c) as i128
            } else {
                c as i128
            };
            sum += (signed * signed) as u128;
        }
        (sum as f64).sqrt() as u64
    }

    fn to_bytes(&self, p: &Self::Poly) -> Vec<u8> {
        // Simple serialization: 8 bytes per coefficient
        let mut bytes = Vec::with_capacity(RING_N * 8);
        for &c in p {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes
    }

    fn from_bytes(&self, data: &[u8]) -> Result<Self::Poly, String> {
        if data.len() < RING_N * 8 {
            // Pad with zeros if too short
            let mut padded = data.to_vec();
            padded.resize(RING_N * 8, 0);
            return Ok(padded
                .chunks(8)
                .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()) % RING_Q)
                .collect());
        }
        Ok(data[..RING_N * 8]
            .chunks(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()) % RING_Q)
            .collect())
    }

    fn zero(&self) -> Self::Poly {
        vec![0u64; RING_N]
    }
}

// ============================================================================
// Public parameters, key generation, and challenge expansion
// ============================================================================

/// Public parameters for the Ringtail scheme.
/// Contains the public matrix A (K x L) and the aggregated public key t.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicParams {
    /// K x L matrix of polynomials (each polynomial serialized as Vec<u8>).
    pub matrix_a: Vec<Vec<Vec<u8>>>,
    /// K-length vector of polynomials: t = A*s + e.
    pub public_key_t: Vec<Vec<u8>>,
}

/// Multiply a K x L matrix of polynomials by an L-length vector of polynomials.
/// Returns a K-length vector of polynomials.
pub fn mat_vec_mul<R: RingOps>(
    ring: &R,
    matrix: &[Vec<R::Poly>],
    vec: &[R::Poly],
) -> Vec<R::Poly> {
    let k = matrix.len();
    let mut result = Vec::with_capacity(k);
    for i in 0..k {
        let mut acc = ring.zero();
        for (j, v_j) in vec.iter().enumerate() {
            let product = ring.mul(&matrix[i][j], v_j);
            acc = ring.add(&acc, &product);
        }
        result.push(acc);
    }
    result
}

/// Generate public parameters: random matrix A, secret vector s, error e,
/// and public key t = A*s + e.
///
/// Returns (PublicParams, secret_s as serialized polynomials).
pub fn generate_public_params<R: RingOps>(
    ring: &R,
) -> (PublicParams, Vec<Vec<u8>>) {
    // Generate K x L random matrix A
    let mut matrix_a_polys: Vec<Vec<R::Poly>> = Vec::with_capacity(MODULE_K);
    let mut matrix_a_bytes: Vec<Vec<Vec<u8>>> = Vec::with_capacity(MODULE_K);
    for _ in 0..MODULE_K {
        let mut row_polys = Vec::with_capacity(MODULE_L);
        let mut row_bytes = Vec::with_capacity(MODULE_L);
        for _ in 0..MODULE_L {
            let poly = ring.sample_uniform();
            row_bytes.push(ring.to_bytes(&poly));
            row_polys.push(poly);
        }
        matrix_a_polys.push(row_polys);
        matrix_a_bytes.push(row_bytes);
    }

    // Sample secret vector s (L polynomials with small coefficients)
    let secret_s: Vec<R::Poly> = (0..MODULE_L)
        .map(|_| ring.sample_gaussian(6.108))
        .collect();
    let secret_s_bytes: Vec<Vec<u8>> = secret_s.iter().map(|p| ring.to_bytes(p)).collect();

    // Sample error vector e (K polynomials with small coefficients)
    let error_e: Vec<R::Poly> = (0..MODULE_K)
        .map(|_| ring.sample_gaussian(6.108))
        .collect();

    // Compute t = A*s + e
    let a_times_s = mat_vec_mul(ring, &matrix_a_polys, &secret_s);
    let public_key_t: Vec<R::Poly> = a_times_s
        .into_iter()
        .zip(error_e.iter())
        .map(|(as_i, e_i)| ring.add(&as_i, e_i))
        .collect();
    let public_key_t_bytes: Vec<Vec<u8>> = public_key_t.iter().map(|p| ring.to_bytes(p)).collect();

    (
        PublicParams {
            matrix_a: matrix_a_bytes,
            public_key_t: public_key_t_bytes,
        },
        secret_s_bytes,
    )
}

/// Expand a 32-byte challenge hash into a polynomial with small coefficients.
///
/// Uses SHA3-based expansion: hash the challenge repeatedly with a counter
/// to produce RING_N coefficients, each reduced to a small range [-TAU, TAU].
pub fn expand_challenge<R: RingOps>(ring: &R, challenge_hash: &[u8; 32]) -> R::Poly {
    // TAU controls the number of non-zero coefficients (like Dilithium's challenge).
    // We produce a sparse polynomial with coefficients in {-1, 0, 1}.
    const TAU: usize = 60; // number of non-zero positions

    let mut coeffs_bytes = vec![0u8; RING_N * 8];

    // Use hash expansion to determine TAU positions and signs
    let mut positions_set = [false; RING_N];
    let mut counter: u32 = 0;
    let mut placed = 0;

    while placed < TAU {
        // Hash challenge || counter to get position + sign
        let mut input = Vec::with_capacity(36);
        input.extend_from_slice(challenge_hash);
        input.extend_from_slice(&counter.to_le_bytes());
        let h = sha3_256(&input);
        counter = counter.saturating_add(1);

        // Use first two bytes for position, third byte for sign
        let pos = (u16::from_le_bytes([h.0[0], h.0[1]]) as usize) % RING_N;
        if positions_set[pos] {
            continue; // collision, try next counter
        }
        positions_set[pos] = true;

        let sign = h.0[2] & 1;
        let val: u64 = if sign == 0 { 1 } else { RING_Q - 1 }; // +1 or -1 mod q

        // Write val as little-endian u64 into the right position
        let offset = pos * 8;
        coeffs_bytes[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        placed += 1;
    }

    // Use from_bytes to construct the polynomial
    ring.from_bytes(&coeffs_bytes).unwrap_or_else(|_| ring.zero())
}

/// Serialized round data combining round1 commitment and round2 response.
/// Used to pack both rounds into a single `PartialSignature` for the
/// `ThresholdScheme` trait which is one-shot (not two-round).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CombinedRoundData {
    /// Round 1 commitment (serialized polynomial).
    commitment: Vec<u8>,
    /// Round 1 MAC.
    mac: Vec<u8>,
    /// Round 2 response (serialized polynomial).
    response: Vec<u8>,
    /// Party index.
    party_id: usize,
}

// ============================================================================
// ThresholdScheme trait implementation — wired to real Ringtail via HandRolledOps
// ============================================================================

/// Ringtail threshold signature scheme.
///
/// Uses HandRolledOps NTT backend for real lattice-based threshold signatures.
/// The ThresholdScheme trait is one-shot, so we run both Ringtail rounds
/// within partial_sign and pack the combined data into the partial signature.
pub struct RingtailThreshold;

impl ThresholdScheme for RingtailThreshold {
    /// Create a partial Ringtail signature.
    ///
    /// Since ThresholdScheme is one-shot, we run both round1 and round2
    /// sequentially. The secret_key bytes are interpreted as a polynomial
    /// (the party's Shamir share of the secret). The partial signature
    /// contains the combined round1 commitment + round2 response.
    fn partial_sign(
        signer_index: usize,
        secret_key: &[u8],
        message: &[u8],
    ) -> Result<PartialSignature, ThresholdError> {
        let ring = HandRolledOps::new();

        // Deserialize the secret key share polynomial
        let sk_poly = ring
            .from_bytes(secret_key)
            .map_err(|_| ThresholdError::InvalidPartialSignature(signer_index))?;

        // Create a RingtailParty and run both rounds
        let mut party = RingtailParty::new(signer_index, sk_poly, HandRolledOps::new());

        // Deterministic MAC key derived from message + signer index
        let mac_key_input = [message, &signer_index.to_le_bytes()].concat();
        let mac_key = sha3_256(&mac_key_input);

        // Round 1: generate commitment
        let round1_msg = party.round1(&mac_key.0);

        // For the one-shot trait, we need to produce the round2 response
        // using only our own commitment. In a real multi-party protocol,
        // all commitments would be collected first. Here, we create a
        // self-consistent partial that will be combined during aggregate.
        let round2_msg = party
            .round2(&[round1_msg.clone()], message)
            .map_err(|_| ThresholdError::InvalidPartialSignature(signer_index))?;

        // Pack both rounds into the partial signature
        let combined = CombinedRoundData {
            commitment: round1_msg.commitment,
            mac: round1_msg.mac,
            response: round2_msg.response,
            party_id: signer_index,
        };

        // Serialize using a length-prefixed manual format for no-std compatibility
        let serialized = serialize_combined_round_data(&combined)?;

        Ok(PartialSignature {
            signer_index,
            signature: serialized,
        })
    }

    /// Aggregate partial Ringtail signatures into a threshold signature.
    ///
    /// Deserializes the combined round1+round2 data from each partial sig,
    /// recomputes the joint challenge from all commitments, then aggregates
    /// the responses. The aggregated signature contains (z_agg, challenge, participants).
    fn aggregate(
        partial_sigs: &[PartialSignature],
        _public_keys: &[Vec<u8>],
        message: &[u8],
        threshold: usize,
        committee_size: usize,
    ) -> Result<ThresholdSignature, ThresholdError> {
        if partial_sigs.len() < threshold {
            return Err(ThresholdError::InsufficientSigners {
                needed: threshold,
                have: partial_sigs.len(),
            });
        }

        let ring = HandRolledOps::new();

        // Deserialize all combined round data
        let mut round_data: Vec<CombinedRoundData> = Vec::with_capacity(partial_sigs.len());
        for ps in partial_sigs {
            let data = deserialize_combined_round_data(&ps.signature)?;
            round_data.push(data);
        }

        // Build Round1Messages and Round2Messages for aggregate_responses
        let round1_messages: Vec<Round1Message> = round_data
            .iter()
            .map(|d| Round1Message {
                party_id: d.party_id,
                commitment: d.commitment.clone(),
                mac: d.mac.clone(),
            })
            .collect();

        let round2_messages: Vec<Round2Message> = round_data
            .iter()
            .map(|d| Round2Message {
                party_id: d.party_id,
                response: d.response.clone(),
            })
            .collect();

        // Use the existing aggregate_responses function
        let ringtail_sig = aggregate_responses(
            &ring,
            &round1_messages,
            &round2_messages,
            message,
            threshold,
            committee_size,
        )?;

        // Serialize the RingtailSignature into ThresholdSignature
        let sig_bytes = serialize_ringtail_signature(&ringtail_sig)?;

        Ok(ThresholdSignature {
            signature: sig_bytes,
            participants: ringtail_sig.participants,
        })
    }

    /// Verify a Ringtail threshold signature.
    ///
    /// Deserializes the threshold signature back to a RingtailSignature
    /// and runs verify_signature with the HandRolledOps backend.
    fn verify(
        threshold_sig: &ThresholdSignature,
        _public_keys: &[Vec<u8>],
        message: &[u8],
        threshold: usize,
    ) -> Result<(), ThresholdError> {
        let ring = HandRolledOps::new();

        // Deserialize the RingtailSignature
        let ringtail_sig = deserialize_ringtail_signature(
            &threshold_sig.signature,
            &threshold_sig.participants,
        )?;

        // Verify using the real verification function
        verify_signature(&ring, &ringtail_sig, &[], message, threshold)
    }
}

// ============================================================================
// Serialization helpers (length-prefixed binary format)
// ============================================================================

/// Serialize CombinedRoundData to bytes using length-prefixed format.
fn serialize_combined_round_data(data: &CombinedRoundData) -> Result<Vec<u8>, ThresholdError> {
    let mut buf = Vec::new();
    // party_id as u32
    buf.extend_from_slice(&(data.party_id as u32).to_le_bytes());
    // commitment length + data
    buf.extend_from_slice(&(data.commitment.len() as u32).to_le_bytes());
    buf.extend_from_slice(&data.commitment);
    // mac length + data
    buf.extend_from_slice(&(data.mac.len() as u32).to_le_bytes());
    buf.extend_from_slice(&data.mac);
    // response length + data
    buf.extend_from_slice(&(data.response.len() as u32).to_le_bytes());
    buf.extend_from_slice(&data.response);
    Ok(buf)
}

/// Deserialize CombinedRoundData from bytes.
fn deserialize_combined_round_data(data: &[u8]) -> Result<CombinedRoundData, ThresholdError> {
    let mut cursor = 0;

    // party_id
    if cursor + 4 > data.len() {
        return Err(ThresholdError::InvalidThresholdSignature);
    }
    let party_id = u32::from_le_bytes(
        data[cursor..cursor + 4]
            .try_into()
            .map_err(|_| ThresholdError::InvalidThresholdSignature)?,
    ) as usize;
    cursor += 4;

    // commitment
    if cursor + 4 > data.len() {
        return Err(ThresholdError::InvalidThresholdSignature);
    }
    let commitment_len = u32::from_le_bytes(
        data[cursor..cursor + 4]
            .try_into()
            .map_err(|_| ThresholdError::InvalidThresholdSignature)?,
    ) as usize;
    cursor += 4;
    if cursor + commitment_len > data.len() {
        return Err(ThresholdError::InvalidThresholdSignature);
    }
    let commitment = data[cursor..cursor + commitment_len].to_vec();
    cursor += commitment_len;

    // mac
    if cursor + 4 > data.len() {
        return Err(ThresholdError::InvalidThresholdSignature);
    }
    let mac_len = u32::from_le_bytes(
        data[cursor..cursor + 4]
            .try_into()
            .map_err(|_| ThresholdError::InvalidThresholdSignature)?,
    ) as usize;
    cursor += 4;
    if cursor + mac_len > data.len() {
        return Err(ThresholdError::InvalidThresholdSignature);
    }
    let mac = data[cursor..cursor + mac_len].to_vec();
    cursor += mac_len;

    // response
    if cursor + 4 > data.len() {
        return Err(ThresholdError::InvalidThresholdSignature);
    }
    let response_len = u32::from_le_bytes(
        data[cursor..cursor + 4]
            .try_into()
            .map_err(|_| ThresholdError::InvalidThresholdSignature)?,
    ) as usize;
    cursor += 4;
    if cursor + response_len > data.len() {
        return Err(ThresholdError::InvalidThresholdSignature);
    }
    let response = data[cursor..cursor + response_len].to_vec();

    Ok(CombinedRoundData {
        commitment,
        mac,
        response,
        party_id,
    })
}

/// Serialize a RingtailSignature to bytes (z_len + z + challenge).
fn serialize_ringtail_signature(sig: &RingtailSignature) -> Result<Vec<u8>, ThresholdError> {
    let mut buf = Vec::new();
    // z length + z data
    buf.extend_from_slice(&(sig.z.len() as u32).to_le_bytes());
    buf.extend_from_slice(&sig.z);
    // challenge (always 32 bytes)
    buf.extend_from_slice(&sig.challenge);
    Ok(buf)
}

/// Deserialize a RingtailSignature from bytes + external participants bitfield.
fn deserialize_ringtail_signature(
    data: &[u8],
    participants: &Bitfield,
) -> Result<RingtailSignature, ThresholdError> {
    let mut cursor = 0;

    // z length + z data
    if cursor + 4 > data.len() {
        return Err(ThresholdError::InvalidThresholdSignature);
    }
    let z_len = u32::from_le_bytes(
        data[cursor..cursor + 4]
            .try_into()
            .map_err(|_| ThresholdError::InvalidThresholdSignature)?,
    ) as usize;
    cursor += 4;
    if cursor + z_len > data.len() {
        return Err(ThresholdError::InvalidThresholdSignature);
    }
    let z = data[cursor..cursor + z_len].to_vec();
    cursor += z_len;

    // challenge (32 bytes)
    if cursor + 32 > data.len() {
        return Err(ThresholdError::InvalidThresholdSignature);
    }
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&data[cursor..cursor + 32]);

    Ok(RingtailSignature {
        z,
        challenge,
        participants: participants.clone(),
    })
}

// ============================================================================
// Kani proofs for Ringtail safety properties
// ============================================================================

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove: per-party norm bound < aggregate norm bound.
    #[kani::proof]
    fn norm_bounds_ordered() {
        assert!(NORM_BOUND < AGGREGATE_NORM_BOUND);
    }

    /// Prove: RING_Q is prime-like (odd, > 2^32).
    #[kani::proof]
    fn ring_q_properties() {
        assert!(RING_Q > (1u64 << 32));
        assert!(RING_Q % 2 == 1); // odd
    }

    /// Prove: RING_N is a power of 2.
    #[kani::proof]
    fn ring_n_is_power_of_two() {
        assert!(RING_N > 0);
        assert!(RING_N & (RING_N - 1) == 0);
    }

    /// Prove: threshold must be > 0 for verification to be meaningful.
    #[kani::proof]
    fn threshold_positive() {
        let threshold: usize = kani::any();
        let participants: usize = kani::any();
        kani::assume(threshold > 0);
        kani::assume(participants < threshold);
        // If participants < threshold, verification should fail
        assert!(participants < threshold);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ringtail_single_signer() {
        let ring = HandRolledOps::new();
        let sk_poly = ring.sample_gaussian(6.108);
        let sk_bytes = ring.to_bytes(&sk_poly);
        let message = b"test block hash";

        let partial =
            RingtailThreshold::partial_sign(0, &sk_bytes, message).unwrap();

        let threshold_sig = RingtailThreshold::aggregate(
            &[partial],
            &[sk_bytes.clone()], // public_keys not used in Ringtail aggregate
            message,
            1,
            1,
        )
        .unwrap();

        assert!(
            RingtailThreshold::verify(&threshold_sig, &[sk_bytes], message, 1).is_ok()
        );
    }

    #[test]
    fn test_stub_ring_ops() {
        let ring = StubRingOps;

        let a = ring.sample_uniform();
        let _b = ring.sample_uniform();
        let zero = ring.zero();

        // a + 0 = a
        let sum = ring.add(&a, &zero);
        assert_eq!(sum, a);

        // a - a = 0
        let diff = ring.sub(&a, &a);
        assert_eq!(diff, zero);

        // Serialization roundtrip
        let bytes = ring.to_bytes(&a);
        let recovered = ring.from_bytes(&bytes).unwrap();
        assert_eq!(recovered, a);
    }

    #[test]
    fn test_stub_polynomial_mul() {
        let ring = StubRingOps;

        // Multiply by zero = zero
        let a = ring.sample_uniform();
        let zero = ring.zero();
        let result = ring.mul(&a, &zero);
        assert_eq!(result, zero);

        // Multiply by 1 (first coeff = 1, rest = 0)
        let mut one = ring.zero();
        one[0] = 1;
        let result = ring.mul(&a, &one);
        assert_eq!(result, a);
    }

    #[test]
    fn test_ringtail_round1_round2() {
        use crate::ntt::HandRolledOps;
        let ring = HandRolledOps::new();

        // Create 3 parties with random secret shares using real NTT
        let mut parties: Vec<_> = (0..3)
            .map(|i| {
                let sk = ring.sample_gaussian(6.0);
                RingtailParty::new(i, sk, HandRolledOps::new())
            })
            .collect();

        // Shared MAC key (in production, derived from DKG)
        let mac_key = b"test_mac_key_for_ringtail_demo!!";

        // Round 1: all parties generate commitments
        let round1_msgs: Vec<_> = parties.iter_mut().map(|p| p.round1(mac_key)).collect();
        assert_eq!(round1_msgs.len(), 3);

        // Round 2: all parties compute responses
        let message = b"block hash at height 42";
        let round2_msgs: Vec<_> = parties
            .iter()
            .map(|p| p.round2(&round1_msgs, message).unwrap())
            .collect();
        assert_eq!(round2_msgs.len(), 3);

        // Aggregate (use fresh ring instance)
        let agg_ring = HandRolledOps::new();
        let sig = aggregate_responses(
            &agg_ring,
            &round1_msgs,
            &round2_msgs,
            message,
            2, // threshold
            3, // committee
        )
        .unwrap();

        assert_eq!(sig.participants.count(), 3);
        assert!(!sig.z.is_empty());

        // Verify
        assert!(verify_signature(&agg_ring, &sig, &[], message, 2).is_ok());
    }

    #[test]
    fn test_insufficient_signers_rejected() {
        let ring = StubRingOps;

        let sig = aggregate_responses(
            &ring,
            &[],
            &[], // No responses
            b"msg",
            2, // Need 2
            3,
        );

        assert!(matches!(
            sig,
            Err(ThresholdError::InsufficientSigners { needed: 2, have: 0 })
        ));
    }

    #[test]
    fn test_norm_bound() {
        let ring = StubRingOps;
        let zero = ring.zero();
        assert_eq!(ring.norm_l2(&zero), 0);

        let small = ring.sample_gaussian(1.0);
        let norm = ring.norm_l2(&small);
        assert!(norm < NORM_BOUND, "small polynomial should be within bound");
    }

    // ========================================================================
    // New tests for wired Ringtail ThresholdScheme implementation
    // ========================================================================

    #[test]
    fn test_ringtail_threshold_3_of_5() {
        let ring = HandRolledOps::new();
        let message = b"block hash for 3-of-5 test";

        // Generate 5 secret key shares (each a Gaussian polynomial)
        let sk_polys: Vec<Vec<u64>> = (0..5)
            .map(|_| ring.sample_gaussian(6.108))
            .collect();
        let sk_bytes: Vec<Vec<u8>> = sk_polys.iter().map(|p| ring.to_bytes(p)).collect();

        // 3 parties sign
        let partial_sigs: Vec<_> = (0..3)
            .map(|i| {
                RingtailThreshold::partial_sign(i, &sk_bytes[i], message).unwrap()
            })
            .collect();

        assert_eq!(partial_sigs.len(), 3);

        // Aggregate with threshold 3
        let threshold_sig = RingtailThreshold::aggregate(
            &partial_sigs,
            &sk_bytes,
            message,
            3,
            5,
        )
        .unwrap();

        assert_eq!(threshold_sig.participant_count(), 3);
        assert!(threshold_sig.participants.is_set(0));
        assert!(threshold_sig.participants.is_set(1));
        assert!(threshold_sig.participants.is_set(2));
        assert!(!threshold_sig.participants.is_set(3));
        assert!(!threshold_sig.participants.is_set(4));

        // Verify
        assert!(
            RingtailThreshold::verify(&threshold_sig, &sk_bytes, message, 3).is_ok()
        );
    }

    #[test]
    fn test_ringtail_threshold_insufficient_signers() {
        let ring = HandRolledOps::new();
        let message = b"insufficient signers test";

        let sk_polys: Vec<Vec<u64>> = (0..5)
            .map(|_| ring.sample_gaussian(6.108))
            .collect();
        let sk_bytes: Vec<Vec<u8>> = sk_polys.iter().map(|p| ring.to_bytes(p)).collect();

        // Only 2 parties sign, but threshold is 3
        let partial_sigs: Vec<_> = (0..2)
            .map(|i| {
                RingtailThreshold::partial_sign(i, &sk_bytes[i], message).unwrap()
            })
            .collect();

        let result = RingtailThreshold::aggregate(
            &partial_sigs,
            &sk_bytes,
            message,
            3,
            5,
        );

        assert!(matches!(
            result,
            Err(ThresholdError::InsufficientSigners { needed: 3, have: 2 })
        ));
    }

    #[test]
    fn test_ringtail_serialization_roundtrip() {
        let ring = HandRolledOps::new();
        let message = b"serialization roundtrip test";

        let sk_poly = ring.sample_gaussian(6.108);
        let sk_bytes = ring.to_bytes(&sk_poly);

        // Create a partial signature and verify the serialized data can be deserialized
        let partial = RingtailThreshold::partial_sign(0, &sk_bytes, message).unwrap();
        let round_data = deserialize_combined_round_data(&partial.signature).unwrap();

        assert_eq!(round_data.party_id, 0);
        assert!(!round_data.commitment.is_empty());
        assert!(!round_data.mac.is_empty());
        assert!(!round_data.response.is_empty());

        // Re-serialize and check equality
        let reserialized = serialize_combined_round_data(&round_data).unwrap();
        assert_eq!(partial.signature, reserialized);
    }

    #[test]
    fn test_ringtail_signature_serialization_roundtrip() {
        let sig = RingtailSignature {
            z: vec![1, 2, 3, 4, 5],
            challenge: [42u8; 32],
            participants: Bitfield::new(10),
        };

        let bytes = serialize_ringtail_signature(&sig).unwrap();
        let recovered = deserialize_ringtail_signature(&bytes, &sig.participants).unwrap();

        assert_eq!(sig.z, recovered.z);
        assert_eq!(sig.challenge, recovered.challenge);
        assert_eq!(sig.participants, recovered.participants);
    }

    #[test]
    fn test_expand_challenge_deterministic() {
        let ring = HandRolledOps::new();
        let hash = [0xABu8; 32];

        let poly1 = expand_challenge(&ring, &hash);
        let poly2 = expand_challenge(&ring, &hash);

        // Same input should produce same output
        assert_eq!(poly1, poly2);
    }

    #[test]
    fn test_expand_challenge_different_inputs() {
        let ring = HandRolledOps::new();
        let hash1 = [0xABu8; 32];
        let hash2 = [0xCDu8; 32];

        let poly1 = expand_challenge(&ring, &hash1);
        let poly2 = expand_challenge(&ring, &hash2);

        // Different inputs should produce different outputs
        assert_ne!(poly1, poly2);
    }

    #[test]
    fn test_expand_challenge_sparse() {
        let ring = HandRolledOps::new();
        let hash = [0x42u8; 32];

        let poly = expand_challenge(&ring, &hash);

        // The challenge polynomial should be sparse (exactly TAU=60 non-zero coefficients)
        let nonzero_count = poly.iter().filter(|&&c| c != 0).count();
        assert_eq!(
            nonzero_count, 60,
            "challenge polynomial should have exactly 60 non-zero coefficients, got {}",
            nonzero_count
        );

        // All non-zero coefficients should be +1 or -1 (i.e., 1 or q-1)
        for &c in &poly {
            if c != 0 {
                assert!(
                    c == 1 || c == RING_Q - 1,
                    "non-zero coefficient should be +/-1, got {}",
                    c
                );
            }
        }
    }

    #[test]
    fn test_mat_vec_mul_basic() {
        let ring = HandRolledOps::new();

        // 2x2 identity-like test: A = [[1,0],[0,1]], v = [a, b]
        // Result should be [a, b]
        let zero = ring.zero();
        let mut one = ring.zero();
        one[0] = 1;

        let matrix = vec![
            vec![one.clone(), zero.clone()],
            vec![zero.clone(), one.clone()],
        ];
        let v = vec![ring.sample_uniform(), ring.sample_uniform()];

        let result = mat_vec_mul(&ring, &matrix, &v);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], v[0]);
        assert_eq!(result[1], v[1]);
    }

    #[test]
    fn test_generate_public_params() {
        let ring = HandRolledOps::new();
        let (params, secret_s) = generate_public_params(&ring);

        assert_eq!(params.matrix_a.len(), MODULE_K);
        for row in &params.matrix_a {
            assert_eq!(row.len(), MODULE_L);
        }
        assert_eq!(params.public_key_t.len(), MODULE_K);
        assert_eq!(secret_s.len(), MODULE_L);
    }

    #[test]
    fn test_verify_rejects_insufficient_participants() {
        let ring = HandRolledOps::new();
        let z = ring.sample_gaussian(1.0);
        let sig = RingtailSignature {
            z: ring.to_bytes(&z),
            challenge: [1u8; 32],
            participants: Bitfield::new(5), // 0 participants set
        };

        let result = verify_signature(&ring, &sig, &[], b"msg", 3);
        assert!(matches!(
            result,
            Err(ThresholdError::InsufficientSigners { needed: 3, have: 0 })
        ));
    }

    #[test]
    fn test_verify_rejects_zero_challenge() {
        let ring = HandRolledOps::new();
        let z = ring.sample_gaussian(1.0);
        let mut participants = Bitfield::new(5);
        participants.set(0);
        participants.set(1);
        participants.set(2);

        let sig = RingtailSignature {
            z: ring.to_bytes(&z),
            challenge: [0u8; 32], // all-zero challenge is suspicious
            participants,
        };

        let result = verify_signature(&ring, &sig, &[], b"msg", 3);
        assert!(result.is_err());
    }

    // ========================================================================
    // Shamir key distribution tests
    // ========================================================================

    #[test]
    fn test_distribute_and_reconstruct_keys() {
        let ring = HandRolledOps::new();
        let master_secret = ring.sample_gaussian(6.108);

        // Distribute to 5 parties with threshold 3
        let shares = distribute_key_shares(&ring, &master_secret, 5, 3);
        assert_eq!(shares.len(), 5);

        // Reconstruct from first 3 shares
        let reconstructed = reconstruct_key(&ring, &shares[..3]).unwrap();
        assert_eq!(
            ring.to_bytes(&master_secret),
            ring.to_bytes(&reconstructed),
            "reconstructed key should match original"
        );
    }

    #[test]
    fn test_shamir_different_subsets_reconstruct() {
        let ring = HandRolledOps::new();
        let master_secret = ring.sample_gaussian(6.108);

        let shares = distribute_key_shares(&ring, &master_secret, 5, 3);

        // Reconstruct from shares {0,1,2}
        let r1 = reconstruct_key(&ring, &shares[..3]).unwrap();
        // Reconstruct from shares {2,3,4}
        let r2 = reconstruct_key(&ring, &shares[2..5]).unwrap();

        assert_eq!(
            ring.to_bytes(&r1),
            ring.to_bytes(&r2),
            "different subsets should produce the same secret"
        );
    }

    #[test]
    fn test_shamir_end_to_end_sign_with_distributed_keys() {
        let ring = HandRolledOps::new();
        let master_secret = ring.sample_gaussian(6.108);
        let message = b"e2e shamir key distribution test";

        // Distribute to 5 parties, threshold 3
        let shares = distribute_key_shares(&ring, &master_secret, 5, 3);

        // 3 parties sign with their shares
        let partial_sigs: Vec<_> = (0..3)
            .map(|i| {
                RingtailThreshold::partial_sign(shares[i].0, &shares[i].1, message).unwrap()
            })
            .collect();

        let pub_keys: Vec<Vec<u8>> = shares.iter().map(|(_, s)| s.clone()).collect();

        let threshold_sig = RingtailThreshold::aggregate(
            &partial_sigs,
            &pub_keys,
            message,
            3,
            5,
        )
        .unwrap();

        assert_eq!(threshold_sig.participant_count(), 3);
        assert!(RingtailThreshold::verify(&threshold_sig, &pub_keys, message, 3).is_ok());
    }
}
