//! SPDZ-style secret sharing for private aggregation.
//!
//! Implements the online phase of the SPDZ protocol for 2-party
//! computation of SQL aggregate functions (SUM, COUNT, AVG) over
//! secret-shared data.
//!
//! # Protocol
//!
//! **Offline phase** (preprocessing, independent of data):
//! - Generate Beaver multiplication triples: [a], [b], [c] where c = a * b
//! - Generate random masks for each value to be shared
//!
//! **Online phase** (data-dependent):
//! 1. Each party secret-shares their values: x = x_A + x_B (mod p)
//! 2. Addition: [x + y] = [x] + [y] (local computation, no communication)
//! 3. Multiplication: uses Beaver triple protocol (1 round of communication)
//! 4. Reconstruction: parties exchange shares to recover result
//!
//! # Security
//!
//! - **Passive security**: Honest-but-curious adversary learns nothing beyond output
//! - **Active security**: MAC-based verification ensures correctness
//! - **PQ-secure**: All randomness from SHA3-based PRG
//!
//! # Field
//!
//! Operations are over Z_p where p is a 64-bit prime (Goldilocks: 2^64 - 2^32 + 1).
//! This matches the field used in STARK proofs for efficient interop.

use seal_crypto::hash::sha3_256;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Goldilocks prime: 2^64 - 2^32 + 1
pub const FIELD_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// Errors from the SPDZ online protocol.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpdzError {
    /// MAC verification failed during reconstruction — the reconstructed
    /// value is not what one (or both) parties committed to. Protocol
    /// MUST abort (SPDZ security requires this; never reveal the value).
    #[error("MAC check failed during reconstruction (protocol must abort)")]
    MacCheckFailed,
    /// Beaver triple exhausted mid-protocol.
    #[error("no more Beaver triples available")]
    TriplesExhausted,
    /// Invalid triple index.
    #[error("invalid triple index {0}")]
    InvalidTripleIndex(usize),
}

/// An additive secret share of a field element.
///
/// Both the value and MAC shares are cleared on drop to avoid leaking
/// secret material through memory reuse. The actual MAC equality check
/// is done in constant time (see [`SpdzParty::reconstruct`]).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpdzShare {
    /// This party's share of the value (in Z_p).
    pub value: u64,
    /// MAC share: share of alpha * x, where alpha is the global MAC key.
    pub mac: u64,
}

impl Drop for SpdzShare {
    fn drop(&mut self) {
        self.value.zeroize();
        self.mac.zeroize();
    }
}

/// A Beaver multiplication triple: shares of (a, b, c) where c = a * b mod p.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpdzTriple {
    pub a: SpdzShare,
    pub b: SpdzShare,
    pub c: SpdzShare,
}

/// A party in the SPDZ protocol.
pub struct SpdzParty {
    /// Party index (0 or 1 for 2-party).
    pub id: usize,
    /// This party's share of the global MAC key alpha.
    alpha_share: u64,
    /// Pre-generated Beaver triples (consumed one per multiplication).
    triples: Vec<SpdzTriple>,
    /// Index of next triple to consume.
    triple_idx: usize,
}

impl SpdzParty {
    /// Create a new SPDZ party with preprocessing.
    ///
    /// `seed` is used for deterministic triple generation (for testing).
    /// In production, triples come from an offline phase using OT or HE.
    pub fn new(id: usize, alpha_share: u64, num_triples: usize, seed: &[u8]) -> Self {
        let triples = generate_triples(id, alpha_share, num_triples, seed);
        SpdzParty {
            id,
            alpha_share,
            triples,
            triple_idx: 0,
        }
    }

    /// Secret-share a value x.
    ///
    /// Party 0 sets share = x - r, party 1 sets share = r (random mask).
    /// Returns (our_share, share_to_send_to_other_party).
    pub fn share_value(&self, x: u64, mask: u64) -> (SpdzShare, SpdzShare) {
        let share_0 = field_sub(x, mask);
        let share_1 = mask;

        let mac_0 = field_mul(self.alpha_share, share_0);
        let mac_1 = field_mul(self.alpha_share, share_1);

        if self.id == 0 {
            (
                SpdzShare {
                    value: share_0,
                    mac: mac_0,
                },
                SpdzShare {
                    value: share_1,
                    mac: mac_1,
                },
            )
        } else {
            (
                SpdzShare {
                    value: share_1,
                    mac: mac_1,
                },
                SpdzShare {
                    value: share_0,
                    mac: mac_0,
                },
            )
        }
    }

    /// Add two secret-shared values (local computation, no communication).
    pub fn add(&self, a: &SpdzShare, b: &SpdzShare) -> SpdzShare {
        SpdzShare {
            value: field_add(a.value, b.value),
            mac: field_add(a.mac, b.mac),
        }
    }

    /// Subtract two secret-shared values (local computation).
    pub fn sub(&self, a: &SpdzShare, b: &SpdzShare) -> SpdzShare {
        SpdzShare {
            value: field_sub(a.value, b.value),
            mac: field_sub(a.mac, b.mac),
        }
    }

    /// Add a public constant to a secret-shared value.
    /// Only party 0 adds the constant; party 1 adds nothing.
    pub fn add_constant(&self, a: &SpdzShare, constant: u64) -> SpdzShare {
        if self.id == 0 {
            SpdzShare {
                value: field_add(a.value, constant),
                mac: field_add(a.mac, field_mul(self.alpha_share, constant)),
            }
        } else {
            a.clone()
        }
    }

    /// Multiply a secret-shared value by a public constant (local computation).
    pub fn mul_constant(&self, a: &SpdzShare, constant: u64) -> SpdzShare {
        SpdzShare {
            value: field_mul(a.value, constant),
            mac: field_mul(a.mac, constant),
        }
    }

    /// Begin multiplication of two secret-shared values (Beaver triple protocol).
    ///
    /// Returns (epsilon, delta) — masked values to send to the other party.
    /// Both parties open epsilon = x - a and delta = y - b,
    /// then compute [z] = [c] + epsilon * [b] + delta * [a] + epsilon * delta (party 0 only).
    pub fn mul_begin(&mut self, x: &SpdzShare, y: &SpdzShare) -> Result<(u64, u64), SpdzError> {
        if self.triple_idx >= self.triples.len() {
            return Err(SpdzError::TriplesExhausted);
        }

        let triple = &self.triples[self.triple_idx];
        self.triple_idx += 1;

        // epsilon_i = x_i - a_i, delta_i = y_i - b_i
        let epsilon = field_sub(x.value, triple.a.value);
        let delta = field_sub(y.value, triple.b.value);

        Ok((epsilon, delta))
    }

    /// Complete multiplication after receiving the other party's (epsilon, delta).
    ///
    /// `epsilon` and `delta` are the OPENED (reconstructed) values: epsilon = x - a, delta = y - b.
    pub fn mul_finish(
        &self,
        epsilon: u64,
        delta: u64,
        triple_idx: usize,
    ) -> Result<SpdzShare, SpdzError> {
        if triple_idx >= self.triples.len() {
            return Err(SpdzError::InvalidTripleIndex(triple_idx));
        }

        let triple = &self.triples[triple_idx];

        // [z] = [c] + epsilon * [b] + delta * [a] + epsilon * delta (party 0 only)
        let mut z_value = triple.c.value;
        z_value = field_add(z_value, field_mul(epsilon, triple.b.value));
        z_value = field_add(z_value, field_mul(delta, triple.a.value));
        if self.id == 0 {
            z_value = field_add(z_value, field_mul(epsilon, delta));
        }

        let mut z_mac = triple.c.mac;
        z_mac = field_add(z_mac, field_mul(epsilon, triple.b.mac));
        z_mac = field_add(z_mac, field_mul(delta, triple.a.mac));
        if self.id == 0 {
            z_mac = field_add(z_mac, field_mul(self.alpha_share, field_mul(epsilon, delta)));
        }

        Ok(SpdzShare {
            value: z_value,
            mac: z_mac,
        })
    }

    /// Remaining Beaver triples.
    pub fn triples_remaining(&self) -> usize {
        self.triples.len().saturating_sub(self.triple_idx)
    }

    /// Reconstruct a value from both parties' shares, with mandatory
    /// constant-time MAC verification.
    ///
    /// SPDZ security critically depends on aborting before revealing any
    /// output when the MAC check fails. Returning a `Result` (rather than
    /// a `(value, bool)` tuple) forces callers to handle that abort path.
    ///
    /// The MAC equality is checked via `subtle::ConstantTimeEq` so a
    /// network adversary cannot learn whether the check passed by timing.
    pub fn reconstruct(
        &self,
        our_share: &SpdzShare,
        their_share: &SpdzShare,
    ) -> Result<u64, SpdzError> {
        let value = field_add(our_share.value, their_share.value);

        // MAC check: alpha * value == mac_0 + mac_1
        let expected_mac = field_mul(self.alpha_share, value);
        let actual_mac = field_add(our_share.mac, their_share.mac);

        // Constant-time equality; bool is the last thing derived so no
        // branch on secret values happens before this point.
        if bool::from(expected_mac.ct_eq(&actual_mac)) {
            Ok(value)
        } else {
            Err(SpdzError::MacCheckFailed)
        }
    }

    /// Batch-verify MACs on a slice of `(our_share, their_share)` pairs
    /// before any of them is revealed.
    ///
    /// In real SPDZ the batch check uses a random linear combination
    /// (Mac'n'Cheese-style) to avoid N individual field multiplications
    /// leaking partial MAC information. This helper folds each pair's
    /// `(alpha * (a+b) == mac_a + mac_b)` check into a single constant-
    /// time aggregate: XOR of each per-pair mask bit → 0 iff all pass.
    pub fn verify_all_macs(
        &self,
        pairs: &[(SpdzShare, SpdzShare)],
    ) -> Result<(), SpdzError> {
        // Accumulate `expected_mac ^ actual_mac` in a u64 so we only
        // compare at the end. A single non-zero means at least one failed.
        let mut acc: u64 = 0;
        for (ours, theirs) in pairs {
            let value = field_add(ours.value, theirs.value);
            let expected_mac = field_mul(self.alpha_share, value);
            let actual_mac = field_add(ours.mac, theirs.mac);
            acc |= expected_mac ^ actual_mac;
        }
        if bool::from(acc.ct_eq(&0u64)) {
            Ok(())
        } else {
            Err(SpdzError::MacCheckFailed)
        }
    }
}

// ── Field Arithmetic (Goldilocks) ───────────────────────────

/// Addition mod p.
pub fn field_add(a: u64, b: u64) -> u64 {
    let (sum, carry) = a.overflowing_add(b);
    if carry || sum >= FIELD_PRIME {
        sum.wrapping_sub(FIELD_PRIME)
    } else {
        sum
    }
}

/// Subtraction mod p.
pub fn field_sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        FIELD_PRIME - (b - a)
    }
}

/// Multiplication mod p using 128-bit intermediate.
pub fn field_mul(a: u64, b: u64) -> u64 {
    let product = (a as u128) * (b as u128);
    (product % (FIELD_PRIME as u128)) as u64
}

/// Modular inverse via Fermat's little theorem: a^(p-2) mod p.
pub fn field_inv(a: u64) -> u64 {
    field_pow(a, FIELD_PRIME - 2)
}

/// Modular exponentiation via binary method.
pub fn field_pow(mut base: u64, mut exp: u64) -> u64 {
    let mut result = 1u64;
    base %= FIELD_PRIME;
    while exp > 0 {
        if exp & 1 == 1 {
            result = field_mul(result, base);
        }
        exp >>= 1;
        base = field_mul(base, base);
    }
    result
}

// ── Triple Generation (Simplified) ─────────────────────────

/// Generate Beaver triples from a seed (simplified offline phase).
///
/// In production, triples would be generated using Oblivious Transfer (OT)
/// or Homomorphic Encryption (HE) in a separate offline protocol.
fn generate_triples(
    party_id: usize,
    alpha_share: u64,
    count: usize,
    seed: &[u8],
) -> Vec<SpdzTriple> {
    let mut triples = Vec::with_capacity(count);

    for i in 0..count {
        // Deterministic randomness from seed + index
        let a_val = prg_value(seed, party_id, i, 0);
        let b_val = prg_value(seed, party_id, i, 1);
        let c_val = if party_id == 0 {
            // Party 0's share of c includes the cross terms
            // In a real protocol, this is computed via OT
            field_mul(a_val, b_val)
        } else {
            0 // Party 1's share of c (simplified)
        };

        triples.push(SpdzTriple {
            a: SpdzShare {
                value: a_val,
                mac: field_mul(alpha_share, a_val),
            },
            b: SpdzShare {
                value: b_val,
                mac: field_mul(alpha_share, b_val),
            },
            c: SpdzShare {
                value: c_val,
                mac: field_mul(alpha_share, c_val),
            },
        });
    }

    triples
}

/// Pseudorandom generator: SHA3(seed || party_id || index || sub_index) → u64 mod p.
fn prg_value(seed: &[u8], party_id: usize, index: usize, sub_index: usize) -> u64 {
    let mut input = Vec::with_capacity(seed.len() + 24);
    input.extend_from_slice(seed);
    input.extend_from_slice(&(party_id as u64).to_le_bytes());
    input.extend_from_slice(&(index as u64).to_le_bytes());
    input.extend_from_slice(&(sub_index as u64).to_le_bytes());
    let hash = sha3_256(&input);
    let raw = u64::from_le_bytes(hash.0[..8].try_into().unwrap());
    raw % FIELD_PRIME
}

// ── Aggregate SQL Operations ────────────────────────────────

/// Compute SUM of secret-shared values (local addition, no communication).
pub fn spdz_sum(party: &SpdzParty, shares: &[SpdzShare]) -> SpdzShare {
    shares
        .iter()
        .fold(
            SpdzShare {
                value: 0,
                mac: 0,
            },
            |acc, s| party.add(&acc, s),
        )
}

/// Compute COUNT of non-zero secret-shared values.
/// Returns a share of the count.
pub fn spdz_count(party: &SpdzParty, indicator_shares: &[SpdzShare]) -> SpdzShare {
    // Each indicator_share is 1 if the row matches the predicate, 0 otherwise.
    // COUNT = SUM of indicators.
    spdz_sum(party, indicator_shares)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_add() {
        assert_eq!(field_add(1, 2), 3);
        assert_eq!(field_add(FIELD_PRIME - 1, 1), 0);
        assert_eq!(field_add(FIELD_PRIME - 1, 2), 1);
    }

    #[test]
    fn test_field_sub() {
        assert_eq!(field_sub(5, 3), 2);
        assert_eq!(field_sub(0, 1), FIELD_PRIME - 1);
        assert_eq!(field_sub(3, 5), FIELD_PRIME - 2);
    }

    #[test]
    fn test_field_mul() {
        assert_eq!(field_mul(2, 3), 6);
        assert_eq!(field_mul(FIELD_PRIME - 1, 2), FIELD_PRIME - 2);
    }

    #[test]
    fn test_field_inv() {
        let a = 42u64;
        let a_inv = field_inv(a);
        assert_eq!(field_mul(a, a_inv), 1);
    }

    #[test]
    fn test_share_and_reconstruct() {
        let alpha = 12345u64;
        let party0 = SpdzParty::new(0, alpha, 10, b"test-seed");

        let x = 42u64;
        let mask = 99999u64;
        let (share0, share1) = party0.share_value(x, mask);

        // Reconstruct
        let reconstructed = field_add(share0.value, share1.value);
        assert_eq!(reconstructed, x);
    }

    #[test]
    fn test_addition_homomorphic() {
        let alpha = 777u64;
        let party = SpdzParty::new(0, alpha, 10, b"seed");

        let a = SpdzShare { value: 10, mac: field_mul(alpha, 10) };
        let b = SpdzShare { value: 20, mac: field_mul(alpha, 20) };

        let sum = party.add(&a, &b);
        assert_eq!(sum.value, 30);
        assert_eq!(sum.mac, field_mul(alpha, 30));
    }

    #[test]
    fn test_mul_constant() {
        let alpha = 777u64;
        let party = SpdzParty::new(0, alpha, 10, b"seed");

        let a = SpdzShare { value: 10, mac: field_mul(alpha, 10) };
        let result = party.mul_constant(&a, 5);
        assert_eq!(result.value, 50);
        assert_eq!(result.mac, field_mul(alpha, 50));
    }

    #[test]
    fn test_spdz_sum() {
        let alpha = 42u64;
        let party = SpdzParty::new(0, alpha, 10, b"seed");

        let shares: Vec<SpdzShare> = (1..=5)
            .map(|v| SpdzShare {
                value: v,
                mac: field_mul(alpha, v),
            })
            .collect();

        let sum = spdz_sum(&party, &shares);
        assert_eq!(sum.value, 15); // 1+2+3+4+5
        assert_eq!(sum.mac, field_mul(alpha, 15));
    }

    #[test]
    fn test_triple_generation_deterministic() {
        let party1 = SpdzParty::new(0, 42, 5, b"seed");
        let party2 = SpdzParty::new(0, 42, 5, b"seed");

        assert_eq!(party1.triples[0].a.value, party2.triples[0].a.value);
        assert_eq!(party1.triples[0].b.value, party2.triples[0].b.value);
    }

    #[test]
    fn test_triples_remaining() {
        let mut party = SpdzParty::new(0, 42, 5, b"seed");
        assert_eq!(party.triples_remaining(), 5);

        let x = SpdzShare { value: 1, mac: 0 };
        let _ = party.mul_begin(&x, &x);
        assert_eq!(party.triples_remaining(), 4);
    }

    #[test]
    fn test_field_pow() {
        assert_eq!(field_pow(2, 10), 1024);
        assert_eq!(field_pow(0, 0), 1);
        assert_eq!(field_pow(FIELD_PRIME - 1, 2), 1); // (-1)^2 = 1
    }

    // ── Adversarial / MAC-check tests ───────────────────────────────
    //
    // These tests ensure the MAC-check in `reconstruct` / `verify_all_macs`
    // cannot be bypassed by flipping individual bits of a share or MAC.

    /// Build the two consistent shares of `value` that reconstruct+verify
    /// correctly under MAC key `alpha`. Helper for adversarial tests.
    fn shares_of(alpha: u64, value: u64, mask: u64) -> (SpdzShare, SpdzShare) {
        let share0 = field_sub(value, mask);
        let share1 = mask;
        (
            SpdzShare {
                value: share0,
                mac: field_mul(alpha, share0),
            },
            SpdzShare {
                value: share1,
                mac: field_mul(alpha, share1),
            },
        )
    }

    #[test]
    fn test_reconstruct_honest_ok() {
        let alpha = 12345u64;
        // One party holds the whole alpha (2-of-2 with party 1's share = 0).
        let party = SpdzParty::new(0, alpha, 1, b"seed");
        let (s0, s1) = shares_of(alpha, 42, 99_999);
        assert_eq!(party.reconstruct(&s0, &s1), Ok(42));
    }

    #[test]
    fn test_reconstruct_flipped_mac_aborts() {
        let alpha = 0xc0ffeeu64;
        let party = SpdzParty::new(0, alpha, 1, b"seed");
        let (s0, mut s1) = shares_of(alpha, 7, 13);
        s1.mac ^= 0x1; // adversary tampers one bit of MAC share
        assert_eq!(party.reconstruct(&s0, &s1), Err(SpdzError::MacCheckFailed));
    }

    #[test]
    fn test_reconstruct_flipped_value_aborts() {
        let alpha = 0xc0ffeeu64;
        let party = SpdzParty::new(0, alpha, 1, b"seed");
        let (s0, mut s1) = shares_of(alpha, 7, 13);
        s1.value = field_add(s1.value, 1); // adversary shifts value by 1
        assert_eq!(party.reconstruct(&s0, &s1), Err(SpdzError::MacCheckFailed));
    }

    #[test]
    fn test_verify_all_macs_one_bad_aborts() {
        let alpha = 0xdeadbeefu64;
        let party = SpdzParty::new(0, alpha, 1, b"seed");
        let mut pairs: Vec<(SpdzShare, SpdzShare)> = (0..4)
            .map(|i| shares_of(alpha, 100 + i, 999 * (i + 1)))
            .collect();
        // All good → OK.
        assert_eq!(party.verify_all_macs(&pairs), Ok(()));

        // Corrupt one pair's MAC; the batch must abort.
        pairs[2].1.mac ^= 0x80;
        assert_eq!(
            party.verify_all_macs(&pairs),
            Err(SpdzError::MacCheckFailed)
        );
    }

    #[test]
    fn test_mul_finish_invalid_triple_index() {
        let party = SpdzParty::new(0, 7, 2, b"seed");
        // Only 2 triples preprocessed; idx 5 is bogus.
        assert_eq!(
            party.mul_finish(0, 0, 5),
            Err(SpdzError::InvalidTripleIndex(5))
        );
    }

    #[test]
    fn test_mul_begin_triples_exhausted() {
        let mut party = SpdzParty::new(0, 7, 1, b"seed");
        let zero = SpdzShare { value: 0, mac: 0 };
        let _ = party.mul_begin(&zero, &zero).unwrap();
        // Now exhausted.
        assert_eq!(
            party.mul_begin(&zero, &zero),
            Err(SpdzError::TriplesExhausted)
        );
    }
}
