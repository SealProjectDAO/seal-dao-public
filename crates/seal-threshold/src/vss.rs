//! Verifiable Secret Sharing (VSS) with SHA3-256 commitments.
//!
//! This module adds commitment-based verification to Shamir secret sharing.
//! The dealer publishes two types of commitments:
//!
//! 1. **Secret commitment** — `SHA3-256(0 || secret_bytes)` for the shared
//!    secret (the constant term of the Shamir polynomial). Used to verify
//!    the reconstructed secret.
//! 2. **Share commitments** — `SHA3-256(i || share_i_bytes)` for each party's
//!    share. Used for immediate per-share verification.
//!
//! # Protocol
//!
//! ```text
//! Dealer:
//!   1. Generate polynomial f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
//!      over R_q = Z_q[X]/(X^N + 1), where a_0 = secret
//!   2. Secret commitment: C = SHA3-256(0 || a_0_bytes)
//!   3. Evaluate f(i) for i = 1..n, producing shares
//!   4. Share commitments: S_i = SHA3-256(i || share_i_bytes)
//!   5. Publish C and distribute {(i, share_i, S_i)}
//!
//! Receiver i:
//!   1. Receive share_i and S_i
//!   2. Immediate check: SHA3-256(i || share_i_bytes) == S_i
//!      (verifies the share is genuine — produced by this dealer)
//!
//! Reconstruction:
//!   1. Collect t shares, Lagrange interpolate to recover f(0) = secret
//!   2. Verify: SHA3-256(0 || recovered_secret_bytes) == C
//!      (verifies the recovered secret matches the dealer's commitment)
//! ```

use serde::{Deserialize, Serialize};
use sha3::Digest;
use sha3::Sha3_256;

/// 32-byte SHA3-256 commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VssCommitment(pub [u8; 32]);

impl VssCommitment {
    /// Commit to a value: SHA3-256(index_le_bytes || value_bytes).
    fn from_bytes(index: usize, value: &[u64]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(&index.to_le_bytes());
        for &c in value {
            hasher.update(&c.to_le_bytes());
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        Self(hash)
    }

    /// Verify that a value matches this commitment.
    pub fn verify(&self, index: usize, value: &[u64]) -> bool {
        *self == Self::from_bytes(index, value)
    }
}

/// A VSS share: party index + Shamir share polynomial coefficients.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VssShare {
    /// Party index (0-based, matching evaluation point i+1).
    pub party_index: usize,
    /// The share polynomial coefficients (each a ring element, stored as u64[]).
    pub coeff: Vec<u64>,
}

/// A VSS commitment set: secret + share commitments.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VssCommitments {
    /// Number of parties (n).
    pub n: usize,
    /// Threshold (t).
    pub t: usize,
    /// Commitment to the secret (constant term).
    /// Used for post-reconstruction verification.
    pub secret_commitment: VssCommitment,
    /// Commitments to shares S_0, ..., S_{n-1}.
    /// Used for immediate per-share verification.
    pub share_commitments: Vec<VssCommitment>,
}

/// Verify a VSS share using its per-share commitment.
///
/// Checks that `SHA3-256(party_index || share.coeff_bytes) == share_commitment`.
/// This verifies the share is genuine (produced by this dealer).
pub fn verify_share(commitments: &VssCommitments, share: &VssShare) -> bool {
    if share.coeff.is_empty() {
        return false;
    }
    if share.party_index >= commitments.n {
        return false;
    }
    commitments.share_commitments[share.party_index]
        .verify(share.party_index, &share.coeff)
}

/// Generate Shamir shares with SHA3 secret + share commitments.
///
/// Delegates share generation to `crate::ntt::shamir_share` and adds
/// commitments for verification.
pub fn shamir_share_with_commitments(
    secret: &[u64],
    n: usize,
    t: usize,
    q: u64,
    ring_n: usize,
) -> (VssCommitments, Vec<VssShare>) {
    assert!(t <= n, "threshold must be <= number of parties");
    assert!(t > 0, "threshold must be > 0");

    // Generate shares using the existing, tested implementation
    let raw_shares = crate::ntt::shamir_share(secret, n, t, q, ring_n);

    // Secret commitment: C = SHA3(0 || secret_bytes)
    let secret_commitment = VssCommitment::from_bytes(0, secret);

    // Convert raw shares to VssShare format
    let shares: Vec<VssShare> = raw_shares
        .into_iter()
        .map(|(idx, coeff)| VssShare {
            party_index: idx,
            coeff,
        })
        .collect();

    // Share commitments: S_i = SHA3(i || share_i_bytes)
    let share_commitments: Vec<VssCommitment> = shares
        .iter()
        .map(|s| VssCommitment::from_bytes(s.party_index, &s.coeff))
        .collect();

    (
        VssCommitments {
            n,
            t,
            secret_commitment,
            share_commitments,
        },
        shares,
    )
}

/// Verify that a reconstructed secret matches the secret commitment.
///
/// After Lagrange interpolation recovers the secret, check that it matches C.
pub fn verify_secret_against_commitments(
    commitments: &VssCommitments,
    reconstructed: &[u64],
) -> bool {
    commitments.secret_commitment.verify(0, reconstructed)
}

/// Verify that all shares in a set are valid against their commitments.
pub fn verify_all_shares(commitments: &VssCommitments, shares: &[VssShare]) -> bool {
    shares.iter().all(|s| verify_share(commitments, s))
}

// == Tests ==

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ringtail::{RING_N, RING_Q};

    #[test]
    fn test_commitment_format() {
        let c1 = VssCommitment::from_bytes(0, &[1, 2, 3]);
        let c2 = VssCommitment::from_bytes(0, &[1, 2, 3]);
        assert_eq!(c1, c2);

        let c1 = VssCommitment::from_bytes(1, &[1, 2, 3]);
        let c2 = VssCommitment::from_bytes(2, &[1, 2, 3]);
        assert_ne!(c1, c2);

        let c1 = VssCommitment::from_bytes(0, &[1, 2, 3]);
        let c2 = VssCommitment::from_bytes(0, &[1, 2, 4]);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_commitment_verify() {
        let coeff = vec![42u64, 137, 9999];
        let commitment = VssCommitment::from_bytes(0, &coeff);
        assert!(commitment.verify(0, &coeff));
        assert!(!commitment.verify(1, &coeff));
        assert!(!commitment.verify(0, &[0, 0, 0]));
    }

    #[test]
    fn test_vss_share_and_reconstruct() {
        let n = 5;
        let t = 3;
        let secret: Vec<u64> = (0..RING_N).map(|i| (i as u64 * 42 + 7) % RING_Q).collect();

        let (commitments, shares) = shamir_share_with_commitments(
            &secret, n, t, RING_Q, RING_N,
        );

        assert_eq!(commitments.n, n);
        assert_eq!(commitments.t, t);
        assert_eq!(commitments.share_commitments.len(), n);
        assert_eq!(shares.len(), n);

        // Each share should verify against its per-share commitment
        for share in &shares {
            assert!(
                verify_share(&commitments, share),
                "share for party {} failed verification",
                share.party_index
            );
        }

        // Reconstruction should recover the secret
        let subset: Vec<_> = shares[0..t].to_vec();
        let reconstructed: Vec<(usize, Vec<u64>)> =
            subset.iter().map(|s| (s.party_index, s.coeff.clone())).collect();
        let recovered = crate::ntt::shamir_reconstruct(&reconstructed, RING_Q, RING_N);

        assert_eq!(
            secret, recovered,
            "VSS reconstruction should recover original secret"
        );

        assert!(
            verify_secret_against_commitments(&commitments, &recovered),
            "reconstructed secret should match secret commitment"
        );
    }

    #[test]
    fn test_vss_different_subsets() {
        let n = 7;
        let t = 4;
        let secret: Vec<u64> = (0..RING_N)
            .map(|i| (i as u64 * 13 + 99) % RING_Q)
            .collect();

        let (commitments, shares) = shamir_share_with_commitments(
            &secret, n, t, RING_Q, RING_N,
        );

        let s1: Vec<_> = shares[0..t].iter().cloned().collect();
        let r1: Vec<(usize, Vec<u64>)> =
            s1.iter().map(|s| (s.party_index, s.coeff.clone())).collect();
        let recovered1 = crate::ntt::shamir_reconstruct(&r1, RING_Q, RING_N);

        let s2: Vec<_> = shares[3..n].iter().cloned().collect();
        let r2: Vec<(usize, Vec<u64>)> =
            s2.iter().map(|s| (s.party_index, s.coeff.clone())).collect();
        let recovered2 = crate::ntt::shamir_reconstruct(&r2, RING_Q, RING_N);

        assert_eq!(recovered1, secret);
        assert_eq!(recovered2, secret);
        assert!(verify_secret_against_commitments(&commitments, &recovered1));
        assert!(verify_secret_against_commitments(&commitments, &recovered2));
    }

    #[test]
    fn test_vss_tampered_share_fails() {
        let n = 3;
        let t = 2;
        let secret: Vec<u64> = (0..RING_N).map(|i| (i as u64 * 11) % RING_Q).collect();

        let (commitments, mut shares) = shamir_share_with_commitments(
            &secret, n, t, RING_Q, RING_N,
        );

        shares[0].coeff[0] ^= 1;

        assert!(verify_share(&commitments, &shares[1]));
        assert!(
            !verify_share(&commitments, &shares[0]),
            "tampered share should fail verification"
        );
    }

    #[test]
    fn test_verify_share_wrong_coeff_count() {
        let n = 3;
        let t = 2;
        let secret: Vec<u64> = vec![1u64, 2, 3];

        let (commitments, _shares) = shamir_share_with_commitments(
            &secret, n, t, 17, 3,
        );

        // Wrong index should fail
        let bad_share = VssShare {
            party_index: 99, // out of range
            coeff: vec![1, 2, 3],
        };
        assert!(!verify_share(&commitments, &bad_share));
    }

    #[test]
    fn test_verify_all_shares() {
        let n = 5;
        let t = 3;
        let secret: Vec<u64> = (0..RING_N).map(|i| (i as u64 * 42 + 7) % RING_Q).collect();

        let (commitments, shares) = shamir_share_with_commitments(
            &secret, n, t, RING_Q, RING_N,
        );

        assert!(verify_all_shares(&commitments, &shares));

        // Tamper one share
        let mut tampered = shares.clone();
        tampered[0].coeff[0] ^= 1;
        assert!(!verify_all_shares(&commitments, &tampered));
    }

    #[test]
    fn test_direct_shamir_roundtrip() {
        let secret: Vec<u64> = vec![42, 137, 9999, 7, 123];
        let shares = crate::ntt::shamir_share(&secret, 5, 3, RING_Q, 5);
        let subset: Vec<_> = shares[0..3].to_vec();
        let reconstructed = crate::ntt::shamir_reconstruct(&subset, RING_Q, 5);
        assert_eq!(secret, reconstructed, "direct shamir roundtrip failed");
    }

    #[test]
    fn test_direct_shamir_with_ringtail_params() {
        let secret: Vec<u64> = (0..RING_N).map(|i| (i as u64 * 42 + 7) % RING_Q).collect();
        let shares = crate::ntt::shamir_share(&secret, 5, 3, RING_Q, RING_N);
        let subset: Vec<_> = shares[0..3].to_vec();
        let reconstructed = crate::ntt::shamir_reconstruct(&subset, RING_Q, RING_N);
        assert_eq!(secret, reconstructed, "ringtail params shamir roundtrip failed");
    }
}
