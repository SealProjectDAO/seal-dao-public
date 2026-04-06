//! Simple threshold scheme — collects individual ML-DSA signatures.
//!
//! This is a development placeholder, NOT a real threshold scheme.
//! Individual signatures are concatenated (not aggregated).
//! Block overhead: N × 3.3 KB instead of the target ~13.4 KB (Ringtail).
//!
//! # TODO: Replace with Ringtail (ePrint 2024/1113)
//!
//! - [ ] Port Ringtail (2-round, LWE-based, scales to 1024 parties)
//! - [ ] Round 1 preprocessing (message-independent, run during previous slot)
//! - [ ] Round 2 on critical path (~800ms with preprocessing)
//! - [ ] Output: single ~13.4 KB threshold sig + 13-byte bitfield
//! - [ ] Lean 4 proof: t-of-n security (adversary with <t shares can't forge)
//! - [ ] Alternative: Quorus (ePrint 2025/1163) for ML-DSA-compatible output

use crate::traits::{Bitfield, PartialSignature, ThresholdScheme, ThresholdSignature};
use crate::ThresholdError;
use seal_crypto::signature::{Signature, SigningKey, VerifyingKey};

/// Simple threshold: collects individual ML-DSA signatures.
pub struct SimpleThreshold;

impl ThresholdScheme for SimpleThreshold {
    fn partial_sign(
        signer_index: usize,
        secret_key: &[u8],
        message: &[u8],
    ) -> Result<PartialSignature, ThresholdError> {
        let sk = SigningKey::from_bytes(secret_key)
            .map_err(|_| ThresholdError::InvalidPartialSignature(signer_index))?;
        let sig = sk.sign(message)
            .map_err(|_| ThresholdError::InvalidPartialSignature(signer_index))?;
        Ok(PartialSignature {
            signer_index,
            signature: sig.to_bytes().to_vec(),
        })
    }

    fn aggregate(
        partial_sigs: &[PartialSignature],
        public_keys: &[Vec<u8>],
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

        let mut bitfield = Bitfield::new(committee_size);
        let mut aggregated = Vec::new();

        for ps in partial_sigs {
            if ps.signer_index >= committee_size {
                return Err(ThresholdError::SignerOutOfRange {
                    index: ps.signer_index,
                    max: committee_size,
                });
            }
            if bitfield.is_set(ps.signer_index) {
                return Err(ThresholdError::DuplicateSigner(ps.signer_index));
            }

            // Verify individual signature
            let vk = VerifyingKey::from_bytes(&public_keys[ps.signer_index])
                .map_err(|_| ThresholdError::InvalidPartialSignature(ps.signer_index))?;
            let sig = Signature::from_bytes(ps.signature.clone());
            vk.verify(message, &sig)
                .map_err(|_| ThresholdError::InvalidPartialSignature(ps.signer_index))?;

            bitfield.set(ps.signer_index);
            // In simple mode, concatenate sigs (wasteful but correct)
            aggregated.extend_from_slice(&(ps.signer_index as u32).to_le_bytes());
            aggregated.extend_from_slice(&(ps.signature.len() as u32).to_le_bytes());
            aggregated.extend_from_slice(&ps.signature);
        }

        Ok(ThresholdSignature {
            signature: aggregated,
            participants: bitfield,
        })
    }

    fn verify(
        threshold_sig: &ThresholdSignature,
        public_keys: &[Vec<u8>],
        message: &[u8],
        threshold: usize,
    ) -> Result<(), ThresholdError> {
        if threshold_sig.participant_count() < threshold {
            return Err(ThresholdError::InsufficientSigners {
                needed: threshold,
                have: threshold_sig.participant_count(),
            });
        }

        // Parse concatenated signatures and verify each
        let mut cursor = 0;
        let data = &threshold_sig.signature;

        while cursor < data.len() {
            if cursor + 8 > data.len() {
                return Err(ThresholdError::InvalidThresholdSignature);
            }
            let signer_index =
                u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
            let sig_len =
                u32::from_le_bytes(data[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
            cursor += 8;

            if cursor + sig_len > data.len() {
                return Err(ThresholdError::InvalidThresholdSignature);
            }
            let sig_bytes = &data[cursor..cursor + sig_len];
            cursor += sig_len;

            if signer_index >= public_keys.len() {
                return Err(ThresholdError::SignerOutOfRange {
                    index: signer_index,
                    max: public_keys.len(),
                });
            }

            let vk = VerifyingKey::from_bytes(&public_keys[signer_index])
                .map_err(|_| ThresholdError::InvalidPartialSignature(signer_index))?;
            let sig = Signature::from_bytes(sig_bytes.to_vec());
            vk.verify(message, &sig)
                .map_err(|_| ThresholdError::InvalidPartialSignature(signer_index))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_committee(n: usize) -> (Vec<SigningKey>, Vec<Vec<u8>>) {
        let mut sks = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..n {
            let (sk, vk) = SigningKey::generate();
            pks.push(vk.to_bytes());
            sks.push(sk);
        }
        (sks, pks)
    }

    #[test]
    fn test_partial_sign_and_aggregate() {
        let (sks, pks) = generate_committee(5);
        let message = b"block_hash_123";

        // 3-of-5 threshold
        let partial_sigs: Vec<_> = (0..3)
            .map(|i| SimpleThreshold::partial_sign(i, &sks[i].to_bytes(), message).unwrap())
            .collect();

        let threshold_sig = SimpleThreshold::aggregate(&partial_sigs, &pks, message, 3, 5).unwrap();

        assert_eq!(threshold_sig.participant_count(), 3);
        assert!(threshold_sig.participants.is_set(0));
        assert!(threshold_sig.participants.is_set(1));
        assert!(threshold_sig.participants.is_set(2));
        assert!(!threshold_sig.participants.is_set(3));
    }

    #[test]
    fn test_verify_threshold_signature() {
        let (sks, pks) = generate_committee(5);
        let message = b"block_to_finalize";

        let partial_sigs: Vec<_> = (0..4)
            .map(|i| SimpleThreshold::partial_sign(i, &sks[i].to_bytes(), message).unwrap())
            .collect();

        let threshold_sig = SimpleThreshold::aggregate(&partial_sigs, &pks, message, 3, 5).unwrap();

        assert!(SimpleThreshold::verify(&threshold_sig, &pks, message, 3).is_ok());
    }

    #[test]
    fn test_insufficient_signers() {
        let (sks, pks) = generate_committee(5);
        let message = b"test";

        let partial_sigs: Vec<_> = (0..2)
            .map(|i| SimpleThreshold::partial_sign(i, &sks[i].to_bytes(), message).unwrap())
            .collect();

        assert!(matches!(
            SimpleThreshold::aggregate(&partial_sigs, &pks, message, 3, 5),
            Err(ThresholdError::InsufficientSigners { needed: 3, have: 2 })
        ));
    }

    #[test]
    fn test_duplicate_signer_rejected() {
        let (sks, pks) = generate_committee(5);
        let message = b"test";

        let ps0 = SimpleThreshold::partial_sign(0, &sks[0].to_bytes(), message).unwrap();
        let ps0_dup = SimpleThreshold::partial_sign(0, &sks[0].to_bytes(), message).unwrap();

        assert!(matches!(
            SimpleThreshold::aggregate(&[ps0, ps0_dup], &pks, message, 2, 5),
            Err(ThresholdError::DuplicateSigner(0))
        ));
    }

    #[test]
    fn test_wrong_message_rejected() {
        let (sks, pks) = generate_committee(3);

        // Sign with correct message
        let partial_sigs: Vec<_> = (0..3)
            .map(|i| SimpleThreshold::partial_sign(i, &sks[i].to_bytes(), b"correct").unwrap())
            .collect();

        // Try to aggregate against wrong message
        assert!(SimpleThreshold::aggregate(&partial_sigs, &pks, b"wrong", 3, 3).is_err());
    }

    #[test]
    fn test_67_of_100_committee() {
        let (sks, pks) = generate_committee(100);
        let message = b"block_at_height_42";

        // 67 out of 100 sign
        let partial_sigs: Vec<_> = (0..67)
            .map(|i| SimpleThreshold::partial_sign(i, &sks[i].to_bytes(), message).unwrap())
            .collect();

        let threshold_sig =
            SimpleThreshold::aggregate(&partial_sigs, &pks, message, 67, 100).unwrap();

        assert_eq!(threshold_sig.participant_count(), 67);
        assert!(SimpleThreshold::verify(&threshold_sig, &pks, message, 67).is_ok());

        // Verify bitfield
        for i in 0..67 {
            assert!(threshold_sig.participants.is_set(i));
        }
        for i in 67..100 {
            assert!(!threshold_sig.participants.is_set(i));
        }
    }
}
