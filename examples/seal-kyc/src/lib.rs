//! kyc.seal — ML-DSA-attested KYC for other on-chain apps.
//!
//! # Model
//!
//! An off-chain *attester* (e.g. a Veriff-style provider, or a
//! government-issued e-ID gateway) holds an ML-DSA keypair. After
//! verifying a user's documents off-chain, they post an `Attestation`
//! row to the `kyc_attestations` table:
//!
//! ```text
//!   subject_addr || tier || expires_at || attestation_id || sig
//! ```
//!
//! Other apps gate access via `HAS_KYC(tier)` in their RLS policies.
//! `HAS_KYC(tier)` resolves to true iff there exists an
//! `kyc_attestations` row for `subject_addr = CURRENT_USER()` with
//! `tier >= requested_tier` and `expires_at > NOW()`.
//!
//! # Threat model
//!
//! * Anyone can post a row, but the row is only consulted by
//!   `HAS_KYC` if its signature verifies under one of the registered
//!   attesters. The attester roster is governance-managed
//!   (`kyc_attesters` table, RLS-locked to the protocol governance
//!   role).
//! * Tier numbers are coarse: 1 = email-verified, 2 =
//!   government-ID, 3 = enhanced due diligence. Apps pick a
//!   threshold; the chain doesn't enforce semantics.
//! * Revocation is a separate row in `kyc_revocations`. `HAS_KYC`
//!   honours it; expiry is the cheaper path for routine churn.
//!
//! # What this crate ships
//!
//! Schema, RLS policies, the canonical `Attestation` byte format
//! (used both for signing and for verification), and a pure
//! `verify_attestation` function. Wiring `HAS_KYC` into seal-sql is
//! the next step.

use seal_crypto::hash::sha3_256;
use seal_crypto::signature::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const SCHEMA_DDL: &str = "
CREATE TABLE kyc_attesters (
    address TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    pubkey_hex TEXT NOT NULL,
    enabled_at_height BIGINT NOT NULL
);

CREATE TABLE kyc_attestations (
    attestation_id TEXT PRIMARY KEY,
    attester_addr TEXT NOT NULL,
    subject_addr TEXT NOT NULL,
    tier BIGINT NOT NULL,
    expires_at_unix BIGINT NOT NULL,
    sig_hex TEXT NOT NULL,
    created_at_height BIGINT NOT NULL
);

CREATE TABLE kyc_revocations (
    attestation_id TEXT PRIMARY KEY,
    attester_addr TEXT NOT NULL,
    revoked_at_height BIGINT NOT NULL,
    sig_hex TEXT NOT NULL
);
";

pub fn rls_policies() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        // Only the registered attester address can post attestations
        // about other subjects. Self-attestation is always rejected.
        (
            "kyc_attestations",
            "INSERT_ATTESTER",
            "attester_addr = CURRENT_USER() AND attester_addr != subject_addr",
        ),
        (
            "kyc_revocations",
            "INSERT_ATTESTER",
            "attester_addr = CURRENT_USER()",
        ),
        // The attester roster is governance-only (the actual
        // governance gate is enforced upstream by `seal-node::rpc`'s
        // requires_auth list).
        ("kyc_attesters", "INSERT_GOV", "false"),
    ]
}

/// Coarse KYC tier. Apps pick a numeric threshold; the chain doesn't
/// attach semantics — the labels here are conventional.
pub mod tier {
    pub const EMAIL_VERIFIED: u64 = 1;
    pub const GOV_ID: u64 = 2;
    pub const ENHANCED_DD: u64 = 3;
}

/// Canonical byte layout the attester signs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestation {
    pub attestation_id: String,
    pub attester_addr: String,
    pub subject_addr: String,
    pub tier: u64,
    pub expires_at_unix: u64,
}

impl Attestation {
    /// Serialize the attestation to the bytes the attester signs over.
    /// SHA3-256 prefix is included so there's no domain ambiguity with
    /// raw KYC documents.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"SEAL-KYC-ATT-V1");
        buf.extend_from_slice(self.attestation_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.attester_addr.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.subject_addr.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.tier.to_le_bytes());
        buf.extend_from_slice(&self.expires_at_unix.to_le_bytes());
        sha3_256(&buf).0.to_vec()
    }
}

/// Verify a signed attestation against the attester's verifying key.
/// Returns `Ok(())` if the signature checks out *and* the attestation
/// has not expired at `now_unix`.
pub fn verify_attestation(
    att: &Attestation,
    sig_hex: &str,
    attester_vk: &VerifyingKey,
    now_unix: u64,
) -> Result<(), String> {
    if now_unix > att.expires_at_unix {
        return Err(format!(
            "attestation expired: now={now_unix}, expires={}",
            att.expires_at_unix
        ));
    }
    let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex: {e}"))?;
    let sig = Signature::from_bytes(sig_bytes);
    let payload = att.signing_bytes();
    attester_vk
        .verify(&payload, &sig)
        .map_err(|e| format!("ml-dsa verify: {e}"))
}

/// Helper: predicate that `HAS_KYC(tier)` will compile to once it
/// lands in seal-sql. Pure Rust so apps can call it from a test
/// harness today.
pub fn has_kyc(
    requested_tier: u64,
    attestations: &[(Attestation, String /* sig_hex */, VerifyingKey)],
    now_unix: u64,
) -> bool {
    attestations.iter().any(|(att, sig, vk)| {
        att.tier >= requested_tier
            && verify_attestation(att, sig, vk, now_unix).is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::signature::SigningKey;

    fn issue(att: &Attestation, sk: &SigningKey) -> String {
        let sig = sk.sign(&att.signing_bytes()).unwrap();
        hex::encode(sig.to_bytes())
    }

    fn make_att(subject: &str, tier: u64, expires: u64) -> Attestation {
        Attestation {
            attestation_id: format!("att-{subject}-{tier}"),
            attester_addr: "attester-1".into(),
            subject_addr: subject.into(),
            tier,
            expires_at_unix: expires,
        }
    }

    #[test]
    fn ddl_parses() {
        seal_sql::parse_sql(SCHEMA_DDL).expect("kyc.seal DDL must parse");
    }

    #[test]
    fn policies_block_self_attestation() {
        let p = rls_policies();
        let att_policy = p
            .iter()
            .find(|(t, _, _)| *t == "kyc_attestations")
            .expect("must have an attestation policy");
        assert!(att_policy.2.contains("attester_addr != subject_addr"));
    }

    #[test]
    fn signed_attestation_verifies() {
        let (sk, vk) = SigningKey::generate();
        let att = make_att("alice", tier::GOV_ID, 9_999_999_999);
        let sig_hex = issue(&att, &sk);
        verify_attestation(&att, &sig_hex, &vk, 1_000_000)
            .expect("honest attestation must verify");
    }

    #[test]
    fn expired_attestation_rejected() {
        let (sk, vk) = SigningKey::generate();
        let att = make_att("alice", tier::EMAIL_VERIFIED, 100);
        let sig_hex = issue(&att, &sk);
        let err = verify_attestation(&att, &sig_hex, &vk, 200).unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn forged_attestation_under_wrong_key_rejected() {
        let (sk_real, vk_real) = SigningKey::generate();
        let (_sk_fake, _vk_fake) = SigningKey::generate();
        let att = make_att("alice", tier::GOV_ID, 9_999_999_999);
        // Sign with the wrong key but try to verify against vk_real.
        let (sk_imposter, _) = SigningKey::generate();
        let sig_hex = issue(&att, &sk_imposter);
        let err = verify_attestation(&att, &sig_hex, &vk_real, 1_000_000).unwrap_err();
        assert!(err.contains("ml-dsa verify"));
        // Sanity: the real attester does verify.
        let real_sig = issue(&att, &sk_real);
        verify_attestation(&att, &real_sig, &vk_real, 1_000_000)
            .expect("honest attester must succeed");
    }

    #[test]
    fn has_kyc_threshold_check() {
        let (sk, vk) = SigningKey::generate();
        let att = make_att("alice", tier::GOV_ID, 9_999_999_999);
        let sig_hex = issue(&att, &sk);
        let bundle = vec![(att, sig_hex, vk)];
        assert!(has_kyc(tier::EMAIL_VERIFIED, &bundle, 1_000_000));
        assert!(has_kyc(tier::GOV_ID, &bundle, 1_000_000));
        assert!(!has_kyc(tier::ENHANCED_DD, &bundle, 1_000_000));
    }

    #[test]
    fn signing_bytes_change_when_tier_changes() {
        let mut a = make_att("alice", tier::EMAIL_VERIFIED, 10);
        let bytes_low = a.signing_bytes();
        a.tier = tier::GOV_ID;
        let bytes_hi = a.signing_bytes();
        assert_ne!(bytes_low, bytes_hi);
    }
}
