//! Ringtail singleton signing helper for the bridge committee path.
//!
//! Behind the `ringtail-singleton` feature. Produces a 1-of-1 Ringtail
//! threshold signature in the byte format the on-chain
//! `ringtail-verify` feature in `bridges/solana/programs/seal-bridge`
//! and `bridges/stellar` accepts.
//!
//! # Why singleton first
//!
//! Multi-validator Ringtail (n-of-n / t-of-n) requires P2P round 1
//! commitment exchange + round 2 partial-response collection across
//! the validator set, which is a separate body of work. The 1-of-1
//! variant uses the same byte format and the same on-chain verifier
//! — it's the foundational "host signs, on-chain verifies"
//! roundtrip that the multi-signer path will eventually replace.
//!
//! Today the bridge defaults to HMAC-SHA-256 committee-of-1 (see
//! `compute_committee_mac`). When the on-chain `ringtail-verify`
//! feature is wired up at deploy time AND the host produces sigs
//! via the helper here, the bridge upgrades from a symmetric MAC
//! (anyone with the key can forge) to an asymmetric PQ signature
//! (only the holder of the secret can sign).
//!
//! # Wire format
//!
//! ```text
//! [z         (2048 bytes, 256 LE-u64 coefficients)]
//! [challenge (32 bytes,   SHA3-256(D || message))]
//! [partcnt   (8  bytes,   little-endian usize)]
//! ```
//!
//! Total: 2088 bytes. The on-chain verifier reads `z` and `challenge`
//! by slice; `participant_count` is passed as a separate ix arg
//! (the on-chain Signature struct has it as a field, not a slice).
//!
//! Public params (matrix_a, public_key_t) are NOT part of the
//! signature wire format — they're a one-time deploy artifact
//! installed alongside the bridge program.

use crate::bridge::{
    solana_recipient_bytes, stellar_address_to_xdr, BRIDGE_DOMAIN_TAG_SOLANA,
    BRIDGE_DOMAIN_TAG_STELLAR,
};
use crate::types::Chain;
use seal_threshold::ntt::HandRolledOps;
use seal_threshold::ringtail::{
    aggregate_commitments, aggregate_responses_full, generate_public_params_no_error,
    sign_single_full, PublicParams as HostParams, RingtailSignature as HostSignature,
};
use serde::{Deserialize, Serialize};

/// Re-exports for bridge consumers that need to construct or shuttle
/// Round1 / Round2 messages between validators (P2P transport layer)
/// without taking a direct dep on `seal-threshold`.
pub use seal_threshold::ringtail::{Round1MessageFull, Round2Message};

/// Wire envelope for the Round1 commitment broadcast on
/// `seal/bridge-ringtail-round1/1.0`. Carries the withdrawal-id +
/// chain so receivers can route to the right per-withdrawal signing
/// session, plus the inner Round1MessageFull from seal-threshold.
///
/// Serde-serializable so the P2P layer (gossipsub) can push the bytes
/// without bringing in a custom encoder. Receivers verify the
/// `withdrawal_id` matches a known pending withdrawal before processing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeRingtailRound1Envelope {
    /// Globally-unique withdrawal id (`wd_<chain_tag>_<nonce>`).
    pub withdrawal_id: String,
    /// Destination chain — informational; the withdrawal_id encodes
    /// it but having it explicit at this layer dodges parse errors.
    pub dest_chain: Chain,
    /// The threshold-crate Round1 commitment payload.
    pub inner: Round1MessageFull,
}

/// Wire envelope for the Round2 partial response broadcast on
/// `seal/bridge-ringtail-round2/1.0`. Same shape as Round1Envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeRingtailRound2Envelope {
    pub withdrawal_id: String,
    pub dest_chain: Chain,
    pub inner: Round2Message,
}

/// Wire envelope for the finalized aggregate signature broadcast on
/// `seal/bridge-ringtail-sigs/1.0`. Lets validators that didn't drive
/// the aggregation themselves attach the sig to their local
/// withdrawal record without re-running aggregate_responses_full.
///
/// `signature_hex` is the hex-encoded 2088-byte wire form (matches
/// what `BridgeWithdrawal::committee_signature_hex` carries).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeRingtailAggregateEnvelope {
    pub withdrawal_id: String,
    pub dest_chain: Chain,
    pub signature_hex: String,
}

/// Length of a serialized response polynomial (256 LE-u64 = 2048 B).
pub const RINGTAIL_Z_LEN: usize = 2048;
/// Length of the challenge hash field (SHA3-256 → 32 B).
pub const RINGTAIL_CHALLENGE_LEN: usize = 32;
/// Length of the participant-count field (LE u64).
pub const RINGTAIL_PARTCNT_LEN: usize = 8;
/// Total wire length: z + challenge + partcnt.
pub const RINGTAIL_SIG_BYTES: usize =
    RINGTAIL_Z_LEN + RINGTAIL_CHALLENGE_LEN + RINGTAIL_PARTCNT_LEN;

/// Errors specific to the Ringtail singleton path.
#[derive(Debug)]
pub enum RingtailError {
    /// `seal-threshold::sign_single_full` rejected the inputs (e.g. sk
    /// bytes don't decode to a polynomial in the ring).
    Sign(seal_threshold::ThresholdError),
    /// Encoded `z` was not 2048 bytes — should never happen for a
    /// valid signature, but exposed so callers don't have to assume.
    BadZLength { got: usize, want: usize },
}

impl core::fmt::Display for RingtailError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RingtailError::Sign(e) => write!(f, "ringtail sign failed: {:?}", e),
            RingtailError::BadZLength { got, want } => {
                write!(f, "ringtail z length: got {got}, expected {want}")
            }
        }
    }
}

impl std::error::Error for RingtailError {}

/// Produce a 1-of-1 Ringtail signature over `message` for the on-chain
/// verifier. `public_params` and `sk_collapsed_bytes` are produced by
/// `generate_public_params_no_error` (which returns the matched
/// `(params, sk_bytes)` pair).
///
/// Returns the canonical `RINGTAIL_SIG_BYTES`-byte wire form.
pub fn sign_singleton(
    public_params: &HostParams,
    sk_collapsed_bytes: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, RingtailError> {
    // `smudging = false` — the cross-check tests (crates/seal-ringtail-
    // verify/tests/crosscheck.rs) prove byte compatibility only in the
    // non-smudging path. Smudging is a follow-up track.
    let sig = sign_single_full(public_params, sk_collapsed_bytes, message, false)
        .map_err(RingtailError::Sign)?;
    encode_signature(&sig)
}

/// Encode a `RingtailSignature` to the canonical wire form. The
/// host signer already serializes `z` as 256 LE-u64 coefficients →
/// 2048 bytes, which is exactly the on-chain verifier's expected
/// layout, so we copy it through verbatim.
pub fn encode_signature(sig: &HostSignature) -> Result<Vec<u8>, RingtailError> {
    if sig.z.len() != RINGTAIL_Z_LEN {
        return Err(RingtailError::BadZLength {
            got: sig.z.len(),
            want: RINGTAIL_Z_LEN,
        });
    }
    let mut out = Vec::with_capacity(RINGTAIL_SIG_BYTES);
    out.extend_from_slice(&sig.z);
    out.extend_from_slice(&sig.challenge);
    let part_count = sig.participants.count() as u64;
    out.extend_from_slice(&part_count.to_le_bytes());
    Ok(out)
}

/// Helper for the public-params bring-up. Returns the canonical
/// (params, sk_bytes) pair used by `sign_singleton`. Wraps
/// `seal_threshold::ringtail::generate_public_params_no_error` so
/// callers don't need to depend on `seal-threshold` directly.
pub fn generate_singleton_keymaterial() -> (HostParams, Vec<u8>) {
    generate_public_params_no_error(&HandRolledOps::new())
}

/// Bundled Ringtail keypair for installation on `BridgeManager`.
/// Mirrors what `compute_committee_ringtail_sig` takes individually,
/// in a single owned struct. Held in `BridgeManager::committee_
/// ringtail_keypair` so the per-withdrawal call site doesn't need to
/// thread two values.
#[derive(Debug)]
pub struct RingtailKeypair {
    pub public_params: HostParams,
    pub sk_collapsed_bytes: Vec<u8>,
}

impl RingtailKeypair {
    /// Generate a fresh Ringtail singleton keypair. Convenience for
    /// the testnet bring-up path; production deploys feed an
    /// operator-controlled (params, sk) pair instead so the public
    /// parameters can be installed on-chain at the same epoch.
    pub fn generate() -> Self {
        let (public_params, sk_collapsed_bytes) = generate_singleton_keymaterial();
        Self {
            public_params,
            sk_collapsed_bytes,
        }
    }

    /// Load a keypair from a JSON file. Format mirrors the wallet
    /// keyfile shape: `{"public_params": {...}, "sk_collapsed_hex": "..."}`.
    /// Errors are flat strings so the operator-facing `seal-node`
    /// can surface them at boot without dragging in a heavier error
    /// type.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, String> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let v: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))?;
        let sk_hex = v
            .get("sk_collapsed_hex")
            .and_then(|x| x.as_str())
            .ok_or("missing 'sk_collapsed_hex'")?;
        let sk_collapsed_bytes =
            hex::decode(sk_hex).map_err(|e| format!("sk_collapsed_hex hex decode: {e}"))?;
        let public_params: HostParams = serde_json::from_value(
            v.get("public_params")
                .cloned()
                .ok_or("missing 'public_params'")?,
        )
        .map_err(|e| format!("public_params parse: {e}"))?;
        Ok(Self {
            public_params,
            sk_collapsed_bytes,
        })
    }

    /// Save a keypair to a JSON file via atomic tmp+rename so a
    /// crash mid-write doesn't leave a truncated file. Mode 0600 is
    /// the operator's responsibility (file permissions are set by
    /// the calling process's umask + a follow-up chmod, not here).
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), String> {
        let v = serde_json::json!({
            "public_params": &self.public_params,
            "sk_collapsed_hex": hex::encode(&self.sk_collapsed_bytes),
        });
        let serialized = serde_json::to_string_pretty(&v).map_err(|e| format!("serialize: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serialized.as_bytes())
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), path.display()))?;
        Ok(())
    }
}

/// Drop-in shape mirror of `bridge.rs::compute_committee_mac`, but
/// produces a Ringtail singleton signature instead of an HMAC-SHA-256
/// MAC. Builds the same per-chain payload (`recipient || amount ||
/// nonce || domain_tag`) that the on-chain `verify_committee_sig`
/// expects, then signs it with the host secret.
///
/// Returns the canonical `RINGTAIL_SIG_BYTES` wire form. Hex-encode
/// the result to land in the existing `committee_signature_hex`
/// field once bridge-state wire-up lands.
pub fn compute_committee_ringtail_sig(
    chain: &Chain,
    public_params: &HostParams,
    sk_collapsed_bytes: &[u8],
    dest_address: &str,
    amount: u64,
    nonce: u64,
) -> Result<Vec<u8>, RingtailError> {
    let payload = build_unlock_payload(chain, dest_address, amount, nonce);
    sign_singleton(public_params, sk_collapsed_bytes, &payload)
}

/// Multi-validator aggregate. The orchestration layer (P2P signing
/// session) collects Round1MessageFull from every signer + Round2Message
/// from every signer, then calls this to produce the canonical wire
/// form the on-chain verifier accepts.
///
/// Layer 4 of P1#5 — the foundational primitive for the t-of-n path.
/// Doesn't drive P2P itself (that's a follow-up); it just folds
/// pre-collected partials into the final aggregate.
///
/// `threshold` is the minimum signers required (2/3 of committee for
/// production); `committee_size` is the total signer count (used to
/// size the participants bitfield).
#[allow(clippy::too_many_arguments)]
pub fn aggregate_committee_ringtail_sig(
    chain: &Chain,
    round1_messages: &[Round1MessageFull],
    round2_messages: &[Round2Message],
    threshold: usize,
    committee_size: usize,
    dest_address: &str,
    amount: u64,
    nonce: u64,
) -> Result<Vec<u8>, RingtailError> {
    let ring = HandRolledOps::new();
    let aggregated_d_bytes =
        aggregate_commitments(&ring, round1_messages).map_err(RingtailError::Sign)?;
    let payload = build_unlock_payload(chain, dest_address, amount, nonce);
    let sig = aggregate_responses_full(
        &ring,
        &aggregated_d_bytes,
        round2_messages,
        &payload,
        threshold,
        committee_size,
    )
    .map_err(RingtailError::Sign)?;
    encode_signature(&sig)
}

/// Build the canonical unlock payload bytes the on-chain verifier
/// reproduces. Identical to the bytes `compute_committee_mac` HMACs
/// over — see the docstring on that function in bridge.rs for the
/// per-chain layout.
pub(crate) fn build_unlock_payload(
    chain: &Chain,
    dest_address: &str,
    amount: u64,
    nonce: u64,
) -> Vec<u8> {
    match chain {
        Chain::Solana => {
            let mut out = Vec::with_capacity(32 + 8 + 8 + BRIDGE_DOMAIN_TAG_SOLANA.len());
            out.extend_from_slice(&solana_recipient_bytes(dest_address));
            out.extend_from_slice(&amount.to_le_bytes());
            out.extend_from_slice(&nonce.to_le_bytes());
            out.extend_from_slice(BRIDGE_DOMAIN_TAG_SOLANA);
            out
        }
        Chain::Stellar => {
            let recipient_xdr = stellar_address_to_xdr(dest_address).unwrap_or_default();
            let mut out =
                Vec::with_capacity(recipient_xdr.len() + 16 + 8 + BRIDGE_DOMAIN_TAG_STELLAR.len());
            out.extend_from_slice(&recipient_xdr);
            // Match the HMAC path: i128 BE, 16 bytes (zero-extended u64).
            let mut amount_be_16 = [0u8; 16];
            amount_be_16[8..].copy_from_slice(&amount.to_be_bytes());
            out.extend_from_slice(&amount_be_16);
            out.extend_from_slice(&nonce.to_be_bytes());
            out.extend_from_slice(BRIDGE_DOMAIN_TAG_STELLAR);
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_ringtail_verify::{
        ntt::NttCtx,
        verify::{PublicParams as BpfParams, Signature as BpfSig},
    };
    use seal_threshold::ringtail::MODULE_K;

    /// Cross-check: sign a message singleton-style host-side, verify
    /// the produced bytes via the on-chain BPF-compatible verifier.
    /// Mirrors `valid_signature_accepted_by_both` in
    /// crates/seal-ringtail-verify/tests/crosscheck.rs but exercises
    /// the bridge-level wrapper.
    #[test]
    fn singleton_sig_roundtrip() {
        let (params, sk_bytes) = generate_singleton_keymaterial();
        let message = b"bridge-singleton-roundtrip-2026-05-16";

        let sig_bytes =
            sign_singleton(&params, &sk_bytes, message).expect("sign_singleton should succeed");
        assert_eq!(sig_bytes.len(), RINGTAIL_SIG_BYTES);

        // Split the wire bytes back out for the on-chain verifier.
        let (z, rest) = sig_bytes.split_at(RINGTAIL_Z_LEN);
        let challenge_arr: &[u8; RINGTAIL_CHALLENGE_LEN] = rest[..RINGTAIL_CHALLENGE_LEN]
            .try_into()
            .expect("32-byte challenge slice");
        let partcnt_bytes: [u8; 8] = rest[RINGTAIL_CHALLENGE_LEN..]
            .try_into()
            .expect("8-byte partcnt slice");
        let participant_count = u64::from_le_bytes(partcnt_bytes) as usize;
        assert_eq!(
            participant_count, 1,
            "singleton produces 1-participant signature"
        );

        // Build the BPF verifier inputs.
        let matrix_a_slices: Vec<&[u8]> = params
            .matrix_a
            .iter()
            .map(|row| row[0].as_slice())
            .collect();
        let t_slices: Vec<&[u8]> = params.public_key_t.iter().map(|p| p.as_slice()).collect();
        assert_eq!(matrix_a_slices.len(), MODULE_K);

        let bpf_sig = BpfSig {
            z,
            challenge: challenge_arr,
            participant_count,
        };
        let bpf_pp = BpfParams {
            matrix_a: [
                matrix_a_slices[0],
                matrix_a_slices[1],
                matrix_a_slices[2],
                matrix_a_slices[3],
                matrix_a_slices[4],
                matrix_a_slices[5],
                matrix_a_slices[6],
                matrix_a_slices[7],
            ],
            public_key_t: [
                t_slices[0],
                t_slices[1],
                t_slices[2],
                t_slices[3],
                t_slices[4],
                t_slices[5],
                t_slices[6],
                t_slices[7],
            ],
        };

        let ctx = NttCtx::new();
        seal_ringtail_verify::verify(&ctx, &bpf_sig, &bpf_pp, message, 1)
            .expect("BPF verifier rejected sign_singleton output");
    }

    #[test]
    fn chain_aware_singleton_solana_roundtrip() {
        // Mirror the existing compute_committee_mac test fixtures so
        // payload bytes match exactly between the HMAC path and the
        // Ringtail path.
        let (params, sk_bytes) = generate_singleton_keymaterial();
        let chain = Chain::Solana;
        let dest = "11111111111111111111111111111111"; // System Program
        let amount = 12345u64;
        let nonce = 7u64;

        let sig_bytes =
            compute_committee_ringtail_sig(&chain, &params, &sk_bytes, dest, amount, nonce)
                .expect("sign should succeed");
        assert_eq!(sig_bytes.len(), RINGTAIL_SIG_BYTES);

        // Reconstruct the BPF inputs and verify the wire bytes.
        let (z, rest) = sig_bytes.split_at(RINGTAIL_Z_LEN);
        let challenge_arr: &[u8; RINGTAIL_CHALLENGE_LEN] =
            rest[..RINGTAIL_CHALLENGE_LEN].try_into().unwrap();
        let matrix_a_slices: Vec<&[u8]> = params
            .matrix_a
            .iter()
            .map(|row| row[0].as_slice())
            .collect();
        let t_slices: Vec<&[u8]> = params.public_key_t.iter().map(|p| p.as_slice()).collect();
        let bpf_sig = BpfSig {
            z,
            challenge: challenge_arr,
            participant_count: 1,
        };
        let bpf_pp = BpfParams {
            matrix_a: [
                matrix_a_slices[0],
                matrix_a_slices[1],
                matrix_a_slices[2],
                matrix_a_slices[3],
                matrix_a_slices[4],
                matrix_a_slices[5],
                matrix_a_slices[6],
                matrix_a_slices[7],
            ],
            public_key_t: [
                t_slices[0],
                t_slices[1],
                t_slices[2],
                t_slices[3],
                t_slices[4],
                t_slices[5],
                t_slices[6],
                t_slices[7],
            ],
        };

        // Recompute the same payload host-side and feed it to the BPF
        // verifier so the test acts as the authoritative spec for what
        // the on-chain code must reproduce.
        let payload = build_unlock_payload(&chain, dest, amount, nonce);
        let ctx = NttCtx::new();
        seal_ringtail_verify::verify(&ctx, &bpf_sig, &bpf_pp, &payload, 1)
            .expect("BPF verifier rejected chain-aware singleton output");
    }

    #[test]
    fn payload_changes_when_nonce_changes() {
        let p1 = build_unlock_payload(&Chain::Solana, "11111111111111111111111111111111", 1, 1);
        let p2 = build_unlock_payload(&Chain::Solana, "11111111111111111111111111111111", 1, 2);
        assert_ne!(p1, p2, "different nonces must produce different payloads");
        // The chain prefix (recipient || amount) is identical; only
        // the nonce LE bytes flip.
        assert_eq!(p1[..40], p2[..40]);
    }

    #[test]
    fn payload_changes_per_chain_for_same_logical_input() {
        let sol = build_unlock_payload(&Chain::Solana, "11111111111111111111111111111111", 1, 1);
        let xlm = build_unlock_payload(
            &Chain::Stellar,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            1,
            1,
        );
        assert_ne!(sol, xlm);
        // Both should end with their respective domain tag.
        assert!(sol.ends_with(BRIDGE_DOMAIN_TAG_SOLANA));
        assert!(xlm.ends_with(BRIDGE_DOMAIN_TAG_STELLAR));
    }

    #[test]
    fn bridge_manager_uses_ringtail_when_keypair_set() {
        // End-to-end through BridgeManager: install Ringtail keypair,
        // initiate a withdrawal, confirm the resulting
        // committee_signature_hex parses back into a signature the
        // BPF verifier accepts.
        use crate::types::{BridgeDeposit, WrappedToken};
        use crate::BridgeManager;

        let mut bridge = BridgeManager::new(1);
        // Set up a wrapped balance so the burn passes.
        bridge
            .observe_deposit(BridgeDeposit {
                id: "d1".into(),
                source_chain: Chain::Stellar,
                source_tx_hash: "tx1".into(),
                source_address: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                seal_address: "seal1user".into(),
                amount: 5000,
                token: WrappedToken::WXLM,
                processed: false,
                confirmations: 1,
            })
            .unwrap();
        bridge.confirm_deposit("d1").unwrap();
        bridge.process_deposit("d1").unwrap();

        // Install Ringtail singleton keypair (preempts the HMAC path
        // even if a committee_key were also set; tested implicitly by
        // not setting one here).
        let kp = RingtailKeypair::generate();
        let pp = HostParams {
            matrix_a: kp.public_params.matrix_a.clone(),
            public_key_t: kp.public_params.public_key_t.clone(),
        };
        bridge.set_committee_ringtail_keypair(kp);
        assert!(bridge.has_ringtail_keypair());

        let dest = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let wd_id = bridge
            .initiate_withdrawal("seal1user", Chain::Stellar, dest, WrappedToken::WXLM, 1000)
            .unwrap();
        let withdrawal = bridge.get_withdrawal(&wd_id).expect("withdrawal stored");
        let sig_hex = withdrawal
            .committee_signature_hex
            .as_ref()
            .expect("ringtail signature attached");
        let sig_bytes = hex::decode(sig_hex).expect("hex decode");
        assert_eq!(
            sig_bytes.len(),
            RINGTAIL_SIG_BYTES,
            "wire format must be 2088 bytes"
        );

        // Verify via BPF verifier.
        let (z, rest) = sig_bytes.split_at(RINGTAIL_Z_LEN);
        let challenge_arr: &[u8; RINGTAIL_CHALLENGE_LEN] =
            rest[..RINGTAIL_CHALLENGE_LEN].try_into().unwrap();
        let payload = build_unlock_payload(&Chain::Stellar, dest, 1000, withdrawal.nonce);
        let matrix_a_slices: Vec<&[u8]> = pp.matrix_a.iter().map(|row| row[0].as_slice()).collect();
        let t_slices: Vec<&[u8]> = pp.public_key_t.iter().map(|p| p.as_slice()).collect();
        let bpf_sig = BpfSig {
            z,
            challenge: challenge_arr,
            participant_count: 1,
        };
        let bpf_pp = BpfParams {
            matrix_a: [
                matrix_a_slices[0],
                matrix_a_slices[1],
                matrix_a_slices[2],
                matrix_a_slices[3],
                matrix_a_slices[4],
                matrix_a_slices[5],
                matrix_a_slices[6],
                matrix_a_slices[7],
            ],
            public_key_t: [
                t_slices[0],
                t_slices[1],
                t_slices[2],
                t_slices[3],
                t_slices[4],
                t_slices[5],
                t_slices[6],
                t_slices[7],
            ],
        };
        let ctx = NttCtx::new();
        seal_ringtail_verify::verify(&ctx, &bpf_sig, &bpf_pp, &payload, 1)
            .expect("BPF verifier rejected BridgeManager-produced ringtail signature");
    }

    #[test]
    fn aggregate_two_of_two_round_trip() {
        // P1#5 layer 4 primitive: feed round1+round2 messages from
        // two real signers into aggregate_committee_ringtail_sig and
        // confirm the BPF verifier accepts the resulting wire bytes.
        // Builds the same shape the eventual P2P-driven path will
        // construct, just with the network omitted.
        use seal_threshold::ntt::HandRolledOps;
        use seal_threshold::ringtail::RingOps as _;
        use seal_threshold::ringtail::MODULE_L;
        use seal_threshold::ringtail::{RingtailParty, MODULE_K as HOST_K};

        let ring = HandRolledOps::new();
        // Shared secret distributed via 2-of-2 trivial sharing
        // (both parties hold sk; aggregate-z arithmetic needs t = A·2sk).
        let sk = ring.sample_gaussian(6.108);
        let two_sk = ring.add(&sk, &sk);

        // Build matching params (same shape the n-of-n crosscheck uses).
        let mut matrix_a_col0_polys = Vec::with_capacity(HOST_K);
        let mut matrix_a_bytes: Vec<Vec<Vec<u8>>> = Vec::with_capacity(HOST_K);
        for _ in 0..HOST_K {
            let col0 = ring.sample_uniform();
            let mut row = Vec::with_capacity(MODULE_L);
            row.push(ring.to_bytes(&col0));
            for _ in 1..MODULE_L {
                row.push(ring.to_bytes(&ring.sample_uniform()));
            }
            matrix_a_col0_polys.push(col0);
            matrix_a_bytes.push(row);
        }
        let public_key_t_bytes: Vec<Vec<u8>> = matrix_a_col0_polys
            .iter()
            .map(|a| ring.to_bytes(&ring.mul(a, &two_sk)))
            .collect();
        let params = HostParams {
            matrix_a: matrix_a_bytes,
            public_key_t: public_key_t_bytes,
        };

        let mut p0 = RingtailParty::new(0, sk.clone(), HandRolledOps::new());
        let mut p1 = RingtailParty::new(1, sk.clone(), HandRolledOps::new());
        let mac_key = b"shared-mac-key";
        let r1_0 = p0.round1_full(&params, mac_key, false).unwrap();
        let r1_1 = p1.round1_full(&params, mac_key, false).unwrap();

        // Now drive the aggregate through the bridge wrapper (which
        // owns the payload construction).
        let chain = Chain::Solana;
        let dest = "11111111111111111111111111111111";
        let amount = 4242u64;
        let nonce = 99u64;

        // Both parties must run round2 against the SAME aggregated D
        // bytes — the bridge wrapper recomputes it internally during
        // aggregate, so we precompute it here only to feed round2.
        let aggregated_d =
            seal_threshold::ringtail::aggregate_commitments(&ring, &[r1_0.clone(), r1_1.clone()])
                .unwrap();
        let payload = build_unlock_payload(&chain, dest, amount, nonce);
        let r2_0 = p0.round2_full(&aggregated_d, &payload).unwrap();
        let r2_1 = p1.round2_full(&aggregated_d, &payload).unwrap();

        let sig_bytes = aggregate_committee_ringtail_sig(
            &chain,
            &[r1_0, r1_1],
            &[r2_0, r2_1],
            2,
            2,
            dest,
            amount,
            nonce,
        )
        .expect("aggregate should succeed");
        assert_eq!(sig_bytes.len(), RINGTAIL_SIG_BYTES);

        // BPF verify against the same params + payload.
        let (z, rest) = sig_bytes.split_at(RINGTAIL_Z_LEN);
        let challenge_arr: &[u8; RINGTAIL_CHALLENGE_LEN] =
            rest[..RINGTAIL_CHALLENGE_LEN].try_into().unwrap();
        let partcnt_bytes: [u8; 8] = rest[RINGTAIL_CHALLENGE_LEN..].try_into().unwrap();
        let partcnt = u64::from_le_bytes(partcnt_bytes) as usize;
        assert_eq!(partcnt, 2, "2-of-2 produces 2-participant signature");

        let matrix_a_slices: Vec<&[u8]> = params
            .matrix_a
            .iter()
            .map(|row| row[0].as_slice())
            .collect();
        let t_slices: Vec<&[u8]> = params.public_key_t.iter().map(|p| p.as_slice()).collect();
        let bpf_sig = BpfSig {
            z,
            challenge: challenge_arr,
            participant_count: partcnt,
        };
        let bpf_pp = BpfParams {
            matrix_a: [
                matrix_a_slices[0],
                matrix_a_slices[1],
                matrix_a_slices[2],
                matrix_a_slices[3],
                matrix_a_slices[4],
                matrix_a_slices[5],
                matrix_a_slices[6],
                matrix_a_slices[7],
            ],
            public_key_t: [
                t_slices[0],
                t_slices[1],
                t_slices[2],
                t_slices[3],
                t_slices[4],
                t_slices[5],
                t_slices[6],
                t_slices[7],
            ],
        };
        let ctx = NttCtx::new();
        seal_ringtail_verify::verify(&ctx, &bpf_sig, &bpf_pp, &payload, 2)
            .expect("BPF verifier rejected 2-of-2 aggregate");
    }

    #[test]
    fn ringtail_aggregate_envelope_serde_roundtrip() {
        // Wire-shape smoke for the envelope that broadcasts the
        // finalized aggregate sig on seal/bridge-ringtail-sigs/1.0.
        let env = BridgeRingtailAggregateEnvelope {
            withdrawal_id: "wd_sol_42".into(),
            dest_chain: Chain::Solana,
            signature_hex: "deadbeef".repeat(522), // dummy 2088-byte hex
        };
        let bytes = serde_json::to_vec(&env).expect("serialize envelope");
        let back: BridgeRingtailAggregateEnvelope =
            serde_json::from_slice(&bytes).expect("deserialize envelope");
        assert_eq!(back.withdrawal_id, env.withdrawal_id);
        assert_eq!(back.dest_chain, env.dest_chain);
        assert_eq!(back.signature_hex, env.signature_hex);
    }

    #[test]
    fn ringtail_round1_envelope_carries_real_message() {
        // Smoke: the inner Round1MessageFull from a real party round-
        // trips through serde inside our envelope. Catches changes to
        // seal-threshold's wire shape that would silently break the
        // P2P transport.
        use seal_threshold::ringtail::RingOps as _;
        use seal_threshold::ringtail::RingtailParty;

        let ring = HandRolledOps::new();
        let sk = ring.sample_gaussian(6.108);
        let mut p = RingtailParty::new(0, sk, HandRolledOps::new());
        let (params, _sk_bytes) = generate_singleton_keymaterial();
        let r1 = p.round1_full(&params, b"smoke", false).expect("round1");

        let env = BridgeRingtailRound1Envelope {
            withdrawal_id: "wd_xlm_7".into(),
            dest_chain: Chain::Stellar,
            inner: r1.clone(),
        };
        let bytes = serde_json::to_vec(&env).expect("serialize");
        let back: BridgeRingtailRound1Envelope =
            serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(back.withdrawal_id, env.withdrawal_id);
        assert_eq!(back.dest_chain, env.dest_chain);
        // Round1MessageFull doesn't impl PartialEq; comparing the
        // serialized commitment field is enough for the wire smoke.
        assert_eq!(back.inner.commitment, r1.commitment);
    }

    #[test]
    fn keypair_save_load_roundtrip_through_file() {
        let kp = RingtailKeypair::generate();
        let tmp = std::env::temp_dir().join("seal-bridge-ringtail-keypair-test.json");
        let _ = std::fs::remove_file(&tmp);
        kp.save_to_file(&tmp).expect("save");
        let kp2 = RingtailKeypair::load_from_file(&tmp).expect("load");
        // Same secret + matching public params (params are
        // serde-serializable as nested arrays of byte vecs; equality
        // checks the round-trip is byte-exact).
        assert_eq!(kp.sk_collapsed_bytes, kp2.sk_collapsed_bytes);
        assert_eq!(
            kp.public_params.matrix_a, kp2.public_params.matrix_a,
            "matrix_a must round-trip byte-exact"
        );
        assert_eq!(
            kp.public_params.public_key_t, kp2.public_params.public_key_t,
            "public_key_t must round-trip byte-exact"
        );

        // Loaded keypair signs identically (sanity).
        let payload = b"keypair-roundtrip-payload";
        let sig1 = sign_singleton(&kp.public_params, &kp.sk_collapsed_bytes, payload).unwrap();
        let sig2 = sign_singleton(&kp2.public_params, &kp2.sk_collapsed_bytes, payload).unwrap();
        // Round1 randomness inside sign_single_full is non-deterministic
        // (sample_gaussian), so signatures DIFFER per call. We just
        // confirm both verify with the same params + payload via the
        // BPF verifier.
        for sig in [sig1, sig2] {
            let (z, rest) = sig.split_at(RINGTAIL_Z_LEN);
            let challenge_arr: &[u8; RINGTAIL_CHALLENGE_LEN] =
                rest[..RINGTAIL_CHALLENGE_LEN].try_into().unwrap();
            let matrix_a_slices: Vec<&[u8]> = kp
                .public_params
                .matrix_a
                .iter()
                .map(|row| row[0].as_slice())
                .collect();
            let t_slices: Vec<&[u8]> = kp
                .public_params
                .public_key_t
                .iter()
                .map(|p| p.as_slice())
                .collect();
            let bpf_sig = BpfSig {
                z,
                challenge: challenge_arr,
                participant_count: 1,
            };
            let bpf_pp = BpfParams {
                matrix_a: [
                    matrix_a_slices[0],
                    matrix_a_slices[1],
                    matrix_a_slices[2],
                    matrix_a_slices[3],
                    matrix_a_slices[4],
                    matrix_a_slices[5],
                    matrix_a_slices[6],
                    matrix_a_slices[7],
                ],
                public_key_t: [
                    t_slices[0],
                    t_slices[1],
                    t_slices[2],
                    t_slices[3],
                    t_slices[4],
                    t_slices[5],
                    t_slices[6],
                    t_slices[7],
                ],
            };
            let ctx = NttCtx::new();
            seal_ringtail_verify::verify(&ctx, &bpf_sig, &bpf_pp, payload, 1)
                .expect("BPF verifier accepts signature from loaded keypair");
        }

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn keypair_load_missing_field_errors() {
        // Truncated JSON without sk_collapsed_hex must surface a clear
        // error string operators can grep on.
        let tmp = std::env::temp_dir().join("seal-bridge-ringtail-missing-test.json");
        std::fs::write(&tmp, r#"{"public_params": null}"#).unwrap();
        let err = RingtailKeypair::load_from_file(&tmp).unwrap_err();
        assert!(err.contains("missing 'sk_collapsed_hex'"), "err: {err}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn wrong_message_fails_bpf_verify() {
        let (params, sk_bytes) = generate_singleton_keymaterial();
        let sig_bytes = sign_singleton(&params, &sk_bytes, b"signed-message").unwrap();

        let (z, rest) = sig_bytes.split_at(RINGTAIL_Z_LEN);
        let challenge_arr: &[u8; RINGTAIL_CHALLENGE_LEN] =
            rest[..RINGTAIL_CHALLENGE_LEN].try_into().unwrap();

        let matrix_a_slices: Vec<&[u8]> = params
            .matrix_a
            .iter()
            .map(|row| row[0].as_slice())
            .collect();
        let t_slices: Vec<&[u8]> = params.public_key_t.iter().map(|p| p.as_slice()).collect();
        let bpf_sig = BpfSig {
            z,
            challenge: challenge_arr,
            participant_count: 1,
        };
        let bpf_pp = BpfParams {
            matrix_a: [
                matrix_a_slices[0],
                matrix_a_slices[1],
                matrix_a_slices[2],
                matrix_a_slices[3],
                matrix_a_slices[4],
                matrix_a_slices[5],
                matrix_a_slices[6],
                matrix_a_slices[7],
            ],
            public_key_t: [
                t_slices[0],
                t_slices[1],
                t_slices[2],
                t_slices[3],
                t_slices[4],
                t_slices[5],
                t_slices[6],
                t_slices[7],
            ],
        };
        let ctx = NttCtx::new();
        let res = seal_ringtail_verify::verify(&ctx, &bpf_sig, &bpf_pp, b"different-message", 1);
        assert!(
            res.is_err(),
            "verifier accepted a signature for a different message"
        );
    }
}
