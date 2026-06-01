//! Per-withdrawal Ringtail signing session state machine.
//!
//! Behind the `ringtail-singleton` feature. Holds the in-progress
//! Round1 commitments + Round2 partials for a single withdrawal_id
//! and advances through the protocol phases as messages arrive.
//!
//! # Phase progression
//!
//! ```text
//!     Created
//!        │
//!        │ ingest_round1 × committee_size
//!        ▼
//!     Round1Complete (aggregated_d_bytes computed)
//!        │
//!        │ ingest_round2 × threshold (validator runs own round2 in
//!        │                            between based on aggregated_d_bytes)
//!        ▼
//!     Round2Complete (final 2088-byte aggregate signature ready)
//! ```
//!
//! The session does NOT hold the validator's sk — it's pure
//! aggregation logic. The validator's own Round1MessageFull /
//! Round2Message are produced outside (via RingtailParty) and fed
//! back in via the same ingest_* methods alongside peer messages.
//!
//! # Threading
//!
//! The struct is `!Sync` by virtue of holding mutable `Vec`s. The
//! intended usage is one session per withdrawal stored under a
//! `tokio::sync::Mutex` in the orchestrator (next layer); each
//! P2P-handler invocation acquires the lock, ingests one envelope,
//! drops the lock.

use crate::ringtail::{build_unlock_payload, RingtailError, Round1MessageFull, Round2Message};
use crate::types::Chain;
use seal_threshold::ntt::HandRolledOps;
use seal_threshold::ringtail::aggregate_commitments;
use serde::{Deserialize, Serialize};

/// Outcome of `ingest_*`. The orchestrator branches on the variant
/// and drives the next protocol step.
#[derive(Debug)]
pub enum SessionEvent {
    /// Not enough partials of this round yet — keep collecting.
    Pending {
        /// How many we have so far (informational; useful for logs +
        /// metrics).
        collected: usize,
        /// How many we expect before advancing.
        expected: usize,
    },
    /// Round1 phase complete. The orchestrator now has access to
    /// `aggregated_d_bytes()` and should run its own
    /// `RingtailParty::round2_full(aggregated_d, payload)` locally,
    /// then re-feed the resulting Round2Message via `ingest_round2`.
    /// Other validators' Round2 messages go through the same call.
    Round1Complete,
    /// Round2 phase complete. The orchestrator should hex-encode the
    /// returned bytes and call `BridgeManager::attach_committee_signature`,
    /// then broadcast the result on the bridge-ringtail-sigs topic so
    /// peers don't have to re-aggregate.
    Round2Complete { signature_bytes: Vec<u8> },
    /// Idempotent fast-path. Subsequent `ingest_*` calls after the
    /// signature is attached just return this; the caller can skip
    /// any per-event work.
    AlreadyComplete,
    /// Aggregation failed for a reason internal to the threshold
    /// crate (e.g. a partial's response polynomial violates the per-
    /// signer norm bound, indicating a misbehaving signer). The
    /// orchestrator surfaces this as a session abort + alert.
    Failed(String),
}

/// One-withdrawal signing session. Created when the bridge sees a
/// withdrawal land in the pending-signature state; destroyed when the
/// signature attaches or the orchestrator times out.
#[derive(Clone, Serialize, Deserialize)]
pub struct RingtailBridgeSession {
    pub withdrawal_id: String,
    pub dest_chain: Chain,
    /// Cached unlock payload — built once at session creation so the
    /// per-message ingest path doesn't re-build it.
    payload: Vec<u8>,
    /// Minimum signers required (2/3 of committee in production).
    threshold: usize,
    /// Total signer count (used to size the participants bitfield).
    committee_size: usize,

    round1_msgs: Vec<Round1MessageFull>,
    round2_msgs: Vec<Round2Message>,
    aggregated_d_bytes: Option<Vec<u8>>,
    final_signature: Option<Vec<u8>>,
}

impl RingtailBridgeSession {
    /// Build a session for a withdrawal that's ready for committee
    /// signing. `dest`, `amount`, `nonce` are the same values
    /// `BridgeManager::initiate_withdrawal` recorded.
    pub fn new(
        withdrawal_id: String,
        dest_chain: Chain,
        dest_address: &str,
        amount: u64,
        nonce: u64,
        threshold: usize,
        committee_size: usize,
    ) -> Self {
        let payload = build_unlock_payload(&dest_chain, dest_address, amount, nonce);
        Self {
            withdrawal_id,
            dest_chain,
            payload,
            threshold,
            committee_size,
            round1_msgs: Vec::with_capacity(committee_size),
            round2_msgs: Vec::with_capacity(committee_size),
            aggregated_d_bytes: None,
            final_signature: None,
        }
    }

    /// Ingest one Round1 commitment. Dedups by `party_id` so re-
    /// broadcast on a flaky network doesn't double-count. Returns
    /// `Round1Complete` once `committee_size` distinct parties have
    /// been seen and the aggregated D bytes are computed.
    pub fn ingest_round1(&mut self, msg: Round1MessageFull) -> SessionEvent {
        if self.final_signature.is_some() {
            return SessionEvent::AlreadyComplete;
        }
        if self.aggregated_d_bytes.is_some() {
            // Round1 already finalized — late commitment is benign.
            return SessionEvent::Pending {
                collected: self.round1_msgs.len(),
                expected: self.committee_size,
            };
        }
        if self.round1_msgs.iter().any(|m| m.party_id == msg.party_id) {
            return SessionEvent::Pending {
                collected: self.round1_msgs.len(),
                expected: self.committee_size,
            };
        }
        self.round1_msgs.push(msg);
        if self.round1_msgs.len() < self.committee_size {
            return SessionEvent::Pending {
                collected: self.round1_msgs.len(),
                expected: self.committee_size,
            };
        }
        let ring = HandRolledOps::new();
        match aggregate_commitments(&ring, &self.round1_msgs) {
            Ok(d) => {
                self.aggregated_d_bytes = Some(d);
                SessionEvent::Round1Complete
            }
            Err(e) => SessionEvent::Failed(format!("aggregate_commitments: {e:?}")),
        }
    }

    /// Ingest one Round2 partial response. Same dedup-by-party_id
    /// rule. Returns `Round2Complete` with the final 2088-byte
    /// aggregate signature once `threshold` partials have landed.
    pub fn ingest_round2(&mut self, msg: Round2Message) -> SessionEvent {
        if self.final_signature.is_some() {
            return SessionEvent::AlreadyComplete;
        }
        if self.aggregated_d_bytes.is_none() {
            // Round2 message arrived before Round1 finished. Buffer is
            // still useful — once Round1 finalizes we'll pick up these
            // partials immediately.
            if self.round2_msgs.iter().any(|m| m.party_id == msg.party_id) {
                return SessionEvent::Pending {
                    collected: self.round2_msgs.len(),
                    expected: self.threshold,
                };
            }
            self.round2_msgs.push(msg);
            return SessionEvent::Pending {
                collected: self.round2_msgs.len(),
                expected: self.threshold,
            };
        }
        if self.round2_msgs.iter().any(|m| m.party_id == msg.party_id) {
            return SessionEvent::Pending {
                collected: self.round2_msgs.len(),
                expected: self.threshold,
            };
        }
        self.round2_msgs.push(msg);
        if self.round2_msgs.len() < self.threshold {
            return SessionEvent::Pending {
                collected: self.round2_msgs.len(),
                expected: self.threshold,
            };
        }
        // Threshold reached — try to aggregate. Recovers the
        // dest_chain / dest / amount / nonce shape from the cached
        // payload by re-using the wrapper that builds them.
        match aggregate_committee_ringtail_sig_from_session(self) {
            Ok(bytes) => {
                self.final_signature = Some(bytes.clone());
                SessionEvent::Round2Complete {
                    signature_bytes: bytes,
                }
            }
            Err(e) => SessionEvent::Failed(format!("aggregate_responses: {e}")),
        }
    }

    /// Aggregated Round1 D bytes — populated once Round1 completes.
    /// The orchestrator passes this into `RingtailParty::round2_full`
    /// to compute its own validator's Round2 partial.
    pub fn aggregated_d_bytes(&self) -> Option<&[u8]> {
        self.aggregated_d_bytes.as_deref()
    }

    /// The unlock payload bytes the session is signing — exposed so
    /// the orchestrator can pass the SAME bytes into its local
    /// `round2_full(aggregated_d, payload)` call.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Final aggregate signature bytes, if Round2 has completed.
    pub fn final_signature(&self) -> Option<&[u8]> {
        self.final_signature.as_deref()
    }

    /// Has this session collected enough Round1 messages to advance?
    pub fn round1_progress(&self) -> (usize, usize) {
        (self.round1_msgs.len(), self.committee_size)
    }

    /// Has this session collected enough Round2 messages to aggregate?
    pub fn round2_progress(&self) -> (usize, usize) {
        (self.round2_msgs.len(), self.threshold)
    }
}

// `aggregate_committee_ringtail_sig` is the public wrapper but it
// recomputes the payload — when called from inside a session we
// already have the cached payload. This helper feeds the session's
// pre-built bytes into the underlying threshold aggregator while
// reusing the same byte-encoding code path.
fn aggregate_committee_ringtail_sig_from_session(
    session: &RingtailBridgeSession,
) -> Result<Vec<u8>, RingtailError> {
    use seal_threshold::ringtail::aggregate_responses_full;
    let ring = HandRolledOps::new();
    let aggregated_d_bytes = session
        .aggregated_d_bytes
        .as_ref()
        .expect("aggregated_d_bytes guarded by call-site check");
    let sig = aggregate_responses_full(
        &ring,
        aggregated_d_bytes,
        &session.round2_msgs,
        &session.payload,
        session.threshold,
        session.committee_size,
    )
    .map_err(RingtailError::Sign)?;
    crate::ringtail::encode_signature(&sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ringtail::{generate_singleton_keymaterial, RINGTAIL_SIG_BYTES};
    use seal_ringtail_verify::{
        ntt::NttCtx,
        verify::{PublicParams as BpfParams, Signature as BpfSig},
    };
    use seal_threshold::ntt::HandRolledOps;
    use seal_threshold::ringtail::{
        PublicParams as HostParams, RingOps as _, RingtailParty, MODULE_K, MODULE_L,
    };

    /// End-to-end: drive a 2-of-2 session through round1 → round2 →
    /// final signature, then verify the produced wire bytes via the
    /// BPF verifier with the cached payload.
    #[test]
    fn session_two_of_two_drives_round_trip() {
        let ring = HandRolledOps::new();
        let sk = ring.sample_gaussian(6.108);
        let two_sk = ring.add(&sk, &sk);

        // Build params with t = A·(2·sk).
        let mut matrix_a_col0 = Vec::with_capacity(MODULE_K);
        let mut matrix_a_bytes: Vec<Vec<Vec<u8>>> = Vec::with_capacity(MODULE_K);
        for _ in 0..MODULE_K {
            let col0 = ring.sample_uniform();
            let mut row = Vec::with_capacity(MODULE_L);
            row.push(ring.to_bytes(&col0));
            for _ in 1..MODULE_L {
                row.push(ring.to_bytes(&ring.sample_uniform()));
            }
            matrix_a_col0.push(col0);
            matrix_a_bytes.push(row);
        }
        let public_key_t_bytes: Vec<Vec<u8>> = matrix_a_col0
            .iter()
            .map(|a| ring.to_bytes(&ring.mul(a, &two_sk)))
            .collect();
        let params = HostParams {
            matrix_a: matrix_a_bytes,
            public_key_t: public_key_t_bytes,
        };

        let mut p0 = RingtailParty::new(0, sk.clone(), HandRolledOps::new());
        let mut p1 = RingtailParty::new(1, sk.clone(), HandRolledOps::new());

        let dest = "11111111111111111111111111111111";
        let amount = 4242u64;
        let nonce = 99u64;

        let mut session = RingtailBridgeSession::new(
            "wd_sol_99".into(),
            Chain::Solana,
            dest,
            amount,
            nonce,
            2,
            2,
        );

        // Each validator runs round1 against the same params + payload.
        let r1_0 = p0.round1_full(&params, b"shared-mac-key", false).unwrap();
        let r1_1 = p1.round1_full(&params, b"shared-mac-key", false).unwrap();

        // Validator 0 ingests its own + peer's round1.
        match session.ingest_round1(r1_0) {
            SessionEvent::Pending {
                collected,
                expected,
            } => {
                assert_eq!(collected, 1);
                assert_eq!(expected, 2);
            }
            e => panic!("unexpected after first round1: {e:?}"),
        }
        match session.ingest_round1(r1_1) {
            SessionEvent::Round1Complete => {}
            e => panic!("expected Round1Complete, got {e:?}"),
        }
        let aggregated_d = session
            .aggregated_d_bytes()
            .expect("aggregated_d after Round1Complete")
            .to_vec();
        let payload = session.payload().to_vec();

        // Each validator runs round2 against the aggregated D + payload.
        let r2_0 = p0.round2_full(&aggregated_d, &payload).unwrap();
        let r2_1 = p1.round2_full(&aggregated_d, &payload).unwrap();

        match session.ingest_round2(r2_0) {
            SessionEvent::Pending {
                collected,
                expected,
            } => {
                assert_eq!(collected, 1);
                assert_eq!(expected, 2);
            }
            e => panic!("unexpected after first round2: {e:?}"),
        }
        let sig_bytes = match session.ingest_round2(r2_1) {
            SessionEvent::Round2Complete { signature_bytes } => signature_bytes,
            e => panic!("expected Round2Complete, got {e:?}"),
        };
        assert_eq!(sig_bytes.len(), RINGTAIL_SIG_BYTES);

        // Subsequent ingest_* calls fast-path to AlreadyComplete.
        let r2_extra = p0.round2_full(&aggregated_d, &payload).unwrap();
        match session.ingest_round2(r2_extra) {
            SessionEvent::AlreadyComplete => {}
            e => panic!("expected AlreadyComplete, got {e:?}"),
        }

        // BPF verifier accepts the same bytes the session produced.
        use crate::ringtail::{RINGTAIL_CHALLENGE_LEN, RINGTAIL_Z_LEN};
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
            participant_count: 2,
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
            .expect("BPF verifier rejected session-driven aggregate");
    }

    #[test]
    fn duplicate_round1_party_id_dedups() {
        let ring = HandRolledOps::new();
        let sk = ring.sample_gaussian(6.108);
        let mut p0 = RingtailParty::new(0, sk.clone(), HandRolledOps::new());
        let (params, _sk_bytes) = generate_singleton_keymaterial();

        let mut session = RingtailBridgeSession::new(
            "wd_xlm_1".into(),
            Chain::Stellar,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            1,
            1,
            2, // threshold
            3, // committee size — bigger than what we'll feed
        );
        let r1 = p0.round1_full(&params, b"k", false).unwrap();
        // First ingest counts.
        match session.ingest_round1(r1.clone()) {
            SessionEvent::Pending { collected, .. } => assert_eq!(collected, 1),
            e => panic!("unexpected: {e:?}"),
        }
        // Re-ingest the same party_id is a no-op (still 1).
        match session.ingest_round1(r1) {
            SessionEvent::Pending { collected, .. } => assert_eq!(collected, 1),
            e => panic!("dedup failed: {e:?}"),
        }
    }

    #[test]
    fn round2_buffered_before_round1_completes() {
        // Validator may receive a round2 envelope before round1
        // finalizes locally (network reordering). Session buffers
        // the partial so it's available the moment round1 completes.
        // This test exercises the buffering path's dedup-by-party_id.
        let ring = HandRolledOps::new();
        let sk = ring.sample_gaussian(6.108);
        let mut p0 = RingtailParty::new(0, sk.clone(), HandRolledOps::new());
        let (params, _sk_bytes) = generate_singleton_keymaterial();
        let r1 = p0.round1_full(&params, b"k", false).unwrap();
        let aggregated = aggregate_commitments(&ring, &[r1.clone()]).unwrap();
        let r2 = p0.round2_full(&aggregated, b"payload").unwrap();

        let mut session = RingtailBridgeSession::new(
            "wd_xlm_2".into(),
            Chain::Stellar,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            1,
            1,
            1,
            2,
        );
        // Buffer a Round2 before any Round1 has landed.
        match session.ingest_round2(r2.clone()) {
            SessionEvent::Pending { collected, .. } => assert_eq!(collected, 1),
            e => panic!("expected Pending, got {e:?}"),
        }
        // Same party_id duplicate is still a no-op.
        match session.ingest_round2(r2) {
            SessionEvent::Pending { collected, .. } => assert_eq!(collected, 1),
            e => panic!("dedup failed: {e:?}"),
        }
        let (collected_r2, threshold) = session.round2_progress();
        assert_eq!(collected_r2, 1);
        assert_eq!(threshold, 1);
    }
}
