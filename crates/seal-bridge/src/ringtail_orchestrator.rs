//! Per-validator Ringtail signing orchestrator.
//!
//! Behind the `ringtail-singleton` feature. Owns one validator's
//! signing state across all in-flight bridge withdrawals: per-
//! withdrawal `RingtailParty` instances + matching
//! `RingtailBridgeSession` trackers, plus the local validator's
//! signing material (sk + party_id + public_params + mac_key).
//!
//! # Driver responsibility
//!
//! The orchestrator exposes message-handler methods that return
//! `Option<envelope>` — the caller (seal-node integration layer) is
//! responsible for actually broadcasting the returned envelopes via
//! seal-p2p gossipsub. This keeps the orchestrator testable in
//! isolation and lets the integration layer choose its own broadcast
//! transport (gossipsub today; could be unicast or a custom request-
//! response protocol later).
//!
//! # Lifecycle
//!
//! 1. `start_signing(withdrawal)` is called once per new pending
//!    withdrawal. It creates the per-withdrawal session, runs the
//!    local Round1 protocol step, returns the envelope to broadcast.
//! 2. `on_round1_envelope(env)` is called for every received Round1
//!    envelope (peer or own — dedup is in the session). Returns
//!    `Some(round2_envelope)` once the local validator has enough
//!    Round1s to compute its own Round2 partial.
//! 3. `on_round2_envelope(env)` is called for every received Round2
//!    envelope. Returns `Some(aggregate_envelope)` once threshold
//!    partials have landed; the integration layer also calls
//!    `BridgeManager::attach_committee_signature` with the same
//!    bytes.
//!
//! # What's NOT here yet
//!
//! - Session timeouts / cleanup of stale withdrawals.
//! - On-receive verification of Round1 commitment MAC (the threshold
//!   crate already includes a per-signer MAC; we should verify it
//!   here before ingesting peer messages so a malicious peer can't
//!   inject garbage that wedges aggregation later).
//! - Persistence — sessions live in memory. Restarts lose progress;
//!   peers will re-broadcast and the protocol resumes.

#[cfg(test)]
use crate::ringtail::Round2Message;
use crate::ringtail::{
    BridgeRingtailAggregateEnvelope, BridgeRingtailRound1Envelope, BridgeRingtailRound2Envelope,
};
use crate::ringtail_session::{RingtailBridgeSession, SessionEvent};
use crate::types::Chain;
use seal_threshold::ntt::{compute_mac, HandRolledOps};
use seal_threshold::ringtail::{PublicParams as HostParams, RingOps, RingtailParty};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// On-disk snapshot of one in-flight session (P1#5 layer 4
/// restart-resume — §3 of the no-excuse-bordel plan). Pairs the
/// fully serializable `RingtailBridgeSession` with the only mutable
/// secret state in `RingtailParty`: the Round1 randomness
/// polynomial. Everything else needed to rebuild the orchestrator
/// (sk, public params, mac_key, party_id, threshold, committee_size)
/// is in `OrchestratorConfig`, which the operator loads from disk
/// at boot anyway.
///
/// **Secrecy note**: the `round1_randomness_bytes` field carries
/// the same secret weight as the validator's sk during an in-flight
/// session — a leak lets an attacker derive a valid Round2 partial
/// for that session. The default disk store writes it in plain
/// (testnet acceptable, mainnet must wire through a KMS — see
/// `seal-bridge::keysource` per P8/§4.4 of the plan).
#[derive(Clone, Serialize, Deserialize)]
pub struct InFlightSnapshot {
    pub withdrawal_id: String,
    pub session: RingtailBridgeSession,
    pub round1_randomness_bytes: Option<Vec<u8>>,
}

/// Configuration installed at orchestrator construction. Shared
/// across all in-flight sessions for this validator.
pub struct OrchestratorConfig {
    /// 0-based party id. Must match the index seal-consensus uses
    /// for this validator in the active validator set so other
    /// peers' Round1 messages from the same party_id dedup correctly.
    pub party_id: usize,
    /// Validator's secret-share polynomial bytes. Pinned for the
    /// lifetime of the orchestrator; rotation = re-construct.
    pub sk_collapsed_bytes: Vec<u8>,
    /// Ringtail public params (deploy artifact installed alongside
    /// the on-chain bridge program at the same epoch).
    pub public_params: HostParams,
    /// MAC key for Round1 commitment authentication. Distinct from
    /// the bridge committee MAC key — this one secures the per-
    /// signer commitment binding.
    pub mac_key: Vec<u8>,
    /// Minimum signers required for the aggregate to be valid.
    pub threshold: usize,
    /// Total signer count. Both the threshold + this number ride
    /// the validator-set size; rotation = re-construct.
    pub committee_size: usize,
}

struct InFlight {
    party: RingtailParty<HandRolledOps>,
    session: RingtailBridgeSession,
    /// Bumped on every successful ingest_*. Used by `prune_stale`
    /// to drop sessions that have been idle longer than the
    /// configured limit (signing protocol got abandoned, peer set
    /// rotated, etc.).
    last_activity: Instant,
}

pub struct RingtailBridgeOrchestrator {
    config: OrchestratorConfig,
    sessions: HashMap<String, InFlight>,
}

impl RingtailBridgeOrchestrator {
    pub fn new(config: OrchestratorConfig) -> Result<Self, String> {
        if config.threshold == 0 {
            return Err("threshold must be > 0".into());
        }
        if config.threshold > config.committee_size {
            return Err(format!(
                "threshold {} > committee_size {}",
                config.threshold, config.committee_size
            ));
        }
        Ok(Self {
            config,
            sessions: HashMap::new(),
        })
    }

    /// Begin signing for a new withdrawal. Idempotent: if a session
    /// already exists for `withdrawal_id`, returns `None` rather than
    /// starting over (re-broadcasting the original Round1 envelope is
    /// the responsibility of the integration layer's keep-alive
    /// timer, not start_signing).
    pub fn start_signing(
        &mut self,
        withdrawal_id: String,
        dest_chain: Chain,
        dest_address: &str,
        amount: u64,
        nonce: u64,
    ) -> Result<Option<BridgeRingtailRound1Envelope>, String> {
        if self.sessions.contains_key(&withdrawal_id) {
            return Ok(None);
        }

        let ring = HandRolledOps::new();
        let sk_poly = ring
            .from_bytes(&self.config.sk_collapsed_bytes)
            .map_err(|_| "sk_collapsed_bytes did not decode to a polynomial".to_string())?;
        let mut party = RingtailParty::new(self.config.party_id, sk_poly, ring);

        let r1 = party
            .round1_full(&self.config.public_params, &self.config.mac_key, false)
            .map_err(|e| format!("round1_full: {e:?}"))?;

        let session = RingtailBridgeSession::new(
            withdrawal_id.clone(),
            dest_chain.clone(),
            dest_address,
            amount,
            nonce,
            self.config.threshold,
            self.config.committee_size,
        );
        let mut inflight = InFlight {
            party,
            session,
            last_activity: Instant::now(),
        };
        // Self-ingest: feed our own Round1 into the session's tracker
        // so the dedup + advance logic stays in one place. Discard
        // the SessionEvent here — the caller handles their own round1
        // via the broadcast they're about to make.
        let _ = inflight.session.ingest_round1(r1.clone());
        self.sessions.insert(withdrawal_id.clone(), inflight);

        Ok(Some(BridgeRingtailRound1Envelope {
            withdrawal_id,
            dest_chain,
            inner: r1,
        }))
    }

    /// Ingest a peer's (or own re-broadcast) Round1 envelope. Returns
    /// `Some(round2_envelope)` once Round1Complete fires, meaning the
    /// local validator computed its own Round2 partial and the
    /// integration layer should broadcast it.
    ///
    /// `Ok(None)` covers both "still waiting for more Round1s" and
    /// "session already complete" (idempotent).
    pub fn on_round1_envelope(
        &mut self,
        env: BridgeRingtailRound1Envelope,
    ) -> Result<Option<BridgeRingtailRound2Envelope>, String> {
        let inflight = match self.sessions.get_mut(&env.withdrawal_id) {
            Some(s) => s,
            None => {
                // Round1 message for an unknown withdrawal — the
                // integration layer should cross-check the
                // withdrawal_id against BridgeManager before calling
                // us; if it slips through, drop quietly.
                return Ok(None);
            }
        };
        // Verify the per-signer MAC before ingesting. A peer that
        // sends a commitment with a bad MAC either (a) has the wrong
        // mac_key (config mismatch) or (b) is malicious. Either way
        // the message gets dropped — accepting it would let an
        // attacker insert garbage into the aggregation that nukes
        // the final signature without producing a usable forgery.
        if !verify_round1_mac(&self.config.mac_key, &env.inner) {
            return Err(format!(
                "round1 MAC mismatch from party {} on {}",
                env.inner.party_id, env.withdrawal_id
            ));
        }
        let event = inflight.session.ingest_round1(env.inner);
        inflight.last_activity = Instant::now();
        match event {
            SessionEvent::Round1Complete => {
                let aggregated = inflight
                    .session
                    .aggregated_d_bytes()
                    .ok_or_else(|| "Round1Complete but no aggregated_d_bytes".to_string())?
                    .to_vec();
                let payload = inflight.session.payload().to_vec();
                let r2 = inflight
                    .party
                    .round2_full(&aggregated, &payload)
                    .map_err(|e| format!("round2_full: {e:?}"))?;
                // Self-ingest our own Round2 so it counts toward the
                // threshold. Discard the event since the caller hasn't
                // broadcast it yet — peers' Round2s will arrive
                // independently and trigger Round2Complete.
                let _ = inflight.session.ingest_round2(r2.clone());
                Ok(Some(BridgeRingtailRound2Envelope {
                    withdrawal_id: env.withdrawal_id,
                    dest_chain: env.dest_chain,
                    inner: r2,
                }))
            }
            SessionEvent::Pending { .. } | SessionEvent::AlreadyComplete => Ok(None),
            SessionEvent::Failed(e) => Err(format!("session aborted: {e}")),
            // Round2Complete on a Round1 ingest is impossible (the
            // session only flips to Round2Complete from ingest_round2)
            // — defensive None.
            SessionEvent::Round2Complete { .. } => Ok(None),
        }
    }

    /// Ingest a peer's Round2 envelope. Returns
    /// `Some(aggregate_envelope)` once threshold partials have
    /// landed; integration layer broadcasts it AND calls
    /// `BridgeManager::attach_committee_signature` with the same
    /// bytes.
    pub fn on_round2_envelope(
        &mut self,
        env: BridgeRingtailRound2Envelope,
    ) -> Result<Option<BridgeRingtailAggregateEnvelope>, String> {
        let inflight = match self.sessions.get_mut(&env.withdrawal_id) {
            Some(s) => s,
            None => return Ok(None),
        };
        let event = inflight.session.ingest_round2(env.inner);
        inflight.last_activity = Instant::now();
        match event {
            SessionEvent::Round2Complete { signature_bytes } => {
                Ok(Some(BridgeRingtailAggregateEnvelope {
                    withdrawal_id: env.withdrawal_id,
                    dest_chain: env.dest_chain,
                    signature_hex: hex::encode(signature_bytes),
                }))
            }
            SessionEvent::Pending { .. } | SessionEvent::AlreadyComplete => Ok(None),
            SessionEvent::Round1Complete => Ok(None), // out-of-order; keep waiting
            SessionEvent::Failed(e) => Err(format!("session aborted: {e}")),
        }
    }

    /// How many sessions are currently in-flight. Useful for the
    /// integration layer's metrics (gauge: in-flight signing sessions).
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Drop a completed session. Called by the integration layer
    /// after `attach_committee_signature` lands so memory doesn't
    /// grow without bound.
    pub fn drop_session(&mut self, withdrawal_id: &str) -> bool {
        self.sessions.remove(withdrawal_id).is_some()
    }

    // Helper for tests + the integration layer that wants to inspect
    // the configured mac_key without holding a reference to the
    // Config struct directly.
    #[cfg(test)]
    pub(crate) fn mac_key(&self) -> &[u8] {
        &self.config.mac_key
    }

    /// Export an in-flight session as a snapshot that can be written
    /// to disk and restored on restart via `restore_session`. Returns
    /// `None` for unknown withdrawals.
    pub fn export_session(&self, withdrawal_id: &str) -> Option<InFlightSnapshot> {
        let infl = self.sessions.get(withdrawal_id)?;
        Some(InFlightSnapshot {
            withdrawal_id: withdrawal_id.to_string(),
            session: infl.session.clone(),
            round1_randomness_bytes: infl.party.export_round1_randomness(),
        })
    }

    /// Restore an in-flight session from a previously-exported
    /// snapshot. The caller (seal-node main) holds the on-disk store
    /// and feeds every previously-persisted snapshot through this
    /// on boot, before driving the receive loop.
    ///
    /// Returns `Err` if a session for the same withdrawal_id already
    /// exists (caller should clear in-memory state first) or if the
    /// snapshot's randomness bytes don't decode against the
    /// orchestrator's ring backend (corrupt file).
    pub fn restore_session(&mut self, snapshot: InFlightSnapshot) -> Result<(), String> {
        if self.sessions.contains_key(&snapshot.withdrawal_id) {
            return Err(format!(
                "session for {} already in memory; restore must happen before start_signing",
                snapshot.withdrawal_id
            ));
        }
        let ring = HandRolledOps::new();
        let sk_poly = ring
            .from_bytes(&self.config.sk_collapsed_bytes)
            .map_err(|_| "sk_collapsed_bytes did not decode to a polynomial".to_string())?;
        let mut party = RingtailParty::new(self.config.party_id, sk_poly, ring);
        if let Some(bytes) = snapshot.round1_randomness_bytes.as_ref() {
            party
                .import_round1_randomness(bytes)
                .map_err(|e| format!("round1 randomness decode: {e}"))?;
        }
        self.sessions.insert(
            snapshot.withdrawal_id.clone(),
            InFlight {
                party,
                session: snapshot.session,
                last_activity: Instant::now(),
            },
        );
        Ok(())
    }

    /// Prune sessions that haven't seen activity in `max_idle`.
    /// Returns the dropped withdrawal_ids so the integration layer
    /// can log + alert on abandoned signing rounds. Call from a
    /// periodic timer (every minute or two is fine).
    ///
    /// Sessions that have already produced a final signature are NOT
    /// pruned by age — they wait for an explicit `drop_session` from
    /// the integration layer (so a slow attach_committee_signature
    /// retry loop doesn't lose its way).
    pub fn prune_stale_sessions(&mut self, max_idle: Duration) -> Vec<String> {
        let now = Instant::now();
        let stale: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, infl)| {
                infl.session.final_signature().is_none()
                    && now.duration_since(infl.last_activity) > max_idle
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in &stale {
            self.sessions.remove(id);
        }
        stale
    }
}

/// Verify the per-signer MAC on an incoming Round1 commitment.
/// Mirrors the input shape `RingtailParty::round1_full` uses on the
/// signer side: `(party_id.to_le_bytes() || commitment_bytes)`.
fn verify_round1_mac(mac_key: &[u8], msg: &crate::ringtail::Round1MessageFull) -> bool {
    let mut input = Vec::with_capacity(std::mem::size_of::<usize>() + msg.commitment.len());
    input.extend_from_slice(&msg.party_id.to_le_bytes());
    input.extend_from_slice(&msg.commitment);
    let computed = compute_mac(mac_key, &input);
    msg.mac.len() == 32 && msg.mac.as_slice() == computed.as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ringtail::generate_singleton_keymaterial;
    use seal_ringtail_verify::{
        ntt::NttCtx,
        verify::{PublicParams as BpfParams, Signature as BpfSig},
    };

    /// 2-validator end-to-end through TWO orchestrators: each one
    /// drives its own validator's Round1+Round2, and they exchange
    /// envelopes the same way the gossipsub layer would. Verify the
    /// final aggregate via the BPF verifier.
    #[test]
    fn two_validator_roundtrip_through_orchestrators() {
        let ring = HandRolledOps::new();

        // Build params with t = A·(2·sk) so the 2-of-2 aggregate
        // verifies. Both validators hold the same sk in this fixture
        // (matches the n_of_n cross-check pattern).
        let sk = ring.sample_gaussian(6.108);
        let two_sk = ring.add(&sk, &sk);

        use seal_threshold::ringtail::{MODULE_K, MODULE_L};
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
        let sk_bytes = ring.to_bytes(&sk);

        let mk_orch = |party_id: usize| {
            RingtailBridgeOrchestrator::new(OrchestratorConfig {
                party_id,
                sk_collapsed_bytes: sk_bytes.clone(),
                public_params: HostParams {
                    matrix_a: params.matrix_a.clone(),
                    public_key_t: params.public_key_t.clone(),
                },
                mac_key: b"shared-mac-key".to_vec(),
                threshold: 2,
                committee_size: 2,
            })
            .unwrap()
        };
        let mut orch0 = mk_orch(0);
        let mut orch1 = mk_orch(1);

        let dest = "11111111111111111111111111111111";
        let amount = 4242u64;
        let nonce = 99u64;

        // Both validators start signing for the same withdrawal.
        let r1_0 = orch0
            .start_signing("wd_sol_99".into(), Chain::Solana, dest, amount, nonce)
            .unwrap()
            .unwrap();
        let r1_1 = orch1
            .start_signing("wd_sol_99".into(), Chain::Solana, dest, amount, nonce)
            .unwrap()
            .unwrap();

        // start_signing is idempotent — second call returns None.
        assert!(orch0
            .start_signing("wd_sol_99".into(), Chain::Solana, dest, amount, nonce)
            .unwrap()
            .is_none());

        // Validators exchange Round1 envelopes. Each ingest of a peer
        // round1 may trigger Round2 once Round1 quorum is hit.
        let r2_from_0 = orch0
            .on_round1_envelope(r1_1.clone())
            .unwrap()
            .expect("orch0 produces Round2 after seeing peer's Round1");
        let r2_from_1 = orch1
            .on_round1_envelope(r1_0.clone())
            .unwrap()
            .expect("orch1 produces Round2 after seeing peer's Round1");

        // Each validator now sees the peer's Round2 — orch0 should
        // produce the aggregate envelope.
        let agg_from_0 = orch0
            .on_round2_envelope(r2_from_1.clone())
            .unwrap()
            .expect("orch0 aggregates after seeing peer's Round2");
        // Symmetrically orch1 also aggregates.
        let agg_from_1 = orch1
            .on_round2_envelope(r2_from_0.clone())
            .unwrap()
            .expect("orch1 aggregates after seeing peer's Round2");

        assert_eq!(
            agg_from_0.signature_hex, agg_from_1.signature_hex,
            "both validators must arrive at the same aggregate signature (deterministic)"
        );

        // Verify the wire bytes via the BPF verifier.
        use crate::ringtail::{
            build_unlock_payload, RINGTAIL_CHALLENGE_LEN, RINGTAIL_SIG_BYTES, RINGTAIL_Z_LEN,
        };
        let sig_bytes = hex::decode(&agg_from_0.signature_hex).expect("hex decode");
        assert_eq!(sig_bytes.len(), RINGTAIL_SIG_BYTES);
        let (z, rest) = sig_bytes.split_at(RINGTAIL_Z_LEN);
        let challenge_arr: &[u8; RINGTAIL_CHALLENGE_LEN] =
            rest[..RINGTAIL_CHALLENGE_LEN].try_into().unwrap();
        let payload = build_unlock_payload(&Chain::Solana, dest, amount, nonce);
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
            .expect("BPF verifier rejected orchestrator-produced aggregate");

        // Cleanup: drop_session removes the in-flight entry.
        assert_eq!(orch0.session_count(), 1);
        assert!(orch0.drop_session("wd_sol_99"));
        assert_eq!(orch0.session_count(), 0);
        assert!(!orch0.drop_session("wd_sol_99")); // already gone
    }

    #[test]
    fn rejects_invalid_threshold_config() {
        let (params, sk) = generate_singleton_keymaterial();
        let bad = OrchestratorConfig {
            party_id: 0,
            sk_collapsed_bytes: sk.clone(),
            public_params: HostParams {
                matrix_a: params.matrix_a.clone(),
                public_key_t: params.public_key_t.clone(),
            },
            mac_key: b"k".to_vec(),
            threshold: 5,
            committee_size: 3,
        };
        assert!(RingtailBridgeOrchestrator::new(bad).is_err());

        let zero_thr = OrchestratorConfig {
            party_id: 0,
            sk_collapsed_bytes: sk,
            public_params: HostParams {
                matrix_a: params.matrix_a,
                public_key_t: params.public_key_t,
            },
            mac_key: b"k".to_vec(),
            threshold: 0,
            committee_size: 3,
        };
        assert!(RingtailBridgeOrchestrator::new(zero_thr).is_err());
    }

    #[test]
    fn prune_drops_idle_unfinished_sessions_only() {
        let (params, sk) = generate_singleton_keymaterial();
        let mut orch = RingtailBridgeOrchestrator::new(OrchestratorConfig {
            party_id: 0,
            sk_collapsed_bytes: sk.clone(),
            public_params: params,
            mac_key: b"k".to_vec(),
            threshold: 1,
            committee_size: 2, // Won't reach quorum on its own — will sit idle.
        })
        .unwrap();

        // Spin up a session that will never reach quorum (only one
        // validator's Round1 is in there).
        orch.start_signing(
            "wd_sol_1".into(),
            Chain::Solana,
            "11111111111111111111111111111111",
            1,
            1,
        )
        .unwrap()
        .unwrap();
        assert_eq!(orch.session_count(), 1);

        // Prune with a very-long max_idle — nothing should drop.
        let pruned = orch.prune_stale_sessions(Duration::from_secs(3600));
        assert!(pruned.is_empty());
        assert_eq!(orch.session_count(), 1);

        // Prune with zero max_idle — the unfinished session is now
        // older than the threshold and should drop. Sleep a tiny bit
        // so duration_since > 0 holds even on very fast hosts.
        std::thread::sleep(Duration::from_millis(2));
        let pruned = orch.prune_stale_sessions(Duration::from_millis(1));
        assert_eq!(pruned, vec!["wd_sol_1".to_string()]);
        assert_eq!(orch.session_count(), 0);
    }

    #[test]
    fn round1_envelope_with_bad_mac_is_rejected() {
        // Spin two orchestrators with DIFFERENT mac_keys — peer's
        // Round1 will carry a MAC computed with the other key, so
        // verify_round1_mac should reject + on_round1_envelope errors
        // without ingesting.
        let (params, sk) = generate_singleton_keymaterial();
        let mut orch_a = RingtailBridgeOrchestrator::new(OrchestratorConfig {
            party_id: 0,
            sk_collapsed_bytes: sk.clone(),
            public_params: HostParams {
                matrix_a: params.matrix_a.clone(),
                public_key_t: params.public_key_t.clone(),
            },
            mac_key: b"key-A".to_vec(),
            threshold: 2,
            committee_size: 2,
        })
        .unwrap();
        let mut orch_b = RingtailBridgeOrchestrator::new(OrchestratorConfig {
            party_id: 1,
            sk_collapsed_bytes: sk,
            public_params: HostParams {
                matrix_a: params.matrix_a.clone(),
                public_key_t: params.public_key_t.clone(),
            },
            mac_key: b"key-B-different".to_vec(),
            threshold: 2,
            committee_size: 2,
        })
        .unwrap();
        // Sanity: the helper used the right key wiring.
        assert_eq!(orch_a.mac_key(), b"key-A");
        assert_eq!(orch_b.mac_key(), b"key-B-different");

        // orch_b starts a session, broadcasts its Round1 (signed
        // with key-B-different).
        let r1_b = orch_b
            .start_signing(
                "wd_sol_1".into(),
                Chain::Solana,
                "11111111111111111111111111111111",
                1,
                1,
            )
            .unwrap()
            .unwrap();
        // orch_a starts a session for the same withdrawal.
        let _ = orch_a
            .start_signing(
                "wd_sol_1".into(),
                Chain::Solana,
                "11111111111111111111111111111111",
                1,
                1,
            )
            .unwrap()
            .unwrap();
        // orch_a tries to ingest orch_b's Round1 — must error on MAC.
        let err = orch_a
            .on_round1_envelope(r1_b)
            .expect_err("MAC mismatch must be rejected");
        assert!(err.contains("round1 MAC mismatch"), "err: {err}");
    }

    #[test]
    fn unknown_withdrawal_envelope_returns_none() {
        let (params, sk) = generate_singleton_keymaterial();
        let mut orch = RingtailBridgeOrchestrator::new(OrchestratorConfig {
            party_id: 0,
            sk_collapsed_bytes: sk.clone(),
            public_params: params,
            mac_key: b"k".to_vec(),
            threshold: 1,
            committee_size: 1,
        })
        .unwrap();

        // Construct a synthetic envelope for an id we never start_signing'd.
        // Round2Message has serializable shape; reuse a dummy message.
        let dummy_r2 = Round2Message {
            party_id: 99,
            response: vec![0u8; 2048],
        };
        let env = BridgeRingtailRound2Envelope {
            withdrawal_id: "wd_unknown_777".into(),
            dest_chain: Chain::Solana,
            inner: dummy_r2,
        };
        let result = orch.on_round2_envelope(env).unwrap();
        assert!(
            result.is_none(),
            "unknown withdrawal must not surface as Some(...)"
        );
    }
}
