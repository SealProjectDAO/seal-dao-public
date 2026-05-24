//! P1#5 layer 4 — integration test for the seal-node Ringtail
//! signing dispatch. Validates that two orchestrators (one per
//! validator) plus two shared BridgeManagers end up with the same
//! `committee_signature_hex` attached after the full Round1 →
//! Round2 → Aggregate exchange — exactly the surface seal-node's
//! network event loop drives in production.
//!
//! This test does NOT spin up libp2p (that's §2's job, in
//! `bridge_ringtail_multi_validator_e2e.rs`). It exercises the
//! same orchestrator + BridgeManager API the network handlers in
//! `network_node.rs` call so a regression in either crate fails
//! here before it reaches docker.

#![cfg(feature = "ringtail-singleton")]

use seal_bridge::ringtail::{BridgeRingtailRound1Envelope, BridgeRingtailRound2Envelope};
use seal_bridge::ringtail_orchestrator::{OrchestratorConfig, RingtailBridgeOrchestrator};
use seal_bridge::types::Chain;
use seal_bridge::{BridgeManager, WrappedToken};
use seal_threshold::ntt::HandRolledOps;
use seal_threshold::ringtail::{PublicParams as HostParams, RingOps as _, MODULE_K, MODULE_L};

/// Build a 2-of-2 PublicParams + shared sk that matches the
/// `n_of_n` cross-check pattern (both validators hold the same
/// secret; t = A·(2·sk)). Mirrors the fixture the orchestrator
/// crate's `two_validator_roundtrip_through_orchestrators` test
/// uses so we share the same algebraic structure.
fn build_params_and_sk(ring: &HandRolledOps) -> (HostParams, Vec<u8>) {
    let sk = ring.sample_gaussian(6.108);
    let two_sk = ring.add(&sk, &sk);

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
    (
        HostParams {
            matrix_a: matrix_a_bytes,
            public_key_t: public_key_t_bytes,
        },
        ring.to_bytes(&sk),
    )
}

fn mk_orchestrator(
    params: &HostParams,
    sk_bytes: &[u8],
    party_id: usize,
    mac_key: &[u8],
) -> RingtailBridgeOrchestrator {
    RingtailBridgeOrchestrator::new(OrchestratorConfig {
        party_id,
        sk_collapsed_bytes: sk_bytes.to_vec(),
        public_params: HostParams {
            matrix_a: params.matrix_a.clone(),
            public_key_t: params.public_key_t.clone(),
        },
        mac_key: mac_key.to_vec(),
        threshold: 2,
        committee_size: 2,
    })
    .expect("orchestrator builds")
}

/// Seeds wrapped balance into a BridgeManager via the
/// deposit-confirm-process path so a downstream
/// `initiate_withdrawal` can burn against it.
fn fund_seal_wrapped(bridge: &mut BridgeManager, owner: &str, token: WrappedToken, amount: u64) {
    use seal_bridge::BridgeDeposit;
    let deposit_id = format!("dep_{owner}_{}_{amount}", token.symbol());
    bridge
        .observe_deposit(BridgeDeposit {
            id: deposit_id.clone(),
            source_chain: token.chain(),
            source_address: "src_placeholder".into(),
            source_tx_hash: "placeholder_tx".into(),
            seal_address: owner.into(),
            amount,
            token,
            confirmations: 1,
            processed: false,
        })
        .expect("observe_deposit");
    bridge
        .process_deposit(&deposit_id)
        .expect("process_deposit");
}

#[tokio::test]
async fn dispatch_round_trip_attaches_signature_to_both_bridges() {
    let ring = HandRolledOps::new();
    let (params, sk_bytes) = build_params_and_sk(&ring);
    let mac_key = b"shared-mac-key-2026".to_vec();

    // Two orchestrators (mirrors two validators) sharing sk +
    // PublicParams + mac_key — same fixture the orchestrator's own
    // two_validator_roundtrip test uses.
    let mut orch0 = mk_orchestrator(&params, &sk_bytes, 0, &mac_key);
    let mut orch1 = mk_orchestrator(&params, &sk_bytes, 1, &mac_key);

    // Two BridgeManagers (mirrors two validators' RPC state). Each
    // holds enough wrapped balance for the burn step. The committee
    // MAC is unset so initiate_withdrawal lands a withdrawal record
    // with committee_signature_hex=None — the Ringtail flow then
    // attaches the multi-validator signature after Round2Complete.
    let mut bridge0 = BridgeManager::new(1);
    let mut bridge1 = BridgeManager::new(1);
    fund_seal_wrapped(&mut bridge0, "seal1alice", WrappedToken::WSOL, 1000);
    fund_seal_wrapped(&mut bridge1, "seal1alice", WrappedToken::WSOL, 1000);

    // Burn on validator 0's bridge — this would emit a
    // WithdrawalReadyForSigning to the signing-signal channel in
    // production; here we just call start_signing directly with the
    // same fields.
    let wd_id = bridge0
        .initiate_withdrawal(
            "seal1alice",
            Chain::Solana,
            "11111111111111111111111111111111",
            WrappedToken::WSOL,
            500,
        )
        .expect("initiate withdrawal");
    assert!(
        bridge0
            .get_withdrawal(&wd_id)
            .and_then(|w| w.committee_signature_hex.clone())
            .is_none(),
        "no committee key set → withdrawal lands without a signature"
    );

    // Both validators kick off signing for the withdrawal. In
    // production the second validator gets the signal via a
    // re-emit OR via re-poll; here we simulate by calling
    // start_signing on both. Validator 1's bridge needs the
    // matching withdrawal record so attach_committee_signature has
    // something to update — replicate via initiate_withdrawal so
    // both BridgeManagers see the same wd_id.
    let wd_id_b1 = bridge1
        .initiate_withdrawal(
            "seal1alice",
            Chain::Solana,
            "11111111111111111111111111111111",
            WrappedToken::WSOL,
            500,
        )
        .expect("validator 1 initiate withdrawal");
    assert_eq!(
        wd_id, wd_id_b1,
        "withdrawal_id derivation must be deterministic across validators (chain_tag + nonce 0)"
    );

    let r1_0 = orch0
        .start_signing(
            wd_id.clone(),
            Chain::Solana,
            "11111111111111111111111111111111",
            500,
            0,
        )
        .expect("orch0 start_signing")
        .expect("Some(Round1 envelope)");
    let r1_1 = orch1
        .start_signing(
            wd_id.clone(),
            Chain::Solana,
            "11111111111111111111111111111111",
            500,
            0,
        )
        .expect("orch1 start_signing")
        .expect("Some(Round1 envelope)");

    // Round-trip the Round1 envelopes through serde — exactly what
    // the gossipsub layer does on the wire — before handing each
    // to the peer's orchestrator. Catches any drift between
    // BridgeRingtailRound1Envelope's serialize and the network
    // layer's bincode/serde_json expectations.
    let r1_0_bytes = serde_json::to_vec(&r1_0).expect("serialize r1_0");
    let r1_1_bytes = serde_json::to_vec(&r1_1).expect("serialize r1_1");
    let r1_0_back: BridgeRingtailRound1Envelope =
        serde_json::from_slice(&r1_0_bytes).expect("deserialize r1_0");
    let r1_1_back: BridgeRingtailRound1Envelope =
        serde_json::from_slice(&r1_1_bytes).expect("deserialize r1_1");

    // Exchange Round1s. Each ingest returns a Round2 envelope.
    let r2_from_0 = orch0
        .on_round1_envelope(r1_1_back)
        .expect("orch0 ingest r1_1")
        .expect("Round1Complete fires");
    let r2_from_1 = orch1
        .on_round1_envelope(r1_0_back)
        .expect("orch1 ingest r1_0")
        .expect("Round1Complete fires");

    let r2_from_0_bytes = serde_json::to_vec(&r2_from_0).expect("serialize r2_0");
    let r2_from_1_bytes = serde_json::to_vec(&r2_from_1).expect("serialize r2_1");
    let r2_from_0_back: BridgeRingtailRound2Envelope =
        serde_json::from_slice(&r2_from_0_bytes).expect("deserialize r2_0");
    let r2_from_1_back: BridgeRingtailRound2Envelope =
        serde_json::from_slice(&r2_from_1_bytes).expect("deserialize r2_1");

    // Exchange Round2s. Each ingest returns the aggregate envelope.
    let agg_from_0 = orch0
        .on_round2_envelope(r2_from_1_back)
        .expect("orch0 ingest r2_1")
        .expect("Round2Complete fires");
    let agg_from_1 = orch1
        .on_round2_envelope(r2_from_0_back)
        .expect("orch1 ingest r2_0")
        .expect("Round2Complete fires");

    assert_eq!(
        agg_from_0.signature_hex, agg_from_1.signature_hex,
        "both validators must agree on the aggregate signature"
    );

    // Attach to both BridgeManagers — the network_node Round2Complete
    // path does this on the aggregating side, and the
    // BridgeRingtailAggregate race-loser arm does it on the peer side.
    bridge0
        .attach_committee_signature(&wd_id, agg_from_0.signature_hex.clone())
        .expect("attach on bridge0");
    bridge1
        .attach_committee_signature(&wd_id, agg_from_1.signature_hex.clone())
        .expect("attach on bridge1");

    let sig0 = bridge0
        .get_withdrawal(&wd_id)
        .and_then(|w| w.committee_signature_hex.clone());
    let sig1 = bridge1
        .get_withdrawal(&wd_id)
        .and_then(|w| w.committee_signature_hex.clone());
    assert_eq!(sig0, sig1, "both bridges hold the same attached signature");
    assert!(sig0.is_some(), "attach landed a non-empty signature");

    // Orchestrators drop the session post-Round2Complete in production.
    assert!(orch0.drop_session(&wd_id));
    assert!(orch1.drop_session(&wd_id));
    assert_eq!(orch0.session_count(), 0);
    assert_eq!(orch1.session_count(), 0);
}
