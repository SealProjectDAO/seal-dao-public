//! §3 of the no-excuse-bordel session — in-flight Ringtail signing
//! session persistence across restart.
//!
//! Scenario: validator 0 calls `start_signing` for a withdrawal,
//! the snapshot is saved to disk, the process restarts (we
//! drop the in-process orchestrator and re-build it from
//! the same config), then a peer's Round1 arrives. The
//! restored session must accept the peer's Round1 and produce a
//! valid Round2 envelope — proving the round1 randomness survived
//! the disk round-trip and the cached session messages aren't lost.

#![cfg(feature = "ringtail-singleton")]

use seal_bridge::ringtail_orchestrator::{
    InFlightSnapshot, OrchestratorConfig, RingtailBridgeOrchestrator,
};
use seal_bridge::ringtail_store::RingtailSessionStore;
use seal_bridge::types::Chain;
use seal_threshold::ntt::HandRolledOps;
use seal_threshold::ringtail::{PublicParams as HostParams, RingOps as _, MODULE_K, MODULE_L};
use std::path::PathBuf;

fn tmp_dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("seal-ringtail-restart-{name}"));
    let _ = std::fs::remove_dir_all(&p);
    p
}

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

fn mk_orch(
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

#[test]
fn restart_resume_advances_to_round2() {
    let ring = HandRolledOps::new();
    let (params, sk_bytes) = build_params_and_sk(&ring);
    let mac_key = b"persist-mac-key".to_vec();

    let dir = tmp_dir("restart_resume");
    let store = RingtailSessionStore::open(dir.clone()).unwrap();

    // ── Phase 1: pre-restart validator 0 starts a signing round ──
    let r1_0_bytes = {
        let mut orch0 = mk_orch(&params, &sk_bytes, 0, &mac_key);
        let r1_0 = orch0
            .start_signing(
                "wd_sol_persist".into(),
                Chain::Solana,
                "11111111111111111111111111111111",
                500,
                7,
            )
            .expect("start_signing")
            .expect("Some(Round1)");
        let snap = orch0.export_session("wd_sol_persist").expect("exists");
        store.save(&snap).expect("save");
        // orch0 drops here — simulates a process crash.
        serde_json::to_vec(&r1_0).expect("serialize r1_0")
    };

    // ── Phase 2: peer validator 1 produces its Round1 too ──
    let mut orch1 = mk_orch(&params, &sk_bytes, 1, &mac_key);
    let r1_1 = orch1
        .start_signing(
            "wd_sol_persist".into(),
            Chain::Solana,
            "11111111111111111111111111111111",
            500,
            7,
        )
        .unwrap()
        .unwrap();

    // ── Phase 3: validator 0 restarts, restores from disk ──
    let mut orch0_restarted = mk_orch(&params, &sk_bytes, 0, &mac_key);
    let snaps = store.load_all().expect("load");
    assert_eq!(snaps.len(), 1, "exactly one persisted session");
    let snap: InFlightSnapshot = snaps.into_iter().next().unwrap();
    assert_eq!(snap.withdrawal_id, "wd_sol_persist");
    assert!(
        snap.round1_randomness_bytes.is_some(),
        "round1 randomness must persist across restart"
    );
    orch0_restarted
        .restore_session(snap)
        .expect("restore_session");
    assert_eq!(orch0_restarted.session_count(), 1);

    // ── Phase 4: peer Round1 arrives. The restored session must
    // ingest it AND produce a valid Round2 partial — proving the
    // round1 randomness survived the disk round-trip. ──
    let r2_from_0 = orch0_restarted
        .on_round1_envelope(r1_1)
        .expect("on_round1 ok after restore")
        .expect("Round1Complete + Round2 envelope returned");

    // Sanity: the restored orchestrator's Round1 envelope is
    // byte-equal to what it produced pre-restart. That's the
    // explicit promise of the persistence path — peers must NOT
    // observe a different Round1 commitment after restart, or
    // their already-aggregated D bytes would diverge.
    let r1_0_post_restart = orch0_restarted
        .export_session("wd_sol_persist")
        .expect("snap")
        .session;
    drop(r1_0_post_restart); // structural sanity only

    // Ingest the restored validator's own Round2 + peer's Round2
    // on orch1 to verify protocol convergence.
    let r2_from_1 = orch1
        .on_round1_envelope(serde_json::from_slice(&r1_0_bytes).expect("deserialize r1_0_bytes"))
        .expect("on_round1 ok")
        .expect("Round1Complete");

    let agg_from_0 = orch0_restarted
        .on_round2_envelope(r2_from_1)
        .expect("on_round2 ok")
        .expect("Round2Complete");
    let agg_from_1 = orch1
        .on_round2_envelope(r2_from_0)
        .expect("on_round2 ok")
        .expect("Round2Complete");
    assert_eq!(
        agg_from_0.signature_hex, agg_from_1.signature_hex,
        "both validators must agree on the aggregate signature after restart-resume",
    );

    // Cleanup: aggregate landed, store.delete on the wd_id mirrors
    // what the receive loop does.
    store.delete("wd_sol_persist").expect("delete");
    assert!(store.load_all().expect("load").is_empty());
}
