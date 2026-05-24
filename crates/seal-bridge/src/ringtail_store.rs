//! On-disk persistence for in-flight Ringtail signing sessions.
//!
//! Behind the `ringtail-singleton` feature. Stores one JSON file per
//! withdrawal_id under `<data_dir>/ringtail-sessions/`. Writes are
//! atomic (write-temp + rename) so a crash mid-write can't corrupt
//! the on-disk snapshot.
//!
//! See `RingtailBridgeOrchestrator::export_session` /
//! `restore_session` for the snapshot shape. §3 of the
//! no-excuse-bordel session plan.

use crate::ringtail_orchestrator::InFlightSnapshot;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// On-disk store of orchestrator session snapshots. Owns a single
/// directory; multiple stores pointed at the same dir would race on
/// writes (don't do that). seal-node main constructs one per node
/// at boot and threads it through the receive loop + start_signing
/// task via the orchestrator wiring.
pub struct RingtailSessionStore {
    dir: PathBuf,
}

impl RingtailSessionStore {
    /// Open (and create on first call) the store directory. The
    /// directory itself must be writable by the seal-node process
    /// user; permissions for the JSON files inside follow the
    /// process umask.
    pub fn open(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Path on disk for one withdrawal's snapshot. Withdrawal IDs
    /// are alphanumeric + underscore (see
    /// `BridgeManager::initiate_withdrawal`'s `wd_<tag>_<nonce>`
    /// pattern) so no escaping is needed.
    fn path_for(&self, withdrawal_id: &str) -> PathBuf {
        self.dir.join(format!("{withdrawal_id}.json"))
    }

    /// Persist one snapshot atomically. Overwrites any prior file
    /// for the same withdrawal_id (snapshots are monotone: each
    /// ingest appends to the round1/round2 lists or sets the
    /// final_signature).
    pub fn save(&self, snapshot: &InFlightSnapshot) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(snapshot).map_err(io::Error::other)?;
        let final_path = self.path_for(&snapshot.withdrawal_id);
        let tmp_path = final_path.with_extension("json.tmp");
        fs::write(&tmp_path, &bytes)?;
        fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }

    /// Load all persisted snapshots. Returns them in directory order
    /// (which is `readdir` order — unspecified but deterministic on
    /// a given filesystem). Corrupt files (bad JSON, missing fields)
    /// are skipped with an `eprintln!` warning rather than failing
    /// the whole load so a single bad file doesn't strand the
    /// orchestrator at boot.
    pub fn load_all(&self) -> io::Result<Vec<InFlightSnapshot>> {
        let mut out = Vec::new();
        if !self.dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[ringtail-store] skipping {path:?}: {e}");
                    continue;
                }
            };
            match serde_json::from_slice::<InFlightSnapshot>(&bytes) {
                Ok(snap) => out.push(snap),
                Err(e) => {
                    eprintln!("[ringtail-store] corrupt snapshot {path:?}: {e} (skipping)");
                }
            }
        }
        Ok(out)
    }

    /// Remove the snapshot for a withdrawal_id. Called after
    /// `BridgeManager::attach_committee_signature` + the
    /// orchestrator `drop_session` so the directory doesn't grow
    /// without bound. Missing-file is a no-op (idempotent — peers
    /// racing to drop the same session shouldn't surface as an
    /// error).
    pub fn delete(&self, withdrawal_id: &str) -> io::Result<()> {
        let path = self.path_for(withdrawal_id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Borrow the store's directory — used for logging at startup.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ringtail::generate_singleton_keymaterial;
    use crate::ringtail_orchestrator::{OrchestratorConfig, RingtailBridgeOrchestrator};
    use crate::types::Chain;
    use seal_threshold::ringtail::PublicParams as HostParams;

    fn tmp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("seal-ringtail-store-test-{name}"));
        let _ = fs::remove_dir_all(&p);
        p
    }

    fn mk_orch_for_test() -> RingtailBridgeOrchestrator {
        let (params, sk) = generate_singleton_keymaterial();
        RingtailBridgeOrchestrator::new(OrchestratorConfig {
            party_id: 0,
            sk_collapsed_bytes: sk,
            public_params: HostParams {
                matrix_a: params.matrix_a,
                public_key_t: params.public_key_t,
            },
            mac_key: b"k".to_vec(),
            threshold: 1,
            committee_size: 1,
        })
        .unwrap()
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tmp_dir("save_load");
        let store = RingtailSessionStore::open(dir.clone()).unwrap();

        let mut orch = mk_orch_for_test();
        orch.start_signing(
            "wd_sol_1".into(),
            Chain::Solana,
            "11111111111111111111111111111111",
            1,
            1,
        )
        .unwrap();

        let snap = orch.export_session("wd_sol_1").expect("exists");
        store.save(&snap).expect("save");

        let loaded = store.load_all().expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].withdrawal_id, "wd_sol_1");

        store.delete("wd_sol_1").expect("delete");
        assert!(store.load_all().expect("load").is_empty());
    }

    #[test]
    fn restore_into_fresh_orchestrator() {
        let mut orch1 = mk_orch_for_test();
        orch1
            .start_signing(
                "wd_sol_42".into(),
                Chain::Solana,
                "11111111111111111111111111111111",
                42,
                42,
            )
            .unwrap();
        let snap = orch1.export_session("wd_sol_42").expect("exists");
        let bytes = serde_json::to_vec(&snap).unwrap();

        // Fresh orchestrator: simulates a process restart that just
        // loaded the same keypair file.
        let mut orch2 = mk_orch_for_test();
        let snap_back: InFlightSnapshot = serde_json::from_slice(&bytes).unwrap();
        orch2.restore_session(snap_back).expect("restore ok");
        assert_eq!(orch2.session_count(), 1);
    }

    #[test]
    fn delete_missing_is_noop() {
        let dir = tmp_dir("delete_missing");
        let store = RingtailSessionStore::open(dir).unwrap();
        // No file present; delete must not error.
        store.delete("wd_does_not_exist").expect("noop");
    }
}
