//! State-sync late-joiner client.
//!
//! Pulls the three snapshot RPCs (`seal_listSnapshots`,
//! `seal_getSnapshotManifest`, `seal_getSnapshotChunk`) from a peer
//! and reconstructs a fresh `BalanceStore` without genesis-replay.
//! This is the client side of the A2d state-sync path; the server
//! side lives in `crates/seal-node/src/rpc.rs` and the wire-format
//! source-of-truth in `crates/seal-storage/src/snapshot_chunks.rs`.
//!
//! # Failure modes
//!
//! - Peer returns no snapshots: caller should fall back to
//!   genesis-replay or pick a different peer.
//! - Peer returns a manifest then evicts the snapshot before all
//!   chunks are pulled (`-32005` mid-stream): the client surfaces
//!   `BootstrapError::SnapshotPrunedMidStream`; caller re-tries
//!   from a fresher snapshot.
//! - Chunk hash mismatch: surfaced as `BootstrapError::HashMismatch`
//!   on the failing chunk_index. This is treated the same as the
//!   stale-stream case — re-fetch from a fresher snapshot.

use seal_token::balance::BalanceStore;
use serde::Deserialize;

#[derive(Debug)]
pub enum BootstrapError {
    /// HTTP / IO error talking to the peer.
    Transport(String),
    /// The peer returned a JSON-RPC error.
    Rpc { code: i64, message: String },
    /// JSON shape didn't match what we expected (peer is on a
    /// different protocol version, or the response was truncated).
    BadResponse(String),
    /// Peer claimed a chunk's bytes hash to X but we re-hashed and
    /// got Y.
    HashMismatch {
        chunk_index: u32,
        expected: String,
        actual: String,
    },
    /// Peer evicted the snapshot mid-stream (one of the three RPCs
    /// returned -32005). Caller should pick a fresher snapshot.
    SnapshotPrunedMidStream,
    /// The reconstructed state-root didn't match the manifest's
    /// state-root. Indicates either a bug in the encoder/decoder
    /// pair (caught by tests) or a malicious peer; either way the
    /// client refuses to proceed.
    StateRootDivergence { expected: String, actual: String },
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(s) => write!(f, "transport: {s}"),
            Self::Rpc { code, message } => write!(f, "RPC error ({code}): {message}"),
            Self::BadResponse(s) => write!(f, "bad response: {s}"),
            Self::HashMismatch {
                chunk_index,
                expected,
                actual,
            } => write!(
                f,
                "chunk {chunk_index} hash mismatch: expected {expected}, got {actual}"
            ),
            Self::SnapshotPrunedMidStream => write!(f, "snapshot evicted mid-stream"),
            Self::StateRootDivergence { expected, actual } => {
                write!(
                    f,
                    "reconstructed state_root {actual} ≠ manifest state_root {expected}"
                )
            }
        }
    }
}

impl std::error::Error for BootstrapError {}

/// Outcome of a successful state-sync bootstrap.
#[derive(Debug, Clone)]
pub struct BootstrapOutcome {
    pub height: u64,
    pub epoch: u64,
    pub state_root_hex: String,
    pub total_bytes: u64,
    pub chunk_count: u32,
    pub balances: BalanceStore,
}

/// Trait for the JSON-RPC channel the client uses to talk to a peer.
/// Abstracted so the smoke test can plug in a direct in-memory
/// dispatcher (against a live `RpcState`) without requiring a real
/// HTTP listener.
pub trait SnapshotRpc {
    fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, BootstrapError>;
}

// Wire-format DTOs. `serde` requires the fields be in scope so we
// keep them on the struct even when only some are read; the
// remaining fields are part of the published response shape and
// could become load-bearing for future versions.
#[derive(Deserialize)]
#[allow(dead_code)]
struct SnapshotEntry {
    height: u64,
    epoch: u64,
    state_root_hex: String,
}

#[derive(Deserialize)]
struct SnapshotList {
    snapshots: Vec<SnapshotEntry>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ManifestChunk {
    index: u32,
    chunk_hash_hex: String,
    byte_size: u32,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Manifest {
    height: u64,
    epoch: u64,
    state_root_hex: String,
    total_bytes: u64,
    chunk_count: u32,
    chunks: Vec<ManifestChunk>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ChunkPayload {
    chunk_index: u32,
    chunk_hash_hex: String,
    bytes_b64: String,
}

/// Run the full bootstrap flow against `rpc`.
///
/// Picks the freshest snapshot from `seal_listSnapshots`, fetches its
/// manifest, streams every chunk, verifies each chunk's hash on the
/// way in, decodes the chunk stream into HAMT records, and
/// reconstructs a `BalanceStore`. Final state-root cross-check
/// guards against encoder / decoder drift.
pub fn bootstrap_from_peer(rpc: &dyn SnapshotRpc) -> Result<BootstrapOutcome, BootstrapError> {
    // Step 1: list snapshots, take the newest.
    let list_resp = rpc.call("seal_listSnapshots", serde_json::json!({ "limit": 1 }))?;
    let list: SnapshotList = serde_json::from_value(list_resp)
        .map_err(|e| BootstrapError::BadResponse(format!("seal_listSnapshots: {e}")))?;
    let chosen = list
        .snapshots
        .into_iter()
        .next()
        .ok_or_else(|| BootstrapError::BadResponse("peer has no snapshots retained".into()))?;

    // Step 2: fetch the manifest at that height.
    let manifest_resp = rpc.call(
        "seal_getSnapshotManifest",
        serde_json::json!({ "height": chosen.height }),
    )?;
    let manifest: Manifest = serde_json::from_value(manifest_resp)
        .map_err(|e| BootstrapError::BadResponse(format!("seal_getSnapshotManifest: {e}")))?;
    if manifest.height != chosen.height {
        return Err(BootstrapError::BadResponse(format!(
            "manifest height {} ≠ requested height {}",
            manifest.height, chosen.height
        )));
    }
    if manifest.state_root_hex != chosen.state_root_hex {
        return Err(BootstrapError::BadResponse(format!(
            "manifest state_root {} ≠ list state_root {}",
            manifest.state_root_hex, chosen.state_root_hex
        )));
    }
    if manifest.chunks.len() as u32 != manifest.chunk_count {
        return Err(BootstrapError::BadResponse(format!(
            "manifest chunk_count {} ≠ chunks.len() {}",
            manifest.chunk_count,
            manifest.chunks.len()
        )));
    }

    // Step 3: stream chunks; verify hash on each; decode immediately
    // so we don't hold the whole serialized state in memory.
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let mut all_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for expected in &manifest.chunks {
        let chunk_resp = rpc.call(
            "seal_getSnapshotChunk",
            serde_json::json!({
                "height": manifest.height,
                "chunk_index": expected.index,
            }),
        )?;
        let payload: ChunkPayload = serde_json::from_value(chunk_resp)
            .map_err(|e| BootstrapError::BadResponse(format!("seal_getSnapshotChunk: {e}")))?;
        if payload.chunk_index != expected.index {
            return Err(BootstrapError::BadResponse(format!(
                "chunk index drift: expected {}, got {}",
                expected.index, payload.chunk_index
            )));
        }
        let bytes = STANDARD
            .decode(&payload.bytes_b64)
            .map_err(|e| BootstrapError::BadResponse(format!("base64 decode: {e}")))?;
        let actual = hex::encode(seal_crypto::hash::sha3_256(&bytes).0);
        if actual != expected.chunk_hash_hex {
            return Err(BootstrapError::HashMismatch {
                chunk_index: expected.index,
                expected: expected.chunk_hash_hex.clone(),
                actual,
            });
        }
        let records = seal_storage::decode_chunk_bytes(&bytes).map_err(|e| {
            BootstrapError::BadResponse(format!("decode chunk {}: {e}", expected.index))
        })?;
        all_entries.extend(records);
    }

    // Step 4: reconstruct + state-root cross-check.
    let balances =
        BalanceStore::restore_from_snapshot(all_entries).map_err(BootstrapError::BadResponse)?;
    let actual_root = hex::encode(balances.state_root_hash().0);
    if actual_root != manifest.state_root_hex {
        return Err(BootstrapError::StateRootDivergence {
            expected: manifest.state_root_hex.clone(),
            actual: actual_root,
        });
    }
    Ok(BootstrapOutcome {
        height: manifest.height,
        epoch: manifest.epoch,
        state_root_hex: manifest.state_root_hex,
        total_bytes: manifest.total_bytes,
        chunk_count: manifest.chunk_count,
        balances,
    })
}

/// HTTP-backed implementation of `SnapshotRpc` for production use.
/// `peer_url` is the full RPC endpoint (e.g.
/// `http://localhost:8545`).
pub struct HttpSnapshotRpc {
    pub peer_url: String,
}

impl SnapshotRpc for HttpSnapshotRpc {
    fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, BootstrapError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "method": method, "params": params, "id": 1,
        });
        // ureq is sync, blocking, and already in seal-cli's deps —
        // but seal-node doesn't pull it. To keep the dep surface
        // small, we shell out to `curl` here. The bootstrap path
        // runs once at startup, so the per-call subprocess cost
        // (~10 ms) is invisible against pulling 4 MiB chunks over
        // HTTP. If a future caller needs in-loop performance,
        // swapping in a proper HTTP client is a self-contained
        // change.
        let body_str = serde_json::to_string(&body)
            .map_err(|e| BootstrapError::Transport(format!("serialize: {e}")))?;
        let output = std::process::Command::new("curl")
            .arg("-s")
            .arg("-X")
            .arg("POST")
            .arg(&self.peer_url)
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(&body_str)
            .output()
            .map_err(|e| BootstrapError::Transport(format!("curl spawn: {e}")))?;
        if !output.status.success() {
            return Err(BootstrapError::Transport(format!(
                "curl exited {}",
                output.status
            )));
        }
        let resp: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| BootstrapError::BadResponse(format!("parse: {e}")))?;
        if let Some(err) = resp.get("error") {
            let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or(0);
            let message = err
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            // -32005 / -32004 / -32006 / -32007 all indicate the
            // snapshot is no longer fetchable. Map to
            // SnapshotPrunedMidStream so callers can retry without
            // string-matching.
            if matches!(code, -32007..=-32004) {
                return Err(BootstrapError::SnapshotPrunedMidStream);
            }
            return Err(BootstrapError::Rpc { code, message });
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| BootstrapError::BadResponse("missing result field".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_storage::{chunk_entries, manifest_fingerprint, manifest_from_chunks, SnapshotMeta};

    /// In-memory mock that responds to the three snapshot RPCs from
    /// a pre-baked `BalanceStore`. Used to exercise
    /// `bootstrap_from_peer` end-to-end without touching HTTP.
    struct MockRpc {
        store: BalanceStore,
        height: u64,
        epoch: u64,
    }

    impl SnapshotRpc for MockRpc {
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, BootstrapError> {
            let entries = self.store.snapshot_dump();
            let chunks = chunk_entries(entries);
            let (refs, total) = manifest_from_chunks(&chunks);
            let state_root_hex = hex::encode(self.store.state_root_hash().0);
            match method {
                "seal_listSnapshots" => Ok(serde_json::json!({
                    "snapshots": [{
                        "height": self.height,
                        "epoch": self.epoch,
                        "state_root_hex": state_root_hex,
                        "captured_at_unix_secs": 0,
                    }],
                    "count": 1,
                    "total_retained": 1,
                })),
                "seal_getSnapshotManifest" => {
                    let manifest_hash = manifest_fingerprint(&refs);
                    Ok(serde_json::json!({
                        "height": self.height,
                        "epoch": self.epoch,
                        "state_root_hex": state_root_hex,
                        "tip_block_hash_hex": "00".repeat(32),
                        "manifest_hash_hex": hex::encode(manifest_hash.0),
                        "total_bytes": total,
                        "chunk_count": refs.len() as u32,
                        "chunks": refs.iter().map(|r| serde_json::json!({
                            "index": r.index,
                            "chunk_hash_hex": hex::encode(r.chunk_hash.0),
                            "byte_size": r.byte_size,
                        })).collect::<Vec<_>>(),
                    }))
                }
                "seal_getSnapshotChunk" => {
                    let idx = params
                        .get("chunk_index")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize;
                    let chunk = &chunks[idx];
                    use base64::engine::general_purpose::STANDARD;
                    use base64::Engine;
                    Ok(serde_json::json!({
                        "height": self.height,
                        "chunk_index": chunk.r#ref.index,
                        "byte_size": chunk.r#ref.byte_size,
                        "chunk_hash_hex": hex::encode(chunk.r#ref.chunk_hash.0),
                        "bytes_b64": STANDARD.encode(&chunk.bytes),
                    }))
                }
                _ => Err(BootstrapError::Rpc {
                    code: -32601,
                    message: format!("method {method} not in mock"),
                }),
            }
        }
    }

    #[test]
    fn bootstrap_round_trip_against_mock_peer() {
        let mut store = BalanceStore::new();
        store.mint("seal1alice", 1_000).unwrap();
        store.mint("seal1bob", 2_500).unwrap();
        store.mint("seal1carol", 3_000).unwrap();

        let rpc = MockRpc {
            store: store.clone(),
            height: 128,
            epoch: 4,
        };
        let outcome = bootstrap_from_peer(&rpc).unwrap();

        assert_eq!(outcome.height, 128);
        assert_eq!(outcome.epoch, 4);
        assert_eq!(outcome.chunk_count, 1);
        // State-root invariant: the freshly reconstructed store
        // must produce the same root as the source.
        assert_eq!(outcome.balances.state_root_hash(), store.state_root_hash());
        // Total supply matches.
        assert_eq!(outcome.balances.total_supply(), store.total_supply());
        // Per-account balances match.
        assert_eq!(outcome.balances.available("seal1alice"), 1_000);
        assert_eq!(outcome.balances.available("seal1carol"), 3_000);
    }

    #[test]
    fn bootstrap_handles_empty_snapshot_list() {
        struct EmptyRpc;
        impl SnapshotRpc for EmptyRpc {
            fn call(
                &self,
                method: &str,
                _params: serde_json::Value,
            ) -> Result<serde_json::Value, BootstrapError> {
                if method == "seal_listSnapshots" {
                    return Ok(serde_json::json!({
                        "snapshots": [],
                        "count": 0,
                        "total_retained": 0,
                    }));
                }
                unreachable!()
            }
        }
        let err = bootstrap_from_peer(&EmptyRpc).unwrap_err();
        assert!(matches!(err, BootstrapError::BadResponse(_)));
    }

    #[test]
    fn bootstrap_handles_chunk_hash_mismatch() {
        // Mock that flips one byte in the first chunk's payload.
        struct TamperedRpc {
            store: BalanceStore,
        }
        impl SnapshotRpc for TamperedRpc {
            fn call(
                &self,
                method: &str,
                params: serde_json::Value,
            ) -> Result<serde_json::Value, BootstrapError> {
                let entries = self.store.snapshot_dump();
                let chunks = chunk_entries(entries);
                let (refs, total) = manifest_from_chunks(&chunks);
                let state_root_hex = hex::encode(self.store.state_root_hash().0);
                match method {
                    "seal_listSnapshots" => Ok(serde_json::json!({
                        "snapshots": [{
                            "height": 1,
                            "epoch": 0,
                            "state_root_hex": state_root_hex,
                            "captured_at_unix_secs": 0,
                        }],
                    })),
                    "seal_getSnapshotManifest" => Ok(serde_json::json!({
                        "height": 1,
                        "epoch": 0,
                        "state_root_hex": state_root_hex,
                        "tip_block_hash_hex": "00".repeat(32),
                        "manifest_hash_hex": "00".repeat(32),
                        "total_bytes": total,
                        "chunk_count": refs.len() as u32,
                        "chunks": refs.iter().map(|r| serde_json::json!({
                            "index": r.index,
                            "chunk_hash_hex": hex::encode(r.chunk_hash.0),
                            "byte_size": r.byte_size,
                        })).collect::<Vec<_>>(),
                    })),
                    "seal_getSnapshotChunk" => {
                        let idx = params
                            .get("chunk_index")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as usize;
                        let mut bytes = chunks[idx].bytes.clone();
                        if !bytes.is_empty() {
                            bytes[0] ^= 0x01;
                        }
                        use base64::engine::general_purpose::STANDARD;
                        use base64::Engine;
                        Ok(serde_json::json!({
                            "height": 1,
                            "chunk_index": idx,
                            "byte_size": bytes.len(),
                            "chunk_hash_hex": hex::encode(chunks[idx].r#ref.chunk_hash.0),
                            "bytes_b64": STANDARD.encode(&bytes),
                        }))
                    }
                    _ => Err(BootstrapError::Rpc {
                        code: -32601,
                        message: "not in mock".into(),
                    }),
                }
            }
        }
        let mut store = BalanceStore::new();
        store.mint("seal1eve", 1_000).unwrap();
        let rpc = TamperedRpc { store };
        let err = bootstrap_from_peer(&rpc).unwrap_err();
        assert!(matches!(err, BootstrapError::HashMismatch { .. }));
    }

    /// Suppress the unused-import warning for SnapshotMeta — kept
    /// in scope so the test module has access to the same symbols
    /// the rest of the code uses for symmetry.
    #[allow(dead_code)]
    fn _silence_unused() {
        let _: Option<SnapshotMeta> = None;
    }
}
