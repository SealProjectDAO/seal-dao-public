//! Trust store: persistent record of paired/authorized nodes.
//!
//! Stored as JSON on disk. Written atomically via write-to-temp-then-rename
//! pattern for crash safety.
//!
//! Integrity: every file carries a SHA3-384 content hash of its own
//! data (nodes + metadata). On load, a mismatching hash is treated as
//! a fatal error — the data was corrupted or modified after the last
//! known-good write.
//!
//! Critical invariant: `signer_index` is monotonically increasing across all
//! restarts. It is never reset or decremented, preventing duplicate Shamir
//! shares when the sidecar restarts.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_384};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use tokio::fs;

use crate::error::{KmsError, KmsResult};

/// Metadata about a paired node.
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node ID = SHA3-384(hex_encode(ML-DSA-65 verifying key)).
    pub node_id: String,
    /// Hex-encoded ML-DSA-65 verifying key (for signature verification).
    pub verifying_key_hex: String,
    /// Hex-encoded hybrid KEM public key (for key encapsulation during pairing).
    pub hybrid_pk_hex: Option<String>,
    /// Unix timestamp when the node was paired.
    pub paired_at: u64,
    /// Unix timestamp of last seen heartbeat.
    pub last_seen: u64,
    /// Whether the node has been revoked.
    pub revoked: bool,
    /// Monotonically increasing index assigned to this node for Shamir share
    /// distribution. Never reset on restart to prevent duplicate shares.
    pub bridge_signer_index: usize,
}

impl NodeInfo {
    pub fn new(node_id: String, verifying_key_hex: String, signer_index: usize) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        NodeInfo {
            node_id,
            verifying_key_hex,
            hybrid_pk_hex: None,
            paired_at: now,
            last_seen: now,
            revoked: false,
            bridge_signer_index: signer_index,
        }
    }

    /// Compute node_id from a hex-encoded ML-DSA-65 verifying key.
    pub fn compute_node_id(verifying_key_hex: &str) -> String {
        let vk_bytes = hex::decode(verifying_key_hex).unwrap_or_default();
        let hash = Sha3_384::digest(&vk_bytes);
        hex::encode(hash)
    }
}

/// Monotonic counter for signer indices. Persisted alongside node list.
#[derive(Clone, Serialize, Deserialize)]
struct IndexMetadata {
    /// Next signer index to assign. Always >= any previously assigned value.
    next_signer_index: usize,
}

/// The trust store: in-memory state backed by on-disk JSON.
///
/// All writes are atomic (temp file + rename). Reads are unlocked snapshots.
/// Integrity is verified via SHA3-384 content hashes on every load.
pub struct TrustStore {
    path: PathBuf,
    /// In-memory cache of all paired nodes, keyed by node_id.
    nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    /// Monotonic counter for signer index assignment.
    metadata: Arc<RwLock<IndexMetadata>>,
}

impl TrustStore {
    /// Load or create a trust store at the given path.
    ///
    /// If the file has an integrity hash that doesn't match the data,
    /// returns `TrustStoreCorrupted` error. Files without an integrity
    /// hash are accepted (legacy) and will be rewritten with one on next save.
    pub async fn load(path: &Path) -> KmsResult<Self> {
        let nodes = Arc::new(RwLock::new(HashMap::new()));
        let metadata = Arc::new(RwLock::new(IndexMetadata {
            next_signer_index: 0,
        }));

        if path.exists() {
            let raw = fs::read_to_string(path).await?;
            let store: TrustStoreData = serde_json::from_str(&raw)?;

            // Verify content hash if present.
            if let Some(ref integrity) = store.integrity {
                let payload_json = serialize_payload(&store.nodes, &store.metadata);
                if !verify_content_hash(&payload_json, &integrity.hash_hex) {
                    return Err(KmsError::TrustStoreCorrupted);
                }
            }

            // Recover nodes
            for (id, info) in &store.nodes {
                nodes.write().await.insert(id.clone(), info.clone());
            }

            // Recover signer index: max assigned + 1, or stored value if empty
            let max_index = store
                .nodes
                .iter()
                .map(|(_, info)| info.bridge_signer_index)
                .max()
                .unwrap_or(0);
            metadata.write().await.next_signer_index = std::cmp::max(
                store.metadata.next_signer_index,
                max_index + 1,
            );
        }

        Ok(TrustStore {
            path: path.to_path_buf(),
            nodes,
            metadata,
        })
    }

    /// Persist current state to disk atomically.
    ///
    /// Includes a SHA3-384 content hash for integrity verification on load.
    pub async fn save(&self) -> KmsResult<()> {
        let nodes = self.nodes.read().await;
        let metadata = self.metadata.read().await;

        // Serialize payload (nodes+metadata only, no integrity field)
        let payload_json = serialize_payload(&nodes, &metadata);
        let hash = compute_content_hash(&payload_json);

        let data = TrustStoreData {
            nodes: nodes.clone(),
            metadata: (*metadata).clone(),
            integrity: Some(TrustStoreIntegrity {
                hash_hex: hex::encode(hash),
            }),
        };

        // Re-serialize with integrity included
        let json = serde_json::to_string_pretty(&data)?;

        // Write to temp file, then rename for atomicity
        let tmp_path = self.path.with_extension("json.tmp");
        let mut file = tokio::fs::File::create(&tmp_path).await?;
        file.write_all(json.as_bytes()).await?;
        file.sync_all().await?;
        tokio::fs::rename(&tmp_path, &self.path).await?;

        Ok(())
    }

    /// Assign a new signer index and persist. Returns (node_id, index).
    pub async fn add_node(
        &self,
        verifying_key_hex: &str,
        _hybrid_pk_hex: Option<String>,
    ) -> KmsResult<NodeInfo> {
        let mut nodes = self.nodes.write().await;
        let mut metadata = self.metadata.write().await;

        let node_id = NodeInfo::compute_node_id(verifying_key_hex);

        if nodes.contains_key(&node_id) {
            return Err(KmsError::NodeAlreadyPaired(node_id));
        }

        let index = metadata.next_signer_index;
        metadata.next_signer_index += 1;

        let info = NodeInfo::new(node_id.clone(), verifying_key_hex.to_string(), index);
        let info_clone = info.clone();

        nodes.insert(node_id.clone(), info);

        drop(nodes);
        drop(metadata);

        self.save().await?;

        Ok(info_clone)
    }

    /// Get node info by ID.
    pub async fn get_node(&self, node_id: &str) -> KmsResult<NodeInfo> {
        let nodes = self.nodes.read().await;
        nodes
            .get(node_id)
            .cloned()
            .ok_or_else(|| KmsError::NodeNotFound(node_id.to_string()))
    }

    /// Check if a node is trusted (exists and not revoked).
    pub async fn is_trusted(&self, node_id: &str) -> bool {
        let nodes = self.nodes.read().await;
        nodes
            .get(node_id)
            .map(|info| !info.revoked)
            .unwrap_or(false)
    }

    /// Update a node's hybrid public key during pairing.
    pub async fn set_hybrid_pk(&self, node_id: &str, hybrid_pk_hex: String) -> KmsResult<()> {
        let mut nodes = self.nodes.write().await;
        let info = nodes
            .get_mut(node_id)
            .ok_or_else(|| KmsError::NodeNotFound(node_id.to_string()))?;
        info.hybrid_pk_hex = Some(hybrid_pk_hex);
        info.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        drop(nodes);
        self.save().await
    }

    /// Heartbeat: update last_seen timestamp.
    pub async fn heartbeat(&self, node_id: &str) -> KmsResult<()> {
        let mut nodes = self.nodes.write().await;
        let info = nodes
            .get_mut(node_id)
            .ok_or_else(|| KmsError::NodeNotFound(node_id.to_string()))?;
        info.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        drop(nodes);
        self.save().await
    }

    /// Revoke a node.
    pub async fn revoke_node(&self, node_id: &str) -> KmsResult<()> {
        let mut nodes = self.nodes.write().await;
        let info = nodes
            .get_mut(node_id)
            .ok_or_else(|| KmsError::NodeNotFound(node_id.to_string()))?;
        info.revoked = true;
        drop(nodes);
        self.save().await
    }

    /// List all nodes.
    pub async fn list_nodes(&self) -> Vec<NodeInfo> {
        let nodes = self.nodes.read().await;
        nodes.values().cloned().collect()
    }

    /// Get the next signer index without assigning (for Shamir reconstruction planning).
    pub async fn next_signer_index(&self) -> usize {
        self.metadata.read().await.next_signer_index
    }

    /// Verify a node's ML-DSA signature against its stored verifying key.
    pub async fn verify_node_signature(
        &self,
        node_id: &str,
        payload: &[u8],
        signature_hex: &str,
    ) -> KmsResult<bool> {
        let info = self.get_node(node_id).await?;
        let vk_bytes =
            hex::decode(&info.verifying_key_hex).map_err(|_| KmsError::InvalidRequest("bad vk".into()))?;
        let sig_bytes =
            hex::decode(signature_hex).map_err(|_| KmsError::InvalidRequest("bad sig".into()))?;

        let vk = seal_crypto::signature::VerifyingKey::from_bytes(&vk_bytes)
            .map_err(|_| KmsError::InvalidRequest("invalid verifying key".into()))?;
        let sig = seal_crypto::signature::Signature::from_bytes(sig_bytes);

        Ok(vk.verify(payload, &sig).is_ok())
    }
}

/// Serializable wrapper for the full trust store data.
#[derive(Serialize, Deserialize)]
struct TrustStoreData {
    nodes: HashMap<String, NodeInfo>,
    metadata: IndexMetadata,
    /// SHA3-384 content hash for integrity verification.
    #[serde(default)]
    integrity: Option<TrustStoreIntegrity>,
}

/// Integrity metadata embedded in each trust store file.
#[derive(Serialize, Deserialize)]
struct TrustStoreIntegrity {
    /// SHA3-384 hash over nodes+metadata JSON.
    hash_hex: String,
}

/// Serialize nodes+metadata to canonical JSON (deterministic, no integrity field).
fn serialize_payload(nodes: &HashMap<String, NodeInfo>, metadata: &IndexMetadata) -> Vec<u8> {
    let payload = TrustStorePayload { nodes, metadata };
    serde_json::to_string_pretty(&payload)
        .expect("payload serialization should never fail")
        .into_bytes()
}

/// Intermediate struct for serializing without the integrity field.
#[derive(Serialize)]
struct TrustStorePayload<'a> {
    nodes: &'a HashMap<String, NodeInfo>,
    metadata: &'a IndexMetadata,
}

/// Compute SHA3-384 hash over data.
fn compute_content_hash(data: &[u8]) -> [u8; 48] {
    let hash = Sha3_384::digest(data);
    let mut out = [0u8; 48];
    out.copy_from_slice(&hash);
    out
}

/// Verify a SHA3-384 content hash.
fn verify_content_hash(payload_json: &[u8], hash_hex: &str) -> bool {
    let hash_bytes = match hex::decode(hash_hex) {
        Ok(b) if b.len() == 48 => b,
        _ => return false,
    };
    hash_bytes == compute_content_hash(payload_json).as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn temp_store() -> (TrustStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust-store.json");
        let store = TrustStore::load(&path).await.unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn test_add_and_get_node() {
        let (store, _dir) = temp_store().await;
        let vk = "00".repeat(1952);
        let info = store.add_node(&vk, None).await.unwrap();
        assert!(!info.node_id.is_empty());
        assert_eq!(info.bridge_signer_index, 0);

        let got = store.get_node(&info.node_id).await.unwrap();
        assert_eq!(got.node_id, info.node_id);
        assert_eq!(got.bridge_signer_index, 0);
    }

    #[tokio::test]
    async fn test_duplicate_node_rejected() {
        let (store, _dir) = temp_store().await;
        let vk = "00".repeat(1952);
        store.add_node(&vk, None).await.unwrap();
        let result = store.add_node(&vk, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_monotonic_signer_index() {
        let (store, _dir) = temp_store().await;
        let vk1 = "01".repeat(1952);
        let vk2 = "02".repeat(1952);
        let vk3 = "03".repeat(1952);

        let info1 = store.add_node(&vk1, None).await.unwrap();
        let info2 = store.add_node(&vk2, None).await.unwrap();
        let info3 = store.add_node(&vk3, None).await.unwrap();

        assert_eq!(info1.bridge_signer_index, 0);
        assert_eq!(info2.bridge_signer_index, 1);
        assert_eq!(info3.bridge_signer_index, 2);
    }

    #[tokio::test]
    async fn test_persistence_across_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust-store.json");

        // Add a node
        let store1 = TrustStore::load(&path).await.unwrap();
        let vk = "00".repeat(1952);
        store1.add_node(&vk, None).await.unwrap();
        drop(store1);

        // Reload and verify
        let store2 = TrustStore::load(&path).await.unwrap();
        let info = store2.get_node(&NodeInfo::compute_node_id(&vk)).await.unwrap();
        assert_eq!(info.bridge_signer_index, 0);
        assert_eq!(store2.next_signer_index().await, 1);
    }

    #[tokio::test]
    async fn test_revocation() {
        let (store, _dir) = temp_store().await;
        let vk = "00".repeat(1952);
        let info = store.add_node(&vk, None).await.unwrap();

        assert!(store.is_trusted(&info.node_id).await);
        store.revoke_node(&info.node_id).await.unwrap();
        assert!(!store.is_trusted(&info.node_id).await);
    }

    #[tokio::test]
    async fn test_node_id_computation() {
        let vk = "ab".repeat(1952);
        let id = NodeInfo::compute_node_id(&vk);
        // SHA3-384 produces 48 bytes = 96 hex chars
        assert_eq!(id.len(), 96);
    }

    #[tokio::test]
    async fn test_hybrid_pk_update() {
        let (store, _dir) = temp_store().await;
        let vk = "00".repeat(1952);
        let info = store.add_node(&vk, None).await.unwrap();

        assert!(store.get_node(&info.node_id).await.unwrap().hybrid_pk_hex.is_none());

        let hybrid_pk = "ff".repeat(1216);
        store.set_hybrid_pk(&info.node_id, hybrid_pk.clone()).await.unwrap();
        assert_eq!(
            store.get_node(&info.node_id).await.unwrap().hybrid_pk_hex,
            Some(hybrid_pk)
        );
    }

    #[tokio::test]
    async fn test_integrity_hash_on_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust-store.json");

        // Create and save a store
        let store = TrustStore::load(&path).await.unwrap();
        let vk = "00".repeat(1952);
        store.add_node(&vk, None).await.unwrap();

        // Read the file and verify integrity field is present
        let raw = tokio::fs::read_to_string(&path).await.unwrap();
        let data: TrustStoreData = serde_json::from_str(&raw).unwrap();
        assert!(data.integrity.is_some());

        // Verify the stored hash matches the payload
        if let Some(ref integrity) = data.integrity {
            let payload_json = serialize_payload(&data.nodes, &data.metadata);
            assert!(verify_content_hash(&payload_json, &integrity.hash_hex));
        }
    }

    #[tokio::test]
    async fn test_corrupted_store_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust-store.json");

        // Create and save a store
        let store = TrustStore::load(&path).await.unwrap();
        let vk = "00".repeat(1952);
        store.add_node(&vk, None).await.unwrap();

        // Write a new file with valid JSON but a zeroed-out integrity hash
        let payload_json = serde_json::to_string_pretty(&serde_json::json!({
            "nodes": {},
            "metadata": { "next_signer_index": 1 }
        }))
        .unwrap();
        let tampered = serde_json::json!({
            "nodes": {},
            "metadata": { "next_signer_index": 1 },
            "integrity": { "hash_hex": "00".repeat(48), "algo": "hmac-sha3-384" }
        });
        tokio::fs::write(&path, tampered.to_string()).await.unwrap();

        // Reload should fail with TrustStoreCorrupted
        let result = TrustStore::load(&path).await;
        assert!(
            matches!(result, Err(KmsError::TrustStoreCorrupted)),
            "expected TrustStoreCorrupted"
        );
    }

    #[tokio::test]
    async fn test_legacy_store_accepted_upgrade_on_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust-store.json");

        // Create a file without integrity field (legacy format)
        let vk = "00".repeat(1952);
        let legacy = serde_json::json!({
            "nodes": {
                "abc123": {
                    "node_id": "abc123",
                    "verifying_key_hex": vk,
                    "hybrid_pk_hex": null,
                    "paired_at": 1000,
                    "last_seen": 1000,
                    "revoked": false,
                    "bridge_signer_index": 0
                }
            },
            "metadata": {
                "next_signer_index": 1
            }
        });
        tokio::fs::write(&path, legacy.to_string()).await.unwrap();

        // Should load successfully (no integrity field)
        let store = TrustStore::load(&path).await.unwrap();
        let info = store.get_node("abc123").await.unwrap();
        assert_eq!(info.node_id, "abc123");

        // After save, integrity field should be present
        store.save().await.unwrap();
        let raw = tokio::fs::read_to_string(&path).await.unwrap();
        let data: TrustStoreData = serde_json::from_str(&raw).unwrap();
        assert!(data.integrity.is_some());
    }

    #[tokio::test]
    async fn test_empty_store_has_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust-store.json");

        let store = TrustStore::load(&path).await.unwrap();
        store.save().await.unwrap();

        let raw = tokio::fs::read_to_string(&path).await.unwrap();
        let data: TrustStoreData = serde_json::from_str(&raw).unwrap();
        assert!(data.integrity.is_some());

        // Reload should work (integrity check passes)
        let store2 = TrustStore::load(&path).await.unwrap();
        let nodes = store2.list_nodes().await;
        assert!(nodes.is_empty());
    }
}
