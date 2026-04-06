//! TEE attestation verification and registry.
//!
//! Each TEE node registers on-chain with a hardware attestation quote.
//! The quote proves: genuine TEE hardware, specific firmware, unmodified code.
//!
//! Verification strategies (defense in depth, SPEC.md §14.3):
//! 1. Multi-vendor: same computation on Intel TDX + AMD SEV + NVIDIA CC
//! 2. TEE + ZK hybrid: ZK proof catches TEE compromise
//! 3. Continuous re-attestation (every 5 minutes)
//! 4. On-chain attestation registry (verifiable by anyone)

use seal_crypto::hash::{sha3_256, Hash256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported TEE hardware vendors.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TeeVendor {
    IntelTDX,
    IntelSGX,
    AmdSEV,
    NvidiaCC, // NVIDIA Confidential Computing (H100/H200)
}

impl std::fmt::Display for TeeVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeeVendor::IntelTDX => write!(f, "Intel TDX"),
            TeeVendor::IntelSGX => write!(f, "Intel SGX"),
            TeeVendor::AmdSEV => write!(f, "AMD SEV-SNP"),
            TeeVendor::NvidiaCC => write!(f, "NVIDIA CC"),
        }
    }
}

/// A TEE attestation quote.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeAttestation {
    /// Node ID (SEAL address of the TEE operator).
    pub node_id: String,
    /// Hardware vendor.
    pub vendor: TeeVendor,
    /// Attestation quote bytes (vendor-specific format).
    /// In production: Intel DCAP quote, AMD SEV-SNP report, NVIDIA CC attestation.
    /// For now: SHA3 hash of node_id + vendor as placeholder.
    pub quote: Vec<u8>,
    /// Timestamp of attestation (Unix seconds).
    pub timestamp: u64,
    /// Hash of the code running inside the TEE (measurement).
    pub code_hash: Hash256,
    /// Models supported by this TEE node.
    pub supported_models: Vec<String>,
}

impl TeeAttestation {
    /// Create a stub attestation for development/testing.
    pub fn stub(node_id: &str, vendor: TeeVendor, models: Vec<String>) -> Self {
        let quote_data = format!("{}:{:?}", node_id, vendor);
        let quote = sha3_256(quote_data.as_bytes()).0.to_vec();
        let code_hash = sha3_256(b"seal-tee-v0.1.0");

        TeeAttestation {
            node_id: node_id.to_string(),
            vendor,
            quote,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            code_hash,
            supported_models: models,
        }
    }

    /// Check if the attestation is still fresh (< max_age seconds old).
    pub fn is_fresh(&self, max_age_secs: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now - self.timestamp < max_age_secs
    }
}

/// On-chain registry of TEE attestations.
#[derive(Default)]
pub struct AttestationRegistry {
    /// Active attestations by node ID.
    attestations: HashMap<String, TeeAttestation>,
    /// Maximum attestation age in seconds (default: 1 hour).
    pub max_age_secs: u64,
}

impl AttestationRegistry {
    pub fn new() -> Self {
        AttestationRegistry {
            attestations: HashMap::new(),
            max_age_secs: 3600, // 1 hour
        }
    }

    /// Register or update a TEE node's attestation.
    pub fn register(&mut self, attestation: TeeAttestation) -> Result<(), crate::TeeError> {
        // In production: verify the attestation quote against vendor's root of trust.
        // For now: accept all attestations (stub).
        self.attestations
            .insert(attestation.node_id.clone(), attestation);
        Ok(())
    }

    /// Get a node's attestation.
    pub fn get(&self, node_id: &str) -> Option<&TeeAttestation> {
        self.attestations.get(node_id)
    }

    /// Check if a node has a valid (fresh) attestation.
    pub fn is_valid(&self, node_id: &str) -> bool {
        self.attestations
            .get(node_id)
            .map(|a| a.is_fresh(self.max_age_secs))
            .unwrap_or(false)
    }

    /// Get all nodes that support a given model.
    pub fn nodes_for_model(&self, model: &str) -> Vec<&TeeAttestation> {
        self.attestations
            .values()
            .filter(|a| {
                a.supported_models.iter().any(|m| m == model) && a.is_fresh(self.max_age_secs)
            })
            .collect()
    }

    /// Count of registered nodes.
    pub fn node_count(&self) -> usize {
        self.attestations.len()
    }

    /// Count of valid (fresh) nodes.
    pub fn valid_node_count(&self) -> usize {
        self.attestations
            .values()
            .filter(|a| a.is_fresh(self.max_age_secs))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_query() {
        let mut registry = AttestationRegistry::new();
        let att = TeeAttestation::stub(
            "seal1tee_node_1",
            TeeVendor::NvidiaCC,
            vec!["llama-3-8b".into(), "mistral-7b".into()],
        );
        registry.register(att).unwrap();

        assert_eq!(registry.node_count(), 1);
        assert!(registry.is_valid("seal1tee_node_1"));
        assert!(!registry.is_valid("seal1nonexistent"));
    }

    #[test]
    fn test_nodes_for_model() {
        let mut registry = AttestationRegistry::new();

        registry
            .register(TeeAttestation::stub(
                "node_a",
                TeeVendor::NvidiaCC,
                vec!["llama-3-8b".into()],
            ))
            .unwrap();
        registry
            .register(TeeAttestation::stub(
                "node_b",
                TeeVendor::AmdSEV,
                vec!["mistral-7b".into()],
            ))
            .unwrap();
        registry
            .register(TeeAttestation::stub(
                "node_c",
                TeeVendor::IntelTDX,
                vec!["llama-3-8b".into(), "mistral-7b".into()],
            ))
            .unwrap();

        let llama_nodes = registry.nodes_for_model("llama-3-8b");
        assert_eq!(llama_nodes.len(), 2); // node_a + node_c

        let mistral_nodes = registry.nodes_for_model("mistral-7b");
        assert_eq!(mistral_nodes.len(), 2); // node_b + node_c
    }

    #[test]
    fn test_multi_vendor() {
        let mut registry = AttestationRegistry::new();

        // Same operator, different TEE vendors (defense in depth)
        for vendor in [TeeVendor::IntelTDX, TeeVendor::AmdSEV, TeeVendor::NvidiaCC] {
            let id = format!("node_{:?}", vendor);
            registry
                .register(TeeAttestation::stub(&id, vendor, vec!["model-x".into()]))
                .unwrap();
        }

        assert_eq!(registry.node_count(), 3);
        assert_eq!(registry.nodes_for_model("model-x").len(), 3);
    }

    #[test]
    fn test_attestation_freshness() {
        let mut att = TeeAttestation::stub("node", TeeVendor::IntelTDX, vec![]);
        assert!(att.is_fresh(3600)); // Fresh within 1 hour

        // Simulate expired attestation
        att.timestamp = 0; // Unix epoch = very old
        assert!(!att.is_fresh(3600));
    }
}
