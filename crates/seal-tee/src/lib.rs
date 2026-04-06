//! TEE attestation and AI inference coordination for Seal DAO.
//!
//! Manages Trusted Execution Environment nodes that run ML/AI inference:
//! - Attestation verification (TEE quote → on-chain proof of hardware)
//! - Inference request routing to TEE nodes
//! - Multi-vendor redundancy (Intel TDX + AMD SEV + NVIDIA CC)
//! - TEE + ZK hybrid verification
//!
//! See SPEC.md §10.6, §10.7, §14.3.

pub mod attestation;
pub mod error;
pub mod inference;

pub use attestation::{AttestationRegistry, TeeAttestation, TeeVendor};
pub use error::TeeError;
pub use inference::{InferenceRequest, InferenceResult};
