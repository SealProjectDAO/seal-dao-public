//! TEE error types.

#[derive(Debug, thiserror::Error)]
pub enum TeeError {
    #[error("attestation verification failed: {0}")]
    AttestationFailed(String),

    #[error("TEE node not registered: {0}")]
    NodeNotRegistered(String),

    #[error("attestation expired")]
    AttestationExpired,

    #[error("inference failed: {0}")]
    InferenceFailed(String),

    #[error("model not available: {0}")]
    ModelNotAvailable(String),
}
