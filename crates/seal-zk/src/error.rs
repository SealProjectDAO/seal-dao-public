//! ZK proof error types.

#[derive(Debug, thiserror::Error)]
pub enum ZkError {
    #[error("proof generation failed: {0}")]
    ProvingFailed(String),

    #[error("proof verification failed")]
    VerificationFailed,

    #[error("invalid state transition: {0}")]
    InvalidTransition(String),

    #[error("invalid proof format")]
    InvalidProofFormat,
}
