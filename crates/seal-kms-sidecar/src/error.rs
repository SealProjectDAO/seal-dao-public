use thiserror::Error;

#[derive(Debug, Error)]
pub enum KmsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] seal_crypto::CryptoError),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Node not found: {0}")]
    NodeNotFound(String),

    #[error("Node not trusted: {0}")]
    NodeNotTrusted(String),

    #[error("Node already paired: {0}")]
    NodeAlreadyPaired(String),

    #[error("Key material not loaded (not yet initialized)")]
    KeyNotInitialized,

    #[error("Circuit breaker open: too many failures")]
    CircuitBreakerOpen,

    #[error("Request timed out: {0}")]
    Timeout(String),

    #[error("Retry exhausted: {0}")]
    RetryExhausted(String),

    #[error("Challenge mismatch")]
    ChallengeMismatch,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Trust store corrupted: integrity hash mismatch")]
    TrustStoreCorrupted,
}

pub type KmsResult<T> = Result<T, KmsError>;
