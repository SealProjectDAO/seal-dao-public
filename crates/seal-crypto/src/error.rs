//! Cryptographic error types.

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("invalid ciphertext")]
    InvalidCiphertext,

    #[error("key encapsulation failed")]
    EncapsulationFailed,

    #[error("decapsulation failed")]
    DecapsulationFailed,

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}
