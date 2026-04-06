//! Wallet error types.

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("key derivation failed: {0}")]
    DerivationFailed(String),

    #[error("wallet locked")]
    Locked,

    #[error("invalid password")]
    InvalidPassword,

    #[error("serialization error: {0}")]
    Serialization(String),
}
