//! Threshold signature error types.

#[derive(Debug, thiserror::Error)]
pub enum ThresholdError {
    #[error("not enough signers: need {needed}, have {have}")]
    InsufficientSigners { needed: usize, have: usize },

    #[error("invalid partial signature from signer {0}")]
    InvalidPartialSignature(usize),

    #[error("invalid threshold signature")]
    InvalidThresholdSignature,

    #[error("duplicate signer index: {0}")]
    DuplicateSigner(usize),

    #[error("signer index out of range: {index}, max {max}")]
    SignerOutOfRange { index: usize, max: usize },
}
