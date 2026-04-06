//! VRF error types.

#[derive(Debug, thiserror::Error)]
pub enum VrfError {
    #[error("invalid VRF proof")]
    InvalidProof,

    #[error("invalid VRF public key")]
    InvalidPublicKey,

    #[error("invalid VRF secret key")]
    InvalidSecretKey,

    #[error("proof verification failed")]
    VerificationFailed,
}
