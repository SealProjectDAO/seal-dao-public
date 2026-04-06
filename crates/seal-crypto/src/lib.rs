#![allow(unexpected_cfgs)] // cfg(kani) used for Kani verification harnesses
//! Post-quantum cryptographic primitives for Seal DAO.
//!
//! This crate wraps NIST-standardized PQC algorithms:
//! - **ML-DSA-65** (Dilithium) for digital signatures (FIPS 204)
//! - **ML-KEM-768** (Kyber) for key encapsulation (FIPS 203)
//! - **SHA3-256** for hashing (FIPS 202)
//!
//! All secret key material is zeroized on drop.

pub mod address;
pub mod bech32m;
pub mod error;
pub mod hash;
pub mod kem;
pub mod signature;

pub use address::SealAddress;
pub use error::CryptoError;
pub use hash::{sha3_256, Sha3Hasher};
pub use kem::{KemCiphertext, KemKeypair, KemPublicKey, KemSecretKey, KemSharedSecret};
pub use signature::{Signature, SigningKey, VerifyingKey};
