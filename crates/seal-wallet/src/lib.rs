//! Multi-chain wallet for Seal DAO.
//!
//! Supports:
//! - **SEAL wallet** (ML-DSA PQC keys) — primary, post-quantum secure
//! - **Solana wallet** (Ed25519) — for bridge operations
//! - **Stellar wallet** (Ed25519) — for bridge operations
//!
//! Key derivation: single mnemonic seed → PQC key pair + Ed25519 key pair,
//! so one recovery phrase covers all chains (SPEC.md §5.4).
//!
//! All secret material zeroized on drop.

pub mod bip39;
pub mod error;
pub mod keystore;
pub mod mnemonic;
pub mod storage;
pub mod wordlist;

pub use error::WalletError;
pub use keystore::{Wallet, WalletInfo};
