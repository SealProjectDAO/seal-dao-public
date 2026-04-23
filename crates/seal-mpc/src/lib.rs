//! Multi-party computation (MPC) for Seal DAO.
//!
//! # Modules
//!
//! - **`spdz`** — SPDZ-style secret sharing for private aggregation over SQL.
//!   Allows computing SUM, COUNT, AVG on shared data without revealing individual
//!   values. Uses Beaver triples for multiplication.
//!
//! - **`psi`** — Private Set Intersection. Allows two parties to find common
//!   elements without revealing their full sets. Used for privacy-preserving
//!   JOIN operations on seal-sql tables.
//!
//! # Architecture
//!
//! ```text
//! Party A (holds rows R_A)        Party B (holds rows R_B)
//!   │                                │
//!   ├── SPDZ share values ───────────┤  (additive secret sharing)
//!   │                                │
//!   ├── Beaver triple: [a] [b] [c]  ─┤  (preprocessing, offline)
//!   │                                │
//!   ├── Open masked values ──────────┤  (online, no secrets revealed)
//!   │                                │
//!   └── Reconstruct aggregate ───────┘  (SUM/COUNT/AVG result)
//! ```
//!
//! All randomness uses SHA3-based PRG seeded from ML-KEM shared secrets
//! for PQ-secure random number generation.

pub mod psi;
pub mod spdz;

pub use psi::{PsiInitiator, PsiResponder, PsiResult};
pub use spdz::{SpdzError, SpdzParty, SpdzShare, SpdzTriple};

/// Errors from the MPC layer.
#[derive(Debug, thiserror::Error)]
pub enum MpcError {
    #[error("SPDZ: {0}")]
    Spdz(#[from] SpdzError),
}
