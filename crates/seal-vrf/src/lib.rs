//! Post-quantum Verifiable Random Function (VRF) for Seal DAO.
//!
//! Three implementations behind the `Vrf` trait:
//!
//! 1. **`HmacVrf`** — HMAC-SHA3 stub (NOT PQ, for testing only)
//! 2. **`PqVrf`** — ML-DSA + SHA3 construction (PQ-secure, practical)
//! 3. **`LatticeVrf`** — LB-VRF placeholder (Module-LWE/SIS, future)
//!
//! **Use `PqVrf` for production.** It provides VRF properties
//! (uniqueness, pseudorandomness, verifiability) using NIST-standard
//! PQC (ML-DSA-65). Proof size: ~3.3 KB (one ML-DSA signature).

pub mod error;
pub mod hmac_vrf;
pub mod key_rotation;
pub mod lattice_vrf;
pub mod lav_vrf;
pub mod pq_vrf;
pub mod traits;

pub use error::VrfError;
pub use hmac_vrf::HmacVrf;
pub use key_rotation::{VrfBackend, VrfKeyManager};
pub use lattice_vrf::LatticeVrf;
pub use lav_vrf::LavVrf;
pub use pq_vrf::PqVrf;
pub use traits::{Vrf, VrfKeypair, VrfOutput, VrfProof};
