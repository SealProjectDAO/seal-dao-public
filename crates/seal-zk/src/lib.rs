//! Zero-knowledge proof generation and verification for Seal DAO.
//!
//! # Architecture
//!
//! Three backends behind the `ZkProver` / `ZkVerifier` traits:
//!
//! 1. **`StubProver`** — SHA3 commitment (32 bytes). For development/testing.
//! 2. **`RiscZeroProver`** — RISC Zero STARK proofs (~200 KB, PQ-secure).
//!    Enable with: `cargo build --features risc0`
//! 3. **`Sp1Prover`** — SP1 STARK proofs (faster, better GPU).
//!    Enable with: `cargo build --features sp1`
//!
//! # GPU Acceleration
//!
//! The `gpu` module provides multi-vendor GPU acceleration:
//! - **NVIDIA CUDA** (`gpu-cuda` feature)
//! - **AMD ROCm/HIP** (`gpu-rocm` feature)
//! - **Apple Metal** (`gpu-metal` feature)
//!
//! Use `GpuAcceleratedProver` to wrap any backend with GPU support:
//! ```ignore
//! let prover = GpuAcceleratedProver::new(RiscZeroProver::with_real_proving());
//! println!("Using: {}", prover.device());
//! ```
//!
//! Without feature flags, both backends fall back to StubProver.
//! See ZK-VM-COMPARISON.md and ZK-PROOF-ARCHITECTURE.md for details.

pub mod batch;
pub mod error;
pub mod gpu;
pub mod risc0;
pub mod risc0_guest;
pub mod sp1;
pub mod stub;
pub mod traits;

pub use batch::{BatchProver, BatchTransition, BatchVerifier};
pub use error::ZkError;
pub use gpu::{
    detect_gpus, estimate_proving_time_secs, GpuAcceleratedProver, GpuAcceleratedVerifier,
    GpuBackend, GpuConfig, GpuDevice,
};
pub use risc0::{RiscZeroProver, RiscZeroVerifier};
pub use sp1::{Sp1Prover, Sp1Verifier};
pub use stub::StubProver;
pub use traits::{StateTransition, ZkProof, ZkProver, ZkVerifier};
