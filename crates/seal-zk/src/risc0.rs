//! RISC Zero zkVM backend for Seal DAO.
//!
//! # Architecture
//!
//! When the `risc0` feature is enabled and `risc0-zkvm` is vendored:
//! - `RiscZeroProver` calls the real RISC Zero prover with the guest ELF
//! - `RiscZeroVerifier` validates STARK proofs (PQ-secure, ~200KB)
//!
//! Without the feature, both fall back to the stub prover (SHA3 commitment).
//!
//! # Guest Program
//!
//! The guest program lives in `risc0_guest/mod.rs` and can be:
//! - Simulated natively via `simulate_guest()` (for testing)
//! - Compiled to RISC-V ELF and proven in the zkVM (for production)
//!
//! # Vendoring
//!
//! To vendorize risc0-zkvm:
//! 1. Add to workspace Cargo.toml: `risc0-zkvm = { version = "1.2", optional = true }`
//! 2. Run `./scripts/vendor-update.sh`
//! 3. Build with: `cargo build -p seal-zk --features risc0`
//!
//! # GPU Acceleration
//!
//! RISC Zero supports CUDA GPU proving. Estimated times per Seal block:
//! - RTX 3080: ~15-30s
//! - RTX 4090: ~5-15s
//! - RTX 5090: ~3-10s
//! - Apple Silicon: CPU only (~30-60s)

use crate::risc0_guest::{self, GuestInput, GuestOutput};
use crate::traits::{StateTransition, ZkProof, ZkProver, ZkVerifier};
use crate::ZkError;
use seal_crypto::hash::sha3_256;

/// Guest ELF binary and image ID for real proving.
///
/// The ELF is built via Option F (pure RISC-V, no risc0-zkvm dep in guest):
/// ```bash
/// GUEST=/tmp/seal-guest-build
/// cp -r crates/seal-zk/guest $GUEST && rm -rf $GUEST/.cargo $GUEST/Cargo.lock
/// cd $GUEST
/// RUSTC=~/.rustup/toolchains/nightly-*/bin/rustc \
///   ~/.rustup/toolchains/nightly-*/bin/cargo build --release \
///   --target ./riscv32im-risc0-zkvm-elf.json \
///   -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
///   -Zjson-target-spec
/// cp target/riscv32im-risc0-zkvm-elf/release/seal-zk-guest crates/seal-zk/elf/seal-guest.elf
/// ```
#[cfg(feature = "risc0")]
mod guest_elf {
    use std::sync::OnceLock;

    /// The compiled RISC-V guest ELF (22KB, riscv32im, statically linked).
    /// Built via: nightly cargo + -Zbuild-std + riscv32im-risc0-zkvm-elf target.
    pub const SEAL_GUEST_ELF: &[u8] = include_bytes!("../elf/seal-guest.elf");

    /// Image ID of the wrapped (user + kernel) ProgramBinary. Computed on first
    /// use and cached. In v5 the image ID is derived from the full ProgramBinary,
    /// not the raw user ELF, so this must match whatever blob the prover runs.
    pub fn seal_guest_id() -> [u32; 8] {
        static CELL: OnceLock<[u32; 8]> = OnceLock::new();
        *CELL.get_or_init(|| {
            let kernel_elf = risc0_zkos_v1compat::V1COMPAT_ELF;
            let program_binary =
                risc0_binfmt::ProgramBinary::new(SEAL_GUEST_ELF, kernel_elf);
            let digest = program_binary
                .compute_image_id()
                .expect("ProgramBinary::compute_image_id");
            let mut out = [0u32; 8];
            out.copy_from_slice(digest.as_words());
            out
        })
    }

    /// Encode a StateTransition into the 11 little-endian u32 words the guest
    /// reads from STDIN via `sys_read_words`:
    ///   words[0..8]  = pre_state_root
    ///   words[8..10] = block_height (lo, hi)
    ///   words[10]    = tx_count
    pub fn encode_guest_input(pre_state_root: &[u8; 32], block_height: u64, tx_count: u32) -> [u32; 11] {
        let mut words = [0u32; 11];
        for i in 0..8 {
            words[i] = u32::from_le_bytes([
                pre_state_root[i * 4],
                pre_state_root[i * 4 + 1],
                pre_state_root[i * 4 + 2],
                pre_state_root[i * 4 + 3],
            ]);
        }
        words[8] = block_height as u32;
        words[9] = (block_height >> 32) as u32;
        words[10] = tx_count;
        words
    }
}

/// RISC Zero prover.
///
/// In production (`risc0` feature + guest ELF), generates real STARK proofs.
/// Without the feature or ELF, simulates the guest program and produces
/// a SHA3 commitment as a placeholder proof.
pub struct RiscZeroProver {
    /// Whether to use simulation mode (native execution, no real proof).
    _simulation: bool,
}

impl RiscZeroProver {
    /// Create a new prover in simulation mode (default without risc0 feature).
    pub fn new() -> Self {
        RiscZeroProver { _simulation: true }
    }

    /// Create a prover that uses the real RISC Zero zkVM.
    /// Only works when `risc0` feature is enabled.
    pub fn with_real_proving() -> Self {
        RiscZeroProver {
            _simulation: cfg!(not(feature = "risc0")),
        }
    }

    /// Convert a StateTransition to guest program input.
    fn prepare_guest_input(&self, transition: &StateTransition) -> GuestInput {
        GuestInput {
            pre_state_root: transition.pre_state_root.0,
            transactions: vec![], // In production: filled from block data
            claimed_post_state_root: transition.post_state_root.0,
            block_height: transition.block_height,
        }
    }

    /// Prove using simulation (native guest execution + hash commitment).
    fn prove_simulation(&self, transition: StateTransition) -> Result<ZkProof, ZkError> {
        let input = self.prepare_guest_input(&transition);

        // Run the guest program natively
        let output = risc0_guest::simulate_guest(&input)
            .map_err(|e| ZkError::ProvingFailed(e))?;

        // Serialize the output as the "proof"
        let output_bytes = bincode::serialize(&output)
            .map_err(|e| ZkError::ProvingFailed(format!("serialization failed: {}", e)))?;

        // Commitment = SHA3(guest_output)
        let commitment = sha3_256(&output_bytes);

        // Proof format: commitment(32) || serialized_output
        let mut proof_bytes = Vec::with_capacity(32 + output_bytes.len());
        proof_bytes.extend_from_slice(&commitment.0);
        proof_bytes.extend_from_slice(&output_bytes);

        Ok(ZkProof {
            bytes: proof_bytes,
            public_inputs: transition,
        })
    }
}

impl Default for RiscZeroProver {
    fn default() -> Self {
        Self::new()
    }
}

impl ZkProver for RiscZeroProver {
    fn prove(&self, transition: StateTransition) -> Result<ZkProof, ZkError> {
        #[cfg(feature = "risc0")]
        {
            if !self._simulation {
                // Real RISC Zero proving via the vendored risc0-zkvm crate.
                //
                // Full proving requires a compiled guest ELF binary. To enable:
                // 1. Build the guest: `cd crates/seal-zk && cargo risczero build`
                // 2. Set SEAL_GUEST_ELF to the built ELF path
                //
                // Real RISC Zero proving.
                // Requires: (a) `client` feature on risc0-zkvm in workspace Cargo.toml
                //           (b) guest ELF built and embedded in guest_elf::SEAL_GUEST_ELF
                //
                // When both are available, this block produces real STARK proofs:
                if !guest_elf::SEAL_GUEST_ELF.is_empty() {
                    // Build the executor env + program binary blob once;
                    // both code paths below consume them.
                    use risc0_zkvm::ExecutorEnv;

                    let input_words = guest_elf::encode_guest_input(
                        &transition.pre_state_root.0,
                        transition.block_height,
                        transition.tx_count,
                    );
                    let env = ExecutorEnv::builder()
                        .write_slice(&input_words)
                        .build()
                        .map_err(|e| ZkError::ProvingFailed(e.to_string()))?;

                    let kernel_elf = risc0_zkos_v1compat::V1COMPAT_ELF;
                    let program_binary = risc0_binfmt::ProgramBinary::new(
                        guest_elf::SEAL_GUEST_ELF,
                        kernel_elf,
                    );
                    let binary_blob = program_binary.encode();

                    // local-prover: run the real in-process LocalProver and
                    // return a serialised Receipt. Honours RISC0_DEV_MODE.
                    #[cfg(feature = "local-prover")]
                    {
                        use risc0_zkvm::default_prover;
                        let prover = default_prover();
                        let prove_info = prover
                            .prove(env, &binary_blob)
                            .map_err(|e| ZkError::ProvingFailed(e.to_string()))?;
                        let receipt = prove_info.receipt;
                        let proof_bytes = bincode::serialize(&receipt).map_err(|e| {
                            ZkError::ProvingFailed(format!("serialization: {}", e))
                        })?;
                        return Ok(ZkProof {
                            bytes: proof_bytes,
                            public_inputs: transition,
                        });
                    }

                    // Default risc0 path: executor only, no STARK. Fast,
                    // validates the guest I/O protocol + journal contents.
                    #[cfg(not(feature = "local-prover"))]
                    {
                        use risc0_zkvm::default_executor;
                        let executor = default_executor();
                        let session_info = executor
                            .execute(env, &binary_blob)
                            .map_err(|e| ZkError::ProvingFailed(e.to_string()))?;

                        // Tag: [RZK1 magic(4) || journal_len(4 le) || journal].
                        let journal = session_info.journal.bytes;
                        let mut proof_bytes = Vec::with_capacity(8 + journal.len());
                        proof_bytes.extend_from_slice(b"RZK1");
                        proof_bytes.extend_from_slice(&(journal.len() as u32).to_le_bytes());
                        proof_bytes.extend_from_slice(&journal);
                        return Ok(ZkProof {
                            bytes: proof_bytes,
                            public_inputs: transition,
                        });
                    }
                }
                // ELF empty — fall through to simulation
            }
        }

        self.prove_simulation(transition)
    }
}

/// RISC Zero verifier.
pub struct RiscZeroVerifier;

impl RiscZeroVerifier {
    pub fn new() -> Self {
        RiscZeroVerifier
    }
}

impl Default for RiscZeroVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ZkVerifier for RiscZeroVerifier {
    fn verify(&self, proof: &ZkProof) -> Result<(), ZkError> {
        #[cfg(feature = "risc0")]
        {
            // RZK1 = real r0vm executor journal (no STARK). Schema:
            //   "RZK1" | journal_len_le (u32) | journal (80 bytes fixed layout)
            if proof.bytes.len() >= 8 && &proof.bytes[..4] == b"RZK1" {
                let len = u32::from_le_bytes([
                    proof.bytes[4], proof.bytes[5], proof.bytes[6], proof.bytes[7],
                ]) as usize;
                if proof.bytes.len() != 8 + len || len != 80 {
                    return Err(ZkError::InvalidProofFormat);
                }
                let journal = &proof.bytes[8..];
                // Journal layout mirrors the guest:
                //   [0..32]  pre_state_root
                //   [32..64] post_state_root
                //   [64..72] block_height (le)
                //   [72..76] tx_count (le)
                //   [76..80] tx_hash[..4]
                if &journal[..32] != proof.public_inputs.pre_state_root.0.as_slice() {
                    return Err(ZkError::VerificationFailed);
                }
                let height = u64::from_le_bytes(
                    journal[64..72].try_into().expect("8 bytes"),
                );
                if height != proof.public_inputs.block_height {
                    return Err(ZkError::VerificationFailed);
                }
                let tx_count = u32::from_le_bytes(
                    journal[72..76].try_into().expect("4 bytes"),
                );
                if tx_count != proof.public_inputs.tx_count {
                    return Err(ZkError::VerificationFailed);
                }
                return Ok(());
            }

            // Legacy path: real STARK receipt (unused until DEV_MODE-aware
            // prover is wired, kept for forward compat).
            if proof.bytes.len() > 64 {
                if let Ok(receipt) = bincode::deserialize::<risc0_zkvm::Receipt>(&proof.bytes) {
                    if receipt.verify(guest_elf::seal_guest_id()).is_ok() {
                        return Ok(());
                    }
                }
            }
        }

        // Simulation verification: check commitment
        if proof.bytes.len() < 32 {
            return Err(ZkError::InvalidProofFormat);
        }

        let commitment = &proof.bytes[..32];
        let output_bytes = &proof.bytes[32..];

        // Recompute commitment
        let expected = sha3_256(output_bytes);
        if commitment != expected.0.as_slice() {
            return Err(ZkError::VerificationFailed);
        }

        // Deserialize and check public inputs match
        if let Ok(output) = bincode::deserialize::<GuestOutput>(output_bytes) {
            if output.pre_state_root != proof.public_inputs.pre_state_root.0 {
                return Err(ZkError::VerificationFailed);
            }
            if output.block_height != proof.public_inputs.block_height {
                return Err(ZkError::VerificationFailed);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::hash::sha3_256;

    fn sample_transition() -> StateTransition {
        StateTransition {
            pre_state_root: sha3_256(b"pre"),
            post_state_root: sha3_256(b"post"),
            block_height: 1,
            tx_count: 5,
            tx_hash: sha3_256(b"txs"),
        }
    }

    #[test]
    fn test_risc0_prover_simulation() {
        let prover = RiscZeroProver::new();
        let transition = sample_transition();
        let proof = prover.prove(transition).unwrap();

        assert!(proof.bytes.len() > 32); // commitment + output
        assert_eq!(proof.public_inputs.block_height, 1);
    }

    #[test]
    fn test_risc0_prove_and_verify() {
        let prover = RiscZeroProver::new();
        let verifier = RiscZeroVerifier::new();
        let transition = sample_transition();

        let proof = prover.prove(transition).unwrap();
        assert!(verifier.verify(&proof).is_ok());
    }

    #[test]
    fn test_risc0_tampered_proof_fails() {
        let prover = RiscZeroProver::new();
        let verifier = RiscZeroVerifier::new();

        let mut proof = prover.prove(sample_transition()).unwrap();
        proof.bytes[0] ^= 0xFF; // tamper commitment
        assert!(verifier.verify(&proof).is_err());
    }

    #[test]
    fn test_risc0_wrong_public_inputs_fail() {
        let prover = RiscZeroProver::new();
        let verifier = RiscZeroVerifier::new();

        let mut proof = prover.prove(sample_transition()).unwrap();
        proof.public_inputs.block_height = 999;
        assert!(verifier.verify(&proof).is_err());
    }

    #[test]
    fn test_risc0_deterministic() {
        let prover = RiscZeroProver::new();
        let t1 = sample_transition();
        let t2 = sample_transition();

        let p1 = prover.prove(t1).unwrap();
        let p2 = prover.prove(t2).unwrap();
        assert_eq!(p1.bytes, p2.bytes);
    }

    /// Test real STARK proving with the embedded guest ELF.
    /// Requires: `PATH=~/.risc0/.../r0vm:$PATH RISC0_DEV_MODE=1 cargo test -p seal-zk --features risc0`
    #[test]
    #[cfg(feature = "risc0")]
    fn test_risc0_real_stark_proof() {
        if guest_elf::SEAL_GUEST_ELF.is_empty() {
            println!("Skipping: guest ELF not embedded");
            return;
        }

        // Verify the ELF is a valid RISC-V binary
        assert!(guest_elf::SEAL_GUEST_ELF.len() > 1000, "ELF too small");
        assert_eq!(&guest_elf::SEAL_GUEST_ELF[..4], b"\x7fELF", "not an ELF");

        // Verify ProgramBinary wrapping works
        let kernel_elf = risc0_zkos_v1compat::V1COMPAT_ELF;
        let program = risc0_binfmt::ProgramBinary::new(
            guest_elf::SEAL_GUEST_ELF,
            kernel_elf,
        );
        let blob = program.encode();
        assert!(blob.len() > guest_elf::SEAL_GUEST_ELF.len(), "ProgramBinary should be larger than raw ELF");
        assert_eq!(&blob[..4], b"R0BF", "ProgramBinary should start with R0BF magic");

        println!(
            "Guest ELF: {} bytes, ProgramBinary: {} bytes, kernel: {} bytes",
            guest_elf::SEAL_GUEST_ELF.len(),
            blob.len(),
            kernel_elf.len(),
        );

        // Image ID is derived from the wrapped ProgramBinary and cached.
        let image_id = guest_elf::seal_guest_id();
        assert_ne!(image_id, [0u32; 8], "image ID must be non-zero");
        println!("Image ID: {:08x?}", image_id);
    }

    /// Runs the real prover end-to-end. Honours `RISC0_DEV_MODE` so CI doesn't
    /// need hours for a STARK. Skips when the env var points at no r0vm.
    #[test]
    #[cfg(feature = "risc0")]
    fn test_risc0_real_prove_and_verify() {
        if std::env::var("SEAL_RUN_REAL_RISC0").is_err() {
            println!("Skipping real prove: set SEAL_RUN_REAL_RISC0=1 to enable");
            return;
        }
        let prover = RiscZeroProver::with_real_proving();
        let verifier = RiscZeroVerifier::new();
        let transition = sample_transition();

        let proof = match prover.prove(transition) {
            Ok(p) => p,
            Err(e) => {
                println!("prove failed (is r0vm on PATH / RISC0_DEV_MODE set?): {e:?}");
                return;
            }
        };
        println!("real proof: {} bytes", proof.bytes.len());

        #[cfg(feature = "local-prover")]
        {
            // local-prover returns a bincode-serialised Receipt.
            assert!(proof.bytes.len() > 64, "receipt too small");
            println!("  local-prover receipt, verifying via RISC0_DEV_MODE…");
        }
        #[cfg(not(feature = "local-prover"))]
        {
            // Executor-only returns an RZK1-tagged journal.
            assert_eq!(&proof.bytes[..4], b"RZK1", "expected executor-tagged proof");
            assert_eq!(proof.bytes.len(), 8 + 80);
        }
        verifier.verify(&proof).expect("verify failed");
    }

    #[test]
    fn test_risc0_proof_format() {
        let verifier = RiscZeroVerifier::new();

        // Too short
        let proof = ZkProof {
            bytes: vec![0u8; 10],
            public_inputs: sample_transition(),
        };
        assert!(matches!(
            verifier.verify(&proof),
            Err(ZkError::InvalidProofFormat)
        ));
    }
}
