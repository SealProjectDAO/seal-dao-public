//! Fuzz target: PqVrf verification should never panic on malformed proofs.
//!
//! Feeds arbitrary bytes as public keys, inputs, outputs, and proofs
//! to the ML-DSA based PqVrf. verify() must return Ok or Err — never panic.

#![no_main]
use libfuzzer_sys::fuzz_target;
use seal_vrf::pq_vrf::PqVrf;
use seal_vrf::traits::{Vrf, VrfOutput, VrfProof};

fuzz_target!(|data: &[u8]| {
    // PqVrf public key is 1952 bytes (ML-DSA-65), proof is 3309 bytes.
    // We need at least: 1952 (pk) + 32 (input) + 32 (output) = 2016 bytes
    // Proof can be whatever remains.
    if data.len() < 2016 {
        return;
    }

    let pk = &data[0..1952];
    let input = &data[1952..1984];
    let mut output_bytes = [0u8; 32];
    output_bytes.copy_from_slice(&data[1984..2016]);
    let proof_bytes = data[2016..].to_vec();

    let output = VrfOutput(output_bytes);
    let proof = VrfProof { bytes: proof_bytes };

    // This must NEVER panic
    let _ = PqVrf::verify(pk, input, &output, &proof);
});
