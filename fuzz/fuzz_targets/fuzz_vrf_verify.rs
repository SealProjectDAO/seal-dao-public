//! Fuzz target: VRF verification should never panic on malformed proofs.
//!
//! Feeds arbitrary bytes as public keys, inputs, outputs, and proofs.
//! verify() must return Ok or Err — never panic.

#![no_main]
use libfuzzer_sys::fuzz_target;
use seal_vrf::traits::{Vrf, VrfOutput, VrfProof};
use seal_vrf::hmac_vrf::HmacVrf;

fuzz_target!(|data: &[u8]| {
    if data.len() < 96 {
        return;
    }

    // Split arbitrary bytes into components
    let pk = &data[0..32];
    let input = &data[32..64];
    let mut output_bytes = [0u8; 32];
    output_bytes.copy_from_slice(&data[64..96]);
    let proof_bytes = data[96..].to_vec();

    let output = VrfOutput(output_bytes);
    let proof = VrfProof { bytes: proof_bytes };

    // This must NEVER panic
    let _ = HmacVrf::verify(pk, input, &output, &proof);
});
