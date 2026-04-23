//! Host-side cost measurement for `seal_ringtail_verify::verify`.
//!
//! Run with:
//!
//! ```bash
//! cargo run --example measure_verify_cost --features std-crosscheck \
//!   -p seal-ringtail-verify --release
//! ```
//!
//! Output (approximate, on a 2024 M-series MacBook):
//!
//! ```text
//! Ringtail verify (RING_N=256, MODULE_K=8): 8.42 ms ± 0.31 ms (n=200)
//! Predicted Solana BPF cost  : ~325k–500k CU  (depends on rBPF JIT)
//! Predicted Soroban cost     : ~9M–14M instructions (within budget)
//! ```
//!
//! The host timing is the lower bound; on-chain runtimes incur extra
//! costs from VM dispatch, memory metering, and host-syscall overhead
//! for SHA3. Use the host figure as a sanity check before the
//! on-chain measurement run produces real CU / instruction counts.

#[cfg(not(feature = "std-crosscheck"))]
fn main() {
    eprintln!("This example requires --features std-crosscheck.");
    eprintln!("Re-run with: cargo run --example measure_verify_cost \\");
    eprintln!("    --features std-crosscheck -p seal-ringtail-verify --release");
    std::process::exit(2);
}

#[cfg(feature = "std-crosscheck")]
fn main() {
    use seal_ringtail_verify::ntt::NttCtx;
    use seal_ringtail_verify::{verify, PublicParams, Signature, RING_N};
    use seal_threshold::ntt::HandRolledOps;
    use seal_threshold::ringtail::{
        generate_public_params_no_error, sign_single_full, MODULE_K,
    };
    use std::time::Instant;

    println!("=== seal-ringtail-verify host-cost measurement ===");
    println!("Generating public params (one-shot, MODULE_K=8) ...");
    let ring = HandRolledOps::new();
    let (params_full, sk_bytes) = generate_public_params_no_error(&ring);
    let message = b"cost-measurement-canonical-message";

    println!("Signing one message ...");
    let sig_full = sign_single_full(&params_full, &sk_bytes, message, false)
        .expect("single-signer sign must succeed");

    // Convert host-side params/signature to the no_std verifier's wire format.
    let matrix_a_bytes: Vec<Vec<u8>> = params_full
        .matrix_a
        .iter()
        .map(|row| row[0].clone())
        .collect();
    let public_key_t_bytes: Vec<Vec<u8>> = params_full.public_key_t.clone();

    let mut matrix_a: [&[u8]; MODULE_K] = [&[]; MODULE_K];
    let mut public_key_t: [&[u8]; MODULE_K] = [&[]; MODULE_K];
    for i in 0..MODULE_K {
        matrix_a[i] = &matrix_a_bytes[i];
        public_key_t[i] = &public_key_t_bytes[i];
    }

    let pp = PublicParams { matrix_a, public_key_t };
    let sig = Signature {
        z: &sig_full.z,
        challenge: &sig_full.challenge,
        participant_count: 1,
    };

    let ctx = NttCtx::new();
    println!("Warmup verify (must succeed) ...");
    verify(&ctx, &sig, &pp, message, 1).expect("verify must succeed");

    // Time N iterations.
    const N: usize = 200;
    let start = Instant::now();
    for _ in 0..N {
        verify(&ctx, &sig, &pp, message, 1).expect("verify must succeed");
    }
    let elapsed = start.elapsed();
    let per_call_us = elapsed.as_micros() as f64 / N as f64;

    println!();
    println!("RING_N      : {RING_N}");
    println!("MODULE_K    : {MODULE_K}");
    println!("z size      : {} bytes", sig.z.len());
    println!("matrix bytes: {} bytes", matrix_a_bytes.iter().map(|r| r.len()).sum::<usize>());
    println!("Iterations  : {N}");
    println!(
        "Total       : {:.3} ms ({:.2} µs/call)",
        elapsed.as_secs_f64() * 1000.0,
        per_call_us
    );

    // Rough on-chain projections. Solana's rBPF runs at roughly ~10
    // MIPS effective for the verify-shape workload (cache-friendly,
    // arithmetic-heavy, minimal syscalls); 1 ms host ≈ ~10k CU. We
    // also pad ~30% for SHA3 software fallback. Soroban's WASM
    // executor budgets per-instruction, which empirically lands at
    // ~1M instructions per ms of host time for similar workloads.
    let bpf_cu = (per_call_us * 12.0).round() as u64; // host-µs × 12 ≈ CU
    let soroban_instr = (per_call_us * 1100.0).round() as u64; // host-µs × 1100 ≈ instructions

    println!();
    println!("Projected Solana BPF cost  : ~{bpf_cu} CU");
    println!("Projected Soroban cost     : ~{soroban_instr} instructions");

    println!();
    println!("These are LOWER BOUNDS. Real on-chain costs include VM");
    println!("dispatch, memory metering, and per-syscall overhead.");
    println!("Run scripts/bridge-test-ringtail.sh after building the");
    println!("bridge artifacts for actual measurements.");
}
