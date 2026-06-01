//! ZK proving benchmarks for Seal DAO.
//!
//! Measures proving and verification time for all backends (Stub, RISC Zero, SP1)
//! with GPU acceleration where available.
//!
//! Run with:
//!   cargo bench -p seal-zk
//!   cargo bench -p seal-zk -- --nocapture   # show GPU detection output
//!
//! With GPU features:
//!   cargo bench -p seal-zk --features gpu-cuda
//!   cargo bench -p seal-zk --features gpu-rocm
//!   cargo bench -p seal-zk --features gpu-metal

#![feature(test)]
extern crate test;

use seal_crypto::hash::sha3_256;
use seal_zk::gpu::{detect_gpus, estimate_proving_time_secs, GpuAcceleratedProver, GpuConfig};
use seal_zk::risc0::{RiscZeroProver, RiscZeroVerifier};
use seal_zk::sp1::{Sp1Prover, Sp1Verifier};
use seal_zk::stub::StubProver;
use seal_zk::traits::{StateTransition, ZkProver, ZkVerifier};
use seal_zk::{BatchProver, BatchTransition};
use test::Bencher;

fn sample_transition(height: u64, tx_count: u32) -> StateTransition {
    StateTransition {
        pre_state_root: sha3_256(format!("pre-{}", height).as_bytes()),
        post_state_root: sha3_256(format!("post-{}", height).as_bytes()),
        block_height: height,
        tx_count,
        tx_hash: sha3_256(format!("txs-{}", height).as_bytes()),
    }
}

// ── Stub Prover Benchmarks ──────────────────────────────────

#[bench]
fn bench_stub_prove_single(b: &mut Bencher) {
    let prover = StubProver;
    b.iter(|| {
        let t = sample_transition(1, 50);
        test::black_box(prover.prove(t).unwrap());
    });
}

#[bench]
fn bench_stub_verify_single(b: &mut Bencher) {
    let prover = StubProver;
    let proof = prover.prove(sample_transition(1, 50)).unwrap();
    let verifier = seal_zk::stub::StubVerifier;
    b.iter(|| {
        test::black_box(verifier.verify(&proof).unwrap());
    });
}

// ── RISC Zero Prover Benchmarks (Simulation Mode) ───────────

#[bench]
fn bench_risc0_prove_simulation(b: &mut Bencher) {
    let prover = RiscZeroProver::new();
    b.iter(|| {
        let t = sample_transition(1, 50);
        test::black_box(prover.prove(t).unwrap());
    });
}

#[bench]
fn bench_risc0_verify_simulation(b: &mut Bencher) {
    let prover = RiscZeroProver::new();
    let proof = prover.prove(sample_transition(1, 50)).unwrap();
    let verifier = RiscZeroVerifier::new();
    b.iter(|| {
        test::black_box(verifier.verify(&proof).unwrap());
    });
}

// ── SP1 Prover Benchmarks (Simulation Mode) ─────────────────

#[bench]
fn bench_sp1_prove_simulation(b: &mut Bencher) {
    let prover = Sp1Prover::new();
    b.iter(|| {
        let t = sample_transition(1, 50);
        test::black_box(prover.prove(t).unwrap());
    });
}

#[bench]
fn bench_sp1_verify_simulation(b: &mut Bencher) {
    let prover = Sp1Prover::new();
    let proof = prover.prove(sample_transition(1, 50)).unwrap();
    let verifier = Sp1Verifier::new();
    b.iter(|| {
        test::black_box(verifier.verify(&proof).unwrap());
    });
}

// ── GPU-Accelerated Prover Benchmarks ───────────────────────

#[bench]
fn bench_gpu_risc0_prove(b: &mut Bencher) {
    let inner = RiscZeroProver::new();
    let prover = GpuAcceleratedProver::with_config(inner, GpuConfig::default());
    eprintln!("GPU device: {}", prover.device());

    b.iter(|| {
        let t = sample_transition(1, 50);
        test::black_box(prover.prove(t).unwrap());
    });
}

#[bench]
fn bench_gpu_sp1_prove(b: &mut Bencher) {
    let inner = Sp1Prover::new();
    let prover = GpuAcceleratedProver::with_config(inner, GpuConfig::default());
    eprintln!("GPU device: {}", prover.device());

    b.iter(|| {
        let t = sample_transition(1, 50);
        test::black_box(prover.prove(t).unwrap());
    });
}

// ── Batch Proving Benchmarks ────────────────────────────────

#[bench]
fn bench_batch_prove_5_blocks(b: &mut Bencher) {
    let inner = RiscZeroProver::new();
    let batch_prover = BatchProver::new(inner);

    b.iter(|| {
        let transitions: Vec<StateTransition> = (0..5)
            .map(|i| StateTransition {
                pre_state_root: sha3_256(format!("state-{}", i).as_bytes()),
                post_state_root: sha3_256(format!("state-{}", i + 1).as_bytes()),
                block_height: i as u64,
                tx_count: 50,
                tx_hash: sha3_256(format!("txs-{}", i).as_bytes()),
            })
            .collect();
        let batch = BatchTransition::new(transitions).unwrap();
        test::black_box(batch_prover.prove_batch(&batch).unwrap());
    });
}

#[bench]
fn bench_batch_prove_20_blocks(b: &mut Bencher) {
    let inner = RiscZeroProver::new();
    let batch_prover = BatchProver::new(inner);

    b.iter(|| {
        let transitions: Vec<StateTransition> = (0..20)
            .map(|i| StateTransition {
                pre_state_root: sha3_256(format!("state-{}", i).as_bytes()),
                post_state_root: sha3_256(format!("state-{}", i + 1).as_bytes()),
                block_height: i as u64,
                tx_count: 100,
                tx_hash: sha3_256(format!("txs-{}", i).as_bytes()),
            })
            .collect();
        let batch = BatchTransition::new(transitions).unwrap();
        test::black_box(batch_prover.prove_batch(&batch).unwrap());
    });
}

// ── GPU Detection Benchmark ─────────────────────────────────

#[bench]
fn bench_gpu_detection(b: &mut Bencher) {
    b.iter(|| {
        test::black_box(detect_gpus());
    });
}

// ── Proving Time Estimation ─────────────────────────────────

#[bench]
fn bench_proving_time_estimate(b: &mut Bencher) {
    let device = GpuConfig::default().select_device();
    b.iter(|| {
        test::black_box(estimate_proving_time_secs(&device, 100));
    });
}
