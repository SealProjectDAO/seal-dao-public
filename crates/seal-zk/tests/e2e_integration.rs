//! End-to-end ZK integration tests.
//!
//! These tests exercise the full proof pipeline:
//! guest program → prover → proof → verifier
//! for both RISC Zero and SP1 backends (in simulation mode).

use seal_crypto::hash::sha3_256;
use seal_zk::risc0::{RiscZeroProver, RiscZeroVerifier};
use seal_zk::risc0_guest::{self, GuestInput, GuestTransaction};
use seal_zk::sp1::{Sp1Prover, Sp1Verifier};
use seal_zk::batch::{BatchProver, BatchTransition, BatchVerifier};
use seal_zk::stub::{StubProver, StubVerifier};
use seal_zk::traits::{StateTransition, ZkProver, ZkVerifier};

fn make_transition(height: u64) -> StateTransition {
    let pre = sha3_256(&format!("state_{}", height - 1).into_bytes());
    let post = sha3_256(&format!("state_{}", height).into_bytes());
    StateTransition {
        pre_state_root: pre,
        post_state_root: post,
        block_height: height,
        tx_count: 3,
        tx_hash: sha3_256(&format!("txs_{}", height).into_bytes()),
    }
}

fn make_chain(count: usize) -> Vec<StateTransition> {
    let mut transitions = Vec::new();
    for i in 0..count {
        let pre = sha3_256(&[i as u8]);
        let post = sha3_256(&[(i + 1) as u8]);
        transitions.push(StateTransition {
            pre_state_root: pre,
            post_state_root: post,
            block_height: i as u64,
            tx_count: 3,
            tx_hash: sha3_256(&[100 + i as u8]),
        });
    }
    transitions
}

// ========================================================================
// Guest program E2E
// ========================================================================

#[test]
fn test_guest_e2e_with_transactions() {
    let input = GuestInput {
        pre_state_root: sha3_256(b"genesis").0,
        transactions: vec![
            GuestTransaction {
                tx_type: 1, // SQL exec
                payload: b"CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT)".to_vec(),
                sender_pubkey: vec![0xAA; 32],
                signature: vec![0xBB; 64],
            },
            GuestTransaction {
                tx_type: 1,
                payload: b"INSERT INTO users VALUES (1, 'alice')".to_vec(),
                sender_pubkey: vec![0xCC; 32],
                signature: vec![0xDD; 64],
            },
            GuestTransaction {
                tx_type: 1,
                payload: b"INSERT INTO users VALUES (2, 'bob')".to_vec(),
                sender_pubkey: vec![0xEE; 32],
                signature: vec![0xFF; 64],
            },
        ],
        claimed_post_state_root: [0u8; 32],
        block_height: 1,
    };

    let output = risc0_guest::simulate_guest(&input).unwrap();

    assert_eq!(output.block_height, 1);
    assert_eq!(output.tx_count, 3);
    assert_eq!(output.pre_state_root, sha3_256(b"genesis").0);
    assert_ne!(output.post_state_root, [0u8; 32]);
    assert_ne!(output.tx_hash, [0u8; 32]);
}

// ========================================================================
// Full pipeline: guest → prover → verifier
// ========================================================================

#[test]
fn test_risc0_full_pipeline() {
    let transition = make_transition(42);

    // Prove
    let prover = RiscZeroProver::new();
    let proof = prover.prove(transition.clone()).unwrap();

    // Proof should be non-trivial
    assert!(proof.bytes.len() > 32);
    assert_eq!(proof.public_inputs.block_height, 42);

    // Verify
    let verifier = RiscZeroVerifier::new();
    verifier.verify(&proof).unwrap();
}

#[test]
fn test_sp1_full_pipeline() {
    let transition = make_transition(99);

    let prover = Sp1Prover::new();
    let proof = prover.prove(transition.clone()).unwrap();

    assert!(proof.bytes.len() > 32);

    let verifier = Sp1Verifier::new();
    verifier.verify(&proof).unwrap();
}

#[test]
fn test_backend_cross_compatibility() {
    let transition = make_transition(1);

    let risc0_proof = RiscZeroProver::new().prove(transition.clone()).unwrap();
    let sp1_proof = Sp1Prover::new().prove(transition.clone()).unwrap();

    // In simulation mode, both backends produce identical proofs
    assert_eq!(risc0_proof.bytes, sp1_proof.bytes);

    // Each verifier accepts its own proof
    RiscZeroVerifier::new().verify(&risc0_proof).unwrap();
    Sp1Verifier::new().verify(&sp1_proof).unwrap();
}

// ========================================================================
// Batch proof E2E
// ========================================================================

#[test]
fn test_batch_proof_e2e() {
    let chain = make_chain(5);
    let batch = BatchTransition::new(chain).unwrap();

    // Prove with each backend
    let stub_proof = BatchProver::new(StubProver).prove_batch(&batch).unwrap();
    let risc0_proof = BatchProver::new(RiscZeroProver::new()).prove_batch(&batch).unwrap();

    // Verify
    BatchVerifier::new(StubVerifier).verify_batch(&stub_proof).unwrap();
    BatchVerifier::new(RiscZeroVerifier::new()).verify_batch(&risc0_proof).unwrap();

    // Both cover height 0-4
    assert_eq!(stub_proof.public_inputs.block_height, 0);
    assert_eq!(stub_proof.public_inputs.tx_count, 15); // 5 blocks * 3 txs
}

#[test]
fn test_batch_proof_10_blocks() {
    let chain = make_chain(10);
    let batch = BatchTransition::new(chain).unwrap();

    assert_eq!(batch.block_count(), 10);
    assert_eq!(batch.height_range().unwrap(), (0, 9));
    assert_eq!(batch.total_tx_count(), 30);

    let proof = BatchProver::new(RiscZeroProver::new()).prove_batch(&batch).unwrap();
    BatchVerifier::new(RiscZeroVerifier::new()).verify_batch(&proof).unwrap();
}

// ========================================================================
// Tamper resistance
// ========================================================================

#[test]
fn test_tampered_proof_detected() {
    let transition = make_transition(1);
    let prover = RiscZeroProver::new();
    let verifier = RiscZeroVerifier::new();

    let mut proof = prover.prove(transition).unwrap();

    // Tamper with commitment
    proof.bytes[0] ^= 0xFF;
    assert!(verifier.verify(&proof).is_err());
}

#[test]
fn test_tampered_public_inputs_detected() {
    let transition = make_transition(1);
    let prover = RiscZeroProver::new();
    let verifier = RiscZeroVerifier::new();

    let mut proof = prover.prove(transition).unwrap();

    // Tamper with public inputs
    proof.public_inputs.block_height = 999;
    assert!(verifier.verify(&proof).is_err());
}

#[test]
fn test_empty_proof_rejected() {
    let verifier = RiscZeroVerifier::new();
    let proof = seal_zk::ZkProof {
        bytes: vec![],
        public_inputs: make_transition(1),
    };
    assert!(verifier.verify(&proof).is_err());
}

// ========================================================================
// Determinism
// ========================================================================

#[test]
fn test_proof_determinism() {
    let transition = make_transition(42);

    let p1 = RiscZeroProver::new().prove(transition.clone()).unwrap();
    let p2 = RiscZeroProver::new().prove(transition.clone()).unwrap();
    let p3 = Sp1Prover::new().prove(transition).unwrap();

    assert_eq!(p1.bytes, p2.bytes);
    assert_eq!(p2.bytes, p3.bytes); // all backends deterministic in sim mode
}
