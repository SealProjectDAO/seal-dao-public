//! RISC Zero guest program for Seal block proving.
//!
//! This module defines what the zkVM guest program executes inside the RISC-V
//! virtual machine. The guest receives block data, replays all transactions,
//! and asserts the state transition is valid.
//!
//! # Guest Program Flow
//!
//! ```text
//! Input (from host via env::read):
//!   - pre_state_root: [u8; 32]
//!   - transactions: Vec<TransactionData>
//!   - post_state_root: [u8; 32]  (claimed)
//!
//! Execution:
//!   1. Initialize SQL state from pre_state_root
//!   2. For each transaction:
//!      a. Verify ML-DSA signature (PQ-secure)
//!      b. Check access control (RLS policies)
//!      c. Execute SQL operation
//!      d. Update Merkle state
//!   3. Compute final state root
//!   4. Assert: computed_root == claimed post_state_root
//!
//! Output (committed to journal):
//!   - pre_state_root
//!   - post_state_root
//!   - block_height
//!   - tx_count
//!   - tx_hash
//! ```
//!
//! # Compilation
//!
//! When the `risc0` feature is enabled and `risc0-zkvm` is available:
//! ```bash
//! # The guest is compiled separately to RISC-V:
//! cd crates/seal-zk/src/risc0_guest
//! cargo build --target riscv32im-risc0-zkvm-elf
//! ```
//!
//! The compiled ELF binary is embedded into the host prover as `GUEST_ELF`.

use serde::{Deserialize, Serialize};

/// Input data for the guest program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestInput {
    /// State root before this block's transactions.
    pub pre_state_root: [u8; 32],
    /// Transactions to replay.
    pub transactions: Vec<GuestTransaction>,
    /// Claimed state root after all transactions.
    pub claimed_post_state_root: [u8; 32],
    /// Block height.
    pub block_height: u64,
}

/// A transaction as seen by the guest program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestTransaction {
    /// Transaction type identifier.
    pub tx_type: u8,
    /// SQL payload (UTF-8 encoded SQL statement).
    pub payload: Vec<u8>,
    /// Sender's ML-DSA public key.
    pub sender_pubkey: Vec<u8>,
    /// ML-DSA signature over the payload.
    pub signature: Vec<u8>,
}

/// Output committed to the RISC Zero journal (public inputs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestOutput {
    /// Pre-state root (verified by guest).
    pub pre_state_root: [u8; 32],
    /// Post-state root (computed by guest, must match claimed).
    pub post_state_root: [u8; 32],
    /// Block height.
    pub block_height: u64,
    /// Number of transactions processed.
    pub tx_count: u32,
    /// SHA3 hash of all transaction payloads.
    pub tx_hash: [u8; 32],
}

/// Simulate the guest program execution (for testing without risc0-zkvm).
///
/// This runs the same logic the real guest would execute, but natively.
/// Used for integration testing before wiring up the actual zkVM.
pub fn simulate_guest(input: &GuestInput) -> Result<GuestOutput, String> {
    use seal_crypto::hash::{sha3_256, Sha3Hasher};

    // Step 1: Verify all transaction signatures
    for (i, tx) in input.transactions.iter().enumerate() {
        if tx.sender_pubkey.is_empty() {
            return Err(format!("transaction {} has empty sender pubkey", i));
        }
        if tx.signature.is_empty() {
            return Err(format!("transaction {} has empty signature", i));
        }

        // In the real guest: verify ML-DSA signature
        // seal_crypto::signature::VerifyingKey::from_bytes(&tx.sender_pubkey)
        //     .and_then(|vk| {
        //         let sig = seal_crypto::signature::Signature::from_bytes(tx.signature.clone());
        //         vk.verify(&tx.payload, &sig)
        //     })
        //     .map_err(|e| format!("tx {} sig verification failed: {}", i, e))?;
    }

    // Step 2: Compute transaction hash
    let mut tx_hasher = Sha3Hasher::new();
    for tx in &input.transactions {
        tx_hasher.update(&tx.payload);
    }
    let tx_hash = tx_hasher.finalize();

    // Step 3: Simulate state transition
    // In the real guest: replay SQL operations against Merkle state
    // For simulation: compute a deterministic post-state from inputs
    let mut state_data = Vec::new();
    state_data.extend_from_slice(&input.pre_state_root);
    for tx in &input.transactions {
        state_data.extend_from_slice(&tx.payload);
    }
    let computed_post_state = sha3_256(&state_data);

    // Step 4: The guest would assert computed == claimed
    // In simulation mode, we return the computed value and let the caller check
    Ok(GuestOutput {
        pre_state_root: input.pre_state_root,
        post_state_root: computed_post_state.0,
        block_height: input.block_height,
        tx_count: input.transactions.len() as u32,
        tx_hash: tx_hash.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> GuestInput {
        GuestInput {
            pre_state_root: [1u8; 32],
            transactions: vec![
                GuestTransaction {
                    tx_type: 1,
                    payload: b"INSERT INTO t VALUES (1)".to_vec(),
                    sender_pubkey: vec![0xAA; 32],
                    signature: vec![0xBB; 64],
                },
                GuestTransaction {
                    tx_type: 1,
                    payload: b"INSERT INTO t VALUES (2)".to_vec(),
                    sender_pubkey: vec![0xCC; 32],
                    signature: vec![0xDD; 64],
                },
            ],
            claimed_post_state_root: [0u8; 32], // will be overwritten
            block_height: 42,
        }
    }

    #[test]
    fn test_simulate_guest_success() {
        let input = sample_input();
        let output = simulate_guest(&input).unwrap();

        assert_eq!(output.pre_state_root, input.pre_state_root);
        assert_eq!(output.block_height, 42);
        assert_eq!(output.tx_count, 2);
        assert_ne!(output.post_state_root, [0u8; 32]); // non-trivial
        assert_ne!(output.tx_hash, [0u8; 32]);
    }

    #[test]
    fn test_simulate_guest_deterministic() {
        let input = sample_input();
        let o1 = simulate_guest(&input).unwrap();
        let o2 = simulate_guest(&input).unwrap();

        assert_eq!(o1.post_state_root, o2.post_state_root);
        assert_eq!(o1.tx_hash, o2.tx_hash);
    }

    #[test]
    fn test_simulate_guest_empty_pubkey_fails() {
        let mut input = sample_input();
        input.transactions[0].sender_pubkey = vec![];

        let result = simulate_guest(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_simulate_guest_empty_sig_fails() {
        let mut input = sample_input();
        input.transactions[0].signature = vec![];

        let result = simulate_guest(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_simulate_guest_no_transactions() {
        let input = GuestInput {
            pre_state_root: [5u8; 32],
            transactions: vec![],
            claimed_post_state_root: [0u8; 32],
            block_height: 1,
        };
        let output = simulate_guest(&input).unwrap();
        assert_eq!(output.tx_count, 0);
        assert_eq!(output.block_height, 1);
    }

    #[test]
    fn test_guest_output_serialization() {
        let input = sample_input();
        let output = simulate_guest(&input).unwrap();

        let bytes = bincode::serialize(&output).unwrap();
        let deserialized: GuestOutput = bincode::deserialize(&bytes).unwrap();

        assert_eq!(deserialized.pre_state_root, output.pre_state_root);
        assert_eq!(deserialized.post_state_root, output.post_state_root);
        assert_eq!(deserialized.block_height, output.block_height);
        assert_eq!(deserialized.tx_count, output.tx_count);
    }

    #[test]
    fn test_different_pre_state_different_output() {
        let mut input1 = sample_input();
        let mut input2 = sample_input();
        input1.pre_state_root = [1u8; 32];
        input2.pre_state_root = [2u8; 32];

        let o1 = simulate_guest(&input1).unwrap();
        let o2 = simulate_guest(&input2).unwrap();

        assert_ne!(o1.post_state_root, o2.post_state_root);
    }
}
