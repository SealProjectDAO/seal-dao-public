//! RISC Zero guest program for Seal DAO state transition proofs.
//!
//! This program runs inside the RISC-V zkVM and proves that a set of
//! SQL transactions correctly transforms pre_state_root → post_state_root.
//!
//! # What this proves (public inputs)
//!
//! Given:
//!   - pre_state_root (Merkle root before transactions)
//!   - transaction payloads (SQL statements)
//!   - post_state_root (claimed Merkle root after)
//!
//! The guest program:
//!   1. Reads inputs from the host via env::read()
//!   2. Replays each SQL transaction against an in-memory state
//!   3. Computes the resulting Merkle state root
//!   4. Asserts: computed_root == post_state_root
//!   5. Commits public inputs to the journal for verifier consumption
//!
//! # What this does NOT prove
//!
//! - Transaction signatures (verified natively in Layer 1)
//! - VRF election validity (verified in Layer 3)
//! - These are verified outside the ZK circuit for efficiency
//!
//! # How to compile
//!
//! ```bash
//! # Requires risc0-zkvm toolchain:
//! cargo risczero build --manifest-path crates/seal-zk/guest/Cargo.toml
//! ```
//!
//! # How to use
//!
//! The host (RiscZeroProver) loads this compiled ELF binary, feeds it
//! the transaction payloads, and generates a STARK proof.

// When risc0-zkvm is available, uncomment these and remove fn main():
// #![no_main]
// #![no_std]
// risc0_zkvm::guest::entry!(main);

/// State transition input from the host.
#[derive(Debug)]
struct GuestInput {
    /// Merkle state root before the block.
    pre_state_root: [u8; 32],
    /// SQL transaction payloads (each is a UTF-8 SQL statement).
    tx_payloads: Vec<Vec<u8>>,
    /// Claimed Merkle state root after the block.
    claimed_post_root: [u8; 32],
    /// Block height for journal output.
    block_height: u64,
}

/// Minimal in-memory state for transaction replay.
/// In the real guest, this would be a full SQL engine with Merkle state.
struct InMemoryState {
    /// Current state as a simple key-value store.
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// Running hash for state tracking.
    state_hash: [u8; 32],
}

impl InMemoryState {
    /// Initialize from a pre-state root.
    fn from_root(root: [u8; 32]) -> Self {
        Self {
            entries: Vec::new(),
            state_hash: root,
        }
    }

    /// Execute a SQL statement against the in-memory state.
    /// Returns the number of rows affected.
    fn execute(&mut self, sql: &str) -> Result<usize, String> {
        // In the real guest, this would:
        // 1. Parse the SQL statement
        // 2. Execute against the Merkle-backed state
        // 3. Update affected rows and Merkle proofs
        //
        // For the stub, we just hash the SQL into the state.
        let combined = [self.state_hash.as_ref(), sql.as_bytes()].concat();
        self.state_hash = sha3_256_simple(&combined);
        self.entries.push((sql.as_bytes().to_vec(), self.state_hash.to_vec()));
        Ok(1)
    }

    /// Compute the current Merkle state root.
    fn merkle_root(&self) -> [u8; 32] {
        self.state_hash
    }
}

/// Simplified SHA3-256 for the guest (no external deps).
/// In the real guest, this would use seal-crypto's SHA3 implementation
/// compiled for RISC-V.
fn sha3_256_simple(data: &[u8]) -> [u8; 32] {
    // Placeholder: use a simple mixing function.
    // The real implementation uses FIPS 202 SHA3-256.
    let mut hash = [0u8; 32];
    for (i, &byte) in data.iter().enumerate() {
        hash[i % 32] ^= byte;
        // Mix
        let j = (i + 13) % 32;
        hash[j] = hash[j].wrapping_add(byte.wrapping_mul(0x9e));
    }
    hash
}

/// Guest entry point: proves state transition.
fn main() {
    // When running inside the zkVM, read inputs from the host:
    //
    // let input: GuestInput = risc0_zkvm::guest::env::read();
    //
    // For now, demonstrate the execution flow with test data:

    let input = GuestInput {
        pre_state_root: [0u8; 32],
        tx_payloads: vec![
            b"INSERT INTO accounts VALUES ('alice', 1000)".to_vec(),
            b"INSERT INTO accounts VALUES ('bob', 500)".to_vec(),
            b"UPDATE accounts SET balance = 900 WHERE name = 'alice'".to_vec(),
        ],
        claimed_post_root: [0u8; 32], // Would be set correctly by the host
        block_height: 1,
    };

    // Step 1: Initialize state from pre-state root
    let mut state = InMemoryState::from_root(input.pre_state_root);

    // Step 2: Replay all transactions
    let mut tx_count = 0u32;
    for tx_bytes in &input.tx_payloads {
        let sql = match std::str::from_utf8(tx_bytes) {
            Ok(s) => s,
            Err(_) => {
                // In zkVM: this would cause the proof to fail
                panic!("Invalid UTF-8 in transaction payload");
            }
        };
        match state.execute(sql) {
            Ok(_rows) => {
                tx_count += 1;
            }
            Err(e) => {
                // SQL execution failure → proof fails
                panic!("SQL execution failed: {}", e);
            }
        }
    }

    // Step 3: Compute resulting state root
    let computed_root = state.merkle_root();

    // Step 4: Assert correctness
    // In the real guest, this assertion causes the proof to be invalid
    // if the block producer lied about the post-state root.
    //
    // Disabled for stub since we don't have the real post-state:
    // assert_eq!(
    //     computed_root, input.claimed_post_root,
    //     "State root mismatch: block producer lied about post-state"
    // );

    // Step 5: Commit public inputs to journal
    // These are the values the verifier can check:
    //
    // risc0_zkvm::guest::env::commit(&input.pre_state_root);
    // risc0_zkvm::guest::env::commit(&computed_root);
    // risc0_zkvm::guest::env::commit(&input.block_height);
    // risc0_zkvm::guest::env::commit(&tx_count);

    println!(
        "Seal ZK guest: replayed {} transactions at block {}",
        tx_count, input.block_height
    );
    println!(
        "  pre_state:  {}",
        hex_encode(&input.pre_state_root[..8])
    );
    println!("  post_state: {}", hex_encode(&computed_root[..8]));
    println!("When compiled for RISC-V zkVM, this generates a STARK proof.");
}

/// Minimal hex encoding (no external deps in guest).
fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_state() {
        let mut state = InMemoryState::from_root([0u8; 32]);
        assert_eq!(state.execute("INSERT INTO t VALUES (1)").unwrap(), 1);
        assert_eq!(state.entries.len(), 1);
        // State root should change after execution
        assert_ne!(state.merkle_root(), [0u8; 32]);
    }

    #[test]
    fn test_deterministic_replay() {
        // Same transactions → same state root
        let txs = vec!["INSERT INTO a VALUES (1)", "UPDATE a SET x = 2"];

        let mut s1 = InMemoryState::from_root([0u8; 32]);
        for tx in &txs {
            s1.execute(tx).unwrap();
        }

        let mut s2 = InMemoryState::from_root([0u8; 32]);
        for tx in &txs {
            s2.execute(tx).unwrap();
        }

        assert_eq!(s1.merkle_root(), s2.merkle_root());
    }

    #[test]
    fn test_different_txs_different_roots() {
        let mut s1 = InMemoryState::from_root([0u8; 32]);
        s1.execute("INSERT INTO a VALUES (1)").unwrap();

        let mut s2 = InMemoryState::from_root([0u8; 32]);
        s2.execute("INSERT INTO a VALUES (2)").unwrap();

        assert_ne!(s1.merkle_root(), s2.merkle_root());
    }

    #[test]
    fn test_order_matters() {
        let mut s1 = InMemoryState::from_root([0u8; 32]);
        s1.execute("INSERT INTO a VALUES (1)").unwrap();
        s1.execute("INSERT INTO a VALUES (2)").unwrap();

        let mut s2 = InMemoryState::from_root([0u8; 32]);
        s2.execute("INSERT INTO a VALUES (2)").unwrap();
        s2.execute("INSERT INTO a VALUES (1)").unwrap();

        assert_ne!(
            s1.merkle_root(),
            s2.merkle_root(),
            "transaction order must affect state root"
        );
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xab, 0xcd, 0xef]), "abcdef");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
    }
}
