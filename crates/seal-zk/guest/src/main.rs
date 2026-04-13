//! Seal DAO ZK guest — proves state transitions inside the risc0 zkVM.
//!
//! Uses risc0-zkvm-platform directly (no serde) for compatibility with
//! -Zbuild-std on nightly. Communicates with the host via risc0 syscalls.
//!
//! # Build
//!
//! ```bash
//! # From outside the workspace (to avoid vendor config interference):
//! GUEST=/tmp/seal-guest-build
//! cp -r crates/seal-zk/guest $GUEST && rm -rf $GUEST/.cargo $GUEST/Cargo.lock
//! cd $GUEST
//! RUSTC=~/.rustup/toolchains/nightly-*/bin/rustc \
//!   ~/.rustup/toolchains/nightly-*/bin/cargo build --release \
//!   --target ./riscv32im-risc0-zkvm-elf.json \
//!   -Zbuild-std=core,alloc -Zjson-target-spec
//! # ELF at: target/riscv32im-risc0-zkvm-elf/release/seal-zk-guest
//! ```

#![cfg_attr(target_os = "zkvm", no_main)]
#![cfg_attr(target_os = "zkvm", no_std)]

// On zkvm target, risc0-zkvm-platform provides: panic handler, entry point, syscalls.
// No heap allocation needed — guest uses only fixed-size arrays.

// ─── Guest I/O via risc0 syscalls ──────────────────────────

/// Read a [u8; 32] from the host input stream.
#[cfg(target_os = "zkvm")]
fn read_bytes32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    // risc0 input is read word-by-word via sys_input
    // For simplicity, read 8 u32 words
    for i in 0..8 {
        let word = risc0_zkvm_platform::syscall::sys_input(i as u32);
        buf[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    buf
}

/// Write 32 bytes to the journal (committed as public output).
#[cfg(target_os = "zkvm")]
fn commit_bytes32(data: &[u8; 32]) {
    // Journal output via sys_write to JOURNAL fd
    unsafe {
        risc0_zkvm_platform::syscall::sys_write(
            risc0_zkvm_platform::fileno::JOURNAL,
            data.as_ptr(),
            data.len(),
        );
    }
}

/// Write a u64 to the journal.
#[cfg(target_os = "zkvm")]
fn commit_u64(val: u64) {
    let bytes = val.to_le_bytes();
    unsafe {
        risc0_zkvm_platform::syscall::sys_write(
            risc0_zkvm_platform::fileno::JOURNAL,
            bytes.as_ptr(),
            8usize,
        );
    }
}

/// Write a u32 to the journal.
#[cfg(target_os = "zkvm")]
fn commit_u32(val: u32) {
    let bytes = val.to_le_bytes();
    unsafe {
        risc0_zkvm_platform::syscall::sys_write(
            risc0_zkvm_platform::fileno::JOURNAL,
            bytes.as_ptr(),
            4usize,
        );
    }
}

// ─── State transition logic (shared between zkvm and native) ───

/// Minimal in-memory state for transaction replay.
struct InMemoryState {
    state_hash: [u8; 32],
}

impl InMemoryState {
    fn from_root(root: [u8; 32]) -> Self {
        Self { state_hash: root }
    }

    fn execute(&mut self, sql: &[u8]) {
        // Hash: new_state = SHA3_simple(old_state || sql)
        self.state_hash = sha3_simple_two(&self.state_hash, sql);
    }

    fn root(&self) -> [u8; 32] {
        self.state_hash
    }
}

/// Minimal hash: H(a || b). NOT cryptographic — placeholder for guest.
/// In production, use the SHA3-256 precompile (risc0 accelerates this).
fn sha3_simple_two(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    for (i, &byte) in a.iter().chain(b.iter()).enumerate() {
        hash[i % 32] ^= byte;
        let j = (i.wrapping_mul(13).wrapping_add(7)) % 32;
        hash[j] = hash[j].wrapping_add(byte.wrapping_mul(0x9e));
    }
    hash
}

// ─── Entry point ────────────────────────────────────────────

#[cfg_attr(target_os = "zkvm", unsafe(no_mangle))]
fn main() {
    // === zkVM mode: read from host, prove, commit to journal ===
    #[cfg(target_os = "zkvm")]
    {
        // Read pre_state_root (32 bytes) from host input
        let pre_state_root = read_bytes32();

        // Read block_height (8 bytes as 2 u32 words)
        let height_lo = risc0_zkvm_platform::syscall::sys_input(8);
        let height_hi = risc0_zkvm_platform::syscall::sys_input(9);
        let block_height = (height_lo as u64) | ((height_hi as u64) << 32);

        // Read tx_count
        let tx_count = risc0_zkvm_platform::syscall::sys_input(10);

        // Replay transactions (host writes SQL bytes to stdin)
        let mut state = InMemoryState::from_root(pre_state_root);
        let mut tx_hash = [0u8; 32];
        let mut executed = 0u32;

        // For now: simple replay of tx_count fixed-size transactions
        // In production: read variable-length tx payloads from stdin
        for _ in 0..tx_count {
            // Placeholder: each tx is "tx_N" where N = executed count
            let tx_bytes = executed.to_le_bytes();
            state.execute(&tx_bytes);
            tx_hash = sha3_simple_two(&tx_hash, &tx_bytes);
            executed += 1;
        }

        let post_state_root = state.root();

        // Commit public outputs to journal
        commit_bytes32(&pre_state_root);
        commit_bytes32(&post_state_root);
        commit_u64(block_height);
        commit_u32(executed);
        commit_bytes32(&tx_hash);

        // Halt with success
        risc0_zkvm_platform::syscall::sys_halt(0, &[0u32; 8]);
    }

    // === Native mode: test execution ===
    #[cfg(not(target_os = "zkvm"))]
    {
        let pre_state = [0u8; 32];
        let mut state = InMemoryState::from_root(pre_state);
        state.execute(b"INSERT INTO accounts VALUES ('alice', 1000)");
        state.execute(b"INSERT INTO accounts VALUES ('bob', 500)");
        println!(
            "Seal ZK guest (native): 2 txs, root = {:02x}{:02x}{:02x}{:02x}...",
            state.root()[0], state.root()[1], state.root()[2], state.root()[3]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_deterministic() {
        let mut s1 = InMemoryState::from_root([0u8; 32]);
        let mut s2 = InMemoryState::from_root([0u8; 32]);
        s1.execute(b"tx1");
        s2.execute(b"tx1");
        assert_eq!(s1.root(), s2.root());
    }

    #[test]
    fn test_state_changes() {
        let mut state = InMemoryState::from_root([0u8; 32]);
        let root0 = state.root();
        state.execute(b"tx");
        assert_ne!(root0, state.root());
    }

    #[test]
    fn test_order_matters() {
        let mut s1 = InMemoryState::from_root([0u8; 32]);
        let mut s2 = InMemoryState::from_root([0u8; 32]);
        s1.execute(b"a");
        s1.execute(b"b");
        s2.execute(b"b");
        s2.execute(b"a");
        assert_ne!(s1.root(), s2.root());
    }
}
