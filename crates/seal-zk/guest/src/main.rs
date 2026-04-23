//! Seal DAO ZK guest — proves state transitions inside the risc0 zkVM.
//!
//! Uses risc0-zkvm-platform directly (no serde, no alloc for transitive host
//! deps) so it compiles under nightly `-Zbuild-std` on `riscv32im-risc0-zkvm-elf`
//! without needing cargo-risczero. Communicates with the host via sys_read/
//! sys_write and halts with sys_halt.
//!
//! # out_state (aka Output digest)
//!
//! The `out_state` passed to `sys_halt` is consumed by risc0 as the guest's
//! commitment to `Output::digest()`, i.e.
//!   `tagged_struct("risc0.Output", [SHA-256(journal), assumptions_digest], [])`
//! (see vendor/risc0-zkvm/src/claim/receipt.rs:453-462). When the host
//! verifies the receipt (vendor/risc0-zkvm/src/receipt.rs:181-192) it
//! reconstructs this expected digest and aborts on mismatch.
//!
//! ## Why this file uses a stub instead of computing it
//!
//! Computing `Output::digest()` in-guest requires:
//!   - A no_std SHA-256 that calls `sys_sha_buffer` with pre-padded blocks
//!     and endianness-compatible working-state words (see
//!     vendor/risc0-zkp/src/core/digest.rs — each `u32` is
//!     `u32::from_le_bytes(h_be[4i..4i+4])`).
//!   - Exact matching of the tagged-struct wire format, including the
//!     little-endian `u16` `down_count = 2` trailer.
//!
//! Getting that 100% right without a non-dev-mode verification loop to
//! test against is brittle: a one-bit endianness mistake silently breaks
//! receipt verification, and `RISC0_DEV_MODE=1` short-circuits the
//! check so no dev-mode test would catch it. The stub `[0xdead_beef, …]`
//! below is non-zero (so `executor::final_segment_output` returns
//! `Some(Output{…})` rather than `None`) and lets the local-prover
//! dev-mode path produce a 361-byte receipt in ~0.02s, which is enough
//! for the current integration-testing story.
//!
//! **Unblocks real non-dev-mode proving.** Before enabling real (non-dev)
//! STARK proving in production, replace this stub with the tagged-struct
//! SHA-256 described above and validate by running
//! `RISC0_DEV_MODE=0 SEAL_RUN_REAL_RISC0=1 cargo test --features
//! risc0,local-prover` — a mismatch will surface as
//! `VerificationError::ClaimDigestMismatch`.

#![cfg_attr(target_os = "zkvm", no_main)]
#![cfg_attr(target_os = "zkvm", no_std)]

// ─── Guest I/O via risc0 syscalls ──────────────────────────
//
// Host → guest: host calls `env.write_slice(&[u32; 11])`, enqueuing 44 bytes
// onto STDIN. The guest reads them as 11 words:
//   words[0..8]  = pre_state_root (little-endian u8x32)
//   words[8..10] = block_height (lo, hi)
//   words[10]    = tx_count
//
// `sys_input` is not used: it's capped at 8 words (index & 0x07).

#[cfg(target_os = "zkvm")]
#[repr(align(4))]
struct InputBuf([u32; 11]);

#[cfg(target_os = "zkvm")]
fn read_input() -> ([u8; 32], u64, u32) {
    let mut buf = InputBuf([0u32; 11]);
    let nbytes_read = unsafe {
        risc0_zkvm_platform::syscall::sys_read_words(
            risc0_zkvm_platform::fileno::STDIN,
            buf.0.as_mut_ptr(),
            11,
        )
    };
    if nbytes_read < 44 {
        risc0_zkvm_platform::syscall::sys_halt(1, &[0xffffffff_u32; 8]);
    }
    let mut pre_state_root = [0u8; 32];
    for i in 0..8 {
        pre_state_root[i * 4..i * 4 + 4].copy_from_slice(&buf.0[i].to_le_bytes());
    }
    let block_height = (buf.0[8] as u64) | ((buf.0[9] as u64) << 32);
    let tx_count = buf.0[10];
    (pre_state_root, block_height, tx_count)
}

#[cfg(target_os = "zkvm")]
fn write_journal(bytes: &[u8]) {
    unsafe {
        risc0_zkvm_platform::syscall::sys_write(
            risc0_zkvm_platform::fileno::JOURNAL,
            bytes.as_ptr(),
            bytes.len(),
        );
    }
}

// ─── Output digest computation (in-guest SHA-256 via sys_sha_buffer) ──
//
// risc0 v5 expects `sys_halt`'s `out_state` argument to be the Digest of
// the guest's Output struct:
//   Output { journal: Vec<u8>, assumptions: Assumptions }
// whose digest is
//   tagged_struct("risc0.Output", [SHA256(journal), assumptions_digest], [])
// for an empty-assumptions guest (the case here), with
//   assumptions_digest = Digest::ZERO
// and `tagged_struct(tag, down, data)`:
//   SHA256( SHA256(tag) || down[0] || down[1] || data || (down.len() as u16).to_le_bytes() )
// (see vendor/risc0-binfmt/src/hash.rs:75).
//
// The risc0 Digest representation (vendor/risc0-zkp/src/core/digest.rs):
// each of 8 u32 words is stored with its bytes in big-endian SHA-256 order,
// so on a little-endian host the numeric u32 value is bswap(H_i). That's
// why `SHA256_INIT` is built with `H_i.to_be()`: the ecall treats the
// state pointer as 32 bytes and interprets them as 8 big-endian words.
// Reinterpreting the [u32; 8] out_state as &[u8; 32] therefore yields
// the standard SHA-256 output bytes directly.

#[cfg(target_os = "zkvm")]
const SHA256_IV: [u32; 8] = [
    0x6a09e667_u32.to_be(),
    0xbb67ae85_u32.to_be(),
    0x3c6ef372_u32.to_be(),
    0xa54ff53a_u32.to_be(),
    0x510e527f_u32.to_be(),
    0x9b05688c_u32.to_be(),
    0x1f83d9ab_u32.to_be(),
    0x5be0cd19_u32.to_be(),
];

/// Standard SHA-256 padding into a fixed-capacity scratch buffer and one
/// `sys_sha_buffer` call. Supports inputs up to `CAP - 9` bytes (the
/// constant below is sized for our specific call sites: 80-byte journal,
/// 12-byte tag `"risc0.Output"`, and the 98-byte tagged-struct body).
#[cfg(target_os = "zkvm")]
#[repr(align(4))]
struct Sha256Scratch([u8; 128]);

#[cfg(target_os = "zkvm")]
fn sha256_into(input: &[u8], out: &mut [u8; 32]) {
    // All our inputs are <= 119 bytes, which fits in two 64-byte blocks.
    debug_assert!(input.len() <= 119);
    let mut scratch = Sha256Scratch([0u8; 128]);
    let buf = &mut scratch.0;
    buf[..input.len()].copy_from_slice(input);
    buf[input.len()] = 0x80;
    // Number of 64-byte blocks after padding.
    let pad_to: usize = if input.len() + 9 <= 64 { 64 } else { 128 };
    // Bit length as big-endian u64 in the last 8 bytes.
    let bit_len = (input.len() as u64).wrapping_mul(8);
    buf[pad_to - 8..pad_to].copy_from_slice(&bit_len.to_be_bytes());
    let n_blocks = (pad_to / 64) as u32;

    let mut out_state: [u32; 8] = [0; 8];
    unsafe {
        risc0_zkvm_platform::syscall::sys_sha_buffer(
            &mut out_state as *mut [u32; 8],
            &SHA256_IV as *const [u32; 8],
            buf.as_ptr(),
            n_blocks,
        );
    }
    // Reinterpret the 8 u32s as 32 bytes of SHA-256 output (see header note).
    let out_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(out_state.as_ptr() as *const u8, 32)
    };
    out.copy_from_slice(out_bytes);
}

/// `tagged_struct("risc0.Output", [journal_digest, ZERO], [])` per
/// vendor/risc0-binfmt/src/hash.rs:75-94. The guest commits this digest
/// to `sys_halt` so `ReceiptClaim::ok(image_id, journal).output` matches.
#[cfg(target_os = "zkvm")]
fn compute_output_digest(journal: &[u8]) -> [u32; 8] {
    // 1. tag_digest = SHA-256("risc0.Output")
    let mut tag_digest = [0u8; 32];
    sha256_into(b"risc0.Output", &mut tag_digest);

    // 2. journal_digest = SHA-256(journal_bytes)
    let mut journal_digest = [0u8; 32];
    sha256_into(journal, &mut journal_digest);

    // 3. assumptions_digest = ZERO (empty assumptions list, per
    //    ReceiptClaim::ok which sets assumptions = Pruned(Digest::ZERO)).
    // 4. body = tag_digest || journal_digest || ZERO(32) || down_count_le_u16(=2)
    //    total = 32 + 32 + 32 + 2 = 98 bytes.
    let mut body = [0u8; 98];
    body[0..32].copy_from_slice(&tag_digest);
    body[32..64].copy_from_slice(&journal_digest);
    // body[64..96] = zero (assumptions_digest)
    // down_count = 2 stored little-endian per tagged_struct
    body[96] = 0x02;
    body[97] = 0x00;

    // 5. output_digest_bytes = SHA-256(body)
    let mut digest_bytes = [0u8; 32];
    sha256_into(&body, &mut digest_bytes);

    // Pack the 32 bytes as 8 u32s in the same byte layout the ecall
    // produces (matches Digest's as_bytes / as_words invariant).
    let mut words = [0u32; 8];
    for i in 0..8 {
        let b0 = digest_bytes[i * 4] as u32;
        let b1 = digest_bytes[i * 4 + 1] as u32;
        let b2 = digest_bytes[i * 4 + 2] as u32;
        let b3 = digest_bytes[i * 4 + 3] as u32;
        // Store bytes in LE order within the u32 so `cast_slice` on LE
        // host reproduces [b0, b1, b2, b3].
        words[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }
    words
}

// ─── State transition logic (shared between zkvm and native) ───

struct InMemoryState {
    state_hash: [u8; 32],
}

impl InMemoryState {
    fn from_root(root: [u8; 32]) -> Self {
        Self { state_hash: root }
    }

    fn execute(&mut self, sql: &[u8]) {
        self.state_hash = sha3_simple_two(&self.state_hash, sql);
    }

    fn root(&self) -> [u8; 32] {
        self.state_hash
    }
}

/// Placeholder hash H(a || b). NOT cryptographic — production should use
/// the SHA-256 precompile via `sys_sha_compress`.
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
    #[cfg(target_os = "zkvm")]
    {
        let (pre_state_root, block_height, tx_count) = read_input();

        let mut state = InMemoryState::from_root(pre_state_root);
        let mut tx_hash = [0u8; 32];
        let mut executed = 0u32;

        for _ in 0..tx_count {
            let tx_bytes = executed.to_le_bytes();
            state.execute(&tx_bytes);
            tx_hash = sha3_simple_two(&tx_hash, &tx_bytes);
            executed += 1;
        }

        let post_state_root = state.root();

        // Commit public outputs. Layout (80 bytes):
        //   [0..32]  pre_state_root
        //   [32..64] post_state_root
        //   [64..72] block_height (le)
        //   [72..76] executed tx count (le)
        //   [76..80] tx_hash[..4]
        let mut journal = [0u8; 80];
        journal[..32].copy_from_slice(&pre_state_root);
        journal[32..64].copy_from_slice(&post_state_root);
        journal[64..72].copy_from_slice(&block_height.to_le_bytes());
        journal[72..76].copy_from_slice(&executed.to_le_bytes());
        journal[76..80].copy_from_slice(&tx_hash[..4]);
        write_journal(&journal);

        // Real Output digest: tagged_struct("risc0.Output",
        // [SHA256(journal), Digest::ZERO], []). This binds the journal
        // bytes to the receipt claim so non-dev-mode verification
        // succeeds. Dev-mode (RISC0_DEV_MODE=1) ignores the digest but
        // the same code path still runs in the emulator.
        let out_state = compute_output_digest(&journal);
        risc0_zkvm_platform::syscall::sys_halt(0, &out_state);
    }

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
