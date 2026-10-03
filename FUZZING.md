# Seal DAO — Fuzzing Guide

## Overview

Fuzzing feeds random/malformed inputs to code and checks it never panics,
hangs, or produces undefined behavior. Seal uses **cargo-fuzz** (libFuzzer)
to test security-critical parsing and verification code.

**7 fuzz targets** cover: SQL parsing, VRF verification, address decoding,
block/transaction deserialization, and Merkle tree operations.

## Prerequisites

```bash
# Install cargo-fuzz (requires nightly Rust)
rustup install nightly
cargo +nightly install cargo-fuzz

# Verify installation
cargo +nightly fuzz --version
```

**Note:** cargo-fuzz requires nightly Rust because libFuzzer uses compiler
instrumentation (`-Zsanitizer=address`) that is only available on nightly.

## Quick Start

```bash
# Run a single target for 60 seconds
cd /path/to/seal-dao-master
cargo +nightly fuzz run fuzz_sql_parser -- -max_total_time=60

# Run all targets (30 seconds each)
./scripts/fuzz-all.sh

# Run a specific target with more time
cargo +nightly fuzz run fuzz_merkle_ops -- -max_total_time=300
```

## Fuzz Targets

### 1. `fuzz_sql_parser` — SQL injection defense

**File:** `fuzz/fuzz_targets/fuzz_sql_parser.rs`

**What it tests:** The PostgreSQL-compatible SQL parser (`seal_sql::parse_sql`)
must never panic on any input string, no matter how malformed.

**Why it matters:** If a validator receives a malicious SQL transaction from
the network, the parser must reject it gracefully — not crash the node.

**Attack surface:** Transaction payloads from the P2P network.

```bash
cargo +nightly fuzz run fuzz_sql_parser -- -max_total_time=120
```

### 2. `fuzz_vrf_verify` — VRF proof forgery defense

**File:** `fuzz/fuzz_targets/fuzz_vrf_verify.rs`

**What it tests:** `HmacVrf::verify()` with arbitrary public keys, inputs,
outputs, and proofs. Must return `Ok` or `Err` — never panic.

**Why it matters:** A malicious block proposer could submit crafted VRF
proofs. Verification must be robust against all malformed inputs.

**Input format:** `data[0..32]` = public key, `[32..64]` = input,
`[64..96]` = VRF output, `[96..]` = proof bytes.

```bash
cargo +nightly fuzz run fuzz_vrf_verify -- -max_total_time=120
```

### 3. `fuzz_pqvrf_verify` — Post-quantum VRF defense

**File:** `fuzz/fuzz_targets/fuzz_pqvrf_verify.rs`

**What it tests:** `PqVrf::verify()` with arbitrary ML-DSA public keys
(1,952 bytes) and ML-DSA signatures (~3,309 bytes). The real PQC
verification path.

**Why it matters:** ML-DSA verification is the production code path.
Malformed keys or signatures must never cause panics in libcrux.

**Input format:** `data[0..1952]` = ML-DSA public key, `[1952..1984]` = input,
`[1984..2016]` = VRF output, `[2016..]` = proof (ML-DSA signature).

**Minimum input size:** 2,016 bytes (smaller inputs are skipped).

```bash
cargo +nightly fuzz run fuzz_pqvrf_verify -- -max_total_time=300
```

### 4. `fuzz_address_parse` — Address parsing defense

**File:** `fuzz/fuzz_targets/fuzz_address_parse.rs`

**What it tests:** `SealAddress::from_string_encoding()` with arbitrary
strings. Must parse valid bech32m addresses and reject invalid ones.

**Why it matters:** User-supplied addresses in transfer transactions
must be validated without crashing.

```bash
cargo +nightly fuzz run fuzz_address_parse -- -max_total_time=60
```

### 5. `fuzz_block_deserialize` — Block parsing defense

**File:** `fuzz/fuzz_targets/fuzz_block_deserialize.rs`

**What it tests:** `bincode::deserialize::<Block>()` with arbitrary bytes.
Deserialization must return `Ok` or `Err` — never panic.

**Why it matters:** Blocks received from the P2P network are deserialized
before validation. Malformed blocks must be rejected gracefully.

```bash
cargo +nightly fuzz run fuzz_block_deserialize -- -max_total_time=60
```

### 6. `fuzz_tx_deserialize` — Transaction parsing defense

**File:** `fuzz/fuzz_targets/fuzz_tx_deserialize.rs`

**What it tests:** `bincode::deserialize::<Transaction>()` with arbitrary
bytes. Same principle as block deserialization.

**Why it matters:** Transactions are received individually via GossipSub.
Each one is deserialized before signature verification.

```bash
cargo +nightly fuzz run fuzz_tx_deserialize -- -max_total_time=60
```

### 7. `fuzz_merkle_ops` — Merkle B-tree integrity

**File:** `fuzz/fuzz_targets/fuzz_merkle_ops.rs`

**What it tests:** Random sequences of insert/get/delete/to_vec operations
on the Merkle B-tree. Validates:
- Insert-then-get roundtrip (always returns the inserted value)
- `to_vec()` output is always sorted (no duplicate keys)
- No panics on any operation sequence

**Why it matters:** The Merkle B-tree stores ALL on-chain state. A bug
here means state corruption affecting every table and every block.

**Input format:** Sequence of `(op, key_len, key_bytes, value_byte)` commands
parsed from the fuzz input.

```bash
cargo +nightly fuzz run fuzz_merkle_ops -- -max_total_time=300
```

## Running All Targets

Create a script or run them sequentially:

```bash
#!/bin/bash
# scripts/fuzz-all.sh
set -e

TARGETS=(
    fuzz_sql_parser
    fuzz_vrf_verify
    fuzz_pqvrf_verify
    fuzz_address_parse
    fuzz_block_deserialize
    fuzz_tx_deserialize
    fuzz_merkle_ops
)

DURATION=${1:-60}  # seconds per target, default 60

for target in "${TARGETS[@]}"; do
    echo "=== Fuzzing $target for ${DURATION}s ==="
    cargo +nightly fuzz run "$target" -- -max_total_time="$DURATION" || {
        echo "CRASH FOUND in $target!"
        exit 1
    }
    echo ""
done

echo "All targets passed (${DURATION}s each)"
```

## Handling Crashes

When a fuzzer finds a crash, it saves the input to:
```
fuzz/artifacts/<target_name>/crash-<hash>
```

To reproduce a crash:
```bash
# Reproduce
cargo +nightly fuzz run fuzz_sql_parser fuzz/artifacts/fuzz_sql_parser/crash-abc123

# Minimize the crash input (find smallest reproducer)
cargo +nightly fuzz tmin fuzz_sql_parser fuzz/artifacts/fuzz_sql_parser/crash-abc123
```

To debug:
```bash
# Run with ASAN (AddressSanitizer) for memory bugs
RUSTFLAGS="-Zsanitizer=address" cargo +nightly fuzz run fuzz_merkle_ops

# Get a backtrace
RUST_BACKTRACE=1 cargo +nightly fuzz run fuzz_sql_parser fuzz/artifacts/fuzz_sql_parser/crash-abc123
```

## Corpus Management

The fuzzer builds a corpus of interesting inputs over time:
```
fuzz/corpus/<target_name>/
```

This corpus is reused across runs, so the fuzzer gets smarter over time.
You can seed the corpus with known-interesting inputs:

```bash
# Add a seed input
echo "SELECT * FROM users WHERE id = 1" > fuzz/corpus/fuzz_sql_parser/seed1.txt
echo "INSERT INTO t VALUES (1, 'hello')" > fuzz/corpus/fuzz_sql_parser/seed2.txt
```

## Coverage

To see which code paths the fuzzer has explored:

```bash
# Generate coverage report
cargo +nightly fuzz coverage fuzz_sql_parser

# View with llvm-cov
cargo +nightly cov -- show fuzz/coverage/fuzz_sql_parser/ \
    --format=html --instr-profile=fuzz/coverage/fuzz_sql_parser/coverage.profdata
```

## CI Integration

Fuzzing runs in `scripts/ci.sh` with short durations (30s per target):

```bash
# In scripts/ci.sh:
if command -v cargo-fuzz &>/dev/null; then
    for target in fuzz_sql_parser fuzz_vrf_verify fuzz_address_parse fuzz_block_deserialize; do
        cargo +nightly fuzz run "$target" -- -max_total_time=30
    done
fi
```

For thorough fuzzing, run overnight or on dedicated infrastructure:
```bash
./scripts/fuzz-all.sh 3600  # 1 hour per target
```

## Adding New Fuzz Targets

1. Create `fuzz/fuzz_targets/fuzz_<name>.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // This must NEVER panic
    let _ = your_crate::parse_something(data);
});
```

2. Add to `fuzz/Cargo.toml`:

```toml
# Add dependency if needed
your-crate = { path = "../crates/your-crate" }

[[bin]]
name = "fuzz_<name>"
path = "fuzz_targets/fuzz_<name>.rs"
doc = false
```

3. Test it:
```bash
cargo +nightly fuzz run fuzz_<name> -- -max_total_time=60
```

## Security Priority

Fuzz targets are ordered by security impact:

| Priority | Target | Attack surface |
|----------|--------|---------------|
| Critical | `fuzz_pqvrf_verify` | Block proposer election forgery |
| Critical | `fuzz_merkle_ops` | State corruption |
| High | `fuzz_sql_parser` | SQL injection via transactions |
| High | `fuzz_block_deserialize` | P2P block propagation |
| High | `fuzz_tx_deserialize` | P2P transaction propagation |
| Medium | `fuzz_vrf_verify` | VRF stub (not production path) |
| Medium | `fuzz_address_parse` | User input validation |

## Troubleshooting

**"error: the `-Zsanitizer` flag is not supported on this platform"**
→ Use Linux x86_64 or macOS ARM64. WASM targets are not supported.

**"cargo-fuzz not found"**
→ `cargo +nightly install cargo-fuzz`

**"nightly toolchain not installed"**
→ `rustup install nightly`

**"compilation error in fuzz target"**
→ Ensure `fuzz/Cargo.toml` has all needed dependencies. Fuzz crate is
excluded from the workspace, so dependencies must be listed explicitly.

**Fuzzer runs but finds no bugs**
→ Good! Run longer (hours/days) or add seed corpus files for better coverage.
