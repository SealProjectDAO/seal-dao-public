# Fuzzing — Coverage-Guided Random Testing

## What is fuzzing?

Fuzzing feeds **random, mutated inputs** to your code and watches for crashes,
panics, and assertion failures. Unlike unit tests (which check specific inputs
you thought of), fuzzing explores inputs you DIDN'T think of.

`cargo-fuzz` uses **coverage-guided** fuzzing (libFuzzer): it tracks which code
paths each input exercises and mutates inputs to maximize coverage. This finds
edge cases that manual tests miss.

## Why we fuzz

Every external input boundary is a potential attack surface:
- SQL parser: malformed SQL → should return error, not panic
- Transaction deserializer: malformed bytes → should reject, not crash
- VRF proof verifier: forged proofs → should return false, not UB
- Block deserializer: corrupted blocks → should reject gracefully
- P2P messages: arbitrary network data → should never crash the node

## Fuzz targets

| Target | What is fuzzed | Crate | Status |
|--------|----------------|-------|--------|
| `fuzz_sql_parser` | Arbitrary strings → `parse_sql()` | seal-sql | TODO |
| `fuzz_tx_deserialize` | Arbitrary bytes → Transaction deserialization | seal-storage | TODO |
| `fuzz_vrf_verify` | Arbitrary proofs → `HmacVrf::verify()` | seal-vrf | TODO |
| `fuzz_block_deserialize` | Arbitrary bytes → Block deserialization | seal-storage | TODO |
| `fuzz_merkle_ops` | Random insert/delete sequences → tree invariants | seal-merkle | TODO |
| `fuzz_address_parse` | Arbitrary strings → `SealAddress::from_string_encoding()` | seal-crypto | TODO |

## How to run

```bash
# Install cargo-fuzz (one-time):
cargo install cargo-fuzz

# Run a fuzz target for 60 seconds:
cargo fuzz run fuzz_sql_parser -- -max_total_time=60

# Run indefinitely (Ctrl+C to stop):
cargo fuzz run fuzz_sql_parser

# Run with specific options:
cargo fuzz run fuzz_sql_parser -- -max_len=4096 -jobs=4
```

## Installation

### macOS
```bash
# Requires nightly Rust (cargo-fuzz uses compiler instrumentation)
rustup toolchain install nightly
cargo install cargo-fuzz
```

### Linux (Debian/Ubuntu)
```bash
rustup toolchain install nightly
cargo install cargo-fuzz

# Optional: for better crash analysis
sudo apt install llvm  # for llvm-symbolizer
```

## How to write a fuzz target

Create a file in `fuzz/fuzz_targets/`:

```rust
// fuzz/fuzz_targets/fuzz_sql_parser.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string (SQL parser expects strings)
    if let Ok(sql) = std::str::from_utf8(data) {
        // This should NEVER panic, regardless of input
        let _ = seal_sql::parse_sql(sql);
    }
});
```

## What fuzzing finds vs. formal methods

| | Fuzzing | Kani | Lean 4 / Rocq |
|---|---|---|---|
| **Input space** | Random subset (millions of inputs) | ALL inputs (bounded) | ALL inputs (unbounded) |
| **Finds** | Crashes, panics, hangs | Same + logical bugs | Mathematical incorrectness |
| **Effort** | Low (minutes to set up) | Low-Medium | High (weeks-months) |
| **Best for** | Parsers, deserializers, network input | Arithmetic, state transitions | Cryptographic properties |

Fuzzing and Kani are complementary:
- Kani proves "this function NEVER panics" (for bounded inputs)
- Fuzzing tests "I ran 10M random inputs and none crashed" (empirical)
- Together they give very high confidence

## Corpus management

Fuzzing builds a **corpus** of interesting inputs over time. Store it in git:
```
fuzz/
├── corpus/
│   └── fuzz_sql_parser/     ← Accumulated interesting inputs
├── artifacts/
│   └── fuzz_sql_parser/     ← Crash-triggering inputs (if found)
└── fuzz_targets/
    └── fuzz_sql_parser.rs   ← The fuzz target code
```

When a crash is found, the crashing input is saved in `artifacts/`.
Fix the bug, then add the crashing input to the corpus so it's tested forever.
