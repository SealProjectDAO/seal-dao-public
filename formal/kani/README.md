# Kani — Bounded Model Checking for Rust

## What is Kani?

Kani is an **automated verification tool** for Rust backed by AWS. It uses
**bounded model checking** (CBMC under the hood) to exhaustively check all
possible inputs up to a bound.

Unlike testing (which checks specific inputs), Kani checks ALL possible values:
```rust
#[kani::proof]
fn no_panic_on_any_input() {
    let x: u64 = kani::any();   // Symbolic: represents ALL possible u64 values
    let y: u64 = kani::any();
    // Kani will verify this for all 2^128 combinations of (x, y)
    let result = x.checked_add(y);
    // If we used x + y instead, Kani would find the overflow
}
```

## Where are the harnesses?

Kani harnesses live **in the Rust source code** under `#[cfg(kani)]` blocks.
They compile only when running `cargo kani`, not during normal builds.

| File | What is verified |
|------|------------------|
| `crates/seal-crypto/src/hash.rs` | SHA3-256 never panics on any input ≤256B; determinism; Hash256 ordering consistency; incremental hasher matches direct |
| `crates/seal-merkle/src/tree.rs` | Insert-get roundtrip for any 4-byte key/value; root changes on distinct inserts; delete removes key |
| `crates/seal-token/src/balance.rs` | Credit-debit roundtrip preserves balance; stake-unstake preserves total; debit never underflows |

## How to run

```bash
# Install Kani (one-time):
cargo install --locked kani-verifier
cargo kani setup

# Run on a specific crate:
cargo kani -p seal-crypto
cargo kani -p seal-merkle
cargo kani -p seal-token

# Run a specific harness:
cargo kani -p seal-crypto --harness sha3_256_no_panic
```

## How to write a new harness

```rust
// In any Rust source file, add:
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(5)]  // Optional: bound loop unrolling
    fn my_property() {
        let input: u32 = kani::any();
        kani::assume(input < 1000);  // Optional: constrain input
        let result = my_function(input);
        assert!(result.is_ok());     // Property to verify
    }
}
```

## What Kani can and cannot prove

**Can prove** (for bounded inputs):
- No panics (array OOB, unwrap on None, integer overflow)
- Functional properties (postconditions, invariants)
- Absence of assertion failures

**Cannot prove**:
- Properties over unbounded loops (without loop invariants)
- Concurrency properties (single-threaded only)
- Termination / liveness
- Properties of external C code (FFI)

## Relationship to other formal methods

Kani is the **lowest-effort, highest-ROI** verification tool. Use it first
on every critical function. For deeper properties (mathematical proofs,
protocol liveness), use Lean 4 or TLA+.
