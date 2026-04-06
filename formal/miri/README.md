# Miri — Undefined Behavior Detection for Rust

## What is Miri?

Miri is Rust's **official interpreter** that detects **undefined behavior** (UB)
at runtime. It ships with rustup and runs your existing test suite — no code
changes needed.

UB in Rust is rare (the type system prevents most of it), but it can happen in:
- `unsafe` blocks (raw pointer dereference, transmute, FFI)
- Incorrect `Pin` usage
- Data races in concurrent code

Miri catches these bugs by interpreting the MIR (Mid-level Intermediate
Representation) with extra checks that the real compiler optimizes away.

## What Miri catches

| Bug class | Example |
|-----------|---------|
| Use after free | Dereferencing a dangling pointer |
| Out-of-bounds access | `*ptr.offset(100)` past allocation |
| Misaligned access | Reading a `u32` from an odd address |
| Aliasing violations | Two `&mut` to the same memory (Stacked/Tree Borrows) |
| Data races | Concurrent non-atomic access |
| Invalid values | `bool` that isn't 0 or 1, null references |
| Memory leaks | (with `-Zmiri-leak-check`) |

## Where it runs

Miri runs on **all existing Rust tests** — no annotations needed.
It's most valuable for crates with `unsafe` code or FFI.

**Priority crates for Miri in Seal:**

| Crate | Why |
|-------|-----|
| `seal-crypto` | Wraps C FFI (pqcrypto-dilithium, pqcrypto-kyber). Pointer handling in zeroize. |
| `seal-merkle` | Content-addressed storage with hash-based references. |
| `seal-storage` | sled FFI, serialization edge cases. |

## How to run

```bash
# macOS:
rustup +nightly component add miri
cargo +nightly miri test -p seal-crypto

# Run on all crates:
cargo +nightly miri test

# With extra checks:
MIRIFLAGS="-Zmiri-leak-check" cargo +nightly miri test -p seal-crypto

# Linux (Debian/Ubuntu):
rustup toolchain install nightly
rustup +nightly component add miri
cargo +nightly miri test
```

## Installation

### macOS
```bash
rustup toolchain install nightly
rustup +nightly component add miri
```

### Linux (Debian/Ubuntu)
```bash
rustup toolchain install nightly
rustup +nightly component add miri
```

That's it — Miri ships with rustup. No external dependencies.

## Limitations

- **Slow**: 10-100x slower than normal test execution.
- **One execution**: Only checks the specific test inputs, not all inputs
  (unlike Kani). Combine with fuzzing for better coverage.
- **FFI**: Cannot interpret C code. Some FFI-heavy crates need stubs.
- **Concurrency**: Supports threads but may miss some weak-memory behaviors.

## Relationship to other tools

- **Kani** proves properties for ALL inputs; Miri checks ONE execution deeply.
- **cargo-fuzz** generates many random inputs; Miri checks each for UB.
- Best used together: fuzz to find crash inputs, Miri to detect UB on tests.
