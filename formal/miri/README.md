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

## Vendored-registry blocker — resolved 2026-04-19

`.cargo/config.toml` redirects `crates-io` → `vendor/` for
reproducible builds. Miri builds its own `std` sysroot on first run,
and std's Cargo.lock pins exact versions of transitive deps
(`cfg-if`, `hashbrown`, …) which may or may not match the versions
we have vendored. Symptom with nightly-2025-09-01 std wanting
`cfg-if 1.0.1` vs our vendored `cfg-if 1.0.4`:

```
failed to build sysroot: failed to select a version for the requirement
  `cfg-if = "^1.0"` (locked to 1.0.1); candidate versions found which
  didn't match: 1.0.4
perhaps a crate was updated and forgotten to be re-vendored?
```

**Fix**: `scripts/ci-formal.sh` step 4 now moves `.cargo/config.toml`
aside for the duration of the Miri step (via `miri_pushd_no_vendor` /
`miri_popd_restore` helpers, plus a `trap EXIT` so a failed run
doesn't leave the project in the hidden state). That lets Miri pull
whatever std's Cargo.lock wants from the real registry.

**Manual invocation** (when running Miri outside the CI script):

```bash
mv .cargo/config.toml .cargo/config.toml.hidden
MIRIFLAGS="-Zmiri-disable-isolation" \
    PATH=~/.rustup/toolchains/nightly-.../bin:$PATH \
    cargo miri test -p seal-merkle --lib
mv .cargo/config.toml.hidden .cargo/config.toml
```

Validated 2026-04-19: `cargo miri test -p seal-merkle` green —
35 tests, no UB, 210 s wall-clock (Miri is 10-100× slower than
native).

## Coverage target (script: `scripts/ci-formal.sh` step 4)

Two disjoint groups:

**A. Crates containing `unsafe`** — genuine Miri targets.

| Crate | ARM64 | Why it matters |
|-------|-------|----------------|
| `seal-vrf` | runs | one `unsafe` block for perf hot path |
| `seal-crypto` | skipped | pqcrypto-* FFI — Miri can't interpret C |
| `seal-storage` | skipped | sled FFI — Miri can't interpret C |

**B. Pure-safe data-structure crates** — regression guard (added
2026-04-18). No `unsafe` today, but we want Miri-clean so the day one
is introduced, the new code is checked end-to-end.

- `seal-merkle` — B-tree; proptest already covers correctness, Miri
  catches any future raw-pointer shortcut.
- `seal-token` — balance/emission arithmetic; light but valuable.
- `seal-threshold` — NTT + Ringtail; `subtle`/`zeroize` buffer handling.
- `seal-mpc` — SPDZ shares; `Drop` + `Zeroize` plumbing we just added.

## Relationship to other tools

- **Kani** proves properties for ALL inputs; Miri checks ONE execution deeply.
- **cargo-fuzz** generates many random inputs; Miri checks each for UB.
- Best used together: fuzz to find crash inputs, Miri to detect UB on tests.
