# Contributing to Seal DAO

## Getting Started

```bash
# Clone
git clone git@github.com:SealProjectDAO/seal-dao-master.git
cd seal-dao-master

# Build
cargo build

# Test
cargo test

# Run node
cargo run -p seal-node -- --no-network

# Run REPL
cargo run -p seal-app
```

## Project Structure

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full crate dependency graph.

Key directories:
- `crates/` — 16 Rust crates (the code)
- `formal/` — Formal verification (TLA+, Lean 4, Rocq, Kani, Miri, fuzz)
- `fuzz/` — Fuzz targets
- `scripts/` — CI and verification scripts

## How to Add a New Feature

### 1. Add to an existing crate

Most features go in `seal-node` (integration) or the relevant domain crate.

```bash
# Create a new module
touch crates/seal-node/src/my_feature.rs

# Add to lib.rs
echo "pub mod my_feature;" >> crates/seal-node/src/lib.rs

# Write tests in the same file
# (see any existing module for the pattern)
```

### 2. Add tests

Every module must have tests. Put them in the same file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_feature() {
        // ...
    }
}
```

### 3. Add Kani harnesses (for critical code)

```rust
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn my_property() {
        let x: u64 = kani::any();
        // Prove property for ALL possible x
    }
}
```

### 4. Run checks before committing

```bash
cargo test                    # All tests pass
cargo clippy --all-targets    # Zero warnings
cargo fmt --all -- --check    # Formatted
```

Or use the CI script:
```bash
./scripts/ci.sh quick   # Tests only
./scripts/ci.sh          # Full checks
```

## Coding Conventions

See [CLAUDE.md](CLAUDE.md) for full conventions. Key points:

- **PostgreSQL-compatible SQL** — subset of PG, not a custom dialect
- **PQC first** — ML-DSA, ML-KEM, SHA3 everywhere
- **Checked arithmetic** — `checked_add`, `saturating_mul` on money
- **Zeroize secrets** — all secret keys implement `Zeroize`
- **Trait-based stubs** — new crypto uses traits with stub + future real impl
- **Commit often** — small, focused commits

## Formal Verification

See [FORMAL-METHODS.md](FORMAL-METHODS.md) for the full plan.
See [formal/README.md](formal/README.md) for tool-specific instructions.
See [TESTING.md](TESTING.md) for the test inventory.

## Key Files

| File | What it is |
|------|-----------|
| `SPEC.md` | Full technical specification |
| `GOVERNANCE.md` | Governance specification |
| `CONSENSUS-COMPARISON.md` | Consensus protocol analysis |
| `FORMAL-METHODS.md` | Formal methods plan |
| `ARCHITECTURE.md` | Crate dependency graph + data flow |
| `TESTING.md` | All 270+ tests documented |
| `CLAUDE.md` | Dev conventions |
