# CLAUDE.md — Seal DAO Development Conventions

## Project overview

Seal DAO is a PQC-native L1 blockchain with a distributed SQL database layer.
Written in Rust. See SPEC.md for the full technical specification.

## Repository structure

- `crates/` — Rust workspace with 17 crates (seal-crypto, seal-sql, seal-mpc, etc.)
- `formal/` — Formal verification (TLA+, Lean 4, Rocq, Kani, Miri, fuzz)
- `fuzz/` — cargo-fuzz targets
- `scripts/` — CI and verification scripts
- `audits/` — External audit scope documents (Veridise PQC, protocol)
- `SPEC.md` — Technical specification
- `GOVERNANCE.md` — Governance specification
- `CONSENSUS-COMPARISON.md` — Consensus protocol analysis
- `FORMAL-METHODS.md` — Formal methods plan and tool survey
- `SECURITY.md` — Threat model and security documentation
- `BUG-BOUNTY.md` — Immunefi bug bounty program
- `TESTNET.md` — Incentivized testnet program
- `LAUNCH-CHECKLIST.md` — Mainnet launch checklist

## Build and test

```bash
cargo build            # Build all crates
cargo test             # Run all 215+ tests
cargo run -p seal-node # Run single-node prototype
cargo run -p seal-cli -- demo  # Run interactive demo
```

## CI scripts (no GitHub Actions)

CI is manual via shell scripts. No GitHub Actions workflows.

```bash
./scripts/ci.sh          # Full CI: build, test, clippy, Kani, Miri, fuzz, audit
./scripts/ci.sh quick    # Quick: build + test + clippy only
./scripts/ci-nightly.sh  # Nightly: ci.sh + extended fuzz (5min/target) + Lean 4 + Rocq
./scripts/ci-formal.sh   # Formal verification pipeline (7 steps)
./scripts/verify.sh      # Quick verification subset
./scripts/fuzz-all.sh    # All 10 fuzz targets (configurable duration)
./scripts/fuzz-extended.sh 3600  # Pre-release fuzz campaign (1hr/target)
```

## Coding conventions

- **PostgreSQL-compatible SQL**: The SQL dialect is a subset of PostgreSQL.
  MySQL support is secondary.
- **PQC first**: All cryptographic operations use post-quantum algorithms
  (ML-DSA, ML-KEM, SHA3). Classical crypto only in bridge modules.
- **Checked arithmetic**: Use `checked_add`, `checked_sub`, `saturating_mul`
  for all token/balance operations. Never use unchecked arithmetic on money.
- **Zeroize secrets**: All secret key material must implement `Zeroize` and
  be dropped correctly. Use the `zeroize` crate.
- **Trait-based stubs**: New crypto primitives (VRF, threshold sigs, ZK proofs)
  use traits with stub implementations. The real implementation is a drop-in
  replacement behind the same trait.
- **Kani harnesses**: Critical functions get `#[cfg(kani)]` proof harnesses.
  These live in the same file as the code they verify.
- **No `.unwrap()` / `.expect()` in production code**: Always handle errors
  with `match`, `if let`, `?`, or `unwrap_or`. `.unwrap()` is only acceptable
  in `#[cfg(test)]` blocks. Production code must never panic on recoverable
  errors — propagate with `?` or handle gracefully.
- **Commit often**: Small, focused commits with descriptive messages.

## Key design decisions

- Algorand-style consensus (VRF + committee voting), not HotStuff
- STARK proofs without SNARK wrapper (preserves PQ security)
- Ringtail threshold signatures for committee (not BLS)
- Burn-and-mint token economics
- Row-level security (PostgreSQL-style CREATE POLICY)
- Three-body governance (Token House + Technical Council + Service Operators)

## Formal methods

Each formal method tool has a directory in `formal/` with a README explaining:
- WHAT the tool does
- WHY we use it
- WHERE the specs/harnesses live
- HOW to install and run

See `formal/README.md` for the overview.
