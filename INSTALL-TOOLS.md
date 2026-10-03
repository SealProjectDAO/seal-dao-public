# Seal DAO — Tool Installation Guide

## Already Installed (your system)

| Tool | Version | Status |
|------|---------|--------|
| Rust (stable) | 1.90.0 | Ready |
| Rust (nightly) | 1.96.0 | Ready |
| cargo-kani | installed | Ready (no nightly needed) |
| cargo-audit | installed | Ready |
| cargo-fuzz | installed | Ready (needs nightly) |
| Rocq/Coq | 9.1.1 | Ready — proofs compile |
| Lean 4 (elan) | 4.28.0 | Ready (source ~/.elan/env) |
| Docker + colima | installed | Ready |
| Java 17 | openjdk 17.0.18 | Ready (needed for Apalache) |

## Not Installed

### Apalache (TLA+ model checker)

Not on Homebrew. Install manually:

```bash
# Download latest release (requires Java, which you have)
curl -L https://github.com/apalache-mc/apalache/releases/latest/download/apalache.tgz \
  -o /tmp/apalache.tgz

# Extract
sudo mkdir -p /opt/apalache
sudo tar xzf /tmp/apalache.tgz -C /opt/apalache --strip-components=1

# Add to PATH
echo 'export PATH="/opt/apalache/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Verify
apalache-mc version

# Run on our consensus spec
apalache-mc check --inv=Agreement formal/tlaplus/SealConsensus.tla
```

**Alternative** (no install, run directly):
```bash
# Run via Java JAR directly
java -jar /opt/apalache/lib/apalache.jar check \
  --inv=Agreement formal/tlaplus/SealConsensus.tla
```

---

## How to Run Each Tool

### Tools that DON'T need nightly Rust

```bash
# 1. Cargo test (stable Rust)
cargo test

# 2. Kani — bounded model checking (own toolchain, not nightly)
cargo kani -p seal-crypto
cargo kani -p seal-merkle
cargo kani -p seal-token
cargo kani -p seal-bridge
cargo kani -p seal-consensus

# 3. cargo-audit — CVE scanning
cargo audit

# 4. Rocq/Coq — formal proofs
cd formal/rocq
coq_makefile -f _CoqProject -o Makefile
make
cd ../..

# 5. Lean 4 — formal proofs
source ~/.elan/env   # Make lean available
cd formal/lean
lake build
cd ../..

# 6. Apalache — TLA+ model checking (after install above)
apalache-mc check --inv=Agreement formal/tlaplus/SealConsensus.tla
apalache-mc check --inv=NoEquivocation formal/tlaplus/SealConsensus.tla

# 7. Clippy — lint
cargo clippy --all-targets

# 8. Format check
cargo fmt --all -- --check

# 9. Docker — multi-node testnet
docker build -t seal-node .
docker-compose up
```

### Tools that NEED nightly Rust

```bash
# 10. cargo-fuzz — fuzzing (needs nightly as default)
rustup default nightly
cd fuzz
cargo fuzz run fuzz_sql_parser -- -max_total_time=60
cargo fuzz run fuzz_address_parse -- -max_total_time=60
cargo fuzz run fuzz_vrf_verify -- -max_total_time=60
cargo fuzz run fuzz_block_deserialize -- -max_total_time=60
cd ..
rustup default stable   # Switch back

# 11. Miri — UB detection (needs full nightly with rust-src)
rustup +nightly component add miri rust-src
cargo +nightly miri test -p seal-crypto
```

---

## Quick Reference: What Proves What

| Tool | What it checks | Nightly? | Install effort |
|------|---------------|----------|----------------|
| `cargo test` | Logic correctness (292 tests) | No | Already installed |
| `cargo kani` | No panics/overflow for ALL inputs | No | `cargo install kani-verifier` |
| `cargo audit` | Known CVEs in dependencies | No | `cargo install cargo-audit` |
| `coqc` (Rocq) | Token conservation, state machine | No | `brew install coq` |
| `lean` (Lean 4) | Hash properties, Merkle invariants | No | Install elan |
| `apalache-mc` | Consensus safety/liveness | No | Download JAR (see above) |
| `cargo clippy` | Code quality | No | Included with Rust |
| `cargo fuzz` | No crashes on random input | **Yes** | `cargo install cargo-fuzz` |
| `cargo miri` | No undefined behavior | **Yes** | `rustup +nightly component add miri` |

---

## Full CI Script (uses only stable tools)

```bash
./scripts/ci.sh       # test + clippy + fmt + audit
./scripts/ci.sh quick # tests only
```

## Full Verification Script (includes all tools)

```bash
./scripts/verify.sh   # test + clippy + miri + audit + kani
```
