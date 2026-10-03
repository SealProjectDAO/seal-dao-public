# Phase 4 — External Dependencies Setup

These items are blocked on external tools/libraries. This document provides
exact installation steps and what to do once each dependency is available.

## 1. Ringtail Threshold Signatures

**Status:** Trait + SimpleThreshold delegation ready. Needs lattice crypto port.
**Source:** https://github.com/daryakaviani/ringtail (ePrint 2024/1113)
**Language:** Rust (~90%)

```bash
# Clone reference implementation
git clone https://github.com/daryakaviani/ringtail /tmp/ringtail
cd /tmp/ringtail && cargo build

# Port into Seal:
# 1. Copy core NTT/polynomial arithmetic into crates/seal-threshold/src/ringtail.rs
# 2. Implement ThresholdScheme trait methods:
#    - partial_sign() → LWE-based partial signature
#    - aggregate() → Combine partials into single ~13.4 KB sig
#    - verify() → Verify aggregated threshold signature
# 3. Add Round 1 preprocessing (message-independent, run during previous slot)
# 4. Add Round 2 on critical path (~800ms with preprocessing)
# 5. Zeroize all secret material on drop
# 6. Add Lean 4 proof: t-of-n security
```

**Integration point:** `crates/seal-threshold/src/ringtail.rs` (currently delegates to SimpleThreshold)

## 2. LB-VRF (Lattice-Based VRF)

**Status:** PqVrf works for production. LB-VRF is optional upgrade.
**Source:** https://github.com/zhenfeizhang/lb-vrf (Esgin et al., FC 2021)
**Language:** Rust (~90%)

```bash
# Clone reference implementation
git clone https://github.com/zhenfeizhang/lb-vrf /tmp/lb-vrf
cd /tmp/lb-vrf && cargo build

# Port into Seal:
# 1. Copy NTT polynomial arithmetic into crates/seal-vrf/src/lattice_vrf.rs
# 2. Implement Vrf trait methods:
#    - keygen() → Module-LWE keypair
#    - eval() → 84-byte output + ~5 KB proof
#    - verify() → ZK verification
# 3. Add per-epoch key rotation (few-time VRF limitation)
#    → VrfKeyManager already handles this
# 4. Zeroize all secret material
# 5. Add Lean 4 proofs: uniqueness, pseudorandomness, verifiability
```

**Integration point:** `crates/seal-vrf/src/lattice_vrf.rs` (currently delegates to HmacVrf)

## 3. RISC Zero ZK Backend

**Status:** Stub prover + batch proving ready. Guest program written.
**Requires:** `risc0-zkvm` crate (~2 GB download)

```bash
# Install RISC Zero toolchain
curl -L https://risczero.com/install | bash
rzup install

# Add dependency to crates/seal-zk/Cargo.toml:
# [dependencies]
# risc0-zkvm = { version = "1.0", features = ["prove"], optional = true }
#
# [features]
# risc0 = ["dep:risc0-zkvm"]

# Build guest program for RISC-V
cargo risczero build --manifest-path crates/seal-zk/guest/Cargo.toml

# Build with RISC Zero feature
cargo build -p seal-zk --features risc0

# The guest/src/main.rs is already written — just needs:
# 1. Uncomment #![no_main] and risc0_zkvm::guest::entry!(main)
# 2. Uncomment env::read() and env::commit() calls
# 3. Wire InMemoryState to use seal-sql engine compiled for RISC-V
```

**Integration point:** `crates/seal-zk/src/risc0.rs` (has `todo!()` behind `#[cfg(feature = "risc0")]`)

**GPU acceleration:**
```bash
# CUDA (RTX 3080+)
cargo build -p seal-zk --features risc0 --features cuda

# Apple Silicon (CPU only, ~30-60s per block)
cargo build -p seal-zk --features risc0
```

## 4. SP1 ZK Backend

**Status:** Stub prover ready.
**Requires:** `sp1-sdk` crate

```bash
# Install SP1 toolchain
curl -L https://sp1.succinct.xyz | bash
sp1up

# Add dependency to crates/seal-zk/Cargo.toml:
# [dependencies]
# sp1-sdk = { version = "3", optional = true }
#
# [features]
# sp1 = ["dep:sp1-sdk"]

# Build with SP1 feature
cargo build -p seal-zk --features sp1

# Same guest program works (SP1 uses same RISC-V ISA)
```

**Integration point:** `crates/seal-zk/src/sp1.rs` (has `todo!()` behind `#[cfg(feature = "sp1")]`)

## 5. Solana Bridge Deployment

**Status:** Full LockProgram with multisig ready. Needs Anchor + devnet.

```bash
# Install Solana CLI
sh -c "$(curl -sSfL https://release.solana.com/v1.18.0/install)"
solana config set --url devnet

# Install Anchor
cargo install --git https://github.com/coral-xyz/anchor anchor-cli

# Create devnet wallet
solana-keygen new --outfile ~/.config/solana/devnet.json
solana airdrop 2

# Deploy
cd contracts/solana
anchor init seal-lock  # Creates full Anchor project
# Copy logic from contracts/solana/programs/seal-lock/src/lib.rs
anchor build
solana program deploy target/deploy/seal_lock.so
```

## 6. Stellar Bridge Deployment

**Status:** Full StellarLockContract with multisig ready. Needs Soroban CLI.

```bash
# Install Soroban CLI
cargo install --locked soroban-cli

# Configure testnet
soroban config network add testnet \
  --rpc-url https://soroban-testnet.stellar.org:443 \
  --network-passphrase "Test SDF Network ; September 2015"

# Create testnet identity
soroban config identity generate alice

# Deploy
cd contracts/stellar
soroban contract build
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/seal_lock.wasm \
  --network testnet --source alice
```

## 7. cargo-fuzz Execution

**Status:** 7 targets written. Needs nightly Rust.

```bash
# Install
rustup install nightly
cargo +nightly install cargo-fuzz

# Run all targets (60s each)
./scripts/fuzz-all.sh 60

# Run specific target
cargo +nightly fuzz run fuzz_merkle_ops -- -max_total_time=300

# See FUZZING.md for full documentation
```
