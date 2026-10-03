# Phase 4 — Heavy Dependencies Setup Guide

## 1. RISC Zero (ZK Proofs)

### Install
```bash
# Install RISC Zero toolchain
cargo install cargo-risczero
cargo risczero install

# Build the guest program
cargo risczero build --manifest-path crates/seal-zk/guest/Cargo.toml

# Build seal-zk with RISC Zero backend
cargo build -p seal-zk --features risc0
```

### What to do
1. Uncomment risc0-zkvm dependency in `crates/seal-zk/Cargo.toml`
2. Uncomment guest program code in `crates/seal-zk/guest/src/main.rs`
3. Implement `RiscZeroProver::prove()` in `crates/seal-zk/src/risc0.rs`
4. Load guest ELF, create executor env, generate STARK proof

### Estimated size
- `risc0-zkvm` crate: ~2GB download (includes RISC-V toolchain)
- Guest compilation: ~30s
- Proof generation: ~30-60s CPU, ~5-15s GPU

---

## 2. SP1 (Alternative ZK Proofs)

### Install
```bash
# Install SP1 toolchain
curl -L https://sp1.succinct.xyz | bash
sp1up

# Build with SP1 backend
cargo build -p seal-zk --features sp1
```

### What to do
1. Add `sp1-sdk = "3"` to seal-zk Cargo.toml (behind feature)
2. Reuse the same guest program (SP1 uses RISC-V ISA)
3. Implement `Sp1Prover::prove()` in `crates/seal-zk/src/sp1.rs`

---

## 3. Ringtail (Lattice Threshold Signatures)

### Source
- Paper: ePrint 2024/1113
- Code: https://github.com/daryakaviani/ringtail

### What to do
1. Port the Rust implementation to `crates/seal-threshold/src/ringtail.rs`
2. Implement `ThresholdScheme` trait
3. Key changes from SimpleThreshold:
   - 2-round interactive protocol (Round 1 preprocessable)
   - Output: ~13.4 KB threshold signature (vs N × 3.3 KB)
   - Security: LWE-based (post-quantum)
4. Benchmark: target 100-member signing within 2s over WAN

### Dependencies
- NTT polynomial arithmetic
- Module-LWE sampling
- Likely needs custom implementation (no crate available)

---

## 4. LB-VRF (Lattice VRF)

### Source
- Paper: ePrint 2020/1222 (Esgin et al., FC 2021)
- Code: https://github.com/zhenfeizhang/lb-vrf

### What to do
1. Port to `crates/seal-vrf/src/lattice_vrf.rs`
2. Implement `Vrf` trait (same interface as HmacVrf)
3. Add per-epoch key rotation (few-time VRF limitation)
4. Key changes from HmacVrf:
   - VRF output: 84 bytes (vs 32 bytes)
   - Proof size: ~5 KB (vs 64 bytes)
   - Security: Module-LWE/SIS (post-quantum)
5. Needs: NTT acceleration, memory zeroization, security audit

### Dependencies
- Same NTT library as Ringtail (share code)
- Likely needs custom implementation

---

## 5. Solana Bridge (Anchor)

### Install
```bash
# Install Solana CLI + Anchor
sh -c "$(curl -sSfL https://release.solana.com/v1.18.0/install)"
cargo install --git https://github.com/coral-xyz/anchor anchor-cli
```

### What to do
1. Create Anchor program in `contracts/solana/`
2. Lock contract: users lock SOL/SPL tokens
3. Seal validators observe via Solana RPC
4. Threshold signature releases locked tokens

---

## 6. Stellar Bridge (Soroban)

### Install
```bash
# Install Stellar CLI
cargo install --locked soroban-cli
```

### What to do
1. Create Soroban contract in `contracts/stellar/`
2. Lock contract for XLM/USDC
3. Same observer + threshold release pattern as Solana

---

## Priority Order

1. **RISC Zero** — most impactful (real ZK proofs)
2. **LB-VRF** — needed for PQ consensus
3. **Ringtail** — needed for efficient committee sigs
4. **SP1** — performance upgrade (after RISC Zero works)
5. **Solana bridge** — first cross-chain
6. **Stellar bridge** — second cross-chain
