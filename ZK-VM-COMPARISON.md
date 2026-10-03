# ZK Virtual Machine Comparison for Seal DAO

## Decision: Which zkVM for block proof generation?

Seal needs a zkVM to prove state transitions (SQL ops + Merkle state diffs).
The proof system must be **PQ-secure** (no Groth16/SNARK wrapper).

## Comparison Table

| | **RISC Zero** | **SP1 (Succinct)** | **OpenVM (Axiom)** | **Jolt (a16z)** |
|---|---|---|---|---|
| **ISA** | RV32IM | RISC-V | RISC-V (modular) | RV64IMAC |
| **Proof system** | STARK + optional Groth16 | STARK (Plonky3) + optional Groth16 | STARK (Plonky3) + optional SNARK | Sumcheck/Lasso |
| **Guest language** | Rust, C, C++ | Rust, any LLVM | Rust | Rust |
| **License** | Apache 2.0 | MIT/Apache 2.0 | MIT/Apache 2.0 | MIT/Apache 2.0 |
| **Maturity** | Production (Boundless mainnet) | Production (used by Optimism, Arbitrum) | Production (audited) | Alpha |
| **Formally verified** | Yes (Veridise) | Yes (Veridise, Cantina) | Yes (Cantina) | No |
| **ETH block prove time** | ~44s (R0VM 2.0) | <12s (16×5090 GPU) | 15s GPU (v1.4) | N/A |
| **CPU proving** | Yes | Yes | Yes | Yes (1M+ cycles/sec) |
| **GPU proving** | Yes | Yes (Hypercube) | Yes (SWIRL) | In development |
| **Proof size (STARK only)** | ~200 KB | ~150-300 KB | Sub-300 KB | ~50 KB |
| **Proof size (with SNARK)** | ~260 bytes | ~260 bytes | N/A | Planned |
| **Recursion** | Yes (STARK-to-STARK) | Yes | Yes | In development |
| **On-chain EVM verify** | Yes (Groth16, 300K gas) | Yes (Groth16) | Yes (SNARK) | Planned |
| **Custom precompiles** | Limited | Yes (5-10x speedup) | Yes (modular extensions) | N/A |

## PQC Security Analysis

**Critical question**: Is the proof system post-quantum secure?

| | STARK (core) | Groth16 wrapper | Net PQ security |
|---|---|---|---|
| **RISC Zero** | ✅ PQ-secure (hash-based) | ❌ NOT PQ (elliptic curve) | ⚠️ PQ only WITHOUT wrapper |
| **SP1** | ✅ PQ-secure | ❌ NOT PQ | ⚠️ PQ only WITHOUT wrapper |
| **OpenVM** | ✅ PQ-secure | ❌ NOT PQ | ⚠️ PQ only WITHOUT wrapper |
| **Jolt** | ⚠️ Sumcheck uses polynomial commitments | N/A | ⚠️ Depends on commitment scheme |

**For Seal**: We MUST use STARK proofs WITHOUT the Groth16/SNARK wrapper.
This means ~200 KB proofs instead of ~260 bytes, but maintains PQ security.
On our own L1, this is fine (no EVM calldata costs).

**Jolt concern**: Jolt's sumcheck-based approach uses polynomial commitments
that may not be PQ-secure depending on the commitment scheme. Needs investigation.

## Performance: zkVM vs Native Runtime

Based on published benchmarks (2025-2026):

| Operation | Native | RISC Zero | SP1 | Overhead |
|-----------|--------|-----------|-----|----------|
| SHA-256 (1KB) | ~1 μs | ~10 ms | ~8 ms | ~10,000x |
| Ed25519 verify | ~50 μs | ~500 ms | ~400 ms | ~10,000x |
| Fibonacci(1000) | ~1 μs | ~100 ms | ~80 ms | ~100,000x |
| Simple state transition | ~1 ms | ~5-10s | ~3-8s | ~5,000x |
| Ethereum block | ~100 ms | ~44s | ~12s (GPU) | ~100-400x |

**Key insight**: zkVMs are 1,000-100,000x slower than native execution.
This is expected — you're generating a mathematical proof of correctness.

**For Seal**: A block with 10 SQL transactions takes ~1ms natively.
In a zkVM, this would take ~5-30 seconds. With a 4-second slot time,
we need either:
1. **Optimistic**: Produce blocks without proof, generate proof async
2. **Pipelined**: Start proving block N while producing block N+1
3. **GPU acceleration**: SP1/OpenVM with GPUs can prove in <10s

## Seal-Specific Requirements

| Requirement | RISC Zero | SP1 | OpenVM | Jolt |
|-------------|-----------|-----|--------|------|
| Rust guest program | ✅ | ✅ | ✅ | ✅ |
| SHA3-256 in guest | ✅ | ✅ (precompile) | ✅ | ✅ |
| ML-DSA verify in guest | ⚠️ Large circuit | ⚠️ Large circuit | ⚠️ Large circuit | ⚠️ |
| Merkle tree ops in guest | ✅ | ✅ | ✅ | ✅ |
| SQL execution in guest | ✅ (any Rust) | ✅ | ✅ | ✅ |
| PQ-secure proof | ✅ (STARK only) | ✅ (STARK only) | ✅ (STARK only) | ⚠️ |
| Apache 2.0 license | ✅ | ✅ | ✅ | ✅ |

**ML-DSA concern**: Verifying ML-DSA-65 signatures inside a zkVM is expensive
(~148K R1CS constraints per signature). With 100 transactions per block,
this dominates proving time. Options:
1. Verify sigs outside the ZK proof (validators verify sigs separately)
2. Use a SNARK-friendly PQ signature (CAPSS, Loquat) for in-circuit verification
3. Batch signature verification

## Recommendation

**Primary: RISC Zero**
- Most mature, formally verified, Apache 2.0
- Best documentation and tooling
- STARK proofs are PQ-secure (our requirement)
- Already prototyped in SealTests/risc0-test0

**Alternative: SP1**
- Faster proving (especially with GPU)
- Same RISC-V ISA, same Rust guest — drop-in replacement
- Better precompile system for crypto ops

**Not recommended for launch:**
- OpenVM: Strong but newer, less documentation
- Jolt: Alpha, PQ security unclear, no recursion yet

**Implementation strategy:**
1. Define a `ZkProver` trait (already done)
2. Implement RISC Zero backend first
3. Keep SP1 as a drop-in alternative behind the same trait
4. Prove SQL state transitions (not ML-DSA sigs — verify sigs outside circuit)

## Cost Estimates (2026 pricing)

| zkVM | CPU proving (per block) | GPU proving (per block) | Cloud cost |
|------|------------------------|------------------------|------------|
| RISC Zero | ~30-60s | ~5-15s | ~$0.01-0.05 |
| SP1 | ~20-40s | ~3-10s | ~$0.005-0.03 |
| OpenVM | ~20-40s | ~3-10s | ~$0.005-0.03 |

These estimates are for a Seal block with ~10 SQL transactions and Merkle state diff.
Actual costs depend on circuit complexity (number of RISC-V cycles).

## Decision: Trait-Based Dual Backend

**Primary: RISC Zero** → correctness-first, formally verified
**Secondary: SP1** → performance upgrade path, better GPU acceleration

Both implement the same `ZkProver` trait. Swap is transparent.

## Target GPUs for Proving Acceleration

| GPU | Type | VRAM | Expected Proving Speed | Notes |
|-----|------|------|----------------------|-------|
| **RTX 3080** | CUDA (Ampere) | 10 GB | ~15-30s/block | Entry-level prover |
| **RTX 4090** | CUDA (Ada) | 24 GB | ~5-15s/block | Sweet spot price/perf |
| **RTX 5090** | CUDA (Blackwell) | 32 GB | ~3-10s/block | SP1 Hypercube target |
| **RTX 6000 Blackwell** | CUDA (pro) | 48 GB | ~2-8s/block | Data center / high-end |
| **Apple M3** | Metal (integrated) | Shared | ~30-60s/block | Development / light nodes |
| **Apple M4** | Metal (integrated) | Shared | ~20-40s/block | Better Neural Engine |
| **Apple M5** | Metal (integrated) | Shared | ~15-30s/block | Expected 2026 |

**CUDA status:**
- RISC Zero: GPU proving supported (CUDA)
- SP1: GPU proving supported (CUDA, Hypercube optimized for multi-GPU)

**Apple Silicon status:**
- RISC Zero: CPU-only on macOS (no Metal GPU acceleration yet)
- SP1: CPU-only on macOS (Metal backend in development)

**Note**: Apple Silicon M-series GPUs use Metal, not CUDA. GPU proving on
Mac currently falls back to CPU. Both RISC Zero and SP1 prioritize CUDA.
For local development/testing on Mac, CPU proving is sufficient (~30-60s).
Production provers should use CUDA GPUs.
