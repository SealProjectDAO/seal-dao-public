# Seal DAO — Benchmark Results

## Platform

- **CPU**: Apple Silicon (aarch64)
- **Rust**: 1.90.0 (stable)
- **OS**: macOS (Darwin 25.1.0)
- **Date**: 2026-03-19

## PQC Cryptography (libcrux — formally verified)

| Operation | Time | Ops/sec | Notes |
|-----------|------|---------|-------|
| ML-DSA-65 keygen | **6.74 ms** | 148 | Seed-deterministic (same seed → same keys) |
| ML-DSA-65 sign (256B msg) | **13.81 ms** | 72 | Includes random nonce generation |
| ML-DSA-65 verify (256B msg) | **5.69 ms** | 176 | Fastest crypto op |
| SHA3-256 (1KB) | **0.14 ms** | 7,143 | RustCrypto sha3 crate |

### Comparison: libcrux vs pqcrypto (previous)

| Operation | libcrux | pqcrypto | Improvement |
|-----------|---------|----------|-------------|
| Keygen | 6.74 ms | 7.80 ms | **14% faster** |
| Sign | 13.81 ms | 16.88 ms | **18% faster** |
| Verify | 5.69 ms | 8.30 ms | **31% faster** |
| SHA3 | 0.14 ms | 0.17 ms | **18% faster** |

libcrux (formally verified with hax + F*) is faster across all operations.

### Key/Signature Sizes

| Primitive | Size |
|-----------|------|
| ML-DSA-65 signing key | 4,032 bytes |
| ML-DSA-65 public key | 1,952 bytes |
| ML-DSA-65 signature | 3,309 bytes |
| ML-KEM-768 public key | 1,184 bytes |
| ML-KEM-768 secret key | 2,400 bytes |
| ML-KEM-768 ciphertext | 1,088 bytes |
| ML-KEM-768 shared secret | 32 bytes |
| SHA3-256 digest | 32 bytes |

## Throughput Estimates

### Transactions per second (single node, CPU)

| Bottleneck | Rate | Notes |
|------------|------|-------|
| ML-DSA verify (per tx) | ~176 tx/s | Each tx needs sig verification |
| SQL execution (per tx) | ~1,000+ tx/s | In-memory, very fast |
| Block production | ~20 blocks/s | Including signing + Merkle root |
| **Net throughput** | **~170 tx/s** | Limited by ML-DSA verify |

### Block timing budget (4-second slot)

| Phase | Budget | Actual |
|-------|--------|--------|
| VRF election | < 100 ms | ~7 ms (keygen) |
| Collect transactions | < 500 ms | — |
| SQL execution (100 txs) | < 100 ms | ~10 ms |
| Merkle state root | < 200 ms | ~5 ms |
| Block signing (ML-DSA) | < 200 ms | ~14 ms |
| Threshold signing (100 members) | < 2,000 ms | ~570 ms (100 × verify) |
| ZK proof generation | Async | 5-30s (future, GPU) |
| **Total** | **< 4,000 ms** | **~606 ms** (fits comfortably) |

## How to Run Benchmarks

```bash
# Run all benchmarks (takes ~2-3 minutes due to SQL INSERT test)
cargo test -p seal-node --lib -- bench --nocapture

# Run specific benchmark
cargo test -p seal-node --lib -- bench_ml_dsa_sign --nocapture
```

## Future Benchmarks (TODO)

- [ ] Multi-node block propagation latency
- [ ] P2P message throughput
- [ ] Merkle proof generation/verification
- [ ] Encrypted wallet save/load
- [ ] ZK proof generation (when RISC Zero integrated)
- [ ] GPU proving speed (CUDA RTX 4090, Apple M4)
