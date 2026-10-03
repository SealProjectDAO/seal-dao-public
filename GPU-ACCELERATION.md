# GPU Acceleration Guide

Seal DAO supports GPU acceleration for ZK proof generation. This document
covers CUDA (NVIDIA) and Metal (Apple Silicon) targets.

## RISC Zero GPU Acceleration

### NVIDIA CUDA

RISC Zero supports CUDA for STARK proof generation. Expected speedups:

| GPU | Seal Block (~100 txs) | ETH-equivalent |
|-----|----------------------|----------------|
| RTX 3080 (10 GB) | ~15-30s | ~44s |
| RTX 3090 (24 GB) | ~10-20s | ~35s |
| RTX 4090 (24 GB) | ~5-15s | ~15s |
| RTX 5090 (32 GB) | ~3-10s | ~8s |
| RTX 6000 Ada (48 GB) | ~3-8s | ~7s |
| A100 (80 GB) | ~2-6s | ~5s |

```bash
# Install CUDA toolkit (11.8+)
# https://developer.nvidia.com/cuda-downloads

# Build with CUDA support
cargo build -p seal-zk --features risc0 --release
# RISC Zero auto-detects CUDA GPUs via env var:
export RISC0_PROVER=cuda

# Verify GPU is detected
nvidia-smi

# Run proof generation (will use GPU)
cargo test -p seal-zk --features risc0 -- test_risc0_prover
```

**Memory requirements:**
- Minimum: 8 GB VRAM (RTX 3060+)
- Recommended: 16+ GB VRAM for larger blocks
- The prover memory scales with the number of constraints (~cycles in guest)

**Multi-GPU:** RISC Zero supports splitting proof generation across multiple GPUs:
```bash
export CUDA_VISIBLE_DEVICES=0,1  # Use GPUs 0 and 1
```

### Apple Silicon (Metal)

RISC Zero on Apple Silicon uses CPU only (Metal backend not yet supported).

| Chip | Seal Block (~100 txs) | Notes |
|------|----------------------|-------|
| M3 (8-core) | ~45-60s | CPU only |
| M3 Pro (12-core) | ~30-45s | CPU only |
| M3 Max (16-core) | ~20-35s | CPU only |
| M4 (10-core) | ~35-50s | CPU only (estimated) |
| M4 Pro (14-core) | ~25-40s | CPU only (estimated) |
| M4 Max (16-core) | ~18-30s | CPU only (estimated) |

```bash
# Apple Silicon: standard build (no special flags)
cargo build -p seal-zk --features risc0 --release

# CPU prover (default on macOS)
export RISC0_PROVER=local
```

**Future:** RISC Zero is working on Metal GPU support. When available:
```bash
export RISC0_PROVER=metal  # Future
```

## SP1 GPU Acceleration (Hypercube)

SP1's Hypercube proof system is optimized for multi-GPU proving.

### NVIDIA CUDA

| Setup | Seal Block | Notes |
|-------|-----------|-------|
| 1× RTX 4090 | ~10-15s | Single GPU |
| 4× RTX 4090 | ~4-6s | Multi-GPU |
| 16× RTX 5090 | ~1-2s | Real-time proving |
| 1× A100 | ~5-8s | Data center |
| 8× H100 | <1s | Extreme |

```bash
# Build with SP1 CUDA support
cargo build -p seal-zk --features sp1 --release

# SP1 auto-detects CUDA
sp1up  # Install SP1 toolchain

# Multi-GPU
export SP1_PROVER=cuda
export CUDA_VISIBLE_DEVICES=0,1,2,3
```

### Apple Silicon

SP1 on Apple Silicon also uses CPU (Metal support planned).

| Chip | Seal Block | Notes |
|------|-----------|-------|
| M3 Max | ~20-40s | CPU, 16 threads |
| M4 Max | ~15-30s | CPU, 16 threads (estimated) |

```bash
export SP1_PROVER=local
```

## NTT GPU Acceleration (Ringtail)

The NTT (Number Theoretic Transform) used in Ringtail threshold signatures
can benefit from GPU acceleration for large committee sizes.

### Current Status

The hand-rolled NTT (256-point, q = 0x1000000004A01) runs in <1ms on CPU.
For single-polynomial operations, GPU overhead exceeds the benefit.

GPU becomes worthwhile when:
- Committee size > 100 members (batch NTT of all responses)
- Module dimension is large (k=8, l=7 → 56 polynomial multiplications)

### CUDA NTT Libraries

```bash
# cuFINUFT or custom CUDA kernel
# Not yet integrated — the CPU NTT is fast enough for current parameters
```

### Apple GPU (Metal)

Metal compute shaders could accelerate batch polynomial operations.
Not yet implemented — CPU is sufficient for N=256.

## Benchmarking

```bash
# Run ZK benchmarks
cargo test -p seal-node --lib -- bench --nocapture

# Profile with RISC Zero
RISC0_PROVER=cuda cargo bench -p seal-zk --features risc0

# Compare CPU vs GPU proving time
time RISC0_PROVER=local cargo test -p seal-zk --features risc0 -- test_risc0_prover
time RISC0_PROVER=cuda cargo test -p seal-zk --features risc0 -- test_risc0_prover
```

## Recommended Hardware

### Testnet Validator
- CPU: Any modern x86_64 or ARM64 (M3+)
- RAM: 16 GB
- GPU: Not required (stub prover)

### Mainnet Validator (with ZK proving)
- CPU: 8+ cores
- RAM: 32+ GB
- GPU: RTX 4090 or better (for <15s block proving)
- Storage: 1 TB NVMe SSD

### High-Performance Prover
- CPU: 16+ cores (for parallel preparation)
- RAM: 64+ GB
- GPU: 4× RTX 5090 or 8× A100 (for <5s proving)
- Network: 10 Gbps (for proof distribution)
