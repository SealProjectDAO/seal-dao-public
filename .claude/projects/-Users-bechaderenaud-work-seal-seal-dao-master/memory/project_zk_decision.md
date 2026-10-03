---
name: ZK VM decision
description: RISC Zero primary, SP1 secondary, GPU support for CUDA + Apple Silicon
type: project
---

ZK VM strategy: trait-based with two backends.

1. **RISC Zero** — primary implementation (most mature, formally verified)
2. **SP1** — secondary/upgrade path (faster, better GPU support)

GPU targets:
- CUDA: RTX 3080 → RTX 6000 Blackwell (middle to high end)
- Apple Silicon: M3, M4, M5 (integrated GPU)

**Why:** Trait boundary means swapping is transparent. RISC Zero for correctness first, SP1 for performance later.

**How to apply:** The ZkProver trait already exists. Implement RiscZeroProver first, then Sp1Prover behind same trait.
