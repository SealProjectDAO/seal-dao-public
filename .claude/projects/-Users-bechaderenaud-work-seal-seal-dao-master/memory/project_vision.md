---
name: Seal DAO project vision
description: Core vision and architecture decisions for the Seal DAO blockchain - PQC L1 chain with distributed SQL, VRF consensus, ZK validation
type: project
---

Seal DAO is a PQC-native L1 blockchain where the state is a distributed SQL database.

**Core idea:** "PHP+MySQL but on a secure blockchain" — developers deploy SQL schemas as apps, write/read via SQL.

**Key architecture decisions:**
- VRF for consensus leader selection + ZK proofs for block validation
- Post-quantum cryptography throughout (ML-DSA/Dilithium, ML-KEM/Kyber, SHA3)
- Own chain (not building on existing L1)
- Local ZK proof generation for SQL writes, local query execution for reads
- MPC planned for Phase 2 (private multi-party queries)
- Bridge to Solana and Stellar for payments

**Why:** Make blockchain as accessible as traditional web databases, while being quantum-resistant from day one.

**How to apply:** All design decisions should favor developer simplicity (SQL over custom languages) and PQC security. Rust is the implementation language. Formal methods (Lean, Rocq, TLA+) verify correctness-critical components.
