# Veridise PQC Cryptography Audit — Scope Document

**Project**: Seal DAO
**Audit Type**: Post-Quantum Cryptography Security Audit
**Requested Firm**: Veridise (https://veridise.com)
**Language**: Rust
**Date Prepared**: 2026-04-02

---

## 1. Executive Summary

Seal DAO is a PQC-native L1 blockchain. All on-chain cryptographic operations
use NIST-standardized post-quantum algorithms. This audit covers the
correctness, security, and integration of all cryptographic primitives.

The primary risk is not in the underlying algorithms (which use the formally
verified `libcrux` library) but in:
1. Correct usage of PQC APIs (parameter selection, nonce management)
2. Custom constructions built on top of PQC primitives (VRF, threshold sigs)
3. Key lifecycle management (generation, storage, zeroization)
4. Integration seams where crypto meets consensus/networking

---

## 2. In-Scope Components

### 2.1 Core Cryptography (`crates/seal-crypto/`)

| Component | File | Algorithm | Priority |
|-----------|------|-----------|----------|
| Transaction signing | `src/signing.rs` | ML-DSA-65 (FIPS 204) | Critical |
| Key generation | `src/keygen.rs` | ML-DSA-65 | Critical |
| Hashing | `src/hash.rs` | SHA3-256 (FIPS 202) | High |
| Address derivation | `src/address.rs` | SHA3-256 + bech32m | High |

**Focus areas**:
- Correct ML-DSA parameter set (ML-DSA-65 = NIST Level 3)
- Signature malleability prevention
- Key material zeroization on drop
- Constant-time comparison for signatures and hashes

### 2.2 VRF Constructions (`crates/seal-vrf/`)

| Component | File | Construction | Priority |
|-----------|------|-------------|----------|
| PQ-VRF | `src/pq_vrf.rs` | ML-DSA + SHA3 (one-time) | Critical |
| LaV VRF | `src/lav_vrf.rs` | Lattice hash-and-sign (many-time) | Critical |
| Lattice VRF | `src/lattice_vrf.rs` | NTT-accelerated lattice VRF | High |
| HMAC VRF | `src/hmac_vrf.rs` | SHA3-HMAC (legacy, to be removed) | Low |

**Focus areas**:
- VRF uniqueness: same key + same input = same output (critical for consensus)
- LaV Gaussian sampling correctness (information leakage through norm)
- NTT correctness (modular reduction, butterfly operations)
- Eval counter enforcement in `LatticeVrf` (few-time security)
- No bias in VRF output distribution

### 2.3 Threshold Signatures (`crates/seal-threshold/`)

| Component | File | Algorithm | Priority |
|-----------|------|-----------|----------|
| Ringtail signing | `src/ringtail.rs` | Lattice-based threshold (ePrint 2024/1113) | Critical |
| NTT ring ops | `src/ntt.rs` | Hand-rolled NTT for Goldilocks | Critical |
| Shamir sharing | `src/shamir.rs` | Shamir secret sharing over Zp | High |
| SNARK aggregation | `src/snark_agg.rs` | Committee sig compression | Medium |

**Focus areas**:
- Norm bound calibration (2^53 per-party, 2^60 aggregate)
- Gaussian noise sampling (discrete Gaussian, not rounded continuous)
- Shamir reconstruction correctness and threshold enforcement
- Challenge expansion (`expand_challenge` with TAU=60)
- Public parameter generation (`generate_public_params`)
- Key share zeroization

### 2.4 P2P Transport (`crates/seal-p2p/`)

| Component | File | Algorithm | Priority |
|-----------|------|-----------|----------|
| PQ transport | `src/pq_transport.rs` | ML-KEM-768 (FIPS 203) | High |

**Focus areas**:
- ML-KEM encapsulation/decapsulation correctness
- Session key derivation (KDF from shared secret)
- Monotonic nonce enforcement (replay prevention)
- Frame encrypt/decrypt with authenticated encryption
- MAC verification (constant-time)

### 2.5 MPC (`crates/seal-mpc/`)

| Component | File | Algorithm | Priority |
|-----------|------|-----------|----------|
| SPDZ protocol | `src/lib.rs` | Secret sharing over Goldilocks | Medium |
| PSI | `src/lib.rs` | Hash-based private set intersection | Medium |

**Focus areas**:
- Beaver triple correctness
- Secret share reconstruction
- PSI salt management and hash collision resistance

---

## 3. Out of Scope

- `libcrux` internals (separately audited by Cryspen with hax + F*)
- SQL parser and execution engine
- Governance logic
- Bridge smart contracts (separate audit)
- Frontend SDKs (JS/WASM/Python)
- Test-only code (`#[cfg(test)]` blocks)

---

## 4. Existing Formal Verification

The auditors should be aware of existing verification coverage:

| Component | Method | Coverage |
|-----------|--------|----------|
| ML-DSA, ML-KEM | hax + F* (Cryspen/libcrux) | Panic freedom, functional correctness, secret independence |
| Modular arithmetic | Kani BMC | 60 harnesses: overflow, roundtrip, bounds |
| VRF uniqueness | Lean 4 | Formalized with axioms (VRF.lean) |
| Merkle tree | Lean 4 | **Proven** — 7 theorems + 6 helper lemmas, 0 sorries as of 2026-05-08 commit `58102e9fc` (`SealVerify/Basic/MerkleTree.lean`) |
| NTT butterfly | Kani | Modular reduction correctness |
| Shamir roundtrip | Kani | share + reconstruct = identity |
| Token arithmetic | Rocq/Coq | 6 theorems (Balance.v) |
| Ringtail verify | cargo-fuzz | Continuous fuzzing target |

**Gaps the audit should fill**:
- No formal proof of LaV VRF security reduction
- No formal proof of Ringtail norm bound sufficiency
- NTT correctness proofs are bounded (Kani), not universal
- Gaussian sampling distribution has not been statistically tested

---

## 5. Key Sizes and Parameters

| Primitive | Parameter | Value |
|-----------|-----------|-------|
| ML-DSA | Security level | Level 3 (ML-DSA-65) |
| ML-DSA | Signing key | 4,032 bytes |
| ML-DSA | Public key | 1,952 bytes |
| ML-DSA | Signature | 3,309 bytes |
| ML-KEM | Security level | Level 3 (ML-KEM-768) |
| ML-KEM | Public key | 1,184 bytes |
| ML-KEM | Ciphertext | 1,088 bytes |
| SHA3 | Digest | 256 bits |
| NTT | Field | Goldilocks (p = 2^64 - 2^32 + 1) |
| NTT | Degree | N = 1024 |
| Ringtail | Threshold | 67-of-100 (configurable) |
| Ringtail | Norm bound (per-party) | 2^53 |
| Ringtail | Norm bound (aggregate) | 2^60 |
| LaV VRF | Gaussian sigma | 100.0 |
| LaV VRF | Challenge weight (TAU) | 60 |

---

## 6. Build Instructions

```bash
# Clone and build
git clone https://github.com/seal-dao/seal-dao.git
cd seal-dao
cargo build

# Run all tests (215+)
cargo test

# Run crypto-specific tests
cargo test -p seal-crypto
cargo test -p seal-vrf
cargo test -p seal-threshold
cargo test -p seal-mpc

# Run Kani proofs (requires kani-verifier)
cargo kani -p seal-crypto
cargo kani -p seal-threshold

# Run Miri (requires nightly)
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test -p seal-crypto

# Fuzz a target
cargo +nightly fuzz run fuzz_ringtail_verify -- -max_total_time=60
```

---

## 7. Deliverables Expected

1. **Finding report** with severity classification (Critical/High/Medium/Low/Informational)
2. **Cryptographic review** of custom constructions (LaV VRF, Ringtail integration)
3. **Parameter assessment** — are norm bounds, Gaussian sigmas, challenge weights sufficient?
4. **Key management review** — lifecycle from generation through zeroization
5. **Recommendations** for any construction that should be replaced or hardened

---

## 8. Contact

- **Technical lead**: security@seal-dao.org
- **Repository**: https://github.com/seal-dao/seal-dao
- **Specification**: See `SPEC.md` in repository root
