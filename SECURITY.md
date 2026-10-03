# Seal DAO — Security Model

## Threat Model

### Actors
- **Honest validators**: Follow the protocol correctly.
- **Byzantine validators**: Up to 1/3 of weighted stake. May equivocate,
  withhold, or send conflicting messages.
- **External attackers**: No stake. May send arbitrary network messages,
  attempt DDoS, or try to exploit software bugs.
- **Quantum adversary** (future): Has access to a large-scale quantum computer.
  Can break ECDSA/RSA but NOT lattice-based crypto (ML-DSA, ML-KEM).

### Trust Boundaries

```
UNTRUSTED                    TRUST BOUNDARY               TRUSTED
──────────────               ───────────────               ──────────
Network messages  ──────────>  P2P layer  ──────────>  Consensus engine
  (arbitrary bytes)            (deserialize,             (VRF election,
                                validate)                block production)

SQL input         ──────────>  SQL parser  ──────────>  SQL engine
  (user strings)               (sqlparser-rs)            (execution)

Bridge events     ──────────>  Bridge mgr  ──────────>  Token balances
  (external chain)             (confirm,                 (mint/burn)
                                threshold)
```

### Attack Surfaces

| Surface | Attack | Mitigation |
|---------|--------|------------|
| P2P messages | Malformed blocks, fake txs | Deserialize → verify sig → verify state root |
| SQL parser | SQL injection, DoS via complex queries | sqlparser-rs parses to AST; no string concatenation; size limits |
| Block proposals | Invalid state root, fake VRF proof | Replay txs to verify state root; verify VRF proof |
| Threshold sigs | Forged committee signatures | Verify threshold ≥ 2/3; verify each partial sig |
| Bridge | Double-spend across chains | Multi-confirmation; invariant: minted ≤ locked |
| Token arithmetic | Overflow/underflow | Checked arithmetic everywhere; Kani proofs |
| Key material | Extraction from memory | Zeroize on drop; constant-time operations |
| Dependencies | Supply chain attack | cargo-audit in CI; cargo-deny for license/source policy |
| TEE | Hardware side-channels | Multi-vendor redundancy; TEE+ZK hybrid |
| Governance | Flash loan attacks | Snapshot voting power at proposal creation |

## Cryptographic Security

### Post-Quantum Resistance
All on-chain cryptography is PQC (NIST standardized):
- **ML-DSA-65** (FIPS 204): Transaction signing, block signing, governance votes
- **ML-KEM-768** (FIPS 203): Encrypted P2P transport
- **SHA3-256** (FIPS 202): State hashing, Merkle trees, address derivation

Implementation: **libcrux** (Cryspen), formally verified with hax + F*.
Verified properties: panic freedom, functional correctness, secret independence.

### What is NOT post-quantum (and why)
- **VRF**: PqVrf uses ML-DSA + SHA3 construction (PQ-secure). LB-VRF upgrade planned.
- **Threshold sigs**: Ringtail lattice-based signatures implemented (352ms for 67-of-100).
- **P2P encryption**: Noise (classical) + application-layer ML-KEM-768 double encryption.

### Key Sizes

| Primitive | Key/Sig Size | Notes |
|-----------|-------------|-------|
| ML-DSA-65 signing key | 4,032 bytes | Larger than ECDSA (32B) |
| ML-DSA-65 public key | 1,952 bytes | Larger than ECDSA (33B) |
| ML-DSA-65 signature | 3,309 bytes | Larger than ECDSA (64B) |
| ML-KEM-768 public key | 1,184 bytes | |
| ML-KEM-768 ciphertext | 1,088 bytes | |
| SHA3-256 digest | 32 bytes | Same as SHA-256 |

## Formal Verification Coverage

| Component | Tool | Status |
|-----------|------|--------|
| PQC crypto (ML-DSA, ML-KEM) | hax + F* (Cryspen) | **Verified** (libcrux) |
| Consensus protocol | TLA+ | **Spec + trace conformance** |
| Token arithmetic | Rocq/Coq | **Proven** (Balance.v — 6 theorems) |
| State machine | Rocq/Coq | **Proven** (StateMachine.v — 5 theorems) |
| Row-level security | Rocq/Coq | **Proven** (RLS.v — 6 theorems) |
| SQL state transitions | Rocq/Coq | **Proven** (SqlState.v — 7 theorems) |
| Hash properties | Lean 4 | Axiomatized |
| Merkle tree invariants | Lean 4 | **Proven** (`SealVerify/Basic/MerkleTree.lean`, 0 sorries as of 2026-05-08 commit `58102e9fc`) |
| VRF properties | Lean 4 | Axiomatized (3 properties) |
| Modular arithmetic | Kani | **66 harnesses** across 19 files |
| Token overflow | Kani | **Proven** (credit/debit/stake roundtrip) |
| Governance | Kani | **Proven** (conviction, threshold, delegation) |
| Emission schedule | Kani | **Proven** (bounded, monotone, no overflow) |
| Slashing | Kani | **Proven** (penalty bounds, saturation) |
| Bridge invariant | Kani | **Proven** (deposit/withdrawal conservation) |
| Input fuzzing | cargo-fuzz | **10 targets** (sql_parser, vrf_verify, pqvrf_verify, address_parse, block_deserialize, tx_deserialize, merkle_ops, ringtail_verify, ringtail_sign, committee_vote) |

## Responsible Disclosure

If you find a security vulnerability, please report it privately.
Do NOT open a public GitHub issue for security bugs.

**Email**: security@seal-dao.org

### Bug Bounty (Pre-mainnet)

A formal bug bounty on Immunefi will launch before mainnet. Scope:

| Component | Max Reward |
|-----------|------------|
| Consensus / Cryptography | $100,000 |
| Token economics / Bridge | $75,000 |
| SQL engine / RLS bypass | $50,000 |
| P2P / TEE | $25,000 |

### Out of Scope

- Denial of service (DoS) attacks
- Issues in vendored dependencies (report upstream)
- Known limitations documented in TODO.md
- Test/example code only
