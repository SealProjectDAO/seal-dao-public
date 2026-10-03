# Seal DAO — Formal Methods Plan

A practical guide to verification tools for a PQC blockchain written in Rust.

---

## 1. Tool Landscape

### 1.1 Rust → Formal Models (extracting proofs from code)

| Tool | Backend | What it proves | Maturity | Effort | Verdict |
|------|---------|----------------|----------|--------|---------|
| **Kani** | CBMC (SAT/SMT) | No panics, no overflow, no OOB, absence of UB | Production (AWS) | Low | **Must-use** |
| **hax** (Cryspen) | F*, Rocq, Lean | Functional correctness, secret independence | Beta/Prod for crypto | High | **Best for PQC** |
| **Verus** | Z3 (SMT) | Functional correctness + concurrency | Research/Beta (MSR) | Medium-High | **For new concurrent modules** |
| **Creusot** | Why3 | Functional correctness of pure algorithms | Research/Beta | Medium-High | Consider for data structures |
| **Aeneas** | Lean 4 | Functional correctness, Mathlib proofs | Research/Beta (MSR) | High | Consider for crypto algos |
| **Prusti** | Viper | Pre/postconditions, no panics | Research/Beta | Medium | Skip (Verus/Creusot better) |
| **coq-of-rust** | Rocq/Coq | Automatic Rust→Rocq translation | Beta | High | Consider for state machines |

### 1.2 Formal Models → Rust (generating verified code)

| Direction | Approach | Status |
|-----------|----------|--------|
| F* → Rust | Cryspen hax: verify Rust, ship Rust. HACL*: extract F* to C/Rust | Production |
| Rocq → Rust | coq-rust-extraction (AU-COBRA). MetaCoq erasure | Research/Early Beta |
| Lean 4 → Rust | No mature extractor. Verify in Lean, implement in Rust, use Aeneas to check correspondence | Toolchain gap |

### 1.3 Distributed Protocol Verification

| Tool | What it does | Maturity | Verdict |
|------|-------------|----------|---------|
| **TLA+/TLC** | Explicit-state model checking (5-7 nodes, ~10 rounds) | Production | **Essential for consensus** |
| **Apalache** | Symbolic TLA+ model checking, SMT-based, parameterized proofs | Production (Informal Systems) | **Better than TLC for proofs** |
| **Quint** | Engineer-friendly syntax compiling to TLA+ | Beta | Lower barrier to entry |

### 1.4 Security Tooling (non-formal, essential)

| Tool | What it catches | Effort | Verdict |
|------|----------------|--------|---------|
| **Miri** | UB, aliasing violations, data races, misaligned access | Near-zero | **Must-use** |
| **cargo-fuzz** | Crashes, panics, logic bugs via coverage-guided fuzzing | Low | **Must-use** |
| **cargo-audit** | Known CVEs in dependencies | Near-zero | **Must-use** |
| **cargo-deny** | License violations, duplicate deps, advisories | Near-zero | **Must-use** |
| **MIRAI** | Taint analysis, potential panics (abstract interpretation) | Low | Nice-to-have |

---

## 2. What to Verify and How

### 2.1 PQC Cryptographic Primitives (Highest Priority)

**Target**: ML-DSA signing/verification, ML-KEM encap/decap, SHA3, VRF

**Recommended approach**: Use **libcrux** (Cryspen's verified PQC library) instead of
pqcrypto-dilithium/pqcrypto-kyber. libcrux is verified with **hax + F*** for:
- Panic freedom
- Functional correctness against NIST specifications
- Secret independence (source-level side-channel resistance)

If using our own implementations (e.g., LB-VRF):
- **Kani** harnesses for: no-panic, no-overflow in NTT, serialization roundtrips
- **hax → F*** for functional correctness against the math spec
- **Lean 4 + VCVio** for game-based security proofs (VRF uniqueness, pseudorandomness)
- **Miri** on all unsafe blocks
- **cargo-fuzz** on malformed inputs

### 2.2 Consensus Protocol (High Priority)

**Target**: VRF leader election, committee voting, block finalization, epoch transitions

**Recommended approach**:
1. Write **TLA+** (or **Quint**) specification of the consensus protocol
2. Check with **TLC** on small configurations (3-5 nodes)
3. Prove with **Apalache** using inductive invariants:
   - Safety: no two different blocks finalized at same height
   - Liveness: blocks keep being produced under partial synchrony
   - Uniqueness: at most one valid proposer per slot
4. **Trace conformance testing**: run Rust implementation, record execution traces,
   verify they are valid executions of the TLA+ spec

**Properties to verify (TLA+)**:
```
Safety == \A h \in Heights: Cardinality({b \in FinalizedBlocks: b.height = h}) <= 1
Liveness == <>(\E b \in FinalizedBlocks: b.height > CurrentHeight)
NoDoubleCert == \A b1, b2 \in CertifiedBlocks:
    (b1.height = b2.height) => (b1 = b2)
```

### 2.3 Merkle B-Tree (Medium Priority)

**Target**: Insert/delete preserves invariants, membership proofs are sound

**Recommended approach**:
- **Kani** harnesses for: balanced tree after operations, no panics on edge cases
- **Lean 4** proofs for:
  - Insertion preserves search-tree invariant
  - Deletion preserves search-tree invariant
  - Membership proof soundness: valid proof ⟹ key is in the tree
  - Membership proof completeness: key in tree ⟹ proof exists
  - Hash collision resistance (axiomatized) ⟹ state integrity

### 2.4 State Transition Function (Medium Priority)

**Target**: SQL operations produce correct state diffs, determinism

**Recommended approach**:
- **Kani** for: no panics in SQL execution, overflow in numeric operations
- **coq-of-rust** for automatic extraction to Rocq, then prove:
  - Determinism: same inputs → same state root
  - Correctness: INSERT adds row, DELETE removes row, UPDATE modifies row
  - Access control: RLS policy evaluation is non-bypassable

### 2.5 Token Arithmetic (Medium Priority)

**Target**: No overflow/underflow in balance operations, conservation of supply

**Recommended approach**:
- **Kani** with function contracts:
```rust
#[kani::proof]
#[kani::requires(amount <= balance_a)]
#[kani::requires(balance_b.checked_add(amount).is_some())]
fn verify_transfer_conserves_supply() {
    let balance_a: u64 = kani::any();
    let balance_b: u64 = kani::any();
    let amount: u64 = kani::any();
    let new_a = balance_a - amount;
    let new_b = balance_b + amount;
    assert!(new_a + new_b == balance_a + balance_b);
}
```

### 2.6 Bridge Protocol (Lower Priority, Phase 3)

**Target**: No double-spend across chains, locked ≥ minted

**Recommended approach**:
- **TLA+** specification of the lock-and-mint protocol
- Prove: `TotalMinted <= TotalLocked` as an invariant
- Prove: `Finalized(BridgeOut) => Eventually(Unlocked)`

---

## 3. Implementation Roadmap

### Immediately (this week)
- [ ] Add `cargo +nightly miri test` to CI / test script
- [ ] Add `cargo audit` and `cargo deny check` to CI
- [ ] Write first `cargo-fuzz` target for SQL parser
- [ ] Write first Kani harness for SHA3 hash properties

### Short-term (weeks)
- [ ] Kani harnesses for seal-crypto (ML-DSA sign/verify roundtrip, no panic)
- [ ] Kani harnesses for seal-merkle (insert/get roundtrip, no panic)
- [ ] Kani harnesses for token arithmetic (overflow freedom)
- [ ] Evaluate libcrux as replacement for pqcrypto-dilithium/pqcrypto-kyber
- [ ] Begin TLA+ consensus specification
- [ ] Add cargo-fuzz targets for VRF proof verification, block deserialization

### Medium-term (months)
- [ ] TLA+ consensus spec reviewed and model-checked with TLC
- [ ] Apalache proofs with inductive invariants for consensus safety/liveness
- [ ] Trace conformance testing: Rust consensus ↔ TLA+ spec
- [ ] hax extraction of VRF code to F* for functional correctness
- [ ] Lean 4 proofs for Merkle B-tree invariants

### Long-term (quarters)
- [ ] Lean 4 + VCVio proofs for VRF security (uniqueness, pseudorandomness)
- [ ] coq-of-rust for state transition machine verification
- [ ] Verus modules for new concurrent consensus code
- [ ] Bridge protocol TLA+ spec and Apalache proofs
- [ ] External cryptographic audit informed by formal proofs

---

## 4. What NOT to Verify Formally

- **The entire codebase**: Focus on the Trusted Computing Base (TCB)
- **Hash collision resistance**: Axiomatize SHA3 as collision-resistant
- **Compiler correctness**: Use Ferrocene if regulatory compliance needed
- **Network timing assumptions**: Model as nondeterministic in TLA+
- **Existing well-audited dependencies**: Trust sled, libp2p, sqlparser-rs

---

## 5. Key Insight: hax + libcrux for PQC

The most impactful decision is whether to use **Cryspen's libcrux** for PQC primitives.
libcrux provides ML-KEM and ML-DSA with **hax + F* verification**, covering:
- Panic freedom (all inputs)
- Functional correctness (matches NIST FIPS 203/204 spec)
- Secret independence (no secret-dependent branching at source level)

This eliminates the need to verify our own PQC implementations, which is the
highest-risk and highest-effort verification task. The LB-VRF (which has no
verified implementation anywhere) remains the one component requiring custom
formal verification.

**Recommendation**: Migrate `seal-crypto` to use libcrux for ML-DSA and ML-KEM.
Keep pqcrypto-* only as a fallback or for algorithms libcrux doesn't cover.

---

## 6. Real-World Track Record

| Project | Tools | Verified |
|---------|-------|----------|
| **libcrux** (Cryspen) | hax + F* | ML-KEM, ML-DSA: correctness + secret independence |
| **HACL*** | F* + KaRaMeL | Crypto in Firefox, Linux, Windows |
| **Tezos** | Mi-Cho-Coq | Smart contract correctness |
| **Algorand** | Coq, CADP | Consensus safety |
| **Tendermint/Cosmos** | TLA+ + Apalache | Consensus, IBC light client |
| **Ethereum** | Lean 4, Dafny | EVM spec, zkEVM, deposit contract |
| **Asterinas** | Verus + TLA+ | OS kernel page tables, concurrency |

---

## References

- Kani: [model-checking.github.io/kani](https://model-checking.github.io/kani/)
- hax: [github.com/cryspen/hax](https://github.com/cryspen/hax)
- libcrux: [github.com/cryspen/libcrux](https://github.com/cryspen/libcrux)
- Verus: [github.com/verus-lang/verus](https://github.com/verus-lang/verus)
- Creusot: [github.com/xldenis/creusot](https://github.com/xldenis/creusot)
- Aeneas: [github.com/AeneasVerif/aeneas](https://github.com/AeneasVerif/aeneas)
- coq-of-rust: [github.com/formal-land/coq-of-rust](https://github.com/formal-land/coq-of-rust)
- Apalache: [github.com/apalache-mc/apalache](https://github.com/apalache-mc/apalache)
- Quint: [github.com/informalsystems/quint](https://github.com/informalsystems/quint)
- VCVio (Lean 4 crypto proofs): [github.com/dtumad/VCVio](https://github.com/dtumad/VCVio)
- Miri: [github.com/rust-lang/miri](https://github.com/rust-lang/miri)
- MIRAI: [github.com/endorlabs/MIRAI](https://github.com/endorlabs/MIRAI)
- Ferrocene: [ferrocene.dev](https://ferrocene.dev)
