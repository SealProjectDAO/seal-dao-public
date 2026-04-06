# Kani — Limitations and When to Use Other Tools

## What Kani Is Good At

Kani is a **bounded model checker**: it converts Rust code into SAT/SMT
constraints and exhaustively checks all possible inputs up to a bound.

**Sweet spot**: Pure arithmetic, data structures, state machines — code
where the logic is complex but the data is small.

| Use case | Example | Result |
|----------|---------|--------|
| Integer overflow | `balance + amount` overflows? | ✅ **Excellent** (0.1-1s) |
| Roundtrip correctness | `debit(credit(x)) == x`? | ✅ **Excellent** (0.3s) |
| State machine invariants | Slot decomposition roundtrip? | ✅ **Excellent** (0.08s) |
| Panic freedom | `debit()` never panics? | ✅ **Excellent** (0.1s) |

## What Kani Cannot Handle

### 1. Cryptographic Hash Functions (SHA3, SHA256, etc.)

**Problem**: Hash functions are designed to be complex — every bit of input
affects every bit of output. When Kani tries to symbolically execute SHA3,
the SAT formula explodes exponentially.

**Symptoms**:
- Runs for hours without terminating
- Memory usage grows to gigabytes
- `block_buffer` assertions fail (internal state too complex)

**Our experience**:
```
cargo kani -p seal-merkle --harness insert_get_roundtrip
→ FAIL: SHA3 buffer assertion (Kani can't model the hash function)

cargo kani -p seal-crypto --harness sha3_256_deterministic
→ Runs for hours, killed after 30+ minutes
```

**Why**: The Merkle tree calls `sha3_256()` on every node operation.
Kani tries to symbolically execute the entire Keccak permutation
(24 rounds × 5 × 5 × 64-bit state), creating millions of constraints.

### 2. Post-Quantum Cryptography (ML-DSA, ML-KEM)

**Problem**: ML-DSA-65 has a 4,032-byte secret key with NTT polynomial
arithmetic, rejection sampling, and matrix operations. Far too complex
for symbolic execution.

**Symptoms**:
- `cargo kani -p seal-crypto` runs indefinitely
- Memory exceeds 16GB before any check completes

**Our experience**:
```
cargo kani -p seal-crypto --harness sha3_256_no_panic
→ Killed after 30+ minutes, no result
```

### 3. Large Data Structures

**Problem**: Kani unrolls loops and inlines function calls. A B-tree
with variable-size nodes creates an exponential number of paths.

### 4. Concurrency

**Problem**: Kani only supports single-threaded sequential execution.
Cannot verify async code, tokio, or multi-threaded logic.

## What Tools to Use Instead

### For each component, the RIGHT verification tool:

| Component | Kani? | Instead use | Why |
|-----------|-------|-------------|-----|
| **Token arithmetic** | ✅ Yes | — | Pure arithmetic, small state |
| **Consensus slot/epoch** | ✅ Yes | — | Pure arithmetic |
| **VRF threshold** | ✅ Yes | — | Float arithmetic |
| **Bridge invariant** | ✅ Yes | — | Balance checking |
| **SHA3-256** | ❌ No | **proptest** + libcrux's hax+F* | Hash too complex for SAT |
| **ML-DSA sign/verify** | ❌ No | **libcrux hax+F*** (Cryspen) | Formally verified by vendor |
| **ML-KEM encap/decap** | ❌ No | **libcrux hax+F*** | Formally verified by vendor |
| **Merkle B-tree** | ❌ No | **proptest** + **Lean 4** | Hash in every operation |
| **SQL parser** | ❌ No | **cargo-fuzz** | Complex string parsing |
| **P2P networking** | ❌ No | **integration tests** | Async, I/O-heavy |
| **Consensus protocol** | ❌ No | **TLA+ / Apalache** | Distributed system |
| **State transitions** | ❌ No | **Rocq proofs** | Mathematical properties |

### Tool comparison matrix

```
                    Kani    proptest   cargo-fuzz   Lean 4    Rocq     TLA+
                    ────    ────────   ──────────   ──────    ────     ────
Exhaustive?         Yes*    No         No           Yes       Yes      Yes*
  (* bounded)       (bounded)(random)  (random)     (∀)       (∀)      (* bounded)

Handles crypto?     ❌      ✅         ✅           N/A       N/A      N/A
Handles async?      ❌      ❌         ❌           N/A       N/A      N/A
Proves ∀ inputs?    Yes*    No         No           Yes       Yes      Yes*
Effort to write?    Low     Low        Low          High      High     Medium
Speed?              Seconds Seconds    Hours        N/A       N/A      Seconds
```

### Decision flowchart

```
Is the code pure arithmetic / small state machine?
  → YES: Use Kani (#[kani::proof])
  → NO: Does it involve crypto (hash, signatures)?
    → YES: Is it OUR code or a library?
      → Library (libcrux): Trust vendor's hax+F* verification
      → Our code: Use proptest + cargo-fuzz
    → NO: Is it a distributed protocol?
      → YES: Use TLA+ / Apalache
      → NO: Is it a mathematical property?
        → YES: Use Lean 4 or Rocq
        → NO: Use proptest / integration tests
```

## Our Verified Components Summary

| Component | Tool | Status | What's proven |
|-----------|------|--------|---------------|
| Token balance ops | **Kani** | ✅ 3/3 verified | No overflow, roundtrip, no underflow |
| Consensus config | **Kani** | ✅ 2/2 verified | Slot roundtrip, threshold bounds |
| Token conservation | **Rocq** | ✅ 7/7 proven | credit/debit/stake/unstake/transfer |
| State machine | **Rocq** | ✅ 5/6 proven | Determinism, mint/burn, invalid rejection |
| Consensus safety | **TLA+** | ✅ 3/3 verified | Agreement, no equivocation, monotonic |
| Composite proof | **TLA+** | ✅ 3/3 verified | Soundness, completeness, independence |
| Hash properties | **Lean 4** | ✅ 4/4 | Determinism, injectivity, incremental |
| Merkle invariants | **Lean 4** | 1/4 (3 sorry) | Root determinism (rest TODO) |
| VRF properties | **Lean 4** | Axiomatized | Uniqueness, correctness, soundness |
| ML-DSA correctness | **hax+F*** | ✅ (Cryspen) | Panic freedom, FIPS 204, secret indep |
| ML-KEM correctness | **hax+F*** | ✅ (Cryspen) | Panic freedom, FIPS 203, secret indep |
| Merkle B-tree | **proptest** | ✅ 5 properties | Roundtrip, overwrite, delete, sorted, deterministic |
| Token ops | **proptest** | ✅ 5 properties | Roundtrip, conservation, safety |
| SQL parser | **cargo-fuzz** | Target ready | No panic on arbitrary input |
| Bridge invariant | **Kani** | Harness ready | minted ≤ locked (needs runtime test) |

## Key Lesson

> **Know your tools.** Kani is powerful for arithmetic and state machines
> but useless for cryptographic code. Don't force a tool into a domain
> it wasn't designed for — use the right tool for each component.
>
> The strongest verification comes from COMBINING tools:
> - Kani for arithmetic correctness
> - proptest for data structure invariants
> - cargo-fuzz for input boundary safety
> - TLA+ for protocol design
> - Lean/Rocq for mathematical properties
> - hax+F* for cryptographic implementations (via libcrux)
