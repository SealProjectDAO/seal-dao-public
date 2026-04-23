# Formal Verification for Seal DAO

This directory contains formal specifications, proofs, and verification
harnesses for correctness-critical components of the Seal protocol.

## Why formal methods?

Blockchains handle real money. A consensus bug = double-spend = catastrophic.
A crypto bug = key extraction = catastrophic. Testing can show the presence
of bugs, but formal verification can prove their absence.

## Directory structure

```
formal/
├── README.md               ← This file (you are here)
│
├── tlaplus/                ← Distributed protocol verification (model checking)
│   ├── README.md           ← What TLA+ is, how to run it, what we prove
│   └── SealConsensus.tla   ← Consensus safety + liveness specification
│
├── lean/                   ← Mathematical algorithm proofs (Lean 4 theorem prover)
│   ├── README.md           ← What Lean 4 is, how to run it, what we prove
│   ├── lakefile.lean       ← Lean 4 build file
│   ├── lean-toolchain      ← Lean version pinning
│   └── SealVerify/Basic/
│       ├── Hash.lean       ← Hash function axioms + properties
│       ├── MerkleTree.lean ← Merkle tree invariant proofs
│       └── VRF.lean        ← VRF uniqueness + pseudorandomness
│
├── rocq/                   ← State machine verification (Coq/Rocq theorem prover)
│   ├── README.md           ← What Rocq is, how to run it, what we prove
│   ├── _CoqProject         ← Rocq build configuration
│   └── seal_verify/
│       ├── Balance.v       ← Token balance conservation proofs
│       └── StateMachine.v  ← State transition correctness
│
├── kani/                   ← Bounded model checking (annotations live in Rust source)
│   └── README.md           ← What Kani is, where the harnesses are, how to run
│
├── miri/                   ← Undefined behavior detection (runs on Rust tests)
│   └── README.md           ← What Miri is, how to run it, what it catches
│
└── fuzz/                   ← Coverage-guided fuzzing (targets + corpus)
    └── README.md           ← What fuzzing is, targets, how to run
```

## Tool comparison

| Tool | Proves | Lives in | Effort | When to use |
|------|--------|----------|--------|-------------|
| **TLA+** | Protocol safety/liveness for ALL executions | `formal/tlaplus/*.tla` | Medium | Consensus, bridge, epoch transitions |
| **Lean 4** | Mathematical properties for ALL inputs | `formal/lean/**/*.lean` | High | VRF correctness, Merkle tree invariants |
| **Rocq/Coq** | State machine correctness for ALL inputs | `formal/rocq/**/*.v` | High | Token conservation, access control |
| **Kani** | No panics/overflow for ALL inputs (bounded) | `#[cfg(kani)]` in Rust source | Low | Crypto primitives, serialization |
| **Miri** | No UB in specific test executions | Runs on `cargo test` | Near-zero | All unsafe code |
| **cargo-fuzz** | No crashes on random inputs | `formal/fuzz/` + `fuzz/` | Low | Parsers, deserializers, crypto inputs |

## How to run everything

```bash
# Run all Rust-embedded verification:
./scripts/verify.sh

# Run Lean 4 proofs:
cd formal/lean && lake build

# Run Rocq proofs:
cd formal/rocq && make

# Run TLA+ model checking.
# Apalache (0.55.0+) takes ONE --inv flag with a comma-separated list
# — repeating --inv triggers the CLI's "Usage … Options ???" help.
apalache-mc check --inv=Agreement formal/tlaplus/SealConsensus.tla
apalache-mc check --inv=Agreement,NoEquivocation,MonotonicHeight \
    formal/tlaplus/SealConsensus.tla

# Bridge spec (wraps the six safety invariants on MC_SealBridge.tla):
./scripts/verify-tla-bridge.sh

# Run Kani (bounded model checking):
cargo kani -p seal-crypto
cargo kani -p seal-merkle
cargo kani -p seal-token

# Run Miri (undefined behavior detection):
cargo +nightly miri test -p seal-crypto

# Run fuzzing:
cargo fuzz run fuzz_sql_parser -- -max_total_time=60
```
