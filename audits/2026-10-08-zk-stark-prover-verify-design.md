# Real ZK/STARK SQL prover + verifier — design note

Date: 2026-10-08 · Status: **research-grade, design-doc + scaffold only; implementation DEFERRED.**
Today's "proof" is a deterministic SHA3 fingerprint, not a proof of computation. Real proving
scaffolds (a RISC-V guest + risc0/SP1) exist but are not wired into the hot path. This note designs
the real prover/verifier and — critically — where a real proof can and cannot sit.

## 1. Current state (validated against primary source, 2026-10-08)

- **The production "proof" is a SHA3-256 fingerprint.** `SqlStarkProof`
  (`crates/seal-zk/src/lib.rs:107-112`) = `{ program_commitment: [u8;32], memory_root: [u8;32],
  nonce: u64, execution_time_ns: u64 }` (80 bytes). `generate_proof` (`lib.rs:125-131`) computes
  `SHA3-256(body)` and `SHA3-256(rows)`; `verify_proof` (`lib.rs:135-165`) **recomputes both hashes
  from the same inputs** and compares. This is a deterministic fingerprint, **not a proof of
  computation and not zero-knowledge** (it re-derives from the inputs, so it proves nothing about the
  computation having run).
- **Live but stub.** The RPC path `seal-node generate_sql_stark_proof` (`rpc.rs:4129-4156`) calls
  `seal_zk::generate_proof` (the SHA3 stub) on SQL execution. So a "proof" is produced on every exec,
  but it is the fingerprint. No real-proof verification is in the consensus path.
- **Real proving scaffolds exist but are unwired.** `crates/seal-zk/guest/` is a **separate workspace**
  (excluded from the main one, `guest/Cargo.toml:2`) containing a RISC-V guest with a real
  `guest_commitment` (`guest/src/lib.rs:27-37`, a hash of source + inputs + outputs) and `prove()`/
  `verify()` (`lib.rs:62-75`), plus an **SP1 program entry** (`guest/src/sp1/mod.rs:1-120`:
  `setup`/`execute`/`verify` via the SP1 SDK). The main workspace declares both proving backends as
  deps — `risc0-zkvm 5.0.0-rc.1` (client) and `sp1-sdk 6.0.2` (`Cargo.toml:102-103`) — but they are
  **not used** by the stub path.
- The `SqlVerifier` trait (`lib.rs:168-175`) is the intended drop-in seam (per the CLAUDE.md
  trait-with-stub convention). No ~200KB target-size constant exists yet.

## 2. Real prover/verifier design

A real STARK must prove "SQL program `P` executed correctly over `input` to produce `output`"
**without** the verifier re-running `P`. Two sub-problems:

1. **A canonical low-level re-implementation of the SQL engine as a RISC-V guest program** — the
   "guest" that replays one SQL op in a deterministic, circuit-friendly form and commits to
   (source, inputs, outputs). The `guest/src/lib.rs::guest_commitment` is the intended shape of the
   real `program_commitment`; the guest is the program the prover attests executed.
2. **The proving system** — risc0 or SP1 producing a ~200KB-class proof from the guest execution.
   `SqlStarkProof` grows to carry the **real proof bytes + verification key**; `verify_proof` checks
   the proof against a public statement `(program hash, input commitment, output/state-root
   commitment)` **without re-deriving** (this is what makes it a proof and makes it zero-knowledge).
   The `SqlVerifier` trait is the drop-in seam for the real backend.

**Where a real proof can and cannot sit (the key scoping decision):**
- **Not per-tx in the F3 consensus hot path (not now).** STARK proving is slow (seconds–minutes) and
  expensive; a per-tx proof in the on-block transition is not viable today, and wiring proof
  verification into the transition would be a consensus-critical (fork-surface) change.
- **Realistic near-term role: auxiliary / periodic off-chain attestation.** A validator attests a
  *checkpoint's* SQL state (a signed snapshot, see the snapshot-bootstrap design note) with a STARK
  proof; third parties verify the proof against the public statement without trusting the validator.
  This is opt-in and non-consensus-gating, so a bad/absent proof cannot halt the chain.
- **Long-term (design-first, deferred):** a real proof as a *consensus gate* (a block's SQL is
  committed only with a valid proof) is an F3-class project requiring the guest to match the
  production SQL engine **exactly** and a performance model.

## 3. Failure modes

- **Guest/engine divergence** — the RISC-V guest re-implementation must match the production SQL
  engine byte-for-byte in state transition, or the proof attests to the *wrong* computation. This is
  the dominant risk; it needs a differential test (guest vs production engine over a large corpus).
- Prover availability/cost (a proof service or in-process prover that may not finish in time).
- Proof-size/verification-cost budget for the chosen backend.

## 4. Status

Research-grade; **design-doc + scaffold only, implementation deferred**. Deliverable is the corrected
framing (current "proof" is an 80-byte SHA3 fingerprint, live-but-stub, not a proof; real RISC-V
guest + risc0/SP1 scaffolds exist but unwired; the honest near-term role is **auxiliary/off-chain
attestation**, not a per-tx consensus gate). Revisit with a regression-first implementation of §2,
gated on the guest/production differential test in §3.
