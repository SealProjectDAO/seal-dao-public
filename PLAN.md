# Seal DAO Mainnet Implementation Plan

## Codebase Summary

**24,789 lines of Rust** across 16 workspace crates, plus formal specs (TLA+, Rocq, Lean 4), fuzz targets, bridge contracts, and wallet apps. The project is a post-quantum blockchain with SQL execution, Merkle state roots, VRF-based consensus, threshold signatures, bridges, TEE attestation, and governance.

---

## Dependency Graph (Phase Parallelism)

```
                         Phase A (Crypto)
                        /       |        \
                       /        |         \
            Phase B (FV)    Phase D (Perf)  Phase E (Bridges)
               |               |                |
               |          Phase C (Multi-Node)   |
               |         /          \           |
               |        /            \          |
            Phase F (Gov/Econ)        \        |
                  \                    |       /
                   \                   |      /
                    Phase G (DX/Apps)  |     /
                           \          |    /
                            \         |   /
                             Phase H (Launch)
```

**Parallelism notes:**
- A, B, D, E can all start immediately in parallel (independent foundations)
- C depends on A (Ringtail wiring) and partially on D (incremental Merkle)
- F depends on C (multi-validator for council voting) and partially on A (threshold for conviction)
- G depends on C (multi-node for SDK testing) and F (governance API)
- H depends on all prior phases reaching completion

---

## PHASE A: Core Crypto Completion

### A1: Wire Ringtail NTT into ThresholdScheme Trait

**A1.1** Implement matrix-vector multiplication (A * r) in `HandRolledOps`
- File: `crates/seal-threshold/src/ntt.rs`
- What: Add a `MatrixVec` struct holding K x L matrices over R_q. Implement `mat_vec_mul(&self, A: &MatrixVec, v: &[Poly]) -> Vec<Poly>` using the existing `poly_mul` and `add` operations from `HandRolledRing`.
- Dependencies: None (HandRolledRing already complete and cross-validated)
- Verification: Unit test comparing against schoolbook matrix multiplication on small (K=2, L=2) inputs. Kani proof for dimension bounds.

**A1.2** Implement DKG (Distributed Key Generation) for Ringtail
- File: `crates/seal-threshold/src/ringtail.rs` (new section), `crates/seal-threshold/src/ntt.rs` (extend Shamir)
- What: Implement a `RingtailDKG` struct that: (a) generates public matrix A via deterministic seed expansion (SHA3-SHAKE), (b) uses existing `shamir_share` from ntt.rs to split secret s among N parties, (c) computes public key t = A*s + e. Return `DkgOutput { public_matrix_a, public_key_t, shares }`.
- Dependencies: A1.1
- Verification: Test that reconstructing t-of-n shares recovers the secret. Proptest with varying t and n. Kani proof that share count invariant holds.

**A1.3** Implement full Round 1 with matrix multiplication
- File: `crates/seal-threshold/src/ringtail.rs`
- What: Replace the simplified `round1` method (line 194, currently `commitment_poly = r_i + e_i`) with full computation: D_i = A*r_i + e_i using the MatrixVec from A1.1. Store the A matrix reference in `RingtailParty`.
- Dependencies: A1.1, A1.2
- Verification: Test that commitments change when different randomness is sampled. Cross-validate against Go reference implementation outputs (test vectors).

**A1.4** Implement challenge expansion (hash-to-ring-element)
- File: `crates/seal-threshold/src/ringtail.rs`
- What: Replace the simplified `from_bytes(&challenge.0).unwrap_or_default()` on line 238 with a proper Gaussian hash expansion: `hash_to_poly(challenge_bytes) -> Poly` using SHAKE-256 to expand the challenge into RING_N coefficients mod q with appropriate distribution.
- Dependencies: None
- Verification: Test determinism: same input always produces same polynomial. Test distribution: coefficients should be well-distributed mod q.

**A1.5** Wire Ringtail into ThresholdScheme trait
- File: `crates/seal-threshold/src/ringtail.rs` (lines 453-488)
- What: Replace the three stub methods in `RingtailThreshold` that currently delegate to `SimpleThreshold`:
  - `partial_sign` -> Create a `RingtailParty`, run `round1` (preprocessed) and `round2`
  - `aggregate` -> Call `aggregate_responses` with `HandRolledOps`
  - `verify` -> Call `verify_signature` with `HandRolledOps`
  - The `ThresholdScheme` trait API is synchronous and one-shot; adapt the two-round protocol by embedding round1 preprocessing into a cached state keyed by (epoch, slot).
- Dependencies: A1.1, A1.2, A1.3, A1.4
- Verification: Run existing test `test_ringtail_fallback` against the new implementation. Add test with 5-of-7 committee. Benchmark signature size (target: ~13.4 KB vs current N * 3.3 KB).

**A1.6** Implement full Ringtail verification
- File: `crates/seal-threshold/src/ringtail.rs`
- What: Complete `verify_signature` (lines 311-338): compute D' = A*z - c*t, check c == H(D'||m), enable norm bound check with calibrated `NORM_BOUND` constant.
- Dependencies: A1.1, A1.4, A1.5
- Verification: Test that valid signatures verify. Test that tampered signatures fail. Test that signatures with wrong public key fail. Proptest with random messages.

**A1.7** Calibrate norm bounds and security parameters
- File: `crates/seal-threshold/src/ringtail.rs`
- What: Based on the paper (ePrint 2024/1113), calculate the correct `NORM_BOUND` for the chosen parameters (N=256, q=0x1000000004A01, sigma=6.108, t-of-n). Enable the `_norm` checks that are currently commented out (lines 280-281, 330-331).
- Dependencies: A1.5, A1.6
- Verification: Statistical test: run 10,000 signing rounds, verify all pass norm check. Adversarial test: inject polynomial with norm > B, verify rejection.

### A2: Integrate PqVrf into Multi-Validator Consensus

**A2.1** Implement PqVrf key distribution in genesis
- File: `crates/seal-consensus/src/validator.rs`, `crates/seal-node/src/consensus_runner.rs`
- What: Extend `ValidatorInfo` to store both the VRF public key (for verification) and a flag indicating VRF scheme type. Currently `vrf_public_key` stores the secret key for HMAC stub (line 79 of consensus_runner). Change to store only the public key and pass the secret through a separate secure channel.
- Dependencies: None
- Verification: Test that validators created with `with_validator_set` correctly separate VRF secret and public keys.

**A2.2** Replace VRF eval in election to use public key for verification
- File: `crates/seal-consensus/src/election.rs`
- What: Currently `run_election` calls `PqVrf::eval(&validator.vrf_public_key, &vrf_input)` (line 44) but PqVrf::eval requires the secret key. Fix the flow: the calling node uses its own secret key for eval, and `verify_election` uses the public key for verification. This is already the intended pattern but the `ValidatorInfo.vrf_public_key` field name is misleading.
- Dependencies: A2.1
- Verification: Run the existing `test_election_verifiable` and `test_verify_election_valid` tests. Add test where validator A proposes and validator B verifies.

**A2.3** Integrate LatticeVrf as alternative VRF backend
- File: `crates/seal-vrf/src/lattice_vrf.rs`, `crates/seal-consensus/src/election.rs`
- What: The LatticeVrf currently has a simplified proof (hash-based, not true ZK). Add a `VrfBackend` enum to `ConsensusConfig` (`PqVrf | LatticeVrf`) and wire the selection into `run_election` and `verify_election`. This allows benchmarking both.
- Dependencies: A2.2
- Verification: Run all election tests with both backends. Benchmark: LatticeVrf should be ~3ms eval vs PqVrf ~14ms.

### A3: ZK Backend Integration

**A3.1** Add risc0-zkvm dependency and compile guest program
- File: `crates/seal-zk/Cargo.toml`, `crates/seal-zk/guest/Cargo.toml`, `crates/seal-zk/guest/src/main.rs`
- What: Add `risc0-zkvm = { version = "1.2", features = ["prove"], optional = true }` and `risc0-build` as build dependency. Uncomment the `#![no_main]` / `#![no_std]` / `entry!(main)` in the guest. Replace `sha3_256_simple` with real SHA3. Replace `InMemoryState.execute` stub with calls to seal-merkle and seal-sql (compiled for RISC-V).
- Dependencies: None
- Verification: `cargo risczero build` succeeds. Guest can replay 3 test transactions.

**A3.2** Implement real RISC Zero prover
- File: `crates/seal-zk/src/risc0.rs`
- What: Inside the `#[cfg(feature = "risc0")]` block (lines 77-91), replace the stubbed-out code with real prover invocation. Load compiled guest ELF, create `ExecutorEnv` with state transition data, invoke `default_prover().prove()`, serialize receipt.
- Dependencies: A3.1
- Verification: Generate a proof for a single-block transition. Verify it. Measure proof size (target: ~200 KB) and generation time.

**A3.3** Implement real RISC Zero verifier
- File: `crates/seal-zk/src/risc0.rs`
- What: Inside the `#[cfg(feature = "risc0")]` block (lines 118-126), deserialize the receipt, call `receipt.verify(GUEST_ID)`, extract and validate public inputs.
- Dependencies: A3.2
- Verification: Valid proofs pass. Tampered proofs fail. Cross-check: generate on one machine, verify on another.

**A3.4** Implement SP1 prover integration
- File: `crates/seal-zk/Cargo.toml`, `crates/seal-zk/src/sp1.rs`
- What: Add `sp1-sdk = { version = "3", optional = true }`. Implement real SP1 prover in the `#[cfg(feature = "sp1")]` block (lines 48-61). Share the same guest ELF (same RISC-V ISA).
- Dependencies: A3.1
- Verification: Generate proof with SP1. Verify. Compare size and speed vs RISC Zero.

**A3.5** Wire ZK prover selection into consensus runner
- File: `crates/seal-node/src/consensus_runner.rs`
- What: Replace `prover: StubProver` (line 66) with a `Box<dyn ZkProver>`. Add a `ZkBackend` config enum (`Stub | RiscZero | Sp1`). Select at construction time.
- Dependencies: A3.2, A3.4
- Verification: Test block production with each backend. Benchmark end-to-end block production time.

**A3.6** Implement SQL replay in ZK guest
- File: `crates/seal-zk/guest/src/main.rs`
- What: Replace the stub `InMemoryState` with a minimal Merkle B-tree and SQL parser (both from seal-merkle and seal-sql, cross-compiled to RISC-V). The guest must: (a) reconstruct state from witness data (Merkle proofs for accessed rows), (b) replay SQL writes, (c) compute new Merkle root, (d) assert equality with claimed post_state_root.
- Dependencies: A3.2, Phase D completion of incremental Merkle
- Verification: End-to-end: produce block on host, prove in guest, verify proof. State root from guest must match host.

---

## PHASE B: Formal Verification Hardening

### B1: TLA+ Trace Conformance

**B1.1** Define trace format and extraction from Rust
- File: New `crates/seal-node/src/trace.rs`, `formal/tlaplus/trace_format.md`
- What: Define a JSON trace format capturing every consensus state change: `{slot, height, proposer, election_result, votes, finalized_block_hash, epoch}`. Instrument `ConsensusRunner::advance_slot` to emit trace records.
- Dependencies: None
- Verification: Run 100-slot single-node test, produce trace file, validate JSON schema.

**B1.2** Build TLA+ trace-checking harness
- File: New `formal/tlaplus/trace_check.py` or `formal/tlaplus/TraceConformance.tla`
- What: Write an Apalache-compatible TLA+ module that reads a trace file and checks it conforms to `SealConsensus.tla`. Each step in the trace must correspond to a valid transition in the TLA+ spec.
- Dependencies: B1.1
- Verification: Known-good traces pass. Inject a fault (duplicate block at same height) and verify rejection.

**B1.3** Add bridge trace conformance
- File: New `formal/tlaplus/BridgeTraceConformance.tla`
- What: Same pattern as B1.2 but for `SealBridge.tla`. Instrument `BridgeManager` to emit deposit/withdrawal/mint/burn events. Check trace against TLA+ spec.
- Dependencies: B1.1
- Verification: Run the existing bridge integration tests, produce trace, validate.

**B1.4** Integrate trace checking into CI
- File: New `.github/workflows/formal.yml`
- What: CI job that: runs Rust tests with trace emission enabled, invokes Apalache on the trace conformance modules, fails build if any trace violates spec.
- Dependencies: B1.2, B1.3
- Verification: PR that intentionally breaks consensus invariant triggers CI failure.

### B2: Rocq RLS Non-Bypassability

**B2.1** Model RLS policy in Rocq
- File: New `formal/rocq/seal_verify/RLS.v`
- What: Model Row-Level Security as a function `rls_check(user, table, row, operation) -> bool`. Define the bypass conditions. Prove: there exists no sequence of SQL operations that reads a row without passing the RLS check for the operating user.
- Dependencies: None
- Verification: `coqc RLS.v` succeeds with all proofs checked.

**B2.2** Model namespace isolation
- File: New `formal/rocq/seal_verify/Namespace.v`
- What: Prove that app A cannot read/write app B's tables through any SQL path (including JOINs, subqueries, dynamic SQL if supported).
- Dependencies: B2.1
- Verification: Prove isolation theorem. Add adversarial lemmas showing cross-namespace access is impossible.

**B2.3** Map Rocq proof to Rust code
- File: `formal/rocq/seal_verify/RLS.v` (documentation), `crates/seal-sql/src/rls.rs`
- What: Add comments in both files mapping each Rocq definition to its Rust counterpart. Write integration tests that exercise every path modeled in Rocq.
- Dependencies: B2.1, B2.2
- Verification: Full test coverage of RLS module matching Rocq model.

### B3: Lean 4 Completions

**B3.1** Prove VRF election fairness theorem
- File: `formal/lean/SealVerify/Basic/VRF.lean`
- What: Currently VRF properties are axiomatized. Add a theorem `election_fair`: given uniqueness + pseudorandomness + verifiability, the probability of a validator being elected is proportional to their stake ratio, within a negligible delta.
- Dependencies: None
- Verification: `lake build` succeeds. Theorem is checked by Lean kernel.

**B3.2** Prove Merkle tree soundness
- File: `formal/lean/SealVerify/Basic/MerkleTree.lean`
- What: 4/4 already proven. Add collision resistance theorem: for any two distinct tree states S1 != S2, Pr[root(S1) == root(S2)] <= 2^(-128) assuming SHA3 collision resistance.
- Dependencies: None
- Verification: `lake build` succeeds.

**B3.3** Model threshold signature security
- File: New `formal/lean/SealVerify/Basic/ThresholdSig.lean`
- What: Axiomatize Ringtail's security: unforgeability (adversary with < t shares cannot forge), correctness (honest t-of-n always produces valid signature). Prove that these compose with VRF for committee signing.
- Dependencies: None
- Verification: `lake build` succeeds.

**B3.4** Model bridge safety
- File: New `formal/lean/SealVerify/Basic/Bridge.lean`
- What: Prove: TotalMinted(token) <= TotalLocked(token) across all operations. This mirrors the Kani harness in bridge.rs but in a higher-order logic.
- Dependencies: None
- Verification: `lake build` succeeds.

### B4: Miri/Kani in CI, Nightly Fuzz

**B4.1** Create CI workflow for Kani verification
- File: New `.github/workflows/kani.yml`
- What: Nightly CI job running all 24 existing Kani harnesses across 8 files: `cargo kani --harness <name>` for each. Fail on any verification failure.
- Dependencies: None
- Verification: All 24 existing harnesses pass in CI.

**B4.2** Create CI workflow for Miri
- File: New `.github/workflows/miri.yml`
- What: Run `cargo +nightly miri test` on all crates except those with FFI (libcrux). Catches undefined behavior, use-after-free, data races.
- Dependencies: None
- Verification: All tests pass under Miri.

**B4.3** Expand fuzz targets
- File: `fuzz/fuzz_targets/` (7 existing targets)
- What: Add 5 new fuzz targets: `fuzz_rls_bypass.rs` (try to bypass RLS via malformed SQL), `fuzz_bridge_deposit.rs` (fuzz deposit/withdrawal sequences), `fuzz_threshold_sig.rs` (fuzz partial signature inputs), `fuzz_governance.rs` (fuzz proposal/vote/tally sequences), `fuzz_consensus_runner.rs` (fuzz transaction acceptance).
- Dependencies: None
- Verification: Each new target runs for 60 seconds without panic.

**B4.4** Set up nightly fuzz infrastructure
- File: New `.github/workflows/fuzz.yml`
- What: Nightly CI running each fuzz target for 5 minutes. Store corpus. Alert on crashes.
- Dependencies: B4.3
- Verification: 7 nights without crashes.

**B4.5** Add new Kani harnesses for critical paths
- File: Various crate files
- What: Add Kani proofs for: (a) fee burn arithmetic never overflows (`seal-node/src/fees.rs`), (b) staking/unstaking preserves total supply (`seal-token/src/staking.rs`), (c) governance tally arithmetic is correct (`seal-node/src/governance.rs`), (d) NTT forward-inverse roundtrip (`seal-threshold/src/ntt.rs` -- already exists but verify in CI), (e) Merkle proof verification consistency.
- Dependencies: None
- Verification: All new harnesses verify successfully.

---

## PHASE C: Multi-Node Networking

### C1: Multi-Validator Genesis

**C1.1** Define genesis block format
- File: New `crates/seal-consensus/src/genesis.rs`
- What: Create a `GenesisConfig` struct containing: initial validator set (public keys, VRF keys, stakes), initial token allocations, consensus parameters, chain ID, genesis timestamp. Implement `fn genesis_block(config: GenesisConfig) -> Block`.
- Dependencies: None
- Verification: Two nodes initialized from same `GenesisConfig` produce identical genesis blocks with identical state roots.

**C1.2** Implement deterministic genesis state
- File: `crates/seal-node/src/consensus_runner.rs`, `crates/seal-consensus/src/genesis.rs`
- What: Add `ConsensusRunner::from_genesis(genesis: GenesisConfig)` that initializes the SQL engine, Merkle tree, token balances, and validator set from the genesis config. All state must be deterministic from the config.
- Dependencies: C1.1
- Verification: Two runners from same genesis have identical state_root at height 0.

**C1.3** Implement genesis file serialization
- File: `crates/seal-consensus/src/genesis.rs`
- What: Serialize/deserialize GenesisConfig to/from JSON and binary (bincode). Add `seal genesis generate` CLI command.
- Dependencies: C1.1
- Verification: Round-trip serialization test. CLI generates valid genesis file.

### C2: GossipSub Committee Signing

**C2.1** Add committee signing GossipSub topics
- File: `crates/seal-p2p/src/topics.rs`
- What: Add new topics: `seal/committee-votes/1.0` for partial signatures, `seal/committee-sigs/1.0` for aggregated threshold signatures, `seal/epoch-transition/1.0` for epoch boundary messages.
- Dependencies: None
- Verification: Nodes subscribe to new topics successfully.

**C2.2** Implement block proposal broadcast
- File: `crates/seal-node/src/network_node.rs`
- What: When proposer produces a block, serialize it (bincode) and publish to `seal/blocks/1.0`. Include the VRF proof in the message so receivers can verify election.
- Dependencies: C1.1
- Verification: Two-node test: node A proposes, node B receives.

**C2.3** Implement committee vote collection
- File: `crates/seal-node/src/network_node.rs`
- What: When a committee member receives a block proposal: (a) verify VRF election proof, (b) verify all transactions in the block, (c) replay transactions to verify state root, (d) compute partial signature on block hash, (e) broadcast partial sig to `seal/committee-votes/1.0`.
- Dependencies: C2.2, A1.5 (Ringtail partial_sign)
- Verification: Three-node test: 1 proposer, 2 committee members. Both members produce valid partial signatures.

**C2.4** Implement threshold signature aggregation
- File: `crates/seal-node/src/network_node.rs`
- What: Proposer collects partial signatures from committee. When threshold is reached, call `RingtailThreshold::aggregate()` and broadcast the finalized block (with threshold signature) to `seal/committee-sigs/1.0`.
- Dependencies: C2.3, A1.5
- Verification: Three-node test: block is finalized with 2-of-3 threshold signature. All nodes store the finalized block.

**C2.5** Implement committee vote timeout
- File: `crates/seal-node/src/network_node.rs`
- What: If proposer doesn't collect enough votes within 75% of slot_duration (3 seconds), the slot is skipped. Committee members that don't receive a proposal within 50% of slot_duration vote to skip.
- Dependencies: C2.4
- Verification: Test: one committee member is offline, block still finalizes (2-of-3). Test: proposer is offline, slot is skipped.

### C3: Fork Choice Rule

**C3.1** Implement GHOST fork choice
- File: New `crates/seal-consensus/src/fork_choice.rs`
- What: Implement Greedy Heaviest Observed Sub-Tree (GHOST) fork choice. Each branch's weight = total stake of attestations. The canonical chain follows the heaviest path from genesis.
- Dependencies: C2.4
- Verification: Test with synthetic fork: two competing blocks at same height, GHOST selects the one with more committee attestations.

**C3.2** Implement block validation pipeline
- File: New `crates/seal-node/src/block_validator.rs`
- What: A `BlockValidator` that checks: (a) parent hash matches a known block, (b) VRF proof is valid for the claimed proposer, (c) state root is correct (by replaying transactions), (d) threshold signature is valid, (e) ZK proof is valid (when enabled).
- Dependencies: C3.1, A3.5
- Verification: Valid blocks pass all checks. Blocks with invalid VRF proof rejected. Blocks with wrong state root rejected.

**C3.3** Implement block storage with fork tracking
- File: `crates/seal-storage/src/block_store.rs`
- What: Extend `BlockStore` to store blocks indexed by both height and hash. Support multiple blocks at the same height (forks). Add `get_canonical_chain(tip: Hash256) -> Vec<Block>`.
- Dependencies: C3.1
- Verification: Store 3 blocks at height 5, retrieve canonical chain using GHOST.

**C3.4** Handle reorgs
- File: `crates/seal-node/src/consensus_runner.rs`
- What: When fork choice changes the canonical tip, replay the new canonical chain from the fork point. Unapply transactions from the old chain, apply transactions from the new chain.
- Dependencies: C3.2, C3.3
- Verification: Simulate a 2-block reorg, verify state root matches after replay.

### C4: Epoch Transitions

**C4.1** Implement validator set rotation at epoch boundary
- File: `crates/seal-consensus/src/epoch.rs`, `crates/seal-node/src/consensus_runner.rs`
- What: At the first slot of a new epoch: (a) compute new epoch seed from accumulated VRF outputs, (b) rotate VRF keys (already implemented in key_rotation.rs), (c) update validator set based on staking changes during the epoch, (d) process pending unstaking completions.
- Dependencies: C2.4
- Verification: Multi-node test: validator stakes more tokens during epoch N, gains proportionally higher election probability in epoch N+1.

**C4.2** Implement epoch boundary block
- File: `crates/seal-consensus/src/epoch.rs`, `crates/seal-storage/src/block_store.rs`
- What: The last block of each epoch includes: finalized epoch seed, validator set snapshot for next epoch, accumulated fees/rewards. Add `EpochBoundary` transaction type.
- Dependencies: C4.1
- Verification: Epoch boundary block contains correct validator set for next epoch. New nodes can reconstruct validator history from epoch boundaries.

**C4.3** Implement slashing for provable misbehavior
- File: New `crates/seal-consensus/src/slashing.rs`
- What: Detect and slash: (a) double proposals (two blocks at same slot from same proposer), (b) double votes (two attestations for different blocks at same slot). Evidence is two conflicting signed messages. Slashing burns a configurable fraction of stake (initially 1%).
- Dependencies: C4.1
- Verification: Submit double-proposal evidence, verify stake is reduced. Verify slashed validator loses election eligibility.

### C5: Testnet Infrastructure

**C5.1** Implement `seal dev` devnet mode
- File: `crates/seal-cli/src/main.rs`, new `crates/seal-cli/src/devnet.rs`
- What: `seal dev` starts a local 3-node devnet with: auto-generated genesis, funded test accounts, fast slots (1s), short epochs (8 slots), automatic block production. Include a built-in faucet.
- Dependencies: C1.2, C2.4
- Verification: `seal dev` starts 3 nodes, produces blocks, processes SQL transactions. Can stop and restart.

**C5.2** Implement devnet Docker compose
- File: New `devnet/docker-compose.yml`, `devnet/Dockerfile`, `devnet/genesis.json`
- What: Docker setup for 5-node devnet. Each node runs in a container. Shared genesis config. Persistent volumes for block storage.
- Dependencies: C5.1
- Verification: `docker compose up` starts 5-node network, blocks finalize.

**C5.3** Implement node sync protocol
- File: New `crates/seal-p2p/src/sync.rs`, `crates/seal-node/src/network_node.rs`
- What: When a new node joins: (a) request blocks from peers starting from its last known height, (b) verify and replay each block, (c) catch up to the current tip. Protocol: request-response over libp2p with block-range requests.
- Dependencies: C3.3, C5.1
- Verification: Start 3-node devnet, produce 100 blocks, start 4th node, verify it syncs all 100 blocks and matches state root.

**C5.4** Implement peer scoring for GossipSub
- File: `crates/seal-p2p/src/node.rs`
- What: Configure GossipSub peer scoring: reward peers that deliver valid blocks/votes quickly, penalize peers that send invalid messages. Use libp2p's built-in scoring parameters.
- Dependencies: C2.4
- Verification: Peer that sends invalid blocks gets score reduced below threshold and is disconnected.

---

## PHASE D: Performance & Data Structures

### D1: Incremental Merkle Updates

**D1.1** Implement per-row Merkle key tracking
- File: `crates/seal-sql/src/merkle_state.rs`
- What: Currently `rebuild_merkle` (called for schema changes and deletes) does O(n) full rebuild. Track stable row identifiers: for each table with a PRIMARY KEY, use `table_name:pk_value` as the Merkle key (already done for inserts). For tables without PK, use `table_name:rowid_hash`.
- Dependencies: None
- Verification: Insert 10,000 rows, verify state root matches full rebuild. Benchmark: incremental update should be O(log n).

**D1.2** Implement incremental delete in Merkle tree
- File: `crates/seal-sql/src/merkle_state.rs`, `crates/seal-merkle/src/tree.rs`
- What: Replace full rebuild on DELETE with: (a) determine the Merkle key for each deleted row, (b) call `merkle.delete(key)`. The B-tree delete already exists in tree.rs. The issue is that `WriteLog.deleted_rows` stores position indices, not PK values. Change `WriteLog` to store PK values.
- Dependencies: D1.1
- Verification: Insert 10,000 rows, delete 100, verify state root matches full rebuild. Benchmark: incremental delete O(k * log n) vs full rebuild O(n).

**D1.3** Implement incremental schema change handling
- File: `crates/seal-sql/src/merkle_state.rs`
- What: For `CREATE TABLE`, just register the table (no rows to add). For `DROP TABLE`, remove all rows for that table from Merkle tree. For `ALTER TABLE`, re-hash affected rows. Avoid full rebuild.
- Dependencies: D1.1
- Verification: CREATE then DROP 100 tables in sequence, verify Merkle root returns to initial state.

**D1.4** Benchmark and optimize Merkle B-tree
- File: `crates/seal-merkle/src/tree.rs`, `crates/seal-node/src/bench.rs`
- What: Add criterion benchmarks: insert_1000, insert_10000, get_random, proof_generate. Profile and optimize hot paths. Consider increasing B-tree branching factor for cache efficiency.
- Dependencies: D1.1
- Verification: Benchmark results stored in CI. Track regression.

### D2: HAMT for Account State

**D2.1** Implement Hash Array Mapped Trie (HAMT)
- File: New `crates/seal-merkle/src/hamt.rs`
- What: Implement a persistent HAMT with SHA3-256 hashing and 32-way branching (5 bits per level). Operations: `get`, `insert`, `delete`, `root_hash`. Each node is content-addressed. Designed for the account state tree (address -> balance+nonce).
- Dependencies: None
- Verification: Proptest: random insert/get/delete sequences. Compare against HashMap for correctness. Benchmark: O(log32 n) ~ O(1) for <1M accounts.

**D2.2** Wire HAMT into token balance storage
- File: `crates/seal-token/src/balance.rs`, `crates/seal-node/src/consensus_runner.rs`
- What: Replace `HashMap<String, Balance>` in `BalanceStore` with HAMT. The HAMT gives us a cryptographic commitment (root hash) to the full account state, enabling lightweight proofs of balance.
- Dependencies: D2.1
- Verification: All existing token tests pass. Balance state root is deterministic and changes on every transfer.

**D2.3** Implement account proof generation
- File: `crates/seal-merkle/src/hamt.rs`
- What: Generate Merkle inclusion/exclusion proofs for individual accounts in the HAMT. A light client can verify an account's balance without downloading the full state.
- Dependencies: D2.1
- Verification: Generate proof for 1000 accounts, verify each independently. Proof size: O(log32 n) hashes ~ 5-7 nodes.

### D3: Persistent Red-Black Trees for SQL Indexes

**D3.1** Wire RB-tree into SQL index module
- File: `crates/seal-sql/src/index.rs`, `crates/seal-merkle/src/rbtree.rs`
- What: The RB-tree implementation exists but isn't wired into SQL execution. Create an `IndexManager` that maintains an RB-tree per indexed column. On INSERT/UPDATE, insert into the relevant RB-trees. On WHERE clauses with indexed columns, use the RB-tree for O(log n) lookup instead of table scan.
- Dependencies: None
- Verification: Create table with 10,000 rows, add index, verify SELECT with WHERE on indexed column is >10x faster than without.

**D3.2** Implement range queries on RB-tree indexes
- File: `crates/seal-merkle/src/rbtree.rs`, `crates/seal-sql/src/index.rs`
- What: Add `range(low, high) -> Iterator` to RB-tree. Wire into SQL `WHERE col BETWEEN x AND y` and `WHERE col > x` patterns.
- Dependencies: D3.1
- Verification: Range query on 10,000-row table with index returns correct results in O(log n + k) time.

### D4: Narwhal-Style Decoupled Mempool

**D4.1** Design DAG-based mempool
- File: New `crates/seal-consensus/src/mempool.rs`
- What: Implement a Narwhal-inspired mempool: validators batch transactions into vertices, exchange vertices via reliable broadcast, form a DAG of acknowledged batches. The consensus layer orders the DAG vertices; the execution layer processes the ordered transactions.
- Dependencies: C2.4
- Verification: Test: 3 validators each submit 100 transactions. DAG converges, all transactions are ordered.

**D4.2** Implement reliable broadcast for mempool batches
- File: `crates/seal-p2p/src/topics.rs`, `crates/seal-consensus/src/mempool.rs`
- What: Add `seal/mempool-batch/1.0` GossipSub topic. Implement 2-round reliable broadcast: (1) validator broadcasts batch, (2) receivers echo an acknowledgment. Batch is considered delivered when 2/3 of validators acknowledge.
- Dependencies: D4.1, C2.1
- Verification: Test: one validator's batch is delivered to all others within 2 round-trips.

**D4.3** Decouple transaction ordering from block production
- File: `crates/seal-node/src/consensus_runner.rs`, `crates/seal-consensus/src/mempool.rs`
- What: The proposer no longer includes raw transactions in the block. Instead, the block references DAG vertices (by hash). Execution layer processes referenced vertices in causal order.
- Dependencies: D4.1, D4.2
- Verification: Block size is constant (vertex references only). Throughput: 100+ TPS with 5 validators.

### D5: GPU Proving (SP1 Hypercube)

**D5.1** Configure SP1 for GPU proving
- File: `crates/seal-zk/Cargo.toml`, `crates/seal-zk/src/sp1.rs`
- What: Add SP1 GPU feature flag. Configure CUDA/Metal backend selection. Set up SP1 network prover as fallback (delegate to Succinct's proving network for validators without GPUs).
- Dependencies: A3.4
- Verification: Generate proof on GPU. Compare time: CPU vs GPU (target: 5-10x speedup).

**D5.2** Implement parallel proving pipeline
- File: New `crates/seal-zk/src/pipeline.rs`
- What: While block N is being proven (5-15s), block N+1 is already being produced and its proof generation starts. Pipeline depth of 2-3 blocks. Use tokio tasks for async proving.
- Dependencies: D5.1
- Verification: Produce 10 blocks in sequence. Total time < 10 * single_proof_time (due to pipelining).

---

## PHASE E: Bridges & TEE

### E1: Solana Observer & Contract

**E1.1** Implement real Solana RPC polling
- File: `crates/seal-bridge/src/observer.rs`
- What: In `SolanaObserver::poll_events`, replace the empty stub (lines 99-118) with real HTTP calls to `getSignaturesForAddress` and `getTransaction`. Parse Anchor event logs to extract `LockEvent` data. Use `reqwest` for HTTP.
- Dependencies: None
- Verification: Deploy seal-lock program to Solana devnet. Lock tokens. Observer detects the event.

**E1.2** Implement Solana finality checking
- File: `crates/seal-bridge/src/observer.rs`
- What: In `SolanaObserver::is_finalized`, call `getTransaction` with `commitment: "finalized"`. Return true only if transaction has finalized commitment (32+ confirmations).
- Dependencies: E1.1
- Verification: Submit transaction to devnet, verify is_finalized returns false immediately and true after finalization.

**E1.3** Port seal-lock to real Anchor program
- File: `contracts/solana/programs/seal-lock/src/lib.rs`
- What: Replace the simulation `LockProgram` with a real Anchor program. Add `#[program]` module with `lock_sol`, `lock_spl`, and `release` instructions. Use PDAs for lock accounts, vault accounts. Implement real Ed25519 signature verification for release multisig.
- Dependencies: None
- Verification: Deploy to devnet. Lock SOL via CLI. Release via multisig. Verify events are emitted.

**E1.4** Connect Solana observer to bridge manager
- File: `crates/seal-node/src/network_node.rs`
- What: Add a `BridgeRunner` that: periodically polls `SolanaObserver`, feeds deposits to `BridgeManager`, triggers wrapped token minting when confirmed.
- Dependencies: E1.1, E1.2
- Verification: End-to-end: lock SOL on Solana devnet, Seal node detects it, mints wSOL on Seal.

### E2: Stellar Observer & Contract

**E2.1** Implement real Stellar Horizon polling
- File: `crates/seal-bridge/src/observer.rs`
- What: In `StellarObserver::poll_events`, replace the empty stub (lines 188-201) with real HTTP calls to Horizon API: `GET /accounts/{contract_id}/operations?cursor=...`. Filter for `invoke_host_function` operations that call the "lock" function. Parse XDR-encoded event data.
- Dependencies: None
- Verification: Deploy seal-lock Soroban contract to Stellar testnet. Lock XLM. Observer detects the event.

**E2.2** Port seal-lock to real Soroban contract
- File: `contracts/stellar/src/lib.rs`
- What: Replace the simulation `StellarLockContract` with a real Soroban contract. Add `#[contract]` and `#[contractimpl]` macros. Use Soroban SDK for token transfers, persistent storage, event emission.
- Dependencies: None
- Verification: Deploy to testnet. Lock XLM via CLI. Release via multisig.

**E2.3** Implement cross-chain withdrawal flow
- File: `crates/seal-bridge/src/bridge.rs`, `crates/seal-node/src/consensus_runner.rs`
- What: When a user burns wrapped tokens on Seal: (a) create withdrawal record, (b) committee members each sign the release message, (c) aggregate threshold signature, (d) submit release transaction to source chain (Solana or Stellar).
- Dependencies: E1.3, E2.2, A1.5 (Ringtail for signing), C2.4 (multi-node for committee)
- Verification: End-to-end: burn wSOL on Seal, validators submit multisig release on Solana, user receives SOL.

### E3: TEE Verification

**E3.1** Implement Intel TDX quote verification
- File: `crates/seal-tee/src/attestation.rs`
- What: Replace the `register` method's stub (line 106, "accept all attestations") with real verification: parse Intel DCAP quote format, verify the quote signature chain up to Intel's root CA, check the code measurement hash matches expected value.
- Dependencies: None (add `dcap-ql-rs` or implement verification manually)
- Verification: Submit a genuine TDX quote from a real TDX machine, verify it passes. Submit a fake quote, verify it fails.

**E3.2** Implement AMD SEV-SNP attestation verification
- File: `crates/seal-tee/src/attestation.rs`
- What: Parse AMD SEV-SNP attestation report. Verify signature against AMD's root of trust. Check firmware version, code measurement.
- Dependencies: None
- Verification: Same pattern as E3.1 for AMD hardware.

**E3.3** Implement multi-vendor cross-validation
- File: `crates/seal-tee/src/attestation.rs`
- What: For critical operations (AI inference), require attestations from at least 2 different vendors (e.g., Intel TDX + AMD SEV). Add `verify_multi_vendor(attestations: &[TeeAttestation]) -> Result<(), TeeError>`.
- Dependencies: E3.1, E3.2
- Verification: Test with 3 attestations from 3 vendors. Verify that single-vendor fails multi-vendor check.

**E3.4** Implement continuous re-attestation
- File: `crates/seal-tee/src/attestation.rs`, `crates/seal-node/src/network_node.rs`
- What: TEE nodes must re-attest every 5 minutes (`max_age_secs = 300`). Stale attestations are automatically removed from the registry. Nodes that fail re-attestation are excluded from inference routing.
- Dependencies: E3.3
- Verification: Register node, wait 6 minutes, verify node is no longer valid.

---

## PHASE F: Governance & Token Economics

### F1: Conviction Voting

**F1.1** Implement conviction multiplier
- File: `crates/seal-node/src/governance.rs`
- What: Add a `Conviction` enum (None=0.1x, 1w=1x, 2w=2x, 4w=4x, 8w=8x, 16w=16x) representing the lock-up period a voter commits to. Weight = stake * conviction_multiplier. Tokens are locked for the conviction period after the vote.
- Dependencies: None
- Verification: Test: voter with 100 stake and 4x conviction has weight 400. Tokens locked for 4 weeks.

**F1.2** Implement vote change and removal
- File: `crates/seal-node/src/governance.rs`
- What: Allow voters to change their vote during the voting period. Old conviction lock is replaced by new one. Allow vote withdrawal (tokens remain locked for the original conviction period).
- Dependencies: F1.1
- Verification: Test: change vote from Yes to No, verify tally updates correctly.

**F1.3** Implement conviction decay
- File: `crates/seal-node/src/governance.rs`
- What: For ongoing proposals (e.g., rolling governance), conviction decays over time. Implement the Polkadot-style conviction curve.
- Dependencies: F1.1
- Verification: Test: conviction weight decreases as lock period expires.

### F2: Adaptive Quorum

**F2.1** Implement adaptive quorum biasing
- File: `crates/seal-node/src/governance.rs`
- What: Replace the fixed approval threshold (lines 24-31) with adaptive quorum: at low turnout, require super-majority approval; at high turnout, simple majority suffices. Formula: `approval_needed = base_threshold + (1 - turnout) * bias`.
- Dependencies: None
- Verification: Test: 10% turnout requires 75% approval. 100% turnout requires 50% approval.

**F2.2** Implement per-track quorum configuration
- File: `crates/seal-node/src/governance.rs`
- What: Each `ProposalTrack` gets its own quorum curve parameters: minimum turnout, bias factor, base threshold.
- Dependencies: F2.1
- Verification: Emergency track requires higher minimum turnout than ParameterChange.

### F3: Delegation

**F3.1** Implement vote delegation
- File: New `crates/seal-node/src/delegation.rs`, `crates/seal-node/src/governance.rs`
- What: Token holders can delegate their voting power to another address. Delegated power stacks. Delegation is per-track (can delegate differently for Treasury vs Protocol).
- Dependencies: F1.1
- Verification: A delegates to B (1000 stake). B votes on proposal with effective weight 1000 + B's own stake.

**F3.2** Implement delegation revocation
- File: `crates/seal-node/src/delegation.rs`
- What: Delegators can revoke at any time. If delegator votes directly, their delegation is automatically overridden for that proposal.
- Dependencies: F3.1
- Verification: A delegates to B. A votes directly. A's vote counts, B's delegated power from A does not.

### F4: Councils

**F4.1** Implement Technical Council
- File: New `crates/seal-node/src/council.rs`
- What: A Technical Council of 7-11 elected members. Powers: fast-track emergency proposals, veto clearly harmful proposals (with 2/3 super-majority). Council elections happen every epoch (or configurable period).
- Dependencies: F3.1, C4.1
- Verification: Test full lifecycle: nominate candidates, vote, elect council, council vetoes a proposal.

**F4.2** Implement Service Operators Council
- File: `crates/seal-node/src/council.rs`
- What: A council of infrastructure operators (TEE operators, bridge relayers). Powers: approve new bridge integrations, set TEE requirements.
- Dependencies: F4.1
- Verification: Test: SOC approves a new bridge chain. SOC rejects an under-attested TEE operator.

### F5: Emission Schedule & Treasury

**F5.1** Implement token emission schedule
- File: New `crates/seal-token/src/emission.rs`
- What: Define the SEAL token emission curve. Initial supply: configurable. Emission: decreasing block rewards over epochs. Target: asymptotic max supply with continuous decay. Implement `fn block_reward(epoch: u64) -> u64`.
- Dependencies: None
- Verification: Test: epoch 0 reward > epoch 100 reward > epoch 1000 reward. Sum of all rewards approaches max supply asymptotically.

**F5.2** Implement validator rewards
- File: `crates/seal-node/src/fees.rs`, `crates/seal-token/src/emission.rs`
- What: Block proposer receives: (a) 50% of transaction fees (already implemented), (b) emission reward from F5.1. Committee members receive a fraction of the emission reward proportional to their attestation.
- Dependencies: F5.1
- Verification: Test: proposer reward = fee_reward + emission_reward. Committee members receive proportional share.

**F5.3** Implement treasury allocation
- File: New `crates/seal-token/src/treasury.rs`
- What: A configurable percentage (e.g., 10%) of emission goes to the on-chain treasury. Treasury funds are disbursed only via governance proposals (TreasurySmall/TreasuryLarge tracks).
- Dependencies: F5.1, F2.1
- Verification: Test: treasury balance grows each epoch. Governance proposal successfully disburses from treasury.

**F5.4** Implement dynamic fee market
- File: `crates/seal-node/src/fees.rs`
- What: Replace the fixed `base_fee_per_byte` with an EIP-1559-style dynamic fee: base fee adjusts based on block utilization. If block > 50% full, base fee increases; if < 50%, decreases.
- Dependencies: None
- Verification: Test: 10 full blocks in a row, base fee increases. 10 empty blocks, base fee decreases.

---

## PHASE G: DX & Applications

### G1: JS/WASM SDK

**G1.1** Create seal-sdk-wasm crate
- File: New `sdks/seal-sdk-wasm/Cargo.toml`, `sdks/seal-sdk-wasm/src/lib.rs`
- What: WASM-compilable crate exposing: wallet creation (BIP-39), transaction signing (ML-DSA), SQL query construction, address generation (bech32m). Use `wasm-bindgen` for JS interop.
- Dependencies: None
- Verification: `wasm-pack build` succeeds. Import in Node.js, create wallet, sign transaction.

**G1.2** Create @seal-dao/sdk npm package
- File: New `sdks/seal-sdk-js/package.json`, `sdks/seal-sdk-js/src/index.ts`
- What: TypeScript wrapper around the WASM module. Provide: `SealClient` (connects to node RPC), `Wallet` (key management), `SQL` (query builder), `Bridge` (lock/unlock).
- Dependencies: G1.1
- Verification: Integration test: create wallet, submit SQL transaction, query result.

**G1.3** Implement JSON-RPC server
- File: New `crates/seal-node/src/rpc.rs`
- What: HTTP JSON-RPC server (using `axum` or `jsonrpc-http-server`). Methods: `seal_getBlock`, `seal_getLatestBlock`, `seal_submitTransaction`, `seal_executeQuery`, `seal_getBalance`, `seal_getProposal`, `seal_getValidatorSet`.
- Dependencies: C5.1
- Verification: curl requests to each endpoint return valid JSON. JS SDK can connect and interact.

**G1.4** Implement WebSocket subscriptions
- File: `crates/seal-node/src/rpc.rs`
- What: WebSocket endpoint for real-time events: `seal_subscribeNewBlocks`, `seal_subscribeNewTransactions`, `seal_subscribeBridgeEvents`.
- Dependencies: G1.3
- Verification: JS client subscribes, receives block notifications in real-time.

### G2: Python SDK

**G2.1** Create seal-sdk-python with PyO3
- File: New `sdks/seal-sdk-python/Cargo.toml`, `sdks/seal-sdk-python/src/lib.rs`, `sdks/seal-sdk-python/seal_sdk/__init__.py`
- What: Python bindings via PyO3/maturin. Expose: `Wallet`, `Client`, `Transaction`, `SQLQuery`.
- Dependencies: None
- Verification: `maturin develop`, `python -c "import seal_sdk; w = seal_sdk.Wallet.create()"` succeeds.

**G2.2** Add Python SDK examples and documentation
- File: New `sdks/seal-sdk-python/examples/`, `sdks/seal-sdk-python/README.md`
- What: Example scripts: create_wallet.py, submit_sql.py, bridge_sol.py, governance_vote.py.
- Dependencies: G2.1
- Verification: All examples run successfully against a devnet.

### G3: GUI Wallet App

**G3.1** Flesh out Electron wallet shell
- File: `apps/seal-wallet/standalone.html`, `apps/seal-wallet/electron.cjs`
- What: Electron shell + `standalone.html` already cover create/import/sign. Extend the UI with balance display, send/receive tokens, and transaction history backed by node RPC.
- Dependencies: G1.3 (RPC server)
- Verification: App launches via `npm run electron`; create wallet, view balance, send tokens on devnet.

**G3.2** Add bridge UI to wallet
- File: `apps/seal-wallet/standalone.html`
- What: UI for bridging: select source chain (Solana/Stellar), enter amount, lock, view wrapped balance, withdraw back.
- Dependencies: G3.1, E2.3
- Verification: End-to-end: bridge SOL to wSOL via wallet UI.

**G3.3** Add governance UI to wallet
- File: `apps/seal-wallet/standalone.html`
- What: View proposals, vote with conviction, delegate voting power, view council members.
- Dependencies: G3.1, F1.1
- Verification: Create proposal via UI, vote, tally passes.

**G3.4** Complete Android wallet
- File: `apps/seal-wallet-android/src/lib.rs`
- What: The UniFFI structure exists. Wire up wallet operations: create, backup, send, receive. Expose via Kotlin/Swift bindings.
- Dependencies: G1.1
- Verification: Android app builds, basic wallet operations work.

### G4: Developer Tooling

**G4.1** Implement seal explorer (basic)
- File: New `apps/seal-explorer/`
- What: Minimal block explorer: list blocks, view block details (transactions, state root, VRF proof), search by height/hash, view account balances.
- Dependencies: G1.3
- Verification: Explorer shows blocks from running devnet.

**G4.2** Implement seal test framework
- File: New `sdks/seal-test/`
- What: Testing framework for Seal app developers. Provides: in-memory node, mock bridge, test accounts with pre-funded balances. `SealTestClient::new() -> (node, client)`.
- Dependencies: G1.2
- Verification: Example test creates table, inserts data, queries, all in-process.

---

## PHASE H: Pre-Mainnet & Launch

### H1: Security Audits

**H1.1** Prepare audit scope document
- File: New `docs/AUDIT_SCOPE.md`
- What: Document all critical code paths, trust assumptions, crypto primitives, and potential attack vectors. Prioritize: (a) consensus/fork-choice, (b) threshold signatures, (c) bridge, (d) token economics, (e) SQL/RLS.
- Dependencies: All prior phases at least 80% complete
- Verification: Internal review by 3+ team members.

**H1.2** Engage external auditors (crypto)
- What: Hire specialized PQC audit firm to review: ML-DSA usage, Ringtail threshold implementation, NTT correctness, VRF construction. Provide test vectors and formal proofs as reference.
- Dependencies: A (complete), B (substantial)
- Verification: Audit report received. All critical findings resolved.

**H1.3** Engage external auditors (consensus + bridge)
- What: Hire blockchain consensus audit firm to review: fork choice, epoch transitions, slashing, bridge state machine, wrapped token accounting.
- Dependencies: C (complete), E (complete)
- Verification: Audit report received. All critical findings resolved.

**H1.4** Engage external auditors (smart contracts)
- What: Hire Solana/Stellar smart contract auditors to review the lock programs.
- Dependencies: E1.3, E2.2
- Verification: Audit reports received.

### H2: Bug Bounty Program

**H2.1** Launch bug bounty on testnet
- What: Publish bounty program covering: consensus breaks, bridge exploits, RLS bypass, token inflation, key extraction. Reward tiers from $500 to $50,000.
- Dependencies: H1.2, H1.3 (audits identify high-level issues first)
- Verification: At least 30 days of active bounty with no critical findings.

**H2.2** Process and resolve bounty submissions
- What: Triage, reproduce, fix, verify each submission. Pay bounties. Publish post-mortems for critical findings.
- Dependencies: H2.1
- Verification: All confirmed vulnerabilities patched and re-tested.

### H3: Formal Verification Final Pass

**H3.1** Complete all TLA+ model checking
- File: `formal/tlaplus/`
- What: Run Apalache on SealConsensus.tla with MaxHeight=10, 5 validators. Run on SealBridge.tla with 100 operations. Run on SealCompositeProof.tla. All invariants must hold.
- Dependencies: B1.4
- Verification: Apalache reports "no violation found" for all specs.

**H3.2** Run Kani on all 30+ harnesses in CI
- File: `.github/workflows/kani.yml`
- What: Final CI run with all Kani harnesses (original 24 + new ones from B4.5). Must all pass.
- Dependencies: B4.1
- Verification: Green CI badge.

**H3.3** Run nightly fuzz for 30 consecutive days
- File: `.github/workflows/fuzz.yml`
- What: All 12 fuzz targets run for 5 hours nightly for 30 days straight. Zero crashes.
- Dependencies: B4.4
- Verification: 30-day clean fuzz log.

**H3.4** Complete Lean 4 verification
- File: `formal/lean/`
- What: All theorems must be proven (no `sorry`). `lake build` must succeed without warnings.
- Dependencies: B3.1-B3.4
- Verification: Clean build.

**H3.5** Complete Rocq verification
- File: `formal/rocq/`
- What: All theorems proven. `coqc` on all .v files succeeds. RLS non-bypassability proven.
- Dependencies: B2.1-B2.3
- Verification: Clean build.

### H4: Incentivized Testnet

**H4.1** Launch incentivized testnet (Phase 1: Validators)
- What: Deploy public testnet. External validators run nodes with test tokens. Rewards for uptime, block production, and finding bugs.
- Dependencies: C5.2 (Docker), H2.1 (bounty)
- Verification: 20+ validators running for 7+ days with 99%+ finality.

**H4.2** Launch incentivized testnet (Phase 2: Bridges)
- What: Enable Solana and Stellar bridges on testnet. Users bridge test tokens. Rewards for successful bridge operations.
- Dependencies: H4.1, E2.3
- Verification: 100+ bridge operations with zero accounting errors.

**H4.3** Launch incentivized testnet (Phase 3: Apps)
- What: Deploy example apps (seal-marketplace, seal-notes). SDK developers build and deploy test apps.
- Dependencies: H4.2, G1.2, G2.1
- Verification: 10+ external apps deployed and functional.

**H4.4** Testnet stability validation
- What: Run the full testnet for 30 days. Monitor: block production rate, finality latency, bridge reliability, memory/CPU usage, storage growth.
- Dependencies: H4.1-H4.3
- Verification: 30-day uptime >99.5%. No consensus faults. No bridge accounting errors.

### H5: Genesis and Mainnet

**H5.1** Finalize genesis parameters
- What: Lock down: initial supply, emission schedule, validator set, bridge configurations, governance parameters, chain ID.
- Dependencies: F5.1, H4.4
- Verification: Genesis config reviewed by team and auditors.

**H5.2** Generate genesis block
- File: `crates/seal-consensus/src/genesis.rs`
- What: Generate the final mainnet genesis block with production parameters. Distribute genesis config to all validators.
- Dependencies: H5.1, C1.3
- Verification: All validators produce identical genesis block hash.

**H5.3** Coordinate mainnet launch
- What: Validators start nodes simultaneously with genesis config. First block produced. Bridge programs deployed to mainnet Solana/Stellar.
- Dependencies: H5.2
- Verification: Chain produces blocks. First 100 blocks finalize correctly. Bridge is operational.

**H5.4** Post-launch monitoring
- What: 24/7 monitoring for first 30 days. Alerting on: missed blocks, fork events, bridge delays, abnormal fee spikes, validator exits.
- Dependencies: H5.3
- Verification: 30-day operational stability.

---

## Step Count Summary

| Phase | Sub-phases | Steps |
|-------|-----------|-------|
| A: Core Crypto | A1 (7) + A2 (3) + A3 (6) | 16 |
| B: Formal Verification | B1 (4) + B2 (3) + B3 (4) + B4 (5) | 16 |
| C: Multi-Node | C1 (3) + C2 (5) + C3 (4) + C4 (3) + C5 (4) | 19 |
| D: Performance | D1 (4) + D2 (3) + D3 (2) + D4 (3) + D5 (2) | 14 |
| E: Bridges & TEE | E1 (4) + E2 (3) + E3 (4) | 11 |
| F: Governance & Econ | F1 (3) + F2 (2) + F3 (2) + F4 (2) + F5 (4) | 13 |
| G: DX & Apps | G1 (4) + G2 (2) + G3 (4) + G4 (2) | 12 |
| H: Pre-Mainnet | H1 (4) + H2 (2) + H3 (5) + H4 (4) + H5 (4) | 19 |
| **Total** | | **120 numbered steps** |

Note: Many steps contain multiple distinct tasks (e.g., A1.5 involves modifying three methods), bringing the total individual work items to approximately 200+.

---

## Critical Path Analysis

The longest dependency chain to mainnet is:

```
A1.5 (Ringtail wiring, ~3 weeks)
  -> C2.4 (Committee signing, ~2 weeks)
    -> C3.1 (Fork choice, ~2 weeks)
      -> C4.1 (Epoch transitions, ~1 week)
        -> C5.1 (Devnet, ~1 week)
          -> H4.1 (Incentivized testnet, ~4 weeks)
            -> H4.4 (30-day stability, ~5 weeks)
              -> H5.3 (Mainnet launch)
```

Total critical path: approximately 18-20 weeks from start of Phase A.

Parallelizable work that can happen alongside the critical path:
- Phase B (Formal Verification): entirely parallel with A/C/D
- Phase D (Performance): D1/D2/D3 parallel with C, D4/D5 after C2
- Phase E (Bridges): parallel with C (bridges are independent of multi-node consensus)
- Phase F (Governance): F1/F2 parallel with C, F3/F4 after C4
- Phase G (DX): starts after C5, parallel with H preparation
- Phase H audits: can start as soon as relevant phase is code-complete

### Critical Files for Implementation

- `/Users/bechaderenaud/work/seal/seal-dao-master/crates/seal-threshold/src/ringtail.rs` -- The primary blocker: lines 453-488 contain the three stub methods that must be wired to real Ringtail NTT. This unlocks multi-node committee signing (Phase C) which is on the critical path.
- `/Users/bechaderenaud/work/seal/seal-dao-master/crates/seal-node/src/consensus_runner.rs` -- The consensus loop that orchestrates everything: block production, VRF election, ZK proof generation, threshold signing. Nearly every phase touches this file.
- `/Users/bechaderenaud/work/seal/seal-dao-master/crates/seal-zk/src/risc0.rs` -- The ZK prover stub (lines 77-91) that must be replaced with real RISC Zero integration. Blocks the transition from trusted to trustless state verification.
- `/Users/bechaderenaud/work/seal/seal-dao-master/crates/seal-bridge/src/observer.rs` -- Bridge observers with empty poll stubs (lines 99-118 for Solana, 188-201 for Stellar). These must be connected to real RPCs for bridge functionality.
- `/Users/bechaderenaud/work/seal/seal-dao-master/crates/seal-node/src/network_node.rs` -- The network node that combines consensus with P2P. Must be extended with committee vote collection, block validation, sync protocol, and bridge runner for multi-node operation.