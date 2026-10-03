# ROADMAP.md — Seal DAO Implementation Plan

> Generated 2026-03-30 from codebase audit. Updated 2026-04-01.
> Covers all remaining work from current state (~65-70% complete) to mainnet.
>
> **2026-04-01**: Eliminated all `.unwrap()` / `.expect()` from production code
> (89 call sites across 25 files). Rule codified in CLAUDE.md. Test code unchanged.

---

## Current State Summary

| Area | Status | Detail |
|------|--------|--------|
| PQC crypto (ML-DSA, ML-KEM, SHA3) | **Done** | libcrux, formally verified |
| Merkle B-tree | **Done** | Insert/delete/proof, proptest coverage |
| SQL engine | **Done** | Parser, execution, RLS, namespaces |
| Storage (sled) | **Done** | Block + state persistence |
| Consensus (VRF election) | **Done** | Algorand-style, pluggable VRF backend |
| P2P networking | **Done** | libp2p + ML-KEM double-encryption |
| Token economics | **Done** | Balances, transfers, staking, checked arith |
| Wallet | **Done** | BIP-39, multi-chain (SEAL + Solana + Stellar) |
| Single-node prototype | **Done** | Full pipeline in seal-node |
| CLI + REPL | **Done** | Migration tool, demo, interactive shell |
| TLA+ specs | **Done** | Consensus, bridge, composite proofs verified |
| Rocq proofs | **Done** | Token conservation, state machine (12+ theorems) |
| Kani harnesses | **Done** | 24 proofs across 8 source files |
| Fuzz targets | **Done** | 7 targets implemented |
| Ringtail threshold sigs | **Partial** | Protocol coded; NTT/Gaussian/Shamir stubbed |
| ZK proofs | **Partial** | Stub prover only; no real STARK backend |
| Bridge observers | **Partial** | Framework done; chain polling stubbed |
| TEE attestation | **Partial** | Types done; quote verification stubbed |
| LatticeVrf (LB-VRF) | **Partial** | Simplified; no true ZK proof |
| Lean 4 proofs | **Partial** | Hash done; Merkle 1/4; VRF axiomatized |
| Incremental Merkle | **Not started** | Currently full rebuild O(n) |
| DAG consensus (Phase 2+) | **Not started** | Mysticeti evaluation pending |
| GPU proving | **Not started** | SP1 Hypercube target |
| Client SDKs | **Not started** | JS/WASM, Python |
| GUI app | Desktop shipping | Electron wallet (`apps/seal-wallet/`); egui explorer scaffold |

---

## Phase 1 — Complete the Core Protocol

**Goal:** All cryptographic building blocks production-ready. Single-node runs with real (not stub) crypto.

### 1.1 Wire NTT into Ringtail (seal-threshold)

The NTT backends (HandRolledOps, LattigoPortOps) are implemented and cross-validated.
The Ringtail protocol structure is implemented. The missing link is wiring them together.

- [ ] **1.1.1** Replace `StubRingOps` delegation in `RingtailThreshold::sign()` and `aggregate()` with `HandRolledOps` (or `LattigoPortOps`)
  - Files: `crates/seal-threshold/src/ringtail.rs` lines 459-488
  - The TODO comments mark exact replacement points
- [ ] **1.1.2** Wire `sample_discrete_gaussian()` from `ntt.rs` into Ringtail Round 1 (r_i, e_i sampling)
  - Currently uses placeholder small-coefficient sampling
- [ ] **1.1.3** Wire `shamir_share()` / `shamir_reconstruct()` from `ntt.rs` into key distribution
  - Dealer splits secret key polynomial into N shares
- [ ] **1.1.4** Implement real `verify_signature()` in Ringtail
  - Currently accepts if participants >= threshold
  - Needs: recompute D from public info, check ‖z‖ < NORM_BOUND, verify challenge hash
- [ ] **1.1.5** Benchmark: 100-party signing completes within 2s over WAN
  - Round 1 is preprocessable (runs during previous slot)
  - Round 2 target: <800ms critical path
- [ ] **1.1.6** Add Kani harnesses for Ringtail sign/verify roundtrip
- [ ] **1.1.7** Add fuzz target for Ringtail verification (malformed signatures, wrong thresholds)
- [ ] **1.1.8** Miri pass on all unsafe in ntt.rs (modular arithmetic, pointer ops)

### 1.2 Plug PqVrf into Consensus (seal-consensus + seal-vrf)

PqVrf (ML-DSA + SHA3 construction) is complete. Consensus currently uses HmacVrf.

- [ ] **1.2.1** Switch `seal-consensus` election to use `PqVrf` instead of `HmacVrf`
  - File: `crates/seal-consensus/src/election.rs`
  - VRF trait is already abstracted — should be a config change
- [ ] **1.2.2** Update `seal-node` to initialize consensus with PqVrf keys
- [ ] **1.2.3** Verify VRF key rotation works across epoch boundaries with PqVrf
- [ ] **1.2.4** Update benchmarks (PqVrf is ~14ms sign vs ~0.1ms HMAC — must fit 4s slot budget)

### 1.3 ZK Proof Backend — RISC Zero (seal-zk)

This is the largest single work item. The stub prover uses SHA3 hash as "proof".

- [ ] **1.3.1** Add `risc0-zkvm` host dependency to `seal-zk/Cargo.toml` (feature-gated)
- [ ] **1.3.2** Write RISC-V guest program (`seal-zk/guest/src/main.rs`):
  - Accept `GuestInput`: pre_state_root, transaction payloads, claimed_post_root
  - Replay SQL write operations against in-memory Merkle state
  - Verify `pre_state_root → post_state_root` transition
  - Verify all transaction signatures (ML-DSA) inside guest
  - Verify access control policies (RLS)
  - Commit public inputs (roots, block height) to journal
- [ ] **1.3.3** Implement `RiscZeroProver::prove()` host-side
  - Serialize guest input, invoke prover, extract receipt
  - Return STARK proof bytes (no Groth16 wrapper — PQ security)
- [ ] **1.3.4** Implement `RiscZeroVerifier::verify()`
  - Deserialize receipt, verify STARK proof, extract journal
  - Compare journal public inputs against block header
- [ ] **1.3.5** Benchmark: target <10s per block proof (10 SQL txs)
  - If >10s: implement pipelined proving (prove block N while producing N+1)
- [ ] **1.3.6** Batch proof aggregation — update `batch.rs` to compose STARK receipts
- [ ] **1.3.7** Integration test: produce block → generate proof → verify proof → accept block

### 1.4 ZK Proof Backend — SP1 (alternative)

SP1 shares the RISC-V ISA, so the same guest code works. Provides GPU acceleration.

- [ ] **1.4.1** Add `sp1-sdk` dependency (feature-gated `sp1`)
- [ ] **1.4.2** Implement `Sp1Prover::prove()` and `Sp1Verifier::verify()`
  - File: `crates/seal-zk/src/sp1.rs` (placeholder exists)
- [ ] **1.4.3** Benchmark SP1 vs RISC Zero on same guest program
- [ ] **1.4.4** Document switching between backends (Cargo feature flags)

### 1.5 Formal Verification — Lean 4 Completions

- [ ] **1.5.1** Prove MerkleTree.lean `insert_lookup_roundtrip` (sorry → proof)
- [ ] **1.5.2** Prove MerkleTree.lean `root_uniqueness` (sorry → proof)
- [ ] **1.5.3** Prove MerkleTree.lean `ordered_search` (sorry → proof)
- [ ] **1.5.4** Begin VRF.lean: formalize PqVrf uniqueness using VCVio game-based framework
- [ ] **1.5.5** Aeneas extraction: extract seal-merkle Rust → Lean 4 for conformance checking

### 1.6 Formal Verification — TLA+ Trace Conformance

- [ ] **1.6.1** Implement trace logger in `seal-consensus`: emit JSON events for each state transition
- [ ] **1.6.2** Write TLA+ trace conformance checker: compare Rust execution trace against `SealConsensus.tla`
- [ ] **1.6.3** Add to CI: run consensus tests → export trace → check conformance

### 1.7 CI Integration

- [ ] **1.7.1** Add Miri to CI pipeline (`cargo +nightly miri test` on seal-crypto, seal-merkle, seal-storage)
- [ ] **1.7.2** Add cargo-fuzz smoke runs (30s per target) to CI
- [ ] **1.7.3** Add Kani verification to CI (24 existing harnesses)
- [ ] **1.7.4** Set up nightly long-running fuzz jobs (hours, not seconds)

---

## Phase 2 — Multi-Node Testnet

**Goal:** 3-10 validators running consensus with real VRF election, Ringtail committee signing, and ZK proofs.

### 2.1 Multi-Node Consensus

- [ ] **2.1.1** Extend `seal-node` to support multi-validator configuration
  - Validator set from genesis config (addresses + stakes + VRF public keys)
- [ ] **2.1.2** Implement block propagation via `seal-p2p` GossipSub
  - Leader produces block → gossip to committee → committee signs → gossip finalized block
- [ ] **2.1.3** Implement Ringtail committee signing flow:
  - Round 1 messages broadcast during slot N-1
  - Round 2 messages broadcast after leader proposes in slot N
  - Combiner aggregates → finalized block
- [ ] **2.1.4** Implement block validation on receiving nodes
  - Verify VRF proof, verify Ringtail aggregate signature, verify ZK proof, apply state transition
- [ ] **2.1.5** Implement fork choice rule (Algorand: single-slot finality, no forks if >2/3 honest)
- [ ] **2.1.6** Epoch transitions: rotate VRF keys, update validator set, update stakes

### 2.2 Testnet Infrastructure

- [ ] **2.2.1** Write `scripts/testnet.sh` for local multi-node testnet (3-5 validators)
- [ ] **2.2.2** Docker compose configuration for testnet
- [ ] **2.2.3** Genesis block generator with initial validator set + stakes
- [ ] **2.2.4** Testnet faucet (mint test tokens)
- [ ] **2.2.5** Basic block explorer (read-only SQL queries against node state)

### 2.3 SQL Engine Hardening

- [ ] **2.3.1** Audit JOIN implementation completeness (INNER, LEFT, RIGHT, CROSS)
- [ ] **2.3.2** Audit GROUP BY + aggregate functions (COUNT, SUM, AVG, MIN, MAX)
- [ ] **2.3.3** Audit ORDER BY + LIMIT + OFFSET
- [ ] **2.3.4** Subquery support verification
- [ ] **2.3.5** Add property-based tests for complex queries (multi-table JOINs + WHERE + GROUP BY)
- [ ] **2.3.6** Benchmark: SQL engine throughput under ZK proving (txs/block target)

### 2.4 Performance — Incremental Merkle Updates

Currently full Merkle rebuild O(n). This becomes a bottleneck with growing state.

- [ ] **2.4.1** Implement path-only rehashing: on insert/update, only rehash nodes on the root path
- [ ] **2.4.2** Track dirty paths during SQL transaction execution
- [ ] **2.4.3** Benchmark: O(log n) updates vs O(n) rebuild at 10K, 100K, 1M entries
- [ ] **2.4.4** Lean 4 proof: `incremental_insert ≡ full_rebuild` (correctness)
- [ ] **2.4.5** Lean 4 proof: O(log n) bound on path length

### 2.5 PqVrf → LatticeVrf Upgrade

PqVrf (ML-DSA+SHA3) works but isn't a "true" VRF with formal security reduction.
LatticeVrf needs a real ZK proof component.

- [ ] **2.5.1** Fork `zhenfeizhang/lb-vrf`, audit Go implementation
- [ ] **2.5.2** Port LB-VRF ZK proof to Rust (replace hash-based placeholder in `lattice_vrf.rs`)
- [ ] **2.5.3** Switch from schoolbook O(N²) poly multiply to NTT-based O(N log N)
- [ ] **2.5.4** Implement proper verification (currently accepts without soundness check)
- [ ] **2.5.5** Engage original authors (Esgin et al.) for academic review
- [ ] **2.5.6** Begin Lean 4 proof of LB-VRF uniqueness + pseudorandomness
- [ ] **2.5.7** Fuzz testing: malformed proofs, edge-case inputs, cross-key verification
- [ ] **2.5.8** Benchmark: LatticeVrf vs PqVrf latency (must fit 4s slot)

### 2.6 Formal Verification — Rocq Extensions

- [ ] **2.6.1** Model SQL engine state transitions in Rocq
- [ ] **2.6.2** Prove RLS non-bypassability (no query can read/write policy-denied rows)
- [ ] **2.6.3** Attempt `coq-of-rust` auto-extraction on seal-token
- [ ] **2.6.4** Composite proof layer independence in Rocq (Lean 4 alternative)

---

## Phase 3 — Bridges, TEE, Governance

**Goal:** Cross-chain interop, hardware-attested AI inference, on-chain governance.

### 3.1 Bridge — Solana Observer (seal-bridge)

- [ ] **3.1.1** Add Solana RPC client dependency (solana-client or reqwest + JSON-RPC)
- [ ] **3.1.2** Implement `SolanaObserver::poll_events()`:
  - Call `getSignaturesForAddress(bridge_program_id, { until: last_cursor })`
  - For each signature, call `getTransaction(sig, { commitment: "finalized" })`
  - Parse instruction data to extract lock events (amount, sender, dest_seal_address)
- [ ] **3.1.3** Implement `SolanaObserver::is_finalized()` — check `commitment: "finalized"`
- [ ] **3.1.4** Write Solana bridge program (Anchor/Rust):
  - `lock(amount, dest_seal_address)` — transfer SPL tokens to escrow PDA
  - `release(amount, dest_solana_address, threshold_sig)` — release from escrow
  - Event emission for lock/release
- [ ] **3.1.5** Integration test: lock on Solana devnet → detect → mint on SEAL → burn → release

### 3.2 Bridge — Stellar Observer (seal-bridge)

- [ ] **3.2.1** Add Stellar Horizon HTTP client (reqwest)
- [ ] **3.2.2** Implement `StellarObserver::poll_events()`:
  - Call `GET /accounts/{contract_id}/operations?cursor={last_cursor}&order=asc`
  - Filter for lock operations, parse amount + destination
- [ ] **3.2.3** Implement `StellarObserver::is_finalized()` — Stellar has ~5s finality
- [ ] **3.2.4** Write Stellar bridge contract (Soroban/Rust):
  - `lock(amount, dest_seal_address)` — hold XLM/asset in contract
  - `release(amount, dest_stellar_address, threshold_sig)` — release
- [ ] **3.2.5** Integration test: lock on Stellar testnet → detect → mint on SEAL → burn → release

### 3.3 Bridge — Security & Verification

- [ ] **3.3.1** Implement threshold signature verification for bridge release operations
  - Use Ringtail aggregate sig (from Phase 1) to authorize releases
- [ ] **3.3.2** Implement bridge deposit confirmation (require N/M validator attestations)
- [ ] **3.3.3** Verify TLA+ `SealBridge.tla` invariant: `TotalMinted ≤ TotalLocked` holds in Rust impl
- [ ] **3.3.4** Add bridge-specific fuzz targets (malformed deposits, double-mint attempts)
- [ ] **3.3.5** Rate limiting and deposit caps (governance-adjustable)

### 3.4 TEE Attestation Verification (seal-tee)

- [ ] **3.4.1** Implement Intel TDX quote verification
  - Parse TDX report structure
  - Verify against Intel DCAP root of trust (PCS API or local collateral)
- [ ] **3.4.2** Implement Intel SGX quote verification (EPID or DCAP)
- [ ] **3.4.3** Implement AMD SEV-SNP report verification
  - Parse SNP attestation report
  - Verify against AMD root key (ARK → ASK → VCEK chain)
- [ ] **3.4.4** Implement NVIDIA Confidential Computing attestation
  - H100/H200 GPU attestation format
  - Verify against NVIDIA RIM (Reference Integrity Manifest)
- [ ] **3.4.5** Implement continuous re-attestation (every 5 minutes)
  - Stale attestation → node removed from active set
- [ ] **3.4.6** Implement ZK + TEE hybrid verification
  - TEE produces inference result + attestation
  - ZK proof wraps attestation for on-chain verification
- [ ] **3.4.7** Implement inference request routing
  - Route to cheapest fresh TEE node supporting requested model
  - Load balancing across multiple TEE nodes

### 3.5 Governance Module (seal-node)

- [ ] **3.5.1** Implement proposal creation (6 tracks from GOVERNANCE.md):
  - Runtime Parameter, Treasury Small (<1%), Treasury Large (>1%), Protocol Upgrade, Emergency, Constitutional
- [ ] **3.5.2** Implement conviction voting with 3-tier multiplier (1×/2×/4× with 30/90-day locks)
- [ ] **3.5.3** Implement adaptive quorum (floor 5%, ceiling 20%, weekly adjustment)
- [ ] **3.5.4** Implement delegation with per-delegate cap (4% of circulating supply)
- [ ] **3.5.5** Implement Technical Council (7-11 members, elected by Token House)
  - Whitelist emergency actions
  - Fast-track PQC algorithm rotation (75% supermajority, 1-day timelock)
- [ ] **3.5.6** Implement Service Operators Council (advisory + binding veto on SLA-breaking)
- [ ] **3.5.7** Snapshot voting power at proposal creation time (flash-loan mitigation)
- [ ] **3.5.8** Implement timelocks per track (1 day emergency → 14 days constitutional)
- [ ] **3.5.9** Post-mortem publication requirement for emergency patches (30-day window)

### 3.6 Token Economics — Burn-and-Mint

- [ ] **3.6.1** Implement fee burning (portion of tx fees burned)
- [ ] **3.6.2** Implement validator rewards (mint new tokens per epoch)
- [ ] **3.6.3** Implement tail emission floor (2% annual inflation minimum)
- [ ] **3.6.4** Implement supply tracking (total minted, total burned, circulating)
- [ ] **3.6.5** Finalize parameters: initial supply, max supply, validator min stake
- [ ] **3.6.6** Rocq proof: burn-and-mint preserves supply invariants

---

## Phase 4 — Performance & Data Structures

**Goal:** Scale to production throughput. Advanced data structures for ZK efficiency.

### 4.1 GPU Proving Acceleration

- [ ] **4.1.1** Integrate SP1 Hypercube for GPU-accelerated STARK proving
- [ ] **4.1.2** Benchmark: CUDA (RTX 4090 / A100) proving times for 10-tx blocks
- [ ] **4.1.3** Investigate Apple Metal acceleration (currently CPU-only on macOS)
- [ ] **4.1.4** Implement pipelined proving: prove block N on GPU while producing N+1 on CPU
- [ ] **4.1.5** Target: <5s proof generation with GPU, <15s without

### 4.2 Persistent Red-Black Trees (Phase 3 data structures)

- [ ] **4.2.1** Implement persistent (purely functional) RB-tree for SQL indexes
  - Based on Appel's verified Coq implementation
  - Path copying for structural sharing
- [ ] **4.2.2** Integrate with SQL engine `index.rs`
- [ ] **4.2.3** Benchmark: index lookup/insert performance vs current approach
- [ ] **4.2.4** Lean 4 proofs: RB invariants (color, black-height balance)

### 4.3 Persistent HAMT (Phase 4 data structures)

- [ ] **4.3.1** Implement Hash Array Mapped Trie for account state
  - 32-way branching, structural sharing across versions
  - Content-addressed nodes (SHA3 hash as pointer)
- [ ] **4.3.2** Replace HashMap-based account storage with HAMT
- [ ] **4.3.3** Benchmark: HAMT vs Merkle B-tree for account lookups at scale
- [ ] **4.3.4** Rocq proof: HAMT lookup correctness, structural sharing efficiency

### 4.4 State Pruning & Archive Nodes

- [ ] **4.4.1** Implement state pruning: discard old Merkle nodes not reachable from recent roots
- [ ] **4.4.2** Implement archive node mode: retain all historical state
- [ ] **4.4.3** Implement state sync: new nodes download recent state snapshot + replay recent blocks
- [ ] **4.4.4** Benchmark: storage growth rate with/without pruning

### 4.5 Decoupled Mempool (Narwhal-style)

- [ ] **4.5.1** Separate transaction dissemination from consensus ordering
- [ ] **4.5.2** Implement mempool with deduplication and priority ordering
- [ ] **4.5.3** Leader references mempool certificates in block proposal
- [ ] **4.5.4** Benchmark: throughput improvement from decoupled mempool

---

## Phase 5 — Advanced Cryptography

**Goal:** Cutting-edge PQC upgrades, MPC capabilities.

### 5.1 LaV Migration (Many-Time PQ-VRF)

- [ ] **5.1.1** Monitor LaV paper/implementation availability
- [ ] **5.1.2** Implement LaV if available (replaces LB-VRF, avoids key rotation)
- [ ] **5.1.3** Formal verification of LaV properties
- [ ] **5.1.4** Migration plan: LB-VRF → LaV with governance vote

### 5.2 SNARKing Committee Signatures

- [ ] **5.2.1** Research: STARK proof of Ringtail aggregate verification
  - Goal: sub-KB on-chain proof (vs 13.4 KB Ringtail output)
- [ ] **5.2.2** Implement recursive STARK composition for signature aggregation
- [ ] **5.2.3** Benchmark: verification cost savings for light clients

### 5.3 MPC Capabilities

- [ ] **5.3.1** Implement SPDZ-style private aggregation (private input sum without revealing individual values)
- [ ] **5.3.2** Implement Private Set Intersection (PSI) for privacy-preserving queries
- [ ] **5.3.3** Integrate with SQL engine (private aggregate functions)

### 5.4 libp2p ML-KEM Transport (upstream dependency)

- [ ] **5.4.1** Track libp2p PQ transport RFC/implementation
- [ ] **5.4.2** When available: replace Noise + ML-KEM double-encryption with native PQ transport
- [ ] **5.4.3** Remove double-encryption layer in `pq_encrypt.rs`
- [ ] **5.4.4** Update HNDL risk assessment (P2P moves from HIGH to NONE)

---

## Phase 6 — Applications & Developer Experience

**Goal:** SDK, GUI, developer tooling for app builders.

### 6.1 Client SDKs

- [ ] **6.1.1** JavaScript/WASM SDK:
  - Wallet management (generate, import, sign)
  - SQL query submission and result parsing
  - Block/tx subscription via WebSocket
  - TypeScript types generated from Rust structs
- [ ] **6.1.2** Python SDK:
  - Same capabilities as JS SDK
  - Jupyter notebook integration for data exploration
- [ ] **6.1.3** SDK documentation with examples

### 6.2 GUI Application

- [x] **6.2.1** GUI stack chosen: Electron + WASM crypto for the wallet; egui for the desktop block explorer
- [ ] **6.2.2** Implement wallet UI: create/import wallet, view balances, send/receive
- [ ] **6.2.3** Implement SQL console: query editor, results table, schema browser
- [ ] **6.2.4** Implement block explorer: block list, tx details, state inspection
- [ ] **6.2.5** Implement governance UI: proposals, voting, delegation
- [ ] **6.2.6** Implement bridge UI: deposit/withdraw across chains

### 6.3 Developer Tooling

- [ ] **6.3.1** `seal migrate` CLI hardening (analyze → plan → apply pipeline)
- [ ] **6.3.2** App deployment tooling (`seal app deploy` with namespace management)
- [ ] **6.3.3** Local devnet mode (`seal dev` — single-node with auto-block production)
- [ ] **6.3.4** Testnet faucet CLI (`seal faucet request`)

---

## Phase 7 — Security Audit & Mainnet

**Goal:** External audit, bug bounty, mainnet launch.

### 7.1 Security Audit

- [ ] **7.1.1** Internal security review (all crates, focus on unsafe, crypto, consensus)
- [ ] **7.1.2** Commission external PQC crypto audit (Veridise recommended — they audited RISC Zero)
- [ ] **7.1.3** Commission external protocol audit (consensus, bridge, governance)
- [ ] **7.1.4** Commission external smart contract audit (Solana + Stellar bridge programs)
- [ ] **7.1.5** Fix all audit findings
- [ ] **7.1.6** Publish audit reports

### 7.2 Bug Bounty

- [ ] **7.2.1** Launch bug bounty program (Immunefi)
- [ ] **7.2.2** Define severity tiers and reward amounts
- [ ] **7.2.3** Security contact email and disclosure policy (currently TBD in SECURITY.md)

### 7.3 Formal Verification — Final Pass

- [ ] **7.3.1** All Lean 4 sorries resolved (MerkleTree.lean, VRF.lean)
- [ ] **7.3.2** LB-VRF Lean 4 proof published alongside implementation
- [ ] **7.3.3** TLA+ trace conformance passing in CI
- [ ] **7.3.4** All Kani harnesses green in CI
- [ ] **7.3.5** Extended fuzzing campaign (days, not seconds)
- [ ] **7.3.6** Publish formal verification report

### 7.4 Mainnet Preparation

- [ ] **7.4.1** Genesis block with initial validator set
- [ ] **7.4.2** Token distribution (foundation, team vesting, ecosystem)
  - Team tokens vest 6 months after economic vesting (anti-capture)
- [ ] **7.4.3** Validator onboarding documentation
- [ ] **7.4.4** Node operator runbook (monitoring, upgrades, key rotation)
- [ ] **7.4.5** Incentivized testnet (stress test with real stakes)
- [ ] **7.4.6** **Mainnet launch**

---

## Phase Dependency Graph

```
Phase 1 (Core Protocol)
  ├── 1.1 Ringtail NTT ──────────────────────────┐
  ├── 1.2 PqVrf in Consensus                      │
  ├── 1.3 ZK Backend (RISC Zero)                  │
  ├── 1.4 ZK Backend (SP1)                        │
  ├── 1.5 Lean 4 completions                      │
  ├── 1.6 TLA+ trace conformance                  │
  └── 1.7 CI integration                          │
                                                   │
Phase 2 (Multi-Node Testnet) ◄─────────────────────┘
  ├── 2.1 Multi-node consensus (needs 1.1 + 1.2 + 1.3)
  ├── 2.2 Testnet infra
  ├── 2.3 SQL hardening
  ├── 2.4 Incremental Merkle
  ├── 2.5 LatticeVrf upgrade
  └── 2.6 Rocq extensions

Phase 3 (Bridges, TEE, Governance) ◄── Phase 2
  ├── 3.1 Solana bridge
  ├── 3.2 Stellar bridge
  ├── 3.3 Bridge security (needs 1.1 Ringtail)
  ├── 3.4 TEE attestation
  ├── 3.5 Governance
  └── 3.6 Token economics

Phase 4 (Performance) ◄── Phase 2
  ├── 4.1 GPU proving
  ├── 4.2 Persistent RB-trees
  ├── 4.3 HAMT
  ├── 4.4 State pruning
  └── 4.5 Decoupled mempool

Phase 5 (Advanced Crypto) ◄── Phase 3, Phase 4
  ├── 5.1 LaV VRF
  ├── 5.2 SNARKing sigs
  ├── 5.3 MPC
  └── 5.4 libp2p ML-KEM

Phase 6 (Applications) ◄── Phase 2
  ├── 6.1 SDKs
  ├── 6.2 GUI
  └── 6.3 Developer tooling

Phase 7 (Audit & Mainnet) ◄── Phase 3, Phase 4, Phase 5
  ├── 7.1 Security audit
  ├── 7.2 Bug bounty
  ├── 7.3 Formal verification final pass
  └── 7.4 Mainnet launch
```

---

## Task Count Summary

| Phase | Tasks | Critical Path |
|-------|-------|---------------|
| **Phase 1** — Core Protocol | 30 | Ringtail NTT + ZK guest program |
| **Phase 2** — Multi-Node Testnet | 27 | Multi-node consensus + incremental Merkle |
| **Phase 3** — Bridges, TEE, Governance | 35 | Bridge observers + TEE verification |
| **Phase 4** — Performance | 16 | GPU proving + persistent data structures |
| **Phase 5** — Advanced Crypto | 11 | LaV VRF + libp2p ML-KEM (upstream) |
| **Phase 6** — Applications | 13 | SDKs + GUI |
| **Phase 7** — Audit & Mainnet | 17 | External audit + mainnet |
| **Total** | **149** | |

---

## Notes

- Phase 1 items (1.1-1.4) can be parallelized — Ringtail, VRF, and ZK are independent work streams.
- Phases 3, 4, and 6 can run in parallel after Phase 2 completes.
- Phase 5 depends on external factors (LaV paper, libp2p upstream).
- Phase 7 is sequential by nature (audit → fix → re-audit → launch).
- Token supply parameters and validator min stake are governance decisions, not engineering tasks — must be finalized before Phase 3.6 and 7.4.
