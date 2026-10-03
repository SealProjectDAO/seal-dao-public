# TODO.md — Seal DAO Actionable Task Tracker

> See ROADMAP.md for the full phased implementation plan.
> See TODOS.md for the session-prioritized PLAN.
> Updated 2026-04-02; last session-pull from TODOS.md is 2026-05-08
> (Lean 0 sorries; PLAN #2/#3/#4/#5/#6/#7 closed).

---

## Done (2026-04-01)

- [x] Remove all `.unwrap()` / `.expect()` from production code (89 sites, 25 files)
- [x] Add no-unwrap rule to CLAUDE.md coding conventions
- [x] Create ROADMAP.md with 7-phase, 149-task plan

## Done (2026-04-02, batch 2)

- [x] GPU proving acceleration: NVIDIA CUDA, AMD ROCm/HIP, Apple Metal (`gpu.rs`)
- [x] `GpuAcceleratedProver` wrapper with auto-detection + env configuration
- [x] Metal compute accelerator scaffold (NTT throughput estimates per Apple chip)
- [x] ZK benchmark harness (`benches/proving.rs`) for Stub/RISC Zero/SP1/GPU/Batch
- [x] Lean 4 Aeneas extraction scaffold (`SealVerify/Aeneas.lean`) + extraction script
- [x] Aeneas correspondence theorems: insert_lookup, insert_other, rootHash_deterministic
- [x] ML-KEM native transport (`pq_transport.rs`) — replaces Noise at connection level
- [x] `PqTransportSession` with monotonic nonce, frame encrypt/decrypt, MAC verification
- [x] SNARKing committee signatures: `SnarkAggregator` + `AggregatedProof` (Phase 5.2)
- [x] Committee root computation, witness building, O(1) verification scaffold
- [x] MPC crate (`seal-mpc`): SPDZ private aggregation over Goldilocks field (Phase 5.3)
- [x] Beaver triple protocol for secret-shared multiplication
- [x] `spdz_sum` / `spdz_count` for privacy-preserving SQL aggregates
- [x] PSI (Private Set Intersection) for privacy-preserving JOINs
- [x] Hash-based PSI with SHA3 + salt, O(n) initiator + O(1) responder lookup
- [x] LaV many-time PQ-VRF (`lav_vrf.rs`) — lattice-based, unlimited evals per key
- [x] Hash-and-sign with Gaussian mask for many-time security, NTT-accelerated
- [x] Lean 4: LaV VRF uniqueness formalization (`VRF.lean` Section 2)
- [x] LaV types, eval definition, uniqueness theorem, many-time safety axiom
- [x] Lean 4: fixed MerkleTree.lean for Lean 4.8.0 (3 helpers need tactic migration)
- [x] Lean 4: full build passes (VRF + Hash + Aeneas + MerkleTree)
- [x] Mainnet genesis config: `GenesisConfig::mainnet()` with 30/20/15/15/10/10 allocation
- [x] `verify_token_distribution()` validates allocations match params.rs constants
- [x] 4 new mainnet genesis tests (allocation, total, determinism, validation)

## Done (2026-04-02)

- [x] Wire NTT (HandRolledOps) into Ringtail sign/aggregate/verify
- [x] Wire `sample_discrete_gaussian()` into Round 1 via HandRolledOps
- [x] Wire `shamir_share()` / `shamir_reconstruct()` into key distribution (`distribute_key_shares`, `reconstruct_key`)
- [x] Enable norm bound checking in `aggregate_responses()` (per-party and aggregate)
- [x] Implement `verify_signature_full()` with public params A and t
- [x] Calibrate NORM_BOUND (2^53 per-party, 2^60 aggregate) for Shamir-distributed keys
- [x] Add `expand_challenge()` with sparse polynomial (TAU=60 non-zero coefficients)
- [x] Implement `generate_public_params()` with matrix A and key t = A*s + e
- [x] PqVrf already wired into consensus election (was done previously)
- [x] VRF key rotation at epoch boundaries (VrfKeyManager in ConsensusRunner)
- [x] Multi-validator genesis config (`genesis.rs` with testnet/devnet helpers)
- [x] Slashing for double-proposal and double-vote (`slashing.rs`)
- [x] 6 proposal tracks with adaptive quorum + min turnout (governance.rs)
- [x] Conviction voting with 7-tier multiplier (None, X1-X6)
- [x] Delegation with per-delegate 4% cap (`delegation.rs`)
- [x] EIP-1559-style dynamic base fee adjustment (`fees.rs`)
- [x] Token emission schedule: 10% -> 5% -> 2% floor (`emission.rs`)
- [x] Treasury with governance-gated disbursement (`treasury.rs`)
- [x] GossipSub topics for committee-votes, committee-sigs, epoch-transition
- [x] Add Kani harnesses: 51 total across 14 files (25 new)
- [x] Add fuzz target for Ringtail verification (`fuzz_ringtail_verify.rs`)
- [x] Lean 4 proofs: all 4 MerkleTree theorems proven (0 sorries)
- [x] Rocq proofs: all 11 theorems proven (0 Admitted)
- [x] Committee signing flow over P2P (`committee.rs`)
- [x] CommitteeVote/CommitteeSignature/EpochTransition P2P message types
- [x] VoteCollector with dedup and threshold aggregation
- [x] ForkChoice: heaviest-attestation-wins with deterministic tie-breaking
- [x] P2P subscriptions for committee-votes, committee-sigs, epoch-transition
- [x] Technical Council: 7-11 members, whitelist, veto, term expiry
- [x] Service Operators Council: registration, advisory endorse, SLA veto
- [x] Incremental Merkle updates already O(log n) path-only rehash
- [x] Token economics params module (`params.rs`) with genesis distribution
- [x] Genesis allocation: 30% validators, 20% treasury, 15% team, 15% ecosystem, 10% public, 10% reserve
- [x] Kani proofs: allocations sum to initial supply, percentages sum to 100%
- [x] Testnet Docker Compose: 5 validators, volumes, health checks, bootstrap peers
- [x] Kani harnesses for fork choice determinism (3 new)
- [x] Kani harnesses for mod_inv correctness, Shamir roundtrip (2 new)
- [x] Fuzz target for committee vote deserialization
- [x] ZK guest program with simulate_guest() for native testing
- [x] RISC Zero + SP1 provers with simulation mode + real prover scaffolding
- [x] Persistent red-black tree for SQL indexes (LLRB, range scan, structural sharing)
- [x] State pruning with mark-and-sweep GC + archive mode
- [x] Narwhal-style decoupled mempool (DAG, multi-worker, batch certification)
- [x] CI scripts: `ci.sh` (full) and `ci-nightly.sh` (extended fuzz + Lean + Rocq)
- [x] TLA+ trace conformance recorder (`trace.rs`) with Agreement/Equivocation/Monotonic checks
- [x] Rocq RLS non-bypassability proof (6 theorems: default deny, restrict-only, non-bypassable)
- [x] Rocq SQL state transition modeling (7 theorems: insert/update/delete correctness)
- [x] CI formal verification pipeline (`scripts/ci-formal.sh`)
- [x] Updated verify.sh and fuzz-all.sh for all 9 fuzz targets
- [x] Removed GitHub Actions workflows (CI is manual via shell scripts)

---

## Done (2026-04-02, batch 3 — pre-mainnet)

- [x] `scripts/ci.sh`: full CI pipeline — build, test, clippy, Kani (6 crates), Miri (3 crates), fuzz (9 targets), audit
- [x] `scripts/ci.sh quick` mode: build + test + clippy only
- [x] `scripts/ci-nightly.sh`: nightly pipeline — ci.sh + extended fuzz (5min/target) + Lean 4 + Rocq
- [x] CI scripts: proper PASS/FAIL/SKIP tracking, elapsed time, exit code on failure
- [x] Veridise PQC audit scope (`audits/veridise-pqc-scope.md`)
- [x] Protocol audit scope (`audits/protocol-audit-scope.md`)
- [x] Audit README with preparation checklist
- [x] Immunefi bug bounty program (`BUG-BOUNTY.md`) — rewards, scope, rules, SLAs
- [x] Incentivized testnet program (`TESTNET.md`) — 8-week plan, 4 phases
- [x] `GenesisConfig::incentivized_testnet()` with scaled committee, u32 validator IDs
- [x] 3 new incentivized testnet genesis tests
- [x] Mainnet launch checklist (`LAUNCH-CHECKLIST.md`) — pre-launch, day-of, post-launch
- [x] Emergency procedures: consensus halt, critical vuln, bridge emergency

---

## Future TODOs

- [x] ~~Anti-DDoS for RPC~~ — DONE (per-IP rate limiter, 120 req/min, 64KB query cap)
- [x] ~~`seal keygen --kem`~~ — DONE
- [x] ~~TUI wallet app~~ — DONE (`seal wallet`)
- [x] ~~Fix Kani harnesses: seal-threshold~~ — DONE (13 harnesses pass)
- [x] ~~Fix Kani harnesses: seal-consensus~~ — DONE (10 harnesses pass)
- [x] ~~Fix Kani harnesses: seal-merkle~~ — DONE (4 harnesses pass)
- [x] ~~Fix Kani harnesses: seal-bridge~~ — DONE (3 harnesses pass)
- [x] ~~Remove compiler warnings~~ — DONE (near-zero)
- [ ] Seal Wallet app icon — use graphic identity from https://seal-dao.project
- [x] ~~SEAL smart contracts: define execution model~~ — DONE 2026-04-19 (ADR-001: SQL procs default, WASM opt-in)
- [x] ~~Smart contract language~~ — DONE 2026-04-19 (both: `LANGUAGE sql` default, `LANGUAGE wasm` opt-in — see `docs/decisions/ADR-001-stored-procedures-and-wasm.md`)
- [ ] Wire DEX matching into block production (per-block batch auction)
- [ ] Token-gated SQL: RLS policies based on token holdings
- [ ] Transfer fees: configurable per custom token
- [ ] GUI examples: more polished TUI, Electron, Android UIs
- [ ] Browser wallet extension (Safari, Chrome, Firefox, Brave, Edge)
  - WASM-based (reuse seal-dao-wasm for ML-DSA signing)
  - Self-contained: no external dependencies
  - Target: macOS/Linux/Windows on amd64, arm64, riscv64
  - WebExtension manifest v3 for Chrome/Firefox/Brave/Edge
  - Safari Web Extension (requires Xcode wrapper)
  - Connect to local node or remote PQ-encrypted endpoint
- [x] AES-256-GCM in `examples/seal-forms/` (replaced demo XOR-stream
      2026-05-08). Core private tables had been on `aes-gcm 0.10`
      since 2026-04-13 (commit `4e717415`); this closes the demo-app
      residual. Implementation in `examples/seal-forms/src/lib.rs`:
  - `Aes256Gcm` keyed by HKDF-SHA3-256 over the ML-KEM shared secret
    (`info = b"forms.seal/v1/aes-key"`).
  - Nonce = `SHA3-256(form_id_le || respondent_addr || idx_le)[..12]`
    — deterministic, auditor-reconstructible.
  - AAD = `form_id_le || schema_hash || respondent_addr` — binds
    ciphertext to form context; cross-form / cross-respondent
    replay detected by tag mismatch.
  - Dropped `examples/seal-forms/src/aead.rs` (bespoke HMAC-SHA3
    + 15-byte prefix wrapper — AES-GCM gives auth+confid in one
    primitive). Removed `xor_stream` and `expand_block`.
  - New API: `pub struct AnswerContext<'a>` (form_id, schema_hash,
    respondent_addr, idx) + `pub fn schema_hash(json) -> [u8; 32]`;
    `encrypt_answer` / `decrypt_answer` take `&AnswerContext`.
  - Tests (7 in `lib.rs`, was 4): round-trip + tag-length assertion,
    chain-links, schema-DDL parses, wrong-secret-returns-error
    (previously silent garbage), AAD drift on respondent change,
    AAD drift on schema change, ciphertext-tamper breaks both tag
    *and* trace, deterministic-nonce-matches-spec.

---

## Example Applications (deferred)

- [ ] **Web block explorer** — real-time blocks, transactions, accounts, token balances
  - HTML/JS connecting to node via RPC (like standalone wallet but for chain inspection)
  - Block list with pagination, tx detail view, address lookup
  - Token supply dashboard, DEX pair charts
- [ ] **DEX trading UI** — order book visualization, place/cancel orders, trade history
- [ ] **Token exchange / bridge UI** — deposit/withdraw across chains, bridge status
- [ ] **Amazon Kindle-style app** — digital content marketplace with PQC DRM
  - Content stored as encrypted blobs, access gated by token ownership
  - Purchase = token transfer, delivery = RLS-gated SQL read
- [ ] **Slack-style chat app** — private channels with bot integration
  - Messages in private tables (app-private type, encrypted at rest)
  - Bots as namespace apps with RLS-scoped access
  - Keep data as private as possible (MPC for analytics, no plaintext on validators)
- [ ] **Secret manager** — multi-signature encrypted vault
  - Shamir secret sharing across N parties (seal-threshold)
  - M-of-N threshold required to decrypt
  - Audit log on-chain, secrets never on-chain
- [ ] **`forms.seal` — encrypted surveys with ZK-ready traces** —
      Google Forms / SurveyMonkey-style app with strict PQC
      encryption and iterated-hash traces so statistics can later
      be proven in zero knowledge.
  - Answers encrypted under the form's ML-KEM public key; private
    half held by form owner (private surveys) or an MPC committee
    via `seal-mpc` SPDZ (public surveys, so no single party can
    decrypt raw answers).
  - Append-only per-form hash trace: `trace_i =
    SHA3(prev_trace || ct_answer_i || block_seed_i)`. Tip commits
    on-chain; full log is Merkle-reconstructible.
  - ZK circuit (deferred, seal-zk): `(ciphertexts, trace,
    decryption witness) → public stat` — prove mean, count,
    threshold cohorts without revealing answers.
  - RLS: raw ciphertexts readable only by owner/MPC quorum;
    trace is public for transcript-integrity verification.
  - Surfaces: TUI form runner + web builder; submit via
    authenticated RPC.
- [ ] **Auth / 2FA app** — decentralized authentication service
  - ML-DSA keypair as identity, TOTP/HOTP via SHA3
  - Hooks API to add 2FA to existing apps
  - Zero-knowledge age/identity proofs via seal-zk
- [ ] **Decentralized DNS** — name → address resolution on-chain
  - `seal1name.seal` → IP/content hash mapping
  - Fully decentralized static web page serving (Merkle tree of content)
  - SQL-linked version: pages as rows, served via namespace RPC
  - Off-chain data with on-chain Merkle root commitment
- [ ] **Decentralized NAS / disk manager** — distributed file storage
  - Files chunked, encrypted, distributed across nodes
  - Metadata (file tree, permissions) in private SQL tables
  - Erasure coding for redundancy
- [ ] **Limited subnetwork consensus** — non-official operating mode
  - Private subnets for NAS/chat/enterprise apps
  - Subset of validators run consensus on app-specific data
  - Lower latency (fewer validators), same Algorand-style protocol
  - Relevant for NAS, Slack, secret manager — apps that don't need global consensus

---

## Token & Payment System — Implementation Plan

Wire the existing token economics (seal-token) into the live node so SEAL
can function as a native coin with transfers, balances, and token creation
(similar to Solana SPL tokens or Stellar assets).

### Phase 1: Native SEAL Coin (wire existing code)

- [ ] `seal_getBalance` RPC — query balance by seal address from the real BalanceStore
- [ ] `seal_transfer` RPC — signed transfer of SEAL between addresses
  - ML-DSA signed, nonce-checked, fee-deducted
  - Creates a `Transfer` transaction type in the pending pool
  - Balance updates applied when block is produced
- [ ] Wire emission schedule into epoch transitions (currently computed but not applied)
- [ ] Wire treasury allocation (10% of emission per epoch to treasury address)
- [ ] Genesis balances: load initial 30/20/15/15/10/10 distribution into BalanceStore at node start
- [ ] Wallet integration: `seal wallet` shows real SEAL balance via `seal_getBalance`
- [ ] Desktop + Android wallets query and display balance

### Phase 2: Custom Token Creation (SPL/Stellar-style)

- [ ] `seal_createToken` RPC — deploy a new token with name, symbol, decimals, max supply
  - Token metadata stored on-chain (namespace: `tokens.<symbol>`)
  - Creator becomes the mint authority
- [ ] `seal_mintToken` RPC — mint new tokens (only mint authority)
- [ ] `seal_transferToken` RPC — transfer custom tokens between addresses
- [ ] `seal_getTokenBalance` RPC — query balance of a specific token
- [ ] `seal_listTokens` RPC — list all deployed tokens
- [ ] Token balances stored in per-token BalanceStore (reuse seal-token/balance.rs)
- [ ] Token metadata: name, symbol, decimals, total_supply, max_supply, mint_authority, freeze_authority

### Phase 3: Advanced Token Features

- [ ] Freeze/unfreeze accounts (freeze authority)
- [ ] Burn tokens (holder or burn authority)
- [ ] Transfer fees (configurable per token, collected by token creator)
- [ ] Token-gated SQL access (RLS policies based on token holdings)
- [ ] DEX: on-chain order book for SEAL ↔ custom token swaps
- [ ] Bridge tokens: wSOL, wXLM, wUSDC backed by bridge deposits

### Architecture Notes

```
Transaction Types:
  SqlExec       — existing: SQL write
  Transfer      — new: SEAL transfer (sender, recipient, amount)
  TokenCreate   — new: deploy custom token
  TokenMint     — new: mint custom tokens
  TokenTransfer — new: transfer custom tokens

Balance Storage:
  SEAL:   BalanceStore (existing in seal-token/balance.rs)
  Custom: HashMap<TokenId, BalanceStore> (one per token)

Fee Flow:
  Transaction → fee deducted from sender → 50% burned, 50% to proposer
  Custom token transfers: optional creator fee on top of SEAL gas fee
```

---

## In-Code TODOs

These are `// TODO` comments found in the source — each maps to a ROADMAP item.

| File | Line | TODO | ROADMAP Ref |
|------|------|------|-------------|
| `seal-zk/src/stub.rs` | 6 | Replace with RISC Zero | Phase 1.3 |
| `seal-threshold/src/simple.rs` | 7 | Replace with Ringtail (ePrint 2024/1113) | Phase 1.1 |
| `seal-vrf/src/hmac_vrf.rs` | 17 | Replace with LB-VRF (Esgin et al. FC 2021) | Phase 2.5 |
| `seal-bridge/src/lib.rs` | 11 | TLA+ spec formal verification | Phase 3.3 |

---

## Blocking Items (must complete before production)

### 1. Wire NTT into Ringtail (Phase 1.1) — DONE
- [x] Replace `StubRingOps` with `HandRolledOps` in `ringtail.rs` sign/aggregate
- [x] Wire `sample_discrete_gaussian()` into Round 1
- [x] Wire `shamir_share()` / `shamir_reconstruct()` into key distribution
- [x] Implement real `verify_signature()` (norm bound + challenge hash check)
- [x] Benchmark: 67-of-100 party signing = 352ms (target <2000ms WAN — PASS)
- [x] Add Kani harnesses for Ringtail sign/verify (4 harnesses)
- [x] Add fuzz target for Ringtail verification

### 2. Plug PqVrf into Consensus (Phase 1.2) — DONE
- [x] Switch `seal-consensus` election from `HmacVrf` to `PqVrf`
- [x] Update `seal-node` to initialize with PqVrf keys
- [x] Verify VRF key rotation across epoch boundaries
- [x] Benchmarks: PqVrf eval 11.6ms, verify 10.4ms

### 3. ZK Proof Backend — RISC Zero (Phase 1.3) — SIMULATION DONE
- [x] Guest program: GuestInput/GuestOutput types, simulate_guest() for native testing
- [x] Implement `RiscZeroProver::prove()` with simulation mode
- [x] Implement `RiscZeroVerifier::verify()` with commitment check
- [x] Batch proof aggregation (batch.rs already complete)
- [x] Vendorize `risc0-zkvm` 5.0 (760 crates, builds with --features risc0)
- [x] GPU acceleration module: NVIDIA CUDA, AMD ROCm, Apple Metal (`gpu.rs`)
- [x] Benchmark harness (`benches/proving.rs`) — awaiting real GPU hardware for numbers
- [x] End-to-end integration test (10 E2E tests in simulation mode)

### 4. ZK Proof Backend — SP1 (Phase 1.4) — SIMULATION DONE
- [x] Implement `Sp1Prover` / `Sp1Verifier` with simulation
- [x] Cross-compatibility verified (same guest output as RISC Zero)
- [x] Vendorize `sp1-sdk` 6.0 (needs Rust 1.91+ to build with feature)
- [x] Benchmark harness ready (`benches/proving.rs`) — awaiting GPU + Rust 1.91 for numbers

### 5. Bridge Chain Observers (Phase 3.1-3.2) — STUBS DONE
- [x] ChainObserver trait + BridgeEvent/DepositConfirmation types
- [x] SolanaObserver stub (getSignaturesForAddress RPC documented)
- [x] StellarObserver stub (Horizon API documented)
- [x] Solana bridge program skeleton (Anchor) — bridges/solana/
- [x] Stellar bridge contract skeleton (Soroban) — bridges/stellar/

### 6. TEE Attestation Verification (Phase 3.4) — STUBS DONE
- [x] TeeAttestation trait + AttestationResult
- [x] Intel TDX quote verification stub (DCAP documented)
- [x] AMD SEV-SNP report verification stub (VCEK chain documented)
- [x] NVIDIA CC attestation stub
- [x] ReattestationTimer (5-min default, expired detection)

---

## Open Tracks — High-Level Summary

- **Formal verification**: DONE — Lean 4, Rocq, Kani, Miri, fuzz all in CI
- **Performance**: GPU benchmarks on real hardware (CUDA/ROCm/Metal) — pending hardware
- **Networking**: DONE — ML-KEM native transport, GossipSub, committee P2P
- **Governance**: DONE — all three bodies implemented
- **DX/Apps**: DONE — SDKs, GUI, `seal dev` local devnet
- **Advanced crypto**: DONE — LaV VRF, SNARKing committee sigs, MPC
- **Pre-mainnet**: DONE — audits scoped, bug bounty program, incentivized testnet, launch checklist

---

## Formal Verification TODOs

- [x] Lean 4: all MerkleTree.lean theorems proven (0 sorries)
- [x] Lean 4: formalize LaV VRF uniqueness (Phase 1.5) — `VRF.lean` Section 2
- [x] Lean 4: Aeneas extraction scaffold + correspondence theorems (Phase 1.5)
- [x] TLA+: trace conformance checker (Phase 1.6) — `trace.rs` with 10 tests
- [x] Rocq: all Balance.v + StateMachine.v theorems proven (0 Admitted)
- [x] Rocq: RLS non-bypassability proof (Phase 2.6) — 6 theorems in RLS.v
- [x] Rocq: SQL engine state transition modeling (Phase 2.6) — 7 theorems in SqlState.v
- [x] CI scripts (`scripts/ci.sh`, `scripts/ci-nightly.sh`) — test, clippy, Kani, Miri, fuzz, audit, Lean 4, Rocq
- [x] Miri in CI (Phase 1.7) — `scripts/ci.sh` step 5, 3 crates (seal-crypto, seal-merkle, seal-storage)
- [x] Kani: 60 harnesses across 16 files (Phase 1.7)
- [x] Kani in CI (Phase 1.7) — `scripts/ci.sh` step 4, 6 crates including seal-bridge
- [x] Nightly long-running fuzz jobs (Phase 1.7) — `scripts/ci-nightly.sh` (extended fuzz + Lean 4 + Rocq)
- [x] Fuzz: 9 targets (added fuzz_ringtail_verify, fuzz_committee_vote)

---

## Performance TODOs

- [x] Incremental Merkle updates — O(log n) path-only rehash (Phase 2.4) — already implemented
- [x] GPU proving module: CUDA + ROCm + Metal (Phase 4.1) — hardware benchmarks pending
- [x] Persistent red-black trees for SQL indexes (Phase 4.2) — LLRB with range scan
- [x] HAMT for account state (Phase 4.3) — 32-way trie, structural sharing, Merkle-compatible
- [x] State pruning & archive nodes (Phase 4.4) — mark-and-sweep GC, archive mode
- [x] Decoupled mempool — Narwhal-style (Phase 4.5) — DAG-based, multi-worker, certified batches

---

## Multi-Node & Networking TODOs

- [x] Multi-validator genesis config (Phase 2.1)
- [x] Block propagation via GossipSub (Phase 2.1)
- [x] Ringtail committee signing flow over P2P (Phase 2.1)
- [x] Block validation on receiving nodes (Phase 2.1) — height, parent hash, VRF, state root
- [x] Fork choice rule (Phase 2.1) — heaviest attestation wins
- [x] Epoch transitions (Phase 2.1) — basic handling + P2P announcement messages
- [x] Testnet infrastructure + Docker compose (Phase 2.2) — 5 validators

---

## Governance & Token Economics TODOs

- [x] 6 proposal tracks (Phase 3.5)
- [x] Conviction voting with 7-tier multiplier (Phase 3.5)
- [x] Adaptive quorum (Phase 3.5)
- [x] Delegation with per-delegate cap (Phase 3.5)
- [x] Technical Council (Phase 3.5) — whitelist, veto, term management
- [x] Service Operators Council (Phase 3.5) — advisory endorse, SLA veto
- [x] Fee burning + validator rewards + EIP-1559 dynamic fees (Phase 3.6)
- [x] Token emission schedule (Phase 3.6)
- [x] Treasury with governance-gated disbursement (Phase 3.6)
- [x] Finalize: initial supply, max supply, validator min stake (Phase 3.6) — `params.rs`

---

## Advanced Crypto TODOs

- [x] LatticeVrf: NTT-accelerated eval + few-time eval counter (Phase 2.5)
- [x] LaV many-time PQ-VRF (Phase 5.1) — `lav_vrf.rs` with 14 tests
- [x] SNARKing committee signatures (Phase 5.2) — `snark_agg.rs` scaffold
- [x] MPC: SPDZ private aggregation + PSI (Phase 5.3) — `seal-mpc` crate
- [x] libp2p ML-KEM native transport (Phase 5.4) — `pq_transport.rs` with session mgmt

---

## Applications & DX TODOs

- [x] JavaScript/WASM SDK scaffold (Phase 6.1) — sdks/js/ + sdks/wasm/
- [x] Python SDK scaffold (Phase 6.1) — sdks/python/
- [x] GUI application — egui block explorer scaffold (Phase 6.2)
- [x] `seal migrate` CLI hardening (Phase 6.3) — 4 new tests, function/view stripping
- [x] Local devnet mode `seal dev` (Phase 6.3) — 1s slots, auto-activity, pretty output

---

## Storage & Right-to-be-Forgotten TODOs (`#STORAGE-FORGET`) — DONE

### SPEC.md formalization — DONE
- [x] SPEC §7.4 Storage Leases — `StorageLease` struct (table, owner, paid_through, row_count, byte_size, rate, governance_hold)
- [x] SPEC §7.3 Row Salting — per-row `salt: [u8; 32]` mixed into Merkle leaf hash (`SHA3(table:pk || salt || row)`)
- [x] SPEC §7.4 Write Invoicing — SEAL burn / Compute Credit deduction per bytes written (INSERT/UPDATE)
- [x] SPEC §7.4 Read Invoicing — micro-fee per SELECT or stake-gate per namespace
- [x] SPEC §7.5 Lease Expiry & Pruning — grace period (governance-adjustable, default 30 days), then validators prune rows + salts
- [x] SPEC §7.5 Expired Data Serving Prohibition — serving expired/pruned data is a slashable offense; governance vote can grant exemptions via `governance_hold` flag

### Implementation — DONE
- [x] `seal-sql/types.rs`: `salt: RowSalt` field with `generate_salt()` (random, local/test) + `derive_salt(block_seed, table, row_index)` (deterministic, consensus)
- [x] `seal-sql/merkle_state.rs`: mixes salt into Merkle leaf (`hex::encode(row.salt) + ":" + values`)
- [x] `seal-token/storage_lease.rs`: `StorageLease` struct + `LeaseManager` + expiry tracking
- [x] `seal-node/consensus_runner.rs`: write invoicing — per-byte burn wired into block application (`apply_write_invoicing`)
- [x] `seal-node`: read stake-gate — namespace access via staked balance (token-gated RLS)
- [x] `seal-storage/pruning.rs`: `PruningManager` + lease expiry hook via `ConsensusRunner::leases`
- [x] Governance parameter for grace period — surfaced as testnet config; production adjustable via Technical Council

---

## Pre-Mainnet TODOs

- [x] External PQC crypto audit — Veridise (Phase 7.1) — scope document: `audits/veridise-pqc-scope.md`
- [x] External protocol audit (Phase 7.1) — scope document: `audits/protocol-audit-scope.md`
- [x] Bug bounty program — Immunefi (Phase 7.2) — program spec: `BUG-BOUNTY.md`
- [x] Security contact email + bug bounty scope in SECURITY.md (Phase 7.2)
- [x] All Lean 4 sorries resolved (Phase 7.3) — confirmed 0 sorries
- [x] Extended fuzzing campaign script (Phase 7.3) — scripts/fuzz-extended.sh (1hr default)
- [x] Incentivized testnet (Phase 7.4) — program: `TESTNET.md`, genesis: `incentivized_testnet()`
- [x] Genesis block + token distribution (Phase 7.4) — `GenesisConfig::mainnet()`
- [x] **Mainnet launch** (Phase 7.4) — launch checklist: `LAUNCH-CHECKLIST.md`

---

## Bridge TODOs

### Solana Bridge (~60% done, ~20% production-ready)

- [x] Anchor program scaffold (`bridges/solana/`)
- [x] `initialize()` — bridge state setup
- [x] `lock_tokens()` — lock SOL/SPL, amount tracking, nonce protection
- [x] `unlock_tokens()` — structure done
- [ ] Real threshold signature verification (currently stubbed, always passes)
- [ ] SPL token transfer CPI (actual on-chain transfer)
- [ ] Event emission for relay service to watch
- [ ] Relay service: watch Solana → submit proofs to Seal
- [ ] `SolanaObserver` — wire stub to real RPC polling

### Stellar Bridge (~60% done, ~20% production-ready)

- [x] Soroban contract scaffold (`bridges/stellar/`)
- [x] `initialize()` — bridge state setup
- [x] `lock_xlm()` / `unlock_xlm()` — structure + nonce protection
- [x] 5 tests (init, lock, unlock, replay)
- [ ] Real ML-DSA/ECDSA threshold signature verification (stubbed)
- [ ] Actual XLM transfer calls (stubbed with TODO)
- [ ] Event emission for relay
- [ ] Relay service: watch Stellar Horizon → submit proofs to Seal
- [ ] `StellarObserver` — wire stub to real Horizon API

### Ethereum Bridge (deferred — Medium complexity, ~2-3 months)

- [ ] `SealBridge.sol` — Solidity lock/mint contract on Ethereum
- [ ] Event relay: watch Ethereum events → submit proofs to Seal
- [ ] ETH event proof verification on Seal (receipt + Merkle proof)
- [ ] wETH minting on Seal when deposit confirmed
- [ ] Withdrawal: burn wETH on Seal → committee signs → contract releases
- [ ] ERC-20 generic support (any ERC-20 bridgeable)
- [ ] 12-32 block confirmation depth

### Bitcoin Bridge (deferred — Very High complexity, ~3-6 months)

- [ ] SPV light client on Seal (verify BTC block headers)
- [ ] BTC header relay service (submit ~144 headers/day)
- [ ] Multi-sig BTC address controlled by Seal committee (Ringtail threshold)
- [ ] Deposit: user sends BTC → relay submits SPV proof → Seal mints wBTC
- [ ] Withdrawal: burn wBTC → committee signs BTC tx → broadcast
- [ ] ECDSA threshold signatures for BTC (BTC doesn't support PQC)
- [ ] 6-block confirmation depth (~60 min)

### Common Bridge Infrastructure

- [x] `ChainObserver` trait + `BridgeEvent` types (`crates/seal-bridge/`)
- [x] Bridge invariant: `minted_on_seal <= locked_on_source` (Kani-proven)
- [x] Ringtail threshold signatures (committee can sign messages)
- [x] Bridge manager RPC: `seal_bridgeDeposit`, `seal_bridgeWithdraw`, `seal_bridgeStatus` — landed 2026-04-19
- [x] Bridge pause mechanism (Technical Council 2/3 vote) — landed 2026-04-19 post-session (`seal_bridgePauseChain` / `seal_bridgeUnpauseChain` / `seal_bridgeListPaused` gated on `TechnicalCouncil::has_two_thirds_approval`; bootstrap via `seal_bridgeCouncil{Add,Remove,List}`)
- [ ] Multi-chain bridge dashboard in wallet apps
