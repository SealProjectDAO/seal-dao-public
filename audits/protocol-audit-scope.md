# Protocol & Economics Audit — Scope Document

**Project**: Seal DAO
**Audit Type**: Protocol Security + Token Economics Audit
**Language**: Rust
**Date Prepared**: 2026-04-02

---

## 1. Executive Summary

This audit covers the non-cryptographic protocol layer of Seal DAO: consensus
mechanism, governance system, token economics, bridge security, and state
management. The goal is to verify protocol-level safety properties and
economic incentive alignment before mainnet launch.

---

## 2. In-Scope Components

### 2.1 Consensus Protocol (`crates/seal-consensus/`)

| Component | File | Priority |
|-----------|------|----------|
| VRF-based leader election | `src/election.rs` | Critical |
| Block production | `src/block.rs` | Critical |
| Committee voting | `src/committee.rs` | Critical |
| Fork choice (heaviest attestation) | `src/fork_choice.rs` | Critical |
| Epoch transitions | `src/epoch.rs` | High |
| Slashing (double-propose, double-vote) | `src/slashing.rs` | High |
| Genesis configuration | `src/genesis.rs` | High |
| Validator set management | `src/validator.rs` | High |

**Key invariants to verify**:
- **Safety**: No two honest validators finalize conflicting blocks at the same height
- **Liveness**: If >2/3 of stake is honest, new blocks are eventually finalized
- **Fairness**: Leader election probability is proportional to stake
- **Slashing correctness**: Only provably misbehaving validators are slashed
- **Fork choice convergence**: All honest nodes converge to the same chain

**Known design**: Algorand-style consensus (VRF sortition + committee voting).
See `SPEC.md` Section 4 and `CONSENSUS-COMPARISON.md` for design rationale.

### 2.2 Token Economics (`crates/seal-token/`)

| Component | File | Priority |
|-----------|------|----------|
| Token parameters | `src/params.rs` | Critical |
| Emission schedule | `src/emission.rs` | Critical |
| Fee mechanism (EIP-1559) | `src/fees.rs` | High |
| Staking / unbonding | `src/staking.rs` | High |
| Treasury | `src/treasury.rs` | High |

**Key invariants to verify**:
- **Supply cap**: Total supply never exceeds MAX_SUPPLY (10B SEAL)
- **Emission monotonicity**: Emission rate decreases over time (10% -> 5% -> 2%)
- **Fee burn**: Burned fees are permanently removed from circulation
- **Staking safety**: Unbonding period prevents nothing-at-stake attacks
- **Treasury**: Only governance can disburse treasury funds
- **No arithmetic overflow**: All token operations use checked arithmetic

**Parameters to assess**:
- Initial supply: 1B SEAL (10^18 micro-SEAL)
- Min validator stake: 1,000 SEAL
- Unbonding period: 21 epochs
- Fee burn rate: 50%
- Emission schedule: 10% -> 5% (years 0-4), 5% -> 2% (years 4-8), 2% floor
- Genesis distribution: 30/20/15/15/10/10

### 2.3 Governance (`crates/seal-token/src/governance.rs`, `delegation.rs`)

| Component | File | Priority |
|-----------|------|----------|
| Proposal tracks (6 types) | `src/governance.rs` | High |
| Conviction voting (7 tiers) | `src/governance.rs` | High |
| Adaptive quorum | `src/governance.rs` | High |
| Delegation (4% cap) | `src/delegation.rs` | High |
| Technical Council | `src/governance.rs` | Medium |
| Service Operators Council | `src/governance.rs` | Medium |

**Key invariants to verify**:
- **No governance capture**: Single entity cannot pass proposals alone
- **Delegation cap**: No delegate controls >4% of circulating supply
- **Conviction lock**: Tokens locked for conviction period
- **Quorum**: Proposals require minimum turnout
- **Three-body checks**: Technical Council veto + Service Operator advisory work correctly
- **Flash loan resistance**: Voting power snapshotted at proposal creation

### 2.4 Bridge (`crates/seal-bridge/`)

| Component | File | Priority |
|-----------|------|----------|
| Chain observer trait | `src/lib.rs` | High |
| Solana observer | `src/lib.rs` | Medium |
| Stellar observer | `src/lib.rs` | Medium |
| Bridge invariants | `src/lib.rs` | Critical |

**Key invariants to verify**:
- **Conservation**: `minted_on_seal <= locked_on_source` at all times
- **No double-mint**: Same deposit event cannot be processed twice
- **Confirmation depth**: Sufficient confirmations before minting
- **Bridge pause**: Emergency pause mechanism works correctly

### 2.5 SQL Engine (`crates/seal-sql/`)

| Component | File | Priority |
|-----------|------|----------|
| SQL parser | `src/parser.rs` | Medium |
| Row-level security | `src/rls.rs` | High |
| App namespace isolation | `src/namespace.rs` | High |

**Key invariant**: RLS policies cannot be bypassed (formally proven in Rocq,
but implementation should be verified against the proof).

### 2.6 State Management

| Component | File | Priority |
|-----------|------|----------|
| Merkle tree | `crates/seal-merkle/` | High |
| State pruning | `crates/seal-storage/` | Medium |
| Persistent indexes (LLRB) | `crates/seal-storage/` | Medium |

---

## 3. Out of Scope

- PQC cryptographic primitives (covered by Veridise audit)
- `libcrux` internals (audited by Cryspen)
- Frontend SDKs (JS/WASM/Python)
- GUI block explorer
- Test-only code

---

## 4. Existing Formal Verification

| Property | Method | Status |
|----------|--------|--------|
| Consensus safety/liveness | TLA+ | Spec + trace conformance |
| Token arithmetic overflow | Kani BMC | 60 harnesses, proven |
| Token conservation | Rocq/Coq | 6 theorems (Balance.v) |
| State machine correctness | Rocq/Coq | 5 theorems (StateMachine.v) |
| RLS non-bypassability | Rocq/Coq | 6 theorems (RLS.v) |
| SQL transitions | Rocq/Coq | 7 theorems (SqlState.v) |
| Bridge deposit/withdrawal | Kani BMC | Conservation proven |
| Merkle tree invariants | Lean 4 | **Proven** — 7 theorems + 6 helper lemmas, 0 sorries as of 2026-05-08 commit `58102e9fc` (`SealVerify/Basic/MerkleTree.lean`) |
| Emission schedule | Kani BMC | Bounded, monotone, no overflow |
| Slashing penalties | Kani BMC | Bounds + saturation proven |
| Fork choice determinism | Kani BMC | 3 harnesses |
| Governance conviction | Kani BMC | Threshold + delegation bounds |

**Gaps the audit should fill**:
- TLA+ spec has not been model-checked with Apalache at scale
- Economic game theory analysis (MEV, validator collusion)
- Bridge security under network partition scenarios
- Governance attack vectors (bribery, dark DAOs)

---

## 5. Threat Model

See `SECURITY.md` for the full threat model. Key actors:
- Honest validators (follow protocol)
- Byzantine validators (up to 1/3 of stake)
- External attackers (no stake)
- Quantum adversary (future)

---

## 6. Build & Test Instructions

```bash
cargo build
cargo test                           # 215+ tests
cargo test -p seal-consensus         # Consensus tests
cargo test -p seal-token             # Token economics tests
cargo kani -p seal-consensus         # Kani proofs
cargo kani -p seal-token             # Token Kani proofs

# Run 5-validator local testnet
docker compose up

# TLA+ model checking (requires Apalache)
apalache-mc check --inv=Agreement formal/tlaplus/SealConsensus.tla
```

---

## 7. Deliverables Expected

1. **Finding report** with severity classification
2. **Economic analysis** — incentive alignment, attack cost analysis
3. **Game theory review** — MEV, validator collusion, governance capture scenarios
4. **Invariant verification** — confirm stated invariants hold in implementation
5. **Recommendations** for parameter tuning or mechanism changes

---

## 8. Contact

- **Technical lead**: security@seal-dao.org
- **Specification**: `SPEC.md` (1400+ lines)
- **Governance spec**: `GOVERNANCE.md`
- **Consensus analysis**: `CONSENSUS-COMPARISON.md`
