# Seal DAO — Governance Specification

## 1. Three-Body System

Inspired by Polkadot OpenGov + Optimism Collective, adapted for a PQC
infrastructure chain.

### 1.1 Token House — All SEAL holders
- Token-weighted voting with 3-tier conviction multiplier:
  - 1× (no lock), 2× (30-day lock), 4× (90-day lock)
- Decides: treasury spending, economics parameters, protocol upgrades
- Delegation: optional, with per-delegate cap of 4% of circulating supply

### 1.2 Technical Council — 7–11 members, elected by Token House, 1-year terms
- Whitelist emergency actions (security patches, PQC algorithm rotation)
- Vet protocol upgrades for correctness
- Manage cryptographic agility (critical for PQC — NIST standards evolve)
- Cannot unilaterally pass proposals; only whitelist for fast-track

### 1.3 Service Operators Council — Representatives of node/TEE operators
- Advisory vote on infrastructure parameters (storage pricing, compute costs)
- Binding veto on changes that would break SLAs
- Ensures infrastructure providers have voice beyond token speculation

---

## 2. Proposal Tracks

| Track               | Approval | Quorum   | Timelock  | Vote Period |
|----------------------|----------|----------|-----------|-------------|
| Parameter Change     | >50%     | 10%      | 3 days    | 5 days      |
| Protocol Upgrade     | >66%     | 15%      | 14 days   | 14 days     |
| Treasury (small <1%) | >50%     | 10%      | 2 days    | 5 days      |
| Treasury (large)     | >66%     | 15%      | 7 days    | 7 days      |
| Emergency            | >75% + TC| 5%       | 6 hours   | 1 day       |
| Constitutional       | >75%     | 20%      | 28 days   | 14 days     |

TC = Technical Council whitelist required.

---

## 3. Treasury

- **Main treasury**: Governance-controlled. Large allocations via passed proposals.
- **Operations fund**: 5-of-9 elected multisig, capped at 5% of treasury,
  replenished quarterly by governance vote. For grants and time-sensitive ops.
- **Emergency reserve**: 3-of-5 Technical Council, capped, with mandatory
  post-hoc governance ratification within 30 days.
- Per-proposal cap: 5% of total treasury.
- Minimum 20% stablecoin reserve for operational runway.

---

## 4. PQC-Specific Governance

- **Cryptographic agility mandate**: Signature schemes for governance itself
  must be upgradeable without hard fork.
- **Algorithm transition track**: Dedicated emergency sub-track for rotating
  PQC primitives if a scheme is broken. Pre-approved fallback list maintained
  by Technical Council.
- **PQC from day one**: All governance votes signed with ML-DSA. No classical
  crypto in the governance path.
- **Foundation/team tokens**: Governance power vests 6 months after economic
  vesting, preventing early capture.

---

## 5. Anti-Plutocracy Measures

- Conviction voting rewards commitment over capital
- Delegate power caps (4%)
- Service Operators Council as infrastructure-user check
- Adaptive quorum: 5% floor, 20% ceiling, adjusted on 90-day trailing participation

---

## 6. Voting Mechanism Details

### 6.1 Conviction Voting

Voters multiply voting power by locking tokens:

| Lock Period | Multiplier | Unlock Delay |
|-------------|------------|--------------|
| None        | 1×         | Immediate    |
| 30 days     | 2×         | 30 days      |
| 90 days     | 4×         | 90 days      |

Simpler than Polkadot's 6-tier system. Rewards long-term alignment without
punishing participation.

### 6.2 Delegation

- Any SEAL holder can delegate to any address
- Delegator can override delegate's vote on specific proposals
- Delegate can sub-delegate (max depth: 1)
- Per-delegate cap: 4% of circulating supply
- Delegation is revocable at any time (immediate effect on future votes)

### 6.3 Quorum

Adaptive quorum based on trailing 90-day participation:
- Base quorum: 10% of staked supply
- Floor: 5% (prevents gridlock during low-participation periods)
- Ceiling: 20% (prevents plutocratic capture via quorum inflation)
- Adjusts weekly based on actual voter turnout

---

## 7. Proposal Lifecycle

```
1. DRAFT       — Author publishes proposal on-chain with deposit
2. DISCUSSION  — 3-day comment period (no voting)
3. VOTING      — Vote period per track (5-14 days)
4. TIMELOCK    — Execution delayed per track (2-28 days)
5. EXECUTION   — Proposal executes automatically on-chain
```

**Deposit**: Required to prevent spam. Returned if proposal passes or
reaches quorum (even if rejected). Burned only if proposal is vetoed
(>33% "No With Veto" votes, Cosmos-style).

**Cancel mechanism**: During timelock, Technical Council or a guardian
multisig can cancel a queued proposal if a vulnerability is discovered.
Requires post-hoc governance ratification.

---

## 8. Emergency Procedures

### 8.1 PQC Algorithm Rotation

If a PQC primitive is broken (e.g., ML-DSA compromised):

1. Technical Council publishes emergency alert on-chain
2. Emergency proposal auto-created with pre-approved fallback algorithm
3. 1-day fast-track vote (75% supermajority required)
4. 6-hour timelock
5. Network-wide key rotation initiated
6. Nodes have 7-day grace period to rotate keys

### 8.2 Security Patches

1. Technical Council whitelists patch
2. Emergency vote (1 day, 75% threshold)
3. 6-hour timelock
4. Binary upgrade or parameter change applied
5. Post-mortem published within 30 days

---

## 9. Implementation Notes

- Governance module is a system-level app in its own namespace (`seal.governance`)
- Proposals are SQL rows in system tables
- Votes are PQC-signed transactions
- Execution: proposals encode `SqlExec` or `AlterSchema` transactions
  that execute after timelock
- All governance state is Merkle-proven and verifiable by light clients

---

## 10. Design Rationale

### Why Three Bodies?
Token House alone leads to plutocracy (top 10 holders control 44-76% in
most DAOs). Technical Council provides competence check for upgrades.
Service Operators represent infrastructure providers who bear real costs
of parameter changes.

### Why Not Quadratic Voting?
Requires Sybil resistance (wallets are cheap). Only 0.62% of DAOs use it.
Conviction voting achieves similar anti-plutocracy goals without identity
requirements.

### Why Adaptive Quorum?
Fixed quorum either (a) prevents governance during low-participation periods
or (b) is set too low and enables governance attacks. Adaptive quorum with
floor/ceiling addresses both failure modes.

### References
- Polkadot OpenGov — [wiki.polkadot.com](https://wiki.polkadot.com/learn/learn-polkadot-opengov/)
- Optimism Collective — Two-house model (Token House + Citizens' House)
- Cosmos Governance — [hub.cosmos.network](https://hub.cosmos.network/main/governance)
- Tezos Self-Amendment — [docs.tezos.com](https://docs.tezos.com/architecture/governance)
- Compound Governor Bravo — [docs.compound.finance](https://docs.compound.finance/v2/governance/)
