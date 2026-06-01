# TLA+ Formal Specifications for Seal DAO

## What is TLA+ and why do we use it?

**TLA+** (Temporal Logic of Actions) is a mathematical language for specifying
and verifying distributed systems. It was created by Leslie Lamport (the L in
LaTeX, Turing Award winner).

**Why we use it**: Distributed consensus protocols are notoriously hard to get
right. Subtle bugs (like the one that cost Beanstalk $182M, or the Tendermint
amnesia bug found by TLA+ at Informal Systems) only manifest under specific
network conditions that are nearly impossible to trigger in unit tests. TLA+
lets us check ALL possible executions mathematically.

**How it works**:
1. You describe the protocol as a state machine (initial state + transitions)
2. You state properties that must always hold (safety) or eventually hold (liveness)
3. A model checker explores every reachable state and verifies the properties
4. If it finds a violation, it gives you a concrete counterexample trace

**What it does NOT do**: TLA+ verifies the PROTOCOL DESIGN, not the Rust code.
The link between them is **trace conformance testing** — we run the Rust
implementation and check that its execution traces are valid under the TLA+ spec.

---

## Files

### `SealConsensus.tla` — Main consensus protocol specification

**Purpose**: Proves that the Seal VRF-based consensus protocol is safe and live.

**What it models**:
- N validators (configurable, typically 3-5 for model checking)
- VRF leader election (modeled as nondeterministic choice — sound because
  we verify safety for ALL possible leader selections)
- Block proposals, committee votes, block finalization
- Slot skipping when proposer is offline

**Key variables**:
- `height`: current block height being decided
- `proposals`: set of blocks that have been proposed
- `votes`: who voted for what at each height
- `finalized`: the finalized block at each height (or "none")
- `proposer`: who was elected as proposer at each height

**Key actions** (state transitions):
- `Propose(v)`: validator v is elected and proposes a block
- `Vote(v, block)`: validator v votes for a block (at most one vote per height!)
- `Finalize(block)`: block gets ≥ Threshold votes → finalized, height advances
- `SkipSlot`: no proposal → skip and advance

**Safety properties proven**:
- `Agreement`: At most one block finalized per height. **THE critical property.**
  A violation means a fork.
- `NoEquivocation`: No validator votes for two blocks at the same height.
  Enforced by protocol rules and verified as invariant.
- `MonotonicHeight`: Chain height never decreases.

**Liveness property proven**:
- `Progress`: Every height is eventually finalized (under fairness assumption).
  "The chain doesn't get stuck."

**How to check**:
```bash
# With TLC (explicit-state, small models):
# Install TLA+ Toolbox, configure:
#   Validators = {"v1", "v2", "v3", "v4"}
#   MaxHeight = 3
#   Threshold = 3

# With Apalache (symbolic, larger models):
apalache-mc check --inv=Agreement SealConsensus.tla
apalache-mc check --inv=NoEquivocation SealConsensus.tla

# Multiple invariants in one run — Apalache (0.55.0+) takes ONE --inv
# flag with a comma-separated list. Repeating --inv makes the CLI
# fall through to its "Usage … Options ???" help banner.
apalache-mc check --inv=Agreement,NoEquivocation,MonotonicHeight \
    SealConsensus.tla
```

For the bridge spec, use the wrapper so the invariant list stays in
one place:

```bash
./scripts/verify-tla-bridge.sh              # default length=10
LENGTH=15 ./scripts/verify-tla-bridge.sh    # deeper search
```

---

## How TLA+ connects to the Rust implementation

```
TLA+ Spec (this file)           Rust Code (seal-consensus)
========================        ==========================
Propose(v)             ↔        ConsensusRunner::advance_slot() → Proposer
Vote(v, block)         ↔        SimpleThreshold::partial_sign()
Finalize(block)        ↔        SimpleThreshold::aggregate() → FinalizedBlock
SkipSlot               ↔        advance_slot() → None (not elected)

Agreement invariant    ↔        Test: no two blocks at same height in chain[]
NoEquivocation         ↔        Test: each validator signs at most once per slot
Progress               ↔        Test: chain height increases over time
```

**Trace conformance** (Done — `crates/seal-consensus/src/trace.rs`,
10 unit tests): the Rust consensus emits `TraceEvent`s for each state
transition; `TlaTraceChecker` validates Agreement / NoEquivocation /
MonotonicHeight against the recorded log. Wired into `scripts/ci.sh`
via the consensus test suite.

---

## Future specs to add

| File | Purpose | Priority |
|------|---------|----------|
| `SealConsensus.tla` | Core consensus safety + liveness | **Done** |
| `SealCompositeProof.tla` | 3-layer proof composition | **Done** |
| `SealBridge.tla` | Bridge lock-and-mint (6 safety invariants) | **Done** |
| `SealToken.tla` | Token conservation (mint/burn/transfer) | Phase 3 |
| `SealEpoch.tla` | Epoch transition + VRF key rotation | Phase 2 |

---

## References

- [TLA+ Home Page](https://lamport.azurewebsites.net/tla/tla.html)
- [Learn TLA+ (tutorial)](https://learntla.com/)
- [Apalache Model Checker](https://apalache-mc.org/)
- [Tendermint TLA+ Spec](https://github.com/cometbft/cometbft/tree/main/spec/light-client)
- [MongoDB TLA+ Conformance Testing (VLDB 2025)](https://www.mongodb.com/company/blog/engineering/conformance-checking-at-mongodb-testing-our-code-matches-our-tla-specs)
