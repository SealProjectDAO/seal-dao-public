# Seal DAO — DEX Speed / PQC Proposal (Track A)

**Status:** Proposal (not yet implemented)
**Author:** design exploration, 2026-06-19
**Related:** `docs/DEX-DESIGN.md` (current batch-auction CLOB), `docs/DEX-PERPS-MARGIN-PROPOSAL.md` (Track B)

## Goal

Match a continuous-CLOB venue's latency profile (reference: `0xmonaco.com`
— *"<1 ms matching and 400 ms settlement"*, *"verifiable order-matching and
single-slot finality on the EVM"*) **while remaining PQC-native**.

Today Seal clears the order book once per ~4 s block inside `produce_block`
(`crates/seal-node/src/consensus_runner.rs:714`, `DexManager::match_all`).
Trade latency therefore equals block time.

## Why Seal is 4 s (and why the matcher is not the bottleneck)

`OrderBook::match_orders` (`crates/seal-token/src/orderbook.rs:189`) is
O(n log n) over `BTreeMap` bid/ask sides — microseconds per block. The 4 s
floor comes from two PQC costs on the consensus hot path (`SPEC.md:242`):

- **Ringtail threshold signature** — ~2.5 s WAN latency per slot.
- **STARK proof** — ~1.5 s budget per slot.

So the lever is **not** "make consensus faster" — it is **decouple matching
from finality** (the dYdX-v4 / Hyperliquid pattern) and move PQC from
*blocking the loop* to *pipelined certification*.

## Design: three latency layers, all PQC

| Layer | Latency | PQC signer | Guarantee |
|-------|---------|-----------|-----------|
| Soft confirm | <1 ms | Sequencer ML-DSA sig over hash-chained match-log entry | "matched, here's a receipt" |
| Economic finality | ~400 ms | **Ringtail threshold cert** over batch Merkle root | committee-certified, irreversible |
| Full verifiability | lagging (a few slots) | **STARK proof** referencing the same root | trustless state-transition proof |

### 1. Continuous matching engine

Promote `DexManager` from "matched only inside `produce_block`" to a
standalone task:

- MPSC order intake; match on arrival (or a ~1 ms tick) rather than on the
  4 s block boundary.
- Monotonic `seq: u64` per accepted order.
- Running `match_log_root: Hash256` (SHA3 Merkle over fills).

This is the `<1 ms` tier and the determinism anchor.

### 2. Hash-chained signed match log = "verifiable order-matching"

Each emitted batch:

```rust
struct MatchBatch {
    from_seq: u64,
    to_seq: u64,
    fills: Vec<Trade>,
    prev_root: Hash256,
    root: Hash256,     // SHA3 Merkle(prev_root || fills)
}
```

The sequencer ML-DSA-signs every batch. Soft-confirm receipts reference
`root`. Anyone replaying orders in `seq` order must reproduce `root` — that
is exactly the "verifiable order-matching" property, PQC-signed.

### 3. Pipeline the Ringtail cert to ~400 ms

`SPEC.md:1427` already notes **Ringtail Round 1 is message-independent and
preprocessed during the previous slot** — so the online cost is Round 2
only. Run the committee certifier on **sub-slot micro-batches**: every
~400 ms the proposer collects partials over the current `match_log_root`
and emits a new `TxType::DexMatchCert` carrying the threshold signature.
That threshold cert *is* economic finality — today's full STARK is not
required for irreversibility; the >2/3 Ringtail quorum is.

### 4. Let the STARK lag (pipelined / optimistic proving)

The proof leaves the hot path: it proves a root that was already
threshold-certified slots earlier. This is where the **RTX 6000 / CUDA
STARK proving** host applies — recursive GPU proving keeps pace with the
400 ms cert cadence without blocking it.

**Net:** <1 ms soft, ~400 ms PQC-certified, STARK-verifiable shortly after —
the reference latency profile, entirely post-quantum.

## Code deltas

- New `TxType::DexMatchCert` (threshold-signed batch root); STARK proof
  references the root.
- `DexManager`: add `seq` / `match_log_root` + MPSC intake + `drain_batch()`.
- `consensus_runner`: stop calling `match_all` inline; instead *certify* the
  engine's latest root each ~400 ms sub-slot.
- Verifier: check `cert.root` chains from the last certified root.

## Risks / decisions

- **Single sequencer** = censorship/liveness risk → rotate per epoch via the
  existing VRF proposer selection.
- **Soft-confirm equivocation** is possible until certified (standard
  pre-confirmation risk); the hash chain + committee cert make *finalized*
  equivocation impossible.
- **STARK lag window**: trades are threshold-final but not yet STARK-proven
  for a few slots — acceptable iff the >2/3 Ringtail quorum is trusted (it
  already is, for blocks).

## Dependencies

Requires **Phase 0 — spot settlement** (atomic two-asset `BalanceStore`
debit/credit on each `Trade`), which is currently missing: `match_all`
moves order quantities, not tokens. See `docs/DEX-PERPS-MARGIN-PROPOSAL.md`
§Phase 0.
