# DexMatch forgeability — design + `tx_root` hardening

Date: 2026-10-08
Status: **`tx_root` implemented (see below). On-chain-order DEX fix DEFERRED.**
Remediates: `audits/2026-09-27-local-security-inspection.md` §6.2 (DEX match
replay/verification), Tier 2 Wave-2 item 12.

## 1. The vulnerability

The per-block DEX match is surfaced as a `TxType::DexMatch` transaction
(`crates/seal-storage/src/block_store.rs:72`). Its payload is a bincode
`Vec<(pair, Vec<Trade>)>` (`crates/seal-node/src/consensus_runner.rs:1095`).

The producer appends that transaction to `block.transactions` **after** the
block's `state_root` is computed:

- `state_root = SHA3(sql_root ‖ balance_root)` — `consensus_runner.rs:1060-1065`.
- DexMatch appended to `txs` — `consensus_runner.rs:1097-1102` (after the root).
- Header built with the pre-DexMatch `state_root` — `consensus_runner.rs:1117`.

Consequences, verified against source:

1. **The `DexMatch` is outside the `state_root`.** The replayer's shared
   transition no-ops it (`_ => {}` at `consensus_runner.rs:1350`) and the fee
   loop filters it out (`:1365`), so it contributes nothing to the recomputed
   root. Replaying a block with a forged, removed, or extra `DexMatch`
   produces the *same* `state_root` → the F2 root check
   (`apply_block_verified`, `consensus_runner.rs:1617`) never fires.
2. **The header has no transaction root.** `BlockHeader`
   (`block_store.rs:14-32`) carries `state_root` but no Merkle root over
   `transactions`. The proposer signature covers the header fields only
   (canonical empty-sig serialization, `block_store.rs:8-13`). So the
   transaction set is bound to *neither* the state root *nor* the signature.
3. **No re-derivation on the replayer.** `verify_and_apply_block`
   (`network_node.rs:694-816`) performs no `DexMatch` re-derivation or payload
   check; the string `DexMatch` appears in no verifier code.

**Net effect:** a validly-signed block can be forwarded with an injected,
mutated, or deleted `DexMatch` transaction and every node commits it. The
same holds for *every* no-op transaction type — token/bridge/stake/gov —
because all of them fall in the same `_ => {}` arm and affect no root.

## 2. Two distinct threat vectors

It is important not to conflate two different forgers:

- **(T1) Relayer / peer tampering.** A *third party* (not the proposer) takes
  a block the proposer already signed and adds/removes/edits a transaction
  before gossiping it. The header signature still verifies (it covers the
  header, not the tx set); the state root still matches (no-op txs). The forged
  tx is committed. **This is the live, general vector.**
- **(T2) Proposer-level DEX forgery.** The *proposer itself* authors a block
  whose `DexMatch` claims trades that never happened (fabricated pair/price/qty),
  then signs a header consistent with that payload. The replayer cannot
  distinguish this from a legitimate match because it does not — and *cannot* —
  re-derive the match (see §3). **This is the deeper DEX-specific vector.**

The `tx_root` hardening in §4 closes **T1** for all transaction types. It does
*not* close **T2**: a malicious proposer can sign a `tx_root` over a forged
`DexMatch`. Closing T2 requires the replayer to re-derive the match, which
requires orders to be deterministic on-chain state — the deferred work in §5.

## 3. Why the plan's (a) re-derive and (b) root-fold are blocked as-scoped

The plan assumed a bounded "re-derive `match_all` on the replayer and
payload-check" or "fold trades into root-covered state." Neither is possible
without first solving the missing order subsystem, because:

- **Orders are not on-chain or replicated.** Orders enter a book only through
  the per-node RPC `seal_placeOrder` (`rpc.rs:3568-3588`), which *auto-matches
  immediately* using local wall-clock time. There is no `OrderPlace` /
  `OrderCancel` transaction type (`TxType`, `block_store.rs:52-73`, has no
  order variants; `docs/DEX-DESIGN.md` lists them as unwired Phase-4 work).
- **The replayer has no pre-block books.** Each node's `DexManager`
  (`orderbook.rs:374-376`) is an in-memory `HashMap<String, OrderBook>`, not
  persisted and not part of any state root, populated only by orders submitted
  to *that node's* RPC. A replayer on a different node does not have the books
  the producer matched against.
- **There is no settlement step.** A `DexMatch` trade mutates neither
  `sql_engine` nor `balances` — the transition's `_ => {}` arm
  (`consensus_runner.rs:1350`) does nothing, and no runner code moves base
  asset on a trade. So there is no root-covered state for a trade to "fold"
  into; the DEX trade is a cosmetic log entry today, and its only effect is an
  untrustworthy on-chain trade record.

So (a) needs orders to be deterministic, replicated, on-chain inputs, and (b)
needs a settlement step that writes root-covered state. Both are the same
underlying project.

## 4. Bounded hardening landed now: signed `tx_root`

Add a Merkle root over the block's transactions to the *signed* header. This
makes the transaction set tamper-evident on every node without requiring the
order subsystem.

- **Field:** `BlockHeader.tx_root: Hash256` (`block_store.rs`). Required field
  (no `#[serde(default)]`), so a block without a `tx_root` is simply invalid.
- **Construction** (a new generic helper in `seal-crypto`,
  `merkle_root(items: &[Vec<u8>]) -> Hash256`):
  - leaf `i` = `SHA3_256(bincode(tx_i))`;
  - internal node = `SHA3_256(left ‖ right)` over the two 32-byte child hashes;
  - an odd node in a level is promoted unchanged;
  - empty transaction list → `SHA3_256(b"")` (fixed, non-zero).
- **Producer** (`consensus_runner.rs:produce_block_with_vrf`): compute
  `tx_root` over `txs` *after* the `DexMatch` is appended (so the match is
  covered), before building/signing the header. `state.rs:produce_block` does
  the same over its `pending_txs`.
- **Verifier** (`network_node.rs:verify_and_apply_block`): recompute the
  Merkle root over `block.transactions` and reject if it differs from
  `header.tx_root`, **before** the signature check. This is the new T1 gate: a
  post-sign injection/removal/edits of any transaction (DexMatch included)
  changes the recomputed root → rejected.
- **Hard break.** Adding a header field changes the canonical signing
  serialization, invalidating every previously-signed header. Pre-upgrade
  chains fail verification → **wipe the data directory on upgrade** (same
  accepted class as the F3 on-block-determinism break).

This is deliberately *not* claimed to close T2; it is the safe, bounded slice
that stops a third party from forging the trade log (and any no-op tx) after
the fact.

## 5. Deferred: making DEX trades real, root-covered, non-forgeable (T2)

To fully close proposer-level DEX forgery, orders and settlement must become
consensus state, so the replayer can re-derive (or root-fold) the match. Scope,
roughly in dependency order:

1. **On-chain orders.** Add `OrderPlace` / `OrderCancel` `TxType`s; make order
   placement/cancellation a deterministic arm of `apply_block_transition`
   (block timestamp, price-time priority) instead of the local RPC
   auto-match.
2. **Deterministic matching in the transition.** Run `match_all` as a
   transition arm (so every node matches identically from the same books),
   not in `produce_block_with_vrf` against a locally-mutated book.
3. **Settlement.** Move base asset on each fill inside the transition (so a
   fill changes `balance_root`/`sql_root` and a forged fill is caught by the
   existing root check).
4. **Then** either re-derive the `DexMatch` on the replayer (approach a) or add
   a `dex_root` to the combine (approach b).

This is the same root-cause family as Wave-2 item 13 (token/bridge/stake state
lives in `RpcState`, applied origin-only, outside the root) — both are
"consensus state that the replayer does not reproduce." Sequencing them
together is a design decision for when that subsystem is tackled.

## 6. Regression test + acceptance criteria

`network_node.rs::test_dexmatch_injected_tx_rejected_on_replay` produces a
block on a two-node pair, then injects a fabricated `DexMatch` transaction
into a *copy* of the validly-signed block (no re-sign) and feeds it to the
receiver. Acceptance: the receiver **rejects** the block and its height is
unchanged. Pre-`tx_root` this is accepted (T1 open); post-`tx_root` the
recomputed root differs and the block is rejected.

The test asserts only T1. A T2 test (proposer signs a forged `DexMatch` with a
consistent `tx_root`) is intentionally *not* written yet — it can only pass
once §5 lands, and would be misleading to add as an ignored test that no
planned change flips to green.
