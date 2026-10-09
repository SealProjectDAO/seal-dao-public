# Token / Bridge / Stake are off-chain — design note (item 13, corrected)

Date: 2026-10-08 · Status: **design-first, implementation DEFERRED** (same treatment as the
deferred DEX T2 in `2026-10-08-dexmatch-txroot-design.md`). This note supersedes the plan's
original item 13 framing ("add the transition arms for `TokenMint`/… — the `_ => {}` no-op").

## 1. What the plan assumed, and why it is a false premise

The 2026-09-27 audit and the plan scoped item 13 as: *"state lives in `RpcState`, applied
origin-only. Add the transition arms for `TokenMint`/`TokenTransfer`/`BridgeIn`/`BridgeOut`/
`StakeDeposit`/`StakeWithdraw` (currently `_ => {}` no-op at `consensus_runner.rs:1350`) so the
replayer reproduces the state."*

That framing assumes these transactions **flow through blocks**. They do not. Validated against
primary source (2026-10-08):

1. **No token/bridge/stake `TxType` is ever constructed in non-test code.** The only references
   are in `is_money_tx_type` (`consensus_runner.rs:58-66`, which lists `TokenTransfer |
   BridgeIn | BridgeOut | StakeDeposit | StakeWithdraw`). There is no `TxType::TokenMint`
   reference at all, and no `tx_type: TxType::Token*|Bridge*|Stake*` construction anywhere in
   the workspace. A whole-workspace grep returns only the `is_money_tx_type` arm. So the
   transition's no-op arm (`consensus_runner.rs:1354-1357`) **never receives one of these txs** —
   there is nothing to replay.

2. **The RPC handlers live-mutate the origin's in-memory state; they submit no transaction.**
   - `handle_mint_token` → `mgr.mint(...)` (`rpc.rs:2692-2694`)
   - `handle_transfer_token` → `mgr.transfer(...)` (`rpc.rs:2724-2729`)
   - `handle_burn_token` → `mgr.burn(...)` (`rpc.rs:2763-2774`)
   - Bridge: `seal_bridgeWithdraw` / `seal_bridgeMarkExecuted` / `seal_bridgeWithdrawAndClaim`
     mutate the origin `BridgeManager` directly.
   Each acquires `state.<store>.lock().await` and calls the mutator, then returns. There is no
   `submit_*`, no `pending_txs.push`, no nonce. The operation is applied to **one node's**
   in-memory store and never enters the chain.

3. **The state root does not cover any of this.** The combine is `sql_root ‖ balance_root` only
   (`consensus_runner.rs:1060-1065` producer, `:1520-1525` replayer). The comment at
   `:1057-1059` already flags it: *"Future work: also fold in `TokenManager::state_root_hash`
   and the [bridge/stake roots] — they live in RpcState."* So token/bridge/stake state has **zero
   consensus footprint**: an arbitrary number of token ops produces the same state root on the
   origin and on every replayer. There is no fork in the *chain*; the divergence is entirely in
   the off-chain subsystem.

Consequence: on a multi-node network, `seal_mintToken`/`seal_transferToken`/`seal_burnToken`
(and the bridge withdraw/mark-executed ops) mutate only the submitting node's private in-memory
state. They are invisible to consensus and diverge from every peer from the first operation.
This is a **bigger architectural gap than "on-block replay divergence"** — the state was never in
consensus to begin with.

4. **No stake-deposit / bridge-in RPC exists.** Only the bridge *withdrawal* side is an RPC.
   `TxType::StakeDeposit`/`StakeWithdraw`/`BridgeIn`/`BridgeOut`/`TokenMint` are therefore dead
   variants; stake is set at validator enrollment (a separate path). "Stake on-block replay" is
   N/A as scoped.

## 2. Two things the plan's map got wrong (record-keeping)

A subagent "map" for this item reported (a) specific handler line numbers and (b) that
"`ConsensusRunner::state` already holds the `RpcState` handle (`attach_rpc_state`)". Both are
false:

- There are no `handle_token_mint` / `handle_stake_deposit` fns; the real fns are
  `handle_mint_token` / `handle_transfer_token` / `handle_burn_token` / `handle_bridge_*`.
- `ConsensusRunner` has **no** `RpcState`/`TokenManager`/`attach_rpc_state` field. It owns only
  its own `dex: Arc<Mutex<DexManager>>` (`consensus_runner.rs:195`), shared with the RPC layer
  via `set_dex_manager` (`:381`). Bringing token state on-chain must first give the runner a
  handle to that state (see §3).

## 3. The real fix — an on-chain token subsystem (deferred, design-first)

This is a consensus-critical subsystem build, not a bounded swap. It touches the on-block
transition the F3 pass just hardened, so per the plan's Wave-2 pattern it is design-first.
Bridge and stake are deferred separately (larger / N/A). Only the **token** path is specified
here, because it is the most user-facing and the most tractable.

### 3.1 The async-lock / sync-transition problem (the crux)

`apply_block_transition` is **sync** (`consensus_runner.rs:1271`). `RpcState.token_manager` is
behind a **`tokio::sync::Mutex`** (`rpc.rs:24,559`). A sync transition cannot `lock().await`.
The DEX already faces this and resolves it with `self.dex.try_lock()` (`:1078`) that **skips the
slot on contention** — which is safe for the DEX *only because the `DexMatch` is appended after
the state root* (`:1089-1102`), so a skipped match has no root impact.

**A token op that is skipped on lock contention WOULD change the state root** → fork. So the
"mirror the DEX `try_lock`" shortcut is **forbidden** here. The acquisition must be
*guaranteed*. Two viable designs, to be chosen at implementation time:

- **(A1) Make `apply_block_transition` async** and `self.token_manager.lock().await`. Cleanest
  semantics, but invasive — the transition is called from `produce_block_with_vrf`,
  `apply_block_verified`, the disk-replay paths, and many tests.
- **(A2) Runner-owned `std::sync::Mutex<TokenManager>`** (not the RPC's tokio one), acquired
  with a blocking `.lock()` in the sync transition. The critical section is a few
  `HashMap` ops, so runtime blocking is short — but the RPC and the transition must share the
  *same* instance (via a `set_token_manager` setter, mirroring `set_dex_manager`) and the
  locking order must be audited for re-entrancy/deadlock (an RPC that triggers a transition
  while holding the token lock would self-deadlock).

**Consensus-safety invariant (non-negotiable):** every token op in a block is applied on every
node, identically, or the root forks. Any `try_lock`-or-skip is a fork. Whichever design is
chosen, this invariant must hold and be covered by a regression.

### 3.2 Shape (mirrors the proven native-`Transfer` pattern)

The native `seal_transfer` is the template that token ops fail to follow (`rpc.rs:2579-2630` →
`submit_money_tx` `consensus_runner.rs:625-658` → transition `Transfer` arm `:1334-1352`):
submit a nonce-stamped, signed tx; apply it **only** in the shared transition; fold its store's
root into the state root.

1. **Handle:** add `pub token_manager: Arc<Mutex<TokenManager>>` to `ConsensusRunner`; share it
   with `RpcState` via a `set_token_manager` setter at node startup (mirror `set_dex_manager`).
2. **Payload:** `TokenPayload { symbol: String, to: String, amount: u64 }` (bincode), encoded as
   `nonce(8 LE) || bincode(TokenPayload)`. The op is implied by the `TxType`
   (`TokenMint`/`TokenTransfer`/`TokenBurn`); `from`/authority = `tx.sender` in all cases.
3. **Submit:** `submit_token_tx(tx_type, symbol, to, amount)` mirroring `submit_money_tx`
   (per-sender nonce, sign, `pending_txs.push`).
4. **RPC handlers:** rewrite `handle_mint_token` / `handle_transfer_token` / `handle_burn_token`
   from live-apply to **preview-check + `submit_token_tx`** (mirror `handle_transfer`'s
   `available_with_pending` overdraft gate). Confirmation moves from RPC-ack to block-inclusion —
   a user-visible behavior change.
5. **Transition arm:** `TxType::TokenMint | TokenTransfer | TokenBurn => { decode; apply to
   `self.token_manager` via the guaranteed acquisition in §3.1; same per-sender nonce check as
   the `Transfer` arm (`:1344-1352`).`
6. **Root fold:** add `token_root = self.token_manager.state_root_hash()`
   (`seal-token/src/tokens.rs:245`) to the combine at `:1060-1065` **and** `:1520-1525`. Use a
   canonical empty root when there are no tokens so both sides agree.
7. **Fee:** token txs flow through `process_block_fees` (native SEAL fee, by payload length,
   `:1367-1383`) — distinct from the token-internal `transfer_fee_bps` applied inside
   `TokenManager::transfer` (`tokens.rs:146-164`). No double-charge; two independent fee systems.

### 3.3 Why the tempting shortcut is catastrophic

**Do not fold `token_root` (or bridge/stake roots) into the combine on its own.** Without the
on-chain apply (§3.2), the first token op makes the origin's `token_root` (mutated) diverge from
every replayer's `token_root` (not mutated) → the origin can no longer produce blocks that
replayers accept → **the chain halts**. The root fold must *accompany* the on-chain apply, never
precede it.

### 3.4 Regression + hard break

- **F3-class regression:** non-origin proposer with a `TokenTransfer` → both nodes' `state_root`
  matches **and** token state matches (mirror `test_f3_non_origin_proposer_transfer`).
- **Determinism regression:** two independent replays of the same block yield identical token
  state (guards against any wall-clock/nonce nondeterminism — `TokenManager` is currently
  deterministic: pure transitions, checked/saturating arithmetic, no wall-clock,
  `tokens.rs:95-165,245,268`).
- **Hard break (F3-class):** folding `token_root` changes `state_root` for **all** blocks,
  including token-free ones → wipe the data dir on upgrade. Token ops no longer live-apply at
  RPC.

## 4. Deferred (not this change)

- **Bridge:** withdrawal-side RPCs + an *external relayer* lock + cross-chain withdrawal records
  + committee keys. Bringing it on-chain requires modeling the off-chain lock as an on-chain
  observation (it cannot be nonce-stamped by an on-chain sender) plus root-folding the
  `BridgeManager` store. Larger design; defer.
- **Stake:** no deposit/withdraw RPC; `TxType::StakeDeposit`/`StakeWithdraw` dead; stake is set at
  validator enrollment. N/A as scoped; defer (revisit once a stake-movement RPC exists).

## 5. Status

Design-first; **implementation deferred**. The corrected finding (token/bridge/stake are entirely
off-chain origin-only state with no consensus footprint, and the transition is sync against an
async-locked store) is the deliverable. Revisit with a dedicated, regression-first implementation
pass for the token subsystem (§3); bridge/stake after.
