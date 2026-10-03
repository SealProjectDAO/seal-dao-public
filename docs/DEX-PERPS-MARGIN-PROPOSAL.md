# Seal DAO — Perps / Portfolio Margin / Prediction Markets Proposal (Track B)

**Status:** Proposal (not yet implemented)
**Author:** design exploration, 2026-06-19
**Related:** `docs/DEX-DESIGN.md` (spot CLOB), `docs/DEX-SPEED-PQC-PROPOSAL.md` (Track A)

## Goal

Extend the spot batch-auction CLOB to **perpetual futures**, **portfolio
(cross) margin**, and **prediction markets** — the product surface of
reference venue `0xmonaco.com` (spot + perps + prediction markets,
portfolio margining, maker rebates).

The CLOB itself is reusable: `OrderBook::match_orders`
(`crates/seal-token/src/orderbook.rs:189`) matches *contracts* the same way
it matches *spot*. What changes is **settlement** (open/adjust a position vs.
swap balances) and a new **risk subsystem**.

## Phase 0 — Spot settlement (prerequisite, currently MISSING)

`DexManager::match_all` (`consensus_runner.rs:716`) produces `Trade`s and
emits `TxType::DexMatch`, but **nothing debits/credits `BalanceStore`** —
the engine moves order quantities, not tokens. Before any of the below:

- On each `Trade`, atomically swap the two assets in `BalanceStore`
  (`crates/seal-token/src/balance.rs` — `debit` / `credit` / `transfer`,
  all `checked_*`), all-or-nothing.
- Add a Kani conservation harness (mirror the existing proofs at
  `orderbook.rs:449`): total base + total quote conserved across settlement.

This unblocks both Track A and Track B.

## Components

### 1. PQC price oracle (the hard, novel piece)

Perps need an index/mark price; there is no PQC oracle in-tree. Build it as:

- Validators submit **ML-DSA-signed** price points.
- Aggregated on-chain by **deterministic integer median** (no floats —
  CLAUDE.md checked-arithmetic rule).
- Optionally Ringtail co-signed per slot.
- Funding rate = f(mark − index).

Everything downstream depends on this → build it first.

### 2. Position state

`BalanceStore` is `available/total: u64`; perps need signed size and a
margin sub-account.

```rust
struct Position {
    owner: String,
    market: String,
    size_i128: i128,        // signed: long > 0, short < 0
    entry_px: u64,
    margin_u64: u64,
    funding_snapshot: i128, // cumulative funding index at last touch
}
```

Add a `collateral` sub-account distinct from spendable balance.

### 3. Margin engine — isolated first, portfolio second

Per account:

```
equity = collateral + Σ unrealized_pnl(position, mark)
maint  = risk(positions)
healthy iff equity ≥ maint
```

- **Isolated margin** (ship first): per-position risk.
- **Portfolio margin** (the reference venue's feature; Seal's
  differentiator): *net* risk across correlated markets via a
  correlation/offset matrix. Highest value, highest risk. All fixed-point,
  all `checked_*` — must be deterministic enough to fold into the STARK
  proof.

### 4. Funding + liquidation + insurance fund

- **Funding**: per-interval payment longs↔shorts via a cumulative funding
  index; positions settle lazily on next touch from `funding_snapshot` diff.
- **Liquidation**: triggers when `equity < maint`; partial/full close routed
  to the CLOB or a backstop.
- **Insurance fund + ADL** (auto-deleverage) fallback. `treasury.rs` is the
  natural home to extend for the insurance fund.

### 5. Settlement branch in the trade callback

Keep `match_orders` untouched; branch the settlement handler:

- **spot** → `BalanceStore` two-asset swap (Phase 0).
- **perp** → position open/adjust + post-trade margin check +
  reject-or-liquidate.

### 6. Prediction markets — reuse, don't rebuild

Model as **conditional tokens on the existing spot CLOB**:

- Mint a complete set (YES + NO = 1 collateral).
- Trade YES/NO on the normal order book.
- Redeem 0/1 at resolution.

Needs only (a) complete-set mint/burn and (b) a **PQC-signed resolver**
(reuse the oracle from §1). No perp machinery required. Scalar markets can
later reuse the perp path.

## Suggested sequencing

| Phase | Deliverable |
|-------|-------------|
| 0 | Spot settlement → `BalanceStore` (atomic, `checked_*`, Kani conservation) — **prerequisite** |
| 1 | PQC oracle: signed feeds + deterministic median aggregation |
| 2 | Linear perps MVP: isolated margin, funding, liquidation, insurance fund — reusing the CLOB |
| 3 | Portfolio margin: cross-market risk netting (reference-parity feature) |
| 4 | Prediction markets: conditional-token complete sets + resolver |
| 5 | **Structured-product vaults: DOVs + iterative looping** (this section) — consumers of the Phase 1–3 engine |

Tracks A and B are independent after Phase 0 (A = consensus/latency
plumbing, B = financial state machine) and can proceed in parallel.

## Extensions: DOVs & iterative looping vaults (risk-first)

These are the natural "additional products" layer. The discipline is
**risk-first**: a vault is not a new financial primitive — it is a
*deterministic policy* that drives the existing margin/oracle/insurance
machinery (§1–§4). If a vault can express its exposure as positions the risk
engine already prices, it inherits liquidation, funding, and STARK-provable
settlement for free. Anything a vault would need that the engine can't price
is a missing engine feature, not a vault feature. Hence Phase 5: nothing here
ships before the risk engine it consumes.

### A. DOVs — DeFi Option Vaults

Automated option-selling vaults (covered call / cash-secured put), the
Ribbon/Thetanuts pattern. Each epoch the vault auctions a short option,
collects premium as yield, and bears the tail.

Requires one new primitive — a **European option contract** settled by the
§1 PQC oracle — plus a vault account:

```rust
struct OptionSeries {
    underlying: String,
    strike_u64: u64,
    expiry_slot: u64,
    is_call: bool,           // call vs put
    // settled cash = max(0, mark − strike) for calls (puts symmetric),
    // all checked_* / fixed-point — folds into the STARK proof
}

struct VaultEpoch {
    series: OptionSeries,
    deposited_u64: u64,      // collateral locked for the epoch
    premium_u64: u64,        // proceeds from the option auction
    short_qty_u64: u64,
}
```

Risk-engine mapping (why this is mostly *reuse*):

- **Collateralization is structural, not margin-call.** A *covered* call is
  backed by the underlying in the vault; a *cash-secured* put by quote. So
  the short option needs **no maintenance margin** — assignment can always be
  met from locked collateral. That is the entire point of starting with these
  two strategies and not naked options.
- **Settlement = a one-shot oracle read at `expiry_slot`** (reuse §1 median),
  payoff computed with `checked_*` integer math. No funding loop.
- **Premium discovery via the CLOB**, not a pricing model on-chain: auction
  the `OptionSeries` as a tradable contract on the existing order book
  (`orderbook.rs:189`) — the book sets the premium, the chain never evaluates
  Black-Scholes. Keeps everything deterministic and STARK-friendly.
- **Insurance fund is *not* the backstop here** (covered ⇒ no shortfall);
  reserve it for the perp/looping path.

MVP = covered calls + cash-secured puts only. Spreads / naked legs need real
option margin and should wait for portfolio margin (§3) to price the offsets.

### B. Iterative looping vaults

Recursive leverage: deposit collateral → borrow → buy more of the yield
asset → re-deposit → repeat, to N loops. Amplifies a positive
carry (staking/RWA yield − borrow cost) and, symmetrically, liquidation
risk. Two ways to express it on Seal, both engine-first:

1. **Synthetic loop via the perp engine (preferred, no new primitive).** A
   k× recursive long collapses to a *single* leveraged perp position
   (§2–§3). The vault just targets leverage `L`; the margin engine already
   prices the liquidation level, funding is the borrow cost, and the
   insurance fund / ADL (§4) is the cascade backstop. Looping becomes a thin
   policy over machinery that already exists — strictly the risk-first path.
2. **Spot-lending loop (needs a borrow primitive).** True looping on a
   collateralized lending market (borrow quote against base, rebuy, redeposit)
   gives real spot yield but requires a lending/borrow module Seal doesn't
   have. Larger surface; defer unless spot lending is independently on the
   roadmap.

Risk-first constraints that must hold *before* any loop opens:

- **Bounded recursion + a deterministic max-leverage cap.** Loop count `N`
  and target `L` are fixed parameters, not runtime-unbounded — the unrolled
  exposure must be expressible as one position the §3 engine can price and
  the STARK can prove.
- **Health re-checked after the *fully unrolled* position**, not per-hop —
  the engine evaluates the terminal leverage, never an intermediate state
  that looks safe mid-loop.
- **Reuse §4 liquidation/ADL wholesale.** A loop unwind is a normal partial
  liquidation routed to the CLOB; no special unwind path, no new solvency
  math.
- All loop and payoff arithmetic `checked_*` / fixed-point — same
  STARK-determinism bar as the rest of Track B.

## Determinism / verifiability constraints

- Risk engine math must be **on-chain deterministic** (integer/fixed-point,
  `checked_*`) so it folds into the STARK proof — no floats anywhere in
  margin, funding, or liquidation math.
- The oracle is the genuinely novel PQC challenge: a post-quantum signed,
  deterministically-aggregated price feed.

## Regulatory note

Perps and prediction markets carry materially higher regulatory exposure
than spot in several target jurisdictions. See `docs/LEGAL-REVIEW.md` before
enabling these features on any public deployment.

The Phase 5 vaults inherit and *stack* that exposure:

- **DOVs** are option-selling products — packaged derivatives. In several
  target markets a tokenized option-yield vault reads as a collective
  investment scheme and/or a derivative offering to retail, on top of the
  options themselves being regulated instruments.
- **Looping vaults** are leveraged products; the synthetic-perp
  implementation *is* a leveraged perp and falls squarely under the
  perps/margin restrictions flagged above.
- **RWA collateral** (tokenized treasuries/equities/credit used as margin)
  is the highest-incremental-risk item: RWAs lean toward **securities**
  classification, pulling the whole account into securities/custody regimes,
  and they depend on **off-chain price/settlement oracles** with halt and
  settlement-calendar risk that the on-chain risk engine must tolerate
  deterministically. Margin RWAs only behind the same region/feature gating
  as perps, with counsel sign-off per market.
