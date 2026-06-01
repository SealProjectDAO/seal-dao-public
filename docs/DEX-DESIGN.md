# Seal DAO — DEX Design (On-Chain Order Book)

## Research Summary

### Industry Approaches

| Project | Architecture | TPS | Matching |
|---------|-------------|-----|----------|
| Serum (Solana) | Fully on-chain CLOB | ~65K (Solana) | On-chain, 400ms blocks |
| dYdX v4 | Cosmos appchain, off-chain matching | ~2,000 | Off-chain engine, on-chain settlement |
| Hyperliquid | Custom L1 | ~200K (1M+ theoretical) | On-chain, optimistic |
| Econia (Aptos) | On-chain via Move | ~10K | On-chain, parallel execution |

### Key Insight

Fully on-chain order books require either:
1. **Very fast block times** (<1s) + high TPS (Solana, Hyperliquid)
2. **Off-chain matching + on-chain settlement** (dYdX v4)
3. **Batch auctions** instead of continuous matching (CoW Protocol)

Seal's 4-second block time is too slow for high-frequency trading.
The recommended approach: **batch auction matching per block** or
**off-chain matching with on-chain settlement**.

---

## Recommended Architecture for Seal

### Approach: Per-Block Batch Auction

Instead of continuous matching (which needs sub-second latency),
Seal uses **batch auctions** that clear once per block (~4 seconds):

1. Users submit orders during the block interval
2. At block production, all pending orders are matched at a **uniform clearing price**
3. Matched trades are included in the block as transactions
4. Unmatched orders remain in the book for the next block

This is MEV-resistant (no front-running within a batch) and works
with Seal's consensus timing.

### Data Structures

```
Order Book (per trading pair):
  Bids: BTreeMap<Price, VecDeque<Order>>  ← price-time priority
  Asks: BTreeMap<Price, VecDeque<Order>>  ← price-time priority

Order:
  id: u64
  owner: SealAddress
  side: Bid | Ask
  price: u64 (fixed-point, 9 decimals)
  quantity: u64
  timestamp: u64
  order_type: Limit | Market | IOC | FOK

Trade:
  maker_order_id: u64
  taker_order_id: u64
  price: u64
  quantity: u64
  maker: SealAddress
  taker: SealAddress
```

### Matching Algorithm

**Price-time priority (FIFO):**

```
fn match_orders(bids, asks) -> Vec<Trade>:
  trades = []
  while best_bid >= best_ask:
    bid = bids.best()
    ask = asks.best()
    trade_price = (bid.price + ask.price) / 2  # or ask.price (maker price)
    trade_qty = min(bid.remaining, ask.remaining)
    trades.push(Trade { price: trade_price, quantity: trade_qty, ... })
    bid.remaining -= trade_qty
    ask.remaining -= trade_qty
    if bid.remaining == 0: bids.remove(bid)
    if ask.remaining == 0: asks.remove(ask)
  return trades
```

**Complexity:** O(n log n) per block where n = number of orders.
With BTreeMap: O(log n) insert, O(1) best price access.

### Expected Throughput

| Metric | Value |
|--------|-------|
| Block time | 4 seconds |
| Orders per block | ~1,000 (limited by block size) |
| Matches per block | ~500 (assuming 50% fill rate) |
| Throughput | ~125-250 trades/second |
| Latency | 4 seconds (1 block confirmation) |

This is not competitive with HFT venues but is adequate for:
- Token swaps (SEAL ↔ custom tokens)
- Low-frequency trading pairs
- RWA (real-world asset) tokens
- Governance token markets

### RPC Methods

Live today (see MANUAL-TESTING.md §19.2 for end-to-end curl /
seal-cli recipes):

```
seal_createPair    { base, quote }                              → { base, quote }     [auth]
seal_placeOrder    { pair, side, price, quantity }              → { order_id, … }     [auth]
seal_cancelOrder   { pair, order_id }                           → { ok }              [auth]
seal_getOrderBook  { pair }                                     → { bids: [...], asks: [...] }
seal_listPairs     {}                                           → { pairs: [{ base, quote, ... }] }
```

Not yet wired (Phase 4 below, deferred for testnet readiness):
`seal_getMyOrders { pair }`, `seal_getTradeHistory { pair, limit }`.
For the "what orders did I place?" query today, walk the global
order book and filter caller-side, or use the `TxType::DexMatch`
emissions on each block (see MANUAL-TESTING.md §23.5).

### Transaction Types

```
TxType::OrderPlace   — place limit/market order
TxType::OrderCancel  — cancel existing order
```

### Fee Structure

- Maker fee: 0.1% (paid in quote token)
- Taker fee: 0.2% (paid in quote token)
- SEAL gas fee: standard EIP-1559 fee per transaction
- Fee destination: 50% burned, 50% to block proposer

### Security

- All orders signed with ML-DSA-65 (PQC)
- Batch auction prevents front-running / MEV
- Order book state in Merkle tree (verifiable)
- Cross-margin possible via token balance checks

---

## Implementation Plan

### Phase 1: Basic Order Book
- [ ] `OrderBook` struct with BTreeMap bid/ask sides
- [ ] `MatchingEngine` with price-time priority
- [ ] `seal_placeOrder` / `seal_cancelOrder` RPC
- [ ] `seal_getOrderBook` / `seal_listPairs` RPC
- [ ] SEAL/TOKEN trading pairs

### Phase 2: Per-Block Batch Matching
- [ ] Wire matching engine into block production
- [ ] Orders collected during block interval
- [ ] Batch match at block finalization
- [ ] Trade settlement updates BalanceStore

### Phase 3: Advanced Features
- [ ] IOC (Immediate or Cancel) / FOK (Fill or Kill)
- [ ] Stop-loss / take-profit orders
- [ ] Cross-margin using token balances
- [ ] Trading pair governance (listing/delisting via proposal)

---

## Sources

- [On-Chain Order Books Guide (Conduit)](https://www.conduit.xyz/blog/onchain-order-books-guide/)
- [Order Book DEX Development Guide (IdeaSoft)](https://ideasoft.io/blog/order-book-dex-development-guide/)
- [Matching Engines (Jelle Pelgrims)](https://jellepelgrims.com/posts/matching_engines)
- [How Hyperliquid Works (RockNBlock)](https://rocknblock.io/blog/how-does-hyperliquid-work-a-technical-deep-dive)
- [Price-Time Priority Matching (Springer)](https://link.springer.com/chapter/10.1007/978-88-470-1766-5_5)
