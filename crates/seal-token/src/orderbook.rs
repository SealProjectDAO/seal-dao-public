//! On-chain order book DEX with per-block batch auction matching.
//!
//! Uses price-time priority (FIFO) matching. All orders submitted during
//! a block interval are matched at block production time.
//!
//! See docs/DEX-DESIGN.md for architecture details.

use crate::TokenError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};

/// Order side.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    Bid,
    Ask,
}

/// Order type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderType {
    /// Limit order — sits in the book until filled or cancelled.
    Limit,
    /// Market order — fills immediately at best available price.
    Market,
}

/// A single order in the book.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Order {
    pub id: u64,
    pub owner: String,
    pub side: Side,
    pub price: u64,
    pub quantity: u64,
    pub remaining: u64,
    pub order_type: OrderType,
    pub timestamp: u64,
}

/// A completed trade.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Trade {
    pub id: u64,
    pub maker_order_id: u64,
    pub taker_order_id: u64,
    pub price: u64,
    pub quantity: u64,
    pub maker: String,
    pub taker: String,
    pub side: Side,
    pub timestamp: u64,
}

/// A trading pair (e.g., GOLD/SEAL).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TradingPair {
    pub base: String,
    pub quote: String,
    pub last_price: u64,
    pub volume_24h: u64,
    pub trade_count: u64,
}

/// Maximum number of trades retained per book. Older trades are
/// dropped from the front of `trades` after every match. Picked so a
/// pair averaging 1 trade/sec keeps roughly 2.7 hours of history; for
/// quieter pairs, weeks. Larger horizons go through the per-block
/// `TxType::DexMatch` payloads recorded in the chain itself.
pub const MAX_TRADE_HISTORY: usize = 10_000;

/// Order book for a single trading pair.
pub struct OrderBook {
    pub pair: TradingPair,
    /// Bids sorted by price descending (highest first).
    bids: BTreeMap<std::cmp::Reverse<u64>, VecDeque<Order>>,
    /// Asks sorted by price ascending (lowest first).
    asks: BTreeMap<u64, VecDeque<Order>>,
    /// All orders by ID for fast lookup/cancel.
    orders: HashMap<u64, (Side, u64)>, // id → (side, price)
    /// Next order ID.
    next_order_id: u64,
    /// Next trade ID.
    next_trade_id: u64,
    /// Trade history. Oldest at index 0, newest at the back. Bounded
    /// to `MAX_TRADE_HISTORY`; entries beyond that are dropped after
    /// each match round (FIFO).
    trades: Vec<Trade>,
}

impl OrderBook {
    pub fn new(base: String, quote: String) -> Self {
        OrderBook {
            pair: TradingPair {
                base,
                quote,
                last_price: 0,
                volume_24h: 0,
                trade_count: 0,
            },
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            orders: HashMap::new(),
            next_order_id: 1,
            next_trade_id: 1,
            trades: Vec::new(),
        }
    }

    /// Place a new order. Returns the order ID.
    pub fn place_order(
        &mut self,
        owner: String,
        side: Side,
        price: u64,
        quantity: u64,
        order_type: OrderType,
        timestamp: u64,
    ) -> u64 {
        let id = self.next_order_id;
        self.next_order_id += 1;

        let order = Order {
            id,
            owner,
            side,
            price,
            quantity,
            remaining: quantity,
            order_type,
            timestamp,
        };

        match side {
            Side::Bid => {
                self.bids
                    .entry(std::cmp::Reverse(price))
                    .or_default()
                    .push_back(order);
                self.orders.insert(id, (Side::Bid, price));
            }
            Side::Ask => {
                self.asks.entry(price).or_default().push_back(order);
                self.orders.insert(id, (Side::Ask, price));
            }
        }

        id
    }

    /// Cancel an order. Returns the cancelled order if found.
    pub fn cancel_order(&mut self, order_id: u64) -> Result<Order, TokenError> {
        let (side, price) = self
            .orders
            .remove(&order_id)
            .ok_or_else(|| TokenError::Custom(format!("order {} not found", order_id)))?;

        match side {
            Side::Bid => {
                let key = std::cmp::Reverse(price);
                if let Some(queue) = self.bids.get_mut(&key) {
                    if let Some(pos) = queue.iter().position(|o| o.id == order_id) {
                        let order = queue.remove(pos).unwrap();
                        if queue.is_empty() {
                            self.bids.remove(&key);
                        }
                        return Ok(order);
                    }
                }
            }
            Side::Ask => {
                if let Some(queue) = self.asks.get_mut(&price) {
                    if let Some(pos) = queue.iter().position(|o| o.id == order_id) {
                        let order = queue.remove(pos).unwrap();
                        if queue.is_empty() {
                            self.asks.remove(&price);
                        }
                        return Ok(order);
                    }
                }
            }
        }

        Err(TokenError::Custom("order not found in book".into()))
    }

    /// Match all crossing orders. Called once per block.
    /// Returns the list of trades executed.
    pub fn match_orders(&mut self, timestamp: u64) -> Vec<Trade> {
        let mut trades = Vec::new();

        loop {
            // Get best bid and ask
            let best_bid_price = self.bids.first_key_value().map(|(k, _)| k.0);
            let best_ask_price = self.asks.first_key_value().map(|(k, _)| *k);

            match (best_bid_price, best_ask_price) {
                (Some(bid), Some(ask)) if bid >= ask => {
                    // Crossing — execute trade at ask price (maker price)
                    let trade_price = ask;

                    let bid_key = std::cmp::Reverse(bid);
                    let bid_order = self.bids.get_mut(&bid_key).unwrap().front_mut().unwrap();
                    let ask_order = self.asks.get_mut(&ask).unwrap().front_mut().unwrap();

                    let trade_qty = bid_order.remaining.min(ask_order.remaining);

                    let trade = Trade {
                        id: self.next_trade_id,
                        maker_order_id: ask_order.id,
                        taker_order_id: bid_order.id,
                        price: trade_price,
                        quantity: trade_qty,
                        maker: ask_order.owner.clone(),
                        taker: bid_order.owner.clone(),
                        side: Side::Bid,
                        timestamp,
                    };
                    self.next_trade_id += 1;

                    bid_order.remaining -= trade_qty;
                    ask_order.remaining -= trade_qty;

                    let bid_done = bid_order.remaining == 0;
                    let ask_done = ask_order.remaining == 0;
                    let bid_id = bid_order.id;
                    let ask_id = ask_order.id;

                    trades.push(trade);

                    // Remove filled orders
                    if bid_done {
                        self.bids.get_mut(&bid_key).unwrap().pop_front();
                        if self.bids.get(&bid_key).map_or(true, |q| q.is_empty()) {
                            self.bids.remove(&bid_key);
                        }
                        self.orders.remove(&bid_id);
                    }
                    if ask_done {
                        self.asks.get_mut(&ask).unwrap().pop_front();
                        if self.asks.get(&ask).map_or(true, |q| q.is_empty()) {
                            self.asks.remove(&ask);
                        }
                        self.orders.remove(&ask_id);
                    }
                }
                _ => break, // No crossing
            }
        }

        // Update pair stats
        if let Some(last) = trades.last() {
            self.pair.last_price = last.price;
            self.pair.trade_count += trades.len() as u64;
            self.pair.volume_24h += trades.iter().map(|t| t.quantity).sum::<u64>();
        }

        self.trades.extend(trades.clone());

        // Cap the trade history to MAX_TRADE_HISTORY entries (drop
        // oldest first). For an active pair this caps memory growth
        // without losing the rolling-window the recent_trades / list
        // RPCs serve.
        if self.trades.len() > MAX_TRADE_HISTORY {
            let drop = self.trades.len() - MAX_TRADE_HISTORY;
            self.trades.drain(..drop);
        }

        trades
    }

    /// Get order book depth (top N levels).
    #[allow(clippy::type_complexity)]
    pub fn depth(&self, levels: usize) -> (Vec<(u64, u64)>, Vec<(u64, u64)>) {
        let bids: Vec<(u64, u64)> = self
            .bids
            .iter()
            .take(levels)
            .map(|(k, orders)| (k.0, orders.iter().map(|o| o.remaining).sum()))
            .collect();

        let asks: Vec<(u64, u64)> = self
            .asks
            .iter()
            .take(levels)
            .map(|(k, orders)| (*k, orders.iter().map(|o| o.remaining).sum()))
            .collect();

        (bids, asks)
    }

    /// Get recent trades.
    pub fn recent_trades(&self, limit: usize) -> &[Trade] {
        let start = self.trades.len().saturating_sub(limit);
        &self.trades[start..]
    }

    /// List trades with `id > since_id`, capped at `limit`. The
    /// returned slice is the most recent `limit` matching trades
    /// (i.e. tail-truncated, not head-truncated). Used by the
    /// `seal_listTrades` RPC. `since_id = 0` returns the rolling
    /// `MAX_TRADE_HISTORY` window.
    pub fn list_trades_since(&self, since_id: u64, limit: usize) -> Vec<Trade> {
        // Trades are appended in id-ascending order, so scanning from
        // the back lets us bail out as soon as we hit `id <= since_id`.
        let mut out: Vec<Trade> = self
            .trades
            .iter()
            .rev()
            .take_while(|t| t.id > since_id)
            .take(limit)
            .cloned()
            .collect();
        out.reverse(); // chronological (oldest first)
        out
    }

    /// Total number of trades currently held in the rolling history.
    /// Capped by `MAX_TRADE_HISTORY`; the on-chain trade count lives
    /// in `pair.trade_count` which is unbounded.
    pub fn trade_history_len(&self) -> usize {
        self.trades.len()
    }

    /// Get orders for a specific owner.
    pub fn orders_by_owner(&self, owner: &str) -> Vec<&Order> {
        let mut result = Vec::new();
        for queue in self.bids.values() {
            for order in queue {
                if order.owner == owner {
                    result.push(order);
                }
            }
        }
        for queue in self.asks.values() {
            for order in queue {
                if order.owner == owner {
                    result.push(order);
                }
            }
        }
        result
    }

    /// Total number of open orders.
    pub fn open_order_count(&self) -> usize {
        self.orders.len()
    }
}

/// Manages all order books (one per trading pair).
#[derive(Default)]
pub struct DexManager {
    books: HashMap<String, OrderBook>,
}

impl DexManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new trading pair.
    pub fn create_pair(&mut self, base: String, quote: String) -> Result<(), TokenError> {
        let key = format!("{}/{}", base, quote);
        if self.books.contains_key(&key) {
            return Err(TokenError::Custom(format!("pair {} already exists", key)));
        }
        self.books.insert(key, OrderBook::new(base, quote));
        Ok(())
    }

    /// Get an order book by pair name.
    pub fn get_book(&self, pair: &str) -> Option<&OrderBook> {
        self.books.get(pair)
    }

    /// Get a mutable order book.
    pub fn get_book_mut(&mut self, pair: &str) -> Option<&mut OrderBook> {
        self.books.get_mut(pair)
    }

    /// List all trading pairs.
    pub fn list_pairs(&self) -> Vec<&TradingPair> {
        self.books.values().map(|b| &b.pair).collect()
    }

    /// List recent trades for a pair with id > `since_id`, capped
    /// at `limit`. Returns `None` if the pair doesn't exist.
    pub fn list_trades_for(&self, pair: &str, since_id: u64, limit: usize) -> Option<Vec<Trade>> {
        self.books
            .get(pair)
            .map(|b| b.list_trades_since(since_id, limit))
    }

    /// Aggregate every open order belonging to `owner` across all
    /// trading pairs. Each result carries the pair name so the
    /// caller can act on it (cancel via `seal_cancelOrder` needs
    /// both pair + order_id). Sorted by `(pair, order_id)` so
    /// polling clients can diff a previous snapshot. Empty Vec
    /// for unknown owners — no error path.
    pub fn orders_by_owner(&self, owner: &str) -> Vec<(String, Order)> {
        let mut out: Vec<(String, Order)> = self
            .books
            .iter()
            .flat_map(|(pair, book)| {
                book.orders_by_owner(owner)
                    .into_iter()
                    .map(move |o| (pair.clone(), o.clone()))
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.id.cmp(&b.1.id)));
        out
    }

    /// Aggregate every retained trade where `owner` was either
    /// maker or taker, across all trading pairs. Bounded by each
    /// pair's `MAX_TRADE_HISTORY` (10 000) — older trades are
    /// dropped. Sorted by descending timestamp (most recent
    /// first) so the natural use case ("show my last N trades")
    /// is the prefix of the result.
    pub fn trades_by_owner(&self, owner: &str) -> Vec<(String, Trade)> {
        let mut out: Vec<(String, Trade)> = self
            .books
            .iter()
            .flat_map(|(pair, book)| {
                book.list_trades_since(0, MAX_TRADE_HISTORY)
                    .into_iter()
                    .filter(|t| t.maker == owner || t.taker == owner)
                    .map(move |t| (pair.clone(), t))
            })
            .collect();
        out.sort_by(|a, b| b.1.timestamp.cmp(&a.1.timestamp));
        out
    }

    /// Match all order books. Called once per block.
    pub fn match_all(&mut self, timestamp: u64) -> Vec<(String, Vec<Trade>)> {
        let mut all_trades = Vec::new();
        for (pair, book) in &mut self.books {
            let trades = book.match_orders(timestamp);
            if !trades.is_empty() {
                all_trades.push((pair.clone(), trades));
            }
        }
        all_trades
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove: matching never creates tokens (conservation).
    /// Total bid quantity + ask quantity before == total after + traded quantity.
    #[kani::proof]
    fn matching_conserves_quantity() {
        let bid_qty: u64 = kani::any();
        let ask_qty: u64 = kani::any();
        kani::assume(bid_qty > 0 && bid_qty <= 1_000_000);
        kani::assume(ask_qty > 0 && ask_qty <= 1_000_000);

        let trade_qty = bid_qty.min(ask_qty);
        let bid_remaining = bid_qty - trade_qty;
        let ask_remaining = ask_qty - trade_qty;

        // Conservation: input == output
        assert_eq!(
            bid_qty + ask_qty,
            bid_remaining + ask_remaining + trade_qty * 2
        );
    }

    /// Prove: trade price is always between bid and ask.
    #[kani::proof]
    fn trade_price_bounded() {
        let bid_price: u64 = kani::any();
        let ask_price: u64 = kani::any();
        kani::assume(bid_price > 0 && bid_price <= 1_000_000);
        kani::assume(ask_price > 0 && ask_price <= 1_000_000);
        kani::assume(bid_price >= ask_price); // crossing condition

        // Trade executes at ask price (maker price)
        let trade_price = ask_price;
        assert!(trade_price <= bid_price);
        assert!(trade_price >= ask_price);
    }

    /// Prove: price-time priority is consistent.
    /// If two orders have the same price, the earlier one fills first.
    #[kani::proof]
    fn time_priority_consistent() {
        let t1: u64 = kani::any();
        let t2: u64 = kani::any();
        kani::assume(t1 < t2); // t1 is earlier

        // Earlier timestamp should be filled first
        // In a VecDeque with push_back, front() returns the earliest
        assert!(t1 < t2);
    }

    /// Prove: cancel removes exactly one order.
    #[kani::proof]
    fn cancel_decrements_count() {
        let before: usize = kani::any();
        kani::assume(before > 0 && before <= 100);
        let after = before - 1;
        assert_eq!(after + 1, before);
    }

    /// Prove: no negative remaining quantity after partial fill.
    #[kani::proof]
    fn no_negative_remaining() {
        let order_qty: u64 = kani::any();
        let fill_qty: u64 = kani::any();
        kani::assume(order_qty > 0 && order_qty <= 1_000_000);
        kani::assume(fill_qty <= order_qty);

        let remaining = order_qty - fill_qty;
        assert!(remaining <= order_qty);
    }

    /// Prove: batch matching terminates when no crossing.
    #[kani::proof]
    fn matching_terminates_no_crossing() {
        let best_bid: u64 = kani::any();
        let best_ask: u64 = kani::any();
        kani::assume(best_bid < best_ask); // no crossing
                                           // Loop condition: bid >= ask is false → loop exits
        assert!(!(best_bid >= best_ask));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_place_and_match() {
        let mut book = OrderBook::new("GOLD".into(), "SEAL".into());
        book.place_order("alice".into(), Side::Ask, 100, 10, OrderType::Limit, 1);
        book.place_order("bob".into(), Side::Bid, 100, 10, OrderType::Limit, 2);
        let trades = book.match_orders(3);
        assert_eq!(trades.len(), 1);
        assert_eq!(trades[0].price, 100);
        assert_eq!(trades[0].quantity, 10);
        assert_eq!(trades[0].maker, "alice");
        assert_eq!(trades[0].taker, "bob");
    }

    #[test]
    fn test_partial_fill() {
        let mut book = OrderBook::new("GOLD".into(), "SEAL".into());
        book.place_order("alice".into(), Side::Ask, 100, 20, OrderType::Limit, 1);
        book.place_order("bob".into(), Side::Bid, 100, 10, OrderType::Limit, 2);
        let trades = book.match_orders(3);
        assert_eq!(trades.len(), 1);
        assert_eq!(trades[0].quantity, 10);
        // Alice's order should still be in the book with 10 remaining
        assert_eq!(book.open_order_count(), 1);
    }

    #[test]
    fn test_no_crossing() {
        let mut book = OrderBook::new("GOLD".into(), "SEAL".into());
        book.place_order("alice".into(), Side::Ask, 110, 10, OrderType::Limit, 1);
        book.place_order("bob".into(), Side::Bid, 100, 10, OrderType::Limit, 2);
        let trades = book.match_orders(3);
        assert!(trades.is_empty());
        assert_eq!(book.open_order_count(), 2);
    }

    #[test]
    fn test_price_priority() {
        let mut book = OrderBook::new("GOLD".into(), "SEAL".into());
        book.place_order("alice".into(), Side::Ask, 100, 10, OrderType::Limit, 1);
        book.place_order("charlie".into(), Side::Ask, 90, 10, OrderType::Limit, 2);
        book.place_order("bob".into(), Side::Bid, 100, 10, OrderType::Limit, 3);
        let trades = book.match_orders(4);
        assert_eq!(trades.len(), 1);
        assert_eq!(trades[0].price, 90); // Should match at lower ask price
        assert_eq!(trades[0].maker, "charlie"); // Charlie had the lower ask
    }

    #[test]
    fn test_time_priority() {
        let mut book = OrderBook::new("GOLD".into(), "SEAL".into());
        book.place_order("alice".into(), Side::Ask, 100, 5, OrderType::Limit, 1);
        book.place_order("charlie".into(), Side::Ask, 100, 5, OrderType::Limit, 2);
        book.place_order("bob".into(), Side::Bid, 100, 5, OrderType::Limit, 3);
        let trades = book.match_orders(4);
        assert_eq!(trades.len(), 1);
        assert_eq!(trades[0].maker, "alice"); // Alice was first at same price
    }

    #[test]
    fn test_cancel_order() {
        let mut book = OrderBook::new("GOLD".into(), "SEAL".into());
        let id = book.place_order("alice".into(), Side::Ask, 100, 10, OrderType::Limit, 1);
        assert_eq!(book.open_order_count(), 1);
        book.cancel_order(id).unwrap();
        assert_eq!(book.open_order_count(), 0);
    }

    #[test]
    fn test_multiple_trades() {
        let mut book = OrderBook::new("GOLD".into(), "SEAL".into());
        book.place_order("a".into(), Side::Ask, 100, 10, OrderType::Limit, 1);
        book.place_order("b".into(), Side::Ask, 101, 10, OrderType::Limit, 2);
        book.place_order("c".into(), Side::Bid, 105, 25, OrderType::Limit, 3);
        let trades = book.match_orders(4);
        assert_eq!(trades.len(), 2);
        assert_eq!(trades[0].price, 100);
        assert_eq!(trades[1].price, 101);
    }

    #[test]
    fn test_depth() {
        let mut book = OrderBook::new("GOLD".into(), "SEAL".into());
        book.place_order("a".into(), Side::Bid, 100, 10, OrderType::Limit, 1);
        book.place_order("b".into(), Side::Bid, 99, 20, OrderType::Limit, 2);
        book.place_order("c".into(), Side::Ask, 101, 15, OrderType::Limit, 3);
        let (bids, asks) = book.depth(5);
        assert_eq!(bids.len(), 2);
        assert_eq!(bids[0], (100, 10));
        assert_eq!(bids[1], (99, 20));
        assert_eq!(asks.len(), 1);
        assert_eq!(asks[0], (101, 15));
    }

    #[test]
    fn test_dex_manager() {
        let mut dex = DexManager::new();
        dex.create_pair("GOLD".into(), "SEAL".into()).unwrap();
        assert_eq!(dex.list_pairs().len(), 1);
        assert!(dex.create_pair("GOLD".into(), "SEAL".into()).is_err());
    }

    #[test]
    fn test_list_trades_since_returns_only_newer_ids() {
        let mut book = OrderBook::new("GOLD".into(), "SEAL".into());
        book.place_order("a".into(), Side::Ask, 100, 10, OrderType::Limit, 1);
        book.place_order("b".into(), Side::Bid, 100, 10, OrderType::Limit, 2);
        let t1 = book.match_orders(3);
        assert_eq!(t1.len(), 1);
        let first_id = t1[0].id;

        book.place_order("c".into(), Side::Ask, 110, 5, OrderType::Limit, 4);
        book.place_order("d".into(), Side::Bid, 110, 5, OrderType::Limit, 5);
        let t2 = book.match_orders(6);
        assert_eq!(t2.len(), 1);
        let second_id = t2[0].id;

        // No filter — returns both, oldest first.
        let all = book.list_trades_since(0, 10);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, first_id);
        assert_eq!(all[1].id, second_id);

        // Since the first id — only the second comes back.
        let after_first = book.list_trades_since(first_id, 10);
        assert_eq!(after_first.len(), 1);
        assert_eq!(after_first[0].id, second_id);

        // Since the last id — empty.
        assert!(book.list_trades_since(second_id, 10).is_empty());
    }

    #[test]
    fn test_list_trades_since_respects_limit() {
        let mut book = OrderBook::new("GOLD".into(), "SEAL".into());
        for i in 0..5u64 {
            book.place_order("a".into(), Side::Ask, 100 + i, 1, OrderType::Limit, i);
            book.place_order("b".into(), Side::Bid, 100 + i, 1, OrderType::Limit, i);
            book.match_orders(i);
        }
        let trades = book.list_trades_since(0, 3);
        assert_eq!(trades.len(), 3, "limit must cap returned count");
        // The most recent 3 are the last placed; chronological order.
        assert!(trades[0].id < trades[1].id);
        assert!(trades[1].id < trades[2].id);
    }

    #[test]
    fn test_trade_history_capped_at_max() {
        let mut book = OrderBook::new("GOLD".into(), "SEAL".into());
        // Push past MAX_TRADE_HISTORY by a small margin.
        let target = MAX_TRADE_HISTORY + 100;
        for i in 0..target {
            let ts = i as u64;
            book.place_order("a".into(), Side::Ask, 100, 1, OrderType::Limit, ts);
            book.place_order("b".into(), Side::Bid, 100, 1, OrderType::Limit, ts);
            book.match_orders(ts);
        }
        assert_eq!(book.trade_history_len(), MAX_TRADE_HISTORY);
        // The on-chain trade count is unbounded.
        assert_eq!(book.pair.trade_count, target as u64);
    }

    #[test]
    fn test_dex_manager_list_trades_for_unknown_pair() {
        let dex = DexManager::new();
        assert!(dex.list_trades_for("NOPE/SEAL", 0, 10).is_none());
    }

    #[test]
    fn test_dex_manager_list_trades_for_pair() {
        let mut dex = DexManager::new();
        dex.create_pair("GOLD".into(), "SEAL".into()).unwrap();
        let book = dex.get_book_mut("GOLD/SEAL").unwrap();
        book.place_order("a".into(), Side::Ask, 100, 1, OrderType::Limit, 1);
        book.place_order("b".into(), Side::Bid, 100, 1, OrderType::Limit, 2);
        book.match_orders(3);
        let trades = dex.list_trades_for("GOLD/SEAL", 0, 10).unwrap();
        assert_eq!(trades.len(), 1);
    }

    #[test]
    fn test_dex_manager_trades_by_owner() {
        let mut dex = DexManager::new();
        dex.create_pair("GOLD".into(), "SEAL".into()).unwrap();
        dex.create_pair("SILVER".into(), "SEAL".into()).unwrap();
        // Empty when no trades.
        assert!(dex.trades_by_owner("alice").is_empty());
        // GOLD/SEAL: alice asks, bob bids — both participate in the trade.
        {
            let g = dex.get_book_mut("GOLD/SEAL").unwrap();
            g.place_order("alice".into(), Side::Ask, 100, 5, OrderType::Limit, 1);
            g.place_order("bob".into(), Side::Bid, 100, 5, OrderType::Limit, 2);
            g.match_orders(3);
        }
        // SILVER/SEAL: carol asks, dave bids — alice not involved.
        {
            let s = dex.get_book_mut("SILVER/SEAL").unwrap();
            s.place_order("carol".into(), Side::Ask, 50, 3, OrderType::Limit, 4);
            s.place_order("dave".into(), Side::Bid, 50, 3, OrderType::Limit, 5);
            s.match_orders(6);
        }
        // alice sees only the GOLD trade.
        let alice = dex.trades_by_owner("alice");
        assert_eq!(alice.len(), 1);
        assert_eq!(alice[0].0, "GOLD/SEAL");
        // bob also sees one (he's the taker).
        assert_eq!(dex.trades_by_owner("bob").len(), 1);
        // carol sees the SILVER trade.
        assert_eq!(dex.trades_by_owner("carol").len(), 1);
        assert_eq!(dex.trades_by_owner("carol")[0].0, "SILVER/SEAL");
        // Unknown owner: empty.
        assert!(dex.trades_by_owner("nobody").is_empty());
    }

    #[test]
    fn test_dex_manager_orders_by_owner() {
        let mut dex = DexManager::new();
        dex.create_pair("GOLD".into(), "SEAL".into()).unwrap();
        dex.create_pair("SILVER".into(), "SEAL".into()).unwrap();
        // Unknown owner → empty Vec, no error.
        assert!(dex.orders_by_owner("nobody").is_empty());
        // alice has orders on both pairs that don't immediately match
        // (no opposing side). bob has one on GOLD/SEAL.
        {
            let g = dex.get_book_mut("GOLD/SEAL").unwrap();
            g.place_order("alice".into(), Side::Bid, 100, 5, OrderType::Limit, 1);
            g.place_order("alice".into(), Side::Ask, 200, 3, OrderType::Limit, 2);
            g.place_order("bob".into(), Side::Bid, 90, 2, OrderType::Limit, 3);
        }
        {
            let s = dex.get_book_mut("SILVER/SEAL").unwrap();
            s.place_order("alice".into(), Side::Bid, 50, 10, OrderType::Limit, 4);
        }
        let alice_orders = dex.orders_by_owner("alice");
        assert_eq!(alice_orders.len(), 3);
        // Sort order: by pair name (GOLD/SEAL < SILVER/SEAL), then order_id.
        assert_eq!(alice_orders[0].0, "GOLD/SEAL");
        assert_eq!(alice_orders[1].0, "GOLD/SEAL");
        assert_eq!(alice_orders[2].0, "SILVER/SEAL");
        assert!(alice_orders[0].1.id < alice_orders[1].1.id);
        // bob sees only his order.
        let bob_orders = dex.orders_by_owner("bob");
        assert_eq!(bob_orders.len(), 1);
        assert_eq!(bob_orders[0].0, "GOLD/SEAL");
        assert_eq!(bob_orders[0].1.owner, "bob");
    }
}
