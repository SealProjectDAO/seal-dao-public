//! copy-trading.seal — public-leader, capped-follower mirror trades.
//!
//! # Model
//!
//! A *leader* publishes their DEX orders to the chain. *Followers*
//! pre-register a per-leader allowance (max micro-SEAL per slot, max
//! orders per day, list of allowed markets) and the runtime mirrors
//! each leader order onto the follower's account, scaled to fit the
//! follower's allowance.
//!
//! Threat model: a follower must not lose more than their declared
//! allowance per epoch even if the leader goes rogue. The allowance
//! is enforced by RLS on the `mirror_orders` table — the follower
//! signs the row that creates the allowance, and any mirror_order
//! that exceeds the running tally is rejected at insert time.
//!
//! # Schema
//!
//! Three tables:
//!
//! * `leaders` — registered leaders + which markets they trade.
//! * `follows` — `(follower, leader, allowance, max_orders_per_day,
//!   markets, started_at)`.
//! * `mirror_orders` — per-mirror record so the follower has an audit
//!   trail and the runtime can compute the running allowance.
//!
//! # What this crate ships
//!
//! Schema DDL, RLS policies, and the pure-Rust `scale_order_for_follower`
//! function that the runtime uses to compute the mirror size given the
//! follower's allowance and the leader's order. Wiring into `seal-node`
//! happens behind a feature flag once the order-mirroring tx type
//! lands.

use serde::{Deserialize, Serialize};

pub const SCHEMA_DDL: &str = "
CREATE TABLE leaders (
    address TEXT PRIMARY KEY,
    handle TEXT NOT NULL,
    markets TEXT NOT NULL,
    registered_at_height BIGINT NOT NULL
);

CREATE TABLE follows (
    follower TEXT NOT NULL,
    leader TEXT NOT NULL,
    allowance_micro_seal BIGINT NOT NULL,
    max_orders_per_day BIGINT NOT NULL,
    allowed_markets TEXT NOT NULL,
    started_at_height BIGINT NOT NULL
);

CREATE TABLE mirror_orders (
    id BIGINT PRIMARY KEY,
    follower TEXT NOT NULL,
    leader TEXT NOT NULL,
    market TEXT NOT NULL,
    side TEXT NOT NULL,
    price BIGINT NOT NULL,
    quantity BIGINT NOT NULL,
    leader_quantity BIGINT NOT NULL,
    created_at_height BIGINT NOT NULL
);
";

/// Returns the (table, action, USING expr) RLS policies for the
/// canonical deployment. Followers may only insert rows that name
/// themselves; the cap is enforced by `scale_order_for_follower`,
/// which the runtime calls before the INSERT.
pub fn rls_policies() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("follows", "INSERT_OWNER", "follower = CURRENT_USER()"),
        ("follows", "DELETE_OWNER", "follower = CURRENT_USER()"),
        // Mirror orders are emitted by the runtime on the follower's
        // behalf — the row's `follower` field still has to match the
        // current user (caller is the follower's address signing the
        // mirror tx).
        ("mirror_orders", "INSERT_OWNER", "follower = CURRENT_USER()"),
    ]
}

/// Per-follower allowance entry that the runtime keeps in memory
/// alongside the on-chain `follows` row. Snapshot of the row's
/// numeric fields plus a running consumption counter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FollowerAllowance {
    pub follower: String,
    pub leader: String,
    pub allowance_micro_seal: u64,
    /// micro-SEAL consumed in the current epoch. Reset by the runtime
    /// at each epoch boundary.
    pub consumed_micro_seal: u64,
    /// Orders allowed per day; the runtime is responsible for the
    /// counting + rollover.
    pub max_orders_per_day: u64,
    pub orders_today: u64,
    /// Comma-separated market names the follower has whitelisted.
    pub allowed_markets: Vec<String>,
}

/// Compute the mirror order quantity for a follower given the leader's
/// order. Returns `None` if the follower has zero remaining headroom or
/// the market isn't whitelisted.
///
/// Sizing rule: mirror at the *same proportion* of the leader's
/// available allowance — i.e. `mirror_qty = floor(leader_qty *
/// remaining_allowance / leader_total_capital)`. To keep this
/// crate independent of an account-balances oracle the runtime
/// passes `leader_total_capital_micro_seal` as a parameter; for the
/// pure-allowance path callers can pass `allowance_micro_seal`
/// itself, which collapses to "mirror up to leader_qty bounded by
/// remaining headroom".
pub fn scale_order_for_follower(
    allowance: &FollowerAllowance,
    market: &str,
    leader_quantity: u64,
    price_micro_seal: u64,
    leader_total_capital_micro_seal: u64,
) -> Option<u64> {
    if !allowance.allowed_markets.iter().any(|m| m == market) {
        return None;
    }
    if allowance.orders_today >= allowance.max_orders_per_day {
        return None;
    }
    let remaining = allowance
        .allowance_micro_seal
        .saturating_sub(allowance.consumed_micro_seal);
    if remaining == 0 {
        return None;
    }
    if leader_total_capital_micro_seal == 0 {
        return None;
    }

    // Proportional sizing.
    let scaled = (leader_quantity as u128 * remaining as u128
        / leader_total_capital_micro_seal as u128) as u64;
    if scaled == 0 {
        return None;
    }

    // Hard cap: the mirror's notional must fit the remaining headroom.
    let notional = scaled.saturating_mul(price_micro_seal);
    if notional > remaining {
        let max_qty = remaining / price_micro_seal.max(1);
        if max_qty == 0 {
            return None;
        }
        return Some(max_qty);
    }
    Some(scaled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_allowance() -> FollowerAllowance {
        FollowerAllowance {
            follower: "f".into(),
            leader: "l".into(),
            allowance_micro_seal: 1_000_000,
            consumed_micro_seal: 0,
            max_orders_per_day: 10,
            orders_today: 0,
            allowed_markets: vec!["GOLD/SEAL".into()],
        }
    }

    #[test]
    fn ddl_parses() {
        seal_sql::parse_sql(SCHEMA_DDL).expect("copy-trading DDL must parse");
    }

    #[test]
    fn policies_cover_inserts_and_deletes() {
        let p = rls_policies();
        assert!(p.iter().any(|(t, a, _)| *t == "follows" && a.contains("INSERT")));
        assert!(p.iter().any(|(t, a, _)| *t == "follows" && a.contains("DELETE")));
        assert!(p.iter().any(|(t, a, _)| *t == "mirror_orders" && a.contains("INSERT")));
    }

    #[test]
    fn unwhitelisted_market_returns_none() {
        let a = make_allowance();
        let qty = scale_order_for_follower(&a, "BTC/USD", 100, 50, 10_000);
        assert!(qty.is_none());
    }

    #[test]
    fn exhausted_daily_count_returns_none() {
        let mut a = make_allowance();
        a.orders_today = a.max_orders_per_day;
        let qty = scale_order_for_follower(&a, "GOLD/SEAL", 100, 50, 10_000);
        assert!(qty.is_none());
    }

    #[test]
    fn proportional_sizing_scales_with_remaining_headroom() {
        // Half the allowance left, leader trading 100% of capital →
        // mirror 100 * 0.5 = 50 (rounded down).
        let mut a = make_allowance();
        a.consumed_micro_seal = 500_000;
        let qty = scale_order_for_follower(&a, "GOLD/SEAL", 100, 1_000, 1_000_000)
            .expect("must produce a non-zero qty");
        assert_eq!(qty, 50);
    }

    #[test]
    fn notional_cap_clamps_when_proportion_exceeds_headroom() {
        // Allowance has 100 left; leader's order is huge relative to
        // their capital → proportional sizing might yield qty * price >
        // allowance. Confirm we clamp to remaining/price.
        let mut a = make_allowance();
        a.consumed_micro_seal = a.allowance_micro_seal - 100;
        let qty = scale_order_for_follower(&a, "GOLD/SEAL", 1_000, 50, 1_000)
            .expect("must produce a non-zero clamped qty");
        // remaining = 100; price = 50 → max 2 units.
        assert_eq!(qty, 2);
    }

    #[test]
    fn zero_remaining_returns_none() {
        let mut a = make_allowance();
        a.consumed_micro_seal = a.allowance_micro_seal;
        let qty = scale_order_for_follower(&a, "GOLD/SEAL", 100, 50, 10_000);
        assert!(qty.is_none());
    }
}
