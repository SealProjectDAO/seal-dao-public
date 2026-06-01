//! BalanceStore scale benchmarks.
//!
//! Run with:
//!   RUSTC_BOOTSTRAP=1 cargo bench -p seal-token --bench balance_scale
//!   (or `rustup run nightly cargo bench …`)
//!
//! Measures the headline win from PLAN #8 step 1 (HAMT-backed
//! `BalanceStore` + cached `state_root_hash`):
//!
//! - **`bench_state_root_cached_*`** — cache hit path (Cell read).
//!   This is what every block production loop sees on every call
//!   after the first per-block invalidation. Should be sub-microsecond
//!   at any ledger size; the pre-PLAN #8 path was O(n log32 n) on
//!   each call.
//! - **`bench_account_count_*`** — `Hamt::len()`; the metric exposed
//!   at `/metrics` (`seal_account_count`).
//! - **`bench_get_existing_*`** / **`bench_get_missing_*`** — HAMT
//!   lookup hot path (sha3 of key + log32 traversal + bincode decode).
//!
//! Heavier benches (sustained mint / transfer / cold-root rebuild)
//! aren't here on purpose: `Bencher::iter` re-runs the closure many
//! times to get a stable measurement, and at 10⁴+ accounts per iter
//! the suite balloons past the per-PR loop. For a one-shot scale
//! test, write an integration test that times the operation under
//! `std::time::Instant::now()` directly. 10⁶ / 10⁷ / 10⁸ scale
//! benchmarks belong with the state-sync scaffolding tracked under
//! `docs/STATE-SYNC.md` (TODO).

#![feature(test)]
extern crate test;

use seal_token::balance::BalanceStore;
use test::Bencher;

/// Build a store pre-populated with `n` accounts. The amount is
/// picked so total_supply doesn't overflow at `n = 10^7`.
fn populated_store(n: usize) -> BalanceStore {
    let mut store = BalanceStore::new();
    for i in 0..n {
        store.mint(&format!("seal1addr{:08x}", i), 1_000).unwrap();
    }
    store
}

#[bench]
fn bench_state_root_cached_10k(b: &mut Bencher) {
    let store = populated_store(10_000);
    let _ = store.state_root_hash(); // prime cache
    b.iter(|| test::black_box(store.state_root_hash()));
}

#[bench]
fn bench_state_root_cached_100k(b: &mut Bencher) {
    let store = populated_store(100_000);
    let _ = store.state_root_hash();
    b.iter(|| test::black_box(store.state_root_hash()));
}

#[bench]
fn bench_account_count_10k(b: &mut Bencher) {
    let store = populated_store(10_000);
    b.iter(|| test::black_box(store.account_count()));
}

#[bench]
fn bench_account_count_100k(b: &mut Bencher) {
    let store = populated_store(100_000);
    b.iter(|| test::black_box(store.account_count()));
}

#[bench]
fn bench_get_existing_10k(b: &mut Bencher) {
    let store = populated_store(10_000);
    let target = format!("seal1addr{:08x}", 5_000); // middle
    b.iter(|| test::black_box(store.available(&target)));
}

#[bench]
fn bench_get_existing_100k(b: &mut Bencher) {
    let store = populated_store(100_000);
    let target = format!("seal1addr{:08x}", 50_000);
    b.iter(|| test::black_box(store.available(&target)));
}

#[bench]
fn bench_get_missing_10k(b: &mut Bencher) {
    let store = populated_store(10_000);
    b.iter(|| test::black_box(store.available("seal1nonexistent")));
}

#[bench]
fn bench_has_account_10k(b: &mut Bencher) {
    let store = populated_store(10_000);
    let target = format!("seal1addr{:08x}", 5_000);
    b.iter(|| test::black_box(store.has_account(&target)));
}

/// Single-shot measurement of the hot transaction path: a transfer
/// updates two accounts and invalidates the root cache. We pre-mint
/// alice with enough headroom, then run one transfer per iter (the
/// closure stays light, so `Bencher::iter` can iterate fast).
#[bench]
fn bench_transfer_one(b: &mut Bencher) {
    let mut store = BalanceStore::new();
    store.mint("alice", u64::MAX / 2).unwrap();
    store.mint("bob", 0).unwrap();
    b.iter(|| {
        store.transfer("alice", "bob", 1).unwrap();
        test::black_box(store.available("bob"))
    });
}

/// Single-shot mint into an EMPTY store. Measures the per-insert
/// HAMT cost on a small trie (the cheap end of the curve). For
/// scale measurement, use a one-shot integration test as discussed
/// in the module docs.
#[bench]
fn bench_mint_one_into_empty(b: &mut Bencher) {
    let mut counter = 0u64;
    b.iter(|| {
        let mut store = BalanceStore::new();
        counter = counter.wrapping_add(1);
        store
            .mint(&format!("seal1addr{:08x}", counter), 1_000)
            .unwrap();
        test::black_box(store.account_count())
    });
}
