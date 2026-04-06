//! Fuzz target: Transaction deserialization should never panic.
//!
//! Feeds arbitrary bytes to bincode deserialization of Transaction.
//! Must return Ok or Err — never panic, never hang.

#![no_main]
use libfuzzer_sys::fuzz_target;
use seal_storage::block_store::Transaction;

fuzz_target!(|data: &[u8]| {
    // This must NEVER panic
    let _: Result<Transaction, _> = bincode::deserialize(data);
});
