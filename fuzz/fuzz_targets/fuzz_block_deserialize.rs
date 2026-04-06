//! Fuzz target: Block deserialization should never panic.
//!
//! Feeds arbitrary bytes to bincode deserialization of Block.
//! Must return Ok or Err — never panic, never hang.

#![no_main]
use libfuzzer_sys::fuzz_target;
use seal_storage::block_store::Block;

fuzz_target!(|data: &[u8]| {
    // This must NEVER panic
    let _: Result<Block, _> = bincode::deserialize(data);
});
