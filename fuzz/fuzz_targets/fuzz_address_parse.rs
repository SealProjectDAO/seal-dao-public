//! Fuzz target: SealAddress parsing should never panic.
//!
//! Feeds arbitrary strings to SealAddress::from_string_encoding().
//! Should return Ok or Err — never panic.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = seal_crypto::address::SealAddress::from_string_encoding(s);
    }
});
