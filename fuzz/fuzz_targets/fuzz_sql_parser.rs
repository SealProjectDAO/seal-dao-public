//! Fuzz target: SQL parser should never panic on any input.
//!
//! Feeds arbitrary byte strings to the PostgreSQL SQL parser.
//! The parser should return Ok or Err — never panic, never hang.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Convert arbitrary bytes to a string (lossy: invalid UTF-8 → replacement chars)
    if let Ok(sql) = std::str::from_utf8(data) {
        // This must NEVER panic
        let _ = seal_sql::parse_sql(sql);
    }
});
