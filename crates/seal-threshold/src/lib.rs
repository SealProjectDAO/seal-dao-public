//! Threshold signature scheme for Seal DAO committee voting.
//!
//! # Architecture
//!
//! Defines a `ThresholdScheme` trait with two implementations:
//!
//! 1. **`SimpleThreshold`** (current) — Collects individual ML-DSA signatures
//!    and a participation bitfield. NOT a real threshold scheme (signatures are
//!    not aggregated). Used for protocol development.
//!
//! 2. **`RingtailThreshold`** (future, TODO) — Ringtail lattice-based threshold
//!    signatures (ePrint 2024/1113). 2-round interactive protocol producing a
//!    single ~13.4 KB signature from 100 committee members. Requires:
//!    - Port Ringtail implementation (github.com/daryakaviani/ringtail)
//!    - Integrate round-1 preprocessing with slot pipeline
//!    - Lean 4 proof of threshold security properties
//!    - Kani/Miri/cargo-fuzz verification
//!    - Benchmark: 100-member signing within 2s over WAN

pub mod error;
pub mod ntt;
pub mod ringtail;
pub mod simple;
pub mod snark_agg;
pub mod traits;

pub use error::ThresholdError;
pub use ringtail::RingtailThreshold;
pub use simple::SimpleThreshold;
pub use snark_agg::{AggregatedProof, SnarkAggregator};
pub use traits::{Bitfield, PartialSignature, ThresholdScheme, ThresholdSignature};
