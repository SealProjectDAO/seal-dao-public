#![allow(unexpected_cfgs)]
//! VRF-based consensus engine for Seal DAO.
//!
//! Algorand-style consensus with PQ-VRF leader selection:
//! - Slots: fixed 4-second intervals
//! - Epochs: 256 slots (~17 minutes), VRF keys rotate per epoch
//! - Leader election: VRF output < threshold(stake) → proposer
//! - Committee: VRF-selected validators vote on proposed blocks
//! - Finality: single-slot (>2/3 committee weight)
//!
//! See SPEC.md §2 and CONSENSUS-COMPARISON.md.

pub mod config;
pub mod election;
pub mod epoch;
pub mod genesis;
pub mod slashing;
pub mod validator;

pub use config::ConsensusConfig;
pub use election::ElectionResult;
pub use epoch::{Epoch, Slot};
pub use validator::{ValidatorInfo, ValidatorSet};
