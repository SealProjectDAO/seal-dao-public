#![allow(unexpected_cfgs)]
//! SEAL token economics: balances, transfers, staking, burn-and-mint.
//!
//! Implements the token model from SPEC.md §10 and §16.1:
//! - Balance tracking per address
//! - Transfers with overflow-checked arithmetic
//! - Staking/unstaking with unbonding period
//! - Fee burn mechanism (50% of base fee)
//! - Supply tracking (total supply, circulating, staked, burned)

pub mod balance;
pub mod emission;
pub mod error;
pub mod hamt;
pub mod orderbook;
pub mod params;
pub mod staking;
pub mod storage_lease;
pub mod tokens;
pub mod transfer;
pub mod treasury;

pub use balance::{Balance, BalanceStore};
pub use emission::EmissionSchedule;
pub use error::TokenError;
pub use staking::{StakeInfo, StakingManager};
pub use storage_lease::{LeaseManager, StorageLease};
pub use transfer::TransferResult;
pub use treasury::Treasury;
