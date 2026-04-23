#![allow(unexpected_cfgs)]
//! Cross-chain bridge for Solana and Stellar.
//!
//! Lock-and-mint mechanism (SPEC.md §5.2, §5.3):
//! 1. User locks SOL/XLM on source chain
//! 2. Seal validators observe the lock event
//! 3. Seal mints wrapped tokens (wSOL, wXLM, wUSDC)
//! 4. Reverse: burn on Seal → unlock on source chain
//!
//! Security: validator committee threshold signature for release.
//! TLA+ spec: formal/tlaplus/SealBridge.tla (TODO)

pub mod bridge;
pub mod error;
pub mod http;
pub mod observer;
pub mod observers;
pub mod types;

pub use bridge::BridgeManager;
pub use error::BridgeError;
pub use observer::{BridgeObserverSet, ChainObserver, SolanaObserver, StellarObserver};
pub use observers::{
    BridgeEvent, ChainObserver as BlockChainObserver, DepositConfirmation,
    SolanaObserver as SolanaBlockObserver, StellarObserver as StellarBlockObserver,
};
pub use types::{BridgeDeposit, BridgeWithdrawal, Chain, WrappedToken};
