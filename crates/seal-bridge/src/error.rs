//! Bridge error types.

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeError {
    #[error("unsupported chain: {0}")]
    UnsupportedChain(String),

    #[error("deposit not found: {0}")]
    DepositNotFound(String),

    #[error("deposit already processed: {0}")]
    DepositAlreadyProcessed(String),

    #[error("insufficient wrapped balance: need {need}, have {have}")]
    InsufficientWrapped { need: u64, have: u64 },

    #[error("withdrawal not confirmed")]
    WithdrawalNotConfirmed,

    #[error("invalid source transaction: {0}")]
    InvalidSourceTx(String),

    #[error("mint would exceed locked amount")]
    MintExceedsLocked,

    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("invalid block range: from={from} to={to}")]
    InvalidBlockRange { from: u64, to: u64 },

    #[error("transaction not found: {0}")]
    TransactionNotFound(String),

    #[error("chain {chain} is paused: {reason}")]
    ChainPaused { chain: String, reason: String },

    #[error("chain {0} is not paused")]
    ChainNotPaused(String),

    #[error("invalid destination address: {0}")]
    InvalidDestAddress(String),
}
