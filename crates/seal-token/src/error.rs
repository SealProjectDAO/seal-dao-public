//! Token error types.

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("insufficient balance: need {need}, have {have}")]
    InsufficientBalance { need: u64, have: u64 },

    #[error("overflow: operation would exceed u64::MAX")]
    Overflow,

    #[error("account not found: {0}")]
    AccountNotFound(String),

    #[error("insufficient stake: need {need}, have {have}")]
    InsufficientStake { need: u64, have: u64 },

    #[error("unbonding period not complete: {remaining_epochs} epochs remaining")]
    UnbondingNotComplete { remaining_epochs: u64 },

    #[error("already staking")]
    AlreadyStaking,

    #[error("insufficient treasury balance: need {need}, have {have}")]
    InsufficientTreasury { need: u64, have: u64 },

    #[error("governance approval required for treasury disbursement")]
    GovernanceRequired,

    #[error("{0}")]
    Custom(String),
}
