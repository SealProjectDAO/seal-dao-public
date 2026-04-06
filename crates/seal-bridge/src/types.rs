//! Bridge types.

use serde::{Deserialize, Serialize};

/// Supported external chains.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Chain {
    Solana,
    Stellar,
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::Solana => write!(f, "Solana"),
            Chain::Stellar => write!(f, "Stellar"),
        }
    }
}

/// A wrapped token on the Seal chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WrappedToken {
    WSOL,  // Wrapped SOL
    WXLM,  // Wrapped XLM
    WUSDC, // Wrapped USDC (from either chain)
}

impl WrappedToken {
    pub fn chain(&self) -> Chain {
        match self {
            WrappedToken::WSOL => Chain::Solana,
            WrappedToken::WXLM => Chain::Stellar,
            WrappedToken::WUSDC => Chain::Solana, // Default USDC source
        }
    }

    pub fn symbol(&self) -> &str {
        match self {
            WrappedToken::WSOL => "wSOL",
            WrappedToken::WXLM => "wXLM",
            WrappedToken::WUSDC => "wUSDC",
        }
    }
}

/// A deposit from an external chain into Seal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeDeposit {
    /// Unique deposit ID.
    pub id: String,
    /// Source chain.
    pub source_chain: Chain,
    /// Source chain transaction hash.
    pub source_tx_hash: String,
    /// Depositor's address on the source chain.
    pub source_address: String,
    /// Recipient's SEAL address.
    pub seal_address: String,
    /// Amount locked on source chain (in source chain's smallest unit).
    pub amount: u64,
    /// Token being bridged.
    pub token: WrappedToken,
    /// Whether the deposit has been processed (minted on Seal).
    pub processed: bool,
    /// Number of validator confirmations.
    pub confirmations: u32,
}

/// A withdrawal from Seal to an external chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeWithdrawal {
    /// Unique withdrawal ID.
    pub id: String,
    /// Destination chain.
    pub dest_chain: Chain,
    /// Destination address on the external chain.
    pub dest_address: String,
    /// SEAL address burning the wrapped tokens.
    pub seal_address: String,
    /// Amount to unlock on destination chain.
    pub amount: u64,
    /// Token being withdrawn.
    pub token: WrappedToken,
    /// Whether the withdrawal has been executed on the destination chain.
    pub executed: bool,
}
