//! Block-height-based chain observers for bridge event detection.
//!
//! This module provides a block-range polling model for observing deposit
//! and withdrawal events on external chains. Unlike the cursor-based
//! [`crate::observer`] module, observers here operate on explicit block
//! height ranges, making it easier to implement resumable, gap-free
//! scanning of source chains.
//!
//! Architecture:
//!   ChainObserver (trait)
//!     |-- SolanaObserver  -- polls Solana RPC (`getSignaturesForAddress`, `getTransaction`)
//!     `-- StellarObserver -- polls Stellar Horizon (`/effects?cursor=...`)

use crate::error::BridgeError;

// ---------------------------------------------------------------------------
// Bridge event types
// ---------------------------------------------------------------------------

/// An event observed on a source chain relevant to the Seal bridge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeEvent {
    /// A deposit (lock) on the source chain destined for Seal.
    Deposit {
        /// Sender address on the source chain.
        sender: String,
        /// Amount locked (in the source chain's smallest unit).
        amount: u64,
        /// Recipient SEAL address that should receive wrapped tokens.
        seal_address: String,
        /// Transaction hash on the source chain.
        tx_hash: String,
        /// Block height at which the lock transaction was included.
        block_height: u64,
    },
    /// A withdrawal (unlock) executed on the source chain.
    Withdrawal {
        /// Recipient address on the source chain.
        recipient: String,
        /// Amount unlocked.
        amount: u64,
        /// Transaction hash on the source chain.
        tx_hash: String,
    },
}

/// Confirmation status of a deposit on its source chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositConfirmation {
    /// Whether the deposit has reached the required number of confirmations.
    pub confirmed: bool,
    /// Current number of confirmations.
    pub confirmations: u64,
    /// Number of confirmations required for finality.
    pub required_confirmations: u64,
}

// ---------------------------------------------------------------------------
// ChainObserver trait
// ---------------------------------------------------------------------------

/// Trait for block-height-based chain observers.
///
/// Implementors poll an external chain's RPC or API endpoint for bridge
/// events within a specified block range. This enables deterministic
/// replay and gap-free scanning.
pub trait ChainObserver {
    /// Human-readable name of the chain being observed (e.g., `"Solana"`).
    fn chain_name(&self) -> &str;

    /// Poll for bridge events in the block range `[from_block, to_block]`.
    ///
    /// Returns `Err(BridgeError::InvalidBlockRange)` when `from_block > to_block`.
    fn poll_events(&self, from_block: u64, to_block: u64) -> Result<Vec<BridgeEvent>, BridgeError>;

    /// Return the latest finalized block height on the source chain.
    fn latest_block_height(&self) -> Result<u64, BridgeError>;

    /// Check the confirmation status of a deposit identified by `tx_hash`.
    fn confirm_deposit(&self, tx_hash: &str) -> Result<DepositConfirmation, BridgeError>;
}

// ---------------------------------------------------------------------------
// SolanaObserver
// ---------------------------------------------------------------------------

/// Block-height-based observer for Solana.
///
/// In production this calls Solana JSON-RPC methods:
/// - `getSignaturesForAddress` to discover transactions in a slot range
/// - `getTransaction` to decode lock instructions and check confirmation count
///
/// The current implementation returns mock data suitable for testing.
pub struct SolanaObserver {
    /// Solana JSON-RPC endpoint (e.g., `"https://api.devnet.solana.com"`).
    pub rpc_url: String,
    /// The seal-lock program ID on Solana.
    pub program_id: String,
    /// Required slot confirmations for finality (Solana optimistic: 32).
    pub required_confirmations: u64,
}

impl SolanaObserver {
    /// Create a new Solana observer.
    pub fn new(rpc_url: &str, program_id: &str, required_confirmations: u64) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            program_id: program_id.to_string(),
            required_confirmations,
        }
    }

    /// Pre-configured for Solana devnet with default 32-slot confirmation.
    pub fn devnet(program_id: &str) -> Self {
        Self::new("https://api.devnet.solana.com", program_id, 32)
    }
}

impl ChainObserver for SolanaObserver {
    fn chain_name(&self) -> &str {
        "Solana"
    }

    fn poll_events(&self, from_block: u64, to_block: u64) -> Result<Vec<BridgeEvent>, BridgeError> {
        if from_block > to_block {
            return Err(BridgeError::InvalidBlockRange {
                from: from_block,
                to: to_block,
            });
        }

        // Stub: in production this would call Solana JSON-RPC:
        //
        // POST {self.rpc_url}
        // {
        //   "jsonrpc": "2.0",
        //   "method": "getSignaturesForAddress",
        //   "params": [
        //     "{self.program_id}",
        //     {
        //       "minContextSlot": from_block,
        //       "commitment": "finalized"
        //     }
        //   ]
        // }
        //
        // Then for each returned signature, fetch the full transaction via
        // `getTransaction` and decode the lock/unlock instruction data.
        //
        // Filter results to only include transactions in [from_block, to_block].

        // Return a mock deposit so tests can exercise the pipeline.
        let mock_block = from_block;
        let events = vec![BridgeEvent::Deposit {
            sender: "SolSender1111111111111111111111111111111111".to_string(),
            amount: 1_000_000_000, // 1 SOL in lamports
            seal_address: "seal1mock_recipient".to_string(),
            tx_hash: format!("sol_mock_tx_{}", mock_block),
            block_height: mock_block,
        }];

        Ok(events)
    }

    fn latest_block_height(&self) -> Result<u64, BridgeError> {
        // Stub: in production would call:
        //
        // POST {self.rpc_url}
        // {
        //   "jsonrpc": "2.0",
        //   "method": "getSlot",
        //   "params": [{ "commitment": "finalized" }]
        // }

        // Return a mock slot height.
        Ok(300_000_000)
    }

    fn confirm_deposit(&self, tx_hash: &str) -> Result<DepositConfirmation, BridgeError> {
        if tx_hash.is_empty() {
            return Err(BridgeError::TransactionNotFound(tx_hash.to_string()));
        }

        // Stub: in production would call:
        //
        // POST {self.rpc_url}
        // {
        //   "jsonrpc": "2.0",
        //   "method": "getTransaction",
        //   "params": [
        //     "{tx_hash}",
        //     { "commitment": "finalized", "maxSupportedTransactionVersion": 0 }
        //   ]
        // }
        //
        // Then compare the transaction's slot against the current finalized
        // slot to derive the confirmation count.

        let mock_confirmations: u64 = 40; // > 32, so confirmed
        Ok(DepositConfirmation {
            confirmed: mock_confirmations >= self.required_confirmations,
            confirmations: mock_confirmations,
            required_confirmations: self.required_confirmations,
        })
    }
}

// ---------------------------------------------------------------------------
// StellarObserver
// ---------------------------------------------------------------------------

/// Block-height-based observer for Stellar.
///
/// In production this calls the Stellar Horizon REST API:
/// - `GET /effects?cursor=...&order=asc` to discover contract invocation events
/// - `GET /transactions/{hash}` to check ledger confirmation
///
/// The current implementation returns mock data suitable for testing.
pub struct StellarObserver {
    /// Horizon API endpoint (e.g., `"https://horizon-testnet.stellar.org"`).
    pub horizon_url: String,
    /// The seal-lock Soroban contract ID on Stellar.
    pub contract_id: String,
    /// Required ledger confirmations for finality (Stellar SCP: ~5).
    pub required_confirmations: u64,
}

impl StellarObserver {
    /// Create a new Stellar observer.
    pub fn new(horizon_url: &str, contract_id: &str, required_confirmations: u64) -> Self {
        Self {
            horizon_url: horizon_url.to_string(),
            contract_id: contract_id.to_string(),
            required_confirmations,
        }
    }

    /// Pre-configured for Stellar testnet with default 5-ledger confirmation.
    pub fn testnet(contract_id: &str) -> Self {
        Self::new("https://horizon-testnet.stellar.org", contract_id, 5)
    }
}

impl ChainObserver for StellarObserver {
    fn chain_name(&self) -> &str {
        "Stellar"
    }

    fn poll_events(&self, from_block: u64, to_block: u64) -> Result<Vec<BridgeEvent>, BridgeError> {
        if from_block > to_block {
            return Err(BridgeError::InvalidBlockRange {
                from: from_block,
                to: to_block,
            });
        }

        // Stub: in production this would call Stellar Horizon:
        //
        // GET {self.horizon_url}/effects?cursor={from_block}&order=asc&limit=200
        //
        // Filter for `invoke_host_function` effects where the contract ID
        // matches `self.contract_id` and the function is "lock" or "unlock".
        // Map ledger sequence numbers to our block_height concept.

        // Return a mock deposit so tests can exercise the pipeline.
        let mock_ledger = from_block;
        let events = vec![BridgeEvent::Deposit {
            sender: "GABCDEF_STELLAR_SENDER".to_string(),
            amount: 10_000_000, // 1 XLM in stroops
            seal_address: "seal1mock_stellar_recipient".to_string(),
            tx_hash: format!("xlm_mock_tx_{}", mock_ledger),
            block_height: mock_ledger,
        }];

        Ok(events)
    }

    fn latest_block_height(&self) -> Result<u64, BridgeError> {
        // Stub: in production would call:
        //
        // GET {self.horizon_url}/ledgers?order=desc&limit=1
        //
        // and extract the `sequence` field from the latest ledger.

        // Return a mock ledger sequence.
        Ok(50_000_000)
    }

    fn confirm_deposit(&self, tx_hash: &str) -> Result<DepositConfirmation, BridgeError> {
        if tx_hash.is_empty() {
            return Err(BridgeError::TransactionNotFound(tx_hash.to_string()));
        }

        // Stub: in production would call:
        //
        // GET {self.horizon_url}/transactions/{tx_hash}
        //
        // Extract the `ledger` field, then compare against the latest
        // ledger sequence to compute confirmations.

        let mock_confirmations: u64 = 8; // > 5, so confirmed
        Ok(DepositConfirmation {
            confirmed: mock_confirmations >= self.required_confirmations,
            confirmations: mock_confirmations,
            required_confirmations: self.required_confirmations,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_observer_chain_name() {
        let obs = SolanaObserver::devnet("SealLock111111111111111111111111111111111111");
        assert_eq!(obs.chain_name(), "Solana");
    }

    #[test]
    fn test_solana_poll_events() {
        let obs = SolanaObserver::devnet("SealLock111111111111111111111111111111111111");

        let events = obs.poll_events(100, 200).unwrap();
        assert!(!events.is_empty(), "stub should return at least one event");

        // Verify the mock deposit structure.
        match &events[0] {
            BridgeEvent::Deposit {
                sender,
                amount,
                seal_address,
                tx_hash,
                block_height,
            } => {
                assert!(!sender.is_empty());
                assert_eq!(*amount, 1_000_000_000);
                assert!(!seal_address.is_empty());
                assert!(tx_hash.starts_with("sol_mock_tx_"));
                assert_eq!(*block_height, 100);
            }
            BridgeEvent::Withdrawal { .. } => {
                panic!("expected Deposit, got Withdrawal");
            }
        }

        // Invalid range should produce an error.
        let err = obs.poll_events(300, 100);
        assert!(err.is_err());
        assert!(matches!(
            err,
            Err(BridgeError::InvalidBlockRange { from: 300, to: 100 })
        ));
    }

    #[test]
    fn test_stellar_observer_chain_name() {
        let obs = StellarObserver::testnet("CDXYZ_CONTRACT_ID");
        assert_eq!(obs.chain_name(), "Stellar");
    }

    #[test]
    fn test_stellar_poll_events() {
        let obs = StellarObserver::testnet("CDXYZ_CONTRACT_ID");

        let events = obs.poll_events(500, 600).unwrap();
        assert!(!events.is_empty(), "stub should return at least one event");

        match &events[0] {
            BridgeEvent::Deposit {
                sender,
                amount,
                seal_address,
                tx_hash,
                block_height,
            } => {
                assert!(!sender.is_empty());
                assert_eq!(*amount, 10_000_000);
                assert!(!seal_address.is_empty());
                assert!(tx_hash.starts_with("xlm_mock_tx_"));
                assert_eq!(*block_height, 500);
            }
            BridgeEvent::Withdrawal { .. } => {
                panic!("expected Deposit, got Withdrawal");
            }
        }

        // Invalid range should produce an error.
        let err = obs.poll_events(700, 600);
        assert!(err.is_err());
        assert!(matches!(
            err,
            Err(BridgeError::InvalidBlockRange { from: 700, to: 600 })
        ));
    }

    #[test]
    fn test_deposit_confirmation() {
        // Solana: mock returns 40 confirmations, required 32 -> confirmed.
        let sol = SolanaObserver::devnet("prog1");
        let conf = sol.confirm_deposit("some_sol_tx_hash").unwrap();
        assert!(conf.confirmed);
        assert_eq!(conf.confirmations, 40);
        assert_eq!(conf.required_confirmations, 32);

        // Stellar: mock returns 8 confirmations, required 5 -> confirmed.
        let xlm = StellarObserver::testnet("contract1");
        let conf = xlm.confirm_deposit("some_xlm_tx_hash").unwrap();
        assert!(conf.confirmed);
        assert_eq!(conf.confirmations, 8);
        assert_eq!(conf.required_confirmations, 5);

        // Empty tx_hash should fail with TransactionNotFound.
        let err = sol.confirm_deposit("");
        assert!(matches!(err, Err(BridgeError::TransactionNotFound(_))));
    }

    #[test]
    fn test_solana_latest_block_height() {
        let obs = SolanaObserver::devnet("prog1");
        let height = obs.latest_block_height().unwrap();
        assert!(height > 0, "mock height should be non-zero");
    }

    #[test]
    fn test_stellar_latest_block_height() {
        let obs = StellarObserver::testnet("contract1");
        let height = obs.latest_block_height().unwrap();
        assert!(height > 0, "mock height should be non-zero");
    }

    #[test]
    fn test_poll_events_same_block() {
        // from_block == to_block is a valid single-block query.
        let obs = SolanaObserver::devnet("prog1");
        let events = obs.poll_events(42, 42).unwrap();
        assert!(!events.is_empty());
    }

    #[test]
    fn test_bridge_event_equality() {
        let e1 = BridgeEvent::Deposit {
            sender: "A".into(),
            amount: 100,
            seal_address: "seal1a".into(),
            tx_hash: "tx1".into(),
            block_height: 1,
        };
        let e2 = e1.clone();
        assert_eq!(e1, e2);

        let e3 = BridgeEvent::Withdrawal {
            recipient: "B".into(),
            amount: 50,
            tx_hash: "tx2".into(),
        };
        assert_ne!(e1, e3);
    }
}
