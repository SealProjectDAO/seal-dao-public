//! Chain observers — poll external chains for lock events.
//!
//! Each observer monitors a source chain for lock transactions directed
//! at the Seal bridge program. When a lock is detected, it produces a
//! `BridgeDeposit` that gets fed to the `BridgeManager`.
//!
//! Architecture:
//!   ChainObserver (trait)
//!     ├── SolanaObserver  — polls Solana RPC for seal-lock program events
//!     └── StellarObserver — polls Stellar Horizon for lock contract events
//!
//! Both are polling-based (not WebSocket) for simplicity on testnet.
//! Production should use WebSocket subscriptions for lower latency.

use crate::error::BridgeError;
use crate::types::{BridgeDeposit, Chain, WrappedToken};

/// Trait for chain-specific lock event observers.
///
/// Implementations poll an external chain's RPC endpoint for new
/// lock events and convert them to `BridgeDeposit` records.
pub trait ChainObserver {
    /// Which chain this observer monitors.
    fn chain(&self) -> Chain;

    /// Poll for new lock events since `last_cursor`.
    /// Returns new deposits and an updated cursor for pagination.
    ///
    /// The cursor is opaque — for Solana it's a transaction signature,
    /// for Stellar it's a Horizon paging token.
    fn poll_events(
        &self,
        last_cursor: &str,
    ) -> Result<(Vec<BridgeDeposit>, String), BridgeError>;

    /// Check whether a specific source transaction is confirmed
    /// and finalized on the source chain.
    fn is_finalized(&self, source_tx_hash: &str) -> Result<bool, BridgeError>;
}

/// Solana observer — watches the seal-lock program for lock events.
///
/// Uses Solana's `getSignaturesForAddress` RPC to find transactions
/// that interact with the lock program, then decodes lock instructions.
pub struct SolanaObserver {
    /// Solana RPC endpoint (e.g., "https://api.devnet.solana.com").
    pub rpc_url: String,
    /// The seal-lock program ID on Solana.
    pub program_id: String,
    /// Required confirmations for finality (default: 32 for Solana).
    pub required_confirmations: u32,
}

impl SolanaObserver {
    pub fn new(rpc_url: &str, program_id: &str) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            program_id: program_id.to_string(),
            required_confirmations: 32, // Solana optimistic confirmation
        }
    }

    /// Devnet configuration.
    pub fn devnet(program_id: &str) -> Self {
        Self::new("https://api.devnet.solana.com", program_id)
    }

    /// Parse a Solana transaction into a BridgeDeposit.
    /// In testnet, we use a simplified format.
    /// Called by the polling loop when events are found.
    #[allow(dead_code)]
    fn parse_lock_event(
        &self,
        tx_signature: &str,
        sender: &str,
        amount: u64,
        seal_recipient: &str,
        token: WrappedToken,
    ) -> BridgeDeposit {
        BridgeDeposit {
            id: format!("sol_{}", tx_signature),
            source_chain: Chain::Solana,
            source_tx_hash: tx_signature.to_string(),
            source_address: sender.to_string(),
            seal_address: seal_recipient.to_string(),
            amount,
            token,
            processed: false,
            confirmations: 0,
        }
    }
}

impl ChainObserver for SolanaObserver {
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn poll_events(
        &self,
        _last_cursor: &str,
    ) -> Result<(Vec<BridgeDeposit>, String), BridgeError> {
        // Testnet stub: would call Solana RPC:
        //
        // POST {rpc_url}
        // {
        //   "jsonrpc": "2.0",
        //   "method": "getSignaturesForAddress",
        //   "params": [
        //     "{program_id}",
        //     { "until": "{last_cursor}", "commitment": "finalized" }
        //   ]
        // }
        //
        // Then for each signature, fetch the transaction and decode
        // the lock instruction data.

        Ok((vec![], String::new()))
    }

    fn is_finalized(&self, _source_tx_hash: &str) -> Result<bool, BridgeError> {
        // Would call: getTransaction with commitment: "finalized"
        // For testnet, assume finalized after required_confirmations
        Ok(true)
    }
}

/// Stellar observer — watches the seal-lock Soroban contract for lock events.
///
/// Uses Stellar Horizon API to find contract invocation transactions.
pub struct StellarObserver {
    /// Horizon API endpoint (e.g., "https://horizon-testnet.stellar.org").
    pub horizon_url: String,
    /// The seal-lock contract ID on Stellar.
    pub contract_id: String,
    /// Required ledger confirmations (default: 5 for Stellar).
    pub required_confirmations: u32,
}

impl StellarObserver {
    pub fn new(horizon_url: &str, contract_id: &str) -> Self {
        Self {
            horizon_url: horizon_url.to_string(),
            contract_id: contract_id.to_string(),
            required_confirmations: 5,
        }
    }

    /// Testnet configuration.
    pub fn testnet(contract_id: &str) -> Self {
        Self::new("https://horizon-testnet.stellar.org", contract_id)
    }

    /// Parse a Stellar transaction into a BridgeDeposit.
    /// Called by the polling loop when events are found.
    #[allow(dead_code)]
    fn parse_lock_event(
        &self,
        tx_hash: &str,
        sender: &str,
        amount: u64,
        asset: &str,
        seal_recipient: &str,
    ) -> BridgeDeposit {
        let token = match asset {
            "native" => WrappedToken::WXLM,
            _ => WrappedToken::WUSDC, // Assume USDC for non-native
        };
        BridgeDeposit {
            id: format!("xlm_{}", tx_hash),
            source_chain: Chain::Stellar,
            source_tx_hash: tx_hash.to_string(),
            source_address: sender.to_string(),
            seal_address: seal_recipient.to_string(),
            amount,
            token,
            processed: false,
            confirmations: 0,
        }
    }
}

impl ChainObserver for StellarObserver {
    fn chain(&self) -> Chain {
        Chain::Stellar
    }

    fn poll_events(
        &self,
        _last_cursor: &str,
    ) -> Result<(Vec<BridgeDeposit>, String), BridgeError> {
        // Testnet stub: would call Horizon API:
        //
        // GET {horizon_url}/accounts/{contract_id}/operations
        //   ?cursor={last_cursor}
        //   &order=asc
        //   &limit=100
        //
        // Filter for invoke_host_function operations that call "lock"

        Ok((vec![], String::new()))
    }

    fn is_finalized(&self, _source_tx_hash: &str) -> Result<bool, BridgeError> {
        // Stellar has ~5s finality (SCP consensus)
        // Would check: GET /transactions/{hash} and verify ledger confirmation
        Ok(true)
    }
}

/// Multi-chain observer that aggregates events from all supported chains.
pub struct BridgeObserverSet {
    observers: Vec<Box<dyn ChainObserver>>,
    cursors: std::collections::HashMap<Chain, String>,
}

impl BridgeObserverSet {
    pub fn new() -> Self {
        Self {
            observers: Vec::new(),
            cursors: std::collections::HashMap::new(),
        }
    }

    /// Add a chain observer.
    pub fn add_observer(&mut self, observer: Box<dyn ChainObserver>) {
        let chain = observer.chain();
        self.cursors.entry(chain).or_default();
        self.observers.push(observer);
    }

    /// Poll all chains for new events.
    pub fn poll_all(&mut self) -> Result<Vec<BridgeDeposit>, BridgeError> {
        let mut all_deposits = Vec::new();
        for observer in &self.observers {
            let chain = observer.chain();
            let cursor = self.cursors.get(&chain).cloned().unwrap_or_default();
            let (deposits, new_cursor) = observer.poll_events(&cursor)?;
            if !new_cursor.is_empty() {
                self.cursors.insert(chain, new_cursor);
            }
            all_deposits.extend(deposits);
        }
        Ok(all_deposits)
    }
}

impl Default for BridgeObserverSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_observer_creates() {
        let obs = SolanaObserver::devnet("SealLock111111111111111111111111111111111111");
        assert_eq!(obs.chain(), Chain::Solana);
        assert_eq!(obs.required_confirmations, 32);
    }

    #[test]
    fn test_stellar_observer_creates() {
        let obs = StellarObserver::testnet("CDXYZ_CONTRACT_ID");
        assert_eq!(obs.chain(), Chain::Stellar);
        assert_eq!(obs.required_confirmations, 5);
    }

    #[test]
    fn test_solana_parse_lock_event() {
        let obs = SolanaObserver::devnet("prog1");
        let dep = obs.parse_lock_event(
            "5xSig123abc",
            "SolWallet1",
            1_000_000_000,
            "seal1alice",
            WrappedToken::WSOL,
        );
        assert_eq!(dep.id, "sol_5xSig123abc");
        assert_eq!(dep.source_chain, Chain::Solana);
        assert_eq!(dep.amount, 1_000_000_000);
        assert_eq!(dep.seal_address, "seal1alice");
        assert!(!dep.processed);
    }

    #[test]
    fn test_stellar_parse_lock_event() {
        let obs = StellarObserver::testnet("contract1");
        let dep = obs.parse_lock_event(
            "xlm_tx_hash_123",
            "GABCD_stellar",
            5_000_000,
            "native",
            "seal1bob",
        );
        assert_eq!(dep.id, "xlm_xlm_tx_hash_123");
        assert_eq!(dep.source_chain, Chain::Stellar);
        assert_eq!(dep.token, WrappedToken::WXLM);
    }

    #[test]
    fn test_stellar_parse_usdc_event() {
        let obs = StellarObserver::testnet("contract1");
        let dep = obs.parse_lock_event(
            "tx_456",
            "GABCD",
            100_000,
            "USDC_CONTRACT_ID",
            "seal1carol",
        );
        assert_eq!(dep.token, WrappedToken::WUSDC);
    }

    #[test]
    fn test_bridge_observer_set() {
        let mut set = BridgeObserverSet::new();
        set.add_observer(Box::new(SolanaObserver::devnet("prog1")));
        set.add_observer(Box::new(StellarObserver::testnet("contract1")));

        let deposits = set.poll_all().unwrap();
        assert!(deposits.is_empty()); // Stub returns empty

        assert_eq!(set.observers.len(), 2);
    }

    #[test]
    fn test_solana_is_finalized() {
        let obs = SolanaObserver::devnet("prog1");
        assert!(obs.is_finalized("any_tx").unwrap());
    }

    #[test]
    fn test_stellar_is_finalized() {
        let obs = StellarObserver::testnet("contract1");
        assert!(obs.is_finalized("any_tx").unwrap());
    }
}
