//! Custom token management (SPL/Stellar-style).
//!
//! Allows creating, minting, and transferring custom tokens on the Seal network.
//! Each token has its own BalanceStore and metadata.

use crate::balance::BalanceStore;
use crate::TokenError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Token metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Unique token ID (e.g., "USDS", "GOLD").
    pub symbol: String,
    /// Human-readable name.
    pub name: String,
    /// Decimal places (e.g., 9 for SEAL, 6 for USDC-style).
    pub decimals: u8,
    /// Maximum supply (0 = unlimited).
    pub max_supply: u64,
    /// Total minted so far.
    pub total_supply: u64,
    /// Address that can mint new tokens.
    pub mint_authority: String,
    /// Address that can freeze accounts (empty = no freeze).
    pub freeze_authority: String,
    /// Creator address.
    pub creator: String,
    /// Whether the token is frozen globally.
    pub frozen: bool,
    /// Transfer fee in basis points (0-10000). 0 = no fee.
    pub transfer_fee_bps: u64,
    /// Address that receives transfer fees.
    pub fee_recipient: String,
}

/// Manages all custom tokens on the network.
#[derive(Default)]
pub struct TokenManager {
    /// Token metadata by symbol.
    tokens: HashMap<String, TokenInfo>,
    /// Balance stores per token.
    balances: HashMap<String, BalanceStore>,
    /// Frozen accounts per token: token_symbol → set of addresses.
    frozen_accounts: HashMap<String, std::collections::HashSet<String>>,
}

impl TokenManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new token. Returns the token info.
    pub fn create_token(
        &mut self,
        symbol: String,
        name: String,
        decimals: u8,
        max_supply: u64,
        creator: String,
    ) -> Result<TokenInfo, TokenError> {
        if self.tokens.contains_key(&symbol) {
            return Err(TokenError::Custom(format!("token '{}' already exists", symbol)));
        }
        let info = TokenInfo {
            symbol: symbol.clone(),
            name,
            decimals,
            max_supply,
            total_supply: 0,
            mint_authority: creator.clone(),
            freeze_authority: creator.clone(),
            creator: creator.clone(),
            frozen: false,
            transfer_fee_bps: 0,
            fee_recipient: creator,
        };
        self.tokens.insert(symbol.clone(), info.clone());
        self.balances.insert(symbol, BalanceStore::new());
        Ok(info)
    }

    /// Mint tokens to an address. Only mint authority can call this.
    pub fn mint(
        &mut self,
        symbol: &str,
        to: &str,
        amount: u64,
        caller: &str,
    ) -> Result<(), TokenError> {
        let info = self.tokens.get(symbol)
            .ok_or_else(|| TokenError::Custom(format!("token '{}' not found", symbol)))?;
        if info.mint_authority != caller {
            return Err(TokenError::Custom("not mint authority".into()));
        }
        if info.max_supply > 0 && info.total_supply.saturating_add(amount) > info.max_supply {
            return Err(TokenError::Custom("would exceed max supply".into()));
        }

        let store = self.balances.get_mut(symbol)
            .ok_or_else(|| TokenError::Custom("token store missing".into()))?;
        store.mint(to, amount)?;

        let info = self.tokens.get_mut(symbol).unwrap();
        info.total_supply = info.total_supply.saturating_add(amount);
        Ok(())
    }

    /// Transfer custom tokens between addresses.
    pub fn transfer(
        &mut self,
        symbol: &str,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Result<(), TokenError> {
        // Check frozen
        if let Some(frozen) = self.frozen_accounts.get(symbol) {
            if frozen.contains(from) {
                return Err(TokenError::Custom("sender account is frozen".into()));
            }
        }
        let info = self.tokens.get(symbol)
            .ok_or_else(|| TokenError::Custom(format!("token '{}' not found", symbol)))?;
        if info.frozen {
            return Err(TokenError::Custom("token is globally frozen".into()));
        }

        let fee_bps = info.transfer_fee_bps;
        let fee_recipient = info.fee_recipient.clone();

        let store = self.balances.get_mut(symbol)
            .ok_or_else(|| TokenError::Custom("token store missing".into()))?;

        if fee_bps > 0 && from != fee_recipient.as_str() {
            let fee = (amount as u128 * fee_bps as u128 / 10_000) as u64;
            let net = amount.saturating_sub(fee);
            store.transfer(from, to, net)?;
            if fee > 0 {
                store.transfer(from, &fee_recipient, fee)?;
            }
            Ok(())
        } else {
            store.transfer(from, to, amount)
        }
    }

    /// Set transfer fee for a token. Only creator can set.
    pub fn set_transfer_fee(
        &mut self,
        symbol: &str,
        fee_bps: u64,
        caller: &str,
    ) -> Result<(), TokenError> {
        let info = self.tokens.get_mut(symbol)
            .ok_or_else(|| TokenError::Custom("token not found".into()))?;
        if info.creator != caller {
            return Err(TokenError::Custom("only creator can set fees".into()));
        }
        if fee_bps > 10_000 {
            return Err(TokenError::Custom("fee cannot exceed 100%".into()));
        }
        info.transfer_fee_bps = fee_bps;
        Ok(())
    }

    /// Get balance of a specific token for an address.
    pub fn balance(&self, symbol: &str, address: &str) -> u64 {
        self.balances.get(symbol)
            .map(|s| s.available(address))
            .unwrap_or(0)
    }

    /// Get token info.
    pub fn get_token(&self, symbol: &str) -> Option<&TokenInfo> {
        self.tokens.get(symbol)
    }

    /// List all tokens.
    pub fn list_tokens(&self) -> Vec<&TokenInfo> {
        self.tokens.values().collect()
    }

    /// Burn tokens from an address.
    pub fn burn(
        &mut self,
        symbol: &str,
        from: &str,
        amount: u64,
    ) -> Result<(), TokenError> {
        let store = self.balances.get_mut(symbol)
            .ok_or_else(|| TokenError::Custom(format!("token '{}' not found", symbol)))?;
        store.burn(from, amount)?;
        if let Some(info) = self.tokens.get_mut(symbol) {
            info.total_supply = info.total_supply.saturating_sub(amount);
        }
        Ok(())
    }

    /// Freeze an account for a token.
    pub fn freeze_account(&mut self, symbol: &str, address: &str, caller: &str) -> Result<(), TokenError> {
        let info = self.tokens.get(symbol)
            .ok_or_else(|| TokenError::Custom("token not found".into()))?;
        if info.freeze_authority != caller {
            return Err(TokenError::Custom("not freeze authority".into()));
        }
        self.frozen_accounts
            .entry(symbol.to_string())
            .or_default()
            .insert(address.to_string());
        Ok(())
    }

    /// Unfreeze an account.
    pub fn unfreeze_account(&mut self, symbol: &str, address: &str, caller: &str) -> Result<(), TokenError> {
        let info = self.tokens.get(symbol)
            .ok_or_else(|| TokenError::Custom("token not found".into()))?;
        if info.freeze_authority != caller {
            return Err(TokenError::Custom("not freeze authority".into()));
        }
        if let Some(frozen) = self.frozen_accounts.get_mut(symbol) {
            frozen.remove(address);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_mint() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold Token".into(), 6, 1_000_000, "alice".into()).unwrap();
        mgr.mint("GOLD", "bob", 100, "alice").unwrap();
        assert_eq!(mgr.balance("GOLD", "bob"), 100);
    }

    #[test]
    fn test_transfer() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into()).unwrap();
        mgr.mint("GOLD", "alice", 1000, "alice").unwrap();
        mgr.transfer("GOLD", "alice", "bob", 300).unwrap();
        assert_eq!(mgr.balance("GOLD", "alice"), 700);
        assert_eq!(mgr.balance("GOLD", "bob"), 300);
    }

    #[test]
    fn test_mint_authority() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into()).unwrap();
        assert!(mgr.mint("GOLD", "bob", 100, "bob").is_err()); // bob is not mint authority
    }

    #[test]
    fn test_max_supply() {
        let mut mgr = TokenManager::new();
        mgr.create_token("LTD".into(), "Limited".into(), 0, 100, "alice".into()).unwrap();
        mgr.mint("LTD", "alice", 100, "alice").unwrap();
        assert!(mgr.mint("LTD", "alice", 1, "alice").is_err()); // exceeds max
    }

    #[test]
    fn test_burn() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into()).unwrap();
        mgr.mint("GOLD", "alice", 1000, "alice").unwrap();
        mgr.burn("GOLD", "alice", 300).unwrap();
        assert_eq!(mgr.balance("GOLD", "alice"), 700);
        assert_eq!(mgr.get_token("GOLD").unwrap().total_supply, 700);
    }

    #[test]
    fn test_freeze() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into()).unwrap();
        mgr.mint("GOLD", "alice", 1000, "alice").unwrap();
        mgr.freeze_account("GOLD", "alice", "alice").unwrap();
        assert!(mgr.transfer("GOLD", "alice", "bob", 100).is_err()); // frozen
        mgr.unfreeze_account("GOLD", "alice", "alice").unwrap();
        mgr.transfer("GOLD", "alice", "bob", 100).unwrap(); // works now
    }

    #[test]
    fn test_list_tokens() {
        let mut mgr = TokenManager::new();
        mgr.create_token("A".into(), "Alpha".into(), 0, 0, "x".into()).unwrap();
        mgr.create_token("B".into(), "Beta".into(), 0, 0, "x".into()).unwrap();
        assert_eq!(mgr.list_tokens().len(), 2);
    }

    #[test]
    fn test_duplicate_token_rejected() {
        let mut mgr = TokenManager::new();
        mgr.create_token("X".into(), "X".into(), 0, 0, "a".into()).unwrap();
        assert!(mgr.create_token("X".into(), "X".into(), 0, 0, "a".into()).is_err());
    }
}
