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
    /// Address that can mutate `transfer_fee_bps` (empty = renounced;
    /// fee is then immutable forever). Defaults to `creator` on
    /// `create_token`. Rotateable + renounceable on the same
    /// pattern as `mint_authority` and `freeze_authority`.
    #[serde(default)]
    pub fee_authority: String,
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
            return Err(TokenError::Custom(format!(
                "token '{}' already exists",
                symbol
            )));
        }
        let info = TokenInfo {
            symbol: symbol.clone(),
            name,
            decimals,
            max_supply,
            total_supply: 0,
            mint_authority: creator.clone(),
            freeze_authority: creator.clone(),
            fee_authority: creator.clone(),
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
        let info = self
            .tokens
            .get(symbol)
            .ok_or_else(|| TokenError::Custom(format!("token '{}' not found", symbol)))?;
        if info.mint_authority != caller {
            return Err(TokenError::Custom("not mint authority".into()));
        }
        if info.max_supply > 0 && info.total_supply.saturating_add(amount) > info.max_supply {
            return Err(TokenError::Custom("would exceed max supply".into()));
        }

        let store = self
            .balances
            .get_mut(symbol)
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
        let info = self
            .tokens
            .get(symbol)
            .ok_or_else(|| TokenError::Custom(format!("token '{}' not found", symbol)))?;
        if info.frozen {
            return Err(TokenError::Custom("token is globally frozen".into()));
        }

        let fee_bps = info.transfer_fee_bps;
        let fee_recipient = info.fee_recipient.clone();

        let store = self
            .balances
            .get_mut(symbol)
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

    /// Set transfer fee for a token. Caller must be the current
    /// `fee_authority` — defaults to creator on `create_token`,
    /// rotateable via `set_fee_authority`, renounceable via
    /// `renounce_fee_authority` (after which the fee is immutable).
    pub fn set_transfer_fee(
        &mut self,
        symbol: &str,
        fee_bps: u64,
        caller: &str,
    ) -> Result<(), TokenError> {
        let info = self
            .tokens
            .get_mut(symbol)
            .ok_or_else(|| TokenError::Custom("token not found".into()))?;
        if info.fee_authority != caller {
            return Err(TokenError::Custom("not fee authority".into()));
        }
        if fee_bps > 10_000 {
            return Err(TokenError::Custom("fee cannot exceed 100%".into()));
        }
        info.transfer_fee_bps = fee_bps;
        Ok(())
    }

    /// Update where transfer fees are routed. Caller must be the
    /// current `fee_authority` (same gate as `set_transfer_fee`).
    /// `new_recipient` must be a non-empty string — empty would
    /// silently route fees to the empty address, which is likely a
    /// bug. After `renounce_fee_authority` this rejects every
    /// caller, so the recipient becomes immutable along with the
    /// rate.
    pub fn set_fee_recipient(
        &mut self,
        symbol: &str,
        new_recipient: &str,
        caller: &str,
    ) -> Result<(), TokenError> {
        if new_recipient.is_empty() {
            return Err(TokenError::Custom("fee_recipient cannot be empty".into()));
        }
        let info = self
            .tokens
            .get_mut(symbol)
            .ok_or_else(|| TokenError::Custom("token not found".into()))?;
        if info.fee_authority != caller {
            return Err(TokenError::Custom("not fee authority".into()));
        }
        info.fee_recipient = new_recipient.to_string();
        Ok(())
    }

    /// Get balance of a specific token for an address.
    pub fn balance(&self, symbol: &str, address: &str) -> u64 {
        self.balances
            .get(symbol)
            .map(|s| s.available(address))
            .unwrap_or(0)
    }

    /// Whether `address` has an entry in `symbol`'s ledger (true even
    /// if current balance is zero, mirroring `BalanceStore::has_account`).
    /// Used by `seal-node`'s recipient-new-account policy to
    /// distinguish "account exists but spent" from "fresh address".
    /// Returns false if the token itself is unknown.
    pub fn has_token_account(&self, symbol: &str, address: &str) -> bool {
        self.balances
            .get(symbol)
            .map(|s| s.has_account(address))
            .unwrap_or(false)
    }

    /// Content-addressed Merkle root over all custom-token ledgers.
    ///
    /// Combines each per-token `BalanceStore::state_root_hash` with
    /// the token symbol, sorted by symbol for determinism. Two
    /// `TokenManager`s with the same `(symbol, account_set)` pairs
    /// produce the same root. Mirrors
    /// `BalanceStore::state_root_hash` for native SEAL.
    pub fn state_root_hash(&self) -> seal_crypto::hash::Hash256 {
        let mut hamt = crate::hamt::Hamt::new();
        let mut symbols: Vec<&String> = self.balances.keys().collect();
        symbols.sort();
        for symbol in symbols {
            let store = &self.balances[symbol];
            let value = store.state_root_hash().0.to_vec();
            hamt.insert(symbol.as_bytes().to_vec(), value);
        }
        hamt.root_hash()
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
    pub fn burn(&mut self, symbol: &str, from: &str, amount: u64) -> Result<(), TokenError> {
        let store = self
            .balances
            .get_mut(symbol)
            .ok_or_else(|| TokenError::Custom(format!("token '{}' not found", symbol)))?;
        store.burn(from, amount)?;
        if let Some(info) = self.tokens.get_mut(symbol) {
            info.total_supply = info.total_supply.saturating_sub(amount);
        }
        Ok(())
    }

    /// Freeze an account for a token.
    pub fn freeze_account(
        &mut self,
        symbol: &str,
        address: &str,
        caller: &str,
    ) -> Result<(), TokenError> {
        let info = self
            .tokens
            .get(symbol)
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
    pub fn unfreeze_account(
        &mut self,
        symbol: &str,
        address: &str,
        caller: &str,
    ) -> Result<(), TokenError> {
        let info = self
            .tokens
            .get(symbol)
            .ok_or_else(|| TokenError::Custom("token not found".into()))?;
        if info.freeze_authority != caller {
            return Err(TokenError::Custom("not freeze authority".into()));
        }
        if let Some(frozen) = self.frozen_accounts.get_mut(symbol) {
            frozen.remove(address);
        }
        Ok(())
    }

    /// Whether `address` is currently frozen for `symbol`. Returns
    /// false for unknown tokens — `seal_listTokens` is the
    /// authoritative existence check.
    pub fn is_frozen(&self, symbol: &str, address: &str) -> bool {
        self.frozen_accounts
            .get(symbol)
            .map(|set| set.contains(address))
            .unwrap_or(false)
    }

    /// Snapshot of every address currently frozen for `symbol`.
    /// Order is insertion-order-independent (HashSet); callers that
    /// need stable order should sort the result. Returns an empty
    /// Vec for unknown tokens or tokens with no frozen accounts.
    pub fn list_frozen(&self, symbol: &str) -> Vec<String> {
        self.frozen_accounts
            .get(symbol)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Total count of `(symbol, address)` frozen-account entries
    /// across every token. Used as a /metrics gauge so ops can
    /// alert on a sudden spike (e.g. mass-freeze automation gone
    /// wrong).
    pub fn total_frozen_accounts(&self) -> usize {
        self.frozen_accounts.values().map(|s| s.len()).sum()
    }

    /// Snapshot of every token symbol where `address` is currently
    /// frozen. Sorted lexicographically for diff-friendly polling.
    /// Empty Vec for addresses with no frozen entries — not an
    /// error. Backs `seal_listFrozenSymbolsForAddress`. Used by
    /// wallets answering "am I blocked from transferring anywhere?"
    pub fn frozen_symbols_for(&self, address: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .frozen_accounts
            .iter()
            .filter(|(_, set)| set.contains(address))
            .map(|(symbol, _)| symbol.clone())
            .collect();
        out.sort();
        out
    }

    /// Snapshot of every token whose `creator` field matches
    /// `address`. Sorted lexicographically by symbol for diff-stable
    /// polling. Empty Vec for addresses that have never created a
    /// token — not an error. Backs `seal_listTokensByCreator`.
    /// Per-owner enumeration paralleling `frozen_symbols_for` and
    /// the recent governance / DEX / bridge per-owner views: a
    /// caller asking "which tokens did I create?" used to have to
    /// scan the full `seal_listTokens` set client-side. Note this
    /// is *immutable creator*, not current authority — after a
    /// `set_mint_authority` rotation the creator stays the same
    /// while the authority moves. The authority-current
    /// counterpart is `tokens_by_mint_authority`.
    pub fn tokens_by_creator(&self, address: &str) -> Vec<&TokenInfo> {
        let mut out: Vec<&TokenInfo> = self
            .tokens
            .values()
            .filter(|t| t.creator == address)
            .collect();
        out.sort_by(|a, b| a.symbol.cmp(&b.symbol));
        out
    }

    /// Tokens whose **current** `mint_authority` matches `address`.
    /// Authority-current counterpart to `tokens_by_creator` (which
    /// is immutable). After a `set_mint_authority` rotation the
    /// outgoing authority disappears from this view and the
    /// incoming one starts appearing; after `renounce_mint_authority`
    /// the symbol stops appearing for any address. Useful for
    /// answering "which tokens can I mint right now?" — a question
    /// the creator-view can't answer once authorities have rotated.
    /// Sorted lexicographically by symbol.
    pub fn tokens_by_mint_authority(&self, address: &str) -> Vec<&TokenInfo> {
        let mut out: Vec<&TokenInfo> = self
            .tokens
            .values()
            .filter(|t| t.mint_authority == address)
            .collect();
        out.sort_by(|a, b| a.symbol.cmp(&b.symbol));
        out
    }

    /// Tokens whose **current** `freeze_authority` matches `address`.
    /// Mirror of `tokens_by_mint_authority` for the freeze-authority
    /// surface — answers "which tokens can I freeze right now?".
    /// `freeze_authority` rotates via `set_freeze_authority` and is
    /// irrevocably cleared by `renounce_freeze_authority`. Sorted
    /// lexicographically by symbol.
    pub fn tokens_by_freeze_authority(&self, address: &str) -> Vec<&TokenInfo> {
        let mut out: Vec<&TokenInfo> = self
            .tokens
            .values()
            .filter(|t| t.freeze_authority == address)
            .collect();
        out.sort_by(|a, b| a.symbol.cmp(&b.symbol));
        out
    }

    /// Tokens whose **current** `fee_authority` matches `address`.
    /// Third leg of the authority-current trio
    /// (mint / freeze / fee) — answers "which tokens' transfer-fee
    /// schedule can I edit right now?". `fee_authority` rotates via
    /// `set_fee_authority` and is irrevocably cleared by
    /// `renounce_fee_authority` (after which `transfer_fee_bps` is
    /// immutable). Sorted lexicographically by symbol.
    pub fn tokens_by_fee_authority(&self, address: &str) -> Vec<&TokenInfo> {
        let mut out: Vec<&TokenInfo> = self
            .tokens
            .values()
            .filter(|t| t.fee_authority == address)
            .collect();
        out.sort_by(|a, b| a.symbol.cmp(&b.symbol));
        out
    }

    /// Number of tokens currently in the global-frozen state
    /// (`info.frozen == true`). Companion gauge to
    /// `total_frozen_accounts` — the kill-switch counter to the
    /// per-account counter. A non-zero value means at least one
    /// freeze authority has flipped the global switch on its
    /// token.
    pub fn total_frozen_tokens(&self) -> usize {
        self.tokens.values().filter(|t| t.frozen).count()
    }

    /// Set the token-level global freeze flag. When true, every
    /// `transfer(...)` rejects with "token is globally frozen"
    /// regardless of per-account state. Caller must be the current
    /// `freeze_authority`. Idempotent — setting to the current
    /// value is a no-op.
    pub fn set_token_frozen(
        &mut self,
        symbol: &str,
        frozen: bool,
        caller: &str,
    ) -> Result<(), TokenError> {
        let info = self
            .tokens
            .get_mut(symbol)
            .ok_or_else(|| TokenError::Custom(format!("token '{}' not found", symbol)))?;
        if info.freeze_authority != caller {
            return Err(TokenError::Custom("not freeze authority".into()));
        }
        info.frozen = frozen;
        Ok(())
    }

    /// Rotate the mint authority. Caller must be the current
    /// `mint_authority`. After this call the new address is the
    /// only one that can `mint(...)`.
    ///
    /// Renounce (set to a non-controllable address) is currently
    /// the operator's responsibility — pass an unfundable address
    /// or follow up with a separate `seal_renounceMintAuthority`
    /// path. Empty-string sentinel is intentionally not supported
    /// here so the RPC's `SealAddress::from_string_encoding` guard
    /// stays meaningful.
    pub fn set_mint_authority(
        &mut self,
        symbol: &str,
        new_authority: &str,
        caller: &str,
    ) -> Result<(), TokenError> {
        let info = self
            .tokens
            .get_mut(symbol)
            .ok_or_else(|| TokenError::Custom(format!("token '{}' not found", symbol)))?;
        if info.mint_authority != caller {
            return Err(TokenError::Custom("not mint authority".into()));
        }
        info.mint_authority = new_authority.to_string();
        Ok(())
    }

    /// Rotate the freeze authority. Caller must be the current
    /// `freeze_authority`. Same caveats as `set_mint_authority`.
    pub fn set_freeze_authority(
        &mut self,
        symbol: &str,
        new_authority: &str,
        caller: &str,
    ) -> Result<(), TokenError> {
        let info = self
            .tokens
            .get_mut(symbol)
            .ok_or_else(|| TokenError::Custom(format!("token '{}' not found", symbol)))?;
        if info.freeze_authority != caller {
            return Err(TokenError::Custom("not freeze authority".into()));
        }
        info.freeze_authority = new_authority.to_string();
        Ok(())
    }

    /// Irrevocably renounce the mint authority. Sets the field to
    /// the empty string `""` — which no real Seal address can match
    /// (every bech32m-encoded address starts with `seal1`/`sealt1`)
    /// and which the RPC's `caller_addr` fallback resolves to
    /// `"anonymous"` rather than `""`, so subsequent mint attempts
    /// always reject. There's no inverse operation: renounce is
    /// terminal.
    pub fn renounce_mint_authority(
        &mut self,
        symbol: &str,
        caller: &str,
    ) -> Result<(), TokenError> {
        self.set_mint_authority(symbol, "", caller)
    }

    /// Irrevocably renounce the freeze authority. Same semantics
    /// as `renounce_mint_authority`.
    pub fn renounce_freeze_authority(
        &mut self,
        symbol: &str,
        caller: &str,
    ) -> Result<(), TokenError> {
        self.set_freeze_authority(symbol, "", caller)
    }

    /// Rotate the fee authority. Caller must be the current
    /// `fee_authority`. After this call the new address is the
    /// only one that can `set_transfer_fee(...)`. Same caveats as
    /// `set_mint_authority`: empty-string sentinel is reserved for
    /// renounce.
    pub fn set_fee_authority(
        &mut self,
        symbol: &str,
        new_authority: &str,
        caller: &str,
    ) -> Result<(), TokenError> {
        let info = self
            .tokens
            .get_mut(symbol)
            .ok_or_else(|| TokenError::Custom(format!("token '{}' not found", symbol)))?;
        if info.fee_authority != caller {
            return Err(TokenError::Custom("not fee authority".into()));
        }
        info.fee_authority = new_authority.to_string();
        Ok(())
    }

    /// Irrevocably renounce the fee authority. After this call
    /// `set_transfer_fee` rejects every caller — the fee is
    /// permanently locked at its current value. Same `""`-sentinel
    /// semantics as `renounce_mint_authority`.
    pub fn renounce_fee_authority(&mut self, symbol: &str, caller: &str) -> Result<(), TokenError> {
        self.set_fee_authority(symbol, "", caller)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_mint() {
        let mut mgr = TokenManager::new();
        mgr.create_token(
            "GOLD".into(),
            "Gold Token".into(),
            6,
            1_000_000,
            "alice".into(),
        )
        .unwrap();
        mgr.mint("GOLD", "bob", 100, "alice").unwrap();
        assert_eq!(mgr.balance("GOLD", "bob"), 100);
    }

    #[test]
    fn test_transfer() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.mint("GOLD", "alice", 1000, "alice").unwrap();
        mgr.transfer("GOLD", "alice", "bob", 300).unwrap();
        assert_eq!(mgr.balance("GOLD", "alice"), 700);
        assert_eq!(mgr.balance("GOLD", "bob"), 300);
    }

    #[test]
    fn test_mint_authority() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        assert!(mgr.mint("GOLD", "bob", 100, "bob").is_err()); // bob is not mint authority
    }

    #[test]
    fn test_max_supply() {
        let mut mgr = TokenManager::new();
        mgr.create_token("LTD".into(), "Limited".into(), 0, 100, "alice".into())
            .unwrap();
        mgr.mint("LTD", "alice", 100, "alice").unwrap();
        assert!(mgr.mint("LTD", "alice", 1, "alice").is_err()); // exceeds max
    }

    #[test]
    fn test_burn() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.mint("GOLD", "alice", 1000, "alice").unwrap();
        mgr.burn("GOLD", "alice", 300).unwrap();
        assert_eq!(mgr.balance("GOLD", "alice"), 700);
        assert_eq!(mgr.get_token("GOLD").unwrap().total_supply, 700);
    }

    #[test]
    fn test_freeze() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.mint("GOLD", "alice", 1000, "alice").unwrap();
        mgr.freeze_account("GOLD", "alice", "alice").unwrap();
        assert!(mgr.transfer("GOLD", "alice", "bob", 100).is_err()); // frozen
        mgr.unfreeze_account("GOLD", "alice", "alice").unwrap();
        mgr.transfer("GOLD", "alice", "bob", 100).unwrap(); // works now
    }

    #[test]
    fn test_list_frozen() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        // No frozen → empty.
        assert!(mgr.list_frozen("GOLD").is_empty());
        // Unknown token → empty (no panic).
        assert!(mgr.list_frozen("MISSING").is_empty());
        // Two accounts frozen.
        mgr.freeze_account("GOLD", "bob", "alice").unwrap();
        mgr.freeze_account("GOLD", "carol", "alice").unwrap();
        let mut frozen = mgr.list_frozen("GOLD");
        frozen.sort();
        assert_eq!(frozen, vec!["bob".to_string(), "carol".to_string()]);
        // Unfreeze drops from the list.
        mgr.unfreeze_account("GOLD", "bob", "alice").unwrap();
        let frozen = mgr.list_frozen("GOLD");
        assert_eq!(frozen, vec!["carol".to_string()]);
    }

    #[test]
    fn test_set_token_frozen() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.mint("GOLD", "alice", 100, "alice").unwrap();
        // Default: not frozen, transfer works.
        mgr.transfer("GOLD", "alice", "bob", 10).unwrap();
        // Bob can't freeze.
        assert!(mgr.set_token_frozen("GOLD", true, "bob").is_err());
        // Alice freezes globally.
        mgr.set_token_frozen("GOLD", true, "alice").unwrap();
        // Transfer now rejects with the global-freeze error,
        // independent of per-account state.
        assert!(mgr.transfer("GOLD", "alice", "bob", 1).is_err());
        // Unfreeze and transfer works again.
        mgr.set_token_frozen("GOLD", false, "alice").unwrap();
        mgr.transfer("GOLD", "alice", "bob", 1).unwrap();
        // Idempotent: re-setting to current value is Ok.
        mgr.set_token_frozen("GOLD", false, "alice").unwrap();
    }

    #[test]
    fn test_total_frozen_accounts() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.create_token("SILVER".into(), "Silver".into(), 6, 0, "alice".into())
            .unwrap();
        // No freezes → 0.
        assert_eq!(mgr.total_frozen_accounts(), 0);
        // Two on GOLD, one on SILVER → 3 total.
        mgr.freeze_account("GOLD", "bob", "alice").unwrap();
        mgr.freeze_account("GOLD", "carol", "alice").unwrap();
        mgr.freeze_account("SILVER", "bob", "alice").unwrap();
        assert_eq!(mgr.total_frozen_accounts(), 3);
        // Unfreeze drops it.
        mgr.unfreeze_account("GOLD", "bob", "alice").unwrap();
        assert_eq!(mgr.total_frozen_accounts(), 2);
    }

    #[test]
    fn test_total_frozen_tokens() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.create_token("SILVER".into(), "Silver".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.create_token("COPPER".into(), "Copper".into(), 6, 0, "alice".into())
            .unwrap();
        // No global freezes → 0.
        assert_eq!(mgr.total_frozen_tokens(), 0);
        // Freeze GOLD globally.
        mgr.set_token_frozen("GOLD", true, "alice").unwrap();
        assert_eq!(mgr.total_frozen_tokens(), 1);
        // Freeze SILVER too.
        mgr.set_token_frozen("SILVER", true, "alice").unwrap();
        assert_eq!(mgr.total_frozen_tokens(), 2);
        // Unfreeze GOLD.
        mgr.set_token_frozen("GOLD", false, "alice").unwrap();
        assert_eq!(mgr.total_frozen_tokens(), 1);
        // Per-account freezes don't move the global counter.
        mgr.freeze_account("COPPER", "bob", "alice").unwrap();
        assert_eq!(mgr.total_frozen_tokens(), 1);
    }

    #[test]
    fn test_is_frozen_accessor() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        // Default: not frozen.
        assert!(!mgr.is_frozen("GOLD", "alice"));
        // Unknown token: not frozen (no panic, no error).
        assert!(!mgr.is_frozen("MISSING", "alice"));
        // Freeze; observe; unfreeze; observe.
        mgr.freeze_account("GOLD", "alice", "alice").unwrap();
        assert!(mgr.is_frozen("GOLD", "alice"));
        assert!(!mgr.is_frozen("GOLD", "bob"));
        mgr.unfreeze_account("GOLD", "alice", "alice").unwrap();
        assert!(!mgr.is_frozen("GOLD", "alice"));
    }

    #[test]
    fn test_frozen_symbols_for() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.create_token("SILVER".into(), "Silver".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.create_token("BRONZE".into(), "Bronze".into(), 6, 0, "alice".into())
            .unwrap();
        // No freezes → empty Vec.
        assert!(mgr.frozen_symbols_for("bob").is_empty());
        // Freeze bob on GOLD and BRONZE; carol on SILVER.
        mgr.freeze_account("GOLD", "bob", "alice").unwrap();
        mgr.freeze_account("BRONZE", "bob", "alice").unwrap();
        mgr.freeze_account("SILVER", "carol", "alice").unwrap();
        // Bob: ["BRONZE", "GOLD"] — sorted lexicographically.
        let bob = mgr.frozen_symbols_for("bob");
        assert_eq!(bob, vec!["BRONZE".to_string(), "GOLD".to_string()]);
        // Carol: ["SILVER"] only.
        assert_eq!(mgr.frozen_symbols_for("carol"), vec!["SILVER".to_string()]);
        // Unknown address: empty Vec.
        assert!(mgr.frozen_symbols_for("nobody").is_empty());
        // Unfreeze bob on GOLD; he should drop to just BRONZE.
        mgr.unfreeze_account("GOLD", "bob", "alice").unwrap();
        assert_eq!(mgr.frozen_symbols_for("bob"), vec!["BRONZE".to_string()]);
    }

    #[test]
    fn test_tokens_by_creator() {
        let mut mgr = TokenManager::new();
        // Alice creates GOLD and BRONZE; bob creates SILVER.
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.create_token("BRONZE".into(), "Bronze".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.create_token("SILVER".into(), "Silver".into(), 6, 0, "bob".into())
            .unwrap();
        // Alice's view: ["BRONZE", "GOLD"], sorted.
        let alice: Vec<&str> = mgr
            .tokens_by_creator("alice")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(alice, vec!["BRONZE", "GOLD"]);
        // Bob's view: just SILVER.
        let bob: Vec<&str> = mgr
            .tokens_by_creator("bob")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(bob, vec!["SILVER"]);
        // Unknown address: empty Vec, not error.
        assert!(mgr.tokens_by_creator("nobody").is_empty());
        // Rotating mint authority does NOT change creator-of-record.
        mgr.set_mint_authority("GOLD", "carol", "alice").unwrap();
        let alice_after: Vec<&str> = mgr
            .tokens_by_creator("alice")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(alice_after, vec!["BRONZE", "GOLD"]);
        // Carol is the new mint authority but didn't create anything.
        assert!(mgr.tokens_by_creator("carol").is_empty());
    }

    #[test]
    fn test_tokens_by_mint_authority() {
        let mut mgr = TokenManager::new();
        // Alice creates GOLD and BRONZE; bob creates SILVER. By
        // default `create_token` seeds `mint_authority = creator`,
        // so alice → [BRONZE, GOLD] / bob → [SILVER] before any
        // rotations. This is the case where the creator-view and
        // the authority-current view agree.
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.create_token("BRONZE".into(), "Bronze".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.create_token("SILVER".into(), "Silver".into(), 6, 0, "bob".into())
            .unwrap();
        let alice: Vec<&str> = mgr
            .tokens_by_mint_authority("alice")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(alice, vec!["BRONZE", "GOLD"]);
        let bob: Vec<&str> = mgr
            .tokens_by_mint_authority("bob")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(bob, vec!["SILVER"]);
        assert!(mgr.tokens_by_mint_authority("nobody").is_empty());

        // Now rotate GOLD's mint authority alice → carol. This is
        // the case the creator-view can't answer: alice no longer
        // controls GOLD but is still its creator-of-record.
        mgr.set_mint_authority("GOLD", "carol", "alice").unwrap();
        let alice_after: Vec<&str> = mgr
            .tokens_by_mint_authority("alice")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        // GOLD has moved to carol — alice retains only BRONZE.
        assert_eq!(alice_after, vec!["BRONZE"]);
        let carol: Vec<&str> = mgr
            .tokens_by_mint_authority("carol")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(carol, vec!["GOLD"]);
        // Creator-of-record for alice is unchanged — both BRONZE
        // and GOLD are still hers by `tokens_by_creator`. Tests in
        // `test_tokens_by_creator` already pin this; we recheck
        // here so the divergence between the two views is visible
        // in a single test for future readers.
        let creator_alice: Vec<&str> = mgr
            .tokens_by_creator("alice")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(creator_alice, vec!["BRONZE", "GOLD"]);

        // Renouncing mint authority should remove GOLD from
        // *every* per-authority view: there is no longer any
        // address that can mint it. Carol is the current authority,
        // so she's the one who renounces.
        mgr.renounce_mint_authority("GOLD", "carol").unwrap();
        assert!(mgr
            .tokens_by_mint_authority("carol")
            .iter()
            .all(|t| t.symbol != "GOLD"));
    }

    #[test]
    fn test_tokens_by_freeze_authority() {
        let mut mgr = TokenManager::new();
        // Both authorities default to creator. Two tokens by alice,
        // one by bob; verify the by-freeze-authority view tracks
        // independently of the by-mint-authority view after a
        // selective rotation.
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.create_token("BRONZE".into(), "Bronze".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.create_token("SILVER".into(), "Silver".into(), 6, 0, "bob".into())
            .unwrap();

        // Pre-rotation: both views agree with creator.
        let alice: Vec<&str> = mgr
            .tokens_by_freeze_authority("alice")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(alice, vec!["BRONZE", "GOLD"]);

        // Rotate GOLD's freeze authority alice → dave (dedicated
        // compliance signer) without touching the mint authority.
        // The two per-authority views must move independently —
        // alice loses GOLD from the freeze view but keeps it in
        // the mint view.
        mgr.set_freeze_authority("GOLD", "dave", "alice").unwrap();
        let alice_freeze: Vec<&str> = mgr
            .tokens_by_freeze_authority("alice")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(alice_freeze, vec!["BRONZE"]);
        let dave_freeze: Vec<&str> = mgr
            .tokens_by_freeze_authority("dave")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(dave_freeze, vec!["GOLD"]);
        // Mint authority is unmoved — alice still mints GOLD.
        let alice_mint: Vec<&str> = mgr
            .tokens_by_mint_authority("alice")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(alice_mint, vec!["BRONZE", "GOLD"]);
    }

    #[test]
    fn test_tokens_by_fee_authority() {
        let mut mgr = TokenManager::new();
        // Authorities default to creator. Two tokens by alice, one
        // by bob; verify the by-fee-authority view tracks
        // independently of the mint and freeze views after a
        // selective fee-authority rotation.
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.create_token("BRONZE".into(), "Bronze".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.create_token("SILVER".into(), "Silver".into(), 6, 0, "bob".into())
            .unwrap();

        // Pre-rotation: all three views agree with creator.
        let alice: Vec<&str> = mgr
            .tokens_by_fee_authority("alice")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(alice, vec!["BRONZE", "GOLD"]);
        assert!(mgr.tokens_by_fee_authority("nobody").is_empty());

        // Rotate GOLD's fee authority alice → eve (a treasury
        // signer that owns the fee-schedule rotation key only).
        // Mint and freeze authorities stay on alice.
        mgr.set_fee_authority("GOLD", "eve", "alice").unwrap();
        let alice_fee: Vec<&str> = mgr
            .tokens_by_fee_authority("alice")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(alice_fee, vec!["BRONZE"]);
        let eve_fee: Vec<&str> = mgr
            .tokens_by_fee_authority("eve")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(eve_fee, vec!["GOLD"]);
        // Mint and freeze are unmoved — alice still owns both on GOLD.
        let alice_mint: Vec<&str> = mgr
            .tokens_by_mint_authority("alice")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(alice_mint, vec!["BRONZE", "GOLD"]);
        let alice_freeze: Vec<&str> = mgr
            .tokens_by_freeze_authority("alice")
            .iter()
            .map(|t| t.symbol.as_str())
            .collect();
        assert_eq!(alice_freeze, vec!["BRONZE", "GOLD"]);

        // Renounce GOLD's fee authority — disappears from every view.
        mgr.renounce_fee_authority("GOLD", "eve").unwrap();
        assert!(mgr
            .tokens_by_fee_authority("eve")
            .iter()
            .all(|t| t.symbol != "GOLD"));
        assert!(mgr
            .tokens_by_fee_authority("alice")
            .iter()
            .all(|t| t.symbol != "GOLD"));
    }

    #[test]
    fn test_set_mint_authority_rotates() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.mint("GOLD", "alice", 100, "alice").unwrap();
        // Bob can't rotate.
        assert!(mgr.set_mint_authority("GOLD", "bob", "bob").is_err());
        // Alice rotates to bob.
        mgr.set_mint_authority("GOLD", "bob", "alice").unwrap();
        // Alice can no longer mint.
        assert!(mgr.mint("GOLD", "alice", 1, "alice").is_err());
        // Bob can.
        mgr.mint("GOLD", "bob", 1, "bob").unwrap();
    }

    #[test]
    fn test_set_freeze_authority_rotates() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        // Bob can't rotate.
        assert!(mgr.set_freeze_authority("GOLD", "bob", "bob").is_err());
        // Alice rotates to bob.
        mgr.set_freeze_authority("GOLD", "bob", "alice").unwrap();
        // Alice can no longer freeze.
        assert!(mgr.freeze_account("GOLD", "carol", "alice").is_err());
        // Bob can.
        mgr.freeze_account("GOLD", "carol", "bob").unwrap();
        assert!(mgr.is_frozen("GOLD", "carol"));
    }

    #[test]
    fn test_renounce_mint_authority_is_terminal() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        mgr.mint("GOLD", "alice", 100, "alice").unwrap();
        // Bob can't renounce on alice's behalf.
        assert!(mgr.renounce_mint_authority("GOLD", "bob").is_err());
        // Alice renounces.
        mgr.renounce_mint_authority("GOLD", "alice").unwrap();
        // Now no one can mint — alice, bob, anonymous, even a
        // future caller named "" (which the RPC layer never sets
        // — the fallback there is "anonymous").
        assert!(mgr.mint("GOLD", "alice", 1, "alice").is_err());
        assert!(mgr.mint("GOLD", "bob", 1, "bob").is_err());
        assert!(mgr.mint("GOLD", "anonymous", 1, "anonymous").is_err());
        // Alice can't even rotate the authority back — the auth
        // gate compares the renounced "" to alice and rejects.
        assert!(mgr.set_mint_authority("GOLD", "alice", "alice").is_err());
    }

    #[test]
    fn test_renounce_freeze_authority_is_terminal() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        // Bob can't renounce.
        assert!(mgr.renounce_freeze_authority("GOLD", "bob").is_err());
        // Alice renounces.
        mgr.renounce_freeze_authority("GOLD", "alice").unwrap();
        // No one can freeze going forward.
        assert!(mgr.freeze_account("GOLD", "carol", "alice").is_err());
        assert!(mgr.freeze_account("GOLD", "carol", "bob").is_err());
        // The whole "set new authority" path is also closed because
        // the auth gate fails for every real caller.
        assert!(mgr.set_freeze_authority("GOLD", "alice", "alice").is_err());
    }

    #[test]
    fn test_set_authority_unknown_token() {
        let mut mgr = TokenManager::new();
        // No token created — authority rotation can't even check
        // the auth gate (no info to read), so it errors with
        // "not found" rather than "not authority".
        assert!(mgr.set_mint_authority("MISSING", "bob", "alice").is_err());
        assert!(mgr.set_freeze_authority("MISSING", "bob", "alice").is_err());
        assert!(mgr.set_fee_authority("MISSING", "bob", "alice").is_err());
    }

    #[test]
    fn test_set_fee_authority_rotates() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        // Default: alice is fee_authority (== creator) and can set fee.
        mgr.set_transfer_fee("GOLD", 50, "alice").unwrap();
        // Bob can't rotate or set fee.
        assert!(mgr.set_fee_authority("GOLD", "bob", "bob").is_err());
        assert!(mgr.set_transfer_fee("GOLD", 100, "bob").is_err());
        // Alice rotates to bob.
        mgr.set_fee_authority("GOLD", "bob", "alice").unwrap();
        // Alice can no longer set fees.
        assert!(mgr.set_transfer_fee("GOLD", 100, "alice").is_err());
        // Bob can.
        mgr.set_transfer_fee("GOLD", 100, "bob").unwrap();
        assert_eq!(mgr.get_token("GOLD").unwrap().transfer_fee_bps, 100);
    }

    #[test]
    fn test_set_fee_recipient() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        // Default: fee_recipient == creator (alice).
        assert_eq!(mgr.get_token("GOLD").unwrap().fee_recipient, "alice");
        // Bob isn't the fee authority — rejected.
        assert!(mgr.set_fee_recipient("GOLD", "treasury", "bob").is_err());
        // Empty recipient rejected (likely a bug, not intent).
        assert!(mgr.set_fee_recipient("GOLD", "", "alice").is_err());
        // Alice routes fees to the treasury.
        mgr.set_fee_recipient("GOLD", "treasury", "alice").unwrap();
        assert_eq!(mgr.get_token("GOLD").unwrap().fee_recipient, "treasury");
        // Verify fees actually route to the new recipient.
        mgr.set_transfer_fee("GOLD", 100, "alice").unwrap(); // 1%
        mgr.mint("GOLD", "alice", 1_000, "alice").unwrap();
        // alice transfers 100 to bob — 1 unit (1%) goes to treasury.
        mgr.transfer("GOLD", "alice", "bob", 100).unwrap();
        assert_eq!(mgr.balance("GOLD", "treasury"), 1);
        // After renounce, recipient is also locked.
        mgr.renounce_fee_authority("GOLD", "alice").unwrap();
        assert!(mgr.set_fee_recipient("GOLD", "evil", "alice").is_err());
        // Existing recipient preserved.
        assert_eq!(mgr.get_token("GOLD").unwrap().fee_recipient, "treasury");
    }

    #[test]
    fn test_renounce_fee_authority_is_terminal() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        // Set a non-zero fee before renouncing — that's the value
        // the token is now permanently locked at.
        mgr.set_transfer_fee("GOLD", 250, "alice").unwrap();
        // Bob can't renounce on alice's behalf.
        assert!(mgr.renounce_fee_authority("GOLD", "bob").is_err());
        // Alice renounces.
        mgr.renounce_fee_authority("GOLD", "alice").unwrap();
        // Now no one can change the fee — alice, bob, anonymous.
        assert!(mgr.set_transfer_fee("GOLD", 0, "alice").is_err());
        assert!(mgr.set_transfer_fee("GOLD", 500, "bob").is_err());
        assert!(mgr.set_transfer_fee("GOLD", 100, "anonymous").is_err());
        // Alice can't rotate the authority back — same "" gate
        // failure as renounce_mint/freeze.
        assert!(mgr.set_fee_authority("GOLD", "alice", "alice").is_err());
        // Fee value is preserved at 250 bps — renounce locks the
        // current value, not the post-renounce input.
        assert_eq!(mgr.get_token("GOLD").unwrap().transfer_fee_bps, 250);
        assert_eq!(mgr.get_token("GOLD").unwrap().fee_authority, "");
    }

    #[test]
    fn test_freeze_authority_gate() {
        let mut mgr = TokenManager::new();
        mgr.create_token("GOLD".into(), "Gold".into(), 6, 0, "alice".into())
            .unwrap();
        // Bob is not the freeze authority — both ops reject.
        assert!(mgr.freeze_account("GOLD", "bob", "bob").is_err());
        // No freeze actually happened.
        assert!(!mgr.is_frozen("GOLD", "bob"));
        // Unfreeze authority check applies even when target wasn't
        // frozen — auth fail beats no-op.
        assert!(mgr.unfreeze_account("GOLD", "bob", "bob").is_err());
    }

    #[test]
    fn test_list_tokens() {
        let mut mgr = TokenManager::new();
        mgr.create_token("A".into(), "Alpha".into(), 0, 0, "x".into())
            .unwrap();
        mgr.create_token("B".into(), "Beta".into(), 0, 0, "x".into())
            .unwrap();
        assert_eq!(mgr.list_tokens().len(), 2);
    }

    #[test]
    fn test_duplicate_token_rejected() {
        let mut mgr = TokenManager::new();
        mgr.create_token("X".into(), "X".into(), 0, 0, "a".into())
            .unwrap();
        assert!(mgr
            .create_token("X".into(), "X".into(), 0, 0, "a".into())
            .is_err());
    }
}
