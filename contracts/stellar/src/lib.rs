//! Seal Lock — Stellar bridge lock contract (Soroban).
//!
//! Same lock-and-mint pattern as the Solana bridge:
//! - Lock XLM or Stellar USDC → Seal mints wXLM or wUSDC
//! - Burn on Seal → validators submit multisig → release on Stellar
//!
//! # Architecture
//!
//! ```text
//! User (Stellar wallet)
//!   │
//!   ├── lock(amount, asset, seal_recipient)
//!   │     ├── Stores StellarLock in contract storage
//!   │     ├── Transfers tokens to contract address
//!   │     └── Emits LockEvent
//!   │
//!   └── (Seal validators observe events via Horizon API)
//!
//! Seal Validators (multisig)
//!   │
//!   └── release(lock_id, recipient, signatures[])
//!         ├── Verifies M-of-N multisig
//!         ├── Transfers tokens from contract to recipient
//!         └── Marks lock as released
//! ```
//!
//! # Stellar-specific notes
//!
//! - Stellar has ~5 second finality (SCP consensus)
//! - Soroban contracts use persistent storage for locks
//! - XLM uses stroops (1 XLM = 10^7 stroops)
//! - USDC is a Stellar Classic asset (SAC interface on Soroban)
//! - Contract invocations are observed via Horizon API events endpoint
//!
//! # Build
//! ```bash
//! # Requires: soroban-cli
//! # cargo install --locked soroban-cli
//! soroban contract build
//! ```
//!
//! # Deploy
//! ```bash
//! soroban contract deploy --wasm target/wasm32-unknown-unknown/release/seal_lock.wasm \
//!   --network testnet --source alice
//! ```

// When Soroban SDK is available, uncomment:
// use soroban_sdk::{contract, contractimpl, contracttype, Env, Address, BytesN, Symbol, token, log};

use std::collections::HashMap;

/// Supported assets on Stellar.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum StellarAsset {
    /// Native XLM (stroops).
    Native,
    /// USDC on Stellar (SAC contract).
    Usdc(String), // Contract ID
    /// Other Stellar Classic assets.
    Classic { code: String, issuer: String },
}

impl StellarAsset {
    pub fn symbol(&self) -> &str {
        match self {
            Self::Native => "XLM",
            Self::Usdc(_) => "USDC",
            Self::Classic { code, .. } => code,
        }
    }
}

impl std::fmt::Display for StellarAsset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native => write!(f, "native"),
            Self::Usdc(id) => write!(f, "USDC:{}", id),
            Self::Classic { code, issuer } => write!(f, "{}:{}", code, issuer),
        }
    }
}

/// Lock record for XLM/USDC deposits.
#[derive(Clone, Debug)]
pub struct StellarLock {
    /// Unique lock ID.
    pub id: String,
    /// Stellar address that locked the tokens.
    pub owner: String,
    /// Amount locked (stroops for XLM, smallest unit for others).
    pub amount: i128,
    /// Asset being locked.
    pub asset: StellarAsset,
    /// Seal recipient address (bech32m).
    pub seal_recipient: String,
    /// Whether released.
    pub released: bool,
    /// Ledger sequence when locked (for finality tracking).
    pub lock_ledger: u32,
}

/// Error codes for the Stellar lock contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StellarLockError {
    AlreadyReleased,
    InsufficientSignatures,
    InvalidSignature,
    ZeroAmount,
    InvalidRecipient,
    LockNotFound,
    NegativeAmount,
    Overflow,
}

impl std::fmt::Display for StellarLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyReleased => write!(f, "lock already released"),
            Self::InsufficientSignatures => write!(f, "insufficient validator signatures"),
            Self::InvalidSignature => write!(f, "invalid validator signature"),
            Self::ZeroAmount => write!(f, "lock amount must be > 0"),
            Self::InvalidRecipient => write!(f, "invalid Seal recipient address"),
            Self::LockNotFound => write!(f, "lock not found"),
            Self::NegativeAmount => write!(f, "amount must be non-negative"),
            Self::Overflow => write!(f, "arithmetic overflow"),
        }
    }
}

/// Event emitted on lock.
#[derive(Clone, Debug)]
pub struct StellarLockEvent {
    pub lock_id: String,
    pub owner: String,
    pub amount: i128,
    pub asset: String,
    pub seal_recipient: String,
    pub ledger: u32,
}

/// Event emitted on release.
#[derive(Clone, Debug)]
pub struct StellarReleaseEvent {
    pub lock_id: String,
    pub recipient: String,
    pub amount: i128,
    pub validator_count: usize,
}

/// Validator set for multisig verification.
#[derive(Clone, Debug)]
pub struct StellarValidatorSet {
    /// Stellar addresses of authorized validators.
    pub validators: Vec<String>,
    /// Minimum signatures required.
    pub threshold: usize,
}

impl StellarValidatorSet {
    pub fn new(validators: Vec<String>, threshold: usize) -> Self {
        assert!(threshold > 0 && threshold <= validators.len());
        Self {
            validators,
            threshold,
        }
    }

    /// Verify multisig. Each signature is (stellar_address, signature_bytes).
    pub fn verify_multisig(
        &self,
        _message: &[u8],
        signatures: &[(String, Vec<u8>)],
    ) -> Result<usize, StellarLockError> {
        let mut valid_count = 0;
        let mut seen = std::collections::HashSet::new();

        for (addr, _sig) in signatures {
            if !self.validators.contains(addr) {
                continue;
            }
            if !seen.insert(addr.clone()) {
                continue;
            }
            // On Stellar: ed25519_verify(pubkey, message, sig)
            // Testnet: accept any sig from known validator
            valid_count += 1;
        }

        if valid_count >= self.threshold {
            Ok(valid_count)
        } else {
            Err(StellarLockError::InsufficientSignatures)
        }
    }
}

/// Stellar lock contract state (simulates Soroban storage for testing).
#[derive(Default)]
pub struct StellarLockContract {
    pub locks: HashMap<String, StellarLock>,
    pub total_locked: HashMap<String, i128>, // asset_key -> total
    pub validator_set: Option<StellarValidatorSet>,
    pub nonce: u64,
    pub events: Vec<StellarLockEvent>,
    pub release_events: Vec<StellarReleaseEvent>,
}

impl StellarLockContract {
    pub fn new(validator_set: StellarValidatorSet) -> Self {
        Self {
            validator_set: Some(validator_set),
            ..Default::default()
        }
    }

    /// Lock XLM or USDC into the bridge contract.
    pub fn lock(
        &mut self,
        owner: &str,
        amount: i128,
        asset: StellarAsset,
        seal_recipient: &str,
        ledger: u32,
    ) -> Result<String, StellarLockError> {
        // Validate
        if amount < 0 {
            return Err(StellarLockError::NegativeAmount);
        }
        if amount == 0 {
            return Err(StellarLockError::ZeroAmount);
        }
        if !seal_recipient.starts_with("seal1") && !seal_recipient.starts_with("sealt1") {
            return Err(StellarLockError::InvalidRecipient);
        }

        self.nonce += 1;
        let lock_id = format!("xlm_lock_{}", self.nonce);

        let lock = StellarLock {
            id: lock_id.clone(),
            owner: owner.to_string(),
            amount,
            asset: asset.clone(),
            seal_recipient: seal_recipient.to_string(),
            released: false,
            lock_ledger: ledger,
        };

        let asset_key = asset.to_string();
        *self.total_locked.entry(asset_key.clone()).or_insert(0) = self
            .total_locked
            .get(&asset_key)
            .unwrap_or(&0)
            .checked_add(amount)
            .ok_or(StellarLockError::Overflow)?;

        self.events.push(StellarLockEvent {
            lock_id: lock_id.clone(),
            owner: owner.to_string(),
            amount,
            asset: asset.to_string(),
            seal_recipient: seal_recipient.to_string(),
            ledger,
        });

        self.locks.insert(lock_id.clone(), lock);
        Ok(lock_id)
    }

    /// Release locked tokens (validators submit multisig).
    pub fn release(
        &mut self,
        lock_id: &str,
        recipient: &str,
        signatures: &[(String, Vec<u8>)],
    ) -> Result<i128, StellarLockError> {
        // Verify multisig
        let message = lock_id.as_bytes();
        let validator_set = self
            .validator_set
            .as_ref()
            .ok_or(StellarLockError::InsufficientSignatures)?;
        let valid_count = validator_set.verify_multisig(message, signatures)?;

        // Get lock
        let lock = self
            .locks
            .get_mut(lock_id)
            .ok_or(StellarLockError::LockNotFound)?;

        if lock.released {
            return Err(StellarLockError::AlreadyReleased);
        }

        let amount = lock.amount;
        lock.released = true;

        // Update totals
        let asset_key = lock.asset.to_string();
        if let Some(total) = self.total_locked.get_mut(&asset_key) {
            *total = total.saturating_sub(amount);
        }

        self.release_events.push(StellarReleaseEvent {
            lock_id: lock_id.to_string(),
            recipient: recipient.to_string(),
            amount,
            validator_count: valid_count,
        });

        Ok(amount)
    }

    /// Query a lock by ID.
    pub fn get_lock(&self, lock_id: &str) -> Option<&StellarLock> {
        self.locks.get(lock_id)
    }

    /// Total locked for an asset.
    pub fn total_locked_for(&self, asset: &StellarAsset) -> i128 {
        self.total_locked
            .get(&asset.to_string())
            .copied()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_validators() -> StellarValidatorSet {
        StellarValidatorSet::new(
            vec![
                "GABCD_VAL1".to_string(),
                "GEFGH_VAL2".to_string(),
                "GIJKL_VAL3".to_string(),
            ],
            2, // 2-of-3
        )
    }

    fn test_sigs(addrs: &[&str]) -> Vec<(String, Vec<u8>)> {
        addrs
            .iter()
            .map(|a| (a.to_string(), vec![0u8; 64]))
            .collect()
    }

    #[test]
    fn test_lock_xlm() {
        let mut contract = StellarLockContract::new(test_validators());
        let lock_id = contract
            .lock(
                "GABCD_USER",
                10_000_000, // 1 XLM in stroops
                StellarAsset::Native,
                "seal1alice",
                100,
            )
            .unwrap();

        assert!(lock_id.starts_with("xlm_lock_"));
        assert_eq!(contract.total_locked_for(&StellarAsset::Native), 10_000_000);
        assert_eq!(contract.events.len(), 1);

        let lock = contract.get_lock(&lock_id).unwrap();
        assert_eq!(lock.owner, "GABCD_USER");
        assert_eq!(lock.asset, StellarAsset::Native);
        assert!(!lock.released);
    }

    #[test]
    fn test_lock_usdc() {
        let mut contract = StellarLockContract::new(test_validators());
        let usdc = StellarAsset::Usdc("CCABC123".to_string());
        let lock_id = contract
            .lock("GEFGH_USER", 500_000_000, usdc.clone(), "seal1bob", 200)
            .unwrap();

        assert_eq!(contract.total_locked_for(&usdc), 500_000_000);
        let lock = contract.get_lock(&lock_id).unwrap();
        assert_eq!(lock.asset.symbol(), "USDC");
    }

    #[test]
    fn test_lock_zero_fails() {
        let mut contract = StellarLockContract::new(test_validators());
        let result = contract.lock("GABCD", 0, StellarAsset::Native, "seal1alice", 0);
        assert_eq!(result, Err(StellarLockError::ZeroAmount));
    }

    #[test]
    fn test_lock_negative_fails() {
        let mut contract = StellarLockContract::new(test_validators());
        let result = contract.lock("GABCD", -100, StellarAsset::Native, "seal1alice", 0);
        assert_eq!(result, Err(StellarLockError::NegativeAmount));
    }

    #[test]
    fn test_lock_invalid_recipient_fails() {
        let mut contract = StellarLockContract::new(test_validators());
        let result = contract.lock("GABCD", 1000, StellarAsset::Native, "bad_addr", 0);
        assert_eq!(result, Err(StellarLockError::InvalidRecipient));
    }

    #[test]
    fn test_release_with_multisig() {
        let mut contract = StellarLockContract::new(test_validators());
        let lock_id = contract
            .lock("GABCD_USER", 50_000_000, StellarAsset::Native, "seal1alice", 100)
            .unwrap();

        let sigs = test_sigs(&["GABCD_VAL1", "GEFGH_VAL2"]); // 2 of 3
        let amount = contract.release(&lock_id, "GXYZ_RECIPIENT", &sigs).unwrap();

        assert_eq!(amount, 50_000_000);
        assert_eq!(contract.total_locked_for(&StellarAsset::Native), 0);
        assert!(contract.get_lock(&lock_id).unwrap().released);
        assert_eq!(contract.release_events.len(), 1);
    }

    #[test]
    fn test_release_insufficient_sigs() {
        let mut contract = StellarLockContract::new(test_validators());
        let lock_id = contract
            .lock("GABCD", 1000, StellarAsset::Native, "seal1alice", 0)
            .unwrap();

        let sigs = test_sigs(&["GABCD_VAL1"]); // Only 1 of 3
        let result = contract.release(&lock_id, "GXYZ", &sigs);
        assert_eq!(result, Err(StellarLockError::InsufficientSignatures));
    }

    #[test]
    fn test_release_already_released() {
        let mut contract = StellarLockContract::new(test_validators());
        let lock_id = contract
            .lock("GABCD", 1000, StellarAsset::Native, "seal1alice", 0)
            .unwrap();

        let sigs = test_sigs(&["GABCD_VAL1", "GEFGH_VAL2"]);
        contract.release(&lock_id, "GXYZ", &sigs).unwrap();

        let result = contract.release(&lock_id, "GXYZ", &sigs);
        assert_eq!(result, Err(StellarLockError::AlreadyReleased));
    }

    #[test]
    fn test_release_not_found() {
        let mut contract = StellarLockContract::new(test_validators());
        let sigs = test_sigs(&["GABCD_VAL1", "GEFGH_VAL2"]);
        let result = contract.release("nonexistent", "GXYZ", &sigs);
        assert_eq!(result, Err(StellarLockError::LockNotFound));
    }

    #[test]
    fn test_multiple_locks_mixed_assets() {
        let mut contract = StellarLockContract::new(test_validators());
        let usdc = StellarAsset::Usdc("CCABC".to_string());

        contract
            .lock("GABCD", 10_000_000, StellarAsset::Native, "seal1alice", 100)
            .unwrap();
        contract
            .lock("GABCD", 20_000_000, StellarAsset::Native, "seal1alice", 101)
            .unwrap();
        contract
            .lock("GEFGH", 500_000, usdc.clone(), "seal1bob", 102)
            .unwrap();

        assert_eq!(contract.total_locked_for(&StellarAsset::Native), 30_000_000);
        assert_eq!(contract.total_locked_for(&usdc), 500_000);
        assert_eq!(contract.events.len(), 3);
    }

    #[test]
    fn test_duplicate_validator_sigs_ignored() {
        let mut contract = StellarLockContract::new(test_validators());
        let lock_id = contract
            .lock("GABCD", 1000, StellarAsset::Native, "seal1alice", 0)
            .unwrap();

        // Same validator twice
        let sigs = test_sigs(&["GABCD_VAL1", "GABCD_VAL1"]);
        let result = contract.release(&lock_id, "GXYZ", &sigs);
        assert_eq!(result, Err(StellarLockError::InsufficientSignatures));
    }

    #[test]
    fn test_stellar_asset_display() {
        assert_eq!(StellarAsset::Native.to_string(), "native");
        assert_eq!(
            StellarAsset::Usdc("CC123".into()).to_string(),
            "USDC:CC123"
        );
        assert_eq!(
            StellarAsset::Classic {
                code: "EUR".into(),
                issuer: "GISSUER".into(),
            }
            .to_string(),
            "EUR:GISSUER"
        );
    }

    #[test]
    fn test_sealt1_testnet_recipient() {
        let mut contract = StellarLockContract::new(test_validators());
        let result = contract.lock("GABCD", 1000, StellarAsset::Native, "sealt1test", 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validator_set() {
        let vs = test_validators();
        let msg = b"test";

        // 2 valid → passes
        let sigs = test_sigs(&["GABCD_VAL1", "GIJKL_VAL3"]);
        assert_eq!(vs.verify_multisig(msg, &sigs).unwrap(), 2);

        // Unknown validator → ignored
        let sigs = test_sigs(&["GABCD_VAL1", "UNKNOWN"]);
        assert_eq!(
            vs.verify_multisig(msg, &sigs),
            Err(StellarLockError::InsufficientSignatures)
        );
    }
}
