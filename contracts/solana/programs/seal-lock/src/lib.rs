//! Seal Lock — Solana bridge lock program.
//!
//! Users lock SOL/SPL tokens here. Seal validators observe the lock
//! event and mint wrapped tokens (wSOL, wUSDC) on the Seal chain.
//!
//! To withdraw: user burns wrapped tokens on Seal, validators produce
//! a threshold signature, and this program releases the locked tokens.
//!
//! # Architecture
//!
//! ```text
//! User (Solana wallet)
//!   │
//!   ├── lock_sol(amount, seal_recipient)
//!   │     ├── Creates LockAccount PDA
//!   │     ├── Transfers SOL to vault PDA
//!   │     └── Emits LockEvent log
//!   │
//!   ├── lock_spl(mint, amount, seal_recipient)
//!   │     ├── Creates LockAccount PDA
//!   │     ├── Transfers SPL tokens to vault ATA
//!   │     └── Emits LockEvent log
//!   │
//!   └── (Seal validators observe LockEvent)
//!
//! Seal Validators (multisig)
//!   │
//!   └── release(lock_id, recipient, signatures[])
//!         ├── Verifies M-of-N multisig (testnet: 2-of-3)
//!         ├── Transfers tokens from vault to recipient
//!         └── Marks lock as released
//! ```
//!
//! # Build
//! ```bash
//! # Requires: Solana CLI + Anchor
//! # cargo install --git https://github.com/coral-xyz/anchor anchor-cli
//! anchor build
//! ```
//!
//! # Deploy
//! ```bash
//! solana program deploy target/deploy/seal_lock.so
//! ```

// When Anchor is available, uncomment:
// use anchor_lang::prelude::*;
// declare_id!("SealLock11111111111111111111111111111111111");

use std::collections::HashMap;

/// Lock account: holds locked SOL/SPL tokens.
#[derive(Clone, Debug)]
pub struct LockAccount {
    /// Unique lock ID (derived from depositor + nonce).
    pub id: String,
    /// Owner (Solana wallet that locked the tokens).
    pub owner: [u8; 32],
    /// Amount locked (lamports for SOL, token units for SPL).
    pub amount: u64,
    /// SPL token mint address (None for native SOL).
    pub mint: Option<[u8; 32]>,
    /// Seal recipient address (bech32m).
    pub seal_recipient: String,
    /// Whether the lock has been released.
    pub released: bool,
    /// Timestamp of lock.
    pub lock_timestamp: i64,
    /// Bump seed for PDA derivation.
    pub bump: u8,
}

/// Error codes for the lock program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    /// Lock has already been released.
    AlreadyReleased,
    /// Insufficient signatures for release.
    InsufficientSignatures,
    /// Invalid validator signature.
    InvalidSignature,
    /// Lock amount is zero.
    ZeroAmount,
    /// Invalid Seal recipient address.
    InvalidRecipient,
    /// Lock not found.
    LockNotFound,
    /// Arithmetic overflow.
    Overflow,
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyReleased => write!(f, "lock already released"),
            Self::InsufficientSignatures => write!(f, "insufficient validator signatures"),
            Self::InvalidSignature => write!(f, "invalid validator signature"),
            Self::ZeroAmount => write!(f, "lock amount must be > 0"),
            Self::InvalidRecipient => write!(f, "invalid Seal recipient address"),
            Self::LockNotFound => write!(f, "lock not found"),
            Self::Overflow => write!(f, "arithmetic overflow"),
        }
    }
}

/// Event emitted when tokens are locked.
#[derive(Clone, Debug)]
pub struct LockEvent {
    pub lock_id: String,
    pub owner: [u8; 32],
    pub amount: u64,
    pub mint: Option<[u8; 32]>,
    pub seal_recipient: String,
    pub timestamp: i64,
}

/// Event emitted when tokens are released.
#[derive(Clone, Debug)]
pub struct ReleaseEvent {
    pub lock_id: String,
    pub recipient: [u8; 32],
    pub amount: u64,
    pub validator_count: usize,
}

/// Validator set for multisig release (testnet: 2-of-3).
#[derive(Clone, Debug)]
pub struct ValidatorSet {
    /// Public keys of authorized validators.
    pub validators: Vec<[u8; 32]>,
    /// Minimum signatures required (M of N).
    pub threshold: usize,
}

impl ValidatorSet {
    pub fn new(validators: Vec<[u8; 32]>, threshold: usize) -> Self {
        assert!(threshold > 0 && threshold <= validators.len());
        Self {
            validators,
            threshold,
        }
    }

    /// Verify that enough valid validator signatures are present.
    /// Each signature is (validator_pubkey, signature_bytes).
    pub fn verify_multisig(
        &self,
        message: &[u8],
        signatures: &[([u8; 32], Vec<u8>)],
    ) -> Result<usize, LockError> {
        let mut valid_count = 0;
        let mut seen_validators = std::collections::HashSet::new();

        for (pubkey, _sig_bytes) in signatures {
            // Check that this is a known validator
            if !self.validators.contains(pubkey) {
                continue;
            }
            // Prevent double-counting
            if !seen_validators.insert(*pubkey) {
                continue;
            }

            // On Solana, we'd use Ed25519 program verification:
            // ed25519_program::verify(pubkey, message, sig_bytes)
            //
            // For testnet, we accept any signature from a known validator.
            // Production: verify Ed25519 sig on Solana side,
            //             verify ML-DSA sig on Seal side.
            valid_count += 1;
        }

        if valid_count >= self.threshold {
            Ok(valid_count)
        } else {
            Err(LockError::InsufficientSignatures)
        }
    }
}

/// Lock program state (simulates on-chain state for testing).
#[derive(Default)]
pub struct LockProgram {
    pub locks: HashMap<String, LockAccount>,
    pub total_locked_sol: u64,
    pub total_locked_by_mint: HashMap<[u8; 32], u64>,
    pub validator_set: Option<ValidatorSet>,
    pub nonce: u64,
    pub events: Vec<LockEvent>,
    pub release_events: Vec<ReleaseEvent>,
}

impl LockProgram {
    pub fn new(validator_set: ValidatorSet) -> Self {
        Self {
            validator_set: Some(validator_set),
            ..Default::default()
        }
    }

    /// Lock native SOL tokens.
    pub fn lock_sol(
        &mut self,
        depositor: &[u8; 32],
        amount: u64,
        seal_recipient: &str,
        timestamp: i64,
    ) -> Result<String, LockError> {
        self.validate_lock(amount, seal_recipient)?;

        self.nonce += 1;
        let lock_id = format!("lock_sol_{}", self.nonce);

        let lock = LockAccount {
            id: lock_id.clone(),
            owner: *depositor,
            amount,
            mint: None,
            seal_recipient: seal_recipient.to_string(),
            released: false,
            lock_timestamp: timestamp,
            bump: 0,
        };

        self.total_locked_sol = self
            .total_locked_sol
            .checked_add(amount)
            .ok_or(LockError::Overflow)?;

        self.events.push(LockEvent {
            lock_id: lock_id.clone(),
            owner: *depositor,
            amount,
            mint: None,
            seal_recipient: seal_recipient.to_string(),
            timestamp,
        });

        self.locks.insert(lock_id.clone(), lock);
        Ok(lock_id)
    }

    /// Lock SPL tokens.
    pub fn lock_spl(
        &mut self,
        depositor: &[u8; 32],
        mint: &[u8; 32],
        amount: u64,
        seal_recipient: &str,
        timestamp: i64,
    ) -> Result<String, LockError> {
        self.validate_lock(amount, seal_recipient)?;

        self.nonce += 1;
        let lock_id = format!("lock_spl_{}", self.nonce);

        let lock = LockAccount {
            id: lock_id.clone(),
            owner: *depositor,
            amount,
            mint: Some(*mint),
            seal_recipient: seal_recipient.to_string(),
            released: false,
            lock_timestamp: timestamp,
            bump: 0,
        };

        *self.total_locked_by_mint.entry(*mint).or_insert(0) = self
            .total_locked_by_mint
            .get(mint)
            .unwrap_or(&0)
            .checked_add(amount)
            .ok_or(LockError::Overflow)?;

        self.events.push(LockEvent {
            lock_id: lock_id.clone(),
            owner: *depositor,
            amount,
            mint: Some(*mint),
            seal_recipient: seal_recipient.to_string(),
            timestamp,
        });

        self.locks.insert(lock_id.clone(), lock);
        Ok(lock_id)
    }

    /// Release locked tokens (validators submit multisig).
    pub fn release(
        &mut self,
        lock_id: &str,
        recipient: &[u8; 32],
        signatures: &[([u8; 32], Vec<u8>)],
    ) -> Result<u64, LockError> {
        // Verify multisig
        let message = lock_id.as_bytes();
        let validator_set = self
            .validator_set
            .as_ref()
            .ok_or(LockError::InsufficientSignatures)?;
        let valid_count = validator_set.verify_multisig(message, signatures)?;

        // Get lock
        let lock = self
            .locks
            .get_mut(lock_id)
            .ok_or(LockError::LockNotFound)?;

        if lock.released {
            return Err(LockError::AlreadyReleased);
        }

        let amount = lock.amount;
        lock.released = true;

        // Update totals
        if lock.mint.is_none() {
            self.total_locked_sol = self.total_locked_sol.saturating_sub(amount);
        } else if let Some(mint) = lock.mint {
            if let Some(total) = self.total_locked_by_mint.get_mut(&mint) {
                *total = total.saturating_sub(amount);
            }
        }

        self.release_events.push(ReleaseEvent {
            lock_id: lock_id.to_string(),
            recipient: *recipient,
            amount,
            validator_count: valid_count,
        });

        Ok(amount)
    }

    /// Query a lock by ID.
    pub fn get_lock(&self, lock_id: &str) -> Option<&LockAccount> {
        self.locks.get(lock_id)
    }

    fn validate_lock(&self, amount: u64, seal_recipient: &str) -> Result<(), LockError> {
        if amount == 0 {
            return Err(LockError::ZeroAmount);
        }
        // Basic validation: seal addresses start with "seal1"
        if !seal_recipient.starts_with("seal1") && !seal_recipient.starts_with("sealt1") {
            return Err(LockError::InvalidRecipient);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_validators() -> ValidatorSet {
        ValidatorSet::new(
            vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            2, // 2-of-3
        )
    }

    fn test_signatures(validators: &[[u8; 32]]) -> Vec<([u8; 32], Vec<u8>)> {
        validators
            .iter()
            .map(|v| (*v, vec![0u8; 64])) // Placeholder sigs
            .collect()
    }

    #[test]
    fn test_lock_sol() {
        let mut prog = LockProgram::new(test_validators());
        let depositor = [10u8; 32];
        let lock_id = prog
            .lock_sol(&depositor, 1_000_000_000, "seal1alice", 1000)
            .unwrap();

        assert!(lock_id.starts_with("lock_sol_"));
        assert_eq!(prog.total_locked_sol, 1_000_000_000);
        assert_eq!(prog.events.len(), 1);
        assert_eq!(prog.events[0].amount, 1_000_000_000);

        let lock = prog.get_lock(&lock_id).unwrap();
        assert_eq!(lock.owner, depositor);
        assert!(!lock.released);
        assert!(lock.mint.is_none());
    }

    #[test]
    fn test_lock_spl() {
        let mut prog = LockProgram::new(test_validators());
        let depositor = [10u8; 32];
        let usdc_mint = [20u8; 32];
        let lock_id = prog
            .lock_spl(&depositor, &usdc_mint, 500_000, "seal1bob", 2000)
            .unwrap();

        assert!(lock_id.starts_with("lock_spl_"));
        assert_eq!(*prog.total_locked_by_mint.get(&usdc_mint).unwrap(), 500_000);

        let lock = prog.get_lock(&lock_id).unwrap();
        assert_eq!(lock.mint, Some(usdc_mint));
    }

    #[test]
    fn test_lock_zero_fails() {
        let mut prog = LockProgram::new(test_validators());
        let result = prog.lock_sol(&[1u8; 32], 0, "seal1alice", 0);
        assert_eq!(result, Err(LockError::ZeroAmount));
    }

    #[test]
    fn test_lock_invalid_recipient_fails() {
        let mut prog = LockProgram::new(test_validators());
        let result = prog.lock_sol(&[1u8; 32], 1000, "invalid_addr", 0);
        assert_eq!(result, Err(LockError::InvalidRecipient));
    }

    #[test]
    fn test_release_with_multisig() {
        let mut prog = LockProgram::new(test_validators());
        let depositor = [10u8; 32];
        let lock_id = prog
            .lock_sol(&depositor, 5_000_000_000, "seal1alice", 1000)
            .unwrap();

        let recipient = [20u8; 32];
        let sigs = test_signatures(&[[1u8; 32], [2u8; 32]]); // 2 of 3

        let amount = prog.release(&lock_id, &recipient, &sigs).unwrap();
        assert_eq!(amount, 5_000_000_000);
        assert_eq!(prog.total_locked_sol, 0);
        assert!(prog.get_lock(&lock_id).unwrap().released);
        assert_eq!(prog.release_events.len(), 1);
    }

    #[test]
    fn test_release_insufficient_sigs() {
        let mut prog = LockProgram::new(test_validators());
        let lock_id = prog
            .lock_sol(&[10u8; 32], 1000, "seal1alice", 0)
            .unwrap();

        let sigs = test_signatures(&[[1u8; 32]]); // Only 1 of 3 (need 2)
        let result = prog.release(&lock_id, &[20u8; 32], &sigs);
        assert_eq!(result, Err(LockError::InsufficientSignatures));
    }

    #[test]
    fn test_release_already_released() {
        let mut prog = LockProgram::new(test_validators());
        let lock_id = prog
            .lock_sol(&[10u8; 32], 1000, "seal1alice", 0)
            .unwrap();

        let sigs = test_signatures(&[[1u8; 32], [2u8; 32]]);
        prog.release(&lock_id, &[20u8; 32], &sigs).unwrap();

        // Second release should fail
        let result = prog.release(&lock_id, &[20u8; 32], &sigs);
        assert_eq!(result, Err(LockError::AlreadyReleased));
    }

    #[test]
    fn test_release_not_found() {
        let mut prog = LockProgram::new(test_validators());
        let sigs = test_signatures(&[[1u8; 32], [2u8; 32]]);
        let result = prog.release("nonexistent", &[20u8; 32], &sigs);
        assert_eq!(result, Err(LockError::LockNotFound));
    }

    #[test]
    fn test_multiple_locks_and_releases() {
        let mut prog = LockProgram::new(test_validators());
        let depositor = [10u8; 32];

        let id1 = prog
            .lock_sol(&depositor, 1000, "seal1alice", 100)
            .unwrap();
        let id2 = prog
            .lock_sol(&depositor, 2000, "seal1bob", 200)
            .unwrap();
        let id3 = prog
            .lock_sol(&depositor, 3000, "seal1carol", 300)
            .unwrap();

        assert_eq!(prog.total_locked_sol, 6000);

        let sigs = test_signatures(&[[1u8; 32], [2u8; 32]]);
        prog.release(&id2, &[20u8; 32], &sigs).unwrap();
        assert_eq!(prog.total_locked_sol, 4000);

        prog.release(&id1, &[20u8; 32], &sigs).unwrap();
        assert_eq!(prog.total_locked_sol, 3000);

        // id3 still locked
        assert!(!prog.get_lock(&id3).unwrap().released);
    }

    #[test]
    fn test_duplicate_validator_sigs_ignored() {
        let mut prog = LockProgram::new(test_validators());
        let lock_id = prog
            .lock_sol(&[10u8; 32], 1000, "seal1alice", 0)
            .unwrap();

        // Same validator twice — should only count once (need 2)
        let sigs = test_signatures(&[[1u8; 32], [1u8; 32]]);
        let result = prog.release(&lock_id, &[20u8; 32], &sigs);
        assert_eq!(result, Err(LockError::InsufficientSignatures));
    }

    #[test]
    fn test_validator_set_verification() {
        let vs = test_validators();
        let msg = b"test message";

        // 2 valid sigs — passes
        let sigs = test_signatures(&[[1u8; 32], [3u8; 32]]);
        assert_eq!(vs.verify_multisig(msg, &sigs).unwrap(), 2);

        // 3 valid sigs — also passes
        let sigs = test_signatures(&[[1u8; 32], [2u8; 32], [3u8; 32]]);
        assert_eq!(vs.verify_multisig(msg, &sigs).unwrap(), 3);

        // Unknown validator — ignored
        let sigs = test_signatures(&[[1u8; 32], [99u8; 32]]);
        assert_eq!(
            vs.verify_multisig(msg, &sigs),
            Err(LockError::InsufficientSignatures)
        );
    }

    #[test]
    fn test_seal_testnet_recipient() {
        let mut prog = LockProgram::new(test_validators());
        // sealt1 prefix for testnet should also be accepted
        let result = prog.lock_sol(&[1u8; 32], 1000, "sealt1test", 0);
        assert!(result.is_ok());
    }
}
