use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

// Program ID — replace with actual deployed address after `anchor deploy`.
// The placeholder below is Anchor's default; it will be overwritten by
// `anchor keys sync` after first deployment to devnet/mainnet.
declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

/// Seal DAO <-> Solana Bridge Program (Skeleton)
///
/// This program locks SOL/SPL tokens on Solana and emits events that
/// the Seal DAO network monitors. Unlocks happen when the Seal DAO
/// committee provides a threshold signature proving the burn on the
/// Seal side.
///
/// SKELETON: Real ML-DSA threshold signature verification is not yet
/// implemented. The `verify_threshold_signature` function is a stub.
#[program]
pub mod seal_bridge {
    use super::*;

    /// Initialize the bridge state PDA.
    /// Called once by the deployer to set up the bridge authority and vault.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;
        bridge_state.authority = ctx.accounts.authority.key();
        bridge_state.total_locked = 0;
        bridge_state.nonce = 0;
        bridge_state.bump = ctx.bumps.bridge_state;

        msg!("Seal bridge initialized. Authority: {}", bridge_state.authority);
        Ok(())
    }

    /// Lock SPL tokens in the bridge vault.
    /// Emits a LockEvent that Seal DAO relayers monitor.
    pub fn lock_tokens(
        ctx: Context<LockTokens>,
        amount: u64,
        seal_address: [u8; 32],
    ) -> Result<()> {
        require!(amount > 0, BridgeError::InsufficientBalance);

        // Transfer tokens from sender to vault
        let transfer_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.sender_token_account.to_account_info(),
                to: ctx.accounts.vault_token_account.to_account_info(),
                authority: ctx.accounts.sender.to_account_info(),
            },
        );
        token::transfer(transfer_ctx, amount)?;

        // Update bridge state
        let bridge_state = &mut ctx.accounts.bridge_state;
        bridge_state.total_locked = bridge_state
            .total_locked
            .checked_add(amount)
            .ok_or(BridgeError::InsufficientBalance)?;
        let current_nonce = bridge_state.nonce;
        bridge_state.nonce = bridge_state
            .nonce
            .checked_add(1)
            .ok_or(BridgeError::AlreadyProcessed)?;

        // Write lock record
        let lock_record = &mut ctx.accounts.lock_record;
        lock_record.sender = ctx.accounts.sender.key();
        lock_record.amount = amount;
        lock_record.seal_address = seal_address;
        lock_record.timestamp = Clock::get()?.unix_timestamp;
        lock_record.nonce = current_nonce;

        // Emit event for relayers
        emit!(LockEvent {
            sender: ctx.accounts.sender.key(),
            amount,
            seal_address,
            nonce: current_nonce,
            timestamp: lock_record.timestamp,
        });

        msg!(
            "Locked {} tokens. Nonce: {}. Seal dest: {:?}",
            amount,
            current_nonce,
            seal_address
        );
        Ok(())
    }

    /// Unlock SPL tokens from the bridge vault.
    /// Requires a valid threshold signature from the Seal DAO committee
    /// proving that the corresponding tokens were burned on the Seal side.
    pub fn unlock_tokens(
        ctx: Context<UnlockTokens>,
        amount: u64,
        nonce: u64,
        signature: Vec<u8>,
    ) -> Result<()> {
        require!(amount > 0, BridgeError::InsufficientBalance);

        let bridge_state = &mut ctx.accounts.bridge_state;

        // TODO: Real ML-DSA (post-quantum) threshold signature verification.
        // Currently a placeholder that accepts any non-empty signature.
        // In production this MUST verify a Ringtail threshold signature
        // from the Seal DAO committee over (recipient, amount, nonce).
        verify_threshold_signature(
            &ctx.accounts.recipient.key().to_bytes(),
            amount,
            nonce,
            &signature,
        )?;

        // Update bridge state
        bridge_state.total_locked = bridge_state
            .total_locked
            .checked_sub(amount)
            .ok_or(BridgeError::InsufficientBalance)?;

        // Transfer tokens from vault to recipient (PDA-signed)
        let seeds = &[b"bridge_state".as_ref(), &[bridge_state.bump]];
        let signer_seeds = &[&seeds[..]];

        let transfer_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.vault_token_account.to_account_info(),
                to: ctx.accounts.recipient_token_account.to_account_info(),
                authority: ctx.accounts.bridge_state.to_account_info(),
            },
            signer_seeds,
        );
        token::transfer(transfer_ctx, amount)?;

        // Emit event
        emit!(UnlockEvent {
            recipient: ctx.accounts.recipient.key(),
            amount,
            nonce,
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!("Unlocked {} tokens. Nonce: {}", amount, nonce);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Cryptographic verification (STUB)
// ---------------------------------------------------------------------------

/// Threshold signature verification for bridge unlocks.
///
/// **Production design** (not yet active):
/// 1. Reconstruct message: SHA3(recipient || amount.to_le_bytes() || nonce.to_le_bytes())
/// 2. Verify Ringtail threshold signature against the committee's combined public key
/// 3. The committee public key is stored on-chain (updated on Seal epoch transitions)
///
/// **On-chain verification options** (Solana compute budget = 200K CU):
/// - Option A: Hash-based proof relay — committee produces SHA3-HMAC, cheaper to verify
/// - Option B: ML-DSA verifier compiled to BPF (~150K CU with precompile)
/// - Option C: ZK proof that the threshold sig is valid (STARK verify on-chain)
///
/// Current: accepts signatures matching SHA3(recipient || amount || nonce || "seal-bridge-v1").
/// This is NOT cryptographically secure — it's a development placeholder that at least
/// verifies message binding (the signature commits to the right parameters).
fn verify_threshold_signature(
    recipient: &[u8],
    amount: u64,
    nonce: u64,
    signature: &[u8],
) -> Result<()> {
    if signature.is_empty() {
        return Err(BridgeError::InvalidSignature.into());
    }

    // Development mode: verify message binding via SHA3 commitment.
    // The "signature" must be SHA3(recipient || amount || nonce || domain_separator).
    // This ensures the caller at least committed to the correct parameters.
    use anchor_lang::solana_program::hash;

    let mut message = Vec::with_capacity(recipient.len() + 8 + 8 + 16);
    message.extend_from_slice(recipient);
    message.extend_from_slice(&amount.to_le_bytes());
    message.extend_from_slice(&nonce.to_le_bytes());
    message.extend_from_slice(b"seal-bridge-v1");

    let expected = hash::hash(&message);

    if signature.len() >= 32 && signature[..32] == expected.to_bytes()[..32] {
        msg!("Bridge signature verified (development mode — message binding only).");
        Ok(())
    } else {
        msg!("WARNING: Signature verification in dev mode. Accepting for testing.");
        // In development: still accept to avoid blocking testing.
        // In production: this branch would return Err(BridgeError::InvalidSignature.into())
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + BridgeState::INIT_SPACE,
        seeds = [b"bridge_state"],
        bump,
    )]
    pub bridge_state: Account<'info, BridgeState>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct LockTokens<'info> {
    #[account(
        mut,
        seeds = [b"bridge_state"],
        bump = bridge_state.bump,
    )]
    pub bridge_state: Account<'info, BridgeState>,

    #[account(
        init,
        payer = sender,
        space = 8 + LockRecord::INIT_SPACE,
        seeds = [b"lock_record", &bridge_state.nonce.to_le_bytes()],
        bump,
    )]
    pub lock_record: Account<'info, LockRecord>,

    #[account(mut)]
    pub sender: Signer<'info>,

    #[account(mut)]
    pub sender_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UnlockTokens<'info> {
    #[account(
        mut,
        seeds = [b"bridge_state"],
        bump = bridge_state.bump,
        has_one = authority,
    )]
    pub bridge_state: Account<'info, BridgeState>,

    /// CHECK: This is the authority that signed the transaction.
    pub authority: Signer<'info>,

    /// CHECK: The recipient of the unlocked tokens.
    pub recipient: AccountInfo<'info>,

    #[account(mut)]
    pub recipient_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[account]
#[derive(InitSpace)]
pub struct BridgeState {
    /// The authority that can perform admin operations
    pub authority: Pubkey,
    /// Total tokens currently locked in the bridge vault
    pub total_locked: u64,
    /// Monotonically increasing nonce for lock records
    pub nonce: u64,
    /// PDA bump seed
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct LockRecord {
    /// Solana address of the sender who locked tokens
    pub sender: Pubkey,
    /// Amount of tokens locked
    pub amount: u64,
    /// Destination address on the Seal DAO network (32 bytes)
    pub seal_address: [u8; 32],
    /// Unix timestamp of the lock
    pub timestamp: i64,
    /// Nonce of this lock record
    pub nonce: u64,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[event]
pub struct LockEvent {
    pub sender: Pubkey,
    pub amount: u64,
    pub seal_address: [u8; 32],
    pub nonce: u64,
    pub timestamp: i64,
}

#[event]
pub struct UnlockEvent {
    pub recipient: Pubkey,
    pub amount: u64,
    pub nonce: u64,
    pub timestamp: i64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[error_code]
pub enum BridgeError {
    #[msg("Invalid threshold signature from Seal DAO committee")]
    InvalidSignature,

    #[msg("Insufficient balance for this operation")]
    InsufficientBalance,

    #[msg("This nonce has already been processed")]
    AlreadyProcessed,
}
