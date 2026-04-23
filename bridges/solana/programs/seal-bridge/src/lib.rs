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
    /// Called once by the deployer to set up the bridge authority, vault,
    /// and the Seal committee's 32-byte verification key used by
    /// `verify_committee_sig` to authenticate unlocks.
    ///
    /// `committee_key` is shared between the bridge program and the Seal
    /// committee. It rotates each Seal epoch — rotation is done via the
    /// admin `rotate_committee_key` ix (TODO). For testnet it's whatever
    /// the `seal-node` committee broadcasts over P2P; mainnet will
    /// derive it from the Ringtail aggregate verification key.
    pub fn initialize(ctx: Context<Initialize>, committee_key: [u8; 32]) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;
        bridge_state.authority = ctx.accounts.authority.key();
        bridge_state.total_locked = 0;
        bridge_state.nonce = 0;
        bridge_state.bump = ctx.bumps.bridge_state;
        bridge_state.committee_key = committee_key;

        msg!(
            "Seal bridge initialized. Authority: {} Committee-key: {:x?}",
            bridge_state.authority,
            &committee_key[..4],
        );
        Ok(())
    }

    /// Rotate the committee verification key. Restricted to the
    /// authority (admin) set at init. In production this is called by
    /// the admin on each Seal epoch transition.
    pub fn rotate_committee_key(
        ctx: Context<RotateCommitteeKey>,
        new_key: [u8; 32],
    ) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;
        bridge_state.committee_key = new_key;
        emit!(KeyRotatedEvent {
            authority: ctx.accounts.authority.key(),
            timestamp: Clock::get()?.unix_timestamp,
        });
        msg!("Committee key rotated by {}", ctx.accounts.authority.key());
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

        // Snapshot the committee key by value before we take any `&mut`
        // borrow of bridge_state — anchor 0.31's borrow checker is
        // stricter than 0.30 and rejects overlapping `&mut` + `&` here.
        let committee_key = ctx.accounts.bridge_state.committee_key;

        // Verify the committee signature. Uses `committee_key` as a
        // shared verification key (not the full Ringtail algebraic
        // verify — that's gated on the `ringtail-verify` feature and
        // blocked on the signer fix).
        verify_committee_sig(
            &ctx.accounts.recipient.key().to_bytes(),
            amount,
            nonce,
            &signature,
            &committee_key,
        )?;

        let bridge_state = &mut ctx.accounts.bridge_state;

        // Algebraic Ringtail verify. Off by default — see Cargo.toml
        // `ringtail-verify` feature. When on, this is an additional
        // proof layer stacked on top of the committee-MAC (defense in
        // depth during the transition). Long-term the MAC goes away.
        #[cfg(feature = "ringtail-verify")]
        verify_ringtail_sig(
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
// Committee signature verification
// ---------------------------------------------------------------------------

/// Domain separator for the committee MAC. Change triggers a
/// forced-break (old signatures won't verify under the new tag) — use
/// that for emergency key rotation without rotating `committee_key`.
pub const BRIDGE_DOMAIN_TAG: &[u8] = b"seal-bridge-solana-v1";

/// Size of the committee signature envelope (HMAC-SHA-256 of the
/// canonical message). The "signature" is not a Ringtail signature
/// blob — it's a committee-MAC that the Seal validators compute
/// off-chain from their shared `committee_key` + the message bytes.
/// See [`BridgeState::committee_key`].
pub const COMMITTEE_SIG_LEN: usize = 32;

/// Verify a committee-MAC authenticating an unlock.
///
/// # What this checks
///
/// 1. `signature.len() == 32` — exact HMAC-SHA-256 output length.
/// 2. `signature == HMAC-SHA-256(committee_key, recipient || amount
///    || nonce || BRIDGE_DOMAIN_TAG)`, compared in constant time.
///
/// # What this does NOT check
///
/// - Algebraic validity of a Ringtail threshold signature. That
///   requires 48-bit prime arithmetic + sparse polynomial ops in BPF,
///   tracked as the long-form B3 in `bridges/DEPLOYMENT.md`. For
///   testnet and the initial mainnet cycles we trust the Seal
///   committee's off-chain Ringtail verify and mirror it on-chain
///   via this MAC. Rotating `committee_key` each epoch bounds the
///   blast radius of a single-epoch committee compromise.
/// - Individual committee-member participation. The MAC is a
///   commitment by the committee-as-a-whole; per-member checks live
///   in the aggregated Ringtail sig that is observed on Seal itself.
fn verify_committee_sig(
    recipient: &[u8],
    amount: u64,
    nonce: u64,
    signature: &[u8],
    committee_key: &[u8; 32],
) -> Result<()> {
    if signature.len() != COMMITTEE_SIG_LEN {
        msg!(
            "InvalidSignature: expected {}-byte MAC, got {}",
            COMMITTEE_SIG_LEN,
            signature.len()
        );
        return Err(BridgeError::InvalidSignature.into());
    }

    // Canonical message: recipient(32) || amount(8 LE) || nonce(8 LE) || domain
    let mut msg_bytes = Vec::with_capacity(
        recipient.len() + 8 + 8 + BRIDGE_DOMAIN_TAG.len(),
    );
    msg_bytes.extend_from_slice(recipient);
    msg_bytes.extend_from_slice(&amount.to_le_bytes());
    msg_bytes.extend_from_slice(&nonce.to_le_bytes());
    msg_bytes.extend_from_slice(BRIDGE_DOMAIN_TAG);

    let expected = hmac_sha256(committee_key, &msg_bytes);

    if ct_eq_32(signature, &expected) {
        Ok(())
    } else {
        msg!("InvalidSignature: committee MAC mismatch");
        Err(BridgeError::InvalidSignature.into())
    }
}

/// HMAC-SHA-256 per RFC 2104, using Solana's native `hash::hash`
/// (SHA-256) syscall. Block size is 64 bytes for SHA-256.
///
/// Keys longer than the block size are pre-hashed; shorter keys are
/// zero-padded. IPAD/OPAD are the RFC constants 0x36 / 0x5c.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use anchor_lang::solana_program::hash;

    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        let pre = hash::hash(key).to_bytes();
        padded[..32].copy_from_slice(&pre);
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut i_pad = [0u8; BLOCK];
    let mut o_pad = [0u8; BLOCK];
    for idx in 0..BLOCK {
        i_pad[idx] = padded[idx] ^ 0x36;
        o_pad[idx] = padded[idx] ^ 0x5c;
    }

    // Inner: SHA256(i_pad || message)
    let mut inner = Vec::with_capacity(BLOCK + message.len());
    inner.extend_from_slice(&i_pad);
    inner.extend_from_slice(message);
    let inner_digest = hash::hash(&inner).to_bytes();

    // Outer: SHA256(o_pad || inner_digest)
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&o_pad);
    outer.extend_from_slice(&inner_digest);
    hash::hash(&outer).to_bytes()
}

/// Algebraic Ringtail verification hook.
///
/// When the `ringtail-verify` feature is enabled, the unlock path
/// additionally decodes `signature` as a Ringtail envelope and runs
/// the full algebraic verify via the no_std `seal-ringtail-verify`
/// crate.
///
/// ```text
/// signature layout (ringtail-verify feature):
///   [0..32]      committee_mac     (HMAC-SHA-256)
///   [32..34]     participant_count (u16 LE)
///   [34..36]     threshold         (u16 LE)
///   [36..68]     challenge         ([u8; 32])
///   [68..2116]   z                 (256 LE-u64 coefficients = 2048 B)
///   [2116..18500] matrix_a[K]      (K × 2048 B = 16384 B for K=8)
///   [18500..34884] public_key_t[K] (K × 2048 B)
/// ```
///
/// MIN envelope = 32 + 2 + 2 + 32 + 2048 + 8·2048 + 8·2048 = 34884 B.
///
/// The committee-MAC at the front continues to authenticate the
/// recipient/amount/nonce binding (the algebraic verify only attests
/// to the signature itself). Both must succeed.
#[cfg(feature = "ringtail-verify")]
fn verify_ringtail_sig(
    _recipient: &[u8],
    _amount: u64,
    _nonce: u64,
    signature: &[u8],
) -> Result<()> {
    use seal_ringtail_verify::{
        verify as ringtail_verify, ntt::NttCtx, PublicParams, Signature as RtSig, RING_N,
    };

    const RING_BYTES: usize = RING_N * 8;
    const MODULE_K: usize = 8;
    const MIN_ENVELOPE: usize =
        32 + 2 + 2 + 32 + RING_BYTES + MODULE_K * RING_BYTES + MODULE_K * RING_BYTES;
    if signature.len() < MIN_ENVELOPE {
        msg!("Ringtail envelope too short: {} < {}", signature.len(), MIN_ENVELOPE);
        return Err(BridgeError::InvalidSignature.into());
    }

    let participant_count =
        u16::from_le_bytes([signature[32], signature[33]]) as usize;
    let threshold =
        u16::from_le_bytes([signature[34], signature[35]]) as usize;
    let challenge_bytes: &[u8; 32] = signature[36..68]
        .try_into()
        .map_err(|_| anchor_lang::error::Error::from(BridgeError::InvalidSignature))?;
    let z = &signature[68..68 + RING_BYTES];

    let mut a_offset = 68 + RING_BYTES;
    let mut matrix_a: [&[u8]; MODULE_K] = [&[]; MODULE_K];
    for slot in matrix_a.iter_mut().take(MODULE_K) {
        *slot = &signature[a_offset..a_offset + RING_BYTES];
        a_offset += RING_BYTES;
    }
    let mut t_offset = a_offset;
    let mut public_key_t: [&[u8]; MODULE_K] = [&[]; MODULE_K];
    for slot in public_key_t.iter_mut().take(MODULE_K) {
        *slot = &signature[t_offset..t_offset + RING_BYTES];
        t_offset += RING_BYTES;
    }

    let sig = RtSig {
        z,
        challenge: challenge_bytes,
        participant_count,
    };
    let pp = PublicParams { matrix_a, public_key_t };

    // Build NTT context once per verify. ~300 mod_muls; cost is tiny
    // compared to the K poly_muls in the verify itself.
    let ctx = NttCtx::new();

    // Algebraic verify uses the recipient/amount/nonce-bound message
    // that the signer hashed. Today the signer hashes a generic
    // payload; once the signer pipes this triple through, replace
    // `b""` below with the canonical message bytes.
    if let Err(e) = ringtail_verify(&ctx, &sig, &pp, b"", threshold) {
        msg!("Ringtail algebraic verify failed: {:?}", e);
        return Err(BridgeError::InvalidSignature.into());
    }

    Ok(())
}

/// Constant-time byte equality on two 32-byte arrays. Runs in O(32)
/// regardless of where the first differing byte is, so timing can't
/// leak how many bytes of the MAC the attacker got right.
fn ct_eq_32(a: &[u8], b: &[u8; 32]) -> bool {
    if a.len() != 32 {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
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
        // Anchor 0.31 requires uniform slice types in the seeds array;
        // coerce both seeds to `&[u8]` so the macro's array literal is
        // homogeneous.
        seeds = [b"lock_record".as_ref(), bridge_state.nonce.to_le_bytes().as_ref()],
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
pub struct RotateCommitteeKey<'info> {
    #[account(
        mut,
        seeds = [b"bridge_state"],
        bump = bridge_state.bump,
        has_one = authority,
    )]
    pub bridge_state: Account<'info, BridgeState>,

    pub authority: Signer<'info>,
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
    /// 32-byte verification key for committee MACs (see
    /// `verify_committee_sig`). Rotated per Seal epoch via
    /// `rotate_committee_key`.
    pub committee_key: [u8; 32],
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

#[event]
pub struct KeyRotatedEvent {
    pub authority: Pubkey,
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Unit tests for the MAC-based committee signature check. Run with
/// `cargo test -p seal-bridge` from `bridges/solana/programs/seal-bridge`.
#[cfg(test)]
mod tests {
    use super::*;

    // Reference HMAC-SHA-256 implementation from RFC 2104 using the
    // standard `sha2` crate. `cargo test` picks this up through the
    // dev-dependency added below; production builds (BPF) do not link
    // it — they use our `hmac_sha256` that wraps the Solana syscall.
    fn reference_hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        const BLOCK: usize = 64;
        let mut k = [0u8; BLOCK];
        if key.len() > BLOCK {
            let mut h = Sha256::new();
            h.update(key);
            k[..32].copy_from_slice(&h.finalize());
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0u8; BLOCK];
        let mut opad = [0u8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        inner.update(msg);
        let inner_digest = inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&opad);
        outer.update(&inner_digest);
        outer.finalize().into()
    }

    fn canonical_msg(recipient: &[u8], amount: u64, nonce: u64) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(recipient);
        m.extend_from_slice(&amount.to_le_bytes());
        m.extend_from_slice(&nonce.to_le_bytes());
        m.extend_from_slice(BRIDGE_DOMAIN_TAG);
        m
    }

    #[test]
    fn hmac_matches_sha2_reference_empty_key_empty_msg() {
        let got = hmac_sha256(&[], &[]);
        let want = reference_hmac(&[], &[]);
        assert_eq!(got, want);
    }

    #[test]
    fn hmac_matches_sha2_reference_short_key() {
        let key = b"key";
        let msg = b"The quick brown fox jumps over the lazy dog";
        let got = hmac_sha256(key, msg);
        let want = reference_hmac(key, msg);
        assert_eq!(got, want);
    }

    #[test]
    fn hmac_matches_sha2_reference_long_key_is_prehashed() {
        // 100-byte key exceeds the 64-byte block; HMAC prehashes first.
        let key = [0x42u8; 100];
        let msg = b"hello";
        let got = hmac_sha256(&key, msg);
        let want = reference_hmac(&key, msg);
        assert_eq!(got, want);
    }

    #[test]
    fn verify_accepts_valid_mac() {
        let committee_key = [0x11u8; 32];
        let recipient = [0xABu8; 32];
        let amount = 1_000_000u64;
        let nonce = 7u64;
        let expected = reference_hmac(&committee_key, &canonical_msg(&recipient, amount, nonce));
        assert!(verify_committee_sig(&recipient, amount, nonce, &expected, &committee_key).is_ok());
    }

    #[test]
    fn verify_rejects_flipped_bit() {
        let committee_key = [0x11u8; 32];
        let recipient = [0xABu8; 32];
        let amount = 1_000_000u64;
        let nonce = 7u64;
        let mut sig = reference_hmac(&committee_key, &canonical_msg(&recipient, amount, nonce));
        sig[0] ^= 1;
        let err =
            verify_committee_sig(&recipient, amount, nonce, &sig, &committee_key).unwrap_err();
        // Anchor wraps BridgeError::InvalidSignature as anchor::Error;
        // easiest check is that the call was not ok.
        let _ = err;
    }

    #[test]
    fn verify_rejects_wrong_length() {
        let committee_key = [0u8; 32];
        let err = verify_committee_sig(
            &[0u8; 32],
            0,
            0,
            &[0u8; 31], // one byte short
            &committee_key,
        )
        .unwrap_err();
        let _ = err;
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let real_key = [0x11u8; 32];
        let fake_key = [0x22u8; 32];
        let recipient = [0xABu8; 32];
        let amount = 1_000_000u64;
        let nonce = 7u64;
        let sig = reference_hmac(&real_key, &canonical_msg(&recipient, amount, nonce));
        // Signature was made with real_key but we verify under fake_key.
        let err =
            verify_committee_sig(&recipient, amount, nonce, &sig, &fake_key).unwrap_err();
        let _ = err;
    }

    #[test]
    fn verify_rejects_wrong_amount() {
        let committee_key = [0x11u8; 32];
        let recipient = [0xABu8; 32];
        let sig = reference_hmac(&committee_key, &canonical_msg(&recipient, 100, 7));
        // Verify with a different amount — MAC should no longer match.
        let err =
            verify_committee_sig(&recipient, 101, 7, &sig, &committee_key).unwrap_err();
        let _ = err;
    }

    #[test]
    fn verify_rejects_wrong_nonce() {
        let committee_key = [0x11u8; 32];
        let recipient = [0xABu8; 32];
        let sig = reference_hmac(&committee_key, &canonical_msg(&recipient, 100, 7));
        let err =
            verify_committee_sig(&recipient, 100, 8, &sig, &committee_key).unwrap_err();
        let _ = err;
    }

    #[test]
    fn ct_eq_agrees_with_regular_eq_on_all_byte_pairs() {
        // Spot-check constant-time equality on a few shapes.
        let a = [1u8; 32];
        let b = [1u8; 32];
        assert!(ct_eq_32(&a, &b));

        let mut c = [1u8; 32];
        c[31] = 2;
        assert!(!ct_eq_32(&a, &c));

        assert!(!ct_eq_32(&[1u8; 31], &a));
    }
}
