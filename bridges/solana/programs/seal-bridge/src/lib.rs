use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("65kPNGiE3eN9YnfTrUyQ8HWSguedtpZ4m7YobXZAMxYe");

/// Seal DAO <-> Solana Bridge Program (Skeleton)
///
/// This program locks SPL tokens on Solana and emits events that the
/// Seal DAO network monitors. Unlocks happen when the Seal DAO
/// committee authorizes a burn on the Seal side.
///
/// **Committee authorization is a k-of-n member multisig.** Each
/// committee member holds an ed25519 keypair; their *public* keys are
/// stored in `BridgeState::committee_members`. An unlock transaction
/// must be signed (as Solana tx signers — verified natively by the
/// runtime, at zero program cost) by at least
/// `BridgeState::unlock_threshold` **distinct** members. There is no
/// shared secret anywhere: forging an unlock requires `threshold`+
/// members' private keys, matching the chain's own trust model (a
/// threshold committee compromise is already a chain compromise).
///
/// Every lock and unlock nonce is replay-protected by a per-nonce PDA
/// record that the ix creates exactly once; a second transaction at
/// the same nonce finds the record already funded and is rejected
/// with `AlreadyProcessed`.
///
/// ## Runtime notes (measured on the pinned 3.1.15 test validator)
///
/// Two measured findings shape this program:
///
/// 1. **Standard vanilla system CPI, validated on-chain.** All
///    account creation goes through `create_pda_account` — a plain
///    `SystemInstruction::CreateAccount` CPI, correct on every Solana
///    cluster. On the local 3.1.15 test validator (fresh
///    `solana-test-validator --reset` ledger) the full `initialize`
///    e2e was executed on-chain and verified byte-for-byte: PDA
///    created by the CPI, rent-exempt, 572-byte layout written.
///    Caveat: one long-running fork ledger observed earlier exhibited
///    a degraded system program (top-level system instructions as
///    no-ops, unreliable fee/status RPC); on such a runtime the
///    create CPI returns without allocating. The post-CPI length
///    check in `create_pda_account` turns that into a clean
///    `AccountCreationFailed` instead of a panic on the layout write.
///    Treat the local fork as a dispatch/deserialization/authorization
///    smoke environment, not a fully faithful cluster.
///
/// 2. **No in-BPF signature verification.** In-BPF ed25519-dalek
///    `verify_strict` exceeds the hard 1.4M CU per-instruction cap
///    (measured: it consumes the full budget and fails), and the
///    ed25519 precompile cannot be bound to on-chain committee keys
///    (it only reads relayer-controlled instruction bytes; this
///    runtime's precompile ignores the alt-account mechanism that
///    would provide the binding — verified empirically). Member
///    multisig needs none of those mechanisms: the runtime already
///    verifies every tx signature.
#[program]
pub mod seal_bridge {
    use super::*;

    /// Initialize the bridge state PDA.
    /// Called once by the deployer to set up the bridge authority and
    /// the committee member set.
    ///
    /// `committee_members` are the ed25519 public keys of committee
    /// members authorized to sign unlocks (distinct, 1..=16 entries);
    /// `unlock_threshold` is the minimum number of distinct members
    /// that must sign an unlock tx (1..=`MAX_COMMITTEE_SLOTS` — a
    /// Solana transaction carries at most 16 signatures, so the
    /// threshold is capped at 8 member slots).
    pub fn initialize(
        ctx: Context<Initialize>,
        committee_members: Vec<Pubkey>,
        unlock_threshold: u8,
    ) -> Result<()> {
        require!(unlock_threshold >= 1, BridgeError::InvalidCommitteeConfig);
        require!(
            unlock_threshold <= MAX_COMMITTEE_SLOTS as u8,
            BridgeError::InvalidCommitteeConfig
        );
        validate_committee_set(&committee_members, unlock_threshold)?;

        // Manual init: standard system CPI to create the PDA, then an
        // explicit layout write (the `#[account]` derive's init path
        // is not used, so committee fields are set once from the
        // instruction args below).
        let (expected_key, bump) =
            Pubkey::find_program_address(&[b"bridge_state"], &crate::ID);
        require_keys_eq!(
            ctx.accounts.bridge_state.key(),
            expected_key,
            BridgeError::InvalidBridgeStatePda
        );
        require!(
            ctx.accounts.bridge_state.lamports() == 0,
            BridgeError::AlreadyInitialized
        );

        let authority = ctx.accounts.authority.key();
        create_pda_account(
            &ctx.accounts.authority,
            &ctx.accounts.bridge_state,
            8 + BridgeState::INIT_SPACE,
            &[b"bridge_state".as_ref(), &[bump]],
        )?;

        // Write the anchor account layout manually (the `#[account]`
        // derive's init path did not run). Layout (Borsh, LE):
        // disc(8) | authority(32) | total_locked(8) | nonce(8) |
        // bump(1) | committee_members(16*32) | member_count(1) |
        // unlock_threshold(1) | paused(1)
        let mut members = [Pubkey::default(); MAX_COMMITTEE_MEMBERS];
        for (i, m) in committee_members.iter().enumerate() {
            members[i] = *m;
        }
        {
            let mut data = ctx.accounts.bridge_state.try_borrow_mut_data()?;
            let disc =
                anchor_lang::solana_program::hash::hash(b"account:BridgeState").to_bytes();
            data[0..8].copy_from_slice(&disc[..8]);
            data[8..40].copy_from_slice(authority.as_ref());
            data[40..48].copy_from_slice(&0u64.to_le_bytes()); // total_locked
            data[48..56].copy_from_slice(&0u64.to_le_bytes()); // nonce
            data[56] = bump;
            for (i, m) in members.iter().enumerate() {
                data[57 + i * 32..57 + (i + 1) * 32].copy_from_slice(m.as_ref());
            }
            let meta = 8 + 32 + 8 + 8 + 1 + MAX_COMMITTEE_MEMBERS * 32;
            data[meta] = committee_members.len() as u8; // member_count
            data[meta + 1] = unlock_threshold;
            data[meta + 2] = 0; // paused
        }

        msg!(
            "Seal bridge initialized. Authority: {} members: {} threshold: {}",
            authority,
            committee_members.len(),
            unlock_threshold,
        );
        Ok(())
    }

    /// Set the in-program pause flag. Restricted to the authority
    /// (admin) set at init. Defence-in-depth: the global per-chain
    /// pause on `seal-node`'s `BridgeManager` already rejects deposits
    /// / processing / withdrawals at the Seal-side router level, but
    /// the on-chain flag here is the source-of-truth that a watcher
    /// or relayer can also observe directly. While paused, both
    /// `lock_tokens` and `unlock_tokens` reject with `BridgePaused`.
    pub fn set_pause(ctx: Context<SetPause>, paused: bool) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;
        bridge_state.paused = paused;
        emit!(PauseStateChanged {
            authority: ctx.accounts.authority.key(),
            paused,
            timestamp: Clock::get()?.unix_timestamp,
        });
        msg!(
            "Bridge pause flag set to {} by {}",
            paused,
            ctx.accounts.authority.key()
        );
        Ok(())
    }

    /// Rotate the committee member set and/or unlock threshold.
    /// Restricted to the authority (admin) set at init. In production
    /// this is called by the admin when committee membership changes.
    pub fn rotate_committee_members(
        ctx: Context<RotateCommitteeMembers>,
        committee_members: Vec<Pubkey>,
        unlock_threshold: u8,
    ) -> Result<()> {
        require!(unlock_threshold >= 1, BridgeError::InvalidCommitteeConfig);
        require!(
            unlock_threshold <= MAX_COMMITTEE_SLOTS as u8,
            BridgeError::InvalidCommitteeConfig
        );
        validate_committee_set(&committee_members, unlock_threshold)?;

        let bridge_state = &mut ctx.accounts.bridge_state;
        for (i, m) in committee_members.iter().enumerate() {
            bridge_state.committee_members[i] = *m;
        }
        // Zero the tail so stale members can't leak past member_count.
        for i in committee_members.len()..MAX_COMMITTEE_MEMBERS {
            bridge_state.committee_members[i] = Pubkey::default();
        }
        bridge_state.member_count = committee_members.len() as u8;
        bridge_state.unlock_threshold = unlock_threshold;
        emit!(CommitteeRotatedEvent {
            authority: ctx.accounts.authority.key(),
            timestamp: Clock::get()?.unix_timestamp,
        });
        msg!(
            "Committee rotated by {} (members: {}, threshold: {})",
            ctx.accounts.authority.key(),
            bridge_state.member_count,
            unlock_threshold
        );
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
        require!(
            !ctx.accounts.bridge_state.paused,
            BridgeError::BridgePaused
        );

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

        // Create the lock record via the shared `create_pda_account`
        // path (manual rather than anchor `init` because the unlock
        // record's seeds include an ix argument, which anchor seed
        // constraints cannot reach — one code path for all PDA
        // creations). The seed is the current bridge nonce,
        // snapshotted before increment.
        let current_nonce = ctx.accounts.bridge_state.nonce;
        let (expected_key, record_bump) = Pubkey::find_program_address(
            &[b"lock_record".as_ref(), &current_nonce.to_le_bytes()],
            &crate::ID,
        );
        require_keys_eq!(
            ctx.accounts.lock_record.key(),
            expected_key,
            BridgeError::InvalidLockRecord
        );
        require!(
            ctx.accounts.lock_record.lamports() == 0,
            BridgeError::AlreadyProcessed
        );
        let sender_key = ctx.accounts.sender.key();
        create_pda_account(
            &ctx.accounts.sender,
            &ctx.accounts.lock_record,
            8 + LockRecord::INIT_SPACE,
            &[
                b"lock_record".as_ref(),
                &current_nonce.to_le_bytes(),
                &[record_bump],
            ],
        )?;
        {
            let mut data = ctx.accounts.lock_record.try_borrow_mut_data()?;
            // disc(8) | sender(32) | amount(8) | seal_address(32) |
            // timestamp(8) | nonce(8)
            let disc = anchor_lang::solana_program::hash::hash(b"account:LockRecord").to_bytes();
            data[0..8].copy_from_slice(&disc[..8]);
            data[8..40].copy_from_slice(sender_key.as_ref());
            data[40..48].copy_from_slice(&amount.to_le_bytes());
            data[48..80].copy_from_slice(&seal_address);
            data[80..88].copy_from_slice(&Clock::get()?.unix_timestamp.to_le_bytes());
            data[88..96].copy_from_slice(&current_nonce.to_le_bytes());
        }

        // Update bridge state
        let bridge_state = &mut ctx.accounts.bridge_state;
        bridge_state.total_locked = bridge_state
            .total_locked
            .checked_add(amount)
            .ok_or(BridgeError::InsufficientBalance)?;
        bridge_state.nonce = bridge_state
            .nonce
            .checked_add(1)
            .ok_or(BridgeError::AlreadyProcessed)?;

        // Emit event for relayers. `mint` is the SPL mint of the
        // transferred tokens — the Seal observer routes locks to
        // WSOL vs WUSDC by comparing this against its configured
        // USDC mint pubkey.
        let mint = ctx.accounts.vault_token_account.mint;
        emit!(LockEvent {
            sender: sender_key,
            amount,
            seal_address,
            mint,
            nonce: current_nonce,
            timestamp: Clock::get()?.unix_timestamp,
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
    ///
    /// Authorization: at least `bridge_state.unlock_threshold`
    /// **distinct** committee members (from `bridge_state
    /// .committee_members`) must have signed this transaction. The
    /// runtime already verified each signature against the tx account
    /// list; the handler checks set membership and de-duplication.
    /// The members' signatures bind the entire tx — recipient,
    /// amount, nonce included — so no separate message-level
    /// signature is needed.
    ///
    /// Replay protection: every `nonce` is bound to its own PDA record
    /// (`UnlockedRecord`) that this ix creates. A second transaction
    /// reusing a nonce finds the record already funded and is rejected
    /// with `AlreadyProcessed` atomically — before any state mutates
    /// and before any tokens move.
    pub fn unlock_tokens(
        ctx: Context<UnlockTokens>,
        amount: u64,
        nonce: u64,
    ) -> Result<()> {
        require!(amount > 0, BridgeError::InsufficientBalance);
        require!(
            !ctx.accounts.bridge_state.paused,
            BridgeError::BridgePaused
        );

        // Snapshot the committee config and bridge PDA by value before
        // we take any `&mut` borrow of bridge_state — anchor 0.31's
        // borrow checker is stricter than 0.30 and rejects overlapping
        // `&mut` + `&` here.
        let committee_members = ctx.accounts.bridge_state.committee_members;
        let member_count = ctx.accounts.bridge_state.member_count;
        let unlock_threshold = ctx.accounts.bridge_state.unlock_threshold;
        let bridge_state_key = ctx.accounts.bridge_state.key();

        // Committee authorization (k-of-n member multisig). Unused
        // slots typically repeat the authority (relayer) key; the
        // count below only tallies distinct in-set members.
        let signer_keys: [Pubkey; MAX_COMMITTEE_SLOTS] = [
            ctx.accounts.committee_signer_0.key(),
            ctx.accounts.committee_signer_1.key(),
            ctx.accounts.committee_signer_2.key(),
            ctx.accounts.committee_signer_3.key(),
            ctx.accounts.committee_signer_4.key(),
            ctx.accounts.committee_signer_5.key(),
            ctx.accounts.committee_signer_6.key(),
            ctx.accounts.committee_signer_7.key(),
        ];
        let distinct = count_distinct_member_signatures(
            &signer_keys,
            &committee_members,
            member_count,
        );
        msg!(
            "Committee authorization: {} distinct member(s) signed (threshold {})",
            distinct,
            unlock_threshold
        );
        require!(
            distinct >= unlock_threshold,
            BridgeError::InsufficientCommitteeSignatures
        );

        // Replay guard (nonce consumed exactly once). The PDA is derived
        // from the ix `nonce`, which anchor's `init` seeds can't reach
        // (seeds may only reference account fields, not ix args) — so
        // the record is checked and created manually here.
        let (unlocked_key, unlocked_bump) = Pubkey::find_program_address(
            &[
                b"unlocked".as_ref(),
                bridge_state_key.as_ref(),
                &nonce.to_le_bytes(),
            ],
            &crate::ID,
        );
        require_keys_eq!(
            ctx.accounts.unlocked_record.key(),
            unlocked_key,
            BridgeError::InvalidUnlockedRecord
        );
        // An already-funded record means this nonce was already
        // unlocked. Reject before mutating any state or moving tokens.
        require!(
            ctx.accounts.unlocked_record.lamports() == 0,
            BridgeError::AlreadyProcessed
        );

        // Create the per-nonce record (owner = this program). The
        // authority (relayer) pays the rent — mirrors `lock_tokens`'
        // sender-pays pattern. The PDA signs the create so the record
        // can never be transferred out from under the guard.
        let record_space = 8 + UnlockedRecord::INIT_SPACE;
        create_pda_account(
            &ctx.accounts.authority,
            &ctx.accounts.unlocked_record,
            record_space,
            &[
                b"unlocked".as_ref(),
                bridge_state_key.as_ref(),
                &nonce.to_le_bytes(),
                &[unlocked_bump],
            ],
        )?;

        // Write the anchor account layout manually (the `#[account]`
        // derive's init path did not run).
        // Layout: disc(8) | recipient(32) | amount(u64 LE) | nonce(u64
        // LE) | timestamp(i64 LE) — identical to what `#[account]`
        // produces.
        {
            let mut data = ctx.accounts.unlocked_record.try_borrow_mut_data()?;
            let discriminator =
                anchor_lang::solana_program::hash::hash(b"account:UnlockedRecord").to_bytes();
            data[0..8].copy_from_slice(&discriminator[..8]);
            data[8..40].copy_from_slice(&ctx.accounts.recipient.key().to_bytes());
            data[40..48].copy_from_slice(&amount.to_le_bytes());
            data[48..56].copy_from_slice(&nonce.to_le_bytes());
            data[56..64]
                .copy_from_slice(&Clock::get()?.unix_timestamp.to_le_bytes());
        }

        let bridge_state = &mut ctx.accounts.bridge_state;

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
// PDA account creation (system CPI)
// ---------------------------------------------------------------------------

/// Create a PDA-owned account via a standard system-program CPI
/// (`SystemInstruction::CreateAccount` — the vanilla wire layout,
/// correct on every Solana runtime). `signer_seeds` are the PDA
/// seeds (including the final bump byte) authorizing `to`.
///
/// Accounts are created manually (rather than via anchor `init`)
/// because the per-nonce record seeds include an ix argument
/// (`nonce`), which anchor seed constraints cannot reference, and so
/// all three account creations share one code path. The post-CPI
/// length check guards against degraded runtimes where the system
/// program returns without allocating (observed on one long-running
/// 3.1.15 fork ledger — see module docs): without it, the layout
/// write that follows would panic on an empty data slice instead of
/// failing with a clean error.
fn create_pda_account<'a>(
    from: &AccountInfo<'a>,
    to: &AccountInfo<'a>,
    space: usize,
    signer_seeds: &[&[u8]],
) -> Result<()> {
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(space);
    let ix =
        anchor_lang::solana_program::system_instruction::create_account(
            &from.key(),
            &to.key(),
            lamports,
            space as u64,
            &crate::ID, // owner = this program
        );
    // `invoke_signed` returns `Result<(), ProgramError>`; anchor 0.31
    // provides `From<ProgramError> for Error`, so `?` maps it directly.
    anchor_lang::solana_program::program::invoke_signed(
        &ix,
        &[from.clone(), to.clone()],
        &[&signer_seeds[..]],
    )?;
    require!(
        to.try_borrow_mut_data()?.len() == space,
        BridgeError::AccountCreationFailed
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Committee authorization (k-of-n member multisig)
// ---------------------------------------------------------------------------

/// Maximum committee members storable in `BridgeState`.
pub const MAX_COMMITTEE_MEMBERS: usize = 16;

/// Maximum distinct members that can authorize a single unlock.
/// Capped by Solana's 16-signature-per-transaction limit (the relayer
/// fee-payer occupies one slot); 8 member slots leave headroom.
pub const MAX_COMMITTEE_SLOTS: usize = 8;

/// Validate a candidate committee member set. Members must be distinct,
/// non-empty, at most `MAX_COMMITTEE_MEMBERS`, and the threshold must
/// fit both the set and the on-tx signer slots.
fn validate_committee_set(members: &[Pubkey], threshold: u8) -> Result<()> {
    require!(!members.is_empty(), BridgeError::InvalidCommitteeConfig);
    require!(
        members.len() <= MAX_COMMITTEE_MEMBERS,
        BridgeError::InvalidCommitteeConfig
    );
    require!(
        (threshold as usize) <= members.len(),
        BridgeError::InvalidCommitteeConfig
    );
    for i in 0..members.len() {
        for j in (i + 1)..members.len() {
            require!(
                members[i] != members[j],
                BridgeError::InvalidCommitteeConfig
            );
        }
    }
    Ok(())
}

/// Count how many **distinct** committee members appear in `signers`.
///
/// The runtime has already verified every tx signature against the tx
/// account list; this function only checks set membership (against
/// `members[..member_count]`) and de-duplicates. Signers that are not
/// committee members (e.g. the relayer fee-payer filling unused slots)
/// are ignored.
fn count_distinct_member_signatures(
    signers: &[Pubkey],
    members: &[Pubkey],
    member_count: u8,
) -> u8 {
    let mut count: u8 = 0;
    let mut seen: [Pubkey; MAX_COMMITTEE_SLOTS] = [Pubkey::default(); MAX_COMMITTEE_SLOTS];
    for s in signers {
        if !members[..member_count as usize].contains(s) {
            continue;
        }
        if seen[..count as usize].contains(s) {
            continue;
        }
        if count < MAX_COMMITTEE_SLOTS as u8 {
            seen[count as usize] = *s;
            count += 1;
        }
    }
    count
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// CHECK: Bridge state PDA for `[b"bridge_state"]`. The handler
    /// verifies the key, checks it is unfunded, creates it via a
    /// vanilla system CPI, and writes the `BridgeState` layout.
    /// Manual creation (shared `create_pda_account` path) rather than
    /// anchor's `init`.
    #[account(mut)]
    pub bridge_state: UncheckedAccount<'info>,

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

    /// CHECK: Per-nonce lock record PDA for
    /// `[b"lock_record", nonce.to_le_bytes()]`. The handler verifies
    /// the key against the current bridge nonce, checks it is
    /// unfunded, creates it via a vanilla system CPI, and writes the
    /// `LockRecord` layout.
    #[account(mut)]
    pub lock_record: UncheckedAccount<'info>,

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
pub struct RotateCommitteeMembers<'info> {
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
pub struct SetPause<'info> {
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

    /// CHECK: The authority (relayer) that signs the transaction and
    /// pays the `unlocked_record` rent.
    #[account(mut)]
    pub authority: Signer<'info>,

    /// CHECK: The recipient of the unlocked tokens.
    pub recipient: AccountInfo<'info>,

    #[account(mut)]
    pub recipient_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,

    /// Committee member signer slots (k-of-n multisig). The relayer
    /// fills at least `unlock_threshold` slots with committee member
    /// keys (each must appear in `bridge_state.committee_members`);
    /// unused slots repeat any already-signed account (typically the
    /// authority). The handler counts distinct in-set members and
    /// requires >= `unlock_threshold`.
    pub committee_signer_0: Signer<'info>,
    pub committee_signer_1: Signer<'info>,
    pub committee_signer_2: Signer<'info>,
    pub committee_signer_3: Signer<'info>,
    pub committee_signer_4: Signer<'info>,
    pub committee_signer_5: Signer<'info>,
    pub committee_signer_6: Signer<'info>,
    pub committee_signer_7: Signer<'info>,

    /// CHECK: Replay-guard record for this unlock nonce. The handler
    /// verifies it is the PDA for
    /// `[b"unlocked", bridge_state, nonce.to_le_bytes()]` and creates
    /// it via a vanilla system CPI; a second tx at the same nonce
    /// finds it already funded and is rejected with
    /// `AlreadyProcessed`.
    #[account(mut)]
    pub unlocked_record: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,

    pub token_program: Program<'info, Token>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[account]
#[derive(InitSpace)]
pub struct BridgeState {
    /// The authority that can perform admin operations (relayer)
    pub authority: Pubkey,
    /// Total tokens currently locked in the bridge vault
    pub total_locked: u64,
    /// Monotonically increasing nonce for lock records
    pub nonce: u64,
    /// PDA bump seed
    pub bump: u8,
    /// Ed25519 public keys of committee members authorized to sign
    /// unlocks. Only the first `member_count` entries are valid; the
    /// rest are zero-padded. Public keys only — no shared secret
    /// exists anywhere in the program (audit C.13).
    pub committee_members: [Pubkey; MAX_COMMITTEE_MEMBERS],
    /// Number of valid entries in `committee_members`.
    pub member_count: u8,
    /// Minimum number of distinct members that must sign an unlock
    /// transaction (1..=`MAX_COMMITTEE_SLOTS`).
    pub unlock_threshold: u8,
    /// In-program kill-switch. When true, `lock_tokens` and
    /// `unlock_tokens` reject with `BridgePaused`. Toggled by the
    /// authority via `set_pause`. Defaults to false.
    pub paused: bool,
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

/// Replay-guard record for an unlock nonce. PDA:
/// `[b"unlocked", bridge_state, nonce.to_le_bytes()]` — one per
/// unlock nonce, created by `unlock_tokens` and never written again.
/// Its existence (not its contents) is the guard: a second unlock tx
/// at the same nonce finds it already funded and is rejected with
/// `AlreadyProcessed`. The fields are stored for observer audit.
///
/// Created manually (vanilla system CPI in `unlock_tokens`) rather
/// than via `#[account(init)]` because the seed includes the ix
/// `nonce`, which anchor seeds cannot reference.
#[account]
#[derive(InitSpace)]
pub struct UnlockedRecord {
    /// Solana address that received the unlocked tokens
    pub recipient: Pubkey,
    /// Amount of tokens unlocked
    pub amount: u64,
    /// Nonce this record was created for (also in the PDA seed)
    pub nonce: u64,
    /// Unix timestamp of the unlock
    pub timestamp: i64,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[event]
pub struct LockEvent {
    pub sender: Pubkey,
    pub amount: u64,
    pub seal_address: [u8; 32],
    /// SPL mint of the locked tokens. The Seal observer routes
    /// to WUSDC when this matches its configured USDC mint and to
    /// WSOL otherwise. Field order matters — observer decodes Borsh
    /// positionally.
    pub mint: Pubkey,
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
pub struct CommitteeRotatedEvent {
    pub authority: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct PauseStateChanged {
    pub authority: Pubkey,
    pub paused: bool,
    pub timestamp: i64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[error_code]
pub enum BridgeError {
    #[msg("Insufficient committee member signatures for this unlock")]
    InsufficientCommitteeSignatures,

    #[msg("Insufficient balance for this operation")]
    InsufficientBalance,

    #[msg("This nonce has already been processed")]
    AlreadyProcessed,

    #[msg("Bridge is paused; lock and unlock are temporarily disabled")]
    BridgePaused,

    #[msg("unlocked_record is not the PDA for this unlock nonce")]
    InvalidUnlockedRecord,

    #[msg("Invalid committee member set or threshold")]
    InvalidCommitteeConfig,

    #[msg("lock_record is not the PDA for this lock nonce")]
    InvalidLockRecord,

    #[msg("bridge_state is not the bridge PDA")]
    InvalidBridgeStatePda,

    #[msg("The bridge has already been initialized")]
    AlreadyInitialized,

    /// The system-program create CPI returned success but did not
    /// allocate the account (observed on one long-running 3.1.15 fork
    /// test ledger, whose system program degraded to a no-op — see
    /// module docs). Failing here with a clean error keeps the
    /// program from panicking on the subsequent layout write into an
    /// empty data slice.
    #[msg("System program did not allocate the account")]
    AccountCreationFailed,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Unit tests for the committee multisig authorization. Run with
/// `cargo test -p seal-bridge` from `bridges/solana/programs/seal-bridge`.
#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> Pubkey {
        Pubkey::new_from_array([b; 32])
    }

    fn member_set(n: u8) -> ([Pubkey; MAX_COMMITTEE_MEMBERS], u8) {
        let mut members = [Pubkey::default(); MAX_COMMITTEE_MEMBERS];
        for i in 0..n as usize {
            members[i] = pk(0xA0 + i as u8);
        }
        (members, n)
    }

    #[test]
    fn count_distinct_members_meets_threshold() {
        let (members, count) = member_set(5);
        // 3 distinct members + the relayer (not in the set).
        let signers = [pk(0xA0), pk(0xA1), pk(0xA2), pk(0xFF)];
        assert_eq!(
            count_distinct_member_signatures(&signers, &members, count),
            3
        );
    }

    #[test]
    fn count_dedupes_repeated_member() {
        let (members, count) = member_set(5);
        // Same member in two slots counts once.
        let signers = [pk(0xA0), pk(0xA0), pk(0xA1), pk(0xA2)];
        assert_eq!(
            count_distinct_member_signatures(&signers, &members, count),
            3
        );
    }

    #[test]
    fn count_ignores_non_members() {
        let (members, count) = member_set(3);
        // 4 signers, only 1 is a member.
        let signers = [pk(0xA0), pk(0x01), pk(0x02), pk(0x03)];
        assert_eq!(
            count_distinct_member_signatures(&signers, &members, count),
            1
        );
    }

    #[test]
    fn count_respects_member_count_bound() {
        // The array has 16 slots but only the first `member_count`
        // entries are valid members — a "member" beyond the bound is
        // ignored.
        let (mut members, mut count) = member_set(2);
        // Plant a fake entry beyond the bound that matches a signer.
        members[5] = pk(0xB9);
        count = 2;
        let signers = [pk(0xA0), pk(0xB9)];
        assert_eq!(
            count_distinct_member_signatures(&signers, &members, count),
            1
        );
    }

    #[test]
    fn validate_committee_set_rejects_empty() {
        assert!(validate_committee_set(&[], 3).is_err());
    }

    #[test]
    fn validate_committee_set_rejects_duplicates() {
        let members = vec![pk(0xA0), pk(0xA0)];
        assert!(validate_committee_set(&members, 1).is_err());
    }

    #[test]
    fn validate_committee_set_rejects_threshold_above_set() {
        let members = vec![pk(0xA0), pk(0xA1)];
        assert!(validate_committee_set(&members, 3).is_err());
    }

    #[test]
    fn validate_committee_set_rejects_too_many_members() {
        let members: Vec<Pubkey> = (0..(MAX_COMMITTEE_MEMBERS + 1))
            .map(|i| pk(i as u8))
            .collect();
        assert!(validate_committee_set(&members, 3).is_err());
    }

    #[test]
    fn validate_committee_set_accepts_valid_set() {
        let members = vec![pk(0xA0), pk(0xA1), pk(0xA2), pk(0xA3)];
        assert!(validate_committee_set(&members, 3).is_ok());
    }

    #[test]
    fn unlocked_record_space_matches_manual_layout() {
        // `unlock_tokens` writes the record by hand:
        // disc(8) | recipient(32) | amount(8) | nonce(8) | timestamp(8)
        // — the rent-exempt allocation must match that layout exactly.
        assert_eq!(UnlockedRecord::INIT_SPACE, 32 + 8 + 8 + 8);
        assert_eq!(8 + UnlockedRecord::INIT_SPACE, 64);
    }

    #[test]
    fn lock_record_space_matches_manual_layout() {
        // disc(8) | sender(32) | amount(8) | seal_address(32) |
        // timestamp(8) | nonce(8)
        assert_eq!(LockRecord::INIT_SPACE, 32 + 8 + 32 + 8 + 8);
        assert_eq!(8 + LockRecord::INIT_SPACE, 96);
    }

    #[test]
    fn bridge_state_space_matches_manual_layout() {
        // disc(8) | authority(32) | total_locked(8) | nonce(8) | bump(1)
        // | members(16*32) | member_count(1) | threshold(1) | paused(1)
        assert_eq!(
            BridgeState::INIT_SPACE,
            32 + 8 + 8 + 1 + MAX_COMMITTEE_MEMBERS * 32 + 1 + 1 + 1
        );
        assert_eq!(8 + BridgeState::INIT_SPACE, 572);
    }
}
