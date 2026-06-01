#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, contracterror, symbol_short, token, Address, Bytes,
    BytesN, Env, log,
};
// Soroban SDK 22 moved `to_xdr` onto the `ToXdr` trait; import it so
// Address::to_xdr(&env) remains callable.
use soroban_sdk::xdr::ToXdr;

/// Seal DAO <-> Stellar Bridge Contract (Skeleton)
///
/// This Soroban contract locks XLM on Stellar and emits events that
/// the Seal DAO network monitors. Unlocks happen when the Seal DAO
/// committee provides a threshold signature proof that the corresponding
/// tokens were burned on the Seal side.
///
/// SKELETON: Real ML-DSA threshold signature verification is not yet
/// implemented. The proof verification function is a stub.

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

// Storage key strings are inlined at `symbol_short!("…")` sites below
// (soroban-sdk 22 requires literal strings there). These constants
// are kept as documentation of which short-symbol maps to which slot;
// `#[allow(dead_code)]` silences the "unused" warning.
#[allow(dead_code)] const ADMIN_KEY: &str = "admin";
#[allow(dead_code)] const BRIDGE_KEY: &str = "brkey";
#[allow(dead_code)] const TOTAL_LOCKED: &str = "locked";
#[allow(dead_code)] const NONCE_KEY: &str = "nonce";
/// Address of the Stellar Asset Contract (SAC) for the token the
/// bridge operates on. For native XLM this is the SAC derived from
/// the Asset::Native() XDR on the target network; for a non-native
/// asset it's the contract ID returned by `stellar contract asset
/// deploy --asset <code:issuer>`.
#[allow(dead_code)] const XLM_SAC_KEY: &str = "xlm_sac";
/// In-contract pause flag. When set to `true`, `lock_xlm` and
/// `unlock_xlm` both reject with `Paused`. Toggled by the admin via
/// `set_pause`.
#[allow(dead_code)] const PAUSED_KEY: &str = "paused";

/// Storage key prefix for processed nonces.
/// Each processed nonce is stored as "done:{nonce}" -> true.
fn nonce_storage_key(env: &Env, nonce: u64) -> Bytes {
    let mut key = Bytes::from_slice(env, b"done:");
    let nonce_bytes = nonce.to_be_bytes();
    key.extend_from_slice(&nonce_bytes);
    key
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Persistent state stored in the contract's ledger entries.
#[contracttype]
#[derive(Clone, Debug)]
pub struct LockInfo {
    pub sender: Address,
    pub amount: i128,
    pub seal_address: BytesN<32>,
    pub timestamp: u64,
    pub nonce: u64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum BridgeError {
    /// The contract has already been initialized
    AlreadyInitialized = 1,
    /// The contract has not been initialized yet
    NotInitialized = 2,
    /// Caller is not the admin
    Unauthorized = 3,
    /// This nonce has already been processed (replay protection)
    AlreadyProcessed = 4,
    /// Insufficient balance for the operation
    InsufficientBalance = 5,
    /// The threshold signature / proof is invalid
    InvalidProof = 6,
    /// Amount must be positive
    InvalidAmount = 7,
    /// Bridge is paused; lock and unlock are temporarily disabled
    Paused = 8,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct SealBridgeContract;

#[contractimpl]
impl SealBridgeContract {
    /// Initialize the bridge contract.
    ///
    /// Must be called exactly once. Sets the admin address, the Seal
    /// DAO committee public key used for verifying unlock proofs, and
    /// the Stellar Asset Contract (SAC) address for the asset this
    /// bridge operates on.
    ///
    /// # Arguments
    /// * `env` - Soroban environment
    /// * `admin` - Address that can perform admin operations
    /// * `seal_bridge_key` - The Seal DAO committee's public key
    ///                       (32 bytes) used to verify threshold
    ///                       signatures on unlocks
    /// * `xlm_sac` - SAC contract address for XLM (or another asset).
    ///               Derived per-network via
    ///               `stellar contract id asset --asset native`.
    pub fn initialize(
        env: Env,
        admin: Address,
        seal_bridge_key: BytesN<32>,
        xlm_sac: Address,
    ) -> Result<(), BridgeError> {
        // Ensure not already initialized
        if env.storage().instance().has(&symbol_short!("admin")) {
            return Err(BridgeError::AlreadyInitialized);
        }

        env.storage()
            .instance()
            .set(&symbol_short!("admin"), &admin);
        env.storage()
            .instance()
            .set(&symbol_short!("brkey"), &seal_bridge_key);
        env.storage()
            .instance()
            .set(&symbol_short!("xlm_sac"), &xlm_sac);
        env.storage()
            .instance()
            .set(&symbol_short!("locked"), &0i128);
        env.storage()
            .instance()
            .set(&symbol_short!("nonce"), &0u64);
        env.storage()
            .instance()
            .set(&symbol_short!("paused"), &false);

        log!(&env, "Seal bridge initialized. Admin: {}", admin);

        Ok(())
    }

    /// Toggle the in-contract pause flag. Admin-only. While paused,
    /// `lock_xlm` and `unlock_xlm` both reject with `Paused`. This
    /// is a defence-in-depth control on top of the Seal-side
    /// `seal_bridgePauseChain` (Technical Council 2/3 supermajority);
    /// even if the host-side relayer is compromised or stops checking
    /// the global pause state, this contract-level switch keeps the
    /// asset locked in the vault.
    pub fn set_pause(env: Env, paused: bool) -> Result<(), BridgeError> {
        if !env.storage().instance().has(&symbol_short!("admin")) {
            return Err(BridgeError::NotInitialized);
        }
        let admin: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("admin"))
            .ok_or(BridgeError::NotInitialized)?;
        admin.require_auth();
        env.storage()
            .instance()
            .set(&symbol_short!("paused"), &paused);
        env.events()
            .publish((symbol_short!("pause"),), (admin, paused));
        log!(&env, "Pause flag set to {}", paused);
        Ok(())
    }

    /// Lock XLM in the bridge contract.
    ///
    /// The caller sends `amount` of XLM to the contract, and a lock event
    /// is emitted for Seal DAO relayers to pick up.
    ///
    /// # Arguments
    /// * `env` - Soroban environment
    /// * `sender` - The address locking tokens (must authorize the call)
    /// * `amount` - Amount of XLM to lock (in stroops)
    /// * `seal_address` - Destination address on the Seal DAO network
    pub fn lock_xlm(
        env: Env,
        sender: Address,
        amount: i128,
        seal_address: BytesN<32>,
    ) -> Result<(), BridgeError> {
        // Verify the contract is initialized
        if !env.storage().instance().has(&symbol_short!("admin")) {
            return Err(BridgeError::NotInitialized);
        }

        // Reject when paused. Read before sender.require_auth() so a
        // paused contract never even prompts for sender auth.
        if env
            .storage()
            .instance()
            .get(&symbol_short!("paused"))
            .unwrap_or(false)
        {
            return Err(BridgeError::Paused);
        }

        // Require sender authorization
        sender.require_auth();

        // Validate amount
        if amount <= 0 {
            return Err(BridgeError::InvalidAmount);
        }

        // Transfer XLM from sender to this contract via the SAC
        // (Stellar Asset Contract). The SAC address was set during
        // `initialize` — for native XLM it's derived via
        // `stellar contract id asset --asset native` per network.
        // `transfer` requires `sender.require_auth()` which we already
        // asserted above.
        let xlm_sac: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("xlm_sac"))
            .ok_or(BridgeError::NotInitialized)?;
        let xlm = token::Client::new(&env, &xlm_sac);
        xlm.transfer(&sender, &env.current_contract_address(), &amount);

        // Update total locked
        let total_locked: i128 = env
            .storage()
            .instance()
            .get(&symbol_short!("locked"))
            .unwrap_or(0);
        let new_total = total_locked
            .checked_add(amount)
            .ok_or(BridgeError::InsufficientBalance)?;
        env.storage()
            .instance()
            .set(&symbol_short!("locked"), &new_total);

        // Increment and read nonce
        let nonce: u64 = env
            .storage()
            .instance()
            .get(&symbol_short!("nonce"))
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&symbol_short!("nonce"), &(nonce + 1));

        // Emit lock event
        env.events().publish(
            (symbol_short!("lock"),),
            LockInfo {
                sender: sender.clone(),
                amount,
                seal_address,
                timestamp: env.ledger().timestamp(),
                nonce,
            },
        );

        log!(
            &env,
            "Locked {} stroops. Nonce: {}. Sender: {}",
            amount,
            nonce,
            sender,
        );

        Ok(())
    }

    /// Unlock XLM from the bridge contract.
    ///
    /// The Seal DAO committee provides a proof (threshold signature) that
    /// the corresponding SEAL tokens were burned. This function verifies
    /// the proof and releases XLM to the recipient.
    ///
    /// # Arguments
    /// * `env` - Soroban environment
    /// * `recipient` - The Stellar address to receive unlocked XLM
    /// * `amount` - Amount of XLM to unlock (in stroops)
    /// * `nonce` - Unique nonce for replay protection
    /// * `proof` - Threshold signature proof from the Seal DAO committee
    pub fn unlock_xlm(
        env: Env,
        recipient: Address,
        amount: i128,
        nonce: u64,
        proof: Bytes,
    ) -> Result<(), BridgeError> {
        // Verify the contract is initialized
        if !env.storage().instance().has(&symbol_short!("admin")) {
            return Err(BridgeError::NotInitialized);
        }

        // Reject when paused. Same defence-in-depth as lock_xlm.
        if env
            .storage()
            .instance()
            .get(&symbol_short!("paused"))
            .unwrap_or(false)
        {
            return Err(BridgeError::Paused);
        }

        // Validate amount
        if amount <= 0 {
            return Err(BridgeError::InvalidAmount);
        }

        // Check replay protection: nonce must not have been processed
        let nonce_key = nonce_storage_key(&env, nonce);
        if env.storage().persistent().has(&nonce_key) {
            return Err(BridgeError::AlreadyProcessed);
        }

        // Verify the committee signature. This checks that the
        // submitted `proof` is HMAC-SHA-256(seal_bridge_key, canonical
        // message) — the same committee-MAC construction used on the
        // Solana side. See `verify_proof` for exactly what is and is
        // not checked.
        verify_proof(&env, &recipient, amount, nonce, &proof)?;

        // Algebraic Ringtail verify. Off by default — see Cargo.toml
        // `ringtail-verify` feature. When on, this is stacked on top
        // of the committee-MAC as a second layer of defense during
        // the transition to a pure lattice-verified bridge.
        #[cfg(feature = "ringtail-verify")]
        verify_ringtail_proof(&env, &recipient, amount, nonce, &proof)?;

        // Mark nonce as processed
        env.storage().persistent().set(&nonce_key, &true);

        // Update total locked
        let total_locked: i128 = env
            .storage()
            .instance()
            .get(&symbol_short!("locked"))
            .unwrap_or(0);
        let new_total = total_locked
            .checked_sub(amount)
            .ok_or(BridgeError::InsufficientBalance)?;
        env.storage()
            .instance()
            .set(&symbol_short!("locked"), &new_total);

        // Transfer XLM from this contract to recipient via the SAC.
        // When the authority is the contract's own address, Soroban
        // forwards the auth from the outer invocation boundary — the
        // SAC recognises `current_contract_address` as a contract
        // caller and allows the transfer without an extra auth
        // signature. See soroban-sdk::token::Client::transfer.
        let xlm_sac: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("xlm_sac"))
            .ok_or(BridgeError::NotInitialized)?;
        let xlm = token::Client::new(&env, &xlm_sac);
        xlm.transfer(&env.current_contract_address(), &recipient, &amount);

        // Emit unlock event
        env.events().publish(
            (symbol_short!("unlock"),),
            (recipient.clone(), amount, nonce),
        );

        log!(
            &env,
            "Unlocked {} stroops. Nonce: {}. Recipient: {}",
            amount,
            nonce,
            recipient,
        );

        Ok(())
    }

    /// Rotate the committee verification key. Only callable by the
    /// admin set at initialization. In production this is invoked
    /// once per Seal epoch when the committee's aggregate key
    /// changes.
    pub fn rotate_committee_key(
        env: Env,
        new_key: BytesN<32>,
    ) -> Result<(), BridgeError> {
        if !env.storage().instance().has(&symbol_short!("admin")) {
            return Err(BridgeError::NotInitialized);
        }
        let admin: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("admin"))
            .ok_or(BridgeError::NotInitialized)?;
        admin.require_auth();
        env.storage()
            .instance()
            .set(&symbol_short!("brkey"), &new_key);
        env.events()
            .publish((symbol_short!("keyrot"),), admin);
        log!(&env, "Committee key rotated");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // USDC bridge — parallel to lock_xlm / unlock_xlm but operates on
    // a separate Stellar Asset Contract address (the USDC SAC, which
    // on testnet is `USDC:GBBD47IF…` issued by the Stellar Foundation).
    // -----------------------------------------------------------------------

    /// Install / rotate the USDC SAC address. Admin-only.
    /// MUST be called once before `lock_usdc` works — `initialize`
    /// doesn't take this argument so existing bridge deployments don't
    /// need a contract upgrade to start handling USDC. Subsequent calls
    /// replace the prior value (no-op for testnet if you only deploy
    /// the bridge once per network).
    pub fn set_usdc_sac(env: Env, usdc_sac: Address) -> Result<(), BridgeError> {
        if !env.storage().instance().has(&symbol_short!("admin")) {
            return Err(BridgeError::NotInitialized);
        }
        let admin: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("admin"))
            .ok_or(BridgeError::NotInitialized)?;
        admin.require_auth();
        env.storage()
            .instance()
            .set(&symbol_short!("usdc_sac"), &usdc_sac);
        env.events()
            .publish((symbol_short!("usdcset"),), usdc_sac);
        log!(&env, "USDC SAC installed");
        Ok(())
    }

    /// Lock USDC in the bridge contract. Mirror of `lock_xlm` but uses
    /// the `usdc_sac` storage slot rather than `xlm_sac`. Emits an
    /// `lockusdc` event so the Seal observer can distinguish the asset
    /// at parse time.
    pub fn lock_usdc(
        env: Env,
        sender: Address,
        amount: i128,
        seal_address: BytesN<32>,
    ) -> Result<(), BridgeError> {
        if !env.storage().instance().has(&symbol_short!("admin")) {
            return Err(BridgeError::NotInitialized);
        }
        if env
            .storage()
            .instance()
            .get(&symbol_short!("paused"))
            .unwrap_or(false)
        {
            return Err(BridgeError::Paused);
        }
        sender.require_auth();
        if amount <= 0 {
            return Err(BridgeError::InvalidAmount);
        }

        let usdc_sac: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("usdc_sac"))
            .ok_or(BridgeError::NotInitialized)?;
        let usdc = token::Client::new(&env, &usdc_sac);
        usdc.transfer(&sender, &env.current_contract_address(), &amount);

        // Track USDC-specific total in its own slot so the XLM-side
        // accounting isn't disturbed. Shared `nonce` keeps withdrawal
        // ids globally unique.
        let total: i128 = env
            .storage()
            .instance()
            .get(&symbol_short!("usdclock"))
            .unwrap_or(0);
        let new_total = total
            .checked_add(amount)
            .ok_or(BridgeError::InsufficientBalance)?;
        env.storage()
            .instance()
            .set(&symbol_short!("usdclock"), &new_total);

        let nonce: u64 = env
            .storage()
            .instance()
            .get(&symbol_short!("nonce"))
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&symbol_short!("nonce"), &(nonce + 1));

        env.events().publish(
            (symbol_short!("lockusdc"),),
            LockInfo {
                sender: sender.clone(),
                amount,
                seal_address,
                timestamp: env.ledger().timestamp(),
                nonce,
            },
        );
        log!(
            &env,
            "Locked {} USDC base units. Nonce: {}. Sender: {}",
            amount,
            nonce,
            sender
        );
        Ok(())
    }

    /// Unlock USDC. Same shape as `unlock_xlm`; the on-host committee
    /// MAC binds (recipient, amount, nonce, BRIDGE_DOMAIN_TAG), so the
    /// same per-chain domain tag covers both XLM and USDC unlocks —
    /// reproducible from the seal-bridge host code (see
    /// `compute_committee_mac` Stellar branch).
    pub fn unlock_usdc(
        env: Env,
        recipient: Address,
        amount: i128,
        nonce: u64,
        proof: Bytes,
    ) -> Result<(), BridgeError> {
        if !env.storage().instance().has(&symbol_short!("admin")) {
            return Err(BridgeError::NotInitialized);
        }
        if env
            .storage()
            .instance()
            .get(&symbol_short!("paused"))
            .unwrap_or(false)
        {
            return Err(BridgeError::Paused);
        }
        if amount <= 0 {
            return Err(BridgeError::InvalidAmount);
        }
        let nonce_key = nonce_storage_key(&env, nonce);
        if env.storage().persistent().has(&nonce_key) {
            return Err(BridgeError::AlreadyProcessed);
        }
        verify_proof(&env, &recipient, amount, nonce, &proof)?;

        let total: i128 = env
            .storage()
            .instance()
            .get(&symbol_short!("usdclock"))
            .unwrap_or(0);
        let new_total = total
            .checked_sub(amount)
            .ok_or(BridgeError::InsufficientBalance)?;
        env.storage()
            .instance()
            .set(&symbol_short!("usdclock"), &new_total);

        let usdc_sac: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("usdc_sac"))
            .ok_or(BridgeError::NotInitialized)?;
        let usdc = token::Client::new(&env, &usdc_sac);
        usdc.transfer(&env.current_contract_address(), &recipient, &amount);

        env.storage().persistent().set(&nonce_key, &true);
        env.events().publish(
            (symbol_short!("unlockusd"),),
            (recipient.clone(), amount, nonce),
        );
        log!(
            &env,
            "Unlocked {} USDC to {}. Nonce: {}",
            amount,
            recipient,
            nonce
        );
        Ok(())
    }

    /// Total USDC currently locked in the bridge vault.
    pub fn get_total_usdc_locked(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&symbol_short!("usdclock"))
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------------

    /// Returns the total amount of XLM currently locked in the bridge.
    pub fn get_total_locked(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&symbol_short!("locked"))
            .unwrap_or(0)
    }

    /// Returns the current nonce (number of locks processed).
    pub fn get_nonce(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&symbol_short!("nonce"))
            .unwrap_or(0)
    }

    /// Check if a given unlock nonce has already been processed.
    pub fn is_nonce_processed(env: Env, nonce: u64) -> bool {
        let nonce_key = nonce_storage_key(&env, nonce);
        env.storage().persistent().has(&nonce_key)
    }

    /// Returns the current pause state. `false` until `set_pause(true)`
    /// is invoked by the admin (and pre-init, returns false).
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&symbol_short!("paused"))
            .unwrap_or(false)
    }

    /// SHA-256 fingerprint over the stored committee verification key.
    /// Used by Seal-side operator dashboards to cross-check that the
    /// host's `committee_key_fingerprint_sha256` (returned by
    /// `seal_bridgeGetCommitteeKeyStatus`) matches what's actually
    /// installed on-chain — drift between the two is the typical
    /// failure mode after a partial `rotate_committee_key` call where
    /// the on-chain ix landed but the Seal-side `seal_bridgeRotate
    /// CommitteeKey` did not (or vice versa).
    ///
    /// Returns `[0u8; 32]` pre-init (no committee key stored) so the
    /// view is callable during the bootstrap window without an
    /// `NotInitialized` error trip — dashboards can detect "not yet
    /// initialized" by the all-zero return.
    pub fn committee_key_hash(env: Env) -> BytesN<32> {
        let key: Option<BytesN<32>> =
            env.storage().instance().get(&symbol_short!("brkey"));
        match key {
            Some(k) => {
                let bytes: Bytes = k.into();
                env.crypto().sha256(&bytes).into()
            }
            None => BytesN::from_array(&env, &[0u8; 32]),
        }
    }
}

// ---------------------------------------------------------------------------
// Committee signature verification
// ---------------------------------------------------------------------------

/// Domain separator for the Stellar committee MAC. Distinct from the
/// Solana tag so a signature for one chain can't be replayed on the
/// other.
const BRIDGE_DOMAIN_TAG: &[u8] = b"seal-bridge-stellar-v1";

/// Size of the committee signature envelope (HMAC-SHA-256 output).
const COMMITTEE_SIG_LEN: u32 = 32;

/// Verify a committee-MAC authenticating an unlock.
///
/// # What this checks
///
/// 1. `proof.len() == 32` — exact HMAC-SHA-256 output length.
/// 2. `proof == HMAC-SHA-256(seal_bridge_key, recipient_bytes ||
///    amount_be_16 || nonce_be_8 || BRIDGE_DOMAIN_TAG)`, compared in
///    constant time.
///
/// The `seal_bridge_key` is the 32-byte shared verification key stored
/// at `initialize` time. It rotates per Seal epoch via an admin
/// action (`rotate_committee_key`); dashboards detect drift via
/// `committee_key_hash()` vs the Seal-side
/// `seal_bridgeGetCommitteeKeyStatus.fingerprint_sha2_hex`.
///
/// # What this does NOT check
///
/// - Algebraic validity of a Ringtail threshold signature. Porting
///   that to Soroban requires 48-bit prime polynomial arithmetic;
///   tracked as B4 in `bridges/DEPLOYMENT.md`. Trust is anchored in
///   per-epoch key rotation.
fn verify_proof(
    env: &Env,
    recipient: &Address,
    amount: i128,
    nonce: u64,
    proof: &Bytes,
) -> Result<(), BridgeError> {
    if proof.len() != COMMITTEE_SIG_LEN {
        log!(
            env,
            "InvalidProof: expected {}-byte MAC, got {}",
            COMMITTEE_SIG_LEN,
            proof.len()
        );
        return Err(BridgeError::InvalidProof);
    }
    let committee_key: BytesN<32> = env
        .storage()
        .instance()
        .get(&symbol_short!("brkey"))
        .ok_or(BridgeError::NotInitialized)?;

    // Canonical message: serialized recipient address || amount
    // (i128 big-endian, 16 bytes) || nonce (u64 big-endian, 8 bytes)
    // || domain tag. RFC 2104 HMAC is hash-agnostic so byte order is
    // arbitrary as long as both sides agree (host = Seal committee,
    // chain = this contract).
    let mut msg = Bytes::new(env);
    msg.append(&recipient.to_xdr(env));
    for byte in amount.to_be_bytes() {
        msg.push_back(byte);
    }
    for byte in nonce.to_be_bytes() {
        msg.push_back(byte);
    }
    msg.append(&Bytes::from_slice(env, BRIDGE_DOMAIN_TAG));

    let key_bytes: Bytes = committee_key.into();
    let expected = hmac_sha256(env, &key_bytes, &msg);
    let expected_bytes: Bytes = expected.into();

    if ct_eq_bytes(proof, &expected_bytes) {
        Ok(())
    } else {
        log!(env, "InvalidProof: committee MAC mismatch");
        Err(BridgeError::InvalidProof)
    }
}

/// Algebraic Ringtail verification hook for Soroban.
///
/// When the `ringtail-verify` feature is enabled, unlock_xlm additionally
/// decodes `proof` as a Ringtail envelope and runs the full algebraic
/// verify via the no_std `seal-ringtail-verify` crate.
///
/// ```text
/// proof layout (ringtail-verify feature):
///   [0..32]      committee_mac     (HMAC-SHA-256)
///   [32..34]     participant_count (u16 BE)
///   [34..36]     threshold         (u16 BE)
///   [36..68]     challenge         ([u8; 32])
///   [68..2116]   z                 (256 LE-u64 = 2048 B)
///   [2116..18500] matrix_a[K]      (K × 2048 B for K=8)
///   [18500..34884] public_key_t[K] (K × 2048 B)
/// ```
///
/// Soroban's `Bytes` is host-allocated; we materialize each slice
/// into a stack `[u8; 2048]` buffer once via `copy_into_slice` so the
/// verifier can borrow it. Per-verify allocation = 17 × 2048 B = 34 KB.
#[cfg(feature = "ringtail-verify")]
fn verify_ringtail_proof(
    env: &Env,
    _recipient: &Address,
    _amount: i128,
    _nonce: u64,
    proof: &Bytes,
) -> Result<(), BridgeError> {
    use seal_ringtail_verify::{
        verify as ringtail_verify, ntt::NttCtx, PublicParams,
        Signature as RtSig, RING_N,
    };

    const RING_BYTES: u32 = (RING_N as u32) * 8;
    const MODULE_K: usize = 8;
    const MIN_ENVELOPE: u32 =
        32 + 2 + 2 + 32 + RING_BYTES + (MODULE_K as u32) * RING_BYTES * 2;
    if proof.len() < MIN_ENVELOPE {
        log!(
            env,
            "Ringtail envelope too short: {} < {}",
            proof.len(),
            MIN_ENVELOPE
        );
        return Err(BridgeError::InvalidProof);
    }

    // Materialize the envelope into a single linear buffer so the
    // verifier can index into &[u8] slices.
    let mut envelope = [0u8; (MIN_ENVELOPE as usize)];
    let copy_len = MIN_ENVELOPE.min(proof.len());
    proof
        .slice(0..copy_len)
        .copy_into_slice(&mut envelope[..copy_len as usize]);

    let participant_count =
        u16::from_be_bytes([envelope[32], envelope[33]]) as usize;
    let threshold = u16::from_be_bytes([envelope[34], envelope[35]]) as usize;
    let challenge_bytes: &[u8; 32] = (&envelope[36..68])
        .try_into()
        .map_err(|_| BridgeError::InvalidProof)?;

    let z = &envelope[68..68 + RING_BYTES as usize];
    let mut a_off = 68 + RING_BYTES as usize;
    let mut matrix_a: [&[u8]; MODULE_K] = [&[]; MODULE_K];
    for slot in matrix_a.iter_mut().take(MODULE_K) {
        *slot = &envelope[a_off..a_off + RING_BYTES as usize];
        a_off += RING_BYTES as usize;
    }
    let mut t_off = a_off;
    let mut public_key_t: [&[u8]; MODULE_K] = [&[]; MODULE_K];
    for slot in public_key_t.iter_mut().take(MODULE_K) {
        *slot = &envelope[t_off..t_off + RING_BYTES as usize];
        t_off += RING_BYTES as usize;
    }

    let sig = RtSig {
        z,
        challenge: challenge_bytes,
        participant_count,
    };
    let pp = PublicParams { matrix_a, public_key_t };
    let ctx = NttCtx::new();

    // Algebraic verify. Once the signer pipes recipient/amount/nonce
    // through to the hashed message, replace `b""` with the canonical
    // bytes the host signs.
    if ringtail_verify(&ctx, &sig, &pp, b"", threshold).is_err() {
        log!(env, "Ringtail algebraic verify failed");
        return Err(BridgeError::InvalidProof);
    }

    Ok(())
}

/// HMAC-SHA-256 per RFC 2104, built on top of `Env::crypto().sha256`
/// (Soroban's SHA-256 host function). Block size 64; IPAD 0x36; OPAD
/// 0x5c. Keys longer than 64 bytes are pre-hashed. Inputs and output
/// use Soroban's `Bytes` / `BytesN<32>` to stay zero-allocation on
/// the guest heap.
fn hmac_sha256(env: &Env, key: &Bytes, message: &Bytes) -> BytesN<32> {
    const BLOCK: u32 = 64;
    let mut padded = [0u8; 64];
    if key.len() > BLOCK {
        let pre = env.crypto().sha256(key).to_array();
        padded[..32].copy_from_slice(&pre);
    } else {
        let mut i = 0u32;
        while i < key.len() {
            padded[i as usize] = key.get_unchecked(i);
            i += 1;
        }
    }

    let mut i_pad = [0u8; 64];
    let mut o_pad = [0u8; 64];
    for idx in 0..(BLOCK as usize) {
        i_pad[idx] = padded[idx] ^ 0x36;
        o_pad[idx] = padded[idx] ^ 0x5c;
    }

    let mut inner = Bytes::from_slice(env, &i_pad);
    inner.append(message);
    let inner_digest = env.crypto().sha256(&inner).to_array();

    let mut outer = Bytes::from_slice(env, &o_pad);
    outer.extend_from_slice(&inner_digest);
    env.crypto().sha256(&outer).into()
}

/// Constant-time byte-slice equality. Both sides must have identical
/// length; any mismatch returns false but does so after examining
/// every byte, so timing cannot reveal where the mismatch occurred.
fn ct_eq_bytes(a: &Bytes, b: &Bytes) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    let mut i = 0u32;
    while i < a.len() {
        diff |= a.get_unchecked(i) ^ b.get_unchecked(i);
        i += 1;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{
        token::{StellarAssetClient, TokenClient},
        Env,
    };

    /// Register a mock Stellar Asset Contract under `issuer` and
    /// return its address + a minting client.
    fn setup_sac(env: &Env) -> (Address, Address) {
        let issuer = Address::generate(env);
        let sac = env.register_stellar_asset_contract(issuer.clone());
        (sac, issuer)
    }

    /// A fixed 32-byte committee key used across tests. In production
    /// the committee rotates this each epoch.
    const TEST_COMMITTEE_KEY: [u8; 32] = [0x11u8; 32];

    /// Compute the same HMAC-SHA-256 over the canonical unlock
    /// message that `verify_proof` expects. Test-only helper so each
    /// test produces a real MAC; keeping it close to the contract's
    /// message layout means renames here force test rewrites too.
    fn make_committee_sig(
        env: &Env,
        recipient: &Address,
        amount: i128,
        nonce: u64,
    ) -> Bytes {
        let mut msg = Bytes::new(env);
        msg.append(&recipient.to_xdr(env));
        for byte in amount.to_be_bytes() {
            msg.push_back(byte);
        }
        for byte in nonce.to_be_bytes() {
            msg.push_back(byte);
        }
        msg.append(&Bytes::from_slice(env, BRIDGE_DOMAIN_TAG));
        let key = Bytes::from_slice(env, &TEST_COMMITTEE_KEY);
        hmac_sha256(env, &key, &msg).into()
    }

    #[test]
    fn test_initialize() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let (sac, _) = setup_sac(&env);

        client.initialize(&admin, &bridge_key, &sac);

        assert_eq!(client.get_total_locked(), 0);
        assert_eq!(client.get_nonce(), 0);
    }

    #[test]
    fn test_initialize_twice_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let (sac, _) = setup_sac(&env);

        client.initialize(&admin, &bridge_key, &sac);
        let result = client.try_initialize(&admin, &bridge_key, &sac);
        assert!(result.is_err());
    }

    #[test]
    fn test_lock_usdc_round_trip() {
        // Mirror of test_lock_xlm_moves_tokens_into_vault + the unlock
        // happy path. Asserts that:
        //   - set_usdc_sac stores the USDC SAC address
        //   - lock_usdc transfers from sender to the contract vault
        //   - the shared nonce counter advances
        //   - unlock_usdc with a valid committee MAC releases the funds
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let seal_address = BytesN::from_array(&env, &[0xCDu8; 32]);

        // Set up two separate SACs — one for XLM (passed to initialize),
        // one for USDC (installed via set_usdc_sac after init). The
        // contract has to track them in distinct storage slots.
        let (xlm_sac, _) = setup_sac(&env);
        let (usdc_sac, _) = setup_sac(&env);

        client.initialize(&admin, &bridge_key, &xlm_sac);
        client.set_usdc_sac(&usdc_sac);

        StellarAssetClient::new(&env, &usdc_sac).mint(&sender, &10_000_000);
        let usdc = TokenClient::new(&env, &usdc_sac);
        assert_eq!(usdc.balance(&sender), 10_000_000);
        assert_eq!(usdc.balance(&client.address), 0);

        client.lock_usdc(&sender, &2_000_000, &seal_address);

        assert_eq!(usdc.balance(&sender), 8_000_000);
        assert_eq!(usdc.balance(&client.address), 2_000_000);
        assert_eq!(client.get_total_usdc_locked(), 2_000_000);
        assert_eq!(client.get_nonce(), 1, "shared nonce advanced");

        // Unlock half to a recipient via the committee MAC.
        let proof = make_committee_sig(&env, &recipient, 1_000_000, 0);
        client.unlock_usdc(&recipient, &1_000_000, &0, &proof);
        assert_eq!(usdc.balance(&recipient), 1_000_000);
        assert_eq!(usdc.balance(&client.address), 1_000_000);
        assert_eq!(client.get_total_usdc_locked(), 1_000_000);
    }

    #[test]
    fn test_lock_usdc_without_sac_set_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let seal_address = BytesN::from_array(&env, &[0xEEu8; 32]);
        let (xlm_sac, _) = setup_sac(&env);

        client.initialize(&admin, &bridge_key, &xlm_sac);
        // No `set_usdc_sac` call → lock_usdc rejects.
        let result = client.try_lock_usdc(&sender, &1_000_000, &seal_address);
        assert!(result.is_err());
    }

    #[test]
    fn test_lock_xlm_moves_tokens_into_vault() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let seal_address = BytesN::from_array(&env, &[0xABu8; 32]);
        let (sac, _) = setup_sac(&env);

        StellarAssetClient::new(&env, &sac).mint(&sender, &10_000_000);
        client.initialize(&admin, &bridge_key, &sac);
        let token = TokenClient::new(&env, &sac);
        assert_eq!(token.balance(&sender), 10_000_000);
        assert_eq!(token.balance(&client.address), 0);

        client.lock_xlm(&sender, &1_000_000, &seal_address);

        assert_eq!(token.balance(&sender), 9_000_000);
        assert_eq!(token.balance(&client.address), 1_000_000);
        assert_eq!(client.get_total_locked(), 1_000_000);
        assert_eq!(client.get_nonce(), 1);
    }

    #[test]
    fn test_unlock_xlm_with_valid_committee_mac() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let seal_address = BytesN::from_array(&env, &[0xABu8; 32]);
        let (sac, _) = setup_sac(&env);

        StellarAssetClient::new(&env, &sac).mint(&sender, &10_000_000);
        client.initialize(&admin, &bridge_key, &sac);
        client.lock_xlm(&sender, &1_000_000, &seal_address);

        let proof = make_committee_sig(&env, &recipient, 500_000, 0);
        client.unlock_xlm(&recipient, &500_000, &0, &proof);

        let token = TokenClient::new(&env, &sac);
        assert_eq!(token.balance(&client.address), 500_000);
        assert_eq!(token.balance(&recipient), 500_000);
        assert_eq!(client.get_total_locked(), 500_000);
        assert!(client.is_nonce_processed(&0));
    }

    #[test]
    fn test_unlock_rejects_wrong_key() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let seal_address = BytesN::from_array(&env, &[0xABu8; 32]);
        let (sac, _) = setup_sac(&env);

        StellarAssetClient::new(&env, &sac).mint(&sender, &10_000_000);
        client.initialize(&admin, &bridge_key, &sac);
        client.lock_xlm(&sender, &1_000_000, &seal_address);

        // Compute a MAC with a wrong key — must be rejected.
        let wrong_key = Bytes::from_slice(&env, &[0x22u8; 32]);
        let mut msg = Bytes::new(&env);
        msg.append(&recipient.clone().to_xdr(&env));
        for byte in 500_000i128.to_be_bytes() {
            msg.push_back(byte);
        }
        for byte in 0u64.to_be_bytes() {
            msg.push_back(byte);
        }
        msg.append(&Bytes::from_slice(&env, BRIDGE_DOMAIN_TAG));
        let bad_proof: Bytes = hmac_sha256(&env, &wrong_key, &msg).into();

        let result = client.try_unlock_xlm(&recipient, &500_000, &0, &bad_proof);
        assert!(result.is_err(), "unlock with wrong key must fail");
    }

    #[test]
    fn test_unlock_rejects_flipped_bit() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let seal_address = BytesN::from_array(&env, &[0xABu8; 32]);
        let (sac, _) = setup_sac(&env);

        StellarAssetClient::new(&env, &sac).mint(&sender, &10_000_000);
        client.initialize(&admin, &bridge_key, &sac);
        client.lock_xlm(&sender, &1_000_000, &seal_address);

        // Valid proof, then flip one bit.
        let good_proof_bytes = make_committee_sig(&env, &recipient, 500_000, 0);
        let good_fixed: BytesN<32> = good_proof_bytes.try_into().unwrap();
        let mut tampered = good_fixed.to_array();
        tampered[0] ^= 1;
        let tampered_bytes = Bytes::from_slice(&env, &tampered);

        let result = client.try_unlock_xlm(&recipient, &500_000, &0, &tampered_bytes);
        assert!(result.is_err(), "bit-flipped MAC must fail");
    }

    #[test]
    fn test_unlock_rejects_wrong_length() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let seal_address = BytesN::from_array(&env, &[0xABu8; 32]);
        let (sac, _) = setup_sac(&env);

        StellarAssetClient::new(&env, &sac).mint(&sender, &10_000_000);
        client.initialize(&admin, &bridge_key, &sac);
        client.lock_xlm(&sender, &1_000_000, &seal_address);

        let short = Bytes::from_slice(&env, &[0u8; 31]);
        let result = client.try_unlock_xlm(&recipient, &500_000, &0, &short);
        assert!(result.is_err(), "wrong-length proof must fail");
    }

    #[test]
    fn test_unlock_replay_protection() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let seal_address = BytesN::from_array(&env, &[0xABu8; 32]);
        let (sac, _) = setup_sac(&env);

        StellarAssetClient::new(&env, &sac).mint(&sender, &10_000_000);
        client.initialize(&admin, &bridge_key, &sac);
        client.lock_xlm(&sender, &2_000_000, &seal_address);

        let proof = make_committee_sig(&env, &recipient, 500_000, 0);
        client.unlock_xlm(&recipient, &500_000, &0, &proof);

        let result = client.try_unlock_xlm(&recipient, &500_000, &0, &proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_pause_defaults_to_false_after_initialize() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let (sac, _) = setup_sac(&env);

        client.initialize(&admin, &bridge_key, &sac);
        assert!(!client.is_paused());
    }

    #[test]
    fn test_set_pause_toggles_flag() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let (sac, _) = setup_sac(&env);

        client.initialize(&admin, &bridge_key, &sac);
        client.set_pause(&true);
        assert!(client.is_paused());
        client.set_pause(&false);
        assert!(!client.is_paused());
    }

    #[test]
    fn test_lock_xlm_rejected_when_paused() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let seal_address = BytesN::from_array(&env, &[0xABu8; 32]);
        let (sac, _) = setup_sac(&env);

        StellarAssetClient::new(&env, &sac).mint(&sender, &10_000_000);
        client.initialize(&admin, &bridge_key, &sac);
        client.set_pause(&true);

        let result = client.try_lock_xlm(&sender, &1_000_000, &seal_address);
        assert!(result.is_err(), "lock_xlm must reject while paused");

        // Vault balance and counters unchanged.
        let token = TokenClient::new(&env, &sac);
        assert_eq!(token.balance(&sender), 10_000_000);
        assert_eq!(token.balance(&client.address), 0);
        assert_eq!(client.get_total_locked(), 0);
        assert_eq!(client.get_nonce(), 0);
    }

    #[test]
    fn test_unlock_xlm_rejected_when_paused() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let seal_address = BytesN::from_array(&env, &[0xABu8; 32]);
        let (sac, _) = setup_sac(&env);

        StellarAssetClient::new(&env, &sac).mint(&sender, &10_000_000);
        client.initialize(&admin, &bridge_key, &sac);
        client.lock_xlm(&sender, &1_000_000, &seal_address);

        // Pause AFTER lock so the vault has 1_000_000 to unlock.
        client.set_pause(&true);
        let proof = make_committee_sig(&env, &recipient, 500_000, 0);
        let result = client.try_unlock_xlm(&recipient, &500_000, &0, &proof);
        assert!(result.is_err(), "unlock_xlm must reject while paused");

        // Nonce not consumed; vault still holds the locked balance.
        assert!(!client.is_nonce_processed(&0));
        assert_eq!(client.get_total_locked(), 1_000_000);
    }

    #[test]
    fn test_unlock_xlm_succeeds_after_unpause() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let seal_address = BytesN::from_array(&env, &[0xABu8; 32]);
        let (sac, _) = setup_sac(&env);

        StellarAssetClient::new(&env, &sac).mint(&sender, &10_000_000);
        client.initialize(&admin, &bridge_key, &sac);
        client.lock_xlm(&sender, &1_000_000, &seal_address);

        // Pause, fail, unpause, succeed — verifies the flag is the
        // only gate (no leftover state from the failed attempt).
        client.set_pause(&true);
        let proof = make_committee_sig(&env, &recipient, 500_000, 0);
        let _ = client.try_unlock_xlm(&recipient, &500_000, &0, &proof);
        client.set_pause(&false);
        client.unlock_xlm(&recipient, &500_000, &0, &proof);

        assert!(client.is_nonce_processed(&0));
        assert_eq!(client.get_total_locked(), 500_000);
    }

    #[test]
    fn test_rotate_committee_key_changes_verification() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let seal_address = BytesN::from_array(&env, &[0xABu8; 32]);
        let (sac, _) = setup_sac(&env);

        StellarAssetClient::new(&env, &sac).mint(&sender, &10_000_000);
        client.initialize(&admin, &bridge_key, &sac);
        client.lock_xlm(&sender, &1_000_000, &seal_address);

        // Before rotation, a MAC made with TEST_COMMITTEE_KEY verifies.
        let old_proof = make_committee_sig(&env, &recipient, 500_000, 0);

        // Rotate to a new key.
        let new_key = BytesN::from_array(&env, &[0x22u8; 32]);
        client.rotate_committee_key(&new_key);

        // Same proof should now be rejected — keyed by the OLD key.
        let result = client.try_unlock_xlm(&recipient, &500_000, &0, &old_proof);
        assert!(result.is_err(), "proof under old key must fail after rotation");
    }

    #[test]
    fn test_committee_key_hash_view() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &TEST_COMMITTEE_KEY);
        let (sac, _) = setup_sac(&env);

        // Pre-init: returns all-zero (sentinel for "not yet ready").
        let pre_init_hash = client.committee_key_hash();
        assert_eq!(pre_init_hash, BytesN::from_array(&env, &[0u8; 32]));

        // After initialize: matches env.crypto().sha256(committee_key)
        // — same as host-side seal_bridgeGetCommitteeKeyStatus
        // .fingerprint_sha2_hex.
        client.initialize(&admin, &bridge_key, &sac);
        let post_init_hash = client.committee_key_hash();
        let expected: BytesN<32> = env
            .crypto()
            .sha256(&Bytes::from_slice(&env, &TEST_COMMITTEE_KEY))
            .into();
        assert_eq!(post_init_hash, expected,
            "committee_key_hash must equal SHA-256(committee_key) post-init");

        // After rotation: hash updates to the new key's SHA-256.
        let new_key = [0x33u8; 32];
        client.rotate_committee_key(&BytesN::from_array(&env, &new_key));
        let rotated_hash = client.committee_key_hash();
        let new_expected: BytesN<32> = env
            .crypto()
            .sha256(&Bytes::from_slice(&env, &new_key))
            .into();
        assert_eq!(rotated_hash, new_expected,
            "committee_key_hash must reflect the rotated key");
        assert_ne!(rotated_hash, post_init_hash,
            "rotated hash must differ from pre-rotation hash");
    }
}
