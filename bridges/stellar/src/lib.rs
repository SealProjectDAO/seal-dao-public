#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, contracterror, symbol_short, Address, Bytes, BytesN, Env,
    log,
};

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

const ADMIN_KEY: &str = "admin";
const BRIDGE_KEY: &str = "brkey";
const TOTAL_LOCKED: &str = "locked";
const NONCE_KEY: &str = "nonce";

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
    /// Must be called exactly once. Sets the admin address and the Seal DAO
    /// committee public key used for verifying unlock proofs.
    ///
    /// # Arguments
    /// * `env` - Soroban environment
    /// * `admin` - Address that can perform admin operations
    /// * `seal_bridge_key` - The Seal DAO committee's public key (32 bytes)
    ///                       used to verify threshold signatures on unlocks
    pub fn initialize(
        env: Env,
        admin: Address,
        seal_bridge_key: BytesN<32>,
    ) -> Result<(), BridgeError> {
        // Ensure not already initialized
        if env.storage().instance().has(&symbol_short!(ADMIN_KEY)) {
            return Err(BridgeError::AlreadyInitialized);
        }

        env.storage()
            .instance()
            .set(&symbol_short!(ADMIN_KEY), &admin);
        env.storage()
            .instance()
            .set(&symbol_short!(BRIDGE_KEY), &seal_bridge_key);
        env.storage()
            .instance()
            .set(&symbol_short!(TOTAL_LOCKED), &0i128);
        env.storage()
            .instance()
            .set(&symbol_short!(NONCE_KEY), &0u64);

        log!(&env, "Seal bridge initialized. Admin: {}", admin);

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
        if !env.storage().instance().has(&symbol_short!(ADMIN_KEY)) {
            return Err(BridgeError::NotInitialized);
        }

        // Require sender authorization
        sender.require_auth();

        // Validate amount
        if amount <= 0 {
            return Err(BridgeError::InvalidAmount);
        }

        // TODO: Actually transfer XLM from sender to this contract.
        // This requires integrating with the Stellar Asset Contract (SAC)
        // for the native XLM token. For the skeleton we just track state.
        //
        // Example (once SAC client is set up):
        //   let xlm_client = token::Client::new(&env, &xlm_contract_id);
        //   xlm_client.transfer(&sender, &env.current_contract_address(), &amount);

        // Update total locked
        let total_locked: i128 = env
            .storage()
            .instance()
            .get(&symbol_short!(TOTAL_LOCKED))
            .unwrap_or(0);
        let new_total = total_locked
            .checked_add(amount)
            .ok_or(BridgeError::InsufficientBalance)?;
        env.storage()
            .instance()
            .set(&symbol_short!(TOTAL_LOCKED), &new_total);

        // Increment and read nonce
        let nonce: u64 = env
            .storage()
            .instance()
            .get(&symbol_short!(NONCE_KEY))
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&symbol_short!(NONCE_KEY), &(nonce + 1));

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
        if !env.storage().instance().has(&symbol_short!(ADMIN_KEY)) {
            return Err(BridgeError::NotInitialized);
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

        // Verify the threshold signature / proof
        // TODO: Real ML-DSA (post-quantum) threshold signature verification.
        // Currently a placeholder that accepts any non-empty proof.
        // In production this MUST verify a Ringtail threshold signature
        // from the Seal DAO committee over (recipient, amount, nonce).
        verify_proof(&env, &recipient, amount, nonce, &proof)?;

        // Mark nonce as processed
        env.storage().persistent().set(&nonce_key, &true);

        // Update total locked
        let total_locked: i128 = env
            .storage()
            .instance()
            .get(&symbol_short!(TOTAL_LOCKED))
            .unwrap_or(0);
        let new_total = total_locked
            .checked_sub(amount)
            .ok_or(BridgeError::InsufficientBalance)?;
        env.storage()
            .instance()
            .set(&symbol_short!(TOTAL_LOCKED), &new_total);

        // TODO: Actually transfer XLM from this contract to recipient.
        // Requires SAC integration, same as lock_xlm above.
        //
        // Example:
        //   let xlm_client = token::Client::new(&env, &xlm_contract_id);
        //   xlm_client.transfer(&env.current_contract_address(), &recipient, &amount);

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

    // -----------------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------------

    /// Returns the total amount of XLM currently locked in the bridge.
    pub fn get_total_locked(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&symbol_short!(TOTAL_LOCKED))
            .unwrap_or(0)
    }

    /// Returns the current nonce (number of locks processed).
    pub fn get_nonce(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&symbol_short!(NONCE_KEY))
            .unwrap_or(0)
    }

    /// Check if a given unlock nonce has already been processed.
    pub fn is_nonce_processed(env: Env, nonce: u64) -> bool {
        let nonce_key = nonce_storage_key(&env, nonce);
        env.storage().persistent().has(&nonce_key)
    }
}

// ---------------------------------------------------------------------------
// Proof verification (STUB)
// ---------------------------------------------------------------------------

/// TODO: Replace with real ML-DSA threshold signature verification.
///
/// In production, this function must:
/// 1. Retrieve the committee public key from storage (seal_bridge_key)
/// 2. Reconstruct the message: (recipient || amount || nonce)
/// 3. Verify the Ringtail threshold signature against the committee key
///
/// The Seal DAO committee uses Ringtail (lattice-based threshold signatures)
/// which provides post-quantum security.
fn verify_proof(
    _env: &Env,
    _recipient: &Address,
    _amount: i128,
    _nonce: u64,
    proof: &Bytes,
) -> Result<(), BridgeError> {
    // SKELETON: Accept any non-empty proof for development/testing.
    // This MUST be replaced before any mainnet deployment.
    if proof.len() == 0 {
        return Err(BridgeError::InvalidProof);
    }
    log!(
        _env,
        "WARNING: Proof verification is stubbed out. Do NOT deploy to mainnet."
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    #[test]
    fn test_initialize() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &[0u8; 32]);

        client.initialize(&admin, &bridge_key);

        assert_eq!(client.get_total_locked(), 0);
        assert_eq!(client.get_nonce(), 0);
    }

    #[test]
    fn test_initialize_twice_fails() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &[0u8; 32]);

        client.initialize(&admin, &bridge_key);

        // Second initialization should fail
        let result = client.try_initialize(&admin, &bridge_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_lock_xlm() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &[0u8; 32]);
        let seal_address = BytesN::from_array(&env, &[0xABu8; 32]);

        client.initialize(&admin, &bridge_key);
        client.lock_xlm(&sender, &1_000_000, &seal_address);

        assert_eq!(client.get_total_locked(), 1_000_000);
        assert_eq!(client.get_nonce(), 1);
    }

    #[test]
    fn test_unlock_xlm() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, SealBridgeContract);
        let client = SealBridgeContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let bridge_key = BytesN::from_array(&env, &[0u8; 32]);
        let seal_address = BytesN::from_array(&env, &[0xABu8; 32]);

        client.initialize(&admin, &bridge_key);

        // Lock first
        client.lock_xlm(&sender, &1_000_000, &seal_address);

        // Unlock with dummy proof
        let proof = Bytes::from_slice(&env, &[0x01, 0x02, 0x03]);
        client.unlock_xlm(&recipient, &500_000, &0, &proof);

        assert_eq!(client.get_total_locked(), 500_000);
        assert!(client.is_nonce_processed(&0));
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
        let bridge_key = BytesN::from_array(&env, &[0u8; 32]);
        let seal_address = BytesN::from_array(&env, &[0xABu8; 32]);

        client.initialize(&admin, &bridge_key);
        client.lock_xlm(&sender, &2_000_000, &seal_address);

        let proof = Bytes::from_slice(&env, &[0x01, 0x02, 0x03]);
        client.unlock_xlm(&recipient, &500_000, &0, &proof);

        // Second unlock with same nonce should fail
        let result = client.try_unlock_xlm(&recipient, &500_000, &0, &proof);
        assert!(result.is_err());
    }
}
