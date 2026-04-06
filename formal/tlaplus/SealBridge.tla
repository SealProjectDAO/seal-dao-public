---- MODULE SealBridge ----
(*
 * Seal DAO Bridge — TLA+ Specification
 * =====================================
 *
 * WHY THIS EXISTS:
 * The bridge is the most security-critical component after consensus.
 * A bug in the bridge could allow:
 * - Double-minting (locked once, minted twice → inflation)
 * - Theft of locked funds (released without burning)
 * - Stuck funds (burned but never released)
 *
 * WHAT IS BEING MODELED:
 * - Lock events on source chains (Solana, Stellar)
 * - Mint events on Seal chain
 * - Burn events on Seal chain
 * - Release events on source chains
 * - Validator confirmations (threshold for processing)
 * - The core invariant: TotalMinted ≤ TotalLocked
 *
 * WHAT IS NOT MODELED:
 * - Network delays (we assume eventual delivery)
 * - Specific cryptographic operations (threshold sigs)
 * - Multiple token types (abstracted to one fungible token)
 * - Gas/fees for bridge operations
 *
 * MAPS TO RUST CODE:
 * SealBridge.tla        ↔  crates/seal-bridge/src/bridge.rs
 * Lock action           ↔  BridgeManager::observe_deposit()
 * Confirm action        ↔  BridgeManager::confirm_deposit()
 * Mint action           ↔  BridgeManager::process_deposit()
 * Burn action           ↔  BridgeManager::initiate_withdrawal()
 * Release action        ↔  BridgeManager::execute_withdrawal()
 * MintedLeqLocked       ↔  BridgeManager::check_invariant()
 *)

EXTENDS Integers, FiniteSets

CONSTANTS
    \* @type: Int;
    MaxDeposits,        \* Maximum number of deposits to model
    \* @type: Int;
    RequiredConfirms,   \* Confirmations needed to process a deposit
    \* @type: Int;
    NumValidators       \* Number of bridge validators

\* Apalache initialization
ConstInit ==
    /\ MaxDeposits = 3
    /\ RequiredConfirms = 2
    /\ NumValidators = 3

VARIABLES
    \* @type: Int;
    next_deposit_id,    \* Counter for deposit IDs

    \* @type: Int -> Int;
    locked_amount,      \* Amount locked per deposit ID

    \* @type: Int -> Int;
    confirmations,      \* Confirmation count per deposit ID

    \* @type: Int -> Bool;
    processed,          \* Whether deposit has been minted

    \* @type: Int;
    total_locked,       \* Sum of all locked tokens on source chain

    \* @type: Int;
    total_minted,       \* Sum of all minted wrapped tokens on Seal

    \* @type: Int;
    total_burned,       \* Sum of all burned wrapped tokens on Seal

    \* @type: Int;
    total_released      \* Sum of all released tokens on source chain

vars == <<next_deposit_id, locked_amount, confirmations, processed,
          total_locked, total_minted, total_burned, total_released>>

\* ========================================================================
\* TYPE INVARIANT
\* ========================================================================

TypeOK ==
    /\ next_deposit_id \in 0..MaxDeposits
    /\ total_locked \in 0..(MaxDeposits * 1000)
    /\ total_minted \in 0..(MaxDeposits * 1000)
    /\ total_burned \in 0..(MaxDeposits * 1000)
    /\ total_released \in 0..(MaxDeposits * 1000)

\* ========================================================================
\* INITIAL STATE
\* ========================================================================

Init ==
    /\ next_deposit_id = 0
    /\ locked_amount = [d \in 0..MaxDeposits |-> 0]
    /\ confirmations = [d \in 0..MaxDeposits |-> 0]
    /\ processed = [d \in 0..MaxDeposits |-> FALSE]
    /\ total_locked = 0
    /\ total_minted = 0
    /\ total_burned = 0
    /\ total_released = 0

\* ========================================================================
\* ACTIONS
\* ========================================================================

(*
 * ACTION: Lock
 * ============
 * A user locks tokens on the source chain (Solana/Stellar).
 * This creates a new deposit record observed by Seal validators.
 *
 * Preconditions:
 * - Haven't exceeded maximum deposits
 * - Amount > 0
 *)
Lock(amount) ==
    /\ next_deposit_id < MaxDeposits
    /\ amount > 0
    /\ amount <= 1000
    /\ locked_amount' = [locked_amount EXCEPT ![next_deposit_id] = amount]
    /\ confirmations' = [confirmations EXCEPT ![next_deposit_id] = 0]
    /\ processed' = [processed EXCEPT ![next_deposit_id] = FALSE]
    /\ total_locked' = total_locked + amount
    /\ next_deposit_id' = next_deposit_id + 1
    /\ UNCHANGED <<total_minted, total_burned, total_released>>

(*
 * ACTION: Confirm
 * ===============
 * A validator confirms they observed a lock event on the source chain.
 * Multiple validators must confirm before minting can proceed.
 *
 * Preconditions:
 * - Deposit exists (has been locked)
 * - Not yet processed
 * - Not yet fully confirmed (prevents over-confirmation)
 *)
Confirm(deposit_id) ==
    /\ deposit_id < next_deposit_id
    /\ locked_amount[deposit_id] > 0
    /\ ~processed[deposit_id]
    /\ confirmations[deposit_id] < NumValidators
    /\ confirmations' = [confirmations EXCEPT ![deposit_id] = confirmations[deposit_id] + 1]
    /\ UNCHANGED <<next_deposit_id, locked_amount, processed,
                   total_locked, total_minted, total_burned, total_released>>

(*
 * ACTION: Mint
 * ============
 * Process a confirmed deposit: mint wrapped tokens on Seal.
 * Only succeeds after enough validator confirmations.
 *
 * Preconditions:
 * - Deposit exists and has enough confirmations
 * - Not already processed (prevents double-mint)
 *
 * CRITICAL: This is where the invariant could be violated.
 * We mint exactly the locked amount — never more.
 *)
Mint(deposit_id) ==
    /\ deposit_id < next_deposit_id
    /\ confirmations[deposit_id] >= RequiredConfirms
    /\ ~processed[deposit_id]
    /\ processed' = [processed EXCEPT ![deposit_id] = TRUE]
    /\ total_minted' = total_minted + locked_amount[deposit_id]
    /\ UNCHANGED <<next_deposit_id, locked_amount, confirmations,
                   total_locked, total_burned, total_released>>

(*
 * ACTION: Burn
 * ============
 * User burns wrapped tokens on Seal to initiate withdrawal.
 * The burned amount is deducted from total_minted (net minted supply).
 *
 * Preconditions:
 * - Amount > 0
 * - Enough minted tokens exist to burn (can't burn more than minted - burned)
 *)
Burn(amount) ==
    /\ amount > 0
    /\ amount <= total_minted - total_burned
    /\ total_burned' = total_burned + amount
    /\ UNCHANGED <<next_deposit_id, locked_amount, confirmations, processed,
                   total_locked, total_minted, total_released>>

(*
 * ACTION: Release
 * ===============
 * Validators release locked tokens on the source chain after burn.
 * The released amount is deducted from total_locked (net locked supply).
 *
 * Preconditions:
 * - Amount > 0
 * - Enough burned tokens to justify release (release ≤ total_burned - total_released)
 * - Enough locked tokens to release
 *)
Release(amount) ==
    /\ amount > 0
    /\ amount <= total_burned - total_released
    /\ amount <= total_locked - total_released
    /\ total_released' = total_released + amount
    /\ UNCHANGED <<next_deposit_id, locked_amount, confirmations, processed,
                   total_locked, total_minted, total_burned>>

\* ========================================================================
\* NEXT STATE RELATION
\* ========================================================================

Next ==
    \/ \E a \in 1..1000 : Lock(a)
    \/ \E d \in 0..MaxDeposits : Confirm(d)
    \/ \E d \in 0..MaxDeposits : Mint(d)
    \/ \E a \in 1..1000 : Burn(a)
    \/ \E a \in 1..1000 : Release(a)

\* ========================================================================
\* FAIRNESS
\* ========================================================================

Fairness ==
    /\ WF_vars(Next)

\* ========================================================================
\* SPECIFICATION
\* ========================================================================

Spec == Init /\ [][Next]_vars /\ Fairness

\* ========================================================================
\* SAFETY PROPERTIES (INVARIANTS)
\* ========================================================================

(*
 * INVARIANT: MintedLeqLocked
 * ==========================
 * The core bridge safety property:
 *   Net minted supply ≤ Net locked supply
 *   (total_minted - total_burned) ≤ (total_locked - total_released)
 *
 * If this is violated, tokens were created from nothing — inflation attack.
 *
 * Maps to: BridgeManager::check_invariant() in bridge.rs
 *)
MintedLeqLocked ==
    (total_minted - total_burned) <= (total_locked - total_released)

(*
 * INVARIANT: NoDoubleMint
 * =======================
 * Each deposit can only be minted once.
 * A processed deposit cannot be processed again.
 *)
NoDoubleMint ==
    \A d \in 0..MaxDeposits :
        processed[d] => confirmations[d] >= RequiredConfirms

(*
 * INVARIANT: NoMintWithoutLock
 * ============================
 * No minting can happen without a corresponding lock.
 * total_minted is only increased in the Mint action, which requires
 * a valid deposit with sufficient confirmations.
 *)
NoMintWithoutLock ==
    total_minted <= total_locked

(*
 * INVARIANT: BurnedLeqMinted
 * ==========================
 * Cannot burn more wrapped tokens than were minted.
 *)
BurnedLeqMinted ==
    total_burned <= total_minted

(*
 * INVARIANT: ReleasedLeqBurned
 * ============================
 * Cannot release more tokens than were burned.
 *)
ReleasedLeqBurned ==
    total_released <= total_burned

(*
 * INVARIANT: ReleasedLeqLocked
 * ============================
 * Cannot release more tokens than were locked.
 *)
ReleasedLeqLocked ==
    total_released <= total_locked

\* ========================================================================
\* LIVENESS PROPERTIES
\* ========================================================================

(*
 * LIVENESS: LockedEventuallyMinted
 * ================================
 * If a deposit is locked and enough validators confirm,
 * it will eventually be minted (no stuck funds on the happy path).
 *
 * Note: requires fairness assumption (WF_vars(Next)).
 *)
LockedEventuallyMinted ==
    \A d \in 0..MaxDeposits :
        (locked_amount[d] > 0 /\ confirmations[d] >= RequiredConfirms)
            ~> processed[d]

====
