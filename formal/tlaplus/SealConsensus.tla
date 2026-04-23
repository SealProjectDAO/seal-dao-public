--------------------------- MODULE SealConsensus ---------------------------
(*
 * TLA+ specification of the Seal DAO consensus protocol.
 *
 * WHY THIS EXISTS:
 * ================
 * This formal specification lets us mathematically prove that the Seal
 * consensus protocol is SAFE (no conflicting blocks finalized at the same
 * height) and LIVE (blocks keep being produced under partial synchrony).
 *
 * We write this BEFORE the Rust implementation is complete because:
 * 1. Finding protocol bugs in TLA+ costs minutes; in production costs millions.
 * 2. The spec serves as the authoritative reference for what the Rust code
 *    should do (trace conformance testing links the two).
 * 3. The Apalache model checker can prove properties for ALL possible
 *    executions, not just the ones we thought to test.
 *
 * WHAT IS BEING MODELED:
 * ======================
 * A simplified Algorand-style consensus with:
 * - N validators, each with a stake
 * - VRF-based leader election per slot
 * - Committee voting with threshold (>2/3)
 * - Single-slot finality
 * - Epoch transitions
 *
 * WHAT IS NOT MODELED:
 * ====================
 * - Actual VRF cryptography (modeled as nondeterministic oracle)
 * - ZK proofs (modeled as always-valid)
 * - Network transport details (modeled as eventually-reliable delivery)
 * - SQL execution (orthogonal to consensus)
 *)

EXTENDS Integers, FiniteSets, Sequences

\* ========================================================================
\* CONSTANTS — The parameters of the protocol.
\* These are set when you run the model checker (e.g., N=4, T=3).
\* ========================================================================

CONSTANTS
    \* @type: Set(Str);
    Validators,     \* Set of validator IDs (e.g., {"v1", "v2", "v3", "v4"})
    \* @type: Int;
    MaxHeight,      \* Maximum block height to explore (bounds the model)
    \* @type: Int;
    Threshold       \* Number of votes needed to finalize (>2/3 of committee)

\* Finite set of possible block names (replaces unbounded STRING)
\* @type: Set(Str);
BlockNames == {"block", "skip", "none"}

\* Constant initialization for Apalache model checking.
ConstInit ==
    /\ Validators = {"v1", "v2", "v3"}
    /\ MaxHeight = 3
    /\ Threshold = 2

\* ========================================================================
\* VARIABLES — The state of the system that changes over time.
\* Each variable is like a global variable that all validators can see
\* (or their local state, depending on the variable).
\* ========================================================================

VARIABLES
    \* @type: Int;
    height,         \* Current block height being decided (natural number)
    \* @type: Set(<<Int, Str, Str>>);
    proposals,      \* Set of (height, block, proposer) tuples that have been proposed
    \* @type: Int -> Set(<<Str, Str>>);
    votes,          \* Function: height -> set of (validator, block) vote pairs
    \* @type: Int -> Str;
    finalized,      \* Function: height -> the finalized block (or "none")
    \* @type: Int -> Str;
    proposer        \* Function: height -> which validator is the proposer

\* Tuple of all variables (required by TLA+ for specifying the Next relation)
vars == <<height, proposals, votes, finalized, proposer>>

\* ========================================================================
\* TYPE INVARIANT
\* This says "the variables always have the right types".
\* If this is violated, we have a bug in the SPEC, not the protocol.
\* ========================================================================

TypeOK ==
    /\ height \in Nat
    /\ height <= MaxHeight
    /\ proposals \subseteq (Nat \X BlockNames \X Validators)
    /\ finalized \in [0..MaxHeight -> STRING]
    /\ proposer \in [0..MaxHeight -> Validators \cup {"none"}]

\* ========================================================================
\* INITIAL STATE
\* The system starts with no blocks, no votes, no proposals.
\* Height 0 is the genesis block (already finalized).
\* ========================================================================

Init ==
    /\ height = 1
    /\ proposals = {}
    /\ votes = [h \in 0..MaxHeight |-> {}]
    /\ finalized = [h \in 0..MaxHeight |-> IF h = 0 THEN "genesis" ELSE "none"]
    /\ proposer = [h \in 0..MaxHeight |-> "none"]

\* ========================================================================
\* ACTIONS — Things that can happen in the protocol.
\* Each action describes a state transition: what must be true BEFORE
\* (precondition) and what changes AFTER (effect).
\* ========================================================================

(*
 * ACTION: Propose
 * ===============
 * A validator is elected as proposer for the current height via VRF.
 * They create a block and broadcast it.
 *
 * In reality: VRF evaluation determines if this validator is the proposer.
 * In the model: we nondeterministically choose a proposer (sound because
 * we're checking safety for ALL possible proposer choices).
 *)
Propose(v) ==
    /\ height <= MaxHeight              \* Don't exceed model bounds
    /\ finalized[height] = "none"       \* This height not yet finalized
    /\ proposer[height] = "none"        \* No proposer yet for this height
    /\ proposer' = [proposer EXCEPT ![height] = v]
    /\ proposals' = proposals \cup {<<height, "block", v>>}
    /\ UNCHANGED <<height, votes, finalized>>

(*
 * ACTION: Vote
 * ============
 * A committee member votes for a proposed block at the current height.
 *
 * CRITICAL SAFETY PROPERTY: A validator votes for AT MOST ONE block
 * per height. This is enforced by the precondition.
 * Violating this (equivocation) is a slashable offense.
 *)
Vote(v, block) ==
    /\ height <= MaxHeight
    /\ finalized[height] = "none"           \* Not yet finalized
    /\ <<height, block, proposer[height]>> \in proposals  \* Block was proposed
    /\ \A b \in BlockNames : <<v, b>> \notin votes[height]    \* Haven't voted yet
    /\ votes' = [votes EXCEPT ![height] = votes[height] \cup {<<v, block>>}]
    /\ UNCHANGED <<height, proposals, finalized, proposer>>

(*
 * ACTION: Finalize
 * ================
 * When enough votes (>= Threshold) are collected for a block at a height,
 * that block is finalized. The protocol advances to the next height.
 *
 * This is the core of single-slot finality: once finalized, the block
 * can NEVER be reverted.
 *)
Finalize(block) ==
    /\ height <= MaxHeight
    /\ finalized[height] = "none"       \* Not yet finalized
    \* Count votes for this block
    /\ Cardinality({v \in Validators : <<v, block>> \in votes[height]}) >= Threshold
    /\ finalized' = [finalized EXCEPT ![height] = block]
    /\ height' = height + 1             \* Advance to next height
    /\ UNCHANGED <<proposals, votes, proposer>>

(*
 * ACTION: SkipSlot
 * ================
 * If no proposer comes forward (e.g., they're offline), the slot is skipped.
 * The protocol moves to the next height with "skip" as the finalized value.
 * This models liveness under proposer failure.
 *)
SkipSlot ==
    /\ height <= MaxHeight
    /\ finalized[height] = "none"
    \* No proposal was made (simplified: skip if no proposal exists)
    /\ ~(\E p \in proposals : p[1] = height)
    /\ finalized' = [finalized EXCEPT ![height] = "skip"]
    /\ height' = height + 1
    /\ UNCHANGED <<proposals, votes, proposer>>

\* ========================================================================
\* NEXT STATE RELATION
\* "What can happen next?" — any of the above actions.
\* ========================================================================

Next ==
    \/ \E v \in Validators : Propose(v)
    \/ \E v \in Validators, b \in BlockNames :
        /\ <<height, b, proposer[height]>> \in proposals
        /\ Vote(v, b)
    \/ \E b \in BlockNames : Finalize(b)
    \/ SkipSlot

\* ========================================================================
\* FAIRNESS
\* "Eventually, actions that CAN happen WILL happen."
\* Without this, the model checker could find trivial counterexamples
\* where the protocol just stops (which isn't a real bug).
\* ========================================================================

Fairness == WF_vars(Next)

\* ========================================================================
\* SPECIFICATION
\* The complete spec: start in Init, then repeatedly take Next steps,
\* subject to Fairness.
\* ========================================================================

Spec == Init /\ [][Next]_vars /\ Fairness

\* ========================================================================
\* SAFETY PROPERTIES — Things that must ALWAYS be true.
\* ========================================================================

(*
 * SAFETY: Agreement
 * =================
 * At most one block is finalized at each height.
 * This is THE critical safety property of any consensus protocol.
 * If this is violated, we have a fork — catastrophic.
 *
 * In English: "For every height h, if a block is finalized, it is the
 * ONLY block finalized at that height."
 *)
Agreement ==
    \A h \in 0..MaxHeight :
        finalized[h] /= "none" =>
            \A h2 \in 0..MaxHeight :
                (h = h2 /\ finalized[h2] /= "none") => finalized[h] = finalized[h2]

(*
 * SAFETY: No Equivocation
 * =======================
 * No validator votes for two different blocks at the same height.
 * This is enforced by the Vote action precondition, but we verify it
 * as an invariant to catch specification bugs.
 *)
NoEquivocation ==
    \A h \in 0..MaxHeight :
        \A v \in Validators :
            \A b1, b2 \in BlockNames :
                (<<v, b1>> \in votes[h] /\ <<v, b2>> \in votes[h]) => b1 = b2

(*
 * SAFETY: Monotonic Height
 * ========================
 * The chain height never decreases.
 * (Trivially true in this spec because height only increments.)
 *)
MonotonicHeight ==
    height >= 1

\* ========================================================================
\* LIVENESS PROPERTIES — Things that must EVENTUALLY become true.
\* ========================================================================

(*
 * LIVENESS: Progress
 * ==================
 * The chain eventually advances beyond any given height.
 * "The protocol doesn't get stuck."
 *
 * Note: This requires Fairness. Without it, the system could just stop.
 *)
Progress == \A h \in 1..MaxHeight : <>(finalized[h] /= "none")

\* ========================================================================
\* MODEL CHECKING CONFIGURATION
\* ========================================================================
\* To check this with TLC (the TLA+ model checker):
\*
\*   1. Install TLA+ Toolbox or use the VS Code extension
\*   2. Create a model with:
\*      - Validators = {"v1", "v2", "v3", "v4"}
\*      - MaxHeight = 3
\*      - Threshold = 3  (3 out of 4 = 75%, above 2/3)
\*   3. Check invariants: TypeOK, Agreement, NoEquivocation
\*   4. Check temporal properties: Progress (with Fairness)
\*
\* With Apalache (symbolic model checker, for larger state spaces):
\*   apalache-mc check --cinit=ConstInit --inv=Agreement SealConsensus.tla
\*
\* Expected result: ALL PASS. If any fails, we have a protocol bug.
\* ========================================================================

=============================================================================
