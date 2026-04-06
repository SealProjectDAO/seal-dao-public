--------------------------- MODULE SealCompositeProof ---------------------------
(*
 * TLA+ specification of the Seal composite proof architecture.
 *
 * WHY THIS EXISTS:
 * ================
 * Seal splits block verification into 3 independent layers:
 *   Layer 1: ML-DSA signature verification (native)
 *   Layer 2: ZK proof of state transition (STARK)
 *   Layer 3: Consensus assertions (VRF + threshold sig)
 *
 * We must prove that this composition is SOUND:
 * - A block is valid IFF all 3 layers pass
 * - No layer can compensate for another's failure
 * - There is no "gap" between layers (everything is checked)
 *
 * See ZK-PROOF-ARCHITECTURE.md for the full design.
 *)

EXTENDS Integers, FiniteSets

\* ========================================================================
\* CONSTANTS
\* ========================================================================

CONSTANTS
    \* @type: Set(Str);
    Transactions,   \* Set of transaction IDs
    \* @type: Int;
    MaxBlocks       \* Maximum blocks to check

\* ========================================================================
\* VARIABLES
\* ========================================================================

VARIABLES
    \* @type: Int;
    block_height,
    \* @type: Int -> Bool;
    layer1_valid,       \* Signature verification result per block
    \* @type: Int -> Bool;
    layer2_valid,       \* ZK proof verification result per block
    \* @type: Int -> Bool;
    layer3_valid,       \* Consensus verification result per block
    \* @type: Int -> Bool;
    block_accepted      \* Whether the block was accepted

vars == <<block_height, layer1_valid, layer2_valid, layer3_valid, block_accepted>>

\* ========================================================================
\* CONSTANT INITIALIZATION (for Apalache)
\* ========================================================================

ConstInit ==
    /\ Transactions = {"tx1", "tx2", "tx3"}
    /\ MaxBlocks = 3

\* ========================================================================
\* INITIAL STATE
\* ========================================================================

Init ==
    /\ block_height = 0
    /\ layer1_valid = [h \in 0..MaxBlocks |-> FALSE]
    /\ layer2_valid = [h \in 0..MaxBlocks |-> FALSE]
    /\ layer3_valid = [h \in 0..MaxBlocks |-> FALSE]
    /\ block_accepted = [h \in 0..MaxBlocks |-> FALSE]

\* ========================================================================
\* ACTIONS
\* ========================================================================

(*
 * A block arrives and each layer produces a verification result.
 * The results are nondeterministic (modeling all possible outcomes).
 *)
VerifyBlock ==
    /\ block_height < MaxBlocks
    /\ block_height' = block_height + 1
    /\ \E l1 \in {TRUE, FALSE}, l2 \in {TRUE, FALSE}, l3 \in {TRUE, FALSE} :
        /\ layer1_valid' = [layer1_valid EXCEPT ![block_height + 1] = l1]
        /\ layer2_valid' = [layer2_valid EXCEPT ![block_height + 1] = l2]
        /\ layer3_valid' = [layer3_valid EXCEPT ![block_height + 1] = l3]
        \* Block accepted IFF ALL three layers pass
        /\ block_accepted' = [block_accepted EXCEPT
            ![block_height + 1] = (l1 /\ l2 /\ l3)]

\* ========================================================================
\* NEXT STATE
\* ========================================================================

Next == VerifyBlock

Spec == Init /\ [][Next]_vars

\* ========================================================================
\* SAFETY PROPERTIES
\* ========================================================================

(*
 * SOUNDNESS: A block is accepted ONLY IF all 3 layers are valid.
 * No single layer passing can cause acceptance if another fails.
 *)
Soundness ==
    \A h \in 1..block_height :
        block_accepted[h] => (layer1_valid[h] /\ layer2_valid[h] /\ layer3_valid[h])

(*
 * COMPLETENESS: If all 3 layers are valid, the block IS accepted.
 * A valid block is never incorrectly rejected.
 *)
Completeness ==
    \A h \in 1..block_height :
        (layer1_valid[h] /\ layer2_valid[h] /\ layer3_valid[h]) => block_accepted[h]

(*
 * LAYER INDEPENDENCE: Each layer's failure independently causes rejection.
 * Layer 2 passing cannot save a Layer 1 failure, etc.
 *)
LayerIndependence ==
    /\ \A h \in 1..block_height :
        (~layer1_valid[h]) => (~block_accepted[h])
    /\ \A h \in 1..block_height :
        (~layer2_valid[h]) => (~block_accepted[h])
    /\ \A h \in 1..block_height :
        (~layer3_valid[h]) => (~block_accepted[h])

=============================================================================
