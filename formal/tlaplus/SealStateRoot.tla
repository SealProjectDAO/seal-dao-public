--------------------------- MODULE SealStateRoot ---------------------------
\* F3 (audits/2026-09-27-local-security-inspection.md, 6.4): the header state
\* root must be a DETERMINISTIC function of (committed pre-state, block), never
\* of a node-local "live" balance store.
\*
\* The full on-block transition is not just a transfer: a block also charges a
\* FEE (half burned, half credited to the proposer), a per-byte STORAGE burn,
\* and -- at an epoch boundary -- a deterministic EMISSION, and it commits the
\* block's SQL. This spec models that composite transition as ONE pure
\* function of (committed pre-state, block), and checks two designs as
\* separate invariant pairs:
\*
\*   FIXED  : a node's stamped root = Root(ApplyBlock(PreState)) -- the single
\*            pure on-block transition applied to the committed pre-state. No
\*            live mutation. Every node computes the same root, so no fork.
\*   BUGGY  : a node's stamped root = Root(LocalPreBuggy(n)) -- a NODE-LOCAL
\*            "live" store. The origin applied the gossiped transfer AND the
\*            block's SQL live (RPC/submit-time) plus its own fee/storage/
\*            emission (produce/advance); a non-origin proposer applied only
\*            its own fee/storage/emission, NOT the foreign transfer or SQL.
\*            The non-origin proposer stamps a root the honest replayer (which
\*            replays the FULL block from the committed pre-state) rejects.
\*
\* Invariants (checked on any state where a block has been produced):
\*   NoMismatch : the proposer's stamped root == the honest replayer's root.
\*   Agreement  : every node computes the same root as the proposer.
\*
\* Expected results:
\*   FIXED design : NoMismatchFixed, AgreementFixed  hold   (no counterexample).
\*   BUGGY design : NoMismatchBuggy, AgreementBuggy   fail  (proposer \in {2,3}).
\*
\* The concrete accounting algebra (conservation of balance + burned, supply
\* minted only by emission) is proved in Lean 4:
\*   formal/lean/SealVerify/Basic/StateRoot.lean
\*
\* Run (TLC, explicit-state; see scripts/verify-tla-stateroot.sh):
\*   java -jar tla2tools.jar -config MC_SealStateRoot_fixed.cfg SealStateRoot.tla
\*   java -jar tla2tools.jar -config MC_SealStateRoot_buggy.cfg  SealStateRoot.tla
\* Run (Apalache, symbolic):
\*   apalache-mc check-model --init=Init --next=Next \
\*     --inv=NoMismatchFixed,AgreementFixed SealStateRoot.tla

EXTENDS Naturals, Integers, Sequences

\* -- small concrete model (no free constants; enlarge Node / the effect ----
\* magnitudes below to scale)
Node == {1, 2, 3}
Origin == 1
\* The money accounts: A (transfer sender), B (transfer receiver), Prop (fee
\* proposer), Val / Tres (emission recipients). Two "tag" accounts carry the
\* cumulative burn and the abstract SQL counter, so the whole on-block state is
\* ONE function Account -> Int and Root(s) == s stays injective.
A == 1
B == 2
Prop == 3
Val == 4
Tres == 5
BurnedTag == 1000
SqlTag == 1001
Acct == {A, B, Prop, Val, Tres, BurnedTag, SqlTag}

\* The block's deterministic effects (magnitudes chosen so no balance goes
\* negative under either design).
TransferAmt == 30
FeeAmt == 10
\* Half of FeeAmt is burned, half credits the proposer (FeeBurn + FeeBurn = FeeAmt).
\* Written as a literal because TLA+ has no / operator.
FeeBurn == 5
StorageAmt == 5
EmissionReward == 20
\* The deterministic emission split, Val : Tres = 9 : 1 of EmissionReward. TLA+
\* has no built-in / operator (only + - *), so the 90/10 split of EmissionReward
\* (== 20) is written as literals; the minted total is conserved:
\*   ValEmission + TresEmission = EmissionReward.
ValEmission == 18
TresEmission == 2

\* The one money tx under test: A -> B of TransferAmt, originated at Node 1.
\* @type: Seq({f: Int, t: Int, a: Int});
Txs == << [f |-> A, t |-> B, a |-> TransferAmt] >>

\* The committed (pre) state: A holds 100, everyone else (incl. the burn and
\* sql tags) holds 0.
PreState == [i \in Acct |-> IF i = A THEN 100 ELSE 0]

\* Apply one transfer (f -> t of amount a) to a balance state.
\* @type: ((Int -> Int), Int, Int, Int) => (Int -> Int);
ApplyOne(s, f, t, a) == [s EXCEPT ![f] = s[f] - a, ![t] = s[t] + a]

\* The block's gossiped money transfer (the one tx in Txs).
\* @type: (Int -> Int) => (Int -> Int);
DoTransfer(s) == ApplyOne(s, Txs[1].f, Txs[1].t, Txs[1].a)

\* A block fee: debit the sender, burn half, credit the proposer the rest.
\* @type: (Int -> Int) => (Int -> Int);
DoFees(s) == [s EXCEPT ![A] = s[A] - FeeAmt,
                   ![Prop] = s[Prop] + (FeeAmt - FeeBurn),
                   ![BurnedTag] = s[BurnedTag] + FeeBurn]

\* Per-byte storage burn: debit the sender, move it to the burn counter.
\* @type: (Int -> Int) => (Int -> Int);
DoStorage(s) == [s EXCEPT ![A] = s[A] - StorageAmt,
                    ![BurnedTag] = s[BurnedTag] + StorageAmt]

\* Deterministic epoch emission: mint to the validator (90%) and treasury (10%).
\* The only effect that increases total supply.
\* @type: (Int -> Int) => (Int -> Int);
DoEmission(s) == [s EXCEPT ![Val] = s[Val] + ValEmission,
                     ![Tres] = s[Tres] + TresEmission]

\* The block's SQL commit, modeled as an abstract deterministic counter.
\* @type: (Int -> Int) => (Int -> Int);
DoSql(s) == [s EXCEPT ![SqlTag] = s[SqlTag] + 1]

\* The FULL on-block transition: one pure function of the committed pre-state.
\* This is what the FIXED design (and every honest replayer) applies.
\* @type: (Int -> Int) => (Int -> Int);
ApplyBlock(s) == DoSql(DoEmission(DoStorage(DoFees(DoTransfer(s)))))

\* The node-local effects every node applies to its OWN store (its own
\* produce/advance): fee + storage + emission -- but NOT the gossiped transfer
\* or the block's SQL, which only the origin applied live.
\* @type: (Int -> Int) => (Int -> Int);
ApplyCommon(s) == DoEmission(DoStorage(DoFees(s)))

\* The state root, modeled AS the state itself: injective, so two states share
\* a root iff they are identical. The real system uses sha3_256(MerkleRoot);
\* injectivity follows from hash collision resistance (see Hash.lean).
\* @type: (Int -> Int) => (Int -> Int);
Root(s) == s

\* The honest replayer's root: replay the FULL block from the committed
\* pre-state. Every node computes this on replay, in either design.
ReplayedRoot == Root(ApplyBlock(PreState))

\* FIXED: no live mutation. Every node derives the root from the committed
\* pre-state + the block -- independent of which node proposes.
\* @type: Int => (Int -> Int);
StampedFixed(n) == Root(ApplyBlock(PreState))

\* BUGGY: node-local live store. The origin has the full on-block result (it
\* applied the transfer and SQL live, plus its own fee/storage/emission); a
\* non-origin proposer has only its own fee/storage/emission (no foreign
\* transfer or SQL).
\* @type: Int => (Int -> Int);
LocalPreBuggy(n) == IF n = Origin THEN ApplyBlock(PreState) ELSE ApplyCommon(PreState)
\* @type: Int => (Int -> Int);
StampedBuggy(n) == Root(LocalPreBuggy(n))

\* -- the (trivial) state machine: pick a proposer, produce the block ---------
VARIABLES
  \* @type: Int;
  proposer,
  \* @type: Bool;
  produced

vars == << proposer, produced >>

Init == /\ proposer = 0
        /\ produced = FALSE

Propose == /\ produced = FALSE
           /\ produced' = TRUE
           /\ proposer' \in Node

Next == Propose

Spec == Init /\ [][Next]_vars

\* -- invariants ----------------------------------------------------------------
\* The proposer's stamped root must equal the honest replayer's root.
NoMismatchFixed == produced => StampedFixed(proposer) = ReplayedRoot
NoMismatchBuggy == produced => StampedBuggy(proposer) = ReplayedRoot

\* Every node must compute the same root as the proposer (no proposer-dependent
\* fork). It must not matter which node proposes.
AgreementFixed == produced => \A n \in Node : StampedFixed(n) = StampedFixed(proposer)
AgreementBuggy == produced => \A n \in Node : StampedBuggy(n) = StampedBuggy(proposer)

=============================================================================
