# Reading the Rocq/Coq Proofs — Line by Line Guide

## What is a Rocq proof?

A Rocq proof is a **machine-checked mathematical argument**. If it compiles,
it is correct — there's no "works on my machine" for math.

## How to read Balance.v

### The Structure

```coq
(* 1. Define types *)
Record Balance := mkBalance { available : nat; staked : nat; total : nat }.

(* 2. Define invariants *)
Definition well_formed (b : Balance) : Prop :=
  total b = available b + staked b.

(* 3. Define operations *)
Definition credit (b : Balance) (amount : nat) : Balance :=
  mkBalance (available b + amount) (staked b) (total b + amount).

(* 4. State theorems *)
Lemma credit_well_formed : forall b amount,
  well_formed b -> well_formed (credit b amount).

(* 5. Prove them *)
Proof.
  intros b amount H.              (* Introduce variables *)
  unfold well_formed, credit in *. (* Expand definitions *)
  simpl.                           (* Simplify expressions *)
  lia.                             (* Solve with linear arithmetic *)
Qed.                               (* Proof accepted ✓ *)
```

### Proof Tactics Explained

| Tactic | What it does | English meaning |
|--------|-------------|-----------------|
| `intros x y` | Introduce variables from `forall` | "Let x and y be given" |
| `unfold f` | Replace `f` with its definition | "By definition of f..." |
| `simpl` | Simplify arithmetic/constructors | "Which simplifies to..." |
| `lia` | Solve linear integer arithmetic automatically | "This is just algebra" |
| `reflexivity` | Prove `x = x` | "Both sides are the same" |
| `rewrite H` | Replace using an equality hypothesis | "Substituting H into the goal..." |
| `destruct x` | Case split on x | "Consider each case of x..." |
| `split` | Prove A ∧ B by proving A then B | "We prove each part separately" |
| `exact H` | The goal IS hypothesis H | "This is exactly what we assumed" |
| `lia` (full name: Linear Integer Arithmetic) | Decides `Nat` equalities/inequalities | "This follows from arithmetic" |

### Reading credit_debit_roundtrip (the key theorem)

```coq
Theorem credit_debit_roundtrip : forall b amount,
  (* For ANY balance b and ANY amount... *)
  well_formed b ->
  (* ...if b is well-formed (total = available + staked)... *)
  let b1 := credit b amount in
  let b2 := debit b1 amount in
  (* ...then crediting then debiting the same amount... *)
  available b2 = available b /\
  staked b2 = staked b /\
  total b2 = total b.
  (* ...returns to the EXACT original balance. *)
Proof.
  intros b amount Hwf.
  (* Let b and amount be arbitrary, assume b is well-formed *)
  unfold credit, debit. simpl. lia.
  (* Expand both operations, simplify, and solve with arithmetic.
     lia sees:
       available (debit (credit b amount) amount)
     = (available b + amount) - amount
     = available b  ✓
     And similarly for staked and total. *)
Qed.
```

### Reading transfer_conserves

```coq
Theorem transfer_conserves : forall a_bal b_bal amount,
  well_formed a_bal -> well_formed b_bal ->
  amount <= available a_bal ->
  (* Given two well-formed balances, transferring amount ≤ sender's balance... *)
  let a_after := debit a_bal amount in
  let b_after := credit b_bal amount in
  total a_after + total b_after = total a_bal + total b_bal.
  (* ...the SUM of both totals is UNCHANGED.
     This is THE financial safety property:
     no money created, no money destroyed. *)
Proof.
  intros a_bal b_bal amount Hwf_a Hwf_b Hsuff.
  unfold debit, credit. simpl. lia.
  (* lia sees:
       (total a - amount) + (total b + amount)
     = total a + total b  ✓
     The +amount and -amount cancel out. *)
Qed.
```

## How to read StateMachine.v

### State representation

```coq
Definition State := Address -> nat.
(* State is a function: give it an address, get a balance.
   This models HashMap<Address, u64> in Rust. *)

Definition update_balance (s : State) (addr : Address) (bal : nat) : State :=
  fun a => if Nat.eqb a addr then bal else s a.
(* "Return a new function that returns `bal` for `addr`,
   and the old balance for every other address."
   This is immutable state — we create a NEW function. *)
```

### Transaction application

```coq
Definition apply_tx (s : State) (tx : Transaction) : option State :=
  match tx with
  | Transfer from to amount =>
    if Nat.leb amount (s from)   (* Is amount ≤ sender's balance? *)
    then Some (...)               (* Yes: return new state *)
    else None                     (* No: reject (insufficient funds) *)
  | Mint to amount => Some (...)  (* Minting always succeeds *)
  | Burn from amount =>
    if Nat.leb amount (s from)
    then Some (...)               (* Burn succeeds if balance sufficient *)
    else None                     (* Reject: can't burn what you don't have *)
  end.
(* Returns `option State`:
   - Some(new_state) = transaction succeeded
   - None = transaction rejected (invalid)
   This models Result<State, Error> in Rust. *)
```

### The transfer conservation proof

```coq
Theorem transfer_conserves_pair : forall s from to amount,
  from <> to ->                    (* from and to are different addresses *)
  amount <= s from ->              (* sender has enough balance *)
  let s' := update_balance
              (update_balance s from (s from - amount))
              to (s to + amount) in
  s' from + s' to = s from + s to.
  (* After the transfer: sender + receiver = original sender + original receiver.
     No money created, no money destroyed. *)
Proof.
  intros s from to amount Hneq Hsuff.
  unfold update_balance. simpl.
  (* Now we have a chain of if-then-else expressions.
     We need to figure out: when we look up `from` in the new state,
     which branch of the if do we take? *)
  destruct (Nat.eqb from from) eqn:E1.
  (* Case: from = from? Obviously yes. *)
  - destruct (Nat.eqb to from) eqn:E2.
    (* Sub-case: to = from? But we assumed from <> to! *)
    + apply Nat.eqb_eq in E2. contradiction.
      (* Nat.eqb_eq says: eqb returns true → values are equal.
         But we have Hneq saying they're NOT equal. Contradiction. *)
    + destruct (Nat.eqb to to) eqn:E3.
      (* Sub-case: to = to? Obviously yes. Now lia solves the arithmetic. *)
      * lia.
      * apply Nat.eqb_neq in E3. contradiction.
  - apply Nat.eqb_neq in E1. contradiction.
    (* from <> from is impossible. *)
Qed.
```

## How to read the Lean 4 proofs

### Hash.lean axioms

```lean
axiom Hash.collision_resistant :
  ∀ (a b : List (Fin 256)), Hash.hash a = Hash.hash b → a = b
-- "For ALL possible inputs a and b:
--  if their hashes are equal, then a and b are the SAME input.
--  i.e., no two different inputs produce the same hash."
--
-- This is an AXIOM (we assume it, not prove it) because
-- collision resistance is a computational hardness assumption.
-- If SHA3 is broken someday, this axiom becomes false and
-- all proofs that depend on it become invalid.
```

### MerkleTree.lean — the sorry proofs

```lean
theorem MTree.insert_lookup (t : MTree) (k : Key) (v : Value) :
    (t.insert k v).lookup k = some v := by
  sorry
-- "sorry" means: "I claim this is true but haven't proven it yet."
-- Lean accepts it but marks the theorem as unverified.
-- When someone fills in the proof, Lean checks every step.
-- A theorem with sorry is a SPECIFICATION, not a proof.
```

### VRF.lean — the security axioms

```lean
axiom VRF.uniqueness :
  ∀ (sk : SecretKey) (input : List (Fin 256)),
    let (output1, _) := VRF.eval sk input
    let (output2, _) := VRF.eval sk input
    output1 = output2
-- "For ANY secret key and ANY input:
--  evaluating the VRF twice gives the SAME output.
--  There is only ONE valid output per (key, input) pair."
--
-- WHY THIS MATTERS:
-- Without uniqueness, an attacker could evaluate the VRF,
-- see the result, and try again to get a better result.
-- Uniqueness prevents this: you get ONE shot.
```
