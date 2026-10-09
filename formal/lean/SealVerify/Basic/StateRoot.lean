/-
  State-root determinism for the Seal DAO F3 fix.

  WHY THIS FILE EXISTS
  ====================
  F3 (audits/2026-09-27-local-security-inspection.md, section 6.4): on a
  multi-node network a gossiped native money transfer forked the proposer from
  its replayers. The balance move was applied LIVE on the send-origin node but
  only ON-REPLAY elsewhere, so the header `state_root` was computed from a
  node-local "live" balance store that differed per node. When the producer was
  not the send-origin node, its stamped root did not match the replayers'
  replayed root, and the block was rejected (state-root mismatch).

  THE FIX (the design these theorems validate)
  ============================================
  Make the header state root a DETERMINISTIC function of (the previous COMMITTED
  balance state, the block's money transactions) -- never of a node-local live
  store. When a block is produced, the producer applies the block's money txns
  to a copy of the last committed state, computes the root from that copy, and
  the result becomes the new committed state. Every node computes it identically
  from (committed_pre, block_txns), so there is no fork.

  WHAT THIS PROVES (algebraic level)
  ==================================
  1. identity    -- applying an empty tx list leaves the state unchanged.
  2. composition -- applying a block's txns at once (replayer) == applying them
                    one-by-one (producer); the result depends only on the start
                    state and the ordered txns.
  3. supply      -- a well-formed transfer moves money, never creates/destroys
                    it (a block's supply conservation follows by induction, one
                    well-formed transfer at a time).
  4. no-fork     -- two nodes with the SAME committed pre-state applying the
                    SAME txns compute the SAME state root. This is the F3 fix:
                    the root is node-independent because it is a pure function
                    of (committed_pre, block_txns).

  DIVISION OF LABOR WITH TLA+
  ===========================
  This module proves the ALGEBRAIC core: the transition and the root are pure,
  composable, supply-preserving functions of (pre, txns). The full
  node-INTERLEAVING invariant (all nodes that finalize a height agree on its
  root, and the buggy live-store design violates it) is model-checked in
  formal/tlaplus/SealStateRoot.tla (TLC / Apalache). Together they show the
  proposal is sound end-to-end.

  MAPS TO RUST CODE
  =================
  applyTxns       <-> ConsensusRunner::replay_block / produce (on-block apply)
  stateRoot       <-> ConsensusRunner header state_root (consensus_runner.rs)
  applyTransfer   <-> BalancesStore::transfer (crates/seal-token/src/balance.rs)
  totalSupply     <-> BalancesStore::total_supply
-/
import SealVerify.Basic.Hash

-- Account ids, abstracted as Nat. The real system uses 32-byte addresses; only
-- equality is used here, so Nat is a faithful abstraction for these proofs.
-- NOTE: `src`/`dst` are used instead of `from`/`to` because `from` is a
-- reserved Lean keyword.
abbrev Account := Nat
abbrev BalancesEl := Account × Nat
abbrev Balances := List BalancesEl
-- A money transaction: (src, dst, amount).
abbrev MoneyTx := Account × Account × Nat
abbrev TxList := List MoneyTx

-- Total supply across all accounts. Defined before `get` (which sums a
-- sub-sheet) so there is no forward reference to a recursive definition.
def totalSupply : Balances → Nat
  | [] => 0
  | (_, amt) :: tl => amt + totalSupply tl

-- Balance of an account = the total held by its sub-sheet. For a well-formed
-- sheet (each account at most once -- the real BalancesStore is a map, so this
-- holds by construction) this is exactly that account's amount. Stating `get`
-- this way (rather than via `List.find?`) keeps the supply theorems definitional.
def Balances.get (b : Balances) (a : Account) : Nat :=
  totalSupply (b.filter (fun p => decide (p.1 = a)))

-- Bool "neither src nor dst" predicate. Written as a Bool (negation of two
-- simple `decide`s) rather than `decide (p.1 ≠ src ∧ p.1 ≠ dst)` so that `simp`
-- can collapse it from the two simple-equality decide facts in the supply proofs.
def isNeither (src dst : Account) : BalancesEl → Bool :=
  fun p => !decide (p.1 = src) && !decide (p.1 = dst)

-- Bool "not account `a`" predicate (the complement of the `= a` sub-sheet).
-- Written as the negation of the simple-equality decide, so `simp` can collapse
-- it from the single `decide (p.1 = a) = true/false` fact (mirrors isNeither).
def isOther (a : Account) : BalancesEl → Bool :=
  fun p => !decide (p.1 = a)

-- Apply ONE money transfer. Invalid (src == dst, or insufficient funds) is a
-- no-op, mirroring BalancesStore::transfer returning Err on the same conditions.
def Balances.applyTransfer (b : Balances) (src dst : Account) (amount : Nat) : Balances :=
  let srcAmt := b.get src
  let dstAmt := b.get dst
  if src = dst ∨ srcAmt < amount then
    b
  else
    b.filter (isNeither src dst) ++ [(src, srcAmt - amount), (dst, dstAmt + amount)]

-- Apply one transaction (named so the fold can be reasoned about by `foldl`).
def applyOne (b : Balances) (tx : MoneyTx) : Balances :=
  match tx with
  | (src, dst, amount) => b.applyTransfer src dst amount

-- Apply a LIST of money txns in order (left fold = the on-block replay order).
def applyTxns (b : Balances) (txns : TxList) : Balances :=
  txns.foldl applyOne b

-- A deterministic byte code for a natural (its low byte). The exact encoding is
-- irrelevant to the theorems -- only that stateRoot is a PURE function of the
-- sheet. (The real system's root is sha3_256 of the Merkle root, injective
-- w.h.p.; a deterministic code suffices here because the no-fork theorem only
-- needs the root to be a function of (pre, txns).)
private def toFin (n : Nat) : Fin 256 := ⟨n % 256, Nat.mod_lt n (by decide)⟩

-- Encode a balance sheet as a byte sequence. Written as a plain structural
-- recursion (not `List.flatMap`) so it builds with the core-only toolchain.
private def encodeBalances : Balances → List (Fin 256)
  | [] => []
  | (a, amt) :: tl => [toFin a, toFin amt] ++ encodeBalances tl

-- The state root: sha3_256 of the sheet encoding. A PURE function of the sheet
-- alone -- it reads no node-local state.
noncomputable def stateRoot (b : Balances) : Digest :=
  Hash.hash (encodeBalances b)

-- ===========================================================================
-- 1. IDENTITY: an empty tx list leaves the state unchanged.
-- ===========================================================================
theorem applyTxns_nil (b : Balances) : applyTxns b [] = b := by
  simp [applyTxns, List.foldl_nil]

-- ===========================================================================
-- 2. COMPOSITION: applying a block's txns at once (replayer) == applying them
--    one-by-one (producer). The result depends only on (start, ordered txns).
-- ===========================================================================
-- foldl over a concatenation = foldl the second list from the first list's
-- result. Proved with a generalized induction over `init`.
private theorem foldl_append_loc {α β} (f : β → α → β) (a b : List α) :
    ∀ init : β, (a ++ b).foldl f init = b.foldl f (a.foldl f init) := by
  induction a with
  | nil =>
    intro init
    rfl
  | cons h t ih =>
    intro init
    rw [List.cons_append, List.foldl_cons]
    rw [ih (f init h)]
    rw [List.foldl_cons]

theorem applyTxns_concat (b : Balances) (xs ys : TxList) :
    applyTxns (applyTxns b xs) ys = applyTxns b (xs ++ ys) := by
  rw [applyTxns, applyTxns, applyTxns]
  exact (foldl_append_loc applyOne xs ys b).symm

-- ===========================================================================
-- 3. SUPPLY CONSERVATION: a transfer moves money; it never creates or destroys
--    it. The theorem below holds for ANY sheet. `wellFormed` (each account at
--    most once -- the real BalancesStore is a map, so it holds by construction)
--    is the store's invariant, not a precondition of the proof.
-- ===========================================================================
def wellFormed (b : Balances) : Prop :=
  ∀ a, (b.filter (fun p => decide (p.1 = a))).length ≤ 1

-- Total supply is additive over concatenation.
private theorem totalSupply_append (a b : Balances) :
    totalSupply (a ++ b) = totalSupply a + totalSupply b := by
  induction a with
  | nil => simp [totalSupply]
  | cons h t ih =>
    simp [totalSupply, List.cons_append, ih]
    omega

-- The three sub-sheets (neither-src-nor-dst / src / dst) partition the sheet
-- when src ≠ dst: each element is in exactly one, so their supplies sum to the
-- total. Each branch computes the two simple `decide` facts, so `simp` collapses
-- every `List.filter_cons` if-branch (the neither-predicate is a Bool built from
-- those two decides) and leaves a linear-arithmetic goal closed by `omega` + ih.
private theorem supply_partition (b : Balances) (src dst : Account) (hne : src ≠ dst) :
    totalSupply (b.filter (isNeither src dst)) +
      totalSupply (b.filter (fun p => decide (p.1 = src))) +
      totalSupply (b.filter (fun p => decide (p.1 = dst))) = totalSupply b := by
  induction b with
  | nil =>
    simp [isNeither, totalSupply]
  | cons hd tl ih =>
    by_cases hs : hd.1 = src
    · by_cases hsd : hd.1 = dst
      · exfalso; exact hne (hs.symm.trans hsd)
      · -- hd = src ≠ dst
        have dsrc : decide (hd.1 = src) = true := by rw [decide_eq_true]; exact hs
        have ddst : decide (hd.1 = dst) = false := by rw [decide_eq_false]; exact hsd
        simp [List.filter_cons, totalSupply, isNeither, dsrc, ddst]
        omega
    · by_cases hsd : hd.1 = dst
      · -- hd = dst ≠ src
        have dsrc : decide (hd.1 = src) = false := by rw [decide_eq_false]; exact hs
        have ddst : decide (hd.1 = dst) = true := by rw [decide_eq_true]; exact hsd
        simp [List.filter_cons, totalSupply, isNeither, dsrc, ddst]
        omega
      · -- hd is neither src nor dst
        have dsrc : decide (hd.1 = src) = false := by rw [decide_eq_false]; exact hs
        have ddst : decide (hd.1 = dst) = false := by rw [decide_eq_false]; exact hsd
        simp [List.filter_cons, totalSupply, isNeither, dsrc, ddst]
        omega

-- The sub-sheet of account `a` holds exactly get a (definitional, since get is
-- defined as the sub-sheet's total supply).
private theorem supply_of_filter (b : Balances) (a : Account) :
    totalSupply (b.filter (fun p => decide (p.1 = a))) = b.get a := by
  unfold Balances.get
  rfl

-- A transfer conserves total supply. (Holds for any sheet, well-formed or not,
-- because `get` is the sub-sheet's total supply; `wellFormed` is the real
-- BalancesStore's invariant, not a precondition of this proof.)
theorem applyTransfer_supply (b : Balances) (src dst : Account) (amount : Nat) :
    totalSupply (b.applyTransfer src dst amount) = totalSupply b := by
  by_cases hcond : src = dst ∨ b.get src < amount
  · -- invalid (src == dst or insufficient funds): the sheet is unchanged.
    have : b.applyTransfer src dst amount = b := by
      unfold Balances.applyTransfer
      simp [hcond]
    rw [this]
  · -- valid: src ≠ dst and srcAmt ≥ amount (hcond : ¬(src = dst ∨ get src < amount)).
    have hne : src ≠ dst := by intro he; exact hcond (Or.inl he)
    -- `amount ≤ b.get src`; collected as a local hypothesis for `omega`, which
    -- reads the whole context, so the binder is intentionally underscored.
    have _hle : amount ≤ b.get src := by
      have hnotlt : ¬(b.get src < amount) := by intro h; exact hcond (Or.inr h)
      exact Nat.le_of_not_lt hnotlt
    have hvalid : b.applyTransfer src dst amount =
        b.filter (isNeither src dst) ++
        [(src, b.get src - amount), (dst, b.get dst + amount)] := by
      unfold Balances.applyTransfer
      simp [hcond]
    rw [hvalid, totalSupply_append]
    simp only [totalSupply]
    -- LHS = totalSupply(filter_neither) + (get src - amount) + (get dst + amount)
    have hsum : totalSupply (b.filter (isNeither src dst)) + b.get src + b.get dst =
        totalSupply b := by
      rw [← supply_of_filter b src, ← supply_of_filter b dst]
      exact supply_partition b src dst hne
    omega

-- ===========================================================================
-- 4. NO FORK: two nodes that committed the SAME pre-state and apply the SAME
--    block txns compute the SAME state root. This is the F3 fix, stated.
--
-- The root is a pure function of (committed_pre, block_txns) -- it never reads a
-- node-local live store -- so identical inputs give identical roots, and no fork
-- can occur. The interleaving-level version is model-checked in
-- formal/tlaplus/SealStateRoot.tla.
-- ===========================================================================
theorem stateRoot_no_fork (pre1 pre2 : Balances) (txns : TxList)
    (h : pre1 = pre2) :
    stateRoot (applyTxns pre1 txns) = stateRoot (applyTxns pre2 txns) := by
  subst h
  rfl

-- Corollary: the block's state root is determined by the committed transition
-- alone, independent of any other (node-local) state.
noncomputable def blockStateRoot (pre : Balances) (txns : TxList) : Digest :=
  stateRoot (applyTxns pre txns)

theorem blockStateRoot_pure (pre : Balances) (txns : TxList) :
    blockStateRoot pre txns = stateRoot (applyTxns pre txns) := by
  rfl

-- ===========================================================================
-- 5. FULL ON-BLOCK TRANSITION. The F3 fix makes the header state root a pure
--    function of (committed pre-state, the block). A block's balance effects
--    are not only a transfer: it also charges a FEE (half burned, half credited
--    to the proposer), a per-byte STORAGE burn, and — at an epoch boundary — a
--    deterministic EMISSION. This section proves the algebraic core of that
--    composite transition: identity, composition, accounting conservation
--    (`balance + burned`, with only emission minting new supply), and no-fork.
--    The node-interleaving agreement (every finalizer of a height computes the
--    same root, and the node-local live-store design forks) is model-checked in
--    formal/tlaplus/SealStateRoot.tla.
-- ===========================================================================

-- A ledger: the balance sheet plus the cumulative supply burned by fees and
-- storage. Moves conserve `totalValue`; emission is the only supply increase.
structure Ledger where
  balances : Balances
  burned : Nat

def Ledger.totalValue (l : Ledger) : Nat := totalSupply l.balances + l.burned

-- Increment account `a`'s balance by `amount`, collapsing any duplicate `a`
-- entries (the real store is a map, so this holds by construction).
def Balances.credit (b : Balances) (a : Account) (amount : Nat) : Balances :=
  b.filter (isOther a) ++ [(a, b.get a + amount)]

-- Decrement account `a`'s balance by `amount`; a no-op if insufficient.
def Balances.debit (b : Balances) (a : Account) (amount : Nat) : Balances :=
  let cur := b.get a
  if cur < amount then b
  else b.filter (isOther a) ++ [(a, cur - amount)]

-- The complement of the `= a` sub-sheet and the `= a` sub-sheet partition the
-- sheet: each entry is in exactly one of the two filters, so their supplies
-- sum to the total. Proved with NO `get` in the goal (both sides are plain
-- `totalSupply` of a filter), so the induction hypothesis matches the goal and
-- `omega` closes it -- the same technique as `supply_partition` above.
private theorem filterComplementSum (b : Balances) (a : Account) :
    totalSupply (b.filter (isOther a)) +
      totalSupply (b.filter (fun p => decide (p.1 = a))) = totalSupply b := by
  induction b with
  | nil =>
    simp [totalSupply]
  | cons hd tl ih =>
    by_cases h : hd.1 = a
    · -- hd is in the `= a` sub-sheet, not the complement.
      have d : decide (hd.1 = a) = true := by rw [decide_eq_true]; exact h
      simp [List.filter_cons, totalSupply, isOther, d]
      omega
    · -- hd is in the complement, not the `= a` sub-sheet.
      have d : decide (hd.1 = a) = false := by rw [decide_eq_false]; exact h
      simp [List.filter_cons, totalSupply, isOther, d]
      omega

-- The sub-sheet of account `a` and its complement partition the sheet: the
-- `get a` term is the `= a` sub-sheet's supply (by `supply_of_filter`).
private theorem supply_partition2 (b : Balances) (a : Account) :
    totalSupply (b.filter (isOther a)) + b.get a = totalSupply b := by
  rw [← supply_of_filter b a]
  exact filterComplementSum b a

-- An account's balance is a summand of the total supply.
private theorem get_le_totalSupply (b : Balances) (a : Account) :
    b.get a ≤ totalSupply b := by
  have hpart := supply_partition2 b a
  omega

-- credit adds exactly `amount` to the total supply.
theorem Balances.credit_supply (b : Balances) (a : Account) (amount : Nat) :
    totalSupply (b.credit a amount) = totalSupply b + amount := by
  unfold Balances.credit
  rw [totalSupply_append]
  simp [totalSupply]
  rw [← Nat.add_assoc, supply_partition2 b a]

-- debit with sufficient funds removes exactly `amount` from the total supply.
theorem Balances.debit_supply (b : Balances) (a : Account) (amount : Nat)
    (h : amount ≤ b.get a) :
    totalSupply (b.debit a amount) = totalSupply b - amount := by
  have hnn : ¬b.get a < amount := Nat.not_lt_of_ge h
  have hpart := supply_partition2 b a
  have hgetle := get_le_totalSupply b a
  unfold Balances.debit
  simp [hnn, totalSupply, totalSupply_append, Nat.add_assoc]
  omega

-- debit with insufficient funds is a no-op.
theorem Balances.debit_noop (b : Balances) (a : Account) (amount : Nat)
    (h : b.get a < amount) : b.debit a amount = b := by
  unfold Balances.debit
  simp [h]

-- One balance effect of a block. The fee's burned part (`burnPart`; the rest is
-- the proposer's reward) and the emission's validator share (`v`; the rest goes
-- to the treasury) are parameters: the conservation invariant holds for any
-- valid split, hence in particular for the concrete 50% fee burn and 90/10
-- emission split used by the node.
inductive BlockOp where
  | transfer (src dst : Account) (amount : Nat)
  | fee (sender proposer : Account) (fee burnPart : Nat)
  | storage (sender : Account) (amount : Nat)
  | emission (validators treasury : Account) (v reward : Nat)

abbrev BlockOps := List BlockOp

-- A fee/emission split is valid when the sub-share does not exceed the whole,
-- so the complementary credit is exact.
def blockOpValid (op : BlockOp) : Prop :=
  match op with
  | BlockOp.fee _ _ fee burnPart => burnPart ≤ fee
  | BlockOp.emission _ _ v reward => v ≤ reward
  | _ => True

-- Every effect in the block is a valid split (the fee/emission sub-share does
-- not exceed the whole, so the complementary credit is exact).
inductive blockOpsValid : BlockOps → Prop where
  | nil : blockOpsValid []
  | cons {op : BlockOp} {tl : BlockOps} (h : blockOpValid op) (ht : blockOpsValid tl) :
      blockOpsValid (op :: tl)

-- Supply minted by a block's emission ops (0 for every other op).
def BlockOp.emissionReward (op : BlockOp) : Nat :=
  match op with
  | BlockOp.emission _ _ _ r => r
  | _ => 0

def emissionTotal (ops : BlockOps) : Nat :=
  match ops with
  | [] => 0
  | op :: tl => emissionTotal tl + op.emissionReward

-- Apply a single effect. A fee/storage burn that the sender cannot pay is a
-- no-op (mirroring the store's Err-on-insufficient), so it conserves value.
def Ledger.applyOp (l : Ledger) (op : BlockOp) : Ledger :=
  match op with
  | BlockOp.transfer src dst amount =>
    { balances := l.balances.applyTransfer src dst amount, burned := l.burned }
  | BlockOp.fee sender proposer fee burnPart =>
    if l.balances.get sender < fee then l
    else
      { balances := (l.balances.debit sender fee).credit proposer (fee - burnPart),
        burned := l.burned + burnPart }
  | BlockOp.storage sender amount =>
    if l.balances.get sender < amount then l
    else
      { balances := l.balances.debit sender amount, burned := l.burned + amount }
  | BlockOp.emission validators treasury v reward =>
    { balances := (l.balances.credit validators v).credit treasury (reward - v),
      burned := l.burned }

-- Apply a block's effects in order (left fold = the on-block application order).
def blockApply (l : Ledger) (ops : BlockOps) : Ledger :=
  ops.foldl (fun acc op => acc.applyOp op) l

-- A transfer conserves total value.
theorem applyOp_transfer_value (l : Ledger) (src dst : Account) (amount : Nat) :
    (l.applyOp (BlockOp.transfer src dst amount)).totalValue = l.totalValue := by
  have hr : l.applyOp (BlockOp.transfer src dst amount) =
        { balances := l.balances.applyTransfer src dst amount, burned := l.burned } := by
    rfl
  simp [hr, Ledger.totalValue]
  rw [applyTransfer_supply l.balances src dst amount]

-- A fee conserves total value: `burnPart` leaves `balances` and enters `burned`;
-- the rest (`fee - burnPart`) is a transfer to the proposer. No-op if the sender
-- cannot pay the full fee.
theorem applyOp_fee_value (l : Ledger) (sender proposer : Account) (fee burnPart : Nat)
    (hsplit : burnPart ≤ fee) :
    (l.applyOp (BlockOp.fee sender proposer fee burnPart)).totalValue = l.totalValue := by
  have hr : l.applyOp (BlockOp.fee sender proposer fee burnPart) =
        if l.balances.get sender < fee then l
        else
          { balances := (l.balances.debit sender fee).credit proposer (fee - burnPart),
            burned := l.burned + burnPart } := by
    rfl
  by_cases h : l.balances.get sender < fee
  · simp [hr, Ledger.totalValue, h]
  · have hle : fee ≤ l.balances.get sender := by omega
    have hfeetot : fee ≤ totalSupply l.balances :=
      Nat.le_trans hle (get_le_totalSupply l.balances sender)
    simp [hr, Ledger.totalValue, h]
    have hde := Balances.debit_supply l.balances sender fee hle
    have hcr := Balances.credit_supply (l.balances.debit sender fee) proposer (fee - burnPart)
    rw [hcr, hde]
    omega

-- A storage burn conserves total value (balance -> burned). No-op if unpays.
theorem applyOp_storage_value (l : Ledger) (sender : Account) (amount : Nat) :
    (l.applyOp (BlockOp.storage sender amount)).totalValue = l.totalValue := by
  have hr : l.applyOp (BlockOp.storage sender amount) =
        if l.balances.get sender < amount then l
        else
          { balances := l.balances.debit sender amount,
            burned := l.burned + amount } := by
    rfl
  by_cases h : l.balances.get sender < amount
  · simp [hr, Ledger.totalValue, h]
  · have hle : amount ≤ l.balances.get sender := by omega
    have hamttot : amount ≤ totalSupply l.balances :=
      Nat.le_trans hle (get_le_totalSupply l.balances sender)
    simp [hr, Ledger.totalValue, h]
    have hde := Balances.debit_supply l.balances sender amount hle
    rw [hde]
    omega

-- Emission is the only supply increase: total value grows by exactly `reward`,
-- split `v` to the validator and `reward - v` to the treasury.
theorem applyOp_emission_value (l : Ledger) (validators treasury : Account)
    (v reward : Nat) (hsplit : v ≤ reward) :
    (l.applyOp (BlockOp.emission validators treasury v reward)).totalValue =
      l.totalValue + reward := by
  have hr : l.applyOp (BlockOp.emission validators treasury v reward) =
        { balances := (l.balances.credit validators v).credit treasury (reward - v),
          burned := l.burned } := by
    rfl
  simp [hr, Ledger.totalValue]
  have hv := Balances.credit_supply l.balances validators v
  have ht := Balances.credit_supply (l.balances.credit validators v) treasury (reward - v)
  rw [ht, hv]
  omega

-- A block's well-formed effects conserve total value, except emission which
-- The foldl step: applying a head op then the tail == applying the head, then
-- folding the tail from the result. This is what lets the induction reuse the
-- IH (which is stated for the tail, starting from `l.applyOp op`).
private theorem blockApply_cons (l : Ledger) (op : BlockOp) (tl : BlockOps) :
    blockApply l (op :: tl) = blockApply (l.applyOp op) tl := by
  unfold blockApply
  simp [List.foldl_cons]

-- mints exactly the block's emission total. Induct on the effects, generalizing
-- the start ledger so the step can relate one more `applyOp`.
theorem blockApply_totalValue (l : Ledger) (ops : BlockOps) (hvalid : blockOpsValid ops) :
    (blockApply l ops).totalValue = l.totalValue + emissionTotal ops := by
  induction ops generalizing l with
  | nil =>
    simp [blockApply, List.foldl_nil, emissionTotal]
  | cons op tl ih =>
    -- hvalid : blockOpsValid (op :: tl) is necessarily the cons constructor;
    -- Lean's dependent elimination dismisses the nil branch automatically.
    cases hvalid with
    | cons hop htl =>
      have ihl := ih (l.applyOp op) htl
      rw [blockApply_cons l op tl, ihl]
      match op with
      | BlockOp.transfer src dst amount =>
        rw [applyOp_transfer_value l src dst amount]
        simp [BlockOp.emissionReward, emissionTotal]
      | BlockOp.fee sender proposer fee burnPart =>
        rw [applyOp_fee_value l sender proposer fee burnPart hop]
        simp [BlockOp.emissionReward, emissionTotal]
      | BlockOp.storage sender amount =>
        rw [applyOp_storage_value l sender amount]
        simp [BlockOp.emissionReward, emissionTotal]
      | BlockOp.emission validators treasury v reward =>
        rw [applyOp_emission_value l validators treasury v reward hop]
        simp [BlockOp.emissionReward, emissionTotal]
        omega

-- The composite transition is composable: applying a block's effects at once
-- (replayer) == applying them one-by-one (producer), depending only on the
-- start ledger and the ordered effects.
theorem blockApply_append (l : Ledger) (xs ys : BlockOps) :
    blockApply (blockApply l xs) ys = blockApply l (xs ++ ys) := by
  unfold blockApply
  exact (foldl_append_loc (Ledger.applyOp) xs ys l).symm

-- The block state root: sha3 of the ledger (balance sheet + burned). A pure
-- function of the ledger alone -- it reads no node-local state.
noncomputable def ledgerRoot (l : Ledger) : Digest :=
  Hash.hash (encodeBalances l.balances ++ [toFin l.burned])

-- NO FORK: two nodes with the same committed ledger applying the same block
-- compute the same root. This generalizes the transfer-only no-fork theorem to
-- the full on-block transition.
theorem ledgerRoot_no_fork (pre1 pre2 : Ledger) (ops : BlockOps)
    (h : pre1 = pre2) :
    ledgerRoot (blockApply pre1 ops) = ledgerRoot (blockApply pre2 ops) := by
  subst h
  rfl
