# Lean 4 — Mathematical Algorithm Proofs

## What is Lean 4?

Lean 4 is a **theorem prover** and programming language. You write mathematical
statements and machine-checked proofs that those statements are true. If Lean
accepts your proof, it IS correct — there's no ambiguity, no "it works on my
machine", no "we tested it with 1000 inputs".

## Why Lean 4 (not Coq/Isabelle/etc.)?

- **Mathlib**: Lean 4's math library has the best coverage for algebra, groups,
  rings, polynomials — exactly what we need for lattice-based crypto proofs.
- **VCVio**: A Lean 4 framework for game-based cryptographic security proofs.
- **Aeneas**: Can extract Rust code to Lean 4 for verification.
- **Active community**: Ethereum Foundation uses Lean 4 for EVM formalization.

## What we prove

| File | Property | Why it matters | Status |
|------|----------|----------------|--------|
| `Hash.lean` | Hash collision resistance (axiom) + determinism | Foundation for Merkle tree integrity | Axioms defined |
| `MerkleTree.lean` | Insert/delete/root-hash invariants | State integrity: same root = same data | **Proven** (0 sorries since 2026-05-08 commit `58102e9fc`) |
| `VRF.lean` | Uniqueness, correctness, soundness | Leader election can't be forged | Axioms + specs defined |

## How proofs work (by example)

```lean
-- We CLAIM: inserting key k then looking it up returns the value we inserted.
theorem MTree.insert_lookup (t : MTree) (k : Key) (v : Value) :
    (t.insert k v).lookup k = some v := by
  sorry  -- ← "sorry" means "proof not done yet". Lean accepts it but marks it.
         --   When we fill in the real proof, Lean checks every step.
```

A completed proof might look like:
```lean
theorem example : 1 + 1 = 2 := by
  norm_num  -- Lean's arithmetic tactic verifies this automatically
```

The key insight: `sorry` compiles but leaves a warning. Lean tracks which
theorems depend on `sorry` so you know exactly what's proven and what isn't.

## Installation

### macOS
```bash
# Install elan (Lean version manager):
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh
source ~/.profile  # or restart terminal

# Build the proofs:
cd formal/lean
lake build

# If you want Mathlib (large download, ~2GB):
# Uncomment the mathlib dependency in lakefile.lean first
lake build
```

### Linux (Debian/Ubuntu)
```bash
# Install elan:
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh
source ~/.profile

# Dependencies:
sudo apt install git curl

# Build:
cd formal/lean
lake build
```

### VS Code (recommended IDE)
```
Install extension: "lean4" by leanprover
```

## File-by-file explanation

### `Hash.lean`
- **Line 1-20**: Comment explaining WHY we axiomatize hash functions
- **`Digest`**: Type alias for a 256-bit value (the hash output)
- **`Hash.hash`**: AXIOM — a hash function exists (we don't define HOW)
- **`Hash.deterministic`**: AXIOM — same input → same output
- **`Hash.collision_resistant`**: AXIOM — different inputs → different outputs
  (the core assumption; if SHA3 is broken, this axiom is wrong)
- **`Hash.injective`**: THEOREM — follows directly from collision resistance
- **`Hash.incremental_correct`**: THEOREM — hashing A++B = hashing [A,B]

### `MerkleTree.lean`
- **`MTree`**: Simplified tree model (sorted list of key-value pairs)
- **`MTree.insert`**: Insert operation (filter duplicates, append, sort)
- **`MTree.lookup`**: Lookup by key
- **`MTree.rootHash`**: Compute hash of all entries (Merkle root)
- **`insert_lookup`**: THEOREM (proven) — insert then lookup = value
- **`insert_lookup_other`**: THEOREM (proven) — insert doesn't corrupt other keys
- **`rootHash_deterministic`**: THEOREM (proven) — same entries = same root
- **`rootHash_injective`**: THEOREM (proven) — different root = different entries
- **`delete_idempotent`**: THEOREM (proven) — deleting twice = deleting once
- **`delete_then_insert`**: THEOREM (proven) — delete-then-insert = insert
- **`delete_changes_root`**: THEOREM (proven) — deleting a present key changes the root
- Helper lemmas: `filter_find_none`, `find_append_none`, `filter_preserves_find`, `find_mem`, `find_pred`, `filter_filter_self` (all proven, no Mathlib dependency)

### `VRF.lean`
- **`VRF.eval`**: AXIOM — VRF evaluation function exists
- **`VRF.verify`**: AXIOM — VRF verification function exists
- **`VRF.uniqueness`**: AXIOM — one output per (key, input)
- **`VRF.correctness`**: AXIOM — honest eval produces valid proof
- **`VRF.soundness`**: AXIOM — can't forge proof for wrong output
- Leader election fairness: informal spec (formal version needs VCVio)

## Relationship to Rust code

```
Lean 4 (this directory)          Rust (crates/)
===========================      ==========================
Hash.hash                   ↔    seal_crypto::sha3_256()
Hash.collision_resistant    ↔    Assumed (SHA3 security)
MTree.insert               ↔    MerkleTree::insert()
MTree.lookup                ↔    MerkleTree::get()
MTree.rootHash              ↔    Engine::state_root()
VRF.eval                    ↔    Vrf::eval()
VRF.verify                  ↔    Vrf::verify()
VRF.uniqueness              ↔    test_eval_deterministic
```

## Next steps

1. Complete `sorry` proofs in MerkleTree.lean (sorted list lemmas)
2. Add Mathlib dependency for algebraic structures (needed for VRF proofs)
3. Formalize LB-VRF construction using VCVio game-based framework
4. Use Aeneas to extract Rust seal-merkle code and verify against Lean model
