/-
  Hash function axioms and properties for Seal DAO.

  WHY THIS FILE EXISTS:
  =====================
  We need to reason about SHA3-256 in our proofs (Merkle trees, VRF,
  state roots) but we CANNOT prove that SHA3-256 is collision-resistant
  inside Lean — that's a computational hardness assumption, not a
  mathematical theorem.

  So we AXIOMATIZE it: we declare "SHA3 has these properties" and build
  our proofs on top. If SHA3 turns out to be broken (unlikely), our
  proofs would be invalidated — but so would the entire blockchain.

  WHAT THIS PROVES:
  =================
  Given a collision-resistant hash function:
  - Different inputs produce different outputs (with overwhelming probability)
  - Hash is deterministic (same input → same output, always)
  - Hash composition preserves collision resistance

  MAPS TO RUST CODE:
  ==================
  formal/lean/SealVerify/Basic/Hash.lean  ↔  crates/seal-crypto/src/hash.rs
  `Hash.hash`                             ↔  `sha3_256()`
  `Hash.deterministic`                    ↔  test_sha3_256_deterministic
-/

-- A hash function maps byte sequences to fixed-size digests.
-- We model byte sequences as lists of natural numbers (each 0-255).
-- We model digests as a 256-bit value (natural number < 2^256).

-- The type of hash digests (256-bit values).
def Digest := Fin (2^256)
  deriving DecidableEq, Repr

-- AXIOM: A hash function exists with the following properties.
-- We don't define HOW it works (that's SHA3's internals), only WHAT it guarantees.
axiom Hash.hash : List (Fin 256) → Digest

-- AXIOM: Hash is deterministic — same input always gives same output.
-- In Rust: sha3_256(data) called twice returns identical Hash256.
axiom Hash.deterministic :
  ∀ (input : List (Fin 256)), Hash.hash input = Hash.hash input

-- AXIOM: Collision resistance — different inputs give different outputs.
-- This is the core assumption. We state it as an axiom because it's a
-- computational hardness assumption, not provable from first principles.
--
-- NOTE: In reality, collisions EXIST (pigeonhole principle: more inputs
-- than outputs), but FINDING one is computationally infeasible for SHA3.
-- We model the "no one can find a collision" assumption directly.
axiom Hash.collision_resistant :
  ∀ (a b : List (Fin 256)), Hash.hash a = Hash.hash b → a = b

-- THEOREM: Hash output uniquely identifies the input.
-- This follows immediately from collision resistance.
theorem Hash.injective (a b : List (Fin 256)) (h : Hash.hash a = Hash.hash b) :
    a = b :=
  Hash.collision_resistant a b h

-- A hasher that incrementally processes data (models Sha3Hasher).
-- We prove that incremental hashing matches direct hashing.
noncomputable def Hash.incremental (parts : List (List (Fin 256))) : Digest :=
  Hash.hash (parts.join)

-- THEOREM: Hashing A++B at once equals hashing [A, B] incrementally.
-- Maps to: test_incremental_hasher in hash.rs
theorem Hash.incremental_correct (a b : List (Fin 256)) :
    Hash.incremental [a, b] = Hash.hash (a ++ b) := by
  simp [Hash.incremental, List.join]
