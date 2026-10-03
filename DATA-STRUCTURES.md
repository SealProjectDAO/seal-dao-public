# Seal DAO — Persistent Data Structures & Formal Proofs

## Motivation

In a ZK-proven blockchain, every byte of state touched during a transaction
adds to the proof circuit. A naive approach (full table scan, full Merkle
rebuild) makes ZK proving prohibitively expensive.

**Goal**: Minimize the data touched per transaction using Okasaki-style
purely functional (persistent) data structures, then formally prove
these structures maintain their invariants.

## Current State (v0.1)

```
Transaction → SQL Engine → Full Merkle Rebuild → State Root
                             ↑ EXPENSIVE: rebuilds entire tree
```

The current `MerkleEngine.rebuild_merkle()` reconstructs the entire
Merkle tree from scratch after every write. This is O(n) where n is
total rows across all tables.

## Target Architecture

```
Transaction → SQL Engine → Incremental Merkle Update → State Root
                             ↑ CHEAP: only modified paths
```

Only the path from the modified leaf to the root gets recomputed.
This is O(log n) — exponentially better.

## Persistent Data Structures

### 1. Persistent Merkle B-Tree (already content-addressed)

The existing B-tree uses hashed references (NodeRef::Hash). This is
already persistent in the Okasaki sense — modifying a node creates a
new node with a new hash, sharing unchanged children.

**What needs to change:**
- Replace `rebuild_merkle()` with incremental path updates
- Track which nodes changed (dirty path)
- Only rehash the path from modified leaf to root

**Formal proofs needed (Lean 4):**
```lean
-- Incremental update produces same root as full rebuild
theorem incremental_correct (t : MTree) (k : Key) (v : Value) :
    incremental_insert t k v = full_rebuild (logical_insert t k v)

-- Incremental update touches O(log n) nodes
theorem incremental_efficient (t : MTree) (k : Key) (v : Value) :
    nodes_touched (incremental_insert t k v) ≤ 2 * depth t + 1
```

### 2. Persistent Red-Black Tree (for table indexes)

For SQL WHERE clauses that filter by indexed columns, we need an
ordered index. A persistent red-black tree (Okasaki, Chapter 3)
provides O(log n) insert/lookup/delete with full persistence.

**Key property**: Every modification returns a NEW tree. The old
tree is unchanged (structural sharing via immutable nodes).

**Formal proofs needed (Lean 4 / Rocq):**
```lean
-- Red-black invariant preserved after insert
theorem insert_preserves_rb (t : RBTree) (k : Key) :
    is_red_black t → is_red_black (insert t k)

-- Balance: height ≤ 2 * log2(n) + 1
theorem height_bound (t : RBTree) :
    is_red_black t → height t ≤ 2 * Nat.log2 (size t) + 1

-- Lookup after insert finds the value
theorem insert_lookup (t : RBTree) (k : Key) (v : Value) :
    lookup (insert t k v) k = some v
```

### 3. Persistent Hash Array Mapped Trie (HAMT)

For the account balance store and other key-value maps, a HAMT
(as in Clojure/Scala) provides:
- O(1) amortized lookup (32-way branching on hash bits)
- Structural sharing on modification
- Efficient serialization (each node is content-addressable)

**Formal proofs needed:**
```lean
-- HAMT lookup is consistent with logical map
theorem hamt_correct (m : HAMT) (k : Key) :
    hamt_lookup m k = map_lookup (to_map m) k

-- Structural sharing: modifying one key doesn't copy the whole trie
theorem hamt_sharing (m : HAMT) (k : Key) (v : Value) :
    shared_nodes (m, insert m k v) ≥ size m - depth m
```

## ZK Circuit Efficiency

Why this matters for ZK proofs:

| Operation | Naive (current) | Optimized (Okasaki) | ZK impact |
|-----------|----------------|---------------------|-----------|
| INSERT 1 row | Rebuild all rows O(n) | Update path O(log n) | ~100x fewer cycles |
| UPDATE 1 row | Rebuild all rows O(n) | Update path O(log n) | ~100x fewer cycles |
| DELETE 1 row | Rebuild all rows O(n) | Update path O(log n) | ~100x fewer cycles |
| State root | Hash all rows O(n) | Rehash path O(log n) | ~100x fewer hashes |

For a table with 10,000 rows:
- Naive: touch 10,000 rows per transaction (~10M cycles in zkVM)
- Okasaki: touch ~14 nodes per transaction (~14K cycles in zkVM)
- **~700x reduction in proving cost**

## Formal Verification Strategy

### Why formal proofs are essential

These data structures are in the **trusted computing base**. A bug in the
persistent tree means wrong state roots → chain divergence → catastrophic.

Okasaki-style code is notoriously tricky:
- Red-black tree rotations have subtle edge cases
- HAMT hash collision handling
- B-tree split/merge during insert/delete

Manual testing can't cover all cases. Formal proofs provide certainty.

### Verification plan

| Structure | Property | Tool | Priority |
|-----------|----------|------|----------|
| Merkle B-tree | Insert-get roundtrip | Lean 4 (started) | High |
| Merkle B-tree | Incremental = full rebuild | Lean 4 | High |
| Merkle B-tree | Root hash uniqueness | Lean 4 (axiomatized) | Done |
| Red-black tree | RB invariant preservation | Lean 4 or Rocq | Medium |
| Red-black tree | Height bound (O(log n)) | Lean 4 | Medium |
| HAMT | Lookup correctness | Lean 4 | Medium |
| All structures | No-panic (Rust) | Kani | High |
| All structures | Property tests | proptest | Done (B-tree) |

### Reference implementations with proofs

| Structure | Verified implementation | Language |
|-----------|----------------------|----------|
| Red-black tree | Okasaki (1998), verified in Coq by Appel (2011) | Coq |
| Merkle tree | Verified in Lean 4 by various authors | Lean 4 |
| HAMT | Verified in Isabelle by Lammich | Isabelle/HOL |
| Persistent arrays | Verified in F* (Ahman et al.) | F* |

We can port these existing verified implementations rather than proving
from scratch. The Coq red-black tree by Andrew Appel is particularly
well-documented and battle-tested.

## Implementation Phases

### Phase 1 (current): Full rebuild
- `MerkleEngine.rebuild_merkle()` — works, correct, slow
- Good enough for prototyping and testing

### Phase 2: Incremental Merkle updates
- Track dirty paths during SQL execution
- Only rehash modified nodes
- Verify: `incremental_root == full_rebuild_root` (test + Lean proof)

### Phase 3: Persistent red-black tree indexes
- For indexed columns (WHERE clause acceleration)
- Port Appel's verified Coq implementation to Rust
- Or use Aeneas to extract verified Lean → Rust

### Phase 4: HAMT for account state
- Replace `HashMap<String, Balance>` with persistent HAMT
- Content-addressable nodes for Merkle integration
- Verify with Lean 4

## References

- Okasaki, C. (1998). *Purely Functional Data Structures*. Cambridge University Press.
- Appel, A.W. (2011). *Efficient Verified Red-Black Trees*. Unpublished manuscript.
  [https://www.cs.princeton.edu/~appel/papers/redblack.pdf]
- Lammich, P. (2019). *Verified Hash Array Mapped Tries*. Isabelle AFP.
- Ahman, D. et al. (2018). *Recalling a Witness: Foundations and Applications of Monotonic State*. F*.
