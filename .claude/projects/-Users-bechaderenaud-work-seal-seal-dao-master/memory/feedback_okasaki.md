---
name: Okasaki-style persistent data structures for SQL state
description: User wants efficient incremental state updates using purely functional data structures (Okasaki style) to minimize data inspection during ZK proofs
type: feedback
---

Use Okasaki-style purely functional data structures for the SQL state engine.

**Why:** In ZK proving, every byte of data touched adds to the circuit cost. Purely functional (persistent) data structures enable:
- Incremental state diffs (only changed nodes need re-hashing)
- Structural sharing (unchanged subtrees share memory)
- Deterministic state roots from structure, not insertion order
- Efficient Merkle proof generation (path from leaf to root)

**How to apply:** The Merkle B-tree already uses content-addressed nodes (hash-based references). Optimize by:
1. Replace full rebuild in MerkleEngine with incremental updates
2. Track only modified paths (Merkle diff, not full tree rebuild)
3. Use persistent red-black trees or finger trees for table indexes
4. Minimize data touched per transaction for ZK circuit efficiency
