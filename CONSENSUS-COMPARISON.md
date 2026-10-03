# Seal DAO — Consensus Protocol Comparison

## Current Design: Algorand-style (VRF + Committee Voting)

Seal currently specifies VRF-based leader selection (LB-VRF) + Ringtail
threshold committee signing. 4-second slots, 100-member committees,
single-slot finality.

---

## Protocol Comparison

| Property | **PBFT** | **Tendermint** | **Algorand BA\*** | **HotStuff** | **HotStuff-2** | **Jolteon** | **Mysticeti (DAG)** |
|---|---|---|---|---|---|---|---|
| Rounds to finality | 2 | 2 | 2 | 3 | **2** | 2 | 3 DAG rounds |
| Message complexity | O(n^2) | O(n^2) | **O(n) gossip** | O(n) linear | O(n) linear | O(n) happy, O(n^2) view-change | O(n) per validator |
| View-change complexity | **O(n^3)** | O(n), non-responsive | N/A (no leader) | O(n) responsive | O(n) responsive | O(n^2) | O(n), embedded in DAG |
| Throughput (benchmark) | 1-5K TPS | 430-10K TPS | ~10K TPS | 100K+ TPS (pipelined) | ~125K TPS | HotStuff + 30% | **300-400K TPS** |
| Finality latency | Sub-second (small n) | 6-7 seconds | **~2.85 seconds** | 1-2 seconds | ~25% faster than HS | 200-300ms faster than HS | **390ms consensus** |
| Leader election | Round-robin | Round-robin | **VRF (secret)** | Rotating (known) | Rotating (known) | Rotating (known) | **Leaderless** |
| DDoS resistance | None | None | **Strong (secret leader)** | Weak (known leader) | Weak (known leader) | Weak | **Strong (no leader)** |

---

## PQC Compatibility (The Critical Dimension)

| Protocol | Aggregate/Threshold Sig Required? | PQC Impact | Ringtail Fit |
|---|---|---|---|
| **PBFT** | No (individual sigs) | O(n^2) × 3.3 KB = **~33 MB/round**. Dead. | N/A |
| **Tendermint** | No (individual, gossip) | O(n^2) × 3.3 KB = costly | Poor |
| **Algorand BA\*** | No (gossip + threshold) | **Best fit**: gossip + 1 threshold sig | **Excellent** |
| **HotStuff** | **Yes** (threshold cert per round) | 3 rounds × Ringtail = ~7.5s. **Too slow.** | 3 rounds won't fit in 4s |
| **HotStuff-2** | **Yes** (2 rounds) | 2 rounds × Ringtail = ~5s. **Tight.** | Barely fits, no margin |
| **Jolteon** | Yes (happy) + O(n^2) view-change | Happy path OK; view-change = 100×100×3.3KB | Workable but risky |
| **Mysticeti (DAG)** | **No in consensus hot path** | Each validator signs own blocks (3.3 KB each). **Best PQC bandwidth.** | Ringtail only for finality certs |

### Key Insight

**DAG-based protocols have the best PQC profile**: no threshold signatures in
the consensus hot path. Each validator signs only their own DAG vertices
(1 × 3.3 KB). Threshold sigs (Ringtail) are used only for finality
certificates, not per-round voting.

**Algorand-style has the best PQC practicality today**: 1 threshold sig per
slot (vs 2-3 for HotStuff-family), secret leader election via VRF, and the
design is already spec'd.

---

## Detailed Assessment

### PBFT — Eliminated

O(n^2) all-to-all with 3.3 KB PQC sigs = ~33 MB per voting round for 100
members. Completely impractical for PQC.

### Tendermint/CometBFT — Poor Fit

- Proven in production (Cosmos, ~250 chains)
- O(n^2) gossip for votes with PQC sigs is expensive (~33 MB/round)
- Non-responsive: waits for timeout Delta, wastes slot time
- Finality: 6-7s on Cosmos, too slow for 4s slots
- **Verdict**: Bandwidth too high for PQC at scale

### Algorand BA\* — Current Choice, Good Fit

- VRF-selected committees + gossip propagation
- Committee votes aggregate via Ringtail threshold sig: 13.4 KB output
- Algorand mainnet: ~2.85s finality, ~10K TPS
- DDoS resistant: leader unknown until reveal
- **Downside**: Can enter recovery mode if proposer is Byzantine (slot skip)
- **Downside**: ~10K TPS ceiling
- **Verdict**: Best balance of simplicity, PQC compatibility, security

### HotStuff (3-round) — Too Slow for PQC

- O(n) linear with threshold certs — elegant design
- **Problem**: 3 rounds × Ringtail (2.5s WAN) = ~7.5s. Does not fit in 4s slot.
- Even with preprocessing, 3 threshold sig aggregations per slot is too many.
- **Verdict**: Eliminated for PQC + 4s slots

### HotStuff-2 (2-round) — Tight Fit

- Reduces to 2 rounds while maintaining O(n) and responsive view changes
- 2 × Ringtail ≈ 5s. Exceeds 4s slot (barely).
- With aggressive preprocessing and sub-2s Ringtail, might fit.
- Loses VRF DDoS resistance unless added separately.
- **Verdict**: Possible but no margin. Risk of slot overruns.

### Jolteon/Ditto — Marginal Over HotStuff-2

- 2-chain commit, 200-300ms faster than HotStuff
- O(n^2) view-change with PQC sigs is expensive when triggered
- Ditto adds async fallback (complex)
- **Verdict**: Marginal benefit over HotStuff-2

### Mysticeti/Bullshark (DAG) — Best Long-Term

- **No threshold sigs in hot path**: each validator signs own DAG vertices
- **Best PQC bandwidth**: 100 validators × 3.3 KB = 330 KB total (same as
  all individual sigs, but distributed naturally across DAG)
- 390ms consensus, 300-400K TPS
- Leaderless = no DDoS target
- **Downside**: Very complex to implement (DAG construction, equivocation
  handling, commit rule, garbage collection)
- **Downside**: Loses VRF-based leader selection (not needed in DAG)
- Finality certificate still uses Ringtail (once per committed anchor)
- **Verdict**: Best performance and PQC profile, but highest complexity

---

## Recommendation

### Phase 1 (Launch): Stay with Algorand-style

1. Ringtail threshold sigs fit naturally (1 per slot, within 4s budget)
2. VRF secret leader election provides DDoS resistance for a young chain
3. ~10K TPS is sufficient for SQL-backed applications at launch
4. Already spec'd and formally analyzable
5. Algorand itself is pursuing the same PQC migration path

### Phase 2+ (Scaling): Evaluate DAG-based (Mysticeti-style)

1. Best PQC bandwidth — no threshold sigs in consensus hot path
2. 10-40× throughput headroom over Algorand-style
3. By Phase 2, more formal analysis and production mileage available
4. Transition path: keep VRF for validator set selection, use DAG for ordering

### Do NOT Switch to HotStuff-2 or Jolteon

1. 2-3 Ringtail rounds per slot barely fits (or doesn't fit) in 4s
2. Known-leader rotation loses DDoS resistance
3. Throughput (30-100K TPS) is an awkward middle — not enough over Algorand,
   not competitive with DAG
4. Pain without proportional gain

### Design Change to Consider Now

**Decouple mempool from consensus** (Narwhal-style):
- Transaction dissemination via DAG mempool, separate from block ordering
- Works with Algorand-style consensus for ordering
- Improves throughput and prepares architecture for future DAG consensus
- Lower-risk incremental step

---

## PQC Bandwidth Reference

| Component | Size | Per-slot (n=100) |
|---|---|---|
| ML-DSA signature | 3.3 KB | 330 KB (all individual) |
| Ringtail threshold sig | 13.4 KB | 13.4 KB (96% reduction) |
| Ringtail online comm/party | 10.5 KB | 1.05 MB aggregate network traffic |
| LB-VRF proof | ~5 KB | Per proposer only |
| STARK block proof | ~200 KB | Per block |

---

## References

- HotStuff-2 — [ePrint 2023/397](https://eprint.iacr.org/2023/397.pdf)
- HotStuff-2 vs HotStuff — [arXiv 2403.18300](https://arxiv.org/html/2403.18300v1)
- Jolteon and Ditto — [arXiv 2106.10362](https://arxiv.org/html/2106.10362v2)
- Narwhal and Tusk — [arXiv 2105.11827](https://arxiv.org/abs/2105.11827)
- Bullshark — [arXiv 2201.05677](https://arxiv.org/abs/2201.05677)
- Mysticeti — [arXiv 2310.14821](https://arxiv.org/pdf/2310.14821)
- Algorand Consensus — [developer.algorand.org](https://developer.algorand.org/docs/get-details/algorand_consensus/)
- MonadBFT — [arXiv 2502.20692](https://arxiv.org/pdf/2502.20692)
- PQC Impact on Blockchain — [arXiv 2505.02239](https://arxiv.org/pdf/2505.02239)
- PBFT vs Tendermint vs HotStuff — [Decentralized Thoughts](https://decentralizedthoughts.github.io/2023-04-01-hotstuff-2/)
