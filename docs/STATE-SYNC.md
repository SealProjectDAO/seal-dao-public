# State sync — snapshot format and bootstrap protocol

How a fresh Seal node catches up to network state without
replaying every historical block. Tier-1 #3 step 6/6.

> **Status: design.** No code is wired yet. The HAMT-backed
> `BalanceStore` and cached `state_root_hash()` (commit
> `a69b9e11a`) are the substrate this protocol assumes. The
> `seal_balance_state_root` and `seal_token_state_root`
> /metrics labels (commit `1f3...`/SPEC §5.7) already expose the
> roots a syncing peer would compare against.

## 1. What is state, exactly

The committed-state set covers everything that block production
folds into `state_root_hash` per slot. Three sub-roots, each over
a HAMT:

| Sub-root | Source | Domain |
|---|---|---|
| `balance_root` | `BalanceStore::state_root_hash()` (`crates/seal-token/src/balance.rs:237`) | Native SEAL `(addr → Balance)` |
| `token_root` | `TokenManager::state_root_hash()` | Per-token `(symbol, addr → balance)` plus token metadata |
| `private_root` | `PrivateTableManager` (deferred) | Encrypted SQL row leaves; **not in v1 snapshot** |

The first two are what this protocol streams. Bridge wrapped-
balances are folded into `token_root` (wrapped tokens like wSOL
live in the same HAMT as user-created tokens). Storage leases
(`seal-token/storage_lease.rs`) are not yet folded — when they
land, they become a fourth sub-root.

Each per-block `BlockHeader.state_root` is the fold-hash of the
sub-roots in lexicographic order:

```
state_root = SHA3-256(
    "seal/v1/state-root" ||
    balance_root ||
    token_root
)
```

A new node that has streamed `balance_root`'s leaves and
`token_root`'s leaves in v1 reconstructs the HAMT, recomputes the
root, and checks against the header. No full-history replay.

## 2. Snapshot format

A snapshot is identified by `(height, state_root)`. Chunked,
content-addressed, streaming-friendly.

### 2.1 Manifest

```
snapshot/
  manifest.json         # tip header + sub-root list + chunk index
  chunks/
    balance-000.bin     # 64 KiB of HAMT leaves
    balance-001.bin
    …
    token-000.bin
    …
```

`manifest.json`:

```json
{
  "version": 1,
  "height": 1234567,
  "state_root_hex": "<32 bytes hex>",
  "tip_block_hash_hex": "<32 bytes hex>",
  "tip_block_signature": "<Ringtail aggregate over tip>",
  "sub_roots": [
    {"name": "balance", "root_hex": "...", "leaf_count": 12500, "chunks": 2},
    {"name": "token",   "root_hex": "...", "leaf_count": 4800,  "chunks": 1}
  ],
  "chunks": [
    {"path": "chunks/balance-000.bin", "size": 65536, "sha3_hex": "..."},
    {"path": "chunks/balance-001.bin", "size": 30100, "sha3_hex": "..."},
    {"path": "chunks/token-000.bin",   "size": 49200, "sha3_hex": "..."}
  ]
}
```

The `tip_block_signature` is the in-protocol Ringtail aggregate
over the tip header. A syncing node verifies it against the
expected committee public-key set (which it gets from the **header
chain**, sync'd separately and cheaper). This is the trust anchor:
no leaf is admitted unless the tip header is committee-signed.

### 2.2 Chunk format

Each chunk is a sequence of length-prefixed `(key, value)` pairs:

```
struct ChunkEntry {
    key_len:   u16,    // big-endian
    key:       [u8; key_len],
    value_len: u16,    // big-endian
    value:     [u8; value_len],
}
```

Big-endian since this is on-the-wire and we don't want
implementation drift between LE and BE archs to cause
divergence. The chunk file ends when the byte stream is consumed;
no terminator.

A chunk is **not** self-verifying — only the manifest's
`sha3_hex` covers it, and the manifest itself is the only
authenticated-against-the-header artifact. Anti-DoS: a peer
serving a chunk whose SHA3 doesn't match the manifest entry is
banned for the slot.

### 2.3 Reconstruction

```
new HAMT
for chunk in chunks-for(sub_root):
    verify SHA3(chunk) == manifest.chunks[i].sha3_hex
    for (k, v) in parse(chunk):
        HAMT.insert(k, v)
assert HAMT.root_hash() == manifest.sub_roots[i].root_hex
```

Reconstruction is **insertion-order-independent** (the existing
HAMT property — see `state_root_hash_is_insertion_order_independent`
in `balance.rs`), so chunks may arrive out of order across peers
without affecting the final root.

## 3. Wire protocol

Three new RPC methods. All read-only, no auth (snapshots are
public state).

### 3.1 `seal_getSnapshotManifest`

```
params: {"height": <u64>}            // REQUIRED
return: <manifest.json with chunks[]> | error
errors:
  -32004 "snapshot at height N not retained (pruned or never captured)"
  -32005 "snapshot at height N has been pruned: live state_root … no
          longer matches snapshot state_root …" (raced past tip)
```

Snapshot retention policy is per-operator (see §5); `seal_listSnapshots`
below enumerates the currently retained heights.

### 3.2 `seal_getSnapshotChunk`

```
params: {"height": <u64>, "chunk_index": <u64>}   // both REQUIRED
return: {chunk_index, bytes_b64, claimed_hash, ...}  (JSON envelope)
errors:
  -32007 "chunk_index N out of range (snapshot has M chunks)"
  -32004 / -32005 same as getSnapshotManifest
```

`chunk_index` is the offset into `manifest.chunks[]`; the CLI wrapper
`seal snapshot-chunk --index N` is the same `N`. The chunk's SHA3 is
returned alongside the bytes so the caller can recompute and verify.

### 3.3 `seal_listSnapshots`

```
params: {"limit": <optional u32>}    // newest-first; default cap 32
return: {
  "count":          <u32>,           // returned length
  "total_retained": <u32>,           // node-wide retained set size
  "snapshots": [
    {
      "height":                 <u64>,
      "epoch":                  <u64>,
      "state_root_hex":         "...",
      "tip_aggregate_hex":      "...",
      "captured_at_unix_secs":  <u64>
    },
    ...
  ]
}
```

What this peer is currently serving. Useful for clients picking
the freshest available snapshot from a set of peers.

## 4. Bootstrap flow

A fresh node, given a list of trusted bootstrap peers and
genesis hash:

```
1. Header sync (light-client style)
   - Walk forward from genesis fetching just headers + their
     committee signatures via the existing GossipSub topic.
   - Stop at some recent height H (e.g. tip - 1000).
   - At this point we have committed-to roots at every height
     up to H, but no leaves.

2. Snapshot pick
   - Query seal_listSnapshots from each bootstrap peer.
   - Pick the highest height S where ≥ N peers report the same
     state_root_hex. This is the social-fork-choice; refuses to
     proceed if peers disagree (forces operator decision).

3. State stream
   - Fetch the manifest from one peer.
   - Verify tip_block_signature against the committee key set
     for height S (recovered from the header chain).
   - Fetch chunks in parallel from any peers that report the
     same state_root.
   - Verify each chunk's SHA3, insert leaves, recompute sub-root.
   - Refuse to commit if any sub-root mismatch.

4. Tip catch-up
   - From height S, replay headers + transactions to current tip.
   - This is the slow but small interval (~1000 blocks at S = tip-1000).
   - Standard block-replay path.
```

Step 1 is bounded by header-chain length, not state size. Step 3
is the only step that scales with account count, and it scales as
`O(accounts * log_32 accounts)` — for a 10⁷-account testnet, that's
~7-8 chunk-rounds of 64 KiB each, ~50-100 MB of bandwidth.

## 5. Operator surface

### 5.1 `seal_node` flags

```
--snapshot-retention-blocks <N>   keep snapshots taken at heights
                                  where height % N == 0 (default 100_000)
--snapshot-dir <path>             where to write/serve snapshots
                                  (default <data-dir>/snapshots)
--bootstrap-from <url,url,...>    list of peers to query for snapshots
                                  on cold start
```

### 5.2 Producing a snapshot

```
seal-cli snapshot create --node <url> --output snapshot.tar.gz
```

Triggers `seal_takeSnapshot {}` on the target node, waits for the
manifest to land, tarballs the directory. **Authenticated**:
caller must be in `--admin-address` (parallel to bridge admin
gating), since taking a snapshot is heavy (full HAMT walk).

### 5.3 Verifying without consuming

```
seal-cli snapshot verify --manifest manifest.json --chunk-dir ./chunks
```

Reads the manifest, verifies every chunk's SHA3, reconstructs each
sub-root, asserts root match. Doesn't write to a node — pure
client-side check. Useful for archival validation.

## 6. Trust model

What a syncing node verifies:

| Fact | Verified against |
|---|---|
| Tip header is canonical | Ringtail committee aggregate over header |
| Snapshot covers tip-state | Manifest's `state_root_hex` matches tip header |
| Each chunk is intact | SHA3 in manifest |
| Each sub-root is intact | HAMT recomputation |
| Genesis matches what we expect | Operator-supplied genesis hash on first start |

What it explicitly does **not** verify:

- Block contents at heights between genesis and snapshot height
  (header chain alone is enough — the state root commits to
  the result of those blocks).
- That the snapshot was produced by an honest validator. A
  dishonest validator can produce a manifest whose state_root
  doesn't match the committed tip header — the syncing node
  catches this during step 3 (sub-root mismatch).

## 7. Out of scope for v1

- **Incremental sync.** A node that's been offline for a few
  hours just header-syncs forward; it doesn't pull a fresh
  snapshot. This works as long as the offline window is shorter
  than the snapshot retention interval.
- **State-witness sync.** Light clients that want to verify
  individual reads against state-root would benefit from Merkle
  witnesses; that's a separate protocol on top of the same HAMT.
- **Private-table state** (`PrivateTableManager`). Encrypted-row
  state has different distribution rules (per-tenant access)
  and isn't a public-snapshot artifact.
- **Storage leases.** Once `LeaseManager` state folds into a
  fourth sub-root, the v1 chunk-streaming protocol covers it
  with no format change — just a fourth manifest entry.

## 8. Open questions

- **Chunk size.** 64 KiB is a guess. Solana uses ~10 MB chunks
  but snapshots get into the GB range; we'll be smaller. Want
  it big enough that overhead amortizes, small enough that a
  bad peer wastes bounded bandwidth before the SHA3 mismatch
  catches them.
- **Compression.** zstd-level-3 over the chunk bytes is probably
  free perf. Manifest carries `compressed_sha3_hex` and
  `decompressed_sha3_hex` so verification picks the right path.
  Defer until we have a measurement.
- **Parallelism limits.** A peer serving snapshots takes disk-IO
  hits. A new `--snapshot-max-concurrent <N>` setting (default
  4?) would back-pressure aggressive new-node fanout.
