# Session log — 2026-05-10 (testnet-readiness batch close-out)

This is the back-of-session backup that ties together everything
that landed today. The plan that opened the day is in
[`SESSION-2026-05-10-testnet-readiness.md`](SESSION-2026-05-10-testnet-readiness.md);
this file is the close-out — what actually shipped, what's owed,
and where to pick up next.

## Ship summary

**8 / 8 items closed**, **22 commits**, **27 files changed**,
**+4 402 insertions / −54 deletions**, **1077 → 1116 tests**
(+39 new). Every item passed `./scripts/ci.sh quick` back-to-back
(green × 30 over the day). No clippy regressions.

| # | Item | Commits | Status |
|---|------|---------|--------|
| A1 | Stellar quickstart protocol-22 pin | `5e41c7378` + `103209a89` | ✓ |
| A2a | `seal_listSnapshots` RPC + epoch-boundary capture | `26ecbb3a0` + `2127d821c` + `658b0e57c` | ✓ |
| A2b | `seal_getSnapshotManifest` RPC + chunk encoder | `24405b5c2` + `1143e14b7` + `8556f59e8` | ✓ |
| A2c | `seal_getSnapshotChunk` RPC + decoder | `b8b58c653` + `07fcdb06f` + `047e70930` | ✓ |
| A2d | `--bootstrap-from-snapshot` late-joiner + explorer | `62e0f8b34` + `d0a3325b7` + `c146c8d2f` | ✓ |
| A3 | `cuda-bringup.sh` runbook doc-check (NOT a launch gate) | `de2a3ed04` | ✓ |
| B4 | `apps/seal-registration` validator portal + docs | `f14bfe5b5` + `e22c40639` + `11d96c8fc` | ✓ |
| B5 | `scripts/release.sh` + ML-DSA-signed checksums + Docker | `f2dd03e60` + `b3a0e7d49` + `3f4f32956` | ✓ |
| 📚 | `MANUAL-TESTING.md` updates for the batch | `2292534a2` | ✓ |

Plan + close-out commits: `fe9ea49e5` (plan), `3f4f32956`
(batch close-out STATUS+TODOS sync).

## What shipped — by item

### A1. Stellar quickstart protocol-22 pin

Closed Tier-1 #2 lowest-risk option (a). The three-way version
skew that paused PLAN #1 in Q1 2026 (`bridges/stellar/Cargo.toml`
pinned `soroban-sdk = "22"`, local `stellar` CLI 22.0.0, but
`stellar/quickstart:latest` rolled into protocol 25) is fixed by
two pins in `bridges/docker-compose.testnet.yml`:

1. `image: stellar/quickstart:v637-b1047.1-nightly` — newest
   dated multi-arch nightly at 2026-05-10. Stops the image from
   drifting.
2. `command: ["--local", "--protocol-version", "22"]` — the
   start script's flag explicitly downgrades the initial network
   upgrade to protocol 22.

Pin expiry risk + migration path to (b) (coordinated bump to
`soroban-sdk = "25"`) documented inline in
`bridges/docker-compose.testnet.yml` and `bridges/DEPLOYMENT.md`.

**Validated by:** `docker compose -f bridges/docker-compose.testnet.yml
config` parses cleanly with the new pins.
**NOT validated by:** A live `bridge-testnet-demo.sh` round-trip on
this dev machine — that's owed (see "Open follow-ups").

### A2a–A2d. State-sync RPC trio + late-joiner

The state-sync trio is **fully shipped end-to-end** (server side
+ client side + operator UX via CLI + explorer). Late-joining
validators on the testnet can now skip genesis-replay.

**New code:**
- `crates/seal-storage/src/snapshot_index.rs` —
  `SnapshotIndex` (bounded ring of `SnapshotMeta`,
  height-monotonic, default cap 32 ≈ rolling few-hour window).
- `crates/seal-storage/src/snapshot_chunks.rs` —
  `chunk_entries` / `decode_chunk_bytes` / `decode_chunks` /
  `manifest_fingerprint` (4 MiB cap, oversized-row exception,
  order-preserving).
- `crates/seal-token/src/balance.rs` — `snapshot_dump` (sorted
  by key) + `restore_from_snapshot` (validates bincode, drops
  dust).
- `crates/seal-node/src/consensus_runner.rs` — `snapshots:
  SnapshotIndex` field + epoch-boundary capture in
  `advance_slot` (uses chain tip's `(height, state_root)`;
  fills `tip_aggregate` from `SHA3(threshold_signature.signature)`).
- `crates/seal-node/src/rpc.rs` — three handlers
  (`handle_list_snapshots` / `handle_get_snapshot_manifest` /
  `handle_get_snapshot_chunk`). Pruned-snapshot error codes:
  `-32004` evicted, `-32005` state moved past, `-32006` block
  out of memory, `-32007` chunk_index out of range.
- `crates/seal-node/src/snapshot_bootstrap.rs` (new module) —
  `SnapshotRpc` trait, `HttpSnapshotRpc` (curl-shelled to keep
  the dep surface small), `bootstrap_from_peer`. Maps the four
  pruned-snapshot RPC error codes to one
  `SnapshotPrunedMidStream` so callers retry without
  string-matching. Final state-root cross-check guards against
  encoder/decoder drift.
- `crates/seal-node/src/main.rs` —
  `--bootstrap-from-snapshot <peer-url>` flag runs BEFORE
  genesis-mint; on success skips genesis (otherwise the mint
  would overlay the snapshot and diverge state from peers); on
  failure exits with code 3 + clear error rather than silently
  falling back.
- `crates/seal-cli/src/main.rs` — three CLI subcommands:
  `seal snapshots [--limit N]`, `seal snapshot-manifest
  --height <h> [--json]`, `seal snapshot-chunk --height <h>
  --index <n> [--out <file>]`. The chunk command exits 2 on
  hash mismatch for scripted state-sync drills.
- `apps/seal-explorer-web/{index.html,app.js}` — 23rd
  concurrent read on the explorer (State Snapshots section).
  Header tile shows "(N of M retained)"; sig-skipped to avoid
  re-rendering on idle ticks.

**Test coverage (+30 across A2a-d):**
- 8 `SnapshotIndex` unit tests (empty / monotonic / cap-evict /
  zero-cap / find-by-height / equality / default-cap).
- 11 `snapshot_chunks` unit tests (chunk emit + sizes + hash
  determinism + oversized-row exception + cap-split + manifest
  fingerprint + total_bytes + 4 round-trip / truncation).
- 6 `BalanceStore` snapshot tests (lex-sort dump / empty store /
  dump→restore round-trip / malformed bincode rejected /
  empty-stream restore / dust-entry filtering).
- 3 epoch-boundary capture tests (roster-starts-empty /
  captured-at-epoch-boundary with strict monotonicity +
  state-root cross-check / cap enforcement).
- 3 `bootstrap_from_peer` tests (round-trip against in-memory
  mock with state-root equivalence / empty-list edge case /
  hash-mismatch detection on a tampered byte).

**NOT validated by:** A real two-node testnet smoke (peer A
serves snapshots, peer B bootstraps from them via libp2p +
HTTP). The `bootstrap_from_peer` final state-root cross-check
makes silent corruption unreachable in code, but the live
multi-node smoke is owed (see "Open follow-ups").

### A3. cuda-bringup.sh runbook doc-check

Doc-only. User confirmed (2026-05-10) that **testnet launch
does not depend on CUDA** — it stays as a STATUS first-number
on the RTX 6000 host. Confirmed feature flags
(`risc0 local-prover risc0-zkvm/cuda gpu-cuda`) match
`crates/seal-zk/Cargo.toml`'s declared features, the test
target `test_risc0_full_pipeline` exists at
`crates/seal-zk/tests/e2e_integration.rs:89`, and the output
paths are all created in the script. Added a formal CSV schema
doc to the preamble so the GPU host can run it without
surprises:

```
timestamp_unix,wall_seconds,peak_rss_kb,receipt_bytes,gpu_name
```

Closing "Next:" message updated to point at current STATUS
phrasing ("Real CPU vs GPU proving") rather than the obsolete
"CUDA bring-up queued" wording.

### B4. apps/seal-registration

New axum service mirroring the `apps/seal-faucet` shape.

- `POST /register` accepts `{pubkey_hex, vrf_pubkey_hex, name,
  contact, signature_hex}`; signed message is `SHA3(b"register"
  || pubkey_hex || vrf_pubkey_hex || name || contact)`;
  verified against `pubkey_hex` via
  `seal_crypto::VerifyingKey::verify`.
- Already-registered keys are an idempotent
  `status: "already-registered"` 200 — re-submits after
  local-state loss don't surface noise.
- `GET /registrations` returns the public roster sorted by
  `accepted_at_unix_secs` ASC then `pubkey_hex` — `contact` is
  STRIPPED so operator emails / Telegram handles stay private
  on the host.
- Append-only JSONL persistence; in-memory `HashMap<pubkey_hex,
  RegistrationRecord>` for O(1) dedupe; `load_jsonl` on
  startup picks up the existing roster.
- Soft caps: `name ≤ 200`, `contact ≤ 400`. Per-IP cooldown
  defaults to 60 s.

7 unit tests including the canonical-message-byte-string check
that catches a future field-reorder regression which would
silently invalidate every existing signature.

Companion runbook: `docs/TESTNET-REGISTRATION.md` (curl + jq +
seal-cli hand-build recipe + privacy / threat model + JSONL
recovery semantics).

### B5. scripts/release.sh + ML-DSA-signed SHA256SUMS + Docker

PQC-native release pipeline. Per `CLAUDE.md` the project is
post-quantum first; classical sigstore / minisign would
contradict that, so release artifacts are signed with ML-DSA-65
via a new seal-cli subcommand pair:

- `seal sign-file <path> --key <key.json> [--out <sig-path>]`
  SHA3-256 hashes the file's bytes and ML-DSA-65 signs the
  hash. Emits the signature as hex + a sibling `.pubkey` file
  holding the verifying-key hex.
- `seal verify-file <path> --pubkey-hex <hex> --sig-file <path>`
  (or `--sig-hex <hex>`) re-hashes and verifies. Exit 0 OK / 1
  mismatch / 2 IO.

`scripts/release.sh`:
- Cross-builds Linux x86_64 + Linux ARM64 in
  `rust:1.94-bookworm` containers + macOS ARM64 on host Apple
  Silicon.
- Computes deterministic `SHA256SUMS` (sorted filenames so two
  builds of the same source tree produce byte-identical sums).
- ML-DSA-signs `SHA256SUMS` via `seal sign-file`, immediately
  re-runs `seal verify-file` against the just-produced
  signature to refuse shipping an unverifiable release.
- Tarballs `dist/seal-node-${VERSION}.tar.gz` with binaries +
  sums + sig + sig.pubkey.
- Builds Docker image
  `ghcr.io/seal-dao/seal-node:${VERSION}`.
- **Default mode is dry-run.** Docker push gated behind
  `RELEASE_PUBLISH=1`.

Companion runbook: `docs/RELEASE.md` (verifier recipe + pinned-
pubkey workflow defending against a malicious upstream that
swaps both `.sig` and `.sig.pubkey` in the same archive +
explicit "what this script doesn't do yet" callouts).

Manual round-trip validated end-to-end: keygen → sign-file →
verify-file (OK, exit 0) → tamper-the-file → verify-file
(FAIL, exit 1).

### MANUAL-TESTING.md

Three new sections (§26 state-sync RPC trio + late-joiner, §27
registration portal, §28 release pipeline) + a §7.5 Stellar
protocol-22 pin sub-section + a refreshed coverage note +
refreshed test counts (Storage 18 → 37, Token 88 → 94, Node 217
→ 240, new Registration row at 7, total 985 → 1116). Coverage
note flags the live two-node smoke (§26.5) and the bridge-
testnet-demo round-trip (§7.5) as documented but **not run on
this dev machine in this session**.

## Open follow-ups

These are exposed by today's work and worth tracking, but were
**not** in scope for the locked batch.

### Owed live smokes (carried from this batch)

1. **Two-node `--bootstrap-from-snapshot` smoke.** Bring up
   peer A (long-running, has crossed at least one epoch
   boundary), bring up peer B with
   `--bootstrap-from-snapshot http://A:8545`, confirm peer B's
   genesis-mint line is suppressed and the
   `Bootstrap-from-snapshot: balances populated` log fires.
   In-memory mock test covers the protocol; the live HTTP
   round-trip is owed. Recipe is in `MANUAL-TESTING.md` §26.5.
2. **Bridge-testnet-demo round-trip on the protocol-22 pin.**
   Verify `stellar contract install` completes against the new
   `stellar/quickstart:v637-b1047.1-nightly` image and the
   lock side reaches the mint event. Recipe in §7.5.
3. **CUDA bring-up on the RTX 6000 host.** Run
   `scripts/cuda-bringup.sh` for the first GPU wall-time /
   peak-RSS / receipt-size numbers; paste the parsed-metrics
   block into STATUS.md's "Real CPU vs GPU proving" line. NOT
   a launch gate (user confirmed) but worth doing.

### Code-side follow-ups uncovered today

4. **`seal register-validator` subcommand.** The portal works
   today via curl + a hand-built signature recipe (see
   `docs/TESTNET-REGISTRATION.md`). A first-class
   `seal register-validator --name … --contact …
   --vrf-pubkey-hex … --key wallet.json --portal http://…`
   would close the operator-UX loop. ~1 commit.
5. **Total-burned attestation channel for snapshots.**
   `BalanceStore::restore_from_snapshot` resets `total_burned`
   to zero — testnet-acceptable but documented as needing a
   separate totals-attestation channel before mainnet (the
   restored store reports "burned since the snapshot" rather
   than the chain's true cumulative burn). Out of scope today;
   add to mainnet-prerequisite list.
6. **Token-state HAMT in the snapshot stream.** Today's
   snapshot dumps only `BalanceStore`; the token manager's
   per-symbol state still rebuilds via genesis. Once tokens
   are part of the state-root, A2a-d's stream needs to cover
   that surface too. The current `seal_getSnapshotManifest`
   docstring already calls this out as a future split.
7. **Tip catch-up after bootstrap.** The late-joiner currently
   stops at the snapshot height; a real validator must then
   stream blocks `H+1..tip` from a peer to fully sync. The
   existing P2P + replay machinery covers this, but the
   `--bootstrap-from-snapshot` path doesn't yet wire it
   together. Owe a "snapshot-then-header-sync" integration.
8. **`scripts/release.sh` follow-ups** (per
   `docs/RELEASE.md` §"What this script doesn't do yet"):
   - `gh release create` automation under
     `RELEASE_PUBLISH=1`.
   - SLSA-style provenance attestation.
   - Threshold release signing via `seal-threshold` (N-of-M
     operators rather than a single ML-DSA key).

### Deferred — genuinely external (NOT in this batch)

These remain in `TODOS.md` "Deferred — genuinely external" and
were explicitly excluded by the user from the testnet-readiness
batch:

- Veridise PQC audit + Trail-of-Bits / Cryspen Ringtail audit
  + protocol audit
- Immunefi bug bounty program activation
- Validator recruitment for the incentivized testnet
- Bootstrap node infrastructure (DNS, VM provision, regional
  spread)
- Mainnet bridge deploy + governance vote
- Mainnet genesis (30+ validators, distribution execution)

## Next-step recommendations

If the user picks the work back up tomorrow, in priority order:

1. **Run the three owed smokes (1, 2, 3 above).** Cheap to
   execute, surfaces any wire-format / runtime regression the
   unit tests didn't catch. The two-node
   `--bootstrap-from-snapshot` smoke in particular is the
   "did the state-sync trio actually work end-to-end" test.
2. **Add `seal register-validator` (#4).** Closes the operator
   UX loop on the registration portal — without it,
   prospective validators must run a curl + jq recipe by hand
   to register, which is a friction point.
3. **Wire snapshot-then-header-sync (#7).** Today's late-joiner
   stops at the snapshot's height; a real testnet operator
   needs the rest. ~1-2 sessions.
4. **Token-state HAMT in the stream (#6).** Once balance
   snapshots are battle-tested, extend the same encoder /
   decoder / manifest plumbing to cover the token manager.
   Same shape as A2a-d, ~1 session.
5. **Release-pipeline hardening (#8a–c).** `gh release create`
   automation is a one-liner; SLSA + threshold signing are
   bigger. Sequence as needed for the first real release cut.

The deferred-external items remain on hold until the user has
budget / vendor engagement / multi-machine VPN testing capacity
to push them.

## Pointers

### Edited / new files this batch (27 total)

**New crates / apps:**
- `apps/seal-registration/{Cargo.toml,src/main.rs}` — B4
- `crates/seal-storage/src/snapshot_index.rs` — A2a
- `crates/seal-storage/src/snapshot_chunks.rs` — A2b/A2c
- `crates/seal-node/src/snapshot_bootstrap.rs` — A2d

**New scripts:**
- `scripts/release.sh` — B5
- `scripts/cuda-bringup.sh` (preamble + closing message
  rewrite) — A3

**New docs:**
- `docs/TESTNET-REGISTRATION.md` — B4
- `docs/RELEASE.md` — B5
- `TODOS/SESSION-2026-05-10-testnet-readiness.md` — opening plan
- `TODOS/SESSION-2026-05-10-batch-closeout.md` — this file

**Modified — Rust code:**
- `Cargo.toml` (workspace member: seal-registration)
- `crates/seal-cli/{Cargo.toml,src/main.rs}` (4 new
  subcommands: snapshots, snapshot-manifest, snapshot-chunk,
  sign-file, verify-file)
- `crates/seal-cli/Cargo.toml` (+base64)
- `crates/seal-node/{Cargo.toml,src/lib.rs,src/main.rs,
  src/consensus_runner.rs,src/rpc.rs}` (snapshot capture +
  three RPC handlers + late-joiner CLI flag)
- `crates/seal-node/Cargo.toml` (+base64)
- `crates/seal-storage/src/lib.rs` (re-exports)
- `crates/seal-token/src/balance.rs` (snapshot_dump +
  restore_from_snapshot)

**Modified — config / docker:**
- `bridges/docker-compose.testnet.yml` — A1 pins
- `bridges/DEPLOYMENT.md` — A1 doc updates

**Modified — explorer:**
- `apps/seal-explorer-web/{index.html,app.js}` — A2d
  State Snapshots section

**Modified — top-level docs:**
- `STATUS.md` — six entries chained per item
- `TODOS.md` — batch-progress markers + close-out
- `MANUAL-TESTING.md` — §7.5 + §26 + §27 + §28 +
  refreshed totals

### Key entry points for picking the work back up

- **Plan**: [`TODOS/SESSION-2026-05-10-testnet-readiness.md`](SESSION-2026-05-10-testnet-readiness.md)
- **This close-out**: this file
- **Roadmap**: [`TODOS.md`](../TODOS.md) "Testnet-readiness
  batch (8/8 closed)" + "Deferred — genuinely external"
- **Project status matrix**: [`STATUS.md`](../STATUS.md)
- **Manual testing**: [`MANUAL-TESTING.md`](../MANUAL-TESTING.md)
  §26-§28 cover the new functionality; §7.5 covers the Stellar
  pin
- **Operator runbooks**:
  [`docs/TESTNET-REGISTRATION.md`](../docs/TESTNET-REGISTRATION.md),
  [`docs/RELEASE.md`](../docs/RELEASE.md),
  [`bridges/DEPLOYMENT.md`](../bridges/DEPLOYMENT.md)

### Memory-system notes worth carrying forward

- The user's "do not push, stay focused on testnet launch"
  guidance held all session — no `git push`, every commit
  local.
- The standard 3-commit shape (code → docs/explorer wiring →
  STATUS+TODOS sync) was followed for every item except A1
  (single doc-only file → single commit) and A3 (doc-only,
  same).
- Quick CI was run after every code-touching commit (~30
  green runs over the day) per the user's "commit & CI often"
  guidance.
