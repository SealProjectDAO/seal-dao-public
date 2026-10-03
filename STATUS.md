# Seal DAO — Project Status

Last updated: 2026-05-15 afternoon (committee-key rotation +
observability + persistence batch, **10 commits**, 1139 → 1142
tests, all quick CI green)

## 2026-05-15 — Committee-key rotation + observability + persistence

Closes the "rotation needs restart" testnet gap flagged in the
2026-05-15 morning testnet-readiness review (`xxx-bbb.txt` item
4), then wraps the surface with operator-grade observability so
testnet runs can alert on the bridge state without polling JSON-
RPC.

  - 1. `seal_bridgeRotateCommitteeKey` — council-gated (2/3,
    admin-auth) RPC. New `BridgeManager::committee_key_fingerprint`
    (SHA-3, host PQ default) + `_sha256` (cross-chain diff,
    matches Solana `sol_sha256` + Stellar `env.crypto().sha256()`).
  - 2. `seal_bridgeGetCommitteeKeyStatus` — no-auth read,
    surfaces both fingerprints.
  - 3. Persistence — rotation writes
    `<data_dir>/bridge-committee-key.hex` (atomic tmp+rename);
    startup prefers that file over `--bridge-committee-key` so
    rotations survive reboots. Rotate response gains
    `persisted: bool` + `persist_error` so coordinators see
    write failures.
  - 4. `/metrics` bridge surface: 9 gauges
    (`seal_bridge_committee_key_set`,
    `seal_bridge_committee_key_persisted`,
    `seal_bridge_paused_chains`,
    `seal_bridge_deposits_{total,pending}`,
    `seal_bridge_withdrawals_total`,
    `seal_bridge_invariant_violated`,
    `seal_bridge_total_{locked,minted}{token=…}`,
    label-info `seal_bridge_committee_key_fingerprint{sha2_hex=…}`).
  - 5. Prometheus alerts (`monitoring/alert.rules.yml`): 6 rules
    auto-loaded — committee-key absence, persistence failure,
    paused chains, deposit backlog, fingerprint drift,
    invariant violation + per-asset supply mismatch.
  - 6. Grafana dashboard bridge row matches the new gauges (red
    on key-unset, chain-paused, invariant-violated).
  - 7. `seal bridge-key-status` CLI with `--expect-sha2 <hex>`
    drift check (exit 0 match / 1 unset / 2 mismatch). Drop-in
    for bridge-e2e.sh and rotation runbooks.
  - 8. `scripts/bridge-e2e.sh` asserts the docker-compose committee
    key fingerprint on stack-up so config drift surfaces in the
    first 5 seconds rather than after a full forward-leg deploy.
  - 9. `BridgeManager::committee_key_eq` uses `subtle::ConstantTimeEq`
    so the persistence-check metric can't leak the key through
    response timing.

Open follow-up: Soroban `committee_key_hash()` view function so
the per-chain drift cross-check is fully automatic. Drafted +
reverted this session because the contract lives outside the
workspace and its build path requires the `with_crates_io`
vendor-config shim used by `scripts/bridge-e2e.sh`.

## 2026-05-10 evening — Testnet-readiness batch FULLY CLOSED (8/8)

Eight items locked at the start of the day, now all green:

  - A1 ✓ Stellar quickstart protocol-22 pin
  - A2a ✓ seal_listSnapshots RPC
  - A2b ✓ seal_getSnapshotManifest RPC
  - A2c ✓ seal_getSnapshotChunk RPC
  - A2d ✓ --bootstrap-from-snapshot late-joiner
  - A3 ✓ cuda-bringup.sh runbook doc-check (doc-only, NOT a launch gate)
  - B4 ✓ apps/seal-registration validator-registration portal
  - B5 ✓ scripts/release.sh + ML-DSA-signed checksums + Docker

Test count grew from 1077 (start of session) → 1116 (+39 new
tests across the batch). All commits clean clippy + green
CI. State-sync RPC trio fully shipped (server + client + UX);
testnet operations runbooks complete (faucet existed; now
registration + release added).

## 2026-05-10 evening — B5 scripts/release.sh + ML-DSA-signed checksums + Docker (2 commits)

- **`f2dd03e60` — seal-cli + scripts: release.sh + ML-DSA-signed SHA256SUMS + Docker**.
  PQC-native release pipeline. New seal-cli subcommands
  `sign-file <path> --key <key.json> [--out <sig-path>]` and
  `verify-file <path> --pubkey-hex <hex> --sig-file <path>`
  (or `--sig-hex <hex>`). sign-file SHA3-hashes the file's
  bytes and ML-DSA-65 signs the hash; emits the signature as
  hex + a sibling `.pubkey` file. verify-file recomputes,
  exit 0 OK / 1 mismatch / 2 IO. New `scripts/release.sh`
  cross-builds linux-x86_64 + linux-aarch64 in
  `rust:1.94-bookworm` containers + darwin-aarch64 on host
  Apple Silicon, computes SHA256SUMS (sorted filenames so
  two builds of the same source produce byte-identical
  sums), ML-DSA-signs SHA256SUMS via `seal sign-file`,
  immediately re-runs `seal verify-file` against its own
  pubkey to refuse shipping an unverifiable signature,
  tarballs everything, builds Docker image
  `ghcr.io/seal-dao/seal-node:${VERSION}`. **Default mode
  is dry-run**; Docker push gated behind `RELEASE_PUBLISH=1`.
  Per CLAUDE.md: classical sigstore / minisign would
  contradict the post-quantum-first policy, so the signing
  primitive matches the chain's own ML-DSA-65 identity
  scheme.
- **`b3a0e7d49` — docs: RELEASE.md companion runbook**.
  Documents what artifacts the script produces, the
  PQC-rationale, prerequisites (release keypair backup),
  the verifier-side recipe a downloader runs (sums + signed
  manifest), the pinned-pubkey workflow defending against a
  malicious upstream that swaps both `.sig` and `.sig.pubkey`,
  and explicit "what this script doesn't do yet" callouts
  (no gh release create, no SLSA provenance, no threshold
  release signing — all future hardenings).
- Quick CI #29: **green, 1116 tests, clippy clean, 81s**.

## 2026-05-10 evening — B4 apps/seal-registration validator-registration portal (2 commits)

- **`f14bfe5b5` — apps/seal-registration: validator-registration portal**.
  New axum service mirroring the apps/seal-faucet shape. POST
  /register accepts an ML-DSA-signed
  `{pubkey_hex, vrf_pubkey_hex, name, contact, signature_hex}`;
  signed message is `SHA3(b"register" || pubkey_hex ||
  vrf_pubkey_hex || name || contact)`; verified against the
  supplied pubkey via `seal_crypto::VerifyingKey::verify`.
  Anyone can submit any operator's payload; without the
  operator's signing key the signature won't verify.
  Already-registered pubkeys are an idempotent
  `status: "already-registered"` 200, not an error.
  `GET /registrations` returns the public roster sorted by
  `accepted_at_unix_secs` ASC then `pubkey_hex` — `contact` is
  STRIPPED so operator emails / Telegram handles stay private.
  Append-only JSONL persistence; in-memory HashMap on
  pubkey_hex backs O(1) dedupe; load_jsonl on startup picks
  up the existing roster. Soft caps: name ≤ 200, contact ≤
  400. Per-IP cooldown defaults to 60 s. 7 unit tests
  including the canonical-message-byte-string check that
  catches a future field-reorder regression which would
  silently invalidate every existing signature.
- **`e22c40639` — docs: TESTNET-REGISTRATION.md companion runbook**.
  Mirrors `docs/TESTNET-FAUCETS.md` shape. Documents portal
  role (NOT an admission gate, just a roster), wire format,
  curl + jq + seal-cli hand-build recipe (until `seal
  register-validator` lands), JSONL persistence + recovery
  semantics, privacy / threat model (contact stays
  operator-private, the portal proves nothing about stake or
  node control).
- Quick CI #27: **green, 1116 tests (+7 new), clippy clean,
  47s elapsed**.

## 2026-05-10 evening — A3 cuda-bringup.sh runbook doc-check (1 commit)

- **Doc-only on this dev machine.** User confirmed
  (2026-05-10) that **testnet launch does not depend on CUDA**;
  it stays as a STATUS first-number on the RTX 6000 host. The
  doc-check confirmed `scripts/cuda-bringup.sh` is current —
  references existing `seal-zk` features (`risc0`,
  `local-prover`, `gpu-cuda` + `risc0-zkvm/cuda`), targets the
  real `test_risc0_full_pipeline` integration test in
  `crates/seal-zk/tests/e2e_integration.rs:89`, writes to
  `target/cuda-bringup/{host-info.txt,results.txt,results.csv,
  time.log}`. CSV schema is now formally documented in the
  preamble (`timestamp_unix,wall_seconds,peak_rss_kb,
  receipt_bytes,gpu_name`) so the GPU host can run it without
  surprises. Closing "Next:" message updated to point at the
  current STATUS phrasing ("Real CPU vs GPU proving") rather
  than the obsolete "CUDA bring-up queued" wording.

## 2026-05-10 evening — A2d --bootstrap-from-snapshot late-joiner (2 commits)

- **`62e0f8b34` — seal-node + seal-token: --bootstrap-from-snapshot late-joiner**.
  Closes the state-sync RPC trio's client side. With A2a-c
  already serving snapshots / manifests / chunks, A2d wires
  them into a one-shot bootstrap that populates a fresh node's
  BalanceStore from a peer's most recent snapshot, skipping
  genesis-replay. New `seal-token::BalanceStore::restore_from_snapshot`
  inverts `snapshot_dump` (validates bincode, drops dust,
  rebuilds total_supply); `total_burned` resets to zero
  (testnet-acceptable, mainnet needs a totals-attestation
  channel — out of scope for this batch). New
  `crates/seal-node/src/snapshot_bootstrap.rs` module: trait
  `SnapshotRpc` + `HttpSnapshotRpc` (curl-shelled, ~10 ms
  per-call invisible against pulling 4 MiB chunks) +
  `bootstrap_from_peer(rpc) -> BootstrapOutcome`. Maps
  pruned-snapshot error codes (-32004/-32005/-32006/-32007) to
  a single `SnapshotPrunedMidStream` so callers retry without
  string-matching. Final state-root cross-check guards against
  encoder/decoder drift. New `--bootstrap-from-snapshot
  <peer-rpc-url>` flag in `seal-node` runs the client BEFORE
  genesis-mint; on success skips genesis (otherwise the mint
  would overlay the snapshot and diverge state from peers); on
  failure exits with code 3 + clear message rather than
  silently falling back. 7 new tests: 4 BalanceStore restore
  (round-trip / malformed / empty / dust filter) + 3 bootstrap
  client (round-trip / empty list / hash mismatch).
- **`d0a3325b7` — explorer: State Snapshots section in seal-explorer-web**.
  23rd concurrent read on the explorer. Header tile with
  "(N of M retained)" liveness count + one-paragraph
  operator-facing explanation pointing at
  `seal-node --bootstrap-from-snapshot` + four-column table
  (height, epoch, state_root[trunc], captured-at).
  Sig-skipped to avoid re-rendering on idle ticks. Older
  nodes without the RPC silently render an empty section.
- Quick CI #24: **green, 1109 tests (+7 new), clippy clean,
  58s + 43s back-to-back**.

State-sync RPC trio is now FULLY shipped: server side (A2a-c)
+ client side (A2d) + operator UX (CLI commands `seal
snapshots` / `seal snapshot-manifest` / `seal snapshot-chunk` +
explorer State Snapshots tile). Late-joining validators on the
testnet can skip genesis-replay end-to-end.

## 2026-05-10 evening — A2c seal_getSnapshotChunk state-sync RPC (2 commits)

- **`b8b58c653` — seal-storage + seal-node: seal_getSnapshotChunk + decode_chunks**.
  Third sub-step of the state-sync RPC trio. With A2a + A2b
  already returning the manifest, A2c serves the actual chunk
  byte payload by `(height, chunk_index)`. New
  `decode_chunk_bytes` and `decode_chunks` in
  `seal-storage::snapshot_chunks` — the inverse of
  `chunk_entries`. Well-formed chunks round-trip exactly;
  truncated chunks surface a structured `Err("chunk truncated:
  ...")` rather than panic so the late-joiner can detect a
  host that moved past the snapshot mid-stream and re-fetch.
  4 new round-trip / truncation unit tests. Handler base64-
  encodes the chunk's byte payload (~33% transit overhead,
  well within the 4 MiB cap), validates `chunk_index` against
  the freshly-computed chunk count (`-32007`), reuses the
  pruned-snapshot error codes from A2b. The decoded
  `(key, value)` records are exactly what the late-joiner
  (A2d) will feed into a fresh `BalanceStore`.
- **`07fcdb06f` — seal-cli: 'seal snapshot-chunk' subcommand**.
  Decodes the server's base64 payload, recomputes a fresh SHA3
  hash locally, prints MATCH / MISMATCH. Optional `--out
  <file>` persists raw bytes for offline inspection. Exit code
  2 on hash mismatch so scripts driving an end-to-end
  state-sync drill can fail fast.
- Quick CI #22: **green, 1102 tests (+4 new), clippy clean,
  61s + 47s back-to-back**.

## 2026-05-10 evening — A2b seal_getSnapshotManifest state-sync RPC (2 commits)

- **`24405b5c2` — seal-storage + seal-token + seal-node: seal_getSnapshotManifest**.
  Second sub-step of the state-sync RPC trio. Builds on A2a's
  roster: a late-joiner that picked
  `(height, state_root)` from `seal_listSnapshots` can now fetch
  the chunk-list manifest and verify each chunk before pulling
  bytes via A2c. New
  `crates/seal-storage/src/snapshot_chunks.rs` with `Chunk`,
  `ChunkRef`, `MAX_CHUNK_BYTES = 4 MiB`,
  `chunk_entries(Vec<(key, value)>) -> Vec<Chunk>`
  (order-preserving; soft cap with oversized-row exception so
  >4 MiB rows get their own chunk rather than infinite-looping),
  `manifest_from_chunks` and `manifest_fingerprint` (single-hash
  manifest identity). 7 unit tests on the chunker.
  `BalanceStore::snapshot_dump` emits raw HAMT leaves sorted
  byte-wise by key — the chunker is order-preserving so this is
  the source of cross-node manifest determinism. 2 unit tests.
  `ConsensusRunner::advance_slot` now fills `tip_aggregate` from
  `SHA3(threshold_signature.signature)` — single-node /
  pre-Ringtail nodes get a non-trivial fingerprint so the
  manifest commits to *something* attestation-shaped from day
  one. `seal_getSnapshotManifest` handler refuses pruned
  manifests on three error codes: `-32004` snapshot evicted
  from cap, `-32005` live state has moved past the snapshot
  point, `-32006` block at height not in memory. Returns
  `{ height, epoch, state_root_hex, tip_block_hash_hex,
  manifest_hash_hex, total_bytes, chunk_count, chunks: [...],
  tip_aggregate_hex? }`.
- **`1143e14b7` — seal-cli: 'seal snapshot-manifest' subcommand**.
  Renders summary fields + chunk preview (first 8 + last 4 with
  elision marker for >12-chunk manifests); `--json` flag for
  piping straight into `seal_getSnapshotChunk` (A2c) once it
  lands. Companion to `seal snapshots` from A2a.
- Quick CI #20: **green, 1098 tests (+10 new), clippy clean,
  58s + 47s back-to-back**.

## 2026-05-10 afternoon — A2a seal_listSnapshots state-sync RPC (2 commits)

- **`26ecbb3a0` — seal-storage + seal-node: seal_listSnapshots**.
  First sub-step of the state-sync RPC trio
  (A2a → A2b → A2c → A2d). Late-joining validators on the
  testnet need to skip genesis-replay; the recipe is (1) pick a
  recent snapshot from the roster, (2) fetch chunk-list manifest,
  (3) stream content-addressed chunks, (4) resume header-sync
  from the snapshot tip. New
  `crates/seal-storage/src/snapshot_index.rs`:
  `SnapshotMeta { height, epoch, state_root,
  captured_at_unix_secs, tip_aggregate }` in a bounded ring
  with strictly height-monotonic inserts and default cap = 32
  (≈ a rolling few-hour window at 32-slot epochs). Capture
  fires from `ConsensusRunner::advance_slot` at every epoch
  boundary, sourced from the chain tip so snapshots reference
  actually-finalized state. RPC `seal_listSnapshots` returns
  newest-first with optional `limit` param; `tip_aggregate_hex`
  is only emitted when populated (A2b will fill it). 8 unit
  tests on `SnapshotIndex` + 3 integration tests on the
  capture hook (roster-starts-empty / captured-at-epoch-boundary
  with strict monotonicity + state-root cross-check / cap
  enforcement).
- **`2127d821c` — seal-cli: 'seal snapshots' subcommand**.
  Operator entry point ahead of A2d. `seal snapshots
  --node <url> [--limit <N>]`. Fixed-width
  `height / epoch / state_root[24] / captured_s` table,
  newest-first. Explorer wiring deliberately deferred to A2d
  — snapshots aren't address-keyed and the chain-wide tab
  earns its place once there's a "this snapshot just
  bootstrapped a peer" UX hook to render.
- Quick CI #17: **green, 1088 tests (+11 new), clippy clean,
  42s elapsed**.

## 2026-05-10 afternoon — A1 Stellar quickstart protocol-22 pin (1 commit)

- **`5e41c7378` — bridges: pin stellar/quickstart + protocol-22**.
  First item of the testnet-readiness batch. Closes Tier-1 #2
  lowest-risk option (a). The three-way version skew
  (`bridges/stellar/Cargo.toml` `soroban-sdk = "22"`, local
  `stellar` CLI `22.0.0`, but `stellar/quickstart:latest`
  rolled into protocol 25 in Q1 2026) made `stellar contract
  install` reject our 22.x WASM. Two pins fix it:
  (1) `image: stellar/quickstart:v637-b1047.1-nightly` — newest
  dated multi-arch nightly at 2026-05-10, stops the image from
  drifting under us; (2) `command: --local --protocol-version
  22` — the start script's flag explicitly pins the initial
  network upgrade to protocol 22, matching the Soroban 22 ABI.
  Pin expiry risk and migration path to (b) (coordinated
  soroban-sdk 25 bump) documented inline in
  `bridges/docker-compose.testnet.yml` and
  `bridges/DEPLOYMENT.md`. Quick CI #16 green.

## 2026-05-10 midday — Testnet-readiness batch planned

User locked the next batch: Stellar SDK skew (A1), state-sync
RPCs (A2a–d), CUDA bring-up doc check (A3), validator
registration portal (B4), release script (B5). Audits, bug
bounty, recruitment, bootstrap-node infra explicitly excluded.
**CUDA is *not* a testnet-launch gate** — it's a STATUS row 7/8
first-number on the GPU host. Plan saved to
`TODOS/SESSION-2026-05-10-testnet-readiness.md`. Implementation
follows the standard 3-commit-per-item shape with a quick CI
run after each.

## 2026-05-10 midday — listTokensByFeeAuthority + 15th quick CI green (2 more commits)

- **`bb90bcc41` — `seal_listTokensByFeeAuthority`**.
  Third leg of the authority-current trio (mint / freeze /
  fee). Closes the explicit follow-up the prior cascade had
  spun out. Treasury-style operators sometimes hold the
  fee-authority key independently of mint and freeze, so the
  by-fee view diverges from both after a `set_fee_authority`
  rotation; after `renounce_fee_authority` the symbol
  disappears from every view (transfer fee then immutable).
  New `TokenManager::tokens_by_fee_authority`. seal-token
  tests +1: rotates GOLD's fee authority alice → eve while
  keeping mint+freeze pinned, asserts independent
  divergence, then renounces and confirms the row disappears
  from every per-fee-authority view. CLI `seal
  my-fee-authorities --address <addr>` renders the per-row
  `transfer_fee_bps` (the fee an operator is about to
  consider rotating).
- **`2bdc446a4` — explorer: Account Lookup adds tokens-by-fee-authority sub-table**.
  Twenty-second concurrent read (was 21). Sits next to the
  mint-authority and freeze-authority sub-tables; the three
  together let an operator see, at a glance, which authority
  surfaces still answer to this address after any combination
  of rotations and renouncements. New "Fee authority" summary
  card + sub-table. Fee-bps column color-shifts to the accent
  on a non-zero rate, dim on zero — a fee-authority operator
  deciding whether to rotate or renounce sees the live rate
  first.
- Quick CI #15 (back-to-back with #14): **green, 1077 tests,
  clippy clean, 101s elapsed**. Note: rebuild from scratch
  because root partition was at 99% (170 MiB free) and the
  prior link aborted with `errno=28`; `cargo clean` reclaimed
  37.3 GiB, build then went green.

## 2026-05-10 morning — listTokensByFreezeAuthority + 14th quick CI green (2 more commits)

- **`d4de3f074` — `seal_listTokensByFreezeAuthority`**.
  Mirror of the immediately-prior
  `seal_listTokensByMintAuthority` for the freeze-authority
  surface. Compliance and operational separation often pair
  a long-lived deployer/mint authority with a short-lived
  freeze authority on a dedicated key, so the by-freeze view
  diverges from the by-mint view independently once that
  rotation happens. New
  `TokenManager::tokens_by_freeze_authority`. seal-token
  tests +1: rotates GOLD's freeze authority alice → dave
  without touching the mint authority and asserts the two
  per-authority views move independently. CLI
  `seal my-freeze-authorities --address <addr>`. The CLI
  table renders the per-row `frozen` (global-kill-switch)
  state — actionable for an operator since a token already
  globally-frozen has nothing to do.
- **`e095b4c2f` — explorer: Account Lookup adds tokens-by-freeze-authority sub-table**.
  Twenty-first concurrent read (was 20). Sits next to the
  previous commit's mint-authority sub-table; together they
  make the post-rotation divergence visible. New "Freeze
  authority" summary card + sub-table with a globally-frozen
  column that color-shifts red on YES — operationally-
  actionable rows. Creator column reuses the "self"
  (dimmed) / head…tail-ellipsis treatment for visual parity.
- Quick CI #14 (back-to-back with #13): **green, 1076
  tests, clippy clean, 75s elapsed**.

## 2026-05-10 morning — listTokensByMintAuthority + 13th quick CI green (2 more commits)

- **`23c7453f4` — `seal_listTokensByMintAuthority`**.
  Closes the explicit follow-up that the
  `tokens_by_creator` doc comment had been carrying
  ("authority-current view is left for a follow-up if
  needed"). Mint authority is mutable —
  `set_mint_authority` rotates it, `renounce_mint_authority`
  irrevocably clears it — so the creator view (immutable)
  and the authority-current view diverge as soon as any
  token rotates. Both views are useful; the new RPC answers
  "which tokens can I mint right now?" — a question the
  creator-view cannot answer post-rotation. New
  `TokenManager::tokens_by_mint_authority`. seal-token tests
  +1: pre-rotation agreement / post-rotation divergence
  (alice → carol on GOLD while alice keeps BRONZE) /
  post-renounce removal from every per-authority view. CLI
  `seal my-mint-authorities --address <addr>`.
- **`47ec30789` — explorer: Account Lookup adds tokens-by-mint-authority sub-table**.
  Twentieth concurrent read (was 19). The new sub-table
  sits next to "Tokens created by this address" — the
  asymmetry is the point: a token whose deployer renounced
  or rotated authority disappears from one view and reappears
  (or doesn't) in the other. Creator column renders "self"
  (dimmed) when the row's creator equals the queried
  address; rotated-into-this-address rows show a head…tail-
  ellipsis of the bech32m creator with the full address on
  the cell title attribute, so the eye lands on the
  surprising entries.
- Quick CI #13 (back-to-back with #12): **green, 1075
  tests, clippy clean, 76s elapsed**.

## 2026-05-10 morning — getCouncilMemberByAddress + 12th quick CI green (2 more commits)

- **`cdfcf4478` — `seal_getCouncilMemberByAddress`**.
  Per-address Technical Council membership lookup,
  paralleling the immediately-prior
  `seal_getValidatorByAddress`. Until this RPC, a wallet
  asking "am I on the council?" pulled the full
  `seal_bridgeCouncilList` and ran
  `SHA3-256(hex_decode(pubkey)) == address_hash` client-side.
  New `TechnicalCouncil::find_by_address_hash` hex-decodes
  each member's stored pubkey, hashes the bytes, and matches
  against the supplied 32-byte address-hash. Hex-decode
  errors on a stored member skip that entry rather than
  aborting the scan (belt-and-suspenders — malformed pubkeys
  can only enter via an add-member RPC that itself validates
  hex). Linear scan is fine; the council caps at 11 seats.
  Returns the member's pubkey hex / name / term-start /
  term-end epochs, or `member: null`. Unsigned read;
  `seal_bridgeCouncilList` exposes the same data. CLI
  `seal council-status --address <addr>`. seal-node
  governance tests +1.
- **`fb71b01de` — explorer: Account Lookup adds Tech Council card**.
  Nineteenth concurrent read (was 18) — mirrors the
  validator-status card from the previous commit so both
  governance-adjacent role surfaces ("are you a validator? are
  you on the council?") read at a glance. Two colored states:
  "SEATED" (green) / "no" (dim). Detail line carries display
  name + term-start/term-end epochs so operators see how long
  until the seat needs renewal.
- Quick CI #12 (back-to-back with #11): **green, 1074 tests,
  clippy clean, 68s elapsed**.

## 2026-05-10 morning — getValidatorByAddress + 11th quick CI green (2 more commits)

- **`8ee00412b` — `seal_getValidatorByAddress`**.
  Per-address validator-status lookup. Until this RPC, a
  wallet asking "am I a validator?" pulled the full
  `seal_listValidators` set and ran
  `SHA3-256(public_key_hex) == address_hash` client-side. New
  `ValidatorSet::find_by_address_hash` does the same scan
  server-side: hashes each validator's pubkey and matches
  against the supplied 32-byte address-hash (an address
  encodes `bech32m(SHA3-256(pubkey))`). Linear scan — fine
  for the typical sub-thousand validator set; promotable to a
  hash-keyed index per epoch if it ever matters. Returns the
  validator's pubkey hex / VRF pubkey hex / stake / active
  flag, or `validator: null` if not in the set. Unsigned
  read; `seal_listValidators` already exposes the same data.
  CLI `seal validator-status --address <addr>`. seal-
  consensus tests 57 → 58.
- **`4c7be262a` — explorer: Account Lookup adds Validator status card**.
  Eighteenth concurrent read (was 17). Three colored states so
  they read at a glance: "ACTIVE" (green, in set + healthy),
  "inactive" (red, in set but slashed/unbonding — visually
  distinct from non-validator because the failure mode
  differs), "no" (dim, not in the set). Detail line under the
  card carries stake (micro-SEAL) + pubkey fingerprint (first
  16 hex chars; full hex stays in the RPC JSON for callers
  that need to verify identity exactly).
- Quick CI #11 (back-to-back with #10): **green, 1073 tests,
  clippy clean, 76s elapsed**.

## 2026-05-10 morning — listBridgeWithdrawalsByInitiator + 10th quick CI green (2 more commits)

- **`873b2dcba` — `seal_listBridgeWithdrawalsByInitiator`**.
  Per-initiator gap-closer paralleling the immediately-prior
  `seal_listBridgeDepositsByRecipient` — now both sides of the
  bridge expose a per-address view. Until this RPC, a wallet
  asking "what did I send out via the bridge?" pulled the
  global withdrawal stream and filtered `seal_address`
  client-side. New
  `BridgeManager::list_withdrawals_by_initiator` filters the
  withdrawal map by `seal_address` (the burner-on-Seal field)
  and sorts by withdrawal ID — same diff-stable order as
  `list_withdrawals`. Empty Vec for initiators with no
  withdrawals. Unsigned read; bridge state is already publicly
  visible. CLI `seal my-bridge-withdrawals --address <addr>`.
  seal-bridge tests 61 → 62.
- **`5939927c1` — explorer: Account Lookup adds bridge-withdrawals sub-table**.
  Seventeenth concurrent read (was 16). New "Bridge
  withdrawals" summary card + Withdrawal-ID / Dest-chain /
  Token / Amount / Dest-address / Executed sub-table; dest
  addresses (32-56 chars on Solana/Stellar) rendered head…tail-
  ellipsis with the full string available via cell title
  tooltip. Pending (not-yet-executed) rows dim the Executed
  cell so the eye lands on completed ones first.
- Quick CI #10 (back-to-back with #9): **green, 1072 tests,
  clippy clean, 82s elapsed**.

## 2026-05-10 morning — listBridgeDepositsByRecipient + 9th quick CI green (2 more commits)

- **`7ec84c726` — `seal_listBridgeDepositsByRecipient`**.
  Bridge per-recipient gap-closer paralleling the existing
  `seal_listBridgeWrappedBalances`. The wrapped-balance RPC
  covers the post-mint side (current balance per token); this
  one covers the deposit-history side (cross-chain "what came
  in" for the address). Until this RPC a wallet asking "what
  crossed the bridge to me?" pulled the global
  `seal_getBridgeDeposits` stream and filtered `seal_address`
  client-side. New `BridgeManager::list_deposits_by_recipient`
  filters and sorts by deposit ID (same diff-stable order as
  `list_deposits`). CLI `seal my-bridge-deposits --address
  <addr>`. seal-bridge tests 60 → 61.
- **`e557f6f09` — explorer: Account Lookup adds bridge-deposits sub-table**.
  Sixteenth concurrent read (was 15). New "Bridge deposits"
  summary card + Deposit-ID / Source-chain / Token / Amount /
  Confirmations / Processed sub-table; unprocessed (still in
  flight) rows dim the Processed cell so the eye lands on
  minted deposits first.
- Quick CI #9 (back-to-back with #8): **green, 1071 tests,
  clippy clean, 68s elapsed**.

## 2026-05-10 morning — listNamespacesByOwner + 8th quick CI green (2 more commits)

- **`dd3c9b720` — `seal_listNamespacesByOwner`**.
  Namespace per-owner gap, completing the four-RPC cluster with
  the immediately-prior `seal_listTokensByCreator` /
  `seal_listPrivateTablesByOwner` / `seal_listLeasesByOwner`.
  Until this RPC any caller asking "which namespaces have I
  deployed?" pulled the full `seal_getNamespaces` set and
  filtered owner client-side. Handler filters
  `NamespaceEntry.owner` inline (the registry already lives in
  `RpcState` as a `Vec<NamespaceEntry>`, so no manager-side
  accessor is needed). Sorted lexicographically by name. CLI
  `seal my-namespaces --address <addr>`.
- **`727fecc7a` — explorer: Account Lookup adds namespaces sub-table**.
  Fifteenth concurrent read (was 14). New "Namespaces" summary
  card + Name / Visibility / Replication / Schema-hash sub-
  table; schema_hash truncated to 12 chars + ellipsis (full
  hash still in the RPC JSON for callers that need it).
- Quick CI #8 (back-to-back with #7): **green, 1070 tests,
  clippy clean, 65s elapsed**.

## 2026-05-10 morning — listLeasesByOwner + 7th quick CI green (2 more commits)

- **`4e5a55f95` — `seal_listLeasesByOwner`**.
  Storage-lease per-owner gap completing the trio with the
  immediately-prior `seal_listTokensByCreator` and
  `seal_listPrivateTablesByOwner`. The lease's owner is the raw
  ML-DSA verifying-key bytes; bech32m address encodes
  `SHA3-256(verifying_key)`. New
  `LeaseManager::leases_by_owner_hash(&[u8; 32])` takes the
  address-hash and hashes each lease's pubkey for comparison —
  testnet/mainnet-agnostic since both encodings of the same key
  share the same hash. RPC accepts a bech32m `address`,
  derives the hash via `SealAddress::from_string_encoding`, and
  honors the optional `expired_only` filter mirroring
  `seal_listLeases`. CLI `seal my-leases --address <addr>
  [--expired-only]`. seal-token tests 129 → 130.
- **`bfcc8c948` — explorer: Account Lookup adds storage-leases sub-table**.
  Fourteenth concurrent read (was 13). New "Storage leases"
  summary card plus Table / Rows / Bytes / Paid-through /
  Expired sub-table; the expired column reds when true.
- Quick CI #7 (back-to-back with the listPrivateTablesByOwner
  run): **green, 1070 tests, clippy clean, 70s elapsed**.

## 2026-05-10 morning — listPrivateTablesByOwner + 6th quick CI green (2 more commits)

- **`a6537fd76` — `seal_listPrivateTablesByOwner`**.
  Per-owner gap on the private-table surface, paralleling the
  immediately-prior `seal_listTokensByCreator`. Until this RPC
  any caller asking "which private tables do I own?" had to
  scan the global `seal_listPrivateTables` set client-side — a
  problem on a node with thousands of regulated/app-private
  tables. New `PrivateTableManager::tables_by_owner(address)`
  returns `Vec<&PrivateTableMeta>` sorted lexicographically by
  name. Owner is set at `register()` time and never rotates
  today, so the view is stable across the table's lifetime.
  CLI: `seal my-private-tables --address <addr>`. seal-node
  tests 234 → 235.
- **`95bfaca57` — explorer: Account Lookup adds private-tables sub-table**.
  Thirteenth concurrent read in the Promise.all (was 12). New
  "Private tables" summary card + Name / Type / Row-count
  sub-table.
- Quick CI #6 (back-to-back with the listTokensByCreator run):
  **green, 1069 tests, clippy clean, 61s elapsed**.

## 2026-05-10 morning — listTokensByCreator + 5th quick CI green (2 more commits)

- **`4fed78e8a` — `seal_listTokensByCreator`**.
  Token-creation per-owner gap, paralleling the recent
  `seal_listFrozenSymbolsForAddress` (token freeze inverse) and
  the governance / DEX / bridge per-voter clusters. Until this
  commit a deployer asking "which tokens did I create?" iterated
  every entry of `seal_listTokens` client-side and matched on
  `creator`. New `TokenManager::tokens_by_creator(address)`
  returns `Vec<&TokenInfo>` sorted lexicographically by symbol.
  Creator is the immutable original-deployer field — a test
  asserts that `set_mint_authority` rotation does NOT change
  creator-of-record. RPC stays unauthed-read like
  `seal_listTokens`. CLI: `seal my-tokens --address <addr>`.
  seal-token tests 128 → 129.
- **`dec1ccd0b` — explorer: Account Lookup adds tokens-created sub-table**.
  Twelfth concurrent read in the Promise.all (was 11). New
  "Tokens created" summary card + Symbol / Name / Decimals /
  Total supply / Mint authority sub-table. `mint_authority`
  rendered as "renounced" (dimmed) when the RPC emits null.
- Quick CI #5 (post-listValidators / pre-listTokensByCreator
  baseline reused): **green, 1068 tests, clippy clean, 79s elapsed**.

## 2026-05-09 dawn-of-2026-05-10 — listValidators + 4th quick CI green (1 more commit)

- **`149db9f9f` — `seal_listValidators`**.
  Validator visibility: the only previous surface was the
  `validators: <count>` field on /status. New RPC returns each
  validator's public-key hex, VRF public-key hex, stake, active
  flag, plus active_count + total_stake aggregates. Inactive
  (slashed/unbonding) validators included so callers see the full
  set. CLI `seal validators` with tabular output.
- Quick CI #4 (after the 9-RPC per-owner cluster + delegation
  views): **green, 58s elapsed, build + test + clippy all pass**.

## 2026-05-09 dawn-of-2026-05-10 — explorer delegations (1 more commit)

- **`3fe384d96` — Account Lookup adds delegation in/out sub-tables**.
  Last surface for the per-owner thread: the panel now also runs
  `seal_govListDelegationsFrom` and `seal_govListDelegationsTo`,
  rendering both as track/peer/weight tables. Summary card shows
  "out / in" counts (e.g. "3 / 12"). Eleven concurrent reads in
  the Promise.all.

## 2026-05-09 dawn-of-2026-05-10 — delegation per-owner views (1 more commit)

- **`78f3e9170` — `seal_govListDelegationsFrom` /
  `seal_govListDelegationsTo`**.
  Last per-owner gap on governance: the existing
  seal_govEffectiveWeight returned a number but a delegator
  couldn't see *what* they had delegated, and a delegate
  couldn't see *who* delegates to them. New
  `DelegationManager::delegations_from` / `delegations_to`
  accessors back the RPCs. Delegation struct promoted from
  private to pub (carries no secrets — just
  delegator/delegate/track/weight). CLI: `seal my-delegations`
  / `seal delegations-to-me`. seal-node tests 233 → 234.

## 2026-05-09 dawn-of-2026-05-10 — frozen-symbols inverse + CHANGELOG batch (3 more commits)

- **`faa56684c` — CHANGELOG batch**.
  Captures ~25 commits of today's work in CHANGELOG: per-owner
  views fan-out (10 commits), eager dust-prune, bridge testnet
  runbook, state-sync design. Five new sub-sections under the
  Unreleased header.
- **`6262137c8` — `seal_listFrozenSymbolsForAddress`**.
  Inverse of `seal_listFrozenAccounts`: was "who's frozen on
  GOLD?"; now also "which tokens am I frozen on?" in one query
  rather than iterating every known symbol. New
  `TokenManager::frozen_symbols_for(address)` accessor sorts
  lexicographically. RPC returns `{address, symbols[], count}`.
  CLI `seal frozen-symbols`. seal-token tests 127 → 128.
- **`73f3d9f09` — explorer panel surfaces frozen-symbol status**.
  Ninth concurrent read in the Account Lookup; rendered as a
  red tag-list above the wrapped-balances table. Empty-state
  message is "Not frozen on any token."

## 2026-05-09 dawn-of-2026-05-10 — explorer governance + 2nd quick CI (1 more commit)

- **`3c5c8de59` — explorer Account Lookup gets governance sub-tables**.
  Surfaces the three new RPCs from 5258639f6: proposals authored,
  votes cast, active conviction locks. Three more cards in the
  summary row, three more sub-tables. Concurrent-read count
  goes 6 → 8.
- Second quick-CI run after the per-voter / per-owner gap-closing
  cluster: **green, 1065 tests, clippy clean, 66s elapsed**.

## 2026-05-09 dawn-of-2026-05-10 — governance per-voter views (1 more commit)

- **`5258639f6` — three governance per-voter RPCs**.
  Closes the per-owner gap on governance, paralleling the recent
  DEX + bridge + lease work. New accessors on `GovernanceModule`:
  `proposals_by_proposer`, `votes_by_voter`, `locks_by_voter`.
  Three new RPCs (`seal_govListProposalsByProposer`,
  `seal_govListVotesByVoter`, `seal_govListLocksByVoter`)
  answer the natural questions: "what did I propose?", "what
  did I vote on?", "when do my tokens unlock?". Locks sort
  ascending by unlock_epoch so "next to unlock" is at index 0.
  CLI: `seal my-proposals`, `seal my-votes`, `seal my-locks`.
  seal-node tests 232 → 233.

## 2026-05-09 dawn-of-2026-05-10 — storage-lease list (1 more commit)

- **`06a51709e` — `seal_listLeases`**.
  Storage-lease surface had only the `seal_leases_active` /metrics
  count; operators couldn't see *which* tables were leased or
  when they expired. New `LeaseManager::all_leases()` accessor
  (sorted by table name for diff stability) backs an unsigned
  `seal_listLeases` RPC. Optional `expired_only: true` filters
  to leases where `paid_through < now`. Owner emitted as raw
  ML-DSA verifying-key hex (the lease stores the full pubkey,
  not the bech32m address — callers comparing against `seal1...`
  derive `SHA3-256` and bech32m-encode themselves). Flat CLI
  `seal list-leases [--expired-only]` with tabular output and
  table-name truncation at 32 chars.
  seal-token tests 126 → 127.

## 2026-05-09 dawn-of-2026-05-10 — bridge wrapped-balance enumeration (1 more commit)

- **`b8c35d454` — `seal_listBridgeWrappedBalances`**.
  Per-owner gap on the bridge surface paralleling the recent
  `seal_listOrdersByOwner` / `seal_listTradesByOwner` work: the
  existing `seal_getBridgeWrappedBalance` requires the caller to
  know the symbol up-front, so a wallet enumerating wSOL/wXLM/
  wUSDC had to make N hardcoded calls. New
  `WrappedToken::all_variants()` accessor + the RPC iterates and
  filters zero-balance entries. Wired through CLI
  (`seal wrapped-balances`) + wallet TUI (`wrapped`) + explorer
  Account Lookup (sixth concurrent read; new sub-table + summary
  card). Quick CI green at the start of this segment (1063 tests,
  clippy clean).

## 2026-05-09 dawn-of-2026-05-10 — explorer Account Lookup (1 more commit)

- **`90727e40e` — explorer Account Lookup section.** Ties together
  every per-owner view the node exposes — SEAL balance, custom-
  token balances, open orders, recent fills — in a single
  `?account=sealt1…`-deep-linkable panel. Five RPCs run via
  `Promise.all` (independent managers server-side, ~5× faster
  than serial). Empty-state messaging on each sub-table; frozen-
  token rows render red; trade `role` derived as maker-or-taker
  from the trade record. Wallets can now hand users a "view me
  on the explorer" URL.

## 2026-05-09 dawn-of-2026-05-10 — DEX per-owner views (3 more commits)

After the eager dust-prune closed Tier-1 #3 step 2(b), pivoted to a
DEX-side gap parallel to the token-side `seal_listFrozenAccounts`
work: a user with multiple open orders had no way to enumerate
them without scanning every pair. Closed the same shape of gap
on the DEX surface.

- **`f8556f068` — `seal_listOrdersByOwner`**.
  `DexManager::orders_by_owner(owner)` aggregates across all
  trading pairs, returns `Vec<(pair, Order)>` sorted by
  `(pair, order_id)`. RPC + flat-CLI `seal list-orders --address
  <addr>` + tabular output (pair / id / side / price / qty /
  remaining). The pair tag matters because cancel needs both
  pair + order_id.
- **`5511667d7` — wallet TUI `orders` command.** Auto-supplies
  the active wallet's address. Same tabular output. Listed in
  `help` between `pairs` and `mpc`.
- **`1d5275c6d` — `seal_listTradesByOwner`**.
  Per-user fill history across pairs — companion to
  listOrdersByOwner ("what fills happened?" vs. "what's open?").
  Sorted descending by timestamp; bounded by per-pair
  `MAX_TRADE_HISTORY` (10 000). RPC + flat-CLI `seal trade-history
  --address <addr>` + wallet TUI `trade-history` / `my-trades`.
  `role` column derived as maker-or-taker from the trade record.

`seal-token` tests 124 → 126 (+2 — orders_by_owner and
trades_by_owner). Build clean across stack.

## 2026-05-09 dawn-of-2026-05-10 — eager dust-prune (1 more commit)

- **`6ed1c2274` — eager dust-prune (Tier-1 #3 step 2/6 part b).**
  `BalanceStore::put` now branches on `is_empty(bal)` — balances
  with both available and staked at zero are HAMT-removed, not
  written. Companion to `--min-opening-balance` (c042b406b): that
  prevents dust accounts from being created cheaply, this
  prevents existing accounts from sticking around after they
  drain. Combined, they close storage-rent option (b) statelessly
  — no `last_seen_epoch` field, no consensus hook, no wire-format
  churn. Option (a) (ongoing rent-per-epoch) remains deferred;
  revisit only if (b)'s cost barrier proves insufficient. Three
  new tests cover full-drain, staked-only-not-pruned, full-
  transfer-prunes-sender. SPEC.md §5.6.1 updated to flag the
  has_account semantics change at the recipient-policy boundary.
  seal-token tests 121 → 124; seal-node 232 (no regressions).

## 2026-05-09 dawn-of-2026-05-10 — state-sync design + addr utils (2 more commits)

Two follow-ups after Tier-3 #10 closed.

- **`cfa2b3fdc` — `seal hex-to-addr` inverse utility.**
  Operators inspecting bridge program logs see Seal addresses as
  raw 32-byte hex; the previous addr-to-hex (d0a2a76b2) covers
  bech32m → hex but not the inverse. Now operators can take a
  hex from a Solana log and turn it into a `seal1...` /
  `sealt1...` address. Round-trip tested. `--mainnet` flag flips
  the HRP for prod inspection.
- **`d6267059f` — `docs/STATE-SYNC.md` design (Tier-1 #3 step 6/6).**
  Final open box on Tier-1 #3 closed. ~290-line design doc for
  HAMT-leaf snapshot streaming: chunked content-addressed format,
  manifest tied to tip Ringtail aggregate, three new RPCs
  (`seal_getSnapshotManifest` / `seal_getSnapshotChunk` /
  `seal_listSnapshots`), four-step bootstrap flow, trust model,
  operator flags, deferred work flagged. Multi-session
  implementation tracked separately.

## 2026-05-09 dawn-of-2026-05-10 — Tier-3 #10 closed (4 commits)

After the token surface was complete, switched to the next clean
single-session unit on the tier list: public-testnet bridge runbook.

- **`fa1c5f369` — `docs/BRIDGE-TESTNET.md` + `scripts/bridge-testnet-demo.sh`**
  — ~320-line runbook walking Solana devnet (Anchor program
  deploy via `anchor deploy --provider.cluster devnet`) + Stellar
  testnet (Soroban contract deploy + initialize) bring-up, then
  the lock→mint and burn→unlock flows for SOL/XLM/USDC. Companion
  ~235-line script automates the lock side; gated behind
  `BRIDGE_TESTNET_DEMO_LIVE=1` so a stray invocation can't burn
  devnet airdrop quotas. Refuses to run if the deployer doesn't
  have ≥ 0.2 SOL on devnet (airdrop guard). MANUAL-TESTING.md
  §17 cross-linked. Burn→unlock narratively documented but not
  scripted — committee signing depends on operator's testnet
  validator set.
- **`d0a2a76b2` — `seal addr-to-hex` CLI utility.** The bridge
  programs' lock_* calls take a 32-byte hex `seal_address` field
  (bech32m with prefix + checksum stripped); operators were
  deriving this manually. New subcommand prints just the hex
  so it's pipeable into shell vars. Round-trip-tested.
- **`64eda58bc` — bridge-testnet-demo.sh uses built seal-cli.**
  Replaced `cargo run -p seal-cli` with a direct
  `target/debug/seal` invocation (or $SEAL_CLI override) — `cargo
  run` from inside a script already spending testnet balance is
  risky (stale Cargo.lock or compile error blocks forever).
- **`4a71e9073` — TUI balance view flags FROZEN tokens.**
  Polish follow-up to the kill-switch cascade: the TUI `balance`
  command now annotates frozen tokens (`(FROZEN — transfers
  disabled)`), matching the existing FRZ column on `tokens` and
  the explorer red-text styling.

## 2026-05-09 graveyard shift — kill-switch UX + fee authority (6 more commits)

After the kill-switch RPC landed (7035cdc9a), the remaining work
was making the new state visible across every UI surface plus
closing one final asymmetry in the authority model.

- **`74f4409fd` — `seal token --symbol` shows `frozen` line.**
  `seal_getToken` started returning the field but `run_token`
  never read it, so the kill switch was invisible from the CLI.
  Renders "YES (globally frozen)" / "no".
- **`772b553c6` — wallets render FROZEN unit + tooltip.**
  Both Electron `standalone.html` and the browser-extension
  `popup.js` per-token rows now read `t.frozen` from
  `seal_listTokens` and replace the `10^-N` unit cell with red
  "FROZEN" text; symbol carries an explanatory tooltip.
- **`94bf1fefc` — TUI `tokens` listing FRZ column.**
  Same surface gap, fixed in the Rust TUI. Table widened 50 → 57
  for the new 6-char column.
- **`7cc6f3ba0` — `seal_frozen_tokens` /metrics gauge.**
  Counts how many tokens have `info.frozen == true`. Companion
  to `seal_frozen_accounts`: per-account vs global counter. New
  `TokenManager::total_frozen_tokens()` accessor + dedicated
  unit test confirming per-account freezes don't move it.
- **`c9c6b7692` — fee authority rotation + renounce (full stack).**
  Closed the asymmetry: `set_transfer_fee` was hard-gated to
  creator while mint/freeze authorities were rotateable +
  renounceable. New `fee_authority: String` field on TokenInfo
  (defaults to creator on `create_token`), `set_fee_authority` +
  `renounce_fee_authority` manager methods, `Authority::Fee`
  enum variant routing through the existing handle_set_authority
  / handle_renounce_authority paths. CLI `set-fee-authority` /
  `renounce-fee-authority` reuse the same kind=fee dispatcher.
  Surfaced in `seal_listTokens` / `seal_getToken` (null when
  renounced). Explorer Tokens panel gained a "Fee authority"
  column. SPEC.md §5.8 documents the lifecycle for all three
  authorities including the subtle renounce-locks-current-fee
  invariant. MANUAL-TESTING.md §16.2 updated.
- **`79f7c823f` — `seal_setFeeRecipient`.**
  Closed the last fee-side gap: `fee_recipient` was set to creator
  at create-token and never mutable; even after rotating
  `fee_authority` to a treasury multisig, fees still routed to the
  original creator. The field also wasn't surfaced anywhere — no
  RPC response carried it, no CLI showed it. New
  `TokenManager::set_fee_recipient(symbol, new_recipient, caller)`
  on the same `fee_authority` gate, so renounce locks the recipient
  alongside the rate. Empty new_recipient rejected at the manager
  layer (likely a bug, not intent). RPC validates as a Seal address
  before the manager call. Surfaced in `seal_listTokens` /
  `seal_getToken`; CLI `seal token` detail now shows fee_recipient.
  Stale "creator" wording in `seal set-transfer-fee` usage updated
  to match the post-c9c6b7692 gating change.

`seal-token` tests: 117 → 121 (+4 — fee rotation, renounce-is-terminal,
total_frozen_tokens, set_fee_recipient). `seal-node` tests: 232
(test_requires_auth gained three assertions but stays one test).

## 2026-05-09 night-late — token surface fill-in continued (6 more commits)

After the first 5-commit batch landed, six more polish commits closed
the remaining read-side gaps and added a token-level kill switch.

- **`5cb76dbaf` — `seal_listTokens` surfaces both authorities.**
  The list response carried supply + fee but not `mint_authority` /
  `freeze_authority`, so on-chain authority state was set-only via
  RPC. Now returned in every token entry.
- **`ded72c52f` — explorer Tokens panel.** Renders supply + both
  authorities (truncated bech32m, `(renounced)` for the empty-string
  sentinel). Closes the visible end of the round-trip.
- **`911a4eda8` — `seal_listFrozenAccounts`.** Unsigned read,
  sorted lexicographically so polling clients can diff. New
  `TokenManager::list_frozen` + `seal list-frozen --symbol <S>` CLI.
  Empty Vec for unknown tokens / no frozen accounts (no error path).
- **`c4e83cbf6` — SPEC.md §5.8 token authority lifecycle.**
  Documents the state machine (creator → rotated → renounced),
  the `""` sentinel, and the rotate-vs-renounce decision tree.
- **`61f141c74` — `seal_getToken`.** Single-token detail RPC —
  cheaper than scanning `listTokens` when the symbol is known.
  Carries the global freeze flag too.
- **`30298ff83` — `seal_frozen_accounts` /metrics gauge.**
  Total `(symbol, address)` frozen-account entries across all
  tokens. New `total_frozen_accounts()` accessor backs it. Lets
  ops alert on freeze-authority abuse.
- **`7035cdc9a` — `seal_setTokenFrozen` global freeze switch.**
  Token-level kill switch that rejects every transfer regardless
  of per-account state — `info.frozen` was already honored by
  `transfer()` but had no setter or RPC. Idempotent. `listTokens`
  / `getToken` now carry the flag; explorer renders red when set.
  Per-account freeze for surgical, this for "stop the world."

`seal-token` tests: 117 (+2 over the round — list_frozen,
total_frozen_accounts, set_token_frozen folded into existing
suites). All passing.

## 2026-05-09 night — token surface fill-in (5 commits)

The SPL-style token lifecycle was missing several pieces. Filled
in over five small commits, each gated through `requires_auth`
and validated at the address level via
`SealAddress::from_string_encoding` before reaching the manager.

- **`c042b406b` — `--min-opening-balance` dust-spam cost shift.**
  `RpcConfig::min_opening_balance: u64` (CLI flag); when non-zero,
  transfers to fresh recipients must include at least that many
  base units, code `-32008`. Independent of `--allow-new-recipients`
  — a faucet posture (allow=true + non-zero min) keeps the policy
  active. SPEC.md §5.6.1 documents the rule.
- **`a3eb88b1e` — `seal_burnToken` RPC + CLI.** Closed the gap
  where `TokenManager::burn` was wired but never exposed; signed,
  caller is the from-address (no separate burn-authority concept
  yet). Returns the new `total_supply` so callers don't need a
  follow-up `seal_listTokens`.
- **`9175078b0` — `seal_freezeAccount` / `seal_unfreezeAccount` /
  `seal_isFrozen`.** Same gap as burn — manager methods existed,
  RPC didn't. `is_frozen` read accessor added; the `frozen_accounts`
  HashMap had no public reader before.
- **`ba7d0cbc3` — token authority rotation.**
  `set_mint_authority` / `set_freeze_authority` on `TokenManager`
  + `seal_setMintAuthority` / `seal_setFreezeAuthority` RPCs +
  `seal set-mint-authority` / `seal set-freeze-authority` CLI
  subcommands. Caller must be the current holder.
- **`0cf9ec0a1` — irrevocable authority renounce.**
  `renounce_mint_authority` / `renounce_freeze_authority` set the
  field to `""` (impossible for any real bech32m Seal address) so
  every subsequent mint/freeze/rotate attempt rejects, including
  by the original creator. Companion RPCs and CLI subcommands.

`seal-token` test count: 15 (was 8 before this round; +2 burn
helpers, +2 is_frozen, +2 rotation, +2 renounce — minus the
existing ones, total +7 over the round). `seal-node` lib tests:
232 (+5 min-opening-balance). Quick CI green.

## 2026-05-09 late evening — Tier-3 #9 (faucet) closed

- **`032f96162` — `seal-faucet` testnet HTTP service (Tier-3 #9)**
  New `apps/seal-faucet/` axum binary. POST /faucet forwards an
  ML-DSA-signed `seal_transfer` from a dedicated faucet keypair to
  the requested address. Per-address + per-IP cooldowns (default
  1 h, bumped on success only so a 502 doesn't burn the requester's
  quota). HRP cross-network paste guard refuses `sealt1← seal1` (and
  vice versa). CLI: `--key`, `--node`, `--port`, `--bind`, `--drip`,
  `--interval-secs`. /health endpoint for liveness probes. 3 unit
  tests + end-to-end Python-stub-node smoke test covering /health,
  success, cooldown, malformed, HRP cross-network. Companion doc
  `docs/TESTNET-FAUCETS.md` cross-references Stellar friendbot,
  Solana airdrop, Circle USDC sandbox, and the seal-node
  `--dev-faucet` unsigned override (refused under `--mainnet`).
  **Not wired into `scripts/ci.sh`** — the keypair holds real
  testnet balance and a CI loop would burn it.

## 2026-05-09 evening — Tier-2 #5/#7 closed + idle auto-lock

Three more commits on top of the morning batch. Closes Tier-2 #5
fully and the remaining UI surfaces of Tier-2 #7 (browser
extension + web explorer); the morning's Tier-2 #8 partial idle
auto-lock keeps its WASM-handle follow-up still pending.

- **`9be04106c` — Browser-extension idle auto-lock (Tier-2 #8 partial)**
  5-minute popup-side idle timer that calls `lock()` on fire and
  routes back to screen-unlock. Capture-phase listeners on click /
  keydown / focus reset the timer. Wired into createWallet,
  importMnemonic, unlock, change-passphrase. Heavier WASM-handle
  piece (move SK bytes off the JS path) deferred to a future
  session.

- **`a43fe12fa` — Wallets: QR + balance readout + per-token rows
  (Tier-2 #5)**
  Both wallets show the user's address as a QR (toggle button)
  and keep a live balance row above the rest of the screen.
  Per-token rows below SEAL via `seal_listTokens` +
  `seal_getTokenBalance`. New `qrcode.js` (~270 lines, byte mode,
  L EC, auto-versioning v1-5, mask 0) vendored once into each app.
  Round-trip-tested against jsQR for input lengths 1, 11, 45, 65,
  105 (versions 1, 1, 3, 4, 5). 5-second auto-poll while the
  account screen is visible; lock and screen-change tear it down.
  Deferred: Scan-destination QR for Send forms (needs jsQR + a
  `camera` permission in the extension manifest).

- **`ded167312` — Explorer + extension: DEX trade tape (Tier-2 #7
  cascade)**
  Web explorer gets a "Markets" section: pair `<select>` populated
  from `seal_listPairs`, table polling `seal_listTrades` on the
  existing 2 s refresh tick. `?pair=GOLD/SEAL` deep-link supported.
  Browser-extension popup gets the same surface: pair selector +
  `<ul>` tape (30 rows, scrollable) reusing the 5 s balance-poll
  tick (one timer instead of two). DOM construction everywhere so
  a hostile pair / address can't inject markup. The morning's
  Electron tape + CLI + TUI fix already shipped — Tier-2 #7 is
  now fully closed.

## 2026-05-09 — Tier-1/Tier-2 PLAN execution (4 commits)

Picked up the 2026-05-08 PLAN with CUDA deferred to the GPU host.
Closed Tier-1 #4, advanced Tier-1 #3 (step 1 of 6), closed Tier-2 #7
(RPC + CLI). 4 commits:

- **`0c05de220` — In-program bridge pause (Tier-1 #4)**
  Solana: `BridgeState.paused: bool`, `set_pause(paused)` ix gated
  on `has_one = authority`, `lock_tokens` and `unlock_tokens` reject
  with `BridgePaused`, new `PauseStateChanged` event.
  Stellar: `paused` instance-storage flag, `set_pause(paused)` gated
  on `admin.require_auth()`, `lock_xlm` and `unlock_xlm` reject with
  `Paused` (pause check runs BEFORE `sender.require_auth()` so a
  paused contract never even prompts), `is_paused()` view.
  Defence-in-depth on top of the Seal-side per-chain pause
  (`seal_bridgePauseChain`, 2/3 Technical Council).
  Tests: 11/11 Solana, 14/14 Stellar (+5 pause tests). Pre-existing
  borrow-after-move bug in `test_unlock_rejects_wrong_key` fixed.

- **`a69b9e11a` — HAMT-backed BalanceStore (Tier-1 #3 step 1/6)**
  Replaced `HashMap<String, Balance>` with `accounts: Hamt` storing
  bincode-serialized `Balance` records. Added `Cell<Option<Hash256>>`
  cache invalidated on every mutation, so block production's
  `state_root_hash()` is now O(1) instead of O(n log32 n).
  HAMT extensions: `iter()` (DFS), `contains_key()`. New closure
  helpers `update<F>` / `update_or_create<F>` replace the removed
  `pub(crate) get_mut`; transfer.rs and staking.rs migrated.
  Tests: seal-token 102 lib + 5 proptests, seal-node 227 (no
  regressions). 4 new cache-invalidation tests + 4 new HAMT
  iterator/contains tests.
  Remaining steps for #3: storage-rent + benchmark + state-sync
  snapshot format (multi-session).

- **`42cd05a89` — `seal_listTrades` RPC + bounded trade history (Tier-2 #7)**
  `OrderBook.trades` now caps at `MAX_TRADE_HISTORY = 10_000` (FIFO
  drop after `match_orders`). New `OrderBook::list_trades_since(since_id, limit)`
  scans from the back so polling cost is O(returned). New
  `DexManager::list_trades_for(pair, since_id, limit) -> Option<Vec<Trade>>`.
  RPC handler `seal_listTrades({pair, since_id?, limit?})` returns
  `{pair, trades[], count, last_id}`; default limit 100, cap
  `LIST_TRADES_MAX_LIMIT = 1000`. orderbook tests: 14 (was 9).

- **`1805a700b` — `seal trades` CLI subcommand**
  `seal trades --pair <BASE/QUOTE> [--since-id <N>] [--limit <N>]
  [--node <url>]` — read-only, plain JSON-RPC. Prints the trade
  table (id / side / price / qty / maker / taker, addresses
  truncated at 14 chars) and `last_id` so a polling client can
  continue with `--since-id last_id`. Closes the CLI piece of #7.

- **`74434ac9e` — wallet TUI `pairs` view rendering fix**
  `seal_listPairs` returns objects like `{pair, last_price,
  volume_24h, trade_count}`, but the TUI was rendering each via
  `p.as_str().unwrap_or("?")` so every line showed "?". Now
  extracts the named fields and prints a four-column table.

- **`681d80b59` — `balance_scale` bench (PLAN #8 step 5)**
  `crates/seal-token/benches/balance_scale.rs` — 11 microbenches
  exercising the headline win from `a69b9e11a`: cache-hit
  `state_root_hash` (sub-microsecond), HAMT lookup hot path, the
  `transfer` two-update path. Heavy 10⁴+ workloads intentionally
  excluded; documented in the module preamble. Run with
  `RUSTC_BOOTSTRAP=1 cargo bench -p seal-token --bench balance_scale`.

- **`93298597f` — Electron wallet native SEAL Send form (Tier-2 #6)**
  New "Send SEAL" panel between Chain and SQL: read-only balance
  row + Refresh button, recipient/amount inputs, Send via
  `signedRpc('seal_transfer', {to, amount})`. Auto-refreshes
  balance 1.5 s after a successful send (one slot of the dev
  devnet). Wired through `connect()`, `showWallet()`, and
  `lockWallet()` so the panel visibility tracks both
  walletKeys-loaded and connected state.

- **`857d57719` — Electron DEX trade tape (Tier-2 #7 cascade)**
  Added "Tape" button to the DEX panel: opens a rolling 50-trade
  view that polls `seal_listTrades` every 2 s with `since_id` for
  forward-stream behaviour. Trade list newest-first, sides colored
  (bid green, ask red) to match the LOB.

Last updated: 2026-05-08

## 2026-05-08 session — 8 PLAN items closed

Mostly mainnet-prerequisite cleanups. See
`TODOS/SESSION-2026-05-08.md` for the full hand-off; one-line per
item:

- **PLAN #2** — `rustls-webpki 0.103.12 → 0.103.13` vendor refresh
  (cleared RUSTSEC-2026-0104; new advisories
  RUSTSEC-2026-0119/0118 on hickory-proto 0.25.2 ignored with
  reachability justifications, tracked as a follow-up).
- **PLAN #3** — `examples/seal-forms/` swapped from XOR-stream +
  bespoke HMAC-SHA3 wrapper to real `Aes256Gcm` with HKDF-SHA3-256
  key derivation, deterministic nonce, AAD-bound ciphertext. Dropped
  `aead.rs` entirely. 7 lib tests (+3).
- **PLAN #4** — bridge `dest_address` per-chain format validator
  (`validate_dest_address` for Solana/Stellar) wired into
  `BridgeManager::initiate_withdrawal` so a malformed
  cross-chain address fails *before* the wrapped-balance burn.
  +5 tests.
- **PLAN #5** — 11 typed `seal-cli` mutations: 4 token
  (create/mint/transfer/set-fee), 2 DEX (place/cancel), 5
  governance (propose/vote/withdraw-vote/delegate/revoke).
  Unblocked MANUAL-TESTING.md §16.2.
- **PLAN #6** — admin gating on bridge-bootstrap RPCs
  (`seal_addBridgeObserver`, `seal_bridgeCouncilAdd/Remove`,
  `seal_bridgePauseChain/Unpause`).
  `RpcConfig::admin_addresses` + `--admin-address` CLI flag;
  open-mode preserves alpha-testnet bootstrap. SPEC.md §5.5.
- **PLAN #7** — recipient-new-account policy (block / confirm /
  allow modes) on `seal_transfer` + `seal_transferToken`.
  `RpcConfig::allow_new_recipients` + `--allow-new-recipients`
  flag; per-request `confirm_new_recipient: true` opt-in. SPEC.md
  §5.6. +6 tests.
- **PLAN #8** — partial: `/metrics` now exposes
  `seal_account_count`, `seal_total_supply_micro`, and
  `seal_tokens_registered` (dust-fanout signal pre-HAMT). HAMT
  wiring + storage-rent + bench remain multi-session.
- **CUDA reclassification (PLAN #9 prep)** — RTX 6000 host became
  available; CUDA STARK proving moved out of the "Blocked" table.
  `scripts/cuda-bringup.sh` is the bring-up artifact.

Test counts at end-of-day: seal-node 227 / seal-bridge 60 /
seal-token 94 / seal-forms 21 / Lean 0 sorries. `cargo audit`
exit 0. Full `./scripts/ci.sh` 6/0/1 (Miri legitimately skipped).
Workspace `cargo build` clean.

## 2026-05-08 afternoon push — 9 more items advanced

After the morning batch closed PLAN #2/#3/#4/#5/#6/#7 + partial
#8 + #9 prep, an afternoon "no excuses" push moved several items
the morning had classified as blocked:

- **PLAN #1 bridge-e2e — Solana side fully green** (commits
  `9c15d6775`, `03f5125c3`, `0b27842e4`): vendor-config workaround
  (`with_crates_io` helper), `~/.cargo/bin` PATH fix for the
  rustup proxy, `cargo build-sbf -- --locked` instead of `anchor
  build` (anchor swallows cargo-build-sbf failures), `solana
  program deploy --use-rpc` instead of `anchor deploy` (TPU client
  times out against the dockerized validator). Real Program Id +
  signature now print on every run.
- **PLAN #1 bridge-e2e — Stellar plumbing** (`9d38ff999`): Soroban
  RPC bound to `0.0.0.0:8003` via entrypoint `sed` of the runtime
  config template, friendbot called directly via curl at
  `:8000/friendbot` (CLI's auto-fund constructed the wrong URL),
  healthcheck waits for Horizon + Soroban RPC + friendbot, stale
  `bridges/stellar/.stellar/` config wiped at start of each run.
  Stellar deploy now reaches the install transaction; remaining
  `xdr value invalid` is a real CLI 22 vs SDK 22 vs network
  protocol 25 skew documented in TODOS.md.
- **Lean 7 sorries discharged** (`58102e9fc`):
  `formal/lean/SealVerify/Basic/MerkleTree.lean` builds with
  zero sorries; `filter_find_none`, `find_append_none`,
  `filter_preserves_find`, `find_mem`, `find_pred` (new),
  `filter_filter_self` (new) helper lemmas, then
  `MTree.delete_idempotent`, `delete_then_insert`,
  `delete_changes_root` close out via those helpers. DEX.lean
  unused-var lints silenced (`b8670c331`).
- **Browser-extension cross-browser polyfill** (`9fb9beec7`):
  `browserApi` alias resolves `browser`/`chrome` at startup;
  inline 3-liner in `background.js` + `popup.js` (modules), IIFE
  in `src/browser-polyfill.js` for content-script context (loaded
  before `content.js` in manifest). All 5 JS files pass
  `node --check`; same source on Chromium MV3, Firefox MV3,
  Safari Web Extensions.
- **Metal Option A vendor wiring** (`26f8b3d2e`): un-commented
  `vendor/risc0-circuit-rv32im-sys-5.0.0-rc.1/build.rs` for the
  Metal HAL compile path (with `is_metal()` gated on
  `CARGO_FEATURE_METAL` + macOS), added `metal` feature, added
  `risc0_circuit_rv32im_m3_prover_new_metal` FFI entry, plumbed
  through `risc0-circuit-rv32im` (`metal` feature + `cfg_if!`
  Metal arm in `segment_prover`) and `risc0-zkvm`
  (`metal = ["prove", "risc0-circuit-rv32im/metal"]`). Default
  build unaffected; `--features metal` build now reaches deeper
  upstream gaps documented in `crates/seal-zk/METAL.md` (metal-cpp
  wrapper not vendored; `.metal` kernels can't compile via
  cc::Build, need `xcrun -sdk macosx metal`).
- **PLAN #8 stepping-stone** (commits `03297bb0c`, `ebbe369da`,
  `bd039d7b6`, `961f6cc5b`): added `BalanceStore::state_root_hash`
  + `TokenManager::state_root_hash` (HAMT-backed Merkle
  commitments) without changing storage layout. Folded
  `BalanceStore`'s into `BlockHeader.state_root` (was SQL-only):
  `state_root = SHA3(sql_root || balance_root)`. Exposed in
  `/metrics` (`seal_balance_state_root{root_hex=…}`,
  `seal_token_state_root`) and `seal_getStateRoot` (now returns
  `{state_root, components: {balance_root_hex, token_root_hex}}`).
  SPEC.md §5.7 documents the new state-root contract.

Total commits today: 18 (10 morning + 8 afternoon). All CI-verified
before commit; nothing pushed (per instruction).

Test counts at end of afternoon push: seal-node 227 / seal-bridge
60 / seal-token 94 / seal-forms 21 / Lean 0 sorries.

## 2026-05-08 evening — orphan-TODO triage + doc-cascade

After the morning + afternoon code batches, an evening pass swept
all `.md` files outside `TODO.md` / `TODOS.md` for stale or orphan
TODO markers. Fixed the following stale claims:

- **Lean 0-sorries cascade** (the major cleanup) — STATUS.md
  component table row "Formal: Lean 4", `SECURITY.md:84` Merkle
  invariants row, `formal/lean/README.md` table + per-file section,
  `formal/kani/LIMITATIONS.md:174`, `audits/protocol-audit-scope.md:146`,
  and `audits/veridise-pqc-scope.md:123` all updated from
  "Partial / 7 sorries" to "Proven / 0 sorries (commit `58102e9fc`)".
- **`formal/tlaplus/README.md:108`** — "Trace conformance (TODO)"
  rewritten as Done (`crates/seal-consensus/src/trace.rs`, 10 unit
  tests, wired into `scripts/ci.sh`).
- **`formal/fuzz/README.md` table** — all 6 originally-listed
  targets marked Done; added the 4 newer targets (`fuzz_pqvrf_verify`,
  `fuzz_committee_vote`, `fuzz_ringtail_verify`, `fuzz_ringtail_sign`)
  to reach the actual count of 10.
- **`TESTING.md:62 / :148`** — dropped stale "lattice VRF TODO" and
  "Ringtail TODO" stub references. seal-vrf section now describes
  `PqVrf` (default) + `LavVrf` + `HmacVrf`; seal-threshold section
  reflects 66 tests + full-protocol Ringtail with BPF cross-check.
- **`patches/README.md`** — `libp2p-noise-pqc.patch` and
  `libp2p-core-pqc.patch` marked **superseded** by
  `crates/seal-p2p/src/pq_transport.rs` (ML-KEM-768 native transport
  one layer above libp2p) + `seal-crypto::SealAddress`
  (application-level identity over `SHA3-256(ML-DSA pk)`). The
  in-Noise patch path stays in git history if a future libp2p-native
  PQC story needs it.
- **`crates/seal-p2p/PQC-TRANSPORT.md`** — "Priority TODO: Vendorize
  libp2p with Full PQC" replaced with a Status section that
  documents what's shipped (ML-KEM transport + SealAddress) vs.
  what's mainnet-tracking (native libp2p PQC peer-IDs as a future
  simplification, not a blocker).

True orphans (not stale, just untracked) folded into TODOS.md
"Orphans now indexed" subsection: 5 future benchmarks from
`BENCHMARKS.md`, and 4 composite-ZK formal verification rows from
`ZK-PROOF-ARCHITECTURE.md:269-272`. Bridge in-program pause + fee
collection items from `bridges/{solana,stellar}/README.md` were
already in the bridge work matrix; promoted to Tier-1 #4 in the
new PLAN.

## Component Status

| Component | Status | Notes |
|-----------|--------|-------|
| **Consensus** (VRF + committee) | Done | Algorand-style, VRF election, threshold voting |
| **SQL engine** | Done | PostgreSQL subset, 85+ tests |
| **Merkle B-tree** | Done | Content-addressed, proofs, delete correctness proven in Lean 4 |
| **Row salts** (#STORAGE-FORGET) | Done | Per-row salt, deterministic block-seed derivation |
| **StorageLease + expiry pruning** | Done | LeaseManager wired into consensus runner |
| **Read/write invoicing** | Done | Per-byte burn on writes, stake-gate on reads |
| **Token economics** | Done | Balances, transfers, staking, emission, burn-and-mint |
| **DEX order book** | Done | Limit order book with matching; `match_all` runs per block via shared `Arc<Mutex<DexManager>>` between `RpcState` and `ConsensusRunner`; matched trades now emitted as `TxType::DexMatch` so they fold into `tx_hash` + the per-block ZK proof (2026-04-20 cont.). |
| **RLS (row-level security)** | Done | PostgreSQL-style policies, token-gated access; node now routes namespace SQL through `AppNamespace::execute_as` so policies actually fire (2026-04-20). HAS_TOKEN(...) reads a per-block balance mirror refreshed in `produce_block_with_vrf`. |
| **Private tables** | Done | AppPrivate/UserPrivate/RegulatedPrivate, real AES-256-GCM with 96-bit random nonce, Zeroize'd `EncryptionKey`, auth-tag + commitment tamper-detect tests |
| **MPC** | Scaffold+ | SPDZ + PSI; `reconstruct` now returns `Result<u64, SpdzError>` forcing MAC-check handling; constant-time MAC equality via `subtle::ConstantTimeEq`; `SpdzShare` zeroizes value+mac on drop; batch `verify_all_macs` helper; 6 adversarial tests (26 total); triple gen still test-only |
| **ZK proofs (RISC Zero)** | Done | Guest ELF runs end-to-end in r0vm v5.0.0-rc.1 executor; `--features local-prover` enables in-process LocalProver; real **non-dev-mode** CPU STARK proof verified end-to-end (205 842-byte receipt in 10.9s, 657 MB peak RSS on 10-core M-series); dev-mode receipt is 361 bytes in 0.02s; image ID computed from ProgramBinary; in-guest tagged-struct Output digest (matches `ReceiptClaim::ok`); Metal shader compiler present (Xcode + `MetalToolchain`), 117 KB `metal_kernels_zkp.metallib` built, `risc0-zkvm/metal` feature activatable — but upstream `risc0-circuit-rv32im::prove::segment_prover` only branches CPU vs CUDA (`vendor/risc0-circuit-rv32im/src/prove.rs:193-199`), so **Metal only accelerates the recursion/lift stage, not the main segment STARK**; for our tiny guest that means Metal compiles and runs without errors but wall-time is marginally *worse* (~17s vs 10.9s CPU) due to setup overhead. Real Metal win needs a recursion-heavy workload. |
| **ZK proofs (SP1)** | Ready | Vendored, compiles with `--features sp1`, guest ELF not yet built |
| **Threshold sigs (Ringtail)** | Scaffold+ | Real NTT, **66 tests** (+5 full-protocol tests 2026-04-20), constant-time centered-reduction (`ntt.rs::centered_abs_ct` via `subtle`), `RingtailParty::drop` zeroizes `sk_share`+`round1_randomness` via `RingOps::zeroize_poly`, `fuzz_ringtail_sign`. **Paper-shape `D_i = A·r_i + e_i` full-protocol path landed 2026-04-20** (`round1_full`, `aggregate_commitments`, `aggregate_responses_full`, `generate_public_params_no_error`, `sign_single_full`); BPF cross-check now passes byte-exact 1-of-1 + 2-of-2. **Committee migration landed (2026-04-20 cont.)** — `CommitteeManagerFull` drives the full-protocol rounds end-to-end with a byte-exact verify against `verify_signature_full`. **Lagrange + rounding helpers shipped** (`seal_threshold::lagrange`, `seal_threshold::rounding`); smudging-with-rounding still gated on noise budget. External audit still pending. |
| **VRF** | Done | PqVrf (ML-DSA, default), LavVrf (lattice), HmacVrf (test) — VrfBackend switchable |
| **P2P networking** | Done | libp2p + ML-KEM PQ transport |
| **Namespace persistence** | Done | RPC deploy + list, disk store |
| **Committee messages** | Done | Vote, signature, epoch transition handlers |
| **Bridges (Solana)** | Alpha | Anchor program w/ lock/unlock, committee-MAC verify (HMAC-SHA-256), key rotation ix. Host-side `SolanaObserver` with real JSON-RPC client. **Algebraic Ringtail verify wired (2026-04-20 cont.)** — `verify_ringtail_sig` decodes the full envelope and calls `seal_ringtail_verify::verify`; CU measurement via `scripts/measure-ringtail-cost.sh` (host projection ~11k CU). |
| **Bridges (Stellar)** | Alpha | Soroban contract w/ lock/unlock, real SAC transfers, committee-MAC verify, key rotation. Host-side `StellarObserver` with real Horizon client. **Algebraic Ringtail verify wired (2026-04-20 cont.)** — `verify_ringtail_proof` materializes the envelope into a stack buffer and calls `seal_ringtail_verify::verify`; instruction projection ~1M (within budget). |
| **Bridges (emergency pause)** | Done | Per-chain kill switch on `BridgeManager`; `seal_bridgePauseChain`/`seal_bridgeUnpauseChain` gated on 2/3 Technical Council supermajority via `TechnicalCouncil::has_two_thirds_approval` (ceiling arithmetic). Bootstrap via `seal_bridgeCouncilAdd`/`Remove`/`List`. 8 new pause tests + 3 council helpers + 5 RPC helpers. |
| **Bridges (Ethereum)** | Not started | Deferred |
| **Bridges (Bitcoin)** | Not started | Deferred |
| **Monitoring** | Done | /health, /metrics (Prometheus), /status, Grafana dashboards |
| **Web explorer** | Done | Static HTML+JS, auto-refresh, dark theme |
| **Desktop explorer** | Scaffold | egui GUI, mock data |
| **Desktop wallet** | Working | Electron shell + `standalone.html`, Rust crypto compiled to WASM |
| **Browser-extension wallet** | Scaffold | Manifest V3 (`apps/seal-wallet-extension/`); service worker + content script + in-page `window.seal` provider + popup UI; signing via WASM ML-DSA; AES-GCM vault keyed by PBKDF2-SHA-256(310k). Built 2026-04-20. |
| **Android wallet** | Scaffold | Rust FFI/JNI architecture |
| **JS SDK** | Scaffold | Type defs, no runtime |
| **Python SDK** | Scaffold | Async client scaffold |
| **WASM bindings** | Scaffold | SHA3, ML-DSA, SQL parsing |
| **Formal: TLA+** | Done | Consensus + bridge specs with invariants |
| **Formal: Lean 4** | Done | `formal/lean/SealVerify/Basic/MerkleTree.lean` builds clean on Lean 4.8.0 with **0 sorries** as of 2026-05-08 afternoon push (commit `58102e9fc`). Helper lemmas `filter_find_none`, `find_append_none`, `filter_preserves_find`, `find_mem`, `find_pred`, `filter_filter_self` discharged the previous 7-sorry surface so `MTree.delete_idempotent`, `delete_then_insert`, `delete_changes_root` close out via those helpers. `Hash.lean` + `VRF.lean` carry axioms only (cryptographic assumptions). |
| **Formal: Kani** | **66/66 green** | 100% green as of 2026-04-19. `DelegationManager` + `ForkChoice` swapped `HashMap` → `BTreeMap` for Kani tractability; three harnesses refactored to verify decision logic directly rather than drive the API through BTreeMap's intractable internals. Matrix in `formal/kani/README.md`. |
| **Formal: Miri** | Working | `scripts/ci-formal.sh` step 4 moves `.cargo/config.toml` aside for the Miri run so the sysroot build can pull std's exact dep versions from the real registry instead of hitting the vendored-source mismatch. Validated 2026-04-19 on seal-merkle (35 tests, no UB, 210 s). Covers seal-merkle/token/threshold/mpc + any crate that carries `unsafe`. |
| **Formal: Fuzz** | Done | **10 targets** (+`fuzz_ringtail_sign` 2026-04-18), scripts for extended campaigns |

## Blocked

| Item | Blocked on |
|------|-----------|
| **Metal-accelerated** segment STARK proving | Not an Xcode-install blocker (Xcode + `MetalToolchain` are present on this machine). Blocked upstream: segment `cfg_if!` has CPU/CUDA only (`vendor/risc0-circuit-rv32im/src/prove.rs:193-199`), AND the C++ Metal HAL (`vendor/risc0-circuit-rv32im-sys/cxx/hal/metal/hal.cpp`, 609 lines) is commented out of the build script (`vendor/risc0-circuit-rv32im-sys/build.rs:24,93-96,238`). DIY path documented in **`crates/seal-zk/METAL.md`** — Option A (un-comment + add FFI shim) is ~1 day if upstream kernels are complete; Options B/C cover writing our own MSL kernels if not. Today's activation command still compiles + runs (recursion-stage Metal only): `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer cargo test -p seal-zk --features "risc0 local-prover risc0-zkvm/metal" --release`. |
| Real Solana/Stellar token transfers | Bridge programs have stubs; need testnet deployment + SAC integration |
| Ringtail external audit | Needs vendor engagement (Veridise / Trail of Bits / Cryspen). Pre-audit hardening (constant-time norm, zeroize, KAT vectors, extended fuzz target) complete this session. |

CPU non-dev-mode proving is **no longer blocked**: one-time benchmark
captured 205 842-byte receipt in 10.9s, 657 MB peak RSS, end-to-end
verify success.

**CUDA-accelerated** segment STARK proving is **no longer hardware-blocked** —
an RTX 6000 host is available (2026-05-07). Plumbing already in place
(`crates/seal-zk/Cargo.toml` `gpu-cuda`, `crates/seal-zk/src/gpu.rs:521`,
`risc0-zkvm/cuda` feature). Bring-up: `./scripts/cuda-bringup.sh` on the
RTX 6000 host runs the `risc0 local-prover risc0-zkvm/cuda gpu-cuda`
build + the segment prover and records receipt size, wall-time, and
peak RSS to `target/cuda-bringup/results.txt`. Manual activation:
`CUDA_VISIBLE_DEVICES=0 cargo test -p seal-zk --features "risc0 local-prover risc0-zkvm/cuda gpu-cuda" --release`.
This is the one GPU path the rv32im segment prover supports upstream
today.

## Launch Checklist (from LAUNCH-CHECKLIST.md)

All items unchecked — external dependencies:
- [ ] Security audits (Veridise PQC + protocol)
- [ ] Bug bounty (Immunefi, 4+ weeks)
- [ ] Formal verification final pass (Kani 60 harnesses, Miri, 24h fuzz)
- [ ] Incentivized testnet (4 phases, 72h chaos)
- [ ] Genesis (30+ validators, token distribution)
- [ ] Release (v1.0.0, binaries, Docker, checksums)
- [ ] Infrastructure (3+ bootstrap nodes, explorer, Grafana, status page)
- [ ] Documentation (validator guide, runbook, SDK docs, API reference)

## Test Suite

- **975+ tests** across all crates. 2026-04-20 (afternoon session) added another 44+:
  +6 lagrange, +3 rounding, +3 CommitteeManagerFull, +5 wasm_validate,
  +6 plpgsql, +5 CALL dispatch, +5 forms.seal AEAD, +7 forms MPC sum,
  +6 forms ZK stats, +1 DexMatch tx, +7 copy-trading, +7 kyc.seal,
  +7 kindle.seal.
- seal-node alone: 217 tests pass.
- Zero failures on stable Rust 1.94.1.
- Property tests (proptest) for SQL, token, Merkle, consensus.
- Fuzz targets: **10** (added `fuzz_ringtail_sign` — exercises
  partial_sign / aggregate / verify, complements `fuzz_ringtail_verify`).

## Recent Session (2026-05-07)

### Done

1. **Mainnet × dev-faucet mutual exclusion** — `seal-node` now refuses
   `--dev-faucet` under `--mainnet` at startup (exits 2 with a clear
   error). Closes a foot-gun where the signature-less `seal_faucet`
   could otherwise be flipped on against a production chain and silently
   mint arbitrary balances. (`crates/seal-node/src/main.rs:35-41`).
2. **TODO triage + AES-GCM clarification** — corrected the long-running
   "replace XOR placeholder" entry: core private tables already shipped
   AES-256-GCM in 2026-04-13 (commit `4e717415`); the residual XOR is
   confined to `examples/seal-forms/` (demo). Reframed as a focused
   demo-app cleanup with a concrete spec (HKDF-from-shared-secret key,
   deterministic nonce from `(form_id, respondent, idx)`, AAD binding
   to form context). See TODO.md.

### See also

- Full session handoff: `TODOS/SESSION-2026-05-07.md`.
- Open bridge-e2e stack from 2026-04-23 still resumable
  (Solana healthcheck fixed, validators `Created` and ready to build).

## Recent Session (2026-04-20)

### Done

1. **Ringtail signer fix (paper shape)** — Additive full-protocol path
   in `crates/seal-threshold/src/ringtail.rs`: `round1_full` produces
   `D_i = A·r_i + e_i` as a K-vector; `aggregate_commitments` sums per
   row; `aggregate_responses_full` hashes the aggregated D into the
   challenge; `generate_public_params_no_error` builds `t = A·s` keys;
   `sign_single_full` is a 1-of-1 convenience. BPF cross-check
   (`crates/seal-ringtail-verify/tests/crosscheck.rs`) now accepts
   byte-exact 1-of-1 and 2-of-2 signatures (previous `#[ignore]`
   removed). Committee/Lagrange/smudging follow-ups documented in
   memory note.
2. **DexManager → block production** — Shared `Arc<Mutex<DexManager>>`
   on `ConsensusRunner`; `set_dex_manager` lets `start_rpc_server`
   wire its `RpcState.dex` into the runner so order placement and
   `match_all` operate on the same books. Matching runs every block
   via `try_lock` (lock-free).
3. **Token-gated RLS end-to-end** — `NamespaceRegistry` +
   `Arc<RwLock<HashMap<String,u64>>>` balance mirror on the runner;
   `deploy_namespace` installs an RLS token checker that reads from
   the mirror; `submit_sql_in_namespace` routes through
   `AppNamespace::execute_as`; `enable_rls_policy` sets up policies
   programmatically. `produce_block_with_vrf` refreshes the mirror
   each block. RPC `seal_submitSql` / `seal_querySql` now dispatch
   through the namespace path when `namespace` is supplied.
4. **ADR-001 implementation** — New `crates/seal-procs` crate
   (`Procedure`, `ProcedureStore`, `SqlProcEngine`, `WasmProcEngine`
   stub, on-chain `code_hash`). `seal-sql` Engine handles
   `CREATE FUNCTION ... LANGUAGE sql|wasm` with `OR REPLACE`, default
   language SQL, dollar-quoted body extraction.
5. **Browser-extension wallet** — `apps/seal-wallet-extension/` with
   MV3 manifest, service worker (message routing + storage), content
   script + in-page `window.seal` provider (EIP-1193-shaped), popup
   UI that owns WASM ML-DSA signing and an AES-GCM vault keyed by
   PBKDF2-SHA-256(310k). Reuses `sdks/wasm` artefacts in `pkg/`.
6. **Demo apps** — `examples/seal-forms/` full lib + binary (per-form
   ML-KEM keypair, encrypted answers, iterated SHA-3 trace chain);
   `examples/seal-social/`, `examples/seal-auction/` (commit/reveal),
   `examples/seal-x402/` (HTTP 402 + ML-DSA payment receipts) as
   focused libraries with primitives and tests.
7. **Governance JSON-RPC surface** — `GovernanceModule` +
   `DelegationManager` on the runner; 11 new methods:
   `seal_govPropose`, `seal_govVote`, `seal_govWithdrawVote`,
   `seal_govTally`, `seal_govExecute`, `seal_govGetProposal`,
   `seal_govListProposals`, `seal_govGetVotes`, `seal_govDelegate`,
   `seal_govRevokeDelegation`, `seal_govEffectiveWeight`. Mutations
   require ML-DSA auth so proposer/voter/delegator address binds to
   caller key.

## Previous Session (2026-04-13 → 2026-04-18)

### Done

1. **ZK real executor** (`f6d8dcb1`) — Guest ELF rebuilt with STDIN I/O
   (`sys_read_words`), image ID computed from ProgramBinary, r0vm executor
   runs end-to-end (88-byte RZK1 journal verified in 0.05s)
2. **AES-256-GCM for private tables** (`4e717415`) — Replaced XOR placeholder
   with `aes-gcm 0.10`, zeroized `EncryptionKey`, auth-tag tamper detection,
   random 96-bit nonces, 8 tests (3 new security tests)
3. **In-process LocalProver** (`b9bdec19`) — Vendored gdbstub/typetag + 50
   transitive deps, patched Metal stub for macOS w/o Xcode, `local-prover`
   feature enables real dev-mode STARK receipt (361 bytes, 0.02s)

### Remaining TODOs

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Real Output digest in guest (`sys_halt out_state`) | **Done** | In-guest SHA-256 via `sys_sha_buffer` + tagged-struct (`"risc0.Output"` + `[SHA256(journal), ZERO]` + LE u16 = 2). Validated by non-dev-mode prove/verify round-trip (any byte-order error would have surfaced as `ClaimDigestMismatch`). ELF rebuilt (23 092 bytes). |
| 2 | Ringtail threshold sigs hardening | **Partial done** | Constant-time `centered_abs_ct`, `RingtailParty::drop` zeroize, `RingOps::zeroize_poly`, 5 KAT vectors, `fuzz_ringtail_sign` added. **External audit still pending** (see Blocked table). |
| 3a | Bridge host-side observers | **Done 2026-04-19** | B1 + B2 landed. Real JSON-RPC (`getSignaturesForAddress` + `getTransaction`) for Solana, Horizon (`/accounts/{id}/operations`) for Stellar. Pluggable `HttpTransport` trait. 12 mock-transport unit tests. `crates/seal-bridge/src/{http,observer}.rs`. |
| 3b | Bridge on-chain signature verify (committee-MAC) | **Done 2026-04-19** | B3 + B4 landed. HMAC-SHA-256 via each chain's native SHA-256 host function; `committee_key` stored at init, rotatable per epoch; chain-specific domain tags prevent cross-chain replay. Algebraic Ringtail verify in BPF/Soroban (long-form upgrade) still pending. |
| 3b' | Algebraic Ringtail verify on-chain | Pending — multi-week code | Needs 48-bit prime polynomial ops in BPF (~150-200K CU) and Soroban (~10M instructions). Not blocked; deferred until post-audit. |
| 3c | Bridge local-testnet harness | **Done 2026-04-19** | B6+B7+B8 landed. `bridges/docker-compose.testnet.yml` (Solana + Stellar + 3 Seal) + `scripts/bridge-e2e.sh` (preflight, deploy, lock→mint round-trip). Unlock flow placeholder pending seal-node RPC wiring. |
| 3c' | Seal-node bridge RPC wiring | **Done 2026-04-19** | `seal_getBridgeDeposits`, `seal_getBridgeStatus`, `seal_getBridgeWrappedBalance`, `seal_bridgeWithdraw` (auth), `seal_addBridgeObserver`, `seal_listBridgeObservers`, `seal_pollBridges` — all landed in `crates/seal-node/src/rpc.rs`. `bridge-e2e.sh` updated to drive them. |
| 3d | Bridge SAC integration (Stellar XLM transfers) | **Done 2026-04-19** | B5 landed. Real `token::Client::transfer` calls in `lock_xlm` / `unlock_xlm`; `initialize(xlm_sac: Address)` stores the SAC address per deployment. |
| 3e | Mainnet bridge deploy | Deferred (genuinely external) | Requires Seal DAO governance + mainnet multisig. Belongs in `LAUNCH-CHECKLIST.md`, not dev backlog. |
| 4 | MPC (SPDZ + PSI) hardening | **Done** | `reconstruct -> Result`, `SpdzError::MacCheckFailed`/`TriplesExhausted`/`InvalidTripleIndex`, constant-time MAC equality (`subtle`), Drop zeroize on `SpdzShare`, `verify_all_macs` batch helper, 6 adversarial tests. Offline-phase triple gen still test-only (documented). |
| 5 | Kani harnesses 66/66 green | **60/66 done** | +MATRIX in `formal/kani/README.md`. 6 failing seal-node harnesses blocked by Kani's `HashMap`/thread-local-random limitation — remediation requires per-harness rewrite (O(hours) each) deferred to a dedicated session. |
| 6 | Extend Miri coverage | **Script extended** | `scripts/ci-formal.sh` step 4 now also runs Miri on seal-merkle/token/threshold/mpc as a regression guard. Sysroot build **currently blocked** by vendored-registry cfg-if mismatch — see `formal/miri/README.md`. |
| 7 | Non-dev-mode STARK proving | **CPU done; Metal runs (no speedup); CUDA bring-up queued (RTX 6000)** | CPU: 205 842-byte receipt in 10.9s on 10-core M-series, 657 MB peak RSS, verify OK. Metal: builds + runs (~17s) but no perf win because rv32im segment prover has no Metal branch upstream. CUDA: plumbing ready; RTX 6000 host available since 2026-05-07. |
| 8 | CUDA-based zk/proving | **Bring-up queued (RTX 6000)** | Path is the one GPU backend the rv32im segment prover supports. Hardware available since 2026-05-07. Bring-up: `./scripts/cuda-bringup.sh` on the RTX 6000 host. |

## Previous Session (2026-04-10)

Commits:
1. `bf0b6bf1` — Q&A file, brainstorm notes
2. `dee273c3` — Row salts, StorageLease, node improvements, formal proofs, bridges
3. `02c35b35` — Testing guide, SPEC.md #STORAGE-FORGET, VRF backend
4. `227684cf` — Vendored risc0-zkvm + sp1-sdk wired
5. `d5a0548c` — Guest ELF, NTT cleanup, Lean proof, invoicing, lease wiring
6. `56e3f14e` — Guest ELF build setup, toolchain installed
7. `b3dc12d6` — /health, /metrics, /status endpoints
8. `6e633e39` — Web block explorer
9. `e6a86a71` — Grafana dashboards + docker-compose
10. `8f1310e9` — Operator guide + testnet docs updated
