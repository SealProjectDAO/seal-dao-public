# TODOS.md — Active work list

Session-current actionable todos. `STATUS.md` has the component matrix;
`TODO.md` has the long-form roadmap history. This file is the
prioritized list of work items that are *not done and not permanently
deferred*.

Last synced: 2026-05-16 — "no excuse bordel" session **CLOSED 16/16**
(11 commits, 1148 → 1170 tests). Every previously-deferred item
landed:

- P1#5 layer 4 seal-node integration (THE testnet blocker —
  ADR-002 wiring): RpcState plumb, signing-signal channel,
  receive-loop dispatch, periodic prune, metrics + dispatch test.
- Ringtail layer 6 multi-validator harness (in-process Rust e2e
  + scripted docker-compose smoke).
- In-flight signing-session persistence across restart (atomic
  on-disk store under `<data_dir>/ringtail-sessions/`).
- P8 mainnet gates (all 4): per-method rate limits, bridge
  withdrawal fee, admin M-of-N multisig, KMS key-source trait.
- Operator-side automation: `bridge-deploy-devnet.sh`,
  `bridge-redeploy-ringtail.sh`, `bridge-fund-relayer.sh`,
  `docs/RINGTAIL-TESTNET.md`.

Plan + per-slice breakdown in
[`TODOS/SESSION-2026-05-16-no-excuse-bordel.md`](TODOS/SESSION-2026-05-16-no-excuse-bordel.md).
Previous milestone 2026-05-15 (committee-key rotation RPCs:
`seal_bridgeRotateCommitteeKey` + `seal_bridgeGetCommitteeKeyStatus`
+ `BridgeManager::committee_key_fingerprint`). The authority-
current trio + 2026-05-09 evening summary follow this block.

## 2026-05-15 — Committee-key rotation without restart

Closes the "rotation requires a seal-node restart" gap flagged in
the 2026-05-15 morning testnet-readiness review (`xxx-bbb.txt`
item 4). Operators can now rotate the host-side committee MAC key
via a council-gated RPC and verify host-vs-chain alignment via
the fingerprint read RPC; restarting the node is no longer
required.

- [x] `BridgeManager::committee_key_fingerprint() -> Option<[u8;32]>`
  (SHA3-256, host's PQ-native default; never the key itself).
- [x] `BridgeManager::committee_key_fingerprint_sha256() ->
  Option<[u8;32]>` — SHA-256, the cross-chain diff hash. Same
  output that Solana's `sol_sha256` syscall and Stellar's
  `env.crypto().sha256()` return on the same input, so an
  on-chain `committee_key_hash` view returns matching bytes.
- [x] `seal_bridgeRotateCommitteeKey` — admin-auth + 2/3 council,
  same shape as `seal_bridgePauseChain`. Returns both
  fingerprints of the new key so coordinators can cross-check.
- [x] `seal_bridgeGetCommitteeKeyStatus` — no-auth read returning
  `{set, fingerprint_sha3_hex, fingerprint_sha2_hex}`.
- [x] Docs: `docs/BRIDGE-TESTNET.md` §5 curl recipes + SPEC.md
  §5.5 admin-gated list updated.
- [x] Prometheus `/metrics` now exports
  `seal_bridge_committee_key_set`, `seal_bridge_paused_chains`,
  `seal_bridge_{deposits,withdrawals}_{total,pending}`, and
  label-info `seal_bridge_committee_key_fingerprint{sha2_hex}`
  for testnet operator alerting + dashboards.

Open follow-up: ~~add a `committee_key_hash() -> BytesN<32>` view
function to the Soroban contract~~ — **DONE 2026-05-16** (commit
`54410ff82`): contract now exposes `committee_key_hash()` returning
`env.crypto().sha256(&stored_key)` post-init or `[0u8; 32]`
pre-init. One new unit test covers all three states. Built via
the `with_crates_io` shim (workspace vendor config blocks
soroban-sdk lookup; same dance as `scripts/bridge-e2e.sh`). Solana side: the raw
key is already readable via `getAccountInfo` on the `BridgeState`
PDA — no on-chain change needed, dashboards fetch and SHA-256
themselves.

## 2026-05-10 — Testnet-readiness batch FULLY CLOSED (8/8)

Eight items locked by the user. CUDA is **not** a testnet
launch gate (user confirmed); it's only a STATUS first-number
on the GPU host.

**Batch A — code (yellow + the two pulled-in red items):**

- [x] A1. Stellar SDK / quickstart protocol-22 pin → protocol-25 migration.
  **Protocol-22 pin done 2026-05-10, commit `5e41c7378`. Protocol-25
  migration done 2026-05-13.** Protocol-22-era images expired (6-month
  nightly window); forced option (b): `soroban-sdk = "25"`,
  `wasm32v1-none` target (required by sdk 25 on Rust 1.82+), dropped
  `--protocol-version 22`, bumped quickstart tag to
  `v637-b1054.1-nightly`. All 14 contract unit tests pass; no breaking
  API changes in lib.rs (deprecated `events().publish()` still works).
- [x] A2a. `seal_listSnapshots` RPC.
  **Done 2026-05-10 afternoon, commits `26ecbb3a0` + `2127d821c`.**
  New `seal-storage::SnapshotIndex` (bounded ring, default cap
  32, strictly height-monotonic) + epoch-boundary capture in
  `ConsensusRunner::advance_slot` + RPC handler returning
  newest-first with optional `limit`. `seal snapshots` CLI
  command. 11 new tests (8 unit on the index + 3 integration
  on the capture hook). Explorer wiring deferred to A2d.
- [x] A2b. `seal_getSnapshotManifest` RPC.
  **Done 2026-05-10 evening, commits `24405b5c2` + `1143e14b7`.**
  New `seal-storage::snapshot_chunks` module (`MAX_CHUNK_BYTES
  = 4 MiB`, order-preserving chunker with oversized-row
  exception, manifest fingerprint helper).
  `BalanceStore::snapshot_dump` sorts HAMT leaves byte-wise by
  key for cross-node determinism. `tip_aggregate` now filled
  from SHA3(threshold sig) at capture. Handler refuses pruned
  manifests on three error codes (`-32004` evicted, `-32005`
  state moved past, `-32006` block out of memory).
  `seal snapshot-manifest --height <h> [--json]` CLI command
  with chunk-preview + JSON-pipe modes. 10 new tests.
- [x] A2c. `seal_getSnapshotChunk` RPC.
  **Done 2026-05-10 evening, commits `b8b58c653` + `07fcdb06f`.**
  `decode_chunk_bytes` / `decode_chunks` in
  `seal-storage::snapshot_chunks` invert the encoder; truncated
  chunks surface as structured errors. RPC handler
  base64-encodes payloads; new `-32007` error code for
  out-of-range `chunk_index`. CLI `seal snapshot-chunk
  --height <h> --index <n> [--out <file>]` recomputes a fresh
  SHA3 hash, prints MATCH/MISMATCH, exits 2 on mismatch for
  scripted state-sync drills. 4 new round-trip / truncation
  unit tests.
- [x] A2d. `seal-node --bootstrap-from-snapshot` late-joiner path.
  **Done 2026-05-10 evening, commits `62e0f8b34` + `d0a3325b7`.**
  `BalanceStore::restore_from_snapshot` inverts `snapshot_dump`
  (validates bincode, drops dust, rebuilds total_supply).
  New `seal-node::snapshot_bootstrap` module with `SnapshotRpc`
  trait + `HttpSnapshotRpc` (curl-shelled) +
  `bootstrap_from_peer`. Maps the four pruned-snapshot RPC
  error codes to one `SnapshotPrunedMidStream`. Final
  state-root cross-check. New `--bootstrap-from-snapshot
  <peer-url>` flag runs BEFORE genesis-mint; on failure exits 3
  rather than silently falling back. 23rd concurrent read in
  the explorer-web (State Snapshots section). 7 new tests
  (4 balance restore + 3 bootstrap-client).
- [x] A3. `scripts/cuda-bringup.sh` runbook doc-check.
  **Done 2026-05-10 evening (doc-only).** Confirmed feature
  flags (`risc0`, `local-prover`, `gpu-cuda`, `risc0-zkvm/cuda`)
  + test target (`test_risc0_full_pipeline` in
  `crates/seal-zk/tests/e2e_integration.rs:89`) + output paths
  are all current. Added formal CSV schema doc to the
  preamble; updated the closing "Next:" message to point at
  current STATUS phrasing. Real bring-up is the GPU host's
  job; **not a launch gate** per user confirmation.

**Batch B — operational infra (the two pulled-in red items):**

- [x] B4. `apps/seal-registration` axum service.
  **Done 2026-05-10 evening, commits `f14bfe5b5` + `e22c40639`.**
  Mirrors apps/seal-faucet shape. POST /register accepts
  `{pubkey_hex, vrf_pubkey_hex, name, contact, signature_hex}`;
  signed message is `SHA3(b"register" || pubkey_hex ||
  vrf_pubkey_hex || name || contact)`; verified against
  pubkey via `VerifyingKey::verify`. Already-registered keys
  return idempotent 200. GET /registrations strips `contact`
  (operator-private), sorts by accepted_at. JSONL append-only
  persistence with last-write-wins recovery. 60s per-IP
  cooldown. Companion `docs/TESTNET-REGISTRATION.md` documents
  curl + jq hand-build recipe + privacy threat model.
  7 new unit tests including the canonical-message
  byte-string check that catches a future field-reorder
  regression which would silently invalidate existing
  signatures.
- [x] B5. `scripts/release.sh` + ML-DSA-signed SHA256SUMS + Docker.
  **Done 2026-05-10 evening, commits `f2dd03e60` + `b3a0e7d49`.**
  New seal-cli subcommands `sign-file` (SHA3-hashes file +
  ML-DSA-65 signs hash; emits sig + sibling .pubkey) and
  `verify-file` (re-hashes + verifies; exit 0 / 1 / 2).
  `scripts/release.sh` cross-builds linux-x86_64 +
  linux-aarch64 in rust:1.94-bookworm containers + macOS
  ARM64 on host, writes deterministic SHA256SUMS,
  ML-DSA-signs it + post-sign self-verify, tarballs
  everything, builds Docker image. Default dry-run; Docker
  push gated by `RELEASE_PUBLISH=1`. Per CLAUDE.md
  PQC-first; signing primitive matches the chain's own
  ML-DSA-65 identity scheme. Companion `docs/RELEASE.md`
  documents verifier recipe + pinned-pubkey workflow +
  explicit follow-ups (gh release create, SLSA, threshold
  release signing).

**Out of scope this batch (per user):** audits, Immunefi,
recruitment, bootstrap-node infra. They stay in "Deferred —
genuinely external" below.

## 2026-05-10 midday — authority-current trio closed

Two commits in the standard 3-commit shape (RPC+CLI →
explorer → STATUS+TODOS sync follows):

- `bb90bcc41` — `seal_listTokensByFeeAuthority` (RPC + CLI +
  TokenManager method + +1 seal-token test asserting
  rotation alice → eve diverges from mint+freeze, then
  renounce removes from every view)
- `2bdc446a4` — explorer: Account Lookup adds
  tokens-by-fee-authority sub-table (Promise.all 21 → 22
  concurrent reads; fee-bps column color-shifts on non-zero)

Quick CI #15: green, 1077 tests, clippy clean, 101s.
Disk-recovery side-quest: root partition was at 99% (170
MiB free) and the prior link aborted with `errno=28`;
`cargo clean` reclaimed 37.3 GiB, rebuild then went green.

The trio is now closed: a single bech32m address answers, in
one explorer query, every per-address authority surface
(mint / freeze / fee), every per-address asset surface
(creator / balance / orders / trades / wrapped / bridge
in+out / private-tables / leases / namespaces), every
per-address governance surface (proposer / voter / locks /
delegations from+to / validator / council). Twenty-two
concurrent reads.

## 2026-05-10 morning — Account-Lookup per-address gap-closer cascade

15 commits in five three-commit iterations (RPC+CLI → explorer →
STATUS sync), each followed by a back-to-back quick CI run:

| #  | RPC                                  | CI  | Tests |
|----|--------------------------------------|-----|-------|
| 1  | `seal_listBridgeWithdrawalsByInitiator` | #10 | 1072 |
| 2  | `seal_getValidatorByAddress`         | #11 | 1073 |
| 3  | `seal_getCouncilMemberByAddress`     | #12 | 1074 |
| 4  | `seal_listTokensByMintAuthority`     | #13 | 1075 |
| 5  | `seal_listTokensByFreezeAuthority`   | #14 | 1076 |

Account-Lookup `Promise.all` grew from 16 → 21 concurrent reads.
Net effect: a single bech32m address now answers, in one
explorer query, "is this validator/council/active mint /
freeze authority? what bridge in/out have I seen? all the
governance/DEX/private-tables/leases/namespaces I already
had?" — every per-address surface that has a manager-side
backing is now exposed.

Commits: `873b2dcba` `5939927c1` `bce1e74f0` `8ee00412b`
`4c7be262a` `05704a5b2` `cdfcf4478` `fb71b01de` `f4aa90e7d`
`23c7453f4` `47ec30789` `068814ffc` `d4de3f074` `e095b4c2f`
`31c662ec5`. Nothing pushed.

### Follow-ups spun out of this cascade

- **Wallet integration of bridge in/out per-address** ([code])
  — Closes the long-standing TODO.md line 522 "Multi-chain
  bridge dashboard in wallet apps". Both the deposits-by-
  recipient and withdrawals-by-initiator RPCs landed this
  session, so the wallet UIs (Electron `standalone.html` +
  browser-extension popup) can now drop a "Bridge activity"
  panel that polls both. Single session.

- **Validator / council membership badge in wallets** ([code])
  — `seal_getValidatorByAddress` + `seal_getCouncilMemberByAddress`
  could surface as a small badge on the wallet's main screen
  (next to the SEAL balance) so an operator instantly sees
  whether the loaded key is the validator key, the council key,
  or a regular wallet. Single session.

- **Fast-path index for ValidatorSet::find_by_address_hash**
  ([code, perf]) — current scan is linear over `validators`.
  At sub-thousand-validator scale this is a non-issue, but if
  the validator set grows past a few thousand a per-epoch
  `HashMap<[u8;32], usize>` (address-hash → index into
  `validators`) populated in `ValidatorSet::new` would make
  the lookup O(1). Same shape would apply to
  `TechnicalCouncil::find_by_address_hash`, though the council
  caps at 11 so it never matters there.

## 2026-05-09 evening — Tier-2 #5 + #7 cascade + Tier-3 #9 closed; Tier-2 #8 partial

13 commits across three batches. Highlights:
- **Tier-1 #4 closed** — in-program bridge pause (Solana + Stellar)
- **Tier-1 #3** — step 1/6 (HAMT-backed BalanceStore + cached state
  root) and step 5/6 (balance_scale bench) done. Storage-rent +
  state-sync remain.
- **Tier-2 #5 closed** — wallet QR codes (vendored 270-line
  encoder, jsQR-verified) + balance readout + per-token rows on
  both Electron and browser-extension wallets. Scan-destination
  QR spun out as new sub-item #8a.
- **Tier-2 #6 closed** — Electron wallet native SEAL Send form +
  balance readout
- **Tier-2 #7 closed** — `seal_listTrades` RPC + bounded trade
  history + `seal trades` CLI + Electron trade tape + wallet TUI
  pairs view fix + web-explorer Markets section + browser-extension
  popup tape.
- **Tier-2 #8** partial — popup idle auto-lock (5-min timer,
  capture-phase reset). WASM SK handle still pending.
- **Tier-3 #9 closed** — `apps/seal-faucet/` axum service, ML-DSA
  signed `seal_transfer` with per-address + per-IP cooldowns and
  HRP cross-network paste guard. Plus `docs/TESTNET-FAUCETS.md`.

Commits this session: `0c05de220` `a69b9e11a` `42cd05a89`
`1805a700b` `74434ac9e` `681d80b59` `93298597f` `857d57719`
`9be04106c` `a43fe12fa` `ded167312` `032f96162` (+ doc syncs
`b6d761e8d`, `b49b2e447`, `ea9ba19db`, this one).

Predecessor session (2026-05-08): PLAN #2/#3/#4/#5/#6/#7 closed,
Lean 0 sorries, doc cleanup cascade.

Per-session handoff reports live under `TODOS/SESSION-YYYY-MM-DD.md`:

- [SESSION-2026-05-10-testnet-readiness](TODOS/SESSION-2026-05-10-testnet-readiness.md) —
  testnet-readiness batch plan (Stellar SDK skew, state-sync
  RPCs, CUDA runbook check, validator registration portal,
  release script). Implementation pending.
- [SESSION-2026-05-08](TODOS/SESSION-2026-05-08.md) — vendor refresh
  (rustls-webpki 0.103.12 → 0.103.13, RUSTSEC-2026-0104 cleared) +
  address-validation completion (`validate_dest_address` for the
  bridge withdrawal path; format-only Solana/Stellar guard).
- [SESSION-2026-05-07b](TODOS/SESSION-2026-05-07b.md) — afternoon
  batch: RTX 6000 host became available, so CUDA STARK proving was
  reclassified out of "Blocked — needs NVIDIA hardware" and a
  bring-up script (`scripts/cuda-bringup.sh`) landed.
- [SESSION-2026-05-07](TODOS/SESSION-2026-05-07.md) — small-batch:
  `--mainnet` rejects `--dev-faucet`; AES-GCM TODO re-scoped to
  seal-forms demo (core private tables already on AES-GCM since
  2026-04-13).
- [SESSION-2026-04-23](TODOS/SESSION-2026-04-23.md) — interim-release
  state, open bugs, bridge-e2e paused mid-bring-up (Solana now healthy,
  Seal validators Created, ready to resume with `./scripts/bridge-e2e.sh`).

---

## PLAN — next session priorities (2026-05-09 onward)

After 2026-05-08 closed PLAN #2/#3/#4/#5/#6/#7 + Lean 0 sorries +
afternoon Solana bridge-e2e + Metal Option A vendor wiring + combined
state-root in BlockHeader, the remaining items are listed below in
**leverage order**. Each is independent; pick any single one as a
session unit.

### Tier 1 — mainnet-prerequisite, single-session

1. **CUDA STARK bring-up on RTX 6000** ([code+infra]) — *deferred to
   the GPU host (other machine).* `scripts/cuda-bringup.sh`
   is ready; needs to be run on the RTX 6000 host. Captures CUDA
   wall-time, peak RSS, and receipt size into `target/cuda-bringup/results.txt`
   for the same guest the CPU run measured at 10.9 s / 657 MB / 205 842
   bytes. Goal: first GPU number for STATUS.md row 7/8 and TODO.md
   §"Performance".

2. **Stellar SDK / CLI / docker-image alignment** ([code+infra]) —
   PLAN #1 paused on three-way version skew (`bridges/stellar/Cargo.toml`
   pins `soroban-sdk = "22"`, local `stellar` CLI is `22.0.0`,
   `stellar/quickstart:latest` runs protocol **25**). Two options:
   (a) pin `stellar/quickstart:<dated-nightly>` to a tag running
   protocol 22 (lowest risk; docker comment already mentions a similar
   recipe), or (b) coordinated bump to soroban-sdk 25 + CLI 25 (touches
   `bridges/stellar/src/lib.rs` for any breaking API drift; see the
   `symbol_short!` 21→22 migration note as a hint that 22→25 will
   surface similar). Once aligned, the install transaction completes
   and the lock→mint round-trip closes — final mainnet-prerequisite
   gate on the bridge stack.

3. **Native-balance HAMT wiring (PLAN #8 continuation)** ([code+bench])
   — **step 1/6 done 2026-05-09** (commit `a69b9e11a`): `BalanceStore`
   is now HAMT-backed with cache-invalidation on every mutation, so
   block production's `state_root_hash()` is O(1). Closure helpers
   `update<F>` / `update_or_create<F>` replace the removed
   `pub(crate) get_mut`; transfer.rs and staking.rs migrated. HAMT
   gained `iter()` + `contains_key()`.
   **Remaining (multi-session):**
     - [~] Storage-rent on idle accounts. Option **(b) closed**:
       eager dust prune landed `6ed1c2274` (drained-to-zero
       accounts removed from HAMT in `BalanceStore::put`) +
       `--min-opening-balance` landed `c042b406b`. Combined,
       these prevent the dust-fanout attack stateless-ly: an
       attacker can't accumulate empty entries (eager prune) and
       must spend `min_opening_balance` per fresh-account
       creation (cost barrier). Option **(a) deferred**: ongoing
       rent-per-epoch on idle balances (`last_seen_epoch` field
       on `Balance`, `sweep_inactive(epoch, threshold, floor)`
       consensus hook). (a) is more flexible but adds wire-format
       complexity + per-block state-root churn; revisit only if
       (b)'s cost barrier proves insufficient against a real
       adversary.
     - [x] `benches/balance_scale.rs` — **landed 2026-05-09 commit
       `681d80b59`** with 11 microbenches at 10⁴ / 10⁵ scale (cache-
       hit `state_root_hash`, HAMT lookup, transfer hot path). Heavy
       10⁶+ runs deferred to a one-shot integration test under the
       state-sync scaffolding; documented in the bench module preamble.
     - [x] State-sync snapshot format — **design doc landed
       2026-05-09 dawn-of-2026-05-10** (commit `<this>`).
       `docs/STATE-SYNC.md` (~290 lines): chunked content-addressed
       HAMT-leaf stream, manifest tied to tip Ringtail aggregate,
       `seal_getSnapshotManifest` / `seal_getSnapshotChunk` /
       `seal_listSnapshots` RPC surface, four-step bootstrap flow
       (header-sync → pick → stream → tip catch-up), trust model
       table, operator flags, deferred work (incremental sync,
       state-witness sync, private-table state). Implementation
       remains; doc is the contract.
   The `seal_account_count` metric exposed in `/metrics` already makes
   dust-fanout *observable*; storage-rent + min-opening-balance are
   what turn observability into a real cost on the attacker.

4. **~~In-program bridge pause (Solana + Stellar)~~** — **DONE 2026-05-09**
   (commit `0c05de220`). Solana: `BridgeState.paused: bool`,
   `set_pause(paused)` ix (`has_one = authority`), `lock_tokens` and
   `unlock_tokens` guard with `require!(!paused, BridgePaused)`,
   `PauseStateChanged` event. Stellar: `paused` instance-storage
   flag, `set_pause(paused)` (`admin.require_auth()`), `lock_xlm`
   and `unlock_xlm` reject with `Paused` (check runs *before*
   `sender.require_auth()` so paused contracts don't even prompt),
   `is_paused()` view. Tests: 11/11 Solana (no count change — pure
   helper unit tests only), 14/14 Stellar (+5 pause tests). Defence-
   in-depth on top of the Seal-side per-chain pause.

### Tier 2 — wallet-UX + DX, single-session

5. **~~Wallet QR codes + balance readout~~** — **DONE 2026-05-09
   evening** (commit `a43fe12fa`). Both wallets (Electron
   `standalone.html` + browser-extension `popup.{html,js,css}`)
   show the user's address as a QR via a vendored 270-line
   `qrcode.js` (byte mode, L EC, auto-version v1-5, mask 0;
   round-trip-tested against jsQR). Balance row at the top of
   each account screen polls `seal_getBalance(self)` on a 5 s
   `setInterval` and on every wallet-initiated mutation; stops on
   lock and on screen change. Per-token rows render below SEAL
   from `seal_listTokens` + `seal_getTokenBalance`. **Deferred:**
   Scan-destination QR for Send forms — needs vendoring jsQR
   (~70 KB) and, for the extension, a `camera` permission in
   `manifest.json`. Tracked in the new follow-up below.

6. **~~Electron wallet native SEAL Send form~~** — **DONE 2026-05-09**
   (commit `93298597f`). New "Send SEAL" panel between Chain and SQL
   in `apps/seal-wallet/standalone.html`: balance row +
   Refresh button + recipient/amount inputs + Send button calling
   `signedRpc('seal_transfer', {to, amount})`. Auto-refreshes
   balance 1.5 s after send (one dev-devnet slot). Wired through
   `connect()`, `showWallet()`, `lockWallet()` so the panel tracks
   both wallet-loaded and connected state.

7. **~~DEX trade listing RPC + UI cascade~~** — **DONE 2026-05-09**
   across two batches. Morning:
   - `42cd05a89` — `seal_listTrades` RPC + bounded trade history
     in `seal-token/orderbook.rs` (`MAX_TRADE_HISTORY = 10_000`,
     `since_id` cursor).
   - `1805a700b` — `seal trades` CLI subcommand.
   - `74434ac9e` — wallet TUI `pairs` view rendering fix.
   - `857d57719` — Electron DEX trade tape next to the LOB.

   Evening (this session):
   - `ded167312` — Web explorer "Markets" section (pair `<select>`
     populated from `seal_listPairs`, table polling
     `seal_listTrades` on the existing 2 s tick; `?pair=…`
     deep-link). Browser-extension popup tape (pair selector +
     scrollable `<ul>`, reuses the 5 s balance-poll tick).

8. **Browser-extension idle auto-lock + WASM secret-key handle**
   ([code]) — popup-side idle auto-lock landed 2026-05-09
   (commit `9be04106c`): 5-min inactivity timeout, capture-phase
   click/keydown/focus listeners reset, fires `lock()` and routes
   to screen-unlock. **Remaining:** move plaintext SK bytes off
   the JS `JSON.parse` path into an owning Rust/WASM handle so
   JS only ever sees a numeric handle, never the bytes
   (`secrecy` / `rust-secure-memory` pattern; memsec `mlock` is a
   no-op in WASM so the real win is `Zeroize` on every drop +
   handle-only access). Also: optional service-worker
   `chrome.alarms` cross-popup auto-lock if a hot key ever lands
   in the worker (today the popup is the only signing surface so
   the popup-side timer is sufficient).

8a. **Wallet QR scanning for Send forms** ([code]) — follow-up
    spun out of #5. Vendor jsQR (~70 KB) for image decode, add
    a "Scan QR" button to the Send form on both wallets. Electron
    wallet uses `getUserMedia` directly. Browser-extension popup
    needs a `"camera"` permission in `manifest.json` and a UX
    decision: scan-from-camera vs scan-from-uploaded-image
    (image-upload avoids the permission prompt and keeps a
    minimal-permission posture).

### Tier 3 — testnet ops + docs, single-session

9. **~~Faucet HTTP service~~** — **DONE 2026-05-09 evening** (commit
   `032f96162`). New `apps/seal-faucet/` axum service: POST /faucet
   forwards an ML-DSA-signed `seal_transfer` from a dedicated faucet
   keypair. Per-address + per-IP cooldowns (default 1 h), bumped on
   success only so a 502 from the upstream node doesn't burn the
   requester's quota. `SealAddress::from_string_encoding` parses on
   the way in; HRP cross-network paste guard refuses sealt1← seal1
   (and vice versa) before touching the cooldown map. CLI flags:
   `--key <faucet.json>` (required; same shape seal-cli emits),
   `--node`, `--port`, `--bind`, `--drip` (default 1 SEAL),
   `--interval-secs`. 3 unit tests + an end-to-end Python-stub-node
   smoke test (covers /health, success, cooldown, malformed,
   HRP cross-network). Companion doc: `docs/TESTNET-FAUCETS.md`
   cross-references Stellar friendbot, Solana airdrop, Circle USDC,
   and the seal-node `--dev-faucet` unsigned override
   (refused under `--mainnet`). **Not wired into `scripts/ci.sh`**:
   the keypair holds real testnet balance and CI would burn it.
   Open follow-up: cooldown maps grow unbounded — a per-minute LRU
   sweep would cap memory; revisit if the service moves to a
   long-running prod deploy.

10. **~~Bridge testnet runbook~~** — **DONE 2026-05-09 graveyard
    shift** (commits `fa1c5f369`, `d0a2a76b2`, `64eda58bc`).
    `docs/BRIDGE-TESTNET.md` (~320 lines) walks Solana devnet +
    Stellar testnet bring-up: deploy contracts, fund authority,
    wire program IDs into seal-node, lock→mint and burn→unlock
    flows for SOL/XLM/USDC, common-failure-modes table.
    `scripts/bridge-testnet-demo.sh` (~235 lines) automates the
    lock side; gated behind `BRIDGE_TESTNET_DEMO_LIVE=1` so a
    stray invocation never burns devnet airdrop quotas. New
    `seal addr-to-hex` CLI utility (commit `d0a2a76b2`) decodes
    bech32m → 32-byte hex for the `seal_address` field on the
    bridge programs' lock_* calls. Burn → unlock side documented
    narratively but not scripted (committee signing depends on
    operator's testnet validator set). MANUAL-TESTING.md §17
    cross-linked.

### Tier 4 — multi-session, post-tier-1-3

11. **Algebraic Ringtail verify on-chain — real CU/instruction
    measurement** ([code+infra]) — wired since 2026-04-20 but the
    real BPF compute-unit and Soroban instruction numbers are still
    host projections. Needs `anchor build --features ringtail-verify`
    + a local solana-test-validator run for CU; `stellar contract
    build --features ringtail-verify` + `--cost` invoke against a
    local stellar-core for instructions. Both gate on PLAN #2 above
    being green for Stellar.

12. **ADR-001: wasmtime engine wire-up** ([code]) — vendor
    `wasmtime` with deterministic config (no SIMD, no float NaN
    canonicalization differences, fixed page size, fuel metering),
    wire the `WasmProcEngine::execute` path through it, expose the
    gas-metered host ABI from `seal-procs::host_abi`. Drop the
    `LanguageNotImplemented` runtime error for `LANGUAGE wasm`. Adds
    the second smart-contract execution mode end-to-end.

13. **Bridge formal validation** ([formal]) — TLA+ spec for
    lock↔mint / burn↔unlock cycle (conservation, no-replay, no-unlock-without-burn,
    model-check at N≤4 / nonces≤3); Lean 4 lemmas for the committee-MAC
    envelope + Ringtail verify call binding to on-chain nonce; Kani
    harness for the envelope parser + nonce bookkeeping in both
    `bridges/{solana,stellar}/src/lib.rs`; Miri sweep over
    `crates/seal-ringtail-verify` via the `std-crosscheck` feature.
    Deliverable: `formal/bridges/README.md` + ci-formal.sh wiring.

14. **Browser-extension packaging + app-store distribution**
    ([code+docs]) — `scripts/package-extension.sh` produces `.zip`
    (Chromium), `.xpi` (AMO-signed via `web-ext sign`), Safari Web
    Extension project skeleton. Plus `docs/EXTENSION-PUBLISHING.md`
    (per-store metadata + review expectations + signing-keys
    runbook), a minimal hosted privacy policy under `website/`, and
    a release checklist entry in `LAUNCH-CHECKLIST.md`.

### Orphans now indexed (from 2026-05-08 evening triage)

These were caught in the .md-orphan sweep and are now folded into
the matrix above where appropriate. Listed here so future triage
sees them:

- **`BENCHMARKS.md` §"Future Benchmarks"** — multi-node block
  propagation latency, P2P message throughput, Merkle proof
  generation/verification, encrypted wallet save/load, ZK proof
  generation. The CUDA item is Tier-1 #1; the rest are nice-to-have
  for the v1 perf doc and don't gate mainnet.
- **`ZK-PROOF-ARCHITECTURE.md:269-272`** — 4 composite-ZK formal
  verification rows (TLA+ composite soundness, Lean 4 verification
  gap, Rocq layer independence, Lean 4 ZK↔SQL semantics). Folded
  into Tier-4 #13's spirit; deferred until the bridge formal pass
  is shipped (same toolchain).

### Legacy PLAN content (kept for historical context)

The original 2026-05-07/08 PLAN below documented the items closed
this session. Item-level done markers are in the inline body; the
prose stays so future readers can see what was on the slate going
into 2026-05-08.

Ordered by leverage; mostly independent so any single one can be a
session unit. Estimates assume the ringtail/bridge stack is up.

1. **Resume bridge-e2e end-to-end** ([code+script]) — stack was paused
   2026-04-23 mid-build. Re-run attempted 2026-05-08 — 4 issues found,
   2 fixed, 2 remaining:

   **Fixed this session:**

   - **Vendor-config interference** — workspace `.cargo/config.toml`
     redirects all crates.io lookups to `vendor/`, but the bridge
     programs (`bridges/solana/programs/seal-bridge`,
     `bridges/stellar`) depend on `anchor-lang = "0.31"` and
     `soroban-sdk` which aren't vendored. `cargo-build-sbf` was
     failing with `no matching package named 'anchor-lang'`.
     Added `with_crates_io <cmd...>` helper in `scripts/bridge-e2e.sh`
     that moves the config aside (with EXIT trap to restore) for
     the duration of each bridge build. Same pattern
     `scripts/ci-formal.sh` step 4 uses for Miri.
   - **PATH masking the rustup proxy** — `anchor build` invokes
     `cargo +1.89.0-sbpf-solana-v1.52 build-sbf`, which only resolves
     through the rustup `cargo` proxy at `~/.cargo/bin/cargo`. A
     toolchain-specific cargo appeared earlier on PATH on this
     machine (zsh init quirk), so the `+toolchain` directive failed.
     Forced `~/.cargo/bin` first via `export PATH=…` at the top of
     `bridge-e2e.sh`.
   - **Lying `[ok]` markers** — `pass "Solana program deployed"` was
     unconditional even when `anchor build` / `anchor deploy`
     errored. Each step now checks command exit codes *and* verifies
     the build artifact (`.so` for Anchor, `.wasm` for Soroban)
     exists and is non-empty before printing pass.
   - **Friendbot race** — `stellar keys fund seal-e2e` is racy on
     quickstart's friendbot. Added a 5-attempt retry with 2s sleep.

   **Solana side fully green** (commits `0b27842e4`, `9d38ff999`):

   - `cargo build-sbf -- --locked` from inside
     `programs/seal-bridge/` (the program's existing Cargo.lock pins
     `getrandom 0.2.17` + `0.1.16`, both SBF-compatible — without
     `--locked`, cargo re-resolves and pulls `getrandom 0.3` which
     fails the SBF target with `unresolved module 'imp'`).
   - Replace `anchor deploy` with `solana program deploy --use-rpc`
     (anchor's TPU client times out against the docker validator
     which only exposes 8899/8900, not gossip/TPU ports).
   - Result: real `Program Id: FaYr7yX...` and signature returned;
     `[ok] Solana program deployed` correctly fires.

   **Stellar plumbing fully green, deploy hits a SDK/protocol skew**
   (commit `9d38ff999`):

   - Soroban RPC bound to `0.0.0.0:8003` via entrypoint sed of
     `/opt/stellar-default/local/stellar-rpc/etc/stellar-rpc.cfg`
     (was `localhost:8003`, unreachable through docker port forward).
     Docker compose now exposes `:8003` and the healthcheck waits
     for Horizon + Soroban RPC + friendbot together.
   - Friendbot called directly via curl at `:8000/friendbot?addr=`
     (the CLI's auto-fund constructs `<rpc_url>/friendbot` which
     would target the Soroban RPC at `:8003`, returning network
     errors). `stellar keys generate --no-fund seal-e2e` + 30-attempt
     retry loop on the friendbot URL.
   - Stellar CLI now successfully simulates and submits the install
     transaction, prints the transaction hash, then errors with
     **`xdr processing error: xdr value invalid`**. Root cause:
     the docker image (`stellar/quickstart:latest`) runs Stellar
     protocol **25**, but `bridges/stellar/Cargo.toml` pins
     `soroban-sdk = "22"` and the locally-installed `stellar` CLI
     is `22.0.0` — three-way version skew. Fix is one of:
       - Pin `stellar/quickstart:<dated-nightly>` to a tag that runs
         protocol 22 (e.g. `v441-*` era). Docker comment already
         mentions this option for similar regressions.
       - Coordinated bump: `soroban-sdk = "25"` + install
         `stellar-cli` 25+ on the dev box. Larger change — touches
         `bridges/stellar/src/lib.rs` for any breaking soroban-sdk
         API drift (the `symbol_short!` migration note from 21→22
         hints there's usually some).
     Not script-fixable from CI alone.

   Highest-leverage smoke test against the current mainnet-ready
   feature set; full round-trip queued behind the Stellar
   SDK/CLI/image alignment work.

2. **~~Vendor refresh — RUSTSEC-2026-0104~~ — DONE 2026-05-07b**.
   `rustls-webpki 0.103.12 → 0.103.13` landed via
   `cargo update -p rustls-webpki@0.103.12 --precise 0.103.13` +
   `./scripts/vendor-update.sh`. `vendor/rustls-webpki-0.103.12/`
   replaced by `vendor/rustls-webpki-0.103.13/`; `Cargo.lock`
   regenerated; advisory dropped from `.cargo/audit.toml`.
   `cargo build -p seal-zk -p seal-node` clean, `cargo audit` exits
   0. **Mainnet prerequisite resolved.**

   Follow-up emerged: two **new** hickory-proto 0.25.2 advisories
   surfaced (dated 2026-05-01) in the same audit run —
   **RUSTSEC-2026-0119** (O(n²) name-compression CPU exhaustion;
   fixed in >=0.26.1) and **RUSTSEC-2026-0118** (NSEC3 unbounded
   loop; no fix yet). Pinned by `libp2p-mdns 0.48.0` /
   `libp2p-dns 0.44.0` (the libp2p 0.56 family hard-pins
   `hickory-proto = "0.25.2"`). Ignored in `.cargo/audit.toml` with
   reachability justifications (encoding sites only take
   operator-controlled input; DNSSEC not enabled on
   libp2p-dns). **Track:** bump alongside libp2p-mdns 0.49+ when an
   upstream release lifts the pin. Not a mainnet blocker today.

3. **~~Seal-forms AES-GCM swap~~ — DONE 2026-05-08**.
   `examples/seal-forms/src/lib.rs` now uses `Aes256Gcm` with the
   spec'd construction:

   - **Symmetric key**: `HKDF-SHA3-256(ikm = shared_secret,
     salt = None, info = b"forms.seal/v1/aes-key")` → 32 bytes.
   - **Nonce**: `SHA3-256(form_id_le || respondent_addr ||
     idx_le)[..12]` (deterministic; auditor-reconstructible;
     unique-per-submission iff `(form_id, respondent_addr, idx)` is
     unique on-chain — protocol enforces monotonic `idx`).
   - **AAD**: `form_id_le || schema_hash || respondent_addr` (binds
     ciphertext to form context; cross-form / cross-respondent
     replay produces a tag mismatch).
   - **Cipher**: `aes-gcm = "0.10"` with `Payload { msg, aad }` API.

   New public API: `pub struct AnswerContext<'a> { form_id,
   schema_hash, respondent_addr, idx }` + `pub fn schema_hash(json)
   -> [u8; 32]`. `encrypt_answer`/`decrypt_answer` now take
   `&AnswerContext`. Dropped `examples/seal-forms/src/aead.rs`
   (the bespoke HMAC-SHA3 + 15-byte prefix wrapper) entirely —
   AES-GCM gives auth+confid in one primitive. Removed `xor_stream`
   + `expand_block` helpers.

   Updated `main.rs` to construct an `AnswerContext` per response
   (idx = response index in the loop). Demo binary runs end-to-end
   clean: 3 respondents, trace-walk verifies every response, owner
   decrypts all three plaintexts.

   7 tests in `lib.rs` (was 4): `round_trip_single_answer`
   (asserts +16-byte tag growth), `chain_links_three_responses`
   (auditor walk over AEAD-bundled ciphertext), `schema_ddl_parses`,
   `wrong_secret_decrypt_returns_error` (now an actual error,
   previously silent garbage), `aad_drift_rejects_decrypt` (cross-
   respondent replay), `schema_drift_rejects_decrypt` (form-schema
   change post-submission), `ciphertext_tampering_breaks_tag_and_chain`
   (asserts both AEAD-tag failure and trace-chain failure on
   single-bit flip), `deterministic_nonce_matches_spec` (the
   nonce-derivation formula is checked directly so spec drift would
   surface immediately).

   seal-forms 21 tests green; workspace builds clean. The TODO.md
   spec section can now be marked done.

4. **~~Address-validation completion~~ — DONE 2026-05-08**.
   Audit of `crates/seal-node/src/rpc.rs` revealed the
   `SealAddress::from_string_encoding` guard was already in place on
   `handle_get_balance` (line 946), `handle_faucet` (line 976),
   `handle_transfer` (line 1038), `handle_mint_token` (line 1091),
   `handle_transfer_token` (line 1118), and `handle_get_token_balance`
   (line 1143). The TODO entry was stale; only `seal_bridgeWithdraw`
   `dest_address` was missing — and that's a *foreign-chain* address
   (Solana base58 / Stellar strkey), not a Seal bech32m address, so
   `SealAddress` doesn't apply.

   Landed `seal_bridge::types::validate_dest_address(chain, addr)`
   for per-chain format validation: Solana → base58 alphabet +
   length 32-44; Stellar → 56-char strkey with 'G' (account) or 'C'
   (contract) prefix and uppercase base32 alphabet. Wired into
   `BridgeManager::initiate_withdrawal` so a malformed dest_address
   fails *before* burning wrapped tokens. New `BridgeError::
   InvalidDestAddress(String)` variant. 5 new tests:
   `test_withdrawal_rejects_malformed_solana_address` (the ellipsis
   foot-gun + funds-not-burned check),
   `test_withdrawal_rejects_too_short_address`,
   `test_withdrawal_accepts_valid_stellar_address`,
   `test_withdrawal_rejects_solana_address_for_stellar_chain`,
   `test_validate_dest_address_unit` (positive + negative cases on
   both chains, including 'O'/'0' base58 forbidden chars and
   lowercase Stellar). seal-bridge 53 / seal-node 217 tests green.

   Format-only validation, not full cryptographic. Real bs58 →
   32-byte Pubkey + Stellar strkey CRC16 verification is a
   follow-up — would need vendoring `bs58 0.5` as a direct dep
   (already a transitive) and a `stellar-strkey` crate. Not
   blocking mainnet because format validation already catches the
   foot-guns the morning session worried about (typo, ellipsis,
   wrong-chain paste).

5. **~~One-shot CLI mutations — full set~~ — DONE 2026-05-08**.
   11 typed `seal-cli` subcommands across token / DEX / governance.
   Shared `signed_call(url, method, params, key_file)` helper so
   each wrapper is argument-parsing + result-formatting only.

   **Token (4):**
   - `seal create-token --symbol <S> --name <N> [--decimals <D>] [--max-supply <M>]`
   - `seal mint-token --symbol <S> --to <addr> --amount <amt>`
   - `seal transfer-token --symbol <S> --to <addr> --amount <amt>
     [--confirm-new-recipient]` (passes PLAN #7's recipient policy
     override through).
   - `seal set-transfer-fee --symbol <S> --fee-bps <B>`
     **unblocked MANUAL-TESTING.md §16.2 banner** (banner removed,
     doc now shows the subcommand).

   **DEX (2):**
   - `seal place-order --pair <BASE/QUOTE> --side <bid|ask> --price
     <P> --quantity <Q>` — auto-prints order_id, matched-trade
     count, and open-order count from the RPC result.
   - `seal cancel-order --pair <BASE/QUOTE> --order-id <N>` — signs
     if `--key` provided, otherwise unsigned (`seal_cancelOrder`
     doesn't `requires_auth` today; CLI mirrors both paths so
     future auth tightening doesn't break operator scripts).

   **Governance (5):**
   - `seal gov-propose --track <T> --title <S> [--description <S>]
     [--payload <S>]` — track aliases follow `parse_track`
     (parameter / protocol / treasury_small / treasury_large /
     emergency / constitutional). Prints proposal_id + start_epoch.
   - `seal gov-vote --proposal-id <N> --choice <yes|no|abstain>
     --stake <amt> [--conviction x1..x6|none]`
   - `seal gov-withdraw-vote --proposal-id <N>`
   - `seal gov-delegate --delegate <addr> --track <T> --weight <W>`
   - `seal gov-revoke-delegation --track <T>`

   All 11 registered in `main()` dispatch + `print_usage()`.
   Workspace builds clean; usage smoke-tests pass.

6. **~~Alpha-bootstrap RPC auth~~ — DONE 2026-05-08**.
   `RpcConfig::admin_addresses: HashSet<String>` (default empty);
   `requires_admin_auth(method)` lists `seal_addBridgeObserver`,
   `seal_bridgeCouncilAdd/Remove`,
   `seal_bridgePauseChain/Unpause`; `is_admin(addr, config)` returns
   true on empty set (open mode preserves alpha-testnet bootstrap)
   or on membership when populated.

   Dispatch (`handle_rpc`): when `admin_addresses` is non-empty,
   admin-gated methods force authentication first (`-32003` on
   missing/invalid signature) then check `is_admin` (`-32004` on
   non-member). Open mode skips both — `bridge-e2e.sh` keeps working
   unchanged. CLI flag `--admin-address` (repeatable) populates the
   set; `seal-node --mainnet` without any `--admin-address` emits a
   startup warning.

   Tests: `test_requires_auth` (extended), `test_requires_admin_auth`,
   `test_is_admin_open_mode`, `test_is_admin_gated_mode`. seal-node
   220 tests green (was 217). SPEC.md §5.5 documents the gating model
   end-to-end. **Mainnet prerequisite resolved.**

7. **~~Recipient-new-account policy~~ — DONE 2026-05-08**.
   Three-mode guard on `seal_transfer` + `seal_transferToken`:

   - **Block (default)** — `RpcConfig::allow_new_recipients = false`
     and request omits `confirm_new_recipient`. Rejects with
     `-32007` if the recipient has no prior ledger entry.
   - **Confirm (per-request)** — caller passes
     `confirm_new_recipient: true` (JSON boolean strict; `"true"`
     string falls back to block).
   - **Allow (node-wide)** — `--allow-new-recipients` CLI flag for
     bridge/faucet nodes that legitimately mint to fresh accounts.

   Implementation: `BalanceStore::has_account(addr)` and
   `TokenManager::has_token_account(symbol, addr)` (returns true
   even for accounts that drained to zero — a known account is
   still known); `check_recipient_policy(config, params,
   recipient_known, addr)` helper in `crates/seal-node/src/rpc.rs`;
   wired into `handle_transfer` and `handle_transfer_token` after
   the bech32m guard but before the ledger mutation. The two guards
   are independent: typo addresses are rejected at format-validate,
   well-formed-but-unknown at policy.

   6 new tests (`test_recipient_policy_*`): block-default-rejects,
   block-accepts-existing, confirm-unblocks-new,
   confirm-false-still-blocks, allow-mode-skips-check,
   non-bool-confirm-treated-as-false. seal-node 226 / seal-token 88
   green. SPEC.md §5.6 documents the model.

8. **Native-balance scaling** ([code, multi-session]) — partial 2026-05-08:
   - [x] **Surface `account_count` in `/metrics`** — added
     `seal_account_count`, `seal_total_supply_micro`, and
     `seal_tokens_registered` gauges to `handle_metrics`. Dashboards
     can alert on a sudden spike (the dust-fanout signal pre-HAMT).
   - [ ] Wire `seal-token/hamt.rs` into `BalanceStore` (multi-session;
     replaces the `HashMap<String, Balance>` interior with a HAMT
     so the account-set is content-addressed and persistent).
   - [ ] Add storage-rent on native accounts (rent-per-epoch on idle
     accounts; pruning when balance drops below the rent floor).
   - [ ] Add `benches/balance_scale.rs` (probe HAMT vs HashMap perf
     at 10⁶ / 10⁷ accounts).
   Without the HAMT wiring and storage-rent, dust-fanout attacks are
   a real risk; the metrics gauge at least makes a fanout attempt
   observable in real time.

9. **CUDA STARK bring-up on RTX 6000** ([code+infra]) — RTX 6000
   host became available 2026-05-07; CUDA was previously the one
   "blocked on hardware" item (see Blocked table). Run
   `./scripts/cuda-bringup.sh` on the RTX 6000 host. Script pins
   feature flags (`risc0 local-prover risc0-zkvm/cuda gpu-cuda`),
   probes `nvidia-smi` for driver + CUDA runtime versions, runs the
   segment prover end-to-end, and writes receipt size + wall-time +
   peak RSS to `target/cuda-bringup/results.txt`. Goal: capture a
   first CUDA wall-time for the same guest the CPU run measured at
   10.9 s / 657 MB / 205 842-byte receipt. Once results are in,
   update STATUS.md row 7/8 with the actual numbers and unblock
   GPU benchmarks in TODO.md §"Performance".

### Deferred — track but don't pull this session

- ADR-001 wasmtime engine wire-up (CALL dispatch + PL/pgSQL — the
  parser landed; runtime needs `wasmtime` vendored).
- ~~Lean 4 sorries in `MerkleTree.lean`~~ — DONE 2026-05-08 (commit
  `58102e9fc`, 0 sorries; helper lemmas + delete theorems all
  proven without Mathlib).
- ~~Browser-extension cross-browser polyfill~~ — DONE 2026-05-08
  (commit `9fb9beec7`). `browserApi` alias resolves `browser`
  vs `chrome` at startup; same source now runs on Chromium MV3,
  Firefox MV3, and Safari Web Extensions. Inlined in
  `background.js` + `popup.js` (modules); IIFE-style in
  `src/browser-polyfill.js` for content-script context (loaded
  before `content.js` per `manifest.json`). All 5 JS files pass
  `node --check`. Per-browser packaging (`.zip`/`.xpi`/`.safariextz`)
  is a separate workstream.
- Metal segment-prover Option A (~1 day) — only if benchmarking
  proves the recursion-only Metal speedup isn't enough for our
  workload.

---

## Legend

- **[code]** — in-tree engineering task, no external dependency
- **[script]** — infra/scripting task (docker-compose, shell, CI glue)
- **[infra]** — requires external hardware or third-party resource we
  do not currently have
- **[external]** — genuinely external (audit vendor, governance vote)

---

## Active — we can start any of these right now

### Bridges

**B1–B8 landed in the 2026-04-19 session.** What's left:

- [x] **[code]** Algebraic Ringtail verify on Solana BPF — **wired
      2026-04-20 (cont.)**. `verify_ringtail_sig` now decodes a fixed
      34884-byte envelope (committee MAC + participant_count +
      threshold + challenge + z + matrix_a[K] + public_key_t[K]) and
      calls `seal_ringtail_verify::verify(&ctx, &sig, &pp, b"",
      threshold)`. Build remains feature-gated. Host-side cost
      projection via `scripts/measure-ringtail-cost.sh` (~944 µs →
      ~11k CU on M-series). Real CU measurement still pending — needs
      `anchor build --features ringtail-verify` + a local
      test-validator run.
- [x] **[code]** Algebraic Ringtail verify on Soroban — **wired
      2026-04-20 (cont.)**. Same envelope shape (BE u16 fields per
      Soroban convention), materialized into a stack `[u8; 34884]`
      buffer via `Bytes::copy_into_slice`, then handed to
      `seal_ringtail_verify::verify`. Real instruction measurement
      requires `stellar contract build --features ringtail-verify`
      + a `--cost` invoke against a local stellar-core.
- [~] **[code]** Fix seal-threshold signer to match
      `verify_signature_full` — **session 1 landed 2026-04-20**.
      Additive full-protocol path: `RingtailParty::round1_full`
      produces `D_i = A·r_i + e_i` as a K-vector commitment;
      `aggregate_commitments` sums per row; `aggregate_responses_full`
      hashes the aggregated D into the challenge;
      `generate_public_params_no_error` builds `t = A·s` keys;
      `sign_single_full` is a 1-of-1 convenience wrapper. BPF
      cross-check (`crates/seal-ringtail-verify/tests/crosscheck.rs`)
      now accepts byte-exact 1-of-1 + 2-of-2 signatures (previous
      `#[ignore]` removed). The simplified one-shot
      `RingtailThreshold` trait used by `committee.rs` / fuzz / bench
      was left untouched (additive change).
      **Follow-up status (2026-04-20 cont.):**
        - [x] migrated `crates/seal-node/src/committee.rs` — added
          parallel `CommitteeManagerFull` driving the full path
          end-to-end with byte-exact verify (3 tests).
        - [x] Lagrange primitives in `seal-threshold::lagrange`
          (per-coefficient combiner; 6 tests). Wiring into
          `aggregate_responses_full` for true t-of-n Shamir is the
          next-next step (the n-of-n test still uses shared 2·sk).
        - [~] Ringtail rounding/smudging — `seal-threshold::rounding`
          ships the primitives (`round_coeff`, `round_poly`,
          `sample_smudge`) at `DROP_BITS = 0` (identity). Production
          deployment must re-derive `DROP_BITS` and `SIGMA_SMUDGE`
          from the audit's noise budget; the
          `full_single_signer_smudging_breaks_byte_equality` test
          still pins the boundary.
      Reference paper:
      `docs/references/ringtail-eprint-2024-1113.pdf` (ePrint
      2024/1113).
- [x] **[code]** Seal node bridge RPC wiring — **done 2026-04-19**.
      `BridgeManager` + `BridgeObserverSet` in `RpcState`; methods:
      `seal_getBridgeDeposits`, `seal_getBridgeStatus`,
      `seal_getBridgeWrappedBalance`, `seal_bridgeWithdraw` (auth),
      `seal_addBridgeObserver`, `seal_listBridgeObservers`,
      `seal_pollBridges`. `bridge-e2e.sh` rewritten to drive them.
- [x] **[code]** Emergency pause mechanism — **done 2026-04-19**.
      `BridgeManager::{pause,unpause}_chain` blocks deposits,
      processing, and withdrawals on the named chain with a
      `ChainPaused` error; `seal_bridgePauseChain` /
      `seal_bridgeUnpauseChain` / `seal_bridgeListPaused` RPCs
      gated on 2/3 Technical Council supermajority via
      `TechnicalCouncil::has_two_thirds_approval`. Bootstrap
      through `seal_bridgeCouncilAdd`/`Remove`/`List`.
- [ ] **[code]** Ethereum bridge (deferred, ~2-3 months)
- [ ] **[code]** Bitcoin bridge (deferred, ~3-6 months)

### Formal-verification follow-ups from this session

- [x] **[code]** Miri vendor blocker — **done 2026-04-19**. Fixed
      by teaching `scripts/ci-formal.sh` step 4 to move
      `.cargo/config.toml` aside for the Miri run; the sysroot
      build can then pull std's exact deps from the real registry.
      seal-merkle passes Miri green (35 tests, no UB, 210 s).
- [x] **[code]** Kani 66/66 — **done 2026-04-19**. Swapped
      `DelegationManager` + `ForkChoice` to `BTreeMap`; refactored
      3 fork_choice harnesses to verify decision logic directly
      (BTreeMap's internal node-split loops are intractable even
      with tight unwind bounds). Runtime tests still green.

### ZK proving / GPU

- [ ] **[code]** Metal segment-prover Option A — un-comment
      vendored Metal HAL compile in
      `vendor/risc0-circuit-rv32im-sys/build.rs:93-96,238`, add
      `new_metal` FFI entry in `cxx/rv32im/ffi.cpp`, gate with a
      `metal` Cargo feature, extend `prove.rs:193-199` `cfg_if!`.
      See `crates/seal-zk/METAL.md` — ~1 day if upstream's 609-line
      Metal HAL is complete, ~1-6 weeks if we hit missing kernels
      (Options B/C).

### Longer-lived roadmap items from TODO.md

These predate this session; listed here because they're still open
and not deferred. For full descriptions see TODO.md.

- [x] **[code]** `#STORAGE-FORGET` — **done** (already landed before
      2026-04-19 — TODOS.md/TODO.md stale). SPEC.md §7.3 (row
      salting), §7.4 (storage leases + write/read invoicing), §7.5
      (lease expiry, pruning, slashing for serving expired data)
      all present. Implementation: salt field in `seal-sql/types.rs`
      with deterministic `derive_salt` from block seed; salt mixed
      into Merkle leaf in `seal-sql/merkle_state.rs`; `StorageLease`
      + `LeaseManager` in `seal-token/storage_lease.rs`; write-byte
      burn + read stake-gate wired through `ConsensusRunner`.
- [x] **[code]** Token & Payment wiring — Phase 1 **done**: genesis
      balance load (2026-04-19 via `GenesisConfig::apply_balances` +
      `ConsensusRunner::apply_genesis`); `seal_transfer` RPC
      (`rpc.rs:842`); emission-at-epoch hook (`consensus_runner.rs:342-358`,
      already wired pre-session). Phase 2 (custom token RPCs) also
      wired: `seal_createToken` / `seal_mintToken` /
      `seal_transferToken` / `seal_getTokenBalance` /
      `seal_listTokens` all present.
- [x] **[decision]** Smart-contract execution model — **decided
      2026-04-19** (ADR-001). Default `LANGUAGE sql` (PL/pgSQL-style
      stored procs), opt-in `LANGUAGE wasm` (deterministic sandbox,
      minimal host ABI). Postgres multi-language `CREATE FUNCTION`
      as inspiration. See `docs/decisions/ADR-001-stored-procedures-and-wasm.md`
      + SPEC.md §4.1. Implementation (parser, `seal-procs` crate,
      gas schedule) tracked separately.
- [~] **[code]** Implement ADR-001: extend `seal-sql` parser for
      `CREATE FUNCTION`/`PROCEDURE`/`TRIGGER` with `LANGUAGE` clause;
      new `seal-procs` crate with `SqlProcEngine` + `WasmProcEngine`
      (wasmtime, deterministic config, gas-metered host ABI).
      **Session 1 landed 2026-04-20**: `seal-procs` crate created
      (`Procedure`, `ProcedureStore`, `SqlProcEngine`, on-chain
      `code_hash`). `seal-sql` Engine handles `CREATE FUNCTION` (6
      tests + 10 procs tests).
      **Session 2 landed 2026-04-20 (cont.):**
        - `Engine::execute_call` dispatches `CALL proc(arg, ...)`
          through `ProcedureStore` for SQL/PL-pgSQL/WASM bodies
          (4 new tests).
        - `seal-procs::plpgsql` lowers `BEGIN ... END;` blocks; rejects
          unsupported control flow with a clear error (6 tests).
        - `seal-procs::wasm_validate` (feature `wasm-validate`,
          default ON) gates LANGUAGE wasm bytecode at registration via
          `wasmparser` — WASM1 features only, single `run` export, all
          i64 params, no host imports (5 tests).
        - `LanguageNotImplemented` retained at execution time for WASM
          until `wasmtime` is vendored.
      **Remaining:** wasmtime engine wire-up; trigger hooks; richer
      PL/pgSQL control flow.
- [x] **[code]** Browser-extension wallet (manifest v3, WASM crypto,
      ML-DSA signing) — **done 2026-04-20**.
      `apps/seal-wallet-extension/` with MV3 manifest, service-worker
      message routing + storage, content script + in-page
      `window.seal` provider (EIP-1193-shaped), popup UI that owns
      WASM ML-DSA signing and an AES-GCM vault keyed by
      PBKDF2-SHA-256(310k). Reuses `sdks/wasm` artefacts.
- [x] **[code]** Demo apps: `social.seal`, `kyc.seal`, sealed-bid
      auction, copy-trading, decentralized Kindle, x402-style
      payment. **All seven landed under `examples/` by 2026-04-20
      (cont.):** `seal-forms` (ML-KEM + trace chain + new MPC sum +
      ZK statement + AEAD + web frontend), `seal-social` (schema +
      RLS), `seal-auction` (commit/reveal), `seal-x402` (HTTP 402 +
      ML-DSA receipts), `seal-copy-trading` (allowance-capped
      mirror), `seal-kyc` (ML-DSA attestations + HAS_KYC), and
      `seal-kindle` (per-chapter encryption + per-reader ML-KEM
      wrap). 75+ combined tests.
- [x] **[code]** Wire `DexManager.match_all(ts)` into block
      production — **done 2026-04-20**. Shared
      `Arc<Mutex<DexManager>>` on `ConsensusRunner` (`set_dex_manager`
      lets `start_rpc_server` swap in its `RpcState.dex` Arc); matching
      runs every block via `try_lock` inside
      `produce_block_with_vrf` (lock-free — skips a slot if RPC is
      writing). 2 unit tests cover both wiring + state sharing.
      **`TxType::DexMatch` emission landed 2026-04-20 (cont.)**:
      consensus emits a proposer-signed tx whose payload is bincode of
      `Vec<(pair, Vec<Trade>)>` so trades fold into `tx_hash` and the
      per-block ZK proof. Replay's catch-all handles it as a no-op.
- [x] **[code]** Token-gated SQL RLS end-to-end — **done 2026-04-20**.
      Added `NamespaceRegistry` to `ConsensusRunner` plus
      `Arc<RwLock<HashMap<String,u64>>>` `balance_mirror` refreshed
      each produced block. `deploy_namespace` installs a token
      checker that reads from the mirror; `submit_sql_in_namespace`
      routes through `AppNamespace::execute_as`; `enable_rls_policy`
      installs policies programmatically (SQL parser doesn't ingest
      `CREATE POLICY` yet). RPC `seal_submitSql`/`seal_querySql`
      dispatch through the namespace path when `namespace` is
      supplied. End-to-end test mints balances, deploys
      `vault.seal`, enables `HAS_TOKEN('SEAL', 100)` policy, asserts
      holder sees row + non-holder denied.
- [~] **[code]** `forms.seal` — **session 1 landed 2026-04-20**.
      `examples/seal-forms/` ships the full design: per-form ML-KEM
      keypair, encrypted answers via `encapsulate` + XOR-stream from
      shared secret, iterated SHA-3 trace chain
      (`trace_i = SHA3(prev || ct_answer_i)`) starting from a
      `genesis_trace(form_id, owner, schema_json)` root. Auditors
      can verify the chain without decrypting; owner uses ML-KEM
      secret to read. 4 lib tests + working binary. **Remaining:**
      MPC-committee variant for public surveys, ZK-provable
      statistics circuit, frontend (TUI + web form builder),
      AEAD swap-in (currently demo XOR-stream).
      - Schema: `forms` (id, owner, schema_json, pubkey_mlkem,
        created_at), `responses` (form_id, respondent_addr,
        ct_answer, trace_hash, prev_trace_hash, block_height,
        sig).
      - Each answer encrypted under the form's ML-KEM public key
        (per-form recipient keypair, private half held by the
        form owner or MPC committee for public surveys).
      - Append-only hash trace per form: `trace_i =
        SHA3(prev_trace || ct_answer_i || block_seed_i)`. Chain
        commits to the tip of the trace so the full response log
        is Merkle-reconstructible from on-chain data.
      - Later: prove statistics (mean, count-match, cohort
        threshold) with a ZK circuit that takes (ciphertexts,
        trace, decryption share / witness) and emits a public
        result without revealing individual answers. Parks the
        privacy budget on the circuit, not the contract.
      - RLS: raw `ct_answer` readable only by owner (or MPC
        quorum); `trace_hash` public so anyone can verify the
        transcript integrity.
      - Frontend: TUI + web form builder; submission via
        `seal_transfer`-style authenticated RPC.
- [ ] **[security]** Bridge alpha-bootstrap RPCs are unauthenticated.
      `seal_addBridgeObserver`, `seal_bridgeCouncilAdd`,
      `seal_bridgeCouncilRemove`, `seal_bridgePauseChain`,
      `seal_bridgeUnpauseChain` are not listed in `requires_auth()`
      (`crates/seal-node/src/rpc.rs:319-347`), so any RPC client can
      register observers pointing at arbitrary URLs or seat/unseat
      council members. Only `seal_bridgeWithdraw` is ML-DSA-gated.
      Acceptable for the alpha-testnet bootstrap phase (the
      handler comments say so), but before mainnet:
      (1) add an admin-role check (genesis-configured admin pubkey
          or a role registry) to observer + council mutations;
      (2) require approver-side co-signing on
          `seal_bridgePauseChain`/`Unpause` so the `approvers`
          array can't be forged — today the endpoint trusts the
          caller's unsigned list and only checks membership +
          dedup;
      (3) document the role model in SPEC.md and update
          MANUAL-TESTING.md §17 (which currently flags this
          in the preamble but shouldn't need to).

- [~] **[code]** Browser-extension wallet real lock/unlock —
      **session 1 landed 2026-04-22**. `popup.html` now has
      `screen-setpass` (Create/Import both funnel through it; 8-char
      min, confirm-twice) and `screen-unlock`; `popup.js` drops the
      old `DUMMY_PASSPHRASE`, derives the AES-GCM key from the user's
      passphrase, caches the decrypted vault in a single in-popup
      `unlocked: Uint8Array`, zeroes it on explicit Lock and on
      `pagehide`/`beforeunload`, and surfaces a generic "Wrong
      passphrase" on GCM-tag failure. MANUAL-TESTING.md §1.5 +
      `apps/seal-wallet-extension/README.md` updated. Also added
      `apps/seal-wallet-extension/example/index.html` — a static
      example dApp served via `python3 -m http.server` — so the
      §1.5 smoke flow has a concrete target. **Change-passphrase +
      Reset-wallet landed 2026-04-22 (cont.):** `screen-changepass`
      re-encrypts the existing plaintext under a new passphrase
      (keeps the key/address; rejects matching or <8-char new
      passphrases and a wrong current passphrase with a generic
      error); `screen-reset` (linked from both Unlock and Account)
      deletes `seal:vault` + `seal:accounts` after the user types
      the literal word `RESET`, then routes back to "No wallet".
      **Remaining:** (a) idle auto-lock policy beyond popup close
      (service-worker `chrome.alarms` → clear an in-worker flag the
      popup consults, with a user-configurable timeout); (b) move
      the plaintext secret-key bytes out of the JS `JSON.parse`
      path and into the Rust/WASM side so we can wrap them in
      `zeroize::Zeroizing` / `secrecy::SecretBox` — ideally a
      `rust-secure-memory`-style owning handle (memsec `mlock` is a
      no-op in WASM, so the real win is (i) `Zeroize` on drop across
      every copy, (ii) a single owning handle inside WASM that the
      JS side can only reference by handle, never read back).

- [ ] **[code]** Browser-extension wallet cross-browser support —
      today the manifest targets Chromium only (`"manifest_version":
      3`, `minimum_chrome_version: 119`, `chrome.action.openPopup`,
      `chrome.storage`/`chrome.runtime` throughout, MV3 service
      worker). Target matrix + known sharp edges:
        - **Edge, Brave, Opera, Arc** — Chromium-based; should
          already Load-unpacked. Verify each end-to-end and document
          any install deltas.
        - **Firefox** — MV3 is supported but (a) uses `browser.*`
          rather than `chrome.*` (use `webextension-polyfill` or
          feature-detect), (b) background is an *event page*, not a
          true service worker (keep state assumptions minimal), (c)
          ships AMO-signed `.xpi` bundles — add a packaging step.
          `chrome.action.openPopup` behaves differently (gated on a
          user gesture); fall back to a badge/notification when it's
          rejected.
        - **Safari** — requires repackaging as a Safari Web
          Extension via Xcode (`safari-web-extension-converter`),
          distribution through the App Store (or a signed dev
          profile). `crypto.subtle` + `TextEncoder` are fine;
          `chrome.storage.local` maps to the Safari equivalent
          through the converter. Test on macOS + iOS; mnemonic
          copy/paste may need `navigator.clipboard` permission
          handling.
      Work items: introduce a thin `browserApi` shim (or pull in
      `webextension-polyfill`) so the source is one codebase; add
      `scripts/package-extension.sh` that produces `.zip` (Chromium),
      `.xpi` (Firefox), and the Safari project skeleton; extend
      `MANUAL-TESTING.md` §1.5 with per-browser Load-unpacked
      instructions.

- [x] **[bug]** Server address derivation didn't match wallet —
      **fixed 2026-04-22**. `authenticate()` used
      `"seal1" + hex(sha3_256(vk)[0..20])` (20 bytes, plain hex,
      hardcoded mainnet HRP) while wallets use
      `SealAddress::from_verifying_key` = `bech32m("sealt"|"seal",
      sha3_256(vk))` (32 bytes, bech32m, testnet-aware). A transfer
      signed by a `sealt1…` wallet was debiting a phantom
      `seal1<40 hex chars>` account with zero balance, so
      authenticated transfers always failed with "account not
      found". Fix: `rpc.rs` now calls
      `SealAddress::from_verifying_key(&vk, state.config.testnet)
      .to_string_encoding()`. Added `RpcConfig::testnet` (default
      true) and a `--mainnet` flag on `seal-node` to flip it.
      End-to-end faucet → transfer → getBalance round-trip
      verified on both sender and recipient. 18/18 rpc tests
      green.

- [~] **[code+docs]** Seal testnet faucet + external-chain faucet
      docs. **In-node dev faucet landed 2026-04-22**: `seal-node`
      now accepts `--dev-faucet` to enable a signature-less
      `seal_faucet` RPC (rpc.rs `handle_faucet`), capped at 1000
      SEAL per address per 24 h window and disabled by default
      (`-32601` error when the flag is off). `seal-cli wallet`
      TUI gained a `faucet [amount]` command that drips to the
      active wallet's address. MANUAL-TESTING.md §15.1.1
      documents the flow. Smoke-tested end-to-end
      (faucet → getBalance) on 2026-04-22.
      **Remaining:**
        - **`apps/seal-faucet/`** (new) — a small HTTP service
          (axum reuse from seal-node) with a single
          `POST /faucet {address}` endpoint. Rate-limit per
          `address` (e.g. 1 claim / 24h) and per source IP (a few
          / day). Back the drip with an ML-DSA-signed
          `seal_transfer` from a dedicated faucet keypair whose
          balance is topped up by the testnet genesis config.
          Server config: `FAUCET_KEY=…`, `FAUCET_AMOUNT=…`,
          `FAUCET_NODE_URL=…`, `FAUCET_WINDOW_SECS=…`. Include a
          minimal static landing page with a "Claim" button that
          calls the endpoint. Threat model: abuse is the only
          real concern; document that mainnet keys must not
          reuse this path. Tests: rate-limit enforcement,
          signed-transfer round-trip against a local devnet.
        - **`docs/TESTNET-FAUCETS.md`** (new) — onboarding cheat
          sheet that brings the Seal faucet together with the
          external-chain faucets:
            · **Seal**: `curl -XPOST .../faucet -d '{"address":
              "seal1…"}'` (or click the landing page).
            · **Stellar XLM (testnet)**: `curl
              "https://friendbot.stellar.org?addr=<GADDR>"` —
              funds 10 000 XLM to a test account. Separate
              friendbot on the Futurenet for contract work.
            · **Solana SOL (devnet)**: `solana airdrop 2
              <pubkey> --url devnet` (rate-limited to a few SOL
              per request; use `https://faucet.solana.com/` if
              the CLI hits quotas).
            · **SPL USDC (devnet)**: mint address
              `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`. The
              simplest mint-to-you path is the Circle sandbox
              faucet at `https://faucet.circle.com/` (select
              "Solana Devnet", paste recipient). Alternative
              when Circle's UI is down: `spl-token create-account
              <mint>` then request from a community faucet.
        - **Bridge-on-testnets operation section** of the same
          doc — wire the above faucets into the end-to-end flow:
            1. fund `seal1<test-recipient>` via the Seal
               faucet,
            2. fund a Stellar testnet account + the bridge
               distributor via friendbot,
            3. run the XLM lock → Seal mint happy path
               (commands mirror the bridge runbook todo),
            4. same pattern for Solana SOL and SPL USDC using
               devnet airdrop / Circle faucet,
            5. reverse direction (Seal burn → external unlock)
               using the Seal faucet'd balance.
          Link the new doc from `bridges/README.md`,
          `MANUAL-TESTING.md` (Bridges section), and the
          existing bridge-testnet-runbook todo so the two pieces
          stay aligned.
        - **CI/automation**: don't wire the faucet into
          `scripts/ci.sh` (external requests would spam faucets
          and be flaky). Keep it manual / opt-in behind an env
          var, same pattern as the proposed
          `scripts/bridge-testnet-demo.sh`.

- [ ] **[code]** Wallet UX: address QR codes (both directions) +
      visible balance readout. Spans the Electron wallet
      (`apps/seal-wallet/standalone.html`) and the browser
      extension (`apps/seal-wallet-extension/src/popup.html`);
      keep implementations aligned.
        - **Show-my-address QR.** Render the user's `seal1…`
          address as a QR code next to the existing "Address /
          Copy" row so a counterparty can scan it with their own
          wallet. Encoding: raw bech32m address (no `seal:` URI
          scheme yet — decide whether to adopt one before
          shipping; BIP-21-style `seal:<addr>?amount=…` would let
          sender-side scans prefill the amount field too).
        - **Scan-destination QR.** In the Send form (tracked in
          the Electron Send-form todo below and the extension
          wallet todo), add a "Scan" button that opens the device
          camera (via `getUserMedia` → a JS QR decoder such as
          `jsQR` or `zxing-js`) and populates the recipient field
          from the decoded address. In the MV3 extension, camera
          access needs a `camera` permission + a full-page popup
          (the toolbar popup is too small for a viewfinder);
          route through an extension page opened with
          `chrome.tabs.create`.
        - **Balance readout.** Surface the connected node's
          `seal_getBalance(self)` result in a dedicated row at the
          top of the account screen on both wallets, refreshed on
          Connect / after every mutation the wallet initiates /
          on a short poll (e.g. 5 s) while the popup is open.
          Also show per-token balances via `seal_listTokens` +
          `seal_getTokenBalance` for the custom-token panel.
        - **Tests.** Add a TUI-less smoke test for the QR
          encoder/decoder round-trip (feed the encoder a known
          address, decode the PNG via the same lib, assert
          equality) so we catch regressions without needing a
          camera.

- [ ] **[code+docs]** Recipient-new-account policy for transfers.
      The bech32m guard landed in `handle_transfer` today blocks
      *malformed* recipients, but a well-formed `sealt1…` address
      that's never been funded is still indistinguishable from a
      cold wallet — exactly how a typo of the form
      "right checksum, wrong owner" looks on the wire. For those,
      the node should let the caller pick a policy per request:
        - **`block`** — reject if the recipient has no on-chain
          history (never received, never appeared as a signer).
          Safest default for interactive transfers; surfaces typos
          loudly. Error: `-32000 recipient has no prior on-chain
          history; pass confirm_new_recipient=true to override`.
        - **`confirm`** — allow only when the request explicitly
          opts in via `confirm_new_recipient: true` in params (RPC)
          or `--confirm-new-recipient` (CLI). Required whenever
          the caller has verified the address out-of-band (QR
          scan, paste from known source). The CLI should prompt
          on tty before setting the flag.
        - **`allow`** — current behavior. Needed for bridge mints
          (first receive from a cross-chain deposit), the dev
          faucet (it already lands on a fresh address), initial
          genesis allocations, and batched airdrops.
      Work:
      (1) Add an `AccountHistory` probe in `seal-token`
          (`accounts.contains_key(addr) || has_signed(addr)`) —
          `balance.rs:BalanceStore` already has
          `accounts.contains_key`; the signer side needs wiring
          once we track caller addresses per block.
      (2) Extend `handle_transfer` (and `handle_transfer_token`
          when that gets the same guard) to read a per-request
          policy: default **block**, override via
          `confirm_new_recipient: true` (→ **confirm** path), and
          a node-level `--allow-new-recipients` flag on
          `seal-node` to fall back to **allow** for bridge/faucet
          nodes where first-receive is the norm.
      (3) `seal transfer` CLI: add
          `--confirm-new-recipient` (forces through); on a tty
          without the flag, prompt "Recipient has no on-chain
          history; continue? [y/N]". Update the TUI `transfer`
          command the same way.
      (4) Docs: MANUAL-TESTING.md §15.2 gets a "new-recipient
          safety" paragraph; SPEC.md (or a new `docs/TRANSFER-POLICY.md`)
          documents the three modes and which RPC methods honor
          them. Cross-reference the bech32m-validation todo (the
          format guard) so reviewers see both layers.
      (5) Tests: `seal_transfer` → never-seen address rejects by
          default; same params with `confirm_new_recipient: true`
          succeeds; bridge-mint RPC path stays unaffected; an
          integration test exercises the CLI prompt.

- [ ] **[code]** Electron wallet: add a native SEAL Send form.
      `apps/seal-wallet/standalone.html` today has panels for
      Connect / Sign / SQL / MPC / ZK / custom-token
      (create/mint/list) / DEX (create pair, place order) but no
      plain `seal_transfer` UI — the `signedRpc` helper at
      `standalone.html:340-350` already canonicalizes the message
      as `SHA3(method || params_json)` and attaches
      `signature`+`sender`, so wiring a Send form is a small UI
      patch, not a protocol change. Work:
      (1) add a "Send SEAL" panel with `recipient` (address) and
          `amount` (u64) inputs and a "Send" button;
      (2) on click call
          `signedRpc('seal_transfer', {to, amount})` and render the
          returned `{status, tx_hash}`;
      (3) add a live `seal_getBalance(address)` readout above the
          form so the user sees the debit after the next block
          without running curl;
      (4) update MANUAL-TESTING.md §15.2 path A to the real flow
          once it lands.

- [~] **[code]** One-shot non-REPL `seal-cli` mutations. **Session
      1 landed 2026-04-22**: `seal transfer <to> <amt> --node
      --key`, `seal faucet --node --key [--amount] [--address]`,
      and `seal balance --node --key [--address]` now ship at the
      top level (see `run_transfer`/`run_faucet`/`run_balance` in
      `crates/seal-cli/src/main.rs`). They reuse `sign_request`
      for the ML-DSA envelope and accept the same bare-int /
      decimal / `SEAL`-suffix amount syntax as the TUI. Keygen
      now emits bech32m testnet addresses so the faucet → balance
      → transfer pipeline round-trips. MANUAL-TESTING.md §15.2
      path C rewritten with the real commands. End-to-end
      verified (Alice 50 → 39.5, Bob 0 → 10.5).
      **Session 2 landed 2026-04-22 (cont.)**: generic
      `seal rpc --method <M> --params <JSON> --node <url>
      [--key <file>]` passthrough. Signs if `--key` present,
      plain JSON-RPC otherwise. MANUAL-TESTING.md §17 rewritten
      to use it for bridge auth paths
      (`seal_addBridgeObserver`, `seal_bridgeWithdraw`,
      `seal_bridgeCouncilAdd`, `seal_bridgePauseChain`,
      `seal_bridgeUnpauseChain`) with fully-expanded curl for
      read-only paths — no more `curl ...` / `, ...`
      placeholders. End-to-end verified (read: bridge status;
      signed: `seal_transfer` reached handler, GCM tag checked).
      **Remaining** (same plumbing, different method + params):
        - `seal create-token --symbol <S> --name <N> [--max-supply <N>] --key creator.json`
          → `seal_createToken`. Lets scripts create tokens without
          the TUI's quote-sensitive `create-token GOLD "Gold Coin" …`.
        - `seal mint-token --symbol <S> --to <addr> --amount <amt> --key creator.json`
          → `seal_mintToken`. Must be signed by the creator; flat
          CLI should surface the `-32000` non-creator error cleanly.
        - `seal transfer-token --symbol <S> --to <addr> --amount <amt> --key signer.json`
          → `seal_transferToken`. Honors the token's
          `transfer_fee_bps`.
        - **`seal set-transfer-fee --symbol <S> --fee-bps <N> --key creator.json`
          → `seal_setTransferFee`.** Surfaces the fee knob that
          MANUAL-TESTING.md §16.2 documents but currently has no
          CLI/TUI path for — blocks anyone from actually trying
          `fee_bps > 0` without hand-rolling an ML-DSA envelope.
        - `seal place-order --pair <BASE/QUOTE> --side <bid|ask> --price <p> --qty <q> --key trader.json`
          → `seal_placeOrder`. Plus `seal cancel-order --pair
          <P> --id <N> --key …` → `seal_cancelOrder`.
        - `seal gov-propose / -vote / -withdraw-vote / -delegate /
          -revoke-delegation --key voter.json` → the five
          governance mutations in `requires_auth`. Thin wrappers,
          but unblock scripted governance testing on testnet.
      Once `set-transfer-fee` lands, drop the "not ready" banner
      from MANUAL-TESTING.md §16.2.

- [ ] **[code]** Scale the native-token ledger to 10⁸–10⁹ addresses.
      Today `BalanceStore` (`crates/seal-token/src/balance.rs:90`)
      is an in-memory `HashMap<String, Balance>`: ~150 B/entry, so
      10⁹ accounts ≈ 150 GB RAM, and a node restart drops the
      entire ledger (no disk backing, no Merkle commitment on
      balances). The existing persistent HAMT in
      `crates/seal-token/src/hamt.rs` is the right primitive but
      isn't plumbed into `BalanceStore`. Concrete work:
        1. **Back `BalanceStore` with the HAMT** so the balance
           map is structurally-shared, disk-backable, and exposes
           a log-depth Merkle root the state commitment can
           include. Keep the `HashMap` impl as a test double.
        2. **Validate address format at the RPC boundary**
           (`handle_get_balance` at `crates/seal-node/src/rpc.rs:909`
           and all other address-taking handlers). Today
           `{"address":"seal1..."}` returns `{"balance":0,...}`
           silently — you can't tell "unknown address" from
           "address with zero balance" from "typo". Reject
           non-bech32m / non-Seal addresses with `-32602 invalid
           address`.
           **Partial fix landed 2026-04-22**: `handle_transfer`
           and `handle_get_token_balance` now run
           `SealAddress::from_string_encoding(…)` before touching
           the ledger. `handle_get_token_balance` additionally
           rejects unknown token symbols with `-32602 unknown
           token 'X' — see seal_listTokens` instead of the
           previous permissive `{balance: 0, total_supply: 0}`
           response (which made "token doesn't exist" look
           identical to "exists, zero balance"). Previously
           `BalanceStore::transfer` did
           `accounts.entry(to).or_default()` and silently created
           a ghost account for any string — sending to
           `"sealt1recipient…"` or `"seal1notreal"` returned
           `Status: confirmed` while the funds were effectively
           burned. Same guard still needed on
           `handle_get_balance`, `handle_transfer_token`,
           `handle_mint_token`, and the bridge/governance
           handlers that take addresses.
        3. **Apply storage-rent / lease to native accounts.**
           `StorageLease`/`LeaseManager`
           (`crates/seal-token/src/storage_lease.rs`, SPEC.md
           §7.4) already gate SQL rows — extend the same pattern
           to native balances so dust creation has a real cost
           and abandoned accounts can be pruned. Without this an
           attacker with a few SEAL can fan out to millions of
           dust accounts and permanently inflate validator
           memory.
        4. **Surface account-count metrics.** Export
           `balances.account_count()` (per-token, if
           `TokenRegistry` is wired in) through `/metrics` so
           growth is visible before it's a crisis. Add a Grafana
           panel + alert at ≥ 10M accounts for v1.
        5. **Benchmark + load test.** Add `benches/balance_scale.rs`
           (Criterion) that inserts 10⁶ / 10⁷ / 10⁸ accounts,
           reporting RSS, insert throughput, and Merkle-root
           recompute time. Block on (1) before running the 10⁸
           case or it OOMs CI.
        6. **State sync.** Once balances are HAMT-backed, a new
           node can bootstrap from a snapshot root + stream
           leaves instead of replaying the whole history.
           Document the snapshot format under
           `docs/STATE-SYNC.md` (new).
      Touches `seal-token`, `seal-node/rpc.rs`, `seal-storage`
      (snapshot dir layout), observability (`metrics.rs`), and
      docs (SPEC.md §token-ledger, new STATE-SYNC.md).

- [x] **[formal]** ~~Eliminate the 7 Lean 4 `sorry`s in
      `formal/lean/SealVerify/Basic/MerkleTree.lean`~~ — **DONE
      2026-05-08** (commit `58102e9fc`). All 7 discharged without
      Mathlib: 6 helper lemmas (`filter_find_none`, `find_append_none`,
      `filter_preserves_find`, `find_mem`, `find_pred`,
      `filter_filter_self`) close out `MTree.delete_idempotent`,
      `delete_then_insert`, `delete_changes_root`. Doc cascade
      (2026-05-08 evening): STATUS.md component table, SECURITY.md,
      formal/lean/README.md, formal/kani/LIMITATIONS.md,
      audits/{protocol,veridise}-*-scope.md all updated to "Proven /
      0 sorries". `LAUNCH-CHECKLIST.md:23` (Lean sorries discharged)
      can now be checked.

- [ ] **[docs]** Full Solana + Stellar testnet bridge runbook.
      Today we have `scripts/bridge-test-ringtail.sh` (local build +
      compute-cost measurement) and per-bridge READMEs describing
      the message shape, but no end-to-end procedure for driving
      **XLM / SOL / USDC** between a Seal testnet node and the
      Stellar/Solana testnets. Needed:
        - **Prereqs**: fund a Stellar testnet issuer + distributor
          via friendbot (`https://friendbot.stellar.org`), a Solana
          devnet keypair via `solana airdrop`, a running Seal
          node with the `seal-node` binary + `seal-cli` wallet. Pin
          exact CLI versions.
        - **Stellar XLM lock → Seal mint** walkthrough:
          (1) deploy `bridges/stellar/` via
          `stellar contract deploy --network testnet`; (2) call
          `set_xlm_sac` with the native-XLM Stellar Asset Contract
          ID (derive from `Asset::Native` for Testnet passphrase);
          (3) user calls `lock_xlm` with a Seal recipient address,
          nonce, and amount; (4) show the emitted
          `BridgeLocked{nonce, amount, recipient}` event and the
          SAC transfer in Horizon; (5) Seal-side watcher picks up
          the event, committee issues `seal_bridgeMint` with a
          threshold signature. Include the exact `stellar contract
          invoke` commands, expected outputs, and Horizon URLs.
        - **Seal burn → Stellar XLM unlock** walkthrough:
          (1) `seal_bridgeBurn` on Seal; (2) committee signs the
          unlock proof (Ringtail algebraic verify once
          `ringtail-verify` flips ON — it builds now, see the
          2026-04-22 allocator fix); (3) anyone can submit the
          proof to `unlock_xlm`; (4) verify nonce is persisted and
          double-unlock is rejected.
        - **Solana SOL and SPL USDC** (devnet USDC mint
          `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`): mirror the
          XLM flow for `lock_sol`/`unlock_sol` and `lock_spl`/
          `unlock_spl`. Show how to create the committee-MAC'd
          envelope by hand for a first manual test, then the
          scripted happy path.
        - **Failure-mode checklist**: wrong nonce, expired
          message, replay, insufficient balance, wrong SAC, wrong
          SPL mint, committee-MAC length/threshold mismatch — each
          should surface a specific error code, not a panic.
        - **Deliverables**: `docs/BRIDGE-TESTNET.md` (new, linked
          from `bridges/README.md` if present and from
          `MANUAL-TESTING.md` §bridges); `scripts/bridge-testnet-demo.sh`
          that runs the happy-path XLM + SOL + USDC round-trips
          against the public testnets (gated behind an env var so
          CI doesn't spam the faucets); per-bridge README updates
          pointing at the new runbook.

- [ ] **[formal]** Formal validation of bridge algorithms. We
      already have TLA+ for consensus/committee and Lean 4 proofs
      scaffolded for core protocol pieces (7 sorries in MerkleTree
      — separate todo above); the bridge side has
      unit tests + Ringtail verify cross-checks but no machine-
      checked spec. Items:
        - **TLA+ spec for the lock ↔ mint / burn ↔ unlock cycle**
          — states: `locked(nonce, amount, recipient)`, `minted`,
          `burned`, `unlocked`. Invariants: conservation
          (locked_total − unlocked_total == outstanding_minted on
          Seal), no-replay (each nonce enters `processed` at most
          once), no-unlock-without-burn. Model-check in TLC for
          a small `N ≤ 4` committee + `nonces ≤ 3`.
        - **Lean 4 lemmas** for the committee-MAC envelope and
          the Ringtail verify call: "if the envelope's
          `participant_count ≥ threshold` AND the algebraic
          verify passes AND the message binding matches the
          on-chain nonce, then the unlock is authorised". Aim
          for 0 sorries — sit next to existing Lean files under
          `formal/lean/`.
        - **Kani harness** for the envelope parser and nonce
          bookkeeping in both `bridges/solana/src/lib.rs` and
          `bridges/stellar/src/lib.rs` — Kani unwinds small
          nonce spaces well and would catch off-by-ones in the
          `done:{nonce}` storage key logic.
        - **Miri run** over the host-side Ringtail verifier
          `crates/seal-ringtail-verify/` under
          `cargo +nightly miri test` (Miri doesn't love
          `no_std`+BPF; the `std-crosscheck` feature path is the
          right entry point).
        - **Deliverable**: `formal/bridges/README.md`
          summarising all four and wiring them into
          `./scripts/ci-formal.sh`.

- [ ] **[code+docs]** Browser-extension packaging + app-store
      distribution. The cross-browser item above lands a
      `scripts/package-extension.sh`; this todo covers everything
      around getting those artefacts published. Per-store work:
        - **Chrome Web Store** — register a developer account
          ($5 one-time), bundle as `.zip`, fill privacy/permission
          justifications (`storage`, `scripting`, localhost
          `host_permissions`), upload + submit for review. Typical
          review: hours–days.
        - **Firefox Add-ons (AMO)** — AMO account, `.xpi` signed
          through `web-ext sign` (or unlisted self-hosted builds
          with a signed manifest). Source-code submission is
          mandatory for minified/bundled code; we have neither
          today but pin a note so we don't regress.
        - **Edge Add-ons** — Microsoft Partner Center account,
          same `.zip` as Chrome Web Store; separate review queue.
        - **Safari Extensions Gallery / App Store** — requires an
          Apple Developer Program membership ($99/yr), repackaging
          via Xcode (`safari-web-extension-converter`), App Store
          Connect metadata, privacy labels, and (on iOS) a host
          app container. Longest/strictest review.
        - **Brave / Opera / Arc** — install the Chrome Web Store
          build directly; no separate stores needed for Brave
          (they use CWS) or Arc. Opera has its own addons site
          (opera.com/addons) that accepts CRX uploads.
      Deliverables: (1) `docs/EXTENSION-PUBLISHING.md` (or a section
      in the extension's `README.md`) with a checklist per store —
      account signup, required metadata (description, screenshots,
      privacy policy URL, permission justifications), artefact
      build command, upload steps, review expectations, and
      versioning/release cadence; (2) a minimal privacy policy page
      hosted under `website/` (stores require a URL); (3) a
      signing-keys / release-credentials runbook (where the AMO
      key, Apple Developer cert, and CWS publisher key live —
      probably referenced, not committed); (4) a release checklist
      entry in `LAUNCH-CHECKLIST.md`.

- [ ] **[docs]** Mention the browser-extension wallet on the
      website + blog (eventually). `website/index.html` currently
      has no reference to `apps/seal-wallet-extension/`. Once the
      cross-browser work above is far enough along, add:
      (1) a short section on the landing page ("install the Seal
      Wallet extension — Chrome / Firefox / Safari") with
      per-browser install links once the packaging script produces
      real artefacts; (2) a launch blog post covering the PQC story
      (ML-DSA signing in the popup, AES-GCM vault under
      PBKDF2-310k), the `window.seal` provider shape
      (EIP-1193-like), the example dApp under
      `apps/seal-wallet-extension/example/`, and the
      Connect → seal_accounts → seal_signMessage flow from
      MANUAL-TESTING.md §1.5. Park a single "TODO: browser-wallet
      section" placeholder in `website/index.html` near the apps
      list so this doesn't get forgotten.

- [ ] **[code]** DEX trade listing + UI cascade — add a
      `seal_listTrades` RPC (params: `pair`, optional
      `since_block`/`limit`) that returns recent filled trades from
      `DexManager`. Requires persisting/retaining a bounded trade
      history per pair in `seal-token/orderbook.rs` (currently trades
      are only emitted inside the per-block `DexMatch` tx payload and
      not queryable). Then cascade the new endpoint to every DEX
      surface: `seal-cli` wallet (`trades` subcommand), Electron
      wallet (`apps/seal-wallet/standalone.html` DEX panel — render a
      rolling trade tape next to the order book), browser-extension
      wallet, and the web explorer (per-pair trade feed). Also
      backfill the CLI `pairs` view so it uses `pair.pair` rather
      than the raw JSON object (same class of bug as the Electron
      `[object Object]` fix on 2026-04-22).

---

## Blocked — cannot be done from our dev machine today

(empty — CUDA STARK proving was previously here; reclassified
2026-05-07 once an RTX 6000 host became available. See PLAN item
"CUDA bring-up" above and `scripts/cuda-bringup.sh`.)

---

## Deferred — genuinely external

- [ ] **[external]** Ringtail external audit (Veridise / Cryspen /
      Trail of Bits). Pre-audit hardening complete this session:
      constant-time norm, zeroize on drop, KAT vectors, new
      `fuzz_ringtail_sign` target. Needs vendor engagement + budget
      + calendar time (~4-6 weeks end-to-end).
- [ ] **[external]** Veridise PQC audit — scope document is in
      `audits/veridise-pqc-scope.md`.
- [ ] **[external]** Protocol audit — scope in
      `audits/protocol-audit-scope.md`.
- [ ] **[external]** Immunefi bug bounty — program spec in
      `BUG-BOUNTY.md`; needs Immunefi contract + funded reward pool.
- [ ] **[external]** Incentivized testnet launch — program in
      `TESTNET.md`; needs reward pool + participant recruitment.
- [ ] **[external] B9** Mainnet bridge deploy — Seal DAO governance
      vote + mainnet multisig. Belongs in LAUNCH-CHECKLIST.md, not
      dev backlog.
- [ ] **[external]** Mainnet genesis — 30+ validators, token
      distribution execution, infrastructure in 3+ regions.

---

## Done this session (2026-04-20)

Seven user-supplied tasks executed end-to-end in one autonomous loop;
44 new tests added; workspace builds clean.

1. **Ringtail signer fix** — paper-shape `D_i = A·r_i + e_i`
   full-protocol path (`round1_full`, `round2_full`,
   `aggregate_commitments`, `aggregate_responses_full`,
   `generate_public_params_no_error`, `sign_single_full`).
   `crates/seal-ringtail-verify/tests/crosscheck.rs`
   `valid_signature_accepted_by_both` and
   `valid_signature_accepted_by_both_n_of_n` now pass byte-exact
   end-to-end against host + BPF verify (the `#[ignore]` is gone).
   Memory note saved: committee migration / Lagrange / smudging
   are next-session work.
2. **DexManager wired into block production** — shared
   `Arc<Mutex<DexManager>>` between `RpcState` and
   `ConsensusRunner`; `match_all` runs each block via `try_lock`.
3. **Token-gated RLS end-to-end** — `NamespaceRegistry` +
   `balance_mirror` on the runner; SQL routed through
   `AppNamespace::execute_as` when a namespace is supplied;
   `HAS_TOKEN(...)` evaluates against the per-block balance
   snapshot. End-to-end test asserts holder allowed / non-holder
   denied.
4. **ADR-001 implementation (session 1)** — new `crates/seal-procs`
   crate with `Procedure` / `ProcedureStore` / `SqlProcEngine` /
   `WasmProcEngine` (stubbed). `seal-sql` Engine accepts
   `CREATE FUNCTION ... LANGUAGE sql|wasm AS $$body$$` with
   `OR REPLACE` semantics.
5. **Browser-extension wallet** — `apps/seal-wallet-extension/`
   MV3, service worker, content + inject scripts (window.seal),
   popup UI with WASM ML-DSA signing and PBKDF2-AES-GCM vault.
6. **Demo apps** — `examples/seal-forms/` (full lib + binary);
   `examples/seal-social/`, `examples/seal-auction/`,
   `examples/seal-x402/` (focused libs with primitives + tests).
7. **Governance JSON-RPC surface** — `GovernanceModule` +
   `DelegationManager` on the runner; 11 new methods
   (`seal_govPropose`, `seal_govVote`, `seal_govWithdrawVote`,
   `seal_govTally`, `seal_govExecute`, `seal_govGetProposal`,
   `seal_govListProposals`, `seal_govGetVotes`, `seal_govDelegate`,
   `seal_govRevokeDelegation`, `seal_govEffectiveWeight`); auth
   required on mutations. 4 unit tests cover the mutation flows.

---

## Done previous session (2026-04-18 → 2026-04-19)

Moved from "pending" to "done":

Earlier batch (2026-04-18):

- [x] MPC hardening: `reconstruct -> Result`, constant-time MAC via
      `subtle`, `Drop` zeroize on `SpdzShare`, `verify_all_macs`,
      6 adversarial tests (`crates/seal-mpc/src/spdz.rs`).
- [x] Ringtail pre-audit hardening: constant-time `centered_abs_ct`,
      `RingtailParty::drop` zeroize via `RingOps::zeroize_poly`,
      5 KAT vectors, new `fuzz_ringtail_sign` target.
- [x] Real in-guest Output digest:
      `tagged_struct("risc0.Output", [SHA256(journal), ZERO])`
      using `sys_sha_buffer`. ELF rebuilt (23 092 bytes).
      Validated by non-dev-mode CPU STARK verify
      (205 842-byte receipt, 10.9 s, 657 MB RSS).
- [x] Kani matrix documented: 60/66 green; 6 blocked on Kani's
      HashMap/thread-local limitation. `formal/kani/README.md` +
      `formal/kani/LIMITATIONS.md` §5.
- [x] Miri sweep extended to seal-merkle/token/threshold/mpc in
      `scripts/ci-formal.sh`. Sysroot build still blocked on
      `cfg-if` mismatch (todo above).
- [x] Metal shader compiler wired on this Mac (Xcode 16 +
      `MetalToolchain` 17A324). Non-dev-mode prove with
      `risc0-zkvm/metal` builds and runs. Upstream segment prover
      has no Metal branch → no speedup today; full DIY path
      documented at `crates/seal-zk/METAL.md`.
- [x] Bridge work decomposed into B1–B9 with classification
      (code vs script vs infra vs external) in
      `bridges/DEPLOYMENT.md`. STATUS.md item #3 split into #3a/b/c/d.
- [x] CUDA zk/proving added as item #8 in STATUS.md.

Post-pause batch (2026-04-19):

- [x] **ADR-001: smart-contract execution model** — decided.
      `LANGUAGE sql` (PL/pgSQL-style) default; `LANGUAGE wasm`
      opt-in. Postgres multi-language `CREATE FUNCTION` as model.
      `docs/decisions/ADR-001-stored-procedures-and-wasm.md`; SPEC
      §4.1 + §13.3 updated.
- [x] **Ringtail BPF/Soroban verifier foundation** —
      `crates/seal-ringtail-verify` crate added. no_std + alloc,
      field/NTT/challenge/verify modules, 20 unit + 3 cross-check
      tests green. Feature-gated `ringtail-verify` hook in both
      `bridges/solana` and `bridges/stellar` unlock paths.
      End-to-end wire-up blocked on seal-threshold signer fix.
- [x] **forms.seal demo app** — added to the demo-app backlog
      with a specific PQC-encrypted answers + iterated-hash
      trace design for later ZK-provable statistics.
- [x] **Transfer-fee RPCs** — `seal_setTransferFee` /
      `seal_getTransferFee` exposed; `seal_listTokens` now
      includes `transfer_fee_bps` in its payload. Auth on set,
      enforced creator check via TokenManager.

Bridge pause batch (2026-04-19, post-session):

- [x] **Bridge emergency pause** — two-commit landing:
      - `BridgeManager::pause_chain` / `unpause_chain` /
        `is_chain_paused` / `pause_reason` / `list_paused_chains`
        with `ChainPaused`/`ChainNotPaused` errors. 8 new tests.
      - Council-gated RPC: `seal_bridgePauseChain` /
        `seal_bridgeUnpauseChain` / `seal_bridgeListPaused` /
        `seal_bridgeCouncilAdd` / `seal_bridgeCouncilRemove` /
        `seal_bridgeCouncilList`. 2/3 supermajority check via
        new `TechnicalCouncil::has_two_thirds_approval` (ceiling
        arithmetic, dedup, non-member filtering). 8 new tests
        across governance + rpc modules.

Bridge batch (2026-04-19):

- [x] **Seal-node bridge RPC wiring** — 7 new methods on the JSON-RPC
      server; `BridgeManager` + `BridgeObserverSet` threaded through
      `RpcState`; `bridge-e2e.sh` updated to use them.
- [x] **B1** — `SolanaObserver::poll_events` real RPC
      (`getSignaturesForAddress` + `getTransaction`, Anchor
      `LockEvent` log decode). 12 unit tests via MockTransport.
- [x] **B2** — `StellarObserver::poll_events` real Horizon
      (`/accounts/{id}/operations`, `invoke_host_function` filter).
      Pluggable `HttpTransport` trait abstraction.
- [x] **B3** — Solana Anchor `unlock_tokens`: committee-MAC verify
      (HMAC-SHA-256 via `sol_sha256` syscall). `committee_key`
      stored at init, `rotate_committee_key` ix for per-epoch
      rotation. 9 Rust unit tests including sha2 cross-check.
- [x] **B4** — Soroban `unlock_xlm`: mirror committee-MAC verify
      (HMAC-SHA-256 via `Env::crypto().sha256`). Distinct domain
      tag (`seal-bridge-stellar-v1`). Soroban unit tests assert
      real MAC verify + reject wrong-key / flipped-bit /
      wrong-length / replay / rotation.
- [x] **B5** — Stellar SAC transfers in `lock_xlm` / `unlock_xlm`
      via `token::Client::transfer`. `initialize` takes `xlm_sac`
      arg; tests assert real token balance deltas on a mock SAC.
- [x] **B6/B7/B8** — `bridges/docker-compose.testnet.yml`
      (Solana test-validator + Stellar quickstart + 3 Seal nodes)
      + `scripts/bridge-e2e.sh` (preflight, deploy, lock→mint
      round-trip; unlock flow stubbed pending further Seal-node
      RPC wiring).

---

## Remaining-work snapshot (2026-04-20)

| Category | Items | Can do now? |
|---|---|---|
| Bridges — B1–B8 | done | ✅ |
| Bridges — emergency pause (2/3 council) | done | ✅ |
| Bridges — algebraic Ringtail verify (on-chain) | 2 chains | Yes (signer cross-check unblocked 2026-04-20; one-line wire-up + CU measurement remain) |
| Bridges — Ethereum / Bitcoin | 2 | Yes (long) |
| Ringtail — committee migration / Lagrange / smudging | 3 | Yes (multi-session) |
| ADR-001 — wasmtime engine + CALL dispatch + PL/pgSQL | ~3 | Yes |
| Demo apps — copy-trading, decentralized Kindle, kyc.seal | 3 | Yes |
| Formal follow-ups | 2 (Miri vendor bump, Kani-6 refactor) | Yes |
| Metal DIY | 1 (Option A, then maybe B) | Yes, ~1 day for A |
| Audit / bounty / testnet / mainnet | 6 items | **No — external** |
| CUDA validation | 1 item | Yes (RTX 6000 host available 2026-05-07; bring-up via `scripts/cuda-bringup.sh`) |

Net: the 2026-04-20 batch closed DexManager / RLS / browser-extension /
forms.seal / governance-RPC outright and put Ringtail-signer + ADR-001
on the multi-session-progress track. Truly-blocked items remain audits
and mainnet-deploy governance; CUDA was reclassified 2026-05-07 (RTX
6000 host now available, bring-up queued).
