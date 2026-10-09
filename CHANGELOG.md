# Changelog

## Unreleased — 2026-09-28 security fixes

⚠️ **Hard break: wipe your data directory on this upgrade.**
`BlockHeader` gained a `proposer_signature` field. bincode is
positional, so persisted chains from before this change no longer
deserialize; the node fails block replay at block 1 and re-seeds.
Delete `<data-dir>` before upgrading.

- **Blocks are now signed by their proposer.** Producers ML-DSA-sign
  the canonical (empty-signature) serialization of the header and store
  it in `BlockHeader.proposer_signature`; `verify_and_apply_block`
  rejects blocks with a missing or non-matching signature. Combined
  with the VRF election check, a received block must now be provably
  produced by the elected validator's key holder.
- **The VRF secret key is no longer gossiped.** Validator records and
  RPC endpoints serve the real VRF *public* key; election evaluation
  takes the local secret explicitly.
- **RPC auth hardening.** Unsigned `seal_querySql` is restricted to a
  single SELECT statement; `seal_mpcAggregate`, `seal_zkProve`, and the
  six previously open-mode-privileged bridge methods
  (`seal_bridgeCouncilAdd/Remove`, `seal_bridgePauseChain`,
  `seal_bridgeUnpauseChain`, `seal_bridgeRotateCommitteeKey`,
  `seal_addBridgeObserver`) now require a valid signature. CLI and
  Android wallet call sites were switched to signed calls.
- `PqRpcSession`'s `Debug` impl no longer prints the full session key.
- **Balances survive restarts; the genesis mint is idempotent.**
  Balance state is persisted to `<data-dir>/balances.bin` (atomic
  temp-then-rename) after boot, after every produced block, and on
  clean exit. Boot replays the on-disk chain first; if replay breaks
  partway, the store is restored from `balances.bin`. The genesis
  mint now fires only when the store holds no accounts, so restarts
  can no longer double-mint genesis supply or reset balances.
- **Money transactions are nonce-stamped.** `seal_transfer` and other
  money-movement types carry an 8-byte LE sender nonce; the consensus
  runner rejects out-of-order or duplicate nonces, and `replay_block`
  re-applies `Transfer` transactions so a replayer converges to the
  same balances.
- **Epoch transitions are signed and verified.** Crossing an epoch
  boundary stashes an `EpochTransitionMsg` (epoch, prev seed, VRF
  output, new seed) signed by the transitioning validator; peers
  re-derive the seed from local chain state and verify the signature
  against an active validator before applying it. The old format —
  an unsigned 8-byte epoch number that let any peer rewrite the epoch
  seed — is rejected.

## Unreleased — 2026-05-16 "no excuse bordel" session

P1#5 layer 4 closed the testnet blocker and several pre-deferred items
landed in the same pass. Tests grew 1148 → 1170.

### Bridge — Ringtail multi-validator integration (P1#5 layer 4)

- `seal_bridge::ringtail_orchestrator::RingtailBridgeOrchestrator`
  now threaded as `Arc<Mutex<…>>` through `RpcState` (RPC layer
  reads session count), the signing-signal channel (BridgeManager
  → orchestrator → broadcast Round1), and the seal-node network
  receive loop (routes Round1/Round2/Aggregate envelopes →
  orchestrator → broadcasts returned envelopes → calls
  `BridgeManager::attach_committee_signature` on Round2Complete +
  the race-loser Aggregate path).
- New `BridgeRingtailBroadcaster` clone-only handle on
  `seal_p2p::node::SealNode` — three `mpsc::Sender<Vec<u8>>`
  clones — lets the start_signing task and other tokio-spawned
  consumers drive Ringtail broadcasts without holding a
  `MutexGuard<NetworkNode>` over an await (NetworkNode is `!Sync`
  via `Cell<...>` inside `BalanceStore`).
- Periodic `prune_stale_sessions` timer (default 300s tick / 600s
  max-idle; `--bridge-ringtail-prune-secs` /
  `--bridge-ringtail-max-idle-secs`).
- New `seal_bridge_ringtail_sessions` gauge on `/metrics`,
  refreshed from `orchestrator.session_count()` at every scrape;
  same value surfaced in `seal_bridgeRingtailStatus`'s
  `orchestrator_active` + `session_count` fields.
- `crates/seal-node/tests/bridge_ringtail_dispatch.rs` —
  in-process integration test driving two orchestrators + two
  BridgeManagers through Round1 → Round2 → Aggregate → attach.
- `scripts/bridge-test-ringtail-multi.sh` — docker-compose smoke
  that renders a Ringtail override, brings up the testnet stack,
  waits for `orchestrator_active=true` on every node, asserts
  validators converge on the same `committee_signature_hex`.

### Bridge — in-flight signing-session persistence (§3)

- `RingtailBridgeSession` derives `Serialize + Deserialize`.
- `seal_threshold::ringtail::RingtailParty::{export,import}_round1_randomness`
  so the validator's one piece of mutable secret state survives
  a restart.
- `seal_bridge::ringtail_orchestrator::{export_session,
  restore_session}` plus a new `InFlightSnapshot` type.
- New `seal_bridge::ringtail_store` module — atomic per-file
  `<data_dir>/ringtail-sessions/<wd_id>.json` save / load_all /
  delete.
- `seal-node` main loads + restores every persisted snapshot on
  boot; the receive loop persists after every successful ingest
  and deletes on `drop_session`. The start_signing tokio task
  also persists immediately after producing the local Round1.
- `crates/seal-node/tests/bridge_ringtail_persistence.rs` — proves
  a restored session can ingest a peer's Round1 and produce a
  matching aggregate.

### P8 mainnet gates (no longer deferred)

- **Per-method-group rate limits** — `rpc::RateLimiter` now keys
  buckets on `(IpAddr, RpcGroup)`. Groups: `Expensive` (SQL
  writes, bridge withdraws, governance votes — default 20/min),
  `Admin` (the six bridge-bootstrap RPCs — default 5/min), and
  `Default` (everything else — 120/min). Configurable via
  `RpcConfig::{rpm_default, rpm_expensive, rpm_admin}`.
- **Bridge withdrawal fee** — `--bridge-withdrawal-fee <u64>`
  CLI flag. Burned from caller's native SEAL balance on every
  successful `seal_bridgeWithdraw`; refunded if the wrapped burn
  fails (e.g. InsufficientWrapped). New
  `seal_getBridgeWithdrawalFee` read RPC + `bridge.
  withdrawal_fee_base_units` field on `/status` for wallet
  quote-before-submit UX.
- **Admin M-of-N multisig** — `--admin-threshold <n>` CLI flag.
  When ≥ 2, every admin-gated RPC additionally requires
  `admin_signatures: [{sender, signature}, …]` in params with at
  least `threshold` distinct valid signatures from admin-set
  members. Cosigner dedup is keyed on derived address so a
  single stolen key can't replay-forge an M-of-N. Default 0
  preserves the legacy single-sig path.
- **KMS key-source trait** — new `seal_bridge::keysource` module
  with `CommitteeKeySource` / `RingtailKeySource` traits + a
  `FileKeySource` default. `--bridge-kms-config <path>` JSON
  config loads keys via the trait. Mainnet HSM / cloud-KMS
  adapters slot in via the same traits — no call-site changes.

### seal-cli — M-of-N operator UX (UX papercuts)

- `seal admin-sign --method --params --key` produces one
  `{sender, signature}` cosigner entry. Canonicalization (strip
  `admin_signatures` before signing) mirrors `verify_admin_multisig`
  exactly — a unit test pins the contract.
- `seal admin-submit --method --params --primary --cosigners
  a.json,b.json --node` assembles + POSTs the full RPC envelope.
  Closes the operator workflow end-to-end in two commands.

### Operator-side automation

- `scripts/bridge-deploy-devnet.sh` — one-shot `anchor deploy
  --provider.cluster devnet` + `stellar contract deploy
  --network testnet` + `seal_addBridgeObserver` for both
  chains. Captures program-id + contract-id to
  `bridges/.deploy-devnet.env`.
- `scripts/bridge-redeploy-ringtail.sh` — thin wrapper around
  the above with `--features ringtail-verify` injected.
- `scripts/bridge-fund-relayer.sh` — per-validator destination-
  chain key funder; reads a JSON manifest and drives
  `bridge-faucet.sh sol/xlm` per entry.
  `bridges/.relayer-keys.example.json` is the manifest template.
- `docs/RINGTAIL-TESTNET.md` — 6-step operator playbook from
  keygen → devnet deploy → Ringtail flip → seal-node restart →
  relayer funding → smoke + rollback path.

## Unreleased — 2026-05-16 bridge Ringtail multi-validator scaffolding (P1#5)

### Bridge — Ringtail singleton + bridge-side wrappers (layers 1–3)

- New `apps/seal-bridge` ringtail module behind a `ringtail-singleton`
  feature: `sign_singleton(params, sk, message) -> Vec<u8>` produces
  the canonical 2088-byte wire form (z 2048 || challenge 32 ||
  partcnt LE-u64 8) the on-chain `ringtail-verify` feature in
  bridges/{solana,stellar} accepts. Cross-check tests round-trip
  through the no_std `seal-ringtail-verify::verify`.
- `compute_committee_ringtail_sig(chain, params, sk, dest, amount,
  nonce)` mirrors `compute_committee_mac`'s shape so the on-chain
  verifier accepts both styles byte-for-byte once the operator flips
  the `ringtail-verify` feature in the Anchor / Soroban builds.
- `aggregate_committee_ringtail_sig(chain, round1_msgs, round2_msgs,
  …)` is the multi-validator aggregate primitive — folds collected
  partials into the canonical wire form. Re-exports
  `Round1MessageFull` and `Round2Message` from `seal-threshold`.
- `BridgeManager::set_committee_ringtail_keypair` /
  `has_ringtail_keypair`. When set, every new withdrawal's
  `committee_signature_hex` carries a 2088-byte hex-encoded singleton
  signature instead of the 32-byte HMAC. Sign-failure surfaces as
  `None` (no silent HMAC fallback that would mismatch on-chain).
- New `RingtailKeypair { public_params, sk_collapsed_bytes }` plus
  `RingtailKeypair::generate()` for testnet bring-up.

### Bridge — multi-validator P2P signing scaffold (layer 4 host-side)

- New gossipsub topic strings in `seal-p2p::topics`:
  `seal/bridge-ringtail-{round1,round2,sigs}/1.0`. Added to
  `all_validator_topics()` so validators auto-subscribe.
- New `BridgeRingtailRound{1,2,Aggregate}Envelope` structs in
  `seal-bridge::ringtail` — serde-serializable wire envelopes that
  carry `withdrawal_id` + `dest_chain` for routing plus the inner
  threshold-crate payload.
- New `seal-bridge::ringtail_session::RingtailBridgeSession` —
  per-withdrawal state machine that ingests Round1 + Round2 messages
  and advances Pending → Round1Complete → Round2Complete. Dedups by
  `party_id`; buffers Round2s that arrive before Round1 finishes.
- New `seal-bridge::ringtail_orchestrator::RingtailBridgeOrchestrator`
  — owns per-validator signing state across all in-flight bridge
  withdrawals: per-withdrawal `RingtailParty` + matching
  `RingtailBridgeSession`. Driver methods (`start_signing`,
  `on_round1_envelope`, `on_round2_envelope`, `drop_session`,
  `prune_stale_sessions`) return envelopes for the integration layer
  to broadcast.
- `on_round1_envelope` verifies the per-signer MAC before ingesting,
  rejects malicious or mis-keyed peer commitments before aggregation
  is attempted.

### Pending for layer 4 — CLOSED

- seal-node integration layer — **landed in the no-excuse-bordel
  session above** (commits a86b14f3b → 1a3c948f5).
- Multi-validator e2e — **in-process Rust integration test**
  (`bridge_ringtail_dispatch.rs`) **+ docker-compose smoke**
  (`scripts/bridge-test-ringtail-multi.sh`) **landed in the
  no-excuse-bordel session above**.
- On-chain Anchor / Soroban redeploy with `ringtail-verify` —
  **scripted** as `scripts/bridge-redeploy-ringtail.sh` (operator
  drives once per testnet bring-up).

## Unreleased — 2026-05-16 bridge auto-submission relayer + container rebuild

### Bridge — auto-submission relayer (P1#3)
- New `apps/seal-relayer` crate. Per-validator custody model
  (decided 2026-05-16): every Seal validator runs its own relayer
  instance + funded destination-chain keys. Multiple relayers may
  race; the deterministic `SHA3-256(vk || withdrawal_id) %
  max_backoff_secs` back-off ensures the lowest-delay validator
  usually pays gas, races fold into the idempotent
  `was_already_executed` no-op.
- `BridgeManager::execute_withdrawal` is now idempotent — second
  call is a no-op rather than double-decrementing `total_locked`.
- New `seal_bridgeMarkExecuted` RPC + matching `seal
  bridge-mark-executed` CLI. Auth-gated; handler enforces active-
  validator-set membership via `find_by_address_hash`. Returns
  `was_already_executed` so the relayer log can show whether it
  raced. Optional `dest_chain_tx_hash` for the audit trail.
- Per-chain submission helpers (`apps/seal-relayer/src/chains.rs`):
  `submit_stellar` shells out to `stellar contract invoke ...
  unlock_xlm/unlock_usdc`; `submit_solana` shells out to `anchor
  run unlock-tokens` with JIT recipient-ATA derivation via
  `spl-token address`. Tx hash parsed from CLI output for the
  mark-executed payload.
- Per-token (mint, vault) opt-in for Solana — relayer rejects
  half-configured pairs at parse time. Each chain opts in
  independently; an operator can run a Stellar-only relayer,
  Solana-only, or both. `--dry-run` mode logs intended submissions
  without touching either side.
- `apps/seal-relayer/seal-relayer.service` — systemd unit with
  hardening (NoNewPrivileges, ProtectSystem=strict,
  RestrictAddressFamilies, MemoryDenyWriteExecute) +
  `relayer.env.example` for operator-specific config.
- Operator docs added: TESTNET.md "Bridge unlock relayer" section
  with the funding step (`bridge-faucet.sh sol/xlm`), GUIDE-
  OPERATOR.md condensed bring-up, `apps/seal-relayer/README.md` for
  the full reference. Estimated funding: ~5 SOL devnet + ~100 XLM
  testnet per validator covers a few hundred unlocks.
- `scripts/relayer-smoke.sh` — non-destructive dry-run smoke against
  the local docker stack; asserts the polling + filtering + back-off
  path is wired and sees committee-signed withdrawals.

### Bridge — container rebuild + healthcheck repair (P0)
- `scripts/rebuild-containers.sh` wraps both stacks (5-validator
  monitoring stack at repo root + bridge-e2e under `bridges/`) with
  a `main|bridge|both` selector and `--no-cache` / `--wipe` /
  `--logs` flags.
- The cold rebuild surfaced two stale-config bugs that are now
  repaired in `docker-compose.yml`: (1) the old healthcheck
  (`test -f /tmp/seal-healthy`) never passed because nothing in
  seal-node writes that file — replaced with `seal health` exit-
  code semantics + 30 s `start_period` grace; (2) validators 2-5
  didn't expose internal JSON-RPC, so any RPC-based healthcheck
  failed on them — added `--rpc-port 8545` (without
  `--rpc-external`) so the in-container probe works without
  changing the external port surface. Added matching healthcheck
  blocks to node4 + node5 (previously had none).
- `.dockerignore` trim: `fuzz/target/` (4.2 GB), `testnet-data/`
  (782 MB), `seal-data/` (210 MB), `apps/seal-wallet-android/
  android/` (241 MB) now excluded — build context per service
  drops from ~6 GB → ~50 MB.

### Bridge — testnet operator polish (P6 + P9)
- `scripts/bridge-faucet.sh` — one-shot wrapper for the four
  faucet flows: `sol` (Solana devnet airdrop), `xlm` (Stellar
  friendbot), `usdc-xlm` (friendbot + USDC trustline),
  `usdc-sol` (Circle developer-console pointer + ATA snippet).
- `scripts/spl-usdc-bootstrap.sh` — self-serve local USDC mint
  on the local solana-test-validator (6 decimals, mint-authority
  owned by operator). Persists the mint keypair so the pubkey
  stays stable across `docker compose down -v` cycles. Prints
  `SOL_MINT` / `SOL_SENDER_ATA` / `SOL_VAULT_ATA` env exports.
- `scripts/bridge-testnet-demo.sh` `reverse-sol` / `reverse-xlm`
  modes — wraps the burn → committee-sign → on-chain unlock path
  now that `seal_getBridgeWithdrawal` exposes
  `committee_signature_hex`. Same `BRIDGE_TESTNET_DEMO_LIVE=1`
  safety latch as the forward modes.
- `docs/TESTNET-FAUCETS.md` and `docs/BRIDGE-TESTNET.md` §4
  refreshed: leading wrapper section, two-path Solana USDC docs
  (Circle vs local), stale "reverse direction not exposed"
  banner gone.

## Unreleased — 2026-05-15 testnet reverse bridge + USDC

### Bridge — operator polish
- `seal bridge-key-status` CLI: pretty-prints the
  `seal_bridgeGetCommitteeKeyStatus` response. Optional
  `--expect-sha2 <64-hex>` turns it into a scriptable drift check
  — exit 0 on match, 1 if no key installed, 2 on mismatch.
- Prometheus alert rules (`monitoring/alert.rules.yml`) auto-loaded
  into the seal-prometheus container:
  `BridgeCommitteeKeyUnset` (critical, 5m),
  `BridgeChainPaused` (warning, 2m),
  `BridgeDepositsBacklog` (warning, 5m, >20 pending),
  `BridgeCommitteeKeyFingerprintDrift` (critical, 1m).
- Grafana dashboard grows a bridge row matching the new gauges.

### Bridge — Prometheus metrics
- `/metrics` now exports six bridge gauges so testnet operators
  can alert on key state and queue depth without polling JSON-RPC:
  `seal_bridge_committee_key_set`,
  `seal_bridge_paused_chains`,
  `seal_bridge_deposits_total`,
  `seal_bridge_deposits_pending`,
  `seal_bridge_withdrawals_total`, and a label-info
  `seal_bridge_committee_key_fingerprint{sha2_hex="…"}`. The
  fingerprint label lets dashboards diff against on-chain
  `committee_key_hash` values without ever pulling the raw key.
- Per-wrapped-token locked/minted gauges
  (`seal_bridge_total_locked{token=…}`,
  `seal_bridge_total_minted{token=…}`) plus the pre-baked
  `seal_bridge_invariant_violated` 0/1 gauge so dashboards turn
  red the moment `total_minted > total_locked` on any token.
  Two new alerts back this: `BridgeInvariantViolated` (critical,
  1m) and the per-asset `BridgeTokenSupplyMismatch` (critical, 30s).
- New `BridgeManager` len-based helpers (`deposit_count`,
  `pending_deposit_count`, `withdrawal_count`,
  `paused_chain_count`) avoid the sort/clone cost of `list_*`
  on every scrape.

### Testnet bring-up — docker-compose includes registration portal
- `docker-compose up` now starts a `registration` service on
  :8547 alongside the 5 validators. POST /register collects
  validator pubkey + VRF + contact; data persists in a docker
  volume so `docker compose restart` doesn't lose the roster.
- The shared `Dockerfile` now builds `seal-registration` and
  `seal-faucet` alongside `seal-node` + `seal-cli`. Faucet is
  built-but-not-started in the default compose since it needs a
  funded key the compose can't bootstrap on first boot — operators
  start it out-of-band via `docker run seal-faucet --key ...`.

### Testnet ops — bridge-e2e rotation smoke
- `scripts/bridge-e2e.sh` `full` mode now invokes a new
  `verify_committee_key_rotation` after the loaded-fingerprint
  check. It seats a 3-member council on node1, rotates to a known
  test key via `seal_bridgeRotateCommitteeKey`, asserts the
  SHA-256 fingerprint matches the offline-computed value through
  both the rotate response and the read RPC, then rotates back to
  the fixture key. Catches regressions in the council-gating +
  rotate + persistence path before they break downstream reverse-
  leg tests.

### Testnet ops — Stellar observer hardening
- `extract_oldest_ledger` accepts three wire formats now so a
  stellar-rpc upgrade across the 25.x line doesn't take the
  observer down:
  - documented object: `error.data.oldestLedger`
  - message regex: `"startLedger must be within range: N - …"`
  - string `data`: `"oldestLedger is N"` / `=N` / `: N`
- New `fetch_latest_ledger` helper is the ultimate fallback: if
  the first `startLedger=2` attempt fails AND the `oldestLedger`-
  hinted retry also fails (e.g., a fresh chain where the lower
  bound jumps between calls), call `getLatestLedger` and start at
  `max(2, latest - 17280)` — 24 h of 5-second ledgers, enough
  history for fresh observers without missing pending events.
- Closes P7#1 and P7#2 in
  docs/TODOS/BRIDGE-TESTNET-READINESS-2026-05.md.

### Testnet ops — per-observer poll interval
- `seal_addBridgeObserver` now accepts an optional
  `poll_interval_secs` param. The in-process auto-poll loop
  (`--bridge-poll-interval-secs`) honors it via the new
  `BridgeObserverSet::poll_due(now)` path — Solana can run at 5 s
  while Stellar runs at 30 s so a slow Soroban RPC doesn't drag
  the fast chain's observation cadence.
- `seal_listBridgeObservers` returns the per-chain intervals so
  operators confirm their value landed.
- The explicit `seal_pollBridges` RPC keeps the unconditional
  "poll every observer right now" contract — `bridge-e2e.sh` and
  operator debugging still get known-point observation.
- Closes P7#3 in docs/TODOS/BRIDGE-TESTNET-READINESS-2026-05.md.

### Testnet ops — in-process bridge auto-poll
- New `seal-node --bridge-poll-interval-secs <n>` spawns a tokio
  task that runs the same `poll_bridges_once` path
  `seal_pollBridges` exposes — every N seconds. Closes P7#4 in
  the bridge-testnet-readiness doc: operators no longer need
  cron-hitting-RPC to drive deposit observation. Default 0 (off);
  `MissedTickBehavior::Skip` so a slow source-chain RPC can't
  build up backlog. `bridges/docker-compose.testnet.yml` enables
  it with a 10 s interval. The explicit `seal_pollBridges` RPC
  stays available for known-point observation in `bridge-e2e.sh`.

### Testnet ops — --expect-committee-key-sha2 startup assertion
- `seal-node --expect-committee-key-sha2 <64-hex>` is an opt-in
  pre-flight check: the loaded committee MAC key (from CLI flag or
  persisted file) is SHA-256'd and compared to the supplied
  fingerprint. Mismatch surfaces in the existing pre-flight
  warnings block — operators bake the last-known on-chain hash
  into the systemd unit and catch key-file-vs-chain drift in 5 s
  instead of after a withdrawal fails on-chain. Round-trips
  through BridgeManager so the byte-for-byte value matches what
  /metrics + the RPC report.

### Testnet operator visibility — startup pre-flight warnings
- `seal-node` now prints a `=== Pre-flight warnings (N) ===`
  block before the main banner whenever the config has a known
  footgun. Four checks today:
  - No `--bridge-committee-key` AND no persisted key on disk →
    withdrawals will land unsignable.
  - `--rpc-external` set but `--admin-address` is empty →
    bridge bootstrap RPCs reachable by any caller on every
    interface.
  - No `--validator-key` while RPC is enabled → fresh ML-DSA
    identity per boot, on-chain pubkey will flip-flop.
  - `--mainnet` with no bootstrap peers → mDNS-only LAN
    discovery, won't reach the public network.
- All non-fatal — the node still starts. Failure mode addressed:
  these silently bite in production after copy-pasting a systemd
  unit and never noticing the gap.

### Testnet operator ergonomics — bootstrap peers from file
- New `seal-node --bootstrap-peers-file <path>` flag reads a
  newline-delimited list of multiaddrs and appends them to the
  bootstrap-peer set. `#` comments and blank lines are skipped;
  malformed lines log a warning but don't fail startup. Easier to
  swap a public testnet seed list than re-passing N
  `--bootstrap-peers` flags.

### Testnet operator visibility — `seal health` + `seal status` CLI
- New `seal health [--node <url>] [--require-validator]`
  subcommand pretty-prints `/health` for one-shot operator checks.
  Drop-in for systemd healthcheck / cron:
  - exit 0 — node is `ok` and (when `--require-validator`)
    seated in the active set
  - exit 1 — `starting` (uptime <30 s) or `stalled` or RPC error
  - exit 2 — `--require-validator` but `is_validator: false`
- New `seal status [--node <url>]` dumps the full `/status`
  envelope (chain identity, metrics breakdown, bridge object).
  No exit-code semantics; for liveness use `seal health` instead.

### Testnet operator visibility — honest /health
- `/health` no longer hardcodes `status: ok`. Three signals:
  - `status: "starting"|"stalled"|"ok"` based on uptime + height
    growth (stalled = >60 s up with peers but still at height 0).
  - `is_validator: bool` — pubkey is seated in the active set.
  - `validator_pubkey_hex` + `validator_address` so operators
    `curl`ing the health endpoint can confirm the node loaded
    their `--validator-key` (or surfaced its ephemeral identity).
- `blocks_produced` (cumulative) + `blocks_pending` (received-not-
  yet-applied queue depth — sustained non-zero = applier lagging)
  complete the "am I voting?" check without a separate `/metrics`
  scrape.

### Testnet validator onboarding — idempotent register-validator
- `seal register-validator` now pre-checks the portal's
  `GET /registration/:pubkey` first and skips the
  POST + ML-DSA sign step if the pubkey is already in the roster.
  Operators re-running their systemd `ExecStartPre` hit this path
  on every reboot; the slow sign step no longer fires for no
  reason. `--force` re-submits anyway for the rare case where the
  portal's JSONL store got corrupted.

### Testnet validator-registration portal — `seal check-registration` CLI
- New `seal check-registration --portal <url> (--key key.json |
  --pubkey-hex <hex>)` subcommand wraps the new lookup endpoint.
  Operators verify their registration without curl/jq plumbing.
  Exit codes match the surface around it (`seal health`):
  0 found, 1 not-in-roster, 2 portal error.

### Testnet validator-registration portal — per-pubkey lookup
- New `GET /registration/:pubkey_hex` endpoint returns the public
  record on hit (200) or `{"error":"not found"}` on miss (404).
  Operators confirm their POST /register made it into the roster
  without parsing the full `/registrations` list. Pubkey is
  matched case-insensitively.
- Two new `/metrics` counters back it: `seal_registration_lookup_hits`
  and `seal_registration_lookup_misses`. A high miss-rate hints at
  operators paste-failing the hex (typically dropping a leading 0).

### Testnet validator-registration portal — bounded memory + /metrics
- `apps/seal-registration` now applies the same prune-on-read sweep
  to its per-IP cooldown map, so the portal's memory stays bounded
  by active submitters in the past `--interval-secs` window
  (default 60 s).
- New `/metrics` endpoint mirrors the faucet pattern: seven counters
  (`seal_registration_{attempts,accepted,duplicates,cooldown_rejections_ip,bad_request_rejections,signature_failures,persist_failures}`)
  + three gauges (`seal_registration_validators_total`,
  `seal_registration_active_ip_entries`,
  `seal_registration_uptime_seconds`). Operators can now alert on
  signature-failure spikes (key-rotation drift) or persist failures
  (disk full / permission) without log scraping.

### Testnet faucet — bounded memory + /metrics
- `apps/seal-faucet` now prunes expired cooldown entries
  opportunistically on every check, so the rate-limit maps stay
  bounded by *active requesters in the past `interval`* rather than
  growing forever. Closes the open follow-up in TODOS.md item 9
  ("cooldown maps grow unbounded — a per-minute LRU sweep would
  cap memory").
- New `/metrics` endpoint exposes counters
  (`seal_faucet_drips_{attempted,successful}`,
  `seal_faucet_cooldown_rejections_{addr,ip}`,
  `seal_faucet_bad_address_rejections`,
  `seal_faucet_upstream_failures`) and gauges
  (`seal_faucet_active_{addr,ip}_entries`,
  `seal_faucet_uptime_seconds`) so testnet operators can alert on
  drained faucet keypairs, observer-failure ratios, or unexpected
  cooldown-rejection spikes.

### Bridge — explorer surface + /status JSON
- `apps/seal-explorer-web` grows a Bridge section showing per-token
  locked/minted/invariant, committee-key fingerprint (truncated for
  display), paused-chain count. Header badge turns red when the
  committee key is unset, any chain is paused, or the invariant
  has broken — browser-only equivalent of the Grafana bridge row
  for users without the prometheus stack.
- `/status` JSON gains a `bridge` object mirroring the `/metrics`
  bridge gauges, so health-check tooling that prefers structured
  JSON over scrape parsing can read the same data without an extra
  RPC round-trip.

### Bridge — persistence observability
- New `seal_bridge_committee_key_persisted` gauge on `/metrics`
  (0/1: does `<data_dir>/bridge-committee-key.hex` exist and match
  the in-memory key?). Pairs with the new
  `BridgeCommitteeKeyRotationNotPersisted` alert (warning, 2m)
  that fires when the key is set in memory but the on-disk file
  is missing or stale — the next restart would silently revert
  the rotation.
- `BridgeManager::committee_key_eq` for constant-time host-side
  comparison of a candidate key against the stored one. Uses the
  `subtle` crate so even a side-channel-aware attacker scraping
  `/metrics` aggressively can't extract the key by timing the
  persistence-check branch.

### Bridge — committee-key rotation persists across restart
- Rotated keys now survive node reboot. The
  `seal_bridgeRotateCommitteeKey` handler writes the new 32-byte
  key atomically to `<data_dir>/bridge-committee-key.hex` (tmp +
  rename so a crash mid-write can't truncate the file). At startup,
  `seal-node` preferentially loads that file and only falls back to
  the `--bridge-committee-key` CLI flag when it's absent.
  Previously a rotation was in-memory only; on restart the CLI flag
  (or its docker-compose value) silently reverted the rotation and
  subsequent withdrawals were unclaimable.
- Rotate-handler response gains `persisted` (bool) + optional
  `persist_error` (string) so coordinators can detect write
  failures (permission, disk full) without scraping logs. The
  in-memory rotation still succeeds even if persistence fails —
  the operator is just on the hook to re-apply after restart.

### Bridge — committee-key rotation without restart
- **`BridgeManager::committee_key_fingerprint{,_sha256}()`** —
  SHA3-256 (PQ-native default) and SHA-256 (cross-chain diff: matches
  what Solana's `sol_sha256` and Stellar's `env.crypto().sha256()`
  return on the same input) fingerprints over the installed 32-byte
  committee MAC key, or `None` when unset. Closes the operator-
  visibility gap: previously the key was set-once via
  `--bridge-committee-key` and nothing on the JSON-RPC surface
  reported its state.
- **`seal_bridgeRotateCommitteeKey`** — council-gated (2/3
  Technical Council, admin-auth) RPC that installs a new key at
  runtime. Operators no longer need a `seal-node` restart to follow
  the matching `rotate_committee_key` ix on each chain's bridge
  program. Returns both fingerprints of the new key so the
  coordinator can cross-check the chain-side rotation by SHA-256.
- **`seal_bridgeGetCommitteeKeyStatus`** — no-auth read returning
  `{set, fingerprint_sha3_hex, fingerprint_sha2_hex}`. Dashboards
  diff `fingerprint_sha2_hex` against the value passed to each
  chain's bridge program's `rotate_committee_key` to catch drift
  before the next withdrawal stalls.
- `docs/BRIDGE-TESTNET.md` §5 updated with both calls.

### Bridge — reverse direction primitives
- **Committee MAC computation on the host**. `BridgeManager::initiate_withdrawal`
  now assigns a monotonic `nonce` per burn and computes the
  HMAC-SHA-256 committee signature inline when `--bridge-committee-key`
  is set on seal-node. The host-side bytes are byte-exact what the
  on-chain `verify_committee_sig` / `verify_proof` recomputes — Solana
  uses `recipient(32) ‖ amount_le(8) ‖ nonce_le(8) ‖ "seal-bridge-solana-v1"`
  and Stellar uses `XDR(ScVal::Address) ‖ amount_be_16 ‖ nonce_be_8 ‖
  "seal-bridge-stellar-v1"`. New `compute_committee_mac()` covers both
  branches.
- **Stellar StrKey + XDR address serialization**. Implemented
  `stellar_strkey_decode` (G… / C… → 32-byte payload, CRC16-XMODEM
  verified) and `stellar_address_to_xdr` (rebuilds the
  `SCV_ADDRESS ‖ ScAddressType ‖ PublicKey discriminant ‖ payload`
  bytes Soroban's `Address::to_xdr` produces) so the host can hash
  bytes that the contract's verify_proof accepts.
- **`seal_listBridgeWithdrawals` / `seal_getBridgeWithdrawal`** RPCs
  expose the per-withdrawal record including the committee signature
  hex so operators can submit it to the destination-chain unlock ix.
  Old `wd_{address}_{amount}` id was collision-prone — replaced with
  monotonic-counter `wd_{chain}_{n}`.
- **`seal-cli bridge-withdraw` / `bridge-list-withdrawals` /
  `bridge-get-withdrawal`**: typed CLI subcommands so operators don't
  have to drop into `seal rpc --method --params` for every call.
- **`seal-cli register-validator`**: closes the prior hand-build curl
  recipe in TESTNET-REGISTRATION.md — one-shot post that builds the
  canonical bytes, signs, and POSTs to the portal.
- **`anchor run lock-sol`**: parametric devnet lock-tokens driver
  (TS, takes `--amount / --seal-recipient / --mint / --sender-ata
  / --vault-ata`).
- **`bridge-e2e.sh reverse`** mode: structural scaffold for the
  burn → fetch sig → unlock flow. Uses a real on-Seal recipient key
  (`bridges/.seal-e2e-key.json`, generated/reused across runs) so the
  reverse leg can actually sign as the wrapped-balance holder.
- **Stellar reverse leg closes end-to-end** against the containerized
  stack: burning 0.5 wXLM emits `wd_xlm_0` with a 32-byte committee
  MAC; submitting that MAC to `unlock_xlm` on Stellar transfers
  5,000,000 stroops to the recipient on-chain and the contract's
  `verify_proof` accepts. Validates that the host's XDR address
  serialization, amount-as-i128-big-endian, and nonce encoding match
  what Soroban recomputes inside `verify_committee_sig`.
- **bech32m accepted everywhere a bridge view takes an address**.
  Five RPCs (`seal_getBridgeWrappedBalance`,
  `seal_listBridgeWrappedBalances`,
  `seal_listBridgeDepositsByRecipient`,
  `seal_listBridgeWithdrawalsByInitiator`, and the burn side of
  `seal_bridgeWithdraw`) now normalize bech32m input through
  `SealAddress::from_string_encoding(...).as_bytes()` → hex before
  hitting `BridgeManager` state. Until this fix, a wallet querying
  its own `sealt1…` address got `count: 0` even with credited
  deposits, and `seal_bridgeWithdraw` rejected with
  `InsufficientWrapped { have: 0 }` despite the per-token view
  showing the balance.
- **Solana USDC routing**. `LockEvent` carries a `mint: Pubkey` field
  populated from `vault_token_account.mint`. The observer compares it
  against an operator-configured `usdc_mint` (passed through
  `seal_addBridgeObserver`) and routes to `WUSDC` on match, `WSOL`
  otherwise. Closes the prior inline TODO so USDC locks on Solana no
  longer get tagged as wrapped SOL.
- **Solana observer is layout-backward-compatible**. Accepts both v1
  (96-byte) and v2 (128-byte) `LockEvent` payloads. v1 events route to
  WSOL only (no mint to disambiguate); v2 routes by mint. Operators
  who haven't redeployed the Anchor program still see locks observed.
- **`bridge-e2e.sh reverse-solana`** mirrors the validated Stellar
  reverse mode for the Solana side. Same shape:
  `bridge-withdraw → bridge-get-withdrawal → anchor run unlock-tokens`.
  Needs four operator-supplied env vars (`SOL_REVERSE_MINT`,
  `SOL_REVERSE_RECIPIENT`, `SOL_REVERSE_RECIPIENT_ATA`,
  `SOL_REVERSE_AUTHORITY`) since the forward leg's Anchor test
  doesn't pin them; the script fails loud rather than guessing.
- **`anchor run derive-vault-ata`** TS helper computes the
  `bridge_state` PDA + its associated ATA for a given SPL mint, and
  with `--init` funds + creates the ATA. Required before the first
  lock against any new mint (canonical devnet USDC included).

### Bridge — Stellar observer client-side filter + pagination drain
- **Pagination semantics fix**. `pagination.limit` in stellar-rpc
  25.x caps the number of LEDGERS scanned per call, not events
  returned. With ~13K ledgers between genesis and the lock event,
  the original 100-event-per-poll loop never reached it. First pass
  raised limit to 10 000 and looped "drain until events < limit",
  but that broke too early on sparse-event pages. Final fix uses
  `result.cursor` (server-reported pagination state) within the
  drain loop and `result.latestLedger` as the "caught up" signal —
  tracks per-event id separately for across-poll resumption.
  `cursor_ledger()` parses the cursor's `ledger << 32 | …` encoding;
  pinned against real wire bytes captured from local stellar/quickstart.
- **Dropped server-side `contractIds` filter on Stellar `getEvents`**.
  stellar-rpc 25.x silently returns 0 events when filtering by a
  contractId that was deployed after the RPC's first-seen retention
  window — verified today by an unfiltered query returning a lock
  event at ledger 12164 from `CABCJHL7…` while the same filtered
  query returned 0. Observer now polls without the filter and
  branches client-side via the existing `event.contractId ==
  self.contract_id` check in `deposit_from_event`. Restores the
  bridge-e2e Stellar leg's "Stellar deposit visible on Seal" pass.
- **`anchor run unlock-tokens`** parametric driver for the Solana
  reverse claim. Feeds the `(amount, nonce, committee_signature_hex)`
  tuple from `seal bridge-get-withdrawal` into the on-chain
  `unlock_tokens` ix — pairs with the matching Stellar
  `unlock_xlm / unlock_usdc` ix on the other side.

### Bridge — committee-of-1 auto-confirm + auto-process
- **`seal_pollBridges` now auto-credits the wrapped balance**. Before,
  observation just recorded the deposit at `confirmations=0`; with
  `required_confirmations=1` (testnet default) nothing ever advanced
  to `process_deposit`, so the wrapped balance stayed at 0 even after
  the e2e reported "Stellar deposit visible on Seal". Now every
  observed deposit auto-advances via `confirm_deposit` + `process_deposit`
  in the same poll call. Multi-validator testnet will swap this for a
  separate confirmation RPC that quorum drives; for now it closes the
  gap that prevented `bridge-withdraw` from finding a wrapped balance
  to burn.

### Bridge — USDC on Stellar
- **`lock_usdc` / `unlock_usdc` / `set_usdc_sac`** Soroban ix shipped
  in `bridges/stellar/src/lib.rs`. Mirror lock_xlm/unlock_xlm but
  operate on a separate `usdc_sac` storage slot (XLM accounting is
  undisturbed). Shared `nonce` counter keeps withdrawal ids globally
  unique across both assets.
- **StellarObserver** now branches on the `Symbol("lockusdc")` topic
  and tags those deposits as `WrappedToken::WUSDC`.

### Infrastructure
- **`seal-node --bridge-committee-key <64-hex>`**: configures the
  32-byte MAC key. Must match what the on-chain `initialize` ix
  was called with. HRP and length mismatches refuse at startup
  with clear exit-2 errors.
- **`docker/entrypoint.sh`**: also bundles `seal-cli` in the image.
  When `SEAL_VALIDATOR_KEY` env var is set and the file doesn't
  exist, runs `seal keygen` on first boot. `bridges/docker-compose.
  testnet.yml` + root `docker-compose.yml` set the env var on all
  seal nodes so identity persists across container restarts (key
  lives in the data volume).
- **`.dockerignore`**: stops shipping target/ + node_modules/ into
  the build context. Cuts `docker compose --build` context transfer
  from 3+ GB to ~250 MB.
- **`bridge-e2e.sh stack_up`** now splits `build` and `up` calls so
  `up --build --wait` doesn't hang post-build on stale containers.

## Unreleased — 2026-05-14 testnet doc/code accuracy sweep

### Bridge (Stellar) — observable correctness
- **StellarObserver XDR parser**: `parse_lock_info_xdr` was missing
  the `Option<ScMap>` Some-marker that wraps an `ScVal::Map` in real
  Soroban XDR. The unit-test helper had the same bug, so tests
  passed while every real Stellar lock event silently parsed as
  `(amount=0, seal_address="", sender="")` and bridge-e2e.sh
  reported "Stellar deposit visible on Seal" with empty fields.
  Fix reads the marker after the SCV_MAP discriminant + pins a
  real stellar-rpc 25.x wire-byte sample in
  `stellar_parse_lock_info_xdr_real_wire_bytes`.
- **`extract_oldest_ledger`**: stellar-rpc 25.x doesn't populate
  `error.data.oldestLedger` — the live range is only in the error
  message text. The retry never fired before, so `seal_pollBridges`
  returned `null` and the Stellar leg of `bridge-e2e.sh` timed out
  at 60s. Now parses the lower bound from the message text + keeps
  the documented `data.oldestLedger` shape as a fallback.
- **`seal_getBridgeDeposits` chain filter**: the handler read
  `params.get(0)` (positional array) while every doc + sibling used
  `{chain:"..."}`. Named form was silently ignored. Accepts both
  forms now; legacy `bridge-e2e.sh '["Solana"]'` still works.

### Validator identity persistence
- **`seal-node --validator-key <path>`** (closes the prior TESTNET.md
  "Identity persistence (known gap)"). Loads a `seal keygen` JSON
  keyfile and uses it as the on-chain ML-DSA identity, so restarts
  keep the same address + deterministically-derived VRF state.
  Without the flag the node still generates a fresh keypair each
  start. HRP cross-check refuses a `testnet` keyfile under
  `--mainnet` (and vice versa).
- New `ConsensusRunner::new_with_keypair` and
  `NetworkNode::start_with_keypair` constructors; existing `::new`
  shims call into them with a fresh `SigningKey::generate()`.
- 4 new unit tests cover the loader's happy path + three error
  shapes (missing file / missing field / HRP mismatch).

### Hygiene
- **Dead RPC methods removed**: `seal_setVisibility`,
  `seal_enableRls`, `seal_addPolicy` were listed in `requires_auth`
  but had no dispatch arm — callers passed auth then fell through
  to `-32601 method not found`. Removed from the auth table; the
  canonical path is SQL DDL (`ALTER TABLE … ENABLE ROW LEVEL
  SECURITY`, `CREATE POLICY …`) via `seal_submitSql`. GUIDE-DEVELOPER.md
  + TESTING.md updated.
- **`fuzz_ringtail_sign`** was in `fuzz/fuzz_targets/` but not in
  any of `fuzz-all.sh`, `fuzz-extended.sh`, `ci.sh`, `ci-nightly.sh`.
  Added across all four scripts; CLAUDE.md count bumped 9 → 10.
- **Root `docker-compose.yml`** configured 5 validators entirely
  via `SEAL_*` env vars that seal-node doesn't read, so
  `docker compose up` started 5 unconnected nodes. Rewrote with
  explicit `command:` blocks following bridges/docker-compose.testnet.yml.

### Docs — testnet-readiness drift sweep
Verified every curl / CLI / `cargo run` example against a live
running bridge testnet and rebuilt where they didn't match:
- `MANUAL-TESTING.md` (rewrote §15.1, §15.1.1, §17.1, §19.0, §19.3,
  §19.45, §25, §13.1; added §6.4 / §12.3 / §16.3 / §17.1-per-owner
  / §19.45-reads documenting 15+ previously undocumented RPCs).
- `docs/BRIDGE-TESTNET.md` (substantial rewrite — fictional
  `anchor run lock-sol` removed, wrong `xlm_token` arg corrected
  to `seal_bridge_key`+`xlm_sac`, status preamble enumerates what
  works vs what gates on the missing Ringtail-pickup RPC).
- `docs/TESTNET-REGISTRATION.md` (rewrote the hand-build recipe to
  use the real `seal sign-file` subcommand; verified end-to-end
  against a live `seal-registration` portal).
- `docs/TESTNET-FAUCETS.md` (faucet drip is 10⁹ base units, not
  10⁶ "µSEAL"; dropped dead `scripts/spl-usdc-bootstrap.sh` ref).
- `docs/STATE-SYNC.md` (snapshot RPC schemas were wrong — chunk
  arg is `chunk_index` not `path`, manifest height is REQUIRED,
  listSnapshots envelope has 5 fields not 2).
- `docs/RELEASE.md`, `docs/NETWORK.md`, `docs/SHARDING.md`,
  `docs/DATA-ARCHITECTURE.md`, `docs/GUIDE-OPERATOR.md`,
  `docs/GUIDE-USER.md`, `docs/GUIDE-DEVELOPER.md`, `docs/DEX-DESIGN.md`,
  `docs/TESTING.md`, `TESTNET.md`, `CLAUDE.md`, `apps/seal-faucet/README.md`
  — flag drift (`--p2p-port` → `--port`, `--validator-key` /
  `--validator-index` / `--chain-id` removed), response-shape drift
  (`status:"ok"` → `:"confirmed"`, etc.), file-line drift
  (`rpc.rs:230` → `:346`, `main.rs:119-124` → `:237-247`, six more),
  and dead `bridges/README.md` pointers cleaned up.

## Unreleased — 2026-05-09 wallet UX + faucet batch

### Wallets
- **QR codes + balance readout** in both Electron
  (`apps/seal-wallet/standalone.html`) and the browser-extension
  popup (`apps/seal-wallet-extension/src/popup.{html,js,css}`).
  Show-my-address QR via a vendored 270-line `qrcode.js`
  (byte mode, L EC, auto-version v1-5, mask 0; round-trip-tested
  against jsQR for input lengths 1, 11, 45, 65, 105). 5-second
  balance auto-poll while the account screen is visible; per-token
  rows from `seal_listTokens` + `seal_getTokenBalance`. Lock and
  screen change tear down the poll. (Tier-2 #5 closed.)
- **Browser-extension idle auto-lock** (Tier-2 #8 partial):
  5-minute popup-side timer that calls `lock()` and routes back
  to screen-unlock. Capture-phase click / keydown / focus reset
  the timer. Wired into createWallet, importMnemonic, unlock,
  change-passphrase. WASM-handle piece for SK bytes still pending.

### DEX trade tape — UI cascade
- **Web explorer "Markets" section**
  (`apps/seal-explorer-web/`): pair `<select>` populated from
  `seal_listPairs`, table polling `seal_listTrades` on the existing
  2 s refresh tick. `?pair=GOLD/SEAL` deep-link supported.
- **Browser-extension popup tape** with a pair selector + scrollable
  `<ul>` (max 30 rows), reusing the 5 s balance-poll tick rather
  than running a second timer. (Tier-2 #7 cascade closed across
  RPC + CLI + TUI + Electron + extension + explorer.)

### Testnet ops
- **`apps/seal-faucet/` HTTP service** (Tier-3 #9 closed):
  `POST /faucet {address}` forwards an ML-DSA-signed `seal_transfer`
  from a dedicated faucet keypair. Per-address + per-IP cooldowns
  (default 1 h, bumped on success only so a 502 doesn't burn the
  requester's quota). HRP cross-network paste guard refuses
  `sealt1← seal1` and vice versa before touching the cooldown map.
  CLI: `--key`, `--node`, `--port`, `--bind`, `--drip`,
  `--interval-secs`. /health endpoint for liveness probes. 3 unit
  tests + a Python-stub-node end-to-end smoke test (covers /health,
  success, cooldown, malformed, HRP cross-network). Companion doc
  `docs/TESTNET-FAUCETS.md` cross-references Stellar friendbot,
  Solana airdrop, Circle USDC sandbox, and the seal-node
  `--dev-faucet` unsigned override (refused under `--mainnet`).
  Workspace member added in root Cargo.toml. **Not** wired into
  `scripts/ci.sh` — the keypair holds real testnet balance.
- **`seal faucet --http <faucet-url>`** mode in seal-cli targets the
  HTTP service alongside the existing `--node <node-url>`
  `--dev-faucet` mode. Surfaces 429 cooldown's `retry_after_secs`
  distinctly. Required a small fix to `rpc_post` to honor URL paths
  (was hard-coding `POST /`); existing call sites unchanged.
- **`seal-faucet` drip default 1_000_000 → 1_000_000_000**
  (canonical SEAL precision is 9 decimals; the original default
  was 0.001 SEAL not 1 SEAL). Unit label corrected from "µSEAL"
  to "base units" everywhere.

### Token surface fill-in (17 commits)
- **`--min-opening-balance` dust-spam cost shift**:
  `RpcConfig::min_opening_balance: u64` — when non-zero,
  transfers to fresh recipients must include at least that many
  base units (code `-32008`). Complements the existing
  `--allow-new-recipients`: a faucet posture (allow=true +
  non-zero min) keeps the policy active. SPEC.md §5.6.1 documents
  the rule end-to-end.
- **`seal_burnToken` RPC + `seal burn-token` CLI**:
  closed the gap where `TokenManager::burn` was wired but never
  exposed at the RPC layer. Signed; caller is the from-address.
  Returns the post-burn `total_supply`.
- **`seal_freezeAccount` / `seal_unfreezeAccount` / `seal_isFrozen`**:
  signed mutations gated against `info.freeze_authority`, plus an
  unsigned read. New `TokenManager::is_frozen` accessor — the
  `frozen_accounts` map had no public reader before.
- **Token authority rotation**: `seal_setMintAuthority` /
  `seal_setFreezeAuthority` RPCs + matching CLI subcommands.
  `new_authority` validated as a Seal address before the manager
  call so a typo can't orphan the token.
- **Irrevocable authority renounce**:
  `seal_renounceMintAuthority` / `seal_renounceFreezeAuthority`
  set the field to `""` (impossible for any real bech32m Seal
  address). Every subsequent mint / freeze / rotate attempt
  rejects, including by the original creator — terminal, no
  inverse.
- **`seal_listTokens` surfaces authorities**: response now carries
  `mint_authority` + `freeze_authority` per token; explorer Tokens
  panel renders the supply + both authority columns (truncated
  bech32m, `(renounced)` for empty). Closes the gap where the
  on-chain authority state was set-only via RPC.
- **`seal_listFrozenAccounts`**: unsigned read returning every
  address currently frozen for a symbol (sorted lexicographically
  for diff-friendly polling). New `TokenManager::list_frozen` +
  `seal list-frozen --symbol <S>` CLI. Empty Vec for unknown
  tokens / no frozen accounts (no error path).
- **SPEC.md §5.8 — token authority lifecycle**: documents the
  state machine (creator → rotated → renounced), the empty-string
  sentinel, and the rotate-vs-renounce decision tree.
- **`seal_getToken`**: single-token detail RPC — supply,
  decimals, fee, both authorities, global freeze flag. Cheaper
  than scanning `seal_listTokens` for clients that already know
  the symbol.
- **`seal_frozen_accounts` /metrics gauge**: total
  `(symbol, address)` frozen-account entries across all tokens.
  New `TokenManager::total_frozen_accounts` accessor backs it.
  Lets ops alert on freeze-authority abuse.
- **`seal_setTokenFrozen` global freeze switch**: token-level
  kill switch that rejects every transfer regardless of
  per-account state (`info.frozen` was already honored by
  `transfer()` but had no setter or RPC). Idempotent.
  `seal_listTokens` / `seal_getToken` now carry the flag;
  explorer renders it red when set. Companion to per-account
  freeze: per-account for surgical, global for "stop the world."
- **Kill-switch UX cascade**: `seal token --symbol` shows the
  flag, both wallets (Electron + extension) replace the
  `10^-decimals` unit cell with red "FROZEN" + tooltip when a
  held token is globally frozen, and the TUI `tokens` listing
  gains a 6-char `FRZ` column.
- **`seal_frozen_tokens` /metrics gauge**: companion to
  `seal_frozen_accounts` — counts tokens currently in the
  global-frozen state. New `TokenManager::total_frozen_tokens()`
  accessor; per-account freezes don't move it (verified by test).
- **Fee authority rotation + renounce**: closes the asymmetry
  where `set_transfer_fee` was hard-gated to creator while
  mint/freeze authorities were rotateable + renounceable. New
  `fee_authority: String` field on TokenInfo (defaults to creator
  at `create_token` time), `seal_setFeeAuthority` /
  `seal_renounceFeeAuthority` RPCs sharing the existing
  set/renounce-authority handler paths via an `Authority::Fee`
  variant, matching `seal set-fee-authority` /
  `renounce-fee-authority` CLI subcommands. Surfaced in
  `seal_listTokens` / `seal_getToken` (null when renounced) and
  in the explorer Tokens panel. **Renouncing the fee authority
  permanently locks the fee at its current value** — so a creator
  who wants 0% transfer fees forever should set the fee to 0 and
  *then* renounce. SPEC.md §5.8 covers the full state machine
  for all three authorities; MANUAL-TESTING.md §16.2 updated.
- **`seal_setFeeRecipient`**: closes the last fee-side gap.
  `fee_recipient` was set to creator at create-token and never
  mutable, so a token couldn't route fees to a treasury after
  rotating fee_authority. New `TokenManager::set_fee_recipient`
  on the same `fee_authority` gate (so renounce locks the
  recipient too), `seal_setFeeRecipient` RPC + matching CLI.
  Field surfaced in `seal_listTokens` / `seal_getToken` /
  `seal token` detail (was completely hidden before).

### Per-owner views — RPC fan-out (10 commits)
Cross-cutting gap-closure: a wallet asking "what's mine?" had to
query each surface independently and filter client-side. Added
explicit `*ByOwner` / `*ByVoter` / `My*` RPCs across DEX, bridge,
governance, plus a single explorer "Account Lookup" panel that
parallel-fetches all of them.

- **DEX** (commits `f8556f068`, `1d5275c6d`):
  `seal_listOrdersByOwner` aggregates `OrderBook::orders_by_owner`
  across all pairs, returns `(pair, Order)` tuples sorted by
  `(pair, order_id)` so cancel via `seal_cancelOrder` knows both
  args. `seal_listTradesByOwner` filters every retained
  `Trade` (10 000-cap per pair) where the address was maker or
  taker, sorted newest-first. Wallet TUI: `orders` / `trade-history`
  commands auto-fill the active wallet's address.
- **Bridge** (commits `b8c35d454`, `7ec84c726`):
  `seal_listBridgeWrappedBalances` enumerates `WrappedToken::all_variants()`
  for an address and emits only non-zero entries. New
  `WrappedToken::all_variants()` accessor for any caller that
  wants to scan without hardcoding the variant list. CLI
  `seal wrapped-balances`; wallet TUI `wrapped`.
  `seal_listBridgeDepositsByRecipient` (post-mainnet-prep
  follow-up) covers the deposit-history side that
  `seal_listBridgeWrappedBalances` doesn't — "what crossed the
  bridge to me?" Sorted by deposit ID. CLI
  `seal my-bridge-deposits`. seal-bridge tests 60 → 61.
- **Governance** (commit `5258639f6`):
  Three new RPCs — `seal_govListProposalsByProposer` /
  `seal_govListVotesByVoter` / `seal_govListLocksByVoter` —
  answer the natural questions: "what did I propose?", "what
  did I vote on?", "when do my tokens unlock?". Locks sort
  ascending by `unlock_epoch`. CLI: `seal my-proposals` /
  `seal my-votes` / `seal my-locks`.
- **Storage leases** (commit `06a51709e`):
  `seal_listLeases` exposes the full lease table (was only
  visible as the `seal_leases_active` /metrics count). Optional
  `expired_only: true` filter for expiry-watch dashboards.
  Owner emitted as raw verifying-key hex (the lease stores the
  full ML-DSA pubkey, not the bech32m address).
- **Token creation** (commit `4fed78e8a`):
  `seal_listTokensByCreator` answers "which tokens did I
  deploy?" without iterating all of `seal_listTokens`. Creator
  is the immutable original-deployer field — does not move with
  `set_mint_authority` rotations. Same renounce-aware response
  shape as `seal_listTokens`. CLI `seal my-tokens`.
- **Private tables** (commit `a6537fd76`):
  `seal_listPrivateTablesByOwner` answers "which regulated/
  app-private tables do I own?" without iterating all of
  `seal_listPrivateTables`. Owner is set at `register()` and
  never rotates, so the view is lifetime-stable. CLI
  `seal my-private-tables`.
- **Storage leases** (commit `4e5a55f95`):
  `seal_listLeasesByOwner` answers "which tables am I paying
  lease for?" without iterating all of `seal_listLeases` and
  manually matching `owner_pubkey_hex`. The lease stores the
  raw ML-DSA verifying-key; bech32m encodes
  `SHA3-256(verifying_key)`. Handler decodes the bech32m
  address to its 32-byte hash, server hashes each lease's
  pubkey for comparison — testnet/mainnet-agnostic.
  `expired_only` filter mirrors `seal_listLeases`. CLI
  `seal my-leases [--expired-only]`.
- **Namespaces** (commit `dd3c9b720`):
  `seal_listNamespacesByOwner` answers "which namespaces have
  I deployed?" without iterating all of `seal_getNamespaces`.
  Handler filters `NamespaceEntry.owner` inline (the registry
  already lives in `RpcState` as a `Vec`). Owner is set at
  `seal_deployNamespace` time and never rotates today, so the
  view is lifetime-stable. CLI `seal my-namespaces`.
- **Explorer** (commits `90727e40e`, `b8c35d454`, `3c5c8de59`,
  `73f3d9f09`, `3fe384d96`, `dec1ccd0b`, `95bfaca57`,
  `bfcc8c948`, `727fecc7a`, `e557f6f09`):
  `?account=sealt1…`-deep-linkable Account Lookup panel runs
  sixteen RPCs in parallel and renders every per-owner sub-
  table: SEAL balance, custom-token balances (zero-balance
  filtered), open orders, recent trades (with maker/taker role
  derived), wrapped balances, proposals authored, votes cast,
  conviction locks, frozen-symbol tag list, delegations in/out,
  tokens created (with renounced-aware mint-authority
  rendering), private tables owned, storage leases (with
  expired-row red highlight), namespaces deployed (schema-hash
  short-rendered to 12 chars), bridge deposits (with
  unprocessed-row dim cue). Sixteen summary cards + fifteen
  sub-tables + one tag list.
- **CLI utilities** (commits `d0a2a76b2`, `cfa2b3fdc`):
  `seal addr-to-hex` and `seal hex-to-addr` for bridge
  program log inspection (the `lock_*` events emit Seal
  recipients as 32-byte hex; bech32m round-trip lets operators
  go either way).

### Eager dust-prune (Tier-1 #3 step 2/6 part b)
- **commit `6ed1c2274`** — `BalanceStore::put` now removes the HAMT
  entry instead of writing when both `available == 0` and
  `staked == 0`. Combined with the pre-existing
  `--min-opening-balance` (commit `c042b406b`), the dust-fanout
  attack is prevented stateless-ly: per-fresh-account cost
  barrier (min-opening) + no-accumulation (eager prune). Staked-
  only accounts preserved (still hold value). `has_account`
  semantics flipped — a drained-to-zero account now returns
  false, intentionally indistinguishable from "never existed"
  at the recipient-policy boundary. SPEC.md §5.6.1 updated.

### Bridge testnet runbook (Tier-3 #10)
- **commit `fa1c5f369`** — `docs/BRIDGE-TESTNET.md` (~320 lines) +
  `scripts/bridge-testnet-demo.sh` (~235 lines, gated behind
  `BRIDGE_TESTNET_DEMO_LIVE=1`). Solana devnet + Stellar testnet
  bring-up: deploy contracts, fund authority, wire program IDs
  into seal-node, lock→mint and burn→unlock for SOL/XLM/USDC,
  common-failure-modes table. Lock side scripted; burn→unlock
  documented narratively (committee-signing depends on the
  operator's testnet validator set).

### State-sync design (Tier-1 #3 step 6/6)
- **commit `d6267059f`** — `docs/STATE-SYNC.md` (~290 lines).
  Chunked content-addressed HAMT-leaf streaming protocol. New
  RPCs (`seal_getSnapshotManifest` / `seal_getSnapshotChunk` /
  `seal_listSnapshots`), four-step bootstrap flow (header-sync
  → social-fork-choice snapshot pick → state stream → tip
  catch-up), trust model, operator flags. Implementation is
  multi-session; doc is the contract.

### Native-balance Merkle (PLAN #8 / Tier-1 #3 morning)
- **HAMT-backed `BalanceStore`** with cache-invalidated state-root
  (commit `a69b9e11a`). Block production's `state_root_hash` is now
  O(1) instead of O(n log32 n). Closure helpers `update<F>` /
  `update_or_create<F>` replace the removed `pub(crate) get_mut`;
  transfer.rs and staking.rs migrated. HAMT extensions: `iter()`,
  `contains_key()`. Storage-rent + state-sync snapshot format
  remain pending.
- **`balance_scale` bench** (`crates/seal-token/benches/`) — 11
  microbenches at 10⁴ / 10⁵ scale: cache-hit `state_root_hash`
  (sub-microsecond), HAMT lookup, transfer hot path. Documented
  module preamble notes deferred 10⁶+ runs.

### Bridges
- **In-program pause** for Solana + Stellar bridge contracts
  (Tier-1 #4 closed): authority-gated `set_pause(paused)` + reject
  `lock_*` / `unlock_*` when paused. Defence in depth on top of
  the Seal-side per-chain pause (`seal_bridgePauseChain`,
  2/3 Technical Council).

## Unreleased — 2026-05-08 hardening batch

### Security / Mainnet prerequisites
- **`rustls-webpki 0.103.12 → 0.103.13`**: clears RUSTSEC-2026-0104
  (CRL-parsing reachable panic). Vendor refresh via
  `scripts/vendor-update.sh`. Two unrelated 2026-05-01
  hickory-proto 0.25.2 advisories surfaced
  (RUSTSEC-2026-0119/0118) — ignored with reachability
  justifications in `.cargo/audit.toml`; tracked for an
  upstream libp2p-mdns/-dns bump.
- **Admin gating on bridge-bootstrap RPCs**: `seal_addBridgeObserver`,
  `seal_bridgeCouncilAdd/Remove`, `seal_bridgePauseChain/Unpause`
  now require both a valid signature and membership in
  `RpcConfig::admin_addresses` when that set is populated. CLI flag
  `--admin-address` (repeatable) populates it; `--mainnet` without
  any `--admin-address` emits a startup warning. Open-mode (empty
  set) preserves alpha-testnet bootstrap (`bridge-e2e.sh` keeps
  working). SPEC.md §5.5.
- **Recipient-new-account policy**: `seal_transfer` /
  `seal_transferToken` reject transfers to fresh accounts (no prior
  ledger entry) by default. Per-request opt-in via
  `confirm_new_recipient: true` (strict JSON boolean); node-wide
  override `--allow-new-recipients` for bridge/faucet nodes.
  Independent of the bech32m format guard. SPEC.md §5.6.
- **Bridge `dest_address` format validator**: per-chain
  `validate_dest_address` (Solana base58 32-44 chars; Stellar
  56-char G/C-prefixed strkey). Wired into
  `BridgeManager::initiate_withdrawal` so a malformed or
  cross-chain-pasted address fails *before* the wrapped-balance
  burn. New `BridgeError::InvalidDestAddress(String)` variant.

### Demo apps
- **`examples/seal-forms/` swapped from XOR-stream + bespoke
  HMAC-SHA3 wrapper to real `Aes256Gcm`**:
  - HKDF-SHA3-256 over the ML-KEM shared secret derives the
    32-byte symmetric key (`info = b"forms.seal/v1/aes-key"`).
  - Deterministic nonce =
    `SHA3-256(form_id_le || respondent_addr || idx_le)[..12]`.
  - AAD = `form_id_le || schema_hash || respondent_addr` binds the
    ciphertext to its form context (cross-form/cross-respondent
    replay produces a tag mismatch).
  - New `pub struct AnswerContext<'a>` + `pub fn schema_hash(json)`.
  - Removed `examples/seal-forms/src/aead.rs` (the bespoke wrapper)
    and the `xor_stream` / `expand_block` helpers.

### Tooling
- **11 typed `seal-cli` mutations** — `signed_call` helper plus:
  - **Token (4)**: `create-token`, `mint-token`, `transfer-token`
    (with `--confirm-new-recipient`), `set-transfer-fee` (closes
    MANUAL-TESTING.md §16.2).
  - **DEX (2)**: `place-order`, `cancel-order`.
  - **Governance (5)**: `gov-propose`, `gov-vote`,
    `gov-withdraw-vote`, `gov-delegate`, `gov-revoke-delegation`.
- **`scripts/cuda-bringup.sh`** (RTX 6000 host, see PLAN #9): pinned
  feature flags, host snapshot, end-to-end CUDA STARK proof of
  `test_risc0_full_pipeline`, parsed metrics → `target/cuda-bringup/`.

### Observability
- **`/metrics` adds three gauges**: `seal_account_count` (dust-fanout
  signal pre-HAMT), `seal_total_supply_micro`, and
  `seal_tokens_registered`.

### Tests
- seal-node 226 / seal-bridge 60 / seal-token 94 / seal-forms 21.
  +27 net new tests across the four crates this batch (admin gating,
  recipient policy, bridge-validator unit + 7 proptest cases,
  AEAD round-trip + tampering + AAD drift + spec checks, +6
  state_root_hash determinism + sensitivity).
- Workspace `cargo test --workspace --lib` total: 985+.
- `cargo audit` exit 0; full `./scripts/ci.sh` 6/0/1 (Miri legitimately
  skipped — no unsafe code in the touched paths).

### Misc afternoon batch (post mainnet-prereq cleanup)

- **bridge-e2e Solana side fully green** (commits `9c15d6775`,
  `03f5125c3`, `0b27842e4`): vendor-config workaround,
  `~/.cargo/bin` PATH for rustup proxy, `cargo build-sbf -- --locked`
  bypass of anchor's silent build-failure path, `solana program
  deploy --use-rpc` to avoid TPU-port requirement of dockerized
  validator. Stellar deploy plumbing landed but version-skew on
  protocol/SDK/CLI remains (`9d38ff999`, documented).
- **Lean 4 sorries** — all 7 in `MerkleTree.lean` discharged
  (`58102e9fc`); `lake build` now succeeds with 0 sorries.
- **Browser-extension cross-browser polyfill** (`9fb9beec7`) —
  `browserApi` alias resolves `browser`/`chrome` at startup; same
  source on Chromium MV3, Firefox MV3, Safari Web Extensions.
- **Metal Option A partial** (`26f8b3d2e`) — un-comments the
  vendored Metal HAL build path, plumbs `metal` feature through
  `risc0-circuit-rv32im-sys` → `risc0-circuit-rv32im` →
  `risc0-zkvm`; `--features metal` build now reaches deeper
  upstream gaps documented in METAL.md (metal-cpp not vendored,
  `.metal` kernels need `xcrun -sdk macosx metal` not `cc::Build`).
- **PLAN #8 stepping-stone** (`03297bb0c`) —
  `BalanceStore::state_root_hash()` and
  `TokenManager::state_root_hash()` build a HAMT on the fly and
  return its root. Content-addressed Merkle commitment for the
  ledger without changing storage layout. Exposed in `/metrics` as
  `seal_balance_state_root{root_hex=…}` and
  `seal_token_state_root{root_hex=…}`.

---

## v0.3.0 — PQ Integration + Bridge + Batch ZK

### P2P
- **Double encryption**: ML-KEM-768 application-layer encryption on top of Noise
  transport. Protects against Harvest Now Decrypt Later (HNDL) attacks.
  Enable with `NodeConfig { pq_encryption: true, .. }`.
- Per-peer PQ key exchange via GossipSub
- Broadcast encryption with ML-KEM-derived symmetric keys

### Bridge
- **Observer framework**: `ChainObserver` trait + `SolanaObserver` + `StellarObserver`
- `BridgeObserverSet`: multi-chain event aggregation with cursor-based pagination
- Solana contract: full lock/release with multisig validation, event emission,
  SOL + SPL token support, seal1/sealt1 address validation
- Stellar contract: full lock/release with multisig, XLM + USDC + Classic assets,
  Soroban storage simulation, ledger-based finality tracking

### ZK Proofs
- **Batch proving**: `BatchTransition` + `BatchProver` — prove multiple blocks
  in a single STARK proof. Validates state root chain consistency and sequential heights.
- Improved guest program: in-memory state replay, deterministic execution,
  transaction counting, hex output

### VRF
- **Epoch key rotation**: `VrfKeyManager` — deterministic key derivation per epoch
  from master seed. Supports LB-VRF few-time limitation and forward secrecy.
  Key chain: `master_seed → SHA3(seed||epoch) → VRF keypair`

### Merkle B-tree
- **Fix**: Duplicate key after split — when inserted key equaled the promoted
  median, the key was stored both in the parent node and a child leaf.
  Now correctly updates the median in-place.
- New Kani harness: `insert_same_key_no_duplicate` validates the fix

### Formal Verification (Lean 4)
- **Proven**: `MTree.rootHash_injective` — different root hash implies different
  contents (was `sorry`, now proven via `unfold` + `Hash.collision_resistant`)
- **Proven**: `MTree.insert_lookup` — insert then lookup returns the inserted value
  (was `sorry`, now proven with local `filter_find_none` + `find_append_none` lemmas)
- Remaining sorry: `insert_lookup_other` (frame preservation, needs list filter commutativity lemma)

### Consensus
- **VrfKeyManager integration**: ConsensusRunner now uses epoch-based VRF key
  rotation instead of a static keypair. Keys automatically rotate at epoch
  boundaries for forward secrecy.
- **Bug fix**: ValidatorInfo stored VRF secret key in `vrf_public_key` field

### P2P Encryption
- **Nonce-based SHA3-CTR + SHA3-MAC**: Replaced raw XOR with a proper
  nonce-based construction. Each message gets a random 8-byte nonce,
  SHA3-CTR mode encryption, and a SHA3 MAC tag for integrity.
  Format: `nonce (8B) || ciphertext || mac (32B)`

### Formal Verification (TLA+)
- **SealBridge.tla**: New TLA+ specification for the bridge protocol.
  Models: Lock, Confirm, Mint, Burn, Release actions.
  6 safety invariants: MintedLeqLocked, NoDoubleMint, NoMintWithoutLock,
  BurnedLeqMinted, ReleasedLeqBurned, ReleasedLeqLocked.
  1 liveness property: LockedEventuallyMinted.

### Stats
- 395 tests, 0 failures, 0 clippy warnings

---

## v0.2.0 — Hardening + Formal Verification

### Cryptography
- Bech32m address encoding (replaces hex): `seal1<bech32m>`, `sealt1<bech32m>`
- BIP-39 wordlist: 256-word mnemonic backup phrases

### ZK Proofs
- RISC Zero backend (feature-gated: `--features risc0`)
- SP1 backend (feature-gated: `--features sp1`)
- Both fall back to stub without features (no heavy deps by default)
- ZK proof architecture doc: composite 3-layer verification

### Data Structures
- Persistent red-black tree (Okasaki-style, O(log n))
- SQL column indexes backed by RBTree (range queries)
- PK-based Merkle keys (stable across insert/delete)
- WriteLog for incremental state updates

### Formal Verification
- TLA+: 6/6 invariants verified (consensus + composite proof)
- Rocq: 13/13 theorems FULLY PROVEN (zero admits)
- Lean 4: builds OK (5 proven, 3 sorry)
- Kani: 5/5 usable harnesses verified
- proptest: 25 property tests (Merkle, RBTree, Token, SQL)
- Kani limitations documented (crypto too complex for SAT)

### Consensus
- Nonce tracking (replay prevention)
- Block size limits (2MB, 1000 txs)

### Infrastructure
- Testnet script (3-node local)
- Benchmarks doc (libcrux: keygen 6.74ms, sign 13.81ms, verify 5.69ms)

---

## v0.1.0 — Initial Implementation (Phase 0-3)

### Cryptography
- ML-DSA-65 signatures via **libcrux** (formally verified with hax + F*)
- ML-KEM-768 key encapsulation via libcrux
- SHA3-256 hashing
- Seed-deterministic keygen (same mnemonic = same keys)
- Encrypted wallet storage (SHA3-based KDF + XOR)

### Consensus
- VRF-based leader election (HMAC stub, LB-VRF trait ready)
- Epoch/slot management (4s slots, 256-slot epochs)
- Stake-weighted VRF threshold
- Committee threshold signatures (simple stub, Ringtail trait ready)
- ZK proof stub (RISC Zero trait ready)
- Transaction signature validation before pool acceptance
- Nonce tracking (replay prevention)
- Block size limits (2MB, 1000 txs)

### SQL Database
- PostgreSQL-compatible parser (sqlparser-rs)
- Full SQL engine: CREATE TABLE, INSERT, SELECT, UPDATE, DELETE
- JOINs, GROUP BY, WHERE filtering (=, !=, >, <, AND, OR)
- Row-level security (RLS) with owner-based row filtering
- App namespaces with PUBLIC/SHARED/PRIVATE visibility
- Cross-app SQL queries
- MerkleEngine: SQL backed by content-addressed Merkle B-tree
- Deterministic state roots

### Networking
- libp2p with GossipSub + mDNS discovery
- Block broadcast + receive
- Rate limiting (100 msgs/tick, 1000 block queue cap)

### Storage
- sled persistent KV for Merkle nodes + blocks
- Block replay for state reconstruction on restart
- Multi-node sync (sync_blocks, get_chain, verify_and_apply)

### Token Economics
- Balance tracking (credit/debit/stake/unstake)
- Transfers with supply conservation
- Staking with unbonding period (21 epochs)
- Burn-and-mint fees (50% burned, 50% to proposer)

### Governance
- 6 proposal tracks with different thresholds/timelocks
- Voting with stake-weighted power
- Proposal lifecycle: Voting → Passed/Rejected → Timelocked → Executed
- GovPropose + GovVote transaction types

### Bridge
- Solana + Stellar lock-and-mint
- Multi-confirmation deposits
- Withdrawal with invariant: minted ≤ locked

### TEE
- Multi-vendor attestation registry (Intel TDX, AMD SEV, NVIDIA CC)
- AI inference routing with pricing (input + 4×output tokens)

### Migration
- `seal migrate analyze` converts pg_dump → Seal SQL
- Type mapping (PostgreSQL → Seal types)
- Feature stripping with warnings

### Applications
- `seal-node`: networked node with P2P + consensus
- `seal-repl`: interactive SQL shell
- `seal` CLI: demo, migrate, app deploy, sql

### Formal Verification
- **TLA+**: Agreement + NoEquivocation verified by Apalache 0.55
- **Rocq 9.1**: Balance.v fully proven, StateMachine.v 5/6 proven
- **Lean 4.8**: Hash + MerkleTree + VRF specs (4 proven, 3 sorry)
- **Kani**: 15 harnesses across 6 crates
- **proptest**: 10 property tests
- **Fuzz**: 4 targets (SQL parser, address, VRF, block deserialize)
- **cargo-audit**: dependency vulnerability scanning

### Documentation
- SPEC.md: full technical specification
- GOVERNANCE.md: three-body governance
- CONSENSUS-COMPARISON.md: 7 protocols compared
- FORMAL-METHODS.md: tool survey + strategy
- SECURITY.md: threat model + attack surfaces
- ARCHITECTURE.md: crate graph + data flow
- TESTING.md: all 292 tests documented
- ZK-VM-COMPARISON.md: RISC Zero vs SP1 vs OpenVM
- INSTALL-TOOLS.md: verification tool installation
- DEPLOY.md: how to run nodes
- DEPENDENCIES.md: vendoring + supply chain
- CONTRIBUTING.md + CLAUDE.md: dev conventions

### Infrastructure
- Docker + docker-compose (3-node testnet)
- CI script (scripts/ci.sh)
- Vendor script (scripts/vendor-update.sh)
- API docs script (scripts/docs.sh)
