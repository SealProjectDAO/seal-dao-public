# SESSION 2026-05-16 — "no excuse bordel"

Source of truth for this session. The user pulled four threads out of
"deferred" and demanded all of them land:

1. **THE BLOCKER** — P1#5 layer 4 seal-node integration (the
   integration commit ADR-002 specifies).
2. Ringtail layer 6 — multi-validator e2e (was deferred pending #1).
3. In-flight signing-session persistence across restart.
4. P8 mainnet gates — rate limits, bridge fees, admin multisig, KMS.

Plus operator-side bring-up automation (P4 public devnet deploy, P5
on-chain Ringtail flip, per-validator relayer funding).

Two things stay deferred (explicitly):

- P2 TS CLIs in `bridges/tools/` — competes with `seal-cli`,
  not testnet-blocking.
- Mainnet HSM hardware integration — KMS *adapter trait* lands this
  session; the actual HSM/cloud-KMS impl is a follow-up engagement.

Run `./scripts/ci.sh quick` after each commit. No pushing.

---

## §1 — P1#5 layer 4 seal-node integration (THE blocker)

ADR-002 (`docs/decisions/ADR-002-bridge-ringtail-integration.md`)
fully specifies the topology. Every host-side primitive is already
in place (see CHANGELOG: 7b1e39636 → 5d618c13a → 2c6fad9d7 → …).
What remains is wiring:

```
seal-node main()
├── BridgeManager  ── Arc<Mutex<BridgeManager>>  ──────┐
├── RingtailBridgeOrchestrator (when configured)       │
│     ── Arc<Mutex<RingtailBridgeOrchestrator>>  ──────┤
│                                                      ▼
├── RpcState { bridge, ringtail_orchestrator }    ◄────┤
│                                                      │
├── start_signing tokio task                       ◄───┤
│     reads WithdrawalReadyForSigning from channel,    │
│     calls orchestrator.start_signing(...),           │
│     p2p.broadcast_bridge_ringtail_round1(env)        │
│                                                      │
├── network_node receive loop                      ◄───┤
│     BridgeRingtail{Round1,Round2,Aggregate}          │
│       → orchestrator.on_round*_envelope              │
│       → broadcast returned envelope                  │
│       → on Round2Complete: attach_committee_sig +    │
│         drop_session                                 │
│                                                      │
└── prune timer (tokio interval)                   ◄───┘
      orchestrator.prune_stale_sessions()
```

### §1.1 — Slice: orchestrator construction + RpcState plumb

**Files touched**

- `crates/seal-node/src/main.rs`
  - In `run_networked`: when `ringtail_orchestrator_config` is
    `Some`, wrap in `Arc<Mutex<RingtailBridgeOrchestrator>>`.
  - Pass as a new `Option<Arc<Mutex<…>>>` arg to
    `start_rpc_server`.
- `crates/seal-node/src/rpc.rs`
  - Add `ringtail_orchestrator: Option<Arc<Mutex<…>>>` to
    `RpcState` (behind `#[cfg(feature = "ringtail-singleton")]`).
  - `start_rpc_server` signature gains the arg, stuffs it into
    state.
  - `seal_bridgeRingtailStatus` handler now reports both the
    BridgeManager singleton-keypair state AND
    `orchestrator.session_count()` when the orchestrator is
    present.

**Tests**

- `rpc.rs` doctest / unit test: RpcState builds with the field
  set / unset.

**Commit message**: `seal-node: thread RingtailBridgeOrchestrator
Arc through RpcState`.

### §1.2 — Slice: signing-signal channel + start_signing task

**Files touched**

- `crates/seal-node/src/main.rs`
  - After the orchestrator Arc exists, create
    `tokio::sync::mpsc::channel::<WithdrawalReadyForSigning>(256)`.
  - The sender goes to `BridgeManager` via
    `set_signing_signal_sender`. The receiver goes into a
    `tokio::spawn` task that pulls messages and calls
    `orchestrator.lock().await.start_signing(...)` → if
    `Some(env)`, serialise + `p2p.broadcast_bridge_ringtail_round1`
    via the `Arc<Mutex<NetworkNode>>`.

**Subtlety** — `BridgeManager` lives in `RpcState` and is currently
constructed inside `start_rpc_server`. The signing-signal sender
must be passed *into* `start_rpc_server` so the same BridgeManager
that the RPC handlers mutate is the one with the subscriber.
**Move BridgeManager construction up into `run_networked`** so the
same `Arc<Mutex<BridgeManager>>` is shared by RpcState + the
start_signing task + the network loop.

**Tests**

- Already covered by
  `bridge::tests::signing_signal_fires_once_per_withdrawal` —
  no new test needed on the channel itself.
- New test: `main::tests::start_signing_task_handles_burst` —
  feed 3 withdrawals into the channel, assert all 3 get
  `start_signing` calls (mock orchestrator).

**Commit message**: `seal-node: signing-signal channel +
start_signing tokio task`.

### §1.3 — Slice: route Ringtail envelopes through network loop

**Files touched**

- `crates/seal-node/src/network_node.rs`
  - `NetworkNode` gains two new optional fields:
    `bridge: Option<Arc<Mutex<BridgeManager>>>` and
    `ringtail_orchestrator: Option<Arc<Mutex<…>>>`.
  - `start_with_keypair` / `start_with_validators` /
    `start` keep their old signatures (those don't touch
    bridge); add `attach_bridge` + `attach_ringtail_orchestrator`
    methods called from `run_networked` after both are built.
  - Replace the three debug-only match arms in
    `process_network_messages`:
    - `BridgeRingtailRound1 { data, .. }` →
      `serde_json::from_slice::<BridgeRingtailRound1Envelope>`,
      call `orchestrator.on_round1_envelope`, on `Some(env)`
      call `self.p2p.broadcast_bridge_ringtail_round2(...)`.
    - `BridgeRingtailRound2 { data, .. }` → same shape,
      broadcast aggregate envelope on `Some(env)`, AND call
      `bridge.attach_committee_signature(...)` +
      `orchestrator.drop_session(...)`.
    - `BridgeRingtailAggregate { data, .. }` → race-loser path:
      a peer broadcast the aggregate before we computed our own.
      Parse, call `bridge.attach_committee_signature(...)`, drop
      the local session if present.

**Tests**

- New: `crates/seal-node/tests/ringtail_envelope_routing.rs` —
  in-process test that wires a `NetworkNode` + orchestrator,
  feeds a synthetic `BridgeRingtailRound1` directly into the
  process_network_messages path, asserts the orchestrator
  emitted a Round2 broadcast.

**Commit message**: `seal-node: route Ringtail envelopes through
orchestrator + attach final aggregate to BridgeManager`.

### §1.4 — Slice: periodic prune timer

**Files touched**

- `crates/seal-node/src/main.rs`
  - `tokio::spawn` an interval task: every `prune_secs` (parsed
    from `--bridge-ringtail-prune-secs`, default 300), call
    `orchestrator.lock().await.prune_stale_sessions(max_idle)`.
    If non-empty: `warn!(count = dropped.len(), "pruned stale
    signing sessions")`.

**Tests**

- Already covered by orchestrator's
  `prune_drops_idle_unfinished_sessions_only`.

**Commit message**: `seal-node: periodic prune of stale Ringtail
signing sessions`.

### §1.5 — Slice: metrics + seal_bridgeRingtailStatus reflects orchestrator

**Files touched**

- `crates/seal-node/src/metrics.rs` — add
  `ringtail_signing_sessions` gauge.
- `/metrics` exposition: pull the gauge from
  `state.ringtail_orchestrator` if present.
- `seal_bridgeRingtailStatus`: include `session_count` + bool
  `orchestrator_active`.

**Commit message**: `seal-node: surface orchestrator session count
via /metrics + seal_bridgeRingtailStatus`.

---

## §2 — Ringtail layer 6: multi-validator e2e harness

Depends on §1. Once envelope routing is in place, prove a
multi-validator withdrawal end-to-end.

### §2.1 — In-process Rust integration test

`crates/seal-node/tests/ringtail_multi_validator_e2e.rs` — spin up
two `NetworkNode` instances in-process with a shared in-memory
gossip simulator (or two real `SealNode`s on localhost loopback
ports, connected via bootstrap-peers), each with its own
orchestrator. Initiate a withdrawal on validator 0; pump both
ticks; assert both BridgeManagers end with the same
`committee_signature_hex` attached.

**Why in-process Rust, not docker**: docker e2e exists already
(`bridges/docker-compose.testnet.yml`); a Rust test is faster and
runs in CI without docker.

**Commit message**: `seal-node: multi-validator Ringtail e2e
integration test`.

### §2.2 — Shell smoke test against docker-compose

`scripts/bridge-test-ringtail-multi.sh` — boots the docker
compose, deploys bridge programs, runs a withdrawal, polls all 5
validators' `seal_bridgeRingtailStatus`, asserts all 5 ended
with `session_count = 0` (signing completed) and the same
`committee_signature_hex`.

**Commit message**: `scripts: docker-compose multi-validator
Ringtail smoke test`.

---

## §3 — In-flight session persistence across restart

The orchestrator's `HashMap<String, InFlight>` is in-memory only.
On restart we lose progress; peers re-broadcast and protocol
resumes, but the user wants explicit persistence so a 5-validator
restart during a high-volume window doesn't drop withdrawals to
the floor.

### §3.1 — Per-session serialization

**Files touched**

- `crates/seal-bridge/src/ringtail_session.rs` — derive
  `Serialize` / `Deserialize` on `RingtailBridgeSession` (it's
  internally `Round1Message` / `Round2Message` collections,
  which are already serializable on the wire).
- `crates/seal-bridge/src/ringtail_orchestrator.rs` — add
  `serialize_session(wd_id) -> Option<Vec<u8>>` +
  `restore_session(bytes) -> Result<(), String>`.
- `RingtailParty` from `seal-threshold` likely needs a
  serialization helper too; check that crate.

### §3.2 — On-disk store

**Files touched**

- New: `crates/seal-bridge/src/ringtail_store.rs` — atomic
  per-file persistence under
  `<data_dir>/ringtail-sessions/<wd_id>.json`. `save`,
  `load_all`, `delete`.
- `crates/seal-node/src/main.rs` — at orchestrator construction,
  call `store.load_all()` and `restore_session` for each. On
  every successful `on_round*_envelope`, persist; on
  `drop_session`, delete.

### §3.3 — Test

`crates/seal-node/tests/ringtail_persistence.rs` — start an
orchestrator, ingest a Round1, drop the in-process struct,
reconstruct from disk, ingest the matching Round2, assert
aggregate produced. Restart-safe.

**Commit messages** (3): per slice.

---

## §4 — P8 mainnet gates

Each one ships as an independent commit so they can roll back
individually if a testnet operator hits a regression.

### §4.1 — Per-method rate limits

Today: one `max_requests_per_minute` per IP across all RPCs. The
expensive paths (`seal_submitSql`, `seal_bridgeWithdraw`, admin
RPCs) deserve their own buckets so SQL spam can't starve admin
calls.

**Files touched**

- `crates/seal-node/src/rpc.rs` — extend `RateLimiter` to a
  `HashMap<(IpAddr, &'static str), bucket>` keyed by method
  group. Method → group map: `expensive` (SQL writes, bridge
  withdraws), `admin` (admin-gated), `default` (everything
  else).
- `RpcConfig` gains `per_group_rpm: HashMap<&'static str, u64>`
  with sensible defaults: expensive=20/min, admin=5/min,
  default=120/min.

### §4.2 — Bridge withdrawal fee

Operator-configurable SEAL fee on `seal_bridgeWithdraw`,
deducted from caller's native SEAL balance, routed to the
validator pool. Testnet default 0; mainnet default non-zero
(genesis config).

**Files touched**

- `crates/seal-bridge/src/bridge.rs` — `BridgeManager` gains
  `withdrawal_fee: u64`; new helper
  `set_withdrawal_fee`. `initiate_withdrawal` returns the
  required fee as part of its error if balance insufficient.
  Actual debit happens at the RPC layer (BridgeManager doesn't
  hold the SEAL ledger).
- `crates/seal-node/src/main.rs` — `--bridge-withdrawal-fee
  <u64>` CLI flag.
- `crates/seal-node/src/rpc.rs` — `seal_bridgeWithdraw` handler
  debits `BalanceStore` by `fee` before calling
  `initiate_withdrawal`. Refund on inner failure.

### §4.3 — Admin multisig (M-of-N)

Today: single admin signature is enough on every admin-gated RPC
(except `seal_bridgeRotateCommitteeKey` which is 2/3 council).
Mainnet wants M-of-N across the entire admin set.

**Files touched**

- `crates/seal-node/src/rpc.rs`
  - `RpcConfig` gains `admin_threshold: usize` (0 = behave as
    today, single sig).
  - When `admin_threshold > 1`, admin-gated RPC bodies expect
    an `admin_signatures: [{sender, signature}, …]` field with
    ≥ threshold valid signatures from distinct
    `admin_addresses` entries.
  - `verify_admin_multisig(req)` helper used by every
    admin-gated handler.
- `crates/seal-node/src/main.rs` — `--admin-threshold <n>` CLI
  flag.

### §4.4 — KMS adapter trait

The committee MAC + Ringtail SK live as plain bytes on disk
today. Mainnet wants the option to source them from a KMS / HSM
without touching the call sites. Land the *trait* this session;
real HSM/cloud-KMS impls are out of scope.

**Files touched**

- New: `crates/seal-bridge/src/keysource.rs` —
  ```rust
  pub trait CommitteeKeySource: Send + Sync {
      fn read_committee_mac(&self) -> Result<[u8;32], String>;
  }
  pub trait RingtailKeySource: Send + Sync {
      fn read_keypair(&self) -> Result<RingtailKeypair, String>;
  }
  pub struct FileKeySource { /* paths */ }
  impl CommitteeKeySource for FileKeySource { … }
  impl RingtailKeySource for FileKeySource { … }
  ```
- `crates/seal-bridge/src/bridge.rs` — `BridgeManager::new`
  unchanged; new constructor
  `from_key_sources(committee: impl CommitteeKeySource, …)`.
- `crates/seal-node/src/main.rs` — when `--bridge-kms-config
  <path>` is supplied, build a `FileKeySource` from the JSON
  config (today's behavior) instead of CLI bytes; trait makes
  the swap a one-liner for future HSM impls.

---

## §5 — Operator-side automation

### §5.1 — `scripts/bridge-deploy-devnet.sh`

Wraps `anchor deploy --provider.cluster devnet` + `stellar
contract deploy --network testnet` + the two
`seal_addBridgeObserver` JSON-RPC calls. Captures program-id and
contract-id, prints operator-pasteable env-var block at the end.

Usage:
```
./scripts/bridge-deploy-devnet.sh \
    --solana-keypair ~/.config/solana/id.json \
    --stellar-account G… \
    --seal-rpc http://127.0.0.1:9933
```

### §5.2 — `scripts/bridge-redeploy-ringtail.sh`

Same as §5.1 but with `--features ringtail-verify` flipped on
for both chains. Re-uses pieces from
`scripts/bridge-test-ringtail.sh`. Calls
`seal_addBridgeObserver` with the *new* program-id (Ringtail
deploy = different program-id than HMAC deploy because the
WASM/BPF bytes differ).

### §5.3 — `scripts/bridge-fund-relayer.sh`

Reads validator list from `seal listValidators`; for each,
calls `scripts/bridge-faucet.sh sol <pubkey>` and
`bridge-faucet.sh xlm <G-address>` to top up the per-validator
relayer destination-chain keys. Reads the per-validator key
paths from a JSON config (one file per validator with sol/xlm
addresses).

### §5.4 — `docs/RINGTAIL-TESTNET.md` operator playbook

Step-by-step:

1. Generate Ringtail keypair per validator
   (`cargo run -p seal-bridge --example bridge-ringtail-keygen`).
2. Run `scripts/bridge-deploy-devnet.sh` once for the cluster
   (program-id/contract-id are cluster-wide).
3. `seal_addBridgeObserver` (auto-handled by §5.1).
4. Run `scripts/bridge-redeploy-ringtail.sh` to flip
   `--features ringtail-verify`.
5. Restart each `seal-node` with `--bridge-ringtail-*` flags +
   `--bridge-ringtail-keypair-file <path>`.
6. Run `scripts/bridge-fund-relayer.sh` to top up per-validator
   relayer keys.
7. Smoke: `scripts/bridge-test-ringtail-multi.sh` → expect 5/5
   validators report identical `committee_signature_hex`.

---

## Order of work

Top-down through §1 (THE blocker) one slice per commit, then §2
(prove it works multi-validator), then §3 (persistence — also
exercised by the §2 harness), then §4 (mainnet gates, in any
order), then §5 (operator-side scripts + doc).

`./scripts/ci.sh quick` between every commit.

---

## Acceptance criteria

- `cargo test --workspace --features ringtail-singleton` green.
- §2 e2e test passes (multi-validator aggregate signature
  matches across all validators).
- `seal_bridgeRingtailStatus` on a running node with orchestrator
  configured returns `orchestrator_active: true,
  session_count: <n>`.
- All four §4 mainnet gates have a passing unit test.
- §5 scripts run end-to-end on the local devnet stack (one-shot
  manual verification, not CI).
