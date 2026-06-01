# ADR-002 — Bridge multi-validator Ringtail integration in seal-node

Date: 2026-05-16
Status: Drafted (host-side primitives complete; integration pending)

## Context

P1#5 layers 1–4 host-side are closed (commits in CHANGELOG: 7b1e39636,
1caf1742d, bf0fe0da2, 024bdf85d, 12f5a71e0, 8fd54d8ea, cec594e00,
df24b3c71, 5d618c13a, 2c6fad9d7). What's left for layer 4 is the
integration glue in `seal-node` that:

1. Constructs the `RingtailBridgeOrchestrator` at boot when the
   operator opts into Ringtail mode.
2. Receives the three new `NetworkMessage::BridgeRingtail*` variants
   from `seal-p2p` and routes them into the orchestrator.
3. Broadcasts the envelopes the orchestrator returns via
   `SealNode::broadcast_bridge_ringtail_*`.
4. Triggers `orchestrator.start_signing(…)` whenever a withdrawal
   first lands in the pending-signature state.
5. Attaches the final aggregate signature to `BridgeManager` via the
   existing `attach_committee_signature` method.
6. Runs a periodic `prune_stale_sessions` timer.

The hard part is **shared state** — `BridgeManager` lives in
`rpc::RpcState` today, but the orchestrator needs to call
`attach_committee_signature` from the network-event-loop side. A
naive integration would either:

- **Pass `Arc<Mutex<BridgeManager>>` around explicitly** — touches a
  lot of constructors, but keeps ownership obvious.
- **Promote BridgeManager to a SealNode field** — cleaner but
  requires re-plumbing every RPC handler that touches it.

This ADR commits to option A — **explicit `Arc` threading** — because
RPC handlers already work via `Arc<Mutex<BridgeManager>>` (in
`RpcState`); passing the same Arc into `network_node.rs` is a
one-line constructor change rather than a subsystem migration.

## Decision

### Topology

```
seal-node main()
├── BridgeManager  ──── Arc<Mutex<BridgeManager>>  ───┐
├── (when Ringtail enabled)                           │
│   RingtailBridgeOrchestrator  ── Arc<Mutex<…>>  ────┤
│                                                     ▼
├── RpcState { bridge: Arc, orchestrator: Arc }   ◄───┤
│   (RPC handlers read/write either)                  │
│                                                     │
└── network_node loop                              ◄──┘
    on NetworkMessage::BridgeRingtail* {
        orchestrator.on_round*_envelope(env) -> Option<envelope>
        if Some(out) -> seal_node.broadcast_bridge_ringtail_*(out)
        on Round2Complete: bridge.attach_committee_signature(id, hex)
                        + orchestrator.drop_session(id)
    }
```

### CLI flags (operator opts in)

```
--bridge-ringtail-keypair-file <path>
    JSON: {"public_params_hex": "...", "sk_collapsed_hex": "..."}.
    Refusing to start if --bridge-committee-key is also set without
    --bridge-prefer-ringtail (mutual exclusion).

--bridge-ringtail-mac-key-hex <64-hex>
    32-byte MAC key. Distinct from the bridge committee MAC; this
    one secures the per-signer Round1 commitment binding.

--bridge-ringtail-party-id <n>
    0-based. Must match the validator's index in the active set.

--bridge-ringtail-threshold <n>
--bridge-ringtail-committee-size <n>
    Both required. Boot rejects if threshold > committee_size or 0.

--bridge-ringtail-prune-secs <n>
    Default 300. Stale-session cleanup interval.

--bridge-ringtail-max-idle-secs <n>
    Default 600. Session abandoned after N seconds without progress.
```

### Trigger for `start_signing`

The orchestrator needs to know when a withdrawal first lands in the
pending-signature state. Two options:

1. **Polling** — every N seconds, scan `BridgeManager` for
   withdrawals with `committee_signature_hex == None`. Simple but
   adds a delay equal to N.
2. **Push** — modify `BridgeManager::initiate_withdrawal` to take
   a callback (or an outbound channel sender) that fires whenever
   it inserts a new pending withdrawal.

Decision: **push via outbound channel**. Add a new `seal_bridge`
type `WithdrawalReadyForSigning { withdrawal_id, dest_chain,
dest_address, amount, nonce }` and an `Option<Sender<…>>` field on
BridgeManager. seal-node creates the channel + sender, hands it to
BridgeManager at construction, drives the receiver from a tokio
task that calls `orchestrator.start_signing` per message.

### Receive-side flow

```rust
match net_msg {
    NetworkMessage::BridgeRingtailRound1 { data, source } => {
        let env: BridgeRingtailRound1Envelope = serde_json::from_slice(&data)?;
        let mut orch = orchestrator.lock().await;
        match orch.on_round1_envelope(env) {
            Ok(Some(round2_env)) => {
                drop(orch);
                let bytes = serde_json::to_vec(&round2_env)?;
                seal_node.broadcast_bridge_ringtail_round2(bytes).await?;
            }
            Ok(None) => {}                 // pending or already complete
            Err(e) => warn!(?e, "round1 rejected"),  // MAC mismatch
        }
    }
    NetworkMessage::BridgeRingtailRound2 { data, source } => {
        // similar — broadcast aggregate envelope on Round2Complete
        // AND call bridge.attach_committee_signature locally
    }
    NetworkMessage::BridgeRingtailAggregate { data, source } => {
        // race-loser path: peer broadcast the aggregate before us;
        // attach to our local BridgeManager + drop the session.
    }
}
```

### Periodic prune

```rust
tokio::spawn(async move {
    let mut tick = tokio::time::interval(Duration::from_secs(prune_secs));
    loop {
        tick.tick().await;
        let dropped = orchestrator.lock().await
            .prune_stale_sessions(Duration::from_secs(max_idle_secs));
        if !dropped.is_empty() {
            warn!(count = dropped.len(), "pruned stale signing sessions");
        }
    }
});
```

### What NOT to do

- **Don't refactor BridgeManager into seal-node.** RpcState ownership
  works; we just need to share the Arc.
- **Don't persist orchestrator state across restarts.** Peers
  re-broadcast on a fresh start; the protocol resumes within a few
  poll intervals. Persistence adds disk-sync complexity for a recovery
  case that's already handled by the network layer.
- **Don't add a second BridgeManager mutex inside the orchestrator.**
  The orchestrator is `&mut self` for ingest methods; lock contention
  at the orchestrator level is already serialized.

## Consequences

- Operator config grows by 6 CLI flags (or one --bridge-ringtail-config
  file with all of them).
- BridgeManager gains an optional outbound channel that fires per
  withdrawal — small surface change, no behavior change in the
  default (no-channel) path.
- network_node.rs grows two ~40-line match arms.
- Stale sessions auto-prune; misconfig surfaces on the prune log.
- All existing tests pass unchanged; new integration tests live in
  `crates/seal-node/tests/` (out-of-process e2e against the docker
  stack — pending the multi-validator e2e from layer 6).

## Out of scope

- On-chain Anchor/Soroban redeploy with `ringtail-verify` feature on
  (operator-side, layer 5).
- Multi-validator e2e under `bridges/docker-compose.testnet.yml`
  (layer 6 — depends on this integration).
- Rotation of (PublicParams, sk) — orchestrator is rebuilt at restart;
  online rotation can land later if needed.
- Mainnet HSM / KMS for sk material.
