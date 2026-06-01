# Admin M-of-N multisig — operator runbook

Mainnet operators gate the bridge-bootstrap RPCs
(observer registration, council seating, chain pause/unpause,
committee-key rotation) behind an `M-of-N` multisig over the
admin-address set. This document is the step-by-step you run to
configure it on a node and to drive an admin call end-to-end.

Spec reference: P8/§4.3 of
[`TODOS/SESSION-2026-05-16-no-excuse-bordel.md`](../TODOS/SESSION-2026-05-16-no-excuse-bordel.md).
Implementation:
[`crates/seal-node/src/rpc.rs`](../crates/seal-node/src/rpc.rs)
search for `verify_admin_multisig`.

## What's protected

Every RPC matching `requires_admin_auth` in
`crates/seal-node/src/rpc.rs`:

- `seal_addBridgeObserver`
- `seal_bridgeCouncilAdd` / `seal_bridgeCouncilRemove`
- `seal_bridgePauseChain` / `seal_bridgeUnpauseChain`
- `seal_bridgeRotateCommitteeKey`

`seal_bridgeRotateCommitteeKey` additionally requires a 2/3
Technical Council supermajority — both checks run.

## Single-sig vs M-of-N

| `--admin-threshold` | Behaviour |
|---------------------|-----------|
| 0 or 1 (default)    | Legacy: any signed caller whose derived address is in `--admin-address` passes. |
| ≥ 2                 | The signed caller PLUS `threshold - 1` distinct cosigners from the admin set must each contribute a signature over the canonical message. |

## Node configuration

```bash
seal-node \
    --slots 0 \
    --rpc-port 8545 \
    --admin-address sealt1adminA... \
    --admin-address sealt1adminB... \
    --admin-address sealt1adminC... \
    --admin-threshold 2     # 2-of-3
```

`--admin-address` may be passed multiple times. Mainnet operators
typically populate this via the `seal-genesis` config and bake the
threshold into the systemd unit file.

## Operator workflow — 2-of-3 example

Three admins: Alice (primary submitter), Bob, Carol.

### Step 1 — Bob signs locally

```bash
seal admin-sign \
    --method seal_bridgePauseChain \
    --params '{"chain":"Solana"}' \
    --key /path/to/bob-admin.json \
    > cosig-bob.json
```

`cosig-bob.json` looks like:

```json
{
  "sender": "<bob's ml-dsa verifying key, hex>",
  "signature": "<ml-dsa sig over the canonical message, hex>"
}
```

The canonical message is `method || params_without_admin_signatures_json`
hashed with SHA3-256 — the exact same form Alice will sign with
her primary key, so Bob's cosignature stays valid no matter what
Alice's `admin_signatures` array ends up containing.

### Step 2 — Alice assembles + POSTs

Bob sends `cosig-bob.json` to Alice over any out-of-band channel
(email, Signal, Slack — the signature itself is the bearer
credential, no transport secrecy required).

```bash
seal admin-submit \
    --method seal_bridgePauseChain \
    --params '{"chain":"Solana"}' \
    --primary /path/to/alice-admin.json \
    --cosigners cosig-bob.json \
    --node http://seal-node:8545
```

`admin-submit` builds the JSON-RPC envelope:

```json
{
  "jsonrpc": "2.0",
  "method": "seal_bridgePauseChain",
  "params": {
    "chain": "Solana",
    "admin_signatures": [
      {"sender": "...bob...", "signature": "...bob..."}
    ]
  },
  "id": 1,
  "signature": "...alice...",
  "sender": "...alice..."
}
```

Node-side flow on receipt:

1. `authenticate(req)` verifies Alice's `signature` over the
   message (which includes the `admin_signatures` array in this
   round; the canonicalization happens server-side).
2. `is_admin(alice_addr, config)` — Alice must be in the admin set.
3. `verify_admin_multisig(method, params, alice_addr, config)`
   strips `admin_signatures`, recomputes the canonical hash,
   verifies each cosigner entry against it. Dedup by derived
   address — Bob can't replay-forge by re-submitting Alice's
   sig in his slot.
4. If the verified-distinct-admin count is ≥ 2, the request
   proceeds to the handler.

### Step 3 — Carol's signature (if you wanted 3-of-3)

```bash
# Carol:
seal admin-sign --method seal_bridgePauseChain \
    --params '{"chain":"Solana"}' \
    --key carol-admin.json \
    > cosig-carol.json

# Alice:
seal admin-submit --method seal_bridgePauseChain \
    --params '{"chain":"Solana"}' \
    --primary alice-admin.json \
    --cosigners cosig-bob.json,cosig-carol.json \
    --node http://seal-node:8545
```

The `--cosigners` flag takes a comma-separated list.

## Failure modes

| Error                                    | Meaning |
|------------------------------------------|---------|
| `-32004 ... not in admin set`            | Primary caller's derived address is not in `--admin-address`. |
| `-32004 ... requires N-of-M admin multisig; got K`  | Not enough distinct valid cosigner signatures. |
| `-32003 signature verification failed`   | Primary signature itself is malformed or doesn't match the canonical message. |

A cosigner whose signature fails verification, whose address
isn't in the admin set, or who's already represented in the
distinct-address set is **silently skipped** rather than failing
the whole request — that way Alice can collect more signatures
than strictly needed and toss a noisy or stale one without
re-orchestrating with every other admin.

## Rotation

Adding or removing admins requires editing `--admin-address` flags
and restarting `seal-node`. Online rotation via RPC is intentionally
not exposed — that would require an admin-gated call to add/remove
admins, and bootstrapping the multisig itself would need a chicken-
and-egg recovery path. The systemd-unit edit is auditable in git
+ propagates atomically per validator.

## Testing locally

The test fixtures in `crates/seal-node/src/rpc.rs` (search for
`admin_multisig_`) cover the canonicalization, threshold rejection,
threshold acceptance, and dedup cases. Run with:

```bash
cargo test -p seal-node --lib -- admin_multisig
```
