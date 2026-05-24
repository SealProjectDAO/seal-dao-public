# Ringtail multi-validator testnet — operator bring-up

The default Seal bridge unlock path uses a single HMAC committee
key on every validator (committee-of-1; see
[`docs/BRIDGE-TESTNET.md`](BRIDGE-TESTNET.md)). The **Ringtail**
path replaces that with a per-validator 2088-byte lattice
signature aggregated across a committee, with on-chain
verification in BPF (Solana) and WASM (Soroban). This document is
the step-by-step you run to flip your testnet from HMAC to
Ringtail.

Prerequisites:

- A working HMAC testnet (forward + reverse round-trip already
  validated via [`scripts/bridge-e2e.sh`](../scripts/bridge-e2e.sh)).
- The host toolchains installed via
  [`scripts/install-bridge-toolchains.sh`](../scripts/install-bridge-toolchains.sh).
- `jq` on PATH (used by `scripts/bridge-fund-relayer.sh`).

## Step 1 — Generate per-validator Ringtail keypairs

Every validator needs the validator's own keypair file (`PublicParams +
collapsed sk`). For the n-of-n cross-check fixture used in P1#5
layer 4 every validator shares the SAME sk; if you have a real
n-of-m distinguished-share deployment, swap in your DKG output
here.

```bash
# Test-friendly: shared-sk fixture for 3 validators.
mkdir -p bridges/ringtail-keys
cargo run --release -p seal-bridge --features ringtail-singleton \
    --example bridge-ringtail-keygen -- bridges/ringtail-keys/shared.json
for i in 1 2 3; do
    cp bridges/ringtail-keys/shared.json bridges/ringtail-keys/validator-$i.json
done
```

Copy `validator-<n>.json` to each validator's host at, e.g.,
`/var/lib/seal/ringtail-keypair.json`.

## Step 2 — Public devnet deploy (one-shot)

```bash
./scripts/bridge-deploy-devnet.sh \
    --solana-keypair $HOME/.config/solana/id.json \
    --stellar-account G... \
    --seal-rpc http://127.0.0.1:8545
```

Captures `SEAL_BRIDGE_SOL_PROGRAM_ID` and
`SEAL_BRIDGE_XLM_CONTRACT_ID` to `bridges/.deploy-devnet.env`.
The script also fires `seal_addBridgeObserver` for both chains.

If your seal-node isn't running yet, skip the observer step
with `--skip-observer` and call it manually later.

## Step 3 — Redeploy with `--features ringtail-verify`

Once the HMAC path is healthy you flip the on-chain bridge
programs into Ringtail-verify mode. This is a SECOND deploy with
NEW program-ids (the BPF/WASM bytes differ):

```bash
./scripts/bridge-redeploy-ringtail.sh \
    --solana-keypair $HOME/.config/solana/id.json \
    --stellar-account G... \
    --seal-rpc http://127.0.0.1:8545
```

The new IDs land in `bridges/.deploy-devnet.env` (overwrites the
HMAC IDs — operators that want to keep both paths simultaneously
should save the HMAC env before this step).

## Step 4 — Restart each validator with `--bridge-ringtail-*` flags

Each validator's seal-node needs six new flags. For the 3-node
test fixture:

```bash
seal-node --slots 0 \
    --bridge-ringtail-keypair-file /var/lib/seal/ringtail-keypair.json \
    --bridge-ringtail-mac-key-hex 2222222222222222222222222222222222222222222222222222222222222222 \
    --bridge-ringtail-party-id 0 \
    --bridge-ringtail-threshold 2 \
    --bridge-ringtail-committee-size 3 \
    --bridge-poll-interval-secs 10 \
    --rpc-port 8545 --rpc-external --data-dir /var/lib/seal
```

- `--bridge-ringtail-party-id` must be unique per validator
  (0..committee_size-1).
- `--bridge-ringtail-mac-key-hex` must match across all
  validators — this is a different key from
  `--bridge-committee-key` (which can be unset in Ringtail mode).
- `--bridge-ringtail-threshold` and
  `--bridge-ringtail-committee-size` are the M-of-N params.
- Persistence: the orchestrator writes in-flight signing sessions
  to `<data_dir>/ringtail-sessions/`. A restart re-loads them
  automatically. Do NOT delete that directory unless you're
  intentionally resetting all signing rounds.

Verify with:

```bash
curl -sX POST http://127.0.0.1:8545 \
    -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"seal_bridgeRingtailStatus"}'
# expect:
# {"singleton_keypair_installed":false,
#  "signing_signal_subscriber":true,
#  "orchestrator_active":true,
#  "session_count":0,
#  "feature_compiled_in":true}
```

If `orchestrator_active` is false, the binary wasn't compiled
with `--features ringtail-singleton`. Rebuild seal-node with
`cargo build --release -p seal-node --features ringtail-singleton`.

## Step 5 — Fund the per-validator relayer keys

Each validator's per-validator relayer
([P1#3](TODOS/SESSION-2026-05-10-batch-closeout.md)) needs a
funded Solana ed25519 keypair + Stellar G-account on the
destination chains so the unlock-tx submission has gas.

```bash
# Build a manifest of (validator, sol_pubkey, xlm_account):
cp bridges/.relayer-keys.example.json bridges/.relayer-keys.json
$EDITOR bridges/.relayer-keys.json   # fill in real pubkeys

./scripts/bridge-fund-relayer.sh bridges/.relayer-keys.json
```

The script wraps
[`scripts/bridge-faucet.sh`](../scripts/bridge-faucet.sh) per
validator: 2 SOL via the Solana devnet airdrop, one Stellar
friendbot drip (10000 XLM) per account.

## Step 6 — Smoke test

```bash
./scripts/bridge-test-ringtail-multi.sh
```

Generates the override compose, brings up the testnet stack,
waits for `orchestrator_active=true` on every node, polls
`session_count` across all validators, and asserts every node
ends with the same `committee_signature_hex` for each pending
withdrawal.

A real withdrawal flow (forward via `scripts/bridge-e2e.sh
forward-sol`, then reverse via the seal-cli or
`bridge-testnet-demo.sh`) should now produce a Ringtail
aggregate that the on-chain `unlock_tokens` /
`unlock_xlm` ix accepts via the `verify_signature_full`
algebraic check.

## Rollback

If something goes wrong, the HMAC path is still present in the
binaries — restart each validator without the
`--bridge-ringtail-*` flags and the HMAC `--bridge-committee-key`
flow kicks back in. The on-chain bridge programs are independent
deploys so the HMAC program-ids remain valid (if you saved the
HMAC `bridges/.deploy-devnet.env` before Step 3).

## See also

- [`docs/RUNBOOK-TESTNET-OPERATOR.md`](RUNBOOK-TESTNET-OPERATOR.md)
  — full end-to-end runbook (deploy + flip + fund + smoke + verify).
  More verbose than this doc; covers the HMAC-mode smoke between
  steps 2 and 3.
- [`docs/TESTNET-VALIDATOR-SIZES.md`](TESTNET-VALIDATOR-SIZES.md) —
  3 / 5 / 7-validator recipes and variable bridge-committee
  thresholds.
- [`docs/TODOS/BRIDGE-TESTNET-READINESS-2026-05.md`](TODOS/BRIDGE-TESTNET-READINESS-2026-05.md)
  — code-side readiness matrix.
