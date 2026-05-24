# Operator runbook — end-to-end testnet bring-up

> **At-a-glance: the four operator commands.** These cannot be run
> from inside this repo — they must execute on the live VPN
> validator hosts. Once code-side work is at 2026-05-16 EOD state,
> this is everything left:
>
> ```bash
> # 1. Deploy bridge programs to live devnet/testnet (Solana + Stellar)
> ./scripts/bridge-deploy-devnet.sh \
>     --solana-keypair $HOME/.config/solana/id.json \
>     --stellar-account <G-addr> \
>     --seal-rpc http://127.0.0.1:8545
>
> # 2. Flip on-chain bridge programs to Ringtail-verify mode
> ./scripts/bridge-redeploy-ringtail.sh \
>     --solana-keypair $HOME/.config/solana/id.json \
>     --stellar-account <G-addr> \
>     --seal-rpc http://127.0.0.1:8545
>
> # 3. Fund each validator's relayer keys (per-validator custody)
> cp bridges/.relayer-keys.example.json bridges/.relayer-keys.json
> $EDITOR bridges/.relayer-keys.json
> ./scripts/bridge-fund-relayer.sh bridges/.relayer-keys.json
>
> # 4. Run multi-validator Ringtail smoke (asserts cross-validator
> #    signature convergence)
> ./scripts/bridge-test-ringtail-multi.sh
> ```
>
> Detail for each command lives in the sections below (§1 / §3 / §5 / §6).
> For 5- and 7-validator stacks, see
> [`docs/TESTNET-VALIDATOR-SIZES.md`](TESTNET-VALIDATOR-SIZES.md) —
> the multi-validator smoke script in step 4 is a template that
> extends to those committee shapes.

This is the **"how TF do I actually run that stuff and test it"**
manual for an operator standing up a Seal bridge testnet against
live public chains (Solana devnet + Stellar testnet). It assumes
the host-side code is already at the 2026-05-16 EOD state (every
code-side blocker closed; see
[`docs/TODOS/BRIDGE-TESTNET-READINESS-2026-05.md`](TODOS/BRIDGE-TESTNET-READINESS-2026-05.md)).

If you want the **local-stack** equivalent (solana-test-validator +
stellar/quickstart in docker), use
[`scripts/bridge-e2e.sh`](../scripts/bridge-e2e.sh) instead — this
document is for going live against public devnet/testnet.

> **Sizing.** Pick your validator count + bridge-committee shape
> first. See [`docs/TESTNET-VALIDATOR-SIZES.md`](TESTNET-VALIDATOR-SIZES.md)
> for 3 / 5 / 7-validator recipes and how the bridge committee
> threshold/size flags compose.

---

## 0. Pre-flight checklist

Before touching any script, confirm:

```bash
solana --version       # >=1.18
anchor --version       # >=0.30
stellar --version      # 25.x   (22.x rejected by protocol-25 RPCs)
rustup target list --installed | grep wasm32v1-none
rustup target list --installed | grep wasm32-unknown-unknown
jq --version
curl --version
```

Repo also needs:

```bash
cargo build --release -p seal-node --features ringtail-singleton
cargo build --release -p seal-cli
cargo build --release -p seal-relayer
cargo build --release -p seal-bridge --features ringtail-singleton
```

Validate the host-side wiring with the in-process integration test
before touching public chains:

```bash
cargo test -p seal-node --test bridge_ringtail_dispatch
```

It should pass without docker. If it fails, do NOT proceed — the
host-side Ringtail path is broken and live testnet runs will not
converge.

---

## 1. Public-chain deploy (P4)

Single command per environment. The script does:

1. `anchor build` + `anchor deploy --provider.cluster devnet`
2. `stellar contract build` + `stellar contract deploy --network testnet`
3. `seal_addBridgeObserver` for both chains against your `seal-node`
   RPC.

```bash
./scripts/bridge-deploy-devnet.sh \
    --solana-keypair $HOME/.config/solana/id.json \
    --stellar-account G... \
    --seal-rpc http://127.0.0.1:8545
```

Required prep:

- Solana keypair must be **funded on devnet** with ≥3 SOL.
  `./scripts/bridge-faucet.sh sol $(solana address -k $HOME/.config/solana/id.json)`
- Stellar account must be **funded on testnet** with ≥100 XLM.
  `./scripts/bridge-faucet.sh xlm <G-address>`

Output lands in `bridges/.deploy-devnet.env`:

```
SEAL_BRIDGE_SOL_PROGRAM_ID=<base58>
SEAL_BRIDGE_XLM_CONTRACT_ID=<C-address>
```

**Verify the deploy:**

```bash
# Solana side — confirm program id resolves on devnet
solana program show $SEAL_BRIDGE_SOL_PROGRAM_ID --url devnet

# Stellar side — confirm contract id resolves on testnet
stellar contract invoke \
    --id $SEAL_BRIDGE_XLM_CONTRACT_ID \
    --source-account <G-address> \
    --network testnet \
    -- committee_key_hash

# Seal side — confirm the observer is registered
curl -sX POST http://127.0.0.1:8545 \
    -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"seal_listBridgeObservers"}' | jq
```

The third call should return both chains with the program/contract
IDs the script captured plus a `last_polled` field that ticks
forward every `poll_interval_secs`.

---

## 2. HMAC committee-of-1 smoke (optional but recommended)

Before flipping anything Ringtail-ward, prove the deploy works in
the simpler HMAC mode. Pick any address with bridge tokens:

```bash
# Forward: lock SOL → Seal mints wrapped
./scripts/bridge-testnet-demo.sh sol

# Reverse: burn wrapped → Seal committee MAC → claim on-chain
./scripts/bridge-testnet-demo.sh reverse-sol
```

If `reverse-sol` returns a `tx hash` and `solana confirm <hash>`
shows the unlock landed, the HMAC bridge is wired end-to-end. The
mirror commands for Stellar are `xlm` and `reverse-xlm`.

---

## 3. Flip to Ringtail mode (P5)

This is a **second deploy** with new program/contract IDs — BPF
and WASM bytes differ when `ringtail-verify` is on, so existing
HMAC deployments are unaffected. If you want to keep both paths
running side-by-side, copy `bridges/.deploy-devnet.env` aside
first.

```bash
cp bridges/.deploy-devnet.env bridges/.deploy-devnet.hmac.env  # optional

./scripts/bridge-redeploy-ringtail.sh \
    --solana-keypair $HOME/.config/solana/id.json \
    --stellar-account G... \
    --seal-rpc http://127.0.0.1:8545
```

The script is a thin wrapper around `bridge-deploy-devnet.sh
--features ringtail-verify`. New IDs land in
`bridges/.deploy-devnet.env` (overwriting the HMAC IDs).

**Verify the Ringtail deploy is feature-gated correctly:**

```bash
# Solana: dump program data, grep for the verify_signature_full symbol
solana program dump $SEAL_BRIDGE_SOL_PROGRAM_ID /tmp/seal-bridge.so --url devnet
strings /tmp/seal-bridge.so | grep verify_signature_full && echo "ringtail-verify present"

# Stellar: invoke the committee_key_hash view — Ringtail-mode hash differs
stellar contract invoke \
    --id $SEAL_BRIDGE_XLM_CONTRACT_ID \
    --network testnet --source-account <G-addr> \
    -- committee_key_hash
```

If you don't see `verify_signature_full` in the Solana program
dump, the build dropped the feature; re-check that
`scripts/bridge-redeploy-ringtail.sh` ran with `--features
ringtail-verify` and didn't skip on a cached `target/`.

---

## 4. Per-validator Ringtail keypairs + flags

Each validator needs its own keypair file (PublicParams + collapsed
sk) and a matching set of `--bridge-ringtail-*` flags.

Generate the keypairs (test-friendly shared-sk fixture for the
n-of-n cross-check pattern; swap in your DKG output for a real
distinguished-share deployment):

```bash
mkdir -p bridges/ringtail-keys
cargo run --release -p seal-bridge --features ringtail-singleton \
    --example bridge-ringtail-keygen \
    -- bridges/ringtail-keys/shared.json

# One file per validator (copy of the shared keypair):
for i in $(seq 1 $N_VALIDATORS); do
    cp bridges/ringtail-keys/shared.json \
       bridges/ringtail-keys/validator-$i.json
done
```

Distribute `validator-$i.json` to each host (e.g.
`/var/lib/seal/ringtail-keypair.json`).

Restart each validator with:

```bash
seal-node --slots 0 \
    --bridge-ringtail-keypair-file /var/lib/seal/ringtail-keypair.json \
    --bridge-ringtail-mac-key-hex <32-byte hex, same on every validator> \
    --bridge-ringtail-party-id <0..N-1, unique per validator> \
    --bridge-ringtail-threshold <M> \
    --bridge-ringtail-committee-size <N> \
    --bridge-poll-interval-secs 10 \
    --rpc-port 8545 --rpc-external --data-dir /var/lib/seal
```

For 3 / 5 / 7-validator recipes and how to pick M/N, see
[`docs/TESTNET-VALIDATOR-SIZES.md`](TESTNET-VALIDATOR-SIZES.md).

**Verify on every validator:**

```bash
curl -sX POST http://127.0.0.1:8545 \
    -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"seal_bridgeRingtailStatus"}' | jq

# Expected on every node:
# {
#   "singleton_keypair_installed": true,
#   "signing_signal_subscriber":  true,
#   "orchestrator_active":        true,
#   "session_count":              0,
#   "feature_compiled_in":        true
# }
```

If `feature_compiled_in:false` — your seal-node binary wasn't built
with `--features ringtail-singleton`. Rebuild and redeploy.
If `singleton_keypair_installed:false` — the
`--bridge-ringtail-keypair-file` path is unreachable or the JSON
schema is wrong; re-run `bridge-ringtail-keygen`.

---

## 5. Fund the per-validator relayer keys (P1#3 op follow-up)

Each validator runs its own `seal-relayer` instance with its own
destination-chain keys (per-validator custody — decided 2026-05-16,
[`memory project_relayer_custody`]).

Build the manifest:

```bash
cp bridges/.relayer-keys.example.json bridges/.relayer-keys.json
$EDITOR bridges/.relayer-keys.json
```

Schema (one entry per validator):

```json
[
  {"validator": "seal-1", "sol_pubkey": "5kP7…", "xlm_account": "GAB…"},
  {"validator": "seal-2", "sol_pubkey": "6tQ8…", "xlm_account": "GCD…"}
]
```

Fund them in one shot:

```bash
./scripts/bridge-fund-relayer.sh bridges/.relayer-keys.json
```

For `--chains sol` or `--chains xlm` only (e.g. you topped one
chain manually), pass the subset.

**Verify:**

```bash
# Per-validator Solana balance:
solana balance <sol_pubkey> --url devnet

# Per-validator Stellar balance:
curl -s "https://horizon-testnet.stellar.org/accounts/<G-addr>" \
    | jq '.balances[] | select(.asset_type=="native") | .balance'
```

Each relayer needs ≥0.5 SOL and ≥10 XLM to comfortably submit
unlock transactions for the lifetime of the testnet drip.

---

## 6. Multi-validator e2e smoke (P1#5 layer 6)

This is the **gate that proves Ringtail is wired end-to-end across
validators**. It only works once steps 3–5 are done.

For the **3-validator bridge stack** (default — has local
Solana + Stellar):

```bash
./scripts/bridge-test-ringtail-multi.sh
```

For **5 / 7-validator stacks**, use the sibling smoke scripts:

```bash
# 5-validator (3-of-5 full committee), against the main
# 5-validator consensus stack at docker-compose.yml.
# Note: no local Solana/Stellar — point at live devnet/testnet.
./scripts/bridge-test-ringtail-5.sh

# 7-validator (5-of-7 full committee), against the bridge stack
# extended with 4 more validators. Local Solana + Stellar
# included (inherited from bridges/docker-compose.testnet.yml).
./scripts/bridge-test-ringtail-7.sh
```

What `bridge-test-ringtail-multi.sh` does (the 3-validator
reference; the 5/7 sibling scripts follow the same template):

1. Generates per-validator keypairs (or reuses `bridges/ringtail-multi-keys/`).
2. Writes a docker-compose override with the right
   `--bridge-ringtail-*` flags per node.
3. Brings up `bridges/docker-compose.testnet.yml` with the override.
4. Waits for `orchestrator_active=true` on every node's
   `seal_bridgeRingtailStatus`.
5. Polls `session_count` and `committee_signature_hex` across all
   validators to confirm convergence.

**Verify success:**

- Exit code 0.
- Final log line: `all validators agree on committee_signature_hex (<32-char prefix>…)`.

**If it fails:**

| Exit code | Cause | Fix |
|-----------|-------|-----|
| 1 | A validator never reached `orchestrator_active=true` | Check that validator's logs for keypair-file errors; re-run step 4. |
| 2 | No signing session opened | Run a real withdrawal first (`scripts/bridge-e2e.sh reverse-sol --skip-deploy`). Smoke script does NOT bootstrap wrapped balance. |
| 3 | Validators disagreed on `committee_signature_hex` | The mac-key-hex differs across nodes, OR a party-id collides. Verify both per-node via `seal_bridgeRingtailStatus`. |

For a real run against the 5-validator monitoring stack (not the
3-node bridge stack), follow the variable-committee instructions
in [`docs/TESTNET-VALIDATOR-SIZES.md`](TESTNET-VALIDATOR-SIZES.md)
to write the analogous override.

---

## 7. Public-testnet round-trip smoke

Once steps 1–6 pass on the local docker stack, fire a real
round-trip against public devnet/testnet:

```bash
# Forward: lock 0.1 SOL on devnet, watch the observer mint wrapped on Seal
./scripts/bridge-testnet-demo.sh sol

# Wait ~30s for the observer poll cycle, then check Seal balance:
seal-cli balance <your-seal-address>

# Reverse: burn wrapped SOL on Seal, watch the relayer unlock on devnet
./scripts/bridge-testnet-demo.sh reverse-sol

# Verify the on-chain unlock landed:
solana confirm <tx-hash-from-demo-output> --url devnet
```

Mirror for Stellar with `xlm` / `reverse-xlm`.

**USDC round-trips** (wired 2026-05-16 EOD):

```bash
# Solana USDC: requires SOL_USDC_SENDER_ATA + SOL_USDC_VAULT_ATA
# (derive via `anchor run derive-vault-ata --mint <usdc-mint> --init`).
BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh usdc-sol

# Stellar USDC: requires the contract operator to have run
# `set_usdc_sac` once after the bridge was initialized.
BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh usdc-xlm

# Both USDC forward legs in sequence:
BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh usdc-both

# Reverse:
BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh reverse-usdc-sol
BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh reverse-usdc-xlm
```

For where wrapped USDC the bridge produces is liquid (CEX + DEX
listings, regional accessibility), see
[`docs/BRIDGE-USDC-VENUES.md`](BRIDGE-USDC-VENUES.md).

**The signature on the unlock claim is the byte-identical Ringtail
aggregate produced by the host orchestrator.** If the on-chain
verify fails, dump `seal_getBridgeWithdrawal <id>` and compare
`committee_signature_hex` against the proof bytes the unlock tx
carried — the most common failure is the on-chain program was
deployed without `--features ringtail-verify` (re-run step 3).

### Dry-run mode

Before spending testnet balance, validate every env var resolves
and every command path is reachable by running with
`BRIDGE_TESTNET_DEMO_DRY_RUN=1`:

```bash
BRIDGE_TESTNET_DEMO_DRY_RUN=1 \
BRIDGE_TESTNET_DEMO_LIVE=1 \
    ./scripts/bridge-testnet-demo.sh usdc-sol
```

Dry-run keeps the safety latch on for explicit opt-in (`LIVE=1`
required), runs preflight + ID lookups + ATA derivations, and
then prints the exact `anchor` / `stellar` / `seal` commands it
would submit — annotated with `[dry-run]` — without sending
anything. Useful for spotting bad ATA pubkeys, wrong network
selectors, or missing `set_usdc_sac` calls before they burn fees.

---

## 8. Observability

While running, watch these:

- `/metrics` on every validator. Key gauges:
  - `seal_bridge_ringtail_active_sessions` — non-zero during signing
  - `seal_bridge_ringtail_completed_total` — increments on each
    successful aggregate
  - `seal_bridge_committee_signature_hash_mismatch_total` — MUST
    stay at 0; non-zero = validators disagreeing
  - `seal_bridge_rate_limit_tripped_total{group=…}` — P8/§4.1
- Grafana row: `Bridge / Ringtail` (added in commit `6b8c29dd6`).
- Prometheus alerts (3 new ones in `6b8c29dd6`):
  - `BridgeRingtailGateConfigDrift` — validator threshold/size disagree
  - `BridgeRingtailGateMacKeyDrift`
  - `BridgeRingtailGateCommitteeKeyHashDrift`

If any of those alerts fire, the multi-validator smoke
(step 6) **will** fail downstream — fix the config drift before
running anything else.

---

## 9. Rollback / kill-switch

If anything goes sideways:

1. **Revert to HMAC mode** — restart each validator with the
   original `--bridge-committee-key` flag (HMAC binary path is
   still present; the `--bridge-ringtail-*` flag set just becomes
   inactive). The HMAC program IDs are still valid on-chain if you
   saved `bridges/.deploy-devnet.hmac.env` in step 3.
2. **Pause the bridge entirely** —
   `seal-cli bridge-pause <chain>` (council-gated). Halts all
   withdrawals + observer ingestion until `bridge-resume` clears it.
3. **Rotate the committee key** — `seal-cli bridge-rotate-committee-key`
   (also council-gated, atomic on-disk persistence; no restart).

---

## 10. Common gotchas

- **Solana airdrop rate-limits.** 2 SOL per call, devnet faucet
  often denies after a few requests. Spread calls across hours, or
  fund a single deployer key and `solana transfer` the dust to the
  rest.
- **Stellar friendbot one-shot.** Friendbot funds new accounts
  ONLY. For top-ups on already-funded accounts, use
  `stellar payment` from a funded source.
- **`anchor deploy` and `[patch.crates-io]`.** The workspace's
  `.cargo/config.toml` pins vendor sources; that breaks anchor's
  on-the-fly fetches. `scripts/bridge-deploy-devnet.sh` moves the
  file aside and restores it on EXIT, but if you Ctrl-C mid-deploy
  you'll find `.cargo/config.toml.deploy-devnet-bak` left over —
  rename it back manually.
- **Validator clock skew.** Ringtail sessions have a wall-clock
  prune timer (default 60s). NTP skew across validators >30s will
  make sessions look stuck or get pruned mid-flight. Run
  `chronyd`/`ntpd` on every host.
- **Re-running the multi-validator smoke after edits.** Pass
  `--skip-bootstrap` to skip the docker-compose `up`, or
  `--keep-keypairs` to reuse the existing keys (default keeps them
  anyway since 2026-05-16).
- **`session_count` won't decrement.** If a session opens but
  never closes, the most likely cause is one validator's
  `--bridge-ringtail-mac-key-hex` differing from the rest — Round1
  MAC verification rejects, the orchestrator drops the round, the
  session stays "stuck" until prune. Compare keys across
  validators.

---

## See also

- [`docs/TESTNET-VALIDATOR-SIZES.md`](TESTNET-VALIDATOR-SIZES.md) —
  3 / 5 / 7-validator and variable bridge-committee recipes.
- [`docs/RINGTAIL-TESTNET.md`](RINGTAIL-TESTNET.md) — Ringtail
  bring-up overview (shorter, less verbose than this runbook).
- [`docs/BRIDGE-TESTNET.md`](BRIDGE-TESTNET.md) — public-testnet
  bridge reference (deploy + lock/unlock direction details).
- [`docs/GUIDE-OPERATOR.md`](GUIDE-OPERATOR.md) — single-node /
  multi-machine / VPN setup for seal-node itself (not bridge-specific).
- [`MANUAL-TESTING.md`](../MANUAL-TESTING.md) — the manual test
  matrix for the rest of the stack (SQL, DEX, consensus, RPC).
- [`docs/TODOS/BRIDGE-TESTNET-READINESS-2026-05.md`](TODOS/BRIDGE-TESTNET-READINESS-2026-05.md)
  — code-side readiness checklist (what's done vs what's left).
