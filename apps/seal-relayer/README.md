# seal-relayer

Per-validator bridge unlock relayer. Watches `seal_listBridgeWithdrawals`
for committee-signed-but-unexecuted entries and submits the matching
`unlock_*` ix on the destination chain (Solana / Stellar), then calls
`seal_bridgeMarkExecuted` to flip the on-Seal flag.

## Why per-validator

Decided 2026-05-16 (see `MEMORY.md` → `project_relayer_custody.md`).
The alternative — one foundation-run relayer — is a single point of
failure that politically and structurally centralizes the bridge.
Per-validator distributes both the responsibility and the risk;
matches the validator-set trust model.

Multiple validators may race to relay the same withdrawal; the
`SHA3-256(vk || withdrawal_id) % max_backoff_secs` deterministic
back-off ensures different validators get different delays, so the
fastest one usually pays the gas and the rest fold into the
idempotent `was_already_executed` no-op path on the bridge
manager.

## Quickstart

```bash
cargo build -p seal-relayer
target/debug/seal-relayer \
    --key validator.json \
    --node http://localhost:8545 \
    --cursor-file /var/lib/seal/relayer-cursor.json \
    --stellar-source seal-relayer \
    --stellar-contract-id "$(cat bridges/.stellar-testnet-contract-id)" \
    --solana-program-id "$(cat bridges/.solana-devnet-program-id)" \
    --solana-wallet ~/.config/solana/seal-relayer.json \
    --solana-authority "$BRIDGE_STATE_AUTHORITY" \
    --solana-mint-wsol "$SOL_WSOL_MINT" \
    --solana-vault-ata-wsol "$SOL_WSOL_VAULT_ATA" \
    --solana-mint-wusdc 4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU \
    --solana-vault-ata-wusdc "$SOL_WUSDC_VAULT_ATA"
```

## Funding the relayer keys

The relayer pays destination-chain gas for every unlock it submits.
Before pointing it at a node, top up the keys:

```bash
# Solana devnet
./scripts/bridge-faucet.sh sol "$(solana address -k ~/.config/solana/seal-relayer.json)"

# Stellar testnet
./scripts/bridge-faucet.sh xlm "$(stellar keys address seal-relayer)"
```

Per-validator means each validator runs its own funded keys. Estimate
for testnet: 5 SOL + 100 XLM per validator covers a few hundred unlocks
at current devnet/testnet fees.

## Stellar-only or Solana-only mode

Both chains opt in independently. If you only want to handle WXLM /
WUSDC withdrawals from a given validator, omit the `--solana-*` flags
entirely; if you only want Solana, omit `--stellar-*`. Half-configured
state (e.g. `--stellar-network` without `--stellar-source`) rejects
at startup so typos surface immediately.

For Solana, **at least one of** `--solana-mint-wsol` /
`--solana-mint-wusdc` (with its paired vault ATA) must be set; the
relayer rejects mismatched halves.

## Dry-run mode

`--dry-run` logs the withdrawals the relayer *would* submit but
neither shells out to the destination-chain CLI nor calls
`seal_bridgeMarkExecuted`. Useful for verifying the loop sees the
right withdrawals before flipping on real submission.

## Production deployment (systemd)

`seal-relayer.service` is the canonical unit; `relayer.env.example`
captures the operator-specific environment. Bring-up:

```bash
# 1. Build + install the binary
cargo build --release -p seal-relayer
sudo install -m 755 target/release/seal-relayer /usr/local/bin/

# 2. Create user + state dir
sudo useradd --system --home /var/lib/seal --shell /usr/sbin/nologin seal
sudo install -d -o seal -g seal -m 700 /var/lib/seal /var/lib/seal/keys

# 3. Drop the keys (validator + destination-chain wallets) into
#    /var/lib/seal/keys/ as root, chown to seal:seal mode 600.

# 4. Configure the operator-specific env
sudo install -m 600 -o seal -g seal apps/seal-relayer/relayer.env.example /etc/seal/relayer.env
sudo $EDITOR /etc/seal/relayer.env
sudo install -m 644 apps/seal-relayer/seal-relayer.service /etc/systemd/system/

# 5. Start
sudo systemctl daemon-reload
sudo systemctl enable --now seal-relayer
sudo journalctl -u seal-relayer -f
```

Hardening defaults (NoNewPrivileges, ProtectSystem=strict,
RestrictAddressFamilies, MemoryDenyWriteExecute, …) are baked into
the unit. Drop them only if your operator workflow needs the relayer
to spawn helpers from elsewhere on the host.

## Metrics

Pass `--metrics-bind 127.0.0.1:8548` to expose a Prometheus-format
`/metrics` endpoint. Counters:

| Metric | Type | Description |
|---|---|---|
| `seal_relayer_passes_total` | counter | Total polling passes |
| `seal_relayer_withdrawals_seen` | counter | Withdrawals seen with committee_signature set + executed=false |
| `seal_relayer_submissions_total` | counter | Successful destination-chain unlock submissions |
| `seal_relayer_submission_failures` | counter | Failed destination-chain submissions (CLI non-zero exit) |
| `seal_relayer_skipped_not_configured` | counter | Withdrawals skipped because chain isn't configured on this relayer |
| `seal_relayer_mark_executed_total` | counter | Successful `seal_bridgeMarkExecuted` calls (first writer) |
| `seal_relayer_mark_executed_already` | counter | Mark-executed calls where another relayer raced first |
| `seal_relayer_mark_executed_failures` | counter | Mark-executed RPC failures (claim landed, Seal state not updated) |
| `seal_relayer_dry_run_skipped` | counter | Withdrawals logged-but-not-submitted under `--dry-run` |
| `seal_relayer_uptime_secs` | gauge | Seconds since process start |
| `seal_relayer_dry_run` | gauge | 1 when launched with `--dry-run`, else 0 |

`/health` also responds with `200 OK` for systemd / load-balancer
liveness checks.

The endpoint is **disabled by default** so a default invocation
doesn't quietly bind a port. Operators add the flag via
`/etc/seal/relayer.env`.

## Operational notes

* **Race-loser path.** If another validator submits first, the
  destination chain returns `AlreadyClaimed`. The Anchor / Soroban
  CLIs still exit 0 (the claim itself is replay-protected), so the
  relayer proceeds to mark-executed where the bridge manager folds
  the call into a no-op via `was_already_executed = true`.
* **Recipient ATA not initialized (Solana).** Auto-init by the relayer
  would let any address solicit SOL-rent payments — a DoS vector. The
  user is expected to initialize their own ATA before claiming. When
  the ATA is missing, `anchor run unlock-tokens` fails with a clear
  error; the relayer logs and retries on the next pass.
* **Cursor durability.** `--cursor-file` is updated after every
  processed withdrawal via atomic tmp+rename. Restart-safe; rolling
  back the cursor only causes re-processing (which is idempotent
  end-to-end).
* **Polling interval.** Default 10 s. Lower bound is whatever the
  destination-chain RPCs tolerate; 5 s is usually fine for devnet,
  longer for production endpoints.
* **No metrics yet.** Logs via `tracing` are the operational
  surface today. A `/metrics` endpoint mirroring `seal-faucet`'s
  pattern is a follow-up if monitoring needs grow.

## Custody / mainnet gap

For mainnet the relayer needs:
* Fee reimbursement out of bridge fees or treasury, so validators
  don't pay gas indefinitely out of pocket.
* Slashing on no-relay or double-submission spam — the current
  per-validator trust model assumes operator honesty.
* HSM / KMS integration for the destination-chain keys instead of
  JSON files on disk.

None of those gate the testnet path.
