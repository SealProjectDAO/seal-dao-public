# Seal DAO Incentivized Testnet Program

**Chain ID**: `seal-incentivized-testnet-1`
**Target Duration**: 8 weeks
**Target Validators**: 50-200

---

## Overview

The Incentivized Testnet is the final validation phase before mainnet. Validators
earn SEAL token rewards (redeemable at mainnet genesis) for participating in
network validation, stress testing, and bug reporting.

---

## Timeline

| Week | Phase | Focus |
|------|-------|-------|
| 1-2 | **Onboarding** | Validator registration, key generation, node setup |
| 3-4 | **Stability** | Consensus stability, epoch transitions, fork recovery |
| 5-6 | **Stress** | High TPS, large blocks, governance proposals, bridge tests |
| 7-8 | **Graduation** | Full feature validation, chaos testing, final audit fixes |

---

## Participation Requirements

### Minimum Hardware
- 4 CPU cores (8 recommended)
- 16 GB RAM (32 recommended)
- 500 GB NVMe SSD
- 100 Mbps network

### Software
- Linux (Ubuntu 22.04+ or Debian 12+) or macOS 14+
- Rust 1.82+ (for building from source)
- Docker (alternative: pre-built binaries)

### Validator Setup

```bash
# Option 1: Build from source
git clone https://github.com/seal-dao/seal-dao.git
cd seal-dao
cargo build --release -p seal-node -p seal-cli

# Generate the persistent validator identity. This same keyfile is
# the one you'll register on the portal AND pass to seal-node so
# restarts keep the same on-chain address + VRF state.
./target/release/seal keygen --output validator-keys.json

# Register the public key + VRF pubkey via the portal — see
# docs/TESTNET-REGISTRATION.md for the canonical curl recipe.

# Start the node. Real flags:
#   --port             P2P listen port (default 4001)
#   --rpc-port         JSON-RPC port  (0 = disabled, recommend 8545)
#   --rpc-external     bind RPC on 0.0.0.0 rather than 127.0.0.1
#   --bootstrap-peers  multiaddrs to dial on startup (repeat for more)
#   --data-dir         chain state directory (defaults to ./seal-data)
#   --validator-key    persistent ML-DSA validator identity file
#   --serve            namespace allowlist
./target/release/seal-node \
  --port 4001 \
  --rpc-port 8545 \
  --rpc-external \
  --data-dir ./seal-data \
  --validator-key validator-keys.json \
  --bootstrap-peers /dns4/boot1.testnet.seal-dao.org/tcp/4001

# Option 2: Docker. Use the versioned image from scripts/release.sh
# (see docs/RELEASE.md); a rolling `:testnet` tag is a release-pipeline
# convenience the ops team will publish per phase.
docker run -d \
  -v seal-data:/data \
  -v $(pwd)/validator-keys.json:/etc/seal/validator-keys.json:ro \
  -p 4001:4001 -p 8545:8545 \
  ghcr.io/seal-dao/seal-node:<release-tag> \
  --port 4001 --rpc-port 8545 --rpc-external \
  --data-dir /data \
  --validator-key /etc/seal/validator-keys.json \
  --bootstrap-peers /dns4/boot1.testnet.seal-dao.org/tcp/4001
```

### Identity persistence

`--validator-key <path>` loads a `seal keygen` JSON keyfile
(`{type, network, address, signing_key, verifying_key}`) and uses
it as the validator's on-chain ML-DSA identity. The same keyfile
across restarts yields the same address, the same deterministically-
derived VRF state, and the same signing keys — so the address you
registered on the portal IS the address the running node consensus-
signs with. Without the flag the node generates a fresh keypair at
every start (fine for local dev, restart-unsafe for testnet).

The keyfile carries a `network` field; running a `testnet` keyfile
on a `--mainnet` node (or vice versa) fails loud at startup rather
than silently signing on the wrong chain.

---

## Reward Structure

### Validator Rewards

Total testnet reward pool: **10,000,000 SEAL** (1% of initial supply),
drawn from the Public Distribution allocation.

| Activity | Reward | Cap |
|----------|--------|-----|
| Uptime (per epoch online) | 10 SEAL | 50,000 SEAL per validator |
| Block production | 5 SEAL per block proposed | No cap |
| Committee participation | 2 SEAL per vote | No cap |
| Bug reports (via Immunefi) | Per severity (see BUG-BOUNTY.md) | Per bounty table |
| Governance participation | 100 SEAL per proposal vote | 5,000 SEAL per validator |
| Stress test participation | 500 SEAL per event | 5 events |

### Bonus Multipliers

| Achievement | Multiplier |
|-------------|------------|
| 99%+ uptime (full 8 weeks) | 1.5x base rewards |
| Found critical bug | 2x base rewards |
| Top 10 block producers | 1.25x base rewards |
| Ran full archive node | 1.1x base rewards |

### Slashing (Testnet)

Testnet slashing reduces rewards but does not affect mainnet allocation:
- Double-proposal: -50% of accumulated rewards
- Double-vote: -50% of accumulated rewards
- Extended downtime (>24h without notification): -10% of accumulated rewards

---

## Genesis Configuration

**Consensus Parameters**:
- Slot duration: 4 seconds
- Slots per epoch: 128 (8.5 minutes per epoch)
- Committee size: min(50, total_validators)
- Finality threshold: 67%
- Min stake: 1,000 SEAL (testnet tokens)

**Token Allocation**:
- Validator faucet: 10,000 SEAL per registered validator
- Stress test fund: 1,000,000 SEAL
- Governance test fund: 500,000 SEAL

---

## Testnet Phases

### Phase 1: Onboarding (Weeks 1-2)

**Goals**: 50+ validators online, stable consensus

- [ ] Validator registration portal live
- [ ] Bootstrap nodes deployed (3 geographic regions)
- [ ] Faucet operational
- [ ] Block explorer connected
- [ ] Monitoring dashboards (Grafana) accessible

**Success criteria**: 48 hours of uninterrupted block production with 50+ validators.

### Phase 2: Stability (Weeks 3-4)

**Goals**: Epoch transitions, validator churn, fork recovery

- [ ] Successful epoch transitions (100+ epochs)
- [ ] Validator join/leave without consensus stall
- [ ] Fork recovery after simulated network partition
- [ ] VRF key rotation across epoch boundaries
- [ ] Slashing detection for injected equivocations

**Success criteria**: No consensus failures during planned chaos events.

### Phase 3: Stress Testing (Weeks 5-6)

**Goals**: High throughput, governance, bridge

- [ ] Sustained 1000 TPS for 1 hour
- [ ] Governance proposal lifecycle (create, vote, execute)
- [ ] Conviction voting with lock periods
- [ ] Bridge deposit/withdrawal cycle (testnet Solana + Stellar)
- [ ] SQL deployment and cross-app RLS queries
- [ ] Large block propagation (2 MB blocks)

**Success criteria**: No data loss, no state divergence, all invariants hold.

### Phase 4: Graduation (Weeks 7-8)

**Goals**: Final validation, chaos engineering, audit fix verification

- [ ] Chaos monkey: random validator kills, network delays, disk full
- [ ] State sync: new validator syncs from genesis to head
- [ ] Archive node: full history available
- [ ] Audit findings from Veridise + protocol audit remediated
- [ ] Extended fuzz campaign (24h per target) — no new crashes
- [ ] Community governance vote to "approve mainnet readiness"

**Success criteria**: 72 hours of stability under chaos conditions.

---

## Monitoring

- **Block explorer**: https://explorer.testnet.seal-dao.org (or local: `open apps/seal-explorer-web/index.html`)
- **Grafana dashboard**: https://grafana.testnet.seal-dao.org (or local: `cd monitoring && docker-compose -f docker-compose.monitoring.yml up`)
- **Validator leaderboard**: https://testnet.seal-dao.org/leaderboard
- **Status page**: https://status.testnet.seal-dao.org (node: `curl localhost:8545/status`)

### Local monitoring setup

```bash
# 1. Start node with RPC
cargo run -p seal-node -- --slots 0 --rpc-port 8545

# 2. Health check — pretty-printed, exit-code-driven (see below)
seal health
seal health --require-validator   # fail with exit 2 if pubkey not seated

# 3. Prometheus metrics (seal_*, seal_bridge_*, seal_faucet_*,
#    seal_registration_* — see monitoring/README.md for the full list)
curl localhost:8545/metrics

# 4. Start Grafana + Prometheus (includes the new bridge / faucet /
#    registration rows + auto-loaded alert rules from alert.rules.yml)
cd monitoring && docker-compose -f docker-compose.monitoring.yml up -d
# Grafana: http://localhost:3000 (admin/admin)

# 5. Web explorer (mirrors the Grafana bridge row in-browser)
open apps/seal-explorer-web/index.html
```

### `seal health` exit codes (for systemd / cron / docker HEALTHCHECK)

| Exit | Meaning |
|------|---------|
| 0 | `status: ok` and (when `--require-validator`) `is_validator: true` |
| 1 | `status: starting` (uptime <30 s) or `stalled` (>60 s up + peers but height=0) or unreachable RPC |
| 2 | `--require-validator` was passed but the node's pubkey is not seated in the active set |

### Bridge committee-key rotation (mid-testnet)

If the bridge committee key rolls, rotate without restart:

```bash
# 1. Council 2/3 vote rotation on each seal-node:
seal rpc --method seal_bridgeRotateCommitteeKey \
  --params "{\"new_key_hex\":\"$NEW_KEY\",\"approvers\":[\"pk1\",...]}"

# 2. Confirm both fingerprints match what the chain will hold:
seal bridge-key-status --expect-sha2 $EXPECTED_SHA256_HEX

# 3. Rotate the on-chain bridge programs (operator-side):
stellar contract invoke ... -- rotate_committee_key --new_key $NEW_KEY
anchor run rotate-committee-key -- --new-key $NEW_KEY

# 4. The rotation persists to <data_dir>/bridge-committee-key.hex,
#    so a node restart does NOT revert to the docker-compose CLI flag.
```

The `BridgeCommitteeKeyRotationNotPersisted` Prometheus alert fires
within 2 m if step 1 succeeds in-memory but the disk write fails.

For an extra structural check, bake the current expected
fingerprint into the systemd unit so a fresh start flags drift
before consensus traffic begins:

```bash
seal-node ... \
  --bridge-committee-key $KEY \
  --expect-committee-key-sha2 $(echo -n $KEY | xxd -r -p | sha256sum | awk '{print $1}')
```

A mismatch lands in the `=== Pre-flight warnings ===` block at
startup with a pointer at `seal_bridgeRotateCommitteeKey` for
re-alignment. `bridges/docker-compose.testnet.yml` already wires
this for the [0x11; 32] fixture key.

### Bridge unlock relayer (per-validator)

Every validator runs its own `seal-relayer` instance to auto-submit
destination-chain `unlock_*` claims for committee-signed withdrawals.
Custody model: per-validator (decided 2026-05-16). Multiple validators
race on each withdrawal; the deterministic
`SHA3-256(vk || withdrawal_id) % max_backoff_secs` back-off ensures
the lowest-delay one usually pays gas, races fold into the idempotent
`was_already_executed` no-op.

**One-time setup per validator host:**

```bash
# 1. Generate destination-chain wallets
solana-keygen new -o /var/lib/seal/keys/solana-relayer.json
stellar keys generate seal-relayer
stellar keys address seal-relayer > /var/lib/seal/keys/stellar-relayer.G

# 2. Fund them on each chain
./scripts/bridge-faucet.sh sol $(solana address -k /var/lib/seal/keys/solana-relayer.json)
./scripts/bridge-faucet.sh xlm $(cat /var/lib/seal/keys/stellar-relayer.G)

# 3. Install + enable systemd unit (full bring-up checklist in
#    apps/seal-relayer/README.md):
sudo install -m 755 target/release/seal-relayer /usr/local/bin/
sudo install -m 600 apps/seal-relayer/relayer.env.example /etc/seal/relayer.env
sudo $EDITOR /etc/seal/relayer.env  # set the contract IDs + mints
sudo install -m 644 apps/seal-relayer/seal-relayer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now seal-relayer
sudo journalctl -u seal-relayer -f
```

Estimated funding for an 8-week testnet run: ~5 SOL devnet + ~100 XLM
testnet per validator (covers a few hundred unlocks at current fees).
Devnet airdrops are rate-limited per IP — top up gradually rather than
in one shot.

To verify the relayer is seeing withdrawals before flipping on real
submission, start with `--dry-run` (set `ExecStart` to append it, or
test outside systemd first). Dry-run logs the intended submissions
without touching the destination chain or calling
`seal_bridgeMarkExecuted`.

---

## Communication

- **Discord**: #incentivized-testnet channel
- **Weekly calls**: Thursdays 16:00 UTC
- **Bug reports**: Immunefi (see BUG-BOUNTY.md)
- **Node issues**: GitHub Issues (non-security only)

---

## Transition to Mainnet

Testnet rewards are recorded on-chain and included in the mainnet genesis
block under the Public Distribution allocation. Validators who participate
in the incentivized testnet receive priority registration for mainnet
genesis validators.

See `LAUNCH-CHECKLIST.md` for the mainnet launch sequence.
