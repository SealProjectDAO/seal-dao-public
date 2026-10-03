# Seal DAO — Quick Start

Pick the path that matches your needs. All paths work on a laptop with
no external infrastructure.

---

## TL;DR (3 commands)

### 1. Laptop-local bridge e2e — zero external deps
```bash
cd bridges && docker compose up -d
cd ../scripts && ./bridge-e2e.sh full
```
Builds the Docker image, brings up Solana test-validator + Stellar
quickstart + 3 Seal nodes, deploys bridge contracts on both chains,
runs the lock→mint→burn→unlock round trip on both legs. We just
confirmed 5/5 Anchor tests pass.

### 2. Public testnets (Solana devnet + Stellar testnet) — real RPCs
```bash
BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh both
```
Deploys Anchor program to devnet, Soroban contract to testnet, starts
3 local seal nodes with observers wired to public RPCs, runs full
round trip (forward + reverse) on both chains. Requires `BRIDGE_TESTNET_DEMO_LIVE=1`
to prevent accidental testnet fund spend.

### 3. Single-node dev — no Docker
```bash
cargo run -p seal-node          # Node on localhost:8545
./target/release/seal-cli demo  # Interactive REPL
```

---

## Deployment paths

| Path | Source chains | Docker | Cost | Use case |
|--|--|--|--|--|
| **bridge-e2e.sh full** | solana-test-validator + stellar/quickstart | Yes | None | Local dev, testing, CI |
| **bridge-testnet-demo.sh** | Solana devnet + Stellar testnet | No (local seal nodes) | Testnet airdrops | Public testnet validation |
| **bridge-testnet-deploy.sh** | Same as above | Yes | Testnet airdrops | Full lifecycle (deploy→up→demo→teardown) |
| **docker-compose up** | N/A (no bridge) | Yes | None | 3-5 validator Seal testnet only |

---

## Bridge deployment: full lifecycle

```bash
# One-shot: deploy contracts, start nodes, wire observers (public testnet)
./scripts/bridge-testnet-deploy.sh deploy

# Restart nodes only
./scripts/bridge-testnet-deploy.sh up

# Stop
./scripts/bridge-testnet-deploy.sh down

# Verify status
./scripts/bridge-testnet-deploy.sh status

# Run lock→mint flow
./scripts/bridge-testnet-deploy.sh demo

# Full teardown (stop + remove volumes)
./scripts/bridge-testnet-deploy.sh teardown
```

## Bridge e2e: local stack

```bash
# Build + bring up the full stack (Solana + Stellar + 3 Seal nodes)
cd bridges && docker compose up -d --build --wait

# Run the full round-trip test
cd ../scripts && ./bridge-e2e.sh full

# Skip build on subsequent runs (image already compiled)
SKIP_STACK_UP=1 ./bridge-e2e.sh full

# Reverse leg only (burn → unlock)
./bridge-e2e.sh reverse

# Tear down + wipe volumes
cd bridges && docker compose down -v
```

## State persistence

**Docker named volumes** persist chain state across restarts. The key:
- `docker compose down` — stops containers, **keeps volumes** (state persists)
- `docker compose down -v` — stops containers, **deletes volumes** (state wiped)

For the bridge stack:
- `seal-1-data`, `seal-2-data`, `seal-3-data` — Seal node chain state
- `solana-ledger` — Solana test-validator ledger
- `stellar-data` — Stellar node state

To restart with state: `docker compose down && docker compose up -d`
To start fresh: `docker compose down -v && docker compose up -d`

For the validator stack (docker-compose.yml):
- Each node has its own named volume (`seal-1-data`, `seal-2-data`, etc.)
- The `--validator-key` file must be persisted on the host and mounted
  into the container (see `docker-compose.yml` for the `SEAL_VALIDATOR_KEY`
  env var pattern). Without a persistent key, each restart generates a
  new validator identity.

---

## Faucets

| Chain | How to fund |
|--|--|
| **Solana devnet** | `solana airdrop 2 <pubkey> --url https://api.devnet.solana.com` |
| **Stellar testnet** | `curl 'https://friendbot.stellar.org/?addr=<G-addr>'` |
| **Seal testnet** | `curl -X POST <faucet-url>/faucet -d '{"address":"sealt1..."}'` |
| **All chains** | `./scripts/bridge-faucet.sh <chain> <address>` |

---

## Prerequisites

```bash
# Core
rustup target install wasm32v1-none          # Soroban contract
cargo install anchor-cli@0.30.1              # Solana Anchor program
solana install v1.18.26                      # Solana test-validator
stellar install v25.2.0                      # Stellar Soroban CLI

# Utilities
brew install jq curl starship                # macOS
apt install jq curl                          # Debian/Ubuntu
```

---

## Key docs

| Doc | What it covers |
|--|--|
| `QUICKSTART.md` (this file) | **You are here** — quick deploy, state management, faucets |
| `docs/BRIDGE-TESTNET.md` | **Full runbook** — all 7 steps, reverse, USDC, troubleshooting |
| `docs/RUNBOOK-TESTNET-OPERATOR.md` | Operator guide — deploy→Ringtail→fund relayers→multi-validator smoke |
| `docs/NODE-FAILURE-RECOVERY.md` | **Consensus liveness** — node crashes, partitions, slashing, replacement |
| `docs/BACKUP-RESTORE.md` | **Backup & restore** — chain state, keys, snapshots, disaster recovery |
| `docs/STATE-SYNC.md` | Snapshot protocol — bootstrap a fresh node without full replay |
| `docs/GUIDE-OPERATOR.md` | Validator node operator setup |
| `docs/GUIDE-DEVELOPER.md` | Developer environment setup |
| `docs/KEYS-KMS-BRIDGE-OPS.md` | Bridge key transfer, KMS pairing, withdrawal signing |
| `docs/KEYS-KMS-DESIGN.md` | KMS sidecar architecture, secure memory, trust store |
| `docs/TESTNET-VALIDATOR-SIZES.md` | 3/5/7-validator recipes and bridge committee shapes |
| `TESTNET.md` | Incentivized testnet program — timeline, hardware, rewards |
| `DEPLOY.md` | Basic single-node and multi-node deploy (simpler variant) |
| `MANUAL-TESTING.md` | Manual test recipes — bridge, governance, RPC, consensus |
| `PROBLEMS.md` | Open issues, all resolved |
| `LAUNCH-CHECKLIST.md` | Mainnet launch checklist |

---

## Common commands

```bash
# Check observer status
curl -s http://localhost:8645 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_listBridgeObservers","params":{}}'

# Force bridge event sweep
curl -s http://localhost:8645 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_pollBridges","params":{}}'

# Check withdrawal fee
curl -s http://localhost:8645 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getBridgeWithdrawalFee","params":{}}'

# Check committee key status
curl -s http://localhost:8645 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_bridgeGetCommitteeKeyStatus","params":{}}'

# Check wrapped balance
curl -s http://localhost:8645 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getBridgeWrappedBalance",
       "params":{"address":"sealt1...","token":"WSOL"}}'

# Check health/ready
curl -s http://localhost:8645/health
```
