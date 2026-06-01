# Seal DAO Node Operator Guide

This guide covers running a Seal DAO validator node: hardware requirements,
building, single-node operation, multi-node testnet, VPN deployment, Docker,
monitoring, CLI reference, and security considerations.

---

## Table of Contents

1. [Hardware Requirements](#hardware-requirements)
2. [Building seal-node](#building-seal-node)
3. [Running a Single Node](#running-a-single-node)
4. [Running a Multi-Node Testnet](#running-a-multi-node-testnet)
5. [VPN Multi-Machine Setup](#vpn-multi-machine-setup)
6. [Docker Deployment](#docker-deployment)
7. [Monitoring and Persistence](#monitoring-and-persistence)
8. [CLI Flags Reference](#cli-flags-reference)
9. [Security](#security)

---

## Hardware Requirements

### Minimum (testnet / development)

| Resource | Requirement |
|----------|-------------|
| CPU | 2 cores |
| RAM | 4 GB |
| Disk | 20 GB SSD |
| Network | 10 Mbps |
| OS | Linux (x86_64), macOS (ARM64/x86_64) |

### Recommended (validator / production)

| Resource | Requirement |
|----------|-------------|
| CPU | 8+ cores (for ZK proof generation) |
| RAM | 32 GB |
| Disk | 500 GB NVMe SSD |
| Network | 100 Mbps |
| GPU | Optional: NVIDIA (CUDA), AMD (ROCm), or Apple Silicon (Metal) for GPU-accelerated proving |

Post-quantum cryptographic operations (ML-DSA signatures, lattice-based VRF)
are more computationally expensive than classical crypto. The recommended
spec accounts for this overhead.

---

## Building seal-node

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build (release mode recommended for production)
git clone https://github.com/seal-dao/seal-dao.git
cd seal-dao
cargo build --release -p seal-node

# The binary is at target/release/seal-node
ls -la target/release/seal-node
```

The release build takes a few minutes due to PQC library compilation. The
resulting binary is fully self-contained with no runtime dependencies.

---

## Running a Single Node

### Basic (10 slots, no RPC)

```bash
cargo run -p seal-node
```

This runs for 10 slots, creates a sample `users` table, and exits. Useful
for verifying the build works.

### Production (indefinite, with RPC)

```bash
cargo run --release -p seal-node -- --slots 0 --rpc-port 8545
```

Or using the release binary directly:

```bash
./target/release/seal-node --slots 0 --rpc-port 8545
```

This starts the node in indefinite mode with the JSON-RPC server on port 8545.

### With custom data directory

```bash
./target/release/seal-node --slots 0 --rpc-port 8545 --data-dir /var/seal/data
```

### With persistent validator identity

For a production / testnet operator setup, pass `--validator-key`
so restarts keep the same on-chain ML-DSA address (otherwise the
node generates a fresh keypair every start — fine for dev, broken
for any flow that depends on stable identity like portal
registration or on-chain reward accrual):

```bash
# Generate once, back it up offline:
./target/release/seal keygen --output /etc/seal/validator-keys.json
chmod 600 /etc/seal/validator-keys.json

./target/release/seal-node \
  --slots 0 \
  --port 4001 \
  --rpc-port 8545 \
  --data-dir /var/seal/data \
  --validator-key /etc/seal/validator-keys.json
```

`network` field in the keyfile is cross-checked against the running
node's HRP mode — running a `testnet` keyfile under `--mainnet` (or
vice versa) refuses at startup with a clear error.

### Verify the node is running

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_getHeight","params":{},"id":1}'
```

Expected response:

```json
{"jsonrpc":"2.0","result":{"height":5},"id":1}
```

---

## Running a Multi-Node Testnet

### Using the testnet script (recommended)

The `scripts/testnet.sh` script starts multiple nodes on localhost with
automatic peer discovery.

```bash
# Start 3 nodes (default)
./scripts/testnet.sh

# Start 5 nodes
./scripts/testnet.sh 5

# Stop all nodes
./scripts/testnet.sh stop
```

Each node gets:
- A unique P2P port (4001, 4002, 4003, ...)
- A unique RPC port (8545, 8546, 8547, ...)
- Its own data directory (`testnet-data/node-1/`, `testnet-data/node-2/`, ...)
- Node 1 acts as the bootstrap peer; other nodes connect to it

### Querying individual nodes

```bash
# Query node 1
curl -s localhost:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_getHeight","params":{},"id":1}'

# Query node 2
curl -s localhost:8546 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_getHeight","params":{},"id":1}'

# Query node 3
curl -s localhost:8547 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_getHeight","params":{},"id":1}'
```

### Viewing logs

```bash
tail -f testnet-data/node-1/stdout.log
tail -f testnet-data/node-2/stdout.log
```

### Manual multi-node setup

You can also start nodes manually with explicit bootstrap peers:

```bash
# Terminal 1: bootstrap node
./target/release/seal-node --slots 0 --port 4001 --rpc-port 8545 --data-dir node1-data

# Terminal 2: connect to bootstrap
./target/release/seal-node --slots 0 --port 4002 --rpc-port 8546 --data-dir node2-data \
  --bootstrap-peers /ip4/127.0.0.1/tcp/4001

# Terminal 3: connect to bootstrap
./target/release/seal-node --slots 0 --port 4003 --rpc-port 8547 --data-dir node3-data \
  --bootstrap-peers /ip4/127.0.0.1/tcp/4001
```

---

## VPN Multi-Machine Setup

For running validators across multiple physical machines (e.g., over a
WireGuard VPN or cloud VPC), use DNS multiaddrs for bootstrap peers.

### Example: 3 machines on a VPN

Assume three machines with hostnames `validator-1`, `validator-2`,
`validator-3` on a shared network (VPN or VPC).

**Machine 1 (bootstrap):**
```bash
./target/release/seal-node \
  --slots 0 \
  --port 4001 \
  --rpc-port 8545 \
  --data-dir /var/seal/data
```

**Machine 2:**
```bash
./target/release/seal-node \
  --slots 0 \
  --port 4001 \
  --rpc-port 8545 \
  --data-dir /var/seal/data \
  --bootstrap-peers /dns4/validator-1/tcp/4001
```

**Machine 3:**
```bash
./target/release/seal-node \
  --slots 0 \
  --port 4001 \
  --rpc-port 8545 \
  --data-dir /var/seal/data \
  --bootstrap-peers /dns4/validator-1/tcp/4001
```

### Multiple bootstrap peers

You can specify multiple bootstrap peers for redundancy:

```bash
./target/release/seal-node \
  --slots 0 \
  --port 4001 \
  --rpc-port 8545 \
  --data-dir /var/seal/data \
  --bootstrap-peers /dns4/validator-1/tcp/4001 \
  --bootstrap-peers /dns4/validator-2/tcp/4001
```

### Multiaddr formats

| Format | Example | Use case |
|--------|---------|----------|
| `/ip4/<addr>/tcp/<port>` | `/ip4/10.0.0.1/tcp/4001` | Direct IP (LAN/VPN) |
| `/dns4/<hostname>/tcp/<port>` | `/dns4/validator-1/tcp/4001` | DNS hostname (VPN/cloud) |
| `/ip6/<addr>/tcp/<port>` | `/ip6/::1/tcp/4001` | IPv6 |

---

## Docker Deployment

### Using Docker Compose (5-validator testnet)

The repository includes a `docker-compose.yml` for a 5-validator testnet.

```bash
# Start 5 validators
docker compose up

# Start in background
docker compose up -d

# Watch logs
docker compose logs -f

# Watch a specific node
docker compose logs -f node1

# Stop all nodes
docker compose down

# Stop and remove data volumes
docker compose down -v
```

### Docker environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SEAL_VALIDATOR_INDEX` | `0` | Validator index (0-based) |
| `SEAL_P2P_PORT` | `4001` | P2P listen port |
| `SEAL_CHAIN_ID` | `seal-testnet-docker` | Chain identifier |
| `SEAL_SLOTS_PER_EPOCH` | `32` | Slots per epoch |
| `SEAL_COMMITTEE_SIZE` | `5` | Committee size |
| `SEAL_VALIDATOR_COUNT` | `5` | Total validator count |
| `SEAL_LOG_LEVEL` | `info` | Log level |
| `RUST_LOG` | `seal_node=info,seal_p2p=debug` | Rust log filter |

### Building the Docker image

```bash
docker build -t seal-node .
```

### Running a single Docker node

```bash
docker run -d \
  --name seal-validator \
  -p 4001:4001 \
  -v seal-data:/data \
  seal-node
```

---

## Monitoring and Persistence

### Data Directory

The node stores all persistent data in the directory specified by `--data-dir`
(default: `seal-data/`).

```
seal-data/
  blocks.db          # Block database (append-only)
  stdout.log         # Node output (when run via testnet.sh)
```

### Disk Persistence

Blocks are persisted to disk as they are produced. On restart, the node
replays stored blocks to rebuild state:

```
Found 42 blocks on disk, replaying...
Replayed 42 blocks, height=42, state=a1b2c3...
```

### Checking Node Health

```bash
# Quick health check (GET, no JSON-RPC)
curl -s localhost:8545/health | jq .
# → {"status":"ok","height":42,"peers":5,"uptime_secs":3600}

# Rich status (GET, full node info)
curl -s localhost:8545/status | jq .

# Prometheus metrics (for Grafana scraping)
curl -s localhost:8545/metrics

# RPC: block height
curl -s localhost:8545 -d '{"jsonrpc":"2.0","method":"seal_getHeight","params":{},"id":1}'

# RPC: full node info
curl -s localhost:8545 -d '{"jsonrpc":"2.0","method":"seal_getNodeInfo","params":{},"id":1}'
```

### Monitoring Stack (Prometheus + Grafana)

```bash
# Start Prometheus + Grafana (auto-provisioned dashboards)
cd monitoring
docker-compose -f docker-compose.monitoring.yml up -d

# Grafana: http://localhost:3000 (admin/admin)
# Prometheus: http://localhost:9090
```

The `seal-node.json` dashboard shows: block production rate, tx throughput,
SQL operations, peer count, fee economics, and active storage leases.

### Web Block Explorer

```bash
# Open the explorer (connects to localhost:8545 by default)
open apps/seal-explorer-web/index.html

# Or with custom RPC URL:
open "apps/seal-explorer-web/index.html?rpc=http://node1.testnet.seal-dao.org:8545"
```

### Log Levels

Control logging with the `RUST_LOG` environment variable:

```bash
# Minimal logging
RUST_LOG=warn ./target/release/seal-node --slots 0 --rpc-port 8545

# Detailed P2P logging
RUST_LOG=seal_node=info,seal_p2p=debug ./target/release/seal-node --slots 0 --rpc-port 8545

# Full trace logging (very verbose)
RUST_LOG=trace ./target/release/seal-node --slots 0 --rpc-port 8545
```

---

## CLI Flags Reference

```
seal-node [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--slots <N>` | u64 | `10` | Number of consensus slots to run. `0` = run indefinitely |
| `--port <PORT>` | u16 | `4001` | P2P listen port (libp2p TCP) |
| `--rpc-port <PORT>` | u16 | `0` | JSON-RPC HTTP port. `0` = RPC disabled |
| `--bootstrap-peers <MULTIADDR>` | Multiaddr | none | Bootstrap peer address(es). Repeatable |
| `--serve <NAMESPACE>` | String | all | Serve only specific namespace(s). Repeatable |
| `--data-dir <PATH>` | String | `seal-data` | Directory for persistent block storage |
| `--no-network` | flag | off | Run in local-only mode (no P2P) |

### Examples

```bash
# Development: quick 10-slot run
seal-node

# Local validator: run forever with RPC
seal-node --slots 0 --rpc-port 8545

# Custom ports and data directory
seal-node --slots 0 --port 5001 --rpc-port 9545 --data-dir /mnt/seal

# Join existing network
seal-node --slots 0 --rpc-port 8545 --bootstrap-peers /dns4/seed.seal-dao.org/tcp/4001

# Serve specific namespace only
seal-node --slots 0 --rpc-port 8545 --serve myapp --serve payments

# Local mode (no networking, for testing)
seal-node --no-network
```

---

## Security

### RPC is Localhost-Only

The JSON-RPC server binds to `127.0.0.1` by default. It is **not** accessible
from external networks. This is intentional:

- RPC includes mutating endpoints (SQL writes, token transfers)
- Authenticated endpoints require ML-DSA signatures, but read endpoints are open
- Rate limiting (120 req/min per IP) is enforced but not a substitute for firewall rules

If you need external access to RPC:

1. Use a reverse proxy (nginx, caddy) with TLS and authentication
2. Use the PQ transport (`seal_pqHandshake`) for ML-KEM encrypted sessions
3. Never expose the raw RPC port to the public internet

### PQ Transport for Remote Access

For remote RPC over untrusted networks, Seal provides ML-KEM-based
post-quantum encrypted transport:

1. Client sends `seal_pqHandshake` with its ML-KEM public key
2. Server encapsulates a shared secret and returns the ciphertext
3. Subsequent requests are encrypted with the shared key
4. Monotonic nonces prevent replay attacks

### P2P Security

- All P2P communication uses libp2p with GossipSub
- ML-KEM native transport (`pq_transport.rs`) replaces Noise at the
  connection level for post-quantum security
- Peer identity is tied to the node's cryptographic keypair
- mDNS is used for local peer discovery; production deployments should
  use explicit bootstrap peers

### Slashing

Validators can be slashed for:
- **Double-proposal**: Proposing two different blocks for the same slot
- **Double-vote**: Voting for two different blocks in the same round

Slashing is enforced by the consensus protocol and results in stake reduction.

### Firewall Recommendations

| Port | Protocol | Expose | Purpose |
|------|----------|--------|---------|
| 4001 (P2P) | TCP | Yes (validators only) | libp2p peer-to-peer |
| 8545 (RPC) | TCP | No (localhost only) | JSON-RPC API |

```bash
# Example: allow P2P from known validators only
ufw allow from 10.0.0.0/24 to any port 4001 proto tcp
ufw deny 8545
```

## Bridge Unlock Relayer

For the **complete end-to-end testnet bring-up** (public-chain
deploy, flip to Ringtail mode, fund per-validator relayers,
multi-validator smoke, verify), see
[`docs/RUNBOOK-TESTNET-OPERATOR.md`](RUNBOOK-TESTNET-OPERATOR.md).
For 3 / 5 / 7-validator + variable bridge-committee sizing recipes,
see [`docs/TESTNET-VALIDATOR-SIZES.md`](TESTNET-VALIDATOR-SIZES.md).

If your validator handles bridge unlock submissions (the per-validator
custody model — every validator runs its own relayer + funded
destination-chain keys), see
[`apps/seal-relayer/README.md`](../apps/seal-relayer/README.md) for
the full bring-up checklist. Quick summary:

1. **Generate destination-chain wallets** (one per chain you'll relay):
   ```bash
   solana-keygen new -o /var/lib/seal/keys/solana-relayer.json
   stellar keys generate seal-relayer
   ```

2. **Fund each wallet** before pointing the relayer at a node — the
   relayer pays gas for every unlock it submits:
   ```bash
   ./scripts/bridge-faucet.sh sol $(solana address -k /var/lib/seal/keys/solana-relayer.json)
   ./scripts/bridge-faucet.sh xlm $(stellar keys address seal-relayer)
   ```
   Estimated funding for an 8-week testnet run: ~5 SOL devnet + ~100
   XLM testnet per validator. Public airdrops are rate-limited; top up
   gradually rather than in one shot.

3. **Configure + enable** the systemd unit:
   ```bash
   sudo install -m 600 apps/seal-relayer/relayer.env.example /etc/seal/relayer.env
   sudo $EDITOR /etc/seal/relayer.env  # set RPC URL, contract IDs, mint pubkeys, vault ATAs
   sudo install -m 644 apps/seal-relayer/seal-relayer.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now seal-relayer
   ```

4. **Verify** with `--dry-run` first if you want to confirm the relayer
   sees the right withdrawals before flipping on real submission.

You can opt out of either chain (omit the matching `--solana-*` or
`--stellar-*` flags entirely); other validators handle that chain
instead.
