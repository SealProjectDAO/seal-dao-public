# Seal DAO — Deployment Guide

## Single Node (Development)

```bash
# Build
cargo build --release -p seal-node -p seal-app -p seal-cli

# Run node (networked, listens for peers)
./target/release/seal-node

# Run node (local only, no P2P)
./target/release/seal-node --no-network

# Run REPL
./target/release/seal-repl

# Run CLI
./target/release/seal help
./target/release/seal demo
```

## Multi-Node Testnet (Docker)

```bash
# Build Docker image
docker build -t seal-node .

# Run 3-node testnet
docker-compose up

# Watch logs
docker-compose logs -f

# Stop
docker-compose down
```

The 3 nodes share a Docker bridge network and discover each other via mDNS.

## Multi-Node Testnet (Manual)

```bash
# Terminal 1: Node A
cargo run -p seal-node

# Terminal 2: Node B (discovers A via mDNS on same LAN)
cargo run -p seal-node

# Terminal 3: Node C
cargo run -p seal-node
```

Nodes automatically discover each other via mDNS on the local network.
Blocks are broadcast via GossipSub.

## Persistent Node

Data is stored in sled databases. To persist across restarts:

```bash
# The PersistentNode stores blocks to disk and replays on startup.
# Currently used programmatically (not yet exposed via CLI flag).
# See crates/seal-node/src/persistent.rs for the API.
```

## Wallet Management

```bash
# The wallet is created automatically on node start.
# To save/load a wallet (programmatic API):
# See crates/seal-wallet/src/storage.rs
#   save_wallet(&wallet, "wallet.json")
#   load_wallet("wallet.json")
```

## Configuration

Default consensus parameters (adjustable via governance):

| Parameter | Default | Description |
|-----------|---------|-------------|
| Slot time | 4 seconds | Time per consensus slot |
| Epoch length | 256 slots | ~17 minutes per epoch |
| Committee size | 100 | VRF-selected voters per slot |
| Finality threshold | 67% | >2/3 committee for finality |
| Fee per byte | 10 micro-SEAL | Transaction fee rate |
| Fee burn | 50% | Portion of fees burned |

## Monitoring

```bash
# Run with tracing
RUST_LOG=info cargo run -p seal-node

# Detailed logging
RUST_LOG=debug cargo run -p seal-node

# Only consensus events
RUST_LOG=seal_node::consensus_runner=info cargo run -p seal-node
```

## Prerequisites

- Rust 1.75+ (install: https://rustup.rs)
- Docker (optional, for multi-node testnet)
- ~500MB disk space for build
- ~50MB RAM per node (development mode)
