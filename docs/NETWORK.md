# Seal DAO Network Architecture

## P2P Layer

Seal uses **libp2p** for all peer-to-peer communication:
- **Transport**: TCP with Yamux multiplexing
- **Encryption**: Noise protocol (classical) + optional ML-KEM-768 (post-quantum)
- **Discovery**: mDNS (local) + bootstrap peers (public)
- **Messaging**: GossipSub pub/sub

### GossipSub Topics

| Topic | Purpose |
|-------|---------|
| `seal/blocks/1.0` | Block propagation |
| `seal/txs/1.0` | Transaction dissemination |
| `seal/committee-votes/1.0` | Committee voting messages |
| `seal/committee-sigs/1.0` | Threshold signature shares |
| `seal/epoch-transition/1.0` | Epoch transition announcements |

---

## Bootstrap Nodes

A bootstrap node is a regular `seal-node` with a known, stable address.
It serves as the initial meeting point for validators joining the network.

### How it works

```
Validator A ──┐
Validator B ──┼──> Bootstrap Node (VPS, port 4001) ──> nodes discover each other
Validator C ──┘
```

1. Bootstrap node starts first with a public IP
2. Other nodes connect using `--bootstrap-peers /ip4/<IP>/tcp/4001`
3. Once connected, nodes discover each other via GossipSub
4. The bootstrap node is NOT a bottleneck — after discovery, peers communicate directly
5. If the bootstrap node goes down, existing peers remain connected

### Running a bootstrap node

A bootstrap node is the same binary as any validator — no special build needed.

```bash
# On a VPS with public IP (e.g., 203.0.113.50). `--slots 0` runs forever
# (default is 10 = demo mode → exits). `--rpc-external` binds the JSON-
# RPC server on 0.0.0.0 rather than 127.0.0.1; omit on a privacy-
# sensitive host.
seal-node --slots 0 --port 4001 --rpc-port 8545 --rpc-external

# Or with Docker (replace <tag> with a release version from
# scripts/release.sh — see docs/RELEASE.md):
docker run -d -p 4001:4001 -p 8545:8545 \
  ghcr.io/seal-dao/seal-node:<tag> \
  --slots 0 --port 4001 --rpc-port 8545 --rpc-external
```

### Connecting validators to the bootstrap

```bash
# Other validators dial the bootstrap peer's multiaddr. Pass
# --validator-key for a persistent on-chain identity (see TESTNET.md
# "Identity persistence" for the keyfile format).
seal-node --slots 0 --port 4001 \
  --validator-key validator-keys.json \
  --bootstrap-peers /ip4/203.0.113.50/tcp/4001

# For DNS-based (if you have a domain)
seal-node --slots 0 --port 4001 \
  --validator-key validator-keys.json \
  --bootstrap-peers /dns4/boot1.testnet.seal-dao.org/tcp/4001
```

### Multiple bootstrap nodes

For redundancy, run 2-3 bootstrap nodes in different regions:

```bash
seal-node \
  --bootstrap-peers /ip4/203.0.113.50/tcp/4001 \
  --bootstrap-peers /ip4/198.51.100.10/tcp/4001 \
  --bootstrap-peers /ip4/192.0.2.30/tcp/4001
```

When the seed list is long or rotates often, point at a file
instead. One multiaddr per line; `#` comments and blank lines are
skipped; bad lines log a warning but don't fail startup.

```bash
# /etc/seal/testnet-seeds.txt
# Updated 2026-05-15 — see https://testnet.seal-dao.org/seeds
/dns4/boot1.testnet.seal-dao.org/tcp/4001
/dns4/boot2.testnet.seal-dao.org/tcp/4001
/dns4/boot3.testnet.seal-dao.org/tcp/4001

# Then start seal-node with:
seal-node --bootstrap-peers-file /etc/seal/testnet-seeds.txt
```

The `--bootstrap-peers-file` entries are appended to whatever
`--bootstrap-peers` flags were also passed, so you can mix a
local override with the public seed file.

### Local development (no VPS needed)

On a local network (LAN/VPN), mDNS handles discovery automatically:

```bash
# Machine 1
seal-node --slots 0 --port 4001

# Machine 2 (same LAN/VPN) — discovers Machine 1 via mDNS
seal-node --slots 0 --port 4002
```

For machines on a VPN (e.g., WireGuard, Tailscale), use the VPN IP:

```bash
# Machine 2 connects to Machine 1's VPN IP
seal-node --slots 0 --port 4001 \
  --bootstrap-peers /ip4/10.0.0.1/tcp/4001
```

---

## Network Configurations

### 1. Local devnet (single machine)

```bash
cargo run -p seal-cli -- dev --slots 100
```

No networking — single-node consensus with 1s slots.

### 2. Docker testnet (single machine, 5 validators)

```bash
docker compose up
```

5 validators on an internal Docker bridge network (`sealnet`).
mDNS discovery within the container network.

### 3. VPN multi-machine testnet

For testing across multiple physical machines on a VPN:

```bash
# Machine 1 (bootstrap + validator)
seal-node --slots 0 --port 4001 --rpc-port 8545 --rpc-external

# Machine 2
seal-node --slots 0 --port 4001 \
  --bootstrap-peers /ip4/<machine1-vpn-ip>/tcp/4001

# Machine 3
seal-node --slots 0 --port 4001 \
  --bootstrap-peers /ip4/<machine1-vpn-ip>/tcp/4001
```

There is no `--validator-index` flag; each node has its own ML-DSA
identity. Pass `--validator-key <path>` on each machine to pin
identities across restarts (see TESTNET.md "Identity persistence"
for the keyfile format).

### 4. Public testnet (VPS)

Minimum infrastructure: 1 VPS ($5/mo) as bootstrap node.
Validators connect from anywhere.

```bash
# VPS (bootstrap)
seal-node --slots 0 --port 4001 --rpc-port 8545 --rpc-external

# Validators (anywhere with internet)
seal-node --slots 0 --port 4001 \
  --validator-key validator-keys.json \
  --bootstrap-peers /ip4/<vps-public-ip>/tcp/4001
```

---

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 4001 | TCP | P2P (libp2p GossipSub) |
| 8545 | TCP | JSON-RPC (planned) |
| 9090 | TCP | Prometheus metrics (planned) |

---

## Security

- All P2P traffic is encrypted (Noise protocol)
- Optional double encryption with ML-KEM-768 (post-quantum)
- Validators authenticate via ML-DSA signatures on blocks/votes
- No unauthenticated RPC endpoints (planned RPC will require API keys)
