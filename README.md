<p align="center">
  <img src="assets/seal-logo.png" alt="Seal DAO" width="140">
</p>

<h1 align="center">Seal DAO</h1>

<p align="center">
  <strong>Post-quantum secure blockchain with a native distributed SQL database</strong>
</p>

<p align="center">
  <code>PHP+MySQL but on-chain</code> — deploy SQL schemas as decentralized apps, query with PostgreSQL syntax, secured by NIST post-quantum cryptography.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-stable-orange?logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/tests-804_passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/crypto-ML--DSA--65_%7C_ML--KEM--768_%7C_SHA3-blue" alt="PQC">
  <img src="https://img.shields.io/badge/ZK-RISC_Zero_%7C_SP1-purple" alt="ZK">
  <img src="https://img.shields.io/badge/license-Apache--2.0-lightgrey" alt="License">
</p>

---

## Quick Start

```bash
cargo build                          # Build all 17 crates
cargo test                           # Run 804 tests
cargo run -p seal-node -- \
  --slots 0 --rpc-port 8545          # Start a node (P2P + RPC)
cargo run -p seal-cli -- wallet      # Interactive TUI wallet
cargo run -p seal-cli -- demo        # Multi-app demo
```

```bash
# Query from anywhere
curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_querySql","params":{"sql":"SELECT * FROM users"},"id":1}'
```

---

## Features

|                  | Feature               | Details                                                           |
| ---------------- | --------------------- | ----------------------------------------------------------------- |
| **PQC**    | Post-quantum crypto   | ML-DSA-65 + ML-KEM-768 + SHA3-256 (libcrux, formally verified)    |
| **SQL**    | PostgreSQL-compatible | CREATE TABLE, SELECT, INSERT, UPDATE, DELETE, JOINs, RLS policies |
| **VRF**    | Algorand consensus    | VRF leader election, committee voting, single-slot finality       |
| **ZK**     | Verifiable proofs     | RISC Zero & SP1 STARK backends, GPU acceleration                  |
| **DEX**    | On-chain exchange     | Limit order book, custom tokens, create-pair, place-order         |
| **P2P**    | Multi-node sync       | libp2p GossipSub, ML-KEM encrypted transport, mDNS                |
| **MPC**    | Private compute       | SPDZ aggregation on encrypted data (sum, avg, count)              |
| **Gov**    | Three-body governance | Token House + Technical Council + Service Operators               |
| **Bridge** | Cross-chain           | Solana + Stellar lock-and-mint bridge                             |
| **Wallet** | Multi-platform        | TUI, Electron/WASM, Android (ML-DSA signing, BIP-39 recovery)     |

---

## Architecture

```
seal-crypto ──┐
seal-vrf ─────┤
seal-threshold┤
              ├── seal-consensus ──┐
seal-sql ─────┤                    ├── seal-node ── seal-cli
seal-merkle ──┤                    │
seal-storage ─┘                    │
seal-token ────────────────────────┤
seal-p2p ──────────────────────────┤
seal-zk (RISC Zero | SP1) ────────┤
seal-mpc ──────────────────────────┤
seal-bridge ───────────────────────┘
```

---

## Wallets

| Platform           | Command                                                    | Features                                   |
| ------------------ | ---------------------------------------------------------- | ------------------------------------------ |
| **TUI**      | `cargo run -p seal-cli -- wallet`                        | Full: SQL, tokens, DEX, MPC, ZK proofs     |
| **Electron** | `cd apps/seal-wallet && npm install && npm run electron` | WASM crypto, LOB visualization, signed RPC |
| **Android**  | `./apps/seal-wallet-android/build-android.sh`            | ML-DSA signing, hex/BIP-39 import          |

---

## Verification

| Tool                 | What it proves                             | Status     |
| -------------------- | ------------------------------------------ | ---------- |
| **cargo test** | 804 unit + integration + property tests    | All pass   |
| **Kani**       | Bounded model checking (16 harnesses)      | All pass   |
| **Miri**       | Undefined behavior detection               | Pass       |
| **cargo-fuzz** | Crash-free on random input (9 targets)     | 0 crashes  |
| **TLA+**       | Consensus safety & liveness (6 invariants) | Verified   |
| **Lean 4**     | Merkle tree + VRF correctness              | Proven     |
| **Rocq/Coq**   | Token conservation, RLS non-bypass         | 0 Admitted |

```bash
./scripts/ci.sh quick    # build + 804 tests + clippy (~2 min)
./scripts/ci.sh          # + Kani + Miri + fuzz + audit (~5 min)
```

---

## RPC API (27 methods)

<details>
<summary>Expand method list</summary>

| Method                   | Auth     | Description                      |
| ------------------------ | -------- | -------------------------------- |
| `seal_querySql`        | No       | Read-only SQL                    |
| `seal_submitSql`       | ML-DSA   | Write SQL (INSERT/UPDATE/DELETE) |
| `seal_getHeight`       | No       | Chain height                     |
| `seal_getStateRoot`    | No       | State root hash                  |
| `seal_getBlock`        | No       | Block by height                  |
| `seal_getBalance`      | No       | SEAL balance                     |
| `seal_transfer`        | ML-DSA   | Transfer SEAL tokens             |
| `seal_createToken`     | ML-DSA   | Create custom token              |
| `seal_mintToken`       | ML-DSA   | Mint tokens                      |
| `seal_transferToken`   | ML-DSA   | Transfer custom token            |
| `seal_listTokens`      | No       | List all tokens                  |
| `seal_createPair`      | ML-DSA   | Create DEX pair                  |
| `seal_placeOrder`      | ML-DSA   | Place limit order                |
| `seal_cancelOrder`     | ML-DSA   | Cancel order                     |
| `seal_getOrderBook`    | No       | Order book depth                 |
| `seal_listPairs`       | No       | List DEX pairs                   |
| `seal_deployNamespace` | ML-DSA   | Deploy app namespace             |
| `seal_mpcAggregate`    | Optional | MPC aggregate (sum/count/avg)    |
| `seal_zkProve`         | Optional | ZK proof generation              |
| `seal_pqHandshake`     | No       | ML-KEM key exchange              |

</details>

---

## License

Apache-2.0
