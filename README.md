<p align="center">
  <img src="assets/seal-logo.png" alt="Seal DAO" width="140">
</p>

<h1 align="center">Seal DAO</h1>

<p align="center">
  <strong>Post-quantum secure blockchain with a native distributed SQL database</strong>
</p>

<p align="center">
  <code>PHP+MySQL but on-chain</code> &mdash; deploy SQL schemas as decentralized apps, query with PostgreSQL syntax, secured by NIST post-quantum cryptography.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.94.1-orange?logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/tests-996_passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/crypto-ML--DSA--65_%7C_ML--KEM--768_%7C_SHA3-blue" alt="PQC">
  <img src="https://img.shields.io/badge/ZK-RISC_Zero_%7C_SP1-purple" alt="ZK">
  <img src="https://img.shields.io/badge/license-Apache--2.0-lightgrey" alt="License">
</p>

---

## Recent updates (2026-04-23 interim)

- **Dev faucet** — `seal-node --dev-faucet` flag + `seal_faucet` RPC +
  `seal faucet` one-shot CLI. Drips test SEAL to any `sealt1…` address
  (1000 SEAL / 24 h per-address cap, off by default).
- **Flat-CLI one-shots** for scripts and bridge-testnet work —
  `seal transfer / faucet / balance` take `--key key.json --node URL`
  without driving the TUI. Generic `seal rpc --method --params [--key]`
  passthrough covers every other signed RPC (bridge, governance, token
  setup). Amounts accept base-units, decimals, or a `SEAL` suffix
  (`100`, `100.0`, `"100 SEAL"`).
- **Critical address-derivation fix** — `authenticate()` on the node
  used to derive a different `seal1<hex>` address than the wallet's
  canonical `bech32m` one; every signed transfer silently debited a
  ghost account. Now both sides use
  `SealAddress::from_verifying_key(vk, testnet).to_string_encoding()`.
- **Address + token validation** on `handle_transfer` and
  `handle_get_token_balance` — malformed `sealt1…` strings and
  unknown token symbols now produce clean `-32602` errors instead of
  silently creating ghost accounts or returning permissive zeros.
- **SQL-replay ordering fix** — `seal-node` replay now runs before
  the demo seed, so restarting a node with a populated `seal-data`
  dir no longer dies at block 1 with `table already exists: users`.
- **Docker bring-up hardening** (`bridges/docker-compose.testnet.yml` +
  root `Dockerfile`) — Rust base bumped to `1.94-bookworm` for
  `edition2024`/`icu_*` MSRV, Solana healthcheck switched to
  `solana cluster-version` (the image ships without curl), Stellar
  CLI updated to drop the removed `--enable-horizon --enable-core`
  flags.
- **Electron wallet** — lock / unlock / change-passphrase / reset
  flows landed; DEX-pairs `[object Object]` fix.
- **CI** — `./scripts/ci.sh` (full): build ✓ · 996 tests ✓ · clippy ✓ ·
  Kani 66 harnesses across 6 crates ✓ · Miri skipped (no `unsafe`) ·
  9 fuzz targets × 15 s (430k–3M runs each) ✓ · cargo-audit ✓ with
  `RUSTSEC-2026-0104` acknowledged in `.cargo/audit.toml` pending a
  vendor refresh (see `TODOS/SESSION-2026-04-23.md`).

**Manual-testing coverage for this interim release:** §1 through §16
of `MANUAL-TESTING.md` were driven end-to-end. §17–§25 (bridge RPC,
SQL/DEX/MPC/ZK/gov over RPC, Ringtail BPF, procedures runtime,
forms.seal, new demo apps) are documented with corrected commands
but **not all exercised** in this session — bridge stack is
bring-up-ready (Solana + Stellar healthy) but the full lock-mint-burn-
unlock round-trip was paused. Full session handoff:
[`TODOS/SESSION-2026-04-23.md`](TODOS/SESSION-2026-04-23.md).

---

## Quick Start

```bash
cargo build                          # Build all 17 crates
cargo test                           # Run 1100+ tests (some crates need `--lib`)
cargo run -p seal-node -- \
  --slots 0 --rpc-port 8545 --dev-faucet   # Start a node (P2P + RPC + dev faucet)
cargo run -p seal-cli -- wallet      # Interactive TUI wallet
cargo run -p seal-cli -- demo        # Multi-app demo
```

```bash
# Fund a wallet from scratch (requires --dev-faucet on the node):
cargo run -p seal-cli -- keygen --output key.json
cargo run -p seal-cli -- faucet --node http://localhost:8545 --key key.json
cargo run -p seal-cli -- balance --node http://localhost:8545 --key key.json
cargo run -p seal-cli -- transfer sealt1<recipient> 10.5 SEAL \
    --node http://localhost:8545 --key key.json
```

```bash
# Query from anywhere
curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_querySql","params":{"sql":"SELECT * FROM users"},"id":1}'
```

---

## Features

| | Feature | Details |
|---|---------|---------|
| **PQC** | Post-quantum crypto | ML-DSA-65 + ML-KEM-768 + SHA3-256 (libcrux, formally verified) |
| **SQL** | PostgreSQL-compatible | CREATE TABLE, SELECT, INSERT, UPDATE, DELETE, JOINs, RLS policies |
| **VRF** | Algorand consensus | VRF leader election, committee voting, single-slot finality |
| **ZK** | Verifiable proofs | RISC Zero & SP1 STARK backends, GPU acceleration |
| **DEX** | On-chain exchange | Limit order book, custom tokens, create-pair, place-order |
| **P2P** | Multi-node sync | libp2p GossipSub, ML-KEM encrypted transport, mDNS |
| **MPC** | Private compute | SPDZ aggregation on encrypted data (sum, avg, count) |
| **Gov** | Three-body governance | Token House + Technical Council + Service Operators |
| **Bridge** | Cross-chain | Solana + Stellar lock-and-mint bridge |
| **Wallet** | Multi-platform | TUI, Electron/WASM, Android (ML-DSA signing, BIP-39 recovery) |

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

| Platform | Command | Features |
|----------|---------|----------|
| **TUI** | `cargo run -p seal-cli -- wallet` | Full: SQL, tokens, DEX, MPC, ZK proofs |
| **Electron** | `cd apps/seal-wallet && npm install && npm run electron` | WASM crypto, LOB visualization, signed RPC |
| **Android** | `./apps/seal-wallet-android/build-android.sh` | ML-DSA signing, hex/BIP-39 import |

---

## Verification

| Tool | What it proves | Status |
|------|----------------|--------|
| **cargo test** | 804 unit + integration + property tests | All pass |
| **Kani** | Bounded model checking (16 harnesses) | All pass |
| **Miri** | Undefined behavior detection | Pass |
| **cargo-fuzz** | Crash-free on random input (9 targets) | 0 crashes |
| **TLA+** | Consensus safety & liveness (6 invariants) | Verified |
| **Lean 4** | Merkle tree + VRF correctness | Proven |
| **Rocq/Coq** | Token conservation, RLS non-bypass | 0 Admitted |

```bash
./scripts/ci.sh quick    # build + 804 tests + clippy (~2 min)
./scripts/ci.sh          # + Kani + Miri + fuzz + audit (~5 min)
```

---

## Documentation

| Document | Contents |
|----------|----------|
| [SPEC.md](SPEC.md) | Full technical specification (1400+ lines) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Crate dependency graph + data flow |
| [TESTING.md](TESTING.md) | All 804 tests documented |
| [SECURITY.md](SECURITY.md) | Threat model + attack surfaces |
| [GOVERNANCE.md](GOVERNANCE.md) | Three-body governance spec |
| [FORMAL-METHODS.md](FORMAL-METHODS.md) | Verification tool survey + plan |
| [docs/TESTING.md](docs/TESTING.md) | Manual testing guide (21 sections) |
| [DEPLOY.md](DEPLOY.md) | How to run nodes |
| [docs/RUNBOOK-TESTNET-OPERATOR.md](docs/RUNBOOK-TESTNET-OPERATOR.md) | End-to-end testnet operator runbook (deploy + Ringtail flip + fund + smoke) |
| [docs/TESTNET-VALIDATOR-SIZES.md](docs/TESTNET-VALIDATOR-SIZES.md) | 3 / 5 / 7-validator recipes + variable bridge-committee sizing |
| [docs/BRIDGE-USDC-VENUES.md](docs/BRIDGE-USDC-VENUES.md) | Where wrapped USDC produced by the bridge is liquid (CEX + DEX, regional) |
| [docs/CRYPTO-HOSTING-PROVIDERS.md](docs/CRYPTO-HOSTING-PROVIDERS.md) | Hosting providers that accept SOL/XLM/USDC/ETH/BTC, pricing vs AWS/Azure/GCP |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |

---

## RPC API (27 methods)

<details>
<summary>Expand method list</summary>

| Method | Auth | Description |
|--------|------|-------------|
| `seal_querySql` | No | Read-only SQL |
| `seal_submitSql` | ML-DSA | Write SQL (INSERT/UPDATE/DELETE) |
| `seal_getHeight` | No | Chain height |
| `seal_getStateRoot` | No | State root hash |
| `seal_getBlock` | No | Block by height |
| `seal_getBalance` | No | SEAL balance |
| `seal_transfer` | ML-DSA | Transfer SEAL tokens |
| `seal_createToken` | ML-DSA | Create custom token |
| `seal_mintToken` | ML-DSA | Mint tokens |
| `seal_transferToken` | ML-DSA | Transfer custom token |
| `seal_listTokens` | No | List all tokens |
| `seal_createPair` | ML-DSA | Create DEX pair |
| `seal_placeOrder` | ML-DSA | Place limit order |
| `seal_cancelOrder` | ML-DSA | Cancel order |
| `seal_getOrderBook` | No | Order book depth |
| `seal_listPairs` | No | List DEX pairs |
| `seal_deployNamespace` | ML-DSA | Deploy app namespace |
| `seal_mpcAggregate` | Optional | MPC aggregate (sum/count/avg) |
| `seal_zkProve` | Optional | ZK proof generation |
| `seal_pqHandshake` | No | ML-KEM key exchange |

</details>

---

## License

Apache-2.0
