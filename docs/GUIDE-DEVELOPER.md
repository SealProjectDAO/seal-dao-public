# Seal DAO Developer Guide

This guide covers building Seal DAO from source, understanding the codebase,
writing SQL applications, using the JSON-RPC API, creating tokens, working
with MPC/ZK features, building browser apps with WASM, and contributing.

---

## Table of Contents

1. [Building from Source](#building-from-source)
2. [Project Structure](#project-structure)
3. [Writing SQL Applications](#writing-sql-applications)
4. [JSON-RPC API Reference](#json-rpc-api-reference)
5. [Creating Custom Tokens](#creating-custom-tokens)
6. [MPC and ZK Features](#mpc-and-zk-features)
7. [WASM SDK for Browser Apps](#wasm-sdk-for-browser-apps)
8. [Running Tests and CI](#running-tests-and-ci)
9. [Contributing Guidelines](#contributing-guidelines)

---

## Building from Source

### Prerequisites

- Rust 1.80+ (install via [rustup](https://rustup.rs/))
- A C compiler (gcc or clang)
- Optional: Docker (for multi-node testnet)

### Build

```bash
# Clone the repository
git clone https://github.com/seal-dao/seal-dao.git
cd seal-dao

# Build all crates (debug)
cargo build

# Build in release mode
cargo build --release

# Run all tests (785+ tests)
cargo test

# Run the node
cargo run -p seal-node

# Run the CLI demo
cargo run -p seal-cli -- demo
```

### Quick Smoke Test

```bash
# Start a local node with RPC enabled, run for 10 slots
cargo run -p seal-node -- --slots 10 --rpc-port 8545

# In another terminal, query the node
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_getHeight","params":{},"id":1}'
```

---

## Project Structure

Seal DAO is a Rust workspace with 17 crates, example apps, SDKs, and
formal verification code.

### Crates (`crates/`)

| Crate | Purpose |
|-------|---------|
| `seal-crypto` | PQC primitives: ML-DSA signatures, ML-KEM key encapsulation, SHA3 hashing, addresses |
| `seal-vrf` | Verifiable Random Functions: PQ-VRF (lattice-based), LaV many-time VRF, HMAC-VRF stub |
| `seal-merkle` | Merkle tree for state roots, incremental O(log n) updates |
| `seal-sql` | PostgreSQL-compatible SQL engine (parser, planner, executor, RLS) |
| `seal-storage` | Block store, persistent red-black tree indexes, HAMT account state |
| `seal-consensus` | Algorand-style VRF+committee consensus, epoch management, slashing |
| `seal-p2p` | libp2p networking: GossipSub, mDNS, ML-KEM PQ transport |
| `seal-token` | Token economics: balances, emission schedule, fees, treasury, DEX orderbook |
| `seal-threshold` | Ringtail threshold signatures with NTT acceleration, Shamir secret sharing |
| `seal-zk` | ZK proof system: RISC Zero + SP1 provers, GPU acceleration, batch proofs |
| `seal-mpc` | Multi-party computation: SPDZ aggregation, Private Set Intersection |
| `seal-bridge` | Cross-chain bridges: Solana, Stellar, chain observer traits |
| `seal-wallet` | Wallet library: BIP-39 mnemonics, keystore, ML-DSA key management |
| `seal-tee` | TEE attestation: Intel TDX, AMD SEV-SNP, NVIDIA CC verification |
| `seal-node` | Full node binary: consensus runner, RPC server, disk persistence, mempool |
| `seal-app` | Application framework: namespace deployment, migration tools |
| `seal-cli` | CLI binary: `seal` command with wallet, demo, migrate, dev subcommands |

### Other Directories

| Path | Contents |
|------|----------|
| `apps/seal-wallet/` | Electron desktop wallet (HTML/JS + WASM) |
| `apps/seal-wallet-android/` | Android wallet (Rust + Kotlin) |
| `apps/seal-explorer/` | egui block explorer GUI |
| `sdks/js/` | JavaScript SDK scaffold |
| `sdks/python/` | Python SDK scaffold |
| `sdks/wasm/` | Rust-to-WASM SDK for browser apps |
| `bridges/solana/` | Anchor program for Solana bridge |
| `bridges/stellar/` | Soroban contract for Stellar bridge |
| `formal/` | Formal verification: TLA+, Lean 4, Rocq/Coq, Kani harnesses |
| `fuzz/` | cargo-fuzz targets (9 fuzz targets) |
| `scripts/` | CI, testnet, verification, and build scripts |
| `examples/` | Example apps: `seal-notes`, `seal-marketplace` |
| `audits/` | Security audit scope documents |

---

## Writing SQL Applications

Seal DAO provides a PostgreSQL-compatible SQL engine as a first-class feature.
Applications are deployed as SQL schemas within namespaces.

### Concepts

- **Namespace**: An isolated schema scope (like a PostgreSQL schema). Each app
  gets its own namespace.
- **RLS (Row-Level Security)**: PostgreSQL-style `CREATE POLICY` for fine-grained
  access control on table rows.
- **State root**: Every SQL write is reflected in the Merkle state root,
  providing cryptographic proof of database state.

### Deploying an App

```bash
# Deploy a namespace via CLI
seal app deploy --namespace myapp --schema schema.sql

# Or via RPC
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "method":"seal_deployNamespace",
    "params":{"namespace":"myapp","schema":"CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT, price BIGINT)"},
    "signature":"<hex>",
    "sender":"<pubkey_hex>",
    "id":1
  }'
```

### SQL Operations via RPC

**Write (requires ML-DSA signature):**

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "method":"seal_submitSql",
    "params":{"sql":"INSERT INTO items (id, name, price) VALUES (1, '\''Widget'\'', 500)"},
    "signature":"<hex>",
    "sender":"<pubkey_hex>",
    "id":1
  }'
```

**Read (no signature required):**

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_querySql","params":{"sql":"SELECT * FROM items WHERE price > 100"},"id":1}'
```

### Row-Level Security

RLS is driven through SQL DDL via `seal_submitSql`, not through dedicated
JSON-RPC methods. The supported PostgreSQL-shape statements are
documented in `crates/seal-sql/src/rls.rs`:

```bash
# Enable RLS on a table — wrapped in seal_submitSql so the ML-DSA
# signature binds the caller as the DDL initiator.
seal sql "ALTER TABLE items ENABLE ROW LEVEL SECURITY" \
    --node http://localhost:8545 --key alice.json

# Add a policy. Predicates use SQL expressions over the row + a
# small set of built-ins (current_user, has_kyc(<tier>), etc.).
seal sql "CREATE POLICY owner_only ON items FOR SELECT \
          USING (owner = current_user)" \
    --node http://localhost:8545 --key alice.json
```

Equivalent raw curl (object-param `seal_submitSql` with the same
canonicalized envelope `seal sql` builds):

```bash
curl -s localhost:8545 -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"seal_submitSql",
  "params":{"sql":"ALTER TABLE items ENABLE ROW LEVEL SECURITY"},
  "signature":"<ML-DSA hex>","sender":"<verifying-key hex>"
}'
```

(Earlier revisions of this guide showed `seal_enableRls` /
`seal_addPolicy` as dedicated RPCs. No handler was ever wired —
they returned `-32601 method not found` after passing auth. The
entries have been removed from `requires_auth`; use the SQL DDL
above instead.)

### Supported SQL

The SQL dialect is a subset of PostgreSQL:

- **DDL**: `CREATE TABLE`, `DROP TABLE`, `ALTER TABLE`
- **DML**: `INSERT`, `UPDATE`, `DELETE`, `SELECT`
- **Types**: `BIGINT`, `INTEGER`, `SMALLINT`, `TEXT`, `BOOLEAN`, `BYTEA`
- **Constraints**: `PRIMARY KEY`, `NOT NULL`, `UNIQUE`
- **Queries**: `WHERE`, `ORDER BY`, `LIMIT`, `JOIN`, `GROUP BY`, `HAVING`
- **Aggregates**: `COUNT`, `SUM`, `AVG`, `MIN`, `MAX`

---

## JSON-RPC API Reference

The RPC server listens on `http://127.0.0.1:<port>` (localhost only). All
requests use JSON-RPC 2.0 format. Mutating methods require ML-DSA signature
authentication.

### Authentication

Mutating methods require two extra fields in the JSON-RPC request:

- `signature`: Hex-encoded ML-DSA-65 signature of `SHA3(method + params_json)`
- `sender`: Hex-encoded ML-DSA-65 verifying key (public key)

### Rate Limiting

- 120 requests per IP per minute
- 64 KB maximum query size

### Methods

#### SQL Operations

| Method | Auth | Description |
|--------|------|-------------|
| `seal_submitSql` | Yes | Execute a SQL write (INSERT/UPDATE/DELETE/CREATE) |
| `seal_querySql` | No | Execute a read-only SQL query (SELECT) |
| `seal_deployNamespace` | Yes | Deploy a namespace with an initial schema |

**`seal_submitSql`**
```json
{"jsonrpc":"2.0","method":"seal_submitSql","params":{"sql":"INSERT INTO users (id, name) VALUES (3, 'carol')"},"signature":"...","sender":"...","id":1}
```
Response: `{"result":{"rows_affected":1}}`

**`seal_querySql`**
```json
{"jsonrpc":"2.0","method":"seal_querySql","params":{"sql":"SELECT * FROM users"},"id":1}
```
Response: `{"result":{"columns":["id","name","balance"],"rows":[[1,"alice",1000],[2,"bob",500]]}}`

**`seal_deployNamespace`**
```json
{"jsonrpc":"2.0","method":"seal_deployNamespace","params":{"namespace":"myapp","schema":"CREATE TABLE t (id BIGINT PRIMARY KEY)"},"signature":"...","sender":"...","id":1}
```

#### Chain State (no auth)

| Method | Description |
|--------|-------------|
| `seal_getHeight` | Get current block height |
| `seal_getStateRoot` | Get current Merkle state root hash |
| `seal_getBlock` | Get block by height |
| `seal_getPeers` | List connected P2P peers |
| `seal_getNamespaces` | List deployed namespaces |

**`seal_getHeight`**
```json
{"jsonrpc":"2.0","method":"seal_getHeight","params":{},"id":1}
```
Response: `{"result":{"height":42}}`

**`seal_getStateRoot`**
```json
{"jsonrpc":"2.0","method":"seal_getStateRoot","params":{},"id":1}
```
Response: `{"result":{"state_root":"a1b2c3..."}}`

**`seal_getBlock`**
```json
{"jsonrpc":"2.0","method":"seal_getBlock","params":{"height":1},"id":1}
```
Response: `{"result":{"height":1,"parent_hash":"...","state_root":"...","transactions":[...]}}`

**`seal_getPeers`**
```json
{"jsonrpc":"2.0","method":"seal_getPeers","params":{},"id":1}
```
Response: `{"result":{"peers":["12D3Koo..."],"count":3}}`

**`seal_getNamespaces`**
```json
{"jsonrpc":"2.0","method":"seal_getNamespaces","params":{},"id":1}
```

#### Token Operations

| Method | Auth | Description |
|--------|------|-------------|
| `seal_getBalance` | No | Get SEAL balance for an address |
| `seal_transfer` | Yes | Transfer SEAL tokens |
| `seal_createToken` | Yes | Create a new custom token |
| `seal_mintToken` | Yes | Mint custom tokens (mint authority only) |
| `seal_transferToken` | Yes | Transfer custom tokens |
| `seal_getTokenBalance` | No | Get balance of a custom token |
| `seal_listTokens` | No | List all custom tokens |

Addresses below are placeholders (`seal1abc…`, `seal1xyz…`); the
handlers run bech32m validation and reject anything other than a real
key's full encoding (generate one with `seal keygen --output key.json`
and substitute its `address` field). Pasting the placeholders verbatim
yields `-32602 invalid 'address': bech32m: …`.

**`seal_getBalance`**
```json
{"jsonrpc":"2.0","method":"seal_getBalance","params":{"address":"seal1abc..."},"id":1}
```
Response: `{"result":{"address":"…","balance":N,"total_supply":S}}`

**`seal_transfer`**
```json
{"jsonrpc":"2.0","method":"seal_transfer","params":{"to":"seal1xyz...","amount":500},"signature":"...","sender":"...","id":1}
```
Response: `{"result":{"from":"…","to":"…","amount":500,"status":"confirmed"}}`

**`seal_createToken`**
```json
{"jsonrpc":"2.0","method":"seal_createToken","params":{"symbol":"GOLD","name":"Gold Token","decimals":9,"max_supply":1000000},"signature":"...","sender":"...","id":1}
```
Response: `{"result":{"symbol":"GOLD","name":"Gold Token","decimals":9,"max_supply":1000000,"creator":"…","status":"created"}}`

**`seal_mintToken`**
```json
{"jsonrpc":"2.0","method":"seal_mintToken","params":{"symbol":"GOLD","to":"seal1abc...","amount":1000},"signature":"...","sender":"...","id":1}
```

**`seal_transferToken`**
```json
{"jsonrpc":"2.0","method":"seal_transferToken","params":{"symbol":"GOLD","to":"seal1xyz...","amount":100},"signature":"...","sender":"...","id":1}
```

**`seal_getTokenBalance`**
```json
{"jsonrpc":"2.0","method":"seal_getTokenBalance","params":{"symbol":"GOLD","address":"seal1abc..."},"id":1}
```
Response: `{"result":{"symbol":"GOLD","balance":900}}`

**`seal_listTokens`**
```json
{"jsonrpc":"2.0","method":"seal_listTokens","params":{},"id":1}
```
Response: `{"result":{"tokens":[{"symbol":"GOLD","name":"Gold Token","total_supply":1000,"max_supply":1000000}]}}`

#### DEX Operations

| Method | Auth | Description |
|--------|------|-------------|
| `seal_createPair` | Yes | Create a trading pair |
| `seal_placeOrder` | Yes | Place a buy/sell order |
| `seal_cancelOrder` | Yes | Cancel an open order |
| `seal_getOrderBook` | No | Get order book for a pair |
| `seal_listPairs` | No | List all trading pairs |

**`seal_createPair`**
```json
{"jsonrpc":"2.0","method":"seal_createPair","params":{"base":"SEAL","quote":"GOLD"},"signature":"...","sender":"...","id":1}
```

**`seal_placeOrder`**
```json
{"jsonrpc":"2.0","method":"seal_placeOrder","params":{"pair":"SEAL/GOLD","side":"bid","price":100,"quantity":10},"signature":"...","sender":"...","id":1}
```

**`seal_cancelOrder`**
```json
{"jsonrpc":"2.0","method":"seal_cancelOrder","params":{"order_id":"..."},"signature":"...","sender":"...","id":1}
```

**`seal_getOrderBook`**
```json
{"jsonrpc":"2.0","method":"seal_getOrderBook","params":{"pair":"SEAL/GOLD"},"id":1}
```

**`seal_listPairs`**
```json
{"jsonrpc":"2.0","method":"seal_listPairs","params":{},"id":1}
```

#### Privacy and Security

| Method | Auth | Description |
|--------|------|-------------|
| `seal_createPrivateTable` | Yes | Create a private (encrypted) table |
| `seal_listPrivateTables` | No | List private tables |

(Table visibility / RLS toggles / RLS policies all flow through SQL
DDL via `seal_submitSql` — `ALTER TABLE … ENABLE ROW LEVEL SECURITY`
and `CREATE POLICY …`. See the Row-Level Security section above.)

**`seal_createPrivateTable`**
```json
{"jsonrpc":"2.0","method":"seal_createPrivateTable","params":{"table":"secrets","type":"encrypted"},"signature":"...","sender":"...","id":1}
```

#### MPC and ZK

| Method | Auth | Description |
|--------|------|-------------|
| `seal_mpcAggregate` | No | Privacy-preserving aggregate (sum/count/avg) |
| `seal_zkProve` | No | Generate ZK proof of a SQL condition |

**`seal_mpcAggregate`**
```json
{"jsonrpc":"2.0","method":"seal_mpcAggregate","params":{"function":"sum","table":"users","column":"balance"},"id":1}
```
Response: `{"result":{"result":1500,"row_count":2}}`

**`seal_zkProve`**
```json
{"jsonrpc":"2.0","method":"seal_zkProve","params":{"table":"users","statement":"balance > 0"},"id":1}
```
Response: `{"result":{"satisfied":true,"proof":"a1b2c3...","block_height":42}}`

#### PQ Transport

| Method | Auth | Description |
|--------|------|-------------|
| `seal_pqHandshake` | No | Initiate ML-KEM post-quantum encrypted RPC session |

**`seal_pqHandshake`**
```json
{"jsonrpc":"2.0","method":"seal_pqHandshake","params":{"client_public_key":"<ml-kem-pubkey-hex>"},"id":1}
```

---

## Creating Custom Tokens

Seal supports SPL/Stellar-style custom tokens. Any user can create a token
with a symbol, name, decimals, and optional max supply.

### Via TUI Wallet

```
[seal1abc...] > create-token GOLD "Gold Token" 1000000
Token created: GOLD

[seal1abc...] > mint-token GOLD seal1xyz... 500
Minted 500 GOLD to seal1xyz...

[seal1abc...] > tokens
SYMBOL   NAME            SUPPLY       MAX
--------------------------------------------------
GOLD     Gold Token             500      1000000
```

### Via curl

```bash
# Create token
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "method":"seal_createToken",
    "params":{"symbol":"GOLD","name":"Gold Token","decimals":9,"max_supply":1000000},
    "signature":"...","sender":"...","id":1
  }'

# Mint tokens
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "method":"seal_mintToken",
    "params":{"symbol":"GOLD","to":"seal1xyz...","amount":500},
    "signature":"...","sender":"...","id":1
  }'

# Transfer tokens
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "method":"seal_transferToken",
    "params":{"symbol":"GOLD","to":"seal1def...","amount":100},
    "signature":"...","sender":"...","id":1
  }'
```

### Token Properties

| Property | Description |
|----------|-------------|
| `symbol` | Short ticker (e.g., GOLD, USD, MYTOKEN) |
| `name` | Human-readable name |
| `decimals` | Decimal places (typically 9) |
| `max_supply` | Maximum mintable supply (0 = unlimited) |
| `mint_authority` | Creator address (only this address can mint) |

---

## MPC and ZK Features

### MPC: Privacy-Preserving Aggregation

The MPC system uses SPDZ (Secure Multi-Party Computation) over a Goldilocks
field. It supports privacy-preserving SQL aggregates where individual row
values are never revealed.

**Supported functions**: `sum`, `count`, `avg`

```bash
# Compute sum of balance column without revealing individual values
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_mpcAggregate","params":{"function":"sum","table":"users","column":"balance"},"id":1}'
```

The `seal-mpc` crate also provides Private Set Intersection (PSI) for
privacy-preserving JOINs, using SHA3 hashing with salt.

### ZK: Zero-Knowledge Proofs

Generate ZK proofs of SQL conditions without revealing the underlying data.
The ZK system supports RISC Zero and SP1 backends (currently in simulation mode).

```bash
# Prove that a condition holds on a table
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_zkProve","params":{"table":"users","statement":"balance > 0"},"id":1}'
```

Response includes a proof blob and whether the statement is satisfied.

### Using MPC/ZK from the TUI Wallet

```
[seal1abc...] > mpc sum users balance
sum(users.balance) = 1500 (2 rows)

[seal1abc...] > zk users balance > 0
Statement: users WHERE balance > 0
Satisfied: YES
Proof:     a1b2c3d4e5f67890...
Height:    42
```

---

## WASM SDK for Browser Apps

The `sdks/wasm/` directory contains a Rust-to-WASM SDK for building browser
applications that interact with Seal nodes.

### Building the WASM SDK

```bash
cd sdks/wasm

# Install wasm-pack
cargo install wasm-pack

# Build the WASM package
wasm-pack build --target web
```

### Using in a Web App

```html
<script type="module">
  import init, { SealClient } from './seal_dao_wasm.js';

  await init();

  const client = new SealClient("http://localhost:8545");
  const height = await client.getHeight();
  console.log("Chain height:", height);
</script>
```

### JavaScript SDK

The `sdks/js/` directory provides a pure JavaScript SDK for Node.js
environments:

```javascript
const { SealClient } = require('@seal-dao/sdk');

const client = new SealClient('http://localhost:8545');
const height = await client.getHeight();
const result = await client.querySql('SELECT * FROM users');
```

### Python SDK

The `sdks/python/` directory provides a Python SDK:

```python
from seal_sdk import SealClient

client = SealClient("http://localhost:8545")
height = client.get_height()
result = client.query_sql("SELECT * FROM users")
```

---

## Running Tests and CI

### Running Tests

```bash
# Run all tests (785+ tests)
cargo test

# Run tests for a specific crate
cargo test -p seal-crypto
cargo test -p seal-sql
cargo test -p seal-node

# Run with output visible
cargo test -- --nocapture
```

### CI Scripts

| Script | Purpose |
|--------|---------|
| `scripts/ci.sh` | Full CI: build, test, clippy, Kani (6 crates), Miri (3 crates), fuzz (9 targets), audit |
| `scripts/ci.sh quick` | Quick CI: build + test + clippy only |
| `scripts/ci-nightly.sh` | Nightly: full CI + extended fuzz (5 min/target) + Lean 4 + Rocq |
| `scripts/ci-formal.sh` | Formal verification only: Kani, Miri, Lean 4, Rocq |
| `scripts/verify.sh` | Run all formal verification checks |
| `scripts/fuzz-all.sh` | Run all 9 fuzz targets |
| `scripts/fuzz-extended.sh` | Extended fuzzing (1 hour default) |

```bash
# Full CI pipeline
./scripts/ci.sh

# Quick build + test only
./scripts/ci.sh quick

# Nightly with extended fuzzing and formal proofs
./scripts/ci-nightly.sh
```

### Formal Verification

- **Kani**: 52+ model-checking harnesses across 14+ files
- **Miri**: Undefined behavior detection on seal-crypto, seal-merkle, seal-storage
- **Lean 4**: Proofs for Merkle tree, VRF uniqueness, Aeneas extraction (`formal/lean/`)
- **Rocq**: Proofs for RLS, SQL state transitions, balance invariants (`formal/rocq/`)
- **TLA+**: Consensus trace conformance (`formal/tla/`)
- **Fuzz**: 9 cargo-fuzz targets

---

## Contributing Guidelines

### Code Style

- **PQC first**: All cryptographic operations use post-quantum algorithms
  (ML-DSA, ML-KEM, SHA3). Classical crypto only in bridge modules.
- **Checked arithmetic**: Use `checked_add`, `checked_sub`, `saturating_mul`
  for all token/balance operations. Never use unchecked arithmetic on money.
- **Zeroize secrets**: All secret key material must implement `Zeroize`.
- **No `.unwrap()` / `.expect()` in production code**: Always use `?`, `match`,
  `if let`, or `unwrap_or`. `.unwrap()` is only acceptable in `#[cfg(test)]`.
- **Trait-based stubs**: New crypto primitives use traits with stub
  implementations. The real implementation is a drop-in replacement.

### Commit Style

- Small, focused commits with descriptive messages
- Commit often

### Adding a New Crate

1. Create the crate under `crates/seal-<name>/`
2. Add it to the workspace `members` in `Cargo.toml`
3. Add Kani harnesses for critical functions (`#[cfg(kani)]`)
4. Add fuzz targets if the crate processes untrusted input
5. Add tests (aim for high coverage)

### Adding RPC Methods

1. Add the handler function in `crates/seal-node/src/rpc.rs`
2. Add the method name to the `match` in `handle_rpc()`
3. If mutating, add to `requires_auth()` match list
4. Add tests in the `#[cfg(test)]` module
5. Document the method in this guide

### Testing Checklist

- [ ] `cargo test` passes
- [ ] `cargo clippy` clean (no warnings)
- [ ] New Kani harnesses for safety-critical logic
- [ ] Fuzz target if parsing untrusted input
- [ ] No `.unwrap()` in non-test code
