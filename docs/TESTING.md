# Seal DAO — Manual Testing Guide

## Quick Reference

```bash
./scripts/ci.sh quick    # Build + 810+ tests + clippy (~2 min)
./scripts/ci.sh          # Full: + Kani + Miri + fuzz + audit (~5 min)
```

---

## 1. Build

```bash
cargo build --release -p seal-node -p seal-cli
```

## 2. Unit Tests (810+ tests)

```bash
cargo test -- --skip bench
```

---

## 3. Start a Node

```bash
cargo run -p seal-node -- --slots 0 --rpc-port 8545
```

Expected output:
```
Genesis: 1000000000 SEAL minted (6 accounts)
Peer ID: 12D3KooW...
RPC: http://127.0.0.1:8545 (localhost only)
Deployed schema + inserted 2 users
--- Running consensus ---
Slot 0: Block #1 produced (3 txs, state: ...)
```

---

## Authentication (ML-DSA-65 Signatures)

Methods marked **Auth: ML-DSA** in the RPC reference require two extra fields
in the JSON-RPC request body: `"signature"` and `"sender"`.

| Field | Format | Size |
|-------|--------|------|
| `sender` | Hex-encoded ML-DSA-65 **verifying key** | 1952 bytes → 3904 hex chars |
| `signature` | Hex-encoded ML-DSA-65 **signature** | 3309 bytes → 6618 hex chars |

**What is signed:** `SHA3-256( method_name + params_json )`

For example, for `seal_createToken` with params `{"symbol":"GOLD","name":"Gold Token","decimals":6,"max_supply":1000000}`:

```
message = "seal_createToken" + "{\"decimals\":6,\"max_supply\":1000000,\"name\":\"Gold Token\",\"symbol\":\"GOLD\"}"
hash    = SHA3-256(message)
sig     = ML-DSA-65-Sign(signing_key, hash)
```

> **Note:** params are serialized by `serde_json` (keys sorted alphabetically).

### Signing via CLI

The easiest way to send authenticated requests is via the TUI wallet or CLI:

```bash
# TUI wallet (handles signing automatically)
cargo run -p seal-cli -- wallet
> create
> connect http://localhost:8545
> create-token GOLD Gold 1000000

# CLI with key file
cargo run -p seal-cli -- keygen --output mykey.json
cargo run -p seal-cli -- sql "INSERT INTO users VALUES (3, 'charlie', 750)" \
  --node http://localhost:8545 --key mykey.json
```

### Signing via curl (manual)

For curl, you must compute the signature yourself. This is impractical by hand
due to the PQ signature sizes (6618 hex chars). Use the CLI instead, or see
`crates/seal-cli/src/wallet.rs` for the exact signing code.

```bash
# Authenticated curl request structure (abbreviated):
curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "seal_createToken",
    "params": {"symbol":"GOLD","name":"Gold Token","decimals":6,"max_supply":1000000},
    "sender": "<3904-char hex verifying key>",
    "signature": "<6618-char hex signature>",
    "id": 1
  }'
```

> **Read-only methods** (seal_querySql, seal_getHeight, seal_getBalance, etc.)
> do NOT require authentication and work with plain curl.

---

## 4. Chain State

All curl commands need `-H "Content-Type: application/json"`.
CLI equivalents use `seal wallet` (connect first).

```bash
# --- curl ---
curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_getHeight","params":{},"id":1}'
# → {"result":{"height":42}}

curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_getStateRoot","params":{},"id":1}'
# → {"result":{"state_root":"01c8b89f..."}}

curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_getBlock","params":{"height":1},"id":1}'
# → {"result":{"height":1,"tx_count":3,"timestamp":...}}

# --- CLI (TUI wallet) ---
cargo run -p seal-cli -- wallet
> create
> connect http://localhost:8545
> height
# → Chain height: 42
```

---

## 5. SQL Queries

```bash
# --- curl ---
curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_querySql","params":{"sql":"SELECT * FROM users"},"id":1}'
# → {"result":{"columns":["id","name","balance"],"rows":[[{"BigInt":1},{"Text":"alice"},{"BigInt":1000}]...]}}

# --- CLI (direct) ---
cargo run -p seal-cli -- sql "SELECT * FROM users" --node http://localhost:8545
# → id | name | balance
#   1  | alice | 1000
#   2  | bob   | 500

# --- CLI (signed write) ---
cargo run -p seal-cli -- keygen --output mykey.json
cargo run -p seal-cli -- sql "INSERT INTO users VALUES (3, 'charlie', 750)" \
  --node http://localhost:8545 --key mykey.json

# --- TUI wallet ---
cargo run -p seal-cli -- wallet
> create
> connect http://localhost:8545
> query SELECT * FROM users
> send INSERT INTO users VALUES (4, 'dave', 900)
```

---

## 6. Token System

### SEAL Balance
```bash
# --- curl ---
curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_getBalance","params":{"address":"seal1validators"},"id":1}'
# → {"result":{"address":"seal1validators","balance":300000000000000000,"total_supply":1000000000000000000}}

# --- TUI wallet ---
> balance
# → SEAL balance: 0 (0.0000 SEAL)
#   Total supply: 1000000000000000000
```

### Create Custom Token
```bash
# --- TUI wallet (recommended — handles signing automatically) ---
> create-token GOLD Gold 1000000
# → Token created: GOLD

# --- curl (requires signature + sender, see §Authentication) ---
# Unsigned curl will return: {"error":{"code":-32003,"message":"missing 'signature' field"}}
```

### Mint & Transfer Tokens
```bash
# --- TUI wallet (recommended) ---
> mint-token GOLD seal1alice 1000
# → Minted 1000 GOLD to seal1alice

# --- curl (requires signature + sender, see §Authentication) ---
```

### List Tokens
```bash
# --- curl ---
curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_listTokens","params":{},"id":1}'

# --- TUI wallet ---
> tokens
# → SYMBOL   NAME            SUPPLY          MAX
#   GOLD     Gold Token        1000      1000000
```

---

## 7. MPC Aggregates

```bash
# --- curl ---
curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_mpcAggregate","params":{"function":"sum","table":"users","column":"balance"},"id":1}'
# → {"result":{"function":"sum","result":2250,"row_count":3}}

curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_mpcAggregate","params":{"function":"avg","table":"users","column":"balance"},"id":1}'
# → {"result":{"function":"avg","result":750}}

# --- TUI wallet ---
> mpc sum users balance
# → sum(users.balance) = 2250 (3 rows)
> mpc avg users balance
# → avg(users.balance) = 750 (3 rows)
```

---

## 8. ZK Proofs

```bash
# --- curl ---
curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_zkProve","params":{"statement":"balance > 500","table":"users"},"id":1}'
# → {"result":{"satisfied":true,"proof":"03c279...","block_height":42}}

curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_zkProve","params":{"statement":"balance > 9999","table":"users"},"id":1}'
# → {"result":{"satisfied":false,...}}

# --- TUI wallet ---
> zk users balance > 500
# → Statement: users WHERE balance > 500
#   Satisfied: YES
#   Proof: 03c2793e0a4a0d86...1ce91e4954d211f1
#   Height: 42

> zk users balance > 9999
# → Satisfied: NO
```

---

## 9. DEX Order Book

All DEX write methods require authentication (see §Authentication).
Use the TUI wallet which handles signing automatically.

**Step 1: Create a token and a trading pair first:**
```bash
# --- TUI wallet ---
> create-token GOLD Gold 1000000
# → Token created: GOLD

> mint-token GOLD <your-address> 1000
# → Minted 1000 GOLD to <your-address>
```

**Step 2: Create a pair and trade:**
```bash
# These are TUI wallet commands (not yet implemented as wallet commands,
# use the signed RPC approach from §Authentication, or add them to the CLI).
# For now, use curl with signature + sender fields:
#   seal_createPair   {"base":"GOLD","quote":"SEAL"}
#   seal_placeOrder   {"pair":"GOLD/SEAL","side":"ask","price":100,"quantity":10}
#   seal_cancelOrder  {"pair":"GOLD/SEAL","order_id":1}
```

**Step 3: Query the order book (no auth needed):**
```bash
# List pairs
curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_listPairs","params":{},"id":1}'

# View order book (requires pair to exist first)
curl -s localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_getOrderBook","params":{"pair":"GOLD/SEAL"},"id":1}'
```

---

## 10. PQ Handshake (ML-KEM-768)

```bash
# Generate KEM keypair
cargo run -p seal-cli -- keygen --kem --output mykem.json

# Handshake
PK=$(python3 -c "import json; print(json.load(open('mykem.json'))['public_key'])")
curl -s localhost:8545 -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"seal_pqHandshake\",\"params\":{\"client_public_key\":\"$PK\"},\"id\":1}"
# → {"result":{"session_id":"...","ciphertext":"...","server_public_key":"..."}}
```

---

## 11. TUI Wallet

```bash
cargo run -p seal-cli -- wallet
```

```
> create
> connect http://localhost:8545
> height
> balance
> query SELECT * FROM users
> send INSERT INTO users VALUES (5, 'eve', 600)
> transfer seal1treasury 1000
> create-token GOLD Gold 1000000
> mint-token GOLD seal1alice 1000
> tokens
> create-pair GOLD SEAL
> place-order GOLD/SEAL ask 100 10
> orderbook GOLD/SEAL
> pairs
> mpc sum users balance
> zk users balance > 500
> mnemonic
> quit

# Restore a wallet from hex seed:
> restore 3bd557f7051f8c7ead287e285791e7f587237ebfd5205213498a1d8c0958d596
```

---

## 12. Desktop Wallet (Electron + WASM)

```bash
cd apps/seal-wallet
npm install
npm run electron
```

Or via HTTP server:
```bash
cd apps/seal-wallet
python3 -m http.server 3000
# Open http://localhost:3000/standalone.html
```

Features: create wallet (ML-DSA-65 via WASM), connect to node, SQL queries
(signed writes), MPC aggregates, ZK proofs, token management (create/mint/list),
DEX (create pair, place order, order book), hex seed + BIP-39 recovery.

---

## 13. Android Wallet

```bash
# Build APK (needs Android NDK)
./apps/seal-wallet-android/build-android.sh

# Start emulator
$ANDROID_HOME/emulator/emulator @test-device &

# Install
./apps/seal-wallet-android/build-android.sh install
```

From emulator, the node is at `http://10.0.2.2:8545`.

---

## 14. Block Explorer

```bash
cd apps/seal-explorer/web
python3 -m http.server 3001
# Open http://localhost:3001
```

Auto-refreshes every 4 seconds. Tabs: Blocks, Accounts, Tokens, DEX, SQL.

---

## 15. Multi-Node Testnet

```bash
# Start 3 nodes
./scripts/testnet.sh 3

# Query each
curl -s localhost:8545 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"seal_getHeight","params":{},"id":1}'
curl -s localhost:8546 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"seal_getHeight","params":{},"id":1}'
curl -s localhost:8547 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"seal_getHeight","params":{},"id":1}'

# Stop
./scripts/testnet.sh stop
```

---

## 16. Formal Verification

### Kani (52 harnesses, 6 crates)
```bash
cargo kani -p seal-crypto      # 3 harnesses
cargo kani -p seal-token       # 19 harnesses (incl. DEX)
cargo kani -p seal-consensus   # 10 harnesses
cargo kani -p seal-threshold   # 13 harnesses
cargo kani -p seal-merkle      # 4 harnesses
cargo kani -p seal-bridge      # 3 harnesses
```

### Miri
```bash
NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo)")"
mv .cargo/config.toml .cargo/config.toml.bak
MIRIFLAGS="-Zmiri-disable-isolation" PATH="$NIGHTLY_BIN:$PATH" cargo miri test -p seal-merkle
mv .cargo/config.toml.bak .cargo/config.toml
```

### Fuzz (9 targets)
```bash
mv .cargo/config.toml .cargo/config.toml.bak
NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo)")"
PATH="$NIGHTLY_BIN:$PATH" cargo fuzz run fuzz_sql_parser -- -max_total_time=60
mv .cargo/config.toml.bak .cargo/config.toml
```

### cargo-audit
```bash
cargo audit
```

### Lean 4 (7 `sorry`s pending, see TODOS.md)
```bash
cd formal/lean && lake build
```

Builds cleanly on Lean 4.8.0 but the MerkleTree helper/delete lemmas
are still `sorry` pending Mathlib list-lemma imports.

---

## 17. Marketplace Demo

```bash
echo ".quit" | cargo run -p seal-marketplace
```

Expected: seller lists 3 items, buyer purchases Widget, balances update
(buyer=9900, seller=100), block produced.

---

## 18. Interactive SQL REPL

```bash
cargo run -p seal-app
```

```
> CREATE TABLE test (id BIGINT PRIMARY KEY, name TEXT)
> INSERT INTO test VALUES (1, 'hello')
> SELECT * FROM test
> .produce
> .quit
```

---

## 19. RPC Method Reference (27 methods)

| Method | Auth | Description |
|--------|------|-------------|
| `seal_querySql` | No | Read-only SQL |
| `seal_submitSql` | ML-DSA | Write SQL |
| `seal_getHeight` | No | Chain height |
| `seal_getStateRoot` | No | State root |
| `seal_getBlock` | No | Block by height |
| `seal_getPeers` | No | Peer info |
| `seal_getNamespaces` | No | List namespaces |
| `seal_deployNamespace` | ML-DSA | Deploy namespace |
| `seal_getBalance` | No | SEAL balance |
| `seal_transfer` | ML-DSA | Transfer SEAL |
| `seal_createToken` | ML-DSA | Create custom token |
| `seal_mintToken` | ML-DSA | Mint tokens |
| `seal_transferToken` | ML-DSA | Transfer custom token |
| `seal_getTokenBalance` | No | Token balance |
| `seal_listTokens` | No | List tokens |
| `seal_createPair` | ML-DSA | Create DEX pair |
| `seal_placeOrder` | ML-DSA | Place order |
| `seal_cancelOrder` | ML-DSA | Cancel order |
| `seal_getOrderBook` | No | Order book depth |
| `seal_listPairs` | No | List DEX pairs |
| `seal_createPrivateTable` | ML-DSA | Create private table |
| `seal_listPrivateTables` | No | List private tables |
| `seal_mpcAggregate` | Optional | MPC sum/count/avg |
| `seal_zkProve` | Optional | ZK proof |
| `seal_pqHandshake` | No | ML-KEM key exchange |
| `seal_getNodeInfo` | No | Node version, epoch, peers, validators, uptime |

(Table visibility / RLS toggles / RLS policies are SQL DDL via
`seal_submitSql` — `ALTER TABLE … ENABLE ROW LEVEL SECURITY` and
`CREATE POLICY …`. The dedicated `seal_setVisibility` / `seal_enableRls` /
`seal_addPolicy` methods listed in earlier revisions of this table were
never wired; they have been removed from `requires_auth`.)

**HTTP endpoints** (GET, no JSON-RPC):

| Endpoint | Description |
|----------|-------------|
| `/health` | Liveness probe: `{"status":"ok","height":N,"peers":N,"uptime_secs":N}` |
| `/metrics` | Prometheus exposition format (12 counters + 3 gauges) |
| `/status` | Rich JSON: chain state, epoch, validators, leases, all metrics |

---

## 20. CLI Reference

| Command | Description |
|---------|-------------|
| `seal dev [--slots N]` | Local devnet (1s slots) |
| `seal demo` | Interactive demo |
| `seal keygen [--output f]` | ML-DSA-65 keypair |
| `seal keygen --kem [--output f]` | ML-KEM-768 keypair |
| `seal wallet` | Interactive TUI wallet |
| `seal sql "<query>"` | SQL locally |
| `seal sql "<query>" --node <url>` | SQL on remote node |
| `seal sql "<query>" --node <url> --key <f>` | Signed write |
| `seal app deploy --name <n> --schema <f>` | Deploy namespace |
| `seal migrate analyze <file.sql>` | Analyze PostgreSQL dump |

---

## 21. Node CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--slots N` | 10 | Slots to run (0 = forever) |
| `--port N` | 4001 | P2P listen port |
| `--rpc-port N` | 0 (off) | JSON-RPC port (localhost only) |
| `--bootstrap-peers <multiaddr>` | none | Bootstrap peer (repeatable) |
| `--serve <namespace>` | all | Namespace to serve (repeatable) |
| `--data-dir <path>` | seal-data | Disk persistence directory |
| `--no-network` | false | Local mode, no P2P |

---

## 22. Row Salts and Storage Leases (`#STORAGE-FORGET`)

### Verify row salts are generated

```bash
# Two engines with same SQL produce different state roots (random salts)
cargo test -p seal-sql test_state_root_deterministic -- --nocapture
```

Expected: test passes — it verifies that a single engine produces the same root
on repeated calls, but no longer asserts cross-engine equality (salts are random).

### Verify deterministic salts in consensus

```bash
# Block replay produces identical state root (block-seed-derived salts)
cargo test -p seal-node test_replay_single_block -- --nocapture
cargo test -p seal-node test_replay_chain -- --nocapture
```

Expected: both tests pass — producer and replayer derive the same salts from
block height, producing identical state roots.

### StorageLease tests

```bash
cargo test -p seal-token storage_lease -- --nocapture
```

Expected: 7 tests pass — lease creation, extension, expiry, grace period,
governance hold, and lease manager pruning.

### Manual: inspect row salt in Merkle value

```bash
cargo run -p seal-cli -- demo 2>&1 | head -30
```

Merkle leaf values now include the hex-encoded salt prefix:
`"<64-char-hex-salt>:[BigInt(1), Text(\"hello\")]"`

---

## 23. Namespace Registration

### Via RPC

```bash
# Start a node
cargo run -p seal-node -- --slots 0 --rpc-port 8545 &

# Deploy a namespace
curl -s http://localhost:8545 -d '{
  "jsonrpc": "2.0", "id": 1,
  "method": "seal_deployNamespace",
  "params": {"name": "myapp.seal", "schema": "CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT)", "visibility": "public"}
}' | jq .

# List namespaces
curl -s http://localhost:8545 -d '{
  "jsonrpc": "2.0", "id": 2,
  "method": "seal_getNamespaces"
}' | jq .
```

Expected: first call returns `"status": "deployed"`, second returns the namespace list.

### Duplicate rejection

```bash
# Deploy same namespace again — should fail
curl -s http://localhost:8545 -d '{
  "jsonrpc": "2.0", "id": 3,
  "method": "seal_deployNamespace",
  "params": {"name": "myapp.seal", "schema": "CREATE TABLE t (id BIGINT PRIMARY KEY)"}
}' | jq .
```

Expected: error with "namespace 'myapp.seal' already exists".

---

## 24. ZK Prover Backend Selection

Both RISC Zero and SP1 are available (simulation mode until real SDKs vendored).

```bash
# Verify both provers work in simulation
cargo test -p seal-zk test_risc0_prove_and_verify
cargo test -p seal-zk test_sp1_prove_and_verify
cargo test -p seal-zk test_sp1_cross_verify_with_risc0

# All ZK tests
cargo test -p seal-zk
```

Expected: all pass. In simulation mode both produce identical SHA3 commitments.

---

## 25. Committee Message Processing

```bash
# Verify committee vote/sig/epoch handlers compile and wire correctly
cargo test -p seal-node -- --nocapture 2>&1 | grep -E "(committee|epoch|vote)"
```

The consensus runner now has `accept_committee_vote()`, `accept_committee_signature()`,
and `accept_epoch_transition()` methods that deserialize and log P2P messages.

---

## 26. Lean 4 Merkle Delete Theorems

```bash
cd formal/lean && lake build 2>&1 | tail -20
```

New theorems in `SealVerify/Basic/MerkleTree.lean`:
- `delete_lookup` — delete then lookup returns none
- `delete_lookup_other` — delete preserves other keys
- `delete_idempotent` — double delete = single delete
- `delete_then_insert` — delete + insert = insert
- `delete_changes_root` — (sorry, requires further proof work)

---

## 27. Bridge Threshold Signature Testing

### Solana bridge (Anchor)

```bash
cd bridges/solana && anchor test 2>&1 | tail -20
```

The `verify_threshold_signature` now checks message binding via
SHA3(recipient || amount || nonce || "seal-bridge-v1") in development mode.

### Stellar bridge (Soroban)

```bash
cd bridges/stellar && cargo test 2>&1 | tail -20
```

Expected: 5 tests pass (init, lock, unlock, replay protection, double-init rejection).

---

## 28. Monitoring Endpoints

### Health check

```bash
cargo run -p seal-node -- --slots 0 --rpc-port 8545 &
curl -s http://localhost:8545/health | jq .
```

Expected: JSON with `status` (`starting` / `ok` / `stalled` based
on uptime + height growth), `height`, `peers`, `uptime_secs`,
`validator_pubkey_hex`, `validator_address`, `is_validator` (active
in the validator set), `blocks_produced`, `blocks_pending`. The
last three answer "am I producing?" without a /metrics scrape;
`blocks_pending` is the P2P apply-queue depth (sustained non-zero
= applier lagging).

### Prometheus metrics

```bash
curl -s http://localhost:8545/metrics | head -20
```

Expected: Prometheus exposition format with `seal_blocks_produced`, `seal_peers_connected`,
`seal_chain_height`, `seal_uptime_seconds`, and bridge gauges
(`seal_bridge_committee_key_set`, `seal_bridge_paused_chains`,
`seal_bridge_{deposits,withdrawals}_total`, label-info
`seal_bridge_committee_key_fingerprint{sha2_hex="…"}`).

### Rich status

```bash
curl -s http://localhost:8545/status | jq .
```

Expected: JSON with version, chain_id, height, state_root, epoch, slot, peers, validators,
leases_active, full metrics breakdown, plus a `bridge` object
(`committee_key_set`, `committee_key_fingerprint_sha2_hex`,
`paused_chains`, `deposits_total`, `deposits_pending`,
`withdrawals_total`, `invariant_holds`) that mirrors the
`seal_bridge_*` Prometheus gauges in a structured form.

### Node info RPC

```bash
curl -s http://localhost:8545 -d '{"jsonrpc":"2.0","id":1,"method":"seal_getNodeInfo"}' | jq .
```

---

## 29. Web Block Explorer

```bash
# Open directly in browser (connects to localhost:8545 by default)
open apps/seal-explorer-web/index.html

# Or with custom RPC URL
open "apps/seal-explorer-web/index.html?rpc=http://node1.testnet.seal-dao.org:8545"
```

Features: auto-refresh (2s), block list with click-to-expand, namespace list, dark theme.
No build step — pure HTML+JS.

---

## 30. Grafana + Prometheus Monitoring

```bash
# Start the monitoring stack
cd monitoring && docker-compose -f docker-compose.monitoring.yml up -d

# Grafana: http://localhost:3000 (admin/admin)
# Prometheus: http://localhost:9090
```

Dashboard: "Seal Node Overview" — block production rate, tx throughput, SQL ops,
peer count, fees, leases.

---

## 31. Storage Invoicing (#STORAGE-FORGET)

### Write cost deduction

SQL writes burn SEAL proportional to payload size (1 micro-SEAL per byte).
Verify by checking balances before/after a write:

```bash
# Check balance
curl -s localhost:8545 -d '{"jsonrpc":"2.0","id":1,"method":"seal_getBalance","params":{"address":"<sender>"}}' | jq .

# Submit a write
curl -s localhost:8545 -d '{"jsonrpc":"2.0","id":1,"method":"seal_submitSql","params":{"sql":"INSERT INTO t VALUES (1)"},...}' | jq .

# Check balance again — should decrease
```

### Read stake-gate

SELECT queries log a warning when the sender has zero SEAL balance.
Check node logs for: `"Read without SEAL balance (stake-gate warning)"`

### Storage leases

Tables auto-register a lease on CREATE TABLE. Verify:

```bash
cargo test -p seal-token storage_lease -- --nocapture
```

Expected: 7 tests pass (creation, extension, expiry, grace period, governance hold, manager).

---

## 32. Real ZK Proving (RISC Zero)

### Verify guest ELF is embedded

```bash
cargo test -p seal-zk --features risc0 test_risc0_real_stark_proof -- --nocapture
```

Expected: test passes, prints ELF size (~23KB) and ProgramBinary size.

### Full STARK proof (deferred)

Full end-to-end prove() requires rebuilding the guest with `risc0-zkvm` dep
(blocked on serde + -Zbuild-std nightly compatibility). When available:

```bash
R0VM=~/.risc0/extensions/v5.0.0-rc.1-*/r0vm
PATH=$R0VM:$PATH RISC0_DEV_MODE=1 cargo test -p seal-zk --features risc0
```
