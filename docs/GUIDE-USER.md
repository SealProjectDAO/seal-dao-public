# Seal DAO User Guide

This guide covers using the Seal DAO blockchain as an end user: desktop wallet,
TUI wallet, Android wallet, and direct RPC interaction.

---

## Table of Contents

1. [What is Seal DAO?](#what-is-seal-dao)
2. [Desktop Wallet (Electron)](#desktop-wallet-electron)
3. [TUI Wallet (Terminal)](#tui-wallet-terminal)
4. [Android Wallet](#android-wallet)
5. [Using curl to Interact with a Node](#using-curl-to-interact-with-a-node)

---

## What is Seal DAO?

Seal DAO is a post-quantum secure blockchain with a built-in SQL database,
native token system, decentralized exchange (DEX), and privacy features
(MPC aggregation, ZK proofs). It uses lattice-based cryptography (ML-DSA,
ML-KEM, SHA3) that is resistant to both classical and quantum computer
attacks. You can hold SEAL tokens, create custom tokens, trade on the DEX,
deploy SQL-backed applications, and query on-chain data -- all secured by
post-quantum cryptography from day one.

---

## Desktop Wallet (Electron)

The desktop wallet is an Electron application located at `apps/seal-wallet/`.
It provides a graphical interface for managing keys, sending transactions,
querying SQL, and trading on the DEX.

### Installation

```bash
cd apps/seal-wallet

# Install dependencies
npm install

# Start the Electron app
npm run electron

# Or open standalone.html directly in a browser (file:// load works too)
open standalone.html
```

### Creating a Wallet

1. Launch the application.
2. Click **Create Wallet**.
3. The wallet generates an ML-DSA-65 keypair and a BIP-39 recovery phrase.
4. Your Seal address (e.g., `seal1abc123...`) is displayed at the top.

### Backup Your Recovery Phrase

When the wallet is created, you are shown a BIP-39 mnemonic phrase (a list
of words). This phrase is the **only** way to recover your wallet if you lose
access.

- Write the words down on paper. Do not store them digitally.
- Store the paper in a secure location (safe, lockbox).
- Never share your recovery phrase with anyone.
- The wallet uses ML-DSA-65 (FIPS 204) post-quantum signatures. Your keys
  are safe against quantum computers.

### Connecting to a Node

1. Ensure a Seal node is running with RPC enabled:
   ```bash
   cargo run --release -p seal-node -- --slots 0 --rpc-port 8545
   ```
2. In the wallet, enter the node URL: `http://localhost:8545`
3. Click **Connect**. The wallet will display the current chain height.

### Querying SQL

The wallet includes a SQL query interface:

1. Navigate to the **SQL** tab.
2. Enter a query, for example: `SELECT * FROM users`
3. Click **Execute**. Results are displayed in a table.

Write operations (INSERT, UPDATE, DELETE) require signing. The wallet
automatically signs with your ML-DSA key.

### Transferring SEAL

1. Navigate to the **Transfer** tab.
2. Enter the recipient address (e.g., `seal1xyz...`).
3. Enter the amount in SEAL.
4. Click **Send**. The wallet signs the transaction and submits it to the node.

### Creating Custom Tokens

1. Navigate to the **Tokens** tab.
2. Click **Create Token**.
3. Fill in:
   - **Symbol**: A short ticker (e.g., `GOLD`)
   - **Name**: A descriptive name (e.g., `Gold Token`)
   - **Max Supply**: Maximum number of tokens that can be minted (0 = unlimited)
4. Click **Create**. You become the mint authority for this token.

### Minting Tokens

1. On the **Tokens** tab, select your token.
2. Click **Mint**.
3. Enter the recipient address and amount.
4. Click **Mint**. Only the mint authority (creator) can mint.

### Trading on the DEX

1. Navigate to the **DEX** tab.
2. Select a trading pair (e.g., SEAL/GOLD).
3. To place a buy order: enter price and quantity, click **Buy**.
4. To place a sell order: enter price and quantity, click **Sell**.
5. Open orders can be cancelled from the **My Orders** panel.

---

## TUI Wallet (Terminal)

The TUI (Terminal User Interface) wallet runs in your terminal. It is part
of the `seal` CLI tool.

### Starting the TUI Wallet

```bash
cargo run -p seal-cli -- wallet
```

Or, if you have the release binary:

```bash
seal wallet
```

You will see:

```
=== Seal Wallet (TUI) ===
Post-quantum secure. ML-DSA-65 + ML-KEM-768 + SHA3-256.
Type 'help' for commands.

[no wallet] >
```

### Command Reference

#### Wallet Management

| Command | Description |
|---------|-------------|
| `create` | Create a new wallet (testnet by default) |
| `create mainnet` | Create a mainnet wallet |
| `import <words...>` | Import wallet from BIP-39 mnemonic |
| `address` | Show your Seal address |
| `info` | Show wallet details (address, key type, key sizes) |
| `mnemonic` | Show recovery phrase and seed hex |
| `export [file.json]` | Export key to JSON file (default: seal-key.json) |

#### Cryptographic Operations

| Command | Description |
|---------|-------------|
| `sign <message>` | Sign a message with ML-DSA-65 |
| `verify <message> <sig_hex>` | Verify a signature |

#### Node Interaction

| Command | Description |
|---------|-------------|
| `connect <url>` | Connect to a Seal node (e.g., `connect http://localhost:8545`) |
| `balance` | Show SEAL balance and custom token balances |
| `height` | Show current chain height |
| `query <SQL>` | Execute a read-only SQL query |
| `send <SQL>` | Send a signed SQL write transaction |
| `transfer <to> <amount>` | Transfer SEAL tokens to an address |

#### Token Operations

| Command | Description |
|---------|-------------|
| `create-token <SYM> <name> [max_supply]` | Create a new custom token |
| `mint-token <SYM> <to> <amount>` | Mint tokens (mint authority only) |
| `tokens` | List all custom tokens |

#### Privacy Features

| Command | Description |
|---------|-------------|
| `mpc <func> <table> <column>` | MPC aggregate (sum, count, avg) |
| `zk <table> <statement>` | Generate ZK proof of SQL condition |

#### Session

| Command | Description |
|---------|-------------|
| `help` | Show all commands |
| `quit` | Exit the wallet |

### Example Session

```
[no wallet] > create
Created new wallet
  Address:  seal1t9d3e4f5a6b7c8...
  Network:  testnet

  RECOVERY PHRASE (write this down!):
  abandon ability able about above absent absorb abstract absurd abuse access accident

  WARNING: This phrase cannot be recovered. Store it safely.

[seal1t9d3e4f5a6b...] > connect http://localhost:8545
Connected to http://localhost:8545 (height: 12)

[seal1t9d3e4f5a6b...] > balance
SEAL balance: 0 (0.0000 SEAL)
Total supply: 1000000000000

[seal1t9d3e4f5a6b...] > query SELECT * FROM users
id | name | balance
---------------------------------------------
1 | "alice" | 1000
2 | "bob" | 500
(2 rows)

[seal1t9d3e4f5a6b...] > send INSERT INTO users (id, name, balance) VALUES (3, 'carol', 750)
OK (1 rows affected)
Signed by: seal1t9d3e4f5a6b7c8...

[seal1t9d3e4f5a6b...] > transfer seal1xyz... 100
Transferred 100 SEAL to seal1xyz...
Status: ok

[seal1t9d3e4f5a6b...] > create-token GOLD "Gold Token" 1000000
Token created: GOLD

[seal1t9d3e4f5a6b...] > mint-token GOLD seal1t9d3e4f5a6b... 500
Minted 500 GOLD to seal1t9d3e4f5a6b...

[seal1t9d3e4f5a6b...] > tokens
SYMBOL   NAME            SUPPLY       MAX
--------------------------------------------------
GOLD     Gold Token             500      1000000

[seal1t9d3e4f5a6b...] > mpc sum users balance
sum(users.balance) = 2250 (3 rows)

[seal1t9d3e4f5a6b...] > zk users balance > 0
Statement: users WHERE balance > 0
Satisfied: YES
Proof:     a1b2c3d4e5f67890...
Height:    15

[seal1t9d3e4f5a6b...] > quit
Goodbye.
```

---

## Android Wallet

The Android wallet is located at `apps/seal-wallet-android/`. It provides
a native Android interface for key management and transaction signing.

### Building and Installing

```bash
cd apps/seal-wallet-android

# Build the APK (requires Android SDK + NDK)
./build-android.sh

# Install on connected device
adb install -r target/android/release/seal-wallet.apk
```

### Creating a Wallet

1. Open the Seal Wallet app on your Android device.
2. Tap **Create New Wallet**.
3. The app generates an ML-DSA-65 keypair.
4. Write down the displayed BIP-39 recovery phrase and store it securely.
5. Your Seal address is displayed on the main screen.

### Signing Messages

1. Tap **Sign Message**.
2. Enter the message text.
3. Tap **Sign**. The ML-DSA-65 signature is displayed.
4. You can copy the signature to share or verify elsewhere.

### Importing a Wallet

1. Tap **Import Wallet**.
2. Enter your BIP-39 recovery phrase (the same words from any Seal wallet).
3. The wallet derives the same ML-DSA keypair and Seal address.

---

## Using curl to Interact with a Node

You can interact with a Seal node directly using `curl` and the JSON-RPC API.
This works from any machine that can reach the node's RPC port.

### Prerequisites

Ensure a node is running with RPC enabled:

```bash
cargo run --release -p seal-node -- --slots 0 --rpc-port 8545
```

### Basic Queries (no authentication required)

**Get chain height:**

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_getHeight","params":{},"id":1}'
```

**Get state root:**

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_getStateRoot","params":{},"id":1}'
```

**Get a block by height:**

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_getBlock","params":{"height":1},"id":1}'
```

**List connected peers:**

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_getPeers","params":{},"id":1}'
```

**Query SQL (read-only):**

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_querySql","params":{"sql":"SELECT * FROM users"},"id":1}'
```

**Get SEAL balance:** the address must be a full bech32m string (the
form `seal keygen` prints). The `seal1abc…` placeholder below will
return `-32602 invalid 'address'` if pasted verbatim — generate one
with `seal keygen --output key.json` and substitute its `address` field.

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_getBalance","params":{"address":"sealt1<full-bech32m-of-your-key>"},"id":1}'
```

**List all tokens:**

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_listTokens","params":{},"id":1}'
```

**Get DEX order book:**

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_getOrderBook","params":{"pair":"SEAL/GOLD"},"id":1}'
```

**MPC aggregate (privacy-preserving):**

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_mpcAggregate","params":{"function":"sum","table":"users","column":"balance"},"id":1}'
```

**ZK proof:**

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_zkProve","params":{"table":"users","statement":"balance > 0"},"id":1}'
```

### Authenticated Operations

Write operations require an ML-DSA signature. The process is:

1. Construct the request params as JSON.
2. Compute `SHA3-256(method_name + params_json)`.
3. Sign the hash with your ML-DSA-65 private key.
4. Include `signature` (hex) and `sender` (public key hex) in the request.

**Example: submit a SQL write:**

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "method":"seal_submitSql",
    "params":{"sql":"INSERT INTO users (id, name, balance) VALUES (3, '\''carol'\'', 750)"},
    "signature":"<ml-dsa-signature-hex>",
    "sender":"<ml-dsa-public-key-hex>",
    "id":1
  }'
```

For most users, the TUI wallet or desktop wallet handles signing
automatically. Direct curl with authentication is primarily for scripting
and automation.

### Formatting Output with jq

Install `jq` for readable JSON output:

```bash
curl -s localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"seal_querySql","params":{"sql":"SELECT * FROM users"},"id":1}' \
  | jq .
```
