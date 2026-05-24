# Seal DAO — Data Sharding & Distribution Architecture

## Vision

Seal is a **decentralized SQL database on a blockchain** — the Web3 equivalent
of PHP+MySQL. Any developer deploys an app with `seal app deploy`, gets a
namespace with SQL tables, and the network handles replication, privacy, and
verification. No DevOps, no servers, no trust assumptions.

```
Traditional stack:              Seal stack:
  PHP + MySQL + AWS               App + Seal SQL + Seal Network
  ├── You manage servers          ├── Network manages nodes
  ├── You manage backups          ├── Replication built-in
  ├── You manage auth             ├── ML-DSA crypto identity
  ├── You trust your DB           ├── Merkle proofs verify state
  └── You trust your host         └── ZK proofs verify queries
```

---

## Data Distribution Model

### What Every Node Must Have (Consensus Layer)

Every validator stores the consensus state. This is small and bounded:

- Block headers (height, parent hash, state root, timestamp, VRF proof)
- Validator set (public keys, stakes)
- Token balances (HAMT trie)
- Epoch state (current epoch, committee)
- Merkle roots of all namespaces (NOT the data itself)

### What Nodes Choose to Have (Data Layer)

```
┌─────────────────────────────────────────────────────────┐
│                   Global Consensus                       │
│  Block headers, validator set, token balances,           │
│  namespace Merkle roots                                  │
│  EVERY validator has this (~GB scale)                    │
└────────────────────────┬────────────────────────────────┘
                         │
          ┌──────────────┼──────────────────────┐
          │              │                       │
 ┌────────▼────────┐ ┌──▼─────────────┐ ┌──────▼──────────┐
 │  Public Tables   │ │ App Namespaces  │ │ Private Tables   │
 │                  │ │                 │ │                  │
 │ Replicated to    │ │ Stored by app   │ │ Only on owner's  │
 │ all full nodes   │ │ nodes + willing │ │ nodes, encrypted │
 │                  │ │ replicas        │ │ at rest          │
 │ e.g. governance, │ │ e.g. blog.seal  │ │ e.g. salary data │
 │ token registry   │ │ market.seal     │ │ medical records  │
 └─────────────────┘ └────────────────┘ └─────────────────┘
```

---

## Node Types

| Type | Stores | Who runs it | Analogy |
|------|--------|-------------|---------|
| **Validator** | Consensus + Merkle roots only | Staked validators | Ethereum validator |
| **Full node** | Consensus + all public tables | Anyone | Ethereum full node |
| **App node** | Consensus + specific namespaces | App deployers | MySQL server for your app |
| **Private node** | Consensus + owner's private data | Data owners | Your local database |
| **Archive node** | Everything, all history | Infrastructure providers | Etherscan backend |

### How a Developer Uses Seal

```bash
# 1. Deploy your app (like CREATE DATABASE in MySQL)
seal app deploy --name myapp.seal --schema schema.sql

# 2. Your schema.sql is standard PostgreSQL
CREATE TABLE users (
  id BIGINT PRIMARY KEY,
  email TEXT NOT NULL,
  balance BIGINT DEFAULT 0
);
CREATE TABLE orders (
  id BIGINT PRIMARY KEY,
  user_id BIGINT REFERENCES users(id),
  total BIGINT NOT NULL
);

# 3. Your app talks to the nearest node via JSON-RPC
curl -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"seal_querySql","params":{"sql":"SELECT * FROM myapp.users"},"id":1}' \
  http://your-node:8545

# 4. You don't manage servers — the network replicates your data
```

---

## Namespace-Based Sharding (Phase 1)

Each namespace is a natural shard. Nodes declare which namespaces they serve.

### Namespace Configuration

```sql
-- Deploy with replication factor
CREATE NAMESPACE market.seal
  WITH REPLICATION = 3       -- 3 nodes store this data
       VISIBILITY = PUBLIC;  -- anyone can run an app node for this namespace

CREATE NAMESPACE health.seal
  WITH REPLICATION = 2
       VISIBILITY = PRIVATE; -- only owner-approved nodes
```

### Node Registration

```bash
# Start a node that serves specific namespaces
seal-node --slots 0 --rpc-port 8545 \
  --serve blog.seal \
  --serve market.seal

# Validators don't need --serve (they only store consensus state).
# Pass --validator-key for a stable on-chain identity across restarts
# (see TESTNET.md "Identity persistence" for the keyfile format).
seal-node --slots 0 --data-dir /var/lib/seal \
  --validator-key /etc/seal/validator-keys.json
```

### Query Routing

```
Client: SELECT * FROM blog.posts WHERE author = 'alice'
  │
  ▼
Node receives query
  ├── Do I serve blog.seal? → Execute locally
  └── Don't serve it? → Route to a node that does
                         (discovered via GossipSub peer metadata)
```

### Cross-Namespace Queries

```sql
-- JOINs within a namespace: fast (local data)
SELECT p.title, c.body FROM posts p JOIN comments c ON p.id = c.post_id;

-- JOINs across namespaces: routed
SELECT u.name, o.total
FROM blog.users u JOIN market.orders o ON u.id = o.user_id;
-- → Requires both blog.seal and market.seal data
-- → Executed on a node serving both, or via scatter-gather
-- → For private tables: uses PSI (private set intersection)
```

---

## Private Table Taxonomy

Three distinct types of private tables, with different trust models:

### 1. App-Private Tables

Schema and access rules defined by the app, enforced on-chain. Row data belongs
to the user and lives only on their nodes. The app can't see individual data,
but can aggregate via MPC.

**Use cases**: user preferences, GUI customization, saved searches, shopping carts

```
App: social.seal
  Schema (on-chain, immutable, enforced by network):
    CREATE TABLE user_profile (
      user_id TEXT PRIMARY KEY,      -- owner's seal address
      display_name TEXT NOT NULL,
      theme TEXT DEFAULT 'dark',
      avatar_url TEXT
    );
    CREATE POLICY owner_only ON user_profile
      FOR ALL USING (user_id = CURRENT_USER());

  Data (encrypted, on user's own node):
    alice's node: { "seal1alice", "Alice", "dark", "ipfs://..." }
    bob's node:   { "seal1bob",   "Bob",   "light", null }

  On-chain (what validators see):
    ├── Schema hash: 0xabc...  (locked, app can't change without governance)
    ├── Policy: owner_only     (enforced — no one can bypass)
    ├── alice's row commitment: Merkle(encrypted_row)
    └── bob's row commitment:   Merkle(encrypted_row)

  What the app can do:
    ├── Read own user's data (with user's signed consent per session)
    ├── MPC aggregate: "how many users use dark theme?" → count, no names
    └── Cannot: read alice's data from bob's session
```

### 2. User-Private Tables

User defines their own schema, their own rules. Completely opaque to the network.
Like a local SQLite database but replicated across the user's own nodes.

**Use cases**: personal notes, local scratch data, private calculations

```
User: alice
  Schema (user-defined, not enforced by network):
    CREATE TABLE my_notes (id BIGINT PRIMARY KEY, content TEXT);

  On-chain: only a commitment exists
    └── alice_private_root: SHA3(encrypted_blob)

  No app, no policies, no schema enforcement — pure user sovereignty
```

### 3. Regulated-Private Tables

Schema defined by app, rules enforced on-chain AND by regulation. Raw data
never leaves the user's node. Access is exclusively via ZK proofs — the verifier
learns the proven statement (true/false) but never the underlying data.

**Use cases**: ID documents, medical records, KYC, financial statements, credentials

```
App: kyc.seal
  Schema (on-chain, enforced, auditable):
    CREATE TABLE identity (
      user_id TEXT PRIMARY KEY,
      document_hash BYTES,       -- SHA3 of passport/ID, never raw doc
      country TEXT,              -- ZK-provable ("EU citizen?")
      date_of_birth BIGINT,      -- ZK-provable ("over 18?")
      verified_by TEXT,          -- attestor's seal address
      verified_at BIGINT
    );

  Raw data: NEVER leaves user's node, NEVER shared
  
  Access patterns:
    ├── ZK proof:  "prove user is over 18"
    │              → STARK proof against document_hash + date_of_birth
    │              → Verifier learns: true/false ONLY
    │
    ├── ZK proof:  "prove user is EU citizen"
    │              → STARK proof against country field
    │              → No country name revealed
    │
    ├── MPC count: "how many verified EU users?"
    │              → SPDZ protocol across user nodes
    │              → Returns: count only, no individual data
    │
    └── Attestation: verified_by links to a trusted attestor
                     (e.g., government, notary) whose seal address
                     is on a whitelist managed by governance
```

### Summary: Private Table Types

| Type | Schema control | Rule enforcement | Data location | Access by others |
|------|---------------|-----------------|---------------|-----------------|
| **App-private** | App defines | On-chain (RLS) | User's nodes | MPC aggregates, user consent |
| **User-private** | User defines | None (user's rules) | User's nodes | Never |
| **Regulated-private** | App defines | On-chain + legal | User's nodes | ZK proofs only, never raw |

---

## Private Table Storage

### Encrypted at Rest

```
Owner: alice (seal1alice...)
  │
  ├── Alice's Node A (primary)
  │     └── AES-256-GCM encrypted rows
  │         Key derived from alice's ML-KEM keypair
  │
  ├── Alice's Node B (replica)
  │     └── Same encrypted data, synced via P2P
  │
  └── Consensus (all validators)
        └── Only metadata:
            ├── Table exists: alice.private_table
            ├── Schema: (id BIGINT, salary BIGINT)
            ├── Row count commitment: Pedersen(count, blinding)
            └── Encrypted state root: SHA3(encrypted_rows)
```

### Access Patterns for Others

Others can't read private data directly. Three access methods:

**1. MPC Aggregates** — compute without revealing
```sql
-- "What's the average salary?" without revealing any individual salary
SELECT mpc_avg(salary) FROM alice.employees;
-- → SPDZ protocol between alice's nodes
-- → Returns: 75000 (verified, no individual data leaked)
```

**2. ZK Proofs** — prove a statement without revealing data
```sql
-- "Prove alice has balance > 10000" without revealing actual balance
SELECT zk_prove(balance > 10000) FROM alice.accounts WHERE owner = 'alice';
-- → STARK proof generated
-- → Verifiable by anyone against the state root
-- → Reveals: true/false only
```

**3. PSI (Private Set Intersection)** — private JOINs
```sql
-- "Which users are in both alice's app and bob's app?"
SELECT psi_intersect(alice.users.email, bob.customers.email);
-- → Hash-based PSI protocol
-- → Returns: intersection set only
-- → Neither party sees the other's non-matching rows
```

---

## State Root Structure

The global state root is a Merkle tree of Merkle trees:

```
Global State Root (SHA3-256)
  │
  ├── Consensus Root
  │     ├── validator_set_root
  │     ├── token_balances_root (HAMT)
  │     └── epoch_state_hash
  │
  ├── Public Tables Root
  │     ├── governance_proposals_root
  │     └── token_registry_root
  │
  ├── Namespace: blog.seal
  │     ├── posts_root         ← Merkle root of all posts rows
  │     └── comments_root      ← Merkle root of all comments rows
  │
  ├── Namespace: market.seal
  │     ├── products_root
  │     └── orders_root
  │
  └── Private Commitments
        ├── seal1alice_root    ← SHA3(encrypted_data) — opaque to others
        └── seal1bob_root
```

### Verification Without Full Data

A validator can verify a block without storing all namespace data:

```
Block N:
  prev_state_root: 0xabc...
  post_state_root: 0xdef...
  namespace_proofs:
    - blog.seal: Merkle proof showing posts_root changed from X to Y
    - market.seal: unchanged (no txs this block)

Validator checks:
  1. All tx signatures valid (ML-DSA)
  2. Namespace Merkle proofs valid
  3. Recomputed state root matches post_state_root
  → Block accepted WITHOUT having blog.seal or market.seal data
```

---

## Storage Backend

### Per-Node Storage

```
node-data/
  ├── consensus/
  │     ├── blocks.db        ← block headers + metadata (redb/RocksDB)
  │     ├── validators.db    ← validator set snapshots
  │     └── balances.db      ← token balance trie
  ├── namespaces/
  │     ├── blog.seal/
  │     │     ├── posts.db   ← table data
  │     │     └── indexes/   ← B-tree indexes
  │     └── market.seal/
  │           ├── products.db
  │           └── indexes/
  └── private/
        └── encrypted/       ← AES-256-GCM encrypted tables
              └── my_data.db
```

### Backend Options

| Backend | Status | Use case |
|---------|--------|----------|
| **In-memory** | Current | Development, testing |
| **redb** | Recommended Phase 1 | Pure Rust, ACID, crash-safe |
| **RocksDB** | Phase 2 if needed | Proven at scale (Solana, Ethereum) |

---

## Scaling Path

### Phase 1: Namespace Sharding (next)
- Nodes declare which namespaces they serve
- Query routing to namespace nodes
- Replication factor per namespace
- Validators verify blocks via Merkle proofs only

### Phase 2: Private Tables
- Encrypted storage on owner nodes
- MPC/ZK/PSI access for authorized queries
- Private state commitments in global root

### Phase 3: Horizontal Sharding (large namespaces)
- Tables > 100M rows split by key range
- Shard coordinator for cross-shard queries
- Parallel query execution

### Phase 4: Edge Caching
- Read replicas near users (CDN-like)
- Merkle proofs verify cached data freshness
- Stale reads with proof of recency

---

## Comparison with Traditional Stack

| Feature | MySQL + PHP | Seal |
|---------|-------------|------|
| Deploy | Provision server, install, configure | `seal app deploy --name myapp --schema schema.sql` |
| Scale | Buy bigger server or shard manually | Set replication factor, network handles it |
| Auth | Build your own (bcrypt, JWT, sessions) | ML-DSA crypto identity, RLS policies |
| Privacy | Trust your hosting provider | Encrypted at rest, MPC/ZK for access |
| Backups | Cron job + S3 | Built-in replication across nodes |
| Verification | Trust your DB | Merkle proofs, ZK query proofs |
| Availability | Single point of failure | Replicated across N nodes |
| Cost | $50-500/mo per server | Pay per transaction (micro-SEAL) |
| Vendor lock-in | AWS/GCP/Azure | Decentralized, no vendor |
