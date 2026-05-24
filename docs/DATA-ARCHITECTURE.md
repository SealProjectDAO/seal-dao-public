# Seal DAO — Data Architecture

## Where Data Lives

### Current State (In-Memory)

All data is in-memory. No disk persistence. When the node stops, state is lost.

```
seal-node process
  └── NetworkNode (Arc<Mutex<>>)
       ├── P2P (libp2p GossipSub)
       └── ConsensusRunner
            ├── SQL Engine
            │    ├── schemas: HashMap<String, Schema>
            │    ├── tables:  HashMap<String, Vec<Row>>    ← all data here
            │    └── indexes: IndexManager (B-tree)
            ├── Merkle Tree
            │    └── state_root: Hash256 (SHA3 of all table data)
            ├── Block Chain
            │    └── blocks: Vec<Block> (in-memory chain)
            └── Pending Transactions
                 └── pending_txs: Vec<Transaction>
```

### Data Flow

```
Client (seal-cli / curl)
  │
  │  JSON-RPC over HTTP (port 8545)
  ▼
RPC Server (axum)
  │
  │  Arc<Mutex<NetworkNode>>
  ▼
ConsensusRunner
  │
  ├─ Reads:  SQL Engine → QueryResult → RPC response
  │
  └─ Writes: SQL Engine → Transaction (ML-DSA signed)
             → Pending pool → Block production
             → State root update → GossipSub broadcast
```

### Persistence (Planned)

The storage crate (`seal-storage`) has building blocks not yet wired:

| Component | File | Status |
|-----------|------|--------|
| Block store | `crates/seal-storage/src/block_store.rs` | Built, in-memory |
| Persistent disk store | `crates/seal-storage/src/disk_store.rs` | Built, on-disk via `--data-dir` |
| State pruning | `crates/seal-storage/src/pruning.rs` | Built |
| State snapshots | `crates/seal-storage/src/snapshot_index.rs` + `snapshot_chunks.rs` | Built (epoch-boundary capture) |
| HAMT (account trie) | `crates/seal-token/src/hamt.rs` | Built, in-memory |

The `DiskStore` persists chain state across restarts when
`seal-node --data-dir <path>` is set; the validator identity is
persisted separately via `seal-node --validator-key <keyfile>`
(see TESTNET.md "Identity persistence").

---

## Data Privacy Model

### Three Levels of Table Visibility

| Level | Who can read | Who can write | How |
|-------|-------------|---------------|-----|
| **Public** | Anyone | Signed transactions | Default for shared data |
| **RLS-protected** | Policy-based per row | Policy-based per row | PostgreSQL-style CREATE POLICY |
| **Private** | Owner only | Owner only | MPC aggregates or ZK proofs for others |

### Current State vs Target

| Feature | Built? | Wired to RPC? |
|---------|--------|---------------|
| Public tables (read/write) | Yes | Yes (no auth yet) |
| RLS policies | Yes (`seal-sql/src/rls.rs`) | No |
| Namespace isolation | Yes (`seal-sql/src/namespace.rs`) | No |
| ML-DSA signed requests | Yes (crypto exists) | No |
| MPC private aggregates | Yes (`seal-mpc`) | No |
| ZK query proofs | Yes (`seal-zk`) | No |

---

## Namespace System

Every app gets its own namespace (like a PostgreSQL schema):

```
blog.seal/           ← namespace
  ├── posts          ← public table (anyone can SELECT)
  └── comments       ← private table (only blog.seal owner)

market.seal/
  ├── products       ← RLS: public read, seller-only write
  └── orders         ← RLS: buyer/seller can see their own
```

### Visibility Rules

| Visibility | Cross-app read | Cross-app write |
|-----------|---------------|-----------------|
| PUBLIC | Yes | No (owner only) |
| PRIVATE (default) | No | No |
| RLS | Policy-dependent | Policy-dependent |

### Namespace Deployment

```sql
-- Deploy via seal-cli or RPC
seal app deploy --name blog.seal --schema schema.sql

-- The schema.sql contains:
CREATE TABLE posts (id BIGINT PRIMARY KEY, author TEXT, body TEXT);
CREATE POLICY public_read ON posts FOR SELECT USING (true);
```

---

## Row-Level Security (RLS)

PostgreSQL-compatible RLS. Policies are per-table, per-action.

```sql
-- Enable RLS on a table
ALTER TABLE products ENABLE ROW LEVEL SECURITY;

-- Public read
CREATE POLICY public_read ON products
  FOR SELECT USING (true);

-- Only the seller can modify their own rows
CREATE POLICY seller_write ON products
  FOR ALL USING (seller = CURRENT_USER());
```

### Implementation

```
crates/seal-sql/src/rls.rs
  ├── Policy { name, table, action, using_expr, with_check_expr }
  ├── RlsManager.enable_rls(table)
  ├── RlsManager.add_policy(policy)
  └── RlsManager.check_access(table, action, user, row_owner) → bool
```

### How RLS Will Work with RPC

```
1. Client sends signed RPC request
2. RPC extracts sender address from ML-DSA signature
3. SQL engine executes query
4. RLS filters results based on sender identity
5. Only permitted rows returned
```

---

## Private Data Access Patterns

### Pattern 1: MPC Aggregates

For queries like "what's the average salary?" without revealing individual rows:

```
Client A: seal_querySql("SELECT AVG(salary) FROM employees")
  │
  ▼
MPC Protocol (SPDZ over Goldilocks field)
  ├── Node 1: secret share of salary data
  ├── Node 2: secret share of salary data
  └── Node 3: secret share of salary data
  │
  ▼
Result: AVG = 75000 (no individual salary revealed)
```

Built in `crates/seal-mpc/`: `spdz_sum`, `spdz_count`, PSI for JOINs.

### Pattern 2: ZK Query Proofs

Client proves a statement about their data without revealing it:

```
"Prove my balance > 1000 without revealing the actual balance"
  │
  ▼
ZK Proof (STARK via RISC Zero / SP1)
  ├── Witness: actual balance (private)
  ├── Public input: threshold (1000), state root
  └── Proof: verifiable by anyone
```

Built in `crates/seal-zk/`: `StubProver`, `RiscZeroProver`, `Sp1Prover`.

### Pattern 3: Private Set Intersection (PSI)

For JOINs across private tables without revealing non-matching rows:

```
App A has: users = {alice, bob, charlie}
App B has: customers = {bob, dave, eve}

PSI result: {bob}  (intersection, without revealing other rows)
```

Built in `crates/seal-mpc/src/psi.rs`.

---

## Security Boundaries

```
UNTRUSTED                         TRUST BOUNDARY                    TRUSTED
─────────                         ──────────────                    ───────
curl / CLI   ──── HTTP ────────>  RPC Server   ─── Auth check ──>  SQL Engine
                                    │
                                    ├── Verify ML-DSA signature
                                    ├── Check namespace ownership
                                    ├── Apply RLS policies
                                    └── Rate limit
```

### What the RPC Server Must Enforce

1. **Authentication**: Every mutating request signed with ML-DSA
2. **Authorization**: RLS policies checked before returning data
3. **Namespace isolation**: Apps can't read other apps' private tables
4. **Rate limiting**: Prevent DoS via expensive queries
5. **Input validation**: SQL size limits, query complexity limits
6. **Transport encryption**: ML-KEM-768 for PQ-safe transport (planned)
