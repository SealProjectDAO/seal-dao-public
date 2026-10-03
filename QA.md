# Seal DAO — Security & Architecture Q&A

---

## Q1: Where does table data live and how is it encrypted? `#DATA-RESIDENCY`

### Data residency by table type

**Public / Shared tables** — replicated by all validators, data in three layers:
- **In-memory**: `HashMap<String, Vec<Row>>` in the SQL engine for current-block query execution
- **Merkle B-tree**: content-addressed state (`"table:pk"` -> serialized row), produces state root committed in each block header
- **On-disk (sled)**: persistent KV store with 4 trees — `blocks`, `meta`, `tables`, `schemas`

**Private tables** — only a commitment hash (SHA3 of ciphertext) lives on-chain; encrypted data lives off-chain on designated storage nodes. Three sub-types:
- **AppPrivate**: owning app can read; app can aggregate via MPC
- **UserPrivate**: owning user only; fully opaque to everyone else
- **RegulatedPrivate**: access gated by ZK proofs

Private table metadata (schema, commitment, replication factor) is on-chain. Actual rows are encrypted and stored on `replication`-count off-chain nodes.

**Visibility model** (per-namespace):
- `PRIVATE` (default) — only owning app
- `SHARED { granted_apps }` — explicit grants
- `PUBLIC` — any app can read

### Encryption

**At rest (private tables)**:
- Target: AES-256-GCM, key derived from owner's ML-KEM keypair via HKDF
- Current implementation: XOR placeholder with SHA3-derived keystream (not production-ready)
- Format: `EncryptedTable { ciphertext, nonce: [u8; 12], commitment: SHA3(ciphertext) }`

**In transit (P2P)**:
1. Key exchange: ML-KEM-768 (FIPS 203) -> 32-byte shared secret
2. Symmetric: SHA3-CTR (custom) — `keystream[i] = SHA3(key || nonce || block_index)`, XOR
3. Auth: SHA3-MAC encrypt-then-MAC — `MAC = SHA3(key || "mac" || nonce || ciphertext)`
4. Wire format: `nonce (8B) || ciphertext || mac (32B)`
5. Production target: ChaCha20-Poly1305 (current custom AEAD is not standard)

**Crypto stack (all post-quantum, no classical)**:
| Primitive | Algorithm | Use |
|-----------|-----------|-----|
| Signatures | ML-DSA-65 (Dilithium, FIPS 204) | Blocks, transactions, VRF |
| Key encapsulation | ML-KEM-768 (Kyber, FIPS 203) | P2P key exchange, private table key derivation |
| Hashing | SHA3-256 (FIPS 202) | State roots, Merkle nodes, key derivation |

**Row-level security** (PostgreSQL-style):
- `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` + `CREATE POLICY`
- Predicates: `owner = CURRENT_USER()`, `HAS_TOKEN('SYMBOL', amount)`, literal `true`/`false`
- OR semantics (any matching policy grants access); RLS enabled + no policies = deny all

### Current gaps
1. At-rest encryption is placeholder XOR, not AES-256-GCM
2. In-transit cipher is custom SHA3-CTR, not a standard AEAD
3. Private table off-chain replication protocol not fully implemented

---

## Q2: Right to be forgotten for public tables — salted rows + mandatory SEAL invoicing `#STORAGE-FORGET`

### Problem

Public tables are replicated by all validators and their Merkle roots are committed in block headers. Block headers are permanent. How do we provide a "right to be forgotten" when the chain is immutable?

### Design: two-layer separation

**Layer 1 — Block headers (immutable, permanent):**
- Contains only the Merkle state root (a single SHA3-256 hash)
- No row data, no schema, no plaintext — just an opaque commitment

**Layer 2 — Active state (economic lifecycle, forgettable):**
- Actual row data + per-row salts live here, on validator disks
- Retention requires continuous SEAL token payment from the table owner
- When payment stops, data and salts are pruned — the old Merkle roots become meaningless

### A. Row salting (anti-correlation)

Current Merkle leaf:
```
leaf = SHA3("table:pk" || serialized_row)
```

With salting:
```
leaf = SHA3("table:pk" || salt || serialized_row)
salt = random 32 bytes, generated at INSERT, rotated on UPDATE
```

Effects:
- Same row content at different times produces different leaf hashes (salt differs)
- Historical Merkle roots cannot be used to reconstruct or correlate data without the salts
- Salts are stored alongside rows in active state (Layer 2) only — never in block headers

### B. Mandatory SEAL token invoicing

Every table has a **storage lease**:

```
StorageLease {
    table: "namespace.table_name",
    owner: SealAddress,
    paid_through: Timestamp,        // lease expiry
    row_count: u64,
    byte_size: u64,
    rate: SealAmount,               // per-byte-epoch, governance-set
}
```

**Write operations**: burn SEAL (or Compute Credits per SPEC §10.3) proportional to bytes written. Every INSERT/UPDATE is invoiced.

**Read operations**: every SELECT burns a micro-amount of SEAL from the querying user, or alternatively the querying user must stake N SEAL to access a namespace (capital lockup, no burn). Both are enforceable because queries go through the validator SQL engine.

**Expiry / forgetting cycle**:
1. `paid_through < now` → table enters **grace period** (e.g., 30 days, governance-adjustable)
2. Grace period expires → validators **prune all rows and salts** from active state
3. Merkle roots in old blocks remain but are now opaque — no data, no salts, no reconstruction possible

**Archive node rule**: Serving expired/pruned data is a **slashable offense**. Governance vote can grant exemptions (e.g., legal/regulatory holds). This ensures the right to be forgotten is enforced network-wide, not just by cooperative nodes.

### C. What an observer sees after forgetting

| Data | Accessible after expiry? |
|------|--------------------------|
| Block headers + Merkle roots | Yes (permanent, opaque hashes) |
| That *some* table existed at height H | Yes (transaction log) |
| Row contents | No — pruned from all active nodes |
| Row salts | No — pruned with the rows |
| Correlation between historical roots | No — salts make leaf hashes independent |

### D. What needs to be built

1. Row salt field in `seal-sql` — `salt: [u8; 32]` per row, mixed into Merkle leaf hash
2. `StorageLease` struct in `seal-token` / `seal-economics` — per-table lease tracking
3. Write invoicing — burn/CC deduction in transaction pipeline
4. Read invoicing — micro-fee or stake-gate in SQL engine query path
5. Lease expiry + pruning hook — connect `PruningManager` to lease state
6. Grace period governance parameter — adjustable by Technical Council

### Status

This design is **not yet formalized in SPEC.md or implemented**. Current state:
- SQL DELETE works but doesn't erase historical Merkle commitments
- State pruning exists (mark-and-sweep GC for Merkle history) but is not tied to economic leases
- Storage rent is mentioned in SPEC §10.3 as token utility but has zero implementation
- Row salting is absent — rows hash deterministically today
- Token-gated reads (RLS `HAS_TOKEN()`) check balance but don't charge

---

## Q3: What demo applications exist? `#DEMO-APPS`

### Interactive CLI demos

| Command | What it does |
|---------|-------------|
| `cargo run -p seal-cli -- demo` | Multi-app deployment: `blog.seal` + `market.seal` — SQL ops, RLS, cross-app access, block production |
| `cargo run -p seal-cli -- dev [--slots N]` | Local devnet with 1s slots, block production, SQL transactions |
| `cargo run -p seal-cli -- wallet` | TUI wallet — create/import/export keys, ML-DSA-65 signing |

### Example apps (interactive REPLs)

| App | Path | What it shows |
|-----|------|---------------|
| **Seal Marketplace** | `examples/seal-marketplace/` | Multi-user marketplace — list/buy/browse, PQC-signed txs, checked arithmetic balances |
| **Seal Notes** | `examples/seal-notes/` | Encrypted notebook — owner-only RLS, XOR-encrypted notes, "PHP+MySQL but on-chain" |

### GUI / desktop / mobile apps

| App | Path | Stack |
|-----|------|-------|
| **Seal Wallet (Desktop)** | `apps/seal-wallet/` | Electron + `standalone.html`, Rust crypto via WASM |
| **Seal Explorer** | `apps/seal-explorer/` | egui GUI — blocks, validators, chain overview |
| **Seal Wallet (Android)** | `apps/seal-wallet-android/` | Rust FFI/JNI, QR, biometric auth (scaffold) |

### Cross-chain bridges

| Bridge | Path | Status |
|--------|------|--------|
| Solana | `bridges/solana/` | Anchor program skeleton — lock/unlock/threshold sigs |
| Stellar | `bridges/stellar/` | Soroban contract skeleton — lock/unlock/proof verification |

### SDKs

| SDK | Path | Status |
|-----|------|--------|
| JavaScript | `sdks/js/` | API client + type defs (scaffold) |
| Python | `sdks/python/` | Async client (scaffold) |
| WASM | `sdks/wasm/` | Client-side crypto — SHA3, ML-DSA, SQL parsing |

### Test suite

804 tests total — property tests (SQL, token, Merkle, consensus), integration tests (block production, state roots, RLS). These serve as living documentation of every feature.

### Planned but NOT yet implemented

**GUI features (PLAN.md Phase G):**
- Bridge UI in wallet (deposit/withdraw Solana/Stellar)
- Governance UI in wallet (proposals, conviction voting, delegation)
- SQL console (query editor, results table, schema browser)
- `seal-test` framework — in-memory node + mock bridge for app developers

**Developer tooling (ROADMAP.md Phase 6):**
- `seal app deploy` — app deployment with namespace management
- Testnet faucet CLI (`seal faucet request`)

**Reference apps described in SPEC/docs but with NO code:**
- `social.seal` — social app with user profiles, app-private tables (described in `docs/SHARDING.md`)
- `kyc.seal` — KYC/identity with regulated-private tables + ZK proofs (described in `docs/SHARDING.md`)
- Sealed-bid auctions — BOREALIS MPC protocol (SPEC §4.6)
- Cross-org private aggregation — `SELECT SUM(...) MPC BETWEEN org_a, org_b` (SPEC §4.6)
- TEE/AI inference — GPU TEE compute layer (SPEC architecture diagram, Phase 3+)
- Reference migrated app — `seal migrate` CLI exists but no demo PostgreSQL app migrated through it

**Private table use cases described but no demo:**
- App-Private: user preferences, shopping carts, saved searches
- User-Private: personal notes (partially covered by Seal Notes), local scratch data
- Regulated-Private: ID docs, medical records, financial statements, credentials

**Bridges not started:**
- Ethereum bridge (deferred, ~2-3 months estimated)
- Bitcoin bridge (deferred, ~3-6 months estimated)

### App ideas from brainstorm (yyy.txt) mapped to Seal's SQL-on-chain model

Seal's unique advantage: these are "just SQL schemas + RLS policies", not custom smart contracts.

| App idea | Seal advantage | Table model |
|----------|---------------|-------------|
| **Decentralized identity / credentials** | `kyc.seal` — regulated-private tables + ZK proofs (already in spec) | Regulated-Private |
| **Content ownership / publishing** | `blog.seal` demo exists; add IPFS pointers for media, on-chain text | Public |
| **Secure messaging** | User-private tables + ML-KEM P2P transport — PQC native | User-Private |
| **Collaborative docs (CRDT)** | SQL tables as CRDT state store — operational transforms as SQL txs | App-Private or Shared |
| **Decentralized storage pointers** | Public tables with IPFS/Arweave CIDs + Merkle proofs of existence | Public |
| **Task / project management** | Shared tables with RLS — members see own tasks, admins see all | Shared + RLS |
| **Password manager / secrets** | User-private tables, encrypted at rest, ML-KEM key derivation | User-Private |
| **Note-taking / knowledge base** | Seal Notes exists; needs CRDT sync + encrypted private tables | User-Private |
| **Stablecoin payments / remittances** | Token transfers with checked arithmetic, bridge to Solana/Stellar | Public (token ledger) |
| **Decentralized feeds / RSS** | Public tables for post metadata, app-private for personalization | Public + App-Private |

**Key friction points identified (from Web3 landscape):**
- Wallet/seed phrase onboarding — Seal has ML-DSA wallets but no account abstraction or social login yet
- Gas/transaction fees — Seal has burn-and-mint CC model in spec but not implemented
- Real-time sync performance — CRDT-based apps need low-latency; Seal's slot time matters here
- Integration with existing tools (calendar, email) — no SDK integrations exist yet
