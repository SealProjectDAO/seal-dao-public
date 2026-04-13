# Seal DAO Website Specification

Target: [https://seal-dao.network](https://seal-dao.network)

---

## 1. Design System

### 1.1 Color Palette

| Token              | Hex       | Usage                                      |
|--------------------|-----------|---------------------------------------------|
| `--bg-primary`     | `#0A0A0F` | Page background, dark base                  |
| `--bg-secondary`   | `#12121A` | Card backgrounds, elevated surfaces         |
| `--bg-tertiary`    | `#1A1A26` | Code blocks, input fields                   |
| `--border-subtle`  | `#2A2A3A` | Card borders, dividers                      |
| `--border-hover`   | `#3A3A50` | Interactive element borders on hover         |
| `--text-primary`   | `#E8E8ED` | Body text, headings                         |
| `--text-secondary` | `#9090A0` | Labels, captions, secondary info            |
| `--text-muted`     | `#606070` | Placeholder text, disabled states           |
| `--accent-blue`    | `#4A90D9` | Primary links, active states, CTA buttons   |
| `--accent-blue-dim`| `#2A5A8A` | Hover state for blue accent                 |
| `--accent-green`   | `#4ADE80` | Success states, "live" indicators           |
| `--accent-amber`   | `#FBBF24` | Warnings, testnet labels                    |
| `--accent-red`     | `#F87171` | Errors, destructive actions                 |
| `--code-bg`        | `#0D0D14` | Inline code and code block background       |

No light mode. One theme only. Developers work in dark mode.

### 1.2 Typography

| Element            | Font                  | Weight | Size    | Line Height |
|--------------------|-----------------------|--------|---------|-------------|
| H1 (hero)          | JetBrains Mono        | 700    | 48px    | 1.1         |
| H2 (section)       | JetBrains Mono        | 600    | 32px    | 1.2         |
| H3 (subsection)    | JetBrains Mono        | 600    | 24px    | 1.3         |
| Body               | Inter                 | 400    | 16px    | 1.6         |
| Body small          | Inter                 | 400    | 14px    | 1.5         |
| Code inline        | JetBrains Mono        | 400    | 14px    | 1.5         |
| Code block         | JetBrains Mono        | 400    | 13px    | 1.6         |
| Nav link           | Inter                 | 500    | 14px    | 1.0         |
| Button label       | Inter                 | 600    | 14px    | 1.0         |

Font loading: Self-hosted WOFF2 files. `font-display: swap`. No Google Fonts CDN dependency.

### 1.3 Spacing Scale

Based on 4px grid:

| Token  | Value | Usage                                |
|--------|-------|--------------------------------------|
| `xs`   | 4px   | Tight gaps, inline padding           |
| `sm`   | 8px   | Icon gaps, list item padding         |
| `md`   | 16px  | Card padding, element gaps           |
| `lg`   | 24px  | Section padding (inner)              |
| `xl`   | 32px  | Card margins                         |
| `2xl`  | 48px  | Section gaps                         |
| `3xl`  | 64px  | Page section vertical spacing        |
| `4xl`  | 96px  | Hero padding, major section breaks   |

### 1.4 Layout

- Max content width: 1120px, centered.
- Grid: 12-column CSS grid with 24px gutter.
- Breakpoints:
  - `sm`: 640px (single column, stacked)
  - `md`: 768px (two-column layouts)
  - `lg`: 1024px (full nav, three-column grids)
  - `xl`: 1280px (max width kicks in)
- No horizontal scrolling at any viewport width.

### 1.5 Components

#### Card

```
┌─────────────────────────────────┐
│  [optional icon/emoji]          │  bg: --bg-secondary
│  Title (H3, JetBrains Mono)    │  border: 1px solid --border-subtle
│                                 │  border-radius: 8px
│  Body text (Inter, --text-      │  padding: 24px
│  secondary)                     │  hover: border -> --border-hover
│                                 │
│  [optional code snippet]        │
└─────────────────────────────────┘
```

#### Code Block

```
┌─────────────────────────────────┐
│ [language label]         [copy] │  bg: --code-bg
│                                 │  border: 1px solid --border-subtle
│  code here...                   │  border-radius: 6px
│  with syntax highlighting       │  padding: 16px
│                                 │  font: JetBrains Mono 13px
└─────────────────────────────────┘
```

Syntax highlighting: minimal palette. Keywords in `--accent-blue`, strings in `--accent-green`, comments in `--text-muted`, types in `--accent-amber`.

#### Button

| Variant   | Background       | Text             | Border               |
|-----------|------------------|------------------|-----------------------|
| Primary   | `--accent-blue`  | `#FFFFFF`        | none                  |
| Secondary | transparent      | `--accent-blue`  | 1px `--accent-blue`   |
| Ghost     | transparent      | `--text-secondary`| none                 |

All buttons: `border-radius: 6px`, `padding: 10px 20px`, `cursor: pointer`.

#### Navigation Bar

Fixed top. Height: 56px. Background: `--bg-primary` with `backdrop-filter: blur(12px)` at 90% opacity. Bottom border: 1px `--border-subtle`.

```
┌──────────────────────────────────────────────────────────┐
│  [SEAL logo]  Developers  Validators  Governance  Docs  │
│               Blog  Community           [GitHub icon]    │
└──────────────────────────────────────────────────────────┘
```

- Logo: wordmark "SEAL" in JetBrains Mono 700, white. No graphic logo for now.
- Mobile (<1024px): hamburger menu, slide-in from right.

#### Footer

```
┌──────────────────────────────────────────────────────────┐
│  SEAL                                                     │
│                                                           │
│  Protocol          Developers       Community             │
│  Specification     Getting Started  Discord               │
│  Consensus         SQL Reference    GitHub                │
│  Governance        RPC API          Twitter               │
│  Token Economics   SDKs             Blog                  │
│                                                           │
│  ─────────────────────────────────────────────            │
│  Built with Rust. Verified with math.                     │
│  MIT License  |  Source on GitHub                          │
└──────────────────────────────────────────────────────────┘
```

---

## 2. Page Specifications

### 2.1 Landing Page (`/`)

#### Section A: Hero

Full viewport height. No background image or gradient animation. Clean.

```
┌──────────────────────────────────────────────────────────┐
│                                                           │
│                                                           │
│     SQL on a blockchain.                                  │  H1, 48px
│     Post-quantum secure.                                  │  H1, 48px
│                                                           │
│     Deploy apps with PostgreSQL schemas.                  │  Body, --text-secondary
│     The network handles replication, privacy,             │
│     and verification.                                     │
│                                                           │
│     [Get Started]  [Read the Spec]                        │  Primary + Secondary buttons
│                                                           │
│     $ seal app deploy --schema ./my_app.sql               │  Code block, single line
│                                                           │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

#### Section B: The Pitch (3 sentences)

Centered text block, max-width 720px.

> You know SQL. You know how to build apps with PostgreSQL. Seal lets you
> deploy that same schema to a decentralized network that handles replication
> across nodes, enforces row-level access control on-chain, and proves
> query correctness with zero-knowledge proofs. No Solidity. No new
> languages. Just SQL.

#### Section C: Key Features

3-column grid (stacks to 1 column on mobile). Six cards, two rows.

| Card | Title | Content |
|------|-------|---------|
| 1 | PostgreSQL on-chain | Deploy `CREATE TABLE`, `INSERT`, `SELECT` -- the SQL you already know. Row-level security via `CREATE POLICY`. No new smart contract language. |
| 2 | Post-quantum crypto | ML-DSA signatures, ML-KEM encryption, SHA-3 hashing. NIST-standardized algorithms (FIPS 203/204). Secure against both classical and quantum computers. |
| 3 | Three privacy levels | **Public** tables: anyone can read. **RLS-protected** tables: row-level policies control access. **Private** tables: encrypted at rest, MPC for aggregate queries. |
| 4 | Namespace sharding | Each app gets its own namespace and shard. Your tables don't compete with other apps for throughput. Deploy `my_app.seal` and own your keyspace. |
| 5 | ZK-verified queries | SQL writes generate zero-knowledge proofs. Validators verify proofs instead of re-executing queries. Reads execute locally against Merkle-verified state. |
| 6 | Verifiable everything | STARK proofs per block (no SNARK wrapper -- stays post-quantum). VRF-based leader election. Threshold committee signatures. All math, no trust. |

#### Section D: How It Works

Vertical sequence, numbered steps. Each step has a code block on the right (or below on mobile).

**Step 1: Define your schema**
```sql
CREATE TABLE posts (
    id BIGINT PRIMARY KEY,
    author SEAL_ADDRESS NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE POLICY owner_write ON posts
    FOR ALL
    USING (author = CURRENT_USER())
    WITH CHECK (author = CURRENT_USER());

CREATE POLICY public_read ON posts
    FOR SELECT USING (true);
```

**Step 2: Deploy to the network**
```bash
$ seal app deploy --schema ./blog.sql --name "my_blog"
App deployed: my_blog.seal
Namespace: seal1x7f...k3m/my_blog
Tables: posts (1 table, 2 policies)
```

**Step 3: Write data (on-chain transaction)**
```bash
$ seal sql --app my_blog \
    "INSERT INTO posts (id, author, body)
     VALUES (1, CURRENT_USER(), 'Hello, decentralized world')"
Transaction: 0x3a7f...c812
ZK proof generated (local, 1.2s)
Block: #42,891 (finalized)
```

**Step 4: Read data (local, free)**
```bash
$ seal sql --app my_blog "SELECT * FROM posts ORDER BY created_at DESC"
┌────┬──────────────┬───────────────────────────────┬─────────────────────┐
│ id │ author       │ body                          │ created_at          │
├────┼──────────────┼───────────────────────────────┼─────────────────────┤
│  1 │ seal1x7f..   │ Hello, decentralized world    │ 2026-04-02 14:30:00 │
└────┴──────────────┴───────────────────────────────┴─────────────────────┘
Verified against state root: 0x9b2c...
```

#### Section E: Comparison Table

Full-width table. Horizontal scroll on mobile.

| | Traditional (PHP + MySQL) | Web3 (Solidity + IPFS) | Seal DAO |
|---|---|---|---|
| **Data model** | SQL tables | Key-value mappings | SQL tables |
| **Query language** | SQL | Custom ABI calls | SQL |
| **Access control** | App-level (roll your own) | Contract-level `require()` | Row-level security (`CREATE POLICY`) |
| **Replication** | You manage replicas | Blockchain handles it | Blockchain handles it |
| **Privacy** | Your server, your rules | Everything public | Public + RLS + encrypted tables |
| **Private computation** | N/A | N/A | MPC aggregates, ZK proofs |
| **Cryptography** | TLS (quantum-vulnerable) | ECDSA (quantum-vulnerable) | ML-DSA + ML-KEM (post-quantum) |
| **Verification** | Trust the server | Verify on-chain (re-execute) | ZK proofs (verify without re-executing) |
| **Cost model** | Server bills | Gas fees per opcode | Gas fees per SQL operation |
| **Learning curve** | Low (you know SQL) | High (new language) | Low (you know SQL) |

Highlight the "Seal DAO" column with a subtle `--accent-blue` top border.

#### Section F: Network Stats (Placeholder)

Horizontal row of 4 numbers. Values are placeholder until mainnet.

```
4s finality  |  ~10K TPS target  |  100-node committees  |  Post-quantum from day one
```

Style: large monospace numbers (`JetBrains Mono 32px 700`), label underneath in `--text-secondary`.

#### Section G: Call to Action

```
┌──────────────────────────────────────────────────────────┐
│                                                           │
│     Start building.                                       │  H2
│                                                           │
│     Read the specification, run a local node,             │  Body, --text-secondary
│     or deploy your first app on testnet.                  │
│                                                           │
│     [Read the Spec]  [Run a Node]  [Join Discord]         │  3 buttons
│                                                           │
└──────────────────────────────────────────────────────────┘
```

---

### 2.2 Developers Page (`/developers`)

#### Section A: Header

```
Developers                                                  H1
Build SQL-powered decentralized apps.                       Body, --text-secondary
No new language. No ABI encoding. Just PostgreSQL.
```

#### Section B: Getting Started (Quick Start Guide)

Step-by-step walkthrough in card format.

**Prerequisites**
```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Seal CLI
cargo install seal-cli

# Or download the binary
curl -sSL https://seal-dao.network/install.sh | sh
```

**Start a local node**
```bash
$ seal node --dev
Local dev node running at localhost:9944
Block production: 4s slots
Genesis account: seal1dev0...
Balance: 1,000,000 SEAL (dev tokens)
```

**Deploy an app**
```bash
$ seal app deploy --schema ./my_app.sql --name "my_app" --dev
```

**Interact via SQL**
```bash
$ seal sql --app my_app "SELECT * FROM my_table"
```

#### Section C: SQL Reference

Summary table of supported SQL. Link to full reference in docs.

**Supported DDL:**
- `CREATE TABLE`, `ALTER TABLE`, `DROP TABLE`
- `CREATE INDEX`, `DROP INDEX`
- `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`
- `CREATE POLICY`, `DROP POLICY`

**Supported DML:**
- `SELECT` with `JOIN`, `WHERE`, `GROUP BY`, `HAVING`, `ORDER BY`, `LIMIT/OFFSET`
- `INSERT INTO ... VALUES`
- `UPDATE ... SET ... WHERE`
- `DELETE FROM ... WHERE`

**Supported types:** `SMALLINT`, `INTEGER`, `BIGINT`, `REAL`, `DOUBLE PRECISION`, `NUMERIC(p,s)`, `TEXT`, `BYTEA`, `BOOLEAN`, `TIMESTAMP`, `TIMESTAMPTZ`, `INTERVAL`, `UUID`, `JSONB`, `SEAL_ADDRESS`, `SEAL_AMOUNT`

**Aggregates:** `COUNT`, `SUM`, `AVG`, `MIN`, `MAX`

Link: "Full SQL reference ->"

#### Section D: Transaction Types

Table listing all transaction types with descriptions:

| Type | Description | Cost |
|------|-------------|------|
| `CreateApp` | Deploy a new app namespace with SQL schema | Base fee + schema size |
| `SqlExec` | Execute SQL write statement(s) | Base fee + rows affected |
| `AlterSchema` | Modify table structure (migration) | Base fee + schema diff |
| `Transfer` | Native SEAL token transfer | Base fee |
| `BridgeIn` | Deposit from Solana/Stellar | Base fee + bridge fee |
| `BridgeOut` | Withdraw to Solana/Stellar | Base fee + bridge fee |
| `StakeDeposit` | Stake SEAL tokens for validation | Base fee |
| `StakeWithdraw` | Unstake SEAL tokens (unbonding period) | Base fee |

#### Section E: RPC API

Placeholder section with planned endpoints.

```
POST /rpc

Methods:
  seal_submitTransaction   Submit a signed transaction
  seal_getBlock            Get block by number or hash
  seal_getState            Get current state root
  seal_queryApp            Execute a read query against an app
  seal_getAccount          Get account balance and nonce
  seal_getAppSchema        Get the SQL schema of a deployed app
  seal_subscribe           WebSocket subscription to new blocks/events
```

Link: "Full RPC reference ->"

#### Section F: SDKs

Three cards for Rust, JavaScript/WASM, and Python SDKs.

**Rust (native)**
```rust
use seal_sdk::Client;

let client = Client::connect("https://rpc.seal-dao.network").await?;
let app = client.app("my_blog").await?;
let posts = app.query("SELECT * FROM posts LIMIT 10").await?;
```

**JavaScript/TypeScript (WASM)**
```typescript
import { SealClient } from '@seal-dao/sdk';

const client = new SealClient('https://rpc.seal-dao.network');
const app = await client.app('my_blog');
const posts = await app.query('SELECT * FROM posts LIMIT 10');
```

**Python (PyO3)**
```python
from seal_sdk import Client

client = Client("https://rpc.seal-dao.network")
app = client.app("my_blog")
posts = app.query("SELECT * FROM posts LIMIT 10")
```

Status labels on each card: Rust = "Available", JS/Python = "Coming soon" in `--accent-amber`.

---

### 2.3 Validators Page (`/validators`)

#### Section A: Header

```
Validators                                                  H1
Run a node. Secure the network. Earn SEAL.                  Body, --text-secondary
```

#### Section B: How Consensus Works

Brief explanation with diagram.

```
Each slot (4 seconds):
1. Validators compute VRF(secret_key, seed || slot)
2. If VRF output < threshold(stake), you're the proposer
3. Proposer builds block + ZK proof of valid state transition
4. Committee (100 VRF-selected members) verifies and signs
5. Threshold signature from >2/3 committee finalizes the block

Result: single-slot finality, secret leader election, PQC-native
```

Key properties listed as bullet points:
- Algorand-style pure proof-of-stake
- Secret leader election (VRF) -- no DDoS targeting
- 4-second slot time, single-slot finality
- Post-quantum VRF (lattice-based, Module-LWE/SIS)
- Ringtail threshold signatures for committee (96% signature size reduction)
- STARK proofs per block (no SNARK wrapper)

#### Section C: Hardware Requirements

Table:

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 8 cores, x86_64 or ARM64 | 16+ cores |
| RAM | 32 GB | 64 GB |
| Storage | 500 GB NVMe SSD | 2 TB NVMe SSD |
| Network | 100 Mbps symmetric | 1 Gbps symmetric |
| OS | Linux (Ubuntu 22.04+, Debian 12+) | Ubuntu 24.04 LTS |

Notes:
- ZK proof generation is CPU-intensive. More cores = faster proofs.
- GPU acceleration for ZK provers is supported but not required.
- Storage grows with network usage. Archive nodes need more.
- PQC signatures are larger than classical (3.3 KB vs 64 bytes). Budget bandwidth accordingly.

#### Section D: Staking Guide

Step-by-step:

```bash
# 1. Install and sync
$ seal node --sync
Syncing... (estimated 2-4 hours for full sync)

# 2. Generate validator keys
$ seal keys generate --type validator
VRF key pair: saved to ~/.seal/vrf_key
Signing key pair: saved to ~/.seal/signing_key
Address: seal1v8k...

# 3. Fund your validator account
# Transfer SEAL tokens to your validator address

# 4. Register as validator
$ seal staking deposit --amount 10000 --key ~/.seal/signing_key
Transaction submitted: 0x7c3f...
Activation epoch: #1,247 (~20 minutes)

# 5. Start validating
$ seal node --validator --key-dir ~/.seal/
Validator active. Participating in consensus.
```

#### Section E: Rewards

Explanation of reward structure:

- **Block proposer reward**: Proposer receives a portion of transaction fees from the block.
- **Committee participation**: Committee members share a portion of fees for voting.
- **Fee model**: EIP-1559 dynamic base fee. Base fee is burned. Priority tips go to proposer.
- **Slashing**: Equivocation (signing two blocks at same height) results in stake slash. Downtime results in missed rewards but no slashing.
- **Unstaking**: Unbonding period of 7 days. Validator remains in the active set during unbonding but stops earning if they go offline.

---

### 2.4 Governance Page (`/governance`)

#### Section A: Header

```
Governance                                                  H1
Three-body system. No single point of control.              Body, --text-secondary
```

#### Section B: The Three Bodies

3-column layout (stacks on mobile). One card per body.

**Token House**
- All SEAL holders
- Token-weighted voting with conviction multiplier:
  - 1x (no lock), 2x (30-day lock), 4x (90-day lock)
- Decides: treasury spending, economics parameters, protocol upgrades
- Delegation with 4% cap per delegate

**Technical Council**
- 7-11 members elected by Token House
- 1-year terms
- Whitelist emergency actions (security patches, PQC algorithm rotation)
- Vet protocol upgrades for correctness
- Cannot unilaterally pass proposals

**Service Operators Council**
- Representatives of node and TEE operators
- Advisory vote on infrastructure parameters
- Binding veto on changes that break SLAs
- Infrastructure voice beyond token speculation

#### Section C: Proposal Tracks

Table:

| Track | Approval | Quorum | Timelock | Vote Period |
|-------|----------|--------|----------|-------------|
| Parameter Change | >50% | 10% | 3 days | 5 days |
| Protocol Upgrade | >66% | 15% | 14 days | 14 days |
| Treasury (small, <1%) | >50% | 10% | 2 days | 5 days |
| Treasury (large) | >66% | 15% | 7 days | 7 days |
| Emergency | >75% + TC whitelist | 5% | 6 hours | 1 day |
| Constitutional | >75% | 20% | 28 days | 14 days |

#### Section D: Anti-Plutocracy Measures

Bullet list:
- Conviction voting rewards commitment over capital
- Delegate power capped at 4% of circulating supply
- Service Operators Council as infrastructure-user check
- Adaptive quorum: 5% floor, 20% ceiling, adjusted on 90-day trailing participation
- Foundation/team tokens: governance power vests 6 months after economic vesting

#### Section E: PQC-Specific Governance

Brief section explaining:
- Cryptographic agility mandate: signature schemes upgradeable without hard fork
- Dedicated emergency sub-track for rotating PQC primitives if a scheme is broken
- Pre-approved fallback algorithm list maintained by Technical Council
- All governance votes signed with ML-DSA from day one

---

### 2.5 Docs Page (`/docs`)

#### Section A: Header

```
Documentation                                               H1
Specifications, architecture, and formal verification.      Body, --text-secondary
```

#### Section B: Core Documents

Card grid linking to documents. Each card has title, one-line description, and document type label.

| Document | Description | Type |
|----------|-------------|------|
| Technical Specification | Full protocol spec: consensus, crypto, SQL, networking, storage, token economics | Spec |
| Governance Specification | Three-body governance, proposal tracks, conviction voting, treasury | Spec |
| Consensus Comparison | Analysis of PBFT, Tendermint, Algorand, HotStuff, Mysticeti with PQC compatibility | Analysis |
| Formal Methods | Verification plan: TLA+, Lean 4, Rocq, Kani, Miri, fuzz | Plan |

#### Section C: Architecture

Reproduction of the architecture diagram from SPEC.md in a clean, styled format. Layers:

1. Client layer (SQL engine, ZK prover, wallet bridge)
2. P2P network layer (libp2p, QUIC transport)
3. Consensus layer (VRF, ZK block validator, state storage)
4. Cryptography layer (ML-DSA, ML-KEM, SHA-3, LB-VRF, Ringtail)
5. TEE compute layer (Phase 3+)

#### Section D: Formal Verification

Summary of formal methods used:

| Tool | Purpose | What It Covers |
|------|---------|----------------|
| TLA+ | Protocol-level model checking | Consensus safety/liveness, bridge invariants, token conservation |
| Lean 4 | Machine-checked proofs | Merkle tree correctness, VRF properties, cryptographic primitives |
| Rocq (Coq) | Theorem proving | SQL engine correctness, access control policy soundness |
| Kani | Rust model checking | Arithmetic overflow, bounds checking, panic freedom |
| Miri | Undefined behavior detection | Memory safety, unsafe code validation |
| cargo-fuzz | Fuzz testing | Parser robustness, serialization round-trips, edge cases |

#### Section E: Crate Map

Table of all workspace crates:

| Crate | Description |
|-------|-------------|
| `seal-crypto` | PQC primitives (ML-DSA, ML-KEM, SHA-3) |
| `seal-vrf` | Lattice-based VRF (LB-VRF) |
| `seal-consensus` | Block production, committee voting, finality |
| `seal-threshold` | Ringtail threshold signatures |
| `seal-sql` | PostgreSQL-compatible SQL parser and executor |
| `seal-zk` | ZK proof generation and verification |
| `seal-mpc` | MPC protocols (SPDZ) for private computation |
| `seal-p2p` | libp2p networking, gossip, discovery |
| `seal-storage` | Merkle B-tree state storage |
| `seal-node` | Full node binary |
| `seal-cli` | Command-line interface |
| `seal-wallet` | Key management, address derivation |
| `seal-bridge` | Solana/Stellar bridge logic |
| `seal-types` | Shared types and serialization |
| `seal-vm` | Transaction execution and state transitions |
| `seal-sdk` | Client SDK for app developers |

---

### 2.6 Blog Page (`/blog`)

#### Layout

```
Blog                                                        H1
Protocol updates, research notes, and release logs.         Body, --text-secondary

┌───────────────────────────────────────────────────────────┐
│                                                           │
│  [date]  [tag: protocol | research | release]             │
│  Post Title (H3, link)                                    │
│  First 2 lines of post body...                            │  --text-secondary
│                                                           │
│  ─────────────────────────────────────────────            │
│                                                           │
│  [date]  [tag]                                            │
│  Post Title                                               │
│  First 2 lines...                                         │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

- Reverse chronological order
- Tags: `protocol`, `research`, `release`, `governance`
- Tag pills: small rounded labels with subtle background color per tag
- Individual post page: full-width content column (max 720px), markdown rendered
- No comments system. Link to Discord for discussion.

Placeholder: display a single card saying "No posts yet. Follow us on Twitter for updates."

---

### 2.7 Community Page (`/community`)

#### Section A: Header

```
Community                                                   H1
Talk to us. Build with us. Break things with us.            Body, --text-secondary
```

#### Section B: Channels

3-column card grid:

**Discord**
- Primary community hub
- Channels: `#general`, `#dev-help`, `#governance`, `#validators`, `#research`
- Link: `https://discord.gg/seal-dao` (placeholder)
- Button: "Join Discord"

**GitHub**
- All code is open source (MIT License)
- Issues, PRs, and discussions welcome
- Link: `https://github.com/seal-dao`
- Button: "View on GitHub"

**Twitter / X**
- Protocol updates, research threads, release announcements
- Link: `https://twitter.com/seal_dao` (placeholder)
- Button: "Follow @seal_dao"

#### Section C: Contributing

Brief section:

```
Contributing

Seal is written in Rust. The codebase is organized as a Cargo workspace
with 16 crates. We use formal verification extensively (TLA+, Lean 4,
Rocq, Kani, Miri, fuzz).

Good first issues are tagged in GitHub. If you're interested in:
- Cryptography: seal-crypto, seal-vrf, seal-threshold
- Database: seal-sql, seal-storage
- Networking: seal-p2p
- ZK/MPC: seal-zk, seal-mpc
- Formal verification: formal/

Read CLAUDE.md in the repo for coding conventions.
```

---

## 3. Technical Implementation

### 3.1 Stack

| Layer | Technology | Notes |
|-------|------------|-------|
| Static site generator | Astro | Content-focused, ships minimal JS, Markdown support |
| Styling | Tailwind CSS | Utility-first, custom theme via `tailwind.config.ts` |
| Syntax highlighting | Shiki | Build-time highlighting, no runtime JS |
| Deployment | Cloudflare Pages | Global CDN, free tier sufficient |
| Domain | `seal-dao.network` | Already registered |
| Analytics | Plausible (self-hosted) or none | No Google Analytics. Privacy-first. |

### 3.2 Performance Targets

| Metric | Target |
|--------|--------|
| Lighthouse Performance | > 95 |
| First Contentful Paint | < 1.0s |
| Total Blocking Time | < 50ms |
| Cumulative Layout Shift | < 0.05 |
| Total page weight (landing) | < 200 KB (gzipped) |
| JavaScript shipped | < 20 KB (only for mobile nav toggle + copy buttons) |

### 3.3 SEO

- Semantic HTML (`<main>`, `<article>`, `<section>`, `<nav>`)
- Open Graph tags per page
- `<title>` format: `Page Name - Seal DAO`
- Landing page title: `Seal DAO - SQL on a Post-Quantum Blockchain`
- Meta description per page
- Canonical URLs
- `robots.txt` and `sitemap.xml` generated at build time

### 3.4 Accessibility

- WCAG 2.1 AA compliance
- All contrast ratios > 4.5:1 for normal text, > 3:1 for large text
- Keyboard navigable (visible focus indicators)
- Skip-to-content link
- Alt text on all images (there are very few images -- mostly code and text)
- `prefers-reduced-motion` respected (no animations to reduce anyway)

### 3.5 File Structure

```
website/
├── SPECS.md              # This file
├── src/
│   ├── layouts/
│   │   └── BaseLayout.astro
│   ├── pages/
│   │   ├── index.astro           # Landing page
│   │   ├── developers.astro      # Developers page
│   │   ├── validators.astro      # Validators page
│   │   ├── governance.astro      # Governance page
│   │   ├── docs.astro            # Docs page
│   │   ├── blog/
│   │   │   └── index.astro       # Blog listing
│   │   └── community.astro       # Community page
│   ├── components/
│   │   ├── Nav.astro
│   │   ├── Footer.astro
│   │   ├── Card.astro
│   │   ├── CodeBlock.astro
│   │   ├── ComparisonTable.astro
│   │   └── StepList.astro
│   └── styles/
│       └── global.css
├── public/
│   ├── fonts/
│   │   ├── JetBrainsMono-*.woff2
│   │   └── Inter-*.woff2
│   └── favicon.svg
├── astro.config.mjs
├── tailwind.config.ts
├── package.json
└── tsconfig.json
```

---

## 4. Content Principles

1. **No marketing fluff.** Every sentence should convey information. Delete words like "revolutionary", "groundbreaking", "next-generation". Say what it does.

2. **Code over prose.** If a code example can explain it, use the code example. The landing page should have more code blocks than paragraphs.

3. **Honest about status.** Label what's live, what's testnet, what's planned. Use status labels: `Live`, `Testnet`, `In Development`, `Planned`.

4. **PostgreSQL is the reference.** Always compare to PostgreSQL, not to other blockchains. The target developer thinks in SQL, not in smart contracts.

5. **Technical precision.** Use correct algorithm names (ML-DSA-65, not "Dilithium"). Cite FIPS/ePrint numbers. Link to papers. Developers will check.

6. **No JavaScript framework animations.** No parallax. No scroll-triggered reveals. No particle backgrounds. The content loads, it's there, you read it.
