# Seal DAO — Technical Specification v0.3

## Vision

A post-quantum secure blockchain with a native distributed SQL database layer —
essentially "PHP+MySQL but on-chain": any developer can deploy SQL-backed applications
on a decentralized, cryptographically verified infrastructure. The chain is its own
PQC-native L1, with bridge support for Solana and Stellar wallets for payments.

Written in Rust. Correctness-critical components verified with formal methods
(Lean, Rocq/Coq, TLA+). Security-critical Rust code validated with Kani, Miri,
and cargo-fuzz.

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                     Seal Native App                     │
│              (Client node + SQL interface)               │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌───────────┐  ┌───────────┐  ┌──────────────────┐   │
│  │ SQL Engine │  │ ZK Prover │  │ Wallet Bridge    │   │
│  │ (local)    │  │ (local)   │  │ (SOL/XLM/SEAL)  │   │
│  └─────┬─────┘  └─────┬─────┘  └────────┬─────────┘   │
│        │              │                  │              │
├────────┴──────────────┴──────────────────┴──────────────┤
│                    P2P Network Layer                     │
│                 (libp2p / QUIC transport)                │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ VRF Consensus│  │ ZK Block │  │ State Storage    │  │
│  │ (PQ-VRF)    │  │ Validator│  │ (Merkle B-tree)  │  │
│  └──────────────┘  └──────────┘  └──────────────────┘  │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │          PQC Cryptography Layer                   │   │
│  │  Signatures: ML-DSA (Dilithium)                   │   │
│  │  Key Encapsulation: ML-KEM (Kyber)                │   │
│  │  Hash: SHA-3 / SHAKE                              │   │
│  │  VRF: LB-VRF (lattice-based, Module-LWE/SIS)     │   │
│  │  Committee Sigs: Threshold (Ringtail/Quorus)      │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │          TEE Compute Layer (Phase 3+)             │   │
│  │  ML/AI inference in GPU TEE (NVIDIA CC)           │   │
│  │  LLM/SLM execution with attestation               │   │
│  │  On-chain attestation verification via ZK          │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## 2. Consensus: PQ-VRF + ZK

### 2.1 Block Production (PQ-VRF Leader Selection — Day One)

Each epoch, validators use a **post-quantum Verifiable Random Function** to
determine if they are selected as block proposer or committee member.

**Mechanism** (inspired by Algorand's Pure PoS, fully PQC from day one):

1. Each validator holds a PQC signing key pair (ML-DSA) and a VRF key pair
   (LB-VRF, rotated per epoch).
2. At each slot `s`, validator `v` computes:
   ```
   (vrf_output, vrf_proof) = LB_VRF_Eval(vrf_sk_v, seed || slot_number)
   ```
3. If `vrf_output < threshold(stake_v)`, validator is elected as proposer.
4. Proposer assembles block, generates ZK proof of valid state transition,
   broadcasts `(block, vrf_proof, zk_proof)`.
5. Committee members (also VRF-selected) verify and vote via threshold signature.
6. Block is finalized when threshold signature from >2/3 weighted committee is produced.

### 2.2 PQ-VRF Construction: LB-VRF

**Primary: LB-VRF** (Esgin, Zhao, Steinfeld, Liu, Liu — FC 2021)

| Property           | Value                                            |
|--------------------|--------------------------------------------------|
| Security assumption| Module-SIS + Module-LWE (same as ML-DSA/ML-KEM) |
| VRF output size    | 84 bytes                                         |
| Proof size         | ~5 KB                                            |
| Evaluation time    | ~3 ms                                            |
| Verification time  | ~1 ms                                            |
| Public key size    | ~3.32 KB                                         |
| Many-time?         | No — few-time (1–5 evaluations per key pair)     |
| Reference          | [ePrint 2020/1222](https://eprint.iacr.org/2020/1222) |

**Few-time limitation mitigation**: Generate a fresh VRF key pair each epoch
(256 slots). Commit the new public key in the last block of the preceding epoch.
Each key pair needs to evaluate at most once per slot attempt. This is the same
approach Algorand plans for their PQ migration.

**Existing Rust code**: [zhenfeizhang/lb-vrf](https://github.com/zhenfeizhang/lb-vrf)
— experimental, needs NTT acceleration, proper testing, memory zeroization, and
security audit. Starting point for our implementation.

**Upgrade path: LaV** (Esgin, Steinfeld, Liu, Ruj — CRYPTO 2023)

| Property           | Value                                            |
|--------------------|--------------------------------------------------|
| VRF output + proof | ~10.3 KB total                                   |
| Many-time?         | Yes — no key rotation needed                     |
| Maturity           | Paper only, no implementation yet                |
| Reference          | [ePrint 2022/141](https://eprint.iacr.org/2022/141) |

When LaV gets a production implementation, migrate to eliminate key rotation.
Same Module-LWE/SIS assumptions, clean upgrade path.

**Constructions evaluated and rejected:**

| Construction        | Reason for rejection                              |
|---------------------|---------------------------------------------------|
| X-VRF (XMSS-based) | **Broken at FC 2024** — WOTS+ non-uniqueness      |
| SPHINCS+-based      | Hash-based sigs are non-unique; fundamentally unsuitable |
| Capybara/Tsubaki    | CSIDH security margins debated (60-80 bit quantum?), 34-39 KB proofs |
| Code-based          | No practical construction exists                  |
| Multivariate        | No construction exists (Rainbow broken at NIST R3)|
| Classical ECVRF     | Not post-quantum; defeats purpose of PQC chain    |

### 2.3 Block Validation (ZK Proofs)

Each block includes a **zero-knowledge proof** that the state transition is valid:

- **What is proven**: Given `state_root_before` and a list of transactions
  `[tx_1..tx_n]`, applying them produces `state_root_after`, and each
  transaction satisfies its constraints.
- **Proof system**: RISC Zero zkVM (see §2.5 for alternatives).
- **Scope of ZK proof per block**:
  - All SQL write operations (INSERT, UPDATE, DELETE) produce valid state diffs.
  - Permission/access control rules were respected.
  - Cryptographic signatures on transactions are valid.
- **Verification**: Any node can verify the block proof in O(1) without
  replaying transactions.

### 2.4 Committee Signature Aggregation

**Problem**: 100 committee members × 3.3 KB ML-DSA signature = 330 KB per block.

**Solution: Threshold signatures + bitfield**

The committee runs an interactive threshold signing protocol to produce ONE
signature, plus a bitfield indicating which members participated.

**Primary: Ringtail** (ePrint 2024/1113)

| Property          | Value                                              |
|-------------------|----------------------------------------------------|
| Rounds            | 2 (first round is message-independent, preprocessable) |
| Output size       | ~13.4 KB (single threshold signature)              |
| Online comm/party | 10.5 KB at t=1024                                  |
| Max parties       | 1024                                                |
| Security          | Standard LWE                                       |
| Implementation    | [github.com/daryakaviani/ringtail](https://github.com/daryakaviani/ringtail) |
| Demonstrated      | Across 5 continents in 2.5 seconds (NTT + ETH Zurich + UC Berkeley) |

Block overhead: 13.4 KB (threshold sig) + 13 bytes (100-bit bitfield) = **~13.4 KB**
(vs 330 KB raw). **96% reduction.**

**Alternative for ML-DSA compatibility: Quorus** (USENIX Security 2026)

| Property          | Value                                              |
|-------------------|----------------------------------------------------|
| Output            | Single standard ML-DSA signature (~3.3 KB)         |
| Compatibility     | Verifies under standard ML-DSA verification        |
| Online comm/party | ~100 KB per rejection sampling round               |
| Reference         | [ePrint 2025/1163](https://eprint.iacr.org/2025/1163) |

Quorus produces signatures that any ML-DSA verifier can check — maximum
interoperability. Higher communication cost but output is a standard 3.3 KB sig.

**Long-term: SNARKing committee signatures**

Once the ZK infrastructure is mature, prove "I verified >= 67 valid signatures"
inside a SNARK. Output: one small proof (~100–200 KB STARK or sub-KB with
SNARK-friendly PQ signatures like CAPSS). This is the path Ethereum is
researching (Justin Drake et al., ePrint 2025/055).

**Other approaches evaluated:**

| Approach           | Assessment                                         |
|--------------------|----------------------------------------------------|
| Half-aggregation   | Only ~1% compression for ML-DSA — not viable       |
| MuSig-L            | Promising (CRYPTO 2022) but no implementation      |
| Falcon+LaBRADOR    | PQ end-to-end aggregation; implementation exists but Falcon-only |
| Merkle commitment  | Moves data off-chain, doesn't reduce verification  |

### 2.5 ZK Proof System: RISC-V zkVMs

**Primary: RISC Zero**

| Property        | Value                                                |
|-----------------|------------------------------------------------------|
| ISA             | RV32IM (RISC-V 32-bit + multiply/divide)             |
| Proof system    | zk-STARKs + Groth16 SNARK wrapper                    |
| Guest language  | Rust (also C/C++)                                    |
| Performance     | 44s for Ethereum block (R0VM 2.0, April 2025)        |
| On-chain verify | ~300K gas (Groth16 on EVM)                           |
| Maturity        | Production. Boundless mainnet on Base. Formally verified (Veridise) |
| License         | Apache 2.0                                           |
| PQ note         | STARKs are PQ-secure; Groth16 wrapper is NOT (but optional) |

**For Seal, we use STARK proofs without the Groth16 wrapper** to maintain
end-to-end post-quantum security. Verification is done natively, not on EVM.

**Alternatives evaluated:**

| System      | ISA      | Proof System          | Performance              | Production? | License        |
|-------------|----------|-----------------------|--------------------------|-------------|----------------|
| **SP1**     | RISC-V   | STARK (Plonky3)+Groth16| <12s ETH block (16×5090)| Yes         | MIT/Apache 2.0 |
| **OpenVM**  | RISC-V   | STARK (Plonky3)+SNARK | 15s GPU, real-time v2.0  | Yes (audited)| MIT/Apache 2.0|
| **Airbender**| RISC-V  | STARK + FFLONK        | 35s ETH block (1×H100)  | Yes (beta)  | MIT            |
| **Pico**    | RISC-V   | STARK (Plonky3)       | 6.9s (16×5090)           | Active dev  | TBD            |
| **Jolt**    | RV64IMAC | Sumcheck/Lasso        | 1M+ cycles/sec CPU       | Alpha       | MIT/Apache 2.0 |
| **Nexus**   | RV32I    | Stwo + Folding/IVC    | 1000× speedup over v2    | Pre-mainnet | MIT/Apache 2.0 |
| **Valida**  | Custom   | Plonky3/STARK         | Fast (zk-optimized ISA)  | Early       | TBD            |
| **zkWASM**  | WASM     | zk-SNARK              | Poor (57GB RAM)          | Research    | —              |
| **Powdr**   | Modular  | Multi-backend         | Varies                   | Toolkit     | —              |

**Recommendation**: Start with RISC Zero (most mature, Apache 2.0, formally
verified, Rust-native). If proving performance becomes a bottleneck, evaluate
SP1 or Pico as drop-in alternatives (all RISC-V, all accept Rust guest code).

**Key architectural decision**: All three top candidates (RISC Zero, SP1, OpenVM)
produce STARK proofs internally. We use STARKs natively (no SNARK wrapper) for
PQ security. The STARK-to-SNARK wrapper is only needed for EVM on-chain
verification, which we don't need on our own chain.

### 2.6 Consensus Protocol Choice

Algorand-style (VRF + committee voting) was chosen after comparing with
HotStuff, HotStuff-2, Jolteon, Tendermint, and DAG-based protocols (Mysticeti).
See **[CONSENSUS-COMPARISON.md](CONSENSUS-COMPARISON.md)** for full analysis.

**Key findings**:
- HotStuff-family requires 2-3 threshold sig rounds per slot — doesn't fit
  in 4s with Ringtail's 2.5s WAN latency.
- DAG-based (Mysticeti) has best PQC profile (no threshold sigs in hot path)
  and 300-400K TPS, but is far more complex. Planned for Phase 2+ evaluation.
- Algorand-style with 1 Ringtail threshold sig per slot fits comfortably.
- **Future**: Decouple mempool (Narwhal-style DAG) from consensus to improve
  throughput while keeping Algorand-style ordering.

### 2.7 Finality

- **Single-slot finality**: Committee vote in same slot as proposal.
- **No forks by design**: VRF + committee voting = unique block per slot.
- **Liveness**: If proposer is offline, slot is skipped; next slot VRF runs again.

### 2.7 Parameters (initial, tunable)

| Parameter          | Value       | Notes                              |
|--------------------|-------------|------------------------------------|
| Slot time          | 4 seconds   | Time for propose + threshold sign  |
| Epoch length       | 256 slots   | ~17 minutes; VRF key rotation      |
| Committee size     | 100 members | VRF-selected per slot              |
| Finality threshold | 67%         | Byzantine fault tolerance          |
| Min stake          | TBD         | SEAL tokens required to validate   |

---

## 3. Post-Quantum Cryptography

### 3.1 Algorithms (NIST FIPS 203/204/205 standardized)

| Function          | Algorithm       | Standard   | Notes                         |
|-------------------|-----------------|------------|-------------------------------|
| Digital Signature | ML-DSA-65       | FIPS 204   | Dilithium — all tx signing    |
| Key Encapsulation | ML-KEM-768      | FIPS 203   | Kyber — encrypted P2P comms   |
| Hash Signature    | SLH-DSA-128f    | FIPS 205   | SPHINCS+ — fallback/diversity |
| Hash Function     | SHA3-256/SHAKE  | FIPS 202   | State hashing, Merkle trees   |
| VRF              | LB-VRF          | Research   | Module-LWE/SIS, see §2.2     |
| Threshold Sig     | Ringtail        | Research   | LWE-based, see §2.4          |

### 3.2 Address Format

```
seal1<bech32m-encoded-ml-dsa-public-key-hash>
```

- Addresses derived from SHA3-256 hash of ML-DSA public key.
- Bech32m encoding for human readability and error detection.
- Prefix `seal1` for mainnet, `sealt1` for testnet.

### 3.3 Transaction Signing

Every transaction is signed with ML-DSA-65:
```
tx_signed = {
    payload: tx_bytes,
    signature: ML_DSA_Sign(sk, tx_bytes),
    public_key: pk
}
```

ML-DSA signatures are ~3.3 KB. Individual transaction signatures are stored
as-is. Committee signatures use threshold aggregation (§2.4).

---

## 4. Distributed SQL Database

### 4.1 Core Concept

The blockchain's state IS a collection of SQL databases. Each "smart contract"
is a database schema with:
- Table definitions
- Row-level access control policies
- Triggers and stored procedures, in one of two languages:
  - `LANGUAGE sql` — PL/pgSQL-style SQL procedures (default)
  - `LANGUAGE wasm` — opt-in WASM modules, deterministic sandbox, minimal host ABI

This replaces Solidity/Move with SQL — the most widely known data language.
The two-tier proc model mirrors PostgreSQL's multi-language `CREATE FUNCTION`.
See `docs/decisions/ADR-001-stored-procedures-and-wasm.md` for the rationale.

### 4.2 SQL Dialect: PostgreSQL-Compatible

Seal SQL is a **subset of PostgreSQL** syntax and semantics. Any valid Seal SQL
statement is valid PostgreSQL. MySQL compatibility is provided as a secondary
parsing mode. The parser uses [sqlparser-rs](https://github.com/apache/datafusion-sqlparser-rs)
(Apache DataFusion) with the PostgreSQL dialect as default.

**Supported DDL:**
```sql
CREATE TABLE <name> (
    <column> <type> [PRIMARY KEY] [NOT NULL] [DEFAULT <expr>]
        [REFERENCES <table>(<col>)],
    ...
);
ALTER TABLE <name> ADD COLUMN <column> <type>;
ALTER TABLE <name> DROP COLUMN <column>;
CREATE INDEX <name> ON <table> (<columns>);
DROP TABLE <name> [CASCADE];
```

**Supported DML:**
```sql
SELECT <columns> FROM <table>
    [JOIN <table> ON <predicate>]      -- within same app namespace
    [WHERE <predicate>]
    [GROUP BY <columns>]
    [HAVING <predicate>]
    [ORDER BY <col> [ASC|DESC]]
    [LIMIT n] [OFFSET m];
INSERT INTO <table> (<columns>) VALUES (<values>);
UPDATE <table> SET <col> = <expr> [WHERE <predicate>];
DELETE FROM <table> [WHERE <predicate>];
```

**Aggregate functions:** `COUNT`, `SUM`, `AVG`, `MIN`, `MAX`.

**Supported Types (PostgreSQL-compatible names):**

| PostgreSQL Type      | Seal SQL Type    | Notes                         |
|----------------------|------------------|-------------------------------|
| `SMALLINT`           | `SMALLINT`       | 16-bit signed integer         |
| `INTEGER`            | `INTEGER`        | 32-bit signed integer         |
| `BIGINT`             | `BIGINT`         | 64-bit signed integer         |
| `REAL`               | `REAL`           | 32-bit float                  |
| `DOUBLE PRECISION`   | `DOUBLE PRECISION`| 64-bit float                 |
| `NUMERIC(p,s)`       | `NUMERIC(p,s)`   | Arbitrary precision decimal   |
| `TEXT`               | `TEXT`           | Variable-length UTF-8 string  |
| `BYTEA`              | `BYTEA`          | Binary data                   |
| `BOOLEAN`            | `BOOLEAN`        | true/false                    |
| `TIMESTAMP`          | `TIMESTAMP`      | Date and time                 |
| `TIMESTAMPTZ`        | `TIMESTAMPTZ`    | Timestamp with time zone      |
| `INTERVAL`           | `INTERVAL`       | Time duration                 |
| `UUID`               | `UUID`           | Universally unique identifier |
| `JSON` / `JSONB`     | `JSONB`          | JSON data (binary storage)    |
| —                    | `SEAL_ADDRESS`   | Native chain address type     |
| —                    | `SEAL_AMOUNT`    | Native token amount (fixed-point) |

**Not supported** (stripped during migration with warnings):
`SERIAL`/`BIGSERIAL` (use `BIGINT` + app-generated IDs), `ARRAY` types,
`GEOMETRY`/PostGIS, custom domains, composite types.

**Access Control (PostgreSQL-style Row-Level Security):**
```sql
ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;

CREATE POLICY <name> ON <table>
    FOR [SELECT|INSERT|UPDATE|DELETE]
    TO <role>
    USING (<predicate>)                -- for existing rows
    WITH CHECK (<predicate>);          -- for new/modified rows

-- Example: only row owner can modify
CREATE POLICY owner_write ON posts
    FOR ALL
    USING (owner = CURRENT_USER())
    WITH CHECK (owner = CURRENT_USER());

-- Example: public read access
CREATE POLICY public_read ON posts
    FOR SELECT
    USING (true);
```

**MySQL compatibility mode:**

The parser accepts MySQL syntax as a secondary mode:
```bash
$ seal sql --dialect mysql --app my_app "SELECT * FROM posts LIMIT 10"
```
MySQL-specific syntax (backtick quoting, `AUTO_INCREMENT`, `ENGINE=InnoDB`,
`TINYINT`/`MEDIUMINT`, etc.) is translated to PostgreSQL equivalents internally.

### 4.3 State Model

```
Global State
├── System Tables (validator set, epoch info, token balances)
├── App Namespace "app1.seal"
│   ├── Table: users
│   ├── Table: posts
│   └── Policies: [owner-only-write, public-read]
├── App Namespace "app2.seal"
│   ├── Table: orders
│   └── ...
└── ...
```

- State stored as a **Merkle B-tree** (hashed references, as prototyped in
  architecture-test-1 and architecture-test-2).
- Each table is a B-tree of rows, keyed by primary key.
- State root = Merkle root of all tables = committed in block header.

### 4.4 Transaction Types

| Type              | Description                                      |
|-------------------|--------------------------------------------------|
| `CreateApp`       | Deploy a new app namespace with schema            |
| `SqlExec`         | Execute SQL statement(s) against an app           |
| `AlterSchema`     | Modify table structure (migration)                |
| `Transfer`        | Native SEAL token transfer                        |
| `BridgeIn`        | Deposit from Solana/Stellar                       |
| `BridgeOut`       | Withdraw to Solana/Stellar                        |
| `StakeDeposit`    | Stake SEAL tokens for validation                  |
| `StakeWithdraw`   | Unstake SEAL tokens                               |

### 4.5 Local ZK Execution

SQL reads (SELECT) execute **locally** on the client node — no on-chain cost:
- Client node maintains a local replica of relevant app state.
- State is verified against on-chain Merkle root.
- For privacy-sensitive queries, client can generate a **ZK proof** that a
  query result is consistent with the on-chain state without revealing the query.

SQL writes (INSERT/UPDATE/DELETE) are submitted as transactions:
- Client constructs the SQL write operation.
- Client generates a ZK proof that the write satisfies all constraints
  (schema, policies, triggers).
- Transaction = `(sql_op, zk_proof, signature)`.
- Validators verify the ZK proof instead of re-executing the SQL.

### 4.6 MPC (Phase 2)

Privacy-preserving computations on shared data across multiple parties.

**Priority order** (by value/complexity ratio):

| Priority | Use Case                    | Protocol     | Latency (WAN)    |
|----------|-----------------------------|--------------|------------------|
| 1        | Private SUM/COUNT/AVG       | SPDZ online  | ~250 ms / 1K ops |
| 2        | Private Set Intersection    | OT-based PSI | ~5 s / 1M records|
| 3        | Sealed-bid auctions         | BOREALIS     | ~400 ms (3 rounds)|
| 4        | Private WHERE/filtering     | Garbled circuits | Seconds       |
| 5        | General private JOINs       | Secure Yannakakis | Research-grade |

**Protocol: SPDZ** (pronounced "Speedz") for arithmetic MPC:
- Offline phase generates correlated randomness (independent of inputs).
- Online phase: 2 rounds of communication. Addition (SUM, COUNT) is free
  (no communication). Multiplication (AVG division) costs 1 round.
- Malicious-secure with dishonest majority.
- Reference framework: [MP-SPDZ](https://github.com/data61/MP-SPDZ) (30+ protocol
  variants, the benchmark standard).

**SQL-to-MPC translation** (inspired by
[SecretFlow-SCQL](https://github.com/secretflow/scql), production at Ant Group):
```sql
-- Private aggregation across organizations
SELECT SUM(amount), COUNT(*) FROM orders
    WHERE org_id IN ('org_a', 'org_b')
    MPC BETWEEN org_a, org_b;
```
The `MPC BETWEEN` clause signals that each party holds their own rows; the
query executes via SPDZ without revealing individual rows.

**Rust MPC libraries:**
- [Swanky](https://github.com/GaloisInc/swanky) (Galois) — Rust-native, garbled
  circuits + OT + ZK. Research-grade, not production-ready.
- [mpz](https://github.com/privacy-ethereum/mpz) (TLSNotary) — Rust, maturing,
  focused on 2PC/TLS.
- MP-SPDZ (C++ with Python frontend) — most complete; FFI integration for Rust.

**Key constraint**: Over WAN, network latency dominates compute by 10-100x.
Round count is the bottleneck. SPDZ's 2-round online phase is optimal for
aggregation queries.

---

## 5. Payments & Wallet Integration

### 5.1 Native Token: SEAL

- Used for: transaction fees, staking, governance, service payments.
- Denomination: 1 SEAL = 10^9 micro-SEAL (9 decimal places).
- See §10 for full token economics.

### 5.2 Bridge: Solana

- **Mechanism**: Lock-and-mint bridge.
  - User locks SOL/SPL tokens in a Solana program (smart contract).
  - Seal validators observe the lock event (via light client or oracle set).
  - Seal chain mints wrapped tokens (`wSOL`, `wUSDC`, etc.).
  - Reverse: burn on Seal, unlock on Solana.
- **Security**: Validator committee (same as consensus) acts as bridge signers.
  Threshold signature for release.
- **Implementation**: Solana program in Rust (Anchor framework).

### 5.3 Bridge: Stellar

- **Mechanism**: Similar lock-and-mint via Stellar smart contracts (Soroban).
  - Or: federated bridge with Stellar anchors.
- **Tokens**: XLM, USDC (Stellar native USDC is widely used).
- **Implementation**: Soroban contract in Rust.

### 5.4 Wallet Support

The native app supports:
- **Seal wallet** (PQC keys, ML-DSA) — primary.
- **Solana wallet** import (Ed25519) — for bridge operations.
- **Stellar wallet** import (Ed25519) — for bridge operations.
- Key derivation: BIP-39 mnemonic → PQC key pair + Ed25519 key pair from
  same seed, so one recovery phrase covers all chains.

### 5.5 Bridge bootstrap RPC authorization

The bridge-bootstrap RPCs that grant chain-level privilege (registering
observers, seating Technical Council members, pausing/unpausing a
chain, rotating the committee MAC key) are *admin-gated*:

- `seal_addBridgeObserver`
- `seal_bridgeCouncilAdd`, `seal_bridgeCouncilRemove`
- `seal_bridgePauseChain`, `seal_bridgeUnpauseChain`
- `seal_bridgeRotateCommitteeKey`

The node config (`RpcConfig::admin_addresses`, populated by
`--admin-address` repeated flags or genesis config) holds a set of
bech32m Seal addresses authorized to call these methods.

- **Empty set (open mode)** — alpha-testnet bootstrap default. Any
  signed *or unsigned* caller can hit these RPCs. This is what
  `bridge-e2e.sh` and similar scripts rely on for stand-up. Mainnet
  must NOT run in open mode; `seal-node --mainnet` without
  `--admin-address` emits a startup warning.
- **Populated set (gated mode)** — every admin-gated call must carry
  a valid ML-DSA signature *and* the caller's derived address must
  be in the set. Two error codes can return:
  - `-32003` "signature verification failed" — missing/invalid
    signature when `admin_addresses` is non-empty.
  - `-32004` "requires admin authorization (address … not in admin
    set)" — signature OK but address not authorized.

The pause/unpause RPCs additionally require a 2/3 supermajority of
seated Technical Council members (the `approvers` parameter); admin
gating is an *additional* check on who can drive the RPC traffic,
not a replacement for the council vote.

Production deployment binds `admin_addresses` to operator keys at
genesis; rotation goes through the same governance track as council
membership.

#### 5.5.1 Admin M-of-N multisig (P8 mainnet gate)

Single-signature admin gating (above) leaves a single compromised
operator key able to drive any admin RPC. Mainnet operators opt
into an additional `M-of-N` threshold via the `--admin-threshold
<n>` CLI flag on seal-node. Semantics:

| `admin_threshold` | Behaviour |
|-------------------|-----------|
| 0 or 1 (default)  | Legacy single-sig gate (above). |
| ≥ 2               | Primary signer plus `threshold - 1` distinct cosigners from `admin_addresses`, each over the canonical message digest. |

The canonical signing message is
`SHA3-256(method || params_without_admin_signatures_json)`.
Stripping the `admin_signatures` field before signing lets
cosigners sign before the primary submitter assembles the final
envelope. The server's `verify_admin_multisig` (in
`crates/seal-node/src/rpc.rs`) dedups verified cosigners by
derived address — a single stolen key can't replay-forge an
M-of-N. Operator UX: `seal admin-sign` (produces a cosigner
entry) + `seal admin-submit` (assembles and POSTs the envelope).
Full walkthrough in [`docs/ADMIN-MULTISIG.md`](docs/ADMIN-MULTISIG.md).

#### 5.5.2 Per-method-group rate limits (P8 mainnet gate)

The RPC layer keys per-IP rate-limit buckets on
`(IpAddr, RpcGroup)`. Three groups classify every method:

- `Admin` — the six bridge-bootstrap RPCs. Default 5 req/min.
- `Expensive` — SQL writes, bridge withdrawals, governance
  mutations. Default 20 req/min.
- `Default` — everything else (chain reads, snapshot RPCs,
  status). Default 120 req/min.

Configurable via `RpcConfig::{rpm_default, rpm_expensive,
rpm_admin}`. Exhausting one bucket does NOT starve the others
from the same IP — the classifier is in `rpc_group_for_method`.

#### 5.5.3 Bridge withdrawal fee (P8 mainnet gate)

`--bridge-withdrawal-fee <u64>` configures a SEAL fee burned
from the caller's native balance on every successful
`seal_bridgeWithdraw`. Burned BEFORE the wrapped-token burn so
the fee is opt-out via a balance check; refunded if the wrapped
burn fails (e.g. `InsufficientWrapped`). Default 0 keeps the
testnet path free. Read via `seal_getBridgeWithdrawalFee` (no-
auth) or `/status.bridge.withdrawal_fee_base_units`.

#### 5.5.4 Committee-key source: file or KMS

The committee MAC key and Ringtail keypair are loaded via the
`seal_bridge::keysource` trait pair (`CommitteeKeySource`,
`RingtailKeySource`). The default `FileKeySource` reads from a
JSON config the operator writes; mainnet HSM / cloud-KMS
adapters slot in by implementing the same traits — no
call-site changes. Wire via `--bridge-kms-config <path>`.

### 5.6 Recipient-new-account policy

`seal_transfer` and `seal_transferToken` enforce a fresh-recipient
guard. The motivation is the bech32m address-validation guard
catches *malformed* addresses (typos, ellipsis placeholders), but
not a *well-formed-but-unintended* address — e.g. the user
copy-pasted a generated address that's syntactically valid but
belongs to no one. Without a policy, the transfer would silently
create a new ledger entry the sender can't recover from.

Three modes:

- **Block (default)** — `RpcConfig::allow_new_recipients = false` and
  the request omits `confirm_new_recipient`. The handler checks
  `BalanceStore::has_account(recipient)` (or
  `TokenManager::has_token_account` for token transfers); if the
  recipient has no prior ledger entry (even a previously-zeroed
  account counts as "known"), the call rejects with `-32007` and a
  message that names the address and tells the caller how to
  proceed.
- **Confirm (per-request)** — caller passes `confirm_new_recipient:
  true` in the JSON-RPC `params`. The flag must be a JSON boolean
  `true`; any other value (string `"true"`, integer `1`, omitted)
  falls back to block mode. Used by wallet UIs that surface a
  "really send to a new address?" prompt before resubmitting.
- **Allow (node-wide)** — start the node with
  `--allow-new-recipients`. Skips the check entirely. Bridge nodes
  (which mint wrapped tokens to fresh foreign-chain depositor
  addresses) and faucet nodes (whose entire purpose is fresh
  accounts) run in allow mode. Regular wallet-facing nodes must
  not.

The `BalanceStore::has_account` semantics are deliberately broader
than "has positive balance": an account that previously held a
balance and drained to zero is still *known*, so post-spending
transfers don't bounce. The check only rejects on a literal first
contact with that ledger.

This is independent of the bech32m format guard — both must pass.
A typo'd address is rejected at format-validation; a well-formed
unknown address is rejected at policy.

#### 5.6.1 Min-opening-balance — dust-spam cost shift

`RpcConfig::min_opening_balance` (CLI: `--min-opening-balance
<base-units>`) is an additional gate that runs *after* the
recipient-new-account policy and rejects any transfer to a fresh
recipient where `amount < min_opening_balance`. 0 (default)
disables the check.

Where the recipient policy stops accidental fresh-recipient
creation, this raises the *cost* of intentional fresh-recipient
creation: an attacker creating 10⁶ throwaway addresses must fund
each with at least the threshold. With a 100_000 base-units floor
(0.0001 SEAL), 10⁶ accounts cost 10⁵ base-SEAL outright — a real
spend, not just a signature.

Independent of `allow_new_recipients`: a faucet node typically
runs `allow_new_recipients = true` *and* a non-zero
`min_opening_balance`, so it can mint to fresh accounts but only
above the floor. Both checks are independent and either can
reject.

The check uses `has_account` semantics from §5.6: a recipient
with no current entry in the HAMT is treated as fresh and the
floor applies. **Note**: as of the eager dust-prune (commit
`<this>`), an account drained to zero is removed from the HAMT,
so it looks fresh on next contact. This is intentional — the
floor applies the same cost barrier whether the account is
literally new or has cycled through zero. Combined with the
prune, an attacker can no longer accumulate dust accounts; each
fresh recipient costs `min_opening_balance` *every time* the
account is below the empty threshold.

Error: `-32008` with a message naming the recipient, the supplied
amount, and the configured threshold.

### 5.7 Combined global state root in BlockHeader

Each `BlockHeader.state_root` commits to the entire chain state,
not just SQL tables. The 32-byte root is computed as

```
state_root = SHA3-256(sql_root || balance_root)
```

where:

- `sql_root` is the Merkle root of the seal-sql engine's content-
  addressed B-tree (one entry per row, keyed by row salt). Captures
  every CREATE TABLE / INSERT / UPDATE / DELETE.
- `balance_root` is the HAMT root over the native SEAL ledger
  (`(address, Balance)` pairs serialized via bincode). Captures
  every mint / burn / transfer / stake / unstake on native SEAL.

Both are computed inside `ConsensusRunner::produce_block_with_vrf`
before block emission and inside `replay_block` during validator
catch-up. A validator that disagrees on either constituent
produces a different block-header `state_root` and the
disagreement surfaces in consensus.

**Future folds.** `TokenManager::state_root_hash` (custom-token
ledgers) and the bridge wrapped-balance set should join the
combined root once they are owned by the runner; today they live
in `RpcState` so the runner has no handle. Both are exposed
separately in `/metrics` (`seal_token_state_root{root_hex=…}`)
and via the `seal_getStateRoot` RPC under `components.token_root_hex`.

**External observers.** `seal_getStateRoot` returns:

```json
{
  "state_root": "<combined hex>",
  "components": {
    "balance_root_hex": "<HAMT root over native ledger>",
    "token_root_hex":  "<HAMT root over per-token ledgers>"
  }
}
```

Two nodes that report the same `state_root` agree on (sql,
balance); if `balance_root_hex` matches but `state_root` differs,
the disagreement is in the SQL tables.

### 5.8 Token authority lifecycle

Custom tokens (created via `seal_createToken`) carry three
authority fields stored on `TokenInfo`:

- `mint_authority` — caller that can call `seal_mintToken`. Set
  to the creator at `seal_createToken` time.
- `freeze_authority` — caller that can call `seal_freezeAccount`,
  `seal_unfreezeAccount`, `seal_setTokenFrozen`. Set to the
  creator at `seal_createToken` time.
- `fee_authority` — caller that can call `seal_setTransferFee`.
  Set to the creator at `seal_createToken` time. Renouncing this
  permanently locks the transfer fee at its current value.

All three follow the same lifecycle, gated on the **current** holder:

```
create → set_*_authority → … → renounce
                ↑                  │
                └── (terminal) ────┘
```

| Method | Caller must be | Result |
|---|---|---|
| `seal_setMintAuthority {symbol, new_authority}` | current `mint_authority` | `mint_authority := new_authority` |
| `seal_setFreezeAuthority {symbol, new_authority}` | current `freeze_authority` | `freeze_authority := new_authority` |
| `seal_setFeeAuthority {symbol, new_authority}` | current `fee_authority` | `fee_authority := new_authority` |
| `seal_renounceMintAuthority {symbol}` | current `mint_authority` | `mint_authority := ""` (terminal) |
| `seal_renounceFreezeAuthority {symbol}` | current `freeze_authority` | `freeze_authority := ""` (terminal) |
| `seal_renounceFeeAuthority {symbol}` | current `fee_authority` | `fee_authority := ""` (terminal — fee locked) |

**Renounce is terminal.** The empty string `""` is impossible for
any real Seal address (every bech32m-encoded address starts with
`seal1` / `sealt1`), and the RPC's caller-fallback resolves to
`"anonymous"` rather than `""`. So `info.<x>_authority != caller`
is always true after renounce, and every subsequent
mutation / rotation rejects no matter who calls — including the
original creator.

For `fee_authority` specifically this means renouncing freezes the
fee at its **current** value *and* the current `fee_recipient`: a
creator who wants 0% transfer fees forever should set the fee to 0
and *then* renounce, otherwise the fee is locked at whatever it
was at renounce time. `seal_setFeeRecipient {symbol, new_recipient}`
shares the same `fee_authority` gate as `seal_setTransferFee`, so
post-renounce the recipient is also immutable.

**RPC validation.** The set-* paths run
`SealAddress::from_string_encoding(new_authority)` before the
manager call so a typo can't quietly orphan the token. The
renounce-* paths skip that check (no `new_authority` to validate)
and the manager is the sole guard. Renounce flows through
`set_*_authority(symbol, "", caller)` internally so the auth gate
on the way in still uses the live caller.

**`seal_listTokens` / `seal_getToken` shape.** `mint_authority`,
`freeze_authority`, and `fee_authority` are emitted as JSON `null`
after a renounce rather than an empty string, so clients can
render "renounced" distinctly from "missing key". Real addresses
pass through as strings unchanged.

**Read surface.**
- `seal_listTokens` — every token's full `TokenInfo` including
  both authorities (null if renounced).
- `seal_isFrozen {symbol, address}` — point query (per-account).
- `seal_listFrozenAccounts {symbol}` — full set, sorted, capped
  at 10 000 entries with a `truncated: bool` flag.

The error code matrix:

| Code | Cause |
|---|---|
| `-32602` | malformed `symbol`, missing `address`, invalid bech32m, unknown token (for `seal_burnToken` only) |
| `-32000` | manager-level rejection (auth gate, insufficient balance, frozen sender) |

---

## 6. Networking

### 6.1 P2P Layer

- **Library**: libp2p (already prototyped in architecture-test-2).
- **Transport**: QUIC (PQC-secured with ML-KEM handshake when available;
  TLS 1.3 with Kyber hybrid initially).
- **Discovery**: mDNS (local), Kademlia DHT (global), bootstrap nodes.
- **Gossip**: GossipSub for block and transaction propagation.

### 6.2 Node Types

| Type       | Role                                           | Storage    |
|------------|------------------------------------------------|------------|
| Validator  | Produce blocks, vote, full state               | Full       |
| Full Node  | Verify blocks, serve queries, relay txs        | Full       |
| Light Node | Verify block headers + Merkle proofs only      | Headers    |
| App Node   | Full state for subscribed apps, light for rest | Selective  |
| TEE Node   | ML/AI inference in TEE (Phase 3+)              | Model cache|

---

## 7. Storage

### 7.1 On-Disk Format

- **State DB**: Merkle B-tree stored in a key-value store.
  - Engine: `sled` or `RocksDB` (Rust-native options).
  - Keys: SHA3-256 hashes of nodes.
  - Values: serialized B-tree nodes (bincode/borsh).
- **Block DB**: Append-only log of blocks + proofs.
- **WAL**: Write-ahead log for crash recovery.

### 7.2 State Pruning

- Full nodes can prune old state, keeping only:
  - Latest state snapshot.
  - Last N epochs of blocks (for reorg safety, though reorgs shouldn't happen).
  - Archive nodes keep everything.

### 7.3 Row Salting (Anti-Correlation)

Every row carries a 32-byte random salt mixed into its Merkle leaf hash:

```
leaf = SHA3("table:pk" || salt || serialized_row)
```

- **INSERT**: salt derived from `SHA3("row_salt" || block_height || table || counter)`
- **UPDATE**: salt re-derived (new block height → new salt)
- **Determinism**: all validators processing the same block derive identical salts
  from the block height seed, ensuring consensus on the state root
- **Anti-correlation**: same row content at different block heights produces
  different Merkle leaf hashes, preventing cross-block data correlation

After data is pruned (§7.5), the salts are destroyed with the rows. Historical
Merkle roots in block headers become opaque — no reconstruction is possible.

### 7.4 Storage Leases

Every public/shared table has a **storage lease** paid in SEAL tokens:

```
StorageLease {
    table:          String,       // "namespace.table_name"
    owner:          SealAddress,  // pays the lease
    paid_through:   u64,          // timestamp (microseconds since epoch)
    row_count:      u64,          // current row count
    byte_size:      u64,          // current byte size
    rate:           u64,          // per-byte-epoch rate (governance-adjustable)
    governance_hold: bool,        // exemption from pruning (legal/regulatory)
}
```

**Write invoicing**: every INSERT/UPDATE burns SEAL (or Compute Credits per §10.4)
proportional to bytes written. This pays for the state diff propagation and storage.

**Read invoicing**: SELECT queries burn a micro-amount of SEAL from the querying
user, or the user must stake N SEAL to access a namespace (capital lockup, no burn).
Both are enforceable because queries execute on validators.

**Lease extension**: table owners call `seal_extendLease(table, duration)` to
extend `paid_through`. Cost = `byte_size × rate × duration`.

### 7.5 Right to Be Forgotten (Lease Expiry)

When a storage lease expires:

1. **Grace period** (default 30 days, governance-adjustable): table is read-only,
   owner can still extend the lease.
2. **After grace**: validators **prune all rows and salts** from active state.
   The Merkle roots in old blocks remain but are meaningless without data/salts.
3. **Lease record** is removed from state.

**Slashing rule**: serving data from an expired/pruned table is a **slashable
offense**. Governance can grant exemptions (e.g., legal/regulatory holds) by
setting `governance_hold = true` on the lease.

**What remains after pruning**:

| Data | Accessible? |
|------|------------|
| Block headers + Merkle roots | Yes (permanent, opaque hashes) |
| That a table existed at height H | Yes (transaction log) |
| Row contents | No — pruned from all nodes |
| Row salts | No — pruned with the rows |
| Cross-block correlation | No — salts made leaf hashes independent |

This provides a practical "right to be forgotten" on an immutable blockchain:
the commitment layer (block headers) is permanent, but the data layer has an
economic lifecycle controlled by the table owner.

---

## 8. Native Application

### 8.1 Architecture

The Seal native app is a **full node + SQL client + wallet** in one binary:

```
seal-app
├── Node runtime (consensus, P2P, storage)
├── SQL client (query local state, submit write txs)
├── ZK prover (generate proofs for SQL writes locally)
├── Wallet manager (SEAL + SOL + XLM keys)
├── Bridge client (deposit/withdraw cross-chain)
└── UI (TUI, egui desktop explorer, or Electron + WASM wallet)
```

### 8.2 Developer Experience

A developer deploys an app:
```bash
$ seal app deploy --schema ./my_app.sql --name "my_app"
# Deploys tables + policies to chain

$ seal sql --app my_app "INSERT INTO posts (author, body) VALUES (CURRENT_USER(), 'hello')"
# Submits as on-chain transaction

$ seal sql --app my_app "SELECT * FROM posts WHERE author = 'seal1abc...'"
# Executes locally against verified state
```

### 8.3 Client SDKs (future)

- Rust SDK (native)
- JavaScript/TypeScript SDK (via WASM)
- Python SDK (via PyO3 bindings)

---

## 9. Formal Methods & Security Verification

### 9.1 Protocol-Level Verification (TLA+)

TLA+ models written first for all distributed protocol properties.
Model-checked with TLC for bounded state spaces.

| Component              | Properties Verified                               |
|------------------------|---------------------------------------------------|
| Consensus protocol     | Safety: no two blocks finalized at same height    |
|                        | Liveness: blocks keep being produced under partial async |
|                        | Uniqueness: at most one valid proposer per slot   |
| VRF leader selection   | Fairness: election probability proportional to stake |
|                        | Unpredictability: adversary cannot predict next leader |
| Token economics        | Conservation: no tokens created/destroyed except by mint/burn |
|                        | Stake monotonicity: staking/unstaking preserves total supply |
| Bridge protocol        | No double-spend across chains                     |
|                        | Liveness: locked funds always eventually redeemable |
|                        | Safety: minted tokens <= locked tokens             |
| Threshold signing      | Safety: adversary with <t shares cannot forge signature |
|                        | Liveness: honest majority can always produce signature |

### 9.2 Algorithm-Level Verification (Lean 4 / Rocq)

Machine-checked proofs for core data structures and cryptographic algorithms.

| Component              | Properties Verified                               |
|------------------------|---------------------------------------------------|
| Merkle B-tree          | Insertion/deletion preserves tree invariants      |
|                        | Membership proof soundness and completeness       |
|                        | Hash collision resistance → state integrity       |
| State transition fn    | SQL ops produce correct state diffs               |
|                        | Determinism: same inputs → same outputs           |
| VRF correctness        | Uniqueness: one output per input per key          |
|                        | Pseudorandomness: output indistinguishable from random |
|                        | Verifiability: proof convinces verifier of correct evaluation |
| ZK circuit correctness | Circuit matches reference SQL semantics           |
|                        | Soundness: no valid proof for invalid transition  |
| Access control         | Policy evaluation is complete and non-bypassable  |

**Extraction strategy**: Where possible, extract verified code from Lean/Rocq
to Rust (via `lean4-rs` or manual translation with proof correspondence).

### 9.3 Rust Code Security Verification

#### 9.3.1 Kani Model Checker (Bounded Model Checking)

**What**: AWS-backed formal verification tool for Rust. Proves properties
about Rust code by exhaustive exploration of bounded execution paths.

**Applied to**:
- Serialization/deserialization roundtrip correctness (bincode, borsh)
- Integer overflow/underflow absence in token arithmetic
- Array bounds correctness in B-tree operations
- State machine invariants (consensus state transitions)
- Absence of panics in critical paths

```rust
#[kani::proof]
fn verify_token_transfer_no_overflow() {
    let balance_a: u64 = kani::any();
    let balance_b: u64 = kani::any();
    let amount: u64 = kani::any();
    kani::assume(amount <= balance_a);
    kani::assume(balance_b.checked_add(amount).is_some());
    // ... verify transfer preserves total supply
}
```

#### 9.3.2 Miri (Undefined Behavior Detection)

**What**: Rust's official interpreter for detecting undefined behavior.

**Applied to**:
- All `unsafe` code blocks (cryptographic primitives, FFI, SIMD)
- Memory safety in VRF evaluation (NTT operations, polynomial arithmetic)
- Pointer arithmetic in storage engine
- Aliasing violations

**CI requirement**: `cargo +nightly miri test` passes for all crates.

#### 9.3.3 cargo-fuzz / libFuzzer (Fuzz Testing)

**What**: Coverage-guided fuzzing to find crashes, panics, and logic bugs.

**Fuzz targets**:

| Target                  | What is fuzzed                                     |
|-------------------------|----------------------------------------------------|
| SQL parser              | Arbitrary byte strings → parse → no crash          |
| SQL execution engine    | Random valid SQL → execute → no panic, state valid |
| Transaction deserialize | Arbitrary bytes → deserialize → no UB              |
| Merkle tree operations  | Random insert/delete sequences → invariants hold   |
| VRF proof verification  | Malformed proofs → verify returns false, no crash  |
| P2P message handling    | Arbitrary network messages → no crash/hang         |
| Block deserialization   | Malformed blocks → reject gracefully               |

#### 9.3.4 cargo-audit & cargo-deny (Supply Chain)

- `cargo audit` in CI: no known vulnerabilities in dependencies.
- `cargo deny` policy: license allowlist, no duplicate deps, advisory DB check.

#### 9.3.5 MIRAI (Abstract Interpretation)

**What**: Facebook/Meta's abstract interpreter for Rust. Finds bugs via
abstract interpretation without executing code.

**Applied to**:
- Tag analysis: tainted user input never reaches unsafe operations
- Precondition verification on public API boundaries
- Detecting unreachable code and dead assertions

#### 9.3.6 Prusti (Deductive Verification)

**What**: Automated Rust verifier based on Viper. Proves functional
correctness of Rust functions using pre/postconditions.

**Applied to** (selectively, for highest-risk code):
- Token transfer: postcondition `old(a) + old(b) == new(a) + new(b)`
- Merkle proof verification: postcondition matches specification
- Signature verification: return value matches reference implementation

```rust
#[requires(amount <= self.balance)]
#[ensures(result.balance == old(self.balance) - amount)]
fn debit(&mut self, amount: u64) -> Receipt { ... }
```

### 9.4 Security Hardening

| Threat                   | Mitigation                                        |
|--------------------------|---------------------------------------------------|
| Buffer overflow          | Rust memory safety + Miri + Kani bounds checking  |
| Integer overflow         | `checked_*` arithmetic everywhere; Kani verification |
| SQL injection            | Parameterized queries; SQL parser is the only entry point |
| Deserialization attacks  | Fuzz all deserializers; size limits on all inputs  |
| Timing side-channels     | Constant-time crypto (ML-DSA, VRF) via `subtle` crate |
| Stack overflow           | Iterative algorithms for B-tree traversal; stack limits |
| Denial of service        | Bounded resource consumption per transaction; gas metering |
| P2P eclipse attacks      | Diverse peer selection; rate limiting; reputation scoring |
| VRF grinding             | VRF output is unpredictable; threshold is stake-weighted |
| Key extraction           | Zeroize secrets on drop (`zeroize` crate); no logging of keys |
| Dependency supply chain  | cargo-audit + cargo-deny in CI; minimal dependencies |

### 9.5 Verification Schedule

| Phase | Formal Methods Activity                                    |
|-------|------------------------------------------------------------|
| 0     | TLA+ consensus spec; Kani for crypto primitives; fuzz SQL parser |
| 1     | Lean proofs for Merkle B-tree; Miri on all unsafe; fuzz P2P |
| 2     | Rocq proofs for state transitions; Prusti on token arithmetic |
| 3     | TLA+ bridge spec; fuzz bridge message handling              |
| 4     | Full security audit; all formal proofs reviewed             |

---

## 10. Token Economics

### 10.1 Model: Infrastructure Service Provider

Seal provides **database-as-a-service + compute (ZK, TEE/AI) on a blockchain**.
The token model is designed around real service usage, not speculation.

### 10.2 Revenue Streams

| Service            | Pricing Model     | Unit                          |
|--------------------|-------------------|-------------------------------|
| SQL writes         | Per-transaction   | Fee proportional to state diff size |
| SQL reads          | Free (local)      | No on-chain cost              |
| Storage            | Per-byte/month    | Rent for on-chain table data  |
| ZK proof generation| Per-proof          | Fee for block inclusion proof |
| TEE AI inference   | Per-request        | Input+output tokens priced (4× weight on output) |
| TEE LLM/SLM       | Per-request or hourly | Dedicated model reservation or pay-per-query |
| Bridge transfers   | Per-transfer       | Flat fee + relay cost         |

### 10.3 Token Utility

```
SEAL token
├── Transaction fees    — paid for SQL writes, bridge ops, schema deploys
├── Storage rent        — paid monthly for on-chain data persistence
├── Staking             — validators stake SEAL to participate in consensus
├── TEE compute payment — users pay for AI/ML inference in SEAL
├── Governance          — vote on protocol parameters, upgrades, treasury
└── Burn mechanism      — portion of fees burned (deflationary pressure)
```

### 10.4 Fee Mechanism: Burn-and-Mint

Inspired by Akash BME (Burn-and-Mint Equilibrium):

1. Users **burn SEAL** to mint **Compute Credits (CC)** at a USD-pegged rate.
2. CC are used to pay for services (SQL, storage, TEE inference).
3. Validators/TEE operators earn newly minted SEAL proportional to CC consumed.
4. Net effect: SEAL supply decreases when usage > emission. Deflationary under growth.

**Why burn-and-mint**:
- Users get predictable USD-denominated pricing (no SEAL price volatility risk).
- Token demand is anchored to real usage (every dollar of compute requires SEAL burn).
- Similar to Pocket Network's model (2.5% net deflation per cycle).

### 10.5 Staking Economics

| Parameter            | Value                                            |
|----------------------|--------------------------------------------------|
| Validator min stake  | TBD (governance-set)                             |
| Staking rewards      | Share of newly minted SEAL (emission schedule)   |
| Slashing             | For equivocation, liveness failure, invalid proofs|
| Unbonding period     | 14 days (21 epochs)                              |
| Delegation           | Supported; delegators earn proportional rewards   |

### 10.6 TEE Compute Economics

**TEE Node Operators:**
- Run GPU TEE hardware (NVIDIA H100/H200 with Confidential Computing).
- Register on-chain with TEE attestation (verified via ZK proof of attestation,
  ~350K gas equivalent, using Automata DCAP approach).
- Earn SEAL for serving inference requests.

**Pricing reference points** (from industry research):
- Phala Network: ~99% native GPU efficiency in TEE. Per-request or hourly billing.
- Secret Network: Weighted pricing `input_tokens + (4 × output_tokens)`.
- Akash: 60-70% cheaper than hyperscalers via reverse auction.

**Attestation model:**
- Every AI inference result is signed by the TEE.
- On-chain attestation proves: specific model, specific hardware, genuine TEE.
- Users get cryptographic proof that a specific model produced their output.
- Attestation verification: ZK proof of TEE quote (RISC Zero or SP1), submitted
  on-chain. Compact and PQ-secure.

### 10.7 LLM/SLM Execution in TEE

**Performance** (from 2025 research benchmarks):
- Small models (3B–8B): 5–22% QPS overhead in TEE.
- Medium+ models (10B+): <1% latency overhead — essentially free.
- Initial attestation: 2–6 seconds at session start.

**Supported models** (Phase 3+):
- Open-weight models: Llama, Mistral, DeepSeek, Gemma, Phi.
- Users deploy model to TEE pool, pay per inference.
- Model weights remain encrypted at rest and in transit.

### 10.8 Supply Schedule

| Parameter          | Value            | Notes                          |
|--------------------|------------------|--------------------------------|
| Initial supply     | TBD              | Genesis allocation             |
| Max supply         | TBD or uncapped  | Governance decision            |
| Emission schedule  | Decreasing       | Halving or smooth curve        |
| Fee burn rate      | 50% of base fee  | Governance-adjustable          |
| Treasury allocation| 10% of emission  | For development, grants, ops   |

**Note**: Token economics are specified for design completeness but are
**not implemented in early phases**. Testnet uses free test tokens.

---

## 11. Implementation Phases

### Phase 0: Foundation (current → +3 months)
- [ ] PQC crypto library integration (ML-DSA, ML-KEM, SHA3) in Rust
- [ ] LB-VRF implementation (from zhenfeizhang/lb-vrf, hardened)
- [ ] Merkle B-tree with hashed references (extend architecture-test-2)
- [ ] SQL parser + execution engine for Seal SQL subset
- [ ] Basic P2P networking (extend libp2p prototype)
- [ ] TLA+ spec for consensus protocol
- [ ] Kani proofs for crypto primitives (no overflow, no panic)
- [ ] Fuzz targets for SQL parser and deserializers
- [ ] Single-node prototype: local SQL DB with Merkle proofs

### Phase 1: Consensus + Multi-Node (+3–6 months)
- [ ] PQ-VRF leader selection with per-epoch key rotation
- [ ] Ringtail threshold signatures for committee voting
- [ ] Block production and finalization pipeline
- [ ] ZK proof generation for state transitions (RISC Zero)
- [ ] Multi-node testnet (3–10 validators)
- [ ] Lean 4 proofs for Merkle B-tree invariants
- [ ] Miri on all unsafe blocks; fuzz P2P message handling
- [ ] Basic CLI wallet (SEAL keys)

### Phase 2: SQL + App Layer (+6–9 months)
- [ ] Full Seal SQL engine with access control policies
- [ ] App namespace deployment and management
- [ ] Local ZK proof generation for SQL writes
- [ ] Local query execution with Merkle verification
- [ ] Native app binary (node + SQL client + wallet)
- [ ] Developer CLI tools
- [ ] Rocq proofs for state transition function
- [ ] Prusti annotations on token transfer logic

### Phase 3: Bridges + TEE + Payments (+9–12 months)
- [ ] Solana bridge program (Anchor/Rust)
- [ ] Stellar bridge contract (Soroban/Rust)
- [ ] Multi-wallet support (SEAL + SOL + XLM)
- [ ] Token economics implementation (burn-and-mint)
- [ ] TEE node registration + attestation verification
- [ ] TEE ML/AI inference (GPU TEE with NVIDIA CC)
- [ ] TLA+ bridge spec verified
- [ ] Fuzz bridge message handling

### Phase 4: Production Hardening (+12–18 months)
- [ ] LaV migration (many-time PQ-VRF, if implementation available)
- [ ] SNARKing committee signatures (long-term aggregation)
- [ ] MPC for private multi-party queries
- [ ] TEE LLM/SLM execution with attestation
- [ ] State pruning and archive node support
- [ ] Client SDKs (JS/WASM, Python)
- [ ] GUI application (Electron wallet + egui explorer)
- [ ] Full security audit (crypto + code)
- [ ] All formal proofs reviewed and published
- [ ] Mainnet launch

---

## 12. Governance

See **[GOVERNANCE.md](GOVERNANCE.md)** for full governance specification.

**Summary**: Three-body system (Token House + Technical Council + Service
Operators Council). 6 proposal tracks with conviction voting. PQC-native
governance with cryptographic agility mandate. Anti-plutocracy measures
including delegate caps and adaptive quorum.

---

## 13. App Migration Tooling

### 13.1 `seal migrate` CLI

Three-phase pipeline for migrating PostgreSQL/MySQL apps to Seal:

**Phase 1: Analyze**
```bash
$ seal migrate analyze --source pg_dump.sql [--dialect postgres|mysql]
# Produces: my_app.seal.sql + migration-report.json
```
- Parses dump with sqlparser-rs (PostgreSQL dialect default, MySQL secondary)
- Maps types (see §13.2), strips unsupported features with structured warnings
- Outputs transformed schema + detailed report

**Phase 2: Plan**
```bash
$ seal migrate plan --schema ./my_app.seal.sql [--hybrid hybrid.toml]
# Shows: tables to create, estimated fees, hybrid on/off-chain split
```
- Diffs against existing on-chain schema (for upgrades)
- Estimates transaction fees for deployment
- Atlas-style linting: flags destructive changes, data-dependent failures

**Phase 3: Apply**
```bash
$ seal migrate apply --app my_app --schema ./my_app.seal.sql
# Deploys schema as CreateApp or AlterSchema transaction
```
- Dry-run mode available (show transactions without submitting)
- Bulk INSERT support for data migration

### 13.2 Type Mapping (PostgreSQL → Seal SQL)

| PostgreSQL Source       | Seal SQL Target     | Action   |
|-------------------------|---------------------|----------|
| `SMALLINT`              | `SMALLINT`          | Direct   |
| `INTEGER` / `INT`       | `INTEGER`           | Direct   |
| `BIGINT`                | `BIGINT`            | Direct   |
| `SERIAL` / `BIGSERIAL`  | `BIGINT`            | Warn: strip auto-increment |
| `REAL`                  | `REAL`              | Direct   |
| `DOUBLE PRECISION`      | `DOUBLE PRECISION`  | Direct   |
| `NUMERIC(p,s)`          | `NUMERIC(p,s)`      | Direct   |
| `TEXT` / `VARCHAR(n)`    | `TEXT`              | Drop length |
| `BYTEA`                 | `BYTEA`             | Direct   |
| `BOOLEAN`               | `BOOLEAN`           | Direct   |
| `TIMESTAMP[TZ]`         | `TIMESTAMP[TZ]`     | Direct   |
| `INTERVAL`              | `INTERVAL`          | Direct   |
| `UUID`                  | `UUID`              | Direct   |
| `JSON` / `JSONB`        | `JSONB`             | Direct   |
| `ENUM`                  | `TEXT` + CHECK      | Warn     |
| `ARRAY`                 | —                   | Error: use separate table |
| `GEOMETRY`              | —                   | Error: not supported |

### 13.3 Unsupported Features

| Feature                  | Migration Action                              |
|--------------------------|-----------------------------------------------|
| Stored procedures        | Supported via `LANGUAGE sql` / `LANGUAGE wasm` (ADR-001) |
| Views                    | Warn: inline into queries or client-side      |
| Window functions         | Error: rewrite at app layer                   |
| Materialized views       | Error: compute at read time                   |
| Cross-app foreign keys   | Warn: enforce in application logic            |
| Full-text search         | Error: use off-chain indexer                  |
| CTEs (WITH clause)       | Warn: rewrite as subqueries                   |
| RETURNING clause         | Warn: query separately after write            |

### 13.4 Hybrid Migration (On-chain / Off-chain)

Configure via `hybrid.toml`:
```toml
[tables.users]
mode = "on_chain"         # Full on-chain

[tables.posts]
mode = "on_chain"

[tables.media_files]
mode = "anchored"         # Hash on-chain, data off-chain (IPFS/S3)

[tables.analytics_events]
mode = "off_chain"        # Keep in PostgreSQL, not migrated
```

**Anchored tables**: On-chain schema holds `(primary_key, content_hash, owner,
updated_at)`. Full data stored off-chain, referenced by content hash.
CLI generates both on-chain schema and off-chain PostgreSQL schema + sync adapter.

### 13.5 Comparison with Existing Projects

| Project       | SQL Dialect    | Migration UX                        | Types        |
|---------------|----------------|-------------------------------------|--------------|
| **Seal**      | PostgreSQL     | `seal migrate` (pg_dump → on-chain) | Rich (PG subset) |
| Tableland     | SQLite subset  | Manual rewrite                      | 3 types only |
| Kwil          | Kuneiform DDL  | Manual translation                  | 5 types      |
| SpacetimeDB   | Rust structs   | Rewrite as Rust module              | Rich         |
| WeaveDB       | NoSQL (JSON)   | Not applicable                      | JSON docs    |

---

## 14. Technical Analysis: Resolved Questions

### 14.1 Threshold Signing Latency

**Question**: Can 100 committee members complete Ringtail threshold signing
within a 4-second block slot?

**Analysis**:
- Ringtail WAN demo (NTT Research + ETH Zurich + UC Berkeley): 2.5 seconds
  across 5 continents with t=1024.
- Round 1 is message-independent → can be **preprocessed during previous slot**.
- With preprocessing, only Round 2 is on the critical path:
  - WAN RTT: 200–300 ms globally
  - Computation per party: ~10 ms
  - Gossip-based aggregation: ~500 ms for 100 members
  - **Total Round 2: ~800 ms**
- Block slot budget: 4s total → ~1.5s for proposal + ZK proof, ~2s for
  committee signing, ~0.5s for finalization broadcast.
- **Conclusion: Feasible.** With Round 1 preprocessing, 100-member Ringtail
  fits within 2 seconds. The NTT demo confirms this empirically.

**Optimizations**:
- Relay nodes aggregate partial signatures geographically
- Committee members pre-connect to reduce handshake latency
- Round 1 runs continuously, producing fresh preprocessed material each slot

### 14.2 STARK Proof Sizes (No SNARK Wrapper)

**Question**: Are 100–200 KB STARK proofs acceptable for our own L1?

| System    | STARK-only proof size | With Groth16 wrapper |
|-----------|-----------------------|----------------------|
| RISC Zero | ~200 KB (after recursion) | ~260 bytes      |
| SP1       | ~150–300 KB           | ~260 bytes           |
| OpenVM    | Sub-300 KB            | N/A                  |
| Plonky2   | ~45 KB (with recursion) | Optional           |

**Analysis for Seal**:
- We are NOT on EVM. No calldata costs.
- 200 KB/block at 4-second slots = 50 KB/s bandwidth. Trivial.
- Storage: 200 KB × 21,600 blocks/day = 4.3 GB/day. Manageable; prunable.
- Verification time: 2–100 ms (polylogarithmic in computation size). Fast.
- **STARKs are PQ-secure**. Groth16 wrapper would break PQ security.

**Conclusion: 200 KB STARK proofs are fine.** Use STARK-to-STARK recursion
(FRI folding) if further compression is needed. No SNARK wrapper — it would
defeat the PQC purpose of the chain.

### 14.3 TEE Trust Model

**Question**: How to mitigate TEE hardware-level attacks?

**Known attacks**:
- Intel SGX: Foreshadow, Plundervolt, Aepic Leak, SGAxe
- AMD SEV: SEVered, CVE-2024-56161 (malicious microcode)
- Cross-vendor: TEE.Fail (DDR5 bus interposition, ~$1K equipment, physical access)

**Mitigation strategy — defense in depth**:

1. **Multi-vendor redundancy**: Same computation on Intel TDX + AMD SEV-SNP +
   NVIDIA GPU TEE. Result valid only if all agree. Different microarchitectures
   have uncorrelated vulnerabilities.

2. **TEE + ZK hybrid**: TEE executes at near-native speed. ZK proof generated
   in parallel or stochastically. If TEE is compromised, ZK proof catches the
   discrepancy. Failure modes are uncorrelated (hardware vs math).

3. **Continuous attestation**: Re-attest every 5 minutes (Phala model). Quotes
   must be < 1 hour old. On-chain attestation registry verifiable by anyone.

4. **Mandatory patching**: Nodes that don't apply security updates become
   ineligible for committee election (Oasis model).

5. **Attestation via ZK**: Verify TEE attestation quotes inside a ZK proof
   (~350K gas equivalent, Automata DCAP approach). On-chain, compact, PQ-secure.

---

## 15. Implementation Phases (PQC-Prioritized)

### Phase 0: PQC Foundation (current → +3 months)
- [ ] **PQC crypto library** (ML-DSA, ML-KEM, SHA3) — FIRST PRIORITY
- [ ] **LB-VRF implementation** (fork zhenfeizhang/lb-vrf, harden)
- [ ] Merkle B-tree with SHA3 hashed references
- [ ] SQL parser (sqlparser-rs, PostgreSQL dialect) + execution engine
- [ ] Basic P2P networking (libp2p + ML-KEM handshake)
- [ ] TLA+ spec for consensus protocol
- [ ] Kani proofs for PQC primitives (no overflow, no panic)
- [ ] Fuzz targets for SQL parser and PQC deserializers
- [ ] Single-node prototype: local SQL DB with Merkle proofs

### Phase 1: PQC Consensus + Multi-Node (+3–6 months)
- [ ] PQ-VRF leader selection with per-epoch key rotation
- [ ] Ringtail threshold signatures for committee voting
- [ ] Block production and finalization pipeline (all PQC-signed)
- [ ] ZK proof generation for state transitions (RISC Zero, STARK-only)
- [ ] Multi-node testnet (3–10 validators, all PQC)
- [ ] Lean 4 proofs for Merkle B-tree + VRF correctness
- [ ] Miri on all unsafe blocks; fuzz P2P and VRF
- [ ] Basic CLI wallet (ML-DSA keys, PQC-native)

### Phase 2: SQL + App Layer + Governance (+6–9 months)
- [ ] Full PostgreSQL-compatible SQL engine with RLS policies
- [ ] App namespace deployment and management
- [ ] Local ZK proof generation for SQL writes
- [ ] Local query execution with Merkle verification
- [ ] `seal migrate` CLI (analyze + plan + apply)
- [ ] Governance module (Token House + Technical Council)
- [ ] Native app binary (node + SQL client + wallet)
- [ ] Rocq proofs for state transition function
- [ ] Prusti annotations on token arithmetic

### Phase 3: Bridges + TEE + Payments (+9–12 months)
- [ ] Solana bridge program (Anchor/Rust, PQC-signed on Seal side)
- [ ] Stellar bridge contract (Soroban/Rust)
- [ ] Multi-wallet support (SEAL PQC + SOL + XLM)
- [ ] Token economics (burn-and-mint)
- [ ] TEE node registration + multi-vendor attestation
- [ ] TEE ML/AI inference (GPU TEE + ZK hybrid verification)
- [ ] Service Operators Council governance
- [ ] TLA+ bridge spec verified

### Phase 4: Production Hardening (+12–18 months)
- [ ] LaV migration (many-time PQ-VRF, eliminates key rotation)
- [ ] SNARKing committee signatures (sub-KB aggregation)
- [ ] MPC: private aggregation (SPDZ) + PSI
- [ ] TEE LLM/SLM execution with attestation
- [ ] State pruning and archive node support
- [ ] Client SDKs (JS/WASM, Python)
- [ ] GUI application (Electron wallet + egui explorer)
- [ ] Full security audit (PQC crypto + code + protocol)
- [ ] All formal proofs reviewed and published
- [ ] Mainnet launch

---

## 16. Resolved Design Decisions

### 16.1 Token Supply Model

**Alternatives considered:**

| Model | Mechanism | Pros | Cons |
|-------|-----------|------|------|
| **A. Fixed supply + fee burn** | Hard cap (e.g., 1B SEAL), all fees burned | Scarcity narrative, simple model, deflationary | No ongoing staking rewards after emission ends; validator incentive cliff |
| **B. Tail emission** | High initial emission, decreasing to a fixed floor (e.g., 2%/year forever) | Permanent validator incentives, no security cliff | Mild permanent inflation, harder scarcity narrative |
| **C. Burn-and-mint equilibrium** | Fees burned, validators earn fresh mint; net supply adjusts to usage | Self-regulating: deflationary under growth, stable under steady state | Complex to model; potential death spiral if usage drops sharply |

**Recommendation: B + C hybrid (tail emission + burn-and-mint)**

```
Year 0-4:   10% → 5% annual emission (decreasing schedule)
Year 4-8:   5% → 2% annual emission
Year 8+:    2% tail emission (permanent floor)

Fee mechanism: 50% of base fees burned (EIP-1559 style)
Net inflation = emission_rate - burn_rate
```

- If usage grows, burn > emission → deflationary (like ETH post-merge).
- If usage is low, tail emission keeps validators funded → security maintained.
- Initial supply: **1,000,000,000 SEAL** (1 billion).
- No hard cap, but effective supply is governed by burn/emission balance.

**Genesis allocation:**

| Allocation        | %    | Vesting                           |
|-------------------|------|-----------------------------------|
| Validator rewards | 40%  | Emitted over 8+ years per schedule|
| Team + founders   | 15%  | 4-year vest, 1-year cliff, governance power delayed 6 months |
| Treasury (DAO)    | 20%  | Governance-controlled              |
| Ecosystem grants  | 15%  | Distributed via governance proposals |
| Early backers     | 10%  | 2-year vest, 6-month cliff         |

### 16.2 Governance Bootstrapping

**Problem**: Technical Council must exist before token distribution.

**Alternatives considered:**

| Model | Mechanism | Pros | Cons |
|-------|-----------|------|------|
| **A. Genesis committee** | Founding team appoints initial TC, dissolves after first election | Fast bootstrap, competent initial council | Centralized start |
| **B. Testnet election** | Testnet validators vote on TC before mainnet | More decentralized early | Testnet participants may not represent mainnet stakeholders |
| **C. Progressive decentralization** | Team holds all governance power at launch, delegates incrementally over 6-12 months | Common pattern (Optimism, Compound), proven | Concentration risk if team misbehaves |

**Recommendation: A + C hybrid (genesis committee + progressive decentralization)**

1. **Genesis**: Founding team appoints 7-member Technical Council from known
   PQC/blockchain researchers. Published on-chain with transparency.
2. **Month 3**: Service Operators Council bootstrapped from testnet validators.
3. **Month 6**: First Token House election for Technical Council. Genesis
   committee members can stand for election.
4. **Month 12**: Full governance live. Team governance power vested per
   allocation schedule. No special privileges beyond token holdings.

**Safeguard**: Genesis committee has a **sunset clause** — automatically
dissolved if Token House election hasn't happened by month 9. Prevents
indefinite centralized control.

### 16.3 MPC Integration Depth

**Alternatives considered:**

| Model | Approach | Pros | Cons |
|-------|----------|------|------|
| **A. SQL extension** | `MPC BETWEEN` as first-class SQL syntax | Developer-friendly, declarative, SQL-native | Complex parser changes, limited expressiveness for advanced MPC |
| **B. App-layer SDK** | Rust/JS SDK with `seal_mpc::aggregate(...)` | Maximum flexibility, easier to iterate | Breaks the "everything is SQL" promise |
| **C. Hybrid** | SQL extension for common ops (SUM/COUNT/AVG), SDK for advanced (PSI, auctions) | Best of both worlds | Two APIs to maintain |

**Recommendation: C (hybrid)**

Common aggregations as SQL extensions (Phase 2):
```sql
-- First-class SQL syntax for the 80% case
SELECT SUM(amount), COUNT(*) FROM orders
    WHERE category = 'electronics'
    MPC BETWEEN org_a, org_b;

-- Also supported: AVG, MIN, MAX with MPC BETWEEN clause
```

Advanced operations via SDK (Phase 4):
```rust
// Rust SDK for PSI, auctions, custom protocols
let result = seal_mpc::private_set_intersection(
    my_dataset,
    &["peer_a.seal", "peer_b.seal"],
    &psi_config,
).await?;
```

**Parser impact**: `MPC BETWEEN <parties>` is added as an optional clause
after `WHERE`. sqlparser-rs supports custom dialect extensions.

### 16.4 Cross-App Composability

**Alternatives considered:**

| Model | Semantics | Pros | Cons |
|-------|-----------|------|------|
| **A. Full isolation** | Apps cannot read each other's tables. Period. | Simple, strong security boundary | No composability; apps are silos |
| **B. Explicit grants** | App owner grants read (or write) to other apps via `GRANT SELECT ON app1.table TO app2` | PostgreSQL-native semantics, granular control | Schema coupling between apps |
| **C. Public read, owner write** | All tables readable by any app by default; writes restricted by RLS policies | Maximum composability (like public blockchains) | Privacy concerns; no private tables by default |
| **D. Tiered visibility** | Tables are `PUBLIC`, `SHARED`, or `PRIVATE`. `PUBLIC`: anyone reads. `SHARED`: granted apps read. `PRIVATE`: owner only. | Flexible, covers all cases | More complex access model |

**Recommendation: D (tiered visibility)**

```sql
-- Default: PRIVATE (only owning app can access)
CREATE TABLE users (...) VISIBILITY PRIVATE;

-- Explicitly shared with named apps
CREATE TABLE products (...) VISIBILITY SHARED;
GRANT SELECT ON products TO app2, app3;

-- Fully public (any app can read, like on-chain state)
CREATE TABLE price_feeds (...) VISIBILITY PUBLIC;
```

**Cross-app reads**:
```sql
-- From within app2, reading app1's public table:
SELECT * FROM app1.price_feeds WHERE pair = 'SEAL/USD';

-- From within app2, reading app1's shared table (if granted):
SELECT * FROM app1.products WHERE category = 'electronics';
```

**Cross-app writes**: Never allowed directly. Apps interact via transactions:
app2 submits a `SqlExec` transaction targeting app1, which is evaluated
against app1's RLS policies. This preserves the "owner controls writes"
invariant.

**Foreign keys across apps**: Not supported. Use application-level references
(store the foreign app's primary key as a `TEXT` or `SEAL_ADDRESS` column).

### 16.5 PQ-VRF Audit

**Alternatives considered:**

| Model | Who | Timeline | Cost Estimate |
|-------|-----|----------|---------------|
| **A. Academic audit** | Commission from original LB-VRF authors (Esgin, Steinfeld et al., Monash/CSIRO) | 3-6 months | $50-150K |
| **B. Crypto audit firm** | Trail of Bits, NCC Group, Kudelski, Veridise | 2-4 months | $100-300K |
| **C. Bug bounty** | Public audit via Immunefi/Code4rena after internal review | Ongoing | Variable |
| **D. Formal verification** | Lean/Rocq proof of VRF correctness properties alongside code audit | 4-8 months | $150-250K |

**Recommendation: A + B + D (academic review + audit firm + formal verification)**

**Timeline:**

| Phase | Activity | Timeline |
|-------|----------|----------|
| Phase 0 | Fork zhenfeizhang/lb-vrf, harden, add tests | Month 1-2 |
| Phase 0 | Engage original authors (Esgin et al.) for academic review | Month 2 |
| Phase 0 | Begin Lean 4 proof of VRF uniqueness + pseudorandomness | Month 2-5 |
| Phase 1 | Internal security review + fuzz testing (Kani, cargo-fuzz) | Month 3-4 |
| Phase 1 | Commission crypto audit firm (Veridise recommended — they audit RISC Zero) | Month 4-6 |
| Phase 1 | Bug bounty launch (Immunefi) after audit | Month 6 |
| Phase 2 | Lean 4 proof complete; publish alongside implementation | Month 8 |

**Why Veridise**: They formally verified RISC Zero's zkVM (the same proof
system we use). Familiarity with our stack reduces ramp-up time. They use
the Picus tool for automated formal verification of ZK circuits.

**Risk note**: LB-VRF is pre-standardization research crypto. No NIST or
IRTF standard exists for PQ-VRFs. This audit is essential — it is the
highest-risk cryptographic component in the system.

---

## 17. Repository Structure (Proposed)

```
seal-dao-master/
├── SPEC.md                  # This document
├── CLAUDE.md                # Dev conventions
├── Cargo.toml               # Workspace root
├── crates/
│   ├── seal-crypto/         # PQC primitives (ML-DSA, ML-KEM, SHA3)
│   ├── seal-vrf/            # LB-VRF implementation (PQ-VRF)
│   ├── seal-threshold/      # Ringtail/Quorus threshold signatures
│   ├── seal-merkle/         # Merkle B-tree with hashed references
│   ├── seal-sql/            # SQL parser + execution engine
│   ├── seal-consensus/      # VRF leader selection + committee voting
│   ├── seal-zk/             # ZK proof generation and verification (RISC Zero)
│   ├── seal-p2p/            # libp2p networking layer
│   ├── seal-storage/        # On-disk state and block storage
│   ├── seal-bridge/         # Solana + Stellar bridge logic
│   ├── seal-wallet/         # Key management, signing, multi-chain
│   ├── seal-tee/            # TEE attestation, inference coordination
│   ├── seal-token/          # Token economics, burn-and-mint, staking
│   ├── seal-node/           # Full node binary
│   ├── seal-app/            # Native app (node + client + UI)
│   └── seal-cli/            # Developer CLI tools
├── formal/
│   ├── tlaplus/             # TLA+ specs (consensus, bridge, token)
│   ├── lean/                # Lean 4 proofs (data structures, VRF)
│   └── rocq/                # Rocq/Coq proofs (state transitions)
├── contracts/
│   ├── solana/              # Anchor bridge program
│   └── stellar/             # Soroban bridge contract
├── fuzz/                    # Fuzz targets (cargo-fuzz)
└── tests/
    ├── integration/         # Multi-node integration tests
    ├── property/            # Property tests derived from formal specs
    └── kani/                # Kani verification harnesses
```

---

## 14. References

### PQ-VRF
- Esgin et al. "Practical Post-Quantum Few-Time VRF" (FC 2021) — [ePrint 2020/1222](https://eprint.iacr.org/2020/1222)
- Esgin et al. "LaV: Efficient Lattice-Based VRF" (CRYPTO 2023) — [ePrint 2022/141](https://eprint.iacr.org/2022/141)
- LB-VRF Rust implementation — [github.com/zhenfeizhang/lb-vrf](https://github.com/zhenfeizhang/lb-vrf)
- X-VRF broken — [FC 2024](https://www.ifca.ai/fc24/preproceedings/213.pdf)

### Threshold Signatures
- Ringtail (2-round, LWE) — [ePrint 2024/1113](https://eprint.iacr.org/2024/1113)
- Quorus (ML-DSA compatible) — [ePrint 2025/1163](https://eprint.iacr.org/2025/1163)
- Threshold Raccoon (Eurocrypt 2024) — [ePrint 2024/184](https://eprint.iacr.org/2024/184)
- TalonG (bandwidth-efficient) — [ePrint 2026/303](https://eprint.iacr.org/2026/303)
- MuSig-L (multi-sig, CRYPTO 2022) — [ePrint 2022/1036](https://eprint.iacr.org/2022/1036)
- Falcon+LaBRADOR aggregation (CRYPTO 2024) — [ePrint 2024/311](https://eprint.iacr.org/2024/311)

### ZK Proof Systems
- RISC Zero — [risczero.com](https://risczero.com)
- SP1 (Succinct) — [github.com/succinctlabs/sp1](https://github.com/succinctlabs/sp1)
- OpenVM (Axiom) — [openvm.dev](https://openvm.dev)
- Jolt (a16z) — [github.com/a16z/jolt](https://github.com/a16z/jolt)

### TEE & AI
- Phala Network GPU TEE — [phala.com](https://phala.com)
- Automata DCAP attestation — [ata.network](https://ata.network)
- NVIDIA Confidential Computing — [nvidia.com/confidential-computing](https://www.nvidia.com/en-us/data-center/solutions/confidential-computing/)

### Formal Verification Tools (Rust)
- Kani Model Checker — [model-checking.github.io/kani](https://model-checking.github.io/kani/)
- Prusti — [viperproject.github.io/prusti-dev](https://viperproject.github.io/prusti-dev/)
- MIRAI — [github.com/facebookexperimental/MIRAI](https://github.com/facebookexperimental/MIRAI)
- Miri — [github.com/rust-lang/miri](https://github.com/rust-lang/miri)
