# Seal DAO — KMS & Private Key Management Design

> **Scope:** Operational design for how all Seal DAO private keys and secrets are
> generated, stored, distributed, used, rotated, revoked, backed up, and recovered.
>
> **Date:** 2026-05-27
>
> **Related:** [KEY-SECURITY-AUDIT.md](KEY-SECURITY-AUDIT.md) (inventory/assessment),
> [ADR-003](decisions/ADR-003-kms-sidecar-pairing.md) (architecture decision)

---

## 1. Key Classification

Every secret in the Seal DAO stack falls into one of three **classification tiers**:

| Tier | Description | Keys |
|------|------|------|
| **T1 — Bridge signing** | Withdrawal witness authority. Compromise = unlimited bridge drain. | Committee MAC key, Ringtail keypair |
| **T2 — Node identity** | Consensus/P2P identity. Compromise = node impersonation, not fund loss. | Validator key, P2P transport keys |
| **T3 — Infrastructure** | Handshake auth, operational ephemeral keys. Compromise = limited scope. | Master KEM/DSA keys, node handshake keys, council smoke-test keys |

### 1.1 Key Inventory

| # | Key | Tier | Size | Format | Primary Owner |
|---|-----|------|------|--------|---------------|
| K1 | Committee MAC key | T1 | 32 bytes | hex (64 chars) | Master KMS |
| K2 | Ringtail keypair | T1 | ~18 KB | JSON (`public_params` + `sk_collapsed_hex`) | Master KMS |
| K3 | Validator key | T2 | ML-DSA-65 (4032 B sk / 1952 B vk) | JSON keyfile | Individual node |
| K4 | Master KEM keypair | T3 | 1184/2400 B | LockedBuffer | Master KMS |
| K5 | Master DSA keypair | T3 | 1184/4032 B | LockedBuffer | Master KMS |
| K6 | Node KEM keypair | T3 | 1184/2400 B | In-memory (ephemeral per pairing) | Individual node |
| K7 | Node DSA keypair | T3 | 4032 B sk / 1952 B vk | In-memory (persistent per node) | Individual node |
| K8 | P2P transport key | T3 | 1184/2400 B | In-memory (fresh per process start) | Individual node |
| K9 | Solana deployer key | T3 | 64 B Ed25519 | JSON keyfile | Operator workstation |
| K10 | Stellar deployer key | T3 | 64 B Ed25519 | stellar CLI keyring | Operator workstation |
| K11 | Bridge program keypair | T3 | 64 B Ed25519 | JSON keyfile | Operator workstation |
| K12 | E2E recipient key | T3 | ML-DSA-65 | JSON keyfile | Test harness |

---

## 2. Storage Model

### 2.1 Secure Memory (Master KMS)

All T1 keys (K1, K2) and T3 master keys (K4, K5) are **age-encrypted on disk**
and loaded into **`LockedBuffer`** via `rust-secure-memory` at KMS startup.

```
┌─────────────────────────────────────────────────┐
│               LockedBuffer (RAM)                │
│                                                   │
│  [guard_page] [guard_page] [key_material]        │
│  [guard_page] [guard_page] [key_material]        │
│         ↑              ↑                          │
│   mlock() prevents   Sentinel canaries detect   │
│   swap-to-disk       memory tampering            │
│                                                   │
│  On drop/overflow: zeroize with cryptographically │
│  secure wipe pattern (zeroize crate)              │
└─────────────────────────────────────────────────┘
```

**Properties:**
- `mlock()` / `mlockall(MCL_FUTURE)` — kernel prevents page-out
- Guard pages on both sides of each buffer — any OOB access triggers SIGSEGV
- Canary sentinels — read-only markers between guard and data; changed by OOB access
- `zeroize` on drop — cryptographically secure zero-fill

**Two-layer storage model:**

| Layer | Where | What | Encryption |
|-------|-------|------|------------|
| **At rest** (disk) | `/etc/seal-kms/*.enc` | age-encrypted blobs | `age` with master decryption key (PIN-protected or hardware-bound) |
| **At runtime** (RAM) | `LockedBuffer` | plaintext key material | mlock prevents swap; guard pages prevent leaks |

**Lifecycle:**
1. **KMS startup:** read age-encrypted file from disk → decrypt → load into LockedBuffer
2. **Runtime:** all operations use plaintext from LockedBuffer (never serialize to disk)
3. **KMS shutdown:** zeroize LockedBuffer → keys only exist as age-encrypted files on disk

If the machine crashes (no graceful shutdown): LockedBuffer is lost (RAM volatile),
but age-encrypted files on disk survive. Restart KMS → re-decrypt → back to normal.
No key material is exposed on disk in plaintext at any point.

### 2.2 File Storage (Node Validators)

T2 keys (K3) are stored on-node as JSON files with `chmod 600`:

```json
{
  "version": 1,
  "algorithm": "ML-DSA-65",
  "signing_key_hex": "...",
  "verifying_key_hex": "...",
  "metadata": {
    "created_unix": 1748300000,
    "node_id": "a1b2c3d4...",
    "paired_by": "kms-sidecar/0.1.0"
  }
}
```

**Operators may encrypt these files at rest.** The seal-node binary does not handle
file encryption — it trusts the filesystem. Recommended: `ecryptfs` mount, or
`age` encryption with `age -d -i key.txt encrypted-validator-key.json.age`.

### 2.3 Operational Workstations

T3 operational keys (K9-K11) live on the operator's machine:
- Solana: `~/.config/solana/id.json`
- Stellar: `~/.stellar/keys/<name>`
- Bridge program: `bridges/solana/target/deploy/seal_bridge-keypair.json`

These are **never** stored in the repository or on cloud VMs.

### 2.4 On-Chain State

The bridge committee key (K1) is stored on-chain as PDA state in both Solana and
Stellar bridge programs. This is **public** — it's the verification key that the
host-side HMAC/Ringtail signature is computed against. The private key (the HMAC
secret or Ringtail secret polynomial) must never be exposed.

---

## 3. Key Lifecycle

Each key goes through these states:

```
         generate
            │
            ▼
      ┌─────────┐
      │ created  │── revocation/loss ──► revoked
      └────┬─────┘
           │ distribute
           ▼
      ┌─────────┐
      │ active   │── rotation ──►┐
      └────┬─────┘               │
           │ backup               │
           ▼                     ▼
      ┌─────────┐        ┌─────────┐
      │ backed   │        │ retired │
      │ up       │        │ (old)   │
      └─────────┘        └─────────┘
```

### 3.1 Generation

| Key | Method | Entropy Source |
|-----|--------|----------------|
| K1 (committee MAC) | `openssl rand -hex 32` | OS CSPRNG |
| K2 (Ringtail) | `BridgeManager::set_committee_ringtail_keypair()` + `RingtailKeypair::generate()` | ML-KEM/RLWE sampling |
| K3 (validator) | `SEAL_VALIDATOR_KEY=/path/to/key.json` env var → entrypoint generates JSON | OS CSPRNG via seal-crypto |
| K4/K5 (master KMS) | KMS sidecar startup: `HybridKemKeypair::generate()` + `SigningKey::generate()` | OS CSPRNG |
| K6/K7 (node) | Generated during pairing; K6 is ephemeral, K7 is the node's persistent ML-DSA identity | OS CSPRNG |

### 3.2 Distribution

See [Section 5](#5-pairing-and-key-distribution) for the full pairing protocol.
Summary:

| From | To | Method | Secrets Transferred |
|------|-----|--------|---------------------|
| Master KMS | New node | Hybrid KEM-encrypted transfer | Validator key (K3) only |
| Operator | Solana/Stellar programs | CLI deployment tools | Program keypairs (K11) |
| Operator | Operator workstation | Manual transfer / secrets manager | Deployer keys (K9, K10) |

### 3.3 Usage

KMS-sidecar keys (K1, K2, K4, K5) are used only via the Unix socket API:

| API Call | Key Used | Operation |
|----------|----------|-----------|
| `SignCommittee` | K1 (via `hmac_sha256(key, payload)`) | HMAC-SHA-256 of withdrawal payload |
| `SignRingtail` | K2 (via `compute_committee_ringtail_sig`) | Ringtail lattice signature |
| `PairNode` | K4 + K5 | Hybrid KEM encryption + ML-DSA handshake auth |

K3 (validator key) is used directly by seal-node:
- Block production (ML-DSA-65 signing)
- VRF evaluation (post-quantum VRF)
- P2P message authentication

### 3.4 Rotation

| Key | Rotation Method | Downtime | Old Key Impact |
|-----|------|------|-----|
| K1 (committee MAC) | `seal_bridgeRotateCommitteeKey` RPC → new key via `--bridge-committee-key` + `--clear-committee-key-file` | Short (block of withdrawals) | Old signatures become invalid; pending withdrawals unclaimable |
| K2 (Ringtail) | Generate new keypair → deploy bridge programs with new params → migrate pending withdrawals | Extended (needs on-chain redeploy) | All pending Ringtail-signature withdrawals become unclaimable |
| K3 (validator) | New keyfile → restart node with `--validator-key <new-path>` | Node restart | Old identity loses stake; must unstake and re-stake |
| K4/K5 (master) | Regenerate → revoke all paired nodes → re-pair | Full outage | All paired nodes become untrusted |

### 3.5 Revocation

Revocation is managed in the **KMS trust store** (`crates/seal-kms-sidecar/src/trust_store.rs`):

```json
{
  "version": 1,
  "nodes": [
    {
      "node_id": "a1b2c3d4e5f6...",
      "node_hybrid_pk_hex": "...",
      "node_ml_dsa_vk_hex": "...",
      "paired_at_unix": 1748300000,
      "last_seen_unix": 1748400000,
      "revoked": true,
      "revoked_at_unix": 1748500000,
      "revocation_reason": "compromised"
    }
  ]
}
```

When a node is revoked:
1. `TrustStore.revoke(node_id, reason)` marks it `revoked: true`
2. KMS rejects all future `PairNode`, `SignCommittee`, `SignRingtail` requests from that node
3. `KmsTrustRequest` for that node returns `trusted: false`
4. The node's validator key is still on the node, but it can't get bridge signatures

**Governance path for revocation:** A TechnicalCouncil 2/3 supermajority vote can
revoke a node from the trust store. For automated revocation (e.g. detected compromise),
the KMS sidecar supports a `--auto-revoke-on-anomaly` flag that revokes nodes showing
suspicious behavior patterns.

### 3.6 Backup

| Key | Backup Method | Recovery Method |
|-----|------|------|
| K1 (committee MAC) | age-encrypted blob at `/etc/seal-kms/committee-key.enc` | KMS decrypts at startup into LockedBuffer |
| K2 (Ringtail) | age-encrypted blob at `/etc/seal-kms/ringtail-master-keys.enc` | KMS decrypts at startup into LockedBuffer |
| K3 (validator) | Copy `$DATA_DIR/validator-key.json` to secure storage | Mount to `$DATA_DIR` or pass via `--validator-key` |
| K4/K5 (master) | age-encrypted blob at `/etc/seal-kms/master-kem-sig-keys.enc` | KMS decrypts at startup into LockedBuffer |

**Shamir share of age-decryption key — error detection via VSS:**

Standard Shamir secret sharing has no error detection: if one shareholder
provides a bad share (accidentally or maliciously), the reconstructed key
is silently wrong. To prevent this, we use **hash-based Verifiable Secret
Sharing (VSS)**:

1. **Distribution phase:** When splitting the age-decryption key `S` into
   n shares, the dealer computes `H_i = SHA3(share_i)` for each share and
   publishes the commitment list `{ (i, H_i) }`.

2. **Reconstruction phase:** Each shareholder sends their share to the
   reconstruction server. The server computes `H'_i = SHA3(received_share_i)`
   and checks against the published `H_i`.

3. **Detection:** Any mismatch means either:
   - The shareholder is providing a bad share → reject their contribution
   - The transmission was corrupted → retry
   - The commitment list was tampered with → abort

4. **Threshold enforcement:** The reconstruction proceeds with only shares
   that pass the VSS check. If fewer than t valid shares arrive, abort
   (not enough shareholders).

**This is lightweight:** SHA3-256 commitments, no expensive zero-knowledge
proofs. The commitment list is published alongside the Shamir shares
during distribution and never changes.

**All encrypted blobs use the same age decryption key.** This decryption key
is the single point of failure for key recovery. It must be stored independently:
- In a secrets manager (HashiCorp Vault, AWS Secrets Manager)
- On a hardware security key (YubiKey with age plugin)
- Split between N trusted parties via Shamir secret sharing

**Critical:** Committee key and Ringtail key backup is the **highest priority** backup
operation. Loss of these keys means the bridge cannot process any pending withdrawals,
and all future withdrawals are blocked.

### 3.7 Destruction

| Key | Destruction Method |
|-----|---------------------|
| K1 (committee MAC, old) | `zeroize` in LockedBuffer; delete persisted `.hex` file |
| K2 (Ringtail, old) | `zeroize` in LockedBuffer; delete JSON file |
| K3 (validator, decommissioned) | Delete `$DATA_DIR/validator-key.json` |
| K4/K5 (master, rotated) | `zeroize` in LockedBuffer; delete master key files |
| K6 (node, revoked) | Erased from process memory on restart |
| K7 (node, decommissioned) | Delete node's ML-DSA keypair from filesystem |

---

## 4. KMS Sidecar Architecture

### 4.1 Process Model

```
┌──────────────────────────────────────────────────────┐
│                    Master Machine                    │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │          seal-kms-sidecar (PID 1 or systemd)   │  │
│  │                                                │  │
│  │  /tmp/seal-kms.sock  ← Unix socket (mode 0700) │  │
│  │                                                │  │
│  │  ┌──────────────────────────────────────────┐  │  │
│  │  │         LockedBuffer region              │  │  │
│  │  │  K1: committee_key [32 bytes]            │  │  │
│  │  │  K2: ringtail_sk [2048 bytes]            │  │  │
│  │  │  K4: master_kem_sk [2400 bytes]          │  │  │
│  │  │  K5: master_sig_sk [4032 bytes]          │  │  │
│  │  └──────────────────────────────────────────┘  │  │
│  │                                                │  │
│  │  trust_store.json  ← encrypted at rest         │  │
│  │  master_keys/    ← encrypted master keyfiles   │  │
│  └────────────────────────────────────────────────┘  │
│                                                      │
│  ┌───────────┐  ┌──────────┐  ┌──────────┐         │
│  │ seal-1    │  │ seal-2   │  │ seal-3   │         │
│  │ (Docker)  │  │ (Docker) │  │ (cloud)  │         │
│  └───────────┘  └──────────┘  └──────────┘         │
└──────────────────────────────────────────────────────┘
```

### 4.2 Trust Store

The trust store is the KMS sidecar's source of truth for which nodes are authorized
to receive validator keys and sign requests.

**On-disk format (encrypted at rest):**

```json
{
  "version": 1,
  "encryption": "age-v1",
  "encrypted_payload": "age1...base64...",
  "metadata": {
    "created_unix": 1748300000,
    "master_fingerprint": "sha3-of-master-ml-dsa-vk"
  }
}
```

The `age-v1` encryption key is derived from a passphrase + the machine's hardware
fingerprint. If the passphrase is lost, the trust store cannot be recovered — all
paired nodes must be re-paired with a new master keypair.

**CRITICAL — signer_index persistence:**
Bridge operator `signer_index` values are assigned sequentially starting from 0.
The KMS MUST persist the `last_assigned_signer_index` in the trust store metadata
as a monotonically increasing counter. On startup, the KMS reads this counter from
disk and continues from the next value. **Never reset the counter on restart or
backup restore.** Resetting it would assign the same Shamir share to a new node,
creating two machines with identical bridge key shares — catastrophic because
threshold security collapses from t-of-n to 1-of-many.

If the entire trust store is reinitialized (e.g., after master key compromise),
all paired nodes must be re-paired and `signer_index` can restart from 0.

**In-memory representation:**

```rust
struct TrustStore {
    /// node_id → node info
    nodes: HashMap<String, NodeInfo>,
    /// master's ML-DSA verifying key (for signature verification)
    master_ml_dsa_vk: Vec<u8>,
}

struct NodeInfo {
    node_id: String,                  // SHA3(node_ml_dsa_vk) hex
    node_hybrid_pk: HybridKemPublicKey,
    node_ml_dsa_vk: Vec<u8>,          // for verifying node's signing requests
    paired_at: Instant,
    last_seen: Option<Instant>,
    revoked: bool,
    revocation_reason: Option<String>,
    // Bridge-specific fields (populated only when --bridge-operator=true):
    bridge_signer_index: Option<usize>,  // assigned once, persisted, never reused
    bridge_keyshare_encrypted: Option<Vec<u8>>,  // encrypted blob (age or KEM)
}
```

### 4.3 KMS API Protocol

**Transport:** JSON-over-lines over Unix domain socket.

Each message is a single JSON object terminated by `\n`:

```
{"jsonrpc":"2.0","id":1,"method":"PairNode","params":{...}}
{"jsonrpc":"2.0","id":1,"result":{"encrypted_validator_key":"...","master_challenge":"..."}}
```

**Error format:**

```
{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Node not in trust store"}}
```

Standard JSON-RPC 2.0 error codes:
- `-32600`: Invalid request
- `-32601`: Method not found
- `-32602`: Invalid params
- `-32603`: Internal error
- `-32000 to -32099`: Application-specific (e.g., node revoked, key not loaded)

### 4.4 API Endpoint Reference

#### `PairNode`

Pair a new node. The node must first be pre-registered in the trust store via
`TrustStorePreRegister` (out-of-band, done by admin).

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "PairNode",
  "params": {
    "node_id": "a1b2c3d4e5f6...",
    "node_hybrid_pk_hex": "...",
    "node_ml_dsa_sig_hex": "...",
    "challenge_hex": "..."
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "encrypted_validator_key_hex": "...",
    "master_challenge_hex": "...",
    "master_timestamp_unix": 1748400000
  }
}
```

**Validation:**
1. Node must exist in trust store and not be revoked
2. `node_ml_dsa_sig` must verify against `node_ml_dsa_vk` for message
   `SHA3("seal-pair" || node_id || node_hybrid_pk || challenge)`
3. If valid, load validator key from secure storage, encrypt under node's
   hybrid public key, sign response with master signing key

#### `SignCommittee`

Sign a bridge withdrawal payload with the committee MAC key.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "SignCommittee",
  "params": {
    "payload_hex": "...",
    "nonce": 42
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "signature_hex": "..."
  }
}
```

**Operation:** `hmac_sha256(committee_key, payload_hex)`

### 4.5 KMS API Reliability

All KMS API calls are synchronous JSON-over-lines. The calling process (seal-node)
must handle failures gracefully. **No call should block indefinitely.**

**Connection-level:**
- TCP/Unix socket connect timeout: **5 seconds**
- Connection refused → fail open with error (not hang)
- Connection reset → one retry with 1s backoff

**Request-level:**
- Request timeout: **10 seconds** (SignRingtail may be longer for t-of-n rounds)
- Timeout → return error to caller, do not hang bridge withdrawal
- No retry on timeout (caller decides whether to retry)

**Circuit breaker:**
- After 3 consecutive failures within 60 seconds → open circuit
- Open circuit → immediately return error without contacting KMS
- Half-open after 30 seconds → send probe request
- If probe succeeds → close circuit, resume normal operation
- If probe fails → reopen circuit, wait another 30 seconds

**SignRingtail-specific:**
- Round 1 (P2P protocol phase): no KMS call (local P2P)
- Round 2 (aggregation phase): KMS call to sign final response
- Max wait for Round 2 message from other signers: **120 seconds**
- If threshold met before all signers respond: proceed with available shares

**Error propagation:**
```rust
// BridgeManager on KMS timeout:
match kms.sign_committee(&payload).await {
    Ok(sig) => Ok(sig),
    Err(e) => {
        // Log error, create withdrawal record without signature
        // Worker can retry later or operator can manually sign
        warn!("KMS signing failed: {}", e);
        Err("committee_signature_unavailable".into())
    }
}
```

---

#### `SignRingtail`

Sign a bridge withdrawal payload with the Ringtail keypair.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "SignRingtail",
  "params": {
    "payload_hex": "...",
    "chain": "solana"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "signature_hex": "..."
  }
}
```

**Operation:** `compute_committee_ringtail_sig(chain, public_params, sk_collapsed, ...)`

#### `TrustStoreList`

List all paired nodes.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "TrustStoreList",
  "params": {}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "nodes": [
      {
        "node_id": "...",
        "node_hybrid_pk_hex": "...",
        "paired_at_unix": 1748300000,
        "last_seen_unix": 1748400000,
        "revoked": false
      }
    ],
    "total": 3
  }
}
```

#### `TrustStoreRevoke`

Revoke a paired node.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "TrustStoreRevoke",
  "params": {
    "node_id": "...",
    "reason": "compromised"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "revoked": true
  }
}
```

#### `TrustStorePreRegister`

Pre-register a node's verifying key in the trust store. This is an out-of-band
operation performed by the admin, either locally on the master or via a
pre-shared token over the Unix socket.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "TrustStorePreRegister",
  "params": {
    "node_id": "...",
    "node_ml_dsa_vk_hex": "...",
    "description": "us-east-1-bridge-1"
  }
}
```

#### `Health`

**Request:**
```json
{"jsonrpc": "2.0", "id": 7, "method": "Health", "params": {}}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "result": {
    "status": "ok",
    "locked_buffers_active": 4,
    "paired_nodes": 3,
    "uptime_seconds": 86400
  }
}
```

---

## 5. Pairing and Key Distribution

### 5.1 Pre-Registration (Admin)

Before a new node can pair, the admin must pre-register its identity in the trust
store. This is a one-time, out-of-band operation:

```bash
# On the master machine:
seal-kms-cli trust-add \
  --node-id <hex> \
  --ml-dsa-vk <hex> \
  --description "us-east-1-bridge-1"
```

The admin receives the `node_id` from the node operator (who generated it
locally). The `ml_dsa_vk` is the node's ML-DSA verifying key — this is how the
KMS verifies the node's identity during pairing.

### 5.2 Full Pairing Protocol

```
Phase 1 — Node bootstrap
  Node generates:
    - node_hybrid_kem_keypair (K6: ML-KEM + X25519)
    - node_sig_keypair (K7: ML-DSA-65, persistent identity)
    - node_id = SHA3-256(hex_encode(K7_vk))
    - challenge = 32 random bytes from OS CSPRNG

Phase 2 — Pair request
  Node sends PAIR_REQUEST to KMS socket:
    {
      node_id,
      node_hybrid_pk_hex,
      node_ml_dsa_sig_hex,    // signs (SHA3("seal-pair" || node_id || pk || challenge))
      challenge_hex
    }

Phase 3 — KMS verification
  KMS sidecar:
    1. Look up node_id in TrustStore
    2. If not found or revoked → reject
    3. Verify node_ml_dsa_sig against stored node_ml_dsa_vk
    4. If signature invalid → reject (log as attempted unauthorized access)

Phase 4 — Key transfer
  KMS sidecar (if verified):
    a. Load validator_key from LockedBuffer
    b. Encrypt under node_hybrid_pk (hybrid KEM encapsulation):
       (ss, ct_kem, ct_x25519) = node_hybrid_pk.encapsulate(validator_key_as_32B)
       enc_key = ct_kem || ct_x25519
    c. Sign (SHA3("seal-pair-resp" || node_id || challenge)):
       master_sig = master_sig_sk.sign(response_hash)
    d. Generate master_challenge = 32 random bytes
    e. Return {enc_key, master_sig, master_challenge}

Phase 5 — Node verification
  Node:
    a. Verify master_sig against master_ml_dsa_vk (pre-baked or known)
    b. Decrypt enc_key:
       ss = node_hybrid_kem_sk.decapsulate(ct_kem, ct_x25519)
       validator_key = extract_key(ss)
    c. Store validator_key at $DATA_DIR/validator-key.json

Phase 6 — Challenge-response proof
  Node:
    a. Compute reply = SHA3-256(challenge)
    b. Send to KMS: {reply_hex}
  KMS:
    a. Compute expected = SHA3-256(challenge)
    b. If reply == expected → node successfully received the key
    c. Update TrustStore last_seen
    d. Mark node as active
```

### 5.3 What Is Transferred vs. What Is Not

| Item | Transferred to Node? | Stored Where | Can Node Extract Committee Key? |
|------|------|------|------|
| Validator key (K3) | Yes | `$DATA_DIR/validator-key.json` | N/A |
| Committee MAC key (K1) | No | Master LockedBuffer | No — KMS only signs payloads |
| Ringtail keypair (K2) | No | Master LockedBuffer | No — KMS only signs payloads |
| Master KEM keys (K4) | No | Master LockedBuffer | No |
| Master DSA keys (K5) | No | Master LockedBuffer | No |
| Node's own handshake keys (K6/K7) | N/A | Generated locally | N/A |

---

## 6. Bridge Signing Flow

### 6.1 Normal Path (File-Based, Current Behavior)

```
seal_bridgeWithdraw RPC
  → BridgeManager.initiate_withdrawal()
    → compute_committee_signature()
      → HMAC-SHA-256(committee_key_bytes, payload)
        → committee_key read from FileKeySource (on-disk file)
```

### 6.2 KMS Path (New Behavior)

```
seal_bridgeWithdraw RPC
  → BridgeManager.initiate_withdrawal()
    → compute_committee_signature()
      → committee_signer.is_some()? YES
        → committee_signer.sign_committee(payload)
          → HTTP-over-Unix: KmsClient → /tmp/seal-kms.sock
            → KMS sidecar: hmac_sha256(LockedBuffer[K1], payload)
              → signature_hex
```

**Critical:** In the KMS path, `BridgeManager` never holds the raw committee key.
The `KmsClient` sends the payload to the KMS sidecar and receives only the
signature back. The committee MAC key never appears in the node's memory space.

### 6.3 Ringtail Path

Same flow as 6.2, but:
```
→ ringtail_signer.sign_ringtail(payload)
  → HTTP-over-Unix: KmsClient → /tmp/seal-kms.sock
    → KMS sidecar: compute_committee_ringtail_sig(chain, pp, sk, ...)
```

### 6.4 Withdrawal Claim (Relayer)

The KMS signs the withdrawal record. A relayer process (separate concern) reads
the withdrawal from the Seal RPC and submits the unlock on the destination chain:

```
seal_listBridgeWithdrawals (pending)
  → relayer reads withdrawal_id, signature_hex, dest_chain, dest_address
  → relayer constructs on-chain claim:
     Solana: anchor lang idl build ... → unlock_tokens(sig, nonce, ...)
     Stellar: stellar contract invoke ... → unlock_xlm(recipient, amount, nonce, proof)
  → relayer signs with source-chain wallet (separate key, not a Seal key)
  → relayer broadcasts to source-chain RPC
```

---

## 7. Operational Runbooks

### 7.1 Start KMS Sidecar

```bash
# Generate master keys (first run only)
seal-kms-cli init --data-dir /etc/seal-kms

# Start the sidecar
seal-kms-sidecar --data-dir /etc/seal-kms --socket /tmp/seal-kms.sock

# Verify
echo '{"jsonrpc":"2.0","id":7,"method":"Health","params":{}}' | \
  socat - UNIX-CONNECT:/tmp/seal-kms.sock
```

### 7.2 Add Node to Trust Store

```bash
# Get node's ML-DSA verifying key (from node operator)
# Node operator runs:
#   seal-cli keygen --show-vk

seal-kms-cli trust-add \
  --node-id <hex> \
  --ml-dsa-vk <hex> \
  --description "us-east-1-bridge-1"
```

### 7.3 Pair a Node

```bash
# On the node machine:
seal-kms-cli pair \
  --socket tcp://<master-ip>:5150 \
  --trust-store <trusted-master-vk> \
  --output-dir /data
```

Or via the seal-node CLI:

```bash
seal-node \
  --bridge-kms-config /etc/seal-node/kms.json \
  --data-dir /data
```

Where `kms.json` contains:
```json
{
  "mode": "kms",
  "socket": "unix:///tmp/seal-kms.sock"
}
```

### 7.4 Rotate Committee Key

```bash
# 1. Generate new key
NEW_KEY=$(openssl rand -hex 32)

# 2. Drain pending withdrawals (notify users to claim)
# 3. On master KMS:
seal-kms-cli rotate-committee --new-key "$NEW_KEY"

# 4. Update on-chain bridge programs
#    Solana: anchor run rotate_committee_key --cluster devnet
#    Stellar: stellar contract invoke ... rotate_committee_key ...

# 5. On all nodes:
#    Remove stale persisted file + restart with new key
docker compose exec seal-1 rm -f /data/bridge-committee-key.hex
docker compose restart seal-1

# 6. Verify
curl localhost:8645 -d '{"jsonrpc":"2.0","id":1,"method":"seal_getBridgeStatus"}'
```

### 7.5 Revoke Compromised Node

```bash
# 1. Identify the compromised node
seal-kms-cli trust-list

# 2. Revoke
seal-kms-cli trust-revoke \
  --node-id <hex> \
  --reason "detected unauthorized key export attempt"

# 3. Verify
echo '{"jsonrpc":"2.0","id":1,"method":"TrustStoreList","params":{}}' | \
  socat - UNIX-CONNECT:/tmp/seal-kms.sock
```

### 7.6 Disaster Recovery — Lost Committee Key

If the master KMS is lost (disk failure, hardware theft) and the committee key
backup is available:

```bash
# 1. Restore KMS keys from backup
cp /secure/backup/master-keys.tar.enc /etc/seal-kms/
age -d -i /secure/backup/age-key.txt /etc/seal-kms/master-keys.tar.enc | tar xf -

# 2. Restore trust store from backup
cp /secure/backup/trust-store.json.age /etc/seal-kms/
age -d -i /secure/backup/age-key.txt trust-store.json.age > trust-store.json

# 3. Restart KMS sidecar
seal-kms-sidecar --data-dir /etc/seal-kms

# 4. Verify health
# 5. Re-pair any nodes that were decommissioned during the outage
```

If the committee key backup is **also** lost:
1. The bridge is permanently frozen — no withdrawals can be processed
2. TechnicalCouncil must decide: drain (burn all wrapped tokens, return to owners)
   or accept the loss
3. On-chain committee key must be rotated to a new value (new HMAC key) via
   governance proposal
4. All users with pending withdrawals must be compensated from a insurance fund
   or absorbed as a protocol loss

**This is why committee key backup is the highest-priority backup operation.**

### 7.7 Disaster Recovery — Lost Ringtail Keypair

Same severity as lost committee key. Ringtail is the production withdrawal signing
path. If both K1 and K2 are lost, the bridge is frozen.

Recovery steps are identical to 7.6 but with the Ringtail keypair file instead of
the committee MAC hex.

---

## 8. Threat Model

### 8.1 Assets

| Asset | Impact if Compromised |
|-------|------|
| Committee MAC key (K1) | Unlimited bridge fund drain |
| Ringtail keypair (K2) | Unlimited bridge fund drain |
| Validator key (K3) | Node impersonation, potential consensus disruption |
| Master KEM/DSA keys (K4/K5) | Impersonate KMS, pair fake nodes |
| Deployer keys (K9/K10) | Deploy malicious bridge programs (testnet only) |

### 8.2 Attack Vectors

| Threat | Mitigation |
|--------|------|
| Node compromise → committee key extraction | Committee key never leaves master; KMS only returns signatures |
| Disk forensics on master | `LockedBuffer` with `mlock()` + guard pages; no swap; keys zeroized on process exit |
| Man-in-the-middle during pairing | PQ-Noise handshake with ML-DSA identity signatures; challenge-response proof |
| Compromised node in trust store | `TrustStoreRevoke` API; revocation is immediate and permanent |
| KMS process crash | LockedBuffer zeroizes on drop; trust store persisted to disk; validator key was encrypted |
| KMS process replaced by attacker | Master DSA keys (K5) sign all KMS responses; node verifies master signature |
| Brute-force on committee key (256-bit) | 2^256 is infeasible; HMAC-SHA-256 is secure |
| Quantum attack on ML-KEM-768 | ML-KEM-768 is NIST-standardized, believed quantum-resistant |
| Quantum attack on X25519 | Hybrid design: even if X25519 is broken, ML-KEM protects the session |
| Trust store corruption | Encrypted at rest with `age`; integrity checked on load; backup available |

### 8.3 Trust Assumptions

| Assumption | Rationale |
|------|------|
| OS CSPRNG is trustworthy | `/dev/urandom` on modern Linux; NIST SP 800-90C compliant |
| `mlock()` prevents swapping | Linux kernel guarantees; verified via `/proc/`PID`/maps` |
| Master machine is physically secure | If attacker has root + physical access, no software mitigation helps |
| Unix socket is not accessible to untrusted processes | Socket mode `0700`; only KMS operator user can connect |
| `rust-secure-memory` implementation is correct | External crate; needs audit before production use |

---

## 9. File Permissions Checklist

| Path | Mode | Owner | Notes |
|------|------|-------|-------|
| `/tmp/seal-kms.sock` | `0700` | kms user | Unix socket; no world access |
| `/etc/seal-kms/master-keys/` | `0700` | kms user | Encrypted master key material |
| `/etc/seal-kms/trust-store.json.age` | `0600` | kms user | Encrypted trust store |
| `$DATA_DIR/validator-key.json` | `0600` | seal user | On-node validator key |
| `<data_dir>/bridge-committee-key.hex` | `0600` | seal user | Only if using file-based (non-KMS) mode |
| `--bridge-ringtail-keypair-file` | `0600` | seal user | Ringtail keypair JSON |
| `~/.config/solana/id.json` | `0600` | operator | Solana deployer key |
| `~/.stellar/keys/` | `0700` | operator | Stellar keyring directory |

---

### 10.0 Architecture Decisions

The system supports **three deployment models**, ordered by security posture
from simplest to production-grade.

#### Profile A: Single-Operator (Not recommended for production)

All keys on one always-on machine that also serves signing requests.

```
Cloud VM (always-on):
  seal-kms-sidecar — both key store AND signing endpoint
  - age-encrypted keys on disk
  - LockedBuffer at runtime
  - Unix socket for local signing requests
  - bridge-keyshare → seal-node (co-located)
```

**Risk:** Single machine holds all keys. Compromise = bridge drained.
**Best for:** Testnet, internal evaluation.

#### Profile B: Decentralized Workers + Local Authority

Your local machine holds the permanent key store and Shamir shares.
Cloud machines are ephemeral signing workers.

```
Local machine (your laptop / desktop):
  seal-kms-local — key authority + Shamir share storage
  - /etc/seal-kms/*.enc  ← age-encrypted master keys
  - trust-store.json     ← paired nodes registry
  - Shamir shares of age-decryption-key (one per shareholder)

  Runs:
    - seal-kms-cli (admin ops: trust-add, trust-list, pair-initiate)
    - Local KMS HTTP API (exposed on 127.0.0.1 or Tailscale)

Cloud worker (provisioned per-region):
  seal-kms-worker — ephemeral signing endpoint
  - Receives key shares from local KMS via hybrid KEM pairing
  - Keys live ONLY in LockedBuffer (mlock, no disk persistence)
  - On shutdown: zeroize everything → stateless

Bridge nodes (cloud VMs running seal-node):
  - Validator key + bridge key share
  - Connect to cloud worker for signing
```

**Key properties:**
- Cloud workers never persist private keys — compromised worker = zero key exposure
- Cloud workers can be scaled up/down / recreated without key management
- Local machine is the single source of truth

**Tradeoffs:**
- Local machine must be online to provision new workers or recover crashed workers
- No remote access path defined — if laptop is dead, worker provisioning is blocked
- Bridge nodes must reach cloud worker over network (Tailscale/WireGuard/SSH tunnel)

---

## 10. Shamir Reconstruction Protocol (age-decryption key)

When the KMS master keys need to be loaded onto a cloud worker (provisioning,
recovery, rotation), the age-decryption key must be reconstructed from
t-of-n Shamir shares held by independent shareholders. This protocol uses
**PQC-protected channels** (ML-KEM key encapsulation) and **VSS commitments**
for error detection.

### 10.1 Participants

| Role | Holds | Runs |
|------|------|------|
| **Shareholder** | One Shamir share of the age-decryption key | Offline-capable device (local PC, hardware token) |
| **Reconstruction server** | ML-KEM keypair, VSS commitments, encrypted KMS blobs | Always-on cloud backup machine |
| **Cloud worker** | Ephemeral key material in LockedBuffer | Ephemeral cloud VM |

### 10.2 Setup (One-Time)

```
1. Dealer splits age-decryption-key S into n shares: {s_1, s_2, ..., s_n}
2. Dealer computes VSS commitments: H_i = SHA3(s_i) for each share
3. Dealer publishes commitment list: { (1, H_1), (2, H_2), ..., (n, H_n) }
4. Dealer distributes share s_i to shareholder i (out-of-band, encrypted)
5. Reconstruction server generates ML-KEM keypair: (ml_dsk, ml_pk)
6. Shareholders are registered with their identities and ml_pk
```

### 10.3 Reconstruction Protocol

```
Phase 1 — Request:
  Shareholder initiates reconstruction request to reconstruction server
  Server responds with: { ml_pk, commitment_list, session_id }

Phase 2 — Encrypt & send share:
  For each of t shareholders (concurrent):
    1. Shareholder computes commit = SHA3(share_i)
    2. Shareholder verifies commit == commitment_list[i] → abort if mismatch
    3. Shareholder encrypts share_i under ml_pk:
       (ss_i, ct_i) = ML-KEM-768-encapsulate(ml_pk)
       encrypted_share = share_i XOR SHA3(ss_i)  // KEM-then-XOR
    4. Shareholder sends { session_id, i, encrypted_share, ct_i }

Phase 3 — Decrypt & verify:
  Reconstruction server receives t encrypted shares:
    For each share j:
      1. ss_j = ML-KEM-768-decapsulate(ml_dsk, ct_j)
      2. share_j = encrypted_share_j XOR SHA3(ss_j)
      3. commit_j = SHA3(share_j)
      4. Verify commit_j against commitment_list[j] → abort if mismatch
      5. Collect valid shares into valid_shares[]

Phase 4 — Reconstruct:
  If len(valid_shares) >= t:
    age_decryption_key = Shamir-reconstruct(valid_shares, q=large prime)
    Use age_decryption_key to decrypt KMS blobs
    Provision cloud worker with decrypted blobs
    Zeroize age_decryption_key from memory after provisioning
  Else:
    Abort — insufficient valid shareholders
```

### 10.4 Security Properties

| Property | How |
|------|------|
| **Share confidentiality in transit** | ML-KEM-768 encapsulation — quantum-resistant encryption. Eavesdropper sees only ciphertexts. |
| **Share integrity** | VSS SHA3 commitments — server detects bad shares before reconstruction. |
| **Server cannot forge shares** | Server only has ml_dsk (for decryption), not the Shamir shares. Cannot reconstruct without t shareholders. |
| **Shareholder cannot fake identity** | Server verifies VSS commitment for each received share. A fake share fails SHA3 check. |
| **Key is ephemeral** | Reconstructed key is zeroized after use. Never persisted on reconstruction server. |
| **No single point of control** | Server is untrusted orchestration infrastructure. Needs t cooperating shareholders. |

### 10.5 PQC Classification

The Shamir secret sharing itself is **information-theoretically secure** — it
does not rely on any computational assumption, quantum or classical. The PQC
protection applies to the **transmission channel**: ML-KEM-768 key encapsulation
ensures that intercepted Shamir shares during transport are recoverable only by
the reconstruction server (which itself cannot use them without t shareholders).

The full protection chain:
- **Shamir**: Information-theoretic — no amount of computation breaks it
- **ML-KEM-768**: Lattice-based PQC — resistant to classical and quantum attackers
- **SHA3**: Hash-based commitment — collision-resistant, post-quantum safe

This means a quantum computer cannot intercept and reconstruct a shareholder's
transmitted share, and even a quantum attacker cannot break the Shamir property
that individual shares reveal nothing about the secret.

### 10.6 Failure Modes

| Failure | Detection | Recovery |
|------|------|------|
| Bad shareholder share | VSS SHA3 mismatch | Reject share, retry with another shareholder |
| Transmission corruption | VSS SHA3 mismatch | Retry transmission |
| Server compromise | Server has ml_dsk but not shares | No key exposure — server cannot reconstruct alone |
| All shareholders offline | t shares not collected | Abort, try later |
| t-1 or fewer shareholders online | Not enough valid shares | Abort, need t |
| Malicious reconstruction server | Server publishes fake commitment list | Shareholders verify commitment list was received from trusted source during setup |

---

## 11. Deployment Profiles

### 11.1 Single-Operator Testnet (Current)

All keys on one machine. File-based storage. No KMS sidecar.

```
Operator workstation:
  - K9 (Solana deployer)
  - K10 (Stellar deployer)
  - K11 (Bridge program)

Cloud VM (single container):
  - K1 (committee MAC via CLI flag)
  - K2 (Ringtail via file)
  - K3 (validator key per node in Docker volume)
```

**Risk:** All keys on one machine. If VM is compromised, bridge is drained.

### 11.2 Decentralized KMS Workers (Recommended)

Local machine = permanent key store. Cloud VMs = ephemeral signing workers.

```
Local machine (your laptop / always-on desktop):
  /etc/seal-kms/
    ├── committee-key.enc            ← age-encrypted K1
    ├── ringtail-master-keys.enc     ← age-encrypted K2
    ├── master-kem-sig-keys.enc      ← age-encrypted K4/K5
    ├── trust-store.json.age         ← encrypted trust store
    └── age-decryption-key           ← unlocks all above
                                   (or shamir shares of this key)

  seal-kms-local (HTTP API):
    - Accepts admin commands: trust-add, pair-initiate, trust-revoke
    - Serves encrypted blobs to workers on-demand
    - Exposed on Tailscale interface (100.0.0.x) for worker reachability

Cloud worker (provisioned per-region):
  seal-kms-worker (Unix socket):
    - Receives key shares from local KMS on startup
    - All keys in LockedBuffer only (zero disk persistence)
    - Serves SignCommittee / SignRingtail to co-located seal-node
    - On shutdown: zeroize → stateless
    - Can be replaced/recreated at any time without key management

Bridge nodes (Docker/cloud):
  - K3 only (validator key)
  - KMS client connecting to cloud worker
  - Committee/Ringtail signing done remotely via cloud worker
```

**Key properties:**
- Cloud workers never persist keys — compromised worker = zero key exposure
- Bridge nodes reach cloud worker via Tailscale / WireGuard / SSH tunnel
- Your local machine is the only backup target (single source of truth)
- Age-decryption key can be split via Shamir sharing

**Risk:** Cloud workers must be online when withdrawals are processed.
Mitigated by: keep at least 2 workers in different regions; worker pool.

**CRITICAL GAP:** Local machine must be online to provision new workers or
recover crashed workers. If the local machine is dead (no battery, lost,
asleep), worker provisioning is blocked.

### 10.3 Production: Backup Machine + Shamir Threshold Recovery (Recommended)

Local machine = Shamir share storage (offline-capable). Cloud backup machine
= always-on reconstruction server + encrypted blob storage. Shamir reconstruction
of the age-decryption key uses PQC-protected channels.

```
Local machines (shareholders — offline-capable):
  Shareholder 1: Shamir share s_1 of age-decryption-key
  Shareholder 2: Shamir share s_2
  ...
  Shareholder n: Shamir share s_n
  (Each runs seal-kms-cli for admin ops when online)

Cloud backup machine (always-on, reconstruction server):
  /etc/seal-kms/
    ├── committee-key.enc            ← age-encrypted K1
    ├── ringtail-master-keys.enc     ← age-encrypted K2
    ├── master-kem-sig-keys.enc      ← age-encrypted K4/K5
    └── trust-store.json.age         ← encrypted trust store

  seal-kms-reconstruction (ML-KEM server):
    - ml_dsk / ml_pk (ML-KEM-768 keypair for PQC-protected share transmission)
    - VSS commitment list: { (i, SHA3(s_i)) }
    - Stores encrypted KMS blobs (never decrypts)
    - Orchestrates reconstruction when t shareholders connect
    - Never persists age-decryption-key

Cloud workers (ephemeral signing endpoints):
  seal-kms-worker (provisioned on-demand):
    - Receives decrypted KMS blobs from reconstruction server
    - Keys in LockedBuffer only (zero disk persistence)
    - Serves SignCommittee / SignRingtail to co-located seal-node
    - On shutdown: zeroize → stateless

Bridge nodes (cloud VMs running seal-node):
  - K3 (validator key) + Kb (bridge key share)
  - KMS client connecting to cloud worker
```

**Recovery flow (3 AM scenario):**
1. Cloud worker crashes, bridge withdrawals stalled
2. Operator contacts 3 of n shareholders (phone/email/any channel)
3. Each shareholder connects to reconstruction server, sends
   ML-KEM-encrypted Shamir share with VSS proof
4. Reconstruction server decrypts, verifies VSS, reconstructs
   age-decryption-key in memory
5. Server decrypts KMS blobs from disk, provisions fresh cloud worker
6. age-decryption-key zeroized from memory after provisioning
7. Bridge withdrawals resume
8. Local machine never needed — only shareholders' Shamir shares

**Key properties:**
- Local machine is NEVER needed for recovery — only during normal operations
  (admin commands like trust-add, pair-initiate)
- Cloud backup machine stores encrypted blobs but cannot decrypt without t shareholders
- Cloud workers remain ephemeral — zero disk persistence
- Shareholders can be contacted via any communication channel (phone, email, messenger)
- ML-KEM-768 protects share transmission from quantum eavesdroppers

**Risk assessment:**
| Scenario | Impact |
|------|------|
| Cloud worker compromised | Zero key exposure (ephemeral) |
| Cloud backup compromised | Encrypted blobs exposed, useless without t shareholders |
| Reconstruction server compromised | Can orchestrate but cannot decrypt without t shareholders |
| Local machine lost | No impact — Shamir shares are distributed, local machine is not authoritative |
| t-1 shareholders compromised | Zero key exposure (Shamir property) |
| t shareholders compromised | Full key exposure (this is by design — t-of-n threshold) |
| All shareholders offline | Bridge withdrawals stall, but workers don't crash |
| Reconstruction server + t shareholders | Full key exposure — require operational trust separation |

**Operational requirements:**
- t-of-n threshold: recommended 3-of-5 (3 shareholders needed, 5 total)
- Shareholders should be independent entities (different organizations/regions)
- Reconstruction server should be operated by a different entity than shareholders
- VSS commitment list must be distributed securely during setup (e.g., signed by
  Technical Council, published on-chain or in a immutable log)

### 11.3 Distributed Committee (Future)

Instead of a single master holding K1+K2, split K1 into Shamir shares across
N machines. Require t-of-N to sign. Uses the existing Ringtail threshold signing
mechanism but for the committee key itself:

```
N=5, t=3
  Machine A: share 1 of K1
  Machine B: share 1 of K1
  Machine C: share 1 of K1
  Machine D: share 1 of K1
  Machine E: share 1 of K1

  To sign a withdrawal: any 3 machines collaborate via Ringtail session
  to produce the HMAC-SHA-256 signature without any single machine
  holding the full key.
```

This eliminates the single point of failure but adds complexity to key
management and requires the Ringtail P2P orchestration to be production-ready.
