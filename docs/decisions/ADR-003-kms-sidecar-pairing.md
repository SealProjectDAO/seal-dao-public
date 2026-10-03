# ADR-003 — KMS sidecar, hybrid PQC machine pairing, and external validator governance

Date: 2026-05-27
Status: Drafted

## Context

The existing deployment model stores all key material (committee MAC key,
Ringtail keypair, validator key) as files on each seal-node instance.
This works for single-operator testnets but does not support:

1. **Cloud deployments** where operators want no persistent clear-text
   bridge keys on VMs.
2. **Multi-node bridge clusters** where a master machine holds the
   bridge signing keys and individual nodes only hold validator keys.
3. **External validators** that run their own Seal L1 nodes and/or
   bridge observers, with governance controlling their influence.

The repo already has the building blocks:
- `KemKeypair` / `SigningKey` in `seal-crypto` (ML-KEM-768 + ML-DSA-65)
- PQ-Noise 3-way handshake in `seal-p2p/src/pq_handshake.rs` (ephemeral
  KEM + identity auth + derived session key)
- `CommitteeKeySource` / `RingtailKeySource` traits in `seal-bridge/src/keysource.rs`
  (only `FileKeySource` implemented)
- `TechnicalCouncil` + `ServiceOperatorsCouncil` in `seal-node/src/governance.rs`
- `ValidatorSet` with stake-weighted VRF in `seal-consensus/src/validator.rs`
- `BridgeManager::initiate_withdrawal` in `seal-bridge/src/bridge.rs`
  (burns wrapped tokens, attaches committee signature)

What's missing is the KMS sidecar process, the hybrid KEM extension,
and the governance wiring for external participants.

## Decision

### Topology

```
                    ┌─────────────── MASTER MACHINE ───────────────┐
                    │                                               │
                    │  ┌─ Seal KMS Sidecar (Unix socket only) ──┐   │
                    │  │  LockedBuffer(committee_key)            │   │
                    │  │  LockedBuffer(ringtail_keypair)         │   │
                    │  │  LockedBuffer(master_kem_sk)            │   │
                    │  │  LockedBuffer(master_sig_sk)            │   │
                    │  │                                         │   │
                    │  │  KMS API (JSON over /tmp/seal-kms.sock):│   │
                    │  │    PairNode(node_hybrid_pk) → enc_key   │   │
                    │  │    SignCommittee(payload) → hmac_hex    │   │
                    │  │    SignRingtail(payload) → sig_hex      │   │
                    │  │    TrustStore operations                │   │
                    │  └─────────────────────────────────────────┘   │
                    │           │                                     │
                    │           │ PQ-Noise handshake (TCP/TLS)        │
                    │           ▼                                     │
                    │  ┌─ seal-node (validator/bridge node) ────┐     │
                    │  │  --bridge-kms-config /tmp/kms-addr.json│     │
                    │  └─────────────────────────────────────────┘     │
                    └─────────────────────────────────────────────────┘
                                 ▲
                                 │ encrypted transfer (hybrid session key)
                                 │ node receives: validator_key only
                                 │ committee + ringtail stay on master
                                 │
              ┌───────┬───────┬───────┐
              │ Node1 │ Node2 │ Node3 │  (Docker / cloud / bare metal)
              └───────┴───────┴───────┘
```

### Part 1 — Hybrid PQC machine identity

**File: `crates/seal-crypto/src/hybrid_kem.rs`** (new)

Add a hybrid KEM keypair combining ML-KEM-768 (post-quantum) with
X25519 (classical). Both primitives are used in key exchange; the final
shared secret is HKDF(SHA3) of both shared secrets, so compromise of
either primitive alone does not expose the session key.

```rust
struct HybridKemKeypair {
    mlkem: KemKeypair,    // 1184B pk / 2400B sk
    x25519: X25519Keypair, // 32B pk / 32B sk
}

struct HybridKemPublicKey {
    mlkem: KemPublicKey,
    x25519: [u8; 32],
}

impl HybridKemPublicKey {
    /// Returns (hybrid_shared_secret, mlkem_ct, x25519_ct).
    fn encapsulate(&self) -> (Vec<u8>, Vec<u8>, [u8; 32]);
}
```

Key derivation uses SHA3-256 with domain separation:
```
hybrid_ss = SHA3(MLKEM-SS || "hybrid-split-seal" || X25519-SS)
```

**File: `crates/seal-p2p/src/pq_handshake.rs`** — Extend with
`HybridInitiator` and `HybridResponder` variants. The existing
`Initiator` / `Responder` stay untouched. The hybrid variant uses
`HybridKemPublicKey` (1216B) instead of raw `KemPublicKey` (1184B)
in Msg1/Msg2, and `derive_session_key` operates on the hybrid shared
secrets.

**Machine ID:** `SHA3-256(hex_encode(ML-DSA-verifying-key))` — same
format as council member addresses already used in
`TechnicalCouncil::find_by_address_hash`.

### Part 2 — Seal KMS sidecar

**Crate: `crates/seal-kms-sidecar/`** (new)

A separate process from `seal-node`. Listens on a Unix domain socket
(localhost-only, no network exposure).

**File: `crates/seal-kms-sidecar/src/main.rs`** — Unix socket server
serving JSON-over-lines protocol. Commands:

```rust
/// Pair a new node. Returns encrypted validator key transfer.
struct KmsPairRequest {
    node_id: String,              // SHA3(node_ml_dsa_vk) hex
    node_hybrid_pk: String,       // hex-encoded HybridKemPublicKey
    node_ml_dsa_sig: String,      // node signs (node_id || hybrid_pk || challenge)
    challenge: String,            // random nonce from node
}
struct KmsPairResponse {
    encrypted_validator_key: String,  // ML-KEM-encrypted validator key
    master_challenge: String,          // challenge back to node
}

/// Sign a bridge withdrawal with the committee MAC key.
struct KmsSignCommitteeRequest { payload_hex: String, nonce: u64 }
struct KmsSignCommitteeResponse { signature_hex: String }

/// Sign a bridge withdrawal with the Ringtail keypair.
struct KmsSignRingtailRequest { payload_hex: String }
struct KmsSignRingtailResponse { signature_hex: String }

/// Check node trust status.
struct KmsTrustRequest { node_id: String }
struct KmsTrustResponse { trusted: bool }
```

**File: `crates/seal-kms-sidecar/src/secure.rs`** — `rust-secure-memory`
integration. Wraps key material in `LockedBuffer`:
- `mlock()` pins memory (no swap)
- Guard pages + canary sentinels
- `zeroize` on drop

**File: `crates/seal-kms-sidecar/src/trust_store.rs`** — On-disk trust
store for paired nodes (JSON, encrypted at rest). Tracks `paired_at`,
`last_seen`, `revoked` status.

### Part 3 — BridgeManager KMS delegation

**File: `crates/seal-bridge/src/bridge.rs`** — Add two new traits and
delegate signing through them when present:

```rust
pub trait CommitteeSigner: Send + Sync {
    fn sign_committee(&self, payload: &[u8]) -> Result<String, String>;
}
pub trait RingtailSigner: Send + Sync {
    fn sign_ringtail(&self, payload: &[u8]) -> Result<String, String>;
}

pub struct BridgeManager {
    // ... existing fields ...
    committee_signer: Option<Arc<dyn CommitteeSigner>>,
    ringtail_signer: Option<Arc<dyn RingtailSigner>>,
}
```

`compute_committee_signature` checks `committee_signer` first, then
`committee_key`, then `committee_ringtail_keypair`. If `committee_signer`
is set, it never reads the actual committee key — the KMS sidecar
signs on-demand.

**File: `crates/seal-bridge/src/kms_client.rs`** (new) — `KmsKeySource`
implements `CommitteeSigner` + `RingtailSigner` over a Unix socket.

### Part 4 — When the KMS is actually called

| Operation | KMS needed? | Why |
|------|------|------|
| Bridge auto-poll (lock events) | No | Observers are read-only |
| Mint wrapped tokens on Seal | No | Triggered by observed locks |
| **Bridge withdrawal (burn→unlock)** | **Yes** | Needs committee/Ringtail sig |
| **Starting a new node** | **Yes** | Needs validator key transfer |
| Committee key rotation | Yes | Signs the rotation transaction |
| Ringtail session orchestration | Yes | Each round needs signing |

### Part 5 — Node pairing flow

```
Node (fresh VM/Docker)            Master (KMS Sidecar)
────────────────────────────       ─────────────────────
1. Generate:
   - node_hybrid_kem_keypair
   - node_sig_keypair (ML-DSA-65)
   - node_id = SHA3(node_vk_hex)
   - challenge = random 32B

2. PAIR_REQUEST {
       node_id,
       node_hybrid_pk,
       node_sig,      // signs (node_id || pk || challenge)
       challenge,
   }
   ─────────────────────────────────────────────────────► 3. Verify node_sig
                                                            against trust store

4. If trusted:
   a. Load validator_key from LockedBuffer
   b. Encrypt under node_hybrid_pk (hybrid KEM)
   c. Sign (master_id || challenge)

   ◄───────────────────────────────────────────────────── PAIR_RESPONSE {
       enc_validator_key,
       master_sig,
   }

5. Verify master_sig
6. Decrypt enc_validator_key → validator_key
7. Store at $DATA_DIR/validator-key.json

8. CHALLENGE_RESPONSE { SHA3(challenge) }
   ─────────────────────────────────────────────────────► 9. Verify
                                                            → node trusted
```

**What the node receives vs. keeps:**

| Key | Transferred to node? | Stored where? |
|------|------|------|
| Validator key (ML-DSA for consensus) | **Yes** | `$DATA_DIR/validator-key.json` |
| Committee MAC key (HMAC-SHA-256) | **No** | Master LockedBuffer only |
| Ringtail keypair (threshold sig) | **No** | Master LockedBuffer only |

### Part 6 — External validator governance

Two categories of external participants:

| Type | Runs | Controlled by |
|------|------|------|
| L1 Validator | Seal L1 node, consensus participation | `ValidatorSet` — stake-based VRF |
| Bridge Observer | Polls Solana/Stellar for lock events | `seal_addBridgeObserver` — anyone |
| Bridge Withdrawal Signer | Signs burn→unlock txs | `TechnicalCouncil` membership |

**L1 validator weight = SEAL staking** (existing `ValidatorSet` +
`vrf_threshold()`). External validators join by staking SEAL tokens.
Council does not directly control the validator set.

**Bridge signing = TechnicalCouncil** (7-11 members, hex ML-DSA pubkeys,
2/3 supermajority). Council members can sign via the KMS sidecar.

**Infrastructure operators = ServiceOperatorsCouncil** (advisory voice
on infrastructure params, binding SLA veto).

Decision: use SEAL tokens for everything. No separate governance token.
`seal-token/src/staking.rs` handles staking; `GovernanceModule` handles
conviction voting.

## Consequences

- **Security:** Committee/Ringtail keys never leave the master's locked
  memory. Compromised bridge nodes can't forge committee signatures.
- **Ops:** Adds one extra process (KMS sidecar) per deployment. Unix
  socket means no network attack surface for the KMS.
- **Infra:** Three deployment models available:

  **Option A — Decentralized KMS Workers:**
  Local machine holds permanent age-encrypted key store + Shamir shares.
  Cloud VMs are ephemeral signing workers. Simple but local machine needed
  for worker provisioning/recovery.

  **Option B — Centralized Persistent Master:**
  All keys on one always-on cloud VM. Simpler networking, full key exposure.

  **Option C — Production: Backup Machine + Shamir Threshold (Recommended):**
  Local machine = Shamir share storage (offline). Cloud backup = always-on
  reconstruction server. Age-decryption key split via Shamir among n parties,
  t-of-n to reconstruct. PQC-protected via ML-KEM-768 encapsulation on the
  transmission channel. VSS SHA3 commitments for share integrity. Local
  machine is offline-capable — shareholder shares, not the authoritative
  key store. 3 AM recovery requires contacting t shareholders via any
  channel (phone/messenger), not the local machine.

  Local PCs are development workstations: they run `seal-node` and
  `seal-kms-cli` for admin ops, never the long-running KMS process.
- **Code:** New crate `seal-kms-sidecar`, new file `hybrid_kem.rs`,
  new file `kms_client.rs`. `bridge.rs` gains two trait fields. Minimal
  changes to existing code paths.
- **CI:** `cargo build` still passes (new deps: `rust-secure-memory`,
  `x25519` / `smallfield` for X25519).
- **Testing:** Pairing roundtrip, KMS signing path, node revocation
  need integration tests.

## Out of scope

- `rust-secure-memory` crate itself — it's an external dependency.
- HSM integration beyond `LockedBuffer` (future: PKCS#11 / AWS KMS).
- On-chain bridge program changes (committee signing is host-side only).
- Mainnet deployment procedures (operator-side concern).

## Implementation order

1. `hybrid_kem.rs` — hybrid ML-KEM + X25519 primitive
2. `pq_handshake.rs` hybrid variant — `HybridInitiator` / `HybridResponder`
3. `seal-kms-sidecar` crate — basic Unix socket server
4. `rust-secure-memory` integration — `LockedBuffer` wrappers
5. `kms_client.rs` — `KmsKeySource` traits
6. `bridge.rs` delegation — `BridgeManager` routes through signer traits
7. `main.rs` wiring — `--bridge-kms-config` flag
8. Deploy script update — KMS init/trust-add/pair subcommands
9. Tests

## Files to create/modify

| File | Action | Purpose |
|--|--|--|
| `docs/decisions/ADR-003-kms-sidecar-pairing.md` | **Create** | This document |
| `crates/seal-crypto/src/hybrid_kem.rs` | **Create** | Hybrid ML-KEM + X25519 |
| `crates/seal-bridge/src/kms_client.rs` | **Create** | Unix socket KMS client |
| `crates/seal-kms-sidecar/Cargo.toml` | **Create** | New crate manifest |
| `crates/seal-kms-sidecar/src/main.rs` | **Create** | KMS sidecar binary |
| `crates/seal-kms-sidecar/src/trust_store.rs` | **Create** | Paired node trust store |
| `crates/seal-kms-sidecar/src/secure.rs` | **Create** | Secure memory wrappers |
| `crates/seal-p2p/src/pq_handshake.rs` | **Modify** | Hybrid variant |
| `crates/seal-bridge/src/bridge.rs` | **Modify** | Signer trait delegation |
| `crates/seal-node/src/main.rs` | **Modify** | KMS config wiring |
| `scripts/bridge-testnet-deploy.sh` | **Modify** | KMS subcommands |
