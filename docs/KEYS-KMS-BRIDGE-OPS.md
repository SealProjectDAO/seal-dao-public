# Seal DAO — Bridge Node Key Transfer Operations

> **Scope:** Transferable key sets dedicated to bridge operations — how bridge nodes
> receive their own signing keys (analogous to validator key transfer) and how those
> keys map to on-chain bridge program verification.
>
> **Date:** 2026-05-27
>
> **Related:** [KEYS-KMS-DESIGN.md](KEYS-KMS-DESIGN.md),
> [ADR-003](decisions/ADR-003-kms-sidecar-pairing.md),
> [ADR-002](decisions/ADR-002-bridge-ringtail-integration.md)

---

## 1. The Problem

The committee key (HMAC-SHA-256) is a **single shared secret** — the on-chain bridge
programs verify against that one 32-byte value. This means:

- **HMAC path:** No delegation possible. Only the entity holding the 32-byte secret
  can produce valid committee signatures.
- **Ringtail path:** Each committee member has their own **independent ML-DSA identity**
  plus a **shamir share** of the Ringtail secret. The on-chain program verifies against
  the **public key** (which is derived from the public params, not from the secret),
  and any t-of-n subset of partial signatures can be aggregated into a valid threshold
  signature.

**Conclusion:** Ringtail multi-validator mode is the mechanism that enables bridge key
transfer. It's the only path where individual bridge nodes get their own signing key
that the on-chain bridge program recognizes.

---

## 2. Bridge Operator Key Set (Ringtail Multi-Validator)

### 2.1 What Gets Transferred

During KMS pairing, a bridge node receives two things:

| Item | What it is | Size | Stored where |
|------|------|-----|------|
| **Validator key** (K3) | ML-DSA-65 keypair for Seal L1 consensus | 4032 B | `$DATA_DIR/validator-key.json` |
| **Bridge key share** (Kb) | Ringtail Shamir share + ML-DSA identity key for bridge signing | ~2 KB + 4032 B | `$DATA_DIR/bridge-keyshare.json` |

The **validator key** is already covered in ADR-003. The **bridge key share** is new.

### 2.2 Bridge Key Share Structure

```json
{
  "version": 1,
  "bridge_key_share": {
    "signer_index": 2,
    "ml_dsa_vk_hex": "a1b2c3d4...",
    "shamir_share_hex": "e5f6...",
    "smudging": false,
    "public_params_hash": "sha3-of-params"
  },
  "metadata": {
    "created_unix": 1748300000,
    "paired_by": "kms-sidecar/0.1.0",
    "committee_threshold": 3,
    "committee_size": 5
  }
}
```

The bridge key share contains:
- **`signer_index`**: Position in the Ringtail committee (0-based)
- **`ml_dsa_vk_hex`**: This node's ML-DSA verifying key (used for P2P bridge identity)
- **`shamir_share_hex`**: This node's Shamir share of the Ringtail secret polynomial
- **`public_params_hash`**: Hash of the Ringtail public params (for verification)
- **`committee_threshold`**: Minimum signers required (t)
- **`committee_size`**: Total committee members (n)

### 2.3 How It Maps to On-Chain Verification

The on-chain bridge program stores the **Ringtail public params** (matrix A, public key T).
These are identical for all committee members and are installed during bridge program
initialization.

The on-chain verifier:
1. Receives a withdrawal with `nonce`, `dest_address`, `amount`, and a Ringtail signature
2. Decomposes the signature into z, challenge, participant_bitfield
3. Recomputes `D' = A*z - c*t` for each row
4. Recomputes `c' = SHA3(D' || message)` and checks `c' == challenge`
5. Checks `participant_count >= threshold`

**Critically:** the on-chain program never sees individual key shares. It only sees the
**aggregate signature** produced by the Ringtail session orchestration. The key shares
stay on the individual bridge nodes and participate in the P2P signing protocol.

### 2.4 The Signing Flow (Multi-Validator Ringtail)

```
Bridge operator (BridgeManager) initiates withdrawal:
  initiate_withdrawal(seal_addr, dest_chain, dest_addr, token, amount)
    → creates withdrawal record with committee_signature_hex = None
    → fires SigningSignal (WithdrawalReadyForSigning)

RingtailBridgeOrchestrator receives signal:
  orchestrator.start_signing(withdrawal_id, dest_chain, dest_addr, amount, nonce)
    → creates RingtailBridgeSession(signers = [node0, node1, node2, node3, node4])
    → threshold = 3, so any 3 of 5 signers are sufficient

Round 1 (P2P):
  Each of the 5 bridge nodes:
    party.round1_full(params, mac_key, block_hash)
      → produces Round1MessageFull { commitment, mac }
    → broadcasts via NetworkMessage::BridgeRingtailRound1

  Orchestrator collects round1 messages from all 5 nodes:
    orch.on_round1_envelope(env) → aggregate_commitments()
      → computes aggregated_d (combined D polynomial)
      → broadcasts Round2

Round 2 (P2P):
  Each of the 5 bridge nodes:
    party.round2_full(aggregated_d, message)
      → produces Round2Message { response }
    → broadcasts via NetworkMessage::BridgeRingtailRound2

  Orchestrator collects round2 messages:
    aggregate_responses_full(round2_messages, threshold=3)
      → aggregates z = sum(z_i) for the 3+ participants
      → produces RingtailSignature { z, challenge, participants }

Finalization:
  bridge.attach_committee_signature(withdrawal_id, sig_hex)
    → withdrawal record now has valid Ringtail signature
    → relayer broadcasts unlock to source chain
```

**Key property:** Only 3 of 5 nodes need to be online and cooperating. If 2 nodes are
down, the remaining 3 can still produce a valid signature. If all 5 nodes are online,
they all participate and the aggregate is stronger.

---

## 3. Key Transfer Protocol for Bridge Key Shares

The bridge key share is generated by the master KMS and transferred to bridge nodes
during pairing — **using the same pairing flow as the validator key**.

### 3.1 Pre-Registration

Admin pre-registers a bridge node with the KMS, specifying its role:

```bash
seal-kms-cli bridge-add \
  --node-id <hex> \
  --ml-dsa-vk <hex> \
  --bridge-operator true \
  --description "us-east-1-bridge-1"
```

The `--bridge-operator true` flag tells the KMS to generate a bridge key share during
pairing.

### 3.2 Pairing Flow (Validator + Bridge Key Share)

```
Bridge node                              Master KMS
──────                                 ────────
1. Generate:
   - node_hybrid_kem_keypair (K6)
   - node_sig_keypair (K7: ML-DSA-65)
   - node_id = SHA3(K7_vk)
   - challenge = 32 random bytes

2. PAIR_REQUEST {
       node_id,
       node_hybrid_pk,
       node_sig,
       challenge,
       is_bridge_operator: true   ← new field
   }
   ─────────────────────────────► 3. Verify + look up role

4. If is_bridge_operator == true:
   a. Generate validator key (K3) ← same as before
   b. Generate bridge key share (Kb):
      i.  Load (public_params, sk_collapsed) from LockedBuffer
      ii. Compute Shamir share: share_i = sk_collapsed(i) mod q
           where i = next available signer_index
      iii. Generate node's ML-DSA identity keypair for bridge P2P
           (or reuse K7 if one identity serves both roles)
   c. Encrypt BOTH under node_hybrid_pk:
      enc_validator = K6.encapsulate(validator_key_bytes)
      enc_keyshare  = K6.encapsulate(keyshare_bytes)
   d. Sign {enc_validator, enc_keyshare, master_challenge}
   e. Return {enc_validator, enc_keyshare, master_sig, master_challenge}
   ◄─────────────────────────────────

5. Node verifies master_sig
6. Decrypts both:
   validator_key = K6.decapsulate(enc_validator)
   bridge_keyshare = K6.decapsulate(enc_keyshare)
7. Stores:
   $DATA_DIR/validator-key.json     (validator key)
   $DATA_DIR/bridge-keyshare.json   (bridge key share)
8. CHALLENGE_RESPONSE → prove receipt
```

### 3.3 Key Generation on Master

The master KMS generates bridge key shares using the same `generate_public_params_no_error`
that's already in `seal-threshold/src/ringtail.rs`:

```rust
impl KmsSidecar {
    fn generate_bridge_keyshare(
        &self,
        signer_index: usize,
    ) -> Result<BridgeKeyShare, String> {
        // Load master Ringtail key material from LockedBuffer
        let (public_params, sk_collapsed_bytes) =
            self.load_ringtail_keypair_from_secure()?;

        // Generate Shamir share at position signer_index
        // This is already implemented in seal-threshold:
        // let share = shamir_split(&sk_collapsed_bytes, threshold, n)[signer_index]
        let ring = HandRolledOps::new();
        let sk_poly = ring.from_bytes(&sk_collapsed_bytes)
            .map_err(|e| format!("invalid sk bytes: {e}"))?;
        let share = ring.eval(&sk_poly, signer_index as u64);
        let share_bytes = ring.to_bytes(&share);

        // Each bridge node gets its own ML-DSA identity for P2P signing
        // (This is separate from the validator key — it's used
        //  to sign P2P bridge ringtail messages)
        let (bridge_ml_dsa_sk, bridge_ml_dsa_vk) = SigningKey::generate();

        Ok(BridgeKeyShare {
            signer_index,
            ml_dsa_sk: bridge_ml_dsa_sk.to_bytes(),
            ml_dsa_vk: bridge_ml_dsa_vk.to_bytes(),
            shamir_share: share_bytes,
            public_params_hash: sha3_256(&serde_json::to_string(&public_params).unwrap()).0,
        })
    }
}
```

**Important:** The Shamir share is computed from the master Ringtail secret. The
`public_params` are the same for all members and were already deployed on-chain
during bridge program initialization.

---

## 4. Node Configuration

### 4.1 seal-node with Bridge Key Share

```toml
# /etc/seal-node/config.toml

[bridge]
# KMS client config
kms_socket = "unix:///tmp/seal-kms.sock"

# Bridge key share (received via pairing)
bridge_keyshare_file = "/data/bridge-keyshare.json"

# Ringtail orchestrator config
ringtail_orchestrator = {
    party_id = 2,                     # signer_index from key share
    threshold = 3,                    # t-of-n threshold
    committee_size = 5,               # n committee members
    prune_secs = 300,
    max_idle_secs = 600,
    mac_key_hex = "...",              # per-party MAC key for round1 binding
}

# Observer config (no keys needed)
observers = [
    { chain = "solana", rpc_url = "https://api.devnet.solana.com", program_id = "Bridge111..." },
    { chain = "stellar", horizon_url = "https://horizon-testnet.stellar.org", soroban_rpc_url = "https://soroban-testnet.stellar.org", contract_id = "CAaaaa..." },
]
```

### 4.2 seal-node with Only Validator Key (No Bridge Signing)

A node can receive only the validator key (no bridge key share) — it acts as a
pure consensus node and observer, not a bridge signer:

```toml
[bridge]
# No bridge_keyshare_file → node is observer-only
# No ringtail_orchestrator → node does not participate in P2P signing
kms_socket = "unix:///tmp/seal-kms.sock"
```

This is the "observer + validator" role — the node validates blocks and polls for
bridge events, but cannot sign bridge withdrawals.

---

## 5. Key Transfer Summary

| Role | Validator Key | Bridge Key Share | Payer Wallet | Source of Authority |
|------|------|------|------|----|---|---|
| **Validator only** | Yes (K3) | No | No | Consensus participation |
| **Observer only** | No | No | No | Read-only bridge monitoring |
| **Bridge operator** | Yes (K3) | Yes (Kb) | No | Ringtail threshold signing on bridge |
| **Relayer** | No | No | Yes (Kp) | Source-chain gas payment |
| **Full proxy** | Yes (K3) | Yes (Kb) | Yes (Kp) | All of the above |

---

## 6. Operational Commands

### 6.1 Deploy a Bridge Operator Node

```bash
# 1. On master KMS: pre-register
seal-kms-cli bridge-add \
  --node-id <hex> \
  --ml-dsa-vk <hex> \
  --description "us-east-1-bridge-1"

# 2. On bridge node: pair (receives validator key + bridge key share)
seal-kms-cli pair \
  --socket /tmp/seal-kms.sock \
  --output-dir /data

# 3. Verify received files
ls -la /data/
# validator-key.json     ← Seal consensus key
# bridge-keyshare.json   ← Ringtail bridge signing key share

# 4. Start seal-node with ringtail orchestrator
seal-node \
  --validator-key /data/validator-key.json \
  --bridge-ringtail-config /etc/seal-node/ringtail.toml \
  --bridge-keyshare /data/bridge-keyshare.json \
  --data-dir /data
```

### 6.2 Add a New Bridge Committee Member

When the committee needs to grow (e.g., from 3 to 5 members):

```bash
# 1. Generate new Ringtail public params + key material on master
#    (This requires deploying new bridge programs on-chain)
seal-kms-cli bridge-init-new-committee \
  --threshold 3 \
  --committee-size 5 \
  --output /tmp/new-ringtail-keys.enc

# 2. Deploy new bridge programs on Solana + Stellar
#    (anchor deploy --provider.cluster devnet)

# 3. For each new member:
#    seal-kms-cli bridge-add --node-id ... --ml-dsa-vk ...
#    seal-kms-cli pair --socket ... --output-dir /data
```

**Note:** Adding members requires on-chain bridge program redeployment (new public params).
Removing members does NOT require on-chain changes — the removed node's key share is
simply revoked in the KMS trust store and excluded from future signing sessions.

### 6.3 Revoke a Bridge Operator

```bash
# Same as general node revocation (KEYS-KMS-DESIGN.md §7.5)
seal-kms-cli trust-revoke \
  --node-id <hex> \
  --reason "bridge operator compromised"

# Effect:
# - Node is excluded from future Ringtail signing sessions
# - The node's ML-DSA VK remains in the Ringtail public key set
#   (on-chain cannot be updated without redeploy)
# - BUT: the orchestrator checks the trust store before inviting
#   a node to a session, so a revoked node's messages are rejected
```

### 6.4 Emergency: Revoke Entire Committee

If all bridge signing keys are compromised:

```bash
# 1. Pause all bridge chains
seal_bridgePauseChain { chain: "Solana", reason: "committee key compromised" }
seal_bridgePauseChain { chain: "Stellar", reason: "committee key compromised" }

# 2. Generate new Ringtail key material on master
seal-kms-cli bridge-init-new-committee --threshold 3 --committee-size 5

# 3. Deploy new bridge programs (new public params)
anchor deploy --provider.cluster devnet
stellar contract deploy ...

# 4. Re-pair all bridge operators with new key shares

# 5. Unpause
seal_bridgeUnpauseChain { chain: "Solana" }
seal_bridgeUnpauseChain { chain: "Stellar" }

# 6. All pending withdrawals with old signatures become invalid
#    → notify users to re-initiate
```

---

## 7. Security Model for Transferred Bridge Keys

### 7.1 What the Bridge Key Share Reveals

| Property | Value |
|------|-|
| **Shamir share** | Only useful combined with other shares; a single share reveals nothing about the master secret |
| **ML-DSA VK** | Public — needed for P2P identity and on-chain verification |
| **ML-DSA SK** | Private — only used for signing P2P bridge ringtail messages; does NOT sign withdrawal payloads directly |

### 7.2 Why a Compromised Bridge Node Can't Drain the Bridge

A compromised bridge node with a key share can:
- Sign P2P ringtail round1/round2 messages
- Contribute to a threshold signature if it's one of the t active signers

It **cannot**:
- Produce a full withdrawal signature alone (needs t-of-n collaboration)
- Derive the master Ringtail secret from its Shamir share (Shamir's secret sharing is information-theoretically secure)
- Produce an HMAC committee signature (the HMAC key was never transferred)

The worst case for a single-node compromise: if that node is one of the t signers needed for a session, an attacker can **delay** signing (refuse to participate) but cannot **forge** a signature without control of t-1 other nodes.

### 7.3 What If t Nodes Are Compromised

If an attacker controls t or more bridge nodes, they can produce threshold signatures
on any withdrawal. Mitigations:

1. **Geographic distribution:** Place bridge operators in different regions/cloud providers
2. **Independent operators:** Each bridge operator is run by a different entity
3. **Monitoring:** KMS tracks `last_seen` per node; unusual patterns trigger alerts
4. **Rapid rotation:** If compromise is detected, rotate the entire committee (deploy new programs)
5. **Pause:** TechnicalCouncil can pause chains immediately to stop withdrawals during an incident

---

## 8. Alternative: HMAC Delegated Payer Wallet (Simpler)

If Ringtail multi-validator is overkill (e.g., single-operator testnet), the simpler
path is:

1. Transfer only a **payer wallet** to the bridge node (covered in §3 of this doc)
2. The bridge node uses the **local committee key file** (FileKeySource, not KMS)
3. All signing happens locally on the bridge node

This is the current setup. The key transfer is the same pairing protocol, just
transferring a Solana/Stellar keypair instead of a bridge key share:

```bash
seal-kms-cli bridge-add \
  --node-id <hex> \
  --ml-dsa-vk <hex> \
  --chain solana \
  --wallet-file /secure/solana-payer-key.json

seal-kms-cli pair --socket /tmp/seal-kms.sock --output-dir /data
# → receives: validator-key.json + relayer-wallet.json
# → runs seal-node with --bridge-committee-key (local file)
```

**Risk assessment:** The committee key is on the bridge node. If the node is compromised,
the bridge is drained. Acceptable for testnet, not for production.

---

## 9. File Structure

**All key material on disk is age-encrypted.** The KMS sidecar uses a single
age decryption key (the "master decryption key") to open all `.enc` and `.age`
files. This decryption key is stored separately from the encrypted blobs —
e.g., in a hardware security key (YubiKey), a secrets manager (Vault/AWS Secrets),
or protected by a PIN on the operator's workstation.

```
On master machine (/etc/seal-kms/):
├── ringtail-master-keys.enc    ← age-encrypted Ringtail public params + secret
├── bridge-keyshares/           ← per-member bridge key shares
│   ├── share-2.age             ← encrypted for signer_index=2's KMS identity
│   └── share-3.age             ← encrypted for signer_index=3's KMS identity
├── relay-keys/                 ← payer wallets for relayers
│   ├── relayer-sol-1.age
│   └── relayer-xlm-1.age
├── trust-store.json.age        ← encrypted trust store
└── kms-config.toml             ← unencrypted config (socket path, thresholds)
                                ← NO keys in this file

On bridge operator node (/data/):
├── validator-key.json          ← Seal L1 validator key (from pairing)
├── bridge-keyshare.json        ← Ringtail bridge key share (from pairing)
└── kms.json                    ← KMS client config (socket path only, no keys)
```

**Backup requirement:** The age-encrypted files + the age decryption key
must be backed up to offline/storage (e.g., S3 with server-side encryption,
or physical media in a safe). If the KMS master machine is lost:
- Encrypted files on disk → recover from backup
- Age decryption key → recover from secrets manager / hardware key
- Restore → KMS starts → all keys loaded from encrypted blobs → operational

---

## 10. Deployment Models

### 10.A Decentralized Workers + Local Authority

Your local machine is the **permanent key authority**. Cloud machines are **ephemeral
signing workers** that receive key shares at runtime and zeroize on shutdown.

```
Local machine (your laptop / always-on desktop):
  /etc/seal-kms/
    ├── committee-key.enc            ← age-encrypted K1
    ├── ringtail-master-keys.enc     ← age-encrypted K2
    ├── master-kem-sig-keys.enc      ← age-encrypted K4/K5
    ├── trust-store.json.age         ← encrypted trust store
    └── age-decryption-key           ← unlocks all above
       (or shamir shares of this key)

  seal-kms-local (HTTP API over Tailscale/Zerotier):
    - Admin ops: trust-add, pair-initiate, trust-revoke
    - Serves encrypted key blobs to workers on-demand

Cloud worker (provisioned per-region):
  seal-kms-worker (Unix socket, co-located with seal-node):
    - Receives key shares from local KMS on startup via hybrid KEM pairing
    - All keys in LockedBuffer only (zero disk persistence)
    - On shutdown: zeroize everything → stateless

Bridge nodes (Docker/cloud):
  - K3 (validator key) + Kb (bridge key share)
  - KMS client connecting to cloud worker
```

**Networking:** Bridge nodes reach cloud worker via Tailscale / WireGuard / SSH tunnel.
**Limitation:** Local machine must be online to provision new workers or recover
crashed workers.

### 10.B Centralized Persistent Master (Simpler)

All keys on one always-on machine that also serves signing requests.

```
Cloud VM (always-on):
  seal-kms-sidecar — key store + signing endpoint
  - age-encrypted keys on disk
  - LockedBuffer at runtime
  - Unix socket for local seal-node
```

**Risk:** Single machine holds all keys. Compromise = bridge drained.

### 10.C Production: Backup Machine + Shamir Threshold Recovery (Recommended)

Local machine = Shamir share storage (offline). Cloud backup = always-on
reconstruction server + encrypted blob storage.

```
Shareholders (offline-capable devices):
  Shareholder 1: Shamir share s_1 of age-decryption-key
  ...
  Shareholder n: Shamir share s_n  (t-of-n threshold, e.g. 3-of-5)

Cloud backup machine (always-on, reconstruction server):
  /etc/seal-kms/
    ├── committee-key.enc
    ├── ringtail-master-keys.enc
    ├── master-kem-sig-keys.enc
    └── trust-store.json.age

  seal-kms-reconstruction (ML-KEM server):
    - ML-KEM keypair for PQC-protected share transmission
    - VSS commitment list
    - Stores encrypted KMS blobs (never decrypts)

Cloud workers (ephemeral):
  seal-kms-worker — receives decrypted blobs from reconstruction server
  - Keys in LockedBuffer only → zeroize on shutdown

Bridge nodes (cloud VMs running seal-node):
  - K3 (validator key) + Kb (bridge key share)
  - KMS client connecting to cloud worker
```

**3 AM recovery flow:**
1. Cloud worker crashes, withdrawals stalled
2. Operator contacts t of n shareholders (phone/messenger/email)
3. Each shareholder sends ML-KEM-encrypted Shamir share + VSS proof
4. Reconstruction server decrypts, verifies, reconstructs age-decryption-key
5. Server decrypts KMS blobs, provisions fresh cloud worker
6. age-decryption-key zeroized after provisioning
7. **Local machine never needed** — only shareholder shares required

**When local machine IS used:**
| Activity | Runs on | Requires online? |
|--|--|--|
| `seal-kms-cli trust-add` | Local machine | Only during worker provisioning |
| `seal-kms-cli pair` | Local machine | Only during worker provisioning |
| Admin ops (trust-list, revoke) | Local machine | Never for withdrawals |
| Bridge withdrawals | Cloud worker | Local machine NOT needed |

**Local machine is offline-capable.** It holds Shamir shares, not the authoritative
key store. The cloud backup machine + shareholders handle everything.
