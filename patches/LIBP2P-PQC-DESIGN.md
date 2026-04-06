# libp2p PQC Patch — Technical Design

## Overview

Replace all classical crypto in libp2p with post-quantum equivalents:

```
BEFORE (classical):                    AFTER (PQC):
─────────────────                     ────────────
Peer ID: Ed25519 pk → SHA2            Peer ID: ML-DSA-65 pk → SHA3
Key exchange: X25519 DH               Key exchange: ML-KEM-768 encapsulate
Handshake auth: Ed25519 sign           Handshake auth: ML-DSA-65 sign
Symmetric: ChaChaPoly                 Symmetric: ChaChaPoly (unchanged, PQ-safe)
```

## 1. libp2p-noise: Replace Noise XX with PQ-Noise

### Current Noise XX handshake (classical)

```
Initiator                              Responder
─────────                              ─────────
e = X25519.keygen()
→ e.public
                                       e = X25519.keygen()
                                       ee = X25519.dh(e, e_remote)
                                       s = identity_keypair (Ed25519)
                                       es = X25519.dh(e, s_remote)
                                       ← e.public, ENCRYPT(s.public, sig)
s_remote = DECRYPT(...)
se = X25519.dh(s, e_remote)
→ ENCRYPT(s.public, sig)
                                       s_remote = DECRYPT(...)
                                       [session established]
```

### PQ-Noise XX handshake (ML-KEM + ML-DSA)

```
Initiator                              Responder
─────────                              ─────────
(kem_pk, kem_sk) = ML-KEM.keygen()
→ kem_pk
                                       (ss, ct) = ML-KEM.encapsulate(kem_pk)
                                       sym_key = SHA3(ss)
                                       s = identity_keypair (ML-DSA)
                                       sig = ML-DSA.sign(s.sk, kem_pk || ct)
                                       ← ct, ENCRYPT_sym(s.public, sig)
ss = ML-KEM.decapsulate(kem_sk, ct)
sym_key = SHA3(ss)
s_remote = DECRYPT_sym(...)
ML-DSA.verify(s_remote, kem_pk || ct, sig)
sig2 = ML-DSA.sign(my_s.sk, ct || kem_pk)
→ ENCRYPT_sym(my_s.public, sig2)
                                       ML-DSA.verify(...)
                                       [session established with sym_key]
```

### Key differences
- X25519 DH (2 operations) → ML-KEM encap/decap (1 operation)
- Ed25519 sign/verify → ML-DSA sign/verify
- Noise pattern changes from XX to a KEM-based variant
- Symmetric cipher (ChaChaPoly) stays the same (already PQ-safe)

### Files to modify in vendor/libp2p-noise/

```
src/protocol.rs
  - Replace Keypair (X25519) with ML-KEM keypair
  - Replace AuthenticKeypair signature with ML-DSA
  - Remove x25519_dalek dependency
  - Add seal-crypto dependency

src/io/handshake.rs
  - Replace Noise XX pattern with PQ-Noise pattern
  - KEM encapsulate instead of DH
  - ML-DSA signatures instead of Ed25519

src/lib.rs
  - Update Config to use PQ types
  - Update error types

Cargo.toml
  - Remove: x25519_dalek, snow
  - Add: seal-crypto (for ML-KEM + ML-DSA + SHA3)
```

### Size impact

| Component | Classical | PQ |
|-----------|----------|-----|
| Handshake msg 1 (→) | 32 bytes (X25519 pk) | 1,184 bytes (ML-KEM pk) |
| Handshake msg 2 (←) | ~100 bytes (X25519 pk + Ed25519 sig) | ~4,500 bytes (ciphertext + ML-DSA sig) |
| Handshake msg 3 (→) | ~100 bytes | ~5,300 bytes (ML-DSA pk + sig) |
| **Total handshake** | **~230 bytes** | **~11 KB** |
| Per-message overhead | 16 bytes (Poly1305 tag) | 16 bytes (unchanged) |

The handshake is larger but happens once per connection.
Per-message overhead is identical (symmetric crypto is PQ-safe).

## 2. libp2p-core: PQ Peer Identity

### Current peer ID

```rust
// libp2p-core/src/identity.rs (simplified)
pub enum Keypair {
    Ed25519(ed25519::Keypair),
    // ... RSA, secp256k1
}

impl Keypair {
    pub fn to_peer_id(&self) -> PeerId {
        PeerId::from_public_key(&self.public())
    }
}

// PeerId = Multihash(SHA2-256(protobuf(public_key)))
```

### PQ peer ID

```rust
pub enum Keypair {
    Ed25519(ed25519::Keypair),      // Keep for backward compat
    MlDsa65(seal_crypto::SigningKey, seal_crypto::VerifyingKey),  // NEW
}

impl Keypair {
    pub fn generate_pq() -> Self {
        let (sk, vk) = seal_crypto::SigningKey::generate();
        Keypair::MlDsa65(sk, vk)
    }

    pub fn to_peer_id(&self) -> PeerId {
        match self {
            Keypair::MlDsa65(_, vk) => {
                // PeerId from SHA3(ML-DSA public key)
                let hash = seal_crypto::sha3_256(&vk.to_bytes());
                PeerId::from_bytes(&hash.0)
            }
            // ... classical fallback
        }
    }
}
```

### Files to modify in vendor/libp2p-core/

```
src/identity.rs (or src/identity/)
  - Add MlDsa65 variant to Keypair enum
  - Implement sign/verify for MlDsa65
  - PeerId derivation from ML-DSA pk

src/peer_id.rs
  - Accept SHA3-256 hash (currently SHA2-256)

Cargo.toml
  - Add: seal-crypto
```

## 3. Protocol Negotiation

PQ nodes and classical nodes can't directly interoperate.
Options:

### Option A: Hard fork (testnet)
- All nodes must use PQ. No backward compat.
- Simplest. Appropriate for testnet.

### Option B: Multistream negotiation
- PQ nodes advertise `/noise/pq/1.0.0` protocol
- Classical nodes advertise `/noise/1.0.0`
- Nodes negotiate during connection setup
- Fallback to classical if peer doesn't support PQ

### Recommendation
- **Testnet: Option A** (all PQ, no classical)
- **Mainnet: Option B** (negotiate, prefer PQ, allow classical for transition)

## 4. Implementation Priority

1. ML-KEM key exchange in libp2p-noise (most security-critical)
2. ML-DSA handshake authentication
3. ML-DSA peer IDs in libp2p-core
4. Protocol negotiation for mixed networks

## 5. Estimated Effort

| Task | Days | Risk |
|------|------|------|
| Patch libp2p-noise (ML-KEM + ML-DSA) | 5-7 | Medium (snow library removal) |
| Patch libp2p-core (PQ peer ID) | 2-3 | Low |
| Integration testing (2-node handshake) | 2-3 | Medium |
| Protocol negotiation (optional) | 3-5 | Low |
| **Total** | **12-18 days** | |

## 6. Alternative: Custom Transport (skip libp2p patch)

Instead of patching libp2p, we could write a custom PQ transport:

```rust
// Custom PQ transport layer (no libp2p dependency for transport)
struct PqTransport {
    listener: TcpListener,
    kem_keypair: KemKeypair,
    signing_key: SigningKey,
}

impl PqTransport {
    async fn accept(&self) -> PqConnection { ... }
    async fn connect(&self, addr: &str) -> PqConnection { ... }
}

struct PqConnection {
    stream: TcpStream,
    symmetric_key: [u8; 32], // From ML-KEM handshake
}
```

Keep libp2p for GossipSub/mDNS/discovery but use our own transport
encryption layer underneath. This avoids patching libp2p entirely.

**Pros:** No fork maintenance, cleaner separation
**Cons:** More code to write, less battle-tested than libp2p
