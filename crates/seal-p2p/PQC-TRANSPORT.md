# P2P Transport — PQC Migration Plan

## Status

ML-KEM-768 native transport is **shipped** (`pq_transport.rs`,
`PqTransportSession`): we wrap libp2p's transport with our own
ML-KEM handshake + symmetric-frame layer instead of patching
Noise. Application-level identity uses `SealAddress` (bech32m over
`SHA3-256(ML-DSA pk)`), so we don't depend on libp2p peer-id types
for authentication.

**Remaining (mainnet-tracking, not blocking)**: native libp2p PQC
peer-IDs would let us drop the wrapping layer and route directly
on PQ peer-IDs. Track upstream libp2p for native ML-DSA + ML-KEM
support; revisit when an LTS release lands.

## Current State

libp2p 0.55 uses:
- **Noise protocol** with X25519 key exchange (NOT PQ-secure)
- **Ed25519 peer IDs** (NOT PQ-secure)
- TLS 1.3 as alternative transport (also classical)

## Problem: Harvest Now, Decrypt Later (HNDL)

An adversary recording network traffic today could:
1. Store encrypted P2P messages
2. Wait for quantum computers
3. Break X25519 key exchange
4. Decrypt all stored messages (transaction contents, block proposals)

Once a transaction is ON CHAIN, it's protected by SHA3 (PQ-secure).
But the window between P2P broadcast and block inclusion is vulnerable.

## PQC Requirements

### 1. Key Exchange: Replace X25519 with ML-KEM-768

We already have ML-KEM-768 in `seal-crypto`. Need to:
- Create a libp2p `UpgradeInfo` for ML-KEM handshake
- Or: wrap ML-KEM inside the Noise framework as a new DH function
- Or: use TLS 1.3 with post-quantum key exchange (Kyber hybrid)

### 2. Peer IDs: Replace Ed25519 with ML-DSA-65

libp2p peer IDs are derived from Ed25519 public keys.
Need to:
- Create a new `Keypair` variant for ML-DSA
- Derive peer ID from SHA3(ML-DSA public key) instead of SHA2(Ed25519 pk)
- This is a libp2p protocol-level change

### 3. Message Signing: Already PQ (if using Seal signatures)

Seal transactions in GossipSub messages are already ML-DSA signed.
The issue is the transport encryption, not the message signatures.

## Implementation Options

### Option A: libp2p Noise with ML-KEM (patch libp2p)

```
Difficulty: HIGH
Maintenance: HIGH (fork of libp2p)

Approach:
1. Fork libp2p-noise
2. Replace X25519 DH with ML-KEM encapsulate/decapsulate
3. Noise XX handshake becomes:
   → e (ML-KEM public key)
   ← e, ee (encapsulated shared secret)
   → s, es (ML-DSA signed)
4. Peer IDs from ML-DSA public keys
```

**Pros:** Full PQ transport, compatible with Noise framework
**Cons:** Maintaining a fork of libp2p is expensive

### Option B: Double encryption (practical, no fork)

```
Difficulty: MEDIUM
Maintenance: LOW

Approach:
1. Keep libp2p Noise/X25519 for transport (classical)
2. Add application-layer ML-KEM encryption on top:
   - On connect: peers exchange ML-KEM public keys via GossipSub
   - Before sending: encrypt payload with ML-KEM shared secret
   - On receive: decrypt with ML-KEM secret key
3. Even if X25519 is broken, the ML-KEM layer protects content
```

**Pros:** No libp2p fork, layered defense
**Cons:** Double encryption overhead, more complex

### Option C: TLS 1.3 with hybrid PQ (when available)

```
Difficulty: LOW (when upstream supports it)
Maintenance: LOW

Approach:
1. Wait for libp2p to add ML-KEM hybrid key exchange
2. rustls is working on PQ support (X25519+ML-KEM-768 hybrid)
3. Switch libp2p transport from Noise to TLS 1.3 with PQ
```

**Pros:** Standard, well-tested, maintained upstream
**Cons:** Not available yet (rustls PQ is experimental)

### Option D: QUIC with ML-KEM (future)

```
Difficulty: LOW (when available)
Maintenance: LOW

Approach:
1. QUIC transport already in libp2p
2. When QUIC implementations add ML-KEM key exchange
3. Switch to QUIC with PQ
```

## Recommendation

**Short-term (testnet): Option B (double encryption)**
- Implement ML-KEM application-layer encryption
- No libp2p fork needed
- Provides PQ protection for message contents
- Accept that transport metadata (IP addresses, timing) is not PQ-protected

**Medium-term: Option C (TLS 1.3 PQ)**
- Monitor rustls + libp2p for PQ support
- Switch when available (minimal code change)

**Long-term: Full PQ libp2p**
- Eventually libp2p will support PQ natively
- All transport + peer IDs will be PQ

## Peer ID PQC

### Current: Ed25519 peer IDs
```
PeerId = Multihash(SHA2-256(Ed25519_public_key))
```

### PQ peer IDs (need protocol change)
```
PeerId = Multihash(SHA3-256(ML-DSA-65_public_key))
```

This requires a new libp2p protocol negotiation. Nodes with PQ peer IDs
can't interoperate with classical nodes without a compatibility layer.

### Practical approach for testnet
- Use Ed25519 peer IDs for libp2p discovery/routing
- Use ML-DSA identities for Seal consensus (separate from peer ID)
- This is what we already do: `SealAddress` ≠ `PeerId`

## Implementation: Application-Layer ML-KEM Encryption

```rust
// On peer connection:
let (our_kem_pk, our_kem_sk) = KemKeypair::generate();
// Exchange ML-KEM public keys via a handshake message
gossipsub.publish("seal/handshake", our_kem_pk.to_bytes());

// On receiving peer's public key:
let (shared_secret, ciphertext) = peer_kem_pk.encapsulate();
// Send ciphertext to peer
gossipsub.publish("seal/handshake", ciphertext.to_bytes());

// Now both peers have shared_secret
// Encrypt all subsequent messages with SHA3(shared_secret) as symmetric key

// On sending a block:
let encrypted = xor_encrypt(&block_bytes, &symmetric_key);
gossipsub.publish("seal/blocks/1.0", encrypted);

// On receiving:
let decrypted = xor_decrypt(&encrypted, &symmetric_key);
let block: Block = bincode::deserialize(&decrypted)?;
```

Note: XOR encryption is a placeholder. Production would use
AES-256-GCM or ChaCha20-Poly1305 with the ML-KEM derived key.
