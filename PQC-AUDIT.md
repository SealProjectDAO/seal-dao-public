# Seal DAO — Post-Quantum Cryptography Audit

## Summary

| Component | PQC Status | Algorithm | Action |
|-----------|-----------|-----------|--------|
| Transaction signatures | ✅ **PQ-secure** | ML-DSA-65 (libcrux, FIPS 204) | None |
| Key encapsulation | ✅ **PQ-secure** | ML-KEM-768 (libcrux, FIPS 203) | None |
| State hashing | ✅ **PQ-secure** | SHA3-256 (FIPS 202) | None |
| Address derivation | ✅ **PQ-secure** | SHA3-256 + Bech32m | None |
| Merkle tree | ✅ **PQ-secure** | SHA3-256 content addressing | None |
| ZK proofs (future) | ✅ **PQ-secure** | STARK (no Groth16 wrapper) | None |
| VRF | ⚠️ **NOT PQ** | HMAC-SHA3 (stub) | Replace with LB-VRF |
| Threshold sigs | ⚠️ **NOT PQ** | Individual ML-DSA (stub) | Replace with Ringtail |
| P2P encryption | ⚠️ **NOT PQ** | Noise (X25519 via libp2p) | Wait for libp2p ML-KEM |
| Bridge wallet (Ed25519) | ❌ **NOT PQ** | Ed25519 (Solana/Stellar) | By design (external chains) |

## Detailed Analysis

### ✅ Fully PQ-Secure Components

**ML-DSA-65 (Dilithium)** — All on-chain signatures:
- Transaction signing
- Block proposal signing
- Governance votes
- Committee partial signatures
- Wallet: signing key derived from seed deterministically
- Verified by: Cryspen (hax + F*)

**ML-KEM-768 (Kyber)** — Key encapsulation:
- Available for P2P encrypted comms (not yet wired into libp2p)
- Verified by: Cryspen (hax + F*)

**SHA3-256 (Keccak)** — All hashing:
- Merkle tree node hashing
- State root computation
- Address derivation
- Transaction hashing
- VRF input derivation

**STARK proofs** — ZK verification:
- RISC Zero / SP1 STARKs are hash-based (PQ-secure)
- We do NOT use the Groth16 SNARK wrapper (which would break PQ)

### ⚠️ Components Needing PQ Upgrade

**VRF (HMAC-SHA3 stub)**:
- Current: `HmacVrf` — HMAC-based, not a real VRF
- Issue: Not PQ-secure, and not even a proper VRF
- Fix: `LatticeVrf` (LB-VRF, Module-LWE/SIS) — trait ready, needs port
- Timeline: Before mainnet
- Risk: LOW (testnet only, VRF output isn't a secret)

**Threshold signatures (SimpleThreshold)**:
- Current: Collects individual ML-DSA sigs (PQ per-sig, but not aggregated)
- Issue: 330 KB per block instead of 13.4 KB
- Fix: `RingtailThreshold` (LWE-based) — trait ready, needs port
- Timeline: Before mainnet (performance critical)
- Risk: LOW (individual sigs ARE PQ-secure, just large)

**P2P transport (Noise/X25519)**:
- Current: libp2p uses Noise protocol with X25519 key exchange
- Issue: X25519 is NOT PQ-secure (ECDH, broken by quantum)
- Fix: libp2p needs to add ML-KEM support (upstream dependency)
- Workaround: We have ML-KEM-768 ready in seal-crypto
- Timeline: When libp2p adds support (tracked upstream)
- Risk: MEDIUM (network traffic could be recorded now, decrypted later)

### ❌ Intentionally Non-PQ

**Ed25519 in wallet (bridge operations)**:
- Used for: Solana wallet, Stellar wallet (Ed25519 chains)
- Why non-PQ: Solana and Stellar use Ed25519. We can't change their chains.
- Mitigation: Bridge operations are optional. SEAL-native operations are PQ.
- Risk: If quantum computers break Ed25519, bridge funds are at risk.
  Users should bridge back to SEAL before quantum threat materializes.

## PQ Migration Path

```
Phase 1 (now):     ML-DSA ✅  ML-KEM ✅  SHA3 ✅  STARK ✅
Phase 2 (next):    LB-VRF ✅  Ringtail ✅
Phase 3 (upstream): libp2p ML-KEM transport
Phase 4 (external): Solana/Stellar PQ upgrades (not in our control)
```

## Harvest Now, Decrypt Later (HNDL) Analysis

| Data | Encrypted by | HNDL risk | Mitigation |
|------|-------------|-----------|------------|
| Transactions on chain | ML-DSA signatures | NONE (signatures, not encryption) | PQ-secure |
| Block proposals | ML-DSA | NONE | PQ-secure |
| State roots | SHA3-256 | NONE (hashes, not encrypted) | PQ-secure |
| P2P messages | Noise/X25519 | **HIGH** | Upgrade to ML-KEM when available |
| Bridge wallet keys | Ed25519 | **HIGH** | Bridge back to SEAL before quantum |
| Wallet seed | SHA3-based KDF | NONE (local, not transmitted) | PQ-secure |

**Priority**: The P2P transport is the main HNDL risk. An adversary recording
network traffic today could decrypt it with a future quantum computer to
learn transaction contents before they're committed to the chain. Once
committed, the on-chain data is protected by SHA3 (PQ-secure).
