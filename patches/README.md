# Patches — PQC Modifications to Vendored Dependencies

## Why patches?

Some dependencies (libp2p) use classical cryptography internally.
We can't wait for upstream to add PQC support, so we maintain
patches that modify the vendored source.

## How it works

1. `./scripts/vendor-update.sh` — downloads fresh vendor/
2. `./scripts/apply-patches.sh` — applies our PQC patches on top
3. Build uses the patched vendor/ via `.cargo/config.toml`

## Patches

### `libp2p-noise-pqc.patch` (TODO)

Modifies `vendor/libp2p-noise/` to:
- Replace X25519 DH with ML-KEM-768 key encapsulation
- Use ML-DSA-65 for handshake authentication (instead of Ed25519)
- Derive symmetric keys from ML-KEM shared secret

Files modified:
- `src/protocol.rs`: replace `x25519_dalek` with `seal-crypto` ML-KEM
- `src/io/handshake.rs`: modify Noise XX pattern for KEM
- `Cargo.toml`: add `seal-crypto` dependency

### `libp2p-core-pqc.patch` (TODO)

Modifies `vendor/libp2p-core/` to:
- Add ML-DSA-65 as a peer identity key type
- Derive PeerId from SHA3(ML-DSA public key)
- Support PQC key serialization in multicodec format

Files modified:
- `src/identity.rs` (or equivalent): add PQC key variant
- `src/peer_id.rs` (or equivalent): derive from ML-DSA pk

## Applying patches

```bash
# After vendor-update.sh:
./scripts/apply-patches.sh

# Or manually:
cd vendor/libp2p-noise
patch -p1 < ../../patches/libp2p-noise-pqc.patch
```

## Tracking upstream

When libp2p adds native PQC support, we can drop these patches.
Track: https://github.com/libp2p/rust-libp2p/issues (search "post-quantum")
