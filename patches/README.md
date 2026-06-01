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

### `libp2p-noise-pqc.patch` — superseded

Original plan was to patch `vendor/libp2p-noise/` to swap X25519 → ML-KEM-768
inside the Noise framework. **Superseded** by `crates/seal-p2p/src/pq_transport.rs`,
which implements an ML-KEM-768 native transport at a layer above libp2p (no
modification to vendored Noise sources). See STATUS.md row "P2P networking".

If a future libp2p-native PQC story needs the in-Noise patch (e.g. for
QUIC-PQ interop), the original sketch lives in `git log` of this file.

### `libp2p-core-pqc.patch` — superseded

Original plan was to add ML-DSA-65 as a libp2p `Keypair` variant and derive
`PeerId` from `SHA3(ML-DSA pk)`. **Superseded**: `seal-crypto::SealAddress`
serves as the application-level identity (bech32m over `SHA3-256(ML-DSA pk)`),
and the PQ transport binds it independent of libp2p's own peer-id type.
Track upstream libp2p for native PQC peer-id support and revisit only if
we want classic libp2p-rooted peer routing again.

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
