# Seal DAO — Dependency Management

## Vendoring Strategy

We vendor dependencies for **offline builds** and **supply chain security**.

### Full vendor (all 417 crates, ~671MB)
```bash
# Vendor everything (large, for air-gapped builds)
./scripts/vendor-update.sh

# Build with vendored sources
cargo build  # Uses vendor/ automatically via .cargo/config.toml

# To temporarily use crates.io instead:
mv .cargo/config.toml .cargo/config.toml.bak
cargo build
mv .cargo/config.toml.bak .cargo/config.toml
```

### Update process
```bash
# After changing Cargo.toml dependencies:
./scripts/vendor-update.sh
# This will:
#   1. Switch to crates.io temporarily
#   2. cargo update
#   3. Re-vendor
#   4. Verify build + tests
#   5. Tell you what to commit
```

## Key Dependencies (Security-Critical)

These are the dependencies that handle cryptographic material or are
in the trusted computing base. Review these carefully on updates.

### Cryptography

| Crate | Version | What | Verified? |
|-------|---------|------|-----------|
| `libcrux-ml-dsa` | 0.0.7 | ML-DSA-65 signatures (FIPS 204) | **Yes** — hax + F* (Cryspen) |
| `libcrux-ml-kem` | 0.0.7 | ML-KEM-768 key encapsulation (FIPS 203) | **Yes** — hax + F* (Cryspen) |
| `sha3` | 0.10 | SHA3-256 hashing (FIPS 202) | Audited (RustCrypto) |
| `zeroize` | 1.8 | Secret material zeroing on drop | Audited (RustCrypto) |
| `subtle` | 2 | Constant-time comparisons | Audited (dalek-cryptography) |
| `rand` | 0.8 | Cryptographic RNG | Audited (Rust project) |

### Networking

| Crate | Version | What | Notes |
|-------|---------|------|-------|
| `libp2p` | 0.54 | P2P networking (GossipSub, mDNS, Noise) | Large dep tree (~100 crates) |

### Storage

| Crate | Version | What | Notes |
|-------|---------|------|-------|
| `sled` | 0.34 | Embedded key-value database | Pure Rust, no C deps |
| `bincode` | 1 | Binary serialization | Small, well-audited |

### SQL

| Crate | Version | What | Notes |
|-------|---------|------|-------|
| `sqlparser` | 0.53 | SQL parsing (PostgreSQL dialect) | Apache DataFusion project |

### Serialization

| Crate | Version | What | Notes |
|-------|---------|------|-------|
| `serde` | 1 | Serialization framework | De facto standard |
| `serde_json` | 1 | JSON serialization | |
| `borsh` | 1 | Binary Object Representation | Used in Solana ecosystem |

## Dependency Policy

1. **Minimize dependencies**: Every new crate increases attack surface.
2. **Prefer Rust-native**: No C dependencies where possible (except libcrux's verified C).
3. **Pin versions**: Use exact versions in Cargo.lock (committed to git).
4. **Audit on update**: Run `cargo audit` after any dependency change.
5. **Review crypto deps**: Any change to cryptographic dependencies requires team review.

## Supply Chain Security

```bash
# Check for known vulnerabilities
cargo audit

# Check license compliance + duplicate deps
cargo deny check  # (install: cargo install cargo-deny)

# List all dependencies with licenses
cargo license     # (install: cargo install cargo-license)
```

## Dependency Count by Category

```
Cryptography:    ~15 crates  (libcrux, sha3, zeroize, subtle, rand)
Networking:     ~100 crates  (libp2p and its dep tree)
Storage:         ~10 crates  (sled, bincode)
SQL:              ~5 crates  (sqlparser)
Serialization:   ~10 crates  (serde, borsh)
Async runtime:   ~20 crates  (tokio)
Other:          ~250 crates  (transitives)
Total:          ~417 crates
```

Most of the count is libp2p's transitive dependency tree. The core chain
(crypto + storage + SQL) has ~40 direct + transitive dependencies.
