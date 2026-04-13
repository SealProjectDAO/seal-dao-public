# Building the Seal ZK Guest ELF

## Prerequisites

- `cargo-risczero` matching the vendored `risc0-zkvm` version (5.0.0-rc.1)
- Docker (for the standard build path)
- OR: the risc0 Rust toolchain with RISC-V target (`rzup install`)

## Build methods

### Method 1: Docker (standard, cross-platform)

```bash
cargo risczero build --manifest-path crates/seal-zk/guest/Cargo.toml --features risc0
```

The ELF will be output to `target/riscv32im-risc0-zkvm-elf/docker/seal-zk-guest`.

### Method 2: Direct (requires risc0 Rust toolchain)

```bash
# Install risc0 toolchain
rzup install

# Build with the risc0 cargo (nightly-like, has riscv32 target)
~/.risc0/toolchains/*/bin/cargo build \
    --release \
    --target riscv32im-risc0-zkvm-elf \
    -Zbuild-std=core,alloc \
    --features risc0 \
    --manifest-path crates/seal-zk/guest/Cargo.toml
```

### Method 3: Native test (no ZK proof, no RISC-V)

```bash
cargo run -p seal-zk-guest
```

## After building

1. Copy the ELF: `cp target/riscv32im-risc0-zkvm-elf/release/seal-zk-guest crates/seal-zk/elf/seal-guest.elf`
2. Update `crates/seal-zk/src/risc0.rs`: change `SEAL_GUEST_ELF` from `&[]` to `include_bytes!("../elf/seal-guest.elf")`
3. Compute the image ID and update `SEAL_GUEST_ID`
4. Uncomment the real proving/verification code paths

## Current status

- Guest source: ready (`guest/src/main.rs` with risc0 feature)
- Guest Cargo.toml: ready (standalone workspace, excluded from parent)
- Host integration: ready (SEAL_GUEST_ELF/SEAL_GUEST_ID constants defined)
- ELF binary: **not yet built** (blocked on cargo-risczero v5 tooling matching risc0-zkvm 5.0.0-rc.1)

## Version notes

- Vendored risc0-zkvm: 5.0.0-rc.1
- Installed cargo-risczero: 3.0.5 (may not match v5 guest builder image)
- When risc0 v5 is released as stable, the Docker build will work seamlessly
