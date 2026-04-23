# Building the Seal ZK Guest ELF

## Current status

- Guest source: `guest/src/main.rs` — pure `risc0-zkvm-platform` (no alloc/serde)
- Guest Cargo.toml: standalone workspace, excluded from parent
- Host integration: `SEAL_GUEST_ELF` embedded, image ID computed lazily from
  the wrapped `ProgramBinary` (`risc0-binfmt::ProgramBinary::compute_image_id`)
- Host runs the guest under the real r0vm v5.0.0-rc.1 **executor** via
  `default_executor().execute()` — 88-byte RZK1-tagged proof with a journal
  that matches the public inputs (`test_risc0_real_prove_and_verify`)
- STARK proving (`default_prover().prove()`) is stubbed until either the
  in-process LocalProver is enabled, or the IPC r0vm honours `RISC0_DEV_MODE`

## Build method (nightly + -Zbuild-std)

The `risc0-zkvm-platform`-only guest builds with nightly cargo plus
`-Zbuild-std`. No docker, no cargo-risczero.

```bash
GUEST=/tmp/seal-guest-build
rm -rf $GUEST
cp -r crates/seal-zk/guest $GUEST
rm -rf $GUEST/.cargo $GUEST/Cargo.lock $GUEST/target
cd $GUEST

RUSTC=~/.rustup/toolchains/nightly-aarch64-apple-darwin/bin/rustc \
  ~/.rustup/toolchains/nightly-aarch64-apple-darwin/bin/cargo build \
    --release \
    --target ./riscv32im-risc0-zkvm-elf.json \
    -Zbuild-std=core,alloc \
    -Zbuild-std-features=compiler-builtins-mem \
    -Zjson-target-spec
```

ELF lands at `target/riscv32im-risc0-zkvm-elf/release/seal-zk-guest`.

## Install

```bash
cp /tmp/seal-guest-build/target/riscv32im-risc0-zkvm-elf/release/seal-zk-guest \
   crates/seal-zk/elf/seal-guest.elf
```

The host embeds it via `include_bytes!` in `crates/seal-zk/src/risc0.rs`.

## Run the real r0vm executor test

```bash
SEAL_RUN_REAL_RISC0=1 cargo test -p seal-zk --features risc0 \
    test_risc0_real_prove_and_verify -- --nocapture
```

Expected:
```
real executor proof: 88 bytes, magic = "RZK1"
test risc0::tests::test_risc0_real_prove_and_verify ... ok
```

## Host → guest I/O protocol

The host writes 11 little-endian `u32` words to STDIN via
`env.write_slice(&[u32; 11])`:

| Offset | Content |
|--------|---------|
| words[0..8]  | `pre_state_root` (u8x32) |
| words[8..10] | `block_height` (lo, hi) |
| words[10]    | `tx_count` |

The guest reads them back with `sys_read_words(STDIN, buf, 11)`. Do not use
`sys_input`: it's capped at 8 words (`index & 0x07`) and is for the segment's
public-input register file, not a general input stream.

## Guest → host journal layout (80 bytes)

| Offset  | Content |
|---------|---------|
| [0..32] | `pre_state_root` |
| [32..64] | `post_state_root` |
| [64..72] | `block_height` (le) |
| [72..76] | executed tx count (le) |
| [76..80] | `tx_hash[..4]` |

The host verifier checks the journal bytes against the public inputs.

## `sys_halt` out_state

The guest halts with a stub non-zero `out_state` so the executor does not
drop the journal (see `session_journal` in
`risc0_zkvm::host::server::exec::executor`: journals are only captured when
`exec_result.output != Digest::ZERO`). A cryptographically valid Output
digest requires the full risc0-zkvm guest env, which currently does not
build under `-Zbuild-std` alone — several transitive crates (`memmap2`,
`downcast-rs`) fail on `riscv32im-zkvm` because they assume std prelude.
The stub works for the executor path and for STARK proving in DEV_MODE;
it will need to be replaced with the real Output commitment before
production proofs.

## Version notes

- Vendored risc0-zkvm: 5.0.0-rc.1
- Installed r0vm: `~/.risc0/extensions/v5.0.0-rc.1-cargo-risczero-aarch64-apple-darwin/r0vm`
- Nightly used for the guest build: `nightly-aarch64-apple-darwin`
