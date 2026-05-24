# Seal DAO — Manual Test Guide

Step-by-step manual tests for all major features. Run these after
code changes to verify end-to-end functionality.

Sections 1–14 cover the original feature set; sections 15–19 cover
the RPC / bridge / Ringtail-verify surface added 2026-04-18 onwards.
Sections 26–28 cover the **testnet-readiness batch landed
2026-05-10** (state-sync RPC trio + late-joiner bootstrap,
validator-registration portal, PQC-native release pipeline).

> **Coverage note — 2026-04-23 interim release.** This session drove
> §1 through §16 end-to-end (wallet ops, SQL, DEX, consensus, P2P,
> storage, bridge unit tests, CLI, fuzz, formal, custom tokens) on a
> live node with the dev faucet. §17–§25 (bridge JSON-RPC, SQL/DEX/
> MPC/ZK/gov RPC, Ringtail BPF verify, procedures runtime,
> forms.seal, the three new demo apps) are documented with commands
> verified against handler source but **were not exercised on a live
> stack** in this session — the bridge-e2e stack was brought up
> (Solana + Stellar `(healthy)`) but the full lock→mint→burn→unlock
> round-trip was paused. See
> [`TODOS/SESSION-2026-04-23.md`](TODOS/SESSION-2026-04-23.md) for the
> full state of what shipped, what's still open, and where the
> bridge-e2e left off. Before relying on any §17–§25 command at face
> value, re-run it yourself — the patterns are correct but individual
> edge cases (e.g. fresh-account policy, token-symbol canonicalization)
> may have shifted since the last live run.

> **Coverage note — 2026-05-10 testnet-readiness batch.** §26
> (state-sync RPC trio + late-joiner bootstrap), §27 (validator
> registration portal), and §28 (release pipeline + sign-file /
> verify-file) shipped with full unit-test coverage and round-trip
> tests against in-memory mocks (1077 → 1116 tests, +39 new), but
> the late-joiner bootstrap path (§26.5) was not exercised against
> a real two-node testnet in this session — the encode / decode
> primitives have a deterministic state-root cross-check at the
> end of `bootstrap_from_peer`, so a divergence would surface as
> `BootstrapError::StateRootDivergence` rather than silent
> corruption, but the live multi-node smoke is still owed. The
> Stellar quickstart pin (§7.5) was validated by `docker compose
> -f bridges/docker-compose.testnet.yml config` parsing cleanly;
> a full `bridge-testnet-demo.sh` round-trip wasn't run on this
> dev machine. See [`TODOS/SESSION-2026-05-10-testnet-readiness.md`](TODOS/SESSION-2026-05-10-testnet-readiness.md)
> for the full state.

> **Coverage note — 2026-05-16 EOD "no excuse bordel" batch.**
> Bridge multi-validator Ringtail integration landed (P1#5 layer 4
> end-to-end, P8 mainnet gates, in-flight session persistence,
> 3-validator smoke). The operator-side bring-up is documented as
> a dedicated end-to-end runbook — see
> [`docs/RUNBOOK-TESTNET-OPERATOR.md`](docs/RUNBOOK-TESTNET-OPERATOR.md).
> Validator-count + bridge-committee sizing recipes for 3 / 5 / 7
> validators live in
> [`docs/TESTNET-VALIDATOR-SIZES.md`](docs/TESTNET-VALIDATOR-SIZES.md).

## Prerequisites

```bash
cargo build --workspace
```

## 1. Wallet Operations

### 1.1 Launch Desktop Wallet (Electron)

```bash
cd apps/seal-wallet && npm install && npm run electron
```

**Expected:** Electron window opens loading `standalone.html`. UI lets you
create a wallet (displays `sealt1…` address + 24-word BIP-39 mnemonic),
sign messages, and verify signatures. All crypto runs in-browser via the
bundled `seal_dao_wasm_bg.wasm`.

### 1.2 Wallet Tests

```bash
cargo test -p seal-wallet
```

**Expected:** 34 tests pass across `keystore`, `bip39`, `mnemonic`,
`storage`, `wordlist` (covers create, import, sign+verify, BIP-39 round-trip,
encrypted save+load, wrong-password rejection).

### 1.3 Android FFI Bridge

```bash
cargo test --manifest-path apps/seal-wallet-android/Cargo.toml -- --test-threads=1
```

**Expected:** 6 tests pass (create+address, sign+verify, mnemonic, BIP-39, import, lock).

### 1.4 Manual Wallet Roundtrip

```bash
# 1. Launch the desktop wallet
cd apps/seal-wallet && npm run electron
# 2. In the UI: Create wallet → copy the 24-word mnemonic + sealt1 address
# 3. Close the window, relaunch, choose "Import" → paste the mnemonic
# 4. Confirm the imported address matches step 2
# (The automated equivalent lives in `cargo test -p seal-wallet`, §1.2.)
```

### 1.5 Browser-extension wallet (manifest v3)

`apps/seal-wallet-extension/` — Chromium MV3 extension that signs
ML-DSA transactions in-browser. The popup UI manages the AES-GCM
vault (PBKDF2-SHA-256, 310k iterations); the in-page provider exposes
an EIP-1193-shaped `window.seal` object backed by the SDK's WASM
module.

```bash
# Build the WASM SDK the popup loads from.
# Requires wasm-pack — install with one of:
#   cargo install wasm-pack
#   curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
#   brew install wasm-pack
cd sdks/wasm && ./build.sh

# Load the extension in Chrome (or any Chromium):
#   1. chrome://extensions → enable Developer mode
#   2. "Load unpacked" → apps/seal-wallet-extension/
#   3. Pin the Seal icon in the toolbar
#
# Manual smoke flow:
#   - Open popup → "Create new wallet" → set a passphrase (≥ 8 chars,
#     typed twice) → confirm the 24-word mnemonic screen
#   - Click "Lock" (on the account screen) → the popup returns to the
#     Unlock screen; reopen the popup and enter your passphrase to
#     unlock. Wrong passphrase surfaces "Wrong passphrase."
#   - On the account screen, "Change passphrase…" prompts for the
#     current + new (twice); verify by locking and unlocking with the
#     new one. "Reset wallet…" (on either Unlock or Account) requires
#     typing "RESET" in all caps and drops the vault + accounts from
#     chrome.storage.local, returning to "No wallet".
#   - Serve the bundled example dApp (localhost is required — the
#     extension's host_permissions only cover http://localhost:*/*):
#       cd apps/seal-wallet-extension/example && python3 -m http.server 5173
#     then open http://localhost:5173/ and:
#       1. Click "Connect" — a pending request appears in the popup;
#          Approve. (seal_accounts returns [] for unapproved origins,
#          like eth_accounts vs eth_requestAccounts.)
#       2. Click "seal_accounts" — returns ["seal1..."].
#       3. Click "seal_signMessage" — the popup shows a Sign request;
#          approving returns an ML-DSA signature hex.
#     Equivalent from devtools on that page:
#       await window.seal.request({ method: 'seal_requestAccounts' })
#       await window.seal.request({ method: 'seal_accounts' })
#       await window.seal.request({ method: 'seal_signMessage',
#                                   params: ['hello'] })
```

Expected: `seal_accounts` returns the vault's address; `seal_signMessage`
prompts the popup for approval, then returns an ML-DSA signature hex.
The signature must verify under the address's verifying key (validate via
`cargo run -p seal-cli -- verify-sig <addr> hello <sig>`).

## 2. SQL Engine

### 2.1 SQL Tests

```bash
cargo test -p seal-sql
```

**Expected:** 72+ tests pass covering CREATE TABLE, INSERT, SELECT, UPDATE, DELETE,
WHERE clauses, JOINs, indexes, RLS, namespaces, Merkle state.

### 2.2 Interactive SQL REPL

```bash
cargo run -p seal-app
```

**Commands to test:**

```
> CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT)
> INSERT INTO users (id, name) VALUES (1, 'alice')
> INSERT INTO users (id, name) VALUES (2, 'bob')
> SELECT * FROM users
> SELECT * FROM users WHERE id = 1
> UPDATE users SET name = 'ALICE' WHERE id = 1
> SELECT * FROM users
> DELETE FROM users WHERE id = 2
> .tables
> .status
> .produce
> .quit
```

**Expected:** Each query returns correct results. `.produce` creates a block with state root.

## 3. Consensus & Block Production

### 3.1 Consensus Tests

```bash
cargo test -p seal-node --lib
```

**Expected:** 217+ tests pass covering block production, VRF election, threshold signatures,
state roots, parent hash chain, epoch transitions, fees, governance, replay.

### 3.2 Demo Mode

```bash
cargo run -p seal-cli -- demo
```

**Expected:** Runs a full demo: creates wallet, deploys app, inserts data, produces blocks,
queries data, shows state roots.

### 3.3 VRF Key Rotation

```bash
cargo test -p seal-node --lib -- test_vrf_key_rotation_at_epoch
```

**Expected:** VRF key changes after epoch boundary.

### 3.4 VRF Proofs in Blocks

```bash
cargo test -p seal-node --lib -- test_block_has_vrf_proof
```

**Expected:** Block header contains non-empty VRF output (32 bytes) and proof.

## 4. Marketplace Demo

### 4.1 Run Marketplace

```bash
echo ".quit" | cargo run -p seal-marketplace
```

**Expected output includes:**

- Seller and buyer addresses (sealt1...)
- 3 items listed (Widget, Gadget, Doohickey)
- Buyer browses 3 listings
- Order placed, payment transferred
- Final balances: buyer=9900, seller=100
- 2 active listings, 1 order
- Block produced with state root

### 4.2 Interactive Marketplace

```bash
cargo run -p seal-marketplace
```

**Commands to test (enter at the `>` prompt):**

```
> .list Gizmo 500
> .browse
> .buy 4
> .balances
> .produce
> .status
> .quit
```

**Expected:** each command returns a reasonable result; `.balances` reflects the
buyer/seller transfer; `.produce` emits a block with a new `state_root`.

## 5. Cryptographic Primitives

### 5.1 All Crypto Tests

```bash
cargo test -p seal-crypto
```

**Expected:** 23+ tests: ML-DSA sign/verify, SHA3-256, ML-KEM encapsulate/decapsulate,
Bech32m addresses, key serialization, deterministic keygen.

### 5.2 VRF Tests

```bash
cargo test -p seal-vrf
```

**Expected:** 57+ tests: PqVrf (ML-DSA based), HmacVrf, LatticeVrf (polynomial ring),
epoch key rotation, cross-epoch verification, determinism.

### 5.3 Threshold Signature Tests

```bash
cargo test -p seal-threshold
```

**Expected:** 75+ tests: SimpleThreshold signing/aggregation/verification,
Ringtail protocol rounds, NTT cross-validation, Shamir secret sharing,
Gaussian sampling, Bitfield operations.

## 6. P2P Networking

### 6.1 P2P Tests

```bash
cargo test -p seal-p2p
```

**Expected:** 32+ tests: node startup, PQ double-encryption, key exchange,
nonce-based SHA3-CTR+MAC, PQ-Noise handshake (mutual auth, forward secrecy).

### 6.2 Two-Node Test

```bash
cargo test -p seal-p2p test_two_nodes_start
```

**Expected:** Two nodes start on different random ports with different peer IDs.

### 6.3 Testnet Script

```bash
./scripts/testnet.sh
```

**Expected:** Starts 3 local nodes that discover each other via mDNS.

### 6.4 Persistent validator identity

`seal-node --validator-key <path>` pins the on-chain ML-DSA identity
across restarts. Same keyfile in two consecutive runs → same address,
same VRF state, same signing keys. Without the flag the node generates
a fresh keypair every start (fine for local dev, restart-unsafe for
testnet — the address you registered on the portal would drift away
from the address your node actually signs with).

```bash
# Generate once, reuse across restarts:
cargo run -p seal-cli -- keygen --output /tmp/v1.json
ADDR=$(jq -r .address /tmp/v1.json)

# Run 1 — confirm the loaded address matches:
cargo run -p seal-node -- --slots 1 \
    --validator-key /tmp/v1.json --port 4099 --rpc-port 0 \
    2>&1 | grep "Validator identity loaded"
# → Validator identity loaded from /tmp/v1.json (address sealt1…matches $ADDR)

# Run 2 with the same key — identical address.
# Run 3 without the flag — different ephemeral address each time.
```

**Negative paths:**
- Missing / unreadable file: exit 2 with `error: --validator-key
  <path>: read: …`.
- Missing or malformed hex fields: exit 2 with `missing 'signing_key'
  field` / `signing_key hex: …`.
- HRP mismatch (testnet keyfile on `--mainnet` node, or vice versa):
  exit 2 with `network mismatch: keyfile is for 'testnet' but node
  is running in 'mainnet' mode (toggle --mainnet to match)`. Prevents
  silently signing on the wrong chain.

## 7. Bridge

### 7.1 Bridge Tests

```bash
cargo test -p seal-bridge
```

**Expected:** 48+ tests: deposit/confirm/process, withdrawal, invariant
checking, observer creation, event parsing, multi-chain polling, and
the 8 chain-pause tests (`pause_chain` / `unpause_chain` /
`is_chain_paused` / `list_paused_chains` — added 2026-04-19).

### 7.2 Solana Contract Tests

```bash
rustc --edition 2021 --test contracts/solana/programs/seal-lock/src/lib.rs -o /tmp/sol_test && /tmp/sol_test
```

**Expected:** 12 tests: lock SOL, lock SPL, multisig release, error cases.

### 7.3 Stellar Contract Tests

```bash
rustc --edition 2021 --test contracts/stellar/src/lib.rs -o /tmp/xlm_test && /tmp/xlm_test
```

**Expected:** 14 tests: lock XLM, lock USDC, multisig release, error cases.

### 7.4 Bridge toolchain install + on-chain build

For the Solana + Stellar bridge programs (BPF / WASM), install the
chain-native toolchains and build both programs with the
`ringtail-verify` Cargo feature:

```bash
./scripts/install-bridge-toolchains.sh          # native install, idempotent
./scripts/install-bridge-toolchains.sh --check  # dry-run, no install
./scripts/bridge-test-ringtail.sh               # build both programs
```

**Expected (after install):**
- `solana-cli` (Anza stable), `anchor-cli` 0.31.1, `stellar-cli` 25.2.0
  all on PATH.
- `~/.cargo/bin/{cargo,rustc,rustdoc}` symlinked to rustup (proxies
  for `cargo +<toolchain>` directives used internally by anchor +
  soroban build chains).

> **stellar-cli version note:** The CLI (`stellar-cli` on crates.io)
> and the Soroban SDK (`soroban-sdk`) share the same major version
> scheme but are separate crates with independent patch releases.
> `stellar-cli 25.2.0` + `soroban-sdk 25.3.1` are the matching pair
> for `stellar-rpc 25.1.0` (shipped in `stellar/quickstart:v637-*`).
> Do **not** install `stellar-cli 22.0.0` — that was the protocol-22
> era. Install with:
> `cargo install stellar-cli --version "25.2.0" --locked`

**Expected (after test):**
- `bridges/solana/programs/seal-bridge/target/deploy/seal_bridge.so`
  ≈ 270 KB (268 808 bytes at 2026-04-19 landing).
- `bridges/stellar/target/wasm32v1-none/release/seal_bridge_stellar.wasm`
  ≈ 8.6 KB (size may vary slightly after sdk-25 rebuild).

**Negative test:** move `.cargo/config.toml` back in place and re-run
the test script — it should fail fast with a vendor-source error,
which the script auto-handles by moving the config aside during
the build and restoring it on EXIT.

### 7.5 Stellar quickstart protocol-25 migration (completed 2026-05-13)

`bridges/docker-compose.testnet.yml` pins a dated nightly image
(`stellar/quickstart:v637-b1054.1-nightly`, stellar-rpc 25.1.0)
and runs at the image's native protocol 25. The earlier
`--protocol-version 22` pin was dropped when protocol-22-era images
expired (6-month nightly window); stellar-rpc 25.1.0 also requires
`ContractLedgerCostExtV0` which only exists in a protocol-25 ledger.
`bridges/stellar/Cargo.toml` pins `soroban-sdk = "25"` to match;
the WASM build target changed from `wasm32-unknown-unknown` to
`wasm32v1-none` (required by soroban-sdk 25 on Rust 1.82+).

```bash
# Compose syntax sanity-check (works on dev machines without
# spinning up the full stack):
docker compose -f bridges/docker-compose.testnet.yml config | grep -A 2 "image: stellar"
```

**Expected:** `image: stellar/quickstart:v637-b1054.1-nightly`
followed by `command: ["--local"]` (no `--protocol-version` flag).

```bash
# Full round-trip (requires Docker + Solana + Stellar deployer
# keys; not safe in CI):
cd bridges
docker compose -f docker-compose.testnet.yml up -d
../scripts/bridge-e2e.sh    # lock→mint→burn→unlock
```

**Expected:** `stellar contract install` succeeds against
protocol-25 RPC; the lock side reaches the mint event.

**Stale volume hazard:** The `stellar/quickstart` container must
start from a fresh volume each session. If `seal-bridge-stellar`
stays in `starting` state beyond ~5 minutes, the `stellar-data`
volume has stale state — tear down with `down -v` before retrying:
```bash
docker compose -f docker-compose.testnet.yml down -v
docker compose -f docker-compose.testnet.yml up -d
```

**Pin expiry:** Stellar nightlies stop building after ~6 months.
If `docker pull` 404s the tag, bump to a fresher
`vNNN-bMMMM.M-nightly` from
[hub.docker.com/r/stellar/quickstart/tags](https://hub.docker.com/r/stellar/quickstart/tags)
and verify `stellar-rpc version` inside the container still reports
25.x (matching `soroban-sdk = "25"` in Cargo.toml). Full runbook in
[`bridges/DEPLOYMENT.md`](bridges/DEPLOYMENT.md).

### 7.6 Port allocation: validator stack vs bridge stack

The two docker-compose stacks in this repo were historically pinned
to the same host ports (4001/8545+), and bringing one up while the
other was running failed with:

```
Error response from daemon: failed to set up container networking:
  ... Bind for 0.0.0.0:4001 failed: port is already allocated
```

**Fix landed 2026-05-16:** each stack owns a distinct host-port
range, so they coexist by default. Container-internal ports stay at
4001/8545 — only the host mapping differs.

| Stack | File | Host P2P | Host RPC |
|---|---|---|---|
| Validator (5/7-node) | `docker-compose.yml` + `bridges/docker-compose.ringtail-5.override.yml` | 4001-4005 | 8545-8549 |
| Host-side dev testnet | `scripts/testnet.sh` | 4001+ | 8545+ |
| Bridge (3-node + Solana + Stellar) | `bridges/docker-compose.testnet.yml` | 4101 (seal-1 only) | 8645-8647 |
| Bridge 5-of-7 ringtail | `+ bridges/docker-compose.ringtail-7.override.yml` | 4101 | 8645-8651 |

Bridge scripts default `SEAL_RPC` to `http://localhost:8645`. The
host-side dev testnet and the docker validator stack share canonical
defaults (4001/8545) because they're never run simultaneously.

**Diagnosis when a collision recurs:**

```bash
lsof -i :4001 -P -n | head
lsof -i :8545 -P -n | head
docker ps --format '{{.Names}}\t{{.Ports}}' | grep -E '4001|8545|4101|8645'
```

**If something other than the two stacks holds 4001/8545** (e.g.
an orphaned validator container from a prior session, or a host-side
seal-node started via `cargo run -- --port 4001 --rpc-port 8545`):
identify the owner and stop it; do NOT remap the bridge stack back
to 8545, as that re-introduces the original collision pattern.

**If you need to relocate either stack** (e.g. multiple bridge
stacks for fork testing): override compose port mappings via a
local override file, and pass `SEAL_RPC=http://localhost:<port>` to
the bridge scripts. The `:8545` / `:8645` references in script error
messages now read off `${NODE_PORTS[0]}`, so changing the array in
one place updates the messages too.

## 8. ZK Proofs

### 8.1 ZK Tests (default, no zkVM feature)

```bash
cargo test -p seal-zk
```

**Expected:** 46+ tests pass: stub prover/verifier, batch proving, GPU dispatcher,
RISC Zero simulation backend, SP1 simulation backend, proof format/tamper checks.

### 8.2 Feature-Gated Build

```bash
cargo build -p seal-zk --features risc0
cargo build -p seal-zk --features sp1
```

**Expected:** Compiles without errors. `--features risc0` links the vendored
`risc0-zkvm 5.0.0-rc.1` and embeds the 22KB guest ELF
(`crates/seal-zk/elf/seal-guest.elf`). `--features sp1` links the vendored
`sp1-sdk 6.0`.

### 8.3 Real r0vm Executor End-to-End

Exercises the compiled guest ELF in the actual `r0vm` v5.0.0-rc.1 executor
and verifies that the journal round-trips through the seal-zk verifier.

```bash
SEAL_RUN_REAL_RISC0=1 cargo test -p seal-zk --features risc0 \
    test_risc0_real_prove_and_verify -- --nocapture
```

**Expected:**

```
real executor proof: 88 bytes, magic = "RZK1"
test risc0::tests::test_risc0_real_prove_and_verify ... ok
```

The proof is an `RZK1`-tagged 80-byte journal (`pre_state_root` ||
`post_state_root` || `block_height` || `tx_count` || `tx_hash[..4]`).
`SEAL_RUN_REAL_RISC0` is a gate so CI stays fast when r0vm is unavailable.

### 8.4 Guest ELF Validation

```bash
cargo test -p seal-zk --features risc0 test_risc0_real_stark_proof -- --nocapture
```

**Expected:** Prints guest ELF size, wrapped `ProgramBinary` size, and the
non-zero image ID computed lazily from the `ProgramBinary` (
`risc0_binfmt::ProgramBinary::compute_image_id`).

### 8.5 Guest Native Tests

```bash
cargo test --manifest-path crates/seal-zk/guest/Cargo.toml
```

**Expected:** 3 tests: `test_state_deterministic`, `test_state_changes`,
`test_order_matters`. These exercise the `InMemoryState` replay logic on
the host (not the riscv32 target), so no risc0 toolchain is required.

### 8.6 Rebuilding the Guest ELF (when `guest/src/main.rs` changes)

See `crates/seal-zk/guest/BUILD.md`. Short form:

```bash
GUEST=/tmp/seal-guest-build
rm -rf $GUEST && cp -r crates/seal-zk/guest $GUEST
rm -rf $GUEST/.cargo $GUEST/Cargo.lock $GUEST/target
cd $GUEST
RUSTC=~/.rustup/toolchains/nightly-aarch64-apple-darwin/bin/rustc \
  ~/.rustup/toolchains/nightly-aarch64-apple-darwin/bin/cargo build --release \
    --target ./riscv32im-risc0-zkvm-elf.json \
    -Zbuild-std=core,alloc \
    -Zbuild-std-features=compiler-builtins-mem \
    -Zjson-target-spec
cp target/riscv32im-risc0-zkvm-elf/release/seal-zk-guest \
   $OLDPWD/crates/seal-zk/elf/seal-guest.elf
```

**Expected:** ~22KB `seal-guest.elf` that starts with `\x7fELF`. Re-run 8.3
to confirm the new ELF runs end-to-end in r0vm.

### 8.7 In-Process LocalProver (real STARK, dev-mode)

Enables the full risc0 `prove` feature and uses `default_prover()` in-process
(no IPC). Requires `--release` and 16MB stack to avoid debug-mode overflow.

```bash
SEAL_RUN_REAL_RISC0=1 RISC0_DEV_MODE=1 RUST_MIN_STACK=16777216 \
  cargo test --release -p seal-zk --features local-prover \
    test_risc0_real_prove_and_verify -- --nocapture
```

**Expected:**
```
WARNING: proving in dev mode. ...
real proof: 361 bytes
  local-prover receipt, verifying via RISC0_DEV_MODE…
test ... ok      (finished in 0.02s)
```

### 8.8 Historical — no longer stubbed

Both of these were listed as stubs in earlier sessions. They are no
longer the case — keeping the note so old transcripts stay readable:

- **Metal GPU kernels**: no stub-patching exists in
  `vendor/risc0-sys-5.0.0-rc.1/build.rs`; the vendored build
  unconditionally compiles kernels on macOS. Full Xcode (not just
  Command Line Tools) + the `MetalToolchain` component is now a
  real prerequisite, not a skip-condition. CPU-only proving
  remains the default path and works without Metal.
  See `crates/seal-zk/METAL.md` for the current state (recursion
  HAL wired via `risc0-zkvm/metal`; segment HAL still CPU/CUDA
  only upstream — a DIY path, not a stub).
- **Guest `out_state` digest**: **done**. `crates/seal-zk/guest/src/main.rs`
  computes the real `Output::digest()` in-guest via `sys_sha_buffer`
  + the tagged-struct (`"risc0.Output"` + `[SHA256(journal), ZERO]`
  + LE u16 = 2). Validated end-to-end by a non-dev-mode prove + verify
  round-trip (any byte-order error would surface as `ClaimDigestMismatch`).
  See `STATUS.md` (row "Real Output digest in guest") and
  `crates/seal-zk/guest/BUILD.md` for detail.

## 9. Merkle B-Tree

### 9.1 Merkle Tests

```bash
cargo test -p seal-merkle
```

**Expected:** 30+ tests: insert/get/delete, sorted order, root hash determinism,
proptest (insert roundtrip, sorted output, persistence), RB-tree.

### 9.2 Proptest Stress

```bash
cargo test -p seal-merkle -- prop --nocapture
```

**Expected:** 10 property tests pass (256 random cases each).

## 10. Formal Verification

### 10.1 TLA+ (requires Apalache)

```bash
# Install: https://apalache-mc.org/

# Wrapper (recommended): runs all 6 bridge safety invariants together.
./scripts/verify-tla-bridge.sh
# or, override the search length:
LENGTH=15 ./scripts/verify-tla-bridge.sh

# Equivalent raw invocation — NB Apalache (0.55.0+) takes a single
# --inv flag with a comma-separated list; repeating --inv makes the
# CLI dump its "Usage … Options ???" help banner.
apalache-mc check --cinit=ConstInit --init=Init --next=Next \
  --inv=MintedLeqLocked,NoDoubleMint,NoMintWithoutLock,BurnedLeqMinted,ReleasedLeqBurned,ReleasedLeqLocked \
  --length=10 formal/tlaplus/MC_SealBridge.tla
```

**Expected:** All 6 invariants verified (no counterexamples).

### 10.2 Lean 4 (requires Lean)

```bash
cd formal/lean && lake build
```

**Expected:** `Build completed successfully`, with warnings about
**7 `sorry`s** in `SealVerify/Basic/MerkleTree.lean` (lines 90, 97,
154, 247, 260, 277, 293). These are pending — three helper lemmas
need Mathlib list-lemma imports (see commit `6247f2e9`) and four
were sorry'd out in commit `88140e57` to unbreak the Lean 4.8.0
build (`delete_idempotent`, `delete_then_insert`, `find_mem`,
`delete_changes_root`). Tracked in `TODOS.md` — do not treat a
clean build as "theorems proven".

### 10.3 Rocq/Coq (requires Coq)

```bash
cd formal/rocq && make
```

**Expected:** 13 theorems proven (Balance + StateMachine).

### 10.4 Kani (requires cargo-kani)

```bash
cargo kani -p seal-crypto
cargo kani -p seal-merkle
cargo kani -p seal-token
cargo kani -p seal-bridge
cargo kani -p seal-threshold
```

**Expected:** All harnesses verified (bounded model checking).

## 11. Fuzzing

### 11.1 Quick Fuzz (30s per target)

```bash
./scripts/fuzz-all.sh 30
```

**Expected:** All 10 targets pass without crashes. See FUZZING.md for details.

### 11.2 Individual Target

`cargo fuzz` internally invokes `rustc` with `-Zsanitizer=address`,
which stable rejects. The bare `rustup run nightly cargo fuzz …` form
is unreliable because cargo-fuzz probes `rustc` without a `+toolchain`
and picks up whichever one is first on `PATH` — typically the stable
proxy. Pinning nightly's bin dir at the front of `PATH` (same trick
the CI scripts use — see `scripts/ci.sh:163-174`) fixes it:

```bash
NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo)")"
PATH="$NIGHTLY_BIN:$PATH" cargo fuzz run fuzz_merkle_ops -- -max_total_time=60
```

**Expected:** No panics found.

> If you see `error: the option 'Z' is only accepted on the nightly
> compiler`, it means the inner `rustc` resolved to stable. The
> `PATH` prefix above prevents that; alternatively `rustup override
> set nightly` in this directory (remember to `unset` afterward).

## 12. Storage

### 12.1 Storage Tests

```bash
cargo test -p seal-storage
```

**Expected:** 18+ tests: block put/get, latest block, persistence.

### 12.2 Persistent Node

```bash
cargo test -p seal-node --lib -- persistent
```

**Expected:** 3 tests: basic persistence, survives restart, empty start.

### 12.3 Storage-lease RPCs (no auth, plain curl)

Storage leases pay for keeping rows alive — every CREATE TABLE / INSERT
charges the owner's balance, and the row is pruneable past
`paid_through_us`. Two read paths:

**Prereq — a seal-node with RPC enabled.** Either start a standalone
host-side node:

```bash
cargo run -p seal-node -- --slots 0 --rpc-port 8545
NODE=http://localhost:8545
```

…or reuse a running stack (§7.5 bridge stack publishes RPC on 8645;
the docker validator stack on 8545 — see §7.6 for the allocation
map):

```bash
NODE=http://localhost:8645   # bridge stack (seal-bridge-node-1)
# NODE=http://localhost:8545 # validator stack or standalone node
```

**Get a real bech32m address to plug in.** There's no
`seal_listAllAddresses` RPC — the state is address-keyed without an
enumerable index. Three ways to obtain one:

```bash
# 1. Generate a fresh keypair (returns sealt1... in --output JSON):
cargo run -p seal-cli -- keygen --output /tmp/probe.json
ADDR=$(jq -r .address /tmp/probe.json)

# 2. Pluck one from any *ByOwner-feeding RPC that already has state
#    (skips silently if the node is fresh — `// empty` makes jq emit
#    nothing when leases[] is empty, so xargs runs zero times):
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_listLeases","params":{}}' \
  | jq -r '.result.leases[0].owner_pubkey_hex // empty' \
  | xargs -I {} cargo run -q -p seal-cli -- hex-to-addr {}

# 3. Convert a validator's public_key_hex (snapshot of the active set):
cargo run -q -p seal-cli -- validators
```

```bash
# All leases on this node. Optional `{"expired_only": true}` filter
# returns only leases past their paid_through. Each entry includes
# table, owner_pubkey_hex, paid_through_us, row_count, byte_size,
# rate, governance_hold, expired.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_listLeases","params":{}}' | jq

# Per-owner gap-closer — every lease the bech32m address pays for,
# decoded via SHA3-256(verifying_key). Saves wallets from hex-matching
# against the global stream.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d "$(jq -cn --arg a "$ADDR" \
        '{jsonrpc:"2.0",id:2,method:"seal_listLeasesByOwner",
          params:{address:$a}}')" | jq

# Friendlier wrapper (same RPC, no JSON-RPC noise):
cargo run -q -p seal-cli -- my-leases --address "$ADDR" --node "$NODE"
```

**Expected:** `{leases: [...], count, now_us}` from the global call;
`{address, leases: [...], count}` from the per-owner one. Both empty
on a fresh node — to populate, first create a table or insert rows
via `cargo run -p seal-cli -- sql "CREATE TABLE …" --node $NODE --key /tmp/probe.json`
(needs balance — see §15.1.1 for the `--dev-faucet` setup).

## 13. Private Tables (at-rest encryption)

Private tables use AES-256-GCM (authenticated encryption) with a 96-bit
random nonce per seal. Keys are wrapped in `EncryptionKey` which zeroes the
key material on drop.

### 13.1 Unit Tests

```bash
cargo test -p seal-node private_tables
```

**Expected:** 9 tests pass:
- `test_register_private_table`
- `test_encrypt_decrypt_roundtrip`
- `test_decrypt_wrong_owner_denied` — access control
- `test_decrypt_wrong_key_fails` — AES-GCM auth tag with wrong key
- `test_tampered_ciphertext_rejected_by_auth_tag` — bit-flip detected
- `test_commitment_verification` — SHA3(nonce || ciphertext) matches metadata
- `test_nonces_are_distinct_per_store` — same plaintext/key ⇒ different nonce
  ⇒ different ciphertext
- `test_table_types`
- `test_tables_by_owner` — owner-filtered listing

### 13.2 Properties Worth Watching

- **Auth tag**: flipping any byte of `ciphertext` must fail decrypt (covered).
- **Nonce uniqueness**: never reuse `(key, nonce)` — the AEAD assumption
  breaks catastrophically under nonce reuse. Random 96-bit nonces give
  ~2^48 safe seals before birthday-bound concerns; rotate keys earlier for
  long-lived tables.
- **Commitment binding**: the on-chain commitment is `SHA3(nonce || ct)`,
  so replaying an old ciphertext under a new nonce breaks the commitment.

## 14. Full CI

### 14.1 Run CI Script

```bash
./scripts/ci.sh
```

**Expected:** Tests pass, clippy clean, format check, no vulnerabilities.

### 14.2 Quick CI

```bash
./scripts/ci.sh quick
```

**Expected:** Tests pass (skips clippy/fmt/audit).

## 15. Token Transfer + Balance (SEAL native coin)

### 15.1 seal_getBalance (no auth)

Start a node with the JSON-RPC server enabled (the default is off —
`--rpc-port 0` disables it):

```bash
cargo run -p seal-node -- --slots 0 --rpc-port 8545
```

In another shell. Generate a real address first — bech32m validation
rejects the genesis-mint labels (`seal1validators`, `seal1treasury`,
etc. — those are internal-state keys, not queryable via this RPC):

```bash
cargo run -p seal-cli -- keygen --output /tmp/probe.json
ADDR=$(jq -r .address /tmp/probe.json)
curl -s -X POST http://localhost:8545 -H 'content-type: application/json' \
  -d "$(jq -cn --arg a "$ADDR" \
        '{jsonrpc:"2.0",id:1,method:"seal_getBalance",params:{address:$a}}')" | jq
```

**Expected:** `{"result":{"address":"sealt1...","balance":N,"total_supply":S}}`
— balance is 0 on a fresh address; `total_supply` is the chain-wide
SEAL supply. (Older revisions of this doc claimed `locked: M`;
that field never made it into the handler — see `handle_get_balance`
in `crates/seal-node/src/rpc.rs`.)

### 15.1.1 seal_faucet (dev-only)

Genesis pre-mints to fixed addresses (`seal1validators`,
`seal1treasury`, …, `crates/seal-node/src/main.rs:237-247`), so a
freshly-created wallet has balance 0 and no way to pay for anything.
Start the node with `--dev-faucet` to enable a signature-less
`seal_faucet` RPC that drips SEAL to any address (capped at 1000 SEAL
per address per rolling 24 h window, enforced server-side):

```bash
# Node:
cargo run -p seal-node -- --slots 0 --rpc-port 8545 --dev-faucet

# Get a real wallet address. `seal keygen` writes the keypair to JSON
# and prints the bech32m address; we pull it out via jq. The literal
# placeholder `sealt1your-address…` will NOT work — it's not a valid
# bech32m string and the node will reject it with
# "-32602 invalid address: bech32m: invalid character".
cargo run -p seal-cli -- keygen --output /tmp/wallet.json
ADDR=$(jq -r .address /tmp/wallet.json)               # e.g. sealt1…

# Drip 100 SEAL (default) to that address. Using an intermediate
# BODY variable avoids a copy-paste trap where the single-quoted jq
# filter and "$ADDR" collapse into one argument and trigger
# "Invalid numeric literal" from jq.
BODY=$(jq -cn --arg a "$ADDR" '{jsonrpc:"2.0",id:1,method:"seal_faucet",params:{address:$a}}')
curl -s -X POST http://localhost:8545 -H 'content-type: application/json' -d "$BODY" | jq

# Confirm:
BODY=$(jq -cn --arg a "$ADDR" '{jsonrpc:"2.0",id:2,method:"seal_getBalance",params:{address:$a}}')
curl -s -X POST http://localhost:8545 -H 'content-type: application/json' -d "$BODY" | jq

# Pure-bash alternative (no second jq call):
#   curl -s -X POST http://localhost:8545 -H 'content-type: application/json' \
#     -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"seal_faucet\",\"params\":{\"address\":\"$ADDR\"}}" | jq

# Or from inside the wallet TUI (faucets self). All amount-taking
# commands (`faucet`, `transfer`, `mint-token`) accept three forms:
#   bare integer       → base units      (50        → 50 base units = 5×10⁻⁸ SEAL)
#   decimal            → SEAL            (50.0      → 50 SEAL = 50×10⁹ base units)
#   trailing `SEAL`    → SEAL            (50 SEAL   → same; case-insensitive, space optional)
> faucet              # 100 SEAL (default drip)
> faucet 500          # 500 base units (probably not what you want)
> faucet 500.0        # 500 SEAL
> faucet 500 SEAL     # 500 SEAL (explicit suffix)
```

Without `--dev-faucet` the method returns
`-32601 seal_faucet disabled (start the node with --dev-faucet)`.
**Never enable this on a shared/public node** — anyone can drain the
faucet by minting to arbitrary addresses up to the cap.

### 15.2 seal_transfer (auth required)

`seal_transfer` (and every mutating RPC listed in `requires_auth`) is
ML-DSA-authenticated. The signed message is not the transfer payload —
it is **`SHA3-256(method || serde_json::to_string(&params))`**
(`crates/seal-node/src/rpc.rs:420-423`), and the request envelope
carries `signature` (hex) + `sender` (verifying-key hex, **not**
`caller` — the server derives the caller's address from `sender` via
`SealAddress::from_verifying_key(&vk, testnet).to_string_encoding()`,
i.e. `bech32m("sealt"|"seal", sha3_256(vk))`. This matches the wallet
side exactly; pass `--mainnet` on `seal-node` to flip the HRP from
`sealt1…` to `seal1…`).

**Amount syntax** (TUI commands `transfer`, `mint-token`, `faucet`):
a bare integer means base units (`50` = 50 × 10⁻⁹ SEAL); a decimal
or a trailing `SEAL` suffix means SEAL (`50.0` or `50 SEAL` = 50 × 10⁹
base units). Up to 9 fractional digits.

Because hand-signing requires ML-DSA, the practical paths are all
wallet-backed. Pick one:

**A. Desktop wallet (§1.1).** `apps/seal-wallet/standalone.html` ships a
native **Send SEAL** card (between Chain and SQL) that drives
`signedRpc('seal_transfer', {to, amount})` — see the card markup at
`standalone.html:125-141` and the `sendSeal()` handler at
`standalone.html:529`. Typical flow once the Electron window is open:

1. **Create New Wallet** (or **Import** a 24-word mnemonic / 64-hex
   seed) — copy the `sealt1…` address shown under "Wallet".
2. **Connect** to `http://localhost:8545`. When both a wallet is
   loaded and the node is connected, the **Send SEAL** card appears
   and starts a 5 s balance poll (`refreshBalances()` at
   `standalone.html:433`).
3. Fund the address from the dev faucet first (path B/C below) — the
   wallet UI has no faucet button.
4. Paste the recipient `sealt1…` into **`seal1… recipient address`**,
   put the amount in **`amount (µSEAL)`** (units are **base units /
   µSEAL** — 1 SEAL = 10⁹ µSEAL; enter `25000000000` to send 25 SEAL),
   click **Send**. The result line shows `Sent N µSEAL → sealt1…
   (tx: …)`; the balance refreshes 1.5 s later (one dev-devnet slot).

The wallet handles the `method || params_json` canonicalization
(`sortKeys` + `JSON.stringify` at `standalone.html:364-376`), the
SHA3-256 hash, the ML-DSA-65 sign over the hash, and the
`sender`/`signature` envelope — all via the `signedRpc` helper at
`standalone.html:370`.

**B. Interactive TUI** (`cargo run -p seal-cli -- wallet`). Typical
session — paste each line at the `>` prompt:

```
> create testnet             # or: import <24 words> / restore <hex-seed>
> address                    # copy this — it's the sender
> connect http://localhost:8545
> faucet                     # drip 100 SEAL (requires node started with --dev-faucet)
> balance                    # sanity: confirm balance > 0 on the node
> transfer sealt1recipient… 25.0
Transferred 25 SEAL (25000000000 base units) to sealt1recipient…
Status: confirmed
> balance                    # sender now 75 SEAL; recipient's balance rises on next block
```

The TUI handles the `method || params_json` canonicalization, the ML-DSA
sign, and the `sender`/`signature` envelope fields — see
`signed_rpc_call` at `crates/seal-cli/src/wallet.rs:1014`.

**C. One-shot from a key file (no TUI).** Native subcommands on
`seal-cli` — each takes `--node` (default `http://localhost:8545`)
and reads the signing key / address from a key file produced by
`seal keygen --output <file>`:

```bash
# (1) create a key file + drip SEAL to its address from the dev faucet
cargo run -p seal-cli -- keygen --output alice.json
cargo run -p seal-cli -- faucet   --node http://localhost:8545 --key alice.json
# optional: --amount "50 SEAL"  (bare int = base units, decimal/SEAL = SEAL)

# (2) read balance without the TUI
cargo run -p seal-cli -- balance  --node http://localhost:8545 --key alice.json

# (3) signed SEAL transfer
cargo run -p seal-cli -- transfer sealt1recipient… 10.5 \
    --node http://localhost:8545 --key alice.json
# "Transferred 10.5 SEAL (10500000000 base units) to sealt1…"

# (for arbitrary signed SQL against real tables, the existing `sql` path
# still works — it just calls `seal_submitSql`, not `seal_transfer`:)
cargo run -p seal-cli -- sql "INSERT INTO my_table VALUES (…)" \
    --node http://localhost:8545 --key alice.json
```

Note: `seal_transfers` is **not** a SQL table — transfers go through
the `seal_transfer` RPC method that the `seal transfer` subcommand
above wraps. Using `seal sql "INSERT INTO seal_transfers …"` will
error with `table not found`.

**D. Raw `curl`** — **wire-format reference only, NOT a copy-paste
transfer.** Path C above already ships the real one-shot flow; use
that to actually move funds. This block exists so you can inspect
the exact envelope the server expects when debugging a custom
client. Because the signature binds `SHA3-256(method || params_json)`
you cannot skip the signer — pasting the snippet unchanged will
produce `-32003 invalid sender public key` (empty `$SENDER_HEX`).

Envelope shape the server accepts (any method in `requires_auth`):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "seal_transfer",
  "params": { "to": "sealt1…", "amount": 100 },
  "signature": "<hex of ML-DSA-65 signature over SHA3-256(method || params_json)>",
  "sender":    "<hex of the ML-DSA-65 verifying key>"
}
```

To actually generate `signature` + `sender` you need an ML-DSA signer
— the `seal-cli` binary already does this. The easiest debug recipe
is: let `seal transfer` build + send the envelope under strace/tcpdump
so you can capture the exact bytes, or write a tiny Rust helper on top
of `seal_crypto::signature::SigningKey` that reads a `key.json` and
prints the signed body. Do **not** hand-canonicalize `params_json` —
`serde_json::to_string(&params)` determines ordering + whitespace, and
any re-formatting (a space after `:`, a key reorder) changes the hash
and trips `-32003 signature verification failed`.

Error codes to know (both reproducible with the snippet above as a
negative test): `-32003 missing 'signature'/'sender'` (envelope
incomplete), `-32003 invalid sender public key` (empty / malformed
hex), `-32003 signature verification failed` (canonicalization
mismatch — almost always whitespace or key ordering in `params_json`).

**Expected:** transfer recorded in a pending transaction; sender's
balance decreases and recipient's increases after the next block.
Confirm with `seal_getBalance` on both sides (§15.1).

## 16. Custom Tokens (SPL-/Stellar-asset-style)

Requires a node with RPC enabled and `--dev-faucet` (see §15.1). All
mutating RPCs (`seal_createToken`, `seal_mintToken`,
`seal_transferToken`, `seal_burnToken`, `seal_setTransferFee`,
`seal_freezeAccount`, `seal_setTokenFrozen`, etc.) are in
`requires_auth()` (`crates/seal-node/src/rpc.rs`) and need an ML-DSA
`signature` over `SHA3-256(method || params_json)` plus the verifying
key as `sender` — same envelope as §15.2. The `seal-cli` subcommands
below build that envelope for you; drive the flow from the CLI, not
hand-crafted curl (hand-canonicalizing `params_json` will reach
`-32003 signature verification failed` trivially).

### 16.0 Scenario setup (run once for §16.1–§16.3)

Each subsection below assumes these three key files and shell
variables. Run this block in a fresh shell before §16.1:

```bash
export NODE=http://localhost:8545

# Three identities: creator (mints), alice (transfers + burns),
# bob (will get frozen). Addresses are computed from the keys; we
# capture them into shell vars so every later snippet substitutes
# real bech32m strings instead of `sealt1alice…` placeholders.
cargo run -p seal-cli -- keygen --output creator.json
cargo run -p seal-cli -- keygen --output alice.json
cargo run -p seal-cli -- keygen --output bob.json

export CREATOR_ADDR=$(jq -r .address creator.json)
export ALICE_ADDR=$(jq -r .address alice.json)
export BOB_ADDR=$(jq -r .address bob.json)
echo "CREATOR=$CREATOR_ADDR"
echo "ALICE  =$ALICE_ADDR"
echo "BOB    =$BOB_ADDR"

# Each address needs SEAL to cover any future native gas + so the
# faucet rate-limit doesn't trip when we hit it three times in a row.
# (Drop the alice / bob faucets if you only want to run §16.1 reads.)
cargo run -p seal-cli -- faucet --node $NODE --key creator.json --amount '20 SEAL'
cargo run -p seal-cli -- faucet --node $NODE --key alice.json   --amount '20 SEAL'
cargo run -p seal-cli -- faucet --node $NODE --key bob.json     --amount '20 SEAL'

# Sanity-fail loudly if any variable is empty (most common cause:
# you opened a new terminal and skipped §16.0, so `$ALICE_ADDR`
# expands to `''` and mint-token rejects with
# `-32602 invalid 'to' address: invalid address: bech32m: no separator found`).
: "${CREATOR_ADDR:?CREATOR_ADDR is empty — re-run §16.0 in this shell}"
: "${ALICE_ADDR:?ALICE_ADDR is empty — re-run §16.0 in this shell}"
: "${BOB_ADDR:?BOB_ADDR is empty — re-run §16.0 in this shell}"
```

**Already in a new shell?** If `echo $ALICE_ADDR` is empty but the
key files still exist in the cwd, you don't need to re-`keygen` —
just re-derive the vars:

```bash
export NODE=http://localhost:8545
export CREATOR_ADDR=$(jq -r .address creator.json)
export ALICE_ADDR=$(jq -r .address alice.json)
export BOB_ADDR=$(jq -r .address bob.json)
```

A bare integer in `--amount` means base units (10⁻⁹ SEAL); a decimal
or trailing ` SEAL` means whole SEAL. Same convention applies to
`mint-token` and `transfer-token` below — there a bare int is **base
units of the token**, a decimal is **whole token units**.

### 16.1 Create → mint → transfer → query

Continues from §16.0 — needs `creator.json` / `alice.json` / `bob.json`
in the cwd and the `NODE` / `CREATOR_ADDR` / `ALICE_ADDR` / `BOB_ADDR`
shell vars set. The guard below short-circuits the rest of the
section with a clear message if you opened a new terminal — without
it, an unset `$ALICE_ADDR` silently expands to `''` and
`mint-token` rejects with the misleading `-32602 invalid 'to'
address: invalid address: bech32m: no separator found`.

```bash
: "${ALICE_ADDR:?ALICE_ADDR unset — see §16.0 (rehydrate block) to restore from key files}"
: "${BOB_ADDR:?BOB_ADDR unset — see §16.0 (rehydrate block) to restore from key files}"

# (1) Creator creates GOLD with 9 decimals and a 1 000 000-unit cap.
#     create-token sets creator = mint_authority = freeze_authority =
#     fee_authority by default. transfer_fee_bps starts at 0.
cargo run -p seal-cli -- create-token \
    --node $NODE --key creator.json \
    --symbol GOLD --name 'Gold Coin' --decimals 9 --max-supply 1000000

# (2) Creator mints 500 GOLD to Alice and 200 GOLD to Bob. `--amount 500`
#     here = 500 base units (= 500 × 10⁻⁹ GOLD); pass `500.0` for whole
#     GOLD units.
cargo run -p seal-cli -- mint-token \
    --node $NODE --key creator.json \
    --symbol GOLD --to "$ALICE_ADDR" --amount 500
cargo run -p seal-cli -- mint-token \
    --node $NODE --key creator.json \
    --symbol GOLD --to "$BOB_ADDR"   --amount 200

# (3) Read paths (no auth, safe to curl):
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"seal_getTokenBalance\",
       \"params\":{\"symbol\":\"GOLD\",\"address\":\"$ALICE_ADDR\"}}" | jq
# → {"address":"…","balance":500,"symbol":"GOLD","total_supply":700}

curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_listTokens","params":{}}' | jq
# → tokens[*] includes {symbol:"GOLD", transfer_fee_bps:0, total_supply:700,
#                       creator, mint_authority, fee_authority, freeze_authority, …}

# (4) Alice → Bob, signed `seal_transferToken` from the flat CLI.
cargo run -p seal-cli -- transfer-token \
    --node $NODE --key alice.json \
    --symbol GOLD --to "$BOB_ADDR" --amount 100
# → "Transferred 100 GOLD to sealt1…"

# (5) Negative test: a non-creator can't mint (mint_authority gate).
cargo run -p seal-cli -- mint-token \
    --node $NODE --key alice.json \
    --symbol GOLD --to "$BOB_ADDR" --amount 50
# → "mint-token failed: RPC error (-32000): not mint authority"
```

**Expected:** create succeeds; both mints succeed; `listTokens` shows
`total_supply: 700, transfer_fee_bps: 0`; Alice→Bob transfer lands
(Alice 400 / Bob 300 after the block); non-creator mint rejects with
`-32000 not mint authority`. GOLD uses the same 9-decimal convention
as SEAL.

### 16.2 Transfer fees (landed 2026-04-19; CLI subcommand 2026-05-08; fee_authority 2026-05-09)

`seal_setTransferFee` is `fee_authority`-gated, accepts 0–10 000 bps,
and is exposed as `seal set-transfer-fee`. The fee_authority defaults
to the creator at `create-token` time, is rotateable via
`seal_setFeeAuthority` / `seal set-fee-authority`, and is permanently
clearable via `seal_renounceFeeAuthority` / `seal renounce-fee-authority`
(same shape as `mint_authority` / `freeze_authority`).

**Where the fees land.** Every token also carries a `fee_recipient`
field (`crates/seal-token/src/tokens.rs:41`) that defaults to the
**creator** at create-token time (line 87). On each `seal_transferToken`
where `fee_bps > 0` **and** `from != fee_recipient`
(`tokens.rs:154-160`):

- `fee = amount × fee_bps / 10_000` (truncating integer division)
- `net = amount − fee` → debited from sender, credited to the `to` address
- `fee` → debited from sender, credited to `fee_recipient`

**Self-exemption:** when the `fee_recipient` itself is the sender, no
fee is taken — the `from != fee_recipient` guard makes the transfer
a no-op for the fee. Rotate the destination with
`seal set-fee-recipient` / `seal_setFeeRecipient` (same `fee_authority`
gate as `set-transfer-fee`; address is bech32m-validated, so an empty
or malformed string is rejected at the RPC layer). `seal_listTokens`
and `seal_getToken` surface the live `fee_recipient` alongside
`transfer_fee_bps` and `fee_authority`, so you can read it any time.

Continues from §16.1 — `$CREATOR_ADDR`, `$ALICE_ADDR`, `$BOB_ADDR`,
`creator.json`, `alice.json`, `bob.json`, and the GOLD token must exist.

```bash
: "${ALICE_ADDR:?ALICE_ADDR unset — see §16.0 (rehydrate block) to restore from key files}"
: "${BOB_ADDR:?BOB_ADDR unset — see §16.0 (rehydrate block) to restore from key files}"

# (1) Read the current fee — starts at 0 bps for a freshly-created
#     token. No auth; works any time.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getTransferFee",
       "params":{"symbol":"GOLD"}}' | jq
# → {"symbol":"GOLD","fee_bps":0}

# (2) Creator (current fee_authority) sets the fee to 100 bps (1%).
cargo run -p seal-cli -- set-transfer-fee \
    --symbol GOLD --fee-bps 100 \
    --node $NODE --key creator.json
# → "Set transfer fee for GOLD to 100 bps (1%)"

# (3) Re-read to confirm.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_getTransferFee",
       "params":{"symbol":"GOLD"}}' | jq
# → {"symbol":"GOLD","fee_bps":100}

# (4) Negative test: Alice tries to set the fee — rejected, she's
#     not the fee_authority yet.
cargo run -p seal-cli -- set-transfer-fee \
    --symbol GOLD --fee-bps 50 \
    --node $NODE --key alice.json
# → "set-transfer-fee failed: RPC error (-32000): not fee authority"

# (5) Rotate the fee_authority from Creator → Alice. Caller must be
#     the *current* fee_authority (= creator), so sign with creator.json.
#     Note: --new-authority takes a bech32m address with the node's
#     HRP. On a default dev node that's `sealt1…` (testnet); only
#     pass `seal1…` to a node started with `--mainnet`.
cargo run -p seal-cli -- set-fee-authority \
    --symbol GOLD --new-authority "$ALICE_ADDR" \
    --node $NODE --key creator.json
# → "set-fee-authority: fee authority on GOLD → sealt1…"

# (6) Now Creator is no longer the fee_authority and is rejected; Alice
#     can set it instead.
cargo run -p seal-cli -- set-transfer-fee \
    --symbol GOLD --fee-bps 200 \
    --node $NODE --key creator.json
# → "set-transfer-fee failed: RPC error (-32000): not fee authority"
cargo run -p seal-cli -- set-transfer-fee \
    --symbol GOLD --fee-bps 200 \
    --node $NODE --key alice.json
# → "Set transfer fee for GOLD to 200 bps (2%)"

# (7) Read where the fee currently routes — defaults to creator
#     since we never moved it. `seal_listTokens` is the canonical
#     read; `seal_getToken` carries the same fields for a single
#     symbol.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"seal_listTokens","params":{}}' \
  | jq '.result.tokens[] | select(.symbol=="GOLD") | {symbol, fee_recipient, transfer_fee_bps, fee_authority}'
# → fee_recipient is $CREATOR_ADDR, transfer_fee_bps:200, fee_authority is $ALICE_ADDR

# (8) Rotate the fee_recipient from Creator → Bob. Caller must be the
#     current fee_authority (= Alice). After this, every fee debit on
#     a non-self GOLD transfer credits Bob, not Creator.
cargo run -p seal-cli -- set-fee-recipient \
    --symbol GOLD --new-recipient "$BOB_ADDR" \
    --node $NODE --key alice.json
# → "set-fee-recipient: GOLD fees now route to sealt1…(bob)"

# (9) Read back to confirm.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":4,"method":"seal_listTokens","params":{}}' \
  | jq '.result.tokens[] | select(.symbol=="GOLD") | .fee_recipient'
# → "sealt1…(bob)"

# (10) Negative tests for set-fee-recipient:
#      (a) empty / malformed new-recipient is rejected at the bech32m
#          layer before the handler runs.
cargo run -p seal-cli -- rpc \
    --node $NODE --key alice.json --method seal_setFeeRecipient \
    --params '{"symbol":"GOLD","new_recipient":""}'
# → "RPC error (-32602): invalid 'new_recipient': invalid address: bech32m: no separator found"
#      (b) non-fee_authority is rejected. Creator no longer holds it.
cargo run -p seal-cli -- set-fee-recipient \
    --symbol GOLD --new-recipient "$CREATOR_ADDR" \
    --node $NODE --key creator.json
# → "set-fee-recipient failed: RPC error (-32000): not fee authority"

# (11) Demonstrate the split. With fee_bps=200 and fee_recipient=bob,
#      `alice → creator 100` charges fee=2, net=98, so:
#        alice    -100   (debit)
#        creator   +98   (net)
#        bob        +2   (fee)
#      Creator has no GOLD ledger entry (we only minted to alice/bob
#      in §16.1), so the recipient-policy guard fires unless we opt in
#      with `--confirm-new-recipient`. Without the flag you'd see:
#        "RPC error (-32007): recipient sealt1…(creator) is a new
#         account with no prior ledger entry; re-submit with
#         confirm_new_recipient=true to acknowledge…"
bal_of() {
  curl -s -X POST $NODE -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"seal_getTokenBalance\",\"params\":{\"symbol\":\"GOLD\",\"address\":\"$1\"}}" | jq -r '.result.balance // 0'
}
echo "pre  alice/creator/bob: $(bal_of $ALICE_ADDR)/$(bal_of $CREATOR_ADDR)/$(bal_of $BOB_ADDR)"
cargo run -p seal-cli -- transfer-token \
    --node $NODE --key alice.json \
    --symbol GOLD --to "$CREATOR_ADDR" --amount 100 \
    --confirm-new-recipient
echo "post alice/creator/bob: $(bal_of $ALICE_ADDR)/$(bal_of $CREATOR_ADDR)/$(bal_of $BOB_ADDR)"
# → diffs: alice -100, creator +98, bob +2

# (12) Self-exemption — Bob (= fee_recipient) initiating a transfer
#      pays no fee. Sending 50 GOLD bob → alice moves exactly 50, not 49.
echo "pre  alice/bob: $(bal_of $ALICE_ADDR)/$(bal_of $BOB_ADDR)"
cargo run -p seal-cli -- transfer-token \
    --node $NODE --key bob.json \
    --symbol GOLD --to "$ALICE_ADDR" --amount 50
echo "post alice/bob: $(bal_of $ALICE_ADDR)/$(bal_of $BOB_ADDR)"
# → diffs: alice +50, bob -50 (no third leg — `from == fee_recipient` skips the fee branch)

# (13) Out-of-range — fee_bps > 10 000 (100 %) is always rejected.
cargo run -p seal-cli -- set-transfer-fee \
    --symbol GOLD --fee-bps 10001 \
    --node $NODE --key alice.json
# → "set-transfer-fee failed: RPC error (-32000): fee cannot exceed 100%"

# (14) Permanently lock the fee AND the recipient. Caller is the
#      *current* fee_authority (= Alice). After this, both
#      set-transfer-fee and set-fee-recipient reject regardless of
#      caller — the same gate guards both fields.
cargo run -p seal-cli -- renounce-fee-authority \
    --symbol GOLD --node $NODE --key alice.json
# → "renounce-fee-authority: fee authority on GOLD renounced (terminal)"

# (15) Post-renounce: nobody can change the fee or the recipient.
cargo run -p seal-cli -- set-transfer-fee \
    --symbol GOLD --fee-bps 0 \
    --node $NODE --key alice.json
# → "set-transfer-fee failed: RPC error (-32000): not fee authority"
cargo run -p seal-cli -- set-fee-recipient \
    --symbol GOLD --new-recipient "$ALICE_ADDR" \
    --node $NODE --key alice.json
# → "set-fee-recipient failed: RPC error (-32000): not fee authority"
```

**Expected:** the `fee_bps` goes 0 → 100 → 200 in the read calls;
fee_authority rotates creator → alice; fee_recipient rotates creator
→ bob (step 8) and is visible in `seal_listTokens` (step 9); the
two split demos (step 11) and self-exemption check (step 12) move
balances by the documented amounts; both the out-of-range check and
the post-renounce gate (covering set-transfer-fee **and**
set-fee-recipient) fire as `-32000 …`. Every subsequent
`seal_transferToken` debits the locked fee from the sender and
credits the locked `fee_recipient`.

### 16.3 Burn + per-account freeze + global freeze

Continues from §16.1 (and §16.2 if you ran it — the renounced fee
authority does not block this section). Uses `creator.json`,
`alice.json`, `bob.json` and the `$ALICE_ADDR` / `$BOB_ADDR` vars.

```bash
: "${ALICE_ADDR:?ALICE_ADDR unset — see §16.0 (rehydrate block) to restore from key files}"
: "${BOB_ADDR:?BOB_ADDR unset — see §16.0 (rehydrate block) to restore from key files}"

# (1) Alice burns 100 base units of GOLD she holds. Auth required;
#     caller's own balance shrinks and total_supply drops by the
#     same amount.
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_burnToken \
    --params "{\"symbol\":\"GOLD\",\"amount\":100}"
# → {"symbol":"GOLD","from":"sealt1…","amount":100,
#    "total_supply":600,"status":"burned"}

# (2) Creator (freeze_authority, by default) freezes Bob's account
#     on GOLD. Per-account freeze blocks Bob from *initiating* a
#     transfer; he can still be the recipient.
cargo run -p seal-cli -- rpc --node $NODE --key creator.json \
    --method seal_freezeAccount \
    --params "{\"symbol\":\"GOLD\",\"address\":\"$BOB_ADDR\"}"
# → {"symbol":"GOLD","address":"sealt1…","status":"frozen"}

# (3) Read: confirm Bob is frozen on GOLD.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"seal_isFrozen\",
       \"params\":{\"symbol\":\"GOLD\",\"address\":\"$BOB_ADDR\"}}" | jq
# → {"symbol":"GOLD","address":"sealt1…","frozen":true}

# (4) Bob tries to transfer — rejected by the freeze gate.
cargo run -p seal-cli -- transfer-token \
    --node $NODE --key bob.json \
    --symbol GOLD --to "$ALICE_ADDR" --amount 10
# → "transfer-token failed: RPC error (-32000): sender account is frozen"

# (5) Enumerate every frozen account for GOLD (lex-sorted, capped at
#     10 000).
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_listFrozenAccounts",
       "params":{"symbol":"GOLD"}}' | jq
# → {"symbol":"GOLD","frozen":["sealt1…(bob)"],"count":1,"truncated":false}

# (6) Inverse view — every token symbol on which $BOB_ADDR is frozen.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"seal_listFrozenSymbolsForAddress\",
       \"params\":{\"address\":\"$BOB_ADDR\"}}" | jq
# → {"address":"sealt1…","symbols":["GOLD"],"count":1}

# (7) Global freeze: when true, *every* transfer of GOLD rejects,
#     regardless of per-account state. Same freeze_authority gate.
cargo run -p seal-cli -- rpc --node $NODE --key creator.json \
    --method seal_setTokenFrozen \
    --params '{"symbol":"GOLD","frozen":true}'
# → {"symbol":"GOLD","status":"globally_frozen"}

# (8) Now even Alice (who is *not* per-account frozen) cannot transfer.
cargo run -p seal-cli -- transfer-token \
    --node $NODE --key alice.json \
    --symbol GOLD --to "$BOB_ADDR" --amount 5
# → "transfer-token failed: RPC error (-32000): token is globally frozen"

# (9) Negative test: a non-freeze_authority can't toggle either gate.
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_freezeAccount \
    --params "{\"symbol\":\"GOLD\",\"address\":\"$ALICE_ADDR\"}"
# → "RPC error (-32000): not freeze authority"

# (10) Restore: unfreeze Bob, then clear the global freeze.
cargo run -p seal-cli -- rpc --node $NODE --key creator.json \
    --method seal_unfreezeAccount \
    --params "{\"symbol\":\"GOLD\",\"address\":\"$BOB_ADDR\"}"
# → {"symbol":"GOLD","address":"sealt1…","status":"unfrozen"}
cargo run -p seal-cli -- rpc --node $NODE --key creator.json \
    --method seal_setTokenFrozen \
    --params '{"symbol":"GOLD","frozen":false}'
# → {"symbol":"GOLD","status":"globally_unfrozen"}
```

**Expected outputs are inline above.** Freeze authority can be
rotated (`seal_setFreezeAuthority`) and permanently locked
(`seal_renounceFreezeAuthority`) using the exact same envelope as
the fee-authority commands in §16.2 — substitute method name and
`fee` → `freeze` in the `--method` flag.

## 17. Bridge JSON-RPC surface (landed 2026-04-19 batch)

All bridge RPCs assume a node is running with RPC enabled (see §15.1).

**Do I need extra config?** Yes — a freshly-started node has **zero
observers registered** (`BridgeObserverSet::new()` at
`crates/seal-node/src/rpc.rs:346`), so `seal_listBridgeObservers`
returns `{"count": 0}`, `seal_pollBridges` sees nothing, and
`seal_getBridgeDeposits` is empty. Two paths to activity:

- **Manual**: register observers below (`seal_addBridgeObserver`), but
  they only observe if the target chain is reachable on the URL you
  provide. Useful for wire-format debugging, not a full round-trip.
- **Full stack (local)**: run `./scripts/bridge-e2e.sh` — Docker-composed
  solana-test-validator + Stellar quickstart + 3 Seal nodes, with
  the bridge programs deployed on both sides and a scripted
  lock→mint→burn→unlock that populates the endpoints in §17.1–3
  with real data. Prerequisites are checked via
  `./scripts/bridge-e2e.sh check`.
- **Full stack (public testnet)**: see
  [`docs/BRIDGE-TESTNET.md`](docs/BRIDGE-TESTNET.md) for the
  Solana devnet + Stellar testnet runbook (deploy contracts,
  fund the authority, wire program IDs into seal-node). The
  companion `scripts/bridge-testnet-demo.sh` automates the
  round-trip — gated behind `BRIDGE_TESTNET_DEMO_LIVE=1` so it
  never fires from CI (testnet airdrop quotas would be burned).

**Auth.** `seal_bridgeWithdraw` is in `requires_auth()`, so it always
needs an ML-DSA signature (same envelope as a token transfer). The
bootstrap endpoints — `seal_addBridgeObserver`,
`seal_bridgeCouncilAdd` / `Remove`, `seal_bridgePauseChain` /
`UnpauseChain`, `seal_bridgeRotateCommitteeKey` — are **admin-gated
via `requires_admin_auth()`** (`crates/seal-node/src/rpc.rs:682`).
The gate has two modes:

- **Open mode (default).** When the node is started without
  `--admin-address`, `admin_addresses` is empty and these RPCs
  accept **unauthenticated `curl` calls** (`is_admin()` returns
  true for everyone — `rpc.rs:698`). This preserves the
  `scripts/bridge-e2e.sh` one-box bootstrap flow but means **anyone
  who can reach the RPC port can register an arbitrary observer**
  (steering deposit accounting), seat a council member, or pause a
  chain. Do not run a shared / public-internet node like this.
- **Admin mode.** Start the node with one or more
  `--admin-address sealt1…` flags (repeatable; or place the set in
  the genesis config — `crates/seal-node/src/main.rs:95`). The gate
  flips on: every admin-gated request must (1) carry a valid
  ML-DSA signature over `SHA3-256(method || params_json)` (same
  envelope as §15.2), and (2) have the **caller's derived address
  present in the admin set**, else the request fails with
  `-32004 … requires admin authorization (address … not in admin
  set)`. For M-of-N operator multisig (P8 / §4.3), additionally
  pass `--admin-threshold n` at startup; each admin-gated request
  then needs `n − 1` cosigners in an `admin_signatures: [{sender,
  signature}, …]` param over the same payload with that field
  stripped — see `verify_admin_multisig()` at `rpc.rs:711`.

**Recommendation:** start the node with at least one
`--admin-address sealt1…` even on a dev box, so the signed
admin-mode form below is exercised by default and the unsigned
curl form stays a one-box convenience path, not the muscle memory.
On `--mainnet` without any admin address the node prints an
explicit warning at startup (`main.rs:96-100`).

The read-only calls are plain `curl`; signed writes use the generic
`seal rpc --method <M> --params <JSON> --key <file>` passthrough
(`crates/seal-cli/src/main.rs` `run_rpc`), which ML-DSA-signs the
request using the same `sign_request` path as `seal transfer`.

Prerequisites for the examples below:

```bash
# Key file for the withdrawal signer.
cargo run -p seal-cli -- keygen --output treasury.json
TREASURY_ADDR=$(jq -r .address treasury.json)
NODE=http://localhost:8545
```

### 17.1 Observer management + status

**Before registering anything**, confirm which auth mode the node is
running in:

```bash
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_listAdminAddresses","params":{}}' | jq
# → {"addresses":[...], "count":N, "mode":"open"|"gated", "threshold":t}
# `mode:"open"` (count 0) → curl flow (b) below applies, anyone can
# register an observer. `mode:"gated"` → curl flow (b) fails, you
# must use the signed flow (a).
```

Read-only status and listings (always unauthenticated, plain `curl`):

```bash
# List registered observers (starts at {"count": 0} on a fresh node)
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_listBridgeObservers","params":{}}' | jq

# Poll all registered observers once. Returns counters:
#   observed   = deposits returned by *this* poll (NOT observer count
#                — names is misleading; verified in `rpc.rs:4045`)
#   new        = deposits newly recorded by the bridge manager
#   duplicate  = deposits already known (cursor advanced past them)
#   processed  = deposits that advanced to wrapped-balance mint
# Once an observer's cursor has caught up, subsequent polls return
# `observed:0` even though the deposit IS in seal_getBridgeDeposits;
# don't read `observed:0` as "no observers registered".
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_pollBridges","params":{}}' | jq

# Snapshot of invariant / per-token locked+minted / paused chains
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"seal_getBridgeStatus","params":{}}' | jq

# Deposits observed on a specific chain (empty until observers see one)
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":4,"method":"seal_getBridgeDeposits","params":{"chain":"Solana"}}' | jq

# Wrapped-token balance for a Seal address. NOTE `token` is REQUIRED —
# one of "WSOL", "WXLM", "WUSDC". Omitting it returns -32602
# "missing 'token' param".
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d "$(jq -cn --arg a "$TREASURY_ADDR" \
       '{jsonrpc:"2.0",id:5,method:"seal_getBridgeWrappedBalance",params:{address:$a,token:"WSOL"}}')" | jq
```

**Register an observer.** Two flows depending on how the node was
started — see the §17 "Auth" paragraph for context.
`scripts/bridge-e2e.sh` deploys the seal-bridge Anchor program and
prints its id; substitute that for `<deployed-program-id>` (Solana)
and the deployed Soroban contract id for `<soroban-contract-id>`
(Stellar). `usdc_mint` (Solana, optional base58 SPL mint): when a
`LockEvent`'s mint matches, the deposit routes to WUSDC; otherwise
to WSOL. The canonical devnet USDC mint is
`Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr` — omit the field if
you only operate the SOL flow.

**(a) Admin mode (recommended).** Node was started with
`--admin-address sealt1…` matching the address of `admin.json`. The
RPC carries an ML-DSA signature and the admin-membership check
fires server-side.

```bash
# Set up an admin signer once. The address must match (or already
# be in) the node's --admin-address set; otherwise every call below
# returns -32004 "requires admin authorization".
cargo run -p seal-cli -- keygen --output admin.json
ADMIN_ADDR=$(jq -r .address admin.json)
echo "Start the node with: --admin-address $ADMIN_ADDR"

# Solana observer
cargo run -p seal-cli -- rpc --node $NODE --key admin.json \
    --method seal_addBridgeObserver \
    --params '{"chain":"Solana","rpc_url":"http://127.0.0.1:8899","program_id":"<deployed-program-id>","usdc_mint":"Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr"}'

# Stellar observer
cargo run -p seal-cli -- rpc --node $NODE --key admin.json \
    --method seal_addBridgeObserver \
    --params '{"chain":"Stellar","horizon_url":"http://127.0.0.1:8000","contract_id":"<soroban-contract-id>"}'
```

Expected failure if `admin.json` is not in the admin set:
`RPC error (-32004): seal_addBridgeObserver requires admin
authorization (address sealt1… not in admin set)`. For
`--admin-threshold ≥ 2`, the single `seal rpc` form is **not
sufficient** — you need an external helper to collect the
cosigners' signatures and stitch them into an `admin_signatures`
array on the payload (see `verify_admin_multisig` at
`rpc.rs:711`). The `seal rpc` subcommand doesn't ship that
multi-key flow today; track it as a follow-up if you need M-of-N
on a shared box.

**(b) Open mode (single-box dev only).** Node was started without
`--admin-address`. The RPC accepts plain unauthenticated `curl`.
**Anyone with RPC access can register an observer**, so don't run
this configuration on a shared / public-internet node — switch
flow (a) by restarting with `--admin-address sealt1…`.

```bash
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_addBridgeObserver",
       "params":{"chain":"Solana","rpc_url":"http://127.0.0.1:8899","program_id":"<deployed-program-id>","usdc_mint":"Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr"}}' | jq

curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_addBridgeObserver",
       "params":{"chain":"Stellar","horizon_url":"http://127.0.0.1:8000","contract_id":"<soroban-contract-id>"}}' | jq
```

**Per-owner gap-closer reads** (no auth, all object-param). Each
returns the slice scoped to one address — useful for wallets asking
"what crossed for me?" without filtering the global stream
client-side:

```bash
# Inbound: every deposit whose seal_address (the on-Seal recipient) is $ADDR.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d "$(jq -cn --arg a "$TREASURY_ADDR" \
       '{jsonrpc:"2.0",id:1,method:"seal_listBridgeDepositsByRecipient",params:{address:$a}}')" | jq

# Outbound: every withdrawal $ADDR signed (burner-on-Seal).
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d "$(jq -cn --arg a "$TREASURY_ADDR" \
       '{jsonrpc:"2.0",id:2,method:"seal_listBridgeWithdrawalsByInitiator",params:{address:$a}}')" | jq

# Holdings: $ADDR's wrapped balance for every token at once
# (avoids one getBridgeWrappedBalance call per token).
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d "$(jq -cn --arg a "$TREASURY_ADDR" \
       '{jsonrpc:"2.0",id:3,method:"seal_listBridgeWrappedBalances",params:{address:$a}}')" | jq
```

### 17.2 Withdraw (auth required — the only signed bridge RPC today)

`seal_bridgeWithdraw` is the one bridge method in `requires_auth`, so
the caller's ML-DSA signature identifies whose wrapped balance to
burn. Params:
`{dest_chain, dest_address, token, amount}` — **`token` is required**
and `dest_address` is the *destination-chain* pubkey (Solana
ed25519 base58 / Stellar G-address), not a Seal address.

```bash
# Typed CLI (preferred — pairs with bridge-list-withdrawals /
# bridge-get-withdrawal below):
seal bridge-withdraw \
    --dest-chain Solana \
    --dest-address <solana-ed25519-pubkey> \
    --token WSOL \
    --amount 1000000 \
    --node $NODE --key treasury.json
# → Burned 1000000 WSOL → Solana:<pubkey>
#   withdrawal_id: wd_sol_3
#   Next: seal bridge-get-withdrawal --withdrawal-id wd_sol_3 ...

# Generic-RPC equivalent (same request shape, manual envelope):
seal rpc --node $NODE --key treasury.json \
  --method seal_bridgeWithdraw \
  --params '{"dest_chain":"Solana","dest_address":"<solana-ed25519-pubkey>","token":"WSOL","amount":1000000}'
# → {"withdrawal_id":"wd_sol_3", "caller":"sealt1…"}
```

**Expected:** `minted_on_seal <= locked_on_source` invariant always
holds; withdrawals above the caller's wrapped balance fail; to a
paused chain fail with `ChainPaused`. Confirm via `seal_getBridgeStatus`
(§17.1) — the invariant and `paused_chains` are both surfaced there.

**Reverse-claim handoff (committee signature pickup):** the
on-chain `unlock_tokens(amount, nonce, signature)` ix consumes
three fields the burn produced. Fetch them via the typed CLI or
the unauth RPCs:

```bash
# Typed (one-liner):
seal bridge-get-withdrawal --withdrawal-id wd_sol_3 --node $NODE

# All pending withdrawals (optional chain filter):
seal bridge-list-withdrawals --chain Solana --node $NODE

# Generic-RPC equivalents:
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getBridgeWithdrawal",
       "params":{"withdrawal_id":"wd_sol_3"}}' | jq

# Global list with optional `chain` filter. Same envelope per
# entry. Both named ({chain:"Solana"}) and positional (["Solana"])
# param shapes are accepted.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_listBridgeWithdrawals",
       "params":{"chain":"Solana"}}' | jq
```

Each record carries
`{id, nonce, dest_chain, dest_address, seal_address, amount, token,
committee_signature_hex, executed}`. `committee_signature_hex` is
`null` until a committee signature is attached — populated
immediately on burn when seal-node was started with
`--bridge-committee-key` (single-validator testnet path), or
later via the multi-validator Ringtail aggregate path.

For the canonical bytes the on-chain `verify_committee_sig`
recomputes:

| Chain | Payload | Output |
|---|---|---|
| Solana | `recipient_pubkey(32) ‖ amount_le(8) ‖ nonce_le(8) ‖ "seal-bridge-solana-v1"` | HMAC-SHA-256 over `committee_key` |
| Stellar | `Address::to_xdr(32–44 bytes) ‖ amount_be_16 ‖ nonce_be_8 ‖ "seal-bridge-stellar-v1"` | HMAC-SHA-256 over `committee_key` |

`committee_key` is set per seal-node via `--bridge-committee-key
<64-hex-chars>` and MUST match the value the on-chain bridge program
was initialized with (Solana `BridgeState::committee_key`, Stellar
`brkey` storage slot). Rotate via the on-chain `rotate_committee_key`
ix + the host-side `seal_bridgeRotateCommitteeKey` RPC
(council-gated; persists atomically to
`<data_dir>/bridge-committee-key.hex` so seal-node restart no longer
reverts the rotation). See §17.3 for the host-side recipe.

**Claim the unlock on the destination chain.** Once
`committee_signature_hex` is populated, hand the (amount, nonce,
signature) tuple to the destination-chain unlock ix. The Anchor /
Soroban programs recompute the canonical bytes from the table
above and accept iff the bytes match.

```bash
# Solana — `anchor run unlock-tokens` (wraps the Solana ix; uses
# the deployer keypair as authority). recipient_ata + vault_ata are
# the SPL token accounts for the unlock recipient and the bridge
# vault PDA respectively.
JSON=$(seal bridge-get-withdrawal --withdrawal-id wd_sol_3 --node $NODE)
NONCE=$(echo "$JSON" | jq -r '.withdrawal.nonce')
SIG=$(echo "$JSON" | jq -r '.withdrawal.committee_signature_hex')
cd bridges/solana
anchor run unlock-tokens -- \
  --amount 1000000 --nonce "$NONCE" --signature "$SIG" \
  --recipient <solana-ed25519-pubkey> \
  --recipient-ata <spl-token-account> \
  --vault-ata $(anchor run derive-vault-ata -- --mint <mint> | awk '/vault ATA:/ {print $3}') \
  --authority <authority-pubkey>

# Stellar — `stellar contract invoke -- unlock_xlm`. recipient is the
# G-address that receives the released XLM; proof = committee_signature_hex.
stellar contract invoke --id "$(cat bridges/.stellar-testnet-contract-id)" \
  --source seal-bridge-deployer --network testnet \
  -- unlock_xlm \
  --recipient <G-address> --amount 1000000 \
  --nonce "$NONCE" --proof "$SIG"
```

**Expected:** Anchor rejects with `InvalidSignature` if any byte
of the canonical payload disagrees (most common cause: pubkey-vs-
ATA confusion on Solana, or byte-order on Stellar). Soroban rejects
with `InvalidProof`. Replay attempts (same nonce twice) reject
with `AlreadyClaimed` on either chain.

### 17.3 Emergency pause + Technical Council (landed 2026-04-19)

**Auth.** `seal_bridgeCouncilAdd`, `seal_bridgeCouncilRemove`,
`seal_bridgePauseChain`, `seal_bridgeUnpauseChain`, and
`seal_bridgeRotateCommitteeKey` are all in `requires_admin_auth()`
(`crates/seal-node/src/rpc.rs:682`) — same two-mode gate as
`seal_addBridgeObserver` (§17.1):

- **Open mode** (no `--admin-address` flags): every snippet below
  works as plain `curl`. This is the case for the docker-composed
  bridge stack (`bridges/docker-compose.testnet.yml`) and any node
  started with bare `--rpc-port`, so a tester running locally will
  hit this path.
- **Admin mode** (node started with `--admin-address sealt1…`):
  every `seal_bridgeCouncilAdd` / pause / rotate call needs an
  ML-DSA-signed envelope from an admin-set address. Replace each
  curl with `seal rpc --key admin.json --method <M> --params <JSON>`
  (see §17.1 flow (a) for the canonical form). Plain curl returns
  `-32004 ... not in admin set` on these methods.

Quorum is independent of auth — every pause/rotate call still
requires a 2/3 supermajority of council `approvers` regardless of
the auth mode.

Council members are identified by an ML-DSA verifying-key hex (the
`pubkey` field); generate one key file per seat so you have the
hexes handy.

> ⚠️ **Known issue** (2026-05-20): the second `seal_bridgeRotateCommitteeKey`
> call in a sequence — i.e. rotating *back* to a previous key after an
> earlier rotation in the same node lifetime — silently fails the
> council-quorum check inside the handler (the `info!` log line that
> the first rotation emits does NOT appear for the second call). The
> first rotation persists fine. `bridge-e2e.sh` skips the rotate-back
> half of its smoke test by default for this reason
> (`RUN_ROTATION_SMOKE=1` to enable). Tracked as a follow-up; the
> bridge round trip itself is unaffected.

```bash
# Generate seven seats.
for i in 1 2 3 4 5 6 7; do
  cargo run -p seal-cli -- keygen --output "council_$i.json" > /dev/null
done

# Seat each one. seal_bridgeCouncilAdd params: {pubkey, name,
# [term_start_epoch], [term_end_epoch]}. pubkey = verifying_key hex.
for i in 1 2 3 4 5 6 7; do
  VK=$(jq -r .verifying_key "council_$i.json")
  curl -s -X POST $NODE -H 'content-type: application/json' \
    -d "$(jq -cn --arg pk "$VK" --arg n "seat-$i" \
          '{jsonrpc:"2.0",id:1,method:"seal_bridgeCouncilAdd",
            params:{pubkey:$pk,name:$n}}')" | jq
done

# List members (read-only):
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_bridgeCouncilList","params":{}}' | jq

# Look up a single member by their bech32m address. The handler
# decodes the address to its 32-byte SHA3 hash and matches against
# the stored member pubkeys, so the lookup works across testnet /
# mainnet HRP. Returns {address, member: {...} | null}.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_getCouncilMemberByAddress",
       "params":{"address":"sealt1…"}}' | jq

# Same shape for the validator set:
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"seal_getValidatorByAddress",
       "params":{"address":"sealt1…"}}' | jq
# Returns {address, validator: {public_key_hex, vrf_public_key_hex, stake, active} | null}.

# Pause a chain. 2/3 quorum = 5 of 7. `approvers` is a JSON array of
# council verifying-key hexes. Today this is a single-call vote (no
# individual signatures on the approver list yet — tracked in
# TODOS.md alongside the alpha-bootstrap auth gap); the endpoint
# verifies membership + dedupes internally.
APPROVERS=$(jq -s '[.[] | .verifying_key]' \
  council_1.json council_2.json council_3.json council_4.json council_5.json)
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d "$(jq -cn --argjson a "$APPROVERS" \
        '{jsonrpc:"2.0",id:1,method:"seal_bridgePauseChain",
          params:{chain:"Solana",reason:"suspected relay compromise",approvers:$a}}')" | jq

# List paused chains:
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_bridgeListPaused","params":{}}' | jq

# Unpause: same 2/3 rule, same `approvers` shape, no `reason`.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d "$(jq -cn --argjson a "$APPROVERS" \
        '{jsonrpc:"2.0",id:3,method:"seal_bridgeUnpauseChain",
          params:{chain:"Solana",approvers:$a}}')" | jq

# Rotate the committee MAC key without restarting seal-node. Same
# 2/3 rule as pause/unpause. `new_key_hex` is 64 hex chars (32 bytes).
# The host installs the key in BridgeManager and emits the new
# fingerprints in the response so the coordinator can cross-check
# against the value passed to each chain's `rotate_committee_key` ix.
NEW_KEY_HEX=$(openssl rand -hex 32)
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d "$(jq -cn --arg k "$NEW_KEY_HEX" --argjson a "$APPROVERS" \
        '{jsonrpc:"2.0",id:4,method:"seal_bridgeRotateCommitteeKey",
          params:{new_key_hex:$k,approvers:$a}}')" | jq

# Read the host's current key state. Returns
# {set, fingerprint_sha3_hex, fingerprint_sha2_hex}. Compare
# `fingerprint_sha2_hex` against the on-chain `committee_key_hash`
# view (Soroban, follow-up) or against SHA-256(getAccountInfo
# bridge_state.committee_key) on Solana to detect drift.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":5,
       "method":"seal_bridgeGetCommitteeKeyStatus","params":{}}' | jq

# Typed CLI wrapper around the same RPC. Pretty-prints the result
# and exits 1 if no key is installed, 2 if --expect-sha2 mismatches,
# 0 on match — useful in bridge-e2e.sh or rotation runbooks:
seal bridge-key-status --node "$NODE"
seal bridge-key-status --node "$NODE" --expect-sha2 "$EXPECTED_SHA256_HEX"
```

**Expected:**
- Pause with <2/3 valid approvers → `-32000 insufficient council
  approval for pause: need N of M, got K valid`; with 2/3+ → chain
  paused, all `observe_deposit` / `process_deposit` /
  `initiate_withdrawal` on that chain fail with `ChainPaused`.
- Duplicates or non-members in `approvers` are filtered out before
  the 2/3 check.
- Attempting pause before any council members exist →
  `-32000 technical council is empty; bootstrap via seal_bridgeCouncilAdd first`.
- `seal_getBridgeStatus` (§17.1) includes `paused_chains` inline so
  you can verify without a separate RPC.
- `seal_bridgeRotateCommitteeKey` with malformed hex →
  `-32602 new_key_hex must be 64 hex chars (32 bytes)`; with valid
  hex but <2/3 approvers → `-32000 insufficient council approval for
  committee-key rotation: need N of M, got K valid`. Success returns
  `{rotated: true, fingerprint_sha3_hex, fingerprint_sha2_hex}`.
- `seal_bridgeGetCommitteeKeyStatus` is unauth and returns `{set:
  false, fingerprint_sha3_hex: null, fingerprint_sha2_hex: null}`
  before any rotation, then the fingerprints after.
- `/metrics` mirrors the state: `seal_bridge_committee_key_set 1`
  + `seal_bridge_committee_key_fingerprint{sha2_hex="..."} 1` after
  rotate; both 0/empty before.

## 18. Ringtail BPF Verifier (landed 2026-04-19)

### 18.1 Unit + cross-check tests

```bash
cargo test -p seal-ringtail-verify --lib
```

(The `--lib` is required — the default-target invocation runs 0 tests
because the crate's tests live inside the library and aren't picked
up by integration/bin defaults under the current Cargo configuration.)

**Expected:** 20 passed, 0 ignored.
- Unit tests (~17): modular arithmetic, NTT roundtrip, polynomial
  multiply, challenge expansion, verifier input validation.
- Cross-check tests (~3) against `seal-threshold`: module constants
  match, tampered challenge rejected, wrong message rejected.

(Earlier revisions of this doc listed "23 passed, 2 ignored" — the
end-to-end sign→verify and oversized-z ignored tests landed under
`seal-threshold` instead; this crate now only carries the verifier
+ cross-check subset.)

### 18.2 Build check (no_std, wasm target)

Ensures the crate actually builds for BPF / WASM without `std`:

```bash
cargo build -p seal-ringtail-verify --target wasm32-unknown-unknown --release
```

**Expected:** clean build; the resulting
`target/wasm32-unknown-unknown/release/libseal_ringtail_verify.rlib`
is ~60 KB (exact size shifts with toolchain versions).

### 18.3 On-chain build (via bridge-test script)

See §7.4 above. Both `bridges/solana` and `bridges/stellar` link
against `seal-ringtail-verify` behind the `ringtail-verify` feature.

## 19.0 Chain state queries (no auth)

Start a node with RPC enabled (see §15.1 — `cargo run -p seal-node --
--slots 0 --rpc-port 8545`). In another shell:

```bash
BASE="http://localhost:8545"
rpc() { curl -s -X POST "$BASE" -H 'content-type: application/json' -d "$1" | jq; }

rpc '{"jsonrpc":"2.0","id":1,"method":"seal_getHeight","params":{}}'
rpc '{"jsonrpc":"2.0","id":2,"method":"seal_getStateRoot","params":{}}'
rpc '{"jsonrpc":"2.0","id":3,"method":"seal_getBlock","params":{"height":1}}'
rpc '{"jsonrpc":"2.0","id":4,"method":"seal_getPeers","params":{}}'
rpc '{"jsonrpc":"2.0","id":5,"method":"seal_getNamespaces","params":{}}'
rpc '{"jsonrpc":"2.0","id":6,"method":"seal_getNodeInfo","params":{}}'
```

**Expected:** `getHeight` returns 0 at genesis then increments each
slot; `getBlock` returns `null` for non-existent heights; `getPeers`
returns `{received_blocks: N}`; `getNodeInfo` returns
`{version, height, epoch, peers, validators, leases_active, uptime_secs}`.
The node's own address / verifying-key is intentionally **not** in
`getNodeInfo` — read it from the keyfile passed to `--key`, or via
the wallet TUI's `> address` command.

## 19.1 SQL submission (auth required for writes)

`seal_submitSql` and `seal_deployNamespace` are in `requires_auth()`
(see `rpc.rs:442-443`), so writes need an ML-DSA signature. Use
`seal sql --key key.json` (typed wrapper) for DDL/DML, and `seal rpc
--key key.json --method seal_deployNamespace` for namespace deploys.
Reads stay on plain curl.

```bash
# Prereqs:
cargo run -p seal-cli -- keygen --output alice.json
NODE=http://localhost:8545

# DDL + INSERT (signs automatically via seal sql --key):
cargo run -p seal-cli -- sql "CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT);" \
    --node $NODE --key alice.json
cargo run -p seal-cli -- sql \
    "INSERT INTO users (id, name) VALUES (1, 'alice');" \
    --node $NODE --key alice.json

# Read — no auth, runs via the same `sql` subcommand without --key:
cargo run -p seal-cli -- sql "SELECT * FROM users" --node $NODE

# Deploy a namespace (generic passthrough):
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_deployNamespace \
    --params '{"name":"myapp","schema":"CREATE TABLE posts (id BIGINT PRIMARY KEY, body TEXT);"}'
```

**Expected:** writes increment `getHeight` once the next block lands;
reads run against the current state; unauthenticated writes return
`-32003 missing 'signature' field`.

## 19.2 DEX order book

`seal_createPair`, `seal_placeOrder`, `seal_cancelOrder` all need
auth; `seal_getOrderBook` and `seal_listPairs` are reads. No typed
`seal create-pair / place-order / cancel-order` subcommands yet
(tracked in TODOS.md), so use the generic `seal rpc --key` passthrough:

```bash
# Create a pair (auth):
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_createPair --params '{"base":"GOLD","quote":"SEAL"}'

# Place a bid + an ask (auth). Amounts follow the token's decimals;
# GOLD uses 9 like SEAL, so `quantity:5` = 5 base units. If you meant
# 5 GOLD, use 5_000_000_000.
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_placeOrder \
    --params '{"pair":"GOLD/SEAL","side":"bid","price":100,"quantity":5}'
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_placeOrder \
    --params '{"pair":"GOLD/SEAL","side":"ask","price":100,"quantity":5}'

# Inspect (no auth):
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getOrderBook","params":{"pair":"GOLD/SEAL"}}' | jq
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_listPairs","params":{}}' | jq

# Cancel (auth — substitute the real order_id from getOrderBook):
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_cancelOrder \
    --params '{"pair":"GOLD/SEAL","order_id":42}'
```

**Expected:** crossing orders match immediately (price-time priority);
`getOrderBook` shows bids descending + asks ascending by price;
cancel only works for the order owner (server checks the derived
caller address against the stored order).

**Note:** matching now runs at every block via `match_all()` inside
`produce_block_with_vrf` (§3) sharing the same `Arc<Mutex<DexManager>>`
the RPC layer holds. Trades are then emitted as `TxType::DexMatch`
transactions (§23.5) so they fold into `tx_hash` + the per-block ZK
proof. The RPC `seal_placeOrder` path simply enqueues into the shared
book; matching no longer has to be triggered manually.

## 19.3 MPC + ZK RPC handlers

Both `seal_mpcAggregate` and `seal_zkProve` are currently **not
auth-gated** (not listed in `requires_auth()` — see `rpc.rs:439-478`).
Plain curl works today; tighten in a follow-up if these become
billable.

```bash
# SPDZ-style private aggregation over a SQL column. The handler reads
# `{table, column}` rows via SQL, then runs `function` over them
# locally (in production this would shard across parties). Params:
#   function ∈ {sum, count, avg}  (required)
#   table    — table name         (required)
#   column   — column to aggregate (required)
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_mpcAggregate",
       "params":{"function":"sum","table":"users","column":"balance"}}' | jq

# ZK-prove a predicate over a SQL table. Params:
#   statement — SQL predicate that follows `WHERE` (e.g. "balance > 1000")
#   table     — table to evaluate it over
# The handler runs `SELECT * FROM <table> WHERE <statement>` and binds
# the result into a state-transition shaped proof (StubProver by default;
# real STARK proving requires the `risc0` / `sp1` feature gate per §8).
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_zkProve",
       "params":{"table":"users","statement":"balance > 1000"}}' | jq
```

**Expected:**
- MPC aggregate returns `{function, table, column, result}` — the
  scalar aggregate without revealing per-row values. Underlying call
  is `seal-mpc::spdz_sum` / `spdz_count` / `spdz_avg`. Missing any of
  `function`/`table`/`column` → `-32602 missing 'X' param`; unknown
  function → `-32602 unsupported function: …`.
- ZK prove returns `{statement, table, satisfied, proof, proof_size,
  prover, state_root, block_height, caller}`. `satisfied` is true iff
  the predicate matched any row; `prover` names the active backend
  ("stub" by default, `risc0` / `sp1` with the matching feature in §8).

## 19.4 Private tables RPC

`seal_createPrivateTable` is auth-gated (`rpc.rs:463`);
`seal_listPrivateTables` is a public read.

```bash
# Create a private table (auth — signed via seal rpc):
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_createPrivateTable \
    --params '{"name":"secrets","schema":"CREATE TABLE secrets (id BIGINT PRIMARY KEY, payload TEXT);"}'

# List (no auth):
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_listPrivateTables","params":{}}' | jq
```

**Expected:** at-rest-encrypted tables (ML-KEM wrap key, per-row
AEAD) — full test coverage already in §13.

## 19.45 Governance RPC (proposal tracks + conviction voting + delegation)

Six proposal tracks, conviction-multiplier voting (None/X1–X6),
adaptive quorum biasing, vote delegation. All five RPCs are
auth-gated (`rpc.rs:472-476`) — drive via `seal rpc --key`:

```bash
# 1. Propose. `track` ∈ {parameter, protocol, treasury_small,
#    treasury_large, emergency, constitutional} — case-insensitive,
#    underscores optional (see parse_track in rpc.rs). Each track has
#    its own approval threshold (50–75 %) and vote period (1–14 epochs)
#    in governance.rs::ProposalTrack. `payload` is opaque bytes the
#    proposal type interprets (e.g. JSON for parameter changes).
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_govPropose \
    --params '{"track":"treasury_small","title":"Bootstrap grant","payload":"{\"amount\":1000}"}'

# 2. Vote. Required params:
#    proposal_id (u64), choice ∈ {aye/yes, nay/no, abstain},
#    stake (u64 — base units to commit to the vote).
#    Optional: conviction ∈ {none|0, x1|1 … x6|6} (defaults to x1).
#    Effective vote weight = stake × conviction multiplier.
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_govVote \
    --params '{"proposal_id":1,"choice":"aye","stake":1000,"conviction":"x3"}'

# 3. Withdraw an unlocked vote (after the conviction lock expires).
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_govWithdrawVote --params '{"proposal_id":1}'

# 4. Delegate vote weight to another address. Params:
#    delegate (sealt1… address), track, weight (u64 base units).
#    Conviction lives on the votes the delegate casts, not on the
#    delegation itself.
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_govDelegate \
    --params '{"track":"treasury_small","delegate":"sealt1…real-address…","weight":1000}'

# 5. Revoke a delegation (subject to the conviction lock).
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_govRevokeDelegation --params '{"track":"treasury_small"}'
```

**Expected:** proposals advance through Pending → Voting → Decided
states once the per-track period elapses; vote weight = stake ×
conviction multiplier; adaptive quorum biases the threshold based on
turnout (low turnout requires a stronger majority). Underlying
mechanics live in `crates/seal-node/src/{governance,delegation}.rs`
(~30 unit tests). Bridge-pause is gated separately on the Technical
Council 2/3 supermajority — see §17.

**Read paths (no auth, plain curl):**

```bash
# All proposals (id, track, title, proposer, start_epoch, status):
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_govListProposals","params":{}}' | jq

# One proposal in full (adds description + payload):
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_govGetProposal","params":{"proposal_id":0}}' | jq

# Votes cast on a proposal:
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"seal_govGetVotes","params":{"proposal_id":0}}' | jq

# Tally the result (only succeeds once voting_period_epochs has
# elapsed; otherwise -32000 "voting period not over yet"):
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":4,"method":"seal_govTally","params":{"proposal_id":0}}' | jq
```

Additional read paths: `seal_govListProposalsByProposer`,
`seal_govListVotesByVoter`, `seal_govListDelegationsFrom/To`,
`seal_govListLocksByVoter`, `seal_govEffectiveWeight`. Each takes the
obvious identifier param (`address` or `voter`/`delegator`/`delegate`)
and returns the matching slice — same JSON shape as the bulk
endpoints above, sorted by id for diff-stable polling.

## 19.5 PQ-RPC handshake (ML-KEM native transport)

The param is `client_public_key` (hex, not base64) — see
`rpc.rs:2890`. The handshake itself is public; the encrypted frames
that follow use the derived session key.

```bash
# Generate an ML-KEM keypair, then hand the public_key hex to the handshake.
cargo run -p seal-cli -- keygen --kem --output kem.json
CLIENT_PK=$(jq -r .public_key kem.json)
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d "$(jq -cn --arg pk "$CLIENT_PK" \
        '{jsonrpc:"2.0",id:1,method:"seal_pqHandshake",params:{client_public_key:$pk}}')" | jq
```

**Expected:** server responds with
`{ciphertext, server_public_key, session_id}` — `ciphertext` is the
ML-KEM-768 encapsulation of the session key (decapsulated client-side
with the matching ML-KEM secret in `kem.json`), `server_public_key` is
the server's verifying key, and `session_id` is the per-session
opaque handle for follow-up encrypted frames. Subsequent frames use
the derived session key with monotonic nonce + MAC verification. Unit
tests exercise this end-to-end in `seal-node::pq_rpc` (4 tests).

## 19.6 Internal-only state transitions (no RPC surface)

These features are exercised by consensus / epoch / block-production
logic, not by direct RPC. Their manual verification is via unit
tests + observation of on-chain state rather than RPC calls.

### Emission schedule
- File: `crates/seal-token/src/emission.rs`,
  `crates/seal-node/src/consensus_runner.rs:475-490`
- Wired: per-block reward applied inside `produce_block_with_vrf`
  via `EmissionSchedule::default().block_reward(epoch)`.
- Test: `cargo test -p seal-token emission`.
- Observe: `seal_getBalance` on the emission recipient before and
  after a block boundary.

### Treasury disbursement
- File: `crates/seal-token/src/treasury.rs`
- Wired: 10 % of emission per epoch credited to treasury address.
- Test: `cargo test -p seal-token treasury`.
- Observe: treasury balance via `seal_getBalance`.

### Storage-lease expiry + pruning (#STORAGE-FORGET)
- File: `crates/seal-token/src/storage_lease.rs`,
  `crates/seal-storage/src/pruning.rs`
- Wired: per-write burn invoicing + lease-expiry hook via
  `ConsensusRunner::leases`.
- Test: `cargo test -p seal-token storage_lease` +
  `cargo test -p seal-storage pruning`.
- Observe: create a row, advance past lease `paid_through`, trigger
  prune — subsequent queries for the row return nothing and serving
  expired data is a slashable offense (§7.5 SPEC).

### Governance (three-body + proposals + delegation)
- Files: `governance.rs`, `delegation.rs`, `committee.rs`
- **RPC surface:** the 5 proposal/vote/delegation mutations
  (`seal_govPropose/Vote/WithdrawVote/Delegate/RevokeDelegation`)
  are live — see §19.45 for drive-by-CLI recipes. The Service
  Operators Council remains internal-only today. `TechnicalCouncil`
  is exposed via the bridge-pause RPCs (§17.3) plus the
  `seal_bridgeCouncilAdd/Remove/List` bootstrap endpoints.
- Test: `cargo test -p seal-node governance delegation`.

### Fork choice + epoch transitions
- File: `crates/seal-node/src/committee.rs`, `consensus_runner.rs`
- Wired: heaviest-attestation-wins fork choice with deterministic
  tie-breaking; epoch-transition P2P announcements.
- Test: `cargo test -p seal-node committee` +
  `cargo test -p seal-consensus`.

### Slashing
- File: `crates/seal-consensus/src/slashing.rs`
- Wired: double-proposal + double-vote detection; slashed stake
  burned.
- Test: `cargo test -p seal-consensus slashing`.

## 20 ADR-001 reference

Stored-procedure execution-model decision (landed 2026-04-19):
`docs/decisions/ADR-001-stored-procedures-and-wasm.md`. SPEC.md §4.1
updated to reference it; §13.3 flipped "Stored procedures" from
"Error" to supported via `LANGUAGE sql | wasm`.

See §21 for the runtime walkthrough (CALL dispatch + PL/pgSQL +
WASM validation), landed 2026-04-20.

## 21 Procedures runtime (CALL dispatch, PL/pgSQL, WASM validation)

Landed 2026-04-20 as the executor side of ADR-001. Three pieces:

### 21.1 CREATE FUNCTION + CALL (LANGUAGE sql)

```bash
cargo test -p seal-sql call_dispatches_sql_proc_through_engine
```

What this exercises: `CREATE FUNCTION ... LANGUAGE sql AS $$...$$` is
registered into `Engine::procedures`, then `CALL proc(arg, arg, ...)`
substitutes positional `$N`, runs the body through the same engine,
and surfaces the QueryResult back to the caller.

Manual REPL flow:

```
> CREATE TABLE counters (id BIGINT PRIMARY KEY, n BIGINT)
> INSERT INTO counters (id, n) VALUES (1, 10), (2, 20), (3, 30)
> CREATE FUNCTION get_n(target BIGINT) RETURNS BIGINT
    AS $$SELECT n FROM counters WHERE id = $1$$
> CALL get_n(2)
```

Expected: one row with value `20`. The `RETURN <expr>` form is
accepted too — it lowers to `SELECT <expr>` internally.

### 21.2 LANGUAGE plpgsql (BEGIN ... END; bodies)

```bash
cargo test -p seal-procs plpgsql
cargo test -p seal-sql call_plpgsql
```

The shim accepts `BEGIN ...; ...; END;` blocks where each statement
is plain SQL (no `IF`/`LOOP`/`DECLARE` yet — those return a clear
`LanguageNotImplemented`). The trailing `RETURN <expr>` is rewritten
to `SELECT <expr>`; everything else runs in declaration order.

Manual REPL flow:

```
> CREATE TABLE bumps (id BIGINT PRIMARY KEY, n BIGINT)
> CREATE FUNCTION bump(amount BIGINT) RETURNS BIGINT LANGUAGE plpgsql
    AS $$BEGIN INSERT INTO bumps (id, n) VALUES (1, $1); SELECT n FROM bumps; END;$$
> CALL bump(99)
```

Expected: the INSERT runs, then the SELECT returns the new row's `n`
(99). Subsequent `SELECT n FROM bumps` confirms the side effect.

### 21.3 LANGUAGE wasm registration-time validation

```bash
cargo test -p seal-procs --features wasm-validate wasm_validate
```

`seal-procs::wasm_validate::validate_wasm_proc` enforces, at
`CREATE FUNCTION` time:

* Module parses cleanly under WASM1 (MVP + mutable globals only —
  no SIMD, threads, references, GC, exception handling).
* Exactly one exported function named `run`.
* `run` takes only `i64` parameters (matching the procedure's formal
  arg count) and returns one `i64`.
* No host imports — deterministic procs must be self-contained.

Runtime execution still surfaces `LanguageNotImplemented` because
`wasmtime` isn't yet vendored in this workspace; validation gates
malformed bytecode out of the chain ahead of that wiring. Wire-up
plan: add `WasmtimeProcEngine` once the dep lands; current
`wasm_validate.rs` is the validation surface that engine will import.

## 22 Ringtail full-protocol committee (round1_full / round2_full)

Landed 2026-04-20. Adds a parallel `CommitteeManagerFull` in
`seal-node::committee` that drives the paper-shaped Ringtail rounds
(`D_i = A·r_i + e_i`) so the produced signature is byte-exact
accepted by `seal_threshold::ringtail::verify_signature_full` and the
no_std `seal-ringtail-verify` BPF/Soroban verifier.

```bash
cargo test -p seal-node committee_manager_full
cargo test -p seal-threshold lagrange
cargo test -p seal-threshold rounding
```

Expected: all three pass. Notable tests:

* `test_committee_manager_full_single_signer_byte_exact` — runs the
  full-protocol path end-to-end and asserts the host
  `verify_signature_full` accepts the produced signature.
* `test_committee_manager_full_two_of_two_aggregation` — exercises
  the multi-signer round-1 / round-2 plumbing with two parties.
* `lagrange::tests::*` — proves the per-coefficient Lagrange
  primitives reconstruct constant + linear polynomials correctly,
  and that the participant-set coefficients sum to 1 mod q.
* `rounding::tests::*` — pins the Ringtail rounding helper at
  `DROP_BITS = 0` (identity, byte-exact subset) and exposes the
  smudge sampler so callers can opt into noise flooding.

What this *doesn't* do: the n-of-n full path with smudging on still
breaks byte-equality (`full_single_signer_smudging_breaks_byte_equality`
documents this boundary). The round-1 / round-2 / aggregate API now
exposes the rounding hook and the Lagrange combiner needed to close
that — wiring `DROP_BITS > 0` end-to-end is a follow-up that has to
re-derive the noise budget from the audit's σ targets.

Migration of `CommitteeManager` (the simplified one-shot path) to
`CommitteeManagerFull` happens at the consensus-runner integration
layer; both APIs ship in parallel until the cut-over.

## 23 forms.seal MPC + ZK + AEAD additions

Landed 2026-04-20. Three new modules under
`examples/seal-forms/src/`:

```bash
cargo test -p seal-forms
```

### 23.1 AEAD (`aead.rs`)

Wraps the demo's XOR stream cipher in `AEAD_PREFIX || HMAC-SHA3-256
tag || ciphertext`. The tag is keyed by the same shared secret the
stream cipher uses and binds the answer ciphertext to the KEM
ciphertext, so a network attacker can't bit-flip the answer without
the form owner's `unwrap()` call detecting it.

Tests cover: round-trip success, single-bit tag flip rejection,
KEM-swap rejection, short-blob rejection, bad-prefix rejection.

### 23.2 MPC additive sum (`mpc_sum.rs`)

Numeric-question variant: respondent splits `answer mod p` into `n`
additive shares (`p = 2^61 - 1`); each share is encapsulated for one
MPC committee member. The form owner only learns `Σ answers` after
the committee aggregates. Per-party local sums combine into the
survey total via `survey_total`.

Tests cover: split + reconstruct round-trip, the
information-theoretic property that no single share equals the
answer, survey-total composition across multiple respondents.

### 23.3 ZK statistics (`zk_stats.rs`)

`StatementSum::commit` posts a SHA3-binding commitment to the
per-row witness; `StatementSum::verify` recomputes the commitment +
sum and compares. Until a real SNARK backend lands the witness ships
in the clear, but the predicate is exactly what a future risc0/sp1
circuit will compile against — interface stays stable when the
backend swaps in.

Tests cover: honest statement verifies, flipped sum / flipped
witness / truncated witness all fail, deterministic commitment for
fixed seed.

### 23.4 Frontend (`web/`)

Minimal HTML/JS demo at `examples/seal-forms/web/`:

```bash
cd examples/seal-forms/web && python3 -m http.server 5174
open http://localhost:5174
```

Page imports the workspace WASM SDK
(`sdks/wasm/pkg/seal_dao_wasm.js`). Build the SDK first via
`cd sdks/wasm && ./build.sh` if the page reports a missing module.

The page lets a respondent: connect to a Seal node by RPC URL,
fetch a form by ID (reads the `forms` table), encrypt their
answer locally with ML-KEM-768, submit via `seal_submitSql`, then
audit the trace chain by walking from the genesis hash.

## 23.5 DEX trade emission as TxType::DexMatch

Landed 2026-04-20 (cont.). After `DexManager::match_all` runs each
block, the consensus runner appends a `TxType::DexMatch` transaction
whose payload is a bincode-serialized `Vec<(pair, Vec<Trade>)>`.
Sender = proposer pubkey, signature empty (consensus-emitted).

```bash
cargo test -p seal-node test_dex_match_emits_tx_in_produced_block
```

Expected: a crossing bid+ask placed via the runner's shared
`DexManager` produces a `TxType::DexMatch` row in the next block,
the payload deserializes back into the same trades the order book
exposes, and the sender field matches the proposer's pubkey.

## 24 Algebraic Ringtail verify on bridges

Wire-up only. Both bridges are excluded from the workspace and
build via their own toolchains (`anchor build` for Solana, the
Soroban CLI for Stellar); the source changes here unblock turning on
`--features ringtail-verify` once those toolchains are available.

### 24.1 Solana BPF (`bridges/solana/programs/seal-bridge/src/lib.rs`)

`verify_ringtail_sig` now decodes a fixed envelope:

```text
[0..32]      committee MAC (HMAC-SHA-256, unchanged)
[32..34]     participant_count (u16 LE)
[34..36]     threshold (u16 LE)
[36..68]     challenge ([u8; 32])
[68..2116]   z (256 LE-u64 = 2048 B)
[2116..18500] matrix_a[K]      (8 × 2048 B)
[18500..34884] public_key_t[K] (8 × 2048 B)
```

…and calls `seal_ringtail_verify::verify(&ctx, &sig, &pp, b"",
threshold)`. Build with:

```bash
cd bridges/solana/programs/seal-bridge
anchor build --features ringtail-verify
```

(Anchor isn't vendored in this workspace, so `cargo build` from the
root fails at the dep-resolution step. The bridge has its own dep
cache.)

### 24.2 Soroban (`bridges/stellar/src/lib.rs`)

`verify_ringtail_proof` decodes the same envelope shape (with `u16`
fields in big-endian per Soroban convention) into a stack `[u8;
34884]` buffer via `Bytes::copy_into_slice`, then runs
`seal_ringtail_verify::verify`. Build with:

```bash
cd bridges/stellar
stellar contract build --features ringtail-verify
```

CU / instruction-cost measurement for both is the next gate; the
verify path is K=8 polynomial multiplications + one challenge
expansion + one SHA3, expected ~300–500K CU on BPF and ~10M
instructions on Soroban (within budget but worth confirming).

The actual recipient/amount/nonce binding still flows through the
committee-MAC layer; the algebraic verify currently hashes the
empty message. Switching the message to the canonical
`recipient || amount_le || nonce_le || domain_tag` triple is a
parallel change once the host signer pipes that through.

### 24.3 Host-side cost projection

```bash
./scripts/measure-ringtail-cost.sh
```

Runs the example binary in `seal-ringtail-verify` (release mode,
200 iterations), captures host-µs/call, and projects approximate
Solana CU + Soroban instruction count. Output goes to
`target/ringtail-cost/host-projection.txt` and an append-only
`host-projection.csv` history. Use this **before**
`bridge-test-ringtail.sh` to sanity-check the verify cost without
spinning up local Solana / Stellar nets.

First-run baseline on M-series host: ~944 µs/call → ~11k CU on BPF,
~1M instructions on Soroban (well within budgets).

## 25 New demo apps (copy-trading, kyc.seal, kindle.seal)

Landed 2026-04-20 (cont.). Three new library crates under
`examples/`:

```bash
cargo test -p seal-copy-trading -p seal-kyc -p seal-kindle --lib
```

Expected: 21 tests pass total (7 each). Note the trailing `--lib` —
the default-target invocation runs 0 tests for these crates (same
Cargo-target quirk as §18.1), and the flag must come *after* every
`-p` since `-p --lib -p …` confuses cargo's argument parsing and
runs nothing.

### 25.1 copy-trading

`examples/seal-copy-trading/src/lib.rs`. A leader publishes orders;
followers pre-register an allowance + market whitelist;
`scale_order_for_follower` computes the mirror order quantity given
the follower's remaining headroom. Allowance + per-day cap +
market whitelist are all enforced before any mirror tx is emitted.

Key tests:
* `unwhitelisted_market_returns_none`
* `proportional_sizing_scales_with_remaining_headroom`
* `notional_cap_clamps_when_proportion_exceeds_headroom`

### 25.2 kyc.seal

`examples/seal-kyc/src/lib.rs`. ML-DSA-attested KYC: an attester
posts `Attestation` rows (subject_addr || tier || expires); other
apps gate access via `HAS_KYC(tier)`. Self-attestation is blocked
at the RLS layer.

Key tests:
* `signed_attestation_verifies` / `expired_attestation_rejected`
* `forged_attestation_under_wrong_key_rejected`
* `has_kyc_threshold_check`
* `policies_block_self_attestation`

### 25.3 kindle.seal

`examples/seal-kindle/src/lib.rs`. Per-chapter encryption under a
single 32-byte book content key (BCK); per-reader ML-KEM-768 wrap
of the BCK via `wrap_for_reader` / `unwrap_for_reader`. Chapter
index is mixed into the keystream so identical bodies don't repeat.

Key tests:
* `chapter_round_trip`
* `same_plaintext_in_different_chapters_yields_different_ciphertext`
* `grant_unwrap_round_trip`
* `unwrap_with_wrong_key_does_not_recover_bck`

## 26 State-sync RPC trio + late-joiner bootstrap (landed 2026-05-10)

The state-sync trio lets a fresh validator skip genesis-replay
by pulling a recent state snapshot from a peer. Server side is
three RPCs (`seal_listSnapshots` / `seal_getSnapshotManifest` /
`seal_getSnapshotChunk`); client side is
`seal-node --bootstrap-from-snapshot <peer-url>`.

Wire-format source-of-truth in
`crates/seal-storage/src/snapshot_chunks.rs`. Capture cadence
fires from `ConsensusRunner::advance_slot` at every epoch
boundary; default in-memory cap is 32 (rolling few-hour window
at 32-slot epochs).

### 26.1 Encoder / decoder + roster unit tests

```bash
cargo test -p seal-storage snapshot
cargo test -p seal-token  --lib balance::tests::snapshot
cargo test -p seal-node   --lib snapshot
```

**Expected:**
- `seal-storage` runs 8 `SnapshotIndex` tests + 11
  `snapshot_chunks` tests (chunk round-trip / oversized-row
  exception / cap-split / fingerprint-order-sensitivity /
  decoder truncation errors).
- `seal-token` runs 6 balance-snapshot tests
  (lexicographic-sort / dump→restore round-trip / malformed
  bincode / dust-entry filtering / empty-store).
- `seal-node` runs 3 capture-hook tests + 3 bootstrap-client
  tests (round-trip against in-memory mock, empty list edge
  case, hash-mismatch detection on a tampered byte).

### 26.2 `seal_listSnapshots` (operator UX)

After a node has been running long enough to cross at least
one epoch boundary (default config: 256 slots × 4 s = ~17 min;
override via `SEAL_SLOTS_PER_EPOCH=32` for a faster smoke):

```bash
cargo run -p seal-node -- --slots 0 --rpc-port 8545 --no-network &
NODE_PID=$!
# (wait for the first epoch boundary to fire; advance manually
#  in a single-node config by submitting any tx that produces
#  blocks — see §3.1 for the demo loop)
cargo run -p seal-cli -- snapshots --node http://localhost:8545
cargo run -p seal-cli -- snapshots --limit 5
kill $NODE_PID
```

**Expected:** Newest-first table with columns
`height / epoch / state_root[trunc] / captured_s`. If the node
hasn't crossed an epoch boundary yet, the output reads
`No snapshots retained yet (need at least one epoch boundary
to fire).`.

### 26.3 `seal_getSnapshotManifest` (operator UX)

```bash
HEIGHT=$(curl -s -X POST http://localhost:8545 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"seal_listSnapshots","params":{"limit":1},"id":1}' \
    | jq -r '.result.snapshots[0].height')
cargo run -p seal-cli -- snapshot-manifest --height $HEIGHT
cargo run -p seal-cli -- snapshot-manifest --height $HEIGHT --json | jq '.chunks | length'
```

**Expected:** Summary block shows `state_root /
tip_block_hash / manifest_hash / total_bytes / chunk_count`
plus a chunk preview (first 8 + last 4 with `…` elision when
>12 chunks). `--json` returns the raw RPC response for piping
into the chunk-fetch loop.

**Negative tests** (refuses pruned manifests):
- Pick a `height` not in the retained roster → `-32004`
  `snapshot at height N not retained`.
- Pick a height whose snapshot the live state has moved past
  (rare; race a query past the next epoch boundary) →
  `-32005` with `live state_root … no longer matches snapshot
  state_root …`.

### 26.4 `seal_getSnapshotChunk` (operator UX)

```bash
cargo run -p seal-cli -- snapshot-chunk --height $HEIGHT --index 0
cargo run -p seal-cli -- snapshot-chunk --height $HEIGHT --index 0 --out chunk0.bin
```

**Expected:** Prints `claimed_hash` (server-reported) +
`recomputed_hash` (fresh local SHA3) + `(MATCH)`. The CLI
exits 0 on MATCH, 2 on MISMATCH (the "host moved on
mid-stream" signal). `--out chunk0.bin` writes the raw chunk
bytes for offline diff against another peer.

**Negative test:** `--index <chunk_count>` → `-32007`
`chunk_index N out of range (snapshot has M chunks)`.

### 26.5 `--bootstrap-from-snapshot` late-joiner (smoke owed)

The full multi-node smoke (a fresh node converging against a
2-node testnet without genesis-replay) is documented but not
yet run on this dev machine — see the coverage note at the
top. The intended invocation:

```bash
# On peer A (already at height >= 1 with at least one epoch
# boundary crossed):
cargo run -p seal-node -- --slots 0 --rpc-port 8545 --port 4001

# On peer B (fresh):
cargo run -p seal-node -- --slots 0 \
    --rpc-port 8546 --port 4002 \
    --bootstrap-peers /ip4/127.0.0.1/tcp/4001 \
    --bootstrap-from-snapshot http://127.0.0.1:8545
```

**Expected log on peer B:**
```
Bootstrap-from-snapshot: connecting to http://127.0.0.1:8545…
Bootstrap-from-snapshot: replayed N bytes across M chunk(s)
  height = H, epoch = E, state_root = …
Bootstrap-from-snapshot: balances populated, K account(s) live
```

The `Genesis: … SEAL minted` line **must NOT appear** on
peer B — overlaying genesis on top of a bootstrap would
diverge state from peers, and the binary is hard-coded to
skip genesis when bootstrap succeeds. On bootstrap failure
the binary exits with code 3 and a clear error rather than
silently falling back to genesis.

**Negative tests:**
- Point at a non-existent peer URL → exit 3 with
  `transport: curl exited …`.
- Point at a peer that has zero snapshots retained → exit 3
  with `bad response: peer has no snapshots retained`.
- The hash-mismatch case is exercised by the in-memory mock
  in `crates/seal-node/src/snapshot_bootstrap.rs::tests::
  bootstrap_handles_chunk_hash_mismatch`.

### 26.6 Explorer surface

`apps/seal-explorer-web/index.html` gained a **State Snapshots**
section between Namespaces and Tokens. Live-refreshes on the
2 s tick, sig-skipped to avoid re-rendering on idle ticks.
Older nodes without the RPC silently render an empty section
— the chain itself stays functional.

```bash
# Same drill as §3.1 for explorer-web setup, then visit:
#   http://localhost:8000/?rpc=http://localhost:8545
```

**Expected:** Header tile shows `(N of M retained)` count;
table renders `height / epoch / state_root[trunc] /
captured-at` newest-first. The header explanation points
operators at `seal-node --bootstrap-from-snapshot`.

## 27 Validator-registration portal (landed 2026-05-10)

`apps/seal-registration` is a long-running axum service that
collects ML-DSA-signed `(pubkey, vrf_pubkey, name, contact)`
tuples from prospective testnet validators and exposes a
public roster (with `contact` stripped). Mirrors the
apps/seal-faucet shape; full runbook in
[`docs/TESTNET-REGISTRATION.md`](docs/TESTNET-REGISTRATION.md).

### 27.1 Unit tests

```bash
cargo test -p seal-registration
```

**Expected:** 7 tests pass:
- `registration_message_is_canonical` — catches a future
  field-reorder regression that would silently invalidate
  every existing signature (the test asserts the
  byte-string layout `register || pubkey_hex || vrf_pubkey_hex
  || name || contact`).
- `signature_verifies_for_authentic_request` — happy path.
- `signature_fails_when_message_is_tampered` — flips the
  name field, signature must reject.
- `signature_fails_when_pubkey_is_substituted` — sign with
  key A, verify against key B.
- `cooldown_blocks_within_interval_and_clears_after` — the
  per-IP rate limit math.
- `append_and_load_jsonl_round_trip` — persistence layer.
- `load_jsonl_missing_file_yields_empty_map` — fresh-install
  edge case.

### 27.2 End-to-end via curl

```bash
cargo run -p seal-registration -- --port 8547 &
PORTAL_PID=$!
sleep 0.5

# Generate a fresh validator wallet; the keyfile is the same
# shape the faucet expects.
cargo run -p seal-cli -- keygen --output /tmp/reg-test.json
PUB=$(jq -r .verifying_key /tmp/reg-test.json)

# Sign the canonical message manually (until `seal
# register-validator` lands — see TESTNET-REGISTRATION.md
# for the recipe). Easiest path: drive it through Rust:
SIG=$(cargo run --quiet -p seal-cli -- rpc \
    --node "irrelevant" --method "irrelevant" --params '{}' --key /tmp/reg-test.json \
    --print-sig-only 2>/dev/null || echo "manual-sig-needed")

# OR construct the request body in a tiny Python helper:
python3 - <<'PY'
import json, hashlib
# (driver code that builds the message bytes, signs via a
#  Python ML-DSA binding or shells out to seal-cli; see
#  docs/TESTNET-REGISTRATION.md for the canonical recipe.)
PY

curl -X POST http://127.0.0.1:8547/register \
    -H 'Content-Type: application/json' \
    -d "{\"pubkey_hex\":\"$PUB\",
         \"vrf_pubkey_hex\":\"$(printf 'ab%.0s' {1..32})\",
         \"name\":\"validator-alpha\",
         \"contact\":\"alpha@example.com\",
         \"signature_hex\":\"<hex from the helper>\"}"

curl http://127.0.0.1:8547/registrations | jq

kill $PORTAL_PID
```

**Expected:**
- POST returns `{"status":"ok","pubkey_hex":"…","name":"validator-alpha"}`.
- GET `/registrations` lists the entry **without** the
  `contact` field (operator-private — that field stays on
  the on-disk JSONL only).
- A second identical POST returns
  `{"status":"already-registered",…}` — idempotent re-submit
  is a quiet 200, not an error.
- Registration JSONL appears at `./registrations.jsonl` (or
  the path passed to `--store`); each line is a one-record
  JSON document including `accepted_at_unix_secs`.

**Negative tests:**
- Empty `name` or `contact` → 400 with the field-shape error.
- `name > 200` chars or `contact > 400` chars → 400.
- Tampered `name` (signed payload's name ≠ submitted name) →
  401 `signature does not verify against pubkey_hex`.
- Two requests from the same IP within `--interval-secs`
  (default 60) → 429 with `retry_after_secs`.

## 28 Release pipeline + sign-file / verify-file (landed 2026-05-10)

PQC-native release artifacts: ML-DSA-65 signs the
`SHA256SUMS` file rather than the classical sigstore /
minisign pipeline a typical Rust project would use. Per
`CLAUDE.md` the project is post-quantum first; the signing
primitive matches the chain's own identity scheme. Full
runbook in [`docs/RELEASE.md`](docs/RELEASE.md).

### 28.1 `seal sign-file` / `seal verify-file` round-trip

```bash
# Generate a release keypair (back this up — losing it means
# future releases can't sign under the same identity, so
# downstream consumers will start seeing pubkey-mismatch
# errors).
cargo run -p seal-cli -- keygen --output /tmp/release-key.json

# Round-trip on a small file.
echo "hello world" > /tmp/test.txt
cargo run -p seal-cli -- sign-file /tmp/test.txt \
    --key /tmp/release-key.json --out /tmp/test.txt.sig

PUB=$(cat /tmp/test.txt.sig.pubkey)
cargo run -p seal-cli -- verify-file /tmp/test.txt \
    --pubkey-hex "$PUB" --sig-file /tmp/test.txt.sig
echo "exit=$?"   # 0 → OK
```

**Expected:**
- `sign-file` writes `/tmp/test.txt.sig` (~6 600 hex chars =
  3 309-byte ML-DSA-65 signature) + sibling
  `/tmp/test.txt.sig.pubkey` (verifying-key hex).
- `verify-file` prints
  `OK (/tmp/test.txt signature verifies)` and exits 0.

**Negative tests:**
```bash
# Tamper with the file after signing.
echo "tampered" > /tmp/test.txt
cargo run -p seal-cli -- verify-file /tmp/test.txt \
    --pubkey-hex "$PUB" --sig-file /tmp/test.txt.sig
echo "exit=$?"   # 1 → tampered file detected
```

`verify-file` prints
`FAIL (/tmp/test.txt signature does NOT verify)` and exits 1.
Garbage hex / missing files → exit 2.

### 28.2 `scripts/release.sh` dry-run

The script is dry-run by default. The Docker push is gated
behind `RELEASE_PUBLISH=1` so a stray invocation never leaks
to ghcr.io.

```bash
# Generate or reuse a release key first (28.1).
./scripts/release.sh --version v0.0.0-test --key /tmp/release-key.json
ls -la dist/
```

**Expected:**
- `dist/seal-node-v0.0.0-test-linux-x86_64`
- `dist/seal-node-v0.0.0-test-linux-aarch64`
- `dist/seal-node-v0.0.0-test-darwin-aarch64` (only on Apple
  Silicon hosts)
- `dist/SHA256SUMS` — sorted-filename `shasum -a 256` output;
  two builds of the same source tree produce byte-identical
  sums.
- `dist/SHA256SUMS.sig` (~6 600 hex chars).
- `dist/SHA256SUMS.sig.pubkey` (verifying-key hex matching
  the `--key` argument).
- `dist/seal-node-v0.0.0-test.tar.gz` containing all of the
  above.
- Local Docker image
  `ghcr.io/seal-dao/seal-node:v0.0.0-test` (visible via
  `docker images`).
- `[ok] post-sign verify OK` — the script re-runs
  `seal verify-file` against the just-produced signature
  before tarballing, so a sig that doesn't verify against
  its own pubkey aborts the release with exit 3.

**Negative tests:**
- Missing `--key` file → preflight exit 1.
- Missing `docker` / `cargo` / `shasum` on PATH → preflight
  exit 1.
- `RELEASE_PUBLISH=1` without ghcr auth → Docker push fails
  with exit 4; the `dist/` artifacts are still produced.

### 28.3 Downloader-side verification

A consumer pulling the release runs the same two checks the
script's "Verify on a downloader's host" footer prints:

```bash
cd dist/
shasum -a 256 -c SHA256SUMS
cargo run -p seal-cli -- verify-file SHA256SUMS \
    --pubkey-hex "$(cat SHA256SUMS.sig.pubkey)" \
    --sig-file SHA256SUMS.sig
```

**Expected:** Both checks pass (exit 0). For production
deployments, downstream consumers should pin the expected
`pubkey_hex` once and verify all future releases against the
pinned value rather than trusting `SHA256SUMS.sig.pubkey`
out of the same archive — a malicious upstream could swap
both. See `docs/RELEASE.md` "Pinning the release pubkey".

### 28.4 What this section does NOT exercise

The release pipeline is documented but **not** wired into
`scripts/ci.sh` — releasing is an explicit operator action,
not a CI loop. Things still owed (per `docs/RELEASE.md`):
- `gh release create` automation under the
  `RELEASE_PUBLISH=1` branch.
- SLSA-style provenance attestation.
- Threshold release signing via `seal-threshold` (N-of-M
  operators rather than a single ML-DSA key).

## Summary Checklist

Test counts are post-2026-05-10 batch (state-sync trio +
late-joiner + registration + release). Workspace total grew
from 1077 → 1116 (+39 tests across the batch).

| Feature         | Command                           | Expected Tests |
| --------------- | --------------------------------- | -------------- |
| Crypto          | `cargo test -p seal-crypto`     | 26+            |
| VRF             | `cargo test -p seal-vrf`        | 57+            |
| Threshold       | `cargo test -p seal-threshold`  | 75+            |
| Ringtail-verify | `cargo test -p seal-ringtail-verify --lib` | 20+       |
| SQL             | `cargo test -p seal-sql`        | 97+            |
| Merkle          | `cargo test -p seal-merkle`     | 35+            |
| Consensus crate | `cargo test -p seal-consensus`  | 57+            |
| Consensus + Node | `cargo test -p seal-node --lib` | 240+          |
| P2P             | `cargo test -p seal-p2p`        | 32+            |
| Bridge          | `cargo test -p seal-bridge`     | 48+            |
| ZK (default)    | `cargo test -p seal-zk`         | 46+            |
| ZK (real r0vm)  | `SEAL_RUN_REAL_RISC0=1 cargo test -p seal-zk --features risc0` | +8 |
| MPC             | `cargo test -p seal-mpc`        | 26+            |
| Private Tables  | `cargo test -p seal-node private_tables` | 9       |
| Storage         | `cargo test -p seal-storage`    | 37+            |
| Token           | `cargo test -p seal-token`      | 94+            |
| Wallet          | `cargo test -p seal-wallet`     | 34+            |
| TEE             | `cargo test -p seal-tee`        | 6+             |
| CLI             | `cargo test -p seal-cli`        | 10+            |
| Procs           | `cargo test -p seal-procs --features wasm-validate` | 21+    |
| Forms           | `cargo test -p seal-forms`      | 22+            |
| Social          | `cargo test -p seal-social`     | 2+             |
| Auction         | `cargo test -p seal-auction`    | 4+             |
| x402            | `cargo test -p seal-x402`       | 3+             |
| Copy-trading    | `cargo test -p seal-copy-trading --lib` | 7            |
| KYC             | `cargo test -p seal-kyc --lib`        | 7              |
| Kindle          | `cargo test -p seal-kindle --lib`     | 7              |
| Registration    | `cargo test -p seal-registration`     | 7              |
| **Total** | `cargo test --workspace`        | **1116+** |
