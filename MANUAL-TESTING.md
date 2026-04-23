# Seal DAO — Manual Test Guide

Step-by-step manual tests for all major features. Run these after
code changes to verify end-to-end functionality.

Sections 1–14 cover the original feature set; sections 15–19 cover
the RPC / bridge / Ringtail-verify surface added 2026-04-18 onwards.

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
- `solana-cli` (Anza stable), `anchor-cli` 0.31.1, `stellar-cli` 22.0.0
  all on PATH.
- `~/.cargo/bin/{cargo,rustc,rustdoc}` symlinked to rustup (proxies
  for `cargo +<toolchain>` directives used internally by anchor +
  soroban build chains).

**Expected (after test):**
- `bridges/solana/programs/seal-bridge/target/deploy/seal_bridge.so`
  ≈ 270 KB (268 808 bytes at 2026-04-19 landing).
- `bridges/stellar/target/wasm32-unknown-unknown/release/seal_bridge_stellar.wasm`
  ≈ 8.6 KB (8 794 bytes at 2026-04-19 landing).

**Negative test:** move `.cargo/config.toml` back in place and re-run
the test script — it should fail fast with a vendor-source error,
which the script auto-handles by moving the config aside during
the build and restoring it on EXIT.

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

## 13. Private Tables (at-rest encryption)

Private tables use AES-256-GCM (authenticated encryption) with a 96-bit
random nonce per seal. Keys are wrapped in `EncryptionKey` which zeroes the
key material on drop.

### 13.1 Unit Tests

```bash
cargo test -p seal-node private_tables
```

**Expected:** 8 tests pass:
- `test_register_private_table`
- `test_encrypt_decrypt_roundtrip`
- `test_decrypt_wrong_owner_denied` — access control
- `test_decrypt_wrong_key_fails` — AES-GCM auth tag with wrong key
- `test_tampered_ciphertext_rejected_by_auth_tag` — bit-flip detected
- `test_commitment_verification` — SHA3(nonce || ciphertext) matches metadata
- `test_nonces_are_distinct_per_store` — same plaintext/key ⇒ different nonce
  ⇒ different ciphertext
- `test_table_types`

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

In another shell:

```bash
curl -s -X POST http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getBalance","params":{"address":"seal1..."}}' | jq
```

**Expected:** `{"result":{"address":"seal1...","balance":N,"locked":M}}`.

### 15.1.1 seal_faucet (dev-only)

Genesis pre-mints to fixed addresses (`seal1validators`,
`seal1treasury`, …, `crates/seal-node/src/main.rs:119-124`), so a
freshly-created wallet has balance 0 and no way to pay for anything.
Start the node with `--dev-faucet` to enable a signature-less
`seal_faucet` RPC that drips SEAL to any address (capped at 1000 SEAL
per address per rolling 24 h window, enforced server-side):

```bash
# Node:
cargo run -p seal-node -- --slots 0 --rpc-port 8545 --dev-faucet

# Drip 100 SEAL (default) to your wallet:
curl -s -X POST http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_faucet",
       "params":{"address":"sealt1your-address…"}}' | jq

# If the address lives in a key file (from `seal keygen --output key.json`),
# use an intermediate BODY variable — command substitution with jq's single-
# quoted filter next to "$ADDR" is very easy to collapse into a single
# argument when copy-pasted as one line, producing an "Invalid numeric
# literal" from jq.
ADDR=$(jq -r .address key.json)                       # e.g. sealt1…
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

Without `--dev-faucet` the method returns `-32601 seal_faucet disabled`.
**Never enable this on a shared/public node** — anyone can drain the
faucet by minting to arbitrary addresses up to the cap.

### 15.2 seal_transfer (auth required)

`seal_transfer` (and every mutating RPC listed in `requires_auth`) is
ML-DSA-authenticated. The signed message is not the transfer payload —
it is **`SHA3-256(method || serde_json::to_string(&params))`**
(`crates/seal-node/src/rpc.rs:272-281`), and the request envelope
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

**A. Desktop wallet (§1.1) — not yet.** `apps/seal-wallet/standalone.html`
has Connect / Sign / SQL / MPC / ZK / custom-token / DEX panels but
**no native SEAL Send form** and no `seal_transfer` call site (the
`signedRpc` helper at `standalone.html:340-350` is wired, nothing in
the UI drives it for a plain transfer). Tracked in TODOS.md — for now
use path B or C below.

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
`signed_rpc_call` at `crates/seal-cli/src/wallet.rs:735-754`.

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

Requires a node with RPC enabled (see §15.1).

### 16.1 Create → mint → transfer → query

`seal_createToken`, `seal_mintToken`, `seal_transferToken`, and
`seal_setTransferFee` are all in `requires_auth` (see
`crates/seal-node/src/rpc.rs` `requires_auth()`), so each request
needs an ML-DSA `signature` over `SHA3-256(method || params_json)`
plus the verifying key as `sender` (**not** `caller` — the server
derives the address from `sender`). Same envelope as §15.2; the
bech32m guard now rejects `seal1creator…`-style placeholders before
the handler runs. Hand-crafted curl snippets can reach `-32003
signature verification failed` trivially — drive the flow through
the wallet TUI instead.

**TUI session** (node must be running with RPC on 8545):

```
cargo run -p seal-cli -- wallet
> create testnet
> address                                 # copy this — you're the creator
> connect http://localhost:8545
> create-token GOLD "Gold Coin" 1000000   # symbol, name, max_supply (base units)
> mint-token GOLD sealt1alice… 500.0      # decimal = GOLD units; bare int = base units
> tokens                                  # list — includes transfer_fee_bps
```

GOLD uses the same 9-decimal convention as SEAL. Non-creator mint
attempts fail with `-32000`. From a second wallet (Alice, imported
from the minted address), transfer to Bob:

```
> transfer sealt1bob… 100.0               # actually `seal_transferToken` if the active
                                          # token context is GOLD; today the TUI only
                                          # transfers SEAL via `transfer` — use
                                          # `mint-token` from the creator for first
                                          # allocation, and see the follow-up below.
```

**Read paths (no auth, safe to `curl`):**

```bash
# Per-token balance for an address:
curl -s -X POST http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getTokenBalance",
       "params":{"symbol":"GOLD","address":"sealt1alice…"}}' | jq

# All tokens (includes transfer_fee_bps for each):
curl -s -X POST http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_listTokens","params":{}}' | jq
```

**Expected flow:** create succeeds; mint only works for the creator
(non-creator → `-32000`); `listTokens` returns the token with
`transfer_fee_bps: 0`. A one-shot `seal create-token / mint-token /
transfer-token` flat-CLI subcommand pair is tracked in TODOS.md
("One-shot non-REPL `seal-cli` mutations"); once it lands this
section will grow the same path-C recipe that §15.2 has.

### 16.2 Transfer fees (landed 2026-04-19)

> **⚠ Setting fees is not ready to drive from the CLI/TUI yet.**
> The `seal_setTransferFee` RPC exists and enforces creator-only
> auth + the 0–10 000 bps range, but there is no flat-CLI
> `seal set-transfer-fee --key …` subcommand and the wallet TUI
> has no command for it either. Until then, either:
> (a) hand-craft the ML-DSA envelope (same canonicalization as
>     §15.2 path D — brittle, bring your own signer), or
> (b) wait for the subcommand — tracked in `TODOS.md` under
>     "One-shot non-REPL `seal-cli` mutations" → Remaining →
>     `seal set-transfer-fee`.
> The read side (`seal_getTransferFee`) is public and works today;
> until a fee is set, every token's `fee_bps` is legitimately `0`
> (that's the default, not a bug — verified by the handler at
> `crates/seal-node/src/rpc.rs` `handle_get_transfer_fee`, which
> errors with `-32000 token 'X' not found` for unknown symbols).

```bash
# Read the current fee (no auth, works today):
curl -s -X POST http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_getTransferFee",
       "params":{"symbol":"GOLD"}}' | jq
```

**Expected** (once a signed `seal_setTransferFee` has been sent —
currently gated on the CLI todo above):
- Set returns `{"status":"updated","fee_bps":100}`.
- Get returns `{"symbol":"GOLD","fee_bps":100}`.
- Non-creator setting the fee → `-32000` "only creator can set fees".
- `fee_bps > 10_000` → `-32000` "fee cannot exceed 100%".
- Subsequent `seal_transferToken` debits the fee from the amount.

## 17. Bridge JSON-RPC surface (landed 2026-04-19 batch)

All bridge RPCs assume a node is running with RPC enabled (see §15.1).

**Do I need extra config?** Yes — a freshly-started node has **zero
observers registered** (`BridgeObserverSet::new()` at
`crates/seal-node/src/rpc.rs:230`), so `seal_listBridgeObservers`
returns `{"count": 0}`, `seal_pollBridges` sees nothing, and
`seal_getBridgeDeposits` is empty. Two paths to activity:

- **Manual**: register observers below (`seal_addBridgeObserver`), but
  they only observe if the target chain is reachable on the URL you
  provide. Useful for wire-format debugging, not a full round-trip.
- **Full stack**: run `./scripts/bridge-e2e.sh` — Docker-composed
  solana-test-validator + Stellar quickstart + 3 Seal nodes, with
  the bridge programs deployed on both sides and a scripted
  lock→mint→burn→unlock that populates the endpoints in §17.1–3
  with real data. Prerequisites are checked via
  `./scripts/bridge-e2e.sh check`.

**Auth**: per `requires_auth()` at `rpc.rs:319-347`, **only
`seal_bridgeWithdraw` is ML-DSA-authenticated**. `addBridgeObserver`,
`bridgeCouncilAdd/Remove`, `bridgePauseChain/UnpauseChain` are
currently **un-authenticated alpha-testnet bootstrap endpoints** —
anyone with RPC access can register an observer or seat a council
member. Role-based auth for those is a separate SPEC item (not in
this session's scope); drive them from plain `curl` until it lands.

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

All read-only (no auth), plain `curl`:

```bash
# List registered observers (starts at {"count": 0} on a fresh node)
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_listBridgeObservers","params":{}}' | jq

# Poll all registered observers once. With no observers this returns
# {"observed": 0, "new": 0, "duplicate": 0} — expected.
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

Register an observer (no auth today — alpha bootstrap endpoint; see
the §17 preamble):

```bash
# Solana observer — params: {chain, rpc_url, program_id}.
# Replace the program_id with the deployed seal-bridge Anchor program
# id (scripts/bridge-e2e.sh deploys one and prints it).
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_addBridgeObserver",
       "params":{"chain":"Solana","rpc_url":"http://127.0.0.1:8899","program_id":"<deployed-program-id>"}}' | jq

# Stellar observer — params: {chain, horizon_url, contract_id}.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_addBridgeObserver",
       "params":{"chain":"Stellar","horizon_url":"http://127.0.0.1:8000","contract_id":"<soroban-contract-id>"}}' | jq
```

### 17.2 Withdraw (auth required — the only signed bridge RPC today)

`seal_bridgeWithdraw` is the one bridge method in `requires_auth`, so
the caller's ML-DSA signature identifies whose wrapped balance to
burn. Params:
`{dest_chain, dest_address, token, amount}` — **`token` is required**
and `dest_address` is the *destination-chain* pubkey (Solana
ed25519 base58 / Stellar G-address), not a Seal address.

```bash
seal rpc --node $NODE --key treasury.json \
  --method seal_bridgeWithdraw \
  --params '{"dest_chain":"Solana","dest_address":"<solana-ed25519-pubkey>","token":"WSOL","amount":1000000}'
```

**Expected:** `minted_on_seal <= locked_on_source` invariant always
holds; withdrawals above the caller's wrapped balance fail; to a
paused chain fail with `ChainPaused`. Confirm via `seal_getBridgeStatus`
(§17.1) — the invariant and `paused_chains` are both surfaced there.

### 17.3 Emergency pause + Technical Council (landed 2026-04-19)

None of the council RPCs are auth-gated today (alpha bootstrap —
same caveat as observer registration). Plain `curl`. Council members
are identified by an ML-DSA verifying-key hex (the `pubkey` field);
generate one key file per seat so you have the hexes handy.

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
returns an empty list in single-node mode; `getNodeInfo` includes
address + verifying-key + current epoch.

## 19.1 SQL submission (auth required for writes)

`seal_submitSql` and `seal_deployNamespace` are in `requires_auth()`
(see `rpc.rs:323-326`), so writes need an ML-DSA signature. Use
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
auth-gated** (not listed in `requires_auth()` — see `rpc.rs:322-346`).
Plain curl works today; tighten in a follow-up if these become
billable.

```bash
# SPDZ private aggregation (sum/count/avg). `values` is the local
# party's shares; in production each party submits its own slice.
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"seal_mpcAggregate",
       "params":{"values":[10,20,30],"op":"sum"}}' | jq

# ZK prove a state transition. `pre_state_root`, `post_state_root`,
# and `tx_hash` are 32-byte SHA3 hex strings. Simulation mode by
# default; feature-gate `risc0` or `sp1` for real provers (§8).
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"seal_zkProve",
       "params":{"pre_state_root":"<32-byte hex>",
                 "post_state_root":"<32-byte hex>",
                 "block_height":1,"tx_count":3,
                 "tx_hash":"<32-byte hex>"}}' | jq
```

**Expected:**
- MPC aggregate returns the sum/count without revealing per-party
  values; uses `seal-mpc::spdz_sum` / `spdz_count` internally.
- ZK prove returns a proof (simulation mode by default — real STARK
  proving requires the `risc0` / `sp1` feature, §8).

## 19.4 Private tables RPC

`seal_createPrivateTable` is auth-gated (`rpc.rs:333`);
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
auth-gated (`rpc.rs:342-346`) — drive via `seal rpc --key`:

```bash
# 1. Propose. `track` ∈ {root, treasury, parameters, slashing,
#    bridge_pause, council_membership}; `payload` is opaque bytes
#    the proposal type interprets (e.g. JSON for parameter changes).
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_govPropose \
    --params '{"track":"treasury","title":"Bootstrap grant","payload":"{\"amount\":1000}"}'

# 2. Vote. `choice` ∈ {aye, nay, abstain};
#    `conviction` ∈ {none, x1, x2, x3, x4, x5, x6}.
#    Higher conviction = more vote weight + longer lock.
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_govVote \
    --params '{"proposal_id":1,"choice":"aye","conviction":"x3"}'

# 3. Withdraw an unlocked vote (after the conviction lock expires).
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_govWithdrawVote --params '{"proposal_id":1}'

# 4. Delegate vote weight to another address.
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_govDelegate \
    --params '{"track":"treasury","delegate":"sealt1…real-address…","conviction":"x2"}'

# 5. Revoke a delegation (subject to the conviction lock).
cargo run -p seal-cli -- rpc --node $NODE --key alice.json \
    --method seal_govRevokeDelegation --params '{"track":"treasury"}'
```

**Expected:** proposals advance through Pending → Voting → Decided
states once the per-track period elapses; vote weight = balance ×
conviction multiplier; adaptive quorum biases the threshold based on
turnout (low turnout requires a stronger majority). Underlying
mechanics live in `crates/seal-node/src/{governance,delegation}.rs`
(~30 unit tests). Bridge-pause is gated separately on the Technical
Council 2/3 supermajority — see §17.

## 19.5 PQ-RPC handshake (ML-KEM native transport)

The param is `client_public_key` (hex, not base64) — see
`rpc.rs:1350`. The handshake itself is public; the encrypted frames
that follow use the derived session key.

```bash
# Generate an ML-KEM keypair, then hand the public_key hex to the handshake.
cargo run -p seal-cli -- keygen --kem --output kem.json
CLIENT_PK=$(jq -r .public_key kem.json)
curl -s -X POST $NODE -H 'content-type: application/json' \
  -d "$(jq -cn --arg pk "$CLIENT_PK" \
        '{jsonrpc:"2.0",id:1,method:"seal_pqHandshake",params:{client_public_key:$pk}}')" | jq
```

**Expected:** server responds with a ciphertext (ML-KEM encapsulation
of a symmetric session key). Subsequent encrypted frames use the
derived session key with monotonic nonce + MAC verification. Unit
tests exercise this end-to-end in `seal-node::pq_rpc` (4 tests).

## 19.6 Internal-only state transitions (no RPC surface)

These features are exercised by consensus / epoch / block-production
logic, not by direct RPC. Their manual verification is via unit
tests + observation of on-chain state rather than RPC calls.

### Emission schedule
- File: `crates/seal-node/src/emission.rs`, `consensus_runner.rs:342-358`
- Wired: per-epoch emission applied during `produce_block_with_vrf`.
- Test: `cargo test -p seal-node emission` (5+ tests).
- Observe: `seal_getBalance` on the emission recipient before and
  after an epoch boundary.

### Treasury disbursement
- File: `crates/seal-node/src/treasury.rs`
- Wired: 10 % of emission per epoch credited to treasury address.
- Test: `cargo test -p seal-node treasury`.
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
- File: `crates/seal-node/src/slashing.rs`
- Wired: double-proposal + double-vote detection; slashed stake
  burned.
- Test: `cargo test -p seal-node slashing`.

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
cargo test -p seal-copy-trading --lib \
      -p seal-kyc --lib \
      -p seal-kindle --lib
```

Expected: 21 tests pass total (7 each). Note the `--lib` on each
package — the default-target invocation runs 0 tests for these
crates (same Cargo-target quirk as §18.1).

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

## Summary Checklist

| Feature         | Command                           | Expected Tests |
| --------------- | --------------------------------- | -------------- |
| Crypto          | `cargo test -p seal-crypto`     | 26+            |
| VRF             | `cargo test -p seal-vrf`        | 57+            |
| Threshold       | `cargo test -p seal-threshold`  | 75+            |
| Ringtail-verify | `cargo test -p seal-ringtail-verify --lib` | 20+       |
| SQL             | `cargo test -p seal-sql`        | 97+            |
| Merkle          | `cargo test -p seal-merkle`     | 35+            |
| Consensus crate | `cargo test -p seal-consensus`  | 57+            |
| Consensus + Node | `cargo test -p seal-node --lib` | 217+           |
| P2P             | `cargo test -p seal-p2p`        | 32+            |
| Bridge          | `cargo test -p seal-bridge`     | 48+            |
| ZK (default)    | `cargo test -p seal-zk`         | 46+            |
| ZK (real r0vm)  | `SEAL_RUN_REAL_RISC0=1 cargo test -p seal-zk --features risc0` | +8 |
| MPC             | `cargo test -p seal-mpc`        | 26+            |
| Private Tables  | `cargo test -p seal-node private_tables` | 8       |
| Storage         | `cargo test -p seal-storage`    | 18+            |
| Token           | `cargo test -p seal-token`      | 88+            |
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
| **Total** | `cargo test --workspace`        | **985+** |
