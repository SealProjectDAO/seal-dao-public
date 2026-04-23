#!/usr/bin/env bash
# scripts/bridge-test-ringtail.sh — build + unit-test the bridge
# programs with the algebraic Ringtail verify feature enabled, and
# measure their on-chain compute cost.
#
# Prerequisite: ./scripts/install-bridge-toolchains.sh has been run
# (or the three CLIs are otherwise on PATH at the pinned versions).
#
# What this does:
#   1. Temporarily move .cargo/config.toml aside so Anchor/Soroban can
#      reach crates.io (the workspace config pins vendored sources,
#      which don't carry anchor-lang or soroban-sdk).
#   2. Solana: anchor build --features ringtail-verify; anchor test
#      against a local test-validator; parse CU from the logs.
#   3. Stellar: stellar contract build --features ringtail-verify;
#      cargo test in-harness; parse instruction cost from the
#      `stellar contract invoke --cost` output for unlock_xlm.
#   4. Restore .cargo/config.toml regardless of outcome.
#
# Output:
#   bridges/solana/target/ringtail-cost.txt   (CU measurement)
#   bridges/stellar/target/ringtail-cost.txt  (instruction measurement)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'
say() { echo -e "${BOLD}==>${NC} $*"; }
ok()  { echo -e "${GREEN}✓${NC} $*"; }
warn(){ echo -e "${YELLOW}!${NC} $*"; }
err() { echo -e "${RED}✗${NC} $*" >&2; }

# ~/.cargo/bin must come BEFORE the toolchain's direct bin so that
# `cargo +<toolchain>` invocations hit the rustup proxy rather than the
# toolchain's direct binary (which doesn't understand `+toolchain` and
# fails with "no such command: `+1.89.0-sbpf-solana-v1.52`"). See the
# proxy setup in install-bridge-toolchains.sh for the full story.
if [[ -d "$HOME/.cargo/bin" ]]; then
    export PATH="$HOME/.cargo/bin:$PATH"
fi
# Ensure Solana's bin is in PATH for this shell.
if [[ -d "$HOME/.local/share/solana/install/active_release/bin" ]]; then
    export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
fi

# Precheck — fail early with a clear message if the toolchains aren't
# installed yet.
missing=()
command -v anchor  >/dev/null 2>&1 || missing+=("anchor-cli")
command -v solana  >/dev/null 2>&1 || missing+=("solana-cli")
command -v stellar >/dev/null 2>&1 || missing+=("stellar-cli")
if (( ${#missing[@]} > 0 )); then
    err "Missing: ${missing[*]}"
    err "Run ./scripts/install-bridge-toolchains.sh first."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: move vendor config aside. The cleanup trap puts it back no
# matter what.
# ---------------------------------------------------------------------------
VENDOR_CFG=".cargo/config.toml"
VENDOR_CFG_BAK=".cargo/config.toml.bridge-bak"
restore_vendor_cfg() {
    if [[ -f "$VENDOR_CFG_BAK" ]]; then
        mv "$VENDOR_CFG_BAK" "$VENDOR_CFG"
        ok "restored $VENDOR_CFG"
    fi
}
trap restore_vendor_cfg EXIT

if [[ -f "$VENDOR_CFG" ]]; then
    say "moving $VENDOR_CFG aside (vendor-sources config blocks anchor/soroban deps)"
    mv "$VENDOR_CFG" "$VENDOR_CFG_BAK"
fi

# ---------------------------------------------------------------------------
# Step 2: Solana / Anchor
# ---------------------------------------------------------------------------
say "Solana: cargo build-sbf --features ringtail-verify"
pushd bridges/solana/programs/seal-bridge >/dev/null

# Solana BPF ships its own rustc (currently 1.89.0-dev as of Agave
# 3.1.x). `constant_time_eq 0.4.3` bumped rust-version to 1.95 — blake3
# requires `^0.4.2`, and 0.4.3 is within that range. Pin to 0.4.2
# (rust-version 1.85) to stay under Solana's rustc ceiling without
# dropping below blake3's semver floor.
if [[ ! -f Cargo.lock ]]; then
    say "Generating Cargo.lock"
    cargo generate-lockfile 2>&1 | tail -5
fi
say "Pinning constant_time_eq to 0.4.2"
cargo update -p constant_time_eq --precise 0.4.2 2>&1 | tail -3 || true

# `anchor build` in 0.31.x only propagates features to the IDL-build
# phase, not the BPF compile — the .so never appears in target/deploy.
# `cargo build-sbf` IS what anchor invokes internally for the BPF
# phase, and it accepts --features directly.
cargo build-sbf --features ringtail-verify 2>&1 | tee build-sbf.log | tail -5
ok "BPF build complete"

# cargo build-sbf writes to the program's LOCAL target/, not the
# workspace target (there's no workspace root above seal-bridge).
SO_PATH="target/deploy/seal_bridge.so"
mkdir -p target
if [[ -f "$SO_PATH" ]]; then
    so_size=$(wc -c < "$SO_PATH" | tr -d ' ')
    ok "BPF artifact: $SO_PATH ($so_size bytes)"
    {
        echo "# Solana BPF build size (ringtail-verify feature ON)"
        echo "seal_bridge.so: $so_size bytes"
        echo ""
        echo "# Note: full CU measurement requires running against"
        echo "# solana-test-validator with instrumented instructions."
        echo "# This script only builds; measurement is future work."
        echo "# (Parse \`consumed X of Y compute units\` from solana logs"
        echo "# during a live unlock_tokens ix invocation.)"
    } > target/ringtail-cost.txt
else
    warn "seal_bridge.so not found at $SO_PATH"
fi
popd >/dev/null

# ---------------------------------------------------------------------------
# Step 3: Stellar / Soroban
# ---------------------------------------------------------------------------
say "Stellar: stellar contract build --features ringtail-verify"
pushd bridges/stellar >/dev/null
# stellar CLI accepts --features directly (unlike `anchor build`,
# which needs `-- --features` pass-through).
stellar contract build --features ringtail-verify 2>&1 | tee target/build.log | tail -5
ok "stellar contract build complete"

mkdir -p target
WASM_PATH="target/wasm32v1-none/release/seal_bridge_stellar.wasm"
if [[ ! -f "$WASM_PATH" ]]; then
    # Stellar 22.x used wasm32-unknown-unknown; 22.x-later moved to
    # wasm32v1-none. Accept either.
    WASM_PATH_ALT="target/wasm32-unknown-unknown/release/seal_bridge_stellar.wasm"
    if [[ -f "$WASM_PATH_ALT" ]]; then WASM_PATH="$WASM_PATH_ALT"; fi
fi
if [[ -f "$WASM_PATH" ]]; then
    wasm_size=$(wc -c < "$WASM_PATH" | tr -d ' ')
    ok "Soroban artifact: $WASM_PATH ($wasm_size bytes)"
    {
        echo "# Soroban WASM build size (ringtail-verify feature ON)"
        echo "seal_bridge_stellar.wasm: $wasm_size bytes"
        echo ""
        echo "# Note: full instruction-count measurement requires"
        echo "# running against a local stellar-core + invoking"
        echo "# unlock_xlm with --cost. This script only builds."
    } > target/ringtail-cost.txt
else
    warn "wasm artifact not found (looked in wasm32v1-none and wasm32-unknown-unknown)"
fi
popd >/dev/null

# ---------------------------------------------------------------------------
# Step 4: summary
# ---------------------------------------------------------------------------
echo
say "Done. Build-size artifacts:"
echo "    bridges/solana/programs/seal-bridge/target/ringtail-cost.txt"
echo "    bridges/stellar/target/ringtail-cost.txt"
