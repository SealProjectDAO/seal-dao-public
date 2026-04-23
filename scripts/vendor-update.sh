#!/bin/bash
# Update vendored dependencies for the workspace, the fuzz crate, and
# the seal-wallet-android FFI crate.
#
# Usage: ./scripts/vendor-update.sh
#
# Vendors workspace deps first, then the out-of-workspace crates with
# --no-delete so all sets coexist in vendor/.

set -euo pipefail

# One vendor pass that resolves the workspace + fuzz + seal-wallet-android
# lockfiles together. --sync makes cargo consider all three lockfiles in a
# single resolution, and --versioned-dirs ensures version conflicts between
# them land in distinct `name-version/` directories instead of overwriting
# each other.
#
# The fuzz manifest needs the nightly toolchain because it uses
# `cargo-fuzz` build metadata, so we run the whole thing under nightly.

echo "── Vendoring (workspace + fuzz + seal-wallet-android) ──"
mv .cargo/config.toml .cargo/config.toml.bak
NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo)")"
PATH="$NIGHTLY_BIN:$PATH" cargo vendor \
    --versioned-dirs \
    --sync fuzz/Cargo.toml \
    --sync apps/seal-wallet-android/Cargo.toml \
    vendor/ 2>&1 | tail -1
mv .cargo/config.toml.bak .cargo/config.toml
echo ""

echo "── Verifying ──"
cargo build -p seal-crypto 2>&1 | tail -1
echo "Done."
