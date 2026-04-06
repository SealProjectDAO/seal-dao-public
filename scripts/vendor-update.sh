#!/bin/bash
# Update vendored dependencies for both workspace and fuzz crate.
#
# Usage: ./scripts/vendor-update.sh
#
# Vendors workspace deps first, then fuzz deps with --no-delete
# so both sets coexist in vendor/.

set -euo pipefail

echo "── Vendoring workspace deps ──"
mv .cargo/config.toml .cargo/config.toml.bak
cargo vendor vendor/ 2>&1 | tail -1
echo ""

echo "── Vendoring fuzz deps (nightly) ──"
NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo)")"
PATH="$NIGHTLY_BIN:$PATH" cargo vendor --manifest-path fuzz/Cargo.toml --no-delete vendor/ 2>&1 | tail -1
mv .cargo/config.toml.bak .cargo/config.toml
echo ""

echo "── Verifying ──"
cargo build -p seal-crypto 2>&1 | tail -1
echo "Done."
