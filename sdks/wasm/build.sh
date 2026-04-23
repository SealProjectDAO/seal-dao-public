#!/bin/bash
# Build the WASM bindings for seal-crypto/seal-sql/seal-wallet.
#
# Outputs:
#   sdks/wasm/pkg/seal_dao_wasm.js        (glue)
#   sdks/wasm/pkg/seal_dao_wasm_bg.wasm   (binary)
#   sdks/wasm/pkg/seal_dao_wasm.d.ts      (types)
#
# The Electron wallet (apps/seal-wallet/) and the MV3 extension
# (apps/seal-wallet-extension/) both consume the same pkg/ output.
#
# Usage:
#   ./build.sh           # release build (default)
#   ./build.sh --dev     # dev build — faster, larger binary, debug symbols

set -euo pipefail
cd "$(dirname "$0")"

if ! command -v wasm-pack >/dev/null 2>&1; then
    cat >&2 <<'EOF'
error: wasm-pack is not installed.

Install it with one of:
    cargo install wasm-pack
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
    brew install wasm-pack
EOF
    exit 1
fi

PROFILE="--release"
if [[ "${1:-}" == "--dev" ]]; then
    PROFILE="--dev"
fi

# --target web emits the ES-module glue that both the Electron wallet
# (loaded via <script type="module">) and the MV3 extension consume.
wasm-pack build --target web $PROFILE

echo ""
echo "Built pkg/:"
ls -lh pkg/seal_dao_wasm_bg.wasm pkg/seal_dao_wasm.js 2>/dev/null || true
