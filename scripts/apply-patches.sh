#!/bin/bash
# Apply PQC patches to vendored dependencies.
#
# Run this AFTER vendor-update.sh to apply our PQC modifications.
#
# Usage:
#   ./scripts/apply-patches.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== Applying PQC patches ==="

# Check vendor exists
if [ ! -d vendor/libp2p-noise ]; then
    echo "Error: vendor/ not found. Run ./scripts/vendor-update.sh first."
    exit 1
fi

# Apply patches
for patch in patches/*.patch; do
    if [ -f "$patch" ]; then
        echo "Applying: $patch"
        # Extract target dir from patch filename (e.g., libp2p-noise-pqc.patch → vendor/libp2p-noise)
        target=$(basename "$patch" | sed 's/-pqc\.patch//')
        if [ -d "vendor/$target" ]; then
            cd "vendor/$target"
            patch -p1 < "../../$patch" || echo "  Warning: patch may have already been applied"
            cd "$PROJECT_DIR"
        else
            echo "  Skip: vendor/$target not found"
        fi
    fi
done

echo ""
echo "=== Patches applied ==="
echo "Build with: cargo build"
