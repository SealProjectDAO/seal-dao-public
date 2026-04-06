#!/bin/bash
# Build and open API documentation.
#
# Usage:
#   ./scripts/docs.sh        # Build and open in browser
#   ./scripts/docs.sh build  # Build only (no open)

set -e

echo "Building API documentation..."
cargo doc --no-deps 2>&1

if [ "$1" != "build" ]; then
    echo "Opening in browser..."
    open target/doc/seal_crypto/index.html 2>/dev/null || \
    xdg-open target/doc/seal_crypto/index.html 2>/dev/null || \
    echo "Open target/doc/seal_crypto/index.html in your browser"
fi

echo "Done. Docs at: target/doc/"
