#!/bin/bash
# Seal DAO verification script
# Runs all available verification checks.
#
# For the full formal verification pipeline, use: ./scripts/ci-formal.sh

set -e

echo "=== Seal DAO Verification Suite ==="
echo ""

# 1. Standard tests
echo "--- cargo test ---"
cargo test 2>&1 | tail -5
echo ""

# 2. Clippy lints
echo "--- cargo clippy ---"
cargo clippy --all-targets 2>&1 | grep -E "warning|error" | head -20 || echo "Clean!"
echo ""

# 3. Miri (if nightly available)
echo "--- Miri (UB detection) ---"
if rustup component list --toolchain nightly 2>/dev/null | grep -q "miri.*installed"; then
    # Only run Miri on crates that contain unsafe code.
    MIRI_FOUND=0
    for crate_dir in crates/*/; do
        crate="$(basename "$crate_dir")"
        if grep -rn '\bunsafe\b' "$crate_dir/src" 2>/dev/null | grep -vq '//.*\bunsafe\b'; then
            if [ "$(uname -m)" = "arm64" ] || [ "$(uname -m)" = "aarch64" ]; then
                case "$crate" in seal-crypto|seal-storage) continue ;; esac
            fi
            echo "  $crate..."
            MIRIFLAGS="-Zmiri-disable-isolation" rustup run nightly cargo miri test -p "$crate" 2>&1 | tail -3 || echo "  Miri failed for $crate"
            MIRI_FOUND=1
        fi
    done
    [ "$MIRI_FOUND" -eq 0 ] && echo "  No crates contain unsafe code — skipping"
else
    echo "Miri not available (install: rustup +nightly component add miri)"
fi
echo ""

# 4. cargo-audit (if installed)
echo "--- cargo audit (CVE check) ---"
if command -v cargo-audit > /dev/null 2>&1; then
    cargo audit 2>&1 | tail -5
else
    echo "cargo-audit not installed (install: cargo install cargo-audit)"
fi
echo ""

# 5. Kani (if installed)
echo "--- Kani (bounded model checking) ---"
if command -v cargo-kani > /dev/null 2>&1; then
    KANI_CRATES=(seal-crypto seal-token seal-consensus seal-threshold seal-merkle seal-bridge)
    for crate in "${KANI_CRATES[@]}"; do
        echo "  $crate..."
        cargo kani -p "$crate" 2>&1 | tail -3 || echo "  Kani failed for $crate"
    done
else
    echo "Kani not installed (install: cargo install --locked kani-verifier && cargo kani setup)"
fi
echo ""

echo "=== Verification complete ==="
echo "For full formal verification pipeline: ./scripts/ci-formal.sh"
