#!/bin/bash
# Run all fuzz targets for a configurable duration.
#
# Usage:
#   ./scripts/fuzz-all.sh          # 60 seconds per target (default)
#   ./scripts/fuzz-all.sh 300      # 5 minutes per target
#   ./scripts/fuzz-all.sh 3600     # 1 hour per target (overnight)
#
# Prerequisites:
#   rustup install nightly
#   rustup run nightly cargo install cargo-fuzz

set -e

NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo 2>/dev/null)")"
export PATH="$NIGHTLY_BIN:$PATH"

DURATION=${1:-60}

TARGETS=(
    fuzz_sql_parser
    fuzz_vrf_verify
    fuzz_pqvrf_verify
    fuzz_address_parse
    fuzz_block_deserialize
    fuzz_tx_deserialize
    fuzz_merkle_ops
    fuzz_ringtail_verify
    fuzz_committee_vote
)

echo "=== Seal DAO Fuzz Suite ==="
echo "Duration: ${DURATION}s per target"
echo "Targets:  ${#TARGETS[@]}"
echo ""

FAILED=()

for target in "${TARGETS[@]}"; do
    echo "--- Fuzzing $target (${DURATION}s) ---"
    if cargo fuzz run "$target" -- -max_total_time="$DURATION" 2>&1; then
        echo "[OK] $target passed"
    else
        echo "[CRASH] $target found a bug!"
        FAILED+=("$target")
    fi
    echo ""
done

echo "=== Results ==="
echo "Passed: $(( ${#TARGETS[@]} - ${#FAILED[@]} )) / ${#TARGETS[@]}"

if [ ${#FAILED[@]} -gt 0 ]; then
    echo "FAILED:"
    for f in "${FAILED[@]}"; do
        echo "  - $f (check fuzz/artifacts/$f/)"
    done
    exit 1
fi

echo "All targets passed."
