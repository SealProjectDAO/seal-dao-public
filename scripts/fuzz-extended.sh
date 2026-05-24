#!/bin/bash
# Extended fuzz campaign — run before releases and audits.
#
# Usage:
#   ./scripts/fuzz-extended.sh          # 1 hour per target (default)
#   ./scripts/fuzz-extended.sh 3600     # Custom seconds per target
#   ./scripts/fuzz-extended.sh 86400    # 24 hours per target (overnight)
#
# Prerequisites:
#   rustup install nightly
#   rustup run nightly cargo install cargo-fuzz
#
# This script:
# 1. Runs each fuzz target for the specified duration
# 2. Saves crash artifacts to fuzz/artifacts/<target>/
# 3. Generates a coverage report (if cargo-cov available)
# 4. Summarizes results

set -e

NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo 2>/dev/null)")"
export PATH="$NIGHTLY_BIN:$PATH"

DURATION=${1:-3600}  # default: 1 hour per target
TOTAL_START=$(date +%s)

TARGETS=(
    fuzz_sql_parser
    fuzz_vrf_verify
    fuzz_pqvrf_verify
    fuzz_address_parse
    fuzz_block_deserialize
    fuzz_tx_deserialize
    fuzz_merkle_ops
    fuzz_ringtail_verify
    fuzz_ringtail_sign
    fuzz_committee_vote
)

TOTAL_TARGETS=${#TARGETS[@]}
TOTAL_TIME=$((DURATION * TOTAL_TARGETS))

echo "============================================"
echo "  Seal DAO Extended Fuzz Campaign"
echo "============================================"
echo ""
echo "Duration: ${DURATION}s per target ($(( DURATION / 60 )) min)"
echo "Targets:  ${TOTAL_TARGETS}"
echo "Total:    $(( TOTAL_TIME / 3600 ))h $(( (TOTAL_TIME % 3600) / 60 ))m"
echo "Started:  $(date)"
echo ""

CRASHED=()
PASSED=()

for i in "${!TARGETS[@]}"; do
    target="${TARGETS[$i]}"
    num=$((i + 1))
    echo "[$num/$TOTAL_TARGETS] Fuzzing $target for ${DURATION}s..."
    START=$(date +%s)

    if cargo fuzz run "$target" -- -max_total_time="$DURATION" -print_final_stats=1 2>&1 | tail -5; then
        ELAPSED=$(( $(date +%s) - START ))
        echo "  [PASS] $target completed in ${ELAPSED}s"
        PASSED+=("$target")
    else
        ELAPSED=$(( $(date +%s) - START ))
        echo "  [CRASH] $target found a bug after ${ELAPSED}s!"
        echo "  Artifacts: fuzz/artifacts/$target/"
        CRASHED+=("$target")
    fi
    echo ""
done

TOTAL_ELAPSED=$(( $(date +%s) - TOTAL_START ))

echo "============================================"
echo "  Results"
echo "============================================"
echo ""
echo "Duration:  $(( TOTAL_ELAPSED / 3600 ))h $(( (TOTAL_ELAPSED % 3600) / 60 ))m $(( TOTAL_ELAPSED % 60 ))s"
echo "Passed:    ${#PASSED[@]} / $TOTAL_TARGETS"
echo ""

if [ ${#CRASHED[@]} -gt 0 ]; then
    echo "CRASHES FOUND:"
    for target in "${CRASHED[@]}"; do
        echo "  - $target"
        echo "    Artifacts: fuzz/artifacts/$target/"
        if [ -d "fuzz/artifacts/$target" ]; then
            echo "    Files: $(ls fuzz/artifacts/$target/ 2>/dev/null | wc -l | tr -d ' ')"
        fi
    done
    echo ""
    echo "Action: investigate crash artifacts and fix before release."
    exit 1
else
    echo "All targets passed. No crashes found."
    echo ""
    echo "Consider running with longer duration for pre-audit campaigns:"
    echo "  ./scripts/fuzz-extended.sh 86400  # 24h per target"
fi
