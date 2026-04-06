#!/bin/bash
# Seal DAO Nightly CI Pipeline
#
# Extended verification suite — run nightly or before releases.
# Includes everything from ci.sh PLUS:
# - Extended fuzzing (5 min/target)
# - Lean 4 proof building
# - Rocq/Coq proof building
#
# Usage:
#   ./scripts/ci-nightly.sh              # Default: 5 min fuzz per target
#   ./scripts/ci-nightly.sh 3600         # Custom fuzz duration (seconds/target)
#
# Prerequisites (in addition to ci.sh prerequisites):
#   elan (Lean 4): https://leanprover.github.io/lean4/doc/setup.html
#   opam install coq (Rocq/Coq)
#
# Exit code: number of failed steps (0 = all passed)

set -euo pipefail

FUZZ_DURATION=${1:-300}  # default: 5 min per target
PASS=0
FAIL=0
SKIP=0
START_TIME=$(date +%s)

pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  [SKIP] $1 — $2"; SKIP=$((SKIP + 1)); }

TOTAL_FUZZ_TIME=$(( FUZZ_DURATION * 9 ))

echo "============================================"
echo "  Seal DAO Nightly CI Pipeline"
echo "  Fuzz: ${FUZZ_DURATION}s/target ($(( TOTAL_FUZZ_TIME / 60 ))m total)"
echo "  Started: $(date)"
echo "============================================"
echo ""

# ─── 1. Full CI suite ───────────────────────────
echo "── Step 1: Run full CI suite (ci.sh) ──"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if "$SCRIPT_DIR/ci.sh" 2>&1 | tail -5; then
    pass "ci.sh (full suite)"
else
    fail "ci.sh (full suite)"
fi
echo ""

# ─── 2. Extended Fuzz Campaign ──────────────────
echo "── Step 2: Extended fuzz campaign (${FUZZ_DURATION}s/target) ──"
NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo 2>/dev/null)" 2>/dev/null || true)"
if [ -n "$NIGHTLY_BIN" ] && PATH="$NIGHTLY_BIN:$PATH" cargo fuzz --version > /dev/null 2>&1; then
    FUZZ_TARGETS=(
        fuzz_sql_parser fuzz_vrf_verify fuzz_pqvrf_verify
        fuzz_address_parse fuzz_block_deserialize fuzz_tx_deserialize
        fuzz_merkle_ops fuzz_ringtail_verify fuzz_committee_vote
    )
    FUZZ_CRASHES=0
    TOTAL=${#FUZZ_TARGETS[@]}
    for i in "${!FUZZ_TARGETS[@]}"; do
        target="${FUZZ_TARGETS[$i]}"
        num=$((i + 1))
        echo "  [$num/$TOTAL] Fuzzing $target for ${FUZZ_DURATION}s..."
        FSTART=$(date +%s)
        if PATH="$NIGHTLY_BIN:$PATH" cargo fuzz run "$target" -- -max_total_time="$FUZZ_DURATION" 2>&1 | tail -1; then
            FELAPSED=$(( $(date +%s) - FSTART ))
            echo "  PASS ($target, ${FELAPSED}s)"
        else
            FELAPSED=$(( $(date +%s) - FSTART ))
            echo "  CRASH ($target, ${FELAPSED}s) — artifacts: fuzz/artifacts/$target/"
            FUZZ_CRASHES=$((FUZZ_CRASHES + 1))
        fi
    done
    if [ "$FUZZ_CRASHES" -eq 0 ]; then
        pass "Extended fuzz ($TOTAL targets, ${FUZZ_DURATION}s each)"
    else
        fail "Extended fuzz ($FUZZ_CRASHES crashes)"
    fi
else
    skip "Extended fuzz" "cargo-fuzz not installed"
fi
echo ""

# ─── 3. Lean 4 Proofs ──────────────────────────
echo "── Step 3: Lean 4 proofs ──"
if command -v lake > /dev/null 2>&1; then
    LEAN_DIR="$(cd "$(dirname "$0")/.." && pwd)/formal/lean"
    if (cd "$LEAN_DIR" && lake build 2>&1 | tail -3); then
        SORRY_COUNT=$(grep -r "sorry" "$LEAN_DIR/SealVerify/" 2>/dev/null | grep -v "-- sorry" | wc -l | tr -d ' ')
        if [ "$SORRY_COUNT" -eq 0 ]; then
            pass "Lean 4 (0 sorries)"
        else
            fail "Lean 4 ($SORRY_COUNT sorries remaining)"
        fi
    else
        fail "Lean 4 (build failed)"
    fi
else
    skip "Lean 4" "not installed (https://leanprover.github.io/lean4/doc/setup.html)"
fi
echo ""

# ─── 4. Rocq/Coq Proofs ────────────────────────
echo "── Step 4: Rocq/Coq proofs ──"
if command -v coqc > /dev/null 2>&1; then
    ROCQ_DIR="$(cd "$(dirname "$0")/.." && pwd)/formal/rocq"
    if (cd "$ROCQ_DIR" && make 2>&1 | tail -3); then
        ADMITTED=$(grep -r "Admitted" "$ROCQ_DIR/seal_verify/" 2>/dev/null | wc -l | tr -d ' ')
        if [ "$ADMITTED" -eq 0 ]; then
            pass "Rocq/Coq (0 Admitted)"
        else
            fail "Rocq/Coq ($ADMITTED Admitted remaining)"
        fi
    else
        fail "Rocq/Coq (build failed)"
    fi
else
    skip "Rocq/Coq" "not installed (opam install coq)"
fi
echo ""

# ─── Summary ─────────────────────────────────────
ELAPSED=$(( $(date +%s) - START_TIME ))
echo "============================================"
echo "  Nightly Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "  Elapsed: $(( ELAPSED / 3600 ))h $(( (ELAPSED % 3600) / 60 ))m $(( ELAPSED % 60 ))s"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "Failures found. Investigate before release."
    exit 1
else
    echo ""
    echo "All checks passed."
fi
