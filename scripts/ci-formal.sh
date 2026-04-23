#!/bin/bash
# Seal DAO Formal Verification CI Pipeline
#
# Runs all formal verification tools in order of speed:
# 1. cargo test        (~2 min) — 564+ unit/integration tests
# 2. cargo clippy      (~30s)   — lint checks
# 3. Kani              (~5 min) — 60 bounded model checking harnesses
# 4. Miri              (~3 min) — undefined behavior detection
# 5. Fuzz (short)      (~2 min) — 9 fuzz targets, 15s each
# 6. Lean 4            (~1 min) — mathematical proofs
# 7. Rocq              (~1 min) — state machine proofs
#
# Usage:
#   ./scripts/ci-formal.sh          # Run everything
#   ./scripts/ci-formal.sh quick    # Tests + clippy + Kani only
#   ./scripts/ci-formal.sh nightly  # Full suite + long fuzz (5 min/target)
#
# Prerequisites:
#   cargo install --locked kani-verifier && cargo kani setup
#   rustup +nightly component add miri
#   rustup run nightly cargo install cargo-fuzz
#   # For Lean 4: elan (https://leanprover.github.io/lean4/doc/setup.html)
#   # For Rocq: opam install coq

set -e

MODE=${1:-full}
FUZZ_DURATION=15
if [ "$MODE" = "nightly" ]; then
    FUZZ_DURATION=300
fi

PASS=0
FAIL=0
SKIP=0

pass() { echo "[PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }
skip() { echo "[SKIP] $1 — $2"; SKIP=$((SKIP + 1)); }

echo "============================================"
echo "  Seal DAO Formal Verification Pipeline"
echo "  Mode: $MODE"
echo "============================================"
echo ""

# ─── 1. Unit Tests ────────────────────────────────
echo "── Step 1: cargo test ──"
if cargo test 2>&1 | tee /tmp/seal-test-output.txt | tail -3; then
    TEST_COUNT=$(grep "^test result:" /tmp/seal-test-output.txt | awk '{sum+=$4} END {print sum}')
    FAIL_COUNT=$(grep "^test result:" /tmp/seal-test-output.txt | awk '{sum+=$6} END {print sum}')
    if [ "$FAIL_COUNT" = "0" ]; then
        pass "cargo test ($TEST_COUNT tests)"
    else
        fail "cargo test ($FAIL_COUNT failures)"
    fi
else
    fail "cargo test (build/run error)"
fi
echo ""

# ─── 2. Clippy ────────────────────────────────────
echo "── Step 2: cargo clippy ──"
CLIPPY_ERRORS=$(cargo clippy --all-targets 2>&1 | grep "^error" | wc -l)
if [ "$CLIPPY_ERRORS" -eq 0 ]; then
    pass "cargo clippy"
else
    fail "cargo clippy ($CLIPPY_ERRORS errors)"
fi
echo ""

# ─── 3. Kani ──────────────────────────────────────
echo "── Step 3: Kani bounded model checking ──"
if command -v cargo-kani > /dev/null 2>&1; then
    KANI_CRATES=(seal-crypto seal-token seal-consensus seal-threshold seal-merkle seal-bridge)
    KANI_OK=true
    for crate in "${KANI_CRATES[@]}"; do
        echo "  Checking $crate..."
        if cargo kani -p "$crate" 2>&1 | tail -3; then
            true
        else
            echo "  [WARN] Kani failed for $crate"
            KANI_OK=false
        fi
    done
    if $KANI_OK; then
        KANI_COUNT=$(grep -r "kani::proof" crates/ | wc -l | tr -d ' ')
        pass "Kani ($KANI_COUNT harnesses)"
    else
        fail "Kani (some crates failed)"
    fi
else
    skip "Kani" "not installed (cargo install --locked kani-verifier)"
fi
echo ""

if [ "$MODE" = "quick" ]; then
    echo "── Quick mode: skipping Miri, fuzz, Lean, Rocq ──"
    echo ""
    echo "============================================"
    echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
    echo "============================================"
    exit $FAIL
fi

# ─── 4. Miri ─────────────────────────────────────
#
# The workspace `.cargo/config.toml` redirects `crates-io` at the
# vendored `/vendor` directory. That's right for normal builds but
# breaks Miri's sysroot build — Miri's `std` has its own Cargo.lock
# pinning exact dep versions that may not all be in vendor. We
# sidestep the clash by moving the project config aside for the
# duration of the Miri step, then restoring it.
miri_pushd_no_vendor() {
    if [ -f .cargo/config.toml ]; then
        mv .cargo/config.toml .cargo/config.toml.miri-hidden
    fi
}
miri_popd_restore() {
    if [ -f .cargo/config.toml.miri-hidden ]; then
        mv .cargo/config.toml.miri-hidden .cargo/config.toml
    fi
}

echo "── Step 4: Miri (undefined behavior detection) ──"
if rustup component list --toolchain nightly 2>/dev/null | grep -q "miri.*installed"; then
    # We Miri-check two disjoint groups:
    #   A. Crates that contain `unsafe` blocks — high-signal target.
    #      On ARM64 we skip seal-crypto / seal-storage: both route into
    #      C FFI (pqcrypto-*, sled) which Miri can't interpret.
    #   B. Pure-safe crates with non-trivial data-structure logic. These
    #      rarely find bugs, but catch regressions the day someone
    #      introduces an `unsafe` block. Kept cheap: test only.
    MIRI_CRATES=()
    for crate_dir in crates/*/; do
        crate="$(basename "$crate_dir")"
        if grep -rn '\bunsafe\b' "$crate_dir/src" 2>/dev/null | grep -vq '//.*\bunsafe\b'; then
            if [ "$(uname -m)" = "arm64" ] || [ "$(uname -m)" = "aarch64" ]; then
                case "$crate" in seal-crypto|seal-storage) continue ;; esac
            fi
            MIRI_CRATES+=("$crate")
        fi
    done
    # Group B: pure-safe data-structure crates we want to keep UB-clean.
    # Append only those that aren't already present from group A and
    # that do not depend on seal-crypto/seal-storage (FFI transitively).
    MIRI_PURE=(seal-merkle seal-token seal-threshold seal-mpc)
    for c in "${MIRI_PURE[@]}"; do
        skip_already=false
        for existing in "${MIRI_CRATES[@]}"; do
            if [ "$existing" = "$c" ]; then skip_already=true; break; fi
        done
        if ! $skip_already; then
            MIRI_CRATES+=("$c")
        fi
    done
    if [ ${#MIRI_CRATES[@]} -eq 0 ]; then
        skip "Miri" "no candidate crates"
    else
        MIRI_OK=true
        miri_pushd_no_vendor
        trap miri_popd_restore EXIT
        for crate in "${MIRI_CRATES[@]}"; do
            echo "  Checking $crate..."
            if MIRIFLAGS="-Zmiri-disable-isolation" rustup run nightly cargo miri test -p "$crate" 2>&1 | tail -3; then
                true
            else
                echo "  [WARN] Miri failed for $crate"
                MIRI_OK=false
            fi
        done
        miri_popd_restore
        trap - EXIT
        if $MIRI_OK; then
            pass "Miri (${#MIRI_CRATES[@]} crates)"
        else
            fail "Miri"
        fi
    fi
else
    skip "Miri" "not installed (rustup +nightly component add miri)"
fi
echo ""

# ─── 5. Fuzz Targets ─────────────────────────────
echo "── Step 5: Fuzz targets (${FUZZ_DURATION}s each) ──"
NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo 2>/dev/null)" 2>/dev/null || true)"
if [ -n "$NIGHTLY_BIN" ] && PATH="$NIGHTLY_BIN:$PATH" cargo fuzz --version > /dev/null 2>&1; then
    FUZZ_TARGETS=(
        fuzz_sql_parser fuzz_vrf_verify fuzz_pqvrf_verify
        fuzz_address_parse fuzz_block_deserialize fuzz_tx_deserialize
        fuzz_merkle_ops fuzz_ringtail_verify fuzz_committee_vote
    )
    FUZZ_CRASHES=0
    for target in "${FUZZ_TARGETS[@]}"; do
        echo "  Fuzzing $target..."
        if PATH="$NIGHTLY_BIN:$PATH" cargo fuzz run "$target" -- -max_total_time="$FUZZ_DURATION" 2>&1 | tail -1; then
            true
        else
            FUZZ_CRASHES=$((FUZZ_CRASHES + 1))
        fi
    done
    if [ "$FUZZ_CRASHES" -eq 0 ]; then
        pass "Fuzz (${#FUZZ_TARGETS[@]} targets, ${FUZZ_DURATION}s each)"
    else
        fail "Fuzz ($FUZZ_CRASHES crashes found)"
    fi
else
    skip "Fuzz" "nightly cargo-fuzz not found"
fi
echo ""

# ─── 6. Lean 4 ───────────────────────────────────
echo "── Step 6: Lean 4 proofs ──"
if command -v lake > /dev/null 2>&1; then
    cd formal/lean
    if lake build 2>&1 | tail -3; then
        SORRY_COUNT=$(grep -r "sorry" SealVerify/ 2>/dev/null | wc -l | tr -d ' ')
        pass "Lean 4 ($SORRY_COUNT sorries)"
    else
        fail "Lean 4 (build failed)"
    fi
    cd ../..
else
    skip "Lean 4" "not installed (https://leanprover.github.io/lean4/doc/setup.html)"
fi
echo ""

# ─── 7. Rocq ─────────────────────────────────────
echo "── Step 7: Rocq/Coq proofs ──"
if command -v coqc > /dev/null 2>&1; then
    cd formal/rocq
    if make 2>&1 | tail -3; then
        ADMITTED=$(grep -r "Admitted" seal_verify/ 2>/dev/null | wc -l | tr -d ' ')
        pass "Rocq ($ADMITTED Admitted)"
    else
        fail "Rocq (build failed)"
    fi
    cd ../..
else
    skip "Rocq" "not installed (opam install coq)"
fi
echo ""

# ─── Summary ─────────────────────────────────────
echo "============================================"
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
