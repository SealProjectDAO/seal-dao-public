#!/bin/bash
# Seal DAO CI Pipeline
#
# Main CI script — run before every merge.
# Runs build, tests, clippy, Kani, Miri, short fuzz, and cargo-audit.
#
# Usage:
#   ./scripts/ci.sh          # Full CI (all steps)
#   ./scripts/ci.sh quick    # Build + test + clippy only
#
# Prerequisites:
#   rustup install stable nightly
#   rustup +nightly component add miri
#   cargo install --locked kani-verifier && cargo kani setup
#   rustup run nightly cargo install cargo-fuzz
#   cargo install cargo-audit
#
# Exit code: number of failed steps (0 = all passed)

set -euo pipefail

MODE=${1:-full}
PASS=0
FAIL=0
SKIP=0
START_TIME=$(date +%s)

pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  [SKIP] $1 — $2"; SKIP=$((SKIP + 1)); }

echo "============================================"
echo "  Seal DAO CI Pipeline"
echo "  Mode: $MODE"
echo "  Started: $(date)"
echo "============================================"
echo ""

# ─── 1. Build ────────────────────────────────────
echo "── Step 1: cargo build ──"
if cargo build --lib --bins --tests --examples 2>&1 | tail -3; then
    pass "cargo build"
else
    fail "cargo build"
    echo "Build failed — aborting."
    exit 1
fi
echo ""

# ─── 2. Tests ────────────────────────────────────
echo "── Step 2: cargo test ──"
if cargo test -- --skip bench 2>&1 | tee /tmp/seal-ci-test.txt | tail -5; then
    TEST_COUNT=$(grep "^test result:" /tmp/seal-ci-test.txt | awk '{sum+=$4} END {print sum}')
    FAIL_COUNT=$(grep "^test result:" /tmp/seal-ci-test.txt | awk '{sum+=$6} END {print sum}')
    if [ "${FAIL_COUNT:-0}" = "0" ]; then
        pass "cargo test (${TEST_COUNT:-?} tests)"
    else
        fail "cargo test ($FAIL_COUNT failures)"
    fi
else
    fail "cargo test (error)"
fi
echo ""

# ─── 3. Clippy ───────────────────────────────────
echo "── Step 3: cargo clippy ──"
CLIPPY_OUTPUT=$(cargo clippy --lib --bins --tests --examples 2>&1 || true)
CLIPPY_ERRORS=$(echo "$CLIPPY_OUTPUT" | grep -c "^error" || true)
if [ "$CLIPPY_ERRORS" -eq 0 ]; then
    pass "cargo clippy"
else
    fail "cargo clippy ($CLIPPY_ERRORS errors)"
fi
echo ""

if [ "$MODE" = "quick" ]; then
    echo "── Quick mode: stopping after build + test + clippy ──"
    echo ""
    ELAPSED=$(( $(date +%s) - START_TIME ))
    echo "============================================"
    echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
    echo "  Elapsed: ${ELAPSED}s"
    echo "============================================"
    exit $FAIL
fi

# ─── 4. Kani ─────────────────────────────────────
echo "── Step 4: Kani bounded model checking ──"
if cargo kani --version > /dev/null 2>&1; then
    # All 6 Kani crates pass (46 harnesses total).
    KANI_CRATES=(seal-crypto seal-token seal-consensus seal-threshold seal-merkle seal-bridge)
    KANI_FAIL=0
    for crate in "${KANI_CRATES[@]}"; do
        echo "  Checking $crate..."
        if cargo kani -p "$crate" 2>&1 | tail -3; then
            true
        else
            echo "  [WARN] Kani failed for $crate"
            KANI_FAIL=$((KANI_FAIL + 1))
        fi
    done
    KANI_COUNT=$(grep -r "kani::proof" crates/ 2>/dev/null | wc -l | tr -d ' ')
    if [ "$KANI_FAIL" -eq 0 ]; then
        pass "Kani ($KANI_COUNT harnesses across ${#KANI_CRATES[@]} crates)"
    else
        fail "Kani ($KANI_FAIL crates failed)"
    fi
else
    skip "Kani" "not installed (cargo install --locked kani-verifier && cargo kani setup)"
fi
echo ""

# ─── 5. Miri ────────────────────────────────────
# Miri builds a custom sysroot and needs crates.io access for std.
# Temporarily disable vendor config so Miri can download std sources.
echo "── Step 5: Miri (undefined behavior detection) ──"
NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo 2>/dev/null)" 2>/dev/null || true)"
if [ -n "$NIGHTLY_BIN" ] && rustup component list --toolchain nightly 2>/dev/null | grep -q "miri.*installed"; then
    # Only run Miri on crates that actually contain unsafe code — it's an
    # interpreter (~100-1000× slower) so running it on safe-only crates wastes
    # minutes for zero benefit.
    MIRI_CRATES=()
    for crate_dir in crates/*/; do
        crate="$(basename "$crate_dir")"
        if grep -rn '\bunsafe\b' "$crate_dir/src" 2>/dev/null | grep -vq '//.*\bunsafe\b'; then
            # seal-crypto and seal-storage use ARM SHA3 intrinsics Miri can't interpret.
            if [ "$(uname -m)" = "arm64" ] || [ "$(uname -m)" = "aarch64" ]; then
                case "$crate" in seal-crypto|seal-storage) continue ;; esac
            fi
            MIRI_CRATES+=("$crate")
        fi
    done
    if [ ${#MIRI_CRATES[@]} -eq 0 ]; then
        skip "Miri" "no crates contain unsafe code"
    else
        MIRI_FAIL=0
        mv .cargo/config.toml .cargo/config.toml.ci-bak 2>/dev/null || true
        for crate in "${MIRI_CRATES[@]}"; do
            echo "  Checking $crate..."
            if MIRIFLAGS="-Zmiri-disable-isolation" PATH="$NIGHTLY_BIN:$PATH" cargo miri test -p "$crate" 2>&1 | tail -3; then
                true
            else
                echo "  [WARN] Miri failed for $crate"
                MIRI_FAIL=$((MIRI_FAIL + 1))
            fi
        done
        mv .cargo/config.toml.ci-bak .cargo/config.toml 2>/dev/null || true
        if [ "$MIRI_FAIL" -eq 0 ]; then
            pass "Miri (${#MIRI_CRATES[@]} crates)"
        else
            fail "Miri ($MIRI_FAIL crates failed)"
        fi
    fi
else
    skip "Miri" "nightly + miri component not found"
fi
echo ""

# ─── 6. Fuzz (short) ────────────────────────────
# cargo-fuzz needs nightly and its own deps (libfuzzer-sys) from crates.io.
# Temporarily disable vendor config so fuzz deps resolve from crates.io.
echo "── Step 6: Fuzz targets (15s each) ──"
NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo 2>/dev/null)" 2>/dev/null || true)"
if [ -n "$NIGHTLY_BIN" ] && PATH="$NIGHTLY_BIN:$PATH" cargo fuzz --version > /dev/null 2>&1; then
    FUZZ_TARGETS=(
        fuzz_sql_parser fuzz_vrf_verify fuzz_pqvrf_verify
        fuzz_address_parse fuzz_block_deserialize fuzz_tx_deserialize
        fuzz_merkle_ops fuzz_ringtail_verify fuzz_ringtail_sign
        fuzz_committee_vote
    )
    FUZZ_CRASHES=0
    mv .cargo/config.toml .cargo/config.toml.ci-bak 2>/dev/null || true
    for target in "${FUZZ_TARGETS[@]}"; do
        echo "  Fuzzing $target..."
        if PATH="$NIGHTLY_BIN:$PATH" cargo fuzz run "$target" -- -max_total_time=15 2>&1 | tail -1; then
            true
        else
            FUZZ_CRASHES=$((FUZZ_CRASHES + 1))
        fi
    done
    mv .cargo/config.toml.ci-bak .cargo/config.toml 2>/dev/null || true
    if [ "$FUZZ_CRASHES" -eq 0 ]; then
        pass "Fuzz (${#FUZZ_TARGETS[@]} targets, 15s each)"
    else
        fail "Fuzz ($FUZZ_CRASHES crashes)"
    fi
else
    skip "Fuzz" "nightly cargo-fuzz not found (rustup run nightly cargo install cargo-fuzz)"
fi
echo ""

# ─── 7. cargo-audit ─────────────────────────────
# Known warnings (all from transitive dependencies, not our code):
#   - ansi_term 0.12.1      unmaintained  (sp1-sdk via tracing-forest)
#   - bincode 1.3.3          unmaintained  (sp1-sdk, seal-zk, seal-storage)
#   - derivative 2.2.0       unmaintained  (sp1-sdk via ark-ff)
#   - fxhash 0.2.1           unmaintained  (sled → seal-storage)
#   - instant 0.1.13         unmaintained  (sled via parking_lot)
#   - number_prefix 0.4.0    unmaintained  (sp1-sdk via indicatif)
#   - paste 1.0.15           unmaintained  (sp1-sdk, risc0-zkvm, libp2p)
#   - rustls-pemfile 2.2.0   unmaintained  (sp1-sdk via tonic)
#   - lru 0.12.5             UNSOUND       (sp1-prover — RUSTSEC-2026-0002,
#                                            IterMut Stacked Borrows violation;
#                                            blocked on sp1 updating their dep)
# Action: 8/9 are unmaintained with no CVEs. The lru soundness bug is in
# sp1-prover internals; we don't call IterMut on any LRU cache directly.
# Re-evaluate when sp1-sdk or sled publish new releases.
#
# Ignored advisories (see .cargo/audit.toml for justifications):
#   - RUSTSEC-2023-0071  rsa 0.9.10            Marvin Attack, no fix (rzup)
#   - RUSTSEC-2025-0055  tracing-subscriber    0.2.25 ANSI (ark-relations 0.5)
echo "── Step 7: cargo-audit ──"
if cargo audit --version > /dev/null 2>&1; then
    if cargo audit 2>&1 | tail -5; then
        pass "cargo-audit"
    else
        fail "cargo-audit (advisories found)"
    fi
else
    skip "cargo-audit" "not installed (cargo install cargo-audit)"
fi
echo ""

# ─── Summary ─────────────────────────────────────
ELAPSED=$(( $(date +%s) - START_TIME ))
echo "============================================"
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "  Elapsed: $(( ELAPSED / 60 ))m $(( ELAPSED % 60 ))s"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
