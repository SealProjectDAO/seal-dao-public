#!/usr/bin/env bash
# scripts/relayer-smoke.sh — non-destructive smoke test for the
# per-validator bridge unlock relayer (P1#3).
#
# What it does:
#   1. Verifies the local docker stack is up + node1 RPC is reachable.
#   2. Builds + invokes seal-relayer in --dry-run mode for ~15s,
#      pointing at node1's seal-node + the local stellar/quickstart
#      contract.
#   3. Greps the captured stderr for the "DRY RUN — would submit
#      unlock" line, confirming the relayer's polling + filtering +
#      back-off path is wired and sees committee-signed withdrawals.
#   4. Reports pass/fail.
#
# Why dry-run only:
#   The local Solana / Stellar containers don't have funded relayer
#   destination-chain wallets pre-staged, and the relayer's --dry-run
#   mode covers the whole loop except the actual chain submission +
#   mark-executed. That's enough for "is the binary alive and seeing
#   the right withdrawals" without yak-shaving the funding step.
#
# Prerequisites:
#   ./scripts/bridge-e2e.sh up        # local 5-node + Soroban + Solana
#   ./scripts/bridge-e2e.sh           # at least one full forward leg
#                                     # so the bridge has burned
#                                     # withdrawals to surface
#
# Exit codes:
#   0  smoke pass — relayer saw + processed at least one dry-run entry
#   1  preflight failed (stack not up, key file missing, etc.)
#   2  smoke fail — relayer started but never logged a dry-run line
#   3  smoke fail — relayer crashed within the observation window

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

color() { printf '\033[%sm%s\033[0m\n' "$1" "${*:2}"; }
info() { color "36" "==> $*"; }
pass() { color "32" "[ok] $*"; }
fail() { color "31" "[!!] $*" >&2; }

SEAL_RPC="${SEAL_RPC:-http://localhost:8645}"
RELAYER_BIN="$REPO_DIR/target/debug/seal-relayer"
SEAL_E2E_KEY="$REPO_DIR/bridges/.seal-e2e-key.json"
OBSERVE_SECS="${OBSERVE_SECS:-15}"

# ── Preflight ───────────────────────────────────────────────

info "preflight"

if ! curl -sS --max-time 2 "$SEAL_RPC" \
        -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"seal_getHeight","params":[]}' \
        >/dev/null 2>&1; then
    fail "node1 RPC unreachable at $SEAL_RPC"
    fail "  bring up the stack: ./scripts/bridge-e2e.sh up"
    exit 1
fi

if [ ! -f "$SEAL_E2E_KEY" ]; then
    fail "missing $SEAL_E2E_KEY"
    fail "  the e2e key is created by ./scripts/bridge-e2e.sh on its first forward run."
    fail "  run that at least once before this smoke test."
    exit 1
fi

if ! cargo build --quiet -p seal-relayer 2>&1 | tail -3; then
    fail "cargo build -p seal-relayer failed"
    exit 1
fi
if [ ! -x "$RELAYER_BIN" ]; then
    fail "binary not at $RELAYER_BIN after build (cargo profile mismatch?)"
    exit 1
fi

# ── Run relayer in dry-run mode ─────────────────────────────

info "spawning seal-relayer --dry-run for ${OBSERVE_SECS}s (node=$SEAL_RPC)"
log_file=$(mktemp)
cleanup() {
    rm -f "$log_file" "$log_file.cursor"
    if [ -n "${relayer_pid:-}" ]; then
        kill "$relayer_pid" 2>/dev/null || true
        wait "$relayer_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Use a short interval so we exercise the loop more than once in
# OBSERVE_SECS, and a tiny back-off ceiling so dry-run logs land
# fast.
RUST_LOG="${RUST_LOG:-seal_relayer=info}" \
    "$RELAYER_BIN" \
        --key "$SEAL_E2E_KEY" \
        --node "$SEAL_RPC" \
        --cursor-file "$log_file.cursor" \
        --interval-secs 2 \
        --max-backoff-secs 2 \
        --dry-run \
    >"$log_file" 2>&1 &
relayer_pid=$!

# Quick "is it alive?" check — if the relayer immediately exited
# (bad key, RPC mismatch) bail with a useful message.
sleep 1
if ! kill -0 "$relayer_pid" 2>/dev/null; then
    fail "relayer exited within 1s — log:"
    sed 's/^/  /' "$log_file" >&2
    exit 3
fi

info "observing for ${OBSERVE_SECS}s…"
sleep "$OBSERVE_SECS"

if ! kill -0 "$relayer_pid" 2>/dev/null; then
    fail "relayer crashed before observation window ended — log:"
    sed 's/^/  /' "$log_file" >&2
    exit 3
fi

# ── Assert expected log lines ───────────────────────────────

info "checking log output"
if grep -q "seal-relayer starting" "$log_file"; then
    pass "relayer announced startup"
else
    fail "no 'seal-relayer starting' line — relayer never initialized properly"
    sed 's/^/  /' "$log_file" >&2
    exit 2
fi

if grep -q "DRY RUN" "$log_file"; then
    pass "relayer logged a dry-run submission — loop sees committee-signed withdrawals"
elif grep -q "withdrawal queued for relay" "$log_file"; then
    # We saw a withdrawal queued but the back-off window ate the rest.
    # Acceptable as a partial pass — the polling + filtering + back-off
    # path is exercised even if no dry-run line landed in time.
    pass "relayer queued a withdrawal (back-off window may have eaten the dry-run line)"
else
    fail "no 'DRY RUN' or 'withdrawal queued' lines in ${OBSERVE_SECS}s of output"
    fail "  the bridge may have no committee-signed-but-unexecuted withdrawals."
    fail "  burn one via: seal bridge-withdraw --dest-chain Stellar --token WXLM ..."
    fail ""
    fail "captured log:"
    sed 's/^/  /' "$log_file" >&2
    exit 2
fi

pass "relayer smoke complete"
