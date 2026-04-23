#!/usr/bin/env bash
# scripts/verify-tla-bridge.sh — run Apalache against the bridge TLA+
# model (formal/tlaplus/MC_SealBridge.tla).
#
# Apalache (tested against 0.55.0) takes a SINGLE --inv flag with a
# comma-separated list of invariants — not repeated --inv flags. Passing
# --inv twice makes the CLI fall through to its "Usage … Options ???"
# help banner, which is why the obvious-looking invocation from earlier
# sessions failed.
#
# Usage:
#   ./scripts/verify-tla-bridge.sh             # default length=10
#   LENGTH=15 ./scripts/verify-tla-bridge.sh   # deeper search
#   INVARIANTS=MintedLeqLocked,NoDoubleMint ./scripts/verify-tla-bridge.sh
#                                              # subset of invariants

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPEC="$REPO_ROOT/formal/tlaplus/MC_SealBridge.tla"

if ! command -v apalache-mc >/dev/null 2>&1; then
    echo "✗ apalache-mc not on PATH."
    echo "  Install from https://apalache-mc.org/ or brew tap informalsystems/apalache."
    exit 1
fi

if [[ ! -f "$SPEC" ]]; then
    echo "✗ Missing spec: $SPEC"
    exit 1
fi

# Invariants defined in SealBridge.tla. Keep this list in sync with the
# header comment of MC_SealBridge.tla.
INVARIANTS="${INVARIANTS:-MintedLeqLocked,NoDoubleMint,NoMintWithoutLock,BurnedLeqMinted,ReleasedLeqBurned,ReleasedLeqLocked}"
LENGTH="${LENGTH:-10}"

echo "==> apalache-mc $(apalache-mc version 2>&1 | head -1)"
echo "==> spec:       $SPEC"
echo "==> invariants: $INVARIANTS"
echo "==> length:     $LENGTH"
echo

set -x
exec apalache-mc check \
    --cinit=ConstInit \
    --init=Init \
    --next=Next \
    --inv="$INVARIANTS" \
    --length="$LENGTH" \
    "$SPEC"
