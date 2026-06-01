#!/usr/bin/env bash
# scripts/bridge-test-ringtail-5.sh — 5-validator Ringtail smoke
# test against the main 5-validator stack at `docker-compose.yml`,
# layered with `bridges/docker-compose.ringtail-5.override.yml`
# (Variant B: 3-of-5 full committee).
#
# Sibling script of `bridge-test-ringtail-multi.sh` (3-of-3) and
# `bridge-test-ringtail-7.sh` (5-of-7). See
# `docs/TESTNET-VALIDATOR-SIZES.md` for the variant table.
#
# Note: the main `docker-compose.yml` stack does NOT include
# Solana + Stellar containers. Run this against either:
#   * external live chains (Solana devnet + Stellar testnet —
#     the normal operator-side flow), OR
#   * a side-running `bridges/docker-compose.testnet.yml` stack
#     for local chains (network bridging across compose stacks
#     is up to the operator).
#
# Usage:
#   ./scripts/bridge-test-ringtail-5.sh                  # full run
#   ./scripts/bridge-test-ringtail-5.sh --skip-bootstrap # use existing stack

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
say() { echo -e "${BOLD}==>${NC} $*"; }
ok()  { echo -e "${GREEN}✓${NC} $*"; }
warn(){ echo -e "${YELLOW}!${NC} $*"; }
err() { echo -e "${RED}✗${NC} $*" >&2; }

SKIP_BOOTSTRAP=0
for arg in "$@"; do
    case "$arg" in
        --skip-bootstrap) SKIP_BOOTSTRAP=1 ;;
        *) err "unknown arg: $arg"; exit 1 ;;
    esac
done

KEY_DIR="bridges/ringtail-keys"
OVERRIDE="bridges/docker-compose.ringtail-5.override.yml"
COMPOSE="docker-compose.yml"
NODE_PORTS=(8545 8546 8547 8548 8549)
COMMITTEE_SIZE=5

# ---------------------------------------------------------------------------
# Step 1: keypairs (shared-sk fixture for the n_of_n cross-check)
# ---------------------------------------------------------------------------
mkdir -p "$KEY_DIR"
if [[ ! -f "$KEY_DIR/validator-1.json" ]]; then
    say "generating $COMMITTEE_SIZE Ringtail keypairs into $KEY_DIR/"
    if ! cargo run --quiet --release -p seal-bridge --features ringtail-singleton \
            --example bridge-ringtail-keygen -- "$KEY_DIR/shared.json" 2>/dev/null; then
        err "bridge-ringtail-keygen failed"
        exit 1
    fi
    for i in $(seq 1 $COMMITTEE_SIZE); do
        cp "$KEY_DIR/shared.json" "$KEY_DIR/validator-$i.json"
    done
    ok "generated $COMMITTEE_SIZE shared-sk keypairs"
else
    ok "keypairs already present in $KEY_DIR/ (re-using)"
fi

# ---------------------------------------------------------------------------
# Step 2: bring up
# ---------------------------------------------------------------------------
if [[ $SKIP_BOOTSTRAP -eq 0 ]]; then
    say "docker compose up -d (main stack + ringtail-5 override)"
    docker compose -f "$COMPOSE" -f "$OVERRIDE" up -d
fi

say "waiting for each validator's orchestrator to come up..."
for port in "${NODE_PORTS[@]}"; do
    for attempt in {1..60}; do
        body=$(curl --silent --max-time 2 -X POST "http://127.0.0.1:$port" \
            -H 'content-type: application/json' \
            -d '{"jsonrpc":"2.0","id":1,"method":"seal_bridgeRingtailStatus"}' 2>/dev/null || true)
        if echo "$body" | grep -q '"orchestrator_active":true'; then
            ok "validator on :$port has orchestrator_active=true"
            break
        fi
        if [[ $attempt -eq 60 ]]; then
            err "validator on :$port never reached orchestrator_active=true"
            err "last body: $body"
            exit 1
        fi
        sleep 2
    done
done

# ---------------------------------------------------------------------------
# Step 3: signature convergence check (post a real withdrawal first)
# ---------------------------------------------------------------------------
say "all 5 validators report orchestrator_active=true."
say "now run a real withdrawal flow (forward via bridge-e2e.sh"
say "  forward-sol then reverse via the seal-cli) and re-poll"
say "  seal_bridgeRingtailStatus on each port — all should briefly"
say "  show session_count >= 1 then return to 0."

first_sig=""
diverged=0
for port in "${NODE_PORTS[@]}"; do
    body=$(curl --silent --max-time 2 -X POST "http://127.0.0.1:$port" \
        -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"seal_listBridgeWithdrawals","params":{}}')
    sig=$(echo "$body" \
        | grep -oE '"committee_signature_hex":"[^"]*"' \
        | head -1 \
        | sed 's/.*"committee_signature_hex":"\([^"]*\)".*/\1/' \
        || echo "")
    if [[ -z "$sig" ]]; then
        warn "validator on :$port has no withdrawals yet"
        continue
    fi
    if [[ -z "$first_sig" ]]; then
        first_sig="$sig"
    elif [[ "$sig" != "$first_sig" ]]; then
        err "validator on :$port has DIFFERENT signature than :8545"
        err "  :8545 = $first_sig"
        err "  :$port = $sig"
        diverged=1
    fi
done
if [[ $diverged -ne 0 ]]; then
    exit 3
fi
if [[ -n "$first_sig" ]]; then
    ok "all 5 validators agree on committee_signature_hex (${first_sig:0:32}…)"
fi

say "(stack left running; tear down with 'docker compose down -v')"
ok "done."
