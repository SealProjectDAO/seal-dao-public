#!/usr/bin/env bash
# scripts/bridge-test-ringtail-7.sh — 7-validator Ringtail smoke
# test against the bridge stack at `bridges/docker-compose.testnet.yml`
# layered with `bridges/docker-compose.ringtail-7.override.yml`
# (Variant A: 5-of-7 full committee — pre-mainnet shape).
#
# Sibling script of `bridge-test-ringtail-multi.sh` (3-of-3) and
# `bridge-test-ringtail-5.sh` (3-of-5). See
# `docs/TESTNET-VALIDATOR-SIZES.md` for the variant table.
#
# Unlike the 5-validator script, the 7-validator stack DOES bundle
# Solana + Stellar containers (inherited from the bridge base
# stack at bridges/docker-compose.testnet.yml). Run the standard
# `bridge-e2e.sh` against this stack to drive a real withdrawal.
#
# Usage:
#   ./scripts/bridge-test-ringtail-7.sh                  # full run
#   ./scripts/bridge-test-ringtail-7.sh --skip-bootstrap # use existing stack

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
COMPOSE="bridges/docker-compose.testnet.yml"
OVERRIDE="bridges/docker-compose.ringtail-7.override.yml"
NODE_PORTS=(8645 8646 8647 8648 8649 8650 8651)
COMMITTEE_SIZE=7

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
    say "docker compose up -d (bridge stack + ringtail-7 override)"
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
# Step 3: signature convergence check
# ---------------------------------------------------------------------------
say "all 7 validators report orchestrator_active=true."
say "run a real withdrawal (scripts/bridge-e2e.sh reverse-sol)"
say "and the orchestrators should converge on the same"
say "committee_signature_hex (5-of-7 aggregate)."

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
        err "validator on :$port has DIFFERENT signature than :${NODE_PORTS[0]}"
        err "  :${NODE_PORTS[0]} = $first_sig"
        err "  :$port = $sig"
        diverged=1
    fi
done
if [[ $diverged -ne 0 ]]; then
    exit 3
fi
if [[ -n "$first_sig" ]]; then
    ok "all 7 validators agree on committee_signature_hex (${first_sig:0:32}…)"
fi

say "(stack left running; tear down with"
say "  'docker compose -f $COMPOSE -f $OVERRIDE down -v')"
ok "done."
