#!/usr/bin/env bash
# bridge-e2e-diag.sh — diagnostic snapshot for a stuck `bridge-e2e.sh` run.
#
# Run this WHEN bridge-e2e.sh has just printed "timed out: <Chain> deposit
# visible on Seal" and BEFORE you tear the stack down. Captures the
# minimum state needed to tell which leg of the pipeline failed:
#
#   (1) per-node observer counts — should be 1 each by poll-time
#   (2) per-node stored deposits — what `seal_getBridgeDeposits` sees
#   (3) solana-test-validator's view of the program's recent sigs
#   (4) one explicit `seal_pollBridges` on bridge-node-1
#   (5) bridge-node-1 logs for the last 60 s (observer errors land here)
#
# Optional first arg: the Lock tx hash that anchor printed; if omitted
# we just dump the most-recent 5 signatures for the program. Optional
# second arg: chain ("Solana" or "Stellar"); defaults to Solana.
#
# Usage:
#   ./scripts/bridge-e2e-diag.sh
#   ./scripts/bridge-e2e-diag.sh 2aVjrvH9KTsXwZYNxyoSLkfgV8KyP4WpwFF8c…
#   ./scripts/bridge-e2e-diag.sh '' Stellar
#
# Override host RPCs via env (defaults match docker-compose.testnet.yml):
#   SEAL_RPC=http://localhost:8645
#   SOLANA_RPC=http://localhost:8899
#   STELLAR_RPC=http://localhost:8003

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

LOCK_TX="${1:-}"
# Normalize chain arg so `solana`, `Solana`, `SOLANA` all work.
RAW_CHAIN="${2:-Solana}"
case "$(printf '%s' "$RAW_CHAIN" | tr '[:upper:]' '[:lower:]')" in
    solana)  CHAIN="Solana"  ;;
    stellar) CHAIN="Stellar" ;;
    *) echo "unknown CHAIN '$RAW_CHAIN' (expected Solana or Stellar)" >&2; exit 2 ;;
esac

SEAL_RPC="${SEAL_RPC:-http://localhost:8645}"
SOLANA_RPC="${SOLANA_RPC:-http://localhost:8899}"
STELLAR_RPC="${STELLAR_RPC:-http://localhost:8003}"

# Derive the three bridge node host-side ports the same way
# bridge-e2e.sh does — base port from $SEAL_RPC, then base+0/+1/+2.
SEAL_PORT_1="${SEAL_RPC##*:}"
SEAL_PORT_2="$((SEAL_PORT_1 + 1))"
SEAL_PORT_3="$((SEAL_PORT_1 + 2))"

hdr() { printf '\n\033[36m=== %s ===\033[0m\n' "$*"; }

rpc() {
    # rpc URL METHOD PARAMS_JSON
    curl -sS --max-time 5 "$1" -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}"
}

hdr "context"
echo "SEAL_RPC      = $SEAL_RPC"
echo "SEAL ports    = $SEAL_PORT_1 $SEAL_PORT_2 $SEAL_PORT_3"
echo "SOLANA_RPC    = $SOLANA_RPC"
echo "STELLAR_RPC   = $STELLAR_RPC"
echo "CHAIN         = $CHAIN"
echo "LOCK_TX       = ${LOCK_TX:-(none — will dump recent sigs instead)}"

hdr "(1) per-node observer counts"
for p in "$SEAL_PORT_1" "$SEAL_PORT_2" "$SEAL_PORT_3"; do
    printf 'node :%s  ' "$p"
    rpc "http://localhost:$p" seal_listBridgeObservers '{}' | jq -c '.result // .error'
done

hdr "(2) per-node stored deposits for $CHAIN"
for p in "$SEAL_PORT_1" "$SEAL_PORT_2" "$SEAL_PORT_3"; do
    printf 'node :%s  ' "$p"
    rpc "http://localhost:$p" seal_getBridgeDeposits "[\"$CHAIN\"]" \
        | jq -c '{count: (.result // [] | length), first: (.result // [] | .[0])}'
done

if [ "$CHAIN" = "Solana" ]; then
    PROGRAM_ID=""
    KEYPAIR="$REPO_DIR/bridges/solana/target/deploy/seal_bridge-keypair.json"
    if [ -f "$KEYPAIR" ] && command -v solana >/dev/null 2>&1; then
        PROGRAM_ID="$(solana address -k "$KEYPAIR" 2>/dev/null || true)"
    fi
    hdr "(3a) Solana program ID + recent signatures (commitment=confirmed)"
    if [ -n "$PROGRAM_ID" ]; then
        echo "program_id = $PROGRAM_ID"
        rpc "$SOLANA_RPC" getSignaturesForAddress \
            "[\"$PROGRAM_ID\",{\"limit\":5,\"commitment\":\"confirmed\"}]" \
            | jq '.result | map({signature, slot, err, blockTime})'
    else
        echo "(could not derive program_id — keypair missing or solana CLI not in PATH)"
    fi

    if [ -n "$LOCK_TX" ]; then
        hdr "(3b) getTransaction for the lock tx at commitment=confirmed"
        rpc "$SOLANA_RPC" getTransaction \
            "[\"$LOCK_TX\",{\"encoding\":\"json\",\"commitment\":\"confirmed\",\"maxSupportedTransactionVersion\":0}]" \
            | jq '{slot: .result.slot, err: .result.meta.err, rpcError: .error}'
    fi
elif [ "$CHAIN" = "Stellar" ]; then
    hdr "(3) Stellar contract ID + latest soroban events"
    if [ -f "$REPO_DIR/bridges/.stellar-contract-id" ]; then
        CID="$(cat "$REPO_DIR/bridges/.stellar-contract-id")"
        echo "contract_id = $CID"
        # getEvents requires startLedger; ask soroban for the latest ledger first.
        latest=$(rpc "$STELLAR_RPC" getLatestLedger '{}' | jq -r '.result.sequence // 0')
        start=$((latest > 100 ? latest - 100 : 1))
        echo "latest ledger = $latest   queryFromLedger = $start"
        rpc "$STELLAR_RPC" getEvents \
            "{\"startLedger\":$start,\"filters\":[{\"type\":\"contract\",\"contractIds\":[\"$CID\"]}],\"pagination\":{\"limit\":5}}" \
            | jq '.result // .error'
    else
        echo "(no bridges/.stellar-contract-id — Stellar leg never deployed?)"
    fi
fi

hdr "(4) explicit seal_pollBridges on bridge-node-1"
rpc "$SEAL_RPC" seal_pollBridges '[]' | jq
echo '(reminder: "observed" is deposits-this-poll, NOT observer count — rpc.rs:4045)'

hdr "(5) bridge-node-1 logs (last 60 s; observer/poll errors land here)"
if command -v docker >/dev/null 2>&1; then
    docker logs --since 60s seal-bridge-node-1 2>&1 | tail -80
else
    echo "(docker not in PATH)"
fi

hdr "done"
echo "If (1) shows count:0 anywhere, observer registration didn't take on that node."
echo "If (2) shows count:0 everywhere but (3) shows the lock signature, the observer"
echo "    sees the tx on solana but isn't ingesting — check (5) for poll errors."
echo "If (3) is empty / errors, solana-test-validator hasn't indexed yet — wait + retry,"
echo "    or the anchor lock never landed."
echo "Paste this output back to triage further."
