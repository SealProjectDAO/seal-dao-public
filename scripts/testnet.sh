#!/bin/bash
# Start a local multi-node testnet.
#
# Usage:
#   ./scripts/testnet.sh              # 3 nodes on localhost
#   ./scripts/testnet.sh 5            # 5 nodes
#   ./scripts/testnet.sh stop         # Stop all nodes
#   ./scripts/testnet.sh status       # Compact /health table for running nodes
#
# Each node gets its own P2P port (4001-400N), RPC port (8545-854N),
# and data directory (testnet-data/node-N/).
# Node 1 is the bootstrap. Others connect via --bootstrap-peers.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

DATA_DIR="testnet-data"
PID_FILE="$DATA_DIR/pids.txt"
BASE_P2P=4001
BASE_RPC=8545

if [ "${1:-}" = "stop" ]; then
    echo "Stopping testnet..."
    if [ -f "$PID_FILE" ]; then
        while read -r pid; do
            kill "$pid" 2>/dev/null && echo "  Stopped PID $pid" || true
        done < "$PID_FILE"
        rm "$PID_FILE"
    else
        pkill -f "seal-node" 2>/dev/null || true
    fi
    echo "Stopped."
    exit 0
fi

if [ "${1:-}" = "status" ]; then
    # Walk the recorded PID file and hit each node's /health. Compact
    # table; one line per node. Unreachable nodes show as `down`.
    if [ ! -f "$PID_FILE" ]; then
        echo "No PID file at $PID_FILE — testnet not started, or started with a different DATA_DIR."
        exit 1
    fi
    if ! command -v jq >/dev/null 2>&1; then
        echo "error: jq required for status output"
        exit 1
    fi
    printf 'node  pid     status    height  peers  validator  uptime\n'
    printf -- '----  ------  --------  ------  -----  ---------  ------\n'
    i=0
    rc=0
    while read -r pid; do
        i=$((i + 1))
        RPC=$((BASE_RPC + i - 1))
        if ! kill -0 "$pid" 2>/dev/null; then
            printf '%-4s  %-6s  %-8s  %6s  %5s  %-9s  %s\n' "$i" "$pid" "DEAD" "-" "-" "-" "-"
            rc=1
            continue
        fi
        body=$(curl -sS --max-time 2 "http://127.0.0.1:$RPC/health" 2>/dev/null || true)
        if [ -z "$body" ]; then
            printf '%-4s  %-6s  %-8s  %6s  %5s  %-9s  %s\n' "$i" "$pid" "down" "-" "-" "-" "-"
            rc=1
            continue
        fi
        status=$(printf '%s' "$body" | jq -r '.status // "?"')
        height=$(printf '%s' "$body" | jq -r '.height // 0')
        peers=$(printf '%s' "$body" | jq -r '.peers // 0')
        is_val=$(printf '%s' "$body" | jq -r '.is_validator // false')
        uptime=$(printf '%s' "$body" | jq -r '.uptime_secs // 0')
        printf '%-4s  %-6s  %-8s  %6s  %5s  %-9s  %ss\n' \
            "$i" "$pid" "$status" "$height" "$peers" "$is_val" "$uptime"
    done < "$PID_FILE"
    exit $rc
fi

NUM=${1:-3}

echo "=== Seal Local Testnet ($NUM nodes) ==="
echo ""

# Build
if [ ! -f target/release/seal-node ]; then
    echo "Building seal-node (release)..."
    cargo build --release -p seal-node 2>&1 | tail -1
fi

mkdir -p "$DATA_DIR"
> "$PID_FILE"

for i in $(seq 1 "$NUM"); do
    P2P=$((BASE_P2P + i - 1))
    RPC=$((BASE_RPC + i - 1))
    DIR="$DATA_DIR/node-$i"
    mkdir -p "$DIR"

    ARGS="--slots 0 --port $P2P --rpc-port $RPC --data-dir $DIR"
    if [ "$i" -gt 1 ]; then
        ARGS="$ARGS --bootstrap-peers /ip4/127.0.0.1/tcp/$BASE_P2P"
    fi

    RUST_LOG=info ./target/release/seal-node $ARGS > "$DIR/stdout.log" 2>&1 &
    echo "$!" >> "$PID_FILE"
    echo "  Node $i: P2P=$P2P RPC=http://127.0.0.1:$RPC (PID $!)"
done

echo ""
echo "Testnet running."
echo ""
echo "Query:"
for i in $(seq 1 "$NUM"); do
    RPC=$((BASE_RPC + i - 1))
    echo "  curl -s localhost:$RPC -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"seal_getHeight\",\"params\":{},\"id\":1}'"
done
echo ""
echo "Logs:   tail -f $DATA_DIR/node-1/stdout.log"
echo "Status: ./scripts/testnet.sh status"
echo "Stop:   ./scripts/testnet.sh stop"
