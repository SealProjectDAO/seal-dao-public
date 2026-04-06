#!/bin/bash
# Start a local multi-node testnet.
#
# Usage:
#   ./scripts/testnet.sh              # 3 nodes on localhost
#   ./scripts/testnet.sh 5            # 5 nodes
#   ./scripts/testnet.sh stop         # Stop all nodes
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
echo "Logs: tail -f $DATA_DIR/node-1/stdout.log"
echo "Stop: ./scripts/testnet.sh stop"
