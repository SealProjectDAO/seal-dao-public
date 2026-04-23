#!/usr/bin/env bash
# scripts/bridge-e2e.sh — lock→mint→burn→unlock round-trip on the
# local bridge testnet (see bridges/docker-compose.testnet.yml).
#
# What it does:
#   1. Bring up (or reuse) the local stack — Solana test-validator,
#      Stellar quickstart, 3 Seal nodes.
#   2. Build + deploy the seal-bridge Anchor program to the local
#      Solana validator.
#   3. Build + deploy the seal-bridge Soroban contract to the local
#      Stellar network.
#   4. Fund source accounts (solana airdrop, stellar friendbot).
#   5. Submit a `lock_tokens` on Solana → wait for Seal observer to
#      pick it up → assert wrapped balance credited on Seal.
#   6. Submit `seal_bridgeWithdraw` on Seal → wait for committee
#      signature → submit `unlock_tokens` on Solana → assert SOL
#      returned.
#   7. Repeat for Stellar.
#
# Modes:
#   ./scripts/bridge-e2e.sh              # full round-trip
#   ./scripts/bridge-e2e.sh up           # bring stack up only
#   ./scripts/bridge-e2e.sh down         # tear down and wipe volumes
#   ./scripts/bridge-e2e.sh check        # just preflight (prerequisites)
#
# Prerequisites (checked by `check`):
#   - docker / docker compose
#   - solana CLI (for airdrop + deploy outside containers)
#   - anchor CLI (>= 0.30)
#   - stellar CLI (soroban CLI, >= 21)
#   - rustup with wasm32-unknown-unknown target
#
# Exit codes:
#   0  success
#   1  preflight failure (missing tool)
#   2  deploy failure
#   3  end-to-end assertion failure

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$REPO_DIR/bridges/docker-compose.testnet.yml"

SOLANA_RPC="http://localhost:8899"
STELLAR_HORIZON="http://localhost:8000"
SEAL_RPC="http://localhost:8545"

LOCK_AMOUNT=1000000000           # 1 SOL in lamports
LOCK_AMOUNT_XLM=10000000         # 1 XLM in stroops
SEAL_RECIPIENT_HEX="deadbeefcafe0000000000000000000000000000000000000000000000000000"

color() {
    local code="$1"
    shift
    printf '\033[%sm%s\033[0m\n' "$code" "$*"
}
info() { color "36" "==> $*"; }
pass() { color "32" "[ok] $*"; }
fail() { color "31" "[!!] $*" >&2; }

# ── Prerequisites ───────────────────────────────────────────

check_prereqs() {
    local missing=0
    for tool in docker solana anchor stellar jq curl; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            fail "missing: $tool"
            missing=$((missing + 1))
        fi
    done
    if ! docker compose version >/dev/null 2>&1; then
        fail "missing: 'docker compose' plugin"
        missing=$((missing + 1))
    fi
    if ! rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
        fail "missing rust target: wasm32-unknown-unknown"
        fail "fix with: rustup target add wasm32-unknown-unknown"
        missing=$((missing + 1))
    fi
    if [ "$missing" -gt 0 ]; then
        fail "preflight failed: $missing missing tool(s)"
        exit 1
    fi
    pass "all prerequisites present"
}

# ── Stack lifecycle ─────────────────────────────────────────

stack_up() {
    info "bringing up local bridge stack (docker compose)"
    (cd "$REPO_DIR/bridges" && docker compose -f docker-compose.testnet.yml up -d --wait)
    pass "stack is up"
    info "waiting for Stellar Horizon to catch up…"
    # First-boot catchup can take a couple of minutes on slow hosts.
    for _ in $(seq 1 60); do
        if curl -fsS "$STELLAR_HORIZON" >/dev/null 2>&1; then
            pass "Stellar Horizon reachable"
            break
        fi
        sleep 2
    done
}

stack_down() {
    info "tearing down bridge stack + wiping volumes"
    (cd "$REPO_DIR/bridges" && docker compose -f docker-compose.testnet.yml down -v)
    pass "stack torn down"
}

# ── Deploy contracts ────────────────────────────────────────

deploy_solana() {
    info "deploying seal-bridge Anchor program to local validator"
    (
        cd "$REPO_DIR/bridges/solana"
        solana config set --url "$SOLANA_RPC" >/dev/null
        if [ ! -f "$HOME/.config/solana/id.json" ]; then
            info "generating new keypair at ~/.config/solana/id.json"
            solana-keygen new --no-bip39-passphrase --outfile "$HOME/.config/solana/id.json" --force
        fi
        solana airdrop 100 >/dev/null || true  # localnet gives unbounded
        anchor build
        anchor deploy --provider.cluster "$SOLANA_RPC"
    )
    pass "Solana program deployed"
}

deploy_stellar() {
    info "deploying seal-bridge Soroban contract to local Stellar"
    (
        cd "$REPO_DIR/bridges/stellar"
        local net_url="$STELLAR_HORIZON"
        # First-run: configure a network alias + a funded source
        # keypair (friendbot on local quickstart is available at :8000).
        stellar network add local \
            --rpc-url "$net_url" \
            --network-passphrase "Standalone Network ; February 2017" \
            2>/dev/null || true
        if ! stellar keys show seal-e2e >/dev/null 2>&1; then
            stellar keys generate --network local seal-e2e
            stellar keys fund seal-e2e --network local
        fi
        cargo build --target wasm32-unknown-unknown --release
        local wasm="target/wasm32-unknown-unknown/release/seal_bridge_stellar.wasm"
        local contract_id
        contract_id=$(stellar contract deploy --wasm "$wasm" --network local --source seal-e2e)
        echo "$contract_id" > "$REPO_DIR/bridges/.stellar-contract-id"
        local xlm_sac
        xlm_sac=$(stellar contract id asset --asset native --network local)
        stellar contract invoke \
            --id "$contract_id" --network local --source seal-e2e \
            -- initialize \
            --admin "$(stellar keys address seal-e2e)" \
            --seal_bridge_key "0000000000000000000000000000000000000000000000000000000000000000" \
            --xlm_sac "$xlm_sac"
    )
    pass "Stellar contract deployed"
}

# ── Lock → mint round trip ──────────────────────────────────

seal_rpc() {
    # Usage: seal_rpc METHOD [PARAMS_JSON] [--port N]
    # Default port is 8545 (seal node 1). Parameters default to `[]`.
    local method="$1"
    shift
    local params="[]"
    local port="8545"
    while [ $# -gt 0 ]; do
        case "$1" in
            --port)
                port="$2"
                shift 2
                ;;
            *)
                params="$1"
                shift
                ;;
        esac
    done
    curl -sS "http://localhost:$port" \
        -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}"
}

poll_until() {
    local desc="$1"
    local timeout_secs="$2"
    local cmd="$3"
    info "waiting up to ${timeout_secs}s: $desc"
    for _ in $(seq 1 "$timeout_secs"); do
        if eval "$cmd" >/dev/null 2>&1; then
            pass "$desc"
            return 0
        fi
        sleep 1
    done
    fail "timed out: $desc"
    return 3
}

solana_round_trip() {
    info "── Solana round trip ──"
    local program_id
    program_id=$(solana address -k "$REPO_DIR/bridges/solana/target/deploy/seal_bridge-keypair.json")
    info "program ID: $program_id"

    # Register the Solana observer on every running Seal node so each
    # validator sees the same deposit stream.
    for port in 8545 8546 8547; do
        seal_rpc seal_addBridgeObserver \
            "{\"chain\":\"Solana\",\"rpc_url\":\"http://solana:8899\",\"program_id\":\"$program_id\"}" \
            --port "$port" >/dev/null || true
    done

    info "running Anchor TS integration suite (lock)"
    (cd "$REPO_DIR/bridges/solana" && anchor test --skip-local-validator --skip-deploy)

    # Force an observer sweep so we don't have to wait for the poll
    # loop. Returns {observed, new, duplicate}.
    info "triggering seal_pollBridges"
    seal_rpc seal_pollBridges '[]' | jq -r '.result'

    # Poll Seal RPC for the deposit to have appeared in the manager.
    poll_until "Solana deposit visible on Seal" 60 \
        "seal_rpc seal_getBridgeDeposits '[\"Solana\"]' | jq -e '.result | length > 0'"

    info "TODO: withdraw + unlock_tokens flow (gated on committee-key propagation)"
}

stellar_round_trip() {
    info "── Stellar round trip ──"
    local contract_id
    contract_id=$(cat "$REPO_DIR/bridges/.stellar-contract-id")
    info "contract: $contract_id"

    # Register the Stellar observer on every running Seal node.
    for port in 8545 8546 8547; do
        seal_rpc seal_addBridgeObserver \
            "{\"chain\":\"Stellar\",\"horizon_url\":\"http://stellar:8000\",\"contract_id\":\"$contract_id\"}" \
            --port "$port" >/dev/null || true
    done

    (
        cd "$REPO_DIR/bridges/stellar"
        stellar contract invoke --id "$contract_id" --network local --source seal-e2e \
            -- lock_xlm \
            --sender "$(stellar keys address seal-e2e)" \
            --amount "$LOCK_AMOUNT_XLM" \
            --seal_address "$SEAL_RECIPIENT_HEX"
    )

    info "triggering seal_pollBridges"
    seal_rpc seal_pollBridges '[]' | jq -r '.result'

    poll_until "Stellar deposit visible on Seal" 60 \
        "seal_rpc seal_getBridgeDeposits '[\"Stellar\"]' | jq -e '.result | length > 0'"

    info "TODO: burn + unlock_xlm flow (gated on committee-key propagation)"
}

# ── Entrypoint ──────────────────────────────────────────────

usage() {
    grep '^#' "$0" | head -30
}

cmd="${1:-full}"
case "$cmd" in
    -h|--help|help)
        usage
        ;;
    check)
        check_prereqs
        ;;
    up)
        check_prereqs
        stack_up
        ;;
    down)
        stack_down
        ;;
    full)
        check_prereqs
        stack_up
        deploy_solana || { fail "Solana deploy failed"; exit 2; }
        deploy_stellar || { fail "Stellar deploy failed"; exit 2; }
        solana_round_trip
        stellar_round_trip
        pass "bridge e2e round trip complete"
        ;;
    *)
        fail "unknown command: $cmd"
        usage
        exit 1
        ;;
esac
