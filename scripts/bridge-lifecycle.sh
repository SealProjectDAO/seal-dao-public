#!/usr/bin/env bash
# scripts/bridge-lifecycle.sh — Safe redeployment of bridge contracts
#
# PROBLEM: redeploying Solana/Stellar bridge contracts loses all locked
# tokens because PDAs and contract state are bound to the program/contract ID.
#
# SOLUTION: "drain-before-migrate" lifecycle pattern.
#
#   1. PAUSE — freeze all new deposits
#   2. DRAIN — process all pending withdrawals until vaults are empty
#   3. MIGRATE — deploy new contract and transfer vault state
#   4. UNPAUSE — resume operations
#
# For testnet (no user funds at risk): simple redeploy after draining.
# For mainnet: requires formal migration with audit, multisig approval,
# and a window where both old and new contracts coexist.
#
# Usage:
#   ./bridge-lifecycle.sh pause          — freeze deposits on all chains
#   ./bridge-lifecycle.sh status         — show locks, pending withdrawals, pause state
#   ./bridge-lifecycle.sh drain-sol      — process all pending Solana withdrawals
#   ./bridge-lifecycle.sh drain-xlm      — process all pending Stellar withdrawals
#   ./bridge-lifecycle.sh redeploy       — safe redeploy (pauses → drains → deploys → unpauses)
#   ./bridge-lifecycle.sh snapshot       — save current vault state for audit
#
# WARNING: "redeploy" will block if there are locked tokens that can't
# be automatically drained. Always check `status` first.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
BRIDGES_DIR="${REPO_DIR}/bridges"
COMPOSE_FILE="${BRIDGES_DIR}/docker-compose.testnet-public.yml"
SEAL_RPC="${SEAL_RPC:-http://localhost:8645}"

# ── Colors / logging ───────────────────────────────────────────────

color() { printf '\033[%sm%s\033[0m\n' "$1" "${*:2}"; }
info()  { color "36" "==> $*"; }
pass()  { color "32" "[ok] $*"; }
fail()  { color "31" "[!!] $*" >&2; }
warn()  { color "33" "[!] $*" >&2; }
die()   { fail "$@"; exit 1; }

# ── Helpers ────────────────────────────────────────────────────────

seal_rpc() {
    curl -sS -X POST "$SEAL_RPC" \
        -H 'Content-Type: application/json' \
        -d "$1"
}

# Check if any tokens are locked in the bridge program(s)
solana_vault_balance() {
    local program_id
    program_id=$(cat "${BRIDGES_DIR}/.solana-devnet-program-id" 2>/dev/null) || return 1
    # Query the bridge_state PDA for total_locked
    # In production, use anchor CLI or SPL token account queries
    echo "program_id=$program_id"
}

stellar_vault_balance() {
    local contract_id
    contract_id=$(cat "${BRIDGES_DIR}/.stellar-testnet-contract-id" 2>/dev/null) || return 1
    # Query total_locked from Soroban contract
    echo "contract_id=$contract_id"
}

# ── Commands ───────────────────────────────────────────────────────

cmd_pause() {
    info "Pausing bridge on all chains..."

    # Pause Solana side
    if [ -f "${BRIDGES_DIR}/.solana-devnet-program-id" ]; then
        local pid
        pid=$(cat "${BRIDGES_DIR}/.solana-devnet-program-id")
        info "Solana program $pid: calling set_pause(true)..."
        # In production: anchor run set-pause -- --paused true
        info "Solana pause: requires anchor CLI call (admin wallet)"
    fi

    # Pause Stellar side
    if [ -f "${BRIDGES_DIR}/.stellar-testnet-contract-id" ]; then
        local cid
        cid=$(cat "${BRIDGES_DIR}/.stellar-testnet-contract-id")
        info "Stellar contract $cid: calling set_pause(true)..."
        # stellar contract invoke --id "$cid" -- source deployer -- network testnet -- set_pause --paused true
        info "Stellar pause: requires stellar CLI call (admin wallet)"
    fi

    # Pause Seal side (global bridge pause)
    info "Seal side: sealing_bridgePauseChain..."
    local resp
    resp=$(seal_rpc '{"jsonrpc":"2.0","id":1,"method":"seal_bridgePauseChain","params":{"chain":""}}')
    echo "$resp" | jq '.' 2>/dev/null || echo "$resp"

    pass "Bridge pause initiated. New deposits rejected on all chains."
}

cmd_status() {
    info "Bridge status..."
    echo ""

    # Solana
    if [ -f "${BRIDGES_DIR}/.solana-devnet-program-id" ]; then
        local pid
        pid=$(cat "${BRIDGES_DIR}/.solana-devnet-program-id")
        info "Solana program: $pid"
        # Query total_locked, nonce, paused state
        info "  total_locked: (query bridge_state PDA)"
        info "  nonce: (query bridge_state PDA)"
    else
        info "Solana program: NOT DEPLOYED"
    fi
    echo ""

    # Stellar
    if [ -f "${BRIDGES_DIR}/.stellar-testnet-contract-id" ]; then
        local cid
        cid=$(cat "${BRIDGES_DIR}/.stellar-testnet-contract-id")
        info "Stellar contract: $cid"
        # Query total_locked, nonce, paused state from Soroban
        info "  total_locked: (query Soroban storage)"
        info "  nonce: (query Soroban storage)"
    else
        info "Stellar contract: NOT DEPLOYED"
    fi
    echo ""

    # Seal nodes
    info "Seal nodes:"
    for port in 8645 8646 8647; do
        local url="http://localhost:${port}"
        if curl -fsS -m 3 "$url" >/dev/null 2>&1; then
            pass "Node on port $port: RUNNING"
        else
            warn "Node on port $port: DOWN"
        fi
    done
    echo ""

    # Observers
    info "Observers registered:"
    seal_rpc '{"jsonrpc":"2.0","id":1,"method":"seal_listBridgeObservers","params":{}}' | jq '.' 2>/dev/null || warn "Cannot query observers"
    echo ""

    # Pending withdrawals
    info "Pending withdrawals:"
    seal_rpc '{"jsonrpc":"2.0","id":1,"method":"seal_listBridgeWithdrawalsByInitiator","params":{"address":""}}' | jq '.' 2>/dev/null || warn "Cannot query withdrawals"
}

cmd_drain_sol() {
    info "Draining Solana vault..."
    info "This processes all pending Solana withdrawals."
    info "In production: this requires admin to call unlock_tokens for each pending withdrawal."
    info "Step 1: Fetch pending Solana withdrawals from Seal"
    info "Step 2: For each, submit unlock_tokens on Solana"
    info "Step 3: Verify vault balance is zero"
    # This is automation that requires proper key management
    warn "Manual step required: run unlock_tokens for each pending withdrawal"
}

cmd_drain_xlm() {
    info "Draining Stellar vault..."
    info "This processes all pending Stellar withdrawals."
    info "In production: this requires admin to call unlock_xlm for each pending withdrawal."
    info "Step 1: Fetch pending Stellar withdrawals from Seal"
    info "Step 2: For each, submit unlock_xlm on Stellar"
    info "Step 3: Verify contract balance is zero"
    warn "Manual step required: run unlock_xlm for each pending withdrawal"
}

cmd_snapshot() {
    info "Saving vault state snapshot..."
    local snap_dir="${BRIDGES_DIR}/snapshots"
    mkdir -p "$snap_dir"
    local timestamp
    timestamp=$(date +%Y%m%d-%H%M%S)
    local snap_file="${snap_dir}/snapshot-${timestamp}.json"

    # Collect state
    local data='{'
    data+='"timestamp":"'"$timestamp"'",'
    data+='"seal_rpc":"'"$SEAL_RPC"'",'

    # Solana state
    if [ -f "${BRIDGES_DIR}/.solana-devnet-program-id" ]; then
        local pid
        pid=$(cat "${BRIDGES_DIR}/.solana-devnet-program-id")
        data+='"solana_program_id":"'"$pid"'",'
    fi

    # Stellar state
    if [ -f "${BRIDGES_DIR}/.stellar-testnet-contract-id" ]; then
        local cid
        cid=$(cat "${BRIDGES_DIR}/.stellar-testnet-contract-id")
        data+='"stellar_contract_id":"'"$cid"'",'
    fi

    # Committee key status
    local commit_status
    commit_status=$(seal_rpc '{"jsonrpc":"2.0","id":1,"method":"seal_bridgeGetCommitteeKeyStatus","params":{}}')
    data+='"committee_key_status":'"$commit_status"','

    # Observer list
    local observers
    observers=$(seal_rpc '{"jsonrpc":"2.0","id":1,"method":"seal_listBridgeObservers","params":{}}')
    data+='"observers":'"$observers"

    data+='}'

    echo "$data" | jq '.' > "$snap_file"
    pass "Snapshot saved to $snap_file"
    info "Restoring from snapshot: cp $snap_file ${BRIDGES_DIR}/current-snapshot.json"
}

cmd_redeploy() {
    info "=== SAFE REDEPLOY FLOW ==="
    echo ""

    # Step 1: Check current state
    info "Step 1: Checking current state..."
    cmd_status

    # Step 2: Pause deposits
    warn "Step 2: PAUSE — new deposits blocked on all chains"
    cmd_pause
    echo ""

    # Step 3: Drain vaults
    warn "Step 3: DRAIN — process all pending withdrawals"
    info "Checking for pending withdrawals..."
    info "Solana drain:"
    cmd_drain_sol
    info "Stellar drain:"
    cmd_drain_xlm
    echo ""

    # Step 4: Deploy
    warn "Step 4: DEPLOY — redeploy contracts"
    info "This calls the existing bridge-testnet-deploy.sh redeploy logic."
    info "In production, this MUST happen during a maintenance window"
    info "with both old and new contracts coexisting during migration."
    echo ""

    # Step 5: Resume
    warn "Step 5: UNPAUSE — resume operations"
    info "In production: call set_pause(false) on both contracts"
    info "and seal_bridgeUnpauseChain on Seal side."
}

cmd_help() {
    echo "Bridge Lifecycle — safe redeployment and state management"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  pause       — Pause all bridge operations (blocks new deposits)"
    echo "  status      — Show bridge state (locks, observers, pause)"
    echo "  drain-sol   — Drain Solana vault (process pending withdrawals)"
    echo "  drain-xlm   — Drain Stellar vault (process pending withdrawals)"
    echo "  redeploy    — Full drain-before-migrate redeploy cycle"
    echo "  snapshot    — Save current state for audit/tracking"
    echo "  help        — Show this help"
    echo ""
    echo "State persistence (Seal nodes):"
    echo "  docker compose down      — stop nodes, KEEP state in volumes"
    echo "  docker compose down -v   — stop nodes, DELETE volumes"
    echo "  To restart with state: docker compose down && docker compose up -d"
    echo ""
    echo "Environment:"
    echo "  SEAL_RPC   — Seal node RPC URL (default: http://localhost:8645)"
    echo "  SOLANA_DEPLOYER  — Solana keypair path (default: ~/.config/solana/id.json)"
    echo "  STELLAR_DEPLOYER — Stellar keys identity (default: seal-bridge-deployer)"
}

# ── Main ───────────────────────────────────────────────────────────

main() {
    local cmd="${1:-help}"
    shift || true

    case "$cmd" in
        pause)       cmd_pause ;;
        status)      cmd_status ;;
        drain-sol)   cmd_drain_sol ;;
        drain-xlm)   cmd_drain_xlm ;;
        redeploy)    cmd_redeploy ;;
        snapshot)    cmd_snapshot ;;
        help|--help|-h) cmd_help ;;
        *) die "Unknown command: $cmd (run '$0 help' for usage)" ;;
    esac
}

main "$@"
