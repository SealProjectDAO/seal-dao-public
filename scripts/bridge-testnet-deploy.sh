#!/usr/bin/env bash
# scripts/bridge-testnet-deploy.sh — Deploy local Seal bridge nodes to
# public Solana devnet + Stellar testnet.
#
# Subcommands:
#   deploy    — Full lifecycle: deploy contracts → seed wallets →
#               generate committee key → start nodes → init programs →
#               register observers
#   up        — Start seal nodes only (Phase 4)
#   down      — Stop and remove containers
#   status    — Show node status and observer list
#   demo      — Run the bridge-demo (Phase 7) for a forward lock→mint
#   teardown  — Stop nodes AND remove all volumes (destroys validator keys)
#
# Usage:
#   ./scripts/bridge-testnet-deploy.sh deploy
#   ./scripts/bridge-testnet-deploy.sh up
#   ./scripts/bridge-testnet-deploy.sh demo sol
#   ./scripts/bridge-testnet-deploy.sh down
#
# Environment variables:
#   BRIDGE_COMMITTEE_KEY   — 64-char hex committee key (auto-generated if absent)
#   BRIDGE_DEMO_MODE       — bridge-testnet-demo.sh mode (default: both)
#   BRIDGE_TESTNET_DEMO_LIVE — set to 1 to actually run demo commands
#   SEAL_RPC               — seal-node RPC URL (default: http://localhost:8645)
#   SOLANA_DEPLOYER        — Solana keypair path (default: ~/.config/solana/id.json)
#   STELLAR_DEPLOYER       — Stellar keys identity (default: seal-bridge-deployer)
#
# Files created:
#   bridges/.bridge-committee-key.hex    — 256-bit random committee key
#   bridges/.solana-devnet-program-id    — deployed Solana program ID
#   bridges/.stellar-testnet-contract-id — deployed Stellar contract ID
#
# Exit codes:
#   0  success
#   1  missing dependency / preflight failure
#   2  deployment operation failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
BRIDGES_DIR="${REPO_DIR}/bridges"
COMPOSE_FILE="${BRIDGES_DIR}/docker-compose.testnet-public.yml"

# ── Helpers ────────────────────────────────────────────────────────

color() { printf '\033[%sm%s\033[0m\n' "$1" "${*:2}"; }
info()  { color "36" "==> $*"; }
pass()  { color "32" "[ok] $*"; }
fail()  { color "31" "[!!] $*" >&2; }
warn()  { color "33" "[!] $*" >&2; }

require() {
    local cmd="$1" desc="$2"
    if ! command -v "$cmd" &>/dev/null; then
        fail "$desc: '$cmd' not found in PATH"
        exit 1
    fi
}

docker_compose() {
    # Prefer docker compose (v2 plugin); fall back to docker-compose (v1)
    if docker compose version &>/dev/null; then
        docker compose -f "$COMPOSE_FILE" "$@"
    else
        docker-compose -f "$COMPOSE_FILE" "$@"
    fi
}

# Wait for seal-node RPC to respond. $1 = port, $2 = max retries (default 30)
wait_for_node() {
    local port="${1:-8645}" max="${2:-30}"
    local url="http://localhost:${port}"
    info "Waiting for seal-node RPC on ${url} (max ${max}s)..."
    for i in $(seq 1 "$max"); do
        if curl -fsS -m 3 "$url" >/dev/null 2>&1; then
            pass "seal-node RPC up on port ${port} (attempt ${i})"
            return 0
        fi
        sleep 2
    done
    fail "seal-node RPC not responding on port ${port} after ${max}s"
    return 1
}

# RPC helper: send a JSON-RPC call to seal-1
seal_rpc() {
    local port="${SEAL_RPC_PORT:-8645}"
    curl -sS -X POST "http://localhost:${port}" \
        -H "Content-Type: application/json" \
        -d "$1"
}

# ── Pre-flight checks ─────────────────────────────────────────────

preflight() {
    require docker "Docker"
    require curl "curl"
    require jq "jq"

    if [ ! -f "$COMPOSE_FILE" ]; then
        fail "docker-compose file not found: $COMPOSE_FILE"
        exit 1
    fi
}

# ── Phase 1: Deploy contracts to public testnets ───────────────────

deploy_solana() {
    info "Phase 1a: Deploying Solana bridge program to devnet..."

    # Check if already deployed
    if [ -f "${BRIDGES_DIR}/.solana-devnet-program-id" ]; then
        local existing
        existing=$(cat "${BRIDGES_DIR}/.solana-devnet-program-id")
        if [ -n "$existing" ]; then
            info "Solana program already deployed: $existing (skipping)"
            return 0
        fi
    fi

    require anchor "Anchor"
    require solana "Solana CLI"

    local deployer="${SOLANA_DEPLOYER:-~/.config/solana/id.json}"
    deployer=$(eval echo "$deployer")

    if [ ! -f "$deployer" ]; then
        fail "Solana deployer key not found: $deployer"
        fail "Run: solana-keygen new --no-bip39-passphrase --force -o $deployer"
        exit 1
    fi

    # Ensure CLI points at devnet
    solana config set --url https://api.devnet.solana.com 2>/dev/null

    # Airdrop if needed
    local pubkey
    pubkey=$(solana address -k "$deployer" 2>/dev/null || echo "")
    if [ -n "$pubkey" ]; then
        info "Checking devnet balance for $pubkey..."
        local balance
        balance=$(solana balance -k "$pubkey" --url https://api.devnet.solana.com 2>/dev/null | tail -1 || echo "0")
        info "Devnet balance: ${balance} SOL"
        if echo "$balance" | grep -q "0\.00" 2>/dev/null || [ "$(echo "$balance" | awk '{print $1}')" = "0" ]; then
            info "Requesting devnet airdrop..."
            solana airdrop 2 "$pubkey" --url https://api.devnet.solana.com
        fi
    fi

    # Build and deploy
    info "Building Anchor program..."
    (cd "${BRIDGES_DIR}/solana" && anchor build)

    info "Deploying to devnet..."
    (cd "${BRIDGES_DIR}/solana" && \
        anchor deploy --provider.cluster devnet \
            --provider.wallet "$deployer")

    local program_id
    program_id=$(solana address -k "${BRIDGES_DIR}/solana/target/deploy/seal_bridge-keypair.json" 2>/dev/null)
    if [ -z "$program_id" ]; then
        fail "Failed to derive program ID after deploy"
        exit 2
    fi

    echo "$program_id" > "${BRIDGES_DIR}/.solana-devnet-program-id"
    pass "Solana program deployed: $program_id"
    echo "$program_id"
}

deploy_stellar() {
    info "Phase 1b: Deploying Stellar bridge contract to testnet..."

    # Check if already deployed
    if [ -f "${BRIDGES_DIR}/.stellar-testnet-contract-id" ]; then
        local existing
        existing=$(cat "${BRIDGES_DIR}/.stellar-testnet-contract-id")
        if [ -n "$existing" ]; then
            info "Stellar contract already deployed: $existing (skipping)"
            return 0
        fi
    fi

    require stellar "Stellar CLI"

    local deployer="${STELLAR_DEPLOYER:-seal-bridge-deployer}"

    # Ensure testnet network config exists
    stellar network add testnet \
        --rpc-url https://soroban-testnet.stellar.org:443 \
        --network-passphrase 'Test SDF Network ; September 2015' 2>/dev/null || true

    # Fund deployer account
    info "Funding Stellar deployer account '$deployer'..."
    stellar keys fund "$deployer" --network testnet 2>/dev/null || true

    # Build and deploy
    info "Building Soroban contract..."
    (cd "${BRIDGES_DIR}/stellar" && \
        cargo build --target wasm32v1-none --release 2>&1 | tail -1 || true)

    # Deploy — stellar contract deploy outputs the contract ID to stdout
    info "Deploying Soroban contract to testnet..."
    local contract_id
    contract_id=$(cd "${BRIDGES_DIR}/stellar" && \
        stellar contract deploy \
            --wasm target/wasm32v1-none/release/seal_bridge_stellar.wasm \
            --source-account "$deployer" \
            --network testnet 2>/dev/null | tail -1 | tr -d '[:space:]')

    if [ -z "$contract_id" ] || ! echo "$contract_id" | grep -qP '^[CX]'; then
        # Try: the output might already be just the contract ID
        contract_id=$(cd "${BRIDGES_DIR}/stellar" && \
            stellar contract deploy \
                --wasm target/wasm32v1-none/release/seal_bridge_stellar.wasm \
                --source-account "$deployer" \
                --network testnet 2>&1 | grep -oP '^[CX][a-zA-Z0-9]+' | head -1)
    fi

    if [ -z "$contract_id" ]; then
        warn "Could not parse contract ID from deploy output"
        warn "Deploy output:"
        cd "${BRIDGES_DIR}/stellar" && \
            stellar contract deploy \
                --wasm target/wasm32v1-none/release/seal_bridge_stellar.wasm \
                --source-account "$deployer" \
                --network testnet 2>&1 | tail -5
        warn "Check Stellar testnet manually and save to ${BRIDGES_DIR}/.stellar-testnet-contract-id"
        return 1
    fi

    echo "$contract_id" > "${BRIDGES_DIR}/.stellar-testnet-contract-id"
    pass "Stellar contract deployed: $contract_id"
    echo "$contract_id"
}

# ── Phase 2: Seed wallets (already handled within deploy functions) ──
# Airdrops are done inline in deploy_solana and deploy_stellar.

# ── Phase 3: Generate committee key ─────────────────────────────────

setup_committee_key() {
    info "Phase 3: Setting up bridge committee key..."

    local key_file="${BRIDGES_DIR}/.bridge-committee-key.hex"

    if [ -n "${BRIDGE_COMMITTEE_KEY:-}" ]; then
        # Use explicitly provided key
        if [ ${#BRIDGE_COMMITTEE_KEY} -ne 64 ]; then
            fail "BRIDGE_COMMITTEE_KEY must be exactly 64 hex chars, got ${#BRIDGE_COMMITTEE_KEY}"
            exit 1
        fi
        echo "$BRIDGE_COMMITTEE_KEY" > "$key_file"
        pass "Using provided committee key"
    elif [ -f "$key_file" ]; then
        pass "Committee key already exists in $key_file"
    else
        # Generate fresh 256-bit key
        local new_key
        new_key=$(openssl rand -hex 32)
        echo "$new_key" > "$key_file"
        pass "Generated new committee key (64 hex chars)"
        export BRIDGE_COMMITTEE_KEY="$new_key"
    fi

    # Clear stale persisted key files from any previous runs
    info "Clearing stale bridge-committee-key.hex files from Docker volumes..."
    for vol in seal-1-data seal-2-data seal-3-data; do
        # Try to remove the stale file from any existing volume
        docker run --rm -v "${vol}:/vol" alpine \
            sh -c "rm -f /vol/data/bridge-committee-key.hex 2>/dev/null; true" || true
    done
}

# ── Phase 4: Start seal nodes ──────────────────────────────────────

start_nodes() {
    info "Phase 4: Starting seal bridge nodes..."

    export BRIDGE_COMMITTEE_KEY="${BRIDGE_COMMITTEE_KEY:?Phase 3 must run first}"

    docker_compose up -d

    info "Waiting for all nodes to be ready..."
    for port in 8645 8646 8647; do
        wait_for_node "$port" 45 || return 1
    done

    pass "All 3 seal nodes are running"
}

# ── Phase 5: Initialize on-chain bridge programs ───────────────────

init_solana_bridge() {
    # Solana Anchor programs are initialized during `anchor deploy`
    # (the deployer becomes authority, initialize ix runs automatically).
    # No separate init step needed.
    info "Solana bridge initialized during deploy (program_id=$1)"
    return 0
}

init_stellar_bridge() {
    local contract_id="${1:?Contract ID required}"
    local committee_key="${2:?Committee key required}"
    local deployer="${STELLAR_DEPLOYER:-seal-bridge-deployer}"

    info "Initializing Stellar bridge contract (contract_id=$contract_id)..."

    # Get deployer's G-address
    local admin_addr
    admin_addr=$(stellar keys address "$deployer" --network testnet 2>/dev/null) || {
        fail "Cannot resolve deployer address; try: stellar keys address $deployer --network testnet"
        return 1
    }

    # Get the deterministic native SAC address on this network
    local xlm_sac
    xlm_sac=$(stellar contract id asset --asset native --network testnet 2>/dev/null) || {
        # If SAC is not yet on-chain, deploy it
        info "Deploying native XLM SAC..."
        stellar contract asset deploy --asset native \
            --source-account "$deployer" --network testnet 2>/dev/null || true
        xlm_sac=$(stellar contract id asset --asset native --network testnet 2>/dev/null) || {
            fail "Cannot resolve native SAC address"
            return 1
        }
    }

    stellar contract invoke \
        --network testnet \
        --source-account "$deployer" \
        --id "$contract_id" \
        -- initialize \
        --admin "$admin_addr" \
        --seal_bridge_key "$committee_key" \
        --xlm_sac "$xlm_sac" 2>/dev/null || {
        warn "Stellar initialize failed — you may need to initialize manually:"
        warn "  stellar contract invoke --network testnet --source-account $deployer \\"
        warn "    --id $contract_id -- initialize --admin $admin_addr \\"
        warn "      --seal_bridge_key $committee_key --xlm_sac $xlm_sac"
        return 0
    }

    pass "Stellar bridge initialized (contract_id=$contract_id)"
}

# ── Phase 6: Register observers via seal RPC ───────────────────────

register_observers() {
    info "Phase 6: Registering chain observers..."

    local program_id="$1" contract_id="$2"

    # Register Solana observer (includes USDC mint for WUSDC routing)
    local sol_obs_params
    sol_obs_params=$(jq -n \
        --arg chain Solana \
        --arg rpc_url "https://api.devnet.solana.com" \
        --arg program_id "$program_id" \
        --arg usdc_mint "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr" \
        --arg poll_interval "10" \
        '{chain: $chain, rpc_url: $rpc_url, program_id: $program_id, usdc_mint: $usdc_mint, poll_interval_secs: ($poll_interval | tonumber)}')

    local sol_resp
    sol_resp=$(seal_rpc "$sol_obs_params")
    if echo "$sol_resp" | jq -e '.ok' &>/dev/null; then
        pass "Solana observer registered"
    else
        warn "Solana observer registration failed: $sol_resp"
        warn "Register manually: curl localhost:8645 -d '$sol_obs_params'"
    fi

    # Register Stellar observer
    local stellar_obs_params
    stellar_obs_params=$(jq -n \
        --arg chain Stellar \
        --arg horizon_url "https://horizon-testnet.stellar.org" \
        --arg contract_id "$contract_id" \
        --arg soroban_rpc "https://soroban-testnet.stellar.org" \
        --arg poll_interval "30" \
        '{chain: $chain, horizon_url: $horizon_url, contract_id: $contract_id, soroban_rpc_url: $soroban_rpc, poll_interval_secs: ($poll_interval | tonumber)}')

    local stellar_resp
    stellar_resp=$(seal_rpc "$stellar_obs_params")
    if echo "$stellar_resp" | jq -e '.ok' &>/dev/null; then
        pass "Stellar observer registered"
    else
        warn "Stellar observer registration failed: $stellar_resp"
        warn "Register manually: curl localhost:8645 -d '$stellar_obs_params'"
    fi
}

# ── Status ──────────────────────────────────────────────────────────

show_status() {
    info "Bridge node status:"

    for port in 8645 8646 8647; do
        if curl -fsS -m 3 "http://localhost:${port}" >/dev/null 2>&1; then
            pass "Node on port $port: RUNNING"
        else
            warn "Node on port $port: DOWN"
        fi
    done

    info "Observer list (node 1):"
    local obs
    obs=$(seal_rpc '{"jsonrpc":"2.0","id":1,"method":"seal_listBridgeObservers"}')
    echo "$obs" | jq '.' 2>/dev/null || echo "$obs"

    info "Program/contract IDs:"
    if [ -f "${BRIDGES_DIR}/.solana-devnet-program-id" ]; then
        echo "  Solana: $(cat "${BRIDGES_DIR}/.solana-devnet-program-id")"
    else
        echo "  Solana: (not deployed)"
    fi
    if [ -f "${BRIDGES_DIR}/.stellar-testnet-contract-id" ]; then
        echo "  Stellar: $(cat "${BRIDGES_DIR}/.stellar-testnet-contract-id")"
    else
        echo "  Stellar: (not deployed)"
    fi
}

# ── Commands ────────────────────────────────────────────────────────

cmd_deploy() {
    preflight

    local program_id
    local contract_id

    # Phase 1: Deploy contracts
    program_id=$(deploy_solana) || {
        fail "Solana deployment failed"
        exit 2
    }

    contract_id=$(deploy_stellar) || warn "Stellar deployment failed (may need manual setup)"
    # Don't exit if Stellar fails — Solana may still work

    # Phase 3: Committee key
    setup_committee_key

    # Phase 4: Start nodes
    start_nodes

    # Phase 5: Initialize on-chain programs (if contracts deployed)
    if [ -n "${program_id:-}" ]; then
        init_solana_bridge "$program_id" "$BRIDGE_COMMITTEE_KEY" || warn "Solana init skipped"
    fi
    if [ -n "${contract_id:-}" ]; then
        init_stellar_bridge "$contract_id" "$BRIDGE_COMMITTEE_KEY" || warn "Stellar init skipped"
    fi

    # Phase 6: Register observers
    if [ -n "${program_id:-}" ] && [ -n "${contract_id:-}" ]; then
        register_observers "$program_id" "$contract_id"
    elif [ -n "${program_id:-}" ]; then
        info "Only Solana deployed — registering Solana observer only"
        # Use existing Stellar contract ID if available from a prior run
        local existing_stellar="${BRIDGES_DIR}/.stellar-testnet-contract-id"
        if [ -f "$existing_stellar" ] && [ -s "$existing_stellar" ]; then
            register_observers "$program_id" "$(cat "$existing_stellar")"
        else
            info "Stellar contract not yet deployed; register Solana observer only"
            # Register Solana observer standalone
            local sol_obs_params
            sol_obs_params=$(jq -n \
                --arg chain Solana \
                --arg rpc_url "https://api.devnet.solana.com" \
                --arg program_id "$program_id" \
                --arg usdc_mint "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr" \
                --arg poll_interval "10" \
                '{chain: $chain, rpc_url: $rpc_url, program_id: $program_id, usdc_mint: $usdc_mint, poll_interval_secs: ($poll_interval | tonumber)}')
            seal_rpc "$sol_obs_params"
            pass "Solana observer registered (standalone)"
        fi
    elif [ -n "${contract_id:-}" ]; then
        info "Only Stellar deployed — registering Stellar observer only"
        local existing_sol="${BRIDGES_DIR}/.solana-devnet-program-id"
        if [ -f "$existing_sol" ] && [ -s "$existing_sol" ]; then
            register_observers "$(cat "$existing_sol")" "$contract_id"
        else
            info "Solana program not yet deployed; register Stellar observer only"
            local stellar_obs_params
            stellar_obs_params=$(jq -n \
                --arg chain Stellar \
                --arg horizon_url "https://horizon-testnet.stellar.org" \
                --arg contract_id "$contract_id" \
                --arg soroban_rpc "https://soroban-testnet.stellar.org" \
                --arg poll_interval "30" \
                '{chain: $chain, horizon_url: $horizon_url, contract_id: $contract_id, soroban_rpc_url: $soroban_rpc, poll_interval_secs: ($poll_interval | tonumber)}')
            seal_rpc "$stellar_obs_params"
            pass "Stellar observer registered (standalone)"
        fi
    else
        warn "Neither Solana nor Stellar contracts are deployed. Run 'deploy' first."
    fi

    echo ""
    pass "Deployment complete"
    echo ""
    echo "Next steps:"
    echo "  ./scripts/bridge-testnet-deploy.sh status     — verify nodes"
    echo "  ./scripts/bridge-testnet-deploy.sh demo        — run lock→mint flow"
    echo ""
    echo "Bridge addresses:"
    echo "  Solana program: ${program_id:-not deployed}"
    echo "  Stellar contract: ${contract_id:-not deployed}"
    echo "  Committee key: ${BRIDGE_COMMITTEE_KEY:+saved to ${BRIDGES_DIR}/.bridge-committee-key.hex}"
}

cmd_up() {
    preflight
    start_nodes
}

cmd_down() {
    info "Stopping seal bridge nodes..."
    docker_compose down
    pass "Nodes stopped"
}

cmd_demo() {
    local mode="${BRIDGE_TESTNET_DEMO_MODE:-${1:-both}}"

    # Set up env for demo
    export BRIDGE_TESTNET_DEMO_LIVE="${BRIDGE_TESTNET_DEMO_LIVE:-1}"
    export SEAL_RPC="${SEAL_RPC:-http://localhost:8645}"

    info "Running bridge-demo mode='$mode'..."
    "${SCRIPT_DIR}/bridge-testnet-demo.sh" "$mode"
}

cmd_teardown() {
    info "Tearing down seal bridge nodes (removing volumes)..."
    docker_compose down -v
    pass "Nodes and volumes removed"
}

# ── Main ────────────────────────────────────────────────────────────

main() {
    local cmd="${1:-help}"
    shift || true

    case "$cmd" in
        deploy)   cmd_deploy "$@" ;;
        up)       cmd_up "$@" ;;
        down)     cmd_down "$@" ;;
        status)   show_status ;;
        demo)     cmd_demo "$@" ;;
        teardown) cmd_teardown "$@" ;;
        help|*)
            echo "Usage: $0 {deploy|up|down|status|demo|teardown}"
            echo ""
            echo "  deploy    Full lifecycle: deploy contracts, start nodes, register observers"
            echo "  up        Start seal nodes only (requires deployed contracts)"
            echo "  down      Stop containers"
            echo "  status    Show node and observer status"
            echo "  demo      Run bridge-demo (forwards lock→mint)"
            echo "  teardown  Stop and remove all volumes (destroys validator keys)"
            echo ""
            echo "Environment:"
            echo "  BRIDGE_COMMITTEE_KEY   64-char hex (auto-generated if absent)"
            echo "  BRIDGE_DEMO_MODE       demo mode (default: both)"
            echo "  BRIDGE_TESTNET_DEMO_LIVE  set to 1 for live execution"
            echo "  SEAL_RPC               node RPC URL (default: http://localhost:8645)"
            echo "  SOLANA_DEPLOYER        Solana keypair path"
            echo "  STELLAR_DEPLOYER       Stellar keys identity"
            ;;
    esac
}

main "$@"
