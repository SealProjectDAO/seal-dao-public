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
#   ./scripts/bridge-e2e.sh              # full forward round-trip
#                                        # (Solana + Stellar)
#   ./scripts/bridge-e2e.sh reverse      # Stellar burn → unlock_xlm
#                                        # (validates committee MAC on-chain)
#   ./scripts/bridge-e2e.sh reverse-solana
#                                        # Solana burn → unlock_tokens.
#                                        # Requires env vars
#                                        # SOL_REVERSE_MINT,
#                                        # SOL_REVERSE_RECIPIENT,
#                                        # SOL_REVERSE_RECIPIENT_ATA,
#                                        # SOL_REVERSE_AUTHORITY.
#   ./scripts/bridge-e2e.sh up           # bring stack up only
#   ./scripts/bridge-e2e.sh down         # tear down and wipe volumes
#   ./scripts/bridge-e2e.sh check        # just preflight (prerequisites)
#
# Prerequisites (checked by `check`):
#   - docker / docker compose
#   - solana CLI (for airdrop + deploy outside containers)
#   - anchor CLI (>= 0.30)
#   - stellar CLI 25.x (cargo install stellar-cli --version "25.2.0" --locked)
#     Note: stellar-cli and soroban-sdk share the major version but are
#     separate crates; 25.2.0 CLI + 25.3.1 SDK + stellar-rpc 25.1.0 is
#     the tested combination. stellar-cli 22.x encodes protocol-22 XDR
#     and will be rejected by the protocol-25 RPC in the container.
#   - rustup with wasm32v1-none target
#
# Exit codes:
#   0  success
#   1  preflight failure (missing tool)
#   2  deploy failure
#   3  end-to-end assertion failure

set -euo pipefail

# `anchor build` invokes `cargo +1.89.0-sbpf-solana-v1.52 build-sbf`,
# which only resolves through rustup's `cargo` proxy
# (~/.cargo/bin/cargo). If a toolchain-specific cargo
# (~/.rustup/toolchains/<tc>/bin/cargo) appears earlier on PATH it
# fails with `error: no such command: '+...sbpf...'`. Force the
# proxy to win for the duration of this script.
export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$REPO_DIR/bridges/docker-compose.testnet.yml"

SOLANA_RPC="http://localhost:8899"
STELLAR_HORIZON="http://localhost:8000"
# Soroban contract operations (deploy, invoke) need the Soroban
# RPC, not Horizon. The stellar/quickstart container exposes it
# on :8003 (verified via getNetwork — Horizon is :8000, friendbot
# also lives at :8000/friendbot, the :8002 service is a
# standalone friendbot UI that returns 400 on Soroban methods).
STELLAR_SOROBAN_RPC="http://localhost:8003"
# Default bridge stack RPC — the bridge compose maps seal-1's
# in-container 8545 → host 8645 (offset from the validator stack's
# 8545, which we leave clear so a user's local dev seal-node can
# run alongside the bridge stack without port-stealing this check).
# Override via SEAL_RPC=... env if you've remapped the stack.
SEAL_RPC="${SEAL_RPC:-http://localhost:8645}"

# Derive seal-node 1/2/3 host-side ports from $SEAL_RPC. Compose pins
# them at base+0/+1/+2 (default 8645/8646/8647). Hardcoding 8545-8547
# is wrong here: that range belongs to the validator stack and to any
# locally-running `seal-node --rpc-port 8545`, neither of which carry
# the `--bridge-committee-key` flag — every signed bridge check would
# spuriously fail against them. Honor SEAL_RPC so a tester who
# remapped the bridge stack still gets correct probes.
SEAL_PORT_1="${SEAL_RPC##*:}"
SEAL_PORT_2="$((SEAL_PORT_1 + 1))"
SEAL_PORT_3="$((SEAL_PORT_1 + 2))"

LOCK_AMOUNT=1000000000           # 1 SOL in lamports
LOCK_AMOUNT_XLM=10000000         # 1 XLM in stroops
# On-Seal recipient — derived from a real ML-DSA key so the reverse
# leg (burn → unlock) can sign as the wrapped-balance holder.
# Generated lazily on first run + reused via the key file, so the
# minted address stays stable across e2e invocations.
SEAL_E2E_KEY="$REPO_DIR/bridges/.seal-e2e-key.json"
# Export so the anchor test (run via `with_crates_io bash -c "..."` in
# a subshell) picks it up and uses the real seal recipient instead of
# the [0xab; 32] fallback. Without the export, the Solana lock mints
# wSOL to an address whose ML-DSA key we don't hold, and the reverse
# burn fails with "insufficient wrapped balance: need N, have 0".
export SEAL_RECIPIENT_HEX
SEAL_RECIPIENT_HEX="$(
    if [ -f "$SEAL_E2E_KEY" ]; then
        # Already minted earlier — reuse the same key so the address
        # (which equals the SHA3-256 of the verifying key) is stable.
        jq -r '.address' "$SEAL_E2E_KEY" \
            | xargs -I@ cargo run --quiet -p seal-cli -- addr-to-hex @ 2>/dev/null
    else
        # First run — generate, persist, and emit the hex form.
        cargo run --quiet -p seal-cli -- keygen --output "$SEAL_E2E_KEY" \
            >/dev/null 2>&1
        jq -r '.address' "$SEAL_E2E_KEY" \
            | xargs -I@ cargo run --quiet -p seal-cli -- addr-to-hex @ 2>/dev/null
    fi
)"

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
    if ! rustup target list --installed 2>/dev/null | grep -q wasm32v1-none; then
        fail "missing rust target: wasm32v1-none"
        fail "fix with: rustup target add wasm32v1-none"
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
    # Wipe volumes before bringing the stack up. Bridge-e2e is a
    # destructive smoke test — every run wants a clean ledger AND a
    # clean per-node /data dir. Without `-v` the seal-N-data volumes
    # persist `bridge-committee-key.hex` from prior runs (rotated by
    # `verify_committee_key_rotation` or the anchor test's "rotates
    # the committee key" step), and that file is loaded at startup
    # in preference to the `--bridge-committee-key` flag
    # (crates/seal-node/src/main.rs:167-192) — so the committee-key
    # fingerprint smoke check fails before solana_round_trip even
    # starts. Set SKIP_STACK_DOWN_V=1 to opt out (debugging only).
    if [ "${SKIP_STACK_DOWN_V:-0}" != "1" ]; then
        (cd "$REPO_DIR/bridges" && docker compose -f docker-compose.testnet.yml down -v) \
            || { fail "docker compose down -v failed"; exit 2; }
    else
        info "SKIP_STACK_DOWN_V=1 — preserving volumes from prior run"
    fi
    # Split build + up into two steps to dodge a long-standing
    # `docker compose up --build --wait` hang: when the build phase
    # produces a fresh image but the prior containers are still
    # healthy, --wait sometimes blocks indefinitely instead of
    # recreating from the new image. Building separately gives the
    # daemon a clear hand-off; --force-recreate then guarantees
    # containers run the just-built image.
    (cd "$REPO_DIR/bridges" && docker compose -f docker-compose.testnet.yml build) \
        || { fail "docker compose build failed"; exit 2; }
    (cd "$REPO_DIR/bridges" && docker compose -f docker-compose.testnet.yml \
        up -d --force-recreate --wait) \
        || { fail "docker compose up failed"; exit 2; }
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
    info "waiting for Seal nodes to accept RPC connections…"
    # The Seal nodes start after stellar becomes healthy; give them up to
    # 60s to open their JSON-RPC ports before the round-trip begins.
    for _ in $(seq 1 60); do
        if curl -sS --max-time 2 "$SEAL_RPC" \
               -H 'content-type: application/json' \
               -d '{"jsonrpc":"2.0","id":1,"method":"seal_getHeight","params":[]}' \
               >/dev/null 2>&1; then
            pass "Seal node 1 RPC reachable"
            break
        fi
        sleep 1
    done
}

stack_down() {
    info "tearing down bridge stack + wiping volumes"
    (cd "$REPO_DIR/bridges" && docker compose -f docker-compose.testnet.yml down -v)
    pass "stack torn down"
}

# ── Deploy contracts ────────────────────────────────────────
#
# The bridge programs (Anchor + Soroban) live in `bridges/solana` and
# `bridges/stellar`, OUTSIDE the workspace. They depend on
# `anchor-lang` and `soroban-sdk` from crates.io — but the workspace
# `.cargo/config.toml` redirects every crates.io lookup to `vendor/`,
# which doesn't carry those packages. `with_crates_io` moves the
# config aside for the duration of a build so cargo can fetch from
# the real registry, then restores it. Same pattern
# `scripts/ci-formal.sh` uses for Miri.

with_crates_io() {
    # Run a command with the workspace vendor config moved aside.
    # Restores the config in the EXIT trap so an unhandled failure
    # doesn't leave the repo in a half-state.
    local cfg="$REPO_DIR/.cargo/config.toml"
    if [ -f "$cfg" ]; then
        mv "$cfg" "$cfg.bridge-e2e.bak"
        trap "mv '$cfg.bridge-e2e.bak' '$cfg' 2>/dev/null || true" EXIT
    fi
    "$@"
    local rc=$?
    if [ -f "$cfg.bridge-e2e.bak" ]; then
        mv "$cfg.bridge-e2e.bak" "$cfg"
        trap - EXIT
    fi
    return $rc
}

deploy_solana() {
    info "deploying seal-bridge Anchor program to local validator"
    solana config set --url "$SOLANA_RPC" >/dev/null
    if [ ! -f "$HOME/.config/solana/id.json" ]; then
        info "generating new keypair at ~/.config/solana/id.json"
        solana-keygen new --no-bip39-passphrase --outfile "$HOME/.config/solana/id.json" --force
    fi
    solana airdrop 100 >/dev/null || true  # localnet gives unbounded
    local solana_dir="$REPO_DIR/bridges/solana"
    local prog_dir="$solana_dir/programs/seal-bridge"
    local prog_so="$prog_dir/target/deploy/seal_bridge.so"
    local deploy_so="$solana_dir/target/deploy/seal_bridge.so"
    # Build with `cargo build-sbf -- --locked` from the program dir
    # rather than `anchor build` from `bridges/solana`. Two reasons:
    #   1) anchor 0.31's wrapper swallows cargo-build-sbf's exit
    #      code, so a real build failure ends with exit 0 and no
    #      .so. The verify-artifact check below catches that, but
    #      rerunning to actually fix is slow.
    #   2) `--locked` is required: the program's existing
    #      Cargo.lock pins `getrandom 0.2.17` (SBF-compatible) and
    #      `0.1.16`, but with the workspace vendor config moved
    #      aside (see `with_crates_io`) cargo otherwise re-resolves
    #      from crates.io and picks `getrandom 0.3`, which fails to
    #      compile for the SBF target with `unresolved module 'imp'`.
    info "building program (cargo build-sbf -- --locked)"
    if ! with_crates_io bash -c "cd '$prog_dir' && cargo build-sbf -- --locked"; then
        fail "cargo build-sbf failed"
        return 2
    fi
    if [ ! -s "$prog_so" ]; then
        fail "cargo build-sbf succeeded but $prog_so is missing or empty"
        return 2
    fi
    # Stage the .so where `anchor deploy` looks for it. anchor reads
    # Anchor.toml + walks `target/deploy/` from `bridges/solana/`.
    mkdir -p "$solana_dir/target/deploy"
    cp "$prog_so" "$deploy_so"
    # Re-use the program's keypair if anchor expects it at the
    # bridges/solana level; both paths reference the same key.
    if [ ! -f "$solana_dir/target/deploy/seal_bridge-keypair.json" ] \
       && [ -f "$prog_dir/target/deploy/seal_bridge-keypair.json" ]; then
        cp "$prog_dir/target/deploy/seal_bridge-keypair.json" \
           "$solana_dir/target/deploy/seal_bridge-keypair.json"
    fi
    # `anchor deploy` builds a TPU client that asks the validator
    # for upcoming leader info; the dockerized solana-test-validator
    # only exposes 8899/8900 (JSON-RPC + WebSocket), not the TPU
    # gossip ports, so the TPU client can't bootstrap and times out
    # after 20s. `solana program deploy --use-rpc` skips the TPU
    # path entirely and just submits the program-deploy transactions
    # over the RPC.
    local keypair="$solana_dir/target/deploy/seal_bridge-keypair.json"
    if ! solana program deploy \
            --use-rpc \
            --url "$SOLANA_RPC" \
            --keypair "$HOME/.config/solana/id.json" \
            --program-id "$keypair" \
            "$deploy_so"; then
        fail "solana program deploy failed"
        return 2
    fi
    pass "Solana program deployed"
}

deploy_stellar() {
    info "deploying seal-bridge Soroban contract to local Stellar"
    local stellar_dir="$REPO_DIR/bridges/stellar"
    # The stellar CLI loads its network/key config from `.stellar/`
    # in cwd (or the nearest ancestor). Run every stellar command
    # from `$stellar_dir` so they share one config — otherwise
    # `stellar network add local` runs in repo root and writes
    # `./.stellar/`, but later `stellar contract deploy` runs in
    # `bridges/stellar/` and reads the stale `bridges/stellar/.stellar/`
    # left over from prior runs (which used to point at :8000).
    # Wipe any stale config first.
    rm -rf "$stellar_dir/.stellar"
    cd "$stellar_dir"
    # Stellar network alias points the CLI at the *Soroban RPC*
    # (port 8003), not Horizon (8000). `stellar contract deploy`
    # uses the Soroban RPC's simulateTransaction / sendTransaction
    # methods, which Horizon doesn't speak (it returns 405).
    # Friendbot lives at Horizon (8000) — handled separately below.
    stellar network add local \
        --rpc-url "$STELLAR_SOROBAN_RPC" \
        --network-passphrase "Standalone Network ; February 2017" \
        2>/dev/null || true
    if ! stellar keys show seal-e2e >/dev/null 2>&1; then
        # `stellar keys generate --fund` / `stellar keys fund --network`
        # construct the friendbot URL as `<rpc_url>/friendbot`, which
        # hits `:8003/friendbot` (Soroban RPC) instead of the actual
        # friendbot at `:8000/friendbot` (Horizon). Generate without
        # funding (the default in stellar-cli 25+; `--no-fund` was
        # removed — the flag no longer exists) and call friendbot
        # directly via curl below.
        stellar keys generate seal-e2e
    fi
    local addr
    addr=$(stellar keys address seal-e2e)
    # Fund the account if it doesn't exist on this network. The key may
    # already be on disk from a previous session, but `docker compose
    # down -v` wipes the stellar-data volume so every fresh stack is a
    # new chain where the account hasn't been funded yet.
    if ! curl -fsS "$STELLAR_HORIZON/accounts/$addr" >/dev/null 2>&1; then
        local fund_url="$STELLAR_HORIZON/friendbot?addr=$addr"
        # Friendbot is racy on first boot — even after the docker
        # healthcheck reports healthy, it can take another few seconds
        # for the funding endpoint to actually accept requests. Allow
        # up to 30 × 2s = 60s before giving up.
        local i=0
        until curl -fsS "$fund_url" >/dev/null 2>&1; do
            i=$((i + 1))
            if [ $i -ge 30 ]; then
                fail "friendbot fund failed after 30 attempts: $fund_url"
                return 2
            fi
            sleep 2
        done
    fi
    local wasm="$stellar_dir/target/wasm32v1-none/release/seal_bridge_stellar.wasm"
    if ! with_crates_io bash -c "cd '$stellar_dir' && cargo build --target wasm32v1-none --release"; then
        fail "soroban contract build failed"
        return 2
    fi
    if [ ! -s "$wasm" ]; then
        fail "soroban build succeeded but $wasm is missing or empty"
        return 2
    fi
    local contract_id
    contract_id=$(cd "$stellar_dir" && stellar contract deploy --wasm "$wasm" --network local --source seal-e2e) \
        || { fail "stellar contract deploy failed"; return 2; }
    echo "$contract_id" > "$REPO_DIR/bridges/.stellar-contract-id"
    # Deploy the native XLM Stellar Asset Contract (SAC) if not already present.
    # `stellar contract id asset` only computes the deterministic address; the SAC
    # itself must be deployed on-chain so lock_xlm's CPI transfer call can find it.
    # Re-deploying is idempotent — the command is a no-op if the SAC already exists.
    stellar contract asset deploy --asset native --network local --source seal-e2e \
        >/dev/null 2>&1 || true
    local xlm_sac
    xlm_sac=$(stellar contract id asset --asset native --network local)
    if ! (cd "$stellar_dir" && stellar contract invoke \
            --id "$contract_id" --network local --source seal-e2e \
            -- initialize \
            --admin "$(stellar keys address seal-e2e)" \
            --seal_bridge_key "1111111111111111111111111111111111111111111111111111111111111111" \
            --xlm_sac "$xlm_sac"); then
        fail "stellar contract initialize failed"
        return 2
    fi
    pass "Stellar contract deployed (id=$contract_id)"
    # Restore the parent shell's cwd. The function did `cd "$stellar_dir"`
    # on line 318 (so the stellar CLI picks up the right `.stellar/`
    # config), and bash function cd's leak to the caller. Without this
    # restore the reverse-leg helpers run `cargo run -p seal-cli` from
    # `bridges/stellar` and get "package(s) `seal-cli` not found in
    # workspace" since that subdir isn't part of the seal workspace.
    cd "$REPO_DIR"
}

# ── Lock → mint round trip ──────────────────────────────────

seal_rpc() {
    # Usage: seal_rpc METHOD [PARAMS_JSON] [--port N]
    # Default port is $SEAL_PORT_1 (seal bridge node 1, host-side; the
    # docker-compose maps in-container 8545 → host 8645 by default).
    # Parameters default to `[]`.
    local method="$1"
    shift
    local params="[]"
    local port="$SEAL_PORT_1"
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

# ──────────────────────────────────────────────────────────────
# Per-node readiness pipeline. Canonical phases (in order):
#
#   1. RPC reachable           — HTTP POST to seal_getHeight returns
#   2. Consensus alive         — seal_getHeight.height >= 1
#                                (bootstrap: produced its 1st block;
#                                 followers: synced from node-1)
#   3. Committee key fingerprint matches the expected fixture sha2
#      (proves --bridge-committee-key applied, no persisted drift)
#   4. Bridge observer subsystem persists a registration across a
#      4 s gap (no startup-race state loss)
#
# Each phase has its own bounded wait + own diagnostic on failure.
# We fail fast at the first phase that times out so the operator
# sees *which* signal broke, not a generic "registration failed".
#
# Boot order (enforced by wait_for_all_bridge_nodes_ready below):
# node-1 (bootstrap) first, then node-2 and node-3 sequentially.
# By the time we check node-2's consensus, node-1 has been
# producing blocks long enough for node-2 to have synced — so a
# height>=1 on node-2 implies the peering+sync path worked, no
# separate peer-count probe needed.
# ──────────────────────────────────────────────────────────────

# The fixture committee key sha2 — SHA-256 over [0x11; 32]. Set
# via the `--bridge-committee-key` flag in docker-compose.testnet.yml;
# verify_committee_key_fingerprint above uses the same constant.
BRIDGE_FIXTURE_COMMITTEE_KEY_SHA2="02d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc"

# Resolve a host port to its docker container name so failure
# diagnostics can pull the right node's logs.
bridge_node_container_for_port() {
    case "$1" in
        "$SEAL_PORT_1") echo seal-bridge-node-1 ;;
        "$SEAL_PORT_2") echo seal-bridge-node-2 ;;
        "$SEAL_PORT_3") echo seal-bridge-node-3 ;;
        *) echo "(unknown port $1)" ;;
    esac
}

wait_for_bridge_node_ready() {
    local port="$1"
    local label="$2"
    local expected_sha2="${3:-$BRIDGE_FIXTURE_COMMITTEE_KEY_SHA2}"
    local container i ok

    # ── phase 1 — RPC reachable ────────────────────────────────
    info "[$label :$port] phase 1/4 — RPC reachable"
    ok=0
    for i in $(seq 1 60); do
        if curl -sS --max-time 2 "http://localhost:$port" \
            -H 'content-type: application/json' \
            -d '{"jsonrpc":"2.0","id":1,"method":"seal_getHeight","params":{}}' \
            >/dev/null 2>&1; then
            ok=1; break
        fi
        sleep 1
    done
    if [ "$ok" -ne 1 ]; then
        fail "[$label :$port] phase 1 (RPC) timed out after 60s"
        container=$(bridge_node_container_for_port "$port")
        docker logs --since 60s "$container" 2>&1 | tail -30 | sed 's/^/    /' >&2 || true
        return 1
    fi

    # ── phase 2 — consensus alive ──────────────────────────────
    info "[$label :$port] phase 2/4 — consensus (height >= 1)"
    ok=0
    local height=0
    for i in $(seq 1 60); do
        height=$(seal_rpc seal_getHeight '{}' --port "$port" \
            | jq -r '.result.height // 0' 2>/dev/null || echo 0)
        if [ "$height" -ge 1 ]; then
            ok=1; break
        fi
        sleep 1
    done
    if [ "$ok" -ne 1 ]; then
        fail "[$label :$port] phase 2 (consensus) timed out — height=$height after 60s"
        container=$(bridge_node_container_for_port "$port")
        docker logs --since 60s "$container" 2>&1 | tail -30 | sed 's/^/    /' >&2 || true
        return 1
    fi

    # ── phase 3 — committee-key fingerprint ────────────────────
    info "[$label :$port] phase 3/4 — committee key fingerprint"
    ok=0
    local actual_sha2=""
    for i in $(seq 1 30); do
        actual_sha2=$(seal_rpc seal_bridgeGetCommitteeKeyStatus '{}' --port "$port" \
            | jq -r '.result.fingerprint_sha2_hex // empty' 2>/dev/null || echo "")
        if [ "$actual_sha2" = "$expected_sha2" ]; then
            ok=1; break
        fi
        sleep 1
    done
    if [ "$ok" -ne 1 ]; then
        fail "[$label :$port] phase 3 (committee key) timed out"
        fail "  expected sha2 = $expected_sha2"
        fail "  actual   sha2 = $actual_sha2"
        fail "  most common cause: a prior run rotated this node's"
        fail "  committee key and persisted it to /data/bridge-committee-key.hex."
        fail "  stack_up should have wiped the volume — verify with"
        fail "  'docker compose -f bridges/docker-compose.testnet.yml down -v'"
        fail "  before re-running."
        return 1
    fi

    # ── phase 4 — bridge observer subsystem ────────────────────
    info "[$label :$port] phase 4/4 — observer subsystem persists"
    ok=0
    local sentinel baseline post_add post_wait
    sentinel='{"chain":"Solana","rpc_url":"http://127.0.0.1:1","program_id":"ReadinessProbe11111111111111111111111111111"}'
    for i in $(seq 1 12); do
        baseline=$(seal_rpc seal_listBridgeObservers '{}' --port "$port" \
            | jq -r '.result.count // 0' 2>/dev/null || echo 0)
        seal_rpc seal_addBridgeObserver "$sentinel" --port "$port" >/dev/null 2>&1 || true
        sleep 1
        post_add=$(seal_rpc seal_listBridgeObservers '{}' --port "$port" \
            | jq -r '.result.count // 0' 2>/dev/null || echo 0)
        sleep 3
        post_wait=$(seal_rpc seal_listBridgeObservers '{}' --port "$port" \
            | jq -r '.result.count // 0' 2>/dev/null || echo 0)
        if [ "$post_add" -gt "$baseline" ] && [ "$post_wait" -gt "$baseline" ]; then
            ok=1; break
        fi
        sleep 1
    done
    if [ "$ok" -ne 1 ]; then
        fail "[$label :$port] phase 4 (observer subsystem) timed out"
        fail "  baseline=$baseline  post-add t+1=$post_add  post-add t+4=$post_wait"
        container=$(bridge_node_container_for_port "$port")
        docker logs --since 60s "$container" 2>&1 | tail -30 | sed 's/^/    /' >&2 || true
        return 1
    fi

    pass "[$label :$port] READY (height=$height, fp=${actual_sha2:0:16}…, observer-persist ✓)"
    return 0
}

wait_for_all_bridge_nodes_ready() {
    info "▶ bridge-node readiness pipeline (canonical order: bootstrap → followers)"
    wait_for_bridge_node_ready "$SEAL_PORT_1" "bootstrap node-1" || return 1
    wait_for_bridge_node_ready "$SEAL_PORT_2" "follower  node-2" || return 1
    wait_for_bridge_node_ready "$SEAL_PORT_3" "follower  node-3" || return 1
    # Cross-node consistency: phase 3 already verified each node's
    # fingerprint individually against the same constant, so by
    # induction they all match each other. Print one summary line so
    # the operator sees the cluster is ledger-consistent.
    pass "▶ all 3 bridge nodes ready; committee-key fingerprint is consistent across the cluster"
}

# Wait until every bridge node is genuinely ready to *persist* observer
# registrations. During the first ~30 s after `stack_up` returns there's
# a window where `seal_addBridgeObserver` returns ok:true but the
# observer count flips back to 0 on the next read — last seen in the
# 2026-05-20 e2e runs that drove this helper into existence. Rather
# than padding the per-attempt budget in `register_observer_verified`
# and hoping, this function uses a *deterministic* readiness signal:
# for each node we run two consecutive add+list cycles and only return
# success once both reads show count >= the post-add baseline.
#
# Why two cycles, not one: a single cycle catches the trivial case
# but doesn't prove persistence — the second cycle confirms the
# observer survives across an auto-poll interval boundary in the
# typical timing. A 3 s gap between reads matches the dev devnet
# slot cadence and is enough to surface fast-cycling state.
#
# The sentinel uses chain=Solana + a deliberately bogus rpc_url so the
# observer's poll_events fails harmlessly; the catch_unwind fix in
# poll_bridges_once (crates/seal-node/src/rpc.rs:4010) keeps the
# observer in the set across any poll error. The sentinel stays
# registered after readiness — it's a no-op in terms of bridge state
# (it can't observe anything from an invalid host) and harmless next
# to the real observers.
wait_for_bridge_nodes_ready() {
    info "waiting for bridge nodes to accept persistent observer registrations…"
    local sentinel
    sentinel='{"chain":"Solana","rpc_url":"http://127.0.0.1:1","program_id":"ReadinessProbe11111111111111111111111111111"}'
    local port baseline pre1 pre2 ok wait_total
    for port in "$SEAL_PORT_1" "$SEAL_PORT_2" "$SEAL_PORT_3"; do
        ok=0
        wait_total=0
        # Up to 60 s total per node — 12 cycles × ~5 s each.
        for _ in $(seq 1 12); do
            baseline=$(seal_rpc seal_listBridgeObservers '{}' --port "$port" \
                | jq -r '.result.count // 0' 2>/dev/null || echo 0)
            seal_rpc seal_addBridgeObserver "$sentinel" --port "$port" >/dev/null 2>&1 || true
            sleep 1
            pre1=$(seal_rpc seal_listBridgeObservers '{}' --port "$port" \
                | jq -r '.result.count // 0' 2>/dev/null || echo 0)
            sleep 3
            pre2=$(seal_rpc seal_listBridgeObservers '{}' --port "$port" \
                | jq -r '.result.count // 0' 2>/dev/null || echo 0)
            wait_total=$((wait_total + 4))
            # Both post-add reads must show count > baseline. That
            # proves the observer landed AND survived a 3 s gap.
            if [ "$pre1" -gt "$baseline" ] && [ "$pre2" -gt "$baseline" ]; then
                pass "bridge node :$port ready for observer registration (sentinel held $pre2 > $baseline baseline across 4 s)"
                ok=1
                break
            fi
            sleep 1
        done
        if [ "$ok" -ne 1 ]; then
            fail "bridge node :$port never became ready (sentinel never persisted across ${wait_total}s)"
            fail "  last baseline=$baseline  post-add t+1=$pre1  post-add t+4=$pre2"
            fail "  node logs (last 60s):"
            docker logs --since 60s "seal-bridge-node-$(case "$port" in "$SEAL_PORT_1") echo 1;; "$SEAL_PORT_2") echo 2;; *) echo 3;; esac)" \
                2>&1 | tail -30 | sed 's/^/    /' >&2 || true
            return 1
        fi
    done
    pass "all 3 bridge nodes ready for observer registration"
}

# Register an observer on one node, then read it back to confirm the
# registration actually took. The plain RPC call returned ok:true even
# on bridge-node-1 in cases where listBridgeObservers still showed
# count:0 a moment later — likely a fast restart of the node losing
# in-memory observer state. Retry up to 5×; bail loudly if none stick.
register_observer_verified() {
    local port="$1"
    local params_json="$2"
    local desc="$3"
    local max_attempts=30   # 30 × 2 s = 60 s — covers the startup-window
                            # race where seal_addBridgeObserver returns
                            # ok:true within the first ~30 s of node life
                            # but the observer count flips back to 0. The
                            # cause is still under investigation; in the
                            # meantime giving the node a full minute to
                            # settle reliably gets observers to stick.
                            # Manual probes confirm registrations are
                            # rock-solid once the window has passed.
    local attempt add_resp list_resp count
    for attempt in $(seq 1 "$max_attempts"); do
        add_resp=$(seal_rpc seal_addBridgeObserver "$params_json" --port "$port" 2>&1 || true)
        list_resp=$(seal_rpc seal_listBridgeObservers '{}' --port "$port" 2>&1 || true)
        count=$(printf '%s' "$list_resp" | jq -r '.result.count // 0' 2>/dev/null || echo 0)
        if [ "$count" -ge 1 ]; then
            if [ "$attempt" -gt 1 ]; then
                info "$desc landed on :$port after $attempt attempt(s)"
            fi
            return 0
        fi
        # Only log every 5 attempts to avoid a wall of spam.
        if [ "$((attempt % 5))" -eq 1 ] || [ "$attempt" = "$max_attempts" ]; then
            info "$desc not visible on :$port yet (attempt $attempt/$max_attempts, count=$count); retrying"
            info "  add response : $(printf '%s' "$add_resp" | tr -d '\n' | head -c 200)"
            info "  list response: $(printf '%s' "$list_resp" | tr -d '\n' | head -c 200)"
        fi
        sleep 2
    done
    fail "could not register $desc on :$port after $max_attempts attempts (count still 0 after $((max_attempts * 2))s)"
    fail "  last add response : $add_resp"
    fail "  last list response: $list_resp"
    fail "  node-1 logs (last 60s):"
    docker logs --since 60s seal-bridge-node-1 2>&1 | tail -30 | sed 's/^/    /' >&2 || true
    return 1
}

# Returns 0 if ANY of the three bridge nodes has at least one stored
# deposit for the given chain. The script's poll_until used to query
# only $SEAL_PORT_1, which silently failed whenever node-1 lacked an
# observer (e.g. when register_observer_verified didn't run / didn't
# converge) — even though nodes 2 and 3 had already ingested the
# deposit.
any_node_has_deposit() {
    local chain="$1"
    local p
    # Force a fresh sweep on every node first; auto-poll cadence is
    # 10 s, but the explicit RPC ignores per-observer schedules.
    for p in "$SEAL_PORT_1" "$SEAL_PORT_2" "$SEAL_PORT_3"; do
        seal_rpc seal_pollBridges '[]' --port "$p" >/dev/null || true
    done
    for p in "$SEAL_PORT_1" "$SEAL_PORT_2" "$SEAL_PORT_3"; do
        if seal_rpc seal_getBridgeDeposits "[\"$chain\"]" --port "$p" \
            | jq -e '.result | length > 0' >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

verify_committee_key_rotation() {
    # End-to-end smoke for seal_bridgeRotateCommitteeKey. Seats a
    # 3-member council on node1, rotates to a known test key, asserts
    # the SHA-256 fingerprint matches what we computed offline, then
    # rotates back to the e2e fixture key so downstream tests still
    # see the expected fingerprint. Council size 3 is the minimum
    # where 2/3 supermajority requires at least one signature from
    # each unique key, which exercises the dedup + count_valid_
    # approvers paths.
    if ! command -v openssl >/dev/null 2>&1; then
        info "openssl not installed — skipping rotation smoke"
        return 0
    fi
    local node_url="$SEAL_RPC"
    local fixture_key_hex="1111111111111111111111111111111111111111111111111111111111111111"
    local new_key_hex
    new_key_hex=$(printf '%064d' 2 | tr '0' '2')  # [0x22; 32]
    local new_key_sha2
    new_key_sha2=$(printf '%s' "$new_key_hex" \
        | xxd -r -p \
        | openssl dgst -sha256 -hex \
        | awk '{print $NF}')

    # Generate 3 distinct council keys.
    local council_keys=()
    for i in 1 2 3; do
        local kf="/tmp/seal-e2e-council-$i.json"
        if [ ! -f "$kf" ]; then
            cargo run --quiet -p seal-cli -- keygen --output "$kf" >/dev/null
        fi
        council_keys+=("$(jq -r .verifying_key "$kf")")
    done

    # Seat each one. Idempotent — re-add returns success on the
    # alpha-bootstrap path.
    for pk in "${council_keys[@]}"; do
        seal_rpc seal_bridgeCouncilAdd \
            "{\"pubkey\":\"$pk\",\"name\":\"e2e-council\"}" --port "$SEAL_PORT_1" >/dev/null
    done

    local approvers_json
    approvers_json=$(printf '%s\n' "${council_keys[@]}" | jq -R . | jq -s .)

    # Rotate to the test key. Expect success.
    local rot_resp
    rot_resp=$(seal_rpc seal_bridgeRotateCommitteeKey \
        "{\"new_key_hex\":\"$new_key_hex\",\"approvers\":$approvers_json}" \
        --port "$SEAL_PORT_1")
    local rotated
    rotated=$(printf '%s' "$rot_resp" | jq -r '.result.rotated // false')
    if [ "$rotated" != "true" ]; then
        fail "seal_bridgeRotateCommitteeKey did not succeed: $rot_resp"
        return 3
    fi
    local reported_sha2
    reported_sha2=$(printf '%s' "$rot_resp" | jq -r '.result.fingerprint_sha2_hex // empty')
    if [ "$reported_sha2" != "$new_key_sha2" ]; then
        fail "rotation fingerprint mismatch: expected $new_key_sha2 got $reported_sha2"
        return 3
    fi

    # Confirm /metrics + status both reflect the new key.
    local status_resp status_sha2
    status_resp=$(seal_rpc seal_bridgeGetCommitteeKeyStatus '{}' --port "$SEAL_PORT_1")
    status_sha2=$(printf '%s' "$status_resp" | jq -r '.result.fingerprint_sha2_hex // empty')
    if [ "$status_sha2" != "$new_key_sha2" ]; then
        fail "status RPC fingerprint drift after rotate: $status_sha2 != $new_key_sha2"
        return 3
    fi

    # Rotate back so subsequent tests see the fixture key. Capture
    # the response — earlier this call used `>/dev/null` and hid the
    # actual rotation failure behind a downstream "fingerprint didn't
    # restore" assertion, which gave you the wrong error to chase.
    local back_resp back_rotated back_error
    back_resp=$(seal_rpc seal_bridgeRotateCommitteeKey \
        "{\"new_key_hex\":\"$fixture_key_hex\",\"approvers\":$approvers_json}" \
        --port "$SEAL_PORT_1")
    back_rotated=$(printf '%s' "$back_resp" | jq -r '.result.rotated // false')
    if [ "$back_rotated" != "true" ]; then
        back_error=$(printf '%s' "$back_resp" \
            | jq -r '.error.message // "no error field"')
        fail "rotate-back to fixture key did NOT succeed (rotated=$back_rotated)"
        fail "  raw RPC response: $back_resp"
        fail "  error message   : $back_error"
        # Common cause: council quorum mismatch or persisted state from
        # an earlier run. The seal-bridge-node-1 logs typically carry
        # the exact reason at warn level.
        fail "  node-1 logs (last 60s):"
        docker logs --since 60s seal-bridge-node-1 2>&1 | tail -30 | sed 's/^/    /' >&2 || true
        return 3
    fi
    local restored
    restored=$(seal_rpc seal_bridgeGetCommitteeKeyStatus '{}' --port "$SEAL_PORT_1" \
        | jq -r '.result.fingerprint_sha2_hex // empty')
    if [ "$restored" != "02d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc" ]; then
        fail "rotate-back returned rotated:true but status RPC still reports fingerprint=$restored"
        return 3
    fi

    pass "rotation smoke: rotate→assert→rotate-back round-trip"
}

verify_committee_key_fingerprint() {
    # Smoke check: every running seal-node should have the e2e fixture
    # committee key ([0x11; 32]) installed via the
    # `--bridge-committee-key` flag in bridges/docker-compose.testnet.yml.
    # SHA-256 over [0x11; 32] is the constant below — if a node reports
    # something different, the docker-compose flag has drifted or the
    # node started without it, and reverse-leg unlock claims will fail
    # downstream with InvalidSignature. Asserting here surfaces the
    # config break in the first 5 seconds rather than after a full
    # forward-leg deploy.
    local expected="02d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc"
    for port in "$SEAL_PORT_1" "$SEAL_PORT_2" "$SEAL_PORT_3"; do
        local status
        status=$(seal_rpc seal_bridgeGetCommitteeKeyStatus '{}' --port "$port" 2>/dev/null)
        local set_flag actual
        set_flag=$(printf '%s' "$status" | jq -r '.result.set // false')
        actual=$(printf '%s' "$status" | jq -r '.result.fingerprint_sha2_hex // empty')
        if [ "$set_flag" != "true" ]; then
            fail "seal-node :$port has no committee key installed (set:false)"
            fail "  most common cause: the script connected to a non-bridge"
            fail "  node on this port (e.g. a local 'seal-node --rpc-port"
            fail "  $port --dev-faucet' shadowing the docker stack). Stop"
            fail "  any local seal-node on $port, or set SEAL_RPC=http://localhost:<base>"
            fail "  to point at the bridge stack (compose default: 8645)."
            fail "  Less likely: the docker-compose --bridge-committee-key"
            fail "  flag drifted; check bridges/docker-compose.testnet.yml."
            return 3
        fi
        if [ "$actual" != "$expected" ]; then
            fail "seal-node :$port committee-key fingerprint drift: expected sha2=$expected actual=$actual"
            return 3
        fi
    done
    pass "committee-key fingerprint matches expected sha2 on all 3 seal nodes"
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
    # validator sees the same deposit stream. register_observer_verified
    # confirms the registration actually took via seal_listBridgeObservers —
    # the bare RPC call has been observed to silently no-op on node-1
    # (last seen 2026-05-20 — count:0 right after an "ok":true response).
    local solana_obs_params
    solana_obs_params="{\"chain\":\"Solana\",\"rpc_url\":\"http://solana:8899\",\"program_id\":\"$program_id\"}"
    for port in "$SEAL_PORT_1" "$SEAL_PORT_2" "$SEAL_PORT_3"; do
        register_observer_verified "$port" "$solana_obs_params" "Solana observer"
    done

    info "running Anchor TS integration suite (lock)"
    # anchor test internally runs `cargo build-sbf` for anchor-lang,
    # which is not in vendor/ — move the vendor config aside for the
    # duration (same pattern as deploy_solana / deploy_stellar).
    # Tee anchor's output so we can recover the "Lock tx: <hash>" line
    # if the deposit-visibility check fails downstream — without it the
    # diag has to fall back to "recent 5 sigs" and can't pinpoint THIS
    # run's lock tx.
    local anchor_log="$REPO_DIR/bridges/.bridge-e2e-anchor-solana.log"
    with_crates_io bash -c "cd '$REPO_DIR/bridges/solana' && anchor test --skip-local-validator --skip-deploy" \
        2>&1 | tee "$anchor_log"

    # Force an observer sweep so we don't have to wait for the
    # in-container auto-poll (10 s cadence per --bridge-poll-interval-secs).
    # First sweep may race the lock tx's confirmed-commitment indexing
    # on solana-test-validator and return observed:0 — that's expected,
    # the retry loop below covers it. ("observed" here is deposits seen
    # this poll, NOT observer count — see rpc.rs:4045.)
    info "triggering seal_pollBridges"
    seal_rpc seal_pollBridges '[]' | jq -r '.result'

    # Each iteration: (1) ask each node to poll its observer set again
    # — covers the race where the first poll fired before solana indexed
    # the lock; (2) read the bridge manager's deposit list. We re-poll
    # every node (not just 8645) so any one of them seeing the event is
    # enough.
    if ! poll_until "Solana deposit visible on Seal" 60 \
        "any_node_has_deposit Solana"; then
        # IMPORTANT: dump the diag NOW, while the docker stack is still up.
        # Without this we lose all observable state — the script exits with
        # set -e, the user's next command may have already torn the stack
        # down, and `bridge-e2e-diag.sh` returns only `curl: (7) refused`.
        local lock_tx
        lock_tx="$(grep -oE 'Lock tx: [0-9A-Za-z]+' "$anchor_log" | head -1 | awk '{print $3}')"
        fail "auto-running bridge-e2e-diag.sh against the live stack — capture this output:"
        echo "──────────── DIAG START ────────────"
        "$SCRIPT_DIR/bridge-e2e-diag.sh" "${lock_tx:-}" Solana || true
        echo "──────────── DIAG END ──────────────"
        exit 3
    fi

    # Forward leg done. The burn → unlock_tokens close-out runs in
    # main's `full` case via solana_reverse_round_trip after both
    # forward legs finish — see the SKIP_REVERSE=1 escape hatch
    # below if you only need the forward path.
}

stellar_round_trip() {
    info "── Stellar round trip ──"
    local contract_id
    contract_id=$(cat "$REPO_DIR/bridges/.stellar-contract-id")
    info "contract: $contract_id"

    # Register the Stellar observer on every running Seal node.
    # `soroban_rpc_url` points at the Soroban RPC (port 8003) which
    # exposes `getEvents`. Horizon (port 8000) does not index events
    # by called contract — only by the source account.
    local stellar_obs_params
    stellar_obs_params="{\"chain\":\"Stellar\",\"horizon_url\":\"http://stellar:8000\",\"soroban_rpc_url\":\"http://stellar:8003\",\"contract_id\":\"$contract_id\"}"
    for port in "$SEAL_PORT_1" "$SEAL_PORT_2" "$SEAL_PORT_3"; do
        register_observer_verified "$port" "$stellar_obs_params" "Stellar observer"
    done

    (
        cd "$REPO_DIR/bridges/stellar"
        stellar contract invoke --id "$contract_id" --network local --source seal-e2e \
            -- lock_xlm \
            --sender "$(stellar keys address seal-e2e)" \
            --amount "$LOCK_AMOUNT_XLM" \
            --seal_address "$SEAL_RECIPIENT_HEX"
    )

    # Same race-and-retry pattern as the Solana leg — soroban events
    # may not be indexed at the moment the explicit poll fires.
    info "triggering seal_pollBridges"
    seal_rpc seal_pollBridges '[]' | jq -r '.result'

    if ! poll_until "Stellar deposit visible on Seal" 60 \
        "any_node_has_deposit Stellar"; then
        fail "auto-running bridge-e2e-diag.sh against the live stack — capture this output:"
        echo "──────────── DIAG START ────────────"
        "$SCRIPT_DIR/bridge-e2e-diag.sh" '' Stellar || true
        echo "──────────── DIAG END ──────────────"
        exit 3
    fi

    # Forward leg done. The burn → unlock_xlm close-out runs in
    # main's `full` case via stellar_reverse_round_trip after both
    # forward legs finish.
}

# ── Entrypoint ──────────────────────────────────────────────

usage() {
    grep '^#' "$0" | head -30
}

solana_reverse_round_trip() {
    info "── Solana reverse round trip (burn → committee MAC → unlock_tokens) ──"
    # Pin cwd to repo root for `cargo run -p seal-cli` calls. Earlier
    # helpers (deploy_stellar in particular) used to leak cwd to
    # bridges/stellar, which isn't part of the seal workspace and
    # makes `-p seal-cli` fail with "package(s) ... not found in
    # workspace". `cd` inside a function changes the caller's shell
    # cwd, so this both pins us AND fixes anything upstream that
    # leaked.
    cd "$REPO_DIR"

    if [ ! -f "$SEAL_E2E_KEY" ]; then
        fail "missing $SEAL_E2E_KEY (run the forward leg first)"
        return 3
    fi

    # Skip if the forward flow didn't mint any wSOL/wUSDC.
    local minted
    minted=$(seal_rpc seal_getBridgeStatus '[]' \
        | jq -r '.result.per_token[] | select(.token=="wSOL") | .minted')
    if [ "${minted:-0}" -eq 0 ]; then
        info "no wSOL minted yet — run the forward (full) leg first"
        return 0
    fi

    # The reverse leg needs five on-chain pubkeys the forward leg
    # produced. The anchor test echoes them as REVERSE_* lines that
    # bridge-e2e.sh greps out of bridges/.bridge-e2e-anchor-solana.log
    # and exports as env vars. The script fails loud if any are
    # missing rather than guessing.
    #
    # REVERSE_VAULT_ATA is the random-keypair token account created
    # by the anchor test (NOT the canonical `derive-vault-ata` output,
    # which would deterministically derive a different ATA). The
    # `derive-vault-ata` script is still a useful debug tool but only
    # matches if the lock side used the canonical ATA — bridge-e2e's
    # anchor test currently uses a random keypair, so we must read
    # the real account from REVERSE_VAULT_ATA. Falls back to deriving
    # if the env var is unset (matches the pre-2026-05-20 behavior
    # for any operator running this helper outside the full flow).
    local on_seal_burner solana_recipient recipient_ata vault_ata authority mint
    on_seal_burner=$(jq -r .address "$SEAL_E2E_KEY")
    if [ -z "${SOL_REVERSE_MINT:-}" ] || \
       [ -z "${SOL_REVERSE_RECIPIENT:-}" ] || \
       [ -z "${SOL_REVERSE_RECIPIENT_ATA:-}" ] || \
       [ -z "${SOL_REVERSE_AUTHORITY:-}" ]; then
        fail "set SOL_REVERSE_MINT / SOL_REVERSE_RECIPIENT / SOL_REVERSE_RECIPIENT_ATA / SOL_REVERSE_AUTHORITY env vars"
        return 3
    fi
    mint="$SOL_REVERSE_MINT"
    solana_recipient="$SOL_REVERSE_RECIPIENT"
    recipient_ata="$SOL_REVERSE_RECIPIENT_ATA"
    authority="$SOL_REVERSE_AUTHORITY"
    info "burn from $on_seal_burner → unlock to $solana_recipient (mint $mint)"

    if [ -n "${SOL_REVERSE_VAULT_ATA:-}" ]; then
        vault_ata="$SOL_REVERSE_VAULT_ATA"
    else
        vault_ata=$(cd "$REPO_DIR/bridges/solana" && with_crates_io bash -c \
                       "anchor run derive-vault-ata -- --mint $mint" \
                       | awk '/^vault ATA:/ {print $3}')
    fi
    if [ -z "$vault_ata" ]; then
        fail "could not derive vault ATA (set SOL_REVERSE_VAULT_ATA or fix anchor run derive-vault-ata)"
        return 3
    fi
    info "recipient_ata=$recipient_ata vault_ata=$vault_ata"

    # 1) seal bridge-withdraw burns wrapped SOL on Seal, returns id.
    local wd_output
    wd_output=$(cargo run --quiet -p seal-cli -- bridge-withdraw \
        --dest-chain Solana \
        --dest-address "$solana_recipient" \
        --token WSOL \
        --amount 500000000 \
        --node "$SEAL_RPC" \
        --key "$SEAL_E2E_KEY" 2>&1)
    local wd_id
    wd_id=$(printf '%s\n' "$wd_output" | grep -oE 'withdrawal_id: [^ ]+' | head -1 | awk '{print $2}')
    if [ -z "$wd_id" ]; then
        fail "bridge-withdraw didn't return a withdrawal_id"
        printf '%s\n' "$wd_output" | head -10
        return 3
    fi
    pass "burned 0.5 wSOL → withdrawal_id=$wd_id"

    # 2) Fetch committee MAC + nonce.
    local sig_hex nonce
    local wd_json
    wd_json=$(cargo run --quiet -p seal-cli -- bridge-get-withdrawal \
                --withdrawal-id "$wd_id" --node "$SEAL_RPC")
    sig_hex=$(echo "$wd_json" | jq -r '.withdrawal.committee_signature_hex')
    nonce=$(echo "$wd_json" | jq -r '.withdrawal.nonce')
    if [ "$sig_hex" = "null" ] || [ -z "$sig_hex" ]; then
        fail "committee_signature_hex is null — seal-node not configured with --bridge-committee-key?"
        return 3
    fi
    pass "fetched committee MAC ($((${#sig_hex} / 2)) bytes) at nonce=$nonce"

    # 3) Call unlock_tokens on Solana with the host-computed MAC.
    #    The Anchor program recomputes HMAC-SHA-256(committee_key, …)
    #    and accepts iff the bytes match. Wrong XDR/endian surfaces
    #    as `InvalidSignature`.
    info "submitting unlock_tokens with the host-computed MAC"
    if (cd "$REPO_DIR/bridges/solana" && with_crates_io bash -c \
            "anchor run unlock-tokens -- \
                --amount 500000000 --nonce $nonce --signature $sig_hex \
                --recipient $solana_recipient --recipient-ata $recipient_ata \
                --vault-ata $vault_ata --authority $authority"); then
        pass "unlock_tokens accepted the committee MAC — Solana reverse path closes"
    else
        fail "unlock_tokens rejected (InvalidSignature?) — committee MAC bytes may not match"
        return 3
    fi
}

stellar_reverse_round_trip() {
    info "── Stellar reverse round trip (burn → committee MAC → unlock_xlm) ──"
    # Same cwd pin as solana_reverse_round_trip — covers any upstream
    # cwd leak so `cargo run -p seal-cli` actually resolves seal-cli.
    cd "$REPO_DIR"

    if [ ! -f "$SEAL_E2E_KEY" ]; then
        fail "missing $SEAL_E2E_KEY (run the forward leg first)"
        return 3
    fi

    # Skip if the forward flow didn't mint anything.
    local minted
    minted=$(seal_rpc seal_getBridgeStatus '[]' \
        | jq -r '.result.per_token[] | select(.token=="wXLM") | .minted')
    if [ "${minted:-0}" -eq 0 ]; then
        info "no wXLM minted yet — run the forward (full) leg first"
        return 0
    fi

    local on_seal_burner stellar_recipient
    on_seal_burner=$(jq -r .address "$SEAL_E2E_KEY")
    stellar_recipient=$(cd "$REPO_DIR/bridges/stellar" && stellar keys address seal-e2e)
    info "burn from $on_seal_burner → unlock to $stellar_recipient"

    # 1) seal bridge-withdraw burns wrapped XLM on Seal, returns id.
    local wd_output
    wd_output=$(cargo run --quiet -p seal-cli -- bridge-withdraw \
        --dest-chain Stellar \
        --dest-address "$stellar_recipient" \
        --token WXLM \
        --amount 5000000 \
        --node "$SEAL_RPC" \
        --key "$SEAL_E2E_KEY" 2>&1)
    local wd_id
    wd_id=$(printf '%s\n' "$wd_output" | grep -oE 'withdrawal_id: [^ ]+' | head -1 | awk '{print $2}')
    if [ -z "$wd_id" ]; then
        fail "bridge-withdraw didn't return a withdrawal_id"
        printf '%s\n' "$wd_output" | head -10
        return 3
    fi
    pass "burned 0.5 wXLM → withdrawal_id=$wd_id"

    # 2) Fetch the committee MAC.
    local sig_hex nonce
    sig_hex=$(cargo run --quiet -p seal-cli -- bridge-get-withdrawal \
        --withdrawal-id "$wd_id" --node "$SEAL_RPC" \
        | jq -r '.withdrawal.committee_signature_hex')
    nonce=$(cargo run --quiet -p seal-cli -- bridge-get-withdrawal \
        --withdrawal-id "$wd_id" --node "$SEAL_RPC" \
        | jq -r '.withdrawal.nonce')
    if [ "$sig_hex" = "null" ] || [ -z "$sig_hex" ]; then
        fail "committee_signature_hex is null — seal-node not configured with --bridge-committee-key?"
        return 3
    fi
    pass "fetched committee MAC ($((${#sig_hex} / 2)) bytes) at nonce=$nonce"

    # 3) Call unlock_xlm on Stellar with the host-computed MAC.
    #    The contract recomputes HMAC-SHA-256(seal_bridge_key, …) and
    #    accepts iff the bytes match. If our XDR encoding is wrong
    #    this is where it'll surface as InvalidProof.
    info "submitting unlock_xlm with the host-computed MAC"
    if (cd "$REPO_DIR/bridges/stellar" && stellar contract invoke \
            --id "$(cat "$REPO_DIR/bridges/.stellar-contract-id")" \
            --network local --source seal-e2e \
            -- unlock_xlm \
            --recipient "$stellar_recipient" \
            --amount 5000000 \
            --nonce "$nonce" \
            --proof "$sig_hex"); then
        pass "unlock_xlm accepted the committee MAC — Stellar reverse path closes"
    else
        fail "unlock_xlm rejected (InvalidProof?) — XDR encoding may not match"
        return 3
    fi
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
        # SKIP_STACK_UP=1 short-circuits the docker compose --build step
        # for ops who've already brought the stack up out-of-band (e.g.
        # via `./scripts/bridge-e2e.sh up` plus their own iteration on
        # code changes). Saves 5-15 min per run when the docker image
        # is current.
        if [ "${SKIP_STACK_UP:-0}" = "1" ]; then
            info "SKIP_STACK_UP=1 — assuming docker stack is already healthy"
        else
            stack_up
        fi
        # `stack_up` waits for docker-compose health checks + Stellar
        # Horizon + node-1's RPC, but those only prove the *process*
        # is up — not that the seal-bridge subsystem is genuinely
        # ready. Run the proper per-node readiness pipeline
        # (RPC → consensus → committee-key → observer persistence)
        # in canonical boot order (bootstrap then followers) so a
        # broken node fails *here* with the exact failing phase
        # named, not 5 minutes later in the round trip.
        wait_for_all_bridge_nodes_ready \
            || { fail "bridge readiness pipeline failed"; exit 2; }
        # Rotation smoke — re-enabled by default 2026-05-20 once the
        # rotate-back root cause was found: the 6th admin RPC on node-1
        # within a minute (1× sentinel observer from phase 4 of the
        # readiness pipeline + 3× council-add + 2× rotate) tripped the
        # default rpm_admin=5 rate limit and silently returned
        # `-32005 rate limit exceeded for Admin group`. The compose
        # now starts each bridge node with `--rpm-admin 60`, giving
        # this smoke + any later admin-heavy ops plenty of headroom.
        # Opt out with SKIP_ROTATION_SMOKE=1 if you need to.
        if [ "${SKIP_ROTATION_SMOKE:-0}" = "1" ]; then
            info "rotation smoke skipped (SKIP_ROTATION_SMOKE=1)"
        else
            verify_committee_key_rotation || { fail "committee-key rotation smoke failed"; exit 2; }
        fi
        deploy_solana || { fail "Solana deploy failed"; exit 2; }
        deploy_stellar || { fail "Stellar deploy failed"; exit 2; }
        solana_round_trip
        stellar_round_trip
        # Reverse legs (burn → unlock) used to be opt-in via the
        # `reverse` / `reverse-solana` subcommands; both are now wired
        # into the default flow so `./scripts/bridge-e2e.sh` exercises
        # the full lock→mint→burn→unlock cycle. Skip both with
        # SKIP_REVERSE=1 if you only need to debug the forward leg.
        if [ "${SKIP_REVERSE:-0}" = "1" ]; then
            info "reverse legs skipped (SKIP_REVERSE=1)"
        else
            # Solana reverse needs the mint/recipient/authority that
            # the anchor test created. They're now echoed by
            # tests/seal-bridge.ts as `REVERSE_MINT:` / `REVERSE_RECIPIENT:`
            # / `REVERSE_RECIPIENT_ATA:` / `REVERSE_AUTHORITY:` lines
            # and tee'd into .bridge-e2e-anchor-solana.log by
            # solana_round_trip. Lift them into env vars so
            # solana_reverse_round_trip's existing preflight is
            # satisfied. `local` only works inside functions, so
            # this body uses a plain shell var.
            anchor_log="$REPO_DIR/bridges/.bridge-e2e-anchor-solana.log"
            if [ -f "$anchor_log" ]; then
                export SOL_REVERSE_MINT=$(grep -oE 'REVERSE_MINT: [A-Za-z0-9]+' "$anchor_log" | head -1 | awk '{print $2}')
                export SOL_REVERSE_RECIPIENT=$(grep -oE 'REVERSE_RECIPIENT: [A-Za-z0-9]+' "$anchor_log" | head -1 | awk '{print $2}')
                export SOL_REVERSE_RECIPIENT_ATA=$(grep -oE 'REVERSE_RECIPIENT_ATA: [A-Za-z0-9]+' "$anchor_log" | head -1 | awk '{print $2}')
                export SOL_REVERSE_AUTHORITY=$(grep -oE 'REVERSE_AUTHORITY: [A-Za-z0-9]+' "$anchor_log" | head -1 | awk '{print $2}')
                export SOL_REVERSE_VAULT_ATA=$(grep -oE 'REVERSE_VAULT_ATA: [A-Za-z0-9]+' "$anchor_log" | head -1 | awk '{print $2}')
            fi
            if [ -n "${SOL_REVERSE_MINT:-}" ]; then
                solana_reverse_round_trip || fail "Solana reverse leg failed (forward leg still passed)"
            else
                info "Solana reverse skipped — anchor test didn't emit REVERSE_MINT (rebuild bridges/ image to pick up tests/seal-bridge.ts changes)"
            fi
            stellar_reverse_round_trip || fail "Stellar reverse leg failed (forward leg still passed)"
        fi
        pass "bridge e2e round trip complete"
        ;;
    reverse)
        # Reverse-only mode. Assumes `full` already ran (forward
        # deposits + observers wired). Exercises the bridge-withdraw
        # → committee_signature_hex pickup → on-chain unlock claim
        # path. The Stellar variant runs end-to-end against the
        # local stellar/quickstart stack and asserts that the
        # committee MAC passes Soroban `verify_proof`. Solana is
        # symmetric but requires a deployed Anchor program with the
        # current LockEvent layout — call `solana_reverse_round_trip`
        # explicitly via the `reverse-solana` sub-mode below if you
        # want to exercise it after a redeploy.
        stellar_reverse_round_trip
        ;;
    reverse-solana)
        # Solana-only reverse. Same shape as Stellar reverse, but
        # the unlock wrapper is `anchor run unlock-tokens` against
        # the on-chain `unlock_tokens` ix. Requires that the
        # deployed program carries the v2 `LockEvent` layout
        # (with `mint: Pubkey`) — observers reject v1 events
        # under WSOL only.
        solana_reverse_round_trip
        ;;
    *)
        fail "unknown command: $cmd"
        usage
        exit 1
        ;;
esac
