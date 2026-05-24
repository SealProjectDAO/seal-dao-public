#!/usr/bin/env bash
# scripts/bridge-testnet-demo.sh — public-testnet bridge happy-path
# round-trip. The local-stack equivalent is `scripts/bridge-e2e.sh`;
# this is the version that targets Solana **devnet** + Stellar
# **testnet** (real RPCs, real airdrops). Walks lock → wrapped-mint;
# the optional `reverse` subcommand drives burn → committee-sign →
# unlock against the same chains (now that the committee MAC is
# exposed via seal_getBridgeWithdrawal — see docs/BRIDGE-TESTNET.md §2.2).
#
# Modes (forward — lock → mint):
#   BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh sol
#   BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh xlm
#   BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh both
#   BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh usdc-sol
#   BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh usdc-xlm
#   BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh usdc-both
#
# Modes (reverse — burn → unlock):
#   BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh reverse-sol
#   BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh reverse-xlm
#   BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh reverse-usdc-sol
#   BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh reverse-usdc-xlm
#
# Without `BRIDGE_TESTNET_DEMO_LIVE=1` the script no-ops with an
# explanation. This is the safety latch — running this script
# spends real testnet balance, so we don't want it firing from a
# stray `cargo run` shortcut or a CI loop.
#
# Dry-run:
#   BRIDGE_TESTNET_DEMO_DRY_RUN=1 BRIDGE_TESTNET_DEMO_LIVE=1 \
#       ./scripts/bridge-testnet-demo.sh <mode>
# In dry-run mode the script runs all preflight checks + env
# resolution + ID lookups, prints the exact commands it would
# submit on each chain, and then exits without sending anything.
# Useful for validating env wiring / SPL ATA derivations before
# committing testnet funds.
#
# Required env (override defaults if needed):
#   SEAL_RPC          (default http://localhost:8645 — bridge stack)
#   SEAL_RECIPIENT    bech32m sealt1... — where the wrapped mint goes
#   SEAL_KEY          path to the recipient's ML-DSA keypair JSON
#                     (required for the reverse subcommands)
#   SOLANA_DEPLOYER   path to ~/.config/solana/<keypair>.json
#                     (default: ~/.config/solana/id.json)
#   STELLAR_DEPLOYER  stellar keys identity (default: seal-bridge-deployer)
#
# Reverse-sol additional env (only needed for `reverse-sol`):
#   SOL_REVERSE_RECIPIENT      base58 ed25519 pubkey to unlock to
#   SOL_REVERSE_RECIPIENT_ATA  recipient's SPL token account for SOL_MINT
#   SOL_REVERSE_AUTHORITY      bridge_state.authority pubkey
#   SOL_REVERSE_TOKEN          one of WSOL / WUSDC (default WSOL)
#   SOL_REVERSE_AMOUNT         base units to unlock (default 50000000)
#
# Reverse-xlm additional env (only needed for `reverse-xlm`):
#   XLM_REVERSE_RECIPIENT      G-address to unlock to
#   XLM_REVERSE_TOKEN          one of WXLM / WUSDC (default WXLM)
#   XLM_REVERSE_AMOUNT         stroops to unlock (default 5000000)
#
# USDC additional env:
#   SOL_USDC_MINT     SPL mint to use for `usdc-sol` (default
#                     4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU
#                     — canonical Circle devnet USDC mint).
#                     Override to the local SPL_USDC_MINT printed by
#                     scripts/spl-usdc-bootstrap.sh when running
#                     against a local solana-test-validator.
#   SOL_USDC_SENDER_ATA   operator's USDC ATA on Solana devnet (the
#                     source of the locked USDC).
#   SOL_USDC_VAULT_ATA    bridge-vault's USDC ATA (derived via
#                     `anchor run derive-vault-ata --mint $SOL_USDC_MINT --init`).
#   XLM_USDC_AMOUNT   USDC base units (7 decimals) to lock via
#                     `usdc-xlm` (default 10000000 == 1 USDC).
#
#   Prereq for usdc-xlm: the operator must have run
#   `stellar contract invoke … set_usdc_sac` after the bridge
#   contract was initialized (see docs/BRIDGE-TESTNET.md §4 +
#   bridges/stellar/src/lib.rs:447 `lock_usdc`).
#
# Files this script reads (created by the manual deploy in
# docs/BRIDGE-TESTNET.md §1):
#   bridges/.solana-devnet-program-id
#   bridges/.stellar-testnet-contract-id
#
# Exit codes:
#   0  success
#   1  preflight / missing env / safety-latch off
#   2  on-chain operation failed
#   3  observer never picked up the deposit within 60s
#   4  committee signature never attached within 60s

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

color() { printf '\033[%sm%s\033[0m\n' "$1" "${*:2}"; }
info() { color "36" "==> $*"; }
pass() { color "32" "[ok] $*"; }
fail() { color "31" "[!!] $*" >&2; }

# ── Safety latch ────────────────────────────────────────────

if [ "${BRIDGE_TESTNET_DEMO_LIVE:-0}" != "1" ]; then
    fail "this script spends real testnet funds; gated behind"
    fail "  BRIDGE_TESTNET_DEMO_LIVE=1 ./scripts/bridge-testnet-demo.sh"
    fail "    <sol|xlm|both|usdc-sol|usdc-xlm|usdc-both|reverse-…>"
    fail "for dry-run (resolves env + prints commands without sending):"
    fail "  BRIDGE_TESTNET_DEMO_DRY_RUN=1 BRIDGE_TESTNET_DEMO_LIVE=1 \\"
    fail "    ./scripts/bridge-testnet-demo.sh <mode>"
    fail "see docs/BRIDGE-TESTNET.md for the full bring-up runbook."
    exit 1
fi

DRY_RUN="${BRIDGE_TESTNET_DEMO_DRY_RUN:-0}"

# run_or_print — execute a command, or just echo it (dry-run mode).
# Used by every on-chain submission helper below so the dry-run
# flag actually inhibits spending.
run_or_print() {
    if [ "$DRY_RUN" = "1" ]; then
        color "33" "[dry-run] $*"
        return 0
    fi
    "$@"
}

# ── Defaults ────────────────────────────────────────────────

SEAL_RPC="${SEAL_RPC:-http://localhost:8645}"
SOLANA_DEPLOYER="${SOLANA_DEPLOYER:-$HOME/.config/solana/id.json}"
STELLAR_DEPLOYER="${STELLAR_DEPLOYER:-seal-bridge-deployer}"

# Public RPC URLs. SOLANA_DEVNET_RPC is consulted for the deployer
# balance probe; the stellar RPCs live in the `stellar network add
# testnet` config the operator set up per docs/BRIDGE-TESTNET.md §1.2,
# and the `--network testnet` flag below resolves them via that
# alias. Override SOLANA_DEVNET_RPC only if you've decided to point
# at a different solana endpoint (e.g. CI with a private dedicated
# RPC); the stellar network alias is configured separately.
SOLANA_DEVNET_RPC="${SOLANA_DEVNET_RPC:-https://api.devnet.solana.com}"

LOCK_LAMPORTS=100000000     # 0.1 SOL
LOCK_STROOPS=10000000       # 1 XLM
LOCK_USDC_SOL=1000000       # 1 USDC on Solana (6 decimals)
LOCK_USDC_XLM=10000000      # 1 USDC on Stellar (7 decimals)

# Canonical Circle devnet USDC mint. Override via SOL_USDC_MINT
# (e.g. to point at scripts/spl-usdc-bootstrap.sh's local mint).
DEFAULT_SOL_USDC_MINT="4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"

# ── Preflight ───────────────────────────────────────────────

require_env() {
    local var="$1"
    if [ -z "${!var:-}" ]; then
        fail "missing required env: $var"
        exit 1
    fi
}

preflight() {
    local missing=0
    for tool in solana anchor stellar jq curl; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            fail "missing: $tool"
            missing=$((missing + 1))
        fi
    done
    require_env SEAL_RECIPIENT
    if [ "$missing" -gt 0 ]; then
        fail "preflight failed: $missing missing tool(s)"
        exit 1
    fi

    if ! curl -s -m 5 -o /dev/null -w "%{http_code}" "$SEAL_RPC" \
            | grep -q '^[245]'; then
        fail "Seal RPC unreachable at $SEAL_RPC"
        exit 1
    fi
}

# ── Helpers ─────────────────────────────────────────────────

seal_rpc_call() {
    local method="$1"
    local params="${2:-{\}}"
    curl -s -X POST "$SEAL_RPC" -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}"
}

# Address → 32-byte hex form expected by the bridge programs.
# `seal addr-to-hex` landed alongside this script (commit d0a2a76b2).
seal_recipient_hex() {
    local seal_bin
    seal_bin="${SEAL_CLI:-$REPO_DIR/target/debug/seal}"
    if [ ! -x "$seal_bin" ]; then
        fail "seal-cli not built at $seal_bin"
        fail "  cargo build -p seal-cli"
        fail "  or set SEAL_CLI to a release binary"
        exit 2
    fi
    "$seal_bin" addr-to-hex "$SEAL_RECIPIENT" || {
        fail "addr-to-hex failed for '$SEAL_RECIPIENT'"
        exit 2
    }
}

poll_seal_for_deposit() {
    local chain="$1"
    info "polling Seal for $chain deposit (max 60s)…"
    for _ in $(seq 1 30); do
        # Force a sweep so we don't have to wait for the poll loop.
        seal_rpc_call seal_pollBridges '[]' >/dev/null 2>&1 || true
        local count
        count=$(seal_rpc_call seal_getBridgeDeposits "[\"$chain\"]" \
                | jq -r '.result | length')
        if [ "$count" -gt 0 ]; then
            pass "$chain deposit visible on Seal (count: $count)"
            return 0
        fi
        sleep 2
    done
    fail "$chain deposit never landed on Seal in 60s"
    return 3
}

# ── Solana lock → mint ──────────────────────────────────────

solana_lock() {
    local program_id_file="$REPO_DIR/bridges/.solana-devnet-program-id"
    if [ ! -f "$program_id_file" ]; then
        fail "missing $program_id_file (run docs/BRIDGE-TESTNET.md §1.1)"
        return 2
    fi
    local program_id
    program_id=$(cat "$program_id_file")
    info "Solana program ID: $program_id"

    local hex
    hex=$(seal_recipient_hex)

    # Check the deployer balance — refuse to spend if too low.
    local lamports
    lamports=$(solana balance "$(solana address -k "$SOLANA_DEPLOYER")" \
        --url "$SOLANA_DEVNET_RPC" --output json | jq -r '.lamports')
    if [ "$lamports" -lt 200000000 ]; then
        fail "deployer needs ≥ 0.2 SOL on devnet; current: $lamports lamports"
        fail "  airdrop: solana airdrop 2 \$(solana address -k $SOLANA_DEPLOYER) --url $SOLANA_DEVNET_RPC"
        return 2
    fi

    # Devnet operators need a deployed SPL mint + paired sender / vault
    # ATAs before this call — the SPL setup is a separate one-off
    # (`spl-token create-token`, `spl-token create-account`). Honor
    # SOL_MINT / SOL_SENDER_ATA / SOL_VAULT_ATA from the operator's env
    # so they can pin pre-deployed accounts; otherwise refuse with a
    # clear pointer rather than guessing.
    for var in SOL_MINT SOL_SENDER_ATA SOL_VAULT_ATA; do
        if [ -z "${!var:-}" ]; then
            fail "missing required env: $var"
            fail "  Devnet SOL lock needs a pre-deployed SPL mint + ATAs."
            fail "  See docs/BRIDGE-TESTNET.md §2.1 for the spl-token setup."
            return 2
        fi
    done

    info "submitting lock_tokens for $LOCK_LAMPORTS base units"
    cd "$REPO_DIR/bridges/solana"
    run_or_print anchor run lock-sol -- \
        --amount "$LOCK_LAMPORTS" \
        --seal-recipient "$hex" \
        --mint "$SOL_MINT" \
        --sender-ata "$SOL_SENDER_ATA" \
        --vault-ata "$SOL_VAULT_ATA" \
        --program-id "$program_id" \
        --provider.cluster devnet \
        --provider.wallet "$SOLANA_DEPLOYER" \
        || { fail "anchor run lock-sol failed"; return 2; }

    if [ "$DRY_RUN" = "1" ]; then
        pass "dry-run: would have polled Seal for Solana deposit"
        return 0
    fi
    poll_seal_for_deposit "Solana"
}

# ── Stellar lock → mint ─────────────────────────────────────

stellar_lock() {
    local contract_id_file="$REPO_DIR/bridges/.stellar-testnet-contract-id"
    if [ ! -f "$contract_id_file" ]; then
        fail "missing $contract_id_file (run docs/BRIDGE-TESTNET.md §1.2)"
        return 2
    fi
    local contract_id
    contract_id=$(cat "$contract_id_file")
    info "Stellar contract ID: $contract_id"

    local hex
    hex=$(seal_recipient_hex)
    local sender
    sender=$(stellar keys address "$STELLAR_DEPLOYER")

    info "submitting lock_xlm for $LOCK_STROOPS stroops"
    cd "$REPO_DIR/bridges/stellar"
    run_or_print stellar contract invoke --id "$contract_id" \
        --source "$STELLAR_DEPLOYER" --network testnet \
        -- lock_xlm \
        --sender "$sender" \
        --amount "$LOCK_STROOPS" \
        --seal_address "$hex" \
        || { fail "stellar lock_xlm failed"; return 2; }

    if [ "$DRY_RUN" = "1" ]; then
        pass "dry-run: would have polled Seal for Stellar deposit"
        return 0
    fi
    poll_seal_for_deposit "Stellar"
}

# ── USDC lock variants ──────────────────────────────────────
#
# Solana: `lock_tokens` on the bridge is mint-generic — the same
# instruction handles WSOL and WUSDC by switching the (mint,
# sender_ata, vault_ata) trio. usdc-sol defaults SOL_MINT to the
# canonical Circle devnet USDC mint; operator can override via
# SOL_USDC_MINT (e.g. point at the local SPL mint produced by
# scripts/spl-usdc-bootstrap.sh).
#
# Stellar: `lock_usdc` is a dedicated entrypoint on the Soroban
# contract (bridges/stellar/src/lib.rs:447). The USDC SAC must
# have been installed via `set_usdc_sac` before this works.

solana_lock_usdc() {
    info "USDC mode → routing through solana_lock with USDC env"
    # Resolve the mint + ATAs from the USDC-specific env vars, fall
    # back to the canonical Circle devnet mint, and shim them into
    # the generic SOL_MINT/SOL_SENDER_ATA/SOL_VAULT_ATA vars that
    # solana_lock consumes.
    : "${SOL_USDC_MINT:=$DEFAULT_SOL_USDC_MINT}"
    if [ -z "${SOL_USDC_SENDER_ATA:-}" ] || [ -z "${SOL_USDC_VAULT_ATA:-}" ]; then
        fail "usdc-sol requires SOL_USDC_SENDER_ATA + SOL_USDC_VAULT_ATA"
        fail "  derive the vault ATA with:"
        fail "    cd bridges/solana && anchor run derive-vault-ata -- \\"
        fail "      --mint $SOL_USDC_MINT --init"
        fail "  derive the sender ATA with:"
        fail "    spl-token address --token $SOL_USDC_MINT --verbose \\"
        fail "      --owner \$(solana address -k $SOLANA_DEPLOYER) --url $SOLANA_DEVNET_RPC"
        return 1
    fi
    SOL_MINT="$SOL_USDC_MINT" \
    SOL_SENDER_ATA="$SOL_USDC_SENDER_ATA" \
    SOL_VAULT_ATA="$SOL_USDC_VAULT_ATA" \
    LOCK_LAMPORTS="$LOCK_USDC_SOL" \
        solana_lock
}

stellar_lock_usdc() {
    local contract_id_file="$REPO_DIR/bridges/.stellar-testnet-contract-id"
    if [ ! -f "$contract_id_file" ]; then
        fail "missing $contract_id_file (run docs/BRIDGE-TESTNET.md §1.2)"
        return 2
    fi
    local contract_id
    contract_id=$(cat "$contract_id_file")
    info "Stellar contract ID: $contract_id"

    local hex
    hex=$(seal_recipient_hex)
    local sender
    sender=$(stellar keys address "$STELLAR_DEPLOYER")
    local amount="${XLM_USDC_AMOUNT:-$LOCK_USDC_XLM}"

    info "submitting lock_usdc for $amount USDC base units"
    cd "$REPO_DIR/bridges/stellar"
    run_or_print stellar contract invoke --id "$contract_id" \
        --source "$STELLAR_DEPLOYER" --network testnet \
        -- lock_usdc \
        --sender "$sender" \
        --amount "$amount" \
        --seal_address "$hex" \
        || {
            fail "stellar lock_usdc failed"
            fail "  did the operator run 'set_usdc_sac' after initialize?"
            fail "  check trustline: scripts/bridge-faucet.sh usdc-xlm <G-addr>"
            return 2
        }

    if [ "$DRY_RUN" = "1" ]; then
        pass "dry-run: would have polled Seal for Stellar USDC deposit"
        return 0
    fi
    poll_seal_for_deposit "Stellar"
}

# ── Reverse helpers (burn → committee-sign → unlock) ────────
#
# Both reverse paths share the same Seal-side plumbing:
#   1. `seal bridge-withdraw` burns the wrapped balance and creates
#      a withdrawal record. The host attaches an HMAC-SHA-256 over
#      (recipient || amount_le(8) || nonce_le(8) || domain_tag) using
#      --bridge-committee-key.
#   2. Poll `seal bridge-get-withdrawal` until committee_signature_hex
#      is non-null (today: instant, because the testnet runs as
#      committee-of-1 with host-side HMAC; under Ringtail aggregate
#      signing the poll covers signing latency).
#   3. Submit the unlock claim on the source chain.

seal_cli_bin() {
    local seal_bin="${SEAL_CLI:-$REPO_DIR/target/debug/seal}"
    if [ ! -x "$seal_bin" ]; then
        fail "seal-cli not built at $seal_bin"
        fail "  cargo build -p seal-cli"
        return 2
    fi
    echo "$seal_bin"
}

burn_and_wait_for_sig() {
    # args: dest_chain dest_address token amount
    # Returns the triple on stdout as `withdrawal_id|nonce|signature_hex`.
    # All progress chatter (info/pass/fail) goes to stderr so the
    # caller can `triple=$(burn_and_wait_for_sig …)` without parsing
    # decorations.
    local dest_chain="$1"
    local dest_address="$2"
    local token="$3"
    local amount="$4"
    require_env SEAL_KEY
    if [ ! -f "$SEAL_KEY" ]; then
        fail "SEAL_KEY does not point at a readable file: $SEAL_KEY"
        return 1
    fi
    local seal_bin
    seal_bin=$(seal_cli_bin) || return $?

    info "burn $amount $token → $dest_chain:$dest_address" >&2
    if [ "$DRY_RUN" = "1" ]; then
        color "33" "[dry-run] $seal_bin bridge-withdraw --node $SEAL_RPC --key $SEAL_KEY \
--dest-chain $dest_chain --dest-address $dest_address --token $token --amount $amount" >&2
        # Emit a placeholder triple so the caller doesn't choke; the
        # downstream unlock call is also gated on DRY_RUN and will
        # print the would-submit command without consuming these.
        echo "dry-run-wd-id|0|dryrun"
        return 0
    fi
    local burn_out
    if ! burn_out=$("$seal_bin" bridge-withdraw \
            --node "$SEAL_RPC" --key "$SEAL_KEY" \
            --dest-chain "$dest_chain" \
            --dest-address "$dest_address" \
            --token "$token" --amount "$amount" 2>&1); then
        fail "seal bridge-withdraw failed:"
        echo "$burn_out" >&2
        return 2
    fi
    local wd
    wd=$(echo "$burn_out" | awk '/withdrawal_id:/{print $2}' | head -1)
    if [ -z "$wd" ]; then
        fail "couldn't parse withdrawal_id from seal bridge-withdraw"
        echo "$burn_out" >&2
        return 2
    fi
    info "withdrawal_id: $wd — polling for committee signature (max 60s)" >&2

    # Poll for the committee signature. On a committee-of-1 testnet
    # the host attaches the HMAC synchronously, so this normally
    # returns on the first iteration; the loop covers Ringtail-aggregated
    # signing latency under multi-validator testnets.
    local sig=""
    local nonce=""
    for _ in $(seq 1 30); do
        local raw
        raw=$("$seal_bin" bridge-get-withdrawal \
                --node "$SEAL_RPC" --withdrawal-id "$wd" 2>/dev/null) || true
        # `bridge-get-withdrawal` prints the JSON envelope verbatim;
        # extract committee_signature_hex + nonce via jq.
        sig=$(echo "$raw" | jq -r '.withdrawal.committee_signature_hex // empty' 2>/dev/null || true)
        nonce=$(echo "$raw" | jq -r '.withdrawal.nonce // empty' 2>/dev/null || true)
        if [ -n "$sig" ] && [ "$sig" != "null" ]; then
            pass "committee signed (sig=${sig:0:16}…, nonce=$nonce)" >&2
            echo "$wd|$nonce|$sig"
            return 0
        fi
        sleep 2
    done
    fail "committee signature never landed for $wd within 60s"
    return 4
}

solana_unlock() {
    local program_id_file="$REPO_DIR/bridges/.solana-devnet-program-id"
    if [ ! -f "$program_id_file" ]; then
        fail "missing $program_id_file (run docs/BRIDGE-TESTNET.md §1.1)"
        return 2
    fi
    local program_id
    program_id=$(cat "$program_id_file")

    require_env SOL_REVERSE_RECIPIENT
    require_env SOL_REVERSE_RECIPIENT_ATA
    require_env SOL_REVERSE_AUTHORITY
    require_env SOL_VAULT_ATA
    local token="${SOL_REVERSE_TOKEN:-WSOL}"
    local amount="${SOL_REVERSE_AMOUNT:-50000000}"

    local triple
    if ! triple=$(burn_and_wait_for_sig \
            "Solana" "$SOL_REVERSE_RECIPIENT" "$token" "$amount"); then
        return $?
    fi
    local nonce sig
    nonce=$(echo "$triple" | awk -F'|' '{print $2}')
    sig=$(echo "$triple" | awk -F'|' '{print $3}')

    info "submitting unlock_tokens on Solana devnet"
    cd "$REPO_DIR/bridges/solana"
    run_or_print anchor run unlock-tokens -- \
        --amount "$amount" \
        --nonce "$nonce" \
        --signature "$sig" \
        --recipient "$SOL_REVERSE_RECIPIENT" \
        --recipient-ata "$SOL_REVERSE_RECIPIENT_ATA" \
        --vault-ata "$SOL_VAULT_ATA" \
        --authority "$SOL_REVERSE_AUTHORITY" \
        --provider.cluster devnet \
        --provider.wallet "$SOLANA_DEPLOYER" \
        || { fail "anchor run unlock-tokens failed"; return 2; }
    if [ "$DRY_RUN" = "1" ]; then
        pass "dry-run: Solana reverse leg would have closed"
    else
        pass "Solana reverse leg closed (burned $amount $token → unlocked to $SOL_REVERSE_RECIPIENT)"
    fi
}

stellar_unlock() {
    local contract_id_file="$REPO_DIR/bridges/.stellar-testnet-contract-id"
    if [ ! -f "$contract_id_file" ]; then
        fail "missing $contract_id_file (run docs/BRIDGE-TESTNET.md §1.2)"
        return 2
    fi
    local contract_id
    contract_id=$(cat "$contract_id_file")

    require_env XLM_REVERSE_RECIPIENT
    local token="${XLM_REVERSE_TOKEN:-WXLM}"
    local amount="${XLM_REVERSE_AMOUNT:-5000000}"

    local triple
    if ! triple=$(burn_and_wait_for_sig \
            "Stellar" "$XLM_REVERSE_RECIPIENT" "$token" "$amount"); then
        return $?
    fi
    local nonce sig
    nonce=$(echo "$triple" | awk -F'|' '{print $2}')
    sig=$(echo "$triple" | awk -F'|' '{print $3}')

    # Soroban exposes `unlock_xlm` for WXLM and `unlock_usdc` for WUSDC;
    # the wire shape is identical (recipient/amount/nonce/proof).
    local unlock_fn
    case "$token" in
        WXLM)  unlock_fn="unlock_xlm" ;;
        WUSDC) unlock_fn="unlock_usdc" ;;
        *)
            fail "unsupported XLM_REVERSE_TOKEN: $token (use WXLM or WUSDC)"
            return 1
            ;;
    esac

    info "submitting $unlock_fn on Stellar testnet"
    cd "$REPO_DIR/bridges/stellar"
    run_or_print stellar contract invoke --id "$contract_id" \
        --source "$STELLAR_DEPLOYER" --network testnet \
        -- "$unlock_fn" \
        --recipient "$XLM_REVERSE_RECIPIENT" \
        --amount "$amount" \
        --nonce "$nonce" \
        --proof "$sig" \
        || { fail "stellar $unlock_fn failed"; return 2; }
    if [ "$DRY_RUN" = "1" ]; then
        pass "dry-run: Stellar reverse leg would have closed"
    else
        pass "Stellar reverse leg closed (burned $amount $token → unlocked to $XLM_REVERSE_RECIPIENT)"
    fi
}

# ── Entrypoint ──────────────────────────────────────────────

cmd="${1:-}"
case "$cmd" in
    sol|solana)
        preflight
        solana_lock
        ;;
    xlm|stellar)
        preflight
        stellar_lock
        ;;
    both|all)
        preflight
        solana_lock || exit $?
        stellar_lock || exit $?
        pass "both round-trips closed"
        ;;
    usdc-sol|usdc-solana)
        preflight
        solana_lock_usdc
        ;;
    usdc-xlm|usdc-stellar)
        preflight
        stellar_lock_usdc
        ;;
    usdc-both|usdc-all)
        preflight
        solana_lock_usdc || exit $?
        stellar_lock_usdc || exit $?
        pass "both USDC forward legs closed"
        ;;
    reverse-sol|reverse-solana)
        preflight
        solana_unlock
        ;;
    reverse-xlm|reverse-stellar)
        preflight
        stellar_unlock
        ;;
    reverse-usdc-sol|reverse-usdc-solana)
        preflight
        SOL_REVERSE_TOKEN=WUSDC solana_unlock
        ;;
    reverse-usdc-xlm|reverse-usdc-stellar)
        preflight
        XLM_REVERSE_TOKEN=WUSDC stellar_unlock
        ;;
    *)
        fail "usage: $0 <mode>"
        fail "  forward: sol | xlm | both | usdc-sol | usdc-xlm | usdc-both"
        fail "  reverse: reverse-sol | reverse-xlm | reverse-usdc-sol | reverse-usdc-xlm"
        fail "  (BRIDGE_TESTNET_DEMO_LIVE=1 required; see docs/BRIDGE-TESTNET.md)"
        exit 1
        ;;
esac
