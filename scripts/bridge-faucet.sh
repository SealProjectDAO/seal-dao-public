#!/usr/bin/env bash
# scripts/bridge-faucet.sh — one-stop funder for the four faucet
# flows the bridge round-trip touches:
#
#   sol         Solana devnet airdrop (`solana airdrop`)
#   xlm         Stellar testnet friendbot (XLM)
#   usdc-xlm    Stellar testnet friendbot with the Stellar-Foundation
#               USDC trustline (`&asset=USDC:GBBD…`)
#   usdc-sol    Circle developer-console pointer for sandbox USDC
#               on Solana devnet (interactive: prints the URL, mint,
#               and ATA-creation snippet — no in-tree faucet exists)
#
# Usage:
#   ./scripts/bridge-faucet.sh sol      <pubkey>     [amount_sol]
#   ./scripts/bridge-faucet.sh xlm      <G-address>
#   ./scripts/bridge-faucet.sh usdc-xlm <G-address>
#   ./scripts/bridge-faucet.sh usdc-sol <pubkey>
#
# Env overrides:
#   SOLANA_DEVNET_RPC   default https://api.devnet.solana.com
#   STELLAR_FRIENDBOT   default https://friendbot.stellar.org
#                       point at http://127.0.0.1:8000 for the local
#                       stellar/quickstart container.
#
# Exit codes:
#   0  success (funded, or — for usdc-sol — pointer printed)
#   1  usage / unknown chain selector
#   2  upstream faucet failure (airdrop denied, friendbot 4xx, etc.)
#   3  missing CLI dependency (solana, curl, jq)

set -euo pipefail

color() { printf '\033[%sm%s\033[0m\n' "$1" "${*:2}"; }
info() { color "36" "==> $*"; }
pass() { color "32" "[ok] $*"; }
fail() { color "31" "[!!] $*" >&2; }

SOLANA_DEVNET_RPC="${SOLANA_DEVNET_RPC:-https://api.devnet.solana.com}"
STELLAR_FRIENDBOT="${STELLAR_FRIENDBOT:-https://friendbot.stellar.org}"

# Canonical testnet USDC issuer on Stellar (Stellar Foundation).
USDC_XLM_ISSUER="GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
# Canonical Solana devnet USDC mint (Circle sandbox).
USDC_SOL_MINT="4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "missing CLI: $1"
        exit 3
    fi
}

usage() {
    cat >&2 <<EOF
usage: $0 <chain> <address> [amount]

chains:
  sol       Solana devnet airdrop. address=base58 pubkey. amount=SOL (default 2)
  xlm       Stellar testnet friendbot. address=G-address
  usdc-xlm  Stellar friendbot + USDC trustline. address=G-address
  usdc-sol  Solana devnet sandbox USDC (interactive — prints Circle URL +
            ATA creation snippet). address=base58 pubkey

env:
  SOLANA_DEVNET_RPC  default $SOLANA_DEVNET_RPC
  STELLAR_FRIENDBOT  default $STELLAR_FRIENDBOT
EOF
}

faucet_sol() {
    local pubkey="${1:-}"
    local amount="${2:-2}"
    if [ -z "$pubkey" ]; then
        usage; exit 1
    fi
    require_cmd solana
    info "solana airdrop $amount $pubkey ($SOLANA_DEVNET_RPC)"
    if ! solana airdrop "$amount" "$pubkey" --url "$SOLANA_DEVNET_RPC"; then
        fail "airdrop failed — devnet faucet is rate-limited; retry in"
        fail "a few minutes, or split the request into smaller chunks"
        exit 2
    fi
    pass "airdropped $amount SOL to $pubkey"
}

faucet_xlm() {
    local addr="${1:-}"
    if [ -z "$addr" ]; then
        usage; exit 1
    fi
    require_cmd curl
    info "friendbot fund $addr (${STELLAR_FRIENDBOT})"
    local resp
    if ! resp=$(curl -fsS "${STELLAR_FRIENDBOT}/?addr=${addr}"); then
        fail "friendbot rejected the request — most likely the account"
        fail "already exists on this network (friendbot funds new"
        fail "accounts only). Use stellar payment if you need more XLM."
        exit 2
    fi
    pass "funded $addr with 10000 XLM"
    if command -v jq >/dev/null 2>&1; then
        echo "$resp" | jq -r '.hash // empty' | sed 's/^/  tx: /'
    fi
}

faucet_usdc_xlm() {
    local addr="${1:-}"
    if [ -z "$addr" ]; then
        usage; exit 1
    fi
    require_cmd curl
    # The `&asset=` form funds an existing account with a USDC trustline
    # + a small starting balance. If the account doesn't yet exist on
    # testnet, fund it with XLM first (friendbot won't create + asset-
    # fund in one shot).
    info "friendbot USDC fund $addr (asset=USDC:${USDC_XLM_ISSUER:0:8}…)"
    local url="${STELLAR_FRIENDBOT}/?addr=${addr}&asset=USDC:${USDC_XLM_ISSUER}"
    local resp
    if ! resp=$(curl -fsS "$url"); then
        fail "friendbot USDC fund failed — common causes:"
        fail "  * account does not yet exist on testnet"
        fail "    fix:  $0 xlm $addr"
        fail "  * already has the USDC trustline + balance (one-shot)"
        exit 2
    fi
    pass "funded $addr with USDC trustline + sandbox balance"
    if command -v jq >/dev/null 2>&1; then
        echo "$resp" | jq -r '.hash // empty' | sed 's/^/  tx: /'
    fi
}

faucet_usdc_sol() {
    local pubkey="${1:-}"
    if [ -z "$pubkey" ]; then
        usage; exit 1
    fi
    # Solana devnet sandbox USDC is gated behind Circle's developer
    # dashboard — there's no programmatic airdrop endpoint. Print the
    # pointer + the spl-token ATA-creation snippet operators will need
    # before sandbox USDC can be received.
    cat <<EOF
Sandbox USDC on Solana devnet is dispensed by Circle's developer
console (no programmatic endpoint exists).

Steps:
  1. Visit https://developers.circle.com → Sandbox → USDC faucet
     and request a transfer to: $pubkey
  2. Before Circle can deliver, your wallet needs the USDC associated
     token account (ATA) initialized:

       spl-token create-account \\
           $USDC_SOL_MINT \\
           --owner $pubkey \\
           --url $SOLANA_DEVNET_RPC

  3. Confirm receipt:

       spl-token accounts --owner $pubkey --url $SOLANA_DEVNET_RPC

For a self-serve local-stack USDC (no Circle dependency) see
scripts/spl-usdc-bootstrap.sh — that path creates a fresh test mint
on the local solana-test-validator rather than reusing the canonical
devnet USDC.

Canonical devnet USDC mint: $USDC_SOL_MINT
EOF
    pass "pointer printed (Circle developer console)"
}

main() {
    local chain="${1:-}"
    case "$chain" in
        sol|solana)
            shift; faucet_sol "$@" ;;
        xlm|stellar)
            shift; faucet_xlm "$@" ;;
        usdc-xlm|usdc-stellar)
            shift; faucet_usdc_xlm "$@" ;;
        usdc-sol|usdc-solana)
            shift; faucet_usdc_sol "$@" ;;
        ""|-h|--help|help)
            usage; exit 1 ;;
        *)
            fail "unknown chain selector: $chain"
            usage; exit 1 ;;
    esac
}

main "$@"
