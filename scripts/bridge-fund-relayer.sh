#!/usr/bin/env bash
# scripts/bridge-fund-relayer.sh — top up per-validator relayer
# destination-chain keys via scripts/bridge-faucet.sh, reading a
# JSON manifest of (validator_id, sol_pubkey, xlm_account) tuples.
#
# Closes the P1#3 operator follow-up: "Fund the relayer destination-
# chain keys per validator". Each validator runs its own
# seal-relayer with its own Solana ed25519 keypair + Stellar
# G-account, so the funding step is per-validator rather than one
# shared faucet drip.
#
# Manifest JSON shape (example: bridges/.relayer-keys.example.json):
#   [
#     {
#       "validator": "seal-1",
#       "sol_pubkey": "5kP7…",
#       "xlm_account": "GAB…"
#     },
#     { "validator": "seal-2", "sol_pubkey": "6tQ8…", "xlm_account": "GCD…" }
#   ]
#
# Usage:
#   ./scripts/bridge-fund-relayer.sh <manifest.json> [--chains sol,xlm]
#
# --chains comma-separated subset of {sol,xlm}. Default: both.
# Per-validator dust amount: 2 SOL on devnet (Solana faucet cap)
# and one friendbot drip (10000 XLM) on Stellar testnet.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
say() { echo -e "${BOLD}==>${NC} $*"; }
ok()  { echo -e "${GREEN}✓${NC} $*"; }
warn(){ echo -e "${YELLOW}!${NC} $*"; }
err() { echo -e "${RED}✗${NC} $*" >&2; }

MANIFEST=""
CHAINS="sol,xlm"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --chains) CHAINS="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^set/p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *)
            if [[ -z "$MANIFEST" ]]; then
                MANIFEST="$1"
                shift
            else
                err "unknown arg: $1"
                exit 1
            fi
            ;;
    esac
done
if [[ -z "$MANIFEST" ]]; then
    err "usage: $0 <manifest.json> [--chains sol,xlm]"
    exit 1
fi
if [[ ! -f "$MANIFEST" ]]; then
    err "manifest not found: $MANIFEST"
    exit 1
fi

# Sanity: jq is required to walk the manifest.
if ! command -v jq >/dev/null 2>&1; then
    err "jq is required; install with 'brew install jq' or your distro's package manager"
    exit 1
fi

DO_SOL=0; DO_XLM=0
IFS=',' read -ra CHAIN_ARR <<< "$CHAINS"
for c in "${CHAIN_ARR[@]}"; do
    case "$c" in
        sol) DO_SOL=1 ;;
        xlm) DO_XLM=1 ;;
        *) err "unknown chain in --chains: $c"; exit 1 ;;
    esac
done

# Iterate validators in the manifest.
count=$(jq 'length' "$MANIFEST")
say "funding $count validator(s) from $MANIFEST (chains: $CHAINS)"
for i in $(seq 0 $((count - 1))); do
    validator=$(jq -r ".[$i].validator" "$MANIFEST")
    sol_pub=$(jq -r ".[$i].sol_pubkey // empty" "$MANIFEST")
    xlm_acc=$(jq -r ".[$i].xlm_account // empty" "$MANIFEST")
    echo
    say "validator: $validator"
    if [[ $DO_SOL -eq 1 ]]; then
        if [[ -z "$sol_pub" ]]; then
            warn "  no sol_pubkey for $validator — skipping SOL"
        else
            if ./scripts/bridge-faucet.sh sol "$sol_pub" 2; then
                ok "  SOL: 2 SOL airdropped to $sol_pub"
            else
                warn "  SOL airdrop failed for $sol_pub (devnet rate-limit?)"
            fi
        fi
    fi
    if [[ $DO_XLM -eq 1 ]]; then
        if [[ -z "$xlm_acc" ]]; then
            warn "  no xlm_account for $validator — skipping XLM"
        else
            if ./scripts/bridge-faucet.sh xlm "$xlm_acc"; then
                ok "  XLM: friendbot funded $xlm_acc"
            else
                warn "  XLM friendbot failed for $xlm_acc (already-funded?)"
            fi
        fi
    fi
done
echo
ok "done. Per-validator relayer keys topped up."
