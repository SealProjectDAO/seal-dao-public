#!/usr/bin/env bash
# scripts/spl-usdc-bootstrap.sh — set up a self-serve USDC-shaped
# SPL mint on the LOCAL solana-test-validator (the one stood up by
# `bridges/docker-compose.testnet.yml` for `scripts/bridge-e2e.sh`).
#
# Public devnet USDC requires Circle's sandbox console; this script
# is the no-console alternative used by the local stack. It creates
# a fresh test mint (6 decimals, matching real USDC), seeds a sender
# ATA with supply, derives + initializes the bridge vault ATA, and
# prints the env exports `bridge-e2e.sh` and `bridge-testnet-demo.sh`
# consume.
#
# Idempotent: if the persisted mint keypair already maps to an
# existing on-chain mint, the script reuses it (no fresh-token churn).
# Re-runs only top up the sender ATA balance if it's drained.
#
# Usage:
#   ./scripts/spl-usdc-bootstrap.sh                 # localnet defaults
#   SOLANA_RPC=http://localhost:8899 ./scripts/spl-usdc-bootstrap.sh
#   SUPPLY=1000000 ./scripts/spl-usdc-bootstrap.sh  # 1M USDC seeded
#
# Env overrides:
#   SOLANA_RPC      default http://localhost:8899 (local test validator)
#   SOLANA_KEYPAIR  default ~/.config/solana/id.json (pays for tx + owns
#                   the sender ATA)
#   SUPPLY          default 1000000  — base-USDC units to mint (decimals 6)
#   MINT_KEYPAIR    default bridges/.solana-local-usdc-mint.json
#                   (persisted across runs so the mint pubkey is stable)
#   BRIDGE_PROGRAM_DIR  default bridges/solana
#                   (anchor workspace where `derive-vault-ata --init`
#                   is wired up via Anchor.toml [scripts])
#
# Exit codes:
#   0  success — mint ready, env exports printed
#   1  usage / missing dependency
#   2  spl-token / solana CLI failure
#   3  vault-ATA initialization failure

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

color() { printf '\033[%sm%s\033[0m\n' "$1" "${*:2}"; }
info() { color "36" "==> $*"; }
pass() { color "32" "[ok] $*"; }
fail() { color "31" "[!!] $*" >&2; }

SOLANA_RPC="${SOLANA_RPC:-http://localhost:8899}"
SOLANA_KEYPAIR="${SOLANA_KEYPAIR:-$HOME/.config/solana/id.json}"
SUPPLY="${SUPPLY:-1000000}"  # 1M USDC (in whole tokens; scaled by --decimals)
DECIMALS=6                    # real USDC decimals — keep the same shape
MINT_KEYPAIR="${MINT_KEYPAIR:-$REPO_DIR/bridges/.solana-local-usdc-mint.json}"
BRIDGE_PROGRAM_DIR="${BRIDGE_PROGRAM_DIR:-$REPO_DIR/bridges/solana}"

# ── Prereqs ─────────────────────────────────────────────────

for tool in solana spl-token jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        fail "missing CLI: $tool"
        fail "  brew install solana / pipx install solana-cli / etc."
        exit 1
    fi
done

if [ ! -f "$SOLANA_KEYPAIR" ]; then
    fail "missing solana keypair: $SOLANA_KEYPAIR"
    fail "  fix: solana-keygen new --no-bip39-passphrase -o $SOLANA_KEYPAIR"
    exit 1
fi

PAYER=$(solana address -k "$SOLANA_KEYPAIR")

# Sanity-check the RPC. On local validator the call returns "ok"; on
# devnet you'd be racing the public faucet and should use
# `bridge-faucet.sh sol` instead.
if ! solana cluster-version --url "$SOLANA_RPC" >/dev/null 2>&1; then
    fail "solana RPC unreachable at $SOLANA_RPC"
    fail "  for the local stack, start it via: scripts/bridge-e2e.sh up"
    exit 2
fi

# ── Step 1: ensure payer has lamports (local validator only) ──

is_local_rpc=0
case "$SOLANA_RPC" in
    *localhost*|*127.0.0.1*|*0.0.0.0*) is_local_rpc=1 ;;
esac
balance_lamports=$(solana balance --keypair "$SOLANA_KEYPAIR" --url "$SOLANA_RPC" \
    --lamports 2>/dev/null | awk '{print $1}' || echo 0)
if [ "$is_local_rpc" -eq 1 ] && [ "${balance_lamports:-0}" -lt 100000000 ]; then
    info "topping up payer on local validator (10 SOL)"
    solana airdrop 10 "$PAYER" --url "$SOLANA_RPC" --keypair "$SOLANA_KEYPAIR" \
        >/dev/null || true
fi

# ── Step 2: ensure mint keypair + on-chain mint ─────────────

if [ ! -f "$MINT_KEYPAIR" ]; then
    info "generating mint keypair → $MINT_KEYPAIR"
    solana-keygen new --no-bip39-passphrase --silent --force -o "$MINT_KEYPAIR" \
        >/dev/null
fi
SOL_MINT=$(solana address -k "$MINT_KEYPAIR")

# Is the mint already initialized on-chain? `spl-token display $mint`
# succeeds iff the mint exists. (`solana account` would also work but
# returns owner/data raw bytes.)
if spl-token display "$SOL_MINT" --url "$SOLANA_RPC" >/dev/null 2>&1; then
    info "mint already exists on-chain: $SOL_MINT (reusing)"
else
    info "creating fresh SPL mint ($DECIMALS decimals): $SOL_MINT"
    spl-token create-token \
        --decimals "$DECIMALS" \
        --mint-authority "$PAYER" \
        --url "$SOLANA_RPC" \
        --fee-payer "$SOLANA_KEYPAIR" \
        "$MINT_KEYPAIR" >/dev/null \
        || { fail "spl-token create-token failed"; exit 2; }
fi

# ── Step 3: sender ATA + supply ────────────────────────────

SOL_SENDER_ATA=$(spl-token create-account "$SOL_MINT" \
        --owner "$PAYER" \
        --url "$SOLANA_RPC" \
        --fee-payer "$SOLANA_KEYPAIR" 2>/dev/null \
    | grep -oE '[A-HJ-NP-Za-km-z1-9]{32,}' | head -1) \
    || true
# `create-account` exits non-zero when the ATA already exists — fall
# back to deriving the canonical ATA via spl-token address.
if [ -z "$SOL_SENDER_ATA" ]; then
    SOL_SENDER_ATA=$(spl-token address \
        --token "$SOL_MINT" \
        --owner "$PAYER" \
        --verbose --url "$SOLANA_RPC" 2>/dev/null \
        | awk '/Associated token address:/{print $4}')
fi
if [ -z "$SOL_SENDER_ATA" ]; then
    fail "couldn't determine sender ATA for mint $SOL_MINT"
    exit 2
fi

# Top up the sender ATA if it's below the requested supply. `spl-token
# mint` is idempotent in the sense that calling it twice doubles the
# balance — guard with a balance check so re-runs don't pile up tokens.
existing_balance=$(spl-token balance "$SOL_MINT" --owner "$PAYER" --url "$SOLANA_RPC" \
    2>/dev/null | tr -d ',' || echo 0)
existing_balance="${existing_balance:-0}"
# Strip any decimal part for comparison (we mint whole tokens via the
# `SUPPLY` env, not fractional ones).
existing_whole="${existing_balance%%.*}"
existing_whole="${existing_whole:-0}"
if [ "$existing_whole" -lt "$SUPPLY" ]; then
    delta=$((SUPPLY - existing_whole))
    info "minting $delta USDC to sender ATA (current: $existing_whole, target: $SUPPLY)"
    spl-token mint "$SOL_MINT" "$delta" "$SOL_SENDER_ATA" \
        --mint-authority "$SOLANA_KEYPAIR" \
        --url "$SOLANA_RPC" \
        --fee-payer "$SOLANA_KEYPAIR" >/dev/null \
        || { fail "spl-token mint failed"; exit 2; }
else
    info "sender ATA balance already ≥ $SUPPLY ($existing_whole)"
fi

# ── Step 4: vault ATA (PDA-owned) ───────────────────────────
#
# The bridge program expects the vault ATA to be owned by the
# `bridge_state` PDA. `anchor run derive-vault-ata --init --mint $mint`
# computes it and creates the account in one shot. Falls back to
# spl-token create-account with an explicit owner if anchor isn't
# wired up yet (operator hasn't deployed the bridge program locally).

SOL_VAULT_ATA=""
if [ -f "$BRIDGE_PROGRAM_DIR/Anchor.toml" ] && command -v anchor >/dev/null 2>&1; then
    info "deriving + initializing vault ATA via anchor run derive-vault-ata"
    # Anchor reads ANCHOR_WALLET / ANCHOR_PROVIDER_URL from env; set
    # them so we don't pollute the operator's solana CLI defaults.
    SOL_VAULT_ATA=$(
        cd "$BRIDGE_PROGRAM_DIR" && \
        ANCHOR_WALLET="$SOLANA_KEYPAIR" \
        ANCHOR_PROVIDER_URL="$SOLANA_RPC" \
        anchor run derive-vault-ata -- --mint "$SOL_MINT" --init 2>&1 \
            | awk '/vault ATA:/{print $3}' | head -1
    )
fi
if [ -z "$SOL_VAULT_ATA" ]; then
    fail "anchor run derive-vault-ata didn't produce a vault ATA"
    fail "  ensure the bridge program is deployed (scripts/bridge-e2e.sh up)"
    fail "  and the Anchor workspace at $BRIDGE_PROGRAM_DIR builds clean."
    exit 3
fi

# ── Step 5: print env exports ───────────────────────────────

pass "USDC bootstrap complete"
cat <<EOF

# ── paste into bridge-e2e.sh / bridge-testnet-demo.sh ──
export SOL_MINT='$SOL_MINT'
export SOL_SENDER_ATA='$SOL_SENDER_ATA'
export SOL_VAULT_ATA='$SOL_VAULT_ATA'

# Persisted state:
#   mint keypair: $MINT_KEYPAIR
#   payer:        $PAYER
#   supply:       $SUPPLY USDC ($DECIMALS decimals)
#   rpc:          $SOLANA_RPC
EOF
