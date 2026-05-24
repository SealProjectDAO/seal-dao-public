#!/usr/bin/env bash
# scripts/bridge-redeploy-ringtail.sh — re-deploy the Solana
# Anchor + Stellar Soroban bridge programs with
# `--features ringtail-verify` flipped on, so the on-chain unlock
# claim verifies a 2088-byte Ringtail aggregate signature instead
# of the 32-byte HMAC.
#
# Closes P5 of the testnet-readiness checklist for the Ringtail
# path. The HMAC-mode bridge programs and the Ringtail-mode bridge
# programs are DIFFERENT compiled artifacts that get DIFFERENT
# program-ids (BPF/WASM bytes differ), so this script is a fresh
# deploy + a fresh seal_addBridgeObserver, not an "upgrade" of the
# existing program.
#
# Usage:
#   ./scripts/bridge-redeploy-ringtail.sh \
#       --solana-keypair $HOME/.config/solana/id.json \
#       --stellar-account G... \
#       --seal-rpc http://127.0.0.1:8645
#
# All args are forwarded to scripts/bridge-deploy-devnet.sh with
# `--features ringtail-verify` injected. See that script's --help
# for the full list.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

YELLOW='\033[1;33m'; NC='\033[0m'
warn(){ echo -e "${YELLOW}!${NC} $*"; }

warn "this re-deploys with --features ringtail-verify — the resulting"
warn "program-id and contract-id will be DIFFERENT from any prior HMAC"
warn "deployment. seal_addBridgeObserver fires automatically; make"
warn "sure your seal-node validators are running with the matching"
warn "--bridge-ringtail-* flags before triggering a withdrawal."

exec scripts/bridge-deploy-devnet.sh "$@" --features ringtail-verify
