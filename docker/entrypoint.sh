#!/bin/sh
# Dockerfile entrypoint — keeps validator identity stable across
# container restarts when SEAL_VALIDATOR_KEY is set.
#
# Behavior:
#   - SEAL_VALIDATOR_KEY unset → exec seal-node "$@" unchanged
#     (matches the pre-2026-05-14 ephemeral-identity behavior).
#   - SEAL_VALIDATOR_KEY set + file exists → use it.
#   - SEAL_VALIDATOR_KEY set + file missing → run `seal keygen` to
#     create it, then use it. The named volume / bind mount keeps
#     the generated keypair across restarts.
#
# `--mainnet` propagates: if the calling args contain it, pass it
# to seal keygen so the generated keyfile carries `network=mainnet`
# rather than the default `testnet`. seal-node refuses an HRP
# mismatch at startup, so this guard prevents a `--mainnet` node
# from regenerating a `testnet` keyfile on every boot.

set -e

if [ -n "$SEAL_VALIDATOR_KEY" ]; then
    if [ ! -f "$SEAL_VALIDATOR_KEY" ]; then
        # Detect --mainnet in the passed args (literal flag, not
        # value-of-prev-flag — seal-node uses bare flags).
        KEYGEN_NETWORK=""
        for arg in "$@"; do
            if [ "$arg" = "--mainnet" ]; then
                KEYGEN_NETWORK="--mainnet"
                break
            fi
        done
        echo "entrypoint: generating validator key at $SEAL_VALIDATOR_KEY"
        # Ensure parent dir exists (named-volume mount or bind mount).
        mkdir -p "$(dirname "$SEAL_VALIDATOR_KEY")"
        seal keygen $KEYGEN_NETWORK --output "$SEAL_VALIDATOR_KEY"
        chmod 600 "$SEAL_VALIDATOR_KEY"
    else
        echo "entrypoint: reusing existing validator key at $SEAL_VALIDATOR_KEY"
    fi
    exec seal-node "$@" --validator-key "$SEAL_VALIDATOR_KEY"
fi

exec seal-node "$@"
