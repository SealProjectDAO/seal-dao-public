#!/usr/bin/env bash
# Install TLA+ model checkers (TLC + Apalache) locally under ~/tools/tla.
# Idempotent: skips a download if the artifact already exists.
#
#   TLC     -- tla2tools.jar  (explicit-state; used by scripts/verify-tla-stateroot.sh)
#   Apalache-- apalache-mc    (symbolic; optional)
#
# Requires: java 11+, curl, tar, unzip.
set -euo pipefail

DEST="${TLA_DEST:-$HOME/tools/tla}"
mkdir -p "$DEST"
cd "$DEST"

TLC_VERSION="v1.7.4"
APALACHE_VERSION="v0.62.3"
TLC_JAR="$DEST/tla2tools.jar"
APALACHE_URL="https://github.com/apalache-mc/apalache/releases/download/$APALACHE_VERSION/apalache.tgz"

# -- TLC ------------------------------------------------------------------
if [ -f "$TLC_JAR" ]; then
  echo "TLC jar already present: $TLC_JAR"
else
  echo "Downloading TLC $TLC_VERSION ..."
  curl -sSL --max-time 180 -o "$TLC_JAR" \
    "https://github.com/tlaplus/tlaplus/releases/download/$TLC_VERSION/tla2tools.jar"
fi
echo "TLC self-test:"
java -jar "$TLC_JAR" 2>&1 | sed -n '1,6p' || true

# -- Apalache (optional) ---------------------------------------------------
if [ -x "$DEST/apalache/bin/apalache-mc" ] || [ -x "$DEST/apalache-mc" ]; then
  echo "Apalache already present under $DEST"
else
  echo "Downloading Apalache $APALACHE_VERSION ..."
  curl -sSL --max-time 300 -o "$DEST/apalache.tgz" "$APALACHE_URL"
  tar xzf "$DEST/apalache.tgz" -C "$DEST"
  # The archive contains an `apalache/` dir; expose the launcher on PATH.
  chmod +x "$DEST/apalache/bin/apalache-mc" 2>/dev/null || \
    chmod +x "$DEST/apalache-mc" 2>/dev/null || true
fi

cat <<EOF

Installed under $DEST :
  TLC      : $TLC_JAR
  Apalache : $DEST/apalache/bin/apalache-mc   (if present)

Add Apalache to PATH (optional):
  export PATH="$DEST/apalache/bin:\$PATH"

Run the F3 state-root check:
  ./scripts/verify-tla-stateroot.sh
EOF
