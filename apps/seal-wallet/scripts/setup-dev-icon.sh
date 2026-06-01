#!/usr/bin/env bash
# Replace the bundled Electron.app's icon + display name so the macOS
# dock, Cmd+Tab switcher, and Force Quit Applications dialog show
# Seal Wallet branding during `npm run electron` (dev mode) instead of
# the default Electron logo.
#
# macOS reads CFBundleIconFile and CFBundleDisplayName from the running
# .app's Info.plist, NOT from Electron's runtime app.dock.setIcon() /
# app.setName() calls. In dev mode the running .app is
# node_modules/electron/dist/Electron.app — generic. Replacing its icon
# resource is the only way to retag the dock identity for dev.
#
# Idempotent. No-op on non-darwin / when the Electron.app bundle isn't
# where we expect.
#
# Wired as a "postinstall" script in package.json so a fresh
# `npm install` re-applies the override.
set -euo pipefail

[[ "$(uname)" == "Darwin" ]] || { echo "[setup-dev-icon] non-darwin host, skipping"; exit 0; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ICON_SRC="$ROOT/assets/icon.icns"
APP="$ROOT/node_modules/electron/dist/Electron.app"
RES="$APP/Contents/Resources"
PLIST="$APP/Contents/Info.plist"

if [[ ! -d "$APP" ]]; then
  echo "[setup-dev-icon] $APP not found — was npm install run?"
  exit 0
fi
if [[ ! -f "$ICON_SRC" ]]; then
  echo "[setup-dev-icon] $ICON_SRC missing — run scripts/build-icon.sh first"
  exit 0
fi

cp -f "$ICON_SRC" "$RES/electron.icns"
echo "[setup-dev-icon] replaced $RES/electron.icns"

defaults write "$PLIST" CFBundleName "Seal Wallet" 2>/dev/null || true
defaults write "$PLIST" CFBundleDisplayName "Seal Wallet" 2>/dev/null || true
plutil -convert xml1 "$PLIST" 2>/dev/null || true

touch "$APP"
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister \
  -f "$APP" 2>/dev/null || true

echo "[setup-dev-icon] done — restart \`npm run electron\` to see the new icon"
