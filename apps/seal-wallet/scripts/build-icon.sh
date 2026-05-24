#!/usr/bin/env bash
# Regenerate apps/seal-wallet/assets/{icon.png,icon.icns,icon.ico} from
# icon.svg. Portable: tries rsvg-convert (librsvg) first, then
# magick / convert (ImageMagick), then errors with install hints.
#
# macOS: builds icon.icns via the system iconutil.
# Linux/Windows: get icon.png + icon.ico; Electron falls back to icon.png
# when the platform-specific format is absent.
#
# Usage: scripts/build-icon.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SVG="$ROOT/icon.svg"
OUT_PNG="$ROOT/assets/icon.png"
OUT_ICNS="$ROOT/assets/icon.icns"
OUT_ICO="$ROOT/assets/icon.ico"

[[ -f "$SVG" ]] || { echo "missing $SVG" >&2; exit 1; }

mkdir -p "$ROOT/assets"
TMP="$(mktemp -d)"
trap "rm -rf $TMP" EXIT

svg_to_png() {
  local size="$1" out="$2"
  if command -v rsvg-convert >/dev/null 2>&1; then
    rsvg-convert "$SVG" -w "$size" -h "$size" -o "$out"
  elif command -v magick >/dev/null 2>&1; then
    magick -background none -size "${size}x${size}" "$SVG" "$out"
  elif command -v convert >/dev/null 2>&1; then
    convert -background none -size "${size}x${size}" "$SVG" "$out"
  else
    echo "" >&2
    echo "Need rsvg-convert (librsvg) or ImageMagick to render SVG." >&2
    echo "  macOS:  brew install librsvg" >&2
    echo "  Linux:  apt-get install librsvg2-bin   (or imagemagick)" >&2
    exit 1
  fi
}

echo "-> $OUT_PNG (512x512)"
svg_to_png 512 "$OUT_PNG"

if command -v iconutil >/dev/null 2>&1; then
  echo "-> $OUT_ICNS (multi-resolution)"
  ICONSET="$TMP/icon.iconset"
  mkdir -p "$ICONSET"
  for s in 16 32 64 128 256 512; do
    svg_to_png "$s"       "$ICONSET/icon_${s}x${s}.png"
    svg_to_png $((s*2))   "$ICONSET/icon_${s}x${s}@2x.png"
  done
  iconutil -c icns "$ICONSET" -o "$OUT_ICNS"
else
  echo "skipping icon.icns (iconutil only on macOS)"
fi

if command -v magick >/dev/null 2>&1 || command -v convert >/dev/null 2>&1; then
  echo "-> $OUT_ICO (16/32/48/64/128/256)"
  ICO_TMP="$TMP/ico"
  mkdir -p "$ICO_TMP"
  for s in 16 32 48 64 128 256; do
    svg_to_png "$s" "$ICO_TMP/${s}.png"
  done
  if command -v magick >/dev/null 2>&1; then
    magick "$ICO_TMP"/*.png "$OUT_ICO"
  else
    convert "$ICO_TMP"/*.png "$OUT_ICO"
  fi
else
  echo "skipping icon.ico (ImageMagick not installed)"
fi

echo "done"
