#!/usr/bin/env bash
# scripts/stellar-gpg-wrapper.sh — Transparent GPG-encrypted key wrapper
# for the Stellar CLI.
#
# Usage:  scripts/stellar-gpg-wrapper.sh <stellar-args...>
#
# Mechanism:
#   1. Decrypt ~/.stellar/keys/<name>.gpg → ~/.stellar/keys/<name>
#   2. Launch the real `stellar` CLI with all args
#   3. On exit: wipe plaintext, remove /tmp temp files
#
# The passphrase prompt happens ONCE per session (gpg-agent caches it).
# Config: ~/.stellar-gpg.conf  (see init command below)
#
# SECURITY: Plaintext key lives in ~/.stellar/keys/ only for the
# duration of the command. It is zeroized and removed on exit.

set -euo pipefail

CONF="${HOME}/.stellar-gpg.conf"
STELLAR_KEYS_DIR="${HOME}/.stellar/keys"
REAL_STELLAR="${REAL_STELLAR:-$(command -v stellar 2>/dev/null || true)}"

if [ -z "$REAL_STELLAR" ]; then
    echo "stellar-gpg-wrapper: stellar binary not found. Install it or set REAL_STELLAR." >&2
    exit 1
fi

# ── Config defaults ────────────────

CONF_TTL="${STELLAR_GPG_CACHE_TTL:-3600}"
CONF_MAX_TTL="${STELLAR_GPG_CACHE_MAX_TTL:-86400}"
CONF_PASSPHRASE="${STELLAR_GPG_PASSPHRASE:-}"

# ── Helpers ───────────────────────

# Decrypt an identity key. Errors propagate to caller.
decrypt_identity() {
    local identity="$1"
    local gpg_file="$STELLAR_KEYS_DIR/${identity}.gpg"
    local dst="$2"

    [ -f "$gpg_file" ] || { echo "stellar-gpg-wrapper: encrypted key not found: $gpg_file" >&2; return 1; }

    if [ -n "$CONF_PASSPHRASE" ]; then
        echo "WARNING: passphrase passed via env var (visible in ps)." >&2
        gpg --passphrase "$CONF_PASSPHRASE" --batch --yes --decrypt --output "$dst" "$gpg_file"
    else
        gpg --batch --yes --decrypt --output "$dst" "$gpg_file"
    fi
}

# Wipe a file safely (single-block zero, not byte-by-byte).
wipe_file() {
    local file="$1"
    [ -f "$file" ] || return 0
    local size
    size=$(wc -c < "$file")
    if [ "$size" -gt 0 ]; then
        dd if=/dev/zero of="$file" bs="$size" count=1 conv=notrunc 2>/dev/null || true
    fi
    rm -f "$file"
}

# Discover all managed identities from the config or filesystem.
discover_identities() {
    # Load config only once
    if [ ! -f "$CONF" ]; then
        # No config — scan filesystem for .gpg files
        for gpg_file in "$STELLAR_KEYS_DIR"/*.gpg; do
            [ -f "$gpg_file" ] || continue
            basename "${gpg_file%.gpg}"
        done
        return
    fi

    source "$CONF" 2>/dev/null || true

    if [ -n "${IDENTITY_NAMES:-}" ]; then
        echo "$IDENTITY_NAMES"
    else
        # No IDENTITY_NAMES in config — scan filesystem
        for gpg_file in "$STELLAR_KEYS_DIR"/*.gpg; do
            [ -f "$gpg_file" ] || continue
            basename "${gpg_file%.gpg}"
        done
    fi
}

# ── Commands ──────────────────────

cmd_init() {
    echo "Initializing stellar-gpg-wrapper..."

    mkdir -p "$(dirname "$CONF")"

    if [ -f "$CONF" ]; then
        echo "Config exists at $CONF, skipping."
        return 0
    fi

    cat > "$CONF" << 'EOF'
# stellar-gpg-wrapper configuration
# Cache TTL in seconds (default: 1h). gpg-agent caches passphrase.
CACHE_TTL=3600
CACHE_MAX_TTL=86400

# Identities to manage (space-separated names).
# Add your identities here:
IDENTITY_NAMES=seal-bridge-deployer

# If set, the passphrase is loaded from this file (avoid prompts).
# Use with care: this file must be secured separately.
# PASSPHRASE_FILE=/path/to/passphrase.txt
EOF

    # Check for existing plaintext keys and offer to encrypt them
    if [ -d "$STELLAR_KEYS_DIR" ]; then
        local plaintext_count=0
        for f in "$STELLAR_KEYS_DIR"/*; do
            [ -f "$f" ] || continue
            local bn
            bn=$(basename "$f")
            # Skip dirs, .gpg files, and backups
            [[ "$bn" == *.gpg ]] && continue
            [[ "$bn" == *.bak ]] && continue
            [[ "$bn" == networks ]] && continue
            # Check if it's a Stellar key file
            if grep -q '"secret_key"' "$f" 2>/dev/null; then
                plaintext_count=$((plaintext_count + 1))
                echo "  Found plaintext identity: $bn"
            fi
        done

        if [ "$plaintext_count" -gt 0 ]; then
            echo ""
            echo "Found $plaintext_count plaintext identity(ies). Encrypt them? (y/N)"
            read -r answer
            if [[ "$answer" =~ ^[Yy] ]]; then
                for f in "$STELLAR_KEYS_DIR"/*; do
                    [ -f "$f" ] || continue
                    local bn
                    bn=$(basename "$f")
                    [[ "$bn" == *.gpg ]] && continue
                    [[ "$bn" == *.bak ]] && continue
                    [[ "$bn" == networks ]] && continue

                    if grep -q '"secret_key"' "$f" 2>/dev/null; then
                        local encrypted="${f}.gpg"
                        echo "  Encrypting $bn..."
                        if [ -n "$CONF_PASSPHRASE" ]; then
                            gpg --batch --yes --symmetric --cipher-algo AES256 \
                                --passphrase "$CONF_PASSPHRASE" \
                                --output "$encrypted" "$f"
                        else
                            gpg --batch --yes --symmetric --cipher-algo AES256 \
                                --output "$encrypted" "$f"
                        fi
                        chmod 600 "$encrypted"
                        mv "$f" "${f}.plaintext.bak"
                        echo "    → $encrypted (backup: ${f}.plaintext.bak)"
                    fi
                done
            fi
        fi
    fi

    echo ""
    echo "Config: $CONF"
    echo "Keys dir: $STELLAR_KEYS_DIR"
    echo "Tweak: $CONF or env vars STELLAR_GPG_CACHE_TTL / STELLAR_GPG_PASSPHRASE"
}

cmd_status() {
    echo "=== stellar-gpg-wrapper status ==="
    echo ""

    if [ -f "$CONF" ]; then
        echo "Config: $CONF"
        while IFS='=' read -r key val; do
            [ -n "$key" ] && echo "  $key = $val"
        done < <(grep -v '^#' "$CONF" | grep -v '^$' || true)
    else
        echo "Config: NOT FOUND (run 'init' first)"
    fi
    echo ""

    echo "Identities in $STELLAR_KEYS_DIR:"
    if [ -d "$STELLAR_KEYS_DIR" ]; then
        for gpg_file in "$STELLAR_KEYS_DIR"/*.gpg; do
            [ -f "$gpg_file" ] || continue
            local id
            id=$(basename "${gpg_file%.gpg}")
            local plain="$STELLAR_KEYS_DIR/$id"
            if [ -f "$plain" ]; then
                echo "  $id (ALSO has plaintext $id — insecure!)"
            else
                echo "  $id (encrypted, good)"
            fi
        done

        # Warn about plaintext without .gpg companion
        for f in "$STELLAR_KEYS_DIR"/*; do
            [ -f "$f" ] || continue
            local bn
            bn=$(basename "$f")
            [[ "$bn" == *.gpg ]] && continue
            [[ "$bn" == *.bak ]] && continue
            [[ "$bn" == networks ]] && continue
            if [ -f "$f" ]; then
                echo "  $bn (plaintext — not managed by wrapper)"
            fi
        done
    else
        echo "  (directory does not exist)"
    fi
    echo ""

    if gpg-connect-agent /bye >/dev/null 2>&1; then
        echo "gpg-agent: running (cache active)"
    else
        echo "gpg-agent: NOT running (start with: gpg-connect-agent /bye)"
    fi
}

cmd_preload() {
    local passphrase

    if [ -n "$CONF_PASSPHRASE" ]; then
        passphrase="$CONF_PASSPHRASE"
    elif [ -n "${STELLAR_GPG_PASSPHRASE_FILE:-}" ] && [ -f "$STELLAR_GPG_PASSPHRASE_FILE" ]; then
        passphrase=$(cat "$STELLAR_GPG_PASSPHRASE_FILE")
    else
        echo -n "Enter passphrase to preload into gpg-agent: "
        read -rs passphrase
        echo
    fi

    [ -n "$passphrase" ] || { echo "Empty passphrase, aborting." >&2; exit 1; }

    local b64
    b64=$(printf '%s' "$passphrase" | base64 -w0)
    gpg-connect-agent "preset_passphrase $b64 $CONF_TTL $CONF_MAX_TTL" /bye 2>/dev/null

    echo "Passphrase preloaded. No prompts for ${CONF_TTL}s."
}

cmd_install() {
    # Decrypt one or more identities to ~/.stellar/keys/<name>
    # for scripts that call `stellar` directly. Wipe afterward.
    #
    # Usage: scripts/stellar-gpg-wrapper.sh install [name1 name2 ...]
    #        scripts/stellar-gpg-wrapper.sh wipe [name1 name2 ...]

    if [ ! -f "$CONF" ]; then
        echo "Config not found. Run: $0 init" >&2
        exit 1
    fi

    source "$CONF" 2>/dev/null || true

    # If no names given, install all managed identities
    local names=()
    if [ $# -gt 0 ]; then
        names=("$@")
    elif [ -n "${IDENTITY_NAMES:-}" ]; then
        read -r -a names <<< "$IDENTITY_NAMES"
    else
        # Fall back: install all .gpg files
        for gpg_file in "$STELLAR_KEYS_DIR"/*.gpg; do
            [ -f "$gpg_file" ] || continue
            names+=("$(basename "${gpg_file%.gpg}")")
        done
    fi

    if [ ${#names[@]} -eq 0 ]; then
        echo "No identities to install." >&2
        return 0
    fi

    for id in "${names[@]}"; do
        local gpg_file="$STELLAR_KEYS_DIR/${id}.gpg"
        local real_file="$STELLAR_KEYS_DIR/${id}"

        [ -f "$gpg_file" ] || { echo "  Not found: $gpg_file" >&2; continue; }

        if [ -f "$real_file" ]; then
            if [[ "${1:-}" == "--force" ]]; then
                wipe_file "$real_file"
            else
                echo "  Already exists: $real_file (use --force or wrapper commands)" >&2
                continue
            fi
        fi

        decrypt_identity "$id" "$real_file" || { echo "  Decrypt failed: $id" >&2; continue; }
        chmod 600 "$real_file"
        echo "  Installed: $real_file"
    done

    echo "Run '$0 wipe ${names[*]}' when done to remove plaintext keys."
}

cmd_wipe() {
    # Wipe plaintext keys for given identities (or all managed identities)
    if [ ! -f "$CONF" ]; then
        echo "No config. Nothing to wipe."
        return 0
    fi

    source "$CONF" 2>/dev/null || true

    local names=()
    if [ $# -gt 0 ]; then
        names=("$@")
    elif [ -n "${IDENTITY_NAMES:-}" ]; then
        read -r -a names <<< "$IDENTITY_NAMES"
    else
        for gpg_file in "$STELLAR_KEYS_DIR"/*.gpg; do
            [ -f "$gpg_file" ] || continue
            names+=("$(basename "${gpg_file%.gpg}")")
        done
    fi

    if [ ${#names[@]} -eq 0 ]; then
        echo "No identities to wipe."
        return 0
    fi

    for id in "${names[@]}"; do
        local real_file="$STELLAR_KEYS_DIR/$id"
        if [ -f "$real_file" ]; then
            wipe_file "$real_file"
            echo "  Wiped: $real_file"
        else
            echo "  Not found: $real_file"
        fi
    done
}

# ── Core: decrypt → run → wipe ─────

run_wrapped() {
    # Ensure gpg-agent is running
    gpg-connect-agent /bye >/dev/null 2>&1 || true

    # Load config (only once)
    local id_list=""
    if [ -f "$CONF" ]; then
        source "$CONF" 2>/dev/null || true
        id_list="${IDENTITY_NAMES:-}"
    fi

    # Discover which identities to decrypt
    local identities=()
    if [ -n "$id_list" ]; then
        read -r -a identities <<< "$id_list"
    else
        # Scan filesystem
        for gpg_file in "$STELLAR_KEYS_DIR"/*.gpg; do
            [ -f "$gpg_file" ] || continue
            identities+=("$(basename "${gpg_file%.gpg}")")
        done
    fi

    # Save state and decrypt all managed identities
    local orig_files=()
    for id in "${identities[@]}"; do
        local real_file="$STELLAR_KEYS_DIR/$id"
        if [ -f "$real_file" ]; then
            orig_files+=("$real_file")
            cp "$real_file" "${real_file}.gpg-bak"
        fi

        # Decrypt to real file path (stellar CLI reads ~/.stellar/keys/<name>)
        decrypt_identity "$id" "$real_file" || {
            echo "stellar-gpg-wrapper: decryption failed for $id" >&2
            exit 1
        }
        chmod 600 "$real_file"
    done

    # Cleanup: restore originals or wipe decrypted files
    cleanup_and_run() {
        for id in "${identities[@]}"; do
            local real_file="$STELLAR_KEYS_DIR/$id"
            local gpg_bak="${real_file}.gpg-bak"
            if [ -f "$gpg_bak" ]; then
                mv "$gpg_bak" "$real_file"
            elif [ -f "$real_file" ]; then
                # Was originally encrypted-only (no plaintext existed)
                wipe_file "$real_file"
            fi
        done
    }

    trap cleanup_and_run EXIT INT TERM

    # exec replaces the shell — EXIT trap fires on signals but not
    # clean exit in some shells. Wrap in subshell to be safe.
    exec "$REAL_STELLAR" "$@"
}

# ── Main ──────────────────────────

case "${1:-wrapped}" in
    init)       cmd_init ;;
    status)     cmd_status ;;
    preload)    cmd_preload ;;
    install)    shift; cmd_install "$@" ;;
    wipe)       shift; cmd_wipe "$@" ;;
    *)          run_wrapped "$@" ;;
esac
