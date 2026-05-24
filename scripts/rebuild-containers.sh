#!/usr/bin/env bash
# scripts/rebuild-containers.sh — operator-side rebuild for the two
# docker-compose stacks (5-validator monitoring stack at repo root,
# and the bridge-e2e stack under bridges/). Picks up code changes
# (e.g. observer startLedger fallback, topics fix) by rebuilding
# the image fresh and recreating containers so they run the new bin.
#
# Modes:
#   ./scripts/rebuild-containers.sh                 # main stack (5 validators + monitoring)
#   ./scripts/rebuild-containers.sh main            # same as above (explicit)
#   ./scripts/rebuild-containers.sh bridge          # bridges/docker-compose.testnet.yml
#   ./scripts/rebuild-containers.sh both            # main + bridge sequentially
#
# Flags (must come after the mode):
#   --no-cache    # docker compose build --no-cache (force rebuild every layer)
#   --wipe        # docker compose down -v (delete data volumes)
#                 # ONLY do this if you intend to lose all on-chain state.
#   --logs        # tail logs after up
#
# Notes:
#   * Default behavior: down (preserve volumes) → build → up -d --force-recreate
#     so containers always run the freshly-built image.
#   * --wipe drops the named volumes (chain state, ledger, etc.) — use
#     after schema-breaking changes only. The build alone is enough for
#     code-only refreshes like the recent observer fixes.
#   * The script reads the same docker-compose files git tracks; nothing
#     is generated. Re-run it whenever a host-side code change needs to
#     reach the containers.
#
# Exit codes:
#   0  success
#   1  usage / unknown mode
#   2  docker compose failure (build, up, or healthcheck)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

color() { printf '\033[%sm%s\033[0m\n' "$1" "${*:2}"; }
info() { color "36" "==> $*"; }
pass() { color "32" "[ok] $*"; }
fail() { color "31" "[!!] $*" >&2; }

if ! command -v docker >/dev/null 2>&1; then
    fail "docker not installed"
    exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
    fail "docker compose plugin missing (need v2 — 'docker compose', not 'docker-compose')"
    exit 1
fi

NO_CACHE=0
WIPE=0
LOGS=0
MODE="main"

case "${1:-}" in
    ""|main|monitoring)
        MODE="main" ;;
    bridge|bridges|bridge-e2e)
        MODE="bridge" ;;
    both|all)
        MODE="both" ;;
    -h|--help|help)
        awk '/^# / { sub(/^# ?/, ""); print; next } /^[^#]/ { exit }' "$0"
        exit 0 ;;
    *)
        fail "unknown mode: ${1}"
        fail "usage: $0 [main|bridge|both] [--no-cache] [--wipe] [--logs]"
        exit 1 ;;
esac
shift || true

while [ $# -gt 0 ]; do
    case "$1" in
        --no-cache)  NO_CACHE=1 ;;
        --wipe)      WIPE=1 ;;
        --logs)      LOGS=1 ;;
        *)
            fail "unknown flag: $1"
            exit 1 ;;
    esac
    shift
done

# ── Per-stack rebuild ───────────────────────────────────────

rebuild_stack() {
    # args: <label> <compose-file> <working-dir>
    local label="$1"
    local cf="$2"
    local wd="$3"

    if [ ! -f "$cf" ]; then
        fail "compose file missing: $cf"
        return 2
    fi

    info "[$label] tearing down (preserve volumes: $([ "$WIPE" -eq 0 ] && echo yes || echo NO))"
    # macOS ships bash 3.2 where `"${arr[@]}"` on an empty array
    # trips `set -u`. Build the command as a string of safe flags
    # instead — neither -v nor --no-cache need quoting.
    local down_flag=""
    if [ "$WIPE" -eq 1 ]; then
        down_flag="-v"
    fi
    (cd "$wd" && docker compose -f "$cf" down $down_flag) \
        || { fail "[$label] docker compose down failed"; return 2; }

    info "[$label] building images (no-cache: $([ "$NO_CACHE" -eq 1 ] && echo yes || echo no))"
    local build_flag=""
    if [ "$NO_CACHE" -eq 1 ]; then
        build_flag="--no-cache"
    fi
    (cd "$wd" && docker compose -f "$cf" build $build_flag) \
        || { fail "[$label] docker compose build failed"; return 2; }

    # `--force-recreate` makes containers re-launch even when the
    # image digest happens to match the running version. Without it,
    # `docker compose up` can short-circuit and leave the old image
    # running. `--wait` blocks until every healthcheck reports healthy.
    info "[$label] bringing stack up (--force-recreate --wait)"
    (cd "$wd" && docker compose -f "$cf" up -d --force-recreate --wait) \
        || { fail "[$label] docker compose up failed (healthcheck timeout?)"; return 2; }

    pass "[$label] rebuilt and healthy"
    (cd "$wd" && docker compose -f "$cf" ps)
}

# ── Dispatch ────────────────────────────────────────────────

case "$MODE" in
    main)
        rebuild_stack main "$REPO_DIR/docker-compose.yml" "$REPO_DIR"
        ;;
    bridge)
        rebuild_stack bridge "$REPO_DIR/bridges/docker-compose.testnet.yml" "$REPO_DIR/bridges"
        ;;
    both)
        rebuild_stack main "$REPO_DIR/docker-compose.yml" "$REPO_DIR" || exit $?
        rebuild_stack bridge "$REPO_DIR/bridges/docker-compose.testnet.yml" "$REPO_DIR/bridges" || exit $?
        pass "both stacks rebuilt"
        ;;
esac

if [ "$LOGS" -eq 1 ]; then
    case "$MODE" in
        main|both)
            (cd "$REPO_DIR" && docker compose logs -f --tail=20) ;;
        bridge)
            (cd "$REPO_DIR/bridges" && docker compose -f docker-compose.testnet.yml logs -f --tail=20) ;;
    esac
fi
