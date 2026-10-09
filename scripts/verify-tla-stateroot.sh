#!/usr/bin/env bash
# Verify the F3 state-root determinism spec (formal/tlaplus/SealStateRoot.tla).
#
# The F3 fix makes the header state root a deterministic function of
# (committed pre-state, block txns), never of a node-local live store. This spec
# models two designs:
#   FIXED design: NoMismatchFixed + AgreementFixed must HOLD.
#   BUGGY design: NoMismatchBuggy + AgreementBuggy must FAIL.
#     - NoMismatchBuggy fails at a NON-origin proposer (2 or 3): it stamps a root
#       the honest replayer rejects (the exact F3 fork).
#     - AgreementBuggy is violated even at the origin proposer 1 (its live store
#       already reflects the transfer; nodes 2,3's do not).
#
# TLC reports the FIRST violation it reaches in BFS order, so with both buggy
# invariants in one config you only see AgreementBuggy. This script therefore
# runs NoMismatchBuggy in its own config to surface the proposer-in-{2,3} trace.
#
# Checkers (all fetched by scripts/install-tla-tools.sh into ~/tools/tla):
#   SANY      -- parse/type check, best error messages (bundled in tla2tools.jar)
#   TLC       -- explicit-state model checking; PRIMARY, authoritative
#   Apalache  -- symbolic; secondary cross-check (v0.62.3 requires Java 21)
#
# Requires tla2tools.jar. Set TLA2TOOLS=/path/to/tla2tools.jar if not at
# ~/tools/tla/tla2tools.jar.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TLA_DIR="$HERE/../formal/tlaplus"
TLA2TOOLS="${TLA2TOOLS:-$HOME/tools/tla/tla2tools.jar}"
APALACHE="$(command -v apalache-mc || echo "$HOME/tools/tla/apalache/bin/apalache-mc")"

if [ ! -f "$TLA2TOOLS" ]; then
  echo "tla2tools.jar not found at: $TLA2TOOLS" >&2
  echo "Run scripts/install-tla-tools.sh, or set TLA2TOOLS=/path/to/tla2tools.jar" >&2
  exit 2
fi

# Each TLC run gets its own -metadir so its timestamped state dirs never
# collide and nothing is written into the repo.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# run_tlc <cfg-basename> <metadir-label>
run_tlc () {
  ( cd "$TLA_DIR" && java -cp "$TLA2TOOLS" tlc2.TLC -nowarning \
      -config "$1" -metadir "$WORK/$2" SealStateRoot.tla ) 2>&1
}

ok=1

echo "== SANY: parse + type check (expect: no errors) =="
sany="$(java -cp "$TLA2TOOLS" tla2sany.SANY "$TLA_DIR/SealStateRoot.tla" 2>&1)"
if printf '%s' "$sany" | grep -qiE "parse error|encountered|fatal error"; then
  echo "FAIL: SANY parse/type error:" >&2
  printf '%s' "$sany" | grep -iE "parse error|encountered|fatal error" >&2
  exit 1
fi
echo "  parse/type OK"
echo

echo "== TLC: FIXED design (expect: 'No error has been found') =="
out_fixed="$(run_tlc MC_SealStateRoot_fixed.cfg fixed)"
printf '%s\n' "$out_fixed" | grep -iE "Error|No error|state graph|Finished" | head -6
if printf '%s' "$out_fixed" | grep -qi "No error has been found"; then
  echo "  FIXED holds (both invariants)."
else
  echo "FAIL: FIXED design violated an invariant (or TLC errored):" >&2
  printf '%s' "$out_fixed" | grep -iE "Error|violated|Exception" | head -5 >&2
  ok=0
fi
echo

echo "== TLC: BUGGY design (expect: an invariant is violated) =="
out_buggy="$(run_tlc MC_SealStateRoot_buggy.cfg buggy)"
printf '%s\n' "$out_buggy" | grep -iE "Error|violated|proposer =|produced =|State " | head -10
if printf '%s' "$out_buggy" | grep -qi "is violated"; then
  echo "  BUGGY design reproduces the F3 fork (first violation: $(printf '%s' "$out_buggy" | grep -oiE 'Invariant [A-Za-z]+ is violated' | head -1))."
else
  echo "FAIL: BUGGY design did NOT reproduce the F3 mismatch." >&2
  ok=0
fi
echo

echo "== TLC: NoMismatchBuggy alone (the exact F3 trace: a NON-origin proposer) =="
printf 'SPECIFICATION\n  Spec\n\nINVARIANT\n  NoMismatchBuggy\n\nCHECK_DEADLOCK\n  FALSE\n' > "$WORK/nm.cfg"
# -config/-metadir are absolute (temp); cd to TLA_DIR so SealStateRoot.tla resolves.
nm="$( cd "$TLA_DIR" && java -cp "$TLA2TOOLS" tlc2.TLC -nowarning \
      -config "$WORK/nm.cfg" -metadir "$WORK/nm" SealStateRoot.tla 2>&1 )"
printf '%s\n' "$nm" | grep -iE "violated|proposer = " | head -4
if printf '%s' "$nm" | grep -qE "proposer = [23]"; then
  echo "  F3 counterexample: non-origin proposer (2 or 3) stamps a root the replayer rejects."
else
  echo "FAIL: NoMismatchBuggy did not produce a non-origin (proposer 2/3) counterexample." >&2
  ok=0
fi
echo

if [ -x "$APALACHE" ]; then
  echo "== Apalache: FIXED design, symbolic (expect: no error up to bound) =="
  # Apalache writes <specdir>/_apalache-out and requires the module name to match
  # the filename stem, so run on a temp copy that KEEPS the name SealStateRoot.tla.
  cp "$TLA_DIR/SealStateRoot.tla" "$WORK/SealStateRoot.tla"
  ap_out="$("$APALACHE" check --init=Init --next=Next \
      --inv=NoMismatchFixed,AgreementFixed --length=2 --no-deadlock \
      "$WORK/SealStateRoot.tla" 2>&1)"
  printf '%s\n' "$ap_out" | grep -iE "no error|counterexample|SMT timeout|EXITCODE" | head -4
  if printf '%s' "$ap_out" | grep -qi "EXITCODE: OK"; then
    echo "  Apalache agrees: FIXED holds (no counterexample)."
  else
    echo "  (Apalache did not report EXITCODE: OK -- informational; TLC above is authoritative.)"
  fi
else
  echo "(Apalache not found; skipped the symbolic cross-check -- TLC above is authoritative.)"
fi
echo

if [ "$ok" -ne 1 ]; then
  exit 1
fi
echo "PASS: FIXED design holds; BUGGY design reproduces F3 (non-origin proposer state-root mismatch)."
