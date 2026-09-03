#!/usr/bin/env bash
# Prove §0 by RUNNING it: mosura's gate passes with no compiler reachable at all.
#
# `building_any_invocation_runs_no_compiler` checks that constructing a driver runs nothing. That
# is not the same claim. This checks the one JD actually cares about -- a clean machine with zero
# toolchains installed can build and test mosura -- by executing every gate binary with PATH
# pointing nowhere, so ANY attempt to exec dosemu, wcc386 or gcc fails.
#
# The invariant was BROKEN and unnoticed until 2026-09-03 precisely because it was a label on a
# suite nobody ran without a compiler present.
#
# Two claims, because the breach found on 2026-09-03 has two distinct halves:
#   (default)      NO toolchain at all -- the strict §0 claim, "a clean machine with zero
#                  toolchains can build and test mosura".
#   --target-only  no TARGET toolchain (dosemu/Watcom), host gcc still reachable -- the weaker
#                  claim, under which a gcc-based ground-truth gate is a development-environment
#                  requirement rather than a §0 violation.
# Which one mosura promises is a policy question; this script measures both rather than assuming.
set -uo pipefail
cd "$(dirname "$0")/.."
NOWHERE=/nonexistent-toolchain-dir
MODE="${1:-strict}"
if [ "$MODE" = "--target-only" ]; then
  RUNPATH=/usr/bin:/bin          # gcc stays reachable, dosemu (in ~/.local/bin) does not
  HIDDEN="dosemu wcc386"
else
  RUNPATH="$NOWHERE"
  HIDDEN="dosemu gcc wcc386"
fi

echo "== 1. build the gate binaries (normal PATH) =="
cargo test --release -p mosura --no-run --message-format=json 2>/dev/null \
  | python3 -c '
import sys, json
for line in sys.stdin:
    try: m = json.loads(line)
    except ValueError: continue
    exe = m.get("executable")
    if exe and (m.get("target") or {}).get("test"):
        print(exe)' > /tmp/mosura-gate-bins.$$ || { echo "BUILD FAILED"; exit 1; }
mapfile -t BINS < /tmp/mosura-gate-bins.$$; rm -f /tmp/mosura-gate-bins.$$
[ "${#BINS[@]}" -gt 0 ] || { echo "no test binaries found"; exit 1; }
echo "   ${#BINS[@]} test binaries"

echo "== 2. self-check: the toolchain really is hidden =="
# Without this the whole proof could pass vacuously on a box that has no compiler by accident,
# or because PATH was never actually stripped.
# NOTE the absolute /bin/sh: `env PATH=... command -v x` execs a BINARY called `command`, which
# does not exist, so that form "proves" every tool hidden by failing to run at all -- a vacuous
# control, and this script exists to stop exactly that. /bin/sh is found by absolute path, then
# resolves `command -v` as a builtin against the PATH we set.
for tool in $HIDDEN; do
  if env PATH="$RUNPATH" /bin/sh -c "command -v $tool" >/dev/null 2>&1; then
    echo "   FAIL: $tool is still reachable under the stripped PATH"; exit 1
  fi
done
if [ "$MODE" = "--target-only" ] && ! env PATH="$RUNPATH" /bin/sh -c 'command -v gcc' >/dev/null 2>&1; then
  echo "   FAIL: --target-only requires gcc to REMAIN reachable, and it is not"; exit 1
fi
echo "   hidden: $HIDDEN"

echo "== 3. run every gate binary with no toolchain =="
rc=0
for b in "${BINS[@]}"; do
  out=$(env PATH="$RUNPATH" MOSURA_WATCOM_DIR="$NOWHERE" MOSURA_WATCOM="$NOWHERE" "$b" 2>&1)
  line=$(printf '%s\n' "$out" | grep -E '^test result' | tail -1)
  if printf '%s\n' "$out" | grep -q '^test result: FAILED'; then
    echo "   FAILED  $(basename "$b")  $line"
    printf '%s\n' "$out" | grep -A3 '^failures:' | head -20
    rc=1
  else
    echo "   ok      $(basename "$b")  $line"
  fi
done

echo
if [ "$rc" -eq 0 ]; then
  echo "PASS ($MODE): every gate test passes with [$HIDDEN] unreachable."
else
  echo "FAIL ($MODE): the gate needs a toolchain -- see the failures above."
fi
exit "$rc"
