#!/usr/bin/env bash
#
# ci-clean-clone.sh — prove the clean-clone dev/test split (dependency-hardening move #3).
#
# mosura's test surface is designed to be EXACTLY {pinned Ghidra processor data + committed
# in-repo goldens/fixtures} (docs/dependencies.md, BUILD/TEST tier). Everything else — the
# Ghidra C++ oracle (oracle/capture, decomp_dbg), analyzeHeadless, the cross-toolchains, Open
# Watcom, dosemu2, and the user-provided binaries (WAR2/cnv/comcom32) — is regeneration-only,
# and every test that touches it SKIPS when it is absent.
#
# This job proves + guards that: a fresh checkout + the pinned Ghidra data runs the FULL
# `cargo test` suite GREEN with none of the regeneration-only tooling present. If a new test
# grows a hard dependency on any of it (fails instead of skipping when absent), this job goes
# red — keeping the test surface from creeping.
#
# Modes:
#   (default)    CI mode: materialize the pinned Ghidra + compile .sla, then run the full
#                suite. On a CI runner the oracle tools + user binaries are simply absent.
#   --hermetic   LOCAL proof on a machine that HAS the oracle tools / user binaries: hide them
#                (restored on exit, even on Ctrl-C) so the run sees the same absence CI would.
#   --no-fetch   Skip the Ghidra fetch/compile; only verify an existing checkout is at the pin
#                (assumes the .sla are already built — for a quick local re-run).
#
# No absolute paths — everything derives from this script's location and $HOME.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"

log() { printf '\033[1;34m[ci]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[ci:error]\033[0m %s\n' "$*" >&2; }

HERMETIC=0; NO_FETCH=0
for a in "$@"; do
  case "$a" in
    --hermetic) HERMETIC=1 ;;
    --no-fetch) NO_FETCH=1 ;;
    -h|--help)  grep '^#' "$0" | sed 's/^#\? \?//'; exit 0 ;;
    *)          err "unknown arg: $a (try --help)"; exit 2 ;;
  esac
done

# The regeneration-only artifacts that the test surface must NOT require. In real CI they are
# simply absent; --hermetic hides the local copies (restoring them on exit). $HOME-relative so
# there are no absolute paths here (the user-binary defaults from docs/dependencies.md).
HIDE_PATHS=(
  "$REPO/oracle/capture"
  "$REPO/oracle/capture_trace"
  "$REPO/build/oracle-cache"
  # User binaries at the MOSURA_*_EXE locations (env override, else the $HOME default — the
  # same resolution paths.rs uses), so --hermetic hides wherever the tests actually look.
  "${MOSURA_WAR2_EXE:-$HOME/WAR2.EXE}"
  "${MOSURA_CNV_EXE:-$HOME/cnv.exe}"
  "${MOSURA_COMCOM32_EXE:-$HOME/.local/share/comcom32/comcom32.exe}"
)

HIDDEN=()
restore() {
  local p
  for p in "${HIDDEN[@]}"; do
    if [ -e "$p.ci-hidden" ]; then mv -f "$p.ci-hidden" "$p"; fi
  done
}
hide() {
  local p
  # Refuse to run over leftover state from a crashed prior run (never overwrite a real file).
  for p in "${HIDE_PATHS[@]}"; do
    if [ -e "$p.ci-hidden" ]; then
      err "leftover $p.ci-hidden from a crashed run — restore it first"; exit 3
    fi
  done
  trap restore EXIT INT TERM
  for p in "${HIDE_PATHS[@]}"; do
    if [ -e "$p" ]; then
      mv "$p" "$p.ci-hidden"
      HIDDEN+=("$p")
      log "hidden for the run: $p"
    fi
  done
}

mkdir -p "$REPO/build"
LOG="$REPO/build/ci-clean-clone.log"

# 1. The ONE build/test dependency: pinned Ghidra data + compiled .sla (idempotent).
if [ "$NO_FETCH" -eq 1 ]; then
  log "verifying the Ghidra pin (--no-fetch)"
  "$SCRIPT_DIR/setup-ghidra.sh" --verify-only
else
  log "materializing pinned Ghidra data (setup-ghidra.sh)"
  "$SCRIPT_DIR/setup-ghidra.sh"
fi

# 2. Hermetic: hide the regeneration-only tooling so the run sees CI's absence.
[ "$HERMETIC" -eq 1 ] && { log "hermetic mode: hiding oracle tools + user binaries"; hide; }

# 3. Report the environment the suite will actually see.
log "environment for the test run (regeneration-only tooling should be absent):"
for p in "${HIDE_PATHS[@]}"; do
  if [ -e "$p" ]; then echo "   PRESENT: $p"; else echo "   absent:  $p"; fi
done

# 4. Run the FULL suite. --nocapture surfaces each test's skip message.
log "running the full workspace suite"
rc=0
cargo test --workspace -- --nocapture > "$LOG" 2>&1 || rc=$?

# 5. Summarize.
echo
log "test results:"
grep -E "test result:" "$LOG" | sed 's/^/   /' || true
echo
log "tests that SKIPPED (graceful absence — the split working):"
grep -iE "skip" "$LOG" | sed 's/^[[:space:]]*/   /' | sort -u || true

if [ "$rc" -ne 0 ]; then
  echo
  err "FAILED (rc=$rc): a test did NOT skip gracefully when a tool/binary was absent."
  err "That is a real skip-if-absent gap. Failing lines:"
  grep -E "FAILED|panicked|error\[" "$LOG" | head -20 >&2 || true
  exit "$rc"
fi

echo
log "PASS — clean clone + pinned Ghidra data runs the full suite green with no oracle tools."
log "(full log: build/ci-clean-clone.log)"
