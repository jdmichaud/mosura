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
#   --hermetic   LOCAL proof on a machine that HAS the oracle tools / user binaries: reproduce
#                CI's absence without disturbing the user's files — point the MOSURA_*_EXE
#                locator vars at an absent path (the user binaries stay put), and move the
#                in-repo oracle tools aside (gitignored build artifacts; restored on exit).
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
# simply absent. --hermetic moves the in-repo oracle tools aside (gitignored build artifacts,
# restored on exit) — these have no locator var. The user binaries are NOT moved: --hermetic
# points their MOSURA_*_EXE locator vars at $ABSENT instead (see below).
HIDE_PATHS=(
  "$REPO/oracle/capture"
  "$REPO/oracle/capture_trace"
  "$REPO/build/oracle-cache"
)

# A guaranteed-absent location for the user-binary locator vars in --hermetic mode. Unsetting
# them would fall back to the $HOME defaults — exactly where the files are — so the gates would
# still run; pointing them at a nonexistent path is what makes the gates skip, without touching
# the user's real files. Under $REPO/build (gitignored), so no absolute path is baked in.
ABSENT="$REPO/build/hermetic-absent"

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

# 2. Hermetic: reproduce CI's absence — move the in-repo oracle tools aside, and point the
#    user-binary locator vars at $ABSENT (no touching the user's files).
if [ "$HERMETIC" -eq 1 ]; then
  log "hermetic mode: hiding in-repo oracle tools + pointing MOSURA_*_EXE at an absent path"
  hide
  export MOSURA_WAR2_EXE="$ABSENT/WAR2.EXE"
  export MOSURA_CNV_EXE="$ABSENT/cnv.exe"
  export MOSURA_COMCOM32_EXE="$ABSENT/comcom32.exe"
fi

# 3. Report the environment the suite will actually see: the oracle tools + the resolved
#    MOSURA_*_EXE user-binary locations (the hermetic overrides if set, else the $HOME defaults).
log "environment for the test run (regeneration-only tooling should be absent):"
for p in "${HIDE_PATHS[@]}" \
         "${MOSURA_WAR2_EXE:-$HOME/WAR2.EXE}" \
         "${MOSURA_CNV_EXE:-$HOME/cnv.exe}" \
         "${MOSURA_COMCOM32_EXE:-$HOME/.local/share/comcom32/comcom32.exe}"; do
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
