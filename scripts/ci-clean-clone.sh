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
# restored on exit), together with the developer's own dev-config.toml, and writes a dev-config
# that points the user binaries at $ABSENT (see below). The user binaries themselves are NOT moved.
HIDE_PATHS=(
  "$REPO/oracle/capture"
  "$REPO/oracle/capture_trace"
  "$REPO/build/oracle-cache"
  "$REPO/dev-config.toml"
)
WROTE_CFG=0

# A guaranteed-absent location for the user binaries in --hermetic mode. Leaving them unset would
# fall back to the $HOME defaults — exactly where the files are — so the gates would still run;
# a dev-config pointing them at a nonexistent path is what makes the gates skip, without touching
# the user's real files. Under $REPO/build (gitignored), so no absolute path is baked in.
ABSENT="$REPO/build/hermetic-absent"

HIDDEN=()
restore() {
  local p
  if [ "$WROTE_CFG" = 1 ]; then rm -f "$REPO/dev-config.toml"; fi
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
  log "hermetic mode: hiding in-repo oracle tools + the dev-config; writing one that points the user binaries at an absent path"
  hide
  cat > "$REPO/dev-config.toml" <<EOF
# written by scripts/ci-clean-clone.sh --hermetic; the real file is dev-config.toml.ci-hidden until the run ends
[binaries]
war2 = "$ABSENT/WAR2.EXE"
cnv = "$ABSENT/cnv.exe"
comcom32 = "$ABSENT/comcom32.exe"
EOF
  WROTE_CFG=1
fi

# 3. Report the environment the suite will actually see: the oracle tools + the resolved
#    user-binary locations (the hermetic dev-config if written, else the real one / $HOME defaults).
. "$SCRIPT_DIR/devcfg.sh"
log "environment for the test run (regeneration-only tooling should be absent):"
for p in "${HIDE_PATHS[@]}" \
         "$(devcfg binaries.war2 "$HOME/WAR2.EXE")" \
         "$(devcfg binaries.cnv "$HOME/cnv.exe")" \
         "$(devcfg binaries.comcom32 "$HOME/.local/share/comcom32/comcom32.exe")"; do
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
