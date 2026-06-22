#!/usr/bin/env bash
#
# setup-oracle.sh — build mosura's self-contained Ghidra reference oracle.
#
# Builds, from the PINNED Ghidra source tree only (no dependency on any external
# Ghidra install), the offline tools that form the test baseline:
#   - sleigh_opt        SLEIGH spec compiler (.slaspec -> .sla)
#   - decomp_dbg        interactive decompiler console (raw p-code via 'print raw')
#   - decomp_test_dbg   native datatest runner (runs Ghidra's decompiler datatests)
# ...then compiles every processor .slaspec -> .sla in place and verifies by
# running the decompiler datatest suite against the freshly-compiled specs.
#
# Designed to be portable: all paths are derived from this script's own location,
# and the only external input is a standard C++ toolchain + libbfd.
#
# Usage:   mosura/scripts/setup-oracle.sh [--skip-specs] [--verify-only]
# Env:     GHIDRA_SRC   path to the pinned Ghidra checkout (default: <workspace>/ghidra)
#          JOBS         parallel build jobs (default: nproc)
#
set -euo pipefail

GHIDRA_TAG="Ghidra_12.0.3_build"   # must match the version the MCP oracle runs

# --- resolve paths relative to this script (portable across machines) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOSURA_DIR="$(dirname "$SCRIPT_DIR")"
WORKSPACE="$(dirname "$MOSURA_DIR")"
GHIDRA_SRC="${GHIDRA_SRC:-$WORKSPACE/ghidra}"
JOBS="${JOBS:-$(nproc)}"

CPP_DIR="$GHIDRA_SRC/Ghidra/Features/Decompiler/src/decompile/cpp"
DATATESTS="$GHIDRA_SRC/Ghidra/Features/Decompiler/src/decompile/datatests"
PROCESSORS="$GHIDRA_SRC/Ghidra/Processors"
BUILD_DIR="$MOSURA_DIR/build"

log() { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[setup:error]\033[0m %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }

SKIP_SPECS=0; VERIFY_ONLY=0
for a in "$@"; do
  case "$a" in
    --skip-specs)  SKIP_SPECS=1 ;;
    --verify-only) VERIFY_ONLY=1 ;;
    -h|--help)     grep '^#' "$0" | sed 's/^#\? \?//'; exit 0 ;;
    *)             die "unknown arg: $a (try --help)" ;;
  esac
done

check_prereqs() {
  log "checking build prerequisites"
  local missing=()
  for t in g++ make bison flex; do command -v "$t" >/dev/null || missing+=("$t"); done
  echo '#include <bfd.h>' | g++ -E -x c++ - >/dev/null 2>&1 || missing+=("bfd.h (libbfd-dev/binutils-dev)")
  if (( ${#missing[@]} )); then
    err "missing prerequisites: ${missing[*]}"
    err "Debian/Ubuntu:  sudo apt-get install -y build-essential bison flex binutils-dev libbfd-dev zlib1g-dev"
    exit 1
  fi
  log "toolchain OK"
}

check_ghidra_src() {
  [ -d "$CPP_DIR" ] || die "Ghidra source not found (expected $CPP_DIR). Set GHIDRA_SRC or place the pinned checkout at $GHIDRA_SRC."
  if [ -d "$GHIDRA_SRC/.git" ]; then
    local ver; ver="$(git -C "$GHIDRA_SRC" describe --tags 2>/dev/null || true)"
    if [[ "$ver" != "$GHIDRA_TAG"* ]]; then
      err "Ghidra checkout is at '$ver', expected '$GHIDRA_TAG'."
      err "Pin it with:  git -C \"$GHIDRA_SRC\" checkout $GHIDRA_TAG"
      die "oracle version must match the MCP's Ghidra (12.0.3)"
    fi
  else
    log "note: GHIDRA_SRC is not a git checkout — cannot verify it is $GHIDRA_TAG"
  fi
  log "Ghidra source OK ($GHIDRA_SRC)"
}

build_tools() {
  # One make invocation per target: the Makefile keys its object set on MAKECMDGOALS.
  log "building standalone tools with -j$JOBS"
  for tgt in sleigh_opt decomp_dbg decomp_test_dbg; do
    log "  make $tgt"
    make -C "$CPP_DIR" -j"$JOBS" "$tgt" >/dev/null
  done
  for b in sleigh_opt decomp_dbg decomp_test_dbg; do
    [ -x "$CPP_DIR/$b" ] || die "build produced no $b"
  done
  tidy_ghidra_excludes
  log "tools built"
}

build_capture() {
  # mosura's own offline disasm/p-code capture tool, linked against the Ghidra
  # decompiler library. --whole-archive ensures the self-registering "xml"
  # architecture capability is pulled in.
  log "building offline capture tool (oracle/capture)"
  make -C "$CPP_DIR" -j"$JOBS" libdecomp_dbg.a >/dev/null
  g++ -std=c++11 -I"$CPP_DIR" -O2 -o "$MOSURA_DIR/oracle/capture" "$MOSURA_DIR/oracle/capture.cc" \
    -Wl,--whole-archive "$CPP_DIR/libdecomp_dbg.a" -Wl,--no-whole-archive -lbfd -lz
  [ -x "$MOSURA_DIR/oracle/capture" ] || die "capture tool did not build"
}

tidy_ghidra_excludes() {
  # Keep the reference checkout's `git status` clean on any machine: the build
  # drops binaries/object dirs into the cpp dir that Ghidra's .gitignore doesn't
  # all cover. These are local-only excludes (not committed, not copied).
  [ -d "$GHIDRA_SRC/.git" ] || return 0
  local ex="$GHIDRA_SRC/.git/info/exclude" rel="Ghidra/Features/Decompiler/src/decompile/cpp"
  local p
  for p in sleigh_opt sleigh_dbg decomp_dbg decomp_opt decomp_test_dbg ghidra_dbg ghidra_opt \
           sla_opt/ com_dbg/ test_dbg/ ghi_dbg/ ghi_opt/; do
    grep -qxF "$rel/$p" "$ex" 2>/dev/null || echo "$rel/$p" >> "$ex"
  done
}

compile_specs() {
  log "compiling SLEIGH specs from source -> in-place .sla (slow step)"
  # sleigh_opt -a exits non-zero if ANY spec fails; we log but do not abort, since
  # the datatests need only a subset of arches. verify() is the real gate.
  "$CPP_DIR/sleigh_opt" -a "$PROCESSORS" > "$BUILD_DIR/sleigh-compile.log" 2>&1 || true
  local n; n="$(find "$PROCESSORS" -name '*.sla' | wc -l)"
  log "produced $n .sla (full log: build/sleigh-compile.log)"
  (( n > 0 )) || die "no .sla produced — check build/sleigh-compile.log"
}

write_env() {
  cat > "$BUILD_DIR/oracle.env" <<EOF
# generated by setup-oracle.sh — source this to locate the offline oracle from anywhere
export GHIDRA_SRC="$GHIDRA_SRC"
export SLEIGH_OPT="$CPP_DIR/sleigh_opt"
export DECOMP_DBG="$CPP_DIR/decomp_dbg"
export DECOMP_TEST_DBG="$CPP_DIR/decomp_test_dbg"
export CAPTURE="$MOSURA_DIR/oracle/capture"
export DATATESTS="$DATATESTS"
EOF
  log "wrote build/oracle.env"
}

verify() {
  log "verifying: decompiler datatests against the source-tree specs (self-contained)"
  local out rc
  out="$("$CPP_DIR/decomp_test_dbg" -sleighpath "$GHIDRA_SRC" -path "$DATATESTS" datatests 2>&1)" && rc=0 || rc=$?
  echo "$out" | grep -E 'Total tests applied|Total passing tests' || true
  echo "$out" | grep -E 'Error executing|Failures:' | head || true
  [ "${rc:-0}" -eq 0 ] || { err "datatest suite reported failures (exit $rc)"; return "$rc"; }
  log "datatests pass — offline oracle is ready"
}

mkdir -p "$BUILD_DIR"
check_prereqs
check_ghidra_src
if [ "$VERIFY_ONLY" -eq 1 ]; then verify; exit $?; fi
build_tools
build_capture
if [ "$SKIP_SPECS" -eq 0 ]; then compile_specs; else log "skipping spec compile (--skip-specs)"; fi
write_env
verify
log "done — tools in $CPP_DIR"
