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
# Usage:   mosura/scripts/setup-oracle.sh [--skip-specs] [--verify-only] [--sla-only]
#            --sla-only   BUILD/TEST tier only: build sleigh_opt + compile the .sla, and stop
#                         (no capture / decomp_dbg / datatest verify). This is the minimal step
#                         `cargo test` needs; scripts/setup-ghidra.sh calls it after fetching.
# Env:     GHIDRA_SRC   path to the pinned Ghidra checkout (default: <workspace>/ghidra)
#          JOBS         parallel build jobs (default: nproc)
#
set -euo pipefail

GHIDRA_TAG="Ghidra_12.0.3_build"   # must match the version the MCP oracle runs
GHIDRA_COMMIT="09f14c92d3da6e5d5f6b7dea115409719db3cce1"  # the exact pin (tags can move; scripts/setup-ghidra.sh materializes it)

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

SKIP_SPECS=0; VERIFY_ONLY=0; SLA_ONLY=0
for a in "$@"; do
  case "$a" in
    --skip-specs)  SKIP_SPECS=1 ;;
    --verify-only) VERIFY_ONLY=1 ;;
    --sla-only)    SLA_ONLY=1 ;;
    -h|--help)     grep '^#' "$0" | sed 's/^#\? \?//'; exit 0 ;;
    *)             die "unknown arg: $a (try --help)" ;;
  esac
done

check_prereqs() {
  log "checking build prerequisites"
  local missing=()
  for t in g++ make bison flex; do command -v "$t" >/dev/null || missing+=("$t"); done
  # libbfd is only needed by the capture/oracle tools, not by sleigh_opt (the .sla compiler).
  if [ "$SLA_ONLY" -eq 0 ]; then
    echo '#include <bfd.h>' | g++ -E -x c++ - >/dev/null 2>&1 || missing+=("bfd.h (libbfd-dev/binutils-dev)")
  fi
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
    # Verify the EXACT pinned commit, not just the tag (tags can be moved/re-pointed).
    local head; head="$(git -C "$GHIDRA_SRC" rev-parse HEAD 2>/dev/null || true)"
    if [ "$head" != "$GHIDRA_COMMIT" ]; then
      err "Ghidra checkout is at commit '${head:-<none>}', expected the pin $GHIDRA_COMMIT ($GHIDRA_TAG)."
      err "Materialize/verify the pin with:  scripts/setup-ghidra.sh"
      die "oracle must match the pinned Ghidra commit (12.0.3)"
    fi
  else
    log "note: GHIDRA_SRC is not a git checkout — cannot verify it is $GHIDRA_COMMIT"
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
  #
  # CRITICAL: compile with the SAME switches libdecomp_dbg.a is built with
  # (Ghidra Makefile COMMANDLINE_DEBUG = -DCPUI_DEBUG -D__TERMINAL__). These add
  # instance members to core classes, so a mismatch is a silent ABI/struct-layout
  # corruption (no crash) that makes capture's decompilation diverge from canonical
  # Ghidra (decomp_dbg) — e.g. it mis-typed divopt's pointer parameter. See the
  # header comment in oracle/capture.cc.
  log "building offline capture tool (oracle/capture)"
  make -C "$CPP_DIR" -j"$JOBS" libdecomp_dbg.a >/dev/null
  g++ -std=c++11 -DCPUI_DEBUG -D__TERMINAL__ -I"$CPP_DIR" -O2 -o "$MOSURA_DIR/oracle/capture" "$MOSURA_DIR/oracle/capture.cc" \
    -Wl,--whole-archive "$CPP_DIR/libdecomp_dbg.a" -Wl,--no-whole-archive -lbfd -lz
  [ -x "$MOSURA_DIR/oracle/capture" ] || die "capture tool did not build"
}

build_capture_trace() {
  # The rule-application trace tool (Task #2 "killer feature"): emits Ghidra's OPACTION_DEBUG
  # "DEBUG <n>: <RuleName>" before/after trace for a fixture, to diff against mosura's own trace
  # (MOSURA_TRACE=1) via scripts/trace-diff.py.
  #
  # No separate library: types.h does `#ifdef CPUI_DEBUG #define OPACTION_DEBUG`, so the trace
  # machinery is ALREADY in the same libdecomp_dbg.a that oracle/capture links. This is a distinct
  # binary compiled with the IDENTICAL switches (-DCPUI_DEBUG -D__TERMINAL__) so the oracle's
  # capture tool stays 100% untouched and the ABI matches the library (the d5ae08d lesson).
  log "building rule-application trace tool (oracle/capture_trace)"
  # (build_capture_typeprop below builds the TYPE-side twin; same library, same switches.)
  g++ -std=c++11 -DCPUI_DEBUG -D__TERMINAL__ -I"$CPP_DIR" -O2 -o "$MOSURA_DIR/oracle/capture_trace" "$MOSURA_DIR/oracle/capture_trace.cc" \
    -Wl,--whole-archive "$CPP_DIR/libdecomp_dbg.a" -Wl,--no-whole-archive -lbfd -lz
  [ -x "$MOSURA_DIR/oracle/capture_trace" ] || die "capture_trace tool did not build"
}

build_capture_merge() {
  # The MERGE-side twin of capture_trace (K-9): HighVariable membership AND per-member covers at
  # the end of the merge cluster. capture_trace cannot answer merge questions -- OPACTION_DEBUG
  # traces the rule pool, and merge decisions are not PcodeOp modifications -- and decomp_dbg's
  # console cannot either, because `print high` shows membership while `print cover high` prints
  # "Cover dirty" once later phases set the flag (variable.hh:188). Same library, same switches.
  log "building merge-state capture tool (oracle/capture_merge)"
  g++ -std=c++11 -DCPUI_DEBUG -D__TERMINAL__ -I"$CPP_DIR" -O2 -o "$MOSURA_DIR/oracle/capture_merge" "$MOSURA_DIR/oracle/capture_merge.cc" \
    -Wl,--whole-archive "$CPP_DIR/libdecomp_dbg.a" -Wl,--no-whole-archive -lbfd -lz
  [ -x "$MOSURA_DIR/oracle/capture_merge" ] || die "capture_merge tool did not build"
}

build_capture_typeprop() {
  # The TYPE-PROPAGATION trace tool (task #11): emits Ghidra's TYPEPROP_DEBUG
  # "<varnode> : <type> from <op> slot=<n>" log, to diff against mosura's own (MOSURA_TYPEPROP=1)
  # via scripts/typeprop-diff.sh.
  #
  # WHY IT IS SEPARATE FROM capture_trace: that tool drives OPACTION_DEBUG, which is a p-code-OP
  # mutation log and is therefore STRUCTURALLY BLIND to type inference -- ActionInferTypes assigns
  # datatypes to VARNODES and mutates no ops, so it never prints there, on either side. Ghidra ships
  # TYPEPROP_DEBUG as a second channel for exactly that reason.
  #
  # No special flags: types.h:88-91 auto-defines TYPEPROP_DEBUG from CPUI_DEBUG, exactly as it does
  # OPACTION_DEBUG, so the hook is already inside the same libdecomp_dbg.a and the IDENTICAL
  # switches (-DCPUI_DEBUG -D__TERMINAL__) keep the ABI matched (the d5ae08d lesson). The extra
  # requirement is purely at RUNTIME: TypeFactory::propagatedbg_on defaults to false, and the tool
  # sets it.
  log "building type-propagation trace tool (oracle/capture_typeprop)"
  g++ -std=c++11 -DCPUI_DEBUG -D__TERMINAL__ -I"$CPP_DIR" -O2 -o "$MOSURA_DIR/oracle/capture_typeprop" "$MOSURA_DIR/oracle/capture_typeprop.cc" \
    -Wl,--whole-archive "$CPP_DIR/libdecomp_dbg.a" -Wl,--no-whole-archive -lbfd -lz
  [ -x "$MOSURA_DIR/oracle/capture_typeprop" ] || die "capture_typeprop tool did not build"
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
export CAPTURE_TRACE="$MOSURA_DIR/oracle/capture_trace"
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
if [ "$SLA_ONLY" -eq 1 ]; then
  # BUILD/TEST tier: just sleigh_opt + the .sla — exactly what `cargo test` loads, nothing more.
  log "sla-only: building sleigh_opt + compiling specs (no oracle tools)"
  make -C "$CPP_DIR" -j"$JOBS" sleigh_opt >/dev/null
  [ -x "$CPP_DIR/sleigh_opt" ] || die "build produced no sleigh_opt"
  tidy_ghidra_excludes
  compile_specs
  log "sla-only done — .sla compiled; 'cargo test' is self-contained"
  exit 0
fi
build_tools
build_capture
build_capture_trace
build_capture_merge
build_capture_typeprop
if [ "$SKIP_SPECS" -eq 0 ]; then compile_specs; else log "skipping spec compile (--skip-specs)"; fi
write_env
verify
log "done — tools in $CPP_DIR"
