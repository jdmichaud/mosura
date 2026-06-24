#!/usr/bin/env bash
# Regenerate the auto-analysis goldens from the Ghidra oracle (A0).
#
# Runs analyzeHeadless over every corpus binary with the DumpAnalysisSnapshot post-script,
# writing goldens/analysis/<name>.snapshot. Fully offline + reproducible (no running MCP
# server), pinned to the built 12.0.3 distribution.
#
# Prereq: a built distribution — run scripts/build-ghidra-dist.sh first.
# See oracle/analysis-capture.md for the full reproduction chain and the snapshot format.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"          # mosura/
GHIDRA_SRC="${GHIDRA_SRC:-$(cd "$HERE/.." && pwd)/ghidra}"
DIST="${GHIDRA_DIST:-$(echo "$GHIDRA_SRC"/build/dist/ghidra_*_DEV)}"
HEADLESS="$DIST/support/analyzeHeadless"
CORPUS="$HERE/oracle/analysis-corpus"
SCRIPTS="$HERE/oracle/ghidra_scripts"
GOLDENS="$HERE/goldens/analysis"

[ -x "$HEADLESS" ] || { echo "ERROR: no analyzeHeadless at $HEADLESS — run scripts/build-ghidra-dist.sh first"; exit 1; }
mkdir -p "$GOLDENS"
PROJ="$(mktemp -d)"; trap 'rm -rf "$PROJ"' EXIT

# UTF-8 locale for the same reason build-ghidra-dist.sh sets it (jar expansion of non-ASCII
# entries); harmless otherwise.
export LC_ALL=C.UTF-8 LANG=C.UTF-8

# Capture two goldens per binary:
#  - <name>.snapshot         : converged (full auto-analysis)            -> A4+ function gate
#  - <name>.loaded.snapshot  : loader-stage (-noanalysis, no analyzers)  -> A2 memory-map gate
# The loader-stage golden is the loader's own output, before analysis adds artificial
# blocks (e.g. PE's `tdb`); it is what the A2 loader must reproduce exactly.
capture() { # <out> <binary> [extra-args...]
  "$HEADLESS" "$PROJ" cap -import "$2" "${@:3}" \
    -scriptPath "$SCRIPTS" -postScript DumpAnalysisSnapshot.java "$1" -deleteProject >/dev/null 2>&1
  [ -s "$1" ] || { echo "  FAILED: $1"; exit 1; }
}

shopt -s nullglob
for elf in "$CORPUS"/*.elf; do
  name="$(basename "$elf" .elf)"
  echo "capturing $name (converged + loader-stage) …"
  capture "$GOLDENS/$name.snapshot" "$elf"
  capture "$GOLDENS/$name.loaded.snapshot" "$elf" -noanalysis
  echo "  wrote $name.snapshot + $name.loaded.snapshot"
done

# User-provided binaries (not committed): capture only if present. Add paths here.
for ext in "cnv:/home/jd/cnv.exe" "comcom32:/home/jd/.local/share/comcom32/comcom32.exe" "war2:/home/jd/WAR2.EXE"; do
  name="${ext%%:*}"; path="${ext#*:}"
  if [ -f "$path" ]; then
    # cnv's converged snapshot is ~3MB (174k instructions) — too large to commit, so it
    # is smoke-tested in code rather than golden-gated; capture loader-stage only.
    if [ "$name" != "cnv" ]; then
      echo "capturing $name (converged + loader-stage; user-provided) …"
      capture "$GOLDENS/$name.snapshot" "$path"
    else
      echo "capturing $name (loader-stage only; converged too large to commit) …"
    fi
    capture "$GOLDENS/$name.loaded.snapshot" "$path" -noanalysis
    echo "  wrote $name goldens"
  else
    echo "skip $name: $path not present"
  fi
done
echo "done"
