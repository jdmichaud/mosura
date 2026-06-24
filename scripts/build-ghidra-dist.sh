#!/usr/bin/env bash
# Build a runnable Ghidra distribution from the pinned source clone.
#
# WHY: the analysis port's oracle is `analyzeHeadless` (docs/analysis-port-plan.md §3,
# oracle/analysis-capture.md), which only runs from a *packaged distribution* — the bare
# source clone's launcher refuses with "Cannot launch from repo". This produces
#   <ghidra>/build/dist/ghidra_<ver>_DEV/support/analyzeHeadless
# from the clone, so the headless oracle is reproducible in a fresh environment.
#
# Prereqs (same as the Ghidra DevGuide): JDK 21, the ./gradlew wrapper, network for the
# first dependency fetch, and the C/C++ toolchain (already required by setup-oracle.sh).
#
# Two environment gotchas this script handles so a fresh agent need not rediscover them:
#
#  1. LOCALE — gradle's SBOM step expands every jar to disk; jgrapht-core-1.5.1.jar holds a
#     class named `Sørensen…` (non-ASCII). If the JVM's sun.jnu.encoding is ASCII (it can be,
#     even when LANG=…UTF-8, because sun.jnu.encoding follows the *native* locale), expansion
#     dies: "Cannot expand ZIP … InvalidPathException: unmappable characters". We force a
#     UTF-8 locale for the build.
#
#  2. ORACLE POLLUTION — if scripts/setup-oracle.sh already built the C++ oracle, its binaries
#     live in Decompiler/.../cpp/ (decomp_dbg, decomp_test_dbg, sleigh_opt, libdecomp_dbg.a,
#     object dirs). They carry no license header, so Ghidra's `ip` (IP-compliance) task rejects
#     them. We move the generated (git-ignored/untracked) artifacts aside for the build and
#     restore them after. A fresh environment can avoid this entirely by running THIS script
#     BEFORE setup-oracle.sh.
set -euo pipefail

GHIDRA_SRC="${GHIDRA_SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/ghidra}"
# buildGhidra is the canonical target. It runs `assembleAll` (assembles EVERY module — incl.
# the RuntimeScripts launcher scripts that become support/analyzeHeadless) then
# createInstallationZip. `assembleDistribution` ALONE only copies the top-level
# GPL/licenses/docs and omits per-module content, so it never produces analyzeHeadless.
# createInstallationZip deletes the exploded staging after zipping, so we unzip the result.
TASK="${TASK:-buildGhidra}"
CPP="$GHIDRA_SRC/Ghidra/Features/Decompiler/src/decompile/cpp"

[ -x "$GHIDRA_SRC/gradlew" ] || { echo "ERROR: no gradlew at $GHIDRA_SRC (set GHIDRA_SRC)"; exit 1; }
echo "Ghidra source: $GHIDRA_SRC"
git -C "$GHIDRA_SRC" describe --tags 2>/dev/null | sed 's/^/tag: /' || true

# --- move generated C++ oracle artifacts out of the source tree (gotcha 2) ---
STASH="$(mktemp -d)"
mapfile -t ARTS < <(git -C "$GHIDRA_SRC" status --porcelain=v1 --ignored -- "$CPP" 2>/dev/null \
                    | awk '$1=="!!"||$1=="??"{ print substr($0,4) }')
restore() {
  if [ -f "$STASH/arts.tgz" ]; then
    tar -C "$GHIDRA_SRC" -xzf "$STASH/arts.tgz" && echo "restored ${#ARTS[@]} oracle artifact path(s)"
  fi
  rm -rf "$STASH"
}
trap restore EXIT
if [ "${#ARTS[@]}" -gt 0 ]; then
  echo "stashing ${#ARTS[@]} generated oracle artifact path(s) out of cpp/ for the build"
  tar -C "$GHIDRA_SRC" -czf "$STASH/arts.tgz" "${ARTS[@]}"
  for a in "${ARTS[@]}"; do rm -rf "${GHIDRA_SRC:?}/$a"; done
fi

# --- build, under a UTF-8 locale (gotcha 1) ---
export LC_ALL=C.UTF-8 LANG=C.UTF-8
echo "fetchDependencies (idempotent; downloads on first run only)…"
( cd "$GHIDRA_SRC" && ./gradlew --no-daemon --console=plain -I gradle/support/fetchDependencies.gradle )
echo "$TASK …"
( cd "$GHIDRA_SRC" && ./gradlew --no-daemon --console=plain "$TASK" )

# buildGhidra leaves only the installation zip (createInstallationZip deletes the exploded
# staging). Unzip it in place to get the runnable distribution.
if [ "$TASK" = "buildGhidra" ]; then
  ZIP="$(ls -t "$GHIDRA_SRC"/build/dist/*.zip 2>/dev/null | head -1)"
  [ -n "$ZIP" ] || { echo "ERROR: no installation zip produced"; exit 1; }
  echo "unzipping $(basename "$ZIP") …"
  rm -rf "$GHIDRA_SRC"/build/dist/ghidra_*_DEV/
  unzip -q -o "$ZIP" -d "$GHIDRA_SRC/build/dist"
fi

DIST="$(echo "$GHIDRA_SRC"/build/dist/ghidra_*_DEV)"
echo "distribution: $DIST"
[ -x "$DIST/support/analyzeHeadless" ] && echo "OK: $DIST/support/analyzeHeadless" \
  || { echo "ERROR: analyzeHeadless not found in dist"; exit 1; }
