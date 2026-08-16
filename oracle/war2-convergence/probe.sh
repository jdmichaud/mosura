#!/usr/bin/env bash
# One probe iteration for the single-function convergence loop: prints the verdict, the
# divergence-class tally, and the first N real divergences (layout-shift filtered out).
#
# Usage: ./probe.sh [N]
#
# PATHS ARE HARDCODED to the session this came from -- edit them for your own scratch tree.
# Prefer scoring on matched rows over the printed similarity:
#   ... --verbose | awk '/^  0006/{n++} END{print "matched:", n}'
# One probe iteration: check exp3, print sim + first divergences.
M=/home/jd/projects/mosura/mosura
$M/target/release/examples/recompile_check /home/jd/WAR2.EXE sb16/manifest.tsv exp3/src recover \
  /home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM \
  --cache cache --only 02714 --out exp3/o.tsv --divergences exp3/d.tsv >/dev/null 2>&1
awk -F'\t' 'NR>1{print $4" sim="$7"  "$8}' exp3/o.tsv
if [ -f exp3/d.tsv ]; then awk -F'\t' 'NR>1 && $3!="layout-shift"{printf "%s %-12s %-28s | %s\n",$4,$3,$13,$14}' exp3/d.tsv | head -${1:-12}; fi
# match-count metric
M2=/home/jd/projects/mosura/mosura
$M2/target/release/examples/recompile_check /home/jd/WAR2.EXE sb16/manifest.tsv exp3/src recover /home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM --cache cache --only 02714 --verbose 2>/dev/null | awk '/^  0006/{m++} END{print "matched rows:", m}'
