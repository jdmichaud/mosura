#!/usr/bin/env bash
# war2-verdicts.sh — verdict census and baseline comparison for recompile_check TSVs.
#
#   scripts/war2-verdicts.sh <rec.tsv>                  census of one measurement
#   scripts/war2-verdicts.sh <baseline.tsv> <cand.tsv>  census of both + per-function
#                                                       verdict flips + WGSS movement
#   scripts/war2-verdicts.sh --loss <rec.tsv> [N]       WGSS-loss ranking: lost insn
#                                                       weight by dominant cause + the
#                                                       top-N contributing functions
#                                                       (default 20) with orig/cand
#                                                       instruction counts
#
# Column contract (recompile_check --out): 1 idx, 2 va, 3 name, 4 verdict, 7 sim,
# 6 primary cause, 9 orig_n, 10 cand_n.
# A header row starting with "idx" is skipped. Functions are joined BY NAME, never by
# row order, so the comparison stays honest if a tree gains or loses functions.
#
# Written and validated once (2026-08-21, zc2 vs zc5: 746/1979/70/1/1 both, 0 flips,
# 11 WGSS movers net -0.023; synthetic flip exercised the FLIP arm) so corpus rounds
# stop re-deriving ad-hoc awk — a wrong column pick (cut -f3 = names, not verdicts)
# once cost a rerun of the whole census. Inputs are copied to temp files first, so
# pipes and process substitutions are read exactly once; the two-file awk keys on
# FILENAME, immune to the empty-first-file NR==FNR trap.
set -euo pipefail

usage() { echo "usage: $0 [--loss] <rec.tsv> [<candidate.tsv>|N]" >&2; exit 2; }
if [ "${1:-}" = "--loss" ]; then
  shift
  [ $# -ge 1 ] || usage
  n="${2:-20}"
  # census by cause (portable awk: no asorti — ranking is an external sort)
  awk -F'\t' '
    FNR==1 && $1=="idx" { next }
    {
      loss = $9 * (1 - $7)
      tot += loss; w += $9
      cause[$6 == "" ? "(none)" : $6] += loss
    }
    END {
      printf "== loss: total insn weight %d, lost %.0f => WGSS %.4f\n", w, tot, 1 - tot / w
      for (k in cause) printf "  %9.0f lost  %s\n", cause[k], k
    }
  ' "$1"
  echo "== top $n contributors (lost weight | name | sim | orig->cand insns | verdict | cause)"
  awk -F'\t' '
    FNR==1 && $1=="idx" { next }
    { printf "%9.1f  %-16s sim %.3f  n %4d->%-4d  %-10s %s\n", $9 * (1 - $7), $3, $7, $9, $10, $4, $6 }
  ' "$1" | sort -rn | sed -n "1,${n}p"
  exit 0
fi
[ $# -ge 1 ] && [ $# -le 2 ] || usage

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
base="$tmpdir/base.tsv"; cand="$tmpdir/cand.tsv"
cat -- "$1" > "$base" || { echo "unreadable: $1" >&2; exit 2; }
[ $# -eq 2 ] && { cat -- "$2" > "$cand" || { echo "unreadable: $2" >&2; exit 2; }; }

census() { # $1 = file, $2 = display name
  echo "== census: $2"
  awk -F'\t' 'FNR==1 && $1=="idx" {next} {n[$4]++} END {for (v in n) printf "  %5d %s\n", n[v], v}' "$1" | sort -k2
}

census "$base" "$1"
[ $# -eq 1 ] && exit 0
census "$cand" "$2"

echo "== $1 -> $2"
awk -F'\t' -v basefile="$base" '
  FNR==1 && $1=="idx" { next }
  FILENAME==basefile { v[$3]=$4; s[$3]=$7; next }
  {
    seen[$3]=1
    if (!($3 in v)) { printf "  only in candidate: %s (%s)\n", $3, $4; onlyc++; next }
    if (v[$3] != $4) { printf "  FLIP %-16s %s -> %s\n", $3, v[$3], $4; flips++ }
    if (s[$3] != $7) { d=$7-s[$3]; net+=d; moved++; if (d*d > big*big) { big=d; bigf=$3 } }
  }
  END {
    for (f in v) if (!(f in seen)) { printf "  only in baseline: %s (%s)\n", f, v[f]; onlyb++ }
    printf "  flips: %d\n", flips+0
    printf "  wgss:  %d functions moved, net %+.3f", moved+0, net+0
    if (moved) printf " (largest: %s %+.3f)", bigf, big
    printf "\n"
    if (onlyb+onlyc) printf "  membership drift: %d baseline-only, %d candidate-only\n", onlyb+0, onlyc+0
  }
' "$base" "$cand"
