#!/usr/bin/env bash
# Tier-1 non-regression check. ~60s. Run this before every commit.
#
# The tiers, and what each is FOR:
#
#   T1  quick-check.sh          ~60s    every commit. Build + lib suite + clippy + corpus.
#                                       Catches: compile breaks, unit regressions, x86-64
#                                       fixture movement. BLIND TO: everything WAR2/x86-32.
#
#   T2  mvp-check.sh <va>       ~2-4m   when a change targets a specific WAR2 function.
#                                       Decompiles that function and diffs its shape against
#                                       Ghidra's. Validates the FIX on its own specimen.
#
#   T3  war2-battery            ~40m    OCCASIONAL, for reporting — not per commit.
#                                       Full emit + 1303-TU recompile + compare: byte-clean
#                                       count, call gauge, wrong-code scans, strict-subset.
#                                       Batch it across several commits.
#
# Rule of thumb: T1 gates the commit, T2 validates the fix, T3 reports the state.
# A 40-minute cycle must never be the price of a 4-minute change.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
step() { printf '%-22s' "$1"; }
ok()   { echo "ok${1:+  $1}"; }
bad()  { echo "FAIL  $1"; fail=1; }

step "build"
if out=$(cargo build --release --lib 2>&1); then ok; else bad "$(echo "$out" | grep -m1 '^error')"; fi

step "lib suite"
out=$(cargo test --release --lib 2>&1 | grep -m1 'test result')
case "$out" in *" 0 failed"*) ok "$out";; *) bad "$out";; esac

step "clippy"
n=$(cargo clippy --release --lib 2>&1 | grep -cE '^(warning|error)')
[ "$n" -eq 0 ] && ok || bad "$n diagnostics"

step "corpus"
out=$(cargo test --release --test decompile_corpus -- --nocapture 2>&1 | grep -m1 'corpus @')
[ -n "$out" ] && ok "$out" || bad "no corpus line"

echo
[ $fail -eq 0 ] && echo "T1 GREEN — safe to commit. WAR2 state is UNMEASURED (that is T2/T3)." \
               || echo "T1 RED — do not commit."
exit $fail
