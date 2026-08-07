#!/usr/bin/env bash
# Build the `sortperm` helper that wunpack.py shells out to.
#
# It links Open Watcom's OWN wqsort.c rather than reimplementing the sort, because the archive
# format depends on the exact permutation an *unstable* quicksort leaves behind (see wunpack.py's
# sort_lengths). Any other sort decodes to garbage.
#
# -m32 is REQUIRED, not a preference: wqsort.c's portable byteswap fallback reads and writes
# 8-byte `long`s while advancing the pointers by 4 (its comment says "this is for 32 bit
# machines"). On LP64 those overlapping writes corrupt the array — the sort silently returns a
# permutation with duplicated and missing elements. With -m32, `long` is 4 bytes and it is correct.
set -euo pipefail
cd "$(dirname "$0")"

OW=${GHIDRA_OW_SRC:-/data/open-watcom-v2}
[ -f "$OW/bld/wpack/c/wqsort.c" ] || { echo "no Open Watcom source at $OW (set GHIDRA_OW_SRC)"; exit 1; }

gcc -w -m32 -O1 -I"$OW/bld/wpack/h" -o sortperm sortperm.c "$OW/bld/wpack/c/wqsort.c"
echo "built $(pwd)/sortperm"
