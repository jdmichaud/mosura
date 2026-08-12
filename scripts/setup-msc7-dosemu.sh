#!/usr/bin/env bash
# setup-msc7-dosemu.sh — stage Microsoft C/C++ 7.0's DOS run-time libraries so the
# `msc-7.0-*` FID columns can be rebuilt. Sibling of setup-metaware-dosemu.sh and
# setup-watcom-dosemu.sh.
#
# Why this is not just a `7z x`: the media ships every file KWAJ-compressed with a `$` as the
# last extension character (`LIB/SLIBCR.LI$`). Nothing on a modern Linux box here expands KWAJ —
# 7z refuses it ("Can't open as archive"), and msexpand/cabextract are not installed — but
# **Microsoft's own DECOMP.EXE is on the media**, on the profiler disk, and runs fine under
# dosemu2. So the recipe is: pull the compressed libraries and DECOMP.EXE out of the floppy
# images, expand them inside DOS, and rename.
#
#   scripts/setup-msc7-dosemu.sh
#   MSC7_ARCHIVE=/path/to/'Microsoft CC++ 7.0.zip' scripts/setup-msc7-dosemu.sh
#
# Env: MSC7_ARCHIVE (default: the copy under $HOME/software/visual_studio)
#      DOSEMU_C     (default $HOME/.dosemu/drive_c)
#
# Result: $DOSEMU_C/MSC7/LIB/*.LIB — the real-mode DOS run-time, one library per memory model
# (S/M/C/L) plus the math and graphics libraries, which is what rebuild-fid-db.sh expects.
#
# Two things worth knowing:
#   * DECOMP cannot decompress in place, so it writes to a destination directory — and it keeps
#     the SOURCE name there (`slibcr.li$`), rather than restoring the stored original. The rename
#     below is therefore part of the recipe, not tidying.
#   * dosemu writes DOS names in lower case on a case-sensitive host, so the rename globs both.
set -euo pipefail

DEFAULT_ARCHIVE="$HOME/software/visual_studio/microsoft-c-cpp-7.0-3-20-1992-3.5-1.44mb.-7z/Microsoft CC++ 7.0.zip"
ARCHIVE="${MSC7_ARCHIVE:-$DEFAULT_ARCHIVE}"
DC="${DOSEMU_C:-$HOME/.dosemu/drive_c}"
S="$DC/MSC7"

command -v 7z     >/dev/null || { echo "need 7z (p7zip)"; exit 1; }
command -v dosemu >/dev/null || { echo "need dosemu2"; exit 1; }
[ -f "$ARCHIVE" ] || { echo "no archive: $ARCHIVE (set MSC7_ARCHIVE)"; exit 1; }
echo "archive: $ARCHIVE"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
7z x -y -o"$WORK" "$ARCHIVE" >/dev/null 2>&1
imgs=$(find "$WORK" -type f -iname '*.img' | sort)
[ -n "$imgs" ] || { echo "no floppy images inside the archive"; exit 1; }
echo "floppy images: $(echo "$imgs" | wc -l)"

rm -rf "$S"; mkdir -p "$S"

# Microsoft's decompressor, from the profiler disk.
for img in $imgs; do
  7z e -y -o"$S" "$img" DECOMP.EXE >/dev/null 2>&1 || true
  [ -f "$S/DECOMP.EXE" ] && break
done
[ -f "$S/DECOMP.EXE" ] || { echo "DECOMP.EXE not found on any disk"; exit 1; }
echo "DECOMP.EXE: $(stat -c%s "$S/DECOMP.EXE") bytes"

# The real-mode DOS run-time, per memory model, plus math/emulator/graphics.
WANT='LIB/SLIBCR.LI$ LIB/MLIBCR.LI$ LIB/CLIBCR.LI$ LIB/LLIBCR.LI$
      LIB/SLIBFP.LI$ LIB/MLIBFP.LI$ LIB/CLIBFP.LI$ LIB/LLIBFP.LI$
      LIB/SLIBFA.LI$ LIB/MLIBFA.LI$ LIB/CLIBFA.LI$ LIB/LLIBFA.LI$
      LIB/EM.LI$ LIB/87.LI$ LIB/GRAPHICS.LI$ LIB/LIBH.LI$'
n=0
for img in $imgs; do
  for w in $WANT; do
    if 7z e -y -o"$S" "$img" "$w" >/dev/null 2>&1 && [ -f "$S/$(basename "$w")" ]; then
      n=$((n + 1))
    fi
  done
done
echo "compressed libraries staged: $n"

# Expand inside DOS. `-f` forces overwrite; the destination must differ from the source.
bat="$DC/MSC7DEC.BAT"
{
  echo "@echo off"
  echo "C:"
  echo "cd \\MSC7"
  echo "md LIB"
  echo "DECOMP -f *.LI\$ C:\\MSC7\\LIB > C:\\MSC7DEC.OUT"
  echo "dir C:\\MSC7\\LIB >> C:\\MSC7DEC.OUT"
} > "$bat"
dosemu -td -I '$_hogthreshold = (0)' -E "C:\\MSC7DEC.BAT" >/dev/null 2>&1 || true

LIB="$(ls -d "$S"/[Ll][Ii][Bb] 2>/dev/null | head -1)"
[ -n "$LIB" ] || { echo "FAILED: DECOMP produced no LIB directory; see $DC/MSC7DEC.OUT"; exit 1; }

# DECOMP keeps the source name in the destination; restore the real extension.
( cd "$LIB"
  for f in *.li\$ *.LI\$; do
    [ -f "$f" ] || continue
    mv -f "$f" "$(echo "${f%.*}" | tr 'a-z' 'A-Z').LIB"
  done )

echo
echo "expanded into $LIB:"
ls "$LIB" | sed 's/^/  /'
bad=0
for f in "$LIB"/*.LIB; do
  [ "$(head -c1 "$f" | xxd -p)" = "f0" ] || { echo "  !! $(basename "$f") is not an OMF library"; bad=1; }
done
[ "$bad" = 0 ] && echo "all are OMF libraries (0xF0 LIBHDR)"
echo
echo "now: scripts/rebuild-fid-db.sh msc"
