#!/usr/bin/env bash
# Extract the runtime libraries from a staged Borland install-disk directory.
#
# THE FINDING THIS SCRIPT ENCODES: Borland's `.CA1`/`.CA2`/`.CA3` installer archives are
# **ordinary ZIPs behind a 4-byte prefix**, split across disks as volumes that simply
# concatenate. `7z` rejects them only because of those four leading bytes. Strip the prefix
# from each volume, append them in order, and it is a readable ZIP.
#
# That matters because the alternative was running each product's INTERACTIVE DOS installer:
# `INSTALL /b` is only a black-and-white colour switch, not a batch mode, and piping keystrokes
# does not reach a DOS program's INT 16h keyboard reads, so the installer just hangs. Borland's
# own UNPACK.COM (1989) recognises the format ("unCrunching") but cannot read this later
# revision, and their UNZIP.EXE rejects it outright.
#
# The pre-4.0 products (Turbo C++ 1.00/1.01/3.0, Borland C++ 2.0) instead ship their runtimes
# as per-memory-model ZIPs — SLIB/CLIB/MLIB/LLIB/HLIB — which need no unpacking at all.
#
# A raw CD image (`.bin`) is not readable by 7z directly: C++ Builder 5's is Mode 2 Form 1, so
# each 2352-byte sector is 12 sync + 4 header + 8 subheader + 2048 data + 280 ECC. Slice bytes
# 24..2072 out of every sector to get an ISO. (Mode 1 would be offset 16; the sector header's
# 4th byte says which.)
#
# Usage: extract-borland-ca.sh <staged-disk-dir> <output-dir>
#   Stage first with:  7z e -y -o<dir> <each .img/.iso/.bin>
set -uo pipefail
SRC="$1"; OUT="$2"; mkdir -p "$OUT"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
for base in $(ls "$SRC" 2>/dev/null | grep -oiE "^[A-Z0-9_]+\.CA" | sed 's/\.[Cc][Aa]$//' | sort -u); do
  parts=$(ls "$SRC/$base".[Cc][Aa]* 2>/dev/null | sort -V)
  [ -n "$parts" ] || continue
  : > "$tmp/$base.zip"
  for p in $parts; do tail -c +5 "$p" >> "$tmp/$base.zip"; done
  7z e -y -o"$OUT" "$tmp/$base.zip" '*.lib' '*.LIB' >/dev/null 2>&1
done
# Plain ZIPs on the same disks — the pre-4.0 products ship their runtimes as per-memory-model
# archives (SLIB/CLIB/MLIB/LLIB/HLIB) rather than in .CA files. One 7z call per archive: given
# several, it only processes the first.
for z in "$SRC"/*.[Zz][Ii][Pp]; do
  [ -f "$z" ] || continue
  7z e -y -o"$OUT" "$z" '*.lib' '*.LIB' >/dev/null 2>&1
done
cp "$SRC"/*.[Ll][Ii][Bb] "$OUT"/ 2>/dev/null
ls "$OUT" | wc -l
