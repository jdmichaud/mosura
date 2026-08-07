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
# Plain ZIPs and loose libs on the same disks
7z e -y -o"$OUT" "$SRC"/*.[Zz][Ii][Pp] '*.lib' '*.LIB' >/dev/null 2>&1
cp "$SRC"/*.[Ll][Ii][Bb] "$OUT"/ 2>/dev/null
ls "$OUT" | wc -l
