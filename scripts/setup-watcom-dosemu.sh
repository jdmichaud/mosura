#!/usr/bin/env bash
# setup-watcom-dosemu.sh — stage a historical DOS-hosted Watcom C/386 from its archive
# into the dosemu C: drive, ready to compile. This is the codegen-fingerprint toolchain
# (docs/watcom-codegen-fingerprint.md): each wcc386 revision makes revision-specific codegen
# choices, and the committed oracle/codegen-probes/watcom/<rev>.{obj,code} ground truth is
# produced with exactly this setup. The archives keep getting relocated by disk cleanups —
# this script turns any surviving archive back into a working compiler on demand.
#
# Usage:
#   scripts/setup-watcom-dosemu.sh <version> [archive.7z]
#   scripts/setup-watcom-dosemu.sh 10.6                 # auto-find the archive by version
#   scripts/setup-watcom-dosemu.sh 10.6 --compile a.c   # also compile a.c → C:\<stem>.obj
#
# Env: WATCOM_ARCHIVES (default /data/tools/watcom), DOSEMU_C (default ~/.dosemu/drive_c).
#
# Scope: the ISO-based revisions (10.0/10.0a/10.5/10.6/11.0) whose DOS-extender host lives in
# BINW or BINB. The floppy-set revisions (7.0/8.5a/9.01) ship the runtime packed in .WPK and
# need INSTALL.EXE run under dosemu first — out of scope here (see the A4 Stage 2 task note).
set -euo pipefail

VER="${1:?usage: setup-watcom-dosemu.sh <version> [archive.7z] [--compile file.c]}"
shift || true
ARCHIVES="${WATCOM_ARCHIVES:-/data/tools/watcom}"
DC="${DOSEMU_C:-$HOME/.dosemu/drive_c}"
KEY="WAT$(echo "$VER" | tr -d '.[:space:]' | tr '[:lower:]' '[:upper:]')"   # 10.0a -> WAT100A
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# optional explicit archive, and optional --compile
ARCHIVE=""; COMPILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --compile) COMPILE="${2:?--compile needs a .c file}"; shift 2;;
    *.7z|*.iso|*.ISO) ARCHIVE="$1"; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

command -v 7z >/dev/null || { echo "need 7z (p7zip)"; exit 1; }
command -v dosemu >/dev/null || { echo "need dosemu2"; exit 1; }

# 1. locate the archive for this version (most specific match on the version token)
if [ -z "$ARCHIVE" ]; then
  ARCHIVE=$(ls "$ARCHIVES"/*"$VER"*.7z "$ARCHIVES"/*"$VER"*.iso 2>/dev/null | head -1 || true)
fi
[ -n "$ARCHIVE" ] && [ -f "$ARCHIVE" ] || { echo "no archive for '$VER' under $ARCHIVES"; exit 1; }
echo "[watcom] $VER  <-  $ARCHIVE"

# 2. the .7z wraps an .iso; pull the ISO out (a bare .iso is used as-is)
case "$ARCHIVE" in
  *.7z)
    # Spool the listing to a file and read from the file: piping a large listing through an
    # early-closing reader (head/awk-exit) SIGPIPEs the writer (exit 141), and a `printf "$var"`
    # writer is a shell builtin whose death fails the command substitution under `set -e`.
    # -slt gives "Path = <full path>" records, so ISO names containing spaces survive.
    7z l -slt "$ARCHIVE" > "$WORK/alist.txt"
    iso_entry=$(sed -n 's/^Path = //p' "$WORK/alist.txt" | grep -iE '\.iso$' | head -1)
    [ -n "$iso_entry" ] || { echo "no .iso inside $ARCHIVE (floppy set? see A4-S2)"; exit 1; }
    7z e "$ARCHIVE" "$iso_entry" -o"$WORK" -y >/dev/null
    ISO="$WORK/$(basename "$iso_entry")" ;;
  *) ISO="$ARCHIVE" ;;
esac

# 3. find the DOS-extender-hosted compiler: a real (>100 KB) WCC386.EXE under BINW/BINB,
#    never the tiny BINNT/BIN95/BINP host stubs. Its dir is the toolchain BIN; H/LIB386 are
#    siblings under the same root (root is "" for a flat ISO, "WATCOM" for a nested one).
7z l "$ISO" > "$WORK/ilist.txt"   # spool to file; awk reads the file directly (no pipe → no SIGPIPE)
# Pick the LARGEST BINW/BINB WCC386.EXE — the real DOS-extender host. This beats a fixed size
# threshold: excludes the ~9 KB BINNT/BIN95 host stubs, yet still catches 10.5's slim 64 KB build
# (10.6's is 567 KB) without a magic constant that happens to straddle them.
wcc=$(awk 'toupper($NF) ~ /(BINW|BINB)\/WCC386\.EXE$/ && $(NF-2)+0 > sz { sz=$(NF-2); best=$NF } END{ if (sz>20000) print best }' "$WORK/ilist.txt")
[ -n "$wcc" ] || { echo "no DOS-host WCC386.EXE (BINW/BINB) in $ISO"; exit 1; }
bindir=$(dirname "$wcc"); root=$(dirname "$bindir"); [ "$root" = "." ] && root=""
echo "[watcom] host BIN = ${wcc%/*}   root = ${root:-<flat>}"

# 4. extract BIN + H + LIB386 into a fresh versioned dosemu dir (BINW/BINB normalised to BIN)
dest="$DC/$KEY"; rm -rf "$dest"; mkdir -p "$dest"
pick() { 7z x "$ISO" -o"$WORK/x" "$1" -y >/dev/null 2>&1 || true; }
pick "$bindir/*"
[ -n "$root" ] && { pick "$root/H/*"; pick "$root/LIB386/*"; } || { pick "H/*"; pick "LIB386/*"; }
cp -r "$WORK/x/$bindir" "$dest/BIN"
for d in H LIB386; do
  src="$WORK/x/${root:+$root/}$d"; [ -d "$src" ] && cp -r "$src" "$dest/$d"
done
echo "[watcom] staged -> C:\\$KEY  ($(ls "$dest/BIN" | wc -l) BIN files, H=$( [ -d "$dest/H" ] && echo yes || echo no ))"

# 5. emit a compile BAT (DOS command.com: CRLF, single '>' redirect — no 2>&1)
bat_of() {  # $1 = C source stem (8.3, uppercased)
  printf '@echo off\r\nset WATCOM=C:\\%s\r\nset PATH=C:\\%s\\BIN\r\nset INCLUDE=C:\\%s\\H\r\nwcc386 %s.C >WCCOUT.TXT\r\n' \
    "$KEY" "$KEY" "$KEY" "$1"
}

if [ -n "$COMPILE" ]; then
  [ -f "$COMPILE" ] || { echo "no such source: $COMPILE"; exit 1; }
  stem=$(basename "$COMPILE" .c); STEM=$(echo "$stem" | tr '[:lower:]' '[:upper:]' | cut -c1-8)
  cp "$COMPILE" "$DC/$STEM.C"
  bat_of "$STEM" > "$DC/MK$KEY.BAT"
  ( cd "$DC" && timeout 120 dosemu -dumb -quiet -E "MK$KEY.BAT" >/dev/null 2>&1 ) || true
  # dosemu names the object after the 8.3 source stem ($STEM), commonly lowercased
  obj=$(ls "$DC/$(echo "$STEM" | tr '[:upper:]' '[:lower:]').obj" "$DC/$STEM.OBJ" 2>/dev/null | head -1 || true)
  echo "[watcom] --- wcc386 output ---"; tr -d '\r' < "$DC/WCCOUT.TXT" 2>/dev/null | sed 's/^/    /'
  [ -n "$obj" ] && echo "[watcom] object: $obj" || { echo "[watcom] no object produced"; exit 1; }
else
  bat_of "CG" > "$DC/MK$KEY.BAT"
  echo "[watcom] ready. put a source at C:\\CG.C and run:  dosemu -dumb -quiet -E MK$KEY.BAT"
fi
