#!/usr/bin/env bash
# setup-metaware-dosemu.sh — stage a historical MetaWare High C/C++ 386 toolchain from its
# archive into the dosemu C: drive, ready to compile. Sibling of setup-watcom-dosemu.sh;
# same conventions (env-located archives, mktemp work dir, optional --compile).
#
# Why this exists: High C is the compiler behind the FlashTek X-32 containers
# (docs/metaware-highc-support.md). Its calling convention and its run-time library signatures
# are both DERIVED FROM THE TOOLCHAIN'S OWN OUTPUT, never from documentation or memory, so
# re-deriving them has to be one command — not an afternoon of rediscovering DOS installer
# trivia. Everything that was painful the first time is encoded here or in
# scripts/kd-install-driver.py.
#
# Usage:
#   scripts/setup-metaware-dosemu.sh <version> [--compile file.c] [--serial NNNNNN]
#   scripts/setup-metaware-dosemu.sh 2.31
#   scripts/setup-metaware-dosemu.sh 3.03 --compile oracle/probes/highc.c
#   scripts/setup-metaware-dosemu.sh 3.04            # runs the packed installer unattended
#
# Env: METAWARE_ARCHIVES (default $HOME/software/MetaWare.Compilers)
#      DOSEMU_C          (default $HOME/.dosemu/drive_c)
#
# Verified end to end: 2.31 -> 9 .LIB; 3.03 -> 39 .LIB + compiles; 3.04 -> 373 files / 23 .LIB.
#
# Packaging differs per version:
#   2.31  uncompressed 1.2 MB floppies       -> plain extract + merge, no installer
#   3.03  highc.zip (already-installed tree) -> plain extract, no installer
#   3.04  MWHC.001-007 + INSTALL.EXE         -> Knowledge Dynamics INSTALL 3.10, driven
#   3.31  MWHC.001-007 + INSTALL.EXE         -> same installer, same recipe
# 3.2 (OS/2) is not supported: it ships HCOS2_1.ZOO for an OS/2 host, the wrong target for
# x86-32 DOS-extended code.
#
# --------------------------------------------------------------------------------------------
# The packed installer: four things had to be true before it would run unattended, and none of
# them are guessable. (The screen/key details live in scripts/kd-install-driver.py.)
#
#   1. SOURCE AND TARGET MUST BE DIFFERENT DOS DRIVES. Staging the volumes under C: and
#      installing to C: fails with "The output drive cannot be the same as the input drive".
#      So the staged volumes are mounted as their own drive with `dosemu -d` (lands on F:).
#   2. ALL SEVEN @DefineDisk BLOCKS MUST BE MERGED INTO ONE. The engine prompts "place Disk #N
#      in drive F:" at every block boundary and re-verifies DISK.ID — which can only ever say
#      disk 1 when all volumes sit in one directory. Unflattened, the install stalls after 25
#      files; flattened, it completes 373. The @BeginLib MWHC.0NN references stay valid.
#   3. @Subdir IS HARDCODED to "\HIGHC", so two versions installed unmodified silently MERGE
#      into one tree. It is rewritten per version (C:\HC231, C:\HC303, ...).
#   4. dosemu creates the target directory LOWER CASE on a case-sensitive host, so anything
#      checking for it must look for both spellings.
# --------------------------------------------------------------------------------------------
set -euo pipefail

VER="${1:?usage: setup-metaware-dosemu.sh <version> [--compile file.c] [--serial NNNNNN]}"
shift || true

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCHIVES="${METAWARE_ARCHIVES:-$HOME/software/MetaWare.Compilers}"
DC="${DOSEMU_C:-$HOME/.dosemu/drive_c}"
COMPILE=""
SERIAL="123456"        # a FORMAT check ("1-nnnnnn"), not a licence check; the distribution's
                       # own note says to enter any number

while [ $# -gt 0 ]; do
  case "$1" in
    --compile) COMPILE="${2:?--compile needs a .c file}"; shift 2;;
    --serial)  SERIAL="${2:?--serial needs 6 digits}"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

command -v 7z      >/dev/null || { echo "need 7z (p7zip)"; exit 1; }
command -v dosemu  >/dev/null || { echo "need dosemu2"; exit 1; }
command -v python3 >/dev/null || { echo "need python3"; exit 1; }
[ -d "$ARCHIVES" ] || { echo "no archive dir: $ARCHIVES (set METAWARE_ARCHIVES)"; exit 1; }

TAG="$(echo "$VER" | tr -d '.')"          # 3.03 -> 303
DOSDIR="HC$TAG"                            # C:\HC303
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

find_archive() { find "$ARCHIVES" -maxdepth 1 -name '*.7z' -print | grep -iE "$1" | head -1; }
case "$VER" in
  2.31) ARCHIVE="$(find_archive 'High C 386 v2\.31')" ;;
  3.03) ARCHIVE="$(find_archive 'v3\.03')" ;;
  3.04) ARCHIVE="$(find_archive 'v3\.04')" ;;
  3.31) ARCHIVE="$(find_archive 'v3\.31')" ;;
  *) echo "unsupported version: $VER (try 2.31, 3.03, 3.04, 3.31)"; exit 2;;
esac
[ -n "${ARCHIVE:-}" ] && [ -f "$ARCHIVE" ] || { echo "no archive for $VER in $ARCHIVES"; exit 1; }
echo "archive: $ARCHIVE"
echo "target : C:\\$DOSDIR"

7z x -y -o"$WORK/raw" "$ARCHIVE" >/dev/null

# resolve the install dir whatever case dosemu used
resolve_dest() {
  for c in "$DC/$DOSDIR" "$DC/$(echo "$DOSDIR" | tr 'A-Z' 'a-z')"; do
    [ -d "$c" ] && { echo "$c"; return; }
  done
}

case "$VER" in
  2.31|3.03)
    DEST="$DC/$DOSDIR"
    rm -rf "$DEST"; mkdir -p "$DEST"
    if [ "$VER" = 2.31 ]; then
      n=0
      while IFS= read -r img; do
        7z x -y -o"$DEST" "$img" >/dev/null 2>&1 || true; n=$((n+1))
      done < <(find "$WORK/raw" -type f -iname 'disk*.img' | sort)
      echo "merged $n uncompressed floppy image(s)"
    else
      z="$(find "$WORK/raw" -type f -iname 'highc.zip' | head -1)"
      [ -n "$z" ] || { echo "highc.zip not found in $ARCHIVE"; exit 1; }
      7z x -y -o"$DEST" "$z" >/dev/null
      echo "extracted already-installed tree from $(basename "$z")"
    fi
    ;;

  3.04|3.31)
    # Stage every volume FLAT into one directory OUTSIDE the C: drive, so it can be mounted as
    # its own DOS drive (requirement 1). MWHC.0NN are uniquely named; only DISK.ID and
    # INSTALL.DAT collide, and disk 1's copies win.
    VOL="$WORK/volumes"; mkdir -p "$VOL"
    n=0
    while IFS= read -r img; do
      t="$WORK/d$n"; mkdir -p "$t"
      7z x -y -o"$t" "$img" >/dev/null 2>&1 || true
      [ "$n" -gt 0 ] && rm -f "$t/DISK.ID" "$t/INSTALL.DAT"
      cp -rn "$t"/* "$VOL"/ 2>/dev/null || true
      rm -rf "$t"; n=$((n+1))
    done < <(find "$WORK/raw" -type f -iname 'disk*.img' | sort)
    echo "staged $n floppy image(s) flat (mounted as F:)"
    [ -f "$VOL/INSTALL.EXE" ] && [ -f "$VOL/INSTALL.DAT" ] \
      || { echo "INSTALL.EXE/INSTALL.DAT missing after staging"; exit 1; }

    # Requirements 2 and 3: merge the disk blocks, retarget @Subdir.
    python3 - "$VOL/INSTALL.DAT" "$DOSDIR" <<'PY'
import re, sys
path, subdir = sys.argv[1], sys.argv[2]
lines = open(path, 'rb').read().split(b'\n')
first_def = last_end = None
for i, l in enumerate(lines):
    u = l.strip().upper()
    if u.startswith(b'@DEFINEDISK') and first_def is None: first_def = i
    if u.startswith(b'@ENDDISK'): last_end = i
out, ndisk = [], 0
for i, l in enumerate(lines):
    u = l.strip().upper()
    if u.startswith(b'@DEFINEDISK'):
        ndisk += 1
        if i == first_def:
            out += [b'@DefineDisk\r', b'\t@Label = "Disk #1"\r']
        continue
    if u.startswith(b'@LABEL') and b'DISK #' in u:      # replaced by the single label above
        continue
    if u.startswith(b'@ENDDISK'):
        if i == last_end: out.append(b'@EndDisk\r')
        continue
    if re.match(rb'\s*@Subdir\s*=', l, re.I):
        out.append(('\t@Subdir = "\\\\%s"\r' % subdir).encode()); continue
    if re.match(rb'\s*@OutDrive\s*=', l, re.I):
        # v3.31 ships "@OutDrive = Z", which leaves the drive-selection list opened on the
        # wrong entry; the widget ignores a typed letter, so Enter accepts the highlighted
        # drive -- F:, the source -- and the engine dies with "The output drive cannot be the
        # same as the input drive". v3.04 ships "= C" and works. Pin it.
        out.append(b'\t@OutDrive = C\r'); continue
    out.append(l)
open(path, 'wb').write(b'\n'.join(out))
print('  INSTALL.DAT: %d disk blocks -> 1, @Subdir -> \\%s' % (ndisk, subdir))
PY

    rm -rf "$DC/$DOSDIR" "$DC/$(echo "$DOSDIR" | tr 'A-Z' 'a-z')"
    echo "running the installer unattended (a few minutes; it unpacks ~10 MB)"
    python3 "$HERE/kd-install-driver.py" \
      --mount "$VOL" --dest "$DC/$DOSDIR" --serial "$SERIAL" \
      --screens "/tmp/kd-install-$TAG.txt" || {
        echo "installer driver failed; screen transcript: /tmp/kd-install-$TAG.txt" >&2
        exit 3
      }
    ;;
esac

DEST="$(resolve_dest)"
[ -n "$DEST" ] || { echo "FAILED: no install directory for $DOSDIR" >&2; exit 1; }

echo
echo "installed: $DEST"
find "$DEST" -maxdepth 1 -mindepth 1 -printf '  %f\n' | sort
libs=$(find "$DEST" -iname '*.lib' | wc -l)
files=$(find "$DEST" -type f | wc -l)
echo "  $files files, $libs .LIB, $(du -sh "$DEST" | cut -f1)"
[ "$libs" -gt 0 ] || { echo "  WARNING: no libraries — the FID databases need these"; }

# Optional: compile a probe to an OMF .OBJ, which is all the cspec derivation needs — the
# calling convention is visible in the object, so no linker is required.
if [ -n "$COMPILE" ]; then
  [ -f "$COMPILE" ] || { echo "no such file: $COMPILE"; exit 1; }
  # DOS 8.3: a longer or hyphenated stem is simply not openable by the compiler, which reports
  # only "Unable to proceed / Aborting(21)" and looks like a broken toolchain install.
  stem="$(basename "${COMPILE%.*}" | tr -cd 'A-Za-z0-9' | cut -c1-8)"
  [ -n "$stem" ] || stem="PROBE"
  cp "$COMPILE" "$DC/$stem.C"
  COMPILE="$stem.C"
  dosdest="$(basename "$DEST" | tr 'a-z' 'A-Z')"
  bat="$DC/MWCC$TAG.BAT"
  {
    echo "@echo off"
    echo "set PATH=C:\\$dosdest\\BIN;%PATH%"
    echo "set HCDIR=C:\\$dosdest"
    echo "set HCINCLUDE=C:\\$dosdest\\INC"
    echo "C:\\$dosdest\\BIN\\HC386.EXE -c C:\\$COMPILE > C:\\MWCC$TAG.OUT"
    echo "dir C:\\$stem.OBJ >> C:\\MWCC$TAG.OUT"
  } > "$bat"
  dosemu -td -E "C:\\$(basename "$bat")" >/dev/null 2>&1 || true
  echo
  echo "compile log:"; sed 's|^|  |' "$DC/MWCC$TAG.OUT" 2>/dev/null || echo "  (no log)"
  obj="$(find "$DC" -maxdepth 1 -iname "$stem.obj" | head -1)"
  [ -n "$obj" ] && echo "object: $obj ($(stat -c%s "$obj") bytes)" || echo "object: NOT PRODUCED"
fi
