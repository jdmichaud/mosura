#!/usr/bin/env bash
# setup-metaware-dosemu.sh — stage a historical MetaWare High C/C++ 386 toolchain from its
# archive into the dosemu C: drive, ready to compile. Sibling of setup-watcom-dosemu.sh;
# same conventions (env-located archives, mktemp work dir, optional --compile).
#
# Why this exists: High C is the compiler behind the FlashTek X-32 containers
# (docs/metaware-highc-support.md). Its calling convention and its run-time library
# signatures are both DERIVED FROM THE TOOLCHAIN'S OWN OUTPUT, never from documentation or
# memory, so re-deriving them has to be a one-command operation.
#
# Usage:
#   scripts/setup-metaware-dosemu.sh <version> [--compile file.c] [--interactive]
#   scripts/setup-metaware-dosemu.sh 3.03                    # stage only
#   scripts/setup-metaware-dosemu.sh 3.03 --compile probe.c   # stage + compile to .OBJ
#   scripts/setup-metaware-dosemu.sh 3.04 --interactive       # drive the installer by hand
#
# Env: METAWARE_ARCHIVES (default $HOME/software/MetaWare.Compilers)
#      DOSEMU_C          (default $HOME/.dosemu/drive_c)
#
# Packaging differs per version, and only two of the four need the DOS installer at all:
#
#   2.31  uncompressed 1.2 MB floppies       -> plain extract + merge, no installer   [AUTOMATED]
#   3.03  highc.zip (already-installed tree) -> plain extract, no installer           [AUTOMATED]
#   3.04  MWHC.001-007 + INSTALL.EXE         -> Knowledge Dynamics INSTALL 3.10.00    [NEEDS --interactive]
#   3.31  MWHC.001-007 + INSTALL.EXE         -> same installer, byte-identical        [NEEDS --interactive]
#
# 3.2 (OS/2) is not supported: it ships HCOS2_1.ZOO for an OS/2 host, the wrong target for
# x86-32 DOS-extended code.
#
# ---------------------------------------------------------------------------------------
# What the packed installer needs, and why it is not fully automated (all learned the hard
# way; do not re-derive):
#
#   screen                        key                     note
#   ----------------------------- ----------------------- ----------------------------------
#   welcome / @pause              CR
#   Specify Compiler Drive        the drive LETTER, CR    CR alone NEVER completes this list
#   Specify Compiler Directory    CR                      accepts @Subdir from INSTALL.DAT
#   Verify Compiler Directory     SPACE then CR           checkbox defaults to NO; CR loops
#   Enter Serial Number           any 6 digits, CR        a FORMAT check, not a licence check
#                                                         ("1-nnnnnn"); the distribution's own
#                                                         note says to enter any number
#   Choose Installation Options   arrows + SPACE + CR     *** THE BLOCKER, see below ***
#
#   1. DOS's BIOS keyboard buffer is 16 bytes. Piping a burst of CRs loses all but the first
#      few, so early screens consume them and later ones see nothing. Keys must be fed one
#      screen at a time, on screen TRANSITIONS, not on a poll tick — polling re-sends leak
#      into the next screen, which is how the drive letter ended up typed into the
#      subdirectory field, building C:\C\C\C\HC304 and looping forever.
#   2. "Choose Installation Options" draws its Yes/No list in a direct-video sub-window, so
#      its state never reaches stdout, and it does not accept SPACE or CR from a pipe. It
#      wants arrow keys, and an arrow key cannot be delivered: as an ANSI sequence it starts
#      with ESC, and the installer treats ESC as "STOP the installation" and exits.
#      => one interactive run is required. Afterwards the installed tree is a normal
#         directory and can be archived/reused forever; this is a one-time cost per version.
# ---------------------------------------------------------------------------------------
set -euo pipefail

VER="${1:?usage: setup-metaware-dosemu.sh <version> [--compile file.c] [--interactive]}"
shift || true

ARCHIVES="${METAWARE_ARCHIVES:-$HOME/software/MetaWare.Compilers}"
DC="${DOSEMU_C:-$HOME/.dosemu/drive_c}"
COMPILE=""
INTERACTIVE=0
SERIAL="123456"

while [ $# -gt 0 ]; do
  case "$1" in
    --compile)     COMPILE="${2:?--compile needs a .c file}"; shift 2;;
    --interactive) INTERACTIVE=1; shift;;
    --serial)      SERIAL="${2:?--serial needs 6 digits}"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

command -v 7z     >/dev/null || { echo "need 7z (p7zip)"; exit 1; }
command -v dosemu >/dev/null || { echo "need dosemu2"; exit 1; }
[ -d "$ARCHIVES" ] || { echo "no archive dir: $ARCHIVES (set METAWARE_ARCHIVES)"; exit 1; }

TAG="$(echo "$VER" | tr -d '.')"          # 3.03 -> 303
DOSDIR="HC$TAG"                            # C:\HC303
DEST="$DC/$DOSDIR"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# Each version installs to its OWN directory. Deliberate: the packed installer hardcodes
# @Subdir = "\HIGHC", so two versions installed unmodified silently MERGE into one tree.
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
echo "target : C:\\$DOSDIR  ($DEST)"

7z x -y -o"$WORK/raw" "$ARCHIVE" >/dev/null
rm -rf "$DEST"; mkdir -p "$DEST"

case "$VER" in
  2.31)
    n=0
    while IFS= read -r img; do
      7z x -y -o"$DEST" "$img" >/dev/null 2>&1 || true; n=$((n+1))
    done < <(find "$WORK/raw" -type f -iname 'disk*.img' | sort)
    echo "merged $n uncompressed floppy image(s)"
    ;;

  3.03)
    z="$(find "$WORK/raw" -type f -iname 'highc.zip' | head -1)"
    [ -n "$z" ] || { echo "highc.zip not found in $ARCHIVE"; exit 1; }
    7z x -y -o"$DEST" "$z" >/dev/null
    echo "extracted already-installed tree from $(basename "$z")"
    ;;

  3.04|3.31)
    # Stage all disks FLAT into one source dir so the installer never asks for a swap:
    # MWHC.00N are uniquely named, only DISK.ID / INSTALL.DAT collide (disk 1 wins).
    SRC="$DC/MWSRC$TAG"
    rm -rf "$SRC"; mkdir -p "$SRC"
    n=0
    while IFS= read -r img; do
      t="$(mktemp -d)"
      7z x -y -o"$t" "$img" >/dev/null 2>&1 || true
      [ "$n" -gt 0 ] && rm -f "$t/DISK.ID" "$t/INSTALL.DAT"
      cp -rn "$t"/* "$SRC"/ 2>/dev/null || true
      rm -rf "$t"; n=$((n+1))
    done < <(find "$WORK/raw" -type f -iname 'disk*.img' | sort)
    echo "staged $n floppy image(s) flat into C:\\MWSRC$TAG"
    [ -f "$SRC/INSTALL.EXE" ] || { echo "INSTALL.EXE missing after staging"; exit 1; }

    # Point the hardcoded install subdir at this version's own directory.
    if [ -f "$SRC/INSTALL.DAT" ]; then
      sed -i "s|@Subdir[[:space:]]*=[[:space:]]*\"\\\\\\\\HIGHC\"|@Subdir = \"\\\\\\\\$DOSDIR\"|I" "$SRC/INSTALL.DAT"
    fi
    rmdir "$DEST" 2>/dev/null || true    # let the installer create it

    if [ "$INTERACTIVE" = 1 ]; then
      cat <<EOF

Launching INSTALL.EXE interactively. Answer the screens like this:

    welcome / any [more] screen    Enter
    Specify Compiler Drive         type  C   then Enter
    Specify Compiler Directory     Enter                (accepts \\$DOSDIR)
    Verify Compiler Directory      SPACE to make it Yes, then Enter
    Enter Serial Number            $SERIAL              then Enter
    Choose Installation Options    arrow to "Install the C/C++ compiler",
                                   SPACE until it reads Yes, then Enter
    then let it unpack MWHC.001..007 (no disk swapping - all volumes are staged)

Do NOT press Esc: the installer treats it as "stop the installation".

EOF
      read -r -p "press Enter to launch..." _ || true
      dosemu -t -E "C:\\MWSRC$TAG\\INSTALL.EXE" || true
    else
      # Automated best effort: drives every screen up to the checkbox sub-window, which
      # cannot be driven from a pipe (see the header). Reports where it stopped.
      LOG="$WORK/install.log"; FIFO="$WORK/keys"
      mkfifo "$FIFO"
      dosemu -td -E "C:\\MWSRC$TAG\\INSTALL.EXE" < "$FIFO" > "$LOG" 2>&1 &
      DPID=$!
      exec 3>"$FIFO"
      # never fail: with `set -e`, a command substitution that exits non-zero (grep finding
      # nothing on the first tick, before any screen has been drawn) would kill the script.
      banner() { tr -d '\r' < "$LOG" 2>/dev/null | { grep -oE -- '---> [^<]+ <---' || true; } | tail -1 | tr -s ' '; }
      prev=""
      for _ in $(seq 1 40); do
        sleep 2
        kill -0 "$DPID" 2>/dev/null || break
        b="$(banner)"
        if [ "$b" != "$prev" ]; then
          prev="$b"
          case "$b" in
            *"Specify Compiler Drive"*)      printf 'C' >&3; sleep 1; printf '\r' >&3 ;;
            *"Verify Compiler Directory"*)   printf ' ' >&3; sleep 1; printf '\r' >&3 ;;
            *"Enter Serial Number"*)         printf '%s' "$SERIAL" >&3; sleep 1; printf '\r' >&3 ;;
            *"Choose Installation Options"*) break ;;
            *)                               printf '\r' >&3 ;;
          esac
        else
          printf '\r' >&3
        fi
      done
      exec 3>&-; kill "$DPID" 2>/dev/null || true; wait "$DPID" 2>/dev/null || true
      echo
      echo "Reached: $(banner)"
      echo "The option checkbox is a direct-video sub-window and needs arrow keys, which"
      echo "cannot be piped (ESC aborts the installer). Re-run with --interactive:"
      echo "    scripts/setup-metaware-dosemu.sh $VER --interactive"
      exit 3
    fi
    rm -rf "$SRC"
    ;;
esac

[ -d "$DEST" ] || { echo "FAILED: $DEST was not created" >&2; exit 1; }

echo
echo "installed tree:"
find "$DEST" -maxdepth 1 -mindepth 1 -printf '  %f\n' | sort
libs=$(find "$DEST" -iname '*.lib' | wc -l)
echo "  (.LIB files: $libs)"
[ "$libs" -gt 0 ] || echo "  WARNING: no libraries — the FID databases need these"

# Optional: compile a probe to an OMF .OBJ, which is all the cspec derivation needs — the
# calling convention is visible in the object, so no linker is required.
if [ -n "$COMPILE" ]; then
  [ -f "$COMPILE" ] || { echo "no such file: $COMPILE"; exit 1; }
  stem="$(basename "${COMPILE%.*}")"
  cp "$COMPILE" "$DC/$(basename "$COMPILE")"
  bat="$DC/MWCC$TAG.BAT"
  {
    echo "@echo off"
    echo "set PATH=C:\\$DOSDIR\\BIN;%PATH%"
    echo "set HCDIR=C:\\$DOSDIR"
    echo "set HCINCLUDE=C:\\$DOSDIR\\INC"
    echo "C:\\$DOSDIR\\BIN\\HC386.EXE -c C:\\$(basename "$COMPILE") > C:\\MWCC$TAG.OUT"
    echo "dir C:\\$stem.OBJ >> C:\\MWCC$TAG.OUT"
  } > "$bat"
  dosemu -td -E "C:\\$(basename "$bat")" >/dev/null 2>&1 || true
  echo
  echo "compile log:"; sed 's|^|  |' "$DC/MWCC$TAG.OUT" 2>/dev/null || echo "  (no log)"
  obj="$(find "$DC" -maxdepth 1 -iname "$stem.obj" | head -1)"
  [ -n "$obj" ] && echo "object: $obj ($(stat -c%s "$obj") bytes)" || echo "object: NOT PRODUCED"
fi
