#!/usr/bin/env bash
# Rebuild the committed FID recall probes (oracle/fid/binaries/*).
#
# Regeneration-only: `cargo test` reads the committed binaries and never runs this. The
# probes are OUR program (oracle/fid/src/crtprobe.c) compiled against a real runtime, so the
# expected function names come from source we wrote — no Ghidra, no third-party binary.
#
# Toolchains are located by environment variable with a sensible default, per the portability
# rule in docs/dependencies.md.
#
#   ./scripts/build-fid-probes.sh            # every column whose toolchain is present
#   ./scripts/build-fid-probes.sh msvc6      # one column
set -uo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

SRC="$REPO/oracle/fid/src/crtprobe.c"
OUT="$REPO/oracle/fid/binaries"
mkdir -p "$OUT"

WANT="${1:-all}"
built=0

# --- MSVC 6 (Visual Studio 98), x86-32 PE, static CRT (/MT) --------------------------------
# Ghidra's vsOlder_x86 database covers VS 1998, so this column needs no ingest of our own.
# CL.EXE is a 32-bit Windows binary: wine runs it, dosemu cannot.
VC98="${MOSURA_VC98:-/data/msvc/VC98}"
if [ "$WANT" = all ] || [ "$WANT" = msvc6 ]; then
	if [ -x "$VC98/BIN/CL.EXE" ] && command -v wine >/dev/null 2>&1; then
		work="$(mktemp -d)"
		cp "$SRC" "$work/crtprobe.c"
		( cd "$work" && WINEDEBUG=-all wine "$VC98/BIN/CL.EXE" /nologo /O2 /MT \
			/I "$(winepath -w "$VC98/INCLUDE" 2>/dev/null || echo "Z:${VC98}/INCLUDE")" \
			crtprobe.c /link \
			/LIBPATH:"$(winepath -w "$VC98/LIB" 2>/dev/null || echo "Z:${VC98}/LIB")" \
			/OUT:crtprobe.exe ) > "$work/build.log" 2>&1
		if [ -f "$work/crtprobe.exe" ]; then
			cp "$work/crtprobe.exe" "$OUT/crtprobe.msvc6-x86-32.exe"
			echo "  msvc6-x86-32   $(stat -c%s "$OUT/crtprobe.msvc6-x86-32.exe") bytes"
			built=$((built + 1))
		else
			echo "  msvc6-x86-32   FAILED (see $work/build.log)"
		fi
		rm -rf "$work"
	else
		echo "  msvc6-x86-32   skipped (need wine + \$MOSURA_VC98/BIN/CL.EXE)"
	fi
fi

# --- Watcom 10.0a, x86-32 DOS/4G LE, static clib3r ------------------------------------------
#
# Built from oracle/fid/src/watprobe.c, NOT crtprobe.c — see that file's header for why (Watcom
# 10.0a has no 64-bit integer type, and crtprobe's call set could not tell the pre- and post-OMF-fix
# databases apart).
#
# Needs dosemu2 and a Watcom 10.0a staged at C:\WAT100A (scripts/setup-watcom-dosemu.sh 10.0a).
# That script stages the dir holding WCC386 (BINB); the DOS-hosted WLINK.EXE lives in the sibling
# BIN, and the linker resolves `system dos4g` through $WATCOM/binb/wlsystem.lnk — both are staged
# here rather than assumed.
if [ "$WANT" = all ] || [ "$WANT" = watcom ]; then
	DC="${DOSEMU_C:-$HOME/.dosemu/drive_c}"
	if command -v dosemu >/dev/null && [ -x "$DC/WAT100A/BIN/WCC386.EXE" ]; then
		iso=$(ls /data/w10a/*.ISO /data/tools/watcom/*10A*.ISO 2>/dev/null | head -1)
		for f in BIN/WLINK.EXE BINB/WLSYSTEM.LNK; do
			base=$(basename "$f")
			if [ ! -f "$DC/WAT100A/BIN/$base" ] && [ -n "$iso" ]; then
				7z e -y -o"$DC/WAT100A/BIN" "$iso" "WATCOM/$f" >/dev/null 2>&1 || true
			fi
		done
		mkdir -p "$DC/WAT100A/binb"
		[ -f "$DC/WAT100A/BIN/WLSYSTEM.LNK" ] &&
			cp -f "$DC/WAT100A/BIN/WLSYSTEM.LNK" "$DC/WAT100A/binb/wlsystem.lnk"

		work="$DC/fidprobe"; rm -rf "$work"; mkdir -p "$work"
		cp oracle/fid/src/watprobe.c "$work/WATPROBE.C"
		# DOS COMMAND.COM has no `&&` and no `2>&1`: the steps go in a batch file, one redirect each.
		printf '@echo off\r\nset WATCOM=C:\\WAT100A\r\nset PATH=C:\\WAT100A\\BIN\r\nset INCLUDE=C:\\WAT100A\\H\r\nc:\r\ncd \\fidprobe\r\nwcc386 -3r -otexan WATPROBE.C >BUILD.TXT\r\nwlink system dos4g file watprobe name watprobe.exe >>BUILD.TXT\r\n' \
			> "$work/MKW.BAT"
		dosemu -td -E 'c:\fidprobe\mkw.bat' >/dev/null 2>&1
		if [ -s "$work/watprobe.exe" ]; then
			cp "$work/watprobe.exe" "$OUT/watprobe.watcom10.0a-x86-32.exe"
			echo "  watcom10.0a-x86-32  $(stat -c%s "$OUT/watprobe.watcom10.0a-x86-32.exe") bytes"
			built=$((built + 1))
		else
			echo "  watcom10.0a-x86-32  FAILED (see $work/BUILD.TXT)"
		fi
	else
		echo "  watcom10.0a-x86-32  skipped (need dosemu2 + C:\\WAT100A — setup-watcom-dosemu.sh 10.0a)"
	fi
fi

# --- Borland C++ 4.5, x86-16 MZ, two memory models ------------------------------------------
#
# Built from oracle/fid/src/bcprobe.c. TWO models on purpose: the model changes the code (which is
# why Borland has 64 databases), and a far call is segment-relative rather than self-relative, so
# the large model is the only cover for the 16:16 far-pointer fixup.
#
# The .map is committed next to each .exe and is the gate's ground truth for precision — see
# tests/fid_borland_identify.rs. Hence `-M`.
if [ "$WANT" = all ] || [ "$WANT" = borland ]; then
	DC="${DOSEMU_C:-$HOME/.dosemu/drive_c}"
	BC="${MOSURA_BC45:-/data/borland/BC45}"
	if command -v dosemu >/dev/null && [ -x "$BC/BIN/BCC.EXE" ]; then
		work="$DC/bcprobe"; rm -rf "$work"; mkdir -p "$work/INCLUDE" "$work/LIB"
		cp -r "$BC/BIN" "$work/BIN"
		cp "$BC"/INCLUDE/*.H "$work/INCLUDE/" 2>/dev/null
		# Only the 16-bit runtime pieces, not the whole 35 MB LIB tree.
		cp "$BC"/LIB/C?.LIB "$BC"/LIB/MATH?.LIB "$BC"/LIB/C0*.OBJ "$BC"/LIB/EMU.LIB \
			"$BC"/LIB/FP87.LIB "$work/LIB/" 2>/dev/null
		cp oracle/fid/src/bcprobe.c "$work/BCPROBE.C"
		for m in s:cs:BCPS l:cl:BCPL; do
			model=${m%%:*}; rest=${m#*:}; variant=${rest%%:*}; stem=${rest#*:}
			# TLINK must be on PATH; BCC shells out to it by name.
			printf '@echo off\r\nc:\r\ncd \\bcprobe\r\nset PATH=C:\\BCPROBE\\BIN\r\nBIN\\BCC.EXE -m%s -O2 -M -IC:\\BCPROBE\\INCLUDE -LC:\\BCPROBE\\LIB -e%s.EXE BCPROBE.C >BUILD.TXT\r\n' \
				"$model" "$stem" > "$work/MK.BAT"
			dosemu -td -E 'c:\bcprobe\mk.bat' >/dev/null 2>&1
			low=$(echo "$stem" | tr '[:upper:]' '[:lower:]')
			if [ -s "$work/$low.exe" ]; then
				cp "$work/$low.exe" "$OUT/bcprobe.bc4.5-$variant-x86-16.exe"
				cp "$work/$low.map" "$OUT/bcprobe.bc4.5-$variant-x86-16.map"
				echo "  borland bc4.5-$variant  $(stat -c%s "$OUT/bcprobe.bc4.5-$variant-x86-16.exe") bytes"
				built=$((built + 1))
			else
				echo "  borland bc4.5-$variant  FAILED (see $work/BUILD.TXT)"
			fi
		done
	else
		echo "  borland bc4.5       skipped (need dosemu2 + \$MOSURA_BC45/BIN/BCC.EXE)"
	fi
fi

# --- Further columns land with Stage 7 -----------------------------------------------------
# gcc/glibc x86-64 + x86-32 + aarch64 + riscv64 + m68k, sdcc z80. Each needs a signature
# database built by our own ingest first (Stage 6).

echo "built $built probe(s) into oracle/fid/binaries/"
