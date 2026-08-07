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

# --- Further columns land with Stage 7 -----------------------------------------------------
# Watcom (clib3r), gcc/glibc x86-64 + x86-32 + aarch64 + riscv64 + m68k, sdcc z80, Borland.
# Each needs a signature database built by our own ingest first (Stage 6); the probe source
# above is already written to compile under all of them.

echo "built $built probe(s) into oracle/fid/binaries/"
