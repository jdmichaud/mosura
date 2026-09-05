#!/usr/bin/env bash
# Build FID signature databases for a Borland / Turbo C runtime library.
#
# Two routes, and the second is why this script exists:
#
#   objects  — ingest the library's OMF modules directly. Names come from PUBDEF, but a
#              cross-module call is UNLINKED: it still reads `call 0000:0000`, because the
#              real target lives in a FIXUPP record only a linker consumes. Self-relative
#              (near) fixups are patched by the loader; far ones are not, so the far memory
#              models end up with very few caller/callee relations.
#
#   linked   — let the vendor's own linker resolve everything. `omf-uber` generates a program
#              referencing every C-callable public in the library, TCC/BCC compiles it, TLINK
#              links it, and mosura analyses the resulting executable, where every call is
#              real. A DOS .EXE has no symbol table, so the names come from the linker MAP.
#
# Regeneration-only: `cargo test` reads the committed databases and never runs this.
#
#   ./scripts/build-borland-db.sh objects <lib> <version> <model>
#   ./scripts/build-borland-db.sh linked  <toolchain-dir> <version> <model>
#
# Needs dosemu2 for the `linked` route (see the dosemu2 skill; C: is ~/.dosemu/drive_c).
set -uo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"
OUT="$REPO/data/fid"
mkdir -p "$OUT"

MODE="${1:?usage: build-borland-db.sh <objects|linked> ...}"

case "$MODE" in
objects)
	LIB="${2:?path to the .LIB}"; VER="${3:?version, e.g. tc2.0}"; MODEL="${4:?memory model, e.g. cs}"
	cargo run --release -q -p xtask -- fid-build \
		--family Borland --version "$VER" --variant "$MODEL" \
		--out "$OUT/borland-$VER-$MODEL-x86-16.mfid.gz" "$LIB"
	;;

linked)
	TOOLS="${2:?directory holding TCC.EXE/TLINK.EXE, the runtime .LIB and C0*.OBJ}"
	VER="${3:?version}"; MODEL="${4:?memory model letter set, e.g. l}"
	LIB=$(ls "$TOOLS"/C"${MODEL^^}".LIB 2>/dev/null | head -1)
	[ -f "$LIB" ] || { echo "no C${MODEL^^}.LIB in $TOOLS"; exit 1; }

	WORK="$HOME/.dosemu/drive_c/uber"
	rm -rf "$WORK"; mkdir -p "$WORK"
	cp "$TOOLS"/*.EXE "$TOOLS"/*.LIB "$TOOLS"/*.OBJ "$WORK"/ 2>/dev/null

	# 1. the uber program: one reference per C-callable public, so the linker pulls it in
	cargo run --release -q -p xtask -- omf-uber "$LIB" "$WORK/uber.c" || exit 1

	# 2. compile + link with the vendor's own tools. NOTE: DOS COMMAND.COM has no `&&`,
	#    so the steps go in a batch file rather than a chained -E command line.
	printf 'c:\r\ncd \\uber\r\nset PATH=c:\\uber\r\ntcc.exe -m%s -M uber.c > build.txt\r\n' "$MODEL" \
		> "$WORK/mk.bat"
	dosemu -td -E 'c:\uber\mk.bat' >/dev/null 2>&1
	[ -f "$WORK/uber.exe" ] || { echo "link failed:"; tail -20 "$WORK/build.txt"; exit 1; }
	echo "  linked $(stat -c%s "$WORK/uber.exe") bytes"

	# 3. ingest the LINKED image, named from the linker map
	cargo run --release -q -p xtask -- fid-build \
		--family Borland --version "$VER" --variant "$MODEL-linked" \
		--map "$WORK/uber.map" \
		--out "$OUT/borland-$VER-$MODEL-linked-x86-16.mfid.gz" "$WORK/uber.exe"
	;;

*)
	echo "unknown mode: $MODE (expected 'objects' or 'linked')"; exit 2 ;;
esac
