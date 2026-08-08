#!/usr/bin/env bash
# Rebuild every committed FID signature database from its source libraries.
#
# This is the ONE place the full recipe lives in executable form. `docs/fid-building-databases.md`
# explains *why* each column is built the way it is; `tests/fid_database_drift.rs` re-ingests a
# sample and byte-compares, which is what catches a hasher change. Neither could regenerate the
# set: until this script existed, the 85 databases were built by ad-hoc shell loops that survived
# only in a session transcript, so a hasher or loader change that moved every database had no
# repeatable way to produce the new ones.
#
#   ./scripts/rebuild-fid-db.sh              # rebuild all, in place
#   ./scripts/rebuild-fid-db.sh -n           # dry run: print what would be built, check inputs
#   ./scripts/rebuild-fid-db.sh watcom       # only databases whose name matches the pattern
#   ./scripts/rebuild-fid-db.sh -o /tmp/out  # write elsewhere, leaving the committed set alone
#
# A source library that is absent is REPORTED and skipped, never silently dropped: most of these
# come from historical install media staged outside the repo (see the layout table in
# docs/fid-building-databases.md), and a machine without it must not quietly produce a database
# built from fewer libraries than the committed one.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

DRY=0
OUT="$REPO/oracle/fid/db"
PATTERN=""
while [ $# -gt 0 ]; do
	case "$1" in
	-n) DRY=1; shift ;;
	-o) OUT="$2"; shift 2 ;;
	*) PATTERN="$1"; shift ;;
	esac
done
mkdir -p "$OUT"

W="$HOME/.dosemu/drive_c"       # Watcom installs (WAT100A, WAT105, WAT106, WAT110, wat901)
W16="/data/watcom16"            # the 10.5 ISO's 16-bit LIB286 tree
B="/data/borland/work"          # per-product staged Borland media
BC45="/data/borland/BC45/LIB"   # BC++ 4.5 predates that layout
OW2="/data/open-watcom-v2/bld"  # Open Watcom 2, built from source

# db-basename | family | version | variant | libraries...
#
# The variant is not decoration: it is part of the database identity, and two variants of one
# version are separate databases on purpose. `Release` (-3r, registers) and `Stack` (-3s) are
# different builds of the same functions, so merging them would file two different bodies under
# one name; the Borland memory model changes the code outright.
RECIPES=$(cat <<EOF
sdcc-4.5.0-z80|sdcc|4.5.0|z80|/usr/share/sdcc/lib/z80/z80.lib

# Watcom 32-bit, the default register calling convention. The C run-time plus the math libraries
# a program doing float work links: MATH3R (software), MATH387R (coprocessor), EMU387 (emulator)
# and the BGI-equivalent GRAPH.
# WARNING: use the explicit LIB386/DOS path. A Watcom tree holds several CLIB3R.LIB — under
# LIB386/DOS, LIB386/OS2, LIB386/NT — and picking the wrong one silently builds an OS/2 database
# labelled DOS.
watcom-9.01-x86-32|Watcom|9.01|Release|$W/wat901/lib386/dos/clib3r.lib $W/wat901/lib386/math3r.lib $W/wat901/lib386/math387r.lib $W/wat901/lib386/dos/emu387.lib $W/wat901/lib386/dos/graph.lib
watcom-10.0a-x86-32|Watcom|10.0a|Release|$W/WAT100A/LIB386/DOS/CLIB3R.LIB $W/WAT100A/LIB386/MATH3R.LIB $W/WAT100A/LIB386/MATH387R.LIB $W/WAT100A/LIB386/DOS/EMU387.LIB $W/WAT100A/LIB386/DOS/GRAPH.LIB
watcom-10.5-x86-32|Watcom|10.5|Release|$W/WAT105/LIB386/DOS/CLIB3R.LIB $W/WAT105/LIB386/MATH3R.LIB $W/WAT105/LIB386/MATH387R.LIB $W/WAT105/LIB386/DOS/EMU387.LIB $W/WAT105/LIB386/DOS/GRAPH.LIB
watcom-10.6-x86-32|Watcom|10.6|Release|$W/WAT106/LIB386/DOS/CLIB3R.LIB $W/WAT106/LIB386/MATH3R.LIB $W/WAT106/LIB386/MATH387R.LIB $W/WAT106/LIB386/DOS/EMU387.LIB $W/WAT106/LIB386/DOS/GRAPH.LIB
watcom-11.0-x86-32|Watcom|11.0|Release|$W/WAT110/LIB386/DOS/CLIB3R.LIB $W/WAT110/LIB386/MATH3R.LIB $W/WAT110/LIB386/MATH387R.LIB $W/WAT110/LIB386/DOS/EMU387.LIB $W/WAT110/LIB386/DOS/GRAPH.LIB

# Watcom 32-bit, the -3s stack calling convention.
watcom-9.01-stack-x86-32|Watcom|9.01|Stack|$W/wat901/lib386/dos/clib3s.lib $W/wat901/lib386/math3s.lib $W/wat901/lib386/math387s.lib
watcom-10.0a-stack-x86-32|Watcom|10.0a|Stack|$W/WAT100A/LIB386/DOS/CLIB3S.LIB $W/WAT100A/LIB386/MATH3S.LIB $W/WAT100A/LIB386/MATH387S.LIB
watcom-10.5-stack-x86-32|Watcom|10.5|Stack|$W/WAT105/LIB386/DOS/CLIB3S.LIB $W/WAT105/LIB386/MATH3S.LIB $W/WAT105/LIB386/MATH387S.LIB
watcom-10.6-stack-x86-32|Watcom|10.6|Stack|$W/WAT106/LIB386/DOS/CLIB3S.LIB $W/WAT106/LIB386/MATH3S.LIB $W/WAT106/LIB386/MATH387S.LIB
watcom-11.0-stack-x86-32|Watcom|11.0|Stack|$W/WAT110/LIB386/DOS/CLIB3S.LIB $W/WAT110/LIB386/MATH3S.LIB $W/WAT110/LIB386/MATH387S.LIB

# Watcom C++ run-times. These ingested to ZERO until the OMF reader learned COMDAT (0xC2/0xC3):
# C++ emits template instantiations and inline functions as COMDATs so the linker can dedupe
# them, and a C++ archive is almost entirely COMDAT. 9.01 has no PLIB3R, hence four rows.
watcom-10.0a-cpp-x86-32|Watcom|10.0a|Cpp|$W/WAT100A/LIB386/PLIB3R.LIB $W/WAT100A/LIB386/PLBX3R.LIB $W/WAT100A/LIB386/CPLX3R.LIB
watcom-10.5-cpp-x86-32|Watcom|10.5|Cpp|$W/WAT105/LIB386/PLIB3R.LIB $W/WAT105/LIB386/PLBX3R.LIB $W/WAT105/LIB386/CPLX3R.LIB
watcom-10.6-cpp-x86-32|Watcom|10.6|Cpp|$W/WAT106/LIB386/PLIB3R.LIB $W/WAT106/LIB386/PLBX3R.LIB $W/WAT106/LIB386/CPLX3R.LIB
watcom-11.0-cpp-x86-32|Watcom|11.0|Cpp|$W/WAT110/LIB386/PLIB3R.LIB $W/WAT110/LIB386/PLBX3R.LIB $W/WAT110/LIB386/CPLX3R.LIB

# Watcom 16-bit, one database per memory model, from the 10.5 ISO's LIB286 tree.
watcom-10.5-cc-x86-16|Watcom|10.5|cc|$W16/LIB286/DOS/CLIBC.LIB $W16/LIB286/MATH87C.LIB $W16/LIB286/MATHC.LIB $W16/LIB286/DOS/EMU87.LIB $W16/LIB286/DOS/GRAPH.LIB
watcom-10.5-ch-x86-16|Watcom|10.5|ch|$W16/LIB286/DOS/CLIBH.LIB $W16/LIB286/MATH87H.LIB $W16/LIB286/MATHH.LIB $W16/LIB286/DOS/EMU87.LIB $W16/LIB286/DOS/GRAPH.LIB
watcom-10.5-cl-x86-16|Watcom|10.5|cl|$W16/LIB286/DOS/CLIBL.LIB $W16/LIB286/MATH87L.LIB $W16/LIB286/MATHL.LIB $W16/LIB286/DOS/EMU87.LIB $W16/LIB286/DOS/GRAPH.LIB
watcom-10.5-cm-x86-16|Watcom|10.5|cm|$W16/LIB286/DOS/CLIBM.LIB $W16/LIB286/MATH87M.LIB $W16/LIB286/MATHM.LIB $W16/LIB286/DOS/EMU87.LIB $W16/LIB286/DOS/GRAPH.LIB
watcom-10.5-cs-x86-16|Watcom|10.5|cs|$W16/LIB286/DOS/CLIBS.LIB $W16/LIB286/MATH87S.LIB $W16/LIB286/MATHS.LIB $W16/LIB286/DOS/EMU87.LIB $W16/LIB286/DOS/GRAPH.LIB

# Open Watcom 2 — from a local build of the source tree, not a shipped release. Note the exact
# path: that tree holds many clib3r.lib copies and only this one reproduces the database.
watcom-ow2-x86-32|Watcom|ow2|Release|$OW2/clib/library/msdos.386/ms_r/clib3r.lib $OW2/mathlib/library/msdos.386/ms_r/math3r.lib
EOF
)

# Borland / Turbo C 16-bit: C<model> + MATH<model> + EMU + FP87 + GRAPHICS + OVERLAY.
# bc3.0 is the exception — this disk set ships the Windows runtimes (CW<model> + MATHW<model>),
# and it has no GRAPHICS/OVERLAY.
declare -A BDIR=(
	[tc1.0]="$B/tc1.0" [tc1.5]="$B/tc1.5" [tc2.0]="$B/tc2.0" [tc2.01]="$B/tc2.01"
	[tcpp1.0]="$B/tcpp1.0-lib" [tcpp1.01]="$B/tcpp1.01-lib" [tcpp3.0]="$B/tcpp3.0-lib"
	[bc2.0]="$B/bc2.0-lib" [bc4.0]="$B/bc4.0/BC4/LIB" [bc4.5]="$BC45" [bc4.52]="$B/bc4.52/BC45/LIB"
)
for v in tc1.0 tc1.5 tc2.0 tc2.01 tcpp1.0 tcpp1.01 tcpp3.0 bc2.0 bc4.0 bc4.5 bc4.52; do
	for m in cc ch cl cm cs; do
		M=$(echo "$m" | tr a-z A-Z)
		libs=""
		for f in "$M.LIB" "MATH${M#C}.LIB" EMU.LIB FP87.LIB GRAPHICS.LIB OVERLAY.LIB; do
			p=$(find "${BDIR[$v]}" -maxdepth 2 -iname "$f" 2>/dev/null | head -1)
			[ -n "$p" ] && libs="$libs $p"
		done
		RECIPES="$RECIPES
borland-$v-$m-x86-16|Borland|$v|$m|${libs# }"
	done
done
for m in cwc cwl cwm cws; do
	M=$(echo "$m" | tr a-z A-Z)
	libs=""
	for f in "$M.LIB" "MATHW${M#CW}.LIB" EMU.LIB FP87.LIB; do
		p=$(find "$B/bc3.0-lib" -maxdepth 2 -iname "$f" 2>/dev/null | head -1)
		[ -n "$p" ] && libs="$libs $p"
	done
	RECIPES="$RECIPES
borland-bc3.0-$m-x86-16|Borland|bc3.0|$m|${libs# }"
done

# Borland 32-bit flat. There is no MATH32 — the math is inside the runtime.
RECIPES="$RECIPES
borland-bc4.0-flat-x86-32|Borland|bc4.0|flat|$B/bc4.0/BC4/LIB/CW32.LIB
borland-bc4.5-flat-x86-32|Borland|bc4.5|flat|$BC45/CW32.LIB
borland-bc4.52-flat-x86-32|Borland|bc4.52|flat|$B/bc4.52/BC45/LIB/CW32.LIB
borland-cb5-cw32-x86-32|Borland|cb5|cw32|$B/cb5lib/CW32.LIB
borland-cb5-cw32mt-x86-32|Borland|cb5|cw32mt|$B/cb5lib/CW32MT.LIB"

built=0 skipped=0 failed=0
while IFS='|' read -r db family version variant libs; do
	case "$db" in ''|'#'*) continue ;; esac
	[ -n "$PATTERN" ] && case "$db" in *"$PATTERN"*) ;; *) continue ;; esac
	missing=""
	present=""
	for l in $libs; do
		if [ -f "$l" ]; then present="$present $l"; else missing="$missing $(basename "$l")"; fi
	done
	if [ -z "$present" ]; then
		printf "  %-32s SKIP  no source library present\n" "$db"
		skipped=$((skipped + 1))
		continue
	fi
	if [ -n "$missing" ]; then
		printf "  %-32s WARN  absent:%s\n" "$db" "$missing"
	fi
	if [ "$DRY" = 1 ]; then
		printf "  %-32s ok    %d libraries\n" "$db" "$(echo $present | wc -w)"
		built=$((built + 1))
		continue
	fi
	before=""
	[ -f "$OUT/$db.mfid.gz" ] && before=$(zcat "$OUT/$db.mfid.gz" | grep -c '^f ')
	# Build to a scratch path that still ends in `.mfid.gz`: `fid-build` picks compression from
	# the extension, so a `.gz.new` staging name silently writes PLAIN TEXT under a `.gz` name.
	tmp=$(mktemp -d)
	if timeout 3600 cargo run --release -q -p xtask -- fid-build \
		--family "$family" --version "$version" --variant "$variant" \
		--out "$tmp/$db.mfid.gz" $present >/dev/null 2>&1 && [ -s "$tmp/$db.mfid.gz" ]; then
		after=$(zcat "$tmp/$db.mfid.gz" | grep -c '^f ')
		mv "$tmp/$db.mfid.gz" "$OUT/$db.mfid.gz"
		rmdir "$tmp"
		printf "  %-32s %5s -> %-5s records\n" "$db" "${before:-—}" "$after"
		built=$((built + 1))
	else
		rm -rf "$tmp"
		printf "  %-32s FAIL\n" "$db"
		failed=$((failed + 1))
	fi
done <<<"$RECIPES"

echo
echo "built $built   skipped $skipped   failed $failed"
[ "$failed" = 0 ]
