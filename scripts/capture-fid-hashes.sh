#!/usr/bin/env bash
# Regenerate the FID hash-quad goldens (oracle/fid/hashes/*.fidhash).
#
# The oracle is Ghidra's OWN hasher: analyzeHeadless imports each self-compiled
# ground-truth binary, runs FidService.hashFunction over every recovered function, and
# emits the quad plus the function's body address ranges. mosura's gate
# (tests/fid_hash_parity.rs) then hashes exactly those ranges and requires byte-identical
# quads.
#
# Regeneration-only: `cargo test` reads the committed goldens and never runs this.
#
#   ./scripts/capture-fid-hashes.sh              # the default set
#   ./scripts/capture-fid-hashes.sh a.bin b.bin  # specific binaries
set -uo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

. "$REPO/scripts/devcfg.sh"
GHIDRA_SRC="$(devcfg ghidra_src "$(cd "$REPO/.." && pwd)/ghidra")"
DIST="$(echo $(devcfg oracle.ghidra_dist "$GHIDRA_SRC/build/dist/ghidra_*_DEV"))"
HEADLESS="$DIST/support/analyzeHeadless"
[ -x "$HEADLESS" ] || { echo "ERROR: no analyzeHeadless at $HEADLESS (build the dist: scripts/build-ghidra-dist.sh)"; exit 1; }

OUT="$REPO/oracle/fid/hashes"
GT="$REPO/oracle/ground-truth"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The default set: every self-compiled ground-truth binary that carries enough code to
# produce quads, across all the compiler x arch columns we support. Staging them into one
# directory lets a single headless run cover them all (JVM start dominates the cost).
if [ $# -gt 0 ]; then
	BINARIES=("$@")
else
	mapfile -t BINARIES < <(find "$GT" -maxdepth 1 -type f \
		! -name '*.truth' ! -name '*.c' ! -name '*.h' ! -name '*.s' ! -name '*.sh' \
		| sort)
fi

# Binaries Ghidra cannot classify on its own, and the processor to import them with.
#
# A raw CP/M `.COM` is a flat image with no header, no sections and no symbol table — there is
# nothing for the loader to recognise, so an unqualified import yields no language, no functions
# and silently no goldens. That is exactly why the z80 column had none: not because Ghidra cannot
# hash z80 (it can — 6 quads from z80prog), but because nobody told it what the bytes were.
#
# These need their own headless pass, since -processor applies to the whole import.
# ⚠️ The LOAD BASE matters as much as the processor. A `.COM` maps at the CP/M Transient Program
# Area, 0x100 — which is what `loader/com.rs` does — so importing it at Ghidra's default base 0
# produces goldens whose addresses no mosura body can be read at, and the gate silently reports
# "bodies not readable" instead of comparing anything.
needs_processor() {
	case "$(basename "$1")" in
	*.sdcc-z80.com) echo "-processor z80:LE:16:default -loader BinaryLoader -loader-baseAddr 0x100" ;;
	*) echo "" ;;
	esac
}

mkdir -p "$WORK/in" "$WORK/proj" "$OUT"
declare -a QUALIFIED=()
for b in "${BINARIES[@]}"; do
	if [ -n "$(needs_processor "$b")" ]; then
		QUALIFIED+=("$b")
	else
		cp "$b" "$WORK/in/$(basename "$b")"
	fi
done
echo "staged $(ls "$WORK/in" | wc -l) auto-detected binaries, ${#QUALIFIED[@]} needing -processor"

"$HEADLESS" "$WORK/proj" fidhash \
	-import "$WORK/in" \
	-scriptPath "$REPO/oracle/fid" \
	-postScript FidHashDump.java "$OUT" \
	> "$WORK/headless.log" 2>&1
status=$?

# One pass per explicitly-typed binary (they may not share a processor).
for b in "${QUALIFIED[@]}"; do
	# shellcheck disable=SC2086 # deliberate word-splitting: these are multiple flags
	args="$(needs_processor "$b")"
	echo "  $args  $(basename "$b")"
	"$HEADLESS" "$WORK/proj" "fidhash_$(basename "$b" | tr -c 'A-Za-z0-9' '_')" \
		-import "$b" $args \
		-scriptPath "$REPO/oracle/fid" \
		-preScript MarkComEntry.java \
		-postScript FidHashDump.java "$OUT" \
		>> "$WORK/headless.log" 2>&1 || status=$?
done

grep -E "FidHashDump:" "$WORK/headless.log" | sed 's/.*FidHashDump: /  /'
if [ $status -ne 0 ]; then
	echo "ERROR: analyzeHeadless exited $status; see $WORK/headless.log"
	tail -20 "$WORK/headless.log"
	exit $status
fi

# Stamp the Ghidra version the goldens came from, so a pin bump is visible in the diff.
echo "$(basename "$DIST")" > "$OUT/GHIDRA_VERSION"
echo "wrote $(ls "$OUT"/*.fidhash 2>/dev/null | wc -l) goldens to oracle/fid/hashes/"
