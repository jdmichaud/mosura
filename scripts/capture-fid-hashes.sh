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

GHIDRA_SRC="${GHIDRA_SRC:-$(cd "$REPO/.." && pwd)/ghidra}"
DIST="${GHIDRA_DIST:-$(echo "$GHIDRA_SRC"/build/dist/ghidra_*_DEV)}"
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

mkdir -p "$WORK/in" "$WORK/proj" "$OUT"
for b in "${BINARIES[@]}"; do
	cp "$b" "$WORK/in/$(basename "$b")"
done
echo "staged ${#BINARIES[@]} binaries"

"$HEADLESS" "$WORK/proj" fidhash \
	-import "$WORK/in" \
	-scriptPath "$REPO/oracle/fid" \
	-postScript FidHashDump.java "$OUT" \
	> "$WORK/headless.log" 2>&1
status=$?

grep -E "FidHashDump:" "$WORK/headless.log" | sed 's/.*FidHashDump: /  /'
if [ $status -ne 0 ]; then
	echo "ERROR: analyzeHeadless exited $status; see $WORK/headless.log"
	tail -20 "$WORK/headless.log"
	exit $status
fi

# Stamp the Ghidra version the goldens came from, so a pin bump is visible in the diff.
echo "$(basename "$DIST")" > "$OUT/GHIDRA_VERSION"
echo "wrote $(ls "$OUT"/*.fidhash 2>/dev/null | wc -l) goldens to oracle/fid/hashes/"
