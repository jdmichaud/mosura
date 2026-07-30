#!/usr/bin/env bash
# Get GHIDRA's own decompilation of one or many WAR2.EXE functions.
#
# ⚠️ WHY THIS DOES NOT IMPORT WAR2.EXE — DO NOT "FIX" IT TO.
# WAR2.EXE is a DOS/4GW **LE** executable. Ghidra loads only the MZ stub, so `analyzeHeadless`
# on the .EXE cannot see a single byte of the protected-mode code we care about. That blocked
# Ghidra-on-WAR2 for the whole byte-exact campaign.
#
# The way around it: import the FUNCTION BYTES THEMSELVES as a raw binary based at their own VA
# (BinaryLoader + x86:LE:32:default), then create + decompile the function there. Ghidra needs no
# container and no surrounding code: a 179-byte import with entirely unresolved call targets still
# decompiles correctly (calls simply render `func_0xNNNNNNNN()`). Ghidra is working with LESS
# context than mosura, so mosura can never plead missing analysis context for a DEFICIT.
#
# ⚠️ AND IT DOES NOT ALWAYS ANSWER ABOUT THE VA YOU ASKED FOR: an entry Ghidra decides is a thunk
# comes back named after its TARGET (`===== FUNC 00051c2c =====` is followed by
# `void thunk_FUN_00067d45(void)`). Key any per-function comparison on the `===== FUNC` header, and
# never assume the C body's name matches it.
#
# ⛔⛔ THE WORST LIMITATION, AND IT IS NOT ABOUT CALL COUNTS (recorded 2026-07-30). THIS RECIPE CAN
# CHANGE THE BLOCK STRUCTURE OF ANY FUNCTION THAT CALLS ANYTHING, so an UNFORCED run is NOT valid
# ground truth for a structural comparison.
#
# The image holds only the requested functions, so every callee's prototype falls back to the
# database default — NO PARAMETERS. Ghidra's dead-code pass then deletes every register the callee
# "does not read", and deleting a register deletes the instructions that computed it, which deletes
# BASIC BLOCKS, which changes what the structurer can collapse. Worked example, FUN_00077dcb:
# FUN_00063c35 defaulted to no params ⇒ EDX died ⇒ `xor %edx,%edx` (0x77e08) and the `cmp $0x88daa`
# test (0x77e01) were deleted ⇒ Ghidra had 6 basic blocks and a clean `while` where mosura (whole
# program, EDX live) had 8 and three gotos. THE TWO SIDES WERE DECOMPILING DIFFERENT PROGRAMS.
#
# That comparison was read as a mosura structuring defect for THREE SESSIONS. CFG granularity,
# `is_complex`, `select_goto` scoring and the collapse termination test were each hunted and each
# turned out faithful. Forcing the callee's storage made Ghidra reproduce mosura's partition BLOCK FOR
# BLOCK — all 8, same spans, same edge sets — and emit three gotos of its own.
#
# ⚠️ CONSEQUENCE FOR THE RECORD: **EVERY PRIOR STRUCTURAL CONCLUSION DRAWN FROM AN UNFORCED RUN IS
# SUSPECT** — not merely the one above. Blocks, edges, gotos, labels, conditions, loop shape: if the
# claim is structural and the callees were not forced, it has not been measured. Re-measure before
# quoting it. Note which direction the bias runs: the pruning makes GHIDRA'S output look BETTER
# STRUCTURED, so it reads as our bug, which is why it survived so long.
#
# ⭐ MANDATORY RECIPE FOR ANY STRUCTURAL COMPARISON — force the callee storage, callees FIRST in the
# VA list (functions are created in list order, so a callee after its caller still renders
# `func_0x...` with a default prototype and nothing changes):
#
#   GHIDRA_POSTSCRIPT=DecompileWithForcedParams.java GHIDRA_POSTSCRIPT_ARGS='63c35=EDX' \
#     scripts/ghidra-decompile-war2.sh 63cbf 722c8 63c35 77dcb
#
# And to diff the PARTITIONS rather than the C — Ghidra's own `HighFunction::getBasicBlocks`, i.e. the
# very `BlockBasic` list `CollapseStructure` runs on, plus per-block p-code:
#
#   GHIDRA_POSTSCRIPT=DumpBlocks.java scripts/ghidra-decompile-war2.sh 77dcb
#
# Its mosura counterpart is `MOSURA_CFG=1`, which prints the same fields, so the two diff
# line-for-line. Before these two scripts existed there was NO WAY to compare partitions at all — a
# granularity divergence could only be seen as its third-order symptom (extra gotos, an uncollapsed
# graph), which is precisely how it got misdiagnosed three different ways. Both are permanent parts of
# the recipe, not one-off debugging aids.
#
# ⚠️ MEASURED LIMIT OF THAT PROPERTY — the asymmetry only runs one way (recorded 2026-07-29,
# @e840e56). "Less context" does NOT mean "same answer, fewer names": on a few functions the missing
# context makes Ghidra PRUNE LIVE CODE. With the callees unresolvable, guard conditions fold to
# constants and whole blocks are declared dead — Ghidra's own output says so: FUN_00066da8 carries
# NINE `/* WARNING: Removing unreachable block ... */` comments, then emits 2 calls where the bytes
# contain 9. THE CORRECTED FIGURE IS 4 FUNCTIONS / 17 CALLS OF TOTAL SURPLUS — 00066da8 +7,
# 0007baf0 +6, 0006581c +3, 00066ea8 +1 — and NOT the 17-or-18 functions this note was first drafted
# with (see the counter warning below). Of those four, 0007baf0 is the short-slice case described at
# the end of this header; the other three each carry Ghidra's own unreachable-block warnings. Every
# one of mosura's claimed sites in them was checked against the fixup-applied image as a real
# `e8 rel32` at its exact target — but note that check proves MOSURA'S side only: the attribution
# "Ghidra under-emits here" additionally needs the Ghidra-side counter to be right, and for 14 of the
# original 18 it was not.
#
# ⚠️ AND BEFORE BELIEVING ANY SURPLUS, SUSPECT THE COUNTER — that number was 17 functions / 39 calls
# until 2026-07-29, when the extra 14 turned out to be a COUNTING BUG, not pruning. The gauge's call
# predicate began `\b(?:FUN_|func_0x)…` and Ghidra renders thunk calls as `thunk_FUN_00067d38(...)`,
# where the char before `FUN_` is `_` — a word char — so `\b` never matched and 30 Ghidra call sites
# were invisible. mosura emits no `thunk_` name at all, so the blind spot was ONE-SIDED and invented
# surplus out of nothing. A second, opposite bug sat behind it: Ghidra names a thunk entry after its
# TARGET, so the definition line of FUN_00051c2c reads `void thunk_FUN_00067d45(void)` and scored as
# a call. Fixing either one alone gives a WRONG answer — TRAP 3 alone inflates the base deficit to a
# phantom 37 fns / 69 calls. With both fixed the deficit is exactly what was always reported (base
# 28 fns / 60 calls; 4 / 9 after heritage Stage A, same functions, same per-function counts): the
# gate was never wrong, only the surplus and the "% of Ghidra" totals. Fix and negative controls in
# `scripts/war2-absolute-gauge.py` (TRAPs 3-4, `--selftest`).
#
# CONSEQUENCE FOR ANY NUMBER DERIVED FROM THIS SWEEP: a mosura DEFICIT against it is real evidence
# (Ghidra had less and still found more). A mosura SURPLUS is NOT evidence of a mosura defect —
# check the counter first, then the bytes. Never quote "% of Ghidra" as a quality claim; quote the
# deficit, and state any surplus separately with its cause.
#
# SEPARATE, MOSURA-SIDE: the bytes handed to Ghidra are `[entry, next-entry)` (see war2_survey.rs),
# so if mosura's own flow runs PAST the next discovered function entry, Ghidra is given a shorter
# slice and the comparison is not like-for-like. That is exactly 1 function today (FUN_0007baf0:
# 512 bytes given, 1948 covered, +6 "surplus" calls that simply lie outside Ghidra's input). Check
# `cov_hi - va` against `orig_len` in the manifest before attributing such a gap to the oracle.
#
# Bytes come from the survey manifest's `orig_hex` column, which is produced by
# `cargo run --release --example war2_survey` (see docs/war2-recompile-remeasure.md).
#
# Usage:
#   scripts/ghidra-decompile-war2.sh 1bd30 [1b8b8 ...]   # named functions
#   scripts/ghidra-decompile-war2.sh --all               # every function in the manifest
#   scripts/ghidra-decompile-war2.sh --file vas.txt      # one hex VA per line
#
# Output: `===== FUNC <va> =====` followed by Ghidra's C, on stdout.
#
# Env: WAR2_MANIFEST (default ../war2-survey/manifest.tsv), GHIDRA_DIST, OUT.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"                     # mosura/
MANIFEST="${WAR2_MANIFEST:-$(cd "$HERE/.." && pwd)/war2-survey/manifest.tsv}"
GHIDRA_SRC="${GHIDRA_SRC:-$(cd "$HERE/.." && pwd)/ghidra}"
DIST="${GHIDRA_DIST:-$(echo /data/tools/ghidra_12.0.3_PUBLIC/build/dist/ghidra_*_DEV)}"
[ -d "$DIST" ] || DIST="$(echo "$GHIDRA_SRC"/build/dist/ghidra_*_DEV)"
HEADLESS="$DIST/support/analyzeHeadless"
SCRIPTS="$HERE/oracle/ghidra_scripts"
# Which oracle question to ask. `DecompileFunctions.java` (default) prints Ghidra's C — that is what
# ghidra-all.txt holds. `DumpBlocks.java` prints Ghidra's BASIC-BLOCK PARTITION + per-block p-code,
# which the C cannot show: a CFG-granularity divergence only reaches the C as extra gotos.
POSTSCRIPT="${GHIDRA_POSTSCRIPT:-DecompileFunctions.java}"
# Extra whitespace-separated arguments appended after the VA-list file, for scripts that take more
# (e.g. `GHIDRA_POSTSCRIPT_ARGS='63c35=EDX'` with DecompileWithForcedParams.java).
read -r -a POSTSCRIPT_ARGS <<<"${GHIDRA_POSTSCRIPT_ARGS:-}"

[ -x "$HEADLESS" ] || { echo "ERROR: no analyzeHeadless at $HEADLESS (set GHIDRA_DIST)" >&2; exit 1; }
[ -s "$MANIFEST" ] || { echo "ERROR: no manifest at $MANIFEST (set WAR2_MANIFEST); regenerate with the war2_survey example" >&2; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
export LC_ALL=C.UTF-8 LANG=C.UTF-8

case "${1:-}" in
  --all)  awk -F'\t' 'NR>1 && $9!="" {print $2}' "$MANIFEST" > "$WORK/vas.txt" ;;
  --file) [ -n "${2:-}" ] || { echo "ERROR: --file needs a path" >&2; exit 1; }
          tr -d ' \t' < "$2" | grep -v '^$' > "$WORK/vas.txt" ;;
  "")     echo "ERROR: give one or more hex VAs, or --all / --file <path>" >&2; exit 1 ;;
  *)      printf '%s\n' "$@" | sed 's/^0x//' > "$WORK/vas.txt" ;;
esac

# Build ONE sparse flat image holding every requested function at its own VA, so the whole batch is
# a single JVM start + single import rather than one Ghidra run per function (the difference between
# minutes and hours over 1286 functions).
python3 - "$MANIFEST" "$WORK/vas.txt" "$WORK/image.bin" "$WORK/base.txt" <<'PY'
import sys
manifest, valist, imgpath, basepath = sys.argv[1:5]
want = {l.strip().lower().lstrip('0') or '0' for l in open(valist) if l.strip()}
fns = []
for line in open(manifest):
    f = line.rstrip('\n').split('\t')
    if len(f) < 9 or f[0] == 'idx' or not f[8]:
        continue
    va = int(f[1], 16)
    if f'{va:x}'.lstrip('0') not in want and f'{va:x}' not in want:
        continue
    fns.append((va, bytes.fromhex(f[8][:len(f[8]) // 2 * 2])))
if not fns:
    sys.exit("ERROR: none of the requested VAs are in the manifest")
base = min(v for v, _ in fns)
end = max(v + len(b) for v, b in fns)
img = bytearray(end - base)
for va, b in fns:
    img[va - base:va - base + len(b)] = b
open(imgpath, 'wb').write(img)
open(basepath, 'w').write(hex(base))
print(f"image: {len(fns)} functions, base {base:#x}, {len(img)} bytes", file=sys.stderr)
PY

BASE="$(cat "$WORK/base.txt")"
OUTFILE="${OUT:-/dev/stdout}"
# -noanalysis: the image is sparse (zero-filled between functions), so auto-analysis would spend its
# time on padding. The script disassembles and creates each requested function explicitly, which is
# all the decompiler needs.
mkdir -p "$WORK/proj"   # analyzeHeadless requires the project directory to already exist
"$HEADLESS" "$WORK/proj" cap -import "$WORK/image.bin" \
  -loader BinaryLoader -loader-baseAddr "$BASE" -processor "x86:LE:32:default" \
  -noanalysis -scriptPath "$SCRIPTS" \
  -postScript "$POSTSCRIPT" "$WORK/vas.txt" "${POSTSCRIPT_ARGS[@]}" -deleteProject 2>"$WORK/err.log" \
  | sed -n "s/^INFO  ${POSTSCRIPT//./\\.}> \(.*\) (GhidraScript)  *$/\1/p" > "$WORK/out.txt" || {
      echo "ERROR: headless failed; log tail:" >&2; tail -20 "$WORK/err.log" >&2; exit 1; }

[ -s "$WORK/out.txt" ] || { echo "ERROR: no output; log tail:" >&2; tail -20 "$WORK/err.log" >&2; exit 1; }
cat "$WORK/out.txt" > "$OUTFILE"
