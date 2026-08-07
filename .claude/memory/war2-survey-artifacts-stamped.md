---
name: war2-survey-artifacts-stamped
description: "WAR2 survey emits are commit-stamped as of 4f929e8 — the old bare src/ was a 23.6% blend of two trees, and war2-survey/ is NOT in git"
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-08-05T08:30:12.606Z
---

**As of `4f929e8` (2026-08-05) `war2_survey` stamps its output with the commit that produced
it:** `src.<sha>/`, `raw.<sha>/`, `manifest.<sha>.tsv` (`-dirty` suffix for an uncommitted
tree), with the bare `src`/`raw`/`manifest.tsv` as symlinks to the current stamp. The stamped
dirs are CLEARED before writing, a clean-sha re-emit is refused without `--force`, and the
manifest carries a leading `# war2_survey emit @ <stamp>` line.

**Why:** the emit previously wrote those three paths directly and truncated them, so every
measurement destroyed the state it would be compared against. The only defence was the
operator hand-copying a snapshot first — which produced 21 orphaned snapshot dirs (~115MB) in
five naming conventions, 8 of which (`src.prev`, `src.base`, `src.b2-half`, …) name no commit
and are unusable as a baseline for any claim.

**The worse defect, found while fixing it:** `create_dir_all` never clears, so files from
earlier emits survived alongside newer ones. The standing `war2-survey/src/` held **996 .c
files from 2026-08-05 and 307 from 2026-08-03 — a 23.6% blend of two different trees under one
name.** Preserved as `src.pre-stamping`. Any measurement ever taken against that directory
mixed two commits silently. Treat pre-4f929e8 numbers accordingly ([[numbers-stale-unless-sha-stamped]]).

**How to apply:** never diff against a bare `src/` without checking what it resolves to. Prefer
an explicit `src.<sha>/`. If you need a baseline, emit one — don't hand-copy.

## Two traps this exposed

1. **A directory's mtime is not its contents' mtime.** `src/`'s own mtime read 2026-07-30 —
   *older than every file inside it* — because overwriting entries doesn't touch a directory,
   only adding/removing does. An agent read that and reported the pair as "six days apart";
   the real story was a two-day blend. **Cite the timestamp on the data, not the container.**
   Sibling of [[gauge-counting-traps]].
2. **Adding a `#` header line breaks one-line header skips.** `compile.sh` used `tail -n +2`
   and `compare.py` used `header = next(fh)` — both skip exactly ONE line, so a stamp line
   pushes the column header into the data (`compare.py` dies on `int("orig_len")`,
   `compile.sh` silently stores a garbage prologue). Both now drop `#` lines first.

## ⭐ `IFS=$'\t' read` SILENTLY CORRUPTED 20 BYTE-CLEAN VERDICTS

Found 2026-08-05 while validating the stamping fix. **TAB is IFS *whitespace*, so `IFS=$'\t'
read` collapses runs of tabs and DROPS empty fields, shifting every later field left.** It does
not give you tab-delimited columns, however much it looks like it does.

    printf 'a\tb\t\tc\td\n' | while IFS=$'\t' read -r f1 f2 f3 f4 f5; ...  -> f3=c f4=d
    awk -F'\t'                                                            -> f3=  f4=c

`compile.sh` built its `PROLOGUE[idx]` map that way. 224 of 1303 manifest rows have an empty
`smells` (col 8), so `ohex` received col 10 (`ir_calls`) instead of col 9 (`orig_hex`). That
value can never match `558bec|5589e5`, so those functions all fell to `FLAGS_NOFRAME` — and
**20 functions with a real frame prologue were compiled frameless, guaranteeing a
prologue/epilogue mismatch no decompiler improvement could ever fix.** Frame-flagged count was
85; correct is 105. Fixed by letting `awk -F'\t'` split and reading `$1, $9` space-separated.

**How to apply:** never parse a TSV with `IFS=$'\t' read` — use `awk -F'\t'`, or Python's
`split("\t")` (which does NOT collapse; `compare.py` was already safe). Any pre-2026-08-05
byte-clean number was measured with 20 functions structurally unable to pass.

## ⚠️ war2-survey/ IS NOT IN GIT

`/home/jd/projects/mosura/war2-survey/` sits OUTSIDE the repo (`.../mosura/mosura`). So
`compile.sh` and `compare.py` — the scripts that decide byte-clean verdicts — are **untracked
and unversioned**. Edits to them are unrecoverable if overwritten, and no commit records which
comparator produced a number. Larger exposure than the one 4f929e8 fixed; not yet addressed.

Related: [[war2-recompile-survey]] (the campaign), [[war2-survey-manifest-idx-trap]] (key on
the FUN_ name, never the manifest idx), [[measurement-determinism-first]].
