# war2_survey `--le` decode non-determinism — RESOLVED (harness/loader bug, NOT the decompiler)

## Symptom (as observed at the ir-cast-model merge gate)
The `war2_survey` full-survey emit (`cargo run --release --example war2_survey -- WAR2.EXE <dir>`)
decoded a handful of functions (~4 of 1286) in the WRONG address-size mode — 16-bit real-mode
(`segment(seg,off)`, `xunknown2`) instead of 32-bit protected-mode — and a handful of *others*
came back `DECOMPILE_FAIL  returned None`. A 16-bit-decoded function emits `*segment(...)` (an
undeclared C intrinsic) → Watcom **E1029** → COMPILE_FAIL. The affected SET changed run-to-run,
so per-run COMPILE_FAIL / DECOMPILE_FAIL totals jittered by a few and produced PHANTOM
regressions. `dumpwar2 <va>` (one function per process) never showed it.

## Root cause
`analysis::decompiler::decompile_function` called `lang::load` — which re-reads the `.ldefs`,
the `.sla` and the `.pspec` **from disk on every call**. A whole-program survey therefore
re-read and re-parsed the language tables 1286 times, and **every one of those reads was a
chance to fail**: the pinned Ghidra tree lives under `~/tools` → `/data/tools`, a *network*
mount (`jd@10.0.2.2:/home/jd/projects/tools`), so a transient read error is a real event under
load. Both failure paths degraded **silently and per function**:

- `fs::read(<sla>)` fails → `lang::load` → `None` → `decompile_function` → `None` → the survey
  records `DECOMPILE_FAIL  returned None` for that one function. ("returned None" and not a
  panic location is the tell: the survey's panic hook would have named a file:line for any
  pipeline panic, so this row can *only* come from the language load.)
- `fs::read_to_string(<pspec>)` fails → `pspec_context_sets` returned `Vec::new()` →
  `context_from_sets` → an **all-zero context register** → on x86 that is `addrsize=0`/
  `opsize=0`, i.e. **16-bit real mode** (ia.sinc:1126-1134/1419+ gate `segment(...)` on
  `addrsize=0`) → that one function renders `*segment(...)`/`xunknown2` while its neighbours
  render 32-bit.

Evidence: a zero context reproduces the reported render *exactly* (same function, same
`segment(xVar1,iVar2 + -2)` / `xunknown2` shape); the post-`analyze_le_file` analysis state
(functions, code units, references, symbols, blocks) is bit-identical across runs; decompiling
every function twice in one process (fresh hash seeds) diverges for 0/1286; and the failures in
the recorded merge-gate runs cluster in *narrow index windows* (idx 432-443 in one run, 248-254
in another) — a time-localized I/O hiccup, not a per-function property. The earlier
HashMap-iteration-order hypothesis was wrong: nothing in the discovery path is order-sensitive.

## Fix (`lang.rs`, `speccache.rs`, `analysis/decompiler.rs`)
1. **Resolve the language once per process** — `lang::load_cached`, keyed by language id,
   leaking the parsed `Spec` + context. This is Ghidra's own structure:
   `SleighLanguageProvider` keeps a `LinkedHashMap<LanguageID, SleighLanguage>` and
   `getLanguage()` builds each language once, then serves it from that map
   (SleighLanguageProvider.java:58/128-134). `decompile_function` uses it, so every function of
   a whole-program decompile decodes under one identical (tables, context) — deterministic by
   construction, and no repeated network I/O (survey EMIT 239s → 54s).
2. **No silent degradation on an unreadable spec** — `pspec_context_sets` /
   `pspec_laned_size_masks` return `Option`: `None` = could not read/parse (the language load
   fails), `Some(empty)` = the pspec legitimately declares no `<context_set>` / no laned
   registers. Ghidra `SleighLanguage.initialize()` (SleighLanguage.java:116) declares
   `throws DecoderException, SAXException, IOException` and lets a spec-file error propagate —
   the `Language` fails to construct; it never comes up with an unset context register. A
   tree that cannot be read now fails uniformly instead of mis-decoding one function.

## Gates
Two full emits into separate dirs are byte-identical (`diff -r A/raw B/raw` clean, manifests
identical), and both are byte-identical to a pre-fix emit — the fix changes no output, only how
often the tables are read. Corpus: all 60 fixture scores unchanged (0.9527, 57/60). Suite green,
clippy clean. Regression test: `lang::tests::unreadable_pspec_fails_the_load_rather_than_zeroing_the_context`.
