---
name: war2-issues-become-source-tests
description: "USER RULE (2026-07-22): every issue mosura discovers on WAR2.EXE must be reduced to a self-compiled source test — write C reproducing the construct, compile with the Watcom toolchain, verify it reproduces the WAR2 instruction shape, commit as a ground-truth test."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-07-22T14:41:50.487Z
---

**USER RULE (2026-07-22, standing):** whenever mosura work discovers an issue on WAR2.EXE
(wrong decompilation, unrecovered construct, loader gap), DERIVE A CODE TEST from it using
the self-compiled ground-truth strategy: write a small C program exhibiting the same
construct → compile it with the same compiler family (Watcom: the real 10.0a toolchain in
warcraft2-re/tmp/watcom-experiments when present, or native OW `wcc386` at
`$GT_WATCOM/binl/` default `~/tools/open-watcom` — the OW source tree was dropped to free disk;
only the ~295MB release binary remains) → verify the compiled output REPRODUCES the WAR2
instruction shape that triggered the issue (compare disassembly) → commit as a ground-truth
test (source + binary + build-derived truth, the `oracle/ground-truth/` pattern).

**Why:** WAR2 has no source, so a WAR2 finding is un-gateable directly; the reduction has a
known source = exact oracle + permanent regression gate + a minimal repro for the decompiler
agent (30 lines, not a 1279-function game binary), and Watcom compilation reproduces the
real codegen idiom (watcall, cs:-tables, CRT patterns) — not a gcc approximation.

**How to apply:**
- Bar for the derivation: the compiled snippet reproduces the SAME instruction
  shape/construct as the WAR2 site (verify by diffing disassembly against the WAR2 bytes);
  byte-identical codegen is the ideal when compiler version/flags line up. The full
  decompile→recompile→identical-binary loop is the D1 north star (needs the compilable-C
  emitter) — the rule works at construct level today and strengthens as D1 lands.
- Loader-level issues reduce to a minimal LE image (wlink emits LE; `watcom_hello.exe` is
  the existing example), decompiler-level issues to a minimal function.
- First candidate application ✅ DONE `4be984b` — see [[war2-branchind-classification]]: the 9
  unrecovered BRANCHIND classified (4 narrowed-switch decompiler gaps reduced to Watcom
  `narrowsw.*` + filed `docs/decompiler-bug-narrow-switch.md`; 3 unguarded-byte faithful
  non-gaps; 2 computed-goto function-specific gaps). Loader ruled out (tables fixup-relocated).

Relates: [[self-compiled-ground-truth]] (the strategy), [[war2-le-fixups-root-cause]] (the
LE work that left the 9), [[decompiler-misport-backlog]] (where derived decompiler bugs go).
