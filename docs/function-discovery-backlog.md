# Function-discovery backlog

Open items for mosura's function-discovery pipeline, as of 2026-08-06. Written down because this
track has produced several findings that are cheap to lose and expensive to re-derive.

**Standing scope rule (user, 2026-08-06):** *WAR2 is one example among many. mosura will be run
against all kinds of binaries, and we must be able to identify functions produced by **all Watcom
compilers under all options that affect function shape**. The test suite has to reflect that.* So
every item below is judged on whether it generalises, not on whether it moves the WAR2 number.

Current WAR2 state (the diagnostic, not the goal): **2898 functions; 2026 of the expert tracker's
2120 (95.6%); 94 missing; 3 in-body entries, all shown to be legitimate secondary entry points.**

---

## 1. Function bodies over-extend (BIGGEST, and a byte-exactness defect)

**50 of the 94 remaining missing functions are swallowed by a neighbouring function's computed
body** — all 50 lie inside a mosura body, **zero** in open space. The pattern matches them; the
"already inside a function" guard (`FunctionStartAnalyzer.java:403`) then correctly refuses.

So the defect is not discovery, it is **`compute_function_bodies` running past the real end into
the next function**. That also means those neighbours carry wrong extents — and a function with a
wrong extent can never recompile byte-exact however good the decompiler becomes. Same class as the
3 tracked in-body entries.

Next step: compare mosura's body computation against Ghidra's flow/termination rules
(`Function.getBody`, and how Ghidra bounds a body at a following function's entry). Not yet
investigated.

## 2. Bare frame-first prologue is unmatched (17 functions) — ⏳ PARTLY CLOSED, needs a WAR2 run

`55 89 e5` **without** a following `sub esp`. Our set inherited Ghidra's gcc anchors
(`0x5589e583ec`, `0x5589e581ec....0000`) which require it — but per the warcraft2-re census
**81% of framed WAR2 functions have no `sub esp`** (save-first 891 without / 426 with; frame-first
187 without / 52 with). Needs the precision guards in §3 to avoid over-matching, since bare
`55 89 e5` is a common 3-byte sequence.

**Landed:** this was not a missing *invention*, it was an incomplete *inheritance*. Ghidra ships
**six** frame-first patterns and this file had taken two — the two that require `sub esp`. The four
left behind (`0x5589e5..83ec`, `0x5589e5....83ec`, `0x5589e5 01010... 01010...`,
`0x5589e58b 01...101`) are exactly the bare shape. All six are now stated, in both `mov ebp,esp`
encodings, with #5 tightened to Watcom's save order (the saves *after* a frame setup obey the same
order as the ones before — measured on both `-of+` fixtures). 73 → 99 patterns. Gated by
`function_start.rs::frame_first_family_covers_the_bare_prologue`; fixture function sets unmoved.

**Still open, and deliberately:** a frame setup followed by ordinary code with no recognised filler
before it — `55 89 e5 40` (inc eax), `55 89 e5 e8` (call), both present in `wprologue`. Covering
those needs a naked 24-bit `0x5589e5`, which **no Ghidra x86 pattern file states**; every one of
Ghidra's frame-first patterns either adds discriminating bytes or is paired with the filler that
ends the previous function. The unit test pins the residual so adding one is a deliberate act.
**Needs a WAR2 run** to say how many of the 17 the four completed patterns recover, and whether the
naked form is worth its precision cost — precision for it is unmeasurable anywhere else (§5).

## 3. Tighten the pattern with two measured invariants (free precision) — ✅ LANDED

From warcraft2-re's census of 1317 save-first functions — both are zero-recall-cost:

- **The callee-save push order is rigid**: `ebx(53), ecx(51), edx(52), esi(56), edi(57)`.
  Subsequences allowed, reordering never — **1317 conforming, 0 nonconforming**. Watcom 10.0a
  under `-od` reproduces the same order independently.
- **The run never exceeds 5** (there are only five callee-saves besides EBP). A run of 6+ before
  `55 89 e5` is a false positive by construction.

Our current patterns accept any `0x50`–`0x57` run of length 1–5, so enforcing the order is strictly
tighter at no cost.

**Landed:** the save-first family is now the 31 non-empty ordered subsequences × the two `mov
ebp,esp` encodings (62 patterns), gated by
`function_start.rs::save_first_family_enforces_watcoms_push_order` — the ground-truth fixtures
cannot see this property, since `wprologue` and `fnpattern` are both `-of+`, i.e. frame-first.
A third independent confirmation of the order came free: Open Watcom v2's own saves in
`wprologue.watcom-x86-32` read `53 51 52 56`, `51 56 57`, `56 57`. Fixture function sets unmoved
(fnpattern 5, wprologue 15, lestruct 4).

## 4. Save-first regression fixture (closes a real gate gap)

`oracle/ground-truth/src/wprologue.c` gates recall 15/15 and precision 0-spurious — but only for
**frame-first**, because modern Open Watcom emits frame-first while WAR2 is save-first. The
save-first family currently has **no gate**.

Verified recipes (from warcraft2-re, and I reproduced Recipe A first try — it emits
`53 52 55 89 e5`, byte-identical to WAR2 `0x00010bd0`):

```
Recipe A  wcc386 -4r -fpi87 -s -onatx   (source uses alloca)   <- optimized, short-form sub esp
Recipe B  wcc386 -4r -fpi87 -s -od      (no alloca)            <- push runs 3-6 on demand
```

**The operative flag is `-of+`, and it must be REMOVED.** `-of`/`-of+` requests a *traceable* frame,
which forces `55 89 e5` to offset 0. A frame required for *addressing* (alloca, `-od`) is emitted
after the saves. With neither, the optimizer omits the frame pointer and EBP becomes a plain
callee-save — which is the "no `55 89 e5` at all" case.

Note: these reproduce the **shape**, not WAR2's provenance. 891 of WAR2's 1317 save-first functions
have no `sub esp`, so its frame was traceability-only, emitted after the saves — which 10.0a's
`GenProlog` (`bld/cg/intel/c/i86proc.c`) never does. That unresolved difference is warcraft2-re's
`cgflag:ecx-pre-frameptr-save` blocker (~1235 of their rows). A fixture gating the shape is all a
regression gate needs.

## 5. ⭐ Generalise across the Watcom matrix (STANDING SCOPE RULE)

The pattern set is currently specified by one binary. It must cover the axes that actually change
prologue shape, and the corpus must gate each:

| axis | values | why it changes the shape |
| --- | --- | --- |
| **frame mode** | `-of+` / `-od` / neither | frame-first vs save-first vs frame-pointer-omitted — the §4 finding |
| **calling convention** | `-4r`/`-5r` (register, `__watcall`) vs `-4s`/`-5s` (stack, `__cdecl`) | register-based args change callee-save pressure, hence the push run; stack-based changes the whole entry |
| **stack checking** | default vs `-s` | **without `-s` Watcom emits a stack-probe call in the prologue** — a different entry shape entirely. WAR2 used `-s`; most binaries do not |
| **optimization** | `-od` / `-onat` / `-onatx` / `-ox` | frame-pointer omission, and whether saves are hoisted |
| **compiler version** | 9.0x, 10.0/10.0a, 10.5, 10.6, 11.0, OW 1.x, OW 2.0 | measured divergence already: OW2 emits frame-first where WAR2-era emits save-first |
| **target** | `-bt=dos/os2/linux/nt` | affects the runtime and entry conventions |
| **FP model** | `-fpi87` / `-fpi` / `-fpc` | inline x87 vs emulated calls in the body |

**Tooling already exists for this** — no blocker:
- `scripts/setup-watcom-dosemu.sh <ver> --compile <file.c>` stages 10.0a/10.5/10.6/11.0 from the
  archives under `/data/tools/watcom` and compiles (verified: 10.0a, 10.6, 11.0 each reproduce
  their committed `<rev>.code` byte-identically).
- Native Open Watcom v2 at `/data/open-watcom-v2/bld/cc/386/linuxx64/binbuild/wcc386.exe`.
- `~/tools/open-watcom` is the `GT_WATCOM` root the ground-truth `build_watcom` column uses.

Suggested shape: a small prologue-spec source compiled across the matrix, each cell contributing a
fixture whose truth comes from the compiler (symbol table for ELF, linker map for LE/DOS), gating
**recall and precision per cell**. Cells that need dosemu can be committed as artifacts the way
`oracle/codegen-probes/watcom/<rev>.{obj,code}` already are, so CI never needs the historical
toolchain.

⚠️ Do **not** tune the pattern set against WAR2's function count. Precision is unmeasurable there
(the tracker covers 71.4% of the code object, so a hit in a gap is undecidable). Precision is only
measurable on a self-compiled binary where every function is known — that is what the matrix is for.

## 6. Open defect: 7,322 extra instruction starts (over-decode)

255 contiguous runs, 104.4% of Ghidra's code coverage — data decoded as code. It produces almost no
bad functions (3 in-body entries) but it is real over-decoding with **no live hypothesis**. Three
candidates are dead **by measurement** — do not retry them:

- `mustTerminate=true` (`isValidSubroutine`) — measured: function sets identical, −0 +0;
- the flow-disassembler bounds (`708ac08`) — measured: identical;
- the address-table "code target vs function start" thread — refuted (the relocation run at the
  suspect site is a dispatch/vtable, targets scattered across many functions).

## 7. Handed to warcraft2-re, awaiting their verdict

`war2-survey/analysis-gap/mosura-discovered-functions.{csv,md}` — **872 functions in neither the
tracker nor Ghidra** (763 save-first = 87.5%, matching the target's own 84.6% distribution; 71,697
bytes against ~126,770 of measured gap). They accepted the offer. Their verdict feeds back as
either a recall win to keep or a precision problem to fix.

Also pending from their reply: **Watcom's own shipped `CLIB3R.LIB` is save-first** (`write_`,
`__CMain`, verified inside WAR2 with 0 unmasked mismatches). So a frame-first-only pattern set
misses Watcom CRT code in **any** binary — independent support for §5.

---

## Corrections to earlier claims in this repo's notes

- `status=source-done` in `decomp-tracker.csv` does **not** mean byte-matched. It means "faithful C
  authored, byte-diverges by a documented blocker" (byte-exact is `matched`/`matched-fixups`,
  267 rows of 2120). Anything reasoning from "source-done ⇒ byte-identical" is wrong.
- "94% of WAR2 prologues open with a push run" conflates families: `push ebp` is `0x55`, inside
  `0x50`–`0x57`, so frame-first and most frameless functions satisfy it too. The real split is
  **save-first 1317 / frame-first 239 / no-frame 564**; save-first is 84.6% of *framed* functions.
- Ghidra's cold analysis of WAR2 is **2145**, not 1944. The 1944 figure comes from passing
  `-processor "x86:LE:32:default"` to `analyzeHeadless`, which bypasses the ELF opinion and lands
  compiler spec `windows` on an ELF — worth 201 functions. Never pass `-processor` for this image.
