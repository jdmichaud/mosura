# Function-discovery backlog

Open items for mosura's function-discovery pipeline, as of 2026-08-06. Written down because this
track has produced several findings that are cheap to lose and expensive to re-derive.

**Standing scope rule (user, 2026-08-06):** *WAR2 is one example among many. mosura will be run
against all kinds of binaries, and we must be able to identify functions produced by **all Watcom
compilers under all options that affect function shape**. The test suite has to reflect that.* So
every item below is judged on whether it generalises, not on whether it moves the WAR2 number.

Current WAR2 state @ `556cdb3` (the diagnostic, not the goal): **2900 functions; 92 missing vs the
expert tracker's 2120; 3 in-body entries at depths [37,59,65], all shown to be legitimate secondary
entry points; 872 not-in-tracker; 923 not-in-Ghidra.** (Was 2898 / 94 missing @ `4d28561`.)

⚠️ Every number in this file is STALE unless stamped with a commit that is an ancestor of HEAD. A
WAR2 run is ~224s and only the lead runs it; do not quote an unstamped figure.

**The remaining 92, split — this is the number that sets priority:**

```
51  inside an over-extended mosura body   <- §1; NO pattern can ever reach these
41  in open space                          <- of which 15 are bare frame-first (§2)
```

---

## 1. Function bodies over-extend (BIGGEST, and a byte-exactness defect) — ⭐ NEXT

**51 of the 92 remaining missing functions are swallowed by a neighbouring function's computed
body** — all 51 lie inside a mosura body, **zero** in open space. The pattern matches them; the
"already inside a function" guard (`FunctionStartAnalyzer.java:403`) then correctly refuses.

So the defect is not discovery, it is **`compute_function_bodies` running past the real end into
the next function**. That also means those neighbours carry wrong extents — and a function with a
wrong extent can never recompile byte-exact however good the decompiler becomes. Same class as the
3 tracked in-body entries.

**Why it outranks everything else here:** it is 51 of 92 against §2's 15, it is the only item that
no pattern work can ever reach, and it is the only one that is *also* a byte-exactness defect
rather than only a discovery one. §2's residual is explicitly parked behind it.

### Grounding (READ-ONLY, 2026-08-06) — Ghidra's actual mechanism, and three named divergences

Ghidra's path is `CreateFunctionCmd.getFunctionBody(program, entry, includeOtherFunctions=false,
monitor)` → `new FollowFlow(program, entry, dontFollow, false, false, true).getFlowAddressSet()`,
with `dontFollow = {COMPUTED_CALL, CONDITIONAL_CALL, UNCONDITIONAL_CALL, INDIRECTION}`.
(`Ghidra/Features/Base/.../CreateFunctionCmd.java:613`,
`Ghidra/Framework/SoftwareModeling/.../block/FollowFlow.java`.) mosura's equivalent walk exists
**twice** — `analyzers/mod.rs::compute_function_bodies` and
`analyzers/function_start.rs::flow_body` — and they must not drift apart.

**⭐ 1. The no-return fall-through, and it is a DRIFT INSIDE mosura, not a missing port.**
Ghidra asks `currentInstr.getFallThrough()` (`FollowFlow.java:556`), which is null after a call to
a non-returning function. mosura's *disassembler* does exactly this and consults
`program.is_noreturn` (`analyzers/mod.rs:130`, comment: "Ghidra's followFlow consults
Function.isNoReturn"). But `compute_function_bodies`, **170 lines further down the same file**
(:298), recomputes `falls` from the opcode alone:

```rust
let falls = !matches!(last, Some(OpCode::Return | OpCode::Branch | OpCode::Branchind));
```

with no no-return check — and `flow_body` has the same omission. So the decoder correctly stops
after `call <noreturn>`, and the body walk then steps straight over it into the next function.
That is precisely the reported shape: 51 swallowed entries, zero in open space.

**2. The listing, not a re-decode.** Ghidra continues only if
`getListing().getInstructionAt(nextAddress) != null` (`FollowFlow.java:566`) — it walks *defined
instructions*. mosura re-disassembles raw bytes through a 16-byte window and continues regardless,
so it flows through alignment padding and data that were never code.

**3. No instruction at the entry ⇒ a one-byte body.** `getFunctionBody` returns
`new AddressSet(entry, entry)` when the listing has no instruction at the entry
(`CreateFunctionCmd.java:616`). mosura decodes fresh instead; its one-byte fallback fires only when
the walk yields nothing at all.

**Opposite direction, worth noting so a fix does not overshoot:** `FollowFlow` follows
COMPUTED_JUMP by default (`followComputedJump = true`, :42) — computed-jump targets are *in* a
Ghidra body. mosura follows only `Branch`/`Cbranch` static targets and never a `Branchind` target,
so switch-case bodies are too *small*. Do not "fix" that in the same change as the over-extension.

## 2. Bare frame-first prologue is unmatched (17 functions) — ✅ CLOSED `556cdb3`; residual RULED OUT

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

**Measured on WAR2 @ `556cdb3` (lead, 224s):** the four completed patterns recover **2**, and cost
**nothing** in precision — exactly what restoring what Ghidra already ships and validated should
look like.

```
functions            2898 -> 2900   (+2)
missing vs tracker     94 -> 92
bare frame-first miss  17 -> 15
IN-BODY intrusions      3 -> 3      unchanged, identical depths [37,59,65]
not-in-tracker        872 -> 872    no new spurious
not-in-Ghidra         923 -> 923
```

**RULING (lead, 2026-08-06): do NOT add the naked `0x5589e5`.** All 15 remaining *are* in open
space, so a naked pattern could in principle take them — but that is the wrong order of work. Of
the 92 still missing, **51 are behind §1** (an over-extended body, which no pattern can ever
reach) against 41 in open space. Spending a 24-bit pattern with unmeasurable precision on 15, while
51 sit behind a defect that *also* produces wrong extents and therefore blocks byte-exact
recompilation, is backwards. The independent argument stands too: no Ghidra x86 pattern file states
a bare `0x5589e5`, so writing one is an invention, and our fixtures are far too small to bound the
false-positive rate of a 3-byte match on a 443 KB image.

**Revisit only after §1.** Fixing the bodies changes what is reachable, so some of the 15 may
resolve on their own, and the false-positive question can then be asked against a clean baseline.
Leave `frame_first_family_covers_the_bare_prologue`'s residual assertion exactly as it is — it is
what makes adding the naked pattern a deliberate act rather than a drift.

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

## 4. Save-first regression fixture (closes a real gate gap) — ✅ LANDED `cd70db7`

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

**Landed:** `wprologue_sf.watcom-x86-32` via `build_watcom wprologue_sf "-4r -fpi87 -od"` — Recipe
B, on the **native** OW2 toolchain, no dosemu. `src/wprologue_sf.c` is a one-line
`#include "wprologue.c"` so the twins cannot drift; all 15 inherited functions come out save-first,
run lengths 2..5, `p_leaf_` = `53 51 52 56 57 55 89 e5`. (Recipe A also works natively — OW's own
`#pragma aux __doalloca` from `bld/hdr/linux/h/malloc.h` supplies `alloca`, since the corpus
toolchain root has `binl/` only and no headers.)

Two things had to be fixed before the gate measured anything, **both of which apply to every §5
matrix cell**:
- the fixture needed an ORPHAN (`sf_orphan_fn_`, plus `sf_trail_fn_` called from the asm stub to
  keep it off the section edge). Without one, recall is vacuous: every function in `wprologue.c` is
  called from `main`, and it scored 15/15 recall + 0 spurious with the byte-pattern analyzers OFF;
- the fixture could not reach the Watcom pattern file at all — see §5.

Gate: `ground_truth_parity::watcom_save_first_shape_spec`. cspec=watcom 17/17 + 0 spurious ·
orphan gone with the byte-pattern search off · cspec=gcc misses the entry and marks it **+2**,
which is the prologue shift reproduced end to end on a self-compiled binary for the first time
(`src/fnpattern.c` property 1 records that as something this corpus "CANNOT" do).

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

### Two prerequisites every matrix cell inherits (learned building §4's cell)

**(a) A cell cannot reach the Watcom pattern file by default.** The `(language, compiler)` decision
tree picks the pattern file, and `loader::watcom::compiler_spec_id` decides the compiler from the
**run-time copyright banner** — a string in the C run-time, not in anything the compiler emits. The
corpus links `option nodefaultlib` with a hand-written `_cstart_`, so **no ground-truth binary
carries the banner and every one detects as `cspec=gcc`** (measured: `wprologue`, `wprologue_sf`,
`fnpattern`). Until §4 this meant `specs/patterns/x86watcom_patterns.xml` had **zero fixture
coverage of any kind**, and any gate written against a Watcom-compiled fixture was silently
measuring Ghidra's `x86gcc_patterns.xml`. `MOSURA_X86_32_CSPEC=watcom|gcc` routes one binary
through both; it is inert when unset. Every new cell needs the same routing, or a linked CRT.

**(b) A cell needs an orphan, or its recall proves nothing.** If every function is call-reachable,
the reference-driven analyzers recover them all and the pattern set is never load-bearing —
measured on `wprologue_sf` before its orphan existed: 15/15 recall and 0 spurious with the
byte-pattern analyzers OFF. `src/fnpattern.c` properties 2-5 are the specification for this.

### The `compiler version` axis is already partly answered — in the direction that helps

The rigid save order `ebx ecx edx esi edi` is **Watcom codegen, not a WAR2-era artifact**. Three
independent sources agree: warcraft2-re's WAR2 census (1317 conforming / 0 nonconforming, Watcom
10.0a), Watcom 10.0a under `-od` compiled directly, and **native Open Watcom v2** — whose saves in
our own `wprologue.watcom-x86-32` read `53 51 52 56`, `51 56 57`, `56 57`, and in
`fnpattern.watcom-x86-32` read `52`, `56 57`. Two decades of compiler versions, same order. The
same holds for saves emitted *after* a frame setup (§2), so the ordering guard should survive the
whole version axis rather than needing a per-cell measurement.

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
