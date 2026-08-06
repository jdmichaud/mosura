# Function-discovery backlog

Open items for mosura's function-discovery pipeline, as of 2026-08-06. Written down because this
track has produced several findings that are cheap to lose and expensive to re-derive.

**Standing scope rule (user, 2026-08-06):** *WAR2 is one example among many. mosura will be run
against all kinds of binaries, and we must be able to identify functions produced by **all Watcom
compilers under all options that affect function shape**. The test suite has to reflect that.* So
every item below is judged on whether it generalises, not on whether it moves the WAR2 number.

Current WAR2 state @ `556cdb3` (the diagnostic, not the goal): **2900 functions; 2078 of the expert
tracker's 2120 = 98.0%; 42 genuinely missing; 872 not-in-tracker; 923 not-in-Ghidra.**

⚠️ Every number in this file is STALE unless stamped with a commit that is an ancestor of HEAD. A
WAR2 run is ~224s and only the lead runs it; do not quote an unstamped figure.

### ⭐ SCORE SHIFT-TOLERANTLY AGAINST THIS TRACKER — a naive entry comparison overstates the gap by 50

The expert tracker records **save-first functions at the `push ebp`, i.e. MID-PROLOGUE**, with the
callee-save run before it. That is the same `push ebp`-anchoring artifact
`warcraft2-re/analysis/function-boundary-correction.md` documents and corrected for 132 rows — and
50 further rows the correction pass missed. mosura sits at the TRUE entry, so an equality test on
entry addresses scores those 50 as misses when mosura is the more correct of the two:

```
mosura 0001380c [53 51 52 56 57 55 89 e5]   tracker 00013811   delta 5
mosura 000142e8 [53 51 52 55 89 e5 81 ec]   tracker 000142eb   delta 3
mosura 00017850 [53 51 56 57 55 89 e5 83]   tracker 00017854   delta 4
```

**A function counts as recovered when mosura has an entry within 1-7 bytes BEFORE the tracker's,
with a save-first run between them.** Scoring naively:

```
                                          naive   shift-tolerant
tracker functions                          2120            2120
  matched                                  2028            2078
  MISSING                                    92              42
```

The 50-function difference is not a code change — it is the same binary measured correctly. Any
figure in this file or in a report that predates 2026-08-06 and says "92 missing" is the naive
number. See [[war2-tracker-anchors-mid-prologue]].

---


## 1. Function bodies over-extend — ⛔ REFUTED 2026-08-06, NOT A DEFECT

**There was no over-extension.** The item existed because 51 tracker functions mosura "missed" all
lay inside a mosura body and none in open space — a distribution that looked diagnostic. It was an
artifact of the naive entry comparison described at the top of this file.

**The histogram that settled it** (lead, WAR2 @ `556cdb3`): of the 51, **44 had a single-byte push
immediately before them** — `57` push edi ×23, `52` push edx ×13, `56` push esi ×8 — and 7 had no
code unit ending there. A push is not a fall-through signature, which killed the "flow ran past the
end" reading. Reading the bytes instead:

```
bytes at tracker_entry-2:   56 57 | 55 89 e5 83 ec ...
                            ^^^^^   ^^^^^^^^ the tracker's recorded entry
```

The tracker's entry is at the `55`, mid-prologue. Testing for a mosura function slightly earlier:

```
"swallowed" missing entries                   51
  with a mosura function 1-7 bytes BEFORE     50   <- the SAME function, at its TRUE entry
  genuinely absent                             1
```

So mosura was not swallowing them — mosura was **right and the oracle was late**, and right
*because* of the save-first pattern family (§3, §4). The 51 do not exist as a defect; the real
gap is 42.

**What to take from it, beyond the number:**
- the naive comparison overstated the gap by 50 — the shift-tolerant rule at the top of this file
  is now the scoring method, and [[war2-tracker-anchors-mid-prologue]] carries it;
- "all 51 inside a body, zero in open space" felt like a mechanism fingerprint and was a
  measurement artifact. A distribution can be an artifact just as a count can;
- three separate mechanisms (no-return fall-through, opcode-vs-reftype, re-decode-vs-listing) were
  each consistent with that distribution. Consistency with the evidence is not the same as being
  the cause of it — see §9, where they now live on their own merits.

**Do not reopen without a fresh measurement.** The remaining 7 ("no code unit ends here") are a
thread into §6, not into this item.

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

**RULING (lead, 2026-08-06): do NOT add the naked `0x5589e5`. UPHELD after §1 was refuted.**

The ruling was first argued from a premise that turned out to be false — "51 of the 92 are behind
§1, so pattern work is the wrong order". §1 does not exist and the gap is 42, not 92, so that
argument is void. The ruling stands on the argument that never depended on it: no Ghidra x86
pattern file states a bare `0x5589e5` anywhere — every one of its frame-first patterns either adds
discriminating bytes or is paired with the filler ending the previous function — so writing one is
an invention, and the fixtures are far too small to bound the false-positive rate of a 3-byte match
on a 443 KB image. ~15 of the 42 are bare frame-first; that is the whole prize, against an
unmeasurable precision cost.

**Revisit only with a way to measure precision** — §5's matrix, not a WAR2 count (precision is
undecidable there: a hit in the tracker's 28.6% gap could be either). Leave
`frame_first_family_covers_the_bare_prologue`'s residual assertion exactly as it is — it is what
makes adding the naked pattern a deliberate act rather than a drift.

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

### ⭐ CELL 1 ✅ LANDED `a59a886` — stack checking (`-s` vs default): a NEW PROLOGUE SHIFT, 10 bytes

**This cell is the demonstrated case for the standing scope rule, not an assertion of it.** WAR2
could never have shown this defect: WAR2 was built with `-s`, and `-s` is not the default, so the
entire stack-probe family is invisible from that binary alone. The failure mode was also *wrong
address* rather than *missing* — the same class that motivated this whole pattern file — so it
silently produced wrong extents, which block byte-exact recompilation. That is exactly the user's
point that WAR2 is one example among many.

Measured on native OW2, 2026-08-06, **before writing any pattern** (the shapes, then the set).

**Without `-s` every framed function begins with a stack probe.** `wcc386` emits
`push <framesize>; call __CHK` — and where it sits depends on the frame mode:

```
-of+          55 89 e5  68 <imm32>  e8 <rel32>        frame, THEN probe
-od / -oc     68 <imm32>  e8 <rel32>  53 51 52 56 57  55 89 e5    <- probe FIRST, at offset 0
-onatx        (omitted for small frames — no probe at all)
```

**These functions are not invisible. They are found at the WRONG ADDRESS**, which is worse.
`p_frame_` at `08048366` under `-od`:

```
08048366  68 48 00 00 00   push 0x48        <- THE TRUE ENTRY
0804836b  e8 97 fd ff ff   call __CHK
08048370  53 51 52 56 57   push ebx/ecx/edx/esi/edi   <- our save-first family matches HERE, +10
08048375  55 89 e5         push ebp; mov ebp,esp
```

This is **the same defect that motivated this entire pattern file** — `x86gcc_patterns.xml`
anchoring at the `55`, five bytes late — reappearing one level up with the stack probe as the new
prefix. A wrong entry means a wrong extent, so it also blocks byte-exact recompilation (§1's
argument, which survives §1's refutation).

Not one of the file's 99 patterns starts with `0x68`, so nothing anchors the true entry today.

**Why WAR2 never showed this:** WAR2 was built with `-s`. **Most binaries are not** — `-s` is not
the default — so this is the clearest evidence yet for the standing scope rule.

**Proposed shape, NOT yet written** (precision hazard first): the naive anchor
`0x68 ........ 0xe8 ........` is `push imm32; call rel32`, which is an extremely common ordinary
code sequence — every cdecl call with one immediate argument. It must NOT be stated bare. Two
candidate forms, both to be measured:
- probe-first: `0x68 ........ 0xe8 ........` followed by a callee-save push or `0x55`, marking the
  `68` — 15 bytes with 8 wildcarded;
- frame-then-probe: `0x5589e5 0x68 ........ 0xe8 ........`, which is already strongly anchored.

The overlap rule then does the rest: with both the probe pattern (true entry) and the save-first
pattern (+10) matching, `create_functions` keeps the LOWEST — exactly how the save-first family
fixed the original shift.

**LANDED `a59a886`, SUITE-VERIFIED at `18dccdc` (622 passed / 0 failed, default parallelism)** — 8 patterns (99 → 107): two frame-then-probe forms, stated plainly because
`55 89 e5` ahead of the probe already anchors them, and six probe-first forms carrying
`after="defined"` + `validcode="6"` + `possiblefuncstart`. Gate:
`ground_truth_parity::watcom_stack_probe_shape_spec` — recall, precision, **that the anchor is the
probe and not the push run ten bytes in**, and attribution via the analyzer toggle. Measured under
`cspec=watcom` across every Watcom fixture: **zero spurious anywhere**; revert-checked, both +10
shifts return without the family.

⚠️ **Stamp cells suite-verified, not just gate-verified.** Cell 1 was landed and reported on its
own gate; the full suite was red for two commits before anyone noticed, because the break — a
process-global env race in the test harness, not the patterns — was invisible to the fast
per-fixture runs the cell work uses. Fixed at `18dccdc` (see `analysis::overrides`). The standing
practice from here is to checkpoint after **each** cell so the red window is one cell wide at
worst.

### What the trailing-push guard buys — measured, and the fixture cannot see it

The lead's condition before trusting the probe-first form. Raw byte scan for
`68 ?? ?? ?? ?? e8` and how many are followed by a callee-save/`ebp` push:

| binary | bytes | `68..e8` | +save | guard removes |
| --- | ---: | ---: | ---: | ---: |
| `wprobe.watcom-x86-32` | 4,492 | 15 | 15 | **0** |
| `mingw_hello32.exe` (gcc/mingw, cdecl) | 229,835 | 1 | 0 | **1** |
| every other x86-32 fixture | — | 0 | 0 | 0 |

- **On the fixture the guard buys nothing** — all 15 sequences are real stack probes and all 15
  pass it. That is the correct behaviour and it means **the fixture cannot demonstrate the guard's
  precision value**, only its zero recall cost.
- **On real-world code it removed 1 of 1**: mingw's single `push imm32; call rel32` is not
  followed by a save push, so the guard removed exactly the false positive it exists for.
- ⚠️ **Sample size 1.** And the reason is itself worth recording: **gcc/mingw passes arguments with
  `mov [esp+N]`, not `push`**, so gcc-compiled cdecl code barely produces this sequence at all. The
  codegen that would stress it is push-args — Watcom `-4s`/`-5s` or MSVC — **which the corpus does
  not contain**. Cell 2 is therefore the right place to stress this guard, not a WAR2 run.

**Standing caveat:** the probe-first form's false-positive rate is bounded by measurement on
`wprobe` and by a single real-world case. A WAR2 run would raise confidence; cell 2 would raise it
more, on a binary where precision is decidable.

**Build note for this cell:** `build_watcom` hardcodes `-s`, so a no-`-s` cell needs it moved into
the overridable options, and the link needs a `__CHK` stub in the `_cstart` asm — without one
`wlink` fails with `E2028: __CHK is an undefined reference`, which is itself the proof that the
axis changes code generation.

### ✅ CELL 2 CHECKED — calling convention (`-4s` stack vs `-4r` register): **NO NEW SHAPE, no fixture**

Measured 2026-08-06, then **deliberately not turned into a fixture** — the stop rule is that a cell
gets a fixture only if it exposes a shape we would otherwise miss, because a corpus that grows
without adding discriminating power is a maintenance cost dressed as coverage.

A `wcall` fixture was actually built (`wprologue.c` + orphan, `-4s`) and measured across all three
optimization settings, then deleted:

```
-4s -of+    17/17 recovered, 0 spurious      (16 with the byte-pattern search off)
-4s -od     17/17 recovered, 0 spurious      (16 with it off)
-4s -oc     17/17 recovered, 0 spurious      (16 with it off)
```

Full recall with **no new patterns**. The convention changes callee-save *pressure* — and so the
length of the push run — but not the *shape* of the entry, and the existing families already span
the lengths:

```
-4s -of+   55 89 e5 8b 45 08      frame + frame-relative load     x86gcc #6
           55 89 e5 53 8b 5d 08   frame + ONE save + load         family (4), filler-paired
           55 89 e5 53 56 57 …    frame + saves                   x86gcc #5 (53,56,57 conforming)
-4s -od    53 56 57 55 89 e5 …    save-first, conforming run      family (1)
```

The `16 with the search off` column matters: the orphan is pattern-discovered in every variant, so
this is a real measurement of the pattern set and not a vacuous pass.

**What the axis DOES move is the symbol interface, not the prologue.** Under `-4s` wcc386 emits
**bare** symbol names — `main`, not `main_` — so a `-4s` cell cannot share a `_cstart` stub with
any `-4r` cell. That is a build-time obstacle worth knowing before someone tries; it is not a
pattern-set gap.

**Consequence for §5's ranking:** the convention axis was listed as "yes, changes the entry shape".
Measured, it does not. Cross-checked against all three optimization settings, so this is not a
single-cell accident.

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

## 6. Over-decode — ⛔ CLOSED 2026-08-06, NOT A DEFECT

**mosura decodes nothing it should not.** Measured absolutely on WAR2 @ `77c8351`, with the
tool's positive control passing first:

```
self-test: A1, A2, A3, A4 each detect a planted violation and stay silent when clean
== WAR2.EXE ==   instructions 132356   decoded bytes 387761
  obj1_text  00010000..0007c49f  exec=true
  obj2_data  00080000..000ab2ff  exec=false
A1 non-executable decode         starts=0  bytes=0  runs=0
A2 offcut starts                 0
A3 flow into mid-instruction     1        0006ecb4 -> 0006ecec
A4 fixup target mid-instruction  0  (of 17511 relocations; ~3178 code-targeted)
A5 unreachable starts            81 (runs 81)
```

- **A1 = 0** — not one instruction outside what the LE object table itself marks executable;
  `obj2_data` untouched.
- **A2 = 0** — no offcut start in 132,356 instructions.
- **A4 = 0 against a live fixup table** — and this is the check that settles it, because it is the
  only one where the **file itself supplies both the address and the claim that it is code**.
  Every code-targeted fixup lands exactly on an instruction boundary in our decode. Neither inert
  (unlike on the ELF fixtures, which have no relocation table) nor differential.

So "7,322 extra instruction starts / 104.4% of Ghidra's code coverage" was never over-decode on
our side. It was measuring **Ghidra's UNDER-decode** — the differential named a difference that
was a defect on neither side, and the item existed only because the difference was read as ours.
Three hypotheses were killed chasing it (`mustTerminate`, the flow-disassembler bounds, the
address-table thread) before anyone asked whether the premise was sound.

**This is the third item on this track to dissolve under measurement** — §1, the no-return
diagnosis, and now §6 — and in every case the culprit was a differential or a derived summary,
never the binary. The standing consequence is recorded at the top of this file and in
[[absolute-vs-differential-wrongcode]]: **before hunting a defect stated as a differential, build
an absolute measure and give it a positive control.** `docs/over-decode-measure.md` +
`examples/over_decode` are that measure, and are reusable.

⚠️ The run above printed A4's denominator as the **total** relocation count. That overstates its
coverage — A4 only examines fixups whose target is in executable memory (on `lestruct`: 3 of 9).
Fixed after the fact; the current build prints `(of N CODE-TARGETED fixups; M relocations total)`.
The conclusion is unaffected (0 offcut is 0 either way) but the denominator was wrong, and a zero
has to carry the denominator it was measured against.

### Residuals, both small and both real

- **A3 = 1** — `0006ecb4 -> 0006ecec`, one flow edge landing mid-instruction, in 132,356
  instructions. A genuine self-consistency violation that no comparison artifact can explain.
  The tool now dumps the source bytes, the instruction the target lands inside, and the offset
  into it, so **one run diagnoses it** rather than costing a round trip for bytes.
- **A5 = 81 unreachable starts** — probably the byte-pattern search *working*: `Function Start
  Search` exists to create functions with no inbound flow, so it populates A5 by construction.
  Before treating any of it as signal, ablate the four FSS analyzers and subtract. Only starts
  that are neither pattern-discovered nor flow-reachable are interesting.
- **A4 measured and clean** (see above). The first run predated it, which was provable from the
  self-test line naming only A1-A3 — that line is a build identifier as well as a control.

**Part B (provenance by ablation) deliberately NOT built.** Its precondition was "A1 shows
something to attribute"; A1 is 0, so it would attribute nothing.

## 7. Handed to warcraft2-re, awaiting their verdict

`war2-survey/analysis-gap/mosura-discovered-functions.{csv,md}` — **872 functions in neither the
tracker nor Ghidra** (763 save-first = 87.5%, matching the target's own 84.6% distribution; 71,697
bytes against ~126,770 of measured gap). They accepted the offer. Their verdict feeds back as
either a recall win to keep or a precision problem to fix.

**⭐ SECOND THING TO HAND BACK (2026-08-06): 50 boundary corrections.** §1's refutation produced
50 tracker rows whose recorded entry is at the `push ebp`, mid-prologue, with the save-first run
before it — rows their own `function-boundary-correction.md` pass (which corrected 132) missed.
mosura has each at the true entry, 1-7 bytes earlier, with the bytes to prove it. Concrete and
actionable for them, and it is evidence flowing the other way for once: our pattern set correcting
their oracle. The lead is folding it into the existing CSV rather than opening a new thread.

Also pending from their reply: **Watcom's own shipped `CLIB3R.LIB` is save-first** (`write_`,
`__CMain`, verified inside WAR2 with 0 unmasked mismatches). So a frame-first-only pattern set
misses Watcom CRT code in **any** binary — independent support for §5.

## 8. Function bodies UNDER-extend at a computed jump (§1's opposite twin)

Split out of §1 at the lead's request (2026-08-06): §1 is "bodies run past the real end", this is
"bodies stop short of it". Opposite signs, so **never fix them in the same change** — a WAR2 delta
mixing the two cannot be attributed per function.

Ghidra's `FollowFlow` follows computed jumps by default (`followComputedJump = true`,
`FollowFlow.java:42`; `CreateFunctionCmd`'s `dontFollow` list contains COMPUTED_**CALL** and
INDIRECTION but **not** COMPUTED_JUMP), so a switch's case bodies are inside the Ghidra body.
mosura's walk pushes a target only for `Branch`/`Cbranch` and never for `Branchind`
(`analyzers/mod.rs:300-306`, `function_start.rs::flow_body`), so every recovered switch's case
bodies are outside the body unless some other edge happens to reach them.

Not yet measured. The natural gauge is a fixture with a recovered jump table — `narrowsw`,
`switchcall`, `dispatch`, `tables` — asserting the case bodies are inside the function's extent.
Note the same wrong-extent-blocks-byte-exactness argument as §1 applies here.

## 9. Three real divergences in mosura's body walk (surfaced by §1, independent of it)

§1 dissolved, but these did not: each is a genuine difference from Ghidra's body computation,
found by reading both sides, and each survives the refutation on its own merits. **None of them
caused §1**, so none has a WAR2 prediction attached — treat them as correctness work with the
burden of proof on whoever lands one.

Ghidra's path is `CreateFunctionCmd.getFunctionBody(program, entry, includeOtherFunctions=false,
monitor)` → `new FollowFlow(program, entry, dontFollow, false, false, true).getFlowAddressSet()`,
with `dontFollow = {COMPUTED_CALL, CONDITIONAL_CALL, UNCONDITIONAL_CALL, INDIRECTION}`.
(`Ghidra/Features/Base/.../CreateFunctionCmd.java:613`,
`Ghidra/Framework/SoftwareModeling/.../block/FollowFlow.java`.) mosura's equivalent walk exists
**twice** — `analyzers/mod.rs::compute_function_bodies` and
`analyzers/function_start.rs::flow_body` — and they must not drift apart.

**✅ 1. The no-return fall-through — LANDED `0de3523`. Real drift; NOT the cause of the 51.**
Fixed by de-duplication: all three walks now share `analyzers::falls_through`, so the copies
cannot drift again. Gated by `ground_truth_parity::noreturn_call_bounds_the_body` against a new
dynamically-linked fixture, `noret.gcc-x86-64` — the only corpus binary that makes
`noreturn::analyze` run at all. **WAR2 delta 0 by construction** (see below). Landing it exposed a
SECOND defect, invisible until the fixture existed: `noreturn::analyze` ran once before
disassembly, leaving its PLT-thunk propagation dead (it walks `function_manager.functions()`, and
there are none yet), so only the EXTERNAL `abort` was flagged and never the PLT stub — which is
how every call to a dynamically-imported no-return function actually looks. Re-run after the
worklist converges; flagged 1 -> 2. Fix #1 alone left the gate RED.
Original refutation, kept because it is why this carries no WAR2 prediction:
Measured before building anything: `noreturn::analyze` selects its name list from the memory map
and **returns early unless a `.dynsym`, `.plt` or `EXTERNAL` block exists** (`noreturn.rs:128-137`).
WAR2 is a DOS/4GW LE image whose loader names its blocks `objN_text`/`objN_data` (`loader/le.rs:219`)
— none of the three. Confirmed empirically on all four fast fixtures, including the LE path WAR2
uses: **`noreturn_flagged = 0` everywhere** (fnpattern, wprologue, wprologue_sf, lestruct). With
nothing flagged, `falls` is identical with and without the check, so this cannot account for a
single one of the 51. It is still a genuine defect for ELF/PE targets and still worth closing —
but not here, and not as this item's fix. Detail of the drift, for whoever does close it:
Ghidra asks `currentInstr.getFallThrough()` (`FollowFlow.java:556`), which is null after a call to
a non-returning function. mosura's *disassembler* does exactly this and consults
`program.is_noreturn` (`analyzers/mod.rs:130`, comment: "Ghidra's followFlow consults
Function.isNoReturn"). But `compute_function_bodies`, **170 lines further down the same file**
(:298), recomputes `falls` from the opcode alone:

```rust
let falls = !matches!(last, Some(OpCode::Return | OpCode::Branch | OpCode::Branchind));
```

with no no-return check — and `flow_body` has the same omission. So on a target where the analyzer
*does* run, the decoder stops after `call <noreturn>` and the body walk steps over it. On WAR2 the
analyzer never runs, so this is latent, not active.

**2. The listing, not a re-decode.** Ghidra continues only if
`getListing().getInstructionAt(nextAddress) != null` (`FollowFlow.java:566`) — it walks *defined
instructions*. mosura re-disassembles raw bytes through a 16-byte window and continues regardless,
so it flows through alignment padding and data that were never code.

**3. No instruction at the entry ⇒ a one-byte body.** `getFunctionBody` returns
`new AddressSet(entry, entry)` when the listing has no instruction at the entry
(`CreateFunctionCmd.java:616`). mosura decodes fresh instead; its one-byte fallback fires only when
the walk yields nothing at all.

**⭐ 4. THE LIVE CANDIDATE — the body walk reads the OPCODE where Ghidra reads the REFERENCE TYPE.**
Ghidra's `dontFollow` list is expressed in `RefType`s, and a **tail call** (`jmp <function>`) carries
an `UNCONDITIONAL_CALL` reftype after `SharedReturnAnalyzer` has run — so `FollowFlow` refuses to
follow it. mosura's walk instead re-derives the decision from the raw p-code opcode: an unconditional
`jmp` is `OpCode::Branch`, so `falls` is false (correct) **but the branch target is still pushed onto
the worklist**, and if that target is a function mosura has not yet discovered, the walk runs through
the whole callee and swallows it. This is exactly the class recorded in
[[reftype-is-post-override-not-the-instruction]]: *reftypes are analysis OUTPUT; re-deriving flow
from the instruction discards every override the analyzers computed.* It also needs no no-return
flag, which is what makes it the surviving candidate after #1 was refuted.

### Landing conditions for any of them

- **#1 is DONE (`0de3523`).** The rest of this bullet is kept as the record of what it took: Every ground-truth binary measures
  `noreturn_flagged = 0`: the gcc x86-64 column is static/freestanding (`readelf -S`: `.text`, no
  `.dynsym`/`.plt`), the Watcom column links `option nodefaultlib`, and WAR2 goes through
  `analyze_le_file` (`examples/war2_survey.rs:210`) whose blocks are `objN_text`/`objN_data`. So
  `noreturn::analyze` never runs anywhere, and an MVE would pass with the fix reverted. Fixing #1
  means first building a dynamically-linked ELF fixture that calls `abort`/`exit` — which is worth
  having regardless, since `noreturn.rs` is **currently ungated entirely**.
- **One change per measurable effect.** #1, #2, #4 and §8 point in different directions; bundling
  any two makes a WAR2 delta unattributable per function.

---

## Corrections to earlier claims in this repo's notes

- `status=source-done` in `decomp-tracker.csv` does **not** mean byte-matched. It means "faithful C
  authored, byte-diverges by a documented blocker" (byte-exact is `matched`/`matched-fixups`,
  267 rows of 2120). Anything reasoning from "source-done ⇒ byte-identical" is wrong.
- "94% of WAR2 prologues open with a push run" conflates families: `push ebp` is `0x55`, inside
  `0x50`–`0x57`, so frame-first and most frameless functions satisfy it too. The real split is
  **save-first 1317 / frame-first 239 / no-frame 564**; save-first is 84.6% of *framed* functions.
- **"92 missing" / "94 missing" / "51 blocked by over-extended bodies" are all NAIVE-COMPARISON
  figures and are wrong.** The tracker anchors save-first functions mid-prologue at the `push ebp`;
  50 of the apparent misses are the same functions recovered at their TRUE entry. Shift-tolerant,
  the gap is **42** and mosura is at **2078/2120 = 98.0%**. Anything reasoning from the older
  numbers — including the original argument for prioritising §1 — is reasoning from an artifact.
- Ghidra's cold analysis of WAR2 is **2145**, not 1944. The 1944 figure comes from passing
  `-processor "x86:LE:32:default"` to `analyzeHeadless`, which bypasses the ELF opinion and lands
  compiler spec `windows` on an ELF — worth 201 functions. Never pass `-processor` for this image.
