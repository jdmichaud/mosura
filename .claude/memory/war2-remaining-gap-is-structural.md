---
name: war2-remaining-gap-is-structural
description: "81% of WAR2's mismatching functions differ in >40% of their instructions — the gap to byte-exactness is not a tail of small bugs, and only ~97 functions are one or two regions away"
metadata:
  type: project
---

**⭐ MEASURED 2026-08-12 at 375 byte-clean (`classify_diffs.py`, results.m20).** Both instruction
streams are aligned with difflib over normalized mnemonics; each mismatch is classed by how many
divergent regions it has and what fraction of its instructions differ.

| class | count | share |
|---|---|---|
| STRUCTURAL (>40% of instructions differ) | 2079 | 80.0% |
| NEAR/PARTIAL (<=40%) | 424 | 16.3% |
| LOCAL (1 region, <=3 instructions) | 92 | 3.5% |

(Measured at 379 byte-clean with the padding-corrected instrument. An earlier revision of this
file gave 2111/391/78/19 from a tool that compared against the UNTRIMMED original and so invented
a divergent region at the end of every padded function.)

**THE TAIL IS FLAT.** Across the 516 near functions there are **531 distinct divergent-region
shapes over 2106 regions** — about four regions per shape, and the top shapes are generic single
instruction inserts/deletes (`mov`->`-` 184, `pop`->`-` 139, `-`->`mov` 119, `push`->`-` 111),
i.e. register allocation and value materialization, not one mechanical cause. There is no large
remaining lever in the near set; wins come ~4 functions at a time.

**Only 97 functions are within one or two small regions of matching.** Reaching 600 from 375 needs
+225, so it CANNOT come from the near-miss tail — it requires converting ~46% of the 488
non-structural functions, or breaking into the structural bulk.

## What the closest 97 actually need (censused divergent regions)

    13  orig has trailing `8d 40 ..` (lea-NOP padding)   <- comparator, now fixed, gained 0
    10  orig: and eax,0xff        cand: (none)           <- byte-width parameter typing
     6  orig: mov eax,eax         cand: (none)           <- padding
     6  orig: ret                 cand: ret 0x4          <- caller-pop vs callee-pop convention
     5  orig: (none)              cand: mov ah,0x1
     4  orig: shl eax,0x2         cand: lea eax,[eax*4+0] <- peephole/instruction selection
     2  jbe/jae, jl/jle, jg/jge swaps                     <- condition-code recovery

A large share of these are INSTRUCTION SELECTION (peepholes) and comparator artefacts, not
decompiler defects. `add edx,0x12 ; mov eax,edx` vs `lea eax,[edx+0x12]` (FUN_00023210) is the
worked example: both return in EAX and the C is right; only codegen differs.

## Four hypotheses sized and KILLED with the corrected instrument (do not re-derive)

Measured on the 480 "near" functions (<=40% of instructions differ) — the ONLY population where a
convention change could flip a verdict. All report the survey's own verdict via
`compare.classify(..., objp=...)`:

| hypothesis | byte-clean |
|---|---|
| baseline (per-function flags) | 0 of 480 |
| `modify exact []` (blanket) | 0 |
| `modify exact [<precise list from the original's saves>]` | 0 |
| uniform `-onatx` / `-onatx -d1+` | 0 / 1 |

⚠️ **The instrument was broken for the first three runs of this kind.** A probe that compares
`cand == orig` cannot see compare.py's both-sided relocation masking, so every function containing
a call or a global reference reads MISMATCH and BOTH arms report zero — a negative that looks
clean and means nothing. `compare.classify` now takes an `objp` override; any probe MUST use it.

## Confounds ruled out along the way

- **"Functions preserving many registers are a class."** They are not: leading-push count is a
  proxy for function SIZE (median length 30 / 31 / 56 / 87 / 108 / 163 / 232 bytes for 0..6
  pushes). The low byte-clean rate at 4+ pushes is the low rate for big functions.
- **`modify exact []`** (Watcom's forcing form; plain `modify []` is inert) does produce the
  register saves, but sized on 120 functions it gave EXACT 0 -> 0 and mean |delta| 33.5 -> 34.0.
  Blunt instrument: it also saves registers the original does not, including `push gs`.

## The one thing that IS worth knowing

delta==0 is EMPTY: of 2509 mismatches not one has the original's length, while the neighbouring
buckets hold 70-96 each. Getting a function to the right LENGTH is very nearly equivalent to
getting it byte-clean. Length is the metric to chase.

- **`indirect_call` smell (2019 of 2599 mismatches)** is NOT causal: only 3 functions emit an
  indirect call the original lacks. The smell fires on the IR, not on a defect.
- **`rep movs`/`stos`/`scas` expansion** (we render the loop, the original has the string op) is
  real but small: 109 functions, 4 byte-clean.

## What the aggregate says the difference actually IS

Mnemonic totals over 501 mismatching functions (orig vs cand): `pop` -428, `mov` -382, `push`
-207, `je` -199 against `lea` +267, `and` +266, `jne` +117, `setne` +80, `neg` +73. Total
instructions 26686 -> 25054 (-6%). Register saves are 39% of the deficit and fixing them converts
NOTHING, so the verdict is decided by the other 61%: condition polarity (`je`/`jne`, `jl`/`jge`,
`jbe`), boolean materialization (`setne al ; and eax,0xff` where the original branched), and
instruction selection (`lea` for `add`/`shl`). Those are structurer and codegen-shape questions.

## THE LIVE LEAD: call arguments are OVER-recovered, not dropped (2026-08-12)

Four earlier attempts assumed WAR2's calls lose arguments. Instrumented (`MOSURA_STACKARG=1`), the
opposite is true for the caller-pop class:

    original      mov edx,0x1000 ; mov eax,0x11098 ; call          TWO arguments
    mosura        func_0x00050dd8(0x11098, 0x1000, param_2, param_3, param_1)   FIVE

Arguments 3-5 are the CALLER's own incoming EAX/EDX/EBX, still live at the call because nothing
overwrote them. Ghidra's defence against exactly this is `AncestorRealistic`'s `isInput()`
early-out ("we expect to see active movement into the parameter"). `derive_input_map` BYPASSES it:
when a recovered callee `reads` list exists (`committed`), every matching trial is force-marked
active without any realism test. That force-mark was added for a real reason — the pass-through in
`f(x) { g(x); }` is a genuine argument (the regmodify MVE) — so it cannot simply be deleted.

Note also that arg3 is the caller's EDX going into the callee's EBX slot, which would need a
`mov ebx,edx` the original does not have. Whether that is a second defect (argument ORDER) or a
consequence of the first is NOT yet established — do not assume.

Stack arguments are NOT the problem: 6118 of 7021 stack ranges reach guard_calls with a resolved
offset. The 903 that do not are the first stack pass, before the rule pool folds the placeholder —
the window pipeline.rs's priming pass exists to open, working as designed. Reading only the head of
that log shows the stragglers and looks like total failure.

### Why the saved register becomes a parameter — and why the obvious fix is WRONG

FUN_00050dd8 opens `push ebx ; push ecx ; push ebp ; mov ebp,esp ; sub esp,0x1c ; mov ecx,0x600 ;
mov ebx,eax`. EBX and ECX are saved and IMMEDIATELY overwritten, so they cannot be parameters —
yet mosura recovers four (EAX, EDX, EBX, ECX). The `push` gives the incoming value a descendant,
so `ActionInputPrototype` marks the trial active. Every caller of such a function then passes
spurious arguments.

The obvious fix is to correct the cspec: under `__watcall` EAX/EDX/EBX/ECX are the ARGUMENT
registers and are scratch, but `specs/x86-32-watcom.cspec` lists EBX/ECX/EDX as `<unaffected>` and
`<killedbycall>` holds only EAX. **DO NOT MAKE THAT CHANGE — it was tried and it breaks three
build-time-verified ground-truth MVEs** (`callee_register_return_is_recovered_with_its_argument`,
`custom_convention_body_is_not_eliminated_as_dead`,
`indirect_call_does_not_clobber_loop_variable`). The register return in `value [ebx]` stops being
recovered and a byte parameter loses its width.

The `<unaffected>` default is DELIBERATE architecture, not an oversight: mosura overrides it
PER CALLEE from the callee's own body (`analysis::decompiler::callee_effects`, and the per-call
effect override in `heritage::guard_calls`). The default is the conservative floor and evidence
raises it. A blanket cspec change fights that design. Whatever fixes the saved-register case has to
work inside it — most likely by recognising the save/restore pair, not by redeclaring the
convention.

### ORACLE-GROUNDED: the saved-register defect is WATCALL-ONLY, and the cspec is the root

MVE (x86:LE:64:default:gcc, bytes `5748c7c70006000048893c25000060005fc3` at 0x400517) — save a
PARAMETER register, immediately overwrite it, restore it:

    push rdi ; mov rdi,0x600 ; mov [0x600000],rdi ; pop rdi ; ret

Ghidra (`oracle/capture --c`) and mosura (`--example dump`) BOTH produce, identically:

    void func(void) { xRam0000000000600000 = 0x600; return; }

No parameter. mosura handles this correctly on the SysV path — the defect is NOT universal and
NOT in `ActionInputPrototype`.

**The difference is the cspec.** In SysV the parameter registers (RDI/RSI/RDX/RCX) are
`killedbycall` and never `<unaffected>`. In `specs/x86-32-watcom.cspec` EBX/ECX/EDX are BOTH
`<input>` pentries AND `<unaffected>`. That dual membership keeps a saved register's exit value
observable, so the restore stays live, so the save stays live, so the incoming value has a
descendant and becomes a parameter.

**BUT NO SUBSET OF THE FIX IS FREE** — measured, each against `ground_truth_parity` (25 tests):

| moved to killedbycall | result |
|---|---|
| EBX, ECX, EDX | 3 failures |
| EBX, ECX | 2 failures |
| EBX | 2 failures |
| ECX | 1 failure |

The MVEs are build-time-verified source-to-bytes pairs, so these are real output regressions, not
score movements. `callee_register_return_is_recovered_with_its_argument` loses its `value [ebx]`
register return entirely and a byte parameter loses its width.

So the watcall cspec's `<unaffected>` list is simultaneously (a) the root cause of the
saved-register over-recovery and (b) load-bearing for register-return recovery.

**WHY they depend on it — ANSWERED, and it ends at a named missing capability.** With ECX
killedbycall the narrowest MVE loses a parameter:

    expected  void FUN_08048109(xunknown1 param_1, xunknown4 param_2) { … *pxVar1 = param_1; }
    got       void FUN_08048109(xunknown4 param_1)                    { … *pxVar1 = xVar2;   }

It holds a byte parameter in ECX ACROSS a call. Killedbycall makes the call clobber it, so the
incoming value never reaches the store. The optimistic `<unaffected>` default is the ONLY thing
keeping it alive, because **the per-call effect override in `guard_calls` is ONE-DIRECTIONAL**: it
upgrades `<unaffected>` -> killedbycall when `CallSpec::overwrites` says the callee writes the
register, and has no downgrade for a callee that demonstrably PRESERVES a killedbycall register.

The symmetric half was implemented and MEASURED: cspec corrected (EDX/EBX/ECX killedbycall) plus a
downgrade branch gated on `cs.reads.is_some()` (the marker that `callee_effects` completed, so
`overwrites` is exact rather than a lower bound). Still 3 failures — the downgrade never fires,
because `analysis::decompiler::callee_effects` BAILS AT THE FIRST BRANCH and these MVEs' callees
branch. Reverted; 25/25 green.

**So the chain is: correct watcall cspec -> needs the symmetric override -> needs COMPLETE callee
effects for BRANCHING callees.**

That last capability was BUILT and it WORKS — `callee_writes_cfg`, a BFS over the callee's
reachable body collecting every register write, returning `None` on a nested call / indirect branch
/ budget exhaustion so that "absent from the set" is a sound "never written". On the failing MVE's
callee it returns `Some([512, 523, 12, 519, 518, 514, 644])`: EBX (offset 12) plus flags, and
correctly NOT EAX/ECX/EDX. Wired to a symmetric downgrade in `guard_calls` and combined with the
corrected cspec, `ground_truth_parity` went from 3 wrong-output failures to
**`left: ""` — mosura produces NOTHING**, i.e. the decompile itself now fails.

**RESOLVED AND THEN MEASURED — the correction is WRONG FOR THIS BINARY (M23, 2026-08-12).**

The `left: ""` was never a crash: the test's `body()` helper skips lines until one starts with
`void FUN_`, so an empty left means the RETURN TYPE changed, not that decompilation failed. Four
couplings had to be untangled to get all 25 MVEs green with the corrected cspec:

1. `callee_writes_cfg` (a complete CFG write walk) supplies the downgrade evidence `overwrites`
   cannot — it is straight-line and bails at the first branch.
2. `guard_calls` gains the downgrade half, applied where the callee provably never writes the
   register AND where there is NO evidence (indirect call, walk bailed). The model's effect list
   decides the FUNCTION's exit liveness; the per-call override decides what a CALL clobbers.
   Separating them keeps `indirect_call_does_not_clobber_loop_variable`.
3. The RETURN storage is never downgraded — otherwise the caller's pre-call EAX flows across and
   the caller recovers that pass-through as its own return value (regout's `use_` went
   `void` -> value-returning).
4. `callee_effects` had to stop gating its write list on `has_effect == UNAFFECTED`: that coupled
   the killedbycall upgrade to the callee's recovered OUTPUT storage, so correcting the convention
   emptied the output list. Re-gate on "the convention has an opinion" instead, or the flag and
   segment registers land ahead of the real return register in `recovered_output_list`.

All 25 MVEs green, corpus unchanged at 0.9578 — and WAR2 went **385 -> 374 byte-clean (15
regressed, 4 gained)**. Reverted at `4882bd1`.

**What that measurement MEANS, and it is worth more than the change was:** WAR2's callees really do
largely preserve EBX/ECX/EDX. The "wrong" optimistic `<unaffected>` model fits this binary BETTER
than the textbook watcall convention. The cspec is mosura-authored (Ghidra ships no watcall spec),
so it is a MODEL of the binary, not a port — and the binary is the authority. Do not "correct" it
again on documentation grounds; it has now been measured.

### ALSO NAMED: `ActionRestrictLocal` is not ported (zero matches in mosura)

Ghidra `coreaction.cc:1957`. Its second half is precisely the saved-register handling:

```cpp
  eiter = data.getFuncProto().effectBegin();
  for(;eiter!=endeiter;++eiter) {            // Iterate through saved registers
    if ((*eiter).getType() == EffectRecord::killedbycall) continue;   // Not saved
    vn = data.findVarnodeInput((*eiter).getSize(),(*eiter).getAddress());
    if ((vn != (Varnode *)0)&&(vn->isUnaffected())) {
      for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
        op = *iter;
        if (op->code() != CPUI_COPY) continue;
        Varnode *outvn = op->getOut();
        if (!data.getScopeLocal()->isUnaffectedStorage(outvn)) continue;
        data.getScopeLocal()->markNotMapped(outvn->getSpace(),outvn->getOffset(),outvn->getSize(),false);
      }
    }
  }
```

Its FIRST half (locked call parameters) is inert here — mosura's call prototypes are never
input-locked, which `build_input_from_trials` and `resolve_spacebase_relative` both already
document.

mosura has the machinery to port it: `decompile/scope.rs` and `decompile/varmap.rs`, and the
`UNAFFECTED` varnode flag (`varnode.rs:34`) and EffectRecord list (`fspec.rs:647`) already exist.

⚠️ **THE PREMISE IS NOT YET VERIFIED.** This action marks the SAVE SLOT as not-mapped, which stops
it becoming a local. Whether that also stops the saved register becoming a PARAMETER — the actual
defect — has NOT been established. Per CLAUDE.md ("New code is ALWAYS a faithful port — never a
hypothesis to test-and-revert. Before writing any code, ground it READ-ONLY until you have verified
the premise"), ground it with the rule-trace diff / oracle IR dump on FUN_00050dd8 BEFORE writing
any of it. It is a missing faithful port and worth adding on those grounds regardless; do not
assume it is the fix for this class.

## ⚠️ THREE INSTRUMENTS WERE FOUND LYING IN ONE CAMPAIGN

1. trybatch scored `cand == orig`, missing compare.py's relocation masking -> both arms of three
   experiments read zero.
2. whydiff compared against the UNTRIMMED original -> invented a divergent region at the end of
   every padded function (82 of them, top of the census).
3. whydiff disassembles the slice at base 0, so call TARGETS in its ORIGINAL column are meaningless.
   Still unfixed. Do not read call targets out of whydiff.

Rule: any probe must reproduce the known baseline before its negative is believed. trybatch does
this now (384 of 385 clean verdicts reproduced).

Related: [[byte-exact-class-map-2026-08-11]], [[prologue-order-is-chain-frame]],
[[caller-evidence-prototypes]].
