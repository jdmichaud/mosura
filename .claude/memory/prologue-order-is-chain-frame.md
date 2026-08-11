---
name: prologue-order-is-chain-frame
description: "The WAR2 prologue order (save-then-frame vs frame-then-save) is Watcom's CHAIN_FRAME path in GenProlog, selected by -of/-of+ — our survey flags force the wrong one"
metadata:
  type: project
---

**⭐ ANSWERED FROM SOURCE, not guessed. The `+3` / `lea esp,[ebp-N]` difference is Watcom's
`CHAIN_FRAME` branch in `GenProlog`, and OUR SURVEY FLAGS select the wrong branch.**

Open Watcom's code generator is on disk at `/data/open-watcom-v2` — the 10.x compiler's direct
ancestor. Read it instead of decompiling `WCC386.EXE` (which is LX, and mosura's LE loader rejects
LX today).

## The mechanism, `bld/cg/intel/c/x86proc.c:925 GenProlog`

```c
if( CHAIN_FRAME ) {
    QuickSave( HW_xBP, OP_PUSH );   // push ebp
    GenRegMove( HW_xSP, HW_xBP );   // mov ebp,esp
    ...
    Push( to_push );                // THEN save registers   <- OUR shape, needs `lea esp,[ebp-N]`
    AllocStack();
} else {
    DoStackCheck();
    Push( to_push );                // save registers FIRST  <- the ORIGINAL's shape
    Enter();                        // THEN build the frame
}
```

```c
// x86proc.c:78
#define DO_BP_CHAIN (((_IsTargetModel(CGSW_X86_NEED_STACK_FRAME)
                       || (CurrProc->state.attr & ROUTINE_NEEDS_BP_CHAIN)
                       || _IsModel(CGSW_GEN_DBG_CV))
                      && CurrProc->contains_call)
                     || (CurrProc->prolog_state & PST_PROLOG_FAT))
#define CHAIN_FRAME (DO_WINDOWS_CRAP || DO_BP_CHAIN)
```

And `bld/cc/c/cmdlnx86.c:602` — **BOTH `-of` and `-of+` set `CGSW_X86_NEED_STACK_FRAME`.**

So: `-of+` + a function that contains a call ⇒ `CHAIN_FRAME` ⇒ frame-first ⇒ the 3-byte
`lea esp,[ebp-N]`. That is every one of our 216.

## Why the original still has a BP frame WITHOUT -of

`x86proc.c:875` — the `sp_frame` (ESP-addressing, no BP frame) decision returns EARLY, leaving a
BP frame, when `ROUTINE_WANTS_DEBUGGING` or `lex_level > 0`. So debug info keeps the frame while
`DO_BP_CHAIN` stays false — frame AND save-first together.

Confirmed by experiment (10.0a, same source):

| flags | result |
|---|---|
| `-of+ -onatx` | `5589e5 52 ... 8d65fc 5a5dc3` frame-first (ours) |
| `-onatx -d1` | `52 ... 5ac3` save-first, NO frame |
| `-onatx -d2` | `5351525657 5589e5 ... 5d5f5e5a595bc3` **save-first AND frame** |
| ORIGINAL | `52 5589e5 ... 5d5ac3` save-first AND frame |

`-d2` reproduces the ORDER. It does not yet reproduce the exact code (more registers saved, a
`81ec` stack allocation, `c705` instead of `31d2`/`8915`), so debug level alone is not the whole
recipe — but the ORDER question is settled.

## THE FULL RECIPE — REPRODUCED 2026-08-11

```
-os + stack param + a saved register   52 5589e5 8b550c 83c207 8b450c e8.. 8915.. 5d 5a c3
-of+ -onatx (our flags)                5589e5 52 8b4508 8d5007 e8.. 8915.. 8d65fc 5a 5d c3
ORIGINAL                               52 5589e5 ...                        5d 5a c3
```

Three conditions, all necessary:
1. **`-os`** — `OptForSize > 50` makes `AddCacheRegs()` (x86proc.c:855) return early, so `sp_frame`
   stays FALSE and a BP frame is permitted. `-os` alone gives save-first but NO frame.
2. **stack parameters** — `parms.size != 0` makes `NeedBPProlog()` (x86proc.c:275) true, so
   `Enter()` actually emits `push ebp ; mov ebp,esp`. Stack params alone (no `-os`) give ESP
   addressing and no frame.
3. **no `-of` / `-of+`** — leaves `DO_BP_CHAIN` false, so `GenProlog` takes the `else` branch and
   pushes the saved registers BEFORE `Enter()`.

Ruled out along the way: `-d1` (save-first, no frame), `-d2` (right order but bloats — homes params
to memory, saves 5 registers), `-3r`/`-5r`/`-4s`, `-oi`, `-oc`, `-od`, `-zp4`, and six compiler
revisions (9.01/10.0a/10.0beta/10.5/10.6/11.0 all identical here).

## THE CLASS IS NOT REPRODUCIBLE WITH THE AVAILABLE TOOLCHAIN (2026-08-11, comprehensive)

The original shape is save-first + a BP frame + a tight body + ONE saved register. Tested
exhaustively against it:

| axis | tried | result |
|---|---|---|
| compilers | 9.01, 10.0a, 10.0 beta, 10.5, 10.6, 11.0 | all frame-first with `-of`; all save-first-NO-frame without |
| frame flags | `-of+`, `-of`, none | `-of*` -> +3 (`lea`); none -> -4 (no frame) |
| optimisation | `-onatx`, `-onat`, `-oat`, `-oi`, `-oc`, `-od`, `-os`, `-oo`, `-oaxt` | none yields frame + save-first |
| debug | `-d1`, `-d2` | `-d1` no frame; `-d2` right ORDER but bloats (5 saves, params homed) |
| processor / convention | `-3r`, `-4r`, `-5r`, `-4s` | no effect on the order |
| source shape | stack params (`parm []`, `parm caller []`), address-taken local, shared temp, self `#pragma aux` with four `modify` lists | none yields frame + save-first |

Final closing test: the period-correct compilers (10.0 beta, 10.5) and 9.01 were re-run on a
function that HAS locals, without `-of` — the one combination that could have made
`NeedBPProlog()` fire naturally. All three gave save-first with NO frame, identical to 10.0a. So
even recovering the locals would not, by itself, produce a BP frame under any available compiler:
without `-of` these compilers address locals off ESP.

**Only `-d2` produces the order, and it changes the body.** The two available flag settings give
+3 (`-of+`) or -4 (no `-of`) — measured as M10/M11: 0 gained either way.

**Independent corroboration.** warcraft2-re wrote hand-verified source for 980 functions of this
shape and matched NONE of them; 838 carry their own blocker label `cgflag:ecx-pre-frameptr-save`.
Two projects, opposite directions, same wall.

**What IS established and is worth acting on:** without `-of` the emitted BODY matches the original
byte-for-byte (verified on 10.0a). The entire remaining difference is the 4-byte frame, and on the
non-chain path that frame requires `NeedBPProlog()` — `parms.size`/`locals.size`/`NEEDS_PROLOG`
non-zero. Of the 2142 functions, 718 DO reference `[ebp+/-disp]` in the original (403 param refs,
3379 local refs) which mosura recovers as nothing. Recovering that storage is the only path left
that is mosura's to take, and it is decompiler work, not a flag.

## What this means for the survey

`war2-survey/flags.py` picks `-of+` when it sees a frame setup in the first 8 bytes. **That
inference is unsound**: a frame also appears from `Enter()` on the non-CHAIN path. For every
function whose frame came that way we compile with `-of+`, take the CHAIN_FRAME branch, and
guarantee a +3 mismatch. Fixing the flag inference is the real work — NOT rewriting the object
afterwards (that workaround was tried at `f4bd7e2` and is FORBIDDEN; reverted at `684c938`).

Next: find what actually forces `ROUTINE_WANTS_DEBUGGING`/BP-frame in the original build, then
re-derive `flags.py`'s `-of` choice from evidence rather than from the presence of a frame.

Related: [[plus3-is-lea-esp-prologue-order]] (the six-compiler A/B that ruled out a version
difference), [[war2-byte-exact-campaign]].
