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
