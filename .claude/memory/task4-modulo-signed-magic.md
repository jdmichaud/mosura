---
name: task4-modulo-signed-magic
description: Task #4 (TaskList) modulo 64-bit SIGNED magic division — root cause PROVEN (zext-vs-sext of top-bit-set magic → magic65 poison), fix gated
metadata:
  node_type: memory
  type: project
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

Task #4 (TaskList; owner ccprop1; distinct from the older [[task4-comparison-normalization]] which is
the Phase-1c `<=` item): the sole below-baseline residual from the divopt de-fuse — 64-bit SIGNED
65-bit-magic modulo `%0x3c`(60) and `%100` don't collapse. modulo ~0.893. HEAD 654f4f5.

STATE (2026-07-08): instrument-first grounding COMPLETE, root cause PROVEN, all instruments reverted
(mosura + ghidra trees clean, oracle rebuilt pristine, suite 344/0). Fix GATED — plan sent to lead
(msg 19ceb35d), awaiting go. NOT yet coded.

## Failing sites
64-bit signed `%0x3c`(@0x100736) + `%100`(@0x100770). 32-bit signed, ALL unsigned, and 64-bit signed
`%1000` collapse fine (%1000 magic 0x20c49ba5e353f7cf has top bit CLEAR → no correction needed).

## PROVEN mechanism (temp fprintf in ghidra calcDivisor + RuleDivTermAdd; matching mosura eprintln; all reverted)
Ghidra: signed magic 0x8888888888888889 (top bit SET) is SIGN-extended to 0xFFFF...8889. RuleDivTermAdd
`multConst += 2^64` WRAPS it to BARE magic64 (high word 0xFFFF..+1→0). findForm reads it at n=0x45=69,
y0=0x8888888888888889, y1=0, xsize=63 → calcDivisor=60.
mosura: reads the magic ZERO-extended/bare (0x8888888888888889, y1=0) → +2^64 → magic65 =
PIECE(1,0x8888888888888889)=0x18888888888888889 (POISON). Also produces the correct bare-magic64 form
(from a sext read) but findForm reads THAT at n=64 (missing the +5 arith shift) → 0. So mosura NEVER makes
Ghidra's winning (n=69, bare magic64) call. In mosura IR @0x100736: `u0x1126c:16 = PIECE #0x1:8
#0x8888888888888889:8` then `INT_MULT u0x95400(sext x) u0x1126c` = the poison magic65 multiply.

## Root cause
64-bit signed reciprocal magic (top-bit-set) is ZERO-extended in mosura where Ghidra SIGN-extends it, so
RuleDivTermAdd builds magic65 instead of wrapping to bare magic64. calc_divisor (divopt.rs:21) is a
FAITHFUL u128 port — swept n=0..127×xsize62/63/64: magic65 recovers NOTHING, only bare magic64 does
(n=69→60, n=70→100). NOT the bug; fix is UPSTREAM.

## Sub-locus PINNED (2026-07-08, step 1) — it's a MISSING const-fold guard, NOT the lifter
Proven (temp print of the multiplier operand at both sites, reverted): divtermadd sees the magic as
TWO reps across pool sweeps — `def=IntSext -> 0xffff...8889` (correct) AND `isconst=true def=None
size=16 -> 0x8888888888888889` (POISON, a 16-byte CONSTANT varnode with high word 0 = zero-extended).
The 16-byte constant is created by **RuleConstFold (rules.rs:116)** folding `INT_SEXT(magic64:8)`
(16-byte out) into `new_const(16, magic64)` — mosura constants store a u64 (constant_value()), so the
sign-extended high 64 bits are DROPPED. is_constant_extended then reads it bare → +2^64 → magic65.

ROOT: mosura's RuleConstFold ports Ghidra RuleCollapseConstants (ruleaction.cc:3854) but OMITS Ghidra's
`op->isCollapsible()` guard (op.cc:115), specifically `if (getOut()->getSize() > sizeof(uintb)) return
false;` (sizeof(uintb)=8). Ghidra never folds a >8-byte-output op → leaves the INT_SEXT → correct.

## FIX (faithful, gated — awaiting lead go, msg a7c2f7c8)
Add to RuleConstFold::apply_op: `if data.vn(out).size > 8 { return 0; }` (faithful port of the
isCollapsible size clause). Do NOT touch calc_divisor/findForm/is_constant_extended/lifter (all proven
faithful). MOVER (RuleConstFold is general): any fixture folding a >8-byte-output all-const op changes;
expected only-helpful (such folds are always lossy in mosura's u64 constants). Full-corpus delta table
before landing; expect modulo %60/%100 → up.

## Tooling notes
- Oracle instrument: add fprintf to ruleaction.cc, `make -C <ghidra cpp> libdecomp_dbg.a` (incremental)
  + relink `oracle/capture` with the EXACT flags (-DCPUI_DEBUG -D__TERMINAL__ -Wl,--whole-archive
  libdecomp_dbg.a). REVERT + rebuild after (verify ghidra `git status` clean + oracle emits no debug).
- mosura per-site instrument: env-gated eprintln in find_form_apply (n,y,xsize,divisor) + RuleDivTermAdd
  (before/after +2^n, extsize), keyed by `f.op(op).seqnum.pc.offset`. dumpc --raw shows the op-graph.
See [[direction-faithful-port]], [[task20-defuse-divopt-plan]].
