# The no-fold compiler patch — disabling wcc386 10.0a's reg+imm LEA fold

*2026-08-19. A two-site, eight-byte patch to a COPY of Watcom C/C++32 10.0a's `wcc386.exe`
that disables exactly one code-generator decision: folding `reg = reg2; reg += imm` into
`LEA reg,[reg2+imm]`. Written so anyone can reproduce it, verify it, or throw it away.*

## Why

[`watcom-toolchain-synthesis.md`](watcom-toolchain-synthesis.md) splits the subject's compiler
fingerprint into two piles. **Pile B** is the set of behaviours the subject's binary shows that our
10.0a will not produce under any flag or source shape, and its largest member is the absent
add-fold: **zero `LEA reg,[reg+imm]` folds in 380 KB of the subject**, where 10.0a folds under every
optimisation setting we can pass it. The conclusion was an *interim 10.0-line build* with
different code-generator settings — extinct, so unobtainable.

That leaves one way to test the hypothesis: take the compiler we DO have and turn that single
dial off. If the subject was built by a 10.0a-line code generator that did not fold, a no-fold 10.0a
should reproduce more of the subject's bytes. This is a *falsifiable experiment about one variable*,
not an attempt to reconstruct the lost compiler.

## Locating the site (method, because the method generalises)

1. **Source first.** `open_watcom_1.0.0-src.zip` → `bld/cg/intel/c/i86ver.c`, the instruction
   verifier. The fold is one arm of one switch:

   ```c
   case V_LEA_GOOD:
       if( OptForSize > 50 ) return( FALSE );
       /* fall through */
   case V_LEA:
       if( op2->c.const_type != CONS_ABSOLUTE ) return( FALSE );
       switch( ins->head.opcode ) {
           case OP_MUL:    switch( op2->c.int_value ) { case 3: case 5: case 9: return TRUE; } break;
           case OP_LSHIFT: if( op1 == result && _CPULevel( CPU_586 ) ) return( FALSE );
                           ... switch( op2->c.int_value ) { case 1: case 2: case 3: return TRUE; } break;
       case OP_ADD:
       case OP_SUB:
           if( OptForSize < 50 && !_CPULevel( CPU_286 ) ) return( FALSE );
           return( TRUE );          /* <-- the fold */
       }
   ```

   Opcode values from `bld/cg/h/opcodes.h`: `OP_ADD = 1`, `OP_SUB = 3`, `OP_MUL = 5`,
   `OP_LSHIFT = 13`.

2. **Ask the compiler how it lowers switches.** A first signature search (sequential
   `CMP reg,3` / `,5` / `,9`) found nothing. Compiling the verifier's *shape* with 10.0a
   itself (`examples/dumpwc`) showed why: Watcom lowers a sparse switch as a **binary-search
   tree** — `CMP 5` / `JC` / `JBE` / `CMP 9` / `JZ` / `CMP 3` — not a sequence. Instrument
   before hypothesising, including about the tool doing the measuring.

3. **Search with the real shape**, then **disassemble with mosura** (`examples/dumpraw`, the
   port reading its own toolchain). Two hits; one is the verifier, unmistakably:

   ```
   717d8  CMP byte ptr [0x7f90e],0x32   ; V_LEA_GOOD: OptForSize > 50 ?
   717df  JA  0x71ac8                   ;   -> FALSE
   717e5  CMP byte ptr [ESI + 0x18],0x0 ; V_LEA: const_type != CONS_ABSOLUTE ?
   717e9  JNZ 0x71ac8                   ;   -> FALSE
   717ef  MOV AL,byte ptr [EDX + 0x22]  ; ins->head.opcode
   717f2  CMP AL,0x3
   717f4  JC  0x7180f                   ; opcode < 3
   717f6  JBE 0x7187c                   ; opcode == 3 (OP_SUB)  -> ADD/SUB arm
   717fc  CMP AL,0x5
   717fe  JC  0x71ac8                   ; opcode == 4          -> FALSE
   71804  JBE 0x71818                   ; opcode == 5 (OP_MUL) -> MUL arm {3,5,9}
   71806  CMP AL,0xd
   71808  JZ  0x7183c                   ; opcode == 13 (OP_LSHIFT) -> LSHIFT arm
   7180a  JMP 0x71ac8                   ; default              -> FALSE
   7180f  CMP AL,0x1
   71811  JZ  0x7187c                   ; opcode == 1 (OP_ADD) -> ADD/SUB arm
   71813  JMP 0x71ac8                   ; default              -> FALSE

   7187c  CMP byte ptr [0x7f90e],0x32   ; the ADD/SUB arm: OptForSize < 50 ?
   71883  JNC 0x71614                   ;   >= 50 -> TRUE
   71889  MOV AX,[0x7f908]              ; CpuLevel
   7188f  AND AL,0xf
   71891  XOR AH,AH
   71893  CMP AX,0x2                    ; CPU_286
   71897  SETC AL
   7189a  JMP 0x71702

   71614  MOV AL,0x1 ; JMP 0x71aca      ; return TRUE
   71ac8  XOR AL,AL  ; LEAVE ; ... RET  ; return FALSE
   ```

   Corroboration that this is the right function, independent of the source reading: the
   LSHIFT arm at `0x7183c` tests `op1 == result` and then `CpuLevel >= 5` (`CPU_586`) — the
   exact gate whose *behaviour* we had already measured from outside when the `-5r` profile
   change landed (`SHL` instead of in-place scaled `LEA`).

## The patch

Applied to a **copy** of the tree. Two dispatch edges are neutralised so `OP_ADD` and
`OP_SUB` fall through to the verifier's existing FALSE path; nothing else changes.

| file offset | before | after | effect |
| --- | --- | --- | --- |
| `0x717f6` | `0f 86 80 00 00 00` (`JBE 0x7187c`) | `90 90 90 90 90 90` | `OP_SUB` falls to `CMP AL,5` / `JC 0x71ac8` → FALSE |
| `0x71811` | `74 69` (`JZ 0x7187c`) | `90 90` | `OP_ADD` falls to `JMP 0x71ac8` → FALSE |

Why the dispatch and not the arm body: the arm at `0x7187c` is shared, and jumping *from* it
to `0x71ac8` needs a longer displacement than the site affords; NOP-ing the two edges reaches
the same result using control flow the binary already contains. The MUL arm (`0x71818`), the
LSHIFT arm (`0x7183c`) and every other verifier code are byte-identical to stock.

```
sha256  original  c3666de94f6fa6800f452dae8acf45505ecdb62f0ade2cc27cc86c2d9e8e2b6b
sha256  patched   5008710a3acad7ca5175f359575b29e7b7e3715ba57462691730ef760d4f4106
```

Reproduce (idempotent, refuses to run against unexpected bytes):

```python
tgt = "<copy>/WATCOM/BINB/WCC386.EXE"
d = bytearray(open(tgt, "rb").read())
for off, old, new in ((0x717f6, bytes.fromhex("0f8680000000"), b"\x90" * 6),
                      (0x71811, bytes.fromhex("7469"),         b"\x90" * 2)):
    assert bytes(d[off:off + len(old)]) == old, f"pre-image mismatch at {off:#x}"
    d[off:off + len(new)] = new
open(tgt, "wb").write(bytes(d))
```

Reverting is the same script with `old` and `new` swapped, or simply re-copying the reference
install — **the patch is only ever applied to a scratch copy; the reference tree at
`the RE tracker/tmp/watcom-experiments/watcom_10.0a/WATCOM` is never written to.**

## Validation before trusting any number

| probe | stock 10.0a | patched |
| --- | --- | --- |
| `f(x % 4 + 0x12)` (the fold probe) | `LEA EAX,[EDX + 0x12]` | `MOV EAX,EDX ; ADD EAX,0x12` |
| `x * 3` (MUL arm) | identical | identical |
| `x * 4` under `-5r` (LSHIFT arm) | `SHL EAX,0x2` | `SHL EAX,0x2` |

The fold is gone and its replacement is exactly the shape the subject uses; the neighbouring arms are
untouched. Corpus runs with the patched compiler use a SEPARATE object cache
(`/data/be2/cache-nofold`) — the cache is keyed on source content and toolchain id, and the
patch does not change the id, so sharing a cache would silently serve stock objects.

## Result — and what this experiment can and cannot test

**Read this before trusting the conclusions: the wholesale-no-fold patch tests the wrong
proposition.** Turning folding OFF everywhere tests "the subject *never* folds" — a strawman.
It CANNOT test the real hypothesis, "the subject's fold CONDITIONS differ from 10.0a's", because
the subject both folds (336 sites) and declines to fold (the F2 rows) — a wholesale toggle can
match neither state. Any conclusion of the form "hypothesis dead, the subject folds like 10.0a"
drawn from this patch is a construct-validity error and was retracted 2026-08-19. The
load-bearing result is not the ± you get from the toggle; it is the *invariance* finding
below.

Measured on sb93's recovered tree (2797 C functions), stock baseline 687 EXACT / 0.4355 WGSS:

| compiler | EXACT | WGSS |
| --- | --- | --- |
| stock 10.0a | **687** | **0.4355** |
| no-fold patch | **681** | 0.4320 |

Six functions that were byte-exact with the folding compiler broke. Their originals were
then disassembled, and every one of them contains the fold:

```
00500  LEA EDX,[ESI + 0x7c]      01702  LEA EBX,[EAX + 0x1]
00921  LEA EDX,[EAX + 0x7c]      01820  LEA EBX,[EAX + 0x8]
00980  LEA EDX,[EAX + 0x7c]      02053  LEA EAX,[EBX + 0x1]
```

So the subject's compiler **does** fold `reg+imm` into `LEA` — the "never folds" reading is dead.
It does NOT follow that the subject folds *under the same conditions* as 10.0a; the F2 rows are
direct evidence it declines to fold where 10.0a folds. What the no-fold run is actually
good for is the invariance test two sections down.

**And it exposed a wrong foundational measurement.** `watcom-toolchain-synthesis.md` recorded
pile-B's largest member as "**zero** `LEA reg,[reg+imm]` folds in 380KB … the 39 hex hits in
MISMATCH originals are not this form". Counting properly — disassembling every user
function's original bytes rather than matching hex (`examples/dumplea`) — gives:

```
counting every LEA Ereg,[Ereg + imm]          312 functions   586 sites
excluding [ESP+imm]/[EBP+imm] (address-of-local,
i.e. the genuine copy+add fold only)          226 functions   336 sites
   of which MISMATCH: 220     EXACT: 6
```

336 genuine folds, not zero. The original scan was a byte-pattern search — the exact method
`recompile/buildconfig.rs`'s own module doc warns about ("Matching hex … misses the second
encoding of the same instruction"), applied to the one conclusion nobody re-checked because
it had been declared settled.

**Consequences — stated carefully, after an over-correction was itself corrected
(2026-08-19).** Two things change and one does NOT:

1. The *sub-claim* "zero folds in 380KB" is factually wrong (336 exist). That correction
   stands on the recount alone.
2. The fold is not F2's discriminator (the invariance test below): F2's real difference is
   a register-mutation/liveness question on OUR emission side, **whose winnability is
   UNMEASURED** — the pilot's "no source shape avoids the fold" is a live hint it may not be
   recoverable at all, i.e. could still be compiler identity. F2 is therefore *unresolved*,
   not "ordinary recovery work"; it stays parked pending the specific test named below.
3. **The interim-compiler hypothesis is NOT overturned.** It rests on four observations; only
   the fold was examined here, and it turns out not to be a "compiler produces what we can't"
   divergence but an emission question. The other three — allocation order, callee-save
   policy, load scheduling — were never touched by this experiment and remain the interim
   build's to explain. The correct summary is "one of pile-B's four legs was mismeasured and
   reclassified", not "pile-B refuted".

**A stronger positive result the experiment also proves (verified 2026-08-19, Fable
re-audit).** If F2's `missing ADD + MOV>LEA` were a fold-DECISION difference, compiling our
C without folding would convert those functions. It does not: all **15** F2-signature
near-frontier functions are byte-for-byte INVARIANT under the no-fold compiler (verdicts
unchanged), and zero functions corpus-wide went MISMATCH → EXACT. The pilot `00556` shows
why directly — under no-fold our C emits `MOV EAX,EDX ; ADD EAX,0x12` while the original is
`ADD EDX,0x12 ; MOV EAX,EDX`: the divergence moved from the fold instruction to the
MUTATION TARGET (we increment EAX, a fresh value; the original increments EDX in place and
keeps it live). So F2's difference is *located* — it is the `x += k` (in-place mutation)
versus `y = x + k` (fresh value) question, a variable-liveness / coalescing matter on our
emission side — but it is NOT proven to be *winnable* there. Two things are unmeasured, and
one cuts against it: the payoff (it may entangle with allocation, as the widen-after family
did), and — sharper — the pilot found that "no source shape avoids the fold" (five variants
all → LEA), which means it is not yet shown that ANY C we can emit, even one that reuses the
variable, makes 10.0a produce the in-place `ADD EDX,0x12 ; MOV EAX,EDX` form. If it cannot,
F2 is compiler identity after all. **The discriminating test (unmeasured):** hand-write C
that mutates the variable in place with it live afterward, and see whether 10.0a emits the
original's form or still folds/copies. Until that runs, F2 is *unresolved*, and stays parked.

**UPDATE — that test RAN (2026-08-19); F2 is resolved as COMPILER IDENTITY.** Seven C shapes
for the pilot `00556` (expression; `t += k`; `t = t + k`; reuse-after-store; volatile; and
both via-call forms) — **all seven fold** to `LEA EAX,[EDX + 0x12]`. So no emission change
reaches the original's form. Reading the original shows why, and it is NOT liveness (EDX is
dead — it gets popped): `IDIV` leaves the remainder in EDX, and the original's codegen assigns
the add's result to **op1's own register** (in-place `ADD`, then a copy to the return
register), where 10.0a assigns it to the **destination** register and therefore needs the
`LEA`. F2 is a result-register-assignment difference — the same dial as the `regalloc` class
and the RE tracker's `ecx-allocator-mystery` — not a fold decision and not an emission question.
`byte-exact-families.md` records the falsifiable prediction this generates for the
allocation-order experiment (F2's rows should move together with the regalloc class, or the
unification is wrong).

The patched compiler is kept (documented above) as a reusable instrument: the method —
locate a dial in OW source, find it in the 10.0a binary with mosura, patch a copy, measure —
now has a worked example, and the remaining pile-B dials are candidates for the same
treatment. It is NOT used as a verifier; the harness continues to use stock 10.0a.

## Correction to an earlier claim

`watcom-toolchain-synthesis.md` recorded, from black-box probing, that OW 1.0's
`if( OptForSize > 50 ) return FALSE` gate on `V_LEA_GOOD` "measurably does not exist in 10.0a
or 10.5 (both fold under `-os`)". **That inference was wrong.** The gate is right there at
`0x717d8` in 10.0a's own binary (`CMP byte ptr [0x7f90e],0x32 ; JA`), and the ADD/SUB arm
carries its `OptForSize < 50` companion too. The probe conclusion failed because `-os` does
not push `OptForSize` above 50, and/or the fold site in that probe verifies through `V_LEA`
rather than `V_LEA_GOOD` — either way the observable was not the thing being inferred. The
dial-was-being-worked-on argument for the interim build loses this piece of support; what
survives is the direct one: the subject folds zero of these and 10.0a folds all of them, and the
difference is now known to be *one arm of one switch*.
