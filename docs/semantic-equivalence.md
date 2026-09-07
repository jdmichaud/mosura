# The second verdict: is the C FAITHFUL, when the bytes cannot be?

`recompile_check` asks whether a candidate compiles to the original's bytes. That is the right
question for a subject a compiler produced: the bytes are the ground truth, and a source that
reproduces them is the source.

It is the wrong question for a subject written in assembler. There the byte-level differences are
register allocation, calling convention, instruction selection and frame layout — none of which a C
source controls — and a candidate can be *provably the same program* while sharing barely a byte
with the original. Measured on one such subject: of 336 functions the survey counts as
C-recompilable, 189 carry an encoding this compiler never emits, so their byte verdict is decided
before anyone writes a line of C.

`equiv_check` asks the other question, and it is a different instrument, not a looser one.

## What it compares

The original function and the candidate's compiled code are executed over the same machine state
under mosura's p-code interpreter. The comparison is the effects a CALLER could observe:

* every store outside the function's own frame — space, address, width, value, in order;
* every call, in order, with the arguments that call target's contract names;
* the result register the function's own contract names.

Register allocation, frame layout, instruction selection, the order of independent computations and
the function's own entry convention are all free to differ.

## How the state is built

* **Memory that was never written reads as a deterministic function of its address.** A pointer
  arriving in a register is therefore dereferenceable wherever it points, and both runs see the
  same heap without anyone enumerating which addresses the function touches.
* **Most of that memory comes from a pool of interesting values** — every constant the ORIGINAL
  compares against, each of those ±1, and the usual boundaries — with the rest pseudorandom.
  Uniform random words are a poor oracle: a function that branches on `x >= 9` behaves identically
  under almost every random `x`, and a wrong threshold survives thousands of trials. With the pool
  the same mutation is caught.
* **Calls are events, not entered.** The target and its argument registers are recorded, then a
  deterministic value is written to the clobber set, so both runs continue from the same state
  without either side's return-value convention being assumed correct.
* **Stores inside the frame window are not recorded.** Two implementations of one function may lay
  their frames out differently and still be the same function.
* **A call clobbers the arithmetic flags** (CF PF AF ZF SF OF; DF is ABI-preserved and survives).
  One deterministic BIT each, not a byte of fill. Without this a callee that answers in the carry
  flag was compared against a model in which the flag survived the call untouched, and both sides
  agreed on it for free.

## Answers that live in a flag

A hand-written subject can return a boolean in a flag — `STC`/`CLC` in the callee, `CALL` then
`JC`/`JNC`/`JB`/`JAE` in the caller — and a C compiler has no spelling for that: Watcom 10.0a
rejects `#pragma aux f value [cf]`, and no C construct reads the flags a call left. Taken together
with the clobber above, that would make every such branch a coin the original tosses and the
candidate cannot call.

So a flag result is a NAMEABLE result, declared in a magic comment the compiler never sees:

```c
/*@equiv callee 0x000018b4 returns cf in eax */   /* that CALLEE answers in CF; this source
                                                    models it as answering in EAX */
/*@equiv returns cf in eax */                     /* the SUBJECT answers in CF; this source
                                                    returns that answer in EAX */
```

After a call to a declared callee, the ORIGINAL run finds the answer in the flag — which is what
its `JC` reads — and the CANDIDATE run finds the SAME bit in the register, which is what its `if`
reads. Both come from one expression (`emu::call_flag_bit`), and the bit varies with the seed, the
target and the call's ordinal, so across seeds both arms are exercised. The branch is then a test
of whether the candidate USES the returned condition the way the original does: a candidate that
inverts it, or ignores it, still differs. For the subject's own result the original's flag at `RET`
is compared against the truth of the register the candidate returns it in — a function that answers
in a flag no longer has to be declared `void` with its answer unchecked.

Only `cf` and `zf` can be named. They are the two this convention returns answers in; PF, AF, SF
and OF are side effects of arithmetic, not results anybody returns. Any line containing `@equiv`
must parse, or the run stops: an annotation quietly ignored would leave the candidate compared
against a coin and look like an arithmetic bug.

## What a verdict means

`SAME` is evidence, not proof. It reports the number of seeds, how many ran to completion on both
sides, and how many DISTINCT effect traces the seeds produced. That last number is the one to read:
if every seed drove the function down the same path, agreement says almost nothing, and the verdict
is marked `WEAK(one path)`. A healthy verdict on a branchy function shows a trace count close to the
seed count.

`DIFFERS` is sound: it prints the first diverging effect with the seed that produced it, and that
seed reproduces.

## Calibration

The instrument was validated both ways before use:

* **Positive** — functions whose candidates are byte-exact are `SAME`, and so are two whose byte
  verdicts are `SAME_SHAPE`/`MISMATCH` for reasons that are purely encoding or register allocation.
  That is the whole point: the byte verdict rejects them, the semantic verdict accepts them.
* **Negative** — a constant changed in the source (`* 0x10` to `* 0x20`, `+ g` to `- g`, a compare
  threshold moved by one) is caught every time. The threshold mutation is caught *only* because of
  the constant pool, which is why the pool is not an optimisation.

## Usage

```
equiv_check <binary> <manifest> <src-dir> <flags-file> <watcom-dir>
            [--only <idx>,...] [--seeds N] [--cache <dir>] [--verbose]
```

`--verbose` prints both instruction streams as the emulator decodes them and the first diverging
effect. If a verdict looks impossible, read that first: a decode that comes out as 16-bit
instructions means the language context was not passed.
