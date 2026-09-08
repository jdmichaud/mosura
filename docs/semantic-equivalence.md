# The second verdict: is the C FAITHFUL, when the bytes cannot be?

`recompile_check` — now `function.recompile` / `round.run` — asks whether a candidate compiles to
the original's bytes. That is the right question for a subject a compiler produced: the bytes are
the ground truth, and a source that reproduces them is the source.

It is the wrong question for a subject written in assembler. There the byte-level differences are
register allocation, calling convention, instruction selection and frame layout — none of which a C
source controls — and a candidate can be *provably the same program* while sharing barely a byte
with the original.

`function.equiv` asks the other question. It is a different instrument, not a looser one.

## What it does

`mosura equiv <fn> --toolchain <name> [--seeds N]` (the op `function.equiv`) emits and compiles
the candidate exactly as `function.recompile` does, then runs the ORIGINAL function and the
candidate's compiled code over the same seeded machine state under mosura's p-code interpreter
(`sleigh::emu::run_traced`) and compares the effects a CALLER could observe:

* every store outside the function's own frame — space, address, width, value, in order;
* every call, in order, with the arguments that call target's contract names;
* the ports written and read, and the software interrupts raised.

Register allocation, frame layout, instruction selection, the order of independent computations and
the function's own entry convention are all free to differ.

`mosura equiv --all` is the op `program.equiv`: the program thawed once, every candidate compiled in
ONE batch, then the differential per row, scoped with `-o round.scope=user|all|list` (and
`round.scope-file`). Use it for a sweep — a loop over `function.equiv` pays a compiler boot and a
program thaw per row, measured at ~50 s a row on a second subject against ~1 s cached.

## How the state is built

* **Memory that was never written reads as a deterministic function of its address.** A pointer
  arriving in a register is therefore dereferenceable wherever it points, and both runs see the
  same heap without anyone enumerating which addresses the function touches.
* **Most of that memory comes from a pool of interesting values** — every constant the ORIGINAL
  mentions, each of those plus or minus one, and the usual boundaries — with the rest pseudorandom.
  Uniform random words are a poor oracle: a function that branches on `x >= 9` behaves identically
  under almost every random `x`, and a wrong threshold survives thousands of trials. With the pool
  the same mutation is caught.
* **Calls are events, not entered.** The target and its argument registers are recorded, the word
  the call's own push took is given back, and a deterministic value is written to the clobber set —
  and to the arithmetic flags, which a call leaves undefined — so both runs continue from the same
  state without either side's return convention being assumed correct.
* **The function's own bytes are readable as data** (an inline table, a constant pool between blocks,
  a self-referential load), and **stores inside the frame window are not recorded** (two
  implementations may lay their frames out differently).

## What a verdict means

* **`SAME`** is evidence, not proof. The row reports the seed count, how many ran to completion on
  both sides (`finished`), and how many DISTINCT effect traces the seeds produced (`traces`). That
  last number is the one to read: if every seed drove the function down the same path, agreement
  says almost nothing, and the verdict is marked `WEAK(one path)`. A healthy verdict on a branchy
  function shows a trace count well above one.
* **`DIFFERS`** is sound: the `detail` names the first diverging effect (a store address, a call
  target, an early stop) and the seed that produced it, and that seed reproduces.
* **`UNMODELED`** is neither: the interpreter met an operation it does not model (an x87 80-bit
  float, a `CALLOTHER` with no arm), named in `detail`, so the run is no evidence at all.
* **`faults`** counts the seeds on which the original trapped (a divide by zero drawn from the pool);
  a run that faulted is not a silently-finished agreement.

The result register (`EAX`) is reported as a SEPARATE agreement count inside `detail`, never folded
into the verdict — see the scope note below.

## Scope: this is the contract-free instrument

Some conventions of hand-written assembly have no C spelling: a callee that returns a boolean in the
carry flag (`STC`/`CLC` then `CALL` then `JC`), a callee whose flag is a predicate on the value it
returns (`TEST EAX,EAX ; RET`), or a callee that answers in a register an indirect call's `code *`
cannot name. The branch this was re-landed from modelled each with an `@equiv` magic-comment
contract, so the branch on that answer becomes a real test rather than a coin.

That contract layer is **not** in `function.equiv` yet. It exists to model a convention the
repository's own subject does not carry, and it needs a hand-written subject to exercise. Until it
lands, every contract channel the interpreter offers is passed empty (the interpreter's opt-in
"a callee without a contract is unchanged" case), and the result register is reported apart rather
than compared — because a `void` function whose `EAX` is scratch would otherwise read as a false
difference. The interpreter itself already carries the full contract machinery (`FlagReturn`,
`RegReturn`, `FlagSource`, the site/ordinal keying), pinned by
`crates/mosura-core/tests/emu_call_model.rs`; wiring it through the op — parsing the annotations,
holding each named register to the callee's clobber set — is the named follow-up.

## Calibration

The interpreter the verdict rests on was validated where a silent zero would have read as agreement:
`INT_DIV` and its siblings, `LZCOUNT`, the signed-carry widths, the float family at binary32/64
(x87's 80 bits refused, not truncated), the `CALLOTHER` user-ops, and the `<label>` resolution that
makes `BSR`/`BSF` find the bit instead of answering a constant. Each arm is Ghidra's own
(`opbehavior.cc` / `float.cc`, cited at the site); the differential tests assert that a faithful
candidate agrees on every seed, an inverted one on none, and one that ignores the answer on fewer
than all.
