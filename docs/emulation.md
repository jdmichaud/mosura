# Reference execution: `sleigh.emulate`

How to run one routine of an original binary over a chosen machine state and read what it
left behind, through the product surface (`mosura call sleigh.emulate …`, `mosura_call` /
`mosura_emulate` in the C API) or the library (`sleigh::emu::run_with`). The interpreter is the
one the differential check rests on ([semantic-equivalence.md](semantic-equivalence.md)); this
page is its plain, single-program use: a REFERENCE of the original's results, for a client that
reimplements the routine and needs vectors the original itself produced.

## The operation

```sh
mosura call sleigh.emulate lang=x86:LE:32:default bytes=f7f1c3 base=0x1000 \
    emulate.registers=EDX=0,EAX=0x64,ECX=7
```

| key | meaning |
| --- | --- |
| `lang`, `bytes`, `base`, `ctx` | as for `sleigh.lift`: the language, the bytes as hex, their address, the decode context |
| `emulate.entry` | where execution starts (default `base`); the bytes may hold a whole image |
| `emulate.registers` | the initial registers, `NAME=hex,…` — the language's register names, any width (`AX`, `EAX`, `RAX`) |
| `emulate.memory` | the initial memory, `hexaddr=hexbytes;…` (a lookup table, a stack) |
| `emulate.follow-calls` | enter a `CALL`/`CALLIND` whose target lies inside the bytes and return to the caller at its `RETURN`; off (the default) a call is an event: skipped, its callee never run |
| `emulate.max-steps` | the p-code operation budget (default 5,000,000) |

The answer is an `emulation` table of `(kind, name, value)` rows:

| kind | name | value |
| --- | --- | --- |
| `outcome` | `stop` | `returned`, `fault`, `no-instruction`, `step-cap` — **a capture is evidence only when it `returned`** |
| `outcome` | `address` | with `no-instruction`: the address that had none (past the bytes, or a call target outside them) |
| `outcome` | `steps` | how many p-code operations executed |
| `outcome` | `unmodeled`, `unmodeled-op` | how many operations the interpreter does not model were met, and which (any non-zero count makes the run no evidence at all) |
| `register` | the register | its final value as hex, one row per register the state holds in full, widest first — `EAX` is reported, its `AX`/`AL`/`AH` inside it are not |
| `memory` | an address | the bytes the state holds from there, as hex: what was seeded and what the routine stored |

Every stop but `returned` is a reason to reject the capture, and the reason is named:

* **`fault`** — the program trapped. A division by zero, or a quotient the destination cannot
  hold. The second is the hardware's rule (`DIV`/`IDIV` raise `#DE` when the double-width quotient
  does not fit the register) and it is invisible in p-code, which narrows the quotient with a
  `SUBPIECE` and carries on with the truncated value. The interpreter keeps a division's full
  quotient and faults at the narrowing that loses bits: unsigned, any high bit; signed, a low part
  that does not sign-extend back to the whole. The rule is the instruction's, not the target's — a
  language whose division never narrows its quotient can never trip it. So `DX:AX = 0xa00000` over
  `DIV BP` with `BP = 1` is a fault, as on the machine, and not the `AX = 0` a literal p-code
  execution would return.
* **`step-cap`** — the budget ran out. A loop that cycles on the hardware cycles here; the registers
  at that point are not a result.
* **`no-instruction`** — control left the bytes. With `emulate.follow-calls`, a call to a routine
  the bytes do not contain stops here, at the callee's address, rather than continuing past it.

## Calls

Off by default, a call is an event: the instruction's own p-code has already pushed the return
address, the `CALL` itself is skipped, and the routine's own `RET` pops that word. That is the
single-function mode the differential check wants (a callee's behaviour is its own business), and
it captures leaf routines exactly.

With `emulate.follow-calls`, a call whose target lies in the bytes is entered and its `RETURN`
comes back to the caller — nesting to any depth, the stack pointer seeded by the caller. The bytes
can therefore be a whole text section with `emulate.entry` naming the routine, and the instructions
are decoded on demand at every address the run reaches, so a callee behind data or inside what a
linear sweep read as one long instruction still decodes. A software interrupt (`INT n`) stays an
event in both modes: its handler is not in the bytes.

## What it does not do

The interpreter models integer and binary32/64 float p-code, the `LOCK`/`in`/`out`/`swi` user-ops
and nothing else; x87's 80-bit arithmetic and the vector extensions are reported as `unmodeled`
rather than approximated (`semantic-equivalence.md`, calibration). Memory outside the seeded bytes
reads as zero — there is no fill here, unlike the differential run — and nothing outside the bytes
executes: no BIOS, no DOS, no extender. A register wider than eight bytes is not reported.

## The library

`sleigh::emu::run_with(spec, bytes, base, ctx, inputs, &RunOptions { entry, follow_calls, max_steps })`
returns a `Run { machine, steps, stop }`; `run` is the same under `RunOptions::default()`.
`Machine::read(space, offset, size)` and `Machine::written(space)` read the final state.

Instructions are decoded on demand, in 64-byte windows from each address a run reaches, and an
instruction a window cuts is decoded whole from its own address later (the decoder zero-pads a
cut instruction, which can spell a different one). A caller capturing many vectors over one
image keeps the decoded instructions across runs: `let mut image = Image::new(spec, bytes, base,
ctx); image.run(inputs, &opts)` — `run_with` is one such image used once. A whole text section
with the routine inside it therefore costs what the routine executes, and `Image::decoded()`
says how many instructions that took. The
source-built gates are `crates/mosura-core/tests/emu_reference.rs` over
`oracle/ground-truth/src/{divide_fault,spin_until_zero,call_chain}.S`; the operation's are in
`crates/mosura-api/tests/ops_sleigh.rs` and the C API's in `crates/mosura-capi/tests/program.rs`.
