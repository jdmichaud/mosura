# Reference execution: `sleigh.emulate`, `function.emulate` and `function.capture`

How to run one routine of an original binary over a chosen machine state and read what it
left behind, through the product surface — `mosura call sleigh.emulate …` over raw bytes,
`mosura call function.emulate …` over a function of the session's program and `mosura call
function.capture …` for many vectors at once; in the C API `mosura_emulate`,
`mosura_program_emulate` and `mosura_program_capture` (or `mosura_call`); in the Rust binding
`Program::emulate` and `Program::capture` — or the library (`sleigh::emu::run_with`). The interpreter is the
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
| `emulate.memory` | the initial memory, `hexaddr=hexbytes;…` (a lookup table, a stack); the bytes are memory already, as a loaded program's are, and a seed over them wins |
| `emulate.follow-calls` | enter a `CALL`/`CALLIND` whose target lies inside the bytes and return to the caller at its `RETURN`; off (the default) a call is an event: skipped, its callee never run |
| `emulate.max-steps` | the p-code operation budget (default 5,000,000) |
| `emulate.effects` | also list what the run did, in order, as `effect` rows (default off) |
| `emulate.ports` | what `IN` reads, per port: `PORT=V,V,…;…` (hex); a port's reads return its values in order, then the last again — `0x3da=0,0,8` turns ready on the third poll |
| `emulate.state` | start from the machine state stored in the session under this name; the seeds apply on top |
| `emulate.save-state` | store the machine state the run stopped in under this name, replacing any state of that name |

The answer is an `emulation` table of `(kind, name, value, at, step)` rows; `at` and `step` say
where and when a row's event happened — the instruction's address and the 1-based p-code step of
the run — and are 0 for a row that is not an event:

| kind | name | value |
| --- | --- | --- |
| `outcome` | `stop` | `returned`, `fault`, `no-instruction`, `step-cap` — **a capture is evidence only when it `returned`** |
| `outcome` | `address` | with `no-instruction`: the address that had none (past the bytes, or a call target outside them) |
| `outcome` | `steps` | how many p-code operations executed |
| `outcome` | `unmodeled`, `unmodeled-op` | how many operations the interpreter does not model were met, and which (any non-zero count makes the run no evidence at all) |
| `outcome` | `uninitialized` | a register the run read before anything wrote it (the seeds count as writes), at its first such read — see below |
| `outcome` | `unanswered-in` | a port the run read that `emulate.ports` did not answer, at its first such read: it read zero |
| `register` | the register | its final value as hex, one row per register the state holds in full, widest first — `EAX` is reported, its `AX`/`AL`/`AH` inside it are not |
| `memory` | an address | the bytes the state holds from there, as hex: what was seeded and what the routine stored |
| `effect` | `1`, `2`, … | with `emulate.effects`: one thing the run did, in order, at the instruction and step its `at` and `step` name — `store <space> <address> <size> <value>`, `call <target>` (followed or not), `in`/`out <port> <size> <value>`, `swi <number>`, `fault`; numbers in hex, sizes in decimal |

A device the routine talks to is outside the image: an `OUT` is an effect, and an `IN` reads what
`emulate.ports` answers for its port — the values in order, then the last again, so a status bit
that turns on after two polls is `0,0,8` — or zero, reported as an `unanswered-in` row, when
nothing answers it. A routine that polls an unanswered port for a bit that never comes spins to its
step budget; the row says which port it was waiting on.

Effects are for when the ORDER matters, which the final memory cannot show: a store whose meaning
depends on the port write before it, as in unchained VGA where the plane a byte lands in is the
map mask the program last wrote. The writes that prepared the machine are not effects.

## Over a program: `function.emulate`

```sh
mosura -S s add prog.exe && mosura -S s analyze
mosura -S s emulate 0x3a4 --registers ESP=0x0f000000,EDX=0x20000000 [--follow-calls] [--effects]
mosura -S s call function.emulate entry=0x3a4 emulate.registers=ESP=0x0f000000,EDX=0x20000000
```

The command takes a function by address or name and has a flag for every key (`--registers`,
`--memory`, `--follow-calls`, `--max-steps`, `--effects`, `--state`, `--save-state`). The same
keys and the same answer, with the function's `entry` in place of `bytes`, `base` and
`emulate.entry`. The image is the program as loaded: every initialized block of its default space,
decoded where the run reaches and read as memory. A routine finds its tables and the initial value
of every global where the program keeps them, without seeding them, and a followed call enters
its callee wherever it lives. `entry` must be a function of the analyzed program.

## Capturing vectors: `function.capture`

A reimplementation needs thousands of vectors per routine, each the original's own answer.
`function.capture` runs them all through one function over one decoded image — decoded once, the
program's loaded image as memory — from a specification given as JSON text in `capture.spec`:

```json
{
  "registers": { "ESP": "0x0f000000" },
  "memory": [ { "address": "0x2387c", "bytes": "0000000001000000" } ],
  "follow_calls": true,
  "max_steps": 100000,
  "inputs":  [ { "name": "edx", "bits": 32, "pieces": [ { "register": "EDX" } ] } ],
  "outputs": [ { "name": "eax", "bits": 32, "pieces": [ { "register": "EAX" } ] },
               { "name": "hi",  "bits": 16, "pieces": [ { "space": "register", "offset": 2, "size": 2 } ] } ],
  "cases": [
    { "kind": "explicit", "rows": [ { "edx": "0x0" }, { "edx": "0x20000000" } ] },
    { "kind": "range", "input": "edx", "from": 0, "to": "0x1ff" },
    { "kind": "sample", "count": 1000, "seed": 1, "distribution": "log2-uniform",
      "inputs": { "edx": { "min": 1, "max": "0x7fffffff" } } }
  ]
}
```

```sh
mosura -S s --format json capture 0x663 --spec spec.json [--state NAME]
mosura -S s call function.capture entry=0x663 capture.spec="$(cat spec.json)"
```

The command reads the specification file, prints the table and says on stderr how many vectors
ran and why the rejected ones stopped (`capture: 2612 vectors: 2608 returned, 4 fault`).

| key | meaning |
| --- | --- |
| `registers` | registers every vector starts with, by the language's names (a stack pointer, a pointer to a block) |
| `memory` | bytes every vector starts with, `{address, bytes}` (hex); the image is memory already |
| `ports` | what `IN` reads for every vector, `{"0x3da": [0, 0, 8], "0x60": "0x1c"}`: a port's values in order, then the last again |
| `follow_calls` | enter calls whose target is in the image (default false: a call is an event) |
| `max_steps` | the p-code budget of one vector (default 5,000,000) |
| `inputs`, `outputs` | logical unsigned values of `bits` (1–64), each assembled from `pieces`: `{register: NAME}`, or `{space, offset, size}` (1–8 bytes) for part of a register or memory, with an optional `shift` — a piece holds `(value >> shift)` in its `size` bytes, little-endian |
| `cases` | the generators, run in order; a row already produced is skipped |

Numbers are JSON integers or strings in decimal or `0x` hex; `note` is allowed on every object
with fixed keys, as a comment; any other unknown key is refused, as is a register the language
does not have or a value wider than its input. The generators:

* `explicit`: `rows`, one object per vector naming every input.
* `range`: every value of `input` in `[from, to]`, the other inputs from `fixed` (default 0).
* `sample`: `count` rows from splitmix64 seeded with `seed`; each input drawn in its
  `inputs.<name>` `{min, max}` (default the full width), `uniform` (Lemire's multiply-shift of one
  64-bit draw over the span) or `log2-uniform` (one draw picks the bit length uniformly between
  those of `min` and `max`, a second fills the bits below the top one; a value outside the range is
  drawn again up to 64 times, then drawn uniformly), then mapped through `offset + scale * draw`
  modulo the input's width (`scale` signed, default 1). splitmix64:
  `s += 0x9e3779b97f4a7c15; z = s; z = (z ^ z>>30) * 0xbf58476d1ce4e5b9; z = (z ^ z>>27) *
  0x94d049bb133111eb; z ^ z>>31`.
* `chain`: `count` rows from `start`, each next row copying the listed outputs into the listed
  inputs (`feed: [{output, input}]`). A chain ends at the first row that did not return with
  nothing unmodeled, or that was already produced.

`emulate.state` names a stored machine state every vector starts from. The answer is a `capture`
table, one row per vector: `case` (1, 2, …), `generator` (its index in `cases`), `inputs` and
`outputs` (in the specification's order; no outputs unless the run returned), `stop`, `address`
(with `no-instruction`), `steps`, `unmodeled`, `unmodeled_ops` and `uninitialized` (the registers
the vector read before anything wrote them, in the order of their first read). A row is evidence
only when it `returned` with nothing unmodeled; the others are the rejected cases, each with its
reason. A row whose `uninitialized` names a register the specification meant to set — a segment
base above all — depends on a value nobody supplied. The `unanswered` column lists the ports the
vector read that `ports` did not answer (they read zero), in the order of their first read.

The generators are those of the external reference executor this operation replaces, draw for
draw, so its routine specifications carry over: pieces are the same `{space, offset, size, shift}`; its
`stack_pointer` and `registers` become `registers` by register name; its `preload` windows are not
needed, the image being memory; its `depends_on` becomes `follow_calls`; its `name`, `executable`,
`entry`, `length`, `body` and `notes` belong to the client (`entry` is the operation's own
parameter). Two differences remain: `bits` need not be a multiple of four, and a vector that met
an unmodeled operation is a row with its count rather than an error that stops the capture.

## Carrying state from one run to the next

A sequence of runs — a simulation stepped routine by routine, a counter bumped twice — continues
from where the last run stopped by naming a state:

```sh
mosura -S s emulate 0x40101e --save-state shot
mosura -S s emulate 0x40101e --state shot --save-state shot
```

A state is every run of bytes the machine held when the run stopped — registers and memory, in
every space but `unique` (the lifter's temporaries, dead between instructions) — stored in the
session (`states/<name>.tbl`, or in memory for an in-memory session). It is stored whatever the
stop, and a second save under the same name replaces the first: unlike a round, a state is a
working point, not a measurement. A run that names one starts from it, over the image as loaded,
and its own seeds apply on top. States of a C API language handle live in that handle's session.

## Why a run stopped

A register nobody wrote reads as zero, as in Ghidra's emulator, which warns "Uninitialized register
read at <pc>: <register>" for each (`EmulatorHelper.uninitializedRead`); the `uninitialized` rows
are that warning. Most are harmless — a callee-saved register pushed and popped, the stack pointer
of an unseeded `RET` — but a result that depends on one depends on a value nobody supplied. A
segment base is the sharp case: an `FS:` or `GS:` override adds `FS_OFFSET` or `GS_OFFSET` to the
address, so with the base unset a driver's `gs:[disp]` reads flat `disp`, somewhere in the
executable, and the run otherwise looks clean. Seed the base by name (`emulate.registers=
GS_OFFSET=…`); a run that did not is named by its `uninitialized` row.

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
rather than approximated (`semantic-equivalence.md`, calibration). Memory holds the bytes given
and the seeds; everything else reads as zero — there is no fill here, unlike the differential run
— and nothing outside the bytes executes: no BIOS, no DOS, no extender. A register wider than
eight bytes is not reported.

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
says how many instructions that took.

`Image::from_blocks(spec, &[(start, bytes), …], ctx)` is an image of several disjoint blocks — a
program's loaded memory, code decoding from whichever block holds it. `.with_image_memory()`
makes the blocks the machine's memory as well: a byte no run has written reads the image's own
byte (zero outside every block), so a routine reads its constants and the initial value of every
global without seeding them. Without it a never-written byte reads zero.

A run can also start from a machine instead of a seed list: `Image::machine()` hands out a fresh
one, `Machine::write` and `Machine::write_bytes` prepare it, and `Image::resume(machine, &opts)`
runs it. The machine a run returns can be resumed the same way, which is how a sequence of runs
carries its registers and memory from one to the next; each run's effects and unmodeled counts
are its own. `Machine::spaces()` names the spaces a state holds bytes in.

With `trace` on, `Machine::effects` lists what the run did, in order: stores outside the register
and unique spaces, calls by target (followed or not), port accesses and software interrupts. The
writes that prepared the machine are not effects.

The source-built gates are `crates/mosura-core/tests/emu_reference.rs` over
`oracle/ground-truth/src/{divide_fault,spin_until_zero,call_chain,image_data}.S`; the operations'
are in `crates/mosura-api/tests/ops_sleigh.rs` and `crates/mosura-api/tests/ops_emulate.rs`, and
the C API's in `crates/mosura-capi/tests/program.rs`.
