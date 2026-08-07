---
name: print-raw-has-no-dead-filter
description: "GOTCHA: Funcdata::print_raw (funcdata.rs:1118) lists ALL ops including destroyed ones, and a destroyed op prints as a BARE opcode. Counting bare opcodes as survivors reads corpses as live ops and produces a wrong mechanism diagnosis."
metadata: 
  node_type: memory
  type: reference
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-29T08:19:38.287Z
---

# `print_raw` shows dead ops — a bare opcode is a corpse, not a survivor

`Funcdata::print_raw` (`crates/mosura/src/decompile/funcdata.rs:1118`) iterates `self.op_ids()`
with **no dead filter**. `op_destroy` clears the op's `inrefs` and `output`, so a destroyed op still
appears in the dump — as a bare opcode with no operands:

```
0x1bdca:95:  r0x0:4 = CALL r0x1ba38:4      <- LIVE   (has output + inputs)
0x1bdca:95:  CALL                          <- DEAD   (destroyed; operands cleared)
```

**The trap** (hit for real, 2026-07-29): `grep -c CALL` over a `--raw` dump returned 4 on both sides
of an A/B, which reads as "the CALL ops survive, so this is an emission/printc defect". They were all
destroyed. The true diagnosis was the opposite — real calls were being **destroyed** by
`ActionDeterminedBranch` — which lives in a completely different file from where the wrong reading
pointed. A mechanism claim was reported to the lead and had to be retracted.

**How to count correctly**: require operands, e.g. match `:\t.+ .+` (an `=` or an input), or use
`PcodeOp::is_dead()` directly from an `examples/` probe. `Funcdata::op_str` DOES mark a dead op
(renders `**`, Ghidra's `printDebug`) — `print_raw` does not.

**Second trap in the same dump**: `print_raw` shows **no SSA version**, so two different definitions
of the same storage both print as e.g. `u0x17200:4`. "Which def feeds this compare" is NOT readable
from a raw dump — don't infer data flow from it. Instrument, or use the oracle.

General lesson, consistent with [[faithful-type-of-wrong-ir]]: when the question is "which mechanism
did X?", make the code NAME itself — a `std::backtrace::Backtrace::force_capture()` in the mutating
primitive (here `op_destroy`, env-gated and filtered) answers in one run what a chain of dump-reading
guesses gets wrong.

Related: [[rule-indirect-collapse-unblocks-stackptr]], [[numbers-stale-unless-sha-stamped]],
[[war2-band-root-cause]].
