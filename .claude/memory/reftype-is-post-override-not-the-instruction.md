---
name: reftype-is-post-override-not-the-instruction
description: "Ghidra's reported reference type is POST-flow-override — an UNCONDITIONAL_CALL ref can sit on a `jmp`, so never infer the instruction from the reftype."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-05T10:46:14.033Z
---

A Ghidra reference typed `UNCONDITIONAL_CALL` does **not** mean the source instruction is a
`call`. `SharedReturnAnalysisCmd` applies `FlowOverride.CALL_RETURN` to a tail-call `jmp`, which
re-derives the reference type through `getDefaultJumpOrCallFlowType` → `UNCONDITIONAL_CALL`. The
same happens for PLT tail calls (`COMPUTED_CALL_TERMINATOR`).

**Why:** the WAR2 analysis-gap report split its seeds into "3 × UNCONDITIONAL_CALL (plain direct
call)" vs "4 × UNCONDITIONAL_JUMP (tail call)" by reading `DumpCallers.java`'s reftype column. All
seven were `e9 rel32` jumps. The whole "direct-call mechanism" framing of the task was an artifact
of that read, and the real mechanism was `SharedReturnAnalysisCmd` for all of them.

**How to apply:** when a Ghidra reference type is load-bearing, disassemble the source address and
confirm the opcode before building on it — `objdump -b binary -m i386 --adjust-vma` over the image
takes seconds. Reference types are analysis OUTPUT; instructions are the input.

Related: [[war2-per-function-ghidra-oracle]], [[oracle-same-question-not-just-same-tool]],
[[shared-return-cursor-cache-is-semantic]].
