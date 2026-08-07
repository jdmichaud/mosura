---
name: war2-mz-inline-call-parameters
description: "The war2 MZ stub's 0x13a56 thunk family is followed by a 2-byte INLINE PARAMETER, not code — mosura decodes it and destroys a real instruction."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-06T18:19:39.461Z
---

⭐ Measured 2026-08-06 on the war2 MZ stub (the 16-bit `analyze_file` path, not the LE body).
Thunks at `0x13a38 / 0x13a47 / 0x13a4c / 0x13a51`, each `CALL 0x13a56`. The dispatcher pops its own
return address and reads a word through it:

```
00013a56  5b        POP BX                    ; BX = the RETURN ADDRESS
00013a57  2e8b0f    MOV CX, word ptr CS:[BX]  ; the word the call is FOLLOWED BY
00013a69  ff2ef20a  JMPF [0xaf2]
```

So every call site is followed by a **2-byte inline parameter**; control resumes 2 bytes further on
and Ghidra's listing resumes exactly there. mosura's `falls_through` re-derives fall-through from
the opcode and decodes the parameter as an instruction.

**It CORRUPTS, it does not merely add.** Where the parameter bytes are `be 39`, mosura's 3-byte
decode at `00013a54` spans `00013a56` and destroys `POP BX` — the dispatcher's own entry, which
Ghidra HAS. That settles the direction of the error with no oracle run, which is why this was
diagnosable locally.

Worth 45 of the 53 units by which the listing fix moved `pe_mz_convergence_parity`'s war2
over-decode count (8 -> 53). The fix did not cause it — 3 of the 9 clusters are inside functions the
pattern search newly reached, so those bytes were previously never decoded at all.

**How to apply:** a raised over-decode bound on this fixture must name this mechanism, not read as
"tolerance raised". Closing it needs a fall-through override model, which mosura lacks. Same class
as [[reftype-is-post-override-not-the-instruction]]; filed as backlog §9 #5.
