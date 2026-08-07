---
name: command-vs-notification-channel
description: "Ghidra's disassemble/createFunction are COMMANDS on a queue, not codeDefined/functionDefined notifications — modelling them as channels silently drops work."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-06T18:19:14.544Z
---

⭐ Measured 2026-08-06. `FunctionStartAnalyzer.java:835-859` raises **no event**: it takes the
per-program singleton `AutoAnalysisManager.getAnalysisManager(program)` (:949) and calls
`disassemble` (:1128) / `createFunction` (:1132), each `schedule(cmd, priority)` (:860) onto the
**command queue**. `codeDefined` (:262-272) is separate, raised only from real listing changes —
Ghidra's own comment at :385 says disassembly deliberately does NOT go through change events.
**Nothing in Ghidra subscribes disassembly to a channel.**

mosura expressed both as `sched.code_defined` / `sched.function_defined`. One substitution, three
defects: (1) a request only reaches analyzers registered in THAT manager — the byte-pattern passes
run in a second `AutoAnalysisManager` (`analysis/mod.rs:246`) where `function_defined` reached
**zero** consumers, so pattern-discovered functions were never disassembled; (2) seeds shared an
accumulator with the decoded EXTENT the disassembler notified back to itself; (3) a request echoed
to the requester, so the pattern passes re-fired forever — the sole reason the `SCHEDULED` and
`PROPOSED` thread-locals existed. Both retired when the channel was fixed.

**How to apply:** when a Ghidra analyzer "schedules" something, check whether it is a COMMAND or a
CHANGE EVENT before porting it to a `Scheduling` channel. A channel silently drops work when no
analyzer of that type is registered; a command does not. See [[r-min-range-iteration-misport]] and
[[listing-holes-blind-every-query]].
