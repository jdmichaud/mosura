---
name: rule-trace-diff-tool
description: "The mosura↔Ghidra rule-application trace-diff tool — how to use it to find which Ghidra rules mosura doesn't fire."
metadata: 
  node_type: memory
  type: reference
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

The rule-application trace-diff tool (landed this session) is the primary way to find which Ghidra simplification rules mosura is missing or mis-firing — instead of reverse-engineering rule sequences from `--ir` diffs.

**Correction to prior memory:** OPACTION_DEBUG is NOT compiled out. `types.h:88` does `#ifdef CPUI_DEBUG → #define OPACTION_DEBUG`, so the EXISTING `libdecomp_dbg.a` (built with -DCPUI_DEBUG) already contains the trace machinery (debugModPrint/debugSetRange/debugCheckRange). No separate -DOPACTION_DEBUG rebuild is needed — the earlier "compiled OUT, needs Opt-1 separate libdecomp_trace.a" note was wrong.

**How it works:**
- Ghidra side: `oracle/capture_trace` (separate binary, links the SAME existing libdecomp_dbg.a with the SAME -DCPUI_DEBUG -D__TERMINAL__ switches — oracle/capture untouched, no ABI divergence). `--trace` enables fd->debugEnable()+debugSetRange(whole fn)+setDebugStream → emits `DEBUG <n>: <rulename>: <before> => <after>`.
- mosura side: `--debug opaction` env var (OFF by default → corpus byte-identical) hooks ActionPool::apply (action.rs), same format; the alias-probe pool run is suppressed so the trace isn't doubled. Runner = `crates/mosura/examples/trace.rs` (TRACKED; dump*.rs stays gitignored).
- Diff: `scripts/trace-diff.sh <fixture>` reports per-rule counts, Ghidra-only rules (candidate ports), and per-address divergences.

**How to apply:** before porting rules, run `trace-diff.sh <fixture>` on a fixture with a known gap → the "Ghidra-only rules" list is the GROUNDED faithful-port worklist (the trace PROVES Ghidra fires them). Firing-count mismatches (e.g. addmultcollapse 33-vs-1) flag rules mosura has but under-fires. First-run findings fed into the Task-#3 rule backlog. See [[port-all-faithful-rules]].
