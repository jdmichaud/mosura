---
name: worktree-needs-ghidra-src-or-ratchet-lies
description: "A git worktree outside the repo's parent dir silently falls back to the vendored 15-language set, and disasm_pcode_ratchet then reports a REGRESSION rather than skipping."
metadata: 
  node_type: memory
  type: reference
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-06T16:59:41.115Z
---

**Always run a scratch git worktree with `GHIDRA_SRC=/home/jd/projects/mosura/ghidra`.**

`paths::ghidra_src()` (`crates/mosura/src/paths.rs:21`) resolves in order: **`GHIDRA_SRC` env → the
sibling checkout `<workspace>/../ghidra` → the vendored in-repo copy**. A worktree created under
`/tmp/...` has no sibling `ghidra`, so it silently drops to the vendored `third_party/ghidra` — only
**15** `.sla` languages, missing ARM / MIPS / PowerPC.

⚠️ **`disasm_pcode_ratchet` then reports a REGRESSION, not a skip:**

```
disasm parity: 244/244 golden instructions reproduced   <- everything present passes
thread panicked: disasm parity regressed: 244 < 254     <- floor assumes ARM/MIPS/PPC loaded
```

The test skips cleanly when **zero** languages load (`if langs_loaded == 0 { return; }`) but asserts
a fixed floor (`EXPECTED_DISASM_PASS = 254`, unchanged since the initial commit) when *some* load.
So a **partially**-configured environment is indistinguishable from a real parity regression, and
the per-file lines all read `N/N reproduced` — nothing failed, there was simply less to run. Cost
2026-08-06: reported the suite as red at HEAD before finding the cause.

**Diagnostic tell:** several `skip (no tables for ARM:LE:32:...)` / MIPS / PowerPC lines above the
panic. If those appear, fix the environment, don't chase the code. Setting `GHIDRA_SRC` makes it
pass immediately.

✅ **the subject measurements are NOT affected** — `x86.sla` is in the vendored set, and an isolated
worktree at `0acd3a0` reproduced the main worktree's `3018 / 2108 / 12 / 3` and `899/900` exactly.
The fallback only costs the multi-architecture golden test.

Why worktrees at all: doing revert-checks in the shared worktree wiped a running agent's scratch
file and produced a build with the fix absent. Use a worktree — with `GHIDRA_SRC` set. See
[[single-agent-protocol]], [[measurement-determinism-first]].
