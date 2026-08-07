---
name: redirect-output-then-read-the-file
description: USER RULE 2026-08-07 — every launched task redirects its output to a file; then work on the file. Never re-run a command to see its output again.
metadata: 
  node_type: memory
  type: feedback
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-07T08:01:23.441Z
---

**⭐ USER RULE, 2026-08-07.** *"Whenever you launch a task now you redirect the output to a file AND
THEN you work on the file."*

```sh
cmd > /tmp/.../run.log 2>&1
grep ... /tmp/.../run.log        # as many times as needed, free
```

**Never re-run a command to re-read, re-filter, or re-total its output.** The output is data; capture
it once, then query it as often as needed.

**Why:** on 2026-08-07 I ran the full workspace suite (~10 min on a 600 KB binary), grepped one
pattern, then **re-ran the entire suite** just to sum the pass/fail totals — a number that was
already in the output I had discarded. The user stopped it. In this project a single run is minutes:
a WAR2 analysis is ~4 min, `ground_truth_parity` ~145 s, `analysis_parity` ~230 s, the workspace
suite ~10 min. Re-running to re-read is one of the most expensive mistakes available.

**Applies to:** test suites, WAR2 runs, Ghidra `analyzeHeadless`, corpus sweeps, dosemu builds —
anything that takes more than a few seconds.

⚠️ Corollary: pipe the **whole** output to the file, not a pre-filtered subset. `cmd | grep X > f`
throws away everything you did not think to ask for, which guarantees a re-run when the next
question differs. Filter on read, never on write.

Related: [[i-direct-the-agent-not-the-reverse]], [[measurement-determinism-first]],
[[numbers-stale-unless-sha-stamped]].
