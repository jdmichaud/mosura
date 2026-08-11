---
name: never-edit-a-running-script
description: "Editing a bash script while it runs corrupts its execution — bash reads incrementally by byte offset, so the shift resumes it mid-token"
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-08-11T07:38:29.097Z
---

**Never edit a shell script that is currently executing. Copy it to a frozen path and run the
copy if you need to keep working on the original.**

**Why:** bash does not read a script into memory — it reads incrementally, tracking a BYTE
OFFSET. Rewriting the file while it runs shifts everything after the current offset, and bash
resumes in the middle of whatever now occupies that position. It does not fail cleanly: it
executes a fragment.

Measured 2026-08-11: `war2-survey/compile.sh` was mid-run (a ~25 minute dosemu batch) when I
committed an edit to it. The dosemu compile finished, then the object-collection loop died with

```
compile.sh: line 100: ssion: command not found
```

— `ssion` being the tail of the word "session" in a comment that had slid under the read offset.
The whole run's results were lost, and the failure looked like a script bug rather than a
self-inflicted one, which cost a diagnosis cycle.

**How to apply:** before editing any `.sh` that might be executing, check (`pgrep -f`). If it is,
either wait, or `cp script.sh /tmp/frozen.sh && bash /tmp/frozen.sh` so the running copy is
immutable. The same applies to a Python script only while it is still being *imported*; Python
compiles the whole file up front, so it is far less exposed — this is a bash-specific trap.

Related: [[measurement-determinism-first]], [[war2-survey-artifacts-stamped]] (the sibling trap of
reading an artifact mid-write).
