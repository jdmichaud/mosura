---
name: mve-first-then-solve-the-mve
description: "USER RULE (restated 2026-08-05) — a defect found on the subject becomes an MVE first, and the MVE is what you solve; now AGENTS.md directive 6"
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-08-05T08:43:55.634Z
---

**"If you find an issue decompiling the subject, generate an MVE to surface the problem. Then solve the
MVE."** — the owner, 2026-08-05, restating it because it had been lost.

**Why:** the subject is temporary scaffolding and cannot be shipped. A gate built on it dies when the
binary goes, and until then is unreproducible by anyone who lacks it. The owner's framing: *"As
the subject is temporary, this is why I asked you to reinforce our tests with MVEs and small programs
to reproduce the issue you see so that we can 'solidify' our test suite. At one point, the subject will
disappear."* Also 2026-08-05: **no mentions of the copyrighted binary in the mosura repo** — the
survey tooling gets its own repo in `<subject-survey>/` instead.

**How to apply:** the subject defect → minimal self-compiled program in `oracle/ground-truth/src/` →
gate in `crates/mosura/tests/ground_truth_parity.rs` → fix THAT. the subject stays as corroboration,
never as the gate. Two conditions make the MVE worth having:

1. **Prove it FAILS pre-fix and passes post-fix.** A gate that never caught the bug is
   decoration. Recipe that does not disturb a working tree: `git worktree add <scratch>/prefix
   <pre-fix-sha>`, copy the built `.watcom-x86-32{,.truth}` in, append the test fn, run with
   `CARGO_TARGET_DIR=<scratch>/prefix-target`.
2. **Write the load-bearing properties into the .c source**, or a later "cleanup" simplifies the
   program into one that no longer reproduces the defect.

Now [`AGENTS.md`](../../../projects/mosura/mosura/AGENTS.md) operating directive 6 (`8a97638`) —
it was skipped for months precisely because it lived only here. Same lesson as
[[hard-rules-never-stop-one-agent]]: a rule not in the repo is a rule that survives only on my
diligence.

## Building an MVE: traps paid for on `loopcomma.c` (`cc2ebda`)

Four attempts failed before one reproduced. Each cost a Watcom rebuild + decompile:

- an early `return` in the body adds a second exit → **do-while**, not while-do
- if the loaded value's only use is the comparison, the compiler **folds it into the test** and
  no statement is left in the condition block
- a pointer chase (`p = p->next`) does **NOT** prevent for-recovery
- reordering the body does **NOT** either — Watcom schedules the advance last regardless of
  source order

**The lever that works: a GLOBAL loop variable defeats for-recovery** (no loop-carried
MULTIEQUAL in the head, so `findLoopVariable` finds nothing). Use it to force a WhileDo — and
never use it when you need a `for`, or the gate passes vacuously against the wrong printer arm.
This is the same mechanism behind the ~6 `DAT_`-loop-variable cases in [[task7-missed-for-loops]].

Related: (subject-profile note `issues-become-source-tests`) (the older statement of the same rule),
[[self-compiled-ground-truth]], [[the subject survey folder-artifacts-stamped]].
