---
name: inert-is-not-thread-safe
description: ⭐ Inert-when-unset and safe-under-concurrency are DIFFERENT properties — asserting the first implies nothing about the second. The env-var test hook that turned the suite red.
metadata: 
  node_type: memory
  type: feedback
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-06T11:19:53.826Z
---

**Inert-when-unset and safe-under-concurrency are different properties, and asserting the first
implies nothing about the second.** (2026-08-06, agreed formulation.)

## What it cost

A test hook read `MOSURA_X86_32_CSPEC` / `MOSURA_DISABLE_ANALYZERS` from `std::env` at the point of
use, and tests set them with `set_var`. It was reviewed, and the review verified the hook was
**inert when unset** (unset vs explicitly empty, both bit-identical). That was true, and
irrelevant.

`cargo test` runs a binary's tests on **parallel threads in one process**. `set_var` mutates state
shared by all of them, so one test's routing leaked into whatever another test was analysing at
that moment. Suite went 585/2 with **two tests failing for something neither of them tests** —
they passed in isolation and passed under `--test-threads=1`. Restoring the previous value
afterwards cannot help: the race is *inside* the window.

## The fix, and why the obvious one is wrong

`crates/mosura/src/analysis/overrides.rs` — **thread-locals**, env vars kept as fallback. An
analysis runs entirely on its caller's thread, so an override is private to it.

A `Mutex` is the reflex answer and it is quietly useless here: it would have to be taken by
**readers** as well as writers, or a writer still leaks into a concurrent reader mid-analysis —
which degenerates into serialising the whole file, i.e. `--test-threads=1` wearing a lock.
**Remove the shared state; don't guard it.**

Two things worth copying:
- callers get a `#[must_use]` **RAII guard**, because the original's manual restore never ran on a
  failing assert — so one red test could poison every subsequent one. Nastier than the bug being
  fixed.
- a unit test asserts **an override is not visible on another thread**. That is the test that
  would have caught the original design, so it is the one that must be permanent.

## How to apply

When reviewing any global/ambient switch, ask what *axis* the safety argument covers. "Inert when
off", "restores the previous value", "only used in tests" are all real checks that say nothing
about concurrent mutation. And `--test-threads=1` is never a resolution — CI uses the default.

Same shape as the rest of this track (see [[pattern-gate-cspec-routing]],
[[load-the-artifact-directly]], [[absolute-vs-differential-wrongcode]]): the check was real, it
just wasn't checking the thing that could break.
