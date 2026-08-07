---
name: landed-means-reachable-from-a-ref
description: "\"Landed\" means reachable from a ref, not committed — name the return point before any `git checkout <sha>`, and check `git branch --contains` before declaring a land."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-30T10:10:05.129Z
---

A whole battery-green series (8 commits: Stage B through the spacebase-placeholder land) once sat
on an **unreferenced detached HEAD** — `git branch --contains <tip>` returned nothing and only the
reflog held it. The closest this project has come to actually losing work.

The cause was a *measurement* round trip, not a mistake in the work: `git checkout 08ca850` then
`git checkout 62f7812` to get a true per-fixture corpus baseline. That detaches HEAD, and every
commit made afterwards goes somewhere unaddressable. It looked completely normal the whole time —
`git log` showed the series, commits succeeded, the battery passed.

**Why:** a commit is not a land. A commit with no ref pointing at it is garbage-collectable, and
`git log`/`git status` give no hint, because HEAD reaches it fine. Nothing in the normal workflow
surfaces the problem.

**How to apply:**
- Before any `git checkout <sha>` for baseline measurement, record the return point by NAME
  (`git rev-parse --abbrev-ref HEAD`, or create a branch first) — never plan to return by sha.
- Prefer measuring on a throwaway worktree or a named temp branch over detaching the working HEAD.
- Before declaring anything landed, run `git branch --contains <tip>`. Empty output means NOT
  landed, whatever the commit log says.
- If it has already happened: fix it ADDITIVELY — create a branch at the tip. Never "fix" it by
  moving or rewriting an existing branch. See [[gate-byte-identical-only]] for the same
  additive-only instinct applied to gating.
- Check where `master` actually points before assuming a series is on it. In this repo master
  lagged the work by many commits and did not even contain the predecessor's Stage B commit, so
  "landed" meant "landed on a feature branch" — a distinction worth stating explicitly in any
  handoff. Related: [[numbers-stale-unless-sha-stamped]] (a sha alone does not identify a tree, and
  it does not identify a *branch* either).
