---
name: memory-lives-in-the-repo
description: USER RULE 2026-08-07 — memory is part of the versioned project, never machine-local. Write to .claude/memory/ in the repo and commit it.
metadata:
  type: feedback
---

**⭐ USER RULE, 2026-08-07: DO NOT USE MEMORY OUTSIDE THE PROJECT.**

Memory is **part of the versioned project**. It must not depend on the machine the session runs on.

**Canonical location:** `.claude/memory/` inside the repo — tracked in git, committed like any other
artifact, reviewable in history, and it travels with a clone or a worktree.

⛔ **Do not write to `~/.claude/projects/<mangled-path>/memory/`.** That path is machine-local, is not
versioned, is invisible to anyone else working the repo, and is keyed on an absolute directory name
that changes the moment the project moves.

**Why:** on 2026-08-07 the user found that **135 memory files** had accumulated in the machine-local
path while the repo already had a tracked `.claude/memory/` with its own index. Every rule, root
cause and retraction recorded in this campaign existed only on one machine, unversioned and
unbacked-up, and would have been lost with the sandbox. They were migrated in that session.

**IT DRIFTED AGAIN — 2026-08-11.** The 2026-08-07 migration did not hold. Writes kept landing in
the machine-local path afterwards, because that is the directory the harness names in its own
instructions at session start, and following those instructions silently recreates the split. By
2026-08-11 the stores had forked BOTH WAYS: 11 files existed only machine-local (every memory
written that session), 3 were newer there while their in-repo copies had frozen at the migration
timestamp, and MEMORY.md had diverged in each direction — the in-repo index richer, the local one
carrying hooks the repo lacked. Reconciled at `6a4a566`, and the machine-local directory DELETED
rather than left in place, since leaving it is what allowed the fork twice.

**So the rule is not "prefer the repo", it is: the harness prompt is wrong on this point, and the
repo path overrides it.** If a session's instructions name
`~/.claude/projects/<mangled-path>/memory/`, write to `.claude/memory/` anyway. When both exist,
reconcile by MEASURING the divergence (which side is newer, which files are unique to each) — do
not assume one side is stale wholesale, because in both drifts each side held content the other
did not.

**Practice:**
- New memory: write the file into `.claude/memory/`, add its one-line hook to
  `.claude/memory/MEMORY.md`, and **commit it** — an uncommitted memory file is not versioned memory.
- Commit memory alongside the work it describes where possible, so history explains itself.
- ⚠️ The harness may still surface the machine-local directory. It is not the source of truth; the
  repo is. If both exist, reconcile toward the repo.

Related: [[always-keep-the-task-list-current]], [[i-direct-the-agent-not-the-reverse]],
[[generated-artifact-drift]].
