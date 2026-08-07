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

**Practice:**
- New memory: write the file into `.claude/memory/`, add its one-line hook to
  `.claude/memory/MEMORY.md`, and **commit it** — an uncommitted memory file is not versioned memory.
- Commit memory alongside the work it describes where possible, so history explains itself.
- ⚠️ The harness may still surface the machine-local directory. It is not the source of truth; the
  repo is. If both exist, reconcile toward the repo.

Related: [[always-keep-the-task-list-current]], [[i-direct-the-agent-not-the-reverse]],
[[generated-artifact-drift]].
