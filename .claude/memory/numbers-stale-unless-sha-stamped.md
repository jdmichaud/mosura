---
name: numbers-stale-unless-sha-stamped
description: "Every recorded corpus/fixture number (and plan) is STALE unless tagged with the sha it was measured at AND that sha == current HEAD. Re-measure on HEAD before using any recorded number as a premise. The corpus report must be self-dating (emit @sha)."
metadata:
  node_type: memory
  type: feedback
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

User directive (2026-07-11): never build on a stale number again. Root cause seen twice this session: a number recorded at commit X, read later at commit Y, treated as current — "floatcast +0.038" (measured @ old 0.8936 master; p4infer1 falsified it on 0.9209) and revisit "0.477/0.618" (measured pre-guardCalls-ram; mloop4 falsified it — baseline is now 0.679 @ e73a1c0).

THE RULE:
1. Every recorded corpus/fixture number MUST carry the sha it was measured at: `avg 0.9209 / 56-of-60 @ b573e78`. A number without an @sha is unciteable.
2. A number whose @sha != current HEAD is STALE — RE-MEASURE on HEAD (`cargo test -q -p mosura --test decompile_corpus decompile_track_corpus_report -- --nocapture`) before using it as a premise. The startup-check report is the ONLY trusted current number.
3. Same for PLANS: a memory "port X → expect +Y" is a hypothesis dated at some sha. Instrument-first on HEAD before building — this session #8/#10 said "port X" but X was already landed; #12/#13-14 were mis-attributed. The lead's framing (and recorded numbers) are hypotheses; the trace on HEAD is the authority. See [[faithful-type-of-wrong-ir]].

MECHANICAL AID (LANDED e86b7d4): `decompile_track_corpus_report` now stamps `@ <short-sha>` (+ `-dirty` for uncommitted trees) in both header lines — `head_sha()` in crates/mosura/tests/decompile_corpus.rs. Every invocation is dated (can't be bypassed); `@sha != HEAD` is a one-glance stale check; `-dirty` catches measuring uncommitted changes (a clean sha over a modified tree is the same trap). So read numbers straight off the report header, sha included.

AGENT-BRIEF BOILERPLATE (add to every spawn): "Treat every recorded corpus/fixture number as STALE unless it carries current HEAD's sha; re-measure the baseline before building on it. Report numbers as `avg X / N-of-M @<sha>`." Plus: "verify `git status` before claiming tree-clean" (a predecessor claimed clean with a staged probe).
