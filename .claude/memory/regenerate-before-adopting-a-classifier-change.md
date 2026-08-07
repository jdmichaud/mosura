---
name: regenerate-before-adopting-a-classifier-change
description: A more-principled-looking change to the truth classifier would have silently dropped every entry point from the corpus-wide recall gate; only regenerating the corpus first made it visible.
metadata: 
  node_type: memory
  type: feedback
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-06T16:52:20.762Z
---

**Regenerate the corpus BEFORE adopting any change to how truth data is classified — then diff every
file, not the one you were thinking about.**

2026-08-06: backing out pattern family (6) (`50bea92`) left `nfprologue`'s three orphans correctly
unrecoverable while the corpus loop still asserted recall of them, so the suite went red. The seam:
the truth classifier calls them `code` because it has two classes and they aren't `dataptr`, while
the loop's assertion uses `code` to mean **call-reachable** — and they are referenced by nothing.
**Data and assertion disagreed about what the class means**, and the fixture sat exactly on the seam.

The fix first attempted was to add a third `unreferenced` class — genuinely more principled than a
named skip, two lines, and obviously correct on the fixture in hand. **Regenerating the corpus showed
every truth file changing:** `_cstart_` is referenced by nothing in *every* fixture, so it would have
been reclassified out of the recall assertion **corpus-wide**, silently removing every entry point
from the gate. A change that reads as a cleanup, quietly gutting the contract.

Adopted instead: skip the fixture in the loop and let its dedicated test carry the contract — the
precedent already set for `noret.gcc-x86-64`. Less elegant, no blast radius.

**The general form: a classifier change is a change to every assertion that consumes the class.**
The blast radius is not where you edited; it is wherever the class is read. And the failure mode is
silent — a gate that stops checking something still passes.

⚠️ Related failure the same day: a *new pattern* creating a function turned an unrelated existing
test onto a different code branch, where it kept passing while no longer testing its subject
(caught only by an explicit anti-vacuity assertion). Both are the same shape — **an additive-looking
change relocating what a gate measures** — and neither is visible in a green suite. See
[[self-compiled-gate-measures-your-imagination]], [[could-it-have-come-out-otherwise]],
[[generated-artifact-drift]].
