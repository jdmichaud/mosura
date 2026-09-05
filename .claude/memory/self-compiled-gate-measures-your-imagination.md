---
name: self-compiled-gate-measures-your-imagination
description: "A self-compiled fixture corpus can only refute defects its author thought to write; \"0 spurious across 17 known binaries\" was structurally blind to a family matching ordinary mid-function code."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-06T16:42:48.581Z
---

**A self-compiled gate measures its author's imagination, not the pattern's precision.**

Pattern family (6) (no-frame prologues, `50bea92` backs it out) shipped with what looked like strong
precision evidence: fixture recall 3/3 vacuity-checked, **0 spurious across 17 fully-known Watcom
binaries**, zero marks outside its own fixture on the 16 pre-existing ones, and the subject body-intrusions
unchanged at 3. On the subject it then added **53 functions of which 39 do not end like functions** — 26%
on the terminator instrument against a 99.8% population baseline.

**Why:** the ground-truth binaries are small, freestanding, and nearly free of stack-passed
arguments and global reads. The family matched ordinary mid-function code —
`51 52 8b 44 24 08` (push args then `mov eax,[esp+8]`), `56 57 8b 05 <abs32>` (pushes then a global
read) — a shape **the corpus could not contain in principle**. The gate was not weak; it was blind.

**The discriminator that explains why the earlier 900 were fine:** every other family in the file
anchors on a **frame setup** (`55 89 e5` / `55 8b ec`) or the stack probe (`68 ........ e8`). A frame
setup essentially only occurs at a function entry. Family (6) was the first family with no such
anchor, and "some pushes, then a memory access" occurs everywhere in a real binary.

⚠️ **The Watcom push-ORDER invariant does not rescue an unanchored family** — this was the family's
central precision argument and it was wrong. Argument pushes frequently conform to
`ebx,ecx,edx,esi,edi` by coincidence; for a 2-element run **half of all ordered pairs conform**.
Ordering discriminates a save-run from a *reordered* run, never from an argument run.

**The decisive artifact** (the subject `0x53000` region, read from the image): a 16-byte idiom inlined at
dozens of sites, byte-identical including its operand, each preceded by a backward `e9` jmp —

```
idiom       56 57 55 8b 15 14 9a 09 00 42 89 15 ...   push esi,edi,ebp ; mov edx,[0x99a14] ; inc ...
real proto  56 57 55 89 e5 ...                        push esi,edi,ebp ; mov ebp,esp
```

**Identical conforming three-register run ending in `push ebp`; ONE byte position separates them.**
That kills the "conformance is only a coin-flip at short runs" hope — this is a 3-run and it is
mid-function. The shipped 107-pattern file was re-checked against these bytes and does **not** match
(`marks={}`), while it does match the real prologue (`marks={5,6,7}`) — so family (1) survives
*because it requires `55 89 e5`*, not because of the ordering. **The frame setup was always carrying
the discriminating load; the ordering is a refinement on top of it.** Removing the anchor and
keeping the refinement, then arguing the refinement was the safeguard, was the error.

⚠️ **The fall-through guard is NOT a precision backstop for an unanchored pattern.** These sites are
preceded by `e9` (jmp), which does not fall through, so `checkAlreadyInFunctionAbove` correctly
declines to veto — `be85c85` working as ported. The guard removes candidates provably continuing an
existing flow; it says nothing about candidates that aren't. See
[[decoded-not-in-function-needs-address-table]].

**What to do instead:** for any pattern lacking a frame-setup anchor, the self-compiled corpus is
not sufficient evidence — score the **population** on a large real binary against a control
(see (subject-profile note `byte-exact-campaign`) and the terminator instrument: expert-verified 2111/2118 = 99.7%
vs pattern-only 899/900 = 99.9%). ⚠️ Body-intrusion counts are also insufficient alone: they can
only see intrusions into the 28.6% of the subject the tracker covers with sizes.

Also from the same arc: **stating a limitation is not reasoning from it.** The commit documented
both of the family's exclusions and never composed them into "therefore its recall against the 12
is necessarily zero". And **a pre-commitment needs a stop condition** — "if the rate is bad, drop
half X" was overtaken when the mechanism showed *both* halves matched the same wrong class.

Related: [[could-it-have-come-out-otherwise]], [[pattern-gate-cspec-routing]],
[[gauge-counting-traps]], [[absolute-vs-differential-wrongcode]].
