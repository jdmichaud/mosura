---
name: address-equality-is-not-op-equality
description: "trace-diff's per-address columns localize, they do not prove the same op reached the same rule — read the op shape before concluding a rule mis-declined."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-31T01:11:10.821Z
---

`scripts/trace-diff.sh` reports, per shared rule, the addresses where only one engine fired. That is
a **localizer, not a claim about ops.** Both engines key firings on the instruction address, but by
the time the rule pool runs they can hold *different graphs at the same address*.

Worked example (orcompare, 2026-07-31). `RuleSubZext` showed ghidra-only at `0x100031` — the exact
address of a surviving `INT_ZEXT` in mosura's final IR. That reads as a direct hit: "mosura's
RuleSubZext wrongly declines there." **It is false.** Ghidra's `RuleSubZext` (ruleaction.cc:5039)
requires `op->getIn(0)`'s def to be `CPUI_SUBPIECE` or `CPUI_INT_RIGHT`; mosura's op at that address
is `INT_ZEXT(INT_EQUAL(..))` — the input is a comparison, so mosura's rule declines **correctly**.
The real divergence is upstream, in what shaped the graph before the pool.

**Why:** this is the "a death certificate is only valid for the evidence it was measured on" rule
applied to an address. An address matches an *instruction*, not an *op*, and a rule's decision is
about the op.

**How to apply:** before filing "rule X wrongly declines at addr A", dump both sides' op at A and
check the shapes match (`oracle/capture --ir` vs `dumpc --raw`). If they differ, the finding is
upstream and the rule is exonerated. Cost: one dump. It is the same discipline that kept
[[trace-diff-keys-mechanism]] honest — an instrument that localizes is more useful than one that
guesses, but only if its output is read as localization.

Related: [[typeprop-channel-and-width-rootcause]], [[trace-diff-first-not-fifth]].
