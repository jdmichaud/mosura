---
name: load-the-artifact-directly
description: "When a fixture cannot reach the code under test, a test that loads the artifact BY PATH is the real gate — not a consolation prize. The constructive half of the vacuity lesson."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-06T09:47:58.624Z
---

**When a fixture can't reach the code, a test that loads the artifact directly is the real gate,
not a consolation prize.** (Lead, 2026-08-06, accepted as the better formulation.)

[[pattern-gate-cspec-routing]] catalogues how a gate proves nothing — seven instances on the
function-discovery track alone. This is what to do instead.

Worked example: `x86watcom_patterns.xml` is unreachable from every ground-truth fixture (they all
detect as `cspec=gcc`), so "fixture function sets unchanged" was worthless evidence for a rewrite
of that file — the fixtures never parsed it. What actually gated it was
`function_start.rs::save_first_family_enforces_watcoms_push_order`, which reads the real file **by
path** and asserts the property directly (all 31 conforming runs mark the first push in both
encodings; reordered / eax-esp-bearing / 6-push runs do not).

**Why:** a fixture gate is only evidence when the fixture loads the artifact. When it cannot, the
choice is not "weak gate vs no gate" — it is "vacuous gate vs a direct one", and the direct one is
strictly better: it can fail for the reason it claims to test, and it does not depend on a routing
accident staying true.

**How to apply:**
- Ask what the gate LOADS before trusting it. If the artifact under test is a data file (patterns,
  cspec, `.sla`), read it by path in a unit test and assert the property.
- Pair it with an attribution check: toggle the responsible analyzer off and confirm the number
  moves. A gate must be able to fail for its stated reason.
- Say plainly which half of the evidence was vacuous rather than letting a green run stand in for
  a measurement — see [[numbers-stale-unless-sha-stamped]] and
  [[could-it-have-come-out-otherwise]].
