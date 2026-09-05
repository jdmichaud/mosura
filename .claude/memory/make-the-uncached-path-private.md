---
name: make-the-uncached-path-private
description: USER RULE 2026-08-10 — when adding a cache, make the UNCACHED loader private or delete it. Only the cached form stays public, so the mistake cannot recur.
metadata:
  type: feedback
---

**⭐ USER RULE, 2026-08-10: when you add a cache, the uncached function becomes PRIVATE — or is deleted.
Only the cached form stays public.**

*"So that we don't fall into that problem again."*

**A cache that callers MAY use is a cache some caller will not use.** The fix for a repeated expensive
load is never "add a cache and update the call sites" — it is **"make the uncached path unreachable
from outside the module"**. The privacy change is the durable half; the cache alone is a convention,
and conventions decay.

**Why, concretely (2026-08-10):** `lang::resolve_cspec` re-resolved and re-parsed the compiler spec
**from disk on every call** — a `read_dir` over all processor directories plus an XML parse of every
`.ldefs`, at **34.7 ms/call**. It sat behind `cspec::default_input_paramlist` →
`symbolic::integer_arg_registers`, reached from `flow_constants`, and made Constant Propagation
**~94% compiler-spec I/O** — 122 s of a 427 s the subject run. ⚠️ **mosura already cached the SLEIGH side of
the same layer** (`lang::load_cached`) and the cspec side simply never got it. One half cached, one
half not, both public: that is the shape this rule prevents.

**Applying it:**
- Delete the uncached form if the cached one subsumes it — stronger than making it private.
- Otherwise `fn`, not `pub fn`. ⚠️ **Check `pub(crate)` is actually enough** — if an uncached
  resolution is still reachable from outside the module, the constraint is not met.
- Route existing callers through the cached form. Callers in modules you may not edit get the fix
  for free if the shared helper caches internally — prefer that over reaching across a boundary.
- Match the naming/shape of the sibling that is already right, so the pair reads as one design.
- ⚠️ Scope discipline: this is *privacy plus a cache*, not a refactor of the layer. If privacy forces
  signature churn across many call sites, report the count before doing it.

⚠️ **A cache-hit-rate test can rot; a private function cannot be called.** Prefer the structural
guarantee over the test.

Related: [[hard-rules-never-stop-one-agent]] (remove-before-create), [[inert-is-not-thread-safe]]
(remove shared state, do not guard it), [[generated-artifact-drift]].
