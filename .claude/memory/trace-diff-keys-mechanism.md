---
name: trace-diff-keys-mechanism
description: "trace-diff now keys firings on the Ghidra CLASS, not the trace name; and OPACTION_DEBUG is structurally BLIND to type inference on both sides."
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-30T23:44:22.769Z
---

Two facts about `scripts/trace-diff.sh`, both bought on 2026-07-31, both invisible from the code.

**1. It used to compare names as STRINGS, and the port renames things.** Its headline column
("rules Ghidra fires but mosura never does") mixed naming artifacts in with real findings. On
`orcompare` that column was 11 entries; after keying on the underlying class it is **2**. The other
9 split three ways, and the three read completely differently: 1 pure naming pair
(`collect_terms`/`collectterms`), 1 merged action (`returnrecovery` — mosura folds ActionActiveParam
+ ActionReturnRecovery into `resolvecalls`, which was sitting in the OPPOSITE column of the same
output), and **7 rules mosura HAS and simply does not fire on that fixture**. "Not ported" and
"ported but inert" are different defects with different fixes.

`scripts/trace-names.py` builds the map by joining the two source trees on the CLASS name (the port
mirrors Ghidra's class names), derived at every run so there is no generated artifact to drift. Only
6 classes need a hand-written entry. Its ADAPTATION list — classes with no Ghidra class named in the
port — is the **live invention inventory** for the retirement track; run it standalone to audit.
It also caught mosura's own vocabulary colliding with itself (a rule `condnegate` AND an ActionPool
labelled `"condnegate"`; same for `ptrarith`) — unattributable in a trace, since OPACTION_DEBUG
prints actions and rules in one format. Pools renamed.

**2. ⭐ THE TRACE CANNOT SEE TYPE INFERENCE — ON EITHER SIDE.** `infertypes` fires ZERO times in
BOTH traces, and that is structural, not a divergence: Ghidra's OPACTION_DEBUG is a **p-code-OP
mutation log** (`debugModCheck(PcodeOp*)` pushes ops into `modify_list`; `debugModPrint` returns
early on `if (modify_list.empty())`, funcdata.cc:1012/1035). `ActionInferTypes` assigns `Datatype*`
to VARNODES via `updateType` and modifies no ops, so it can never print.
⇒ Never read a type-inference conclusion out of a trace-diff, and never treat a type action's
absence from the "missing" column as evidence of anything. A predecessor read `prototypetypes` /
`returnrecovery` out of that column as "a direct hit on the type-inference thread"; one was a naming
artifact and the instrument could not have named a type mechanism even in principle. That thread
needs a per-varnode type-assignment log instead.

Related: [[trace-diff-first-not-fifth]], [[rule-trace-tool]], [[print-raw-has-no-dead-filter]],
[[generated-artifact-drift]].
