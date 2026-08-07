---
name: typeprop-channel-and-width-rootcause
description: "Ghidra's TYPEPROP_DEBUG is a SECOND trace channel (already in the library); wiring it exonerated type_order — the 1-byte divergence is varnode WIDTH, from SubVariableFlow."
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-31T01:05:25.708Z
---

**The instrument** (`e1d020b`): `scripts/typeprop-diff.sh` + `oracle/capture_typeprop`. Ghidra ships
`TYPEPROP_DEBUG` as a channel SEPARATE from `OPACTION_DEBUG`, precisely because the latter is a
p-code-OP mutation log and cannot see type work (see [[trace-diff-keys-mechanism]]). Hook =
`ActionInferTypes::propagationDebug` (coreaction.cc:4980), called from `propagateTypeEdge` at the
`typeOrder` comparison (coreaction.cc:5105) ⇒ every ACCEPTED type decision with its op+slot.
mosura's mirror already existed and had never been diffed: `MOSURA_TYPEPROP=1`
(infertypes.rs `propagation_debug`).

**No special build is needed** — `types.h:88-91` auto-defines `TYPEPROP_DEBUG` from `CPUI_DEBUG`
alongside `OPACTION_DEBUG`, so the hook is already in `libdecomp_dbg.a`. Only the RUNTIME flag is
extra (`TypeFactory::propagatedbg_on`, default false, type.cc:3101). ⚠️ I concluded the opposite
from a plausible inference and started a library rebuild before one grep refuted it — **a build
premise is checkable in seconds; never carry one on an inference.**

**⭐ THE RESULT: `type_order` is EXONERATED.** On `orcompare`, Ghidra types a **1-byte** chain
(`#0x1:1`, `#0x2:1`, `char` x6, `xunknown1` x4) where mosura types a **4-byte** one (`#0x1:4`,
`#0x2:4`, `Int(4)`; mosura assigns NO 1-byte integer type at all). Both propagate correctly over the
varnodes they have — same algorithm, differently-shaped IR. `getBase(4, TYPE_INT)` is `int4` by
construction, so **no preference-ordering change can yield `char` from a 4-byte varnode.** Do not
touch `type_order`/`op_meta` for this class.

**The real site is SubVariableFlow**, upstream of type inference — and the op trace had already said
so, in the section nobody reads: on the same fixture `subvar_zext` ghidra=6/mosura=10, `subzext`
ghidra=8/mosura=5, `subvar_and` mosura-only x2.

**⭐ THE TRANSFERABLE LESSON: a diff's SHARED / "agreeing" section is not noise.** The answer sat in
the per-rule count column for the whole thread while attention went to the exotic "missing port"
column. When a diff has a headline category, read the boring one too.

Deliberate limit of the tool: no per-varnode join (Ghidra prints `CL(0x00100033:da)`, mosura
`r0x8:4(0x10001b:74)#494`; no identity map exists and an approximate one could report false
agreement). It compares decision mix, varnode widths, and constants by (value,size) — enough here.
