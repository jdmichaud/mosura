---
name: war2-per-function-ghidra-oracle
description: "⭐ RECIPE (2026-07-29): ask Ghidra about ANY WAR2 function despite the DOS/4GW-LE loader problem — raw BinaryLoader import of the function's bytes at its own VA + a DecompileAt.java postScript. Verdict it produced: mosura's dropped loop bodies are a MIS-PORT; Ghidra decompiles them correctly."
metadata: 
  node_type: memory
  type: reference
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-29T08:31:31.121Z
---

# Asking Ghidra about a single WAR2 function (works around the LE loader problem)

WAR2.EXE is DOS/4GW LE and Ghidra loads only the MZ stub ([[war2-dos4gw-le]]), so `analyzeHeadless`
on the .EXE cannot see protected-mode code at all. **Sidestep it entirely**: import just the
function's bytes as a raw binary based at its own VA.

```sh
H=/data/tools/ghidra_12.0.3_PUBLIC/build/dist/ghidra_12.0.3_DEV/support/analyzeHeadless
# bytes come straight from war2-survey/manifest.tsv column 9 (orig_hex)
awk -F'\t' '$2=="0001bd30"{print $9}' war2-survey/manifest.tsv | xxd -r -p > fn.bin
export LC_ALL=C.UTF-8 LANG=C.UTF-8
"$H" /tmp/proj cap -import fn.bin \
  -loader BinaryLoader -loader-baseAddr 0x1bd30 -processor "x86:LE:32:default" \
  -scriptPath ./gscripts -postScript DecompileAt.java 1bd30 -deleteProject
```

`DecompileAt.java` (a `GhidraScript`): `toAddr(arg)` → `getFunctionAt` else `disassemble` +
`createFunction` → `DecompInterface.openProgram(currentProgram)` →
`decompileFunction(f,120,monitor)` → print `getDecompiledFunction().getC()`, prefixing each line
with a grep-able marker. Copy the headless arg pattern from
`mosura-analysis/scripts/capture-analysis.sh` (its raw-`.COM`/z80 branch is the same shape).

**It works with NO surrounding context** — a 179-byte import with unresolved call targets still
decompiles correctly, so Ghidra's result cannot be dismissed as "it had more analysis context".
Call targets outside the range simply render `func_0xNNNNNNNN()`.

## The verdict it delivered (2026-07-29)
For `FUN_0001bd30` **Ghidra emits the full function**: the `for` loop over the linked list, all
**4 calls**, and — decisively — the loop-carried stack local:
```c
for (iVar4 = _DAT_0008f20c; iVar4 != 0; iVar4 = *(int *)(iVar4 + 0x60)) {
  if (... (iVar3 = func_0x0001bc90(), iVar3 == 0)) && (iVar3 = func_0x0001ba38(1), iVar3 != 0)) {
    uVar2 = func_0x0001ec50();
    if ((uVar2 < 0xb) && (uVar2 < uVar1)) { iStack_1c = iVar4; uVar1 = uVar2; }   // loop-carried def
  }
}
if ((iStack_1c != 0) && (iVar4 = func_0x0001ba38(1), iVar4 != 0)) { return 1; }
```
mosura emits **1 of 4 calls** (baseline) or **0 of 4** (with the stack-pointer patch), with the whole
loop body collapsed. `FUN_0001b8b8` is the same story — Ghidra produces nested loops and 3+ calls
where mosura emits `while (!SBORROW4(0,4)) { }`.

⇒ **MIS-PORT, not a faithful-but-unlucky outcome.** Ghidra models the loop-carried write to a stack
slot correctly; mosura's equivalent store (`0x1bdaa mov [ebp-0xc],esi`) is DEAD in *both* builds, so
the later LOAD folds to the prologue constant and a real branch is pruned. Same family as the
already-landed D4 (`mosura-analysis/docs/decompiler-bug-d4-tailcall-empty-loop.md`, "empty infinite
loop with the call dropped") but a different trigger — D4 was a cross-function tail-`jmp`; this
function ends in a normal `ret`. Do not assume they share a mechanism without instrumenting.

Related: [[absolute-vs-differential-wrongcode]], [[war2-stackptr-wrong-code]],
[[goal-is-the-binary-not-ghidra]], [[print-raw-has-no-dead-filter]].

**⚠️ ORACLE LEDGER (2026-07-29, measured): the per-function recipe UNDER-EMITS on ≥18 WAR2 functions (45 call sites)** — isolated raw import means callees can't resolve; Ghidra folds the guards and prunes LIVE blocks (its own "Removing unreachable block" warnings say so; FUN_00066da8: Ghidra 2 calls vs 9 byte-verified; cluster 000683d7..00068608 at zero). **Every "% of Ghidra" gauge number inherits this caveat** — quote deficits, state surpluses separately with cause; >100% is not a quality claim. FILED improvement: whole-image import (fixup-applied image as one raw block, all 1303 entries seeded) should close most of the 18.
