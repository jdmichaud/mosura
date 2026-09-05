# Decompiler bug: a switch case targeting the exit executed a NEIGHBORING case's body (WRONG CODE) — FIXED

**Phase 6 of [`compilable-c-remediation.md`](compilable-c-remediation.md), the
`break`-outside-a-breakable family (Watcom E1000, 3 TUs). Classified against Ghidra and fixed
2026-08-17.** Like the guarded-store hoist, the compile error was the visible tip of a
wrong-code defect.

## Specimen

`FUN_0005ce84` (the subject binary @ `0x5ce84`, 125 bytes): a 5-entry jump table at `0x5ce70` (in the
gap BETWEEN functions) where **case 2's target is the post-switch code** — the entry jumps
straight past the switch.

mosura emitted:

```c
{
  break;                      /* E1000 — outside any breakable statement */
  switch (param_1) {
  ...
  case 2:                     /* WRONG: case 2 executes case 4's body */
  case 4: return (uRam000997f4 & 2) == 0;
  ...
```

Case 2 should reach the `*puRam000a7ef0 == 0x960` chain (returning 3/4/5); it returned
`(uRam & 2) == 0` instead.

## Oracle

The function-slice oracle was blind twice over, and both blindnesses got instruments:

* the jump table lives between functions, in neither slice — `DecompileFunctions.java` now
  accepts `bytes=<hexaddr>:<hexbytes>` (real content, unlike the zero-filled `data=`), and the
  table bytes came from the image via `bytesat`;
* with the table present Ghidra emits the ground truth:

```c
switch(in_EAX) {
  case 0: return ...;
  case 2: break;              /* the exit-bound case, explicit */
  ...
}
if (*puRam000a7ef0 == 0x960) ...
```

Ghidra represents the cut head→exit edge as a **goto-typed case** (`BlockSwitch::addCase` with
`f_goto_goto`, block.cc:3552), prints it via `emitBlockSwitch`'s `getGotoType` arm, and
scopeBreak retypes it `break`.

## The two mosura defects, one root

Label attribution was by ADDRESS ORDER, not structure: `case_labels` assigned each table
target to the case with the minimum entry `>=` target. An exit-bound target (owned by no case)
was captured by whichever case happened to sit next in memory — the wrong-code half — and the
cut edge's own goto record flushed as a stray top-level `break;` before the switch — the E1000
half. A subtlety that defeated the first fix attempt: the exit target `0x5cea9` lies in a
RANGE GAP (its leading instructions were optimized away; blk2 ends `0x5cea8`, blk3 starts
`0x5ceae`), so containment tests miss it.

## Fix (printc, faithful to Ghidra's contract)

Per-target attribution by STRUCTURE — the Ghidra `getIndexByBlock` semantics: map the target
to the block containing it (or the NEXT block by start, for gap targets), walk the structured
parent chain to the owning case component. Targets owned by no case become explicit
`case N: break;` entries (Ghidra's goto-typed cases), and their cut-edge goto records are
suppressed (`switch_exit_suppress`, computed BEFORE the head's statement emission so the flush
sees it — the ordering that made attempt two silently late). The address-order rule is gone.

mosura now emits the specimen semantically identical to Ghidra: `case 2: break;` inside the
switch, the chain reached by fallthrough, no stray break, correct case bodies.
