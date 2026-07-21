# Decompiler bug (D4) → decompiler agent: cross-function tail call becomes an empty infinite loop

**Owner: decompiler track.** Surfaced by the ground-truth bug-hunt (task #3/A7). Classified
**MIS-PORT** (mosura diverges from Ghidra; Ghidra decompiles it correctly) via a same-function
comparison against Ghidra's own C — a real decompiler port bug to fix.

## Symptom

A function whose optimized body ends in a **tail-jump into another function** (`jmp <otherfn>`,
gcc's tail-call of a mutually-recursive pair) is decompiled as an **empty infinite loop** with
the call dropped: `do { } while (n != K); return 1;`. The loop-body work and the tail-call to the
other function are both LOST.

## Repro (self-contained)

Binary: `oracle/ground-truth/tailcall.gcc-x86-64` (committed). Source
`oracle/ground-truth/src/tailcall.c` — mutual tail recursion:

```c
static int is_odd(int n)  { return n == 0 ? 0 : is_even(n - 1); }
static int is_even(int n) { return n == 0 ? 1 : is_odd(n - 1); }
```

gcc -O2 merges the pair into a decrement-by-2 loop split across the two function boundaries:
`is_even` @ **0x401000** (`test/jne; ret 1; sub $1; jmp is_odd`), `is_odd` @ **0x401020**
(`sub $1; jmp is_even`).

```
cargo run -q --example gt_recompile_probe -- oracle/ground-truth/tailcall.gcc-x86-64 401000 401020
```

## mosura C (WRONG)

```c
xunknown8 FUN_00401000(int4 param_1) {   // is_even
  do {
  } while (param_1 != 0);                // empty infinite loop; the `n-=2` body + tail-call DROPPED
  return 1;
}
xunknown8 FUN_00401020(int4 param_1) {   // is_odd
  do {
  } while (param_1 != 1);
  return 1;
}
```

## Ghidra C (CORRECT — the reference)

Ghidra 12.0.3 (`analyzeHeadless` + `DecompInterface`, same stripped binary):

```c
undefined8 FUN_00401000(int param_1) {   // is_even
  undefined8 uVar1;
  if (param_1 == 0) {
    return 1;
  }
  uVar1 = FUN_00401020(param_1 + -1);    // tail-jmp rendered as a CALL to is_odd
  return uVar1;
}
void FUN_00401020(int param_1) {         // is_odd
  FUN_00401000(param_1 + -1);            // tail-jmp rendered as a CALL to is_even
  return;
}
```

## Verdict: MIS-PORT

Ghidra models the tail-`jmp` into another function as a **CALL** to that function followed by a
return; mosura mis-structures it as a **back-edge to its own entry** (an empty self-loop) and
drops the call entirely. This is a structuring / tail-call-recovery divergence in the decompiler.
Fix so mosura renders the cross-function tail-jmp as a call, matching Ghidra.

(Analysis is correct: all three functions — is_even/is_odd/_start — are recovered as separate
functions. This is purely a decompiler emission/structuring bug.)
