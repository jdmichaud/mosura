# Decompiler bug (D5) → decompiler agent: call to a known function rendered as `func_0x<addr>` + `extraout_RAX`

**Owner: decompiler track.** Surfaced by the ground-truth bug-hunt (task #3/A7). Classified
**MIS-PORT** (mosura diverges from Ghidra; Ghidra decompiles it correctly) via a same-function
comparison against Ghidra's own C. This is the single most common recompilation blocker in the
A7 catalog (deep call chains, self-recursion).

## Symptom

A direct call to a function that mosura's analysis HAS recovered is decompiled as:
1. `func_0x<addr>()` — a raw-address call stub, instead of Ghidra's `FUN_<addr>()` (the
   recovered function's name); and
2. `extraout_RAX` — a placeholder for "the value left in RAX", instead of assigning and using the
   call's return value.

Both stem from the call site not inheriting the callee's recovered identity + return prototype.
mosura's analysis recovers the callee as a function (the ground-truth recall gate is green), so
the decompiler is not consulting that when emitting the call.

## Repro (self-contained)

Binary: `oracle/ground-truth/deepchain.gcc-x86-64` (committed). Source
`oracle/ground-truth/src/deepchain.c`:

```c
static int l8(int x) { return x + 8; }
static int l7(int x) { return l8(x) * 2; }   // l7 @ 0x401010 calls l8 @ 0x401000
```

```
cargo run -q --example gt_recompile_probe -- oracle/ground-truth/deepchain.gcc-x86-64 401010 401000
```

## mosura C (WRONG)

```c
int4 FUN_00401010(void) {          // l7
  func_0x00401000();               // <-- raw-address stub; should be FUN_00401000()
  return extraout_RAX * 2;         // <-- return value not captured; should be the call's result
}
```

## Ghidra C (CORRECT — the reference)

Ghidra 12.0.3 (`analyzeHeadless` + `DecompInterface`, same stripped binary):

```c
int FUN_00401010(void) {           // l7
  int iVar1;
  iVar1 = FUN_00401000();          // named call, return value captured
  return iVar1 * 2;
}
int FUN_00401000(int param_1) {    // l8
  return param_1 + 8;
}
```

## Verdict: MIS-PORT

Ghidra renders the call to the recovered function 0x401000 as `iVar1 = FUN_00401000()` (name +
captured return); mosura renders `func_0x00401000(); ... extraout_RAX`. Fix so a call whose target
is a recovered function inherits its name (`FUN_<addr>`) and return prototype (capturing the
result), matching Ghidra. This also removes the `extraout_RAX` and `func_0x` recompilation
blockers catalogued across deepchain / recursion / tailcall.

Related emission divergence (same class): mosura prints unknown-typed varnodes as `xunknown<N>`
where Ghidra prints `undefined<N>` (seen in D3's switch param); an unknown-type naming fix belongs
with this handoff.
