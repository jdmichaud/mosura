# Decompiler bug (D3) → decompiler agent: switch case drops its `OR 0x100` return value

**Owner: decompiler track.** Surfaced by the ground-truth bug-hunt (task #3/A7). Classified
**MIS-PORT** (mosura diverges from Ghidra; Ghidra decompiles it correctly) via a same-function
comparison against Ghidra's own C — so this is a real decompiler port bug to fix, not a
beat-Ghidra limitation.

## Symptom

A `switch` case whose body is `return y | 256;` (`OR` with a constant that sets a high bit,
`0x100`) is decompiled as a **bare `return;`** — the value is DROPPED. A case with a small
constant (`y | 6`) is fine, so the trigger is the specific constant, not `OR` in general.

## Repro (self-contained)

Binary: `oracle/ground-truth/dispatch.gcc-x86-64` (committed), function `classify` @ **0x401030**.
Source: `oracle/ground-truth/src/dispatch.c`:

```c
static int classify(int x, int y) {
    switch (x) {
        case 0: return y + 17;
        case 1: return y * 3;
        case 2: return y - 99;
        case 3: return y ^ 42;
        case 4: return y << 2;
        case 5: return y | 256;   // <-- 0x100
        case 6: return y & 7;
        default: return -1;
    }
}
```

```
cargo run -q --example gt_recompile_probe -- oracle/ground-truth/dispatch.gcc-x86-64 401030
```

## mosura C (WRONG)

```c
uint4 FUN_00401030(xunknown4 param_1, uint4 param_2) {
  switch (param_1) {
    ...
    case 4: return param_2 * 4;
    case 5: return;              // <-- value `param_2 | 0x100` DROPPED
    case 6: return param_2 & 7;
    default: return -1;
  }
}
```

## Ghidra C (CORRECT — the reference)

Ghidra 12.0.3 (`analyzeHeadless` + `DecompInterface`, same stripped binary):

```c
uint FUN_00401030(undefined4 param_1, uint param_2) {
  switch(param_1) {
    ...
    case 4: return param_2 * 4;
    case 5: return param_2 | 0x100;   // <-- correct
    case 6: return param_2 & 7;
    default: return 0xffffffff;
  }
}
```

## Broader repro (A8): the drop is NOT operation-specific

A8's `fallthrough` program shows the same drop on a **plain** `return y`, so the trigger is the
switch-case block structure, not `OR`/`0x100`. `fallthrough.gcc-x86-64` @ **0x401000**, source
`case 2: r += y; break;` (with `r == 0` there, i.e. `return y`):

```
cargo run -q --example gt_recompile_probe -- oracle/ground-truth/fallthrough.gcc-x86-64 401000
```

mosura: `if (param_1 == 2) { return; }`  |  GHIDRA: `if (param_1 == 2) { return param_2; }`

So the earlier "OR with 0x100" narrowing was incidental — mosura drops a switch case's return
VALUE (here just `param_2`) to a bare `return;` in this block shape, regardless of the operation.
A `case` reached by fall-through vs a jump-table case differ in the surrounding block/phi graph;
the fix must recover the return value across that structure.

## Verdict: MIS-PORT

Ghidra emits the case's value (`return param_2 | 0x100;` / `return param_2;`); mosura emits a bare
`return;`, losing the result on the case path — a real divergence in the decompiler's structuring
/ return-value recovery for this shape. Fix so mosura matches Ghidra.

Secondary divergence (same function, lower severity): mosura prints the first switch param as
`xunknown4`, Ghidra prints `undefined4` — an unknown-type **naming** divergence (mosura should
render an unknown-typed varnode as Ghidra's `undefined<N>`, not `xunknown<N>`; see the func_0x /
emission handoff). The `-99` vs `+ -99` and `-1` vs `0xffffffff` differences are cosmetic
signedness/literal formatting, not bugs.
