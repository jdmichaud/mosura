# Decompiler bug (D6) → decompiler agent: 64-bit signed division/modulo rendered as 128-bit (`int16`)

**Owner: decompiler track.** Surfaced by the ground-truth bug-hunt round 2 (task #3/A8). Classified
**MIS-PORT** (mosura diverges from Ghidra; Ghidra renders it as a plain 64-bit `a / b`) via a
same-function comparison against Ghidra's own C. A genuinely new class vs D3/D4/D5 — a
type-inference / width-narrowing divergence, not a value drop / structuring / naming issue.

## Symptom

A 64-bit signed `long / long` (and `long % long`) is decompiled with both operands cast to
`int16` (Ghidra's 16-BYTE = 128-bit int), i.e. a 128-bit division, instead of the 64-bit division
Ghidra recovers. The `int16` casts also block recompilation (no `int16` typedef / `__int128`).

Root: x86-64 lowers `long / long` to `cqo` (sign-extend RAX into the 128-bit RDX:RAX dividend) +
`idiv` (128 ÷ 64). Ghidra's type inference recognizes the sign-extension makes the high half
redundant and narrows the division back to 64-bit; mosura keeps the 128-bit intermediate.

## Repro (self-contained)

Binary: `oracle/ground-truth/arith64.gcc-x86-64` (committed), function `divmod64` @ **0x401010**.
Source `oracle/ground-truth/src/arith64.c`:

```c
static long divmod64(long a, long b) { return a / b + a % b; }
```

```
cargo run -q --example gt_recompile_probe -- oracle/ground-truth/arith64.gcc-x86-64 401010
```

## mosura C (over-widened)

```c
int8 FUN_00401010(uint8 param_1, int8 param_2) {
  return (int8)((int16)param_1 / (int16)param_2) + (int8)((int16)param_1 % (int16)param_2);
}
```

## Ghidra C (CORRECT — the reference)

Ghidra 12.0.3 (`analyzeHeadless` + `DecompInterface`, same stripped binary):

```c
long FUN_00401010(long param_1,long param_2) {
  return param_1 / param_2 + param_1 % param_2;
}
```

## Verdict: MIS-PORT

Ghidra narrows the `cqo; idiv` (128÷64) to a 64-bit `param_1 / param_2 + param_1 % param_2`;
mosura keeps the 128-bit `int16` division. Semantically equivalent for in-range values, but a real
structural + type-width divergence (mosura does not narrow the sign-extended dividend that Ghidra
does), and the `int16` casts block recompilation. Fix so mosura's division/modulo type inference
matches Ghidra.

(Scope: only signed 64-bit `/` and `%` over-widen; `long * long` = `param_1 * param_2` and the
64-bit rotate decompile correctly — same arith64 program, functions 0x401000 / 0x401020.)
