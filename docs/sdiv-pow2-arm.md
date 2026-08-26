# The `sdiv-pow2` emitter arm — Watcom's SBB template for a signed division by a power of two

## The template and its lifted shape

Watcom 10.0a compiles `x / 2^n` (signed `int`) as

```
MOV EDX,EAX ; SAR EDX,0x1f ; SHL EDX,n ; SBB EAX,EDX ; SAR EAX,n
```

= `(x + 2^n - 1) >> n` for a negative `x`, `x >> n` otherwise (the `SHL`'s carry supplies the
`- 1`). Ghidra lifts it faithfully and simplifies the `SHL`/`SBB` into an add/mult/zext chain
(fixture `oracle/fixtures/x86_sdiv_pow2_sbb.xml`, the template extracted from WAR2 0x23108):

```
s  = INT_SRIGHT(x, 31)
r  = INT_SRIGHT( INT_SUB( INT_ADD(x, INT_MULT(s, -2^n)),
                          INT_ZEXT(INT_SLESS(INT_LEFT(s, n-1), 0)) ), n )
```

which mosura prints verbatim: `(x + (x >> 0x1f) * -0x20 - (x >> 0x1f << 4 < 0)) >> 5`. No Ghidra
rule rewrites this shape (`RuleSignNearMult` matches the `AND`-rounding form, `RuleSignDiv2` only
n = 1, `RuleDivOpt` the magic-multiply form, `RuleSignForm`/`RuleSignForm2`/`RuleSignShift` other
sign-shift uses). **Oracle (Ghidra 12.0.3 on the fixture, 2026-08-27):**
`return (int4)((param_2 + (param_2 >> 0x1f) * -0x20) - (uint4)((param_2 >> 0x1f) << 4 < 0)) >> 5;`
— the same arithmetic, so there is nothing to port: the inverse of the template is an emitter
arm, like the string-ops arms.

## Corpus (w8 tree, by bytes: the `SBB EAX,EDX` signature in the original rows)

22 game functions, 43 sites (fable-b's W3 ceiling): 0x1cb28 0x1cc08 ×4 0x22744 ×3 0x228c8 ×4
0x23108 ×2 0x24278 ×2 0x26e78 0x26ef0 0x27298 ×2 0x28008 ×2 0x28594 ×2 0x2d520 ×3 0x2fcfc 0x2ff68
0x31564 ×2 0x34790 ×2 0x36954 0x3eaa4 0x3fa04 0x41d2c 0x42750 ×2 0x4f5e0 ×4. Two spellings in the
C:

1. **the exact shape** (14 sites, 7 TUs: 0x23108 0x24278 0x31564 0x34790 0x3eaa4 0x4f5e0 + library
   0x69fb0; n = 5 ×8, n = 4 ×6; 0x27298's n = 3 on a `>> 0x10` dividend prints `* -8` in decimal);
2. **the folded shape**: `(int4)uRam0008226a[1] >> 4` (0x228c8, 0x22744, 0x1cc08's `>> 2`) — the
   dividend is a zero-extended `uint2`/`uint1`, so the sign shift is provably 0 and the correction
   folded away; the C is value-correct (`x >> n` = `x / 2^n` for a non-negative `x`) but recompiles
   to a lone `SAR`, two instructions short of the original.

Round-trip POC (fable-b, srcform10 at 0x23108): `/ 0x20` ×2 → the template reproduced exactly.

## Design

A witnessed emitter arm, the string-ops shape: report the candidate `INT_SRIGHT` ops (shape 1:
the whole chain over one `x`; shape 2: a bare `INT_SRIGHT(x, n)` whose pc is a `SAR`), witness on
the original bytes — the `NormInsn` at the shift's pc is `SAR r32,imm8` and the instruction before
it is `SBB` (`1B /r`) — and render the recovered sites as `x / 2^n` with `x` through the signed
cast rule (the `(int4)` the arithmetic shift already carries). Value-identical in both shapes
(shape 2 under the fold's own proof). Default arm = the reference rendering.

## What the 22-function census taught (2026-08-27, `war2_survey --only`)

First build: 41 of 43 sites rendered, but four rules were missing, each named by a site:

1. **A failed chain must never fall back to the bare shape.** 0x4f5e0 printed
   `(iVar3 + iVar4 * -0x10 - (iVar4 << 3 < 0)) / 0x10` — the correction applied twice, wrong
   code. A shift whose input is an `INT_SUB` with a `ZEXT` operand is the chain or nothing.
2. **The sign shift may read the value the dividend was arithmetically pre-shifted from.**
   0x27298 / 0x28594: `((v >> 0x10) + s * -8 - (s << 2 < 0)) >> 3` with `s = v >> 0x1f` — the same
   sign; accepted as `(v >> 0x10) / 8`.
3. **The dividend is always signed in the source.** `uVar2 / 2`, `((uint2 *)0x8f670)[i] / 2`
   (0x28008, 0x2ff68, 0x41d2c): an operand Ghidra typed unsigned would compile to `SHR`; the arm
   prints the `(int4)` cast on any non-`int` dividend (Ghidra's own cast for a signed shift).
4. **The folded bare shift may be a logical one.** 0x2d520: `(uint1)x * 0x4d >> 8` — once the
   dividend is proven non-negative Ghidra's shift is `INT_RIGHT`; the witness (`SBB` + `SAR 8`)
   still says the source divided, so the bare shape accepts `INT_RIGHT` too (the exact chain
   roots only at `INT_SRIGHT`).

Second build (all four rules): **43 of 43 sites render** (`--only` over the 22 functions; 0x28008's
two `SBB` + `SAR 2` sites as `(int4)uVar4 / 4` / `(int4)uRam00080322 / 4`, 0x4f5e0's four as
`iVar3 / 0x10` off its `>> 0x10` pre-shift, 0x27298's as `(v >> 0x10) / 8`); no residual chain
fragment. The `uVar / 2` forms beside them predate the arm (Ghidra's own unsigned divisions).

## Measured (round w3 vs w2b, 2026-08-27)

WGSS 0.5450 -> 0.5479 (+348.4 insn-sim, +0.00284); EXACT 840 -> 841 (0x36954 MISMATCH -> EXACT); 0 lost, SAME_SHAPE 78 held, no COMPILE_FAIL change; 25 TUs moved, 25 up / 0 down: 21 of the 22 game functions (0x2d520 flat: its folded `(char)(x * 0x4d >> 8)` shift did not render, 3 sites left) plus 4 library-zone SBB sites (0x65a68 0x69fb0 0x6ac50 0x6ef5a); largest 0x36954 +0.600, 0x24278 +0.433 (0.192 -> 0.625), 0x28008 +0.333, 0x2fcfc +0.280, 0x3eaa4 +0.242, 0x3fa04 +0.226; game memcpy/memset/memcmp unchanged.
