> **Superseded** by [`port-plan.md`](port-plan.md) (the faithful-port plan). Kept for history — this describes the approximation-era feature work.

# Float support — port plan

Recover floating-point code: the 6 float datatests (floatprint, floatcast, floatconv,
nan, mixfloatint, longdouble) score 0.14–0.38 today — the biggest low-score cluster.
The `FLOAT_*` p-code **operators** already render (`build_op` → `+`/`<`/`NAN()`…); what
remains is everything that makes those operators actually *appear* and read like
Ghidra's C. None of it is one feature — it is several, in rough dependency order.

## Why the operators alone don't move the score

Float values live in **XMM registers**, which mosura's integer-only parameter/return
machinery doesn't see — so mixfloatint decompiles to `void func(){return;}` and
floatcast/floatconv to nothing. The operators only matter once the float values are
recovered into the output.

## Reference architecture

- **XMM registers (x86-64 SLEIGH):** `XMM0 = (register, 0x1200)`, `XMM1 = 0x1240`, …,
  stride `0x40`. SysV passes float args in XMM0–7 and returns floats in XMM0.
- **Calling convention** (`fspec.cc` / the cspec) — the float vs integer parameter
  *interleaving*: source-order params alternate between the integer regs (RDI/RSI/…) and
  the XMM regs by type, so `func(float p1, int p2, float p3, …)` ⇒ p1=XMM0, p2=RDI,
  p3=XMM1, … The param *number* follows source order, not register order. Ghidra gets
  this from `ParamListStandard` scanning both register banks together.
- **Float types** (`type.cc` `TypeOp...Float`) — `float4`/`float8`/`float10`; the
  `FLOAT_INT2FLOAT`/`FLOAT2FLOAT`/`TRUNC` casts; float constant printing (a 4/8-byte bit
  pattern → `1.5`, `0.0`, `NAN`, `INFINITY` via `FloatFormat`).
- **PrintC** float idioms — the unordered-comparison fold: gcc emits
  `!((NAN(a)||NAN(b)||a<b) || (…==…))`, which Ghidra simplifies to `a < b` / `b < a`
  etc. (`RuleFloatSign`/the boolean condition rules).

## mosura's substrate

- `FLOAT_*` operators + `ABS`/`SQRT`/`NAN` intrinsics already in `build_op`.
- `x86_param` (cprint.rs) maps integer regs → `param_N`; `live_out` is `EAX`/`RAX`.
- The SLEIGH engine already lifts the SSE instructions to `FLOAT_*` + `CONCAT`/`SUBPIECE`
  p-code (verified — mixfloatint's ops are present).

## Milestones (each measurable on a subset)

- **F1 — XMM params + float return. ✅ DONE (params + 8-byte return).** `x86_param` maps
  XMM0–7 → params (numbering is cosmetic — comparator-erased), `live_out` adds XMM0 at
  8 bytes. floatcast 0.23→0.51, floatconv 0.27→0.36, mixfloatint 0.38→0.53, floatprint
  0.14→0.19; corpus 0.622→0.637. NOT done: the 4-byte float return (mixfloatint's body
  stays `void` — the result is XOR-zeroed at 4 bytes then computed at 8, and mosura's
  overlap-naive SSA traces the 4-byte read to the zero; XMM0 is kept 8-byte-only to
  avoid emitting that wrong value — needs the D3 overlap fix). The `(float8)` casts
  (F1.5) are still transparent.
- **F2 — float constants.** Print 4/8-byte bit patterns as float literals
  (`FloatFormat`: `0x3fc00000`→`1.5`, `0`→`0.0`, the NaN/inf encodings). Needed by
  floatprint and nan.
- **F3 — unordered-compare / NAN idiom fold.** A `simplify` rule turning
  `!((NAN(a)||NAN(b)||a<b)||(…==…))` → `a < b` etc. Lifts **nan** substantially.
- **F4 — globals. ✅ DONE (writes).** `block_stmts` emits an op whose output is an
  absolute `ram` address as `ram_X = value;` (DCE already keeps them — `ram` isn't
  heritaged). HUGE: floatprint 0.19→0.79, convert 0.51→1.00, displayformat 0.40→1.00;
  corpus 0.637→0.684, 20→25 ≥0.70 — global writes were being dropped across MANY
  datatests. (Global reads already render as `ram_X` = ID.)
- **F5 — SSE packing.** `CONCAT44`/`SUB16xx`/`ZEXT816` over 16-byte XMM values for
  floatcast/floatconv (the hardest — these model partial-register / packed access).

## Risks / order

- F1 is the keystone and the first win (mixfloatint). F2–F4 are independent and each
  helps 1–2 datatests. F5 (packed SSE) is the hardest and lowest-leverage — defer.
- The interleaved int/float param numbering needs care (it's prototype/cspec-driven);
  the all-float and all-int cases are easy, mixed cases need the two-bank scan.
- No divopt-style "out-correcting Ghidra" trap here — Ghidra recovers floats cleanly, so
  matching it is a straightforward gain.