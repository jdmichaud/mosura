# The struct-return arm (`struct-return={ghidra,witness}`, 2026-08-28)

**What gcc did.** On i386 a function returning a struct by value takes a HIDDEN POINTER to the
caller's return storage as its first parameter, writes the struct through it and returns the
pointer in EAX. A cdecl (global) callee also pops the pointer's slot — `ret $4`, the SysV rule
(`mk_cdecl.o`: `mov 4(%esp),%eax; mov 8(%esp),%edx; mov %edx,(%eax); mov 0xc(%esp),%edx; mov
%edx,4(%eax); ret $4`), and its caller reads the result back at `0x8(%esp)`/`0xc(%esp)` — offsets
that are right only because the callee popped. gcc's LOCAL convention (`static`, `-O2`, the
regparm case the `__cdecl/__regparm` merged model resolves) keeps the pointer in EAX (regparm
slot 0) and pops nothing: structval's `mk` is `mov %edx,(%eax); mov %ecx,4(%eax); ret`.

**What Ghidra prints** (decomp_dbg 12.0.3, `parse line` locking the return type; the traces are
in docs/ground-truth-findings.md, "Update (2026-08-28, structval)"):
- unlocked, both conventions: `void mk(xunknown4 *param_1, xunknown4 param_2, xunknown4 param_3)
  { *param_1 = param_2; param_1[1] = param_3; }` — exactly our TU. Its hidden-return mechanism is
  TYPE-driven (`ProtoModel::assignParameterStorage` inserts the hidden input only for a struct
  return type: fspec.cc:2420/2451, 1583–1610, 792–805; `ParameterPieces::hiddenretparm`
  fspec.hh:363), so with no type there is nothing to recover;
- locked `pt mk(int4,int4)`: `pt * mk(pt *rethidden,int4 a,int4 b) { rethidden->x = a;
  rethidden->y = b; return rethidden; }` — the pointer an explicit parameter, the output the
  POINTER type; a call renders `mk(&pStack_14,3,4);`. Neither compiles to `ret $4`.

So the fix is entirely beyond Ghidra — a witnessed RECOVERY plus an EMIT ARM, the layer the
frame-fill and struct-copy arms live in (fable-b's ruling, seq 526/528/530). The faithful
hidden-return substrate (the `<rule><datatype name="struct"/><hidden_return/></rule>` decode,
`TYPECLASS_HIDDENRET`, the `HIDDENRETPARM` flag at varnode.rs:46) is deferred until a typed
struct return exists to feed it.

**The fact** (`analysis::sret::sret_shape`, per function, in the whole-program prototype pass):
parameter slot 0 (the cdecl stack slot or the regparm EAX slot), pointer-sized, whose EVERY
reader — through COPY/CAST, INT_ADD by a constant, PTRADD by a constant index, PTRSUB by a
constant — is either the ADDRESS of a STORE (a field write at that displacement) or the RETURN's
value (the pointer returned unchanged); a LOAD through it, a call argument, a compare, a phi or
the pointer itself stored is not this shape. The RETURN has a second form: slot 0 IS the model's
return register and nothing writes it, so every RETURN carries no value (the decompiler recovers
`void`, Ghidra too) — the register holds the pointer at the return by construction. `size` = the
stores' extent, `fields` = the stores `(offset, size, stored type)`, non-overlapping. The pass
also records per CALLEE what every analyzed call says (`call_evidence`: the returned pointer
dead, the slot-0 argument the address of a stack local) — `Program::recovered_sret` and
`Program::sret_callers`, converged by the same fixpoint as the prototypes, copied to the caller's
`CallSpec::sret` and the callee's `Funcdata::sret_callers`; the function's own `RET n` is
`Funcdata::ret_pop` (`callee_cleanup`, the reader callers already used).

**The witness** (`recompile::recovery::struct_return`): the shape AND — cdecl side — the
function's own `ret <pointer size>` (gcc emits it on i386 only for a memory-returned struct), or
— register side — EVERY known call site's evidence. No call site and no pop is no witness. The
shape alone is byte-identical to `int *fill(int *p, ..) { ..; return p; }`; the caller-side
witness can still match such a function whose callers all drop the result.

**That false positive is value-preserving only on an ABI that returns the struct through the
CALLER'S MEMORY** — gcc's i386 memory return, the case this arm is enabled for, where
`local = fill(..)` performs the same stores into the same bytes and the rewrite changes form and
not values; it is NOT value-preserving on a register-return convention like Watcom's, where a
small struct comes back in EAX, so rewriting an out-parameter function moves the value out of the
caller's buffer into a register and the program changes behaviour. State the convention before
reusing this witness on another target.

### Measured on WAR2 (2026-08-31): the axis stays OFF for Watcom

A probe (the survey's prototype pass keeping the sret facts, the axis on the recovered pass only,
side directories, nothing landed) put numbers on it. **Nine of 3,024 functions carry the sret
SHAPE at all; ZERO carry the callee-pop witness** — `on_stack` is false on every one of them,
because Watcom's parameter slot 0 is a register, so that half of the witness is structurally inert
on this target. **One carries the callers witness and it is a false positive**: `FUN_00034918` is
`void f(short *out, short *in)` whose single caller ignores the result, and the arm rewrites it to
a `struct s2_x2` return — which, under Watcom's register return, is exactly the behaviour change
above. **Four of the nine shaped functions are EXACT today and one is SAME_SHAPE, so any widening
of the caller-side witness aims straight at EXACT rows.**

**Enabling the arm for WAR2 would take more than an axis flip: the survey's TU assembly has no
per-TU callee prototypes — every callee is declared `extern int func_0x...();` — so a
struct-returning callee cannot be called from another TU at all** (`FUN_0003495c`, the one caller,
renders `xStack_18 = func_0x00034918(&xStack_1c);` correctly and then fails to compile:
`Error! E1010: Type mismatch`; MISMATCH -> COMPILE_FAIL, the round's only flip, WGSS 0.5576 ->
0.5570). The ground-truth path has the mechanism the survey lacks — `make_tu` copies the callee's
`struct sN { .. };` preamble AND its real signature line — so WAR2 enablement needs that
mechanism plus a witness that can tell an out-parameter from a hidden return pointer on a
register-return ABI. Neither is built; the arm is a ground-truth-column tool.

**The arm** (`decompile/emit/arms/struct_return.rs`; the axis is `witness` in the gt ARMS plan
only — `EmitPlan::arms()` — never in `plain()` (the reference rendering every baseline measured)
nor in the survey's `canonical_arm()`: the WAR2 identity emit is the proof it cannot move):
- DEFINITION: `struct sN f(args minus slot 0) { struct sN __ret; __ret.f<off> = ..; return
  __ret; }`. The signature through the declarations family's FOURTH seam (`arms::signature`: the
  preamble `struct sN { .. };`, the return type, the dropped parameter — consulted once, at the
  port's assembly of `ret_ty`/`plist`); `__ret` through the port's `decls` service; every store
  through the hidden pointer at `ValueSite::Deref` (ahead of array-index); the returned pointer
  at `ValueSite::Var` (ahead of string-ops); a valueless RETURN at the new statement site
  `Site::Return` (`return __ret`).
- CALLER: a call whose callee is witnessed (`CallSpec::sret`), whose returned pointer is dead and
  whose slot-0 argument is a stack local's address prints `local = f(args minus slot 0)` at
  `ValueSite::OpRoot`; the local is declared ONCE as the struct at `declare_slot` (ahead of
  frame-fill) and every slot inside it renders as its field (`SlotName`/`SlotOffset`/
  `SlotAddress`, ahead of frame-fill). THE DECLINE RULE: when frame-fill's aggregate — its SETUP
  state — covers the local, this arm declares nothing and answers no slot inside it; the call then
  renders `*(struct sN *)<the port's address text> = f(..)`, a write within the one aggregate.
  The precedence is the explicit ordered list at `arms::render_value`/`declare_slot`.
- The struct: tag `s<size>` for the contiguous all-`int4` layout, else `s<size>_<sig>`
  (`s8_x4x4`, `s12_i4p4u2p2`) — a function of the LAYOUT alone (`Datatype::struct_tag`, shared
  by the declaration and the printer's spelling of `Datatype::Struct`, which this arm is the one
  producer of, at print time only); fields `f<off>` with the STORED type, gaps `uint1 pad<off>[n]`;
  one declaration per layout per function text; the gt TU builder copies a callee's declaration
  before its extern unless the caller's own text already carries it.

**Result** (2026-08-28): structval arms-32 FAIL(39/24) → PASS — `mk` renders
`struct s8_x4x4 __regparm3 FUN_08049000(xunknown4 param_2, xunknown4 param_3) { struct s8_x4x4
__ret; __ret.f0 = param_2; __ret.f4 = param_3; return __ret; }`, `_start` renders
`struct s8_x4x4 xStack_14; xStack_14 = func_0x08049000(3, 4); xVar1 = xStack_14.f4; ..`; the
plain-32 column is unchanged (13 PASS / 1 FAIL / 13 NOLINK), the gt-arms invariant holds with
structval its one plain-FAIL/arms-PASS line. Not in scope: `dot`'s struct-by-value ARGUMENTS
(gcc's IPA-SRA scalarized `p` into EAX/EDX and left `q` on the stack; our `int4 __regparm2
dot(p1, p2, p3, p4)` is right under both conventions), struct returns larger than the pointer
size on the 64-bit column (SysV returns ≤16-byte structs in registers: no shape, no movement).
