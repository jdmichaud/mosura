/* REFERENCE SOURCE for regout.watcom-x86-32 `use_`.
 *
 * This is not documentation: it is the artifact the MVE is ABOUT. It was worked out from the
 * function's bytes and is VERIFIED AT BUILD TIME to recompile to them — verify-expected.py
 * compiles this file with the compiler and flags named below and compares the result against the
 * function's bytes in the committed binary. A reference that stops matching fails the build, so
 * it cannot drift into being a statement of intent.
 *
 * mosura is expected to REPRODUCE THIS SOURCE from the bytes. That is the whole test.
 *
 * WHAT IT PINS. The callee `bump_` takes a pointer in EBX and a count in EAX and returns the
 * ADVANCED POINTER IN EBX — a register the cspec's default model declares <unaffected>. Believing
 * the default here is wrong code on BOTH sides of one call, and that is what this reference
 * discriminates:
 *
 *   wrong   pxVar1 = pxRam08049070; func_0x08048106(param_2); *pxVar1 = param_1;
 *   right   pxVar1 = (xunknown1 *)func_0x08048106(xRam08049070, param_2); *pxVar1 = param_1;
 *
 * The wrong form discards the call's result and stores through the caller's STALE pre-call
 * pointer. Recovering it needs the callee's own body — its `modify` and `parm` lists — which is
 * why this is `caller-evidence prototypes` and why Ghidra, decompiling one function in isolation,
 * emits the wrong form. Measured on the subject's FUN_00074744/FUN_000748fd, the class this reproduces.
 *
 * BOTH arguments matter. EBX is both an argument and the return register, so a fix that recovers
 * the output half while dropping the input half still fails here — the call must carry
 * `xRam08049070` AND `param_2`, in that order, which is what `parm caller [ebx] [eax]` declares.
 *
 * The names are mosura's, deliberately — a decompiler recovers no symbols, so the reference is
 * written in the form a decompiler can produce: address-derived names, and the `x` prefix the
 * type system gives a byte of unknown signedness.
 *
 * original: mov ebx,[g_dst] ; call bump_ ; mov BYTE PTR [ebx],cl
 * func: use_
 * flags: -4r -fpi87 -s -onatx
 * decl: typedef unsigned char xunknown1;
 * decl: extern xunknown1 *xRam08049070;
 * decl: extern xunknown1 *func_0x08048106(xunknown1 *p, xunknown4 n);
 * decl: #pragma aux func_0x08048106 parm caller [ebx] [eax] value [ebx] modify [eax];
 */
void FUN_08048109(xunknown1 param_1, xunknown4 param_2)
{
  xunknown1 * pxVar1;

  pxVar1 = (xunknown1 *)func_0x08048106(xRam08049070, param_2);
  *pxVar1 = param_1;
  return;
}
