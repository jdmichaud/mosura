/* REFERENCE SOURCE for regmodify.watcom-x86-32 `hold_`.
 *
 * Verified at build time by verify-expected.py to recompile to this function's bytes, so mosura
 * reproducing this text IS the byte-exact property, with no compiler in the test chain.
 *
 * WHAT IT PINS. The value is computed BEFORE the call and used AFTER it:
 *
 *   push edx ; lea edx,[eax+7] ; call keep_ ; mov [g_other],eax ; mov [g_slot],edx ; pop edx ; ret
 *
 * which is legal only because `keep` is declared `modify [eax]` — everything but EAX survives, so
 * the compiler can park `seed+7` in EDX across the call. Two things therefore have to be right and
 * this reference discriminates both:
 *
 *   1. the CALLEE CONTRACT. With the default __watcall contract (eax/ebx/ecx/edx all destroyed) no
 *      register survives, so the compiler must spill — different bytes whatever the logic says.
 *   2. the STATEMENT ORDER. Sinking the `+ 7` past the call makes `seed` the value held across it
 *      instead of `seed + 7`, so the add lands after the call rather than before.
 *
 * The names are mosura's, deliberately — a decompiler recovers no symbols, so the reference is
 * written in the form a decompiler can produce.
 *
 * original: 52 8d5007 e8f5ffffff a370900408 89156c900408 5a c3   (22 bytes)
 * func: hold_
 * flags: -4r -fpi87 -s -onatx
 * decl: extern int xRam08049070;
 * decl: extern int iRam0804906c;
 * decl: extern int func_0x08048106(int v);
 * decl: #pragma aux func_0x08048106 parm caller [eax] value [eax] modify [eax];
 */
void FUN_08048108(int4 param_1)
{
  int4 iVar1;

  iVar1 = param_1 + 7;
  xRam08049070 = func_0x08048106(param_1);
  iRam0804906c = iVar1;
  return;
}
