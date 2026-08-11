/* Ground-truth repro: a TWO-argument __watcall call where mosura recovers only the first.
 *
 * Measured on WAR2 FUN_00011920, the largest byte-delta bucket's representative:
 *
 *     a1 6c120800    mov eax,[g]          <- argument 1
 *     31 d2          xor edx,edx          <- argument 2 (EDX is watcall's SECOND arg register)
 *     e8 ......      call FUN_00059344
 *     89 15 6c120800 mov [g],edx          <- and EDX survives the call
 *
 * mosura emits `func_0x00059344(xRam0008126c);` — one argument. The `xor edx,edx` reads as scratch
 * setup rather than as argument 2, so the call is short an argument and the recompiled code cannot
 * match however good the rest is.
 *
 * Ruled out as the cause before writing this, by A/B under BOTH real compilers (10.0a under dosemu
 * and the 10.0 beta under wine, ~/.wine/drive_c/WBETA): the two emit byte-identical code here, so
 * this is not the compiler-version excursion documented in docs/watcom-10.0-beta-codegen.md.
 *
 * Properties this program depends on — do not "simplify" them away:
 *   1. TWO integer arguments, so the second lands in EDX. With one argument the EAX-only path
 *      (which already works) is what gets tested.
 *   2. the second argument is a CONSTANT, matching the WAR2 shape where it is materialised by
 *      `xor edx,edx` immediately before the call — the form most easily mistaken for scratch.
 *   3. the callee READS both, so both are genuinely arguments and not merely live registers.
 *   4. `add2` is in the .asm, not here: wcc386 inlines a same-TU C definition and no call survives.
 */
const char twoarg_banner[] =
    "WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. "
    "All rights reserved.";

int g_val;

/* Defined in twoarg_cstart.asm: `add eax,edx ; ret` — reads BOTH argument registers. */
extern int add2(int a, int b);
#pragma aux add2 parm caller [eax] [edx] value [eax] modify [eax];

void feed(void) {
    g_val = add2(g_val, 0);
}

/* Same call shape, but the callee BRANCHES — so the straight-line scan claims nothing and the
 * call's parameters must come from the convention. This is the WAR2 shape. */
extern int add2b(int a, int b);
#pragma aux add2b parm caller [eax] [edx] value [eax] modify [eax];

void feedb(void) {
    g_val = add2b(g_val, 0);
}

/* THE WAR2 SHAPE. The second argument is ALSO USED AFTER the call — FUN_00011920 does
 * `xor edx,edx ; call ; mov [g],edx`, storing the very value it passed. A value that is both an
 * argument and a later use is not "used solely to feed this call", which is the test that decides
 * whether a trial stays active. */
int g_val2;

void feedc(void) {
    int z = 0;
    add2b(g_val, z);
    g_val2 = z;
}

int main(void) {
    g_val = (int)twoarg_banner[0];
    feed();
    feedb();
    feedc();
    return g_val;
}
