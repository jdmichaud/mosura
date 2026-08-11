/* Ground-truth repro: a callee that RETURNS A NEW VALUE in a register the model calls preserved.
 *
 * mosura's x86-32 watcom cspec lists EBX <unaffected>, so a value returned in EBX is invisible:
 * the call's result is discarded and the caller keeps using its own pre-call value. Measured on
 * WAR2 — FUN_00074744 computes `ebx += eax*[g] + [h]` and returns it; its caller FUN_000748fd
 * does `mov BYTE PTR [ebx],al` with that pointer, and mosura emits
 *
 *     func_0x00074744(iStack00000008);      // result discarded
 *     *pxStack00000004 = xStack00000014;    // writes through the caller's STALE pointer
 *
 * so the call's result never reaches the store. Wrong code on both sides of one call.
 *
 * Properties this program depends on — do not "simplify" them away:
 *   1. `bump` lives in the .asm, NOT here. A caller/callee pair in one translation unit does not
 *      work: wcc386 INLINES the callee and no call survives (measured — the caller came back as
 *      `mov ecx,[g_dst]; mov [ecx+edx],al` with the callee gone). Assembly is also the faithful
 *      shape: the WAR2 functions in this class ARE hand-written asm with custom conventions,
 *      which is why no #pragma aux C source reproduces FUN_00074744's `mul`.
 *   2. the returned register is EBX — one the cspec declares <unaffected>. With a killedbycall
 *      register (EAX) the result is already visible and the test proves nothing.
 *   3. the caller CONSUMES the result (`*p = v`) rather than merely holding it, so a discarded
 *      return shows up as a store through the wrong pointer.
 *   4. `g_dst` is a global, so the caller's pre-call pointer has a distinct provenance from the
 *      returned one — a discarded result is then visible as the WRONG value, not just a missing
 *      assignment.
 */
const char regout_banner[] =
    "WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. "
    "All rights reserved.";

unsigned char *g_dst;
int regout_hits;

/* Defined in regout_cstart.asm: `add ebx,eax ; ret` — takes the pointer in EBX, the count in
 * EAX, and RETURNS the advanced pointer in EBX. */
extern unsigned char *bump(unsigned char *p, unsigned n);
#pragma aux bump parm caller [ebx] [eax] value [ebx] modify [eax];

void use(unsigned char v, unsigned n) {
    unsigned char *p = g_dst;
    p = bump(p, n);   /* the callee hands back a NEW pointer in EBX */
    *p = v;           /* which must be the one stored through */
}

int main(void) {
    static unsigned char buf[8];
    g_dst = buf;
    use((unsigned char)regout_banner[0], 3);
    regout_hits = regout_hits + 1;
    return regout_hits + (int)buf[3];
}
