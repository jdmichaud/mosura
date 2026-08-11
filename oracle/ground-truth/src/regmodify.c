/* Ground-truth repro: a caller HOLDS A VALUE IN A REGISTER ACROSS A CALL, because the callee's
 * `#pragma aux ... modify` list says that register survives.
 *
 * This is the class behind the WAR2 survey's biggest byte-delta bucket. Measured on FUN_00011920:
 *
 *     original   mov eax,[g] ; xor edx,edx ; call FUN_00059344 ; mov [g],edx
 *     ours       func_0x00059344(g); g = 0;
 *
 * The original computes the 0 into EDX BEFORE the call and stores it AFTER — which is only legal
 * because that callee spares EDX. Our emitted C declared every callee as a bare
 * `extern int func_0xNNN()`, so wcc386 applied the DEFAULT __watcall contract (eax/ebx/ecx/edx all
 * destroyed) and had to rematerialise the constant after the call. No source we emit can compile
 * to the original bytes while the callee is declared with the wrong contract, however correct the
 * logic is — so the contract is part of what must be recovered from the binary.
 *
 * The error runs BOTH ways, which is why the modify list has to be measured rather than assumed:
 * a callee that clobbers ESI/EDI/EBP is assumed BY DEFAULT to preserve them, so a caller may keep
 * a live value in one across a call the original could not.
 *
 * Properties this program depends on — do not "simplify" them away:
 *   1. `keep` must clobber ONLY EAX. That is what makes the `modify [eax]` declaration true and
 *      lets the caller keep its value in EDX. A callee that touches EDX proves nothing.
 *   2. the caller must have a value LIVE ACROSS the call — computed before, used after — so the
 *      wrong contract is forced to spill or rematerialise it and the byte count changes.
 *   3. the held value is a CONSTANT, so a wrong contract rematerialises it (visible as different
 *      bytes) rather than merely moving a spill around.
 *   4. `keep` is in the same TU but must NOT inline: it is called twice and via a pragma, which
 *      wcc386 leaves as a real call.
 */
const char regmodify_banner[] =
    "WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. "
    "All rights reserved.";

int g_slot;
int g_other;

/* Clobbers EAX only — every other register survives the call, which is the whole point. */
extern int keep(int v);
#pragma aux keep parm caller [eax] value [eax] modify [eax];

int keep(int v) { return v + 1; }

/* `n` is computed before the call and stored after it. With `modify [eax]` the compiler may keep
 * it in EDX across the call; with the default contract it must spill or recompute. */
void hold(int seed) {
    int n = seed + 7;
    g_other = keep(seed);
    g_slot = n;
}

int main(void) {
    g_slot = 0;
    hold((int)regmodify_banner[0]);
    return g_slot + g_other;
}
