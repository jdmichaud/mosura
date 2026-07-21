/* Ground-truth corpus program (task #3): a switch + a few direct-called helpers — so the KNOWN
 * source gives an exact, Ghidra-independent oracle for function boundaries + the switch dispatch
 * location. At -O2 the switch becomes a jump table (BRANCHIND / computed jump) on x86-64 /
 * RISC-V / m68k; on AArch64 gcc emits a compare-branch tree for this 7-case switch (so its truth
 * carries no switch — the derivation records what the compiler actually produced, not a wish).
 *
 * Freestanding + noinline + volatile so nothing is inlined or constant-folded away, and every
 * helper is reachable by a DIRECT call from _start (100% recall on the stripped artifact). The
 * arithmetic/switch is arch-neutral; the process exit is the per-arch shim (shim.h). */
#include "shim.h"

__attribute__((noinline)) static int op_add(int a, int b) { return a + b; }
__attribute__((noinline)) static int op_mul(int a, int b) { return a * b; }

/* Dense switch -> jump table: each case a distinct op so gcc -O2 emits a real computed jump. */
__attribute__((noinline)) static int classify(int x, int y) {
    switch (x) {
        case 0: return y + 17;
        case 1: return y * 3;
        case 2: return y - 99;
        case 3: return y ^ 42;
        case 4: return y << 2;
        case 5: return y | 256;
        case 6: return y & 7;
        default: return -1;
    }
}

void _start(void) {
    volatile int s = 5, a = 11, b = 7;
    long r = classify(s, a) + op_add(a, b) + op_mul(a, b);
    sys_exit(r);
}
