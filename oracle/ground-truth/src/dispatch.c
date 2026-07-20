/* Ground-truth corpus program (task #3): a dense switch that compiles to a jump table
 * (BRANCHIND / computed jump), plus a few direct-called helpers — so the KNOWN source gives an
 * exact, Ghidra-independent oracle for function boundaries + the switch dispatch location.
 *
 * Freestanding + noinline + volatile so nothing is inlined or constant-folded away, and every
 * helper is reachable by a DIRECT call from _start (100% recall on the stripped artifact). The
 * x86-64 `_start`/syscall entry is the arch shim; the portable helpers are what scale to other
 * arches (docs/ground-truth-corpus.md). Kept tiny so the derived truth file stays reviewable. */

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
    register long rax asm("rax") = 60;  /* exit */
    register long rdi asm("rdi") = r;
    asm volatile("syscall" : : "r"(rax), "r"(rdi) : "memory");
}
