/* A6 oracle corpus: a dense switch that compiles to a jump table (BRANCHIND through a
 * .rodata table), to validate the decompiler-driven switch analyzer. Each case does a
 * *distinct operation* (so gcc emits a real jump table, not a value-lookup table);
 * freestanding + volatile/noinline so it can't be constant-folded or inlined away. Kept
 * tiny so the golden stays reviewable. */

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

volatile int sel = 5;
volatile int arg = 11;

void _start(void) {
    int r = classify(sel, arg);
    register long rax asm("rax") = 60; /* exit */
    register long rdi asm("rdi") = r;
    asm volatile("syscall" : : "r"(rax), "r"(rdi) : "memory");
}
