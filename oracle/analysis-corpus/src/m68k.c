/* A0 oracle corpus: a freestanding Motorola 68000 (68040 model) ELF (no libc/CRT)
 * so the converged Program state is just our own functions — small + reviewable.
 * mosura's first BIG-ENDIAN (and first 32-bit) corpus fixture; it mirrors
 * freestanding.c / aarch64.c so the function-listing pipeline can be validated
 * against Ghidra on 68000:BE:32:default. Exercises a call chain (_start -> add,
 * _start -> sum_to) and a loop (sum_to). The exit syscall uses the m68k Linux ABI
 * (d0 = syscall number 1 = exit, d1 = arg, `trap #0`). */
static int add(int a, int b) { return a + b; }

static int sum_to(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += i;
    return s;
}

void _start(void) {
    int x = add(3, 4);
    int y = sum_to(x);
    register long d0 asm("d0") = 1;    /* SYS_exit (m68k) */
    register long d1 asm("d1") = y;
    asm volatile("trap #0" :: "r"(d0), "r"(d1) : "memory");
    __builtin_unreachable();
}
