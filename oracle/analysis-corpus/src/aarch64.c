/* A0 oracle corpus: a freestanding AArch64 (ARM64) ELF (no libc/CRT) so the
 * converged Program state is just our own functions — small + reviewable. This is
 * mosura's first non-x86 corpus fixture; it mirrors freestanding.c so the
 * function-listing pipeline can be validated against Ghidra on AArch64. Exercises a
 * call chain (_start -> add, _start -> sum_to) and a loop (sum_to). The exit syscall
 * uses the AArch64 ABI (x8 = syscall number 93 = exit, x0 = arg, `svc #0`). */
static int add(int a, int b) { return a + b; }

static int sum_to(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += i;
    return s;
}

void _start(void) {
    int x = add(3, 4);
    int y = sum_to(x);
    register long x8 asm("x8") = 93;   /* SYS_exit (AArch64) */
    register long x0 asm("x0") = y;
    asm volatile("svc #0" :: "r"(x8), "r"(x0) : "memory");
    __builtin_unreachable();
}
