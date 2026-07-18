/* A0 oracle corpus: a freestanding RISC-V (RV64GC) ELF (no libc/CRT) so the
 * converged Program state is just our own functions — small + reviewable. Mirrors
 * freestanding.c / aarch64.c so the function-listing pipeline can be validated
 * against Ghidra on RISCV:LE:64:default. Exercises a call chain (_start -> add,
 * _start -> sum_to) and a loop (sum_to). The exit syscall uses the RISC-V Linux
 * ABI (a7 = syscall number 93 = exit, a0 = arg, `ecall`). */
static int add(int a, int b) { return a + b; }

static int sum_to(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += i;
    return s;
}

void _start(void) {
    int x = add(3, 4);
    int y = sum_to(x);
    register long a7 asm("a7") = 93;   /* SYS_exit (RISC-V) */
    register long a0 asm("a0") = y;
    asm volatile("ecall" :: "r"(a7), "r"(a0) : "memory");
    __builtin_unreachable();
}
