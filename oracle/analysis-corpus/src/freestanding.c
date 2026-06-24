/* A0 oracle corpus: a freestanding x86-64 ELF (no libc/CRT) so the converged
 * Program state is just our own functions — small + reviewable. Exercises a
 * call edge (_start -> add, _start -> sum_to) and a loop (sum_to). */
static int add(int a, int b) { return a + b; }

static int sum_to(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += i;
    return s;
}

void _start(void) {
    int x = add(3, 4);
    int y = sum_to(x);
    register long rax asm("rax") = 60;   /* SYS_exit */
    register long rdi asm("rdi") = y;
    asm volatile("syscall" :: "r"(rax), "r"(rdi) : "memory");
    __builtin_unreachable();
}
