/* Per-arch freestanding entry shim for the ground-truth corpus (task #3). The arithmetic /
 * switch / data helpers in each program are arch-NEUTRAL C; only the process-exit syscall is
 * arch-specific, isolated here so one source compiles across the gcc ELF matrix (x86-64,
 * AArch64, RISC-V, m68k). `_start` calls the helpers and passes the result to sys_exit so no
 * call is a tail-jump (a tail-jump target has no direct call site and flow analysis folds it
 * into the caller — see docs/ground-truth-corpus.md). Not used by the z80 (CP/M crt0) or
 * Watcom (wasm _cstart_ stub) columns, which have their own entry conventions. */
#ifndef GT_SHIM_H
#define GT_SHIM_H

static inline void sys_exit(long code) {
#if defined(__x86_64__)
    register long rax asm("rax") = 60, rdi asm("rdi") = code; /* Linux x86-64 exit */
    asm volatile("syscall" : : "r"(rax), "r"(rdi) : "memory");
#elif defined(__aarch64__)
    register long x8 asm("x8") = 93, x0 asm("x0") = code;     /* Linux aarch64 exit */
    asm volatile("svc 0" : : "r"(x8), "r"(x0) : "memory");
#elif defined(__riscv)
    register long a7 asm("a7") = 93, a0 asm("a0") = code;     /* Linux riscv exit */
    asm volatile("ecall" : : "r"(a7), "r"(a0) : "memory");
#elif defined(__m68k__)
    register long d0 asm("d0") = 1, d1 asm("d1") = code;      /* Linux m68k exit */
    asm volatile("trap #0" : : "r"(d0), "r"(d1) : "memory");
#else
    (void)code;
    for (;;) { }
#endif
}

#endif
