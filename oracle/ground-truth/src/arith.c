/* Ground-truth corpus program (task #3): a small call graph of arithmetic helpers — a clean
 * exact oracle for function boundaries + the call graph, independent of Ghidra. Freestanding +
 * noinline so each function survives as its own boundary and is reachable by a direct call from
 * _start (100% recall on the stripped artifact). The arithmetic is arch-neutral; the process
 * exit is the per-arch shim (shim.h), so this one source compiles across the gcc ELF matrix.
 * See docs/ground-truth-corpus.md. */
#include "shim.h"

__attribute__((noinline)) static int square(int x) { return x * x; }
__attribute__((noinline)) static int cube(int x) { return square(x) * x; }

/* A counted loop that calls a helper each iteration (a non-trivial body + a nested call). */
__attribute__((noinline)) static long sum_to(int n) {
    long acc = 0;
    for (int i = 1; i <= n; i++) acc += square(i);
    return acc;
}

void _start(void) {
    volatile int n = 6;
    long r = sum_to(n) + cube(n);
    sys_exit(r);
}
