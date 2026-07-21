/* Ground-truth corpus program (task #3): function-pointer indirect dispatch. `apply` performs a
 * genuine indirect call THROUGH a const function-pointer table. Each target is ALSO called
 * directly from _start, so the targets stay call-reachable (recoverable as functions) while the
 * indirect dispatch exercises the analysis: it must not invent spurious functions from the
 * pointer table, and must recover the direct-call graph. (Statically RESOLVING the pointer table
 * to its targets is a separate capability — here targets are validated via their direct-call
 * reachability, and the const table lives in .rodata as data, not code.) Freestanding + shim. */
#include "shim.h"

__attribute__((noinline)) static int fn_add(int a, int b) { return a + b; }
__attribute__((noinline)) static int fn_sub(int a, int b) { return a - b; }
__attribute__((noinline)) static int fn_mul(int a, int b) { return a * b; }
__attribute__((noinline)) static int fn_xor(int a, int b) { return a ^ b; }

typedef int (*binop)(int, int);
static binop const table[4] = { fn_add, fn_sub, fn_mul, fn_xor };

__attribute__((noinline)) static int apply(int which, int a, int b) {
    binop f = table[which & 3];
    int r = f(a, b);   /* indirect call through the table */
    return r + 1;      /* +1 defeats the tail-call so it is a real indirect CALL site */
}

void _start(void) {
    volatile int w = 2, a = 11, b = 7;
    /* direct calls keep every target call-reachable (100% recall on the stripped artifact) */
    long direct = fn_add(a, b) + fn_sub(a, b) + fn_mul(a, b) + fn_xor(a, b);
    long r = direct + apply(w, a, b) + apply(w + 1, a, b);
    sys_exit(r);
}
