/* Ground-truth corpus (A7 bug-hunt): recursion — self-recursive + tree-recursive functions. The
 * seed is volatile so gcc cannot constant-fold the recursive calls away. */
#include "shim.h"
__attribute__((noinline)) static long fact(int n) { return n <= 1 ? 1 : n * fact(n - 1); }
__attribute__((noinline)) static long fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
void _start(void) {
    volatile int n = 6;
    long r = fact(n) + fib(n + 4);
    sys_exit(r);
}
