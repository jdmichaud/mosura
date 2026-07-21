/* Ground-truth corpus (A7 bug-hunt): a deep straight-line call chain l1->l2->...->l8. The seed is
 * volatile so the whole chain isn't constant-folded into a literal. */
#include "shim.h"
__attribute__((noinline)) static int l8(int x) { return x + 8; }
__attribute__((noinline)) static int l7(int x) { return l8(x) * 2; }
__attribute__((noinline)) static int l6(int x) { return l7(x) - 3; }
__attribute__((noinline)) static int l5(int x) { return l6(x) + 5; }
__attribute__((noinline)) static int l4(int x) { return l5(x) ^ 1; }
__attribute__((noinline)) static int l3(int x) { return l4(x) + 7; }
__attribute__((noinline)) static int l2(int x) { return l3(x) * 3; }
__attribute__((noinline)) static int l1(int x) { return l2(x) - 9; }
void _start(void) {
    volatile int n = 4;
    long r = l1(n);
    sys_exit(r);
}
