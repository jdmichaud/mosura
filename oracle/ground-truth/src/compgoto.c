/* Ground-truth corpus (A7 bug-hunt): computed goto (gcc labels-as-values) — a `goto *tab[i]`
 * dispatch, which gcc lowers to an indirect jump through a jump table (BRANCHIND). */
#include "shim.h"
__attribute__((noinline)) static int cgoto(int op, int a, int b) {
    static void *const tab[4] = { &&do_add, &&do_sub, &&do_mul, &&do_def };
    goto *tab[op & 3];
do_add: return a + b;
do_sub: return a - b;
do_mul: return a * b;
do_def: return 0;
}
void _start(void) {
    volatile int op = 2, a = 6, b = 7;
    long r = cgoto(op, a, b) + cgoto(op - 1, a, b);
    sys_exit(r);
}
