/* A8 bug-hunt: irreducible control flow — a jump INTO the middle of a two-block loop gives the
 * loop two entries (an irreducible CFG the structurer must handle, e.g. via node splitting). */
#include "shim.h"
__attribute__((noinline)) static int sm(int start, int n) {
    int acc = 0, i = 0;
    if (start) goto B;
A:  acc += 1; if (++i >= n) goto E; goto B;
B:  acc += 2; if (++i >= n) goto E; goto A;
E:  return acc;
}
void _start(void) {
    volatile int s = 1, n = 9;
    long r = sm(s, n) + sm(0, n);
    sys_exit(r);
}
