/* Ground-truth corpus (A7 bug-hunt): a SPARSE switch (widely-spaced cases -> compare chain or a
 * range-check tree, not a dense jump table) — the jump-vs-if lowering. */
#include "shim.h"
__attribute__((noinline)) static int classify(int x) {
    switch (x) {
        case 1:     return 10;
        case 100:   return 20;
        case 1000:  return 30;
        case 50000: return 40;
        default:    return -1;
    }
}
void _start(void) {
    volatile int v = 1000;
    long r = classify(v) + classify(v + 1);
    sys_exit(r);
}
