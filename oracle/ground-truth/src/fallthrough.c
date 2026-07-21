/* A8 bug-hunt: switch with case fall-through (missing break) — the structurer must chain cases. */
#include "shim.h"
__attribute__((noinline)) static int ft(int x, int y) {
    int r = 0;
    switch (x) {
        case 0: r += 1;      /* falls through */
        case 1: r += 2;      /* falls through */
        case 2: r += y; break;
        case 3: r += 100;    /* falls through */
        default: r += 1000;
    }
    return r;
}
void _start(void) {
    volatile int x = 0, y = 7;
    long r = ft(x, y) + ft(x + 3, y);
    sys_exit(r);
}
