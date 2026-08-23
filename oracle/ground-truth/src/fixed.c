/* Ground-truth corpus (era-style, 2026-08-23): 16.16 fixed-point arithmetic — signed and
 * unsigned multiplies, divides and remainders (the cdq/idiv vs xor/div forms), a linear
 * interpolation, and a distance approximation. Freestanding + per-arch exit shim. */
#include "shim.h"

typedef int fix;
#define FIX(i) ((fix)((i) << 16))

__attribute__((noinline)) static fix fmul(fix a, fix b) { return (fix)(((long)a * b) >> 16); }
__attribute__((noinline)) static fix fdiv(fix a, fix b) { return (fix)(((long)a << 16) / b); }

__attribute__((noinline)) static unsigned udivrem(unsigned a, unsigned b, unsigned *rem) {
    *rem = a % b;
    return a / b;
}

__attribute__((noinline)) static int sdivrem(int a, int b, int *rem) {
    *rem = a % b;
    return a / b;
}

__attribute__((noinline)) static fix lerp(fix a, fix b, fix t) {
    return a + fmul(b - a, t);
}

__attribute__((noinline)) static int approx_dist(int dx, int dy) {
    if (dx < 0) dx = -dx;
    if (dy < 0) dy = -dy;
    int mx = dx > dy ? dx : dy, mn = dx > dy ? dy : dx;
    return mx + (mn >> 1) - (mn >> 3);
}

void _start(void) {
    volatile int seed = 3;
    unsigned ur = 0; int sr = 0;
    long r = fmul(FIX(3), FIX(seed)) >> 16;
    r = r * 16 + (fdiv(FIX(10), FIX(4)) >> 14);
    r = r * 8 + udivrem(1000u + seed, 7u, &ur) % 8;
    r = r * 8 + ur;
    r = r * 8 + (sdivrem(-1000 - seed, 7, &sr) & 7);
    r = r * 8 + (sr & 7);
    r = r * 4 + (lerp(FIX(2), FIX(10), FIX(1) / 4) >> 16);
    r = r * 2 + (approx_dist(-30, 40) & 1);
    sys_exit(r);
}
