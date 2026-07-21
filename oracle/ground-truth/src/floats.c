/* Ground-truth corpus (A7 bug-hunt): float/double arithmetic (hardware-float arches). Seeds are
 * volatile so gcc cannot constant-fold the FP results at compile time. */
#include "shim.h"
__attribute__((noinline)) static double favg(double a, double b) { return (a + b) / 2.0; }
__attribute__((noinline)) static int fscale(float x) { return (int)(x * 3.5f + 1.0f); }
__attribute__((noinline)) static double fpoly(double x) { return x * x * 0.5 - x + 2.0; }
void _start(void) {
    volatile double a = 3.0, b = 5.0, x = 4.0;
    volatile float f = 2.0f;
    long r = (long)favg(a, b) + fscale(f) + (long)fpoly(x);
    sys_exit(r);
}
