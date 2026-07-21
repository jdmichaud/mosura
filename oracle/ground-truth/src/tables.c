/* Ground-truth corpus program (task #3): dense + nested switches. The 12-case `dense` switch is
 * contiguous, so gcc -O2 emits a real jump table (computed jump) on EVERY arch in the matrix,
 * including AArch64 (`br`) where the sparser 7-case dispatch.c stays a branch tree. `nested`
 * layers switches to exercise multi-level control flow. Freestanding + per-arch exit shim. */
#include "shim.h"

/* Dense switch (0..11 contiguous) -> a jump table on every arch, including aarch64. */
__attribute__((noinline)) static int dense(int x, int y) {
    switch (x) {
        case 0:  return y + 1;
        case 1:  return y + 2;
        case 2:  return y * 3;
        case 3:  return y - 4;
        case 4:  return y ^ 5;
        case 5:  return y << 1;
        case 6:  return y | 6;
        case 7:  return y & 7;
        case 8:  return y + 8;
        case 9:  return y * 9;
        case 10: return y - 10;
        case 11: return y + 11;
        default: return -1;
    }
}

/* Nested switch: an outer dispatch whose arms contain inner switches, plus a call to `dense`. */
__attribute__((noinline)) static int nested(int a, int b, int c) {
    switch (a) {
        case 0:
            switch (b) { case 0: return c; case 1: return c+1; case 2: return c+2; case 3: return c+3; default: return 0; }
        case 1:
            switch (b) { case 0: return c*2; case 1: return c*3; case 2: return c*4; case 3: return c*5; default: return 1; }
        default:
            return dense(a, b + c);
    }
}

void _start(void) {
    volatile int a = 7, b = 2, c = 5;
    long r = nested(a, b, c) + dense(a, c);
    sys_exit(r);
}
