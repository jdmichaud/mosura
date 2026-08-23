/* Ground-truth corpus (era-style, 2026-08-23): bit manipulation — variable shifts, masks built
 * from widths, byte extraction/insertion, a popcount loop, and a signed/unsigned shift mix; the
 * sizes and casts the cast strategy has to get right. Freestanding + per-arch exit shim. */
#include "shim.h"

__attribute__((noinline)) static unsigned extract(unsigned word, int lo, int width) {
    unsigned mask = (width >= 32) ? 0xffffffffu : ((1u << width) - 1u);
    return (word >> lo) & mask;
}

__attribute__((noinline)) static unsigned insert(unsigned word, int lo, int width, unsigned v) {
    unsigned mask = ((1u << width) - 1u) << lo;
    return (word & ~mask) | ((v << lo) & mask);
}

__attribute__((noinline)) static int popcount(unsigned v) {
    int c = 0;
    while (v) { v &= v - 1; c++; }
    return c;
}

__attribute__((noinline)) static int sar_mix(int x, unsigned u, int s) {
    int a = x >> s;              /* arithmetic */
    unsigned b = u >> s;         /* logical */
    unsigned char lo = (unsigned char)x;
    short hi = (short)(x >> 8);
    return a + (int)b + lo - hi;
}

__attribute__((noinline)) static unsigned swap16(unsigned x) {
    return ((x & 0xffu) << 8) | ((x >> 8) & 0xffu);
}

void _start(void) {
    volatile unsigned w = 0x12345678u;
    volatile int s = 3;
    long r = extract(w, 4, 8);
    r = r * 4 + (insert(w, 8, 4, 0xfu) >> 8 & 0xf);
    r = r * 8 + popcount(w);
    r = r * 4 + (sar_mix(-1000, w, s) & 7);
    r = r * 16 + (swap16(w & 0xffffu) & 0xf);
    sys_exit(r);
}
