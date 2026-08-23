/* Ground-truth corpus (era-style, 2026-08-23): compare ladders — mixed signed/unsigned
 * comparisons, short-circuit conditions, a bounded search loop with two exits, and a
 * saturating mix of the results. The kind of branchy integer code that fills WAR2's 20-99-insn
 * band. Freestanding + per-arch exit shim. */
#include "shim.h"

__attribute__((noinline)) static int classify(int x, unsigned y, int z) {
    if (x < 0) {
        if (y > 1000u) return 1;
        if (z == x) return 2;
        return 3;
    }
    if (x < 10 && y < 10u) return 4;
    if (x >= 10 && (y >= 10u || z < -5)) return 5;
    if ((unsigned)x == y) return 6;
    if (x > z && y < (unsigned)z) return 7;
    return 8;
}

__attribute__((noinline)) static int search(const int *tab, int n, int key, int *pos) {
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        if (tab[mid] == key) { *pos = mid; return 1; }
        if (tab[mid] < key) lo = mid + 1; else hi = mid - 1;
    }
    *pos = lo;
    return 0;
}

__attribute__((noinline)) static int clamp_mix(int a, int b, int c) {
    int m = a > b ? a : b;
    if (c > m) m = c;
    int s = a + b + c;
    if (s > 255) s = 255;
    else if (s < -255) s = -255;
    unsigned u = (unsigned)s;
    if (u > 200u) u = 200u;
    return (int)u + (m & 15);
}

static const int table[9] = { -9, -3, 0, 4, 7, 11, 20, 33, 64 };

void _start(void) {
    volatile int seed = 5;
    int pos = 0;
    long r = classify(-seed, 2000u, 1) + classify(seed, 3u, 0) * 10 + classify(12, 4u, -9) * 100;
    r = r * 4 + classify(5, 5u, 1) + classify(30, 7u, 2) * 16;
    r = r * 8 + search(table, 9, 11, &pos) * 4 + pos;
    r = r * 8 + search(table, 9, 12, &pos) * 4 + pos;
    r = r * 4 + clamp_mix(seed, 100, 200) + clamp_mix(-300, 1, 2);
    sys_exit(r);
}
