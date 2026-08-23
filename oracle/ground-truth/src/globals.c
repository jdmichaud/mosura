/* Ground-truth corpus (era-style, 2026-08-23): a global game state driven by an event switch —
 * counters, a small score table and a phase variable in .bss/.data, read and written by
 * functions that never take them as parameters (address-tied globals across calls, the
 * INDIRECT/guard machinery). Freestanding + per-arch exit shim. */
#include "shim.h"

static int gold = 100;
static int lumber = 50;
static int phase;
static int scores[4];
static unsigned char log_kinds[16];
static int log_n;

__attribute__((noinline)) static void note(int kind) {
    if (log_n < 16) log_kinds[log_n++] = (unsigned char)kind;
}

__attribute__((noinline)) static int event(int kind, int val) {
    note(kind);
    switch (kind) {
        case 0: gold += val; break;
        case 1: lumber += val; break;
        case 2:
            if (gold >= val) { gold -= val; scores[phase & 3] += val / 10; }
            else return -1;
            break;
        case 3:
            if (lumber >= val && gold >= val * 2) { lumber -= val; gold -= val * 2; scores[phase & 3] += val; }
            else return -2;
            break;
        case 4:
            phase++;
            if (phase > 3) phase = 0;
            break;
        default:
            return -3;
    }
    return gold + lumber;
}

__attribute__((noinline)) static int tally(void) {
    int best = 0, t = 0;
    for (int i = 0; i < 4; i++) {
        t += scores[i];
        if (scores[i] > scores[best]) best = i;
    }
    return best * 1000 + t;
}

__attribute__((noinline)) static int replay(void) {
    int odd = 0;
    for (int i = 0; i < log_n; i++)
        if (log_kinds[i] & 1) odd++;
    return odd;
}

void _start(void) {
    volatile int seed = 2;
    long r = 0;
    r += event(0, 40 + seed);
    r += event(2, 70);
    r += event(4, 0);
    r += event(3, 20);
    r += event(1, 5);
    r += event(2, 500);
    r += event(7, 1);
    r = r * 4 + tally();
    r = r * 8 + replay();
    sys_exit(r);
}
