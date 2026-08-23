/* Ground-truth corpus (era-style, 2026-08-23): a game-like entity table walked through struct
 * fields — field loads/stores at constant offsets off a base pointer, a nearest-search compare
 * ladder, a damage pass with clamping, and a flag count. Mid-size functions (30-120 insns)
 * where WAR2's recompile loss lives. Freestanding + per-arch exit shim. */
#include "shim.h"

struct entity {
    int x, y;
    int hp;
    unsigned flags;
    short kind;
    short owner;
};

static struct entity units[8];

__attribute__((noinline)) static int iabs(int v) { return v < 0 ? -v : v; }

/* Nearest entity to (px,py) among the first n, ignoring dead ones; -1 when none. */
__attribute__((noinline)) static int find_nearest(struct entity *e, int n, int px, int py) {
    int best = -1, bestd = 0x7fffffff;
    for (int i = 0; i < n; i++) {
        if (e[i].hp <= 0) continue;
        int d = iabs(e[i].x - px) + iabs(e[i].y - py);
        if (d < bestd) { bestd = d; best = i; }
        else if (d == bestd && e[i].kind < e[best].kind) best = i;
    }
    return best;
}

/* Apply damage to every living entity of the given owner; clamp hp to [0,100], mark the dead. */
__attribute__((noinline)) static int damage_all(struct entity *e, int n, int owner, int amount) {
    int killed = 0;
    for (int i = 0; i < n; i++) {
        struct entity *u = &e[i];
        if (u->owner != owner || u->hp <= 0) continue;
        u->hp -= amount;
        if (u->hp <= 0) { u->hp = 0; u->flags |= 4u; killed++; }
        else if (u->hp > 100) u->hp = 100;
        if (u->hp < 25) u->flags |= 8u; else u->flags &= ~8u;
    }
    return killed;
}

/* Count entities whose flags contain every bit of `mask`. */
__attribute__((noinline)) static int count_flags(const struct entity *e, int n, unsigned mask) {
    int c = 0;
    for (int i = 0; i < n; i++)
        if ((e[i].flags & mask) == mask) c++;
    return c;
}

void _start(void) {
    volatile int seed = 3;
    for (int i = 0; i < 8; i++) {
        units[i].x = (i * 7 + seed) % 11;
        units[i].y = (i * 5 + seed) % 13;
        units[i].hp = 20 + i * 15;
        units[i].flags = (unsigned)(i & 3);
        units[i].kind = (short)(i % 3);
        units[i].owner = (short)(i & 1);
    }
    long r = find_nearest(units, 8, 4, 6);
    r = r * 16 + damage_all(units, 8, 1, 40);
    r = r * 8 + count_flags(units, 8, 4u);
    r = r * 4 + find_nearest(units, 8, 9, 9);
    sys_exit(r);
}
