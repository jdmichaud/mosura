/* Ground-truth corpus program (task #3 / issues-become-source-tests (subject-profile note)). Open Watcom / x86-32
 * column, compiled by wcc386 into a freestanding ELF32 i386 (x86:LE:32:default) exactly like
 * watprog. A three-way differential on a `switch` with NON-TRIVIAL case bodies -- cases that call
 * and mutate state, as the subject's do, rather than `narrowsw.c`'s `return <const>`.
 *
 * WHY IT EXISTS. the subject shows an EMPTY SWITCH BODY: `FUN_00051298` recovers all eight jump-table
 * targets and then renders `switch (...) { }`, losing 10 of its 12 calls, and `FUN_0006af2c` is
 * the same shape at full severity (10 targets recovered, whole CFG torn down to one block, all 18
 * calls lost). This program was written to reduce that.
 *
 * ⚠️ IT DOES NOT REPRODUCE THE EMPTY BODY -- and that is the useful result. All three functions
 * keep their case bodies. So "narrowed selector + calls inside the cases" is NOT the trigger, and
 * the subject empty body needs a different reduction. Do not delete this file on that basis: a
 * negative reduction that rules out the obvious hypothesis is evidence, and the pair below found a
 * REAL defect on its own (see next paragraph).
 *
 * WHAT IT DOES CATCH. On the narrowed (16-bit) selector the switch EXPRESSION is rendered as the
 * computed jump-table address instead of the switch variable:
 *     sw_call_int    ->  switch (xVar1)                                     (correct)
 *     sw_call_short  ->  switch ((xunknown4 *)((uVar1 & 0xffff) * 4 + 0x80481ca))
 * Only reachable since 6e1b113 made narrowed-selector tables recover at all. Ghidra renders the
 * switch variable in both.
 *
 * Note `sw_call_byte` does NOT get a jump table from wcc386 (it becomes a compare chain), so it is
 * an unused third column for now; keep it, since a future Watcom flag set may table it.
 *
 * Built like watprog (hand-written `_cstart_`, no Watcom C run-time). See build.sh / build_watcom
 * + docs/ground-truth-corpus.md. */

static int acc;

static int helper_a(int v) { acc += v; return v + 1; }
static int helper_b(int v) { acc -= v; return v + 2; }
static int helper_c(int v) { acc ^= v; return v + 3; }

/* CONTROL: 32-bit selector, non-trivial case bodies. */
int sw_call_int(int x, int *out)
{
    switch (x) {
        case 0: *out = helper_a(x); break;
        case 1: *out = helper_b(x); acc += 1; break;
        case 2: *out = helper_c(x); break;
        case 3: *out = helper_a(x) + helper_b(x); break;
        case 4: *out = helper_c(x); acc -= 2; break;
        case 5: *out = helper_a(x); break;
        case 6: *out = helper_b(x) + helper_c(x); break;
        case 7: *out = helper_c(x); acc ^= 4; break;
        default: *out = -1; return 0;
    }
    return acc;
}

/* GAP CANDIDATE: 16-bit narrowed selector (the subject's 0x513a8 / 0x58afb shape). */
int sw_call_short(int xx, int *out)
{
    short x = (short)xx;
    switch (x) {
        case 0: *out = helper_a(x); break;
        case 1: *out = helper_b(x); acc += 1; break;
        case 2: *out = helper_c(x); break;
        case 3: *out = helper_a(x) + helper_b(x); break;
        case 4: *out = helper_c(x); acc -= 2; break;
        case 5: *out = helper_a(x); break;
        case 6: *out = helper_b(x) + helper_c(x); break;
        case 7: *out = helper_c(x); acc ^= 4; break;
        default: *out = -1; return 0;
    }
    return acc;
}

/* GAP CANDIDATE: 8-bit narrowed selector inside a guarded loop -- the FUN_0006af2c shape
 * (`cmp AL,9; ja; and EAX,0xff`), the one that loses its whole CFG. */
int sw_call_byte(unsigned char *p, int *out)
{
    int n = 0;
    while (*p > 9) {
        switch (*p) {
            case 0: *out = helper_a(n); break;
            case 1: *out = helper_b(n); acc += 1; break;
            case 2: *out = helper_c(n); break;
            case 3: *out = helper_a(n) + helper_b(n); break;
            case 4: *out = helper_c(n); acc -= 2; break;
            case 5: *out = helper_a(n); break;
            case 6: *out = helper_b(n) + helper_c(n); break;
            case 7: *out = helper_c(n); acc ^= 4; break;
            case 8: *out = helper_a(n) + 8; break;
            case 9: *out = helper_b(n) + 9; break;
            default: return n;
        }
        p += helper_a(n) + 4;
        n += 1;
    }
    return n;
}

int main(void)
{
    int o = 0;
    unsigned char buf[4];
    buf[0] = 3; buf[1] = 0; buf[2] = 0; buf[3] = 0;
    return sw_call_int(3, &o) + sw_call_short(5, &o) + sw_call_byte(buf, &o);
}
