/* Ground-truth corpus program: the PROLOGUE-SHAPE SPECIFICATION for the Watcom function-start
 * pattern set (`specs/patterns/x86watcom_patterns.xml`, beyond-Ghidra — Ghidra ships no Watcom
 * compiler spec, so that pattern file has no Ghidra oracle and must get one here).
 *
 * WHY THIS EXISTS. Precision is **unmeasurable on the subject**: the expert tracker covers 71.4% of the
 * code object, so a pattern hit in a gap may be a real function the tracker lacks or may be noise,
 * and nothing in the binary distinguishes them. Tuning the pattern against the subject's function count is
 * therefore chasing a number with no specification behind it. Here every function is known from the
 * compiler's own symbol table, so BOTH properties become measurable:
 *   recall    — the search finds every real entry;
 *   precision — it creates nothing that is not one.
 *
 * WHAT IT MUST COVER — measured, not assumed. Reading the first 6 bytes at each of the 2120
 * tracker-known the subject entries gives 376 distinct shapes, dominated by a run of callee-saved pushes
 * followed by a frame setup:
 *
 *     333  4 pushes + 89 e5        288  5 pushes + 89          201  6 pushes + (>6 bytes)
 *      87  3 pushes + 89 e5 83      84  3 pushes + 89 e5 89     59  1 push   + 89 e5 83
 *    1996 of 2120 (94%) begin with at least one 0x50-0x57 push.
 *
 * Two consequences that drove this file, both contradicting the first pattern draft:
 *   - the push run reaches 6, not 5, and `push ebp` (0x55) is itself INSIDE the run;
 *   - `sub esp` (`83 ec`/`81 ec`) is frequently ABSENT, so requiring it — as Ghidra's
 *     x86gcc_patterns.xml `0x5589e583ec` does — misses most real Watcom prologues. That is exactly
 *     why Ghidra's own Function Start Search contributes only 243 functions on the subject.
 *
 * So the functions below are written to force a SPREAD of callee-saved register pressure (wcc386
 * pushes one register per live value it must preserve), plus the frame/no-frame and leaf/non-leaf
 * variants, so the fixture exercises the whole measured family rather than one specimen.
 *
 * Built with the default `-oc` like the other watcom fixtures; the shapes here come from register
 * pressure, not from call/return rewriting, so no special flag is needed.
 */

extern int sink(int);
int g;

/* --- leaf, no frame, no saves: the minimal shape (part of the 124/2120 with no leading push). */
int p_leaf(int a) { return a + 1; }

/* --- increasing callee-saved pressure: each needs one more value live across the call, which
 *     wcc386 answers with one more push in the prologue run. */
int p_push1(int a) {
    int x = a * 3;
    return sink(a) + x;
}

int p_push2(int a, int b) {
    int x = a * 3, y = b * 5;
    return sink(a) + x + y;
}

int p_push3(int a, int b, int c) {
    int x = a * 3, y = b * 5, z = c * 7;
    return sink(a) + x + y + z;
}

int p_push4(int a, int b, int c, int d) {
    int x = a * 3, y = b * 5, z = c * 7, w = d * 11;
    return sink(a) + x + y + z + w;
}

int p_push5(int a, int b, int c, int d, int e) {
    int x = a * 3, y = b * 5, z = c * 7, w = d * 11, v = e * 13;
    return sink(a) + x + y + z + w + v;
}

int p_push6(int a, int b, int c, int d, int e, int f) {
    int x = a * 3, y = b * 5, z = c * 7, w = d * 11, v = e * 13, u = f * 17;
    return sink(a) + x + y + z + w + v + u;
}

/* --- a real stack frame: forces `sub esp` after the frame setup (the `83 ec` tail). */
int p_frame(int a) {
    int buf[8];
    int i;
    for (i = 0; i < 8; i++) buf[i] = a + i;
    return sink(buf[a & 7]);
}

/* --- a large frame: `81 ec` (imm32) rather than `83 ec` (imm8). */
int p_bigframe(int a) {
    int buf[400];
    int i;
    for (i = 0; i < 400; i++) buf[i] = a + i;
    return sink(buf[a & 255]);
}

/* --- frame + saves together: the push-run-then-`89 e5`-then-`83 ec` shape. */
int p_frame_saves(int a, int b, int c) {
    int buf[6];
    int x = a * 3, y = b * 5, z = c * 7;
    int i;
    for (i = 0; i < 6; i++) buf[i] = x + y + z + i;
    return sink(buf[a & 5]) + x + y + z;
}

/* --- non-leaf without locals: call straight through (the `89 e5` with no `sub esp`). */
int p_thru(int a) { return sink(a); }

/* --- touches a global, so the body starts with a memory op rather than a frame setup. */
int p_global(int a) {
    g += a;
    return g;
}

int main(void) {
    int t = 0;
    t += p_leaf(1);
    t += p_push1(2);
    t += p_push2(2, 3);
    t += p_push3(2, 3, 4);
    t += p_push4(2, 3, 4, 5);
    t += p_push5(2, 3, 4, 5, 6);
    t += p_push6(2, 3, 4, 5, 6, 7);
    t += p_frame(3);
    t += p_bigframe(4);
    t += p_frame_saves(2, 3, 4);
    t += p_thru(5);
    t += p_global(6);
    return t;
}
