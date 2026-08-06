/* Ground-truth corpus program: the SAVE-FIRST twin of `wprologue.c`, and the ONLY gate on
 * `specs/patterns/x86watcom_patterns.xml`'s save-first family — 62 of its 73 patterns.
 *
 * SAME SOURCE, ONE FLAG DIFFERENT. `wprologue` is built `-of+`; this is built `-4r -fpi87 -od`
 * (build.sh). Everything `wprologue.c` defines comes in by inclusion below, so the two fixtures
 * cannot drift and their difference is exactly the axis under test. Two functions are added:
 * `sf_orphan_fn_` and `sf_trail_fn_` (see PROPERTIES).
 *
 * WHY IT EXISTS. `wprologue` gates the pattern set for the FRAME-FIRST prologue (`55 89 e5` then
 * the saves) — the only shape modern Open Watcom emits under `-of+`. But WAR2's dominant family,
 * 1317 of its 1556 framed functions (84.6%), is SAVE-FIRST: the callee-save run comes BEFORE the
 * frame setup,
 *
 *     53 51 52 56 57   55 89 e5
 *     push ebx/ecx/edx/esi/edi   push ebp ; mov ebp,esp
 *
 * and that family — the whole reason the Watcom pattern file exists — had NO GATE AT ALL. It
 * could have been deleted outright and every test in the corpus would have stayed green.
 *
 * WHY `-od` PRODUCES IT AND `-of+` DOES NOT. The operative flag is `-of+`, and it must be ABSENT.
 * `-of`/`-of+` requests a *traceable* frame, which forces `push ebp; mov ebp,esp` to offset 0 so a
 * debugger can walk the chain from the first instruction. A frame required merely for *addressing*
 * — which `-od` forces, every local spilled — carries no such constraint, so the compiler emits it
 * in its natural place, after the register saves. With neither flag the optimizer omits the frame
 * pointer altogether and EBP becomes a plain callee-save: the "no `55 89 e5` anywhere" case.
 *
 * MEASURED on the native toolchain the corpus already uses (Open Watcom v2, `~/tools/open-watcom`
 * — no historical compiler, no dosemu). Every function comes out save-first, spanning run lengths
 * 2..5:
 *
 *     p_leaf_      53 51 52 56 57  55 89 e5  81 ec 08 00 00 00   <- run 5, WAR2 0x16ed4's shape
 *     p_push2_     53 51 56 57     55 89 e5                      <- run 4
 *     p_push3_     51 56 57        55 89 e5                      <- run 3
 *     p_push4_     56 57           55 89 e5                      <- run 2
 *
 * Every run is a subsequence of Watcom's rigid save order `ebx ecx edx esi edi`, from a compiler
 * two decades newer than WAR2's 10.0a — a third independent confirmation of the invariant that
 * pattern family (1) is built on.
 *
 * PROPERTIES THIS PROGRAM DEPENDS ON — do not "simplify" any of them away. They are `fnpattern.c`'s
 * properties 2-5, restated for the save-first shape, because RECALL IS VACUOUS WITHOUT THEM:
 * every function in `wprologue.c` is called from `main`, so the reference-driven analyzers alone
 * recover all 15 and the pattern set is never load-bearing. Measured before `sf_orphan_fn_`
 * existed: 15/15 recall and 0 spurious with the byte-pattern analyzers turned OFF.
 *
 *  1. `sf_orphan_fn_` is called from NOWHERE and its address is stored NOWHERE. It is not `static`
 *     (wcc386 would drop it) and it is not named by the asm stub. Any reference at all — even a
 *     data pointer — makes the gate pass vacuously through `datafnptr`'s route.
 *  2. It sits BETWEEN two ordinarily-called functions in source order, which wcc386 preserves as
 *     emission order: `main_` before it, `sf_trail_fn_` after. So it is not at a section edge, and
 *     it is preceded by a `ret` — nothing falls through into it, which is also what a
 *     `funcstart after="defined"` pre-requisite needs to see.
 *  3. `sf_trail_fn_` is called from the asm stub rather than from C, because `main` is already
 *     emitted by the time the include ends and the orphan must not be last.
 *  4. Its body is long enough to satisfy `validcode="6"` (six valid fall-through instructions) —
 *     the loop and the spilled locals guarantee that.
 *  5. It calls `sink`, so its body contains a real call: that is what makes "did this become a
 *     function?" distinguishable from "were these bytes decoded?".
 *
 * WHAT IT DOES NOT COVER, so nobody mistakes it for the whole specification: `-od` never produces
 * a run of length 1 here, and it gives every function a `sub esp`, so the no-`sub esp` save-first
 * shape (891 of WAR2's 1317) is not exercised. The 31-subsequence enumeration itself is gated
 * exhaustively and directly by
 * `analysis::analyzers::function_start::tests::save_first_family_enforces_watcoms_push_order`.
 */

#include "wprologue.c"

extern int sf_orphan_fn(int a, int b, int c, int d);
extern int sf_trail_fn(int x);

/* THE ORPHAN (properties 1-5). Never called, address never taken. */
int sf_orphan_fn(int a, int b, int c, int d) {
    int buf[4];
    int i, s = 0;
    buf[0] = a;
    buf[1] = b;
    buf[2] = c;
    buf[3] = d;
    for (i = 0; i < 4; i++) {
        s += buf[i] * (i + 1);
        s ^= sink(buf[i]);
    }
    return s + a * b + c * d + g;
}

/* Ordinarily called (from the asm stub), immediately after the orphan — property 2. */
int sf_trail_fn(int x) {
    return x * 3 + g;
}
