/* Ground-truth corpus program: §5 CELL 1 — stack checking (`-s` vs default).
 *
 * SAME SOURCE AS `wprologue`/`wprologue_sf`, ONE FLAG DIFFERENT. `wprologue_sf` is built
 * `-4r -fpi87 -od` **with** `-s`; this is the same line **without** it. Everything `wprologue.c`
 * defines comes in by inclusion, so all three fixtures move together and the only variable is the
 * flag under test.
 *
 * WHY THIS CELL IS FIRST. `-s` suppresses Watcom's stack-overflow probe. the subject was built with it;
 * **most binaries are not, because it is not the default** — so this is the axis most likely to
 * matter on a binary that is not the subject, which is the whole point of the standing scope rule.
 *
 * WHAT CHANGES — measured on native OW2 before any pattern was written:
 *
 *     -of+        55 89 e5  68 <imm32>  e8 <rel32>                   frame, THEN probe
 *     -od / -oc   68 <imm32> e8 <rel32>  53 51 52 56 57  55 89 e5    probe FIRST, at offset 0
 *     -onatx      omitted for small frames
 *
 * THE DEFECT IT PINS — a NEW PROLOGUE SHIFT, and the same class the whole pattern file exists
 * for. These functions are not invisible; they are found at the WRONG ADDRESS, which is worse,
 * because a wrong entry is a wrong extent and a wrong extent can never recompile byte-exact:
 *
 *     08048366  68 48 00 00 00   push 0x48      <- THE TRUE ENTRY
 *     0804836b  e8 97 fd ff ff   call __CHK
 *     08048370  53 51 52 56 57   push ebx/…     <- the save-first family matches HERE, +10
 *     08048375  55 89 e5         push ebp; mov ebp,esp
 *
 * `x86gcc_patterns.xml` anchored at the `55`, five bytes late, and that is why this file exists.
 * The stack probe reintroduces exactly that, one level up, ten bytes late. Before this cell not
 * one of the file's 99 patterns started with `0x68`.
 *
 * PROPERTIES THIS PROGRAM DEPENDS ON — do not "simplify" any of them away:
 *
 *  1. `__CHK` is supplied by `src/wprobe_cstart.asm`. Without it the freestanding link fails
 *     `E2028: __CHK is an undefined reference` — which is itself the proof that dropping `-s`
 *     changes code generation rather than merely a check.
 *  2. `probe_orphan_fn_` is called from NOWHERE and its address is stored NOWHERE, so recall is
 *     a statement about the pattern set. Every function in `wprologue.c` is called from `main`,
 *     and a cell without an orphan reports full recall with the byte-pattern analyzers switched
 *     OFF — measured on `wprologue_sf` before its orphan existed (15/15, 0 spurious).
 *  3. `probe_trail_fn_` is called from the asm stub, so the orphan is not last in the section.
 *  4. The orphan takes enough arguments and holds enough live across a call to force a real
 *     save run after the probe, so it exhibits the full `probe → saves → frame` shape rather
 *     than a degenerate one.
 */

#include "wprologue.c"

extern int probe_orphan_fn(int a, int b, int c, int d);
extern int probe_trail_fn(int x);

/* THE ORPHAN (properties 2-4). Never called, address never taken. */
int probe_orphan_fn(int a, int b, int c, int d) {
    int buf[8];
    int i, s = 0;
    buf[0] = a;
    buf[1] = b;
    buf[2] = c;
    buf[3] = d;
    for (i = 4; i < 8; i++) {
        buf[i] = buf[i - 4] * (i + 1);
    }
    for (i = 0; i < 8; i++) {
        s += buf[i];
        s ^= sink(buf[i]);
    }
    return s + a * b + c * d + g;
}

/* Ordinarily called (from the asm stub), immediately after the orphan — property 3. */
int probe_trail_fn(int x) {
    return x * 3 + g;
}
