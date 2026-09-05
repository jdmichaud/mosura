/* Ground-truth corpus program: the NO-RETURN CALL fixture — the only binary in the corpus that
 * makes `analysis/analyzers/noreturn.rs` run at all.
 *
 * WHY IT EXISTS. `noreturn::analyze` (Ghidra's `NoReturnFunctionAnalyzer` +
 * `ElfFunctionsThatDoNotReturn`) selects its name list from the memory map and **returns early
 * unless a `.dynsym`, `.plt` or `EXTERNAL` block exists** (noreturn.rs:128-137). Every other
 * binary in this corpus is freestanding: the gcc columns link `-nostdlib -static` and the Watcom
 * columns link `option nodefaultlib`, and the subject is a DOS/4GW LE image whose objects are named
 * `objN_text`/`objN_data`. Measured on all of them: **`noreturn_functions` is EMPTY**. So an
 * entire analyzer had zero coverage, on any target, and any test asserting a no-return behaviour
 * would have passed whether or not the code under it worked.
 *
 * This is therefore the one fixture built DYNAMICALLY (`-nostartfiles`, no `-static`), purely so
 * that `abort` arrives as a real `.dynsym`/`.plt` import. It is otherwise the same freestanding
 * shape as the rest of the gcc column: our own `_start`, no libc startup.
 *
 * WHAT IT PINS — a body must END at a call that never returns.
 *
 *     401020 <a_dies>:  ... 7e 01 jle ; c3 ret ; 50 push rax
 *     401035:           e8 .. call <abort@plt>      <- the function's LAST flow, ends at 401039
 *     40103a:           66 0f 1f 44 00 00           <- 6 bytes of ALIGNMENT PADDING, nobody's code
 *     401040 <b_next>:  ...                         <- the next function
 *
 * Ghidra asks `Instruction.getFallThrough()` (`FollowFlow.java:556`), which is null after a call
 * to a non-returning function, so the body stops at 401039. mosura's `compute_function_bodies`
 * derived fall-through from the opcode alone and walked on through the padding to 40103f — the
 * padding belongs to neither function and was inside `a_dies`.
 *
 * PROPERTIES THIS PROGRAM DEPENDS ON — do not "simplify" any of them away:
 *
 *  1. `abort` is declared `__attribute__((noreturn))` EXPLICITLY. Under `-ffreestanding` gcc does
 *     not treat it as the builtin, and without the attribute it emits `add rsp,8; ret` after the
 *     call — the call is then not the last flow and the fixture pins nothing. (mosura decides
 *     no-return from the SYMBOL NAME, not from this attribute; the attribute only controls what
 *     gcc emits.)
 *  2. Both functions are `noinline`. At `-O2` gcc otherwise inlines them into `_start` and the
 *     standalone bodies survive only as unreferenced globals — which vanish from the STRIPPED
 *     artifact this corpus analyzes, leaving nothing to measure.
 *  3. `a_dies` keeps an ordinary `return` path as well (`x > 100`), so it is a normal function
 *     with a normal `ret`, not a degenerate one-block wrapper around `abort`.
 *  4. `b_next` is called, so it is a known entry. That is deliberate and makes the test STRICTER:
 *     the body walk stops at a known function entry anyway, so the only thing left to observe is
 *     the alignment padding between them. If the assertion were "does it swallow b_next" it would
 *     pass without the fix.
 */

extern void abort(void) __attribute__((noreturn));

int g;

/* Its last flow is `call abort` — the body must end there. */
__attribute__((noinline)) int a_dies(int x) {
    g += x;
    if (x > 100) {
        return g;
    }
    abort();
}

/* Emitted immediately after `a_dies`, with alignment padding in between. */
__attribute__((noinline)) int b_next(int x) {
    return x * 3 + g;
}

void _start(void) {
    g = a_dies(1) + b_next(2);
    for (;;) {
    }
}
