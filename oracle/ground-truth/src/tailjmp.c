/* Ground-truth corpus program (issues-become-source-tests (subject-profile note)): the source-reduced repro of the
 * AUTO-ANALYSIS gap the subject binary function survey exposed — a function that is reachable ONLY by an
 * unconditional `jmp` tail call is never created, so its whole call sub-tree is lost. Compiled by
 * Open Watcom `wcc386` exactly like watprog/narrowsw into a freestanding ELF32
 * (x86:LE:32:default). Gated in `ground_truth_parity.rs` (recall) + `::tail_jump_shared_return`.
 *
 * WHAT IT REPRODUCES — Ghidra `SharedReturnAnalysisCmd.applyTo`'s `assumeContiguousFunctions`
 * rule: an unconditional jump that crosses a NEIGHBOURING FUNCTION'S ENTRY is a shared-return tail
 * call, and Ghidra creates a function at the destination. On the subject this is the only mechanism that
 * reaches FUN_00067f40 / FUN_00072301 / FUN_00079330 — each the target of a lone `e9 rel32` and of
 * nothing else. (Those three were originally filed as "plain direct call" seeds because Ghidra
 * REPORTS the reference as UNCONDITIONAL_CALL; that is the reference type AFTER the CALL_RETURN
 * flow override this very rule applies. The instructions are `jmp`, not `call`.)
 *
 * PROPERTIES THIS PROGRAM DEPENDS ON — do not "simplify" any of them away:
 *
 *  1. `-oc` (disable Watcom's call/return optimization) is NOT passed for this program, unlike
 *     every other watcom-x86-32 fixture. `-oc` is exactly what suppresses the `call X; ret` ->
 *     `jmp X` rewrite, i.e. it suppresses the shape under test. See `build.sh`.
 *  2. BACKWARD arm (C, `jump_back` -> `tail_lo`): `tail_lo` is defined FIRST so it lands at a
 *     lower address than `jump_back`, whose tail call lowers to `jmp tail_lo_` — a jump back past
 *     `jump_back_`'s own entry. That is the subject shape (0x69032->0x67f40, 0x77dc1->0x72301,
 *     0x7a66b->0x79330 are all backward).
 *  3. FORWARD arm (`tailjmp_cstart.asm`, `fwd_jumper` -> `fwd_landing`): a jump FORWARD over
 *     `gap_fn`'s entry. It lives in the asm stub because wcc386 always lays a tail-call callee
 *     adjacent to (or before) its caller, so the forward arm cannot be produced from C with this
 *     compiler. It exercises the other arm of the same rule (the subject's 0x601f8->0x60270 etc.).
 *  4. Both jump targets are preceded by a `ret`, so NOTHING falls through into them — Ghidra's
 *     `checkIfCouldHaveFallThruTo` must not veto, and the destination is genuinely unreachable
 *     without the rule. Both start with a non-terminator instruction, so the `RefType.TERMINATOR`
 *     veto does not apply either.
 *  5. `tail_lo` and `fwd_landing` are called from NOWHERE ELSE and have no data reference: the
 *     tail-call jump is their ONLY inbound edge. Adding a second (ordinary) call site to either
 *     would let plain call-target discovery create them and the gate would pass vacuously.
 *  6. Every OTHER function is genuinely `call`-reachable from `main`, so the recall assertion in
 *     `ground_truth_parity` isolates the two jump-only functions.
 *
 * PRE-FIX BEHAVIOUR (mosura `b9d8466`): `tail_lo_`/`fwd_landing_` are missing from the recovered
 * function set. mosura's `SharedReturnAnalyzer::could_have_fall_thru_to` carried an invented gate
 * ("a location inside an existing function's body must have a fall-through predecessor") which is
 * not in Ghidra; the destination gets swallowed into the JUMPING function's body (flow follows the
 * `jmp`), so that gate vetoed every tail-call destination — including all three the subject seeds. */

int g_acc;

int tail_lo(int x);
int mid(int x);
int jump_back(int x);
int between(int x);

/* From tailjmp_cstart.asm — the forward arm (property 3). */
extern int fwd_jumper(int x);
extern int gap_fn(int x);

/* Property 2/5: defined first -> lowest address; the ONLY reference to it is the tail-call
 * `jmp` at the end of `jump_back`. */
int tail_lo(int x) {
    g_acc += x;
    return g_acc ^ 0x5a;
}

/* An ordinary called function sitting between `tail_lo` and `jump_back`, so the backward jump
 * genuinely crosses a function boundary. */
int mid(int x) {
    return x * 7 + g_acc;
}

/* Property 2: the tail call in return position -> `jmp tail_lo_` (backward). */
int jump_back(int x) {
    g_acc += x;
    return tail_lo(x + 1);
}

int between(int x) {
    return x - g_acc;
}

int main(void) {
    int a = jump_back(2);
    int c = mid(4);
    int d = between(5);
    int e = fwd_jumper(6);
    int f = gap_fn(7);
    return a + c + d + e + f + g_acc;
}
