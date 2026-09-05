/* Ground-truth repro: an INDIRECT CALL must not clobber the loop variable.
 *
 * mosura has no `ActionDefaultParams` (Ghidra coreaction.hh:659, apply at coreaction.cc:2311), so
 * no call site ever gets its OWN prototype. `Heritage::guardCalls` therefore asks the CONTAINING
 * FUNCTION's model what a call clobbers (heritage.rs, `f.proto_model.has_effect(...)`) where Ghidra
 * asks the CALL's model (`fc->hasEffect`) — the one ActionDefaultParams installs, taking the
 * callee's prototype when the callee is known and `evalfp_called`/`defaultfp` via
 * `setInternal(evalfp, void)` when it is not.
 *
 * The consequence is not cosmetic. When the register holding a loop's induction variable is
 * treated as killed by the call, heritage guards it with an INDIRECT, and then:
 *
 *   - the loop-head MULTIEQUAL's tail input becomes that INDIRECT — a MARKER — so
 *     `BlockWhileDo::findLoopVariable` (block.cc:3164) correctly refuses to form a `for`;
 *   - the real update is left with no consumer except the call ARGUMENT it also feeds, so
 *     `is_explicit` inlines it and NO assignment statement is emitted at all.
 *
 * Together those two produce a loop that cannot terminate. the subject's FUN_00057034 is the specimen:
 *
 *     mosura:  iVar3 = 0;
 *              while (iVar3 < (int4)(uRam000a71b3 + 1)) {
 *                (*(code *)xRam00088aac)(param_1, ..., iVar3 + 1, xVar4);   <- the update, as an ARG
 *              }
 *     ghidra:  for (iVar1 = 0; iVar1 < (int)(DAT_000a71b3 + 1); iVar1 = iVar1 + 1) {
 *                (*_DAT_00088aac)();
 *              }
 *
 * `iVar3` is never assigned in the body. Gated by
 * ground_truth_parity::indirect_call_does_not_clobber_loop_variable.
 *
 * ⚠️ THE INFINITE-LOOP SCAN PREDICATE CANNOT CERTIFY THIS FIX. FUN_00057034's condition reads a
 * GLOBAL bound, which is inside that predicate's documented blind spot
 * (scripts/corpus-wrongcode-scan.py, `infinite_whiles`). The gate below reads the emitted statement
 * and the loop form directly instead.
 */
const char callclob_banner[] =
    "WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. "
    "All rights reserved.";

int callclob_hits;

/* Properties this program depends on. Each is here because losing it loses the shape:
 *
 *   1. the call is INDIRECT, through a pointer the decompiler cannot resolve. A direct call to a
 *      known function gets that function's prototype from ActionDefaultParams' `otherfunc` branch
 *      and the whole question never arises.
 *   2. the callee's signature is UNKNOWN at the call site, so the default model decides the
 *      effects. That is the branch being tested.
 *   3. the induction variable is LIVE ACROSS the call, so heritage has to decide whether the call
 *      kills it. If the loop were unrolled or the variable dead after the call there is nothing to
 *      guard.
 *   4. the update's value is ALSO the call's argument (`fp(i + 1)`), which is what makes the
 *      missing assignment observable: with the update consumed only by the loop, it would print as
 *      a statement even when the `for` is declined, and the loop would still terminate. the subject's
 *      FUN_00057034 has exactly this overlap.
 *   5. the loop BOUND is a PARAMETER, deliberately NOT a global. A global bound would drag in the
 *      separate unported-ActionMapGlobals defect (adjacent globals merged into one oversized
 *      value) and this program would then gate two defects and neither cleanly.
 */
int walk(int n, void (*fp)(int)) {
    int i;
    for (i = 0; i < n; i = i + 1) {
        fp(i + 1);
    }
    return callclob_hits;
}

void sink(int v) {
    callclob_hits = callclob_hits + v;
}

int main(void) {
    callclob_hits = 0;
    /* 6. `sink` is ALSO called directly here. Reached only through the pointer it is invisible to
     *    call-reachability discovery, and the generic ground_truth_parity harness fails the whole
     *    program with "missed call-reachable functions". The direct call keeps it discoverable
     *    without weakening anything: the call inside `walk` is still indirect through `fp`, which
     *    is the only call this program is about. */
    sink(0);
    return walk((int)callclob_banner[0], sink);
}
