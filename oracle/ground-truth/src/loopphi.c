/* Ground-truth repro: for-recovery must not give up on the FIRST loop-head phi it finds.
 *
 * Ghidra's `BlockWhileDo::findLoopVariable` (block.cc:3164) walks back from the exit CBRANCH
 * looking for a MULTIEQUAL in the loop head, and — this is the part mosura lacked — it does NOT
 * commit on reaching one. It checks that phi's tail-slot input and `continue`s the walk if the
 * input is a marker, is not defined in the tail, or is not moveable to the end:
 *
 *     if (defOp->code() == CPUI_MULTIEQUAL) {
 *       if (defOp->getParent() != head) continue;
 *       Varnode *itvn = defOp->getIn(slot);
 *       if (!itvn->isWritten()) continue;
 *       PcodeOp *possibleIterate = itvn->getDef();
 *       if (possibleIterate->getParent() == tail) {
 *         if (possibleIterate->isMarker()) continue;      // <- keeps searching
 *         if (!possibleIterate->isMoveable(lastOp)) continue;
 *         loopDef = defOp; iterateOp = possibleIterate; return;
 *       }
 *     }
 *
 * mosura's `find_loop_phi` returned the FIRST head phi it met and `for_parts` then validated that
 * one, with no backtracking — so a single wrong candidate anywhere on the walk lost the `for`.
 *
 * The wrong candidate is easy to come by, and the subject supplies seven of them. When the loop BOUND is
 * a global that the body modifies, the bound is heritaged, gets its own phi in the loop head, and
 * the operand DFS reaches it BEFORE the register induction variable — the condition is
 * `INT_LESS(i, load(bound))` and the walk pops the second operand first. Instrumenting the subject
 * specimens printed the selected phi's storage and it was `space="ram"` every time:
 *
 *     FORPARTS3 @00026e78 phi_out space="ram" off=0x948b6   itercode=Multiequal
 *     FORPARTS3 @00057034 phi_out space="ram" off=0xa71b3   itercode=Indirect
 *
 * i.e. mosura was validating `DAT_000948b6` — the loop bound — as the induction variable, finding
 * its tail input to be a call-clobber marker, and declining. Ghidra `continue`s past exactly that
 * and goes on to find the register.
 *
 * Expected (Ghidra's shape):   for (i = 0; i < cbound_limit; i = i + 1) { ... }
 * Pre-fix mosura:              i = 0; while (i < cbound_limit) { ... i = i + 1; }
 *
 * Gated by ground_truth_parity::for_recovery_backtracks_past_wrong_phi.
 */
const char loopphi_banner[] =
    "WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. "
    "All rights reserved.";

int cbound_limit;
int cbound_hits;

/* FIVE properties are required, and dropping any one loses the shape:
 *
 *   1. the loop BOUND is a GLOBAL, so it is heritaged and can carry a phi in the loop head. A
 *      local bound has no phi there and `find_loop_phi` would reach the induction variable first
 *      with nothing to trip over — the gate would pass before the fix and prove nothing.
 *   2. the global is modified CONDITIONALLY inside the loop, so the paths rejoin before the back
 *      edge and the head phi's tail-slot input is another MULTIEQUAL — a MARKER. That is what
 *      makes the wrong candidate get REJECTED rather than wrongly accepted, which is precisely
 *      the case Ghidra recovers from by continuing the walk. An UNconditional write would make
 *      the tail input a plain INT_SUB, which BOTH decompilers would accept as a valid iterate,
 *      and the program would then legitimately print `for (cbound_limit = ...)` and test nothing.
 *   3. the bound is read in the condition, so the operand walk reaches its phi. It is the SECOND
 *      operand of the comparison and the walk is LIFO, so it is reached first — the same ordering
 *      as the subject specimens.
 *   4. ⭐ THERE IS NO CALL IN THE LOOP AT ALL, and that is a hard requirement rather than a
 *      simplification. mosura asks the CONTAINING function's model what a call kills rather than
 *      the call's own (the separate unported-ActionDefaultParams defect), so EVERY call — direct
 *      or indirect — clobbers the scratch registers. Watcom puts a loop counter in ECX quite
 *      readily, and two earlier versions of this program did exactly that: the increment came back
 *      as `iVar1 = extraout_RCX + 1`, meaning the induction variable was clobbered too and the
 *      `for` would have been declined for a SECOND reason this fix does not address. The gate
 *      would then have stayed red after a correct fix. Adding a second live local did not move it
 *      out of ECX either. A conditional store needs no call, so the call is simply gone.
 *      `callclob.c` is where the clobber defect is gated.
 *   5. the induction variable is a plain LOCAL in a register with nothing to clobber it, so its
 *      own phi tail input is the plain INT_ADD that for-recovery is supposed to find.
 */
int cbound_walk(int seed) {
    int i;
    int acc;
    acc = seed;
    for (i = 0; i < cbound_limit; i = i + 1) {
        if ((i & 1) != 0) {
            cbound_limit = cbound_limit - 1;
        }
        acc = acc + i;
    }
    cbound_hits = acc;
    return acc;
}

int main(void) {
    cbound_limit = (int)loopphi_banner[0];
    cbound_hits = 0;
    return cbound_walk(1);
}
