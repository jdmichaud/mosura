/* Ground-truth repro (issues-become-source-tests (subject-profile note)) of the E1063 raw-MULTIEQUAL leak the subject
 * survey exposed (e.g. FUN_0002bd14): a for-loop whose induction variable's entry value comes from
 * a PHI (an earlier loop modified it), NOT from a def in the pre-loop block. mosura's for-recovery
 * lacked Ghidra's `BlockWhileDo::findInitializer` (block.cc:3223) checks — that a written
 * initializer's def be a NON-MARKER op in the pre-loop block — so it emitted the phi raw as the
 * for-init: `for (n = MULTIEQUAL(...); ...)`, which wcc386/gcc reject. Fixed: the phi-defined init
 * is rejected, the loop renders `for (; cond; iter)`. Built by wcc386 like watprog/narrowsw; gated
 * by ground_truth_parity::forphi_no_marker_leak.
 *
 * `scan` modifies `n` in the first `while` (creating the phi), then the countdown `for` uses it —
 * so the for-loop's init input is the while-loop's phi. The loop body accumulates into a global
 * (no trivial callee — keeps the recovered function set clean). */
const char forphi_banner[] =
    "WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. "
    "All rights reserved.";

int forphi_sum;

int scan(int n, const int *p) {
    while (n != *p) {   /* first loop: n becomes a phi across the back-edge */
        n = n - 1;
    }
    for (; 0 < n; n = n - 1) {   /* second loop: n's entry value is the phi from loop 1 */
        forphi_sum = forphi_sum + n;
    }
    return n;
}

int main(void) {
    int a = (int)forphi_banner[0];
    forphi_sum = 0;
    return scan(a, &a);
}
