/* Ground-truth corpus: a loop whose HEAD IS THE FUNCTION ENTRY — the shape that requires
 * Ghidra's front-block insertion (`FlowInfo::generateBlocks`, flow.cc:833-840: "Make sure the
 * entry block has no incoming edges").
 *
 * Without that clause the root of the dominator tree has a predecessor, the dominance-frontier
 * walk never puts block 0 in its own frontier, and a value DEFINED IN the entry block gets no
 * MULTIEQUAL at all: every read of it re-links to the function-input varnode, so the loop's own
 * update disappears from the decompiled body. Before the port `spin` printed an EMPTY loop body
 * with an uninitialized variable; Ghidra's own output keeps the update.
 *
 * Properties this program depends on — do not "simplify" them away:
 *  - `do { } while` and NOT `while`: gcc rotates a `while` loop and emits a guard block, which
 *    puts an ordinary block at the entry and the defect does not reproduce.
 *  - the loop variable arrives in an ARGUMENT REGISTER and is updated in place, so its definition
 *    is inside the entry block itself.
 *  - `__attribute__((noinline))` and a `volatile` seed so the chain is not constant-folded.
 *  - `sink` is called from `_start` too, so `spin`'s call to it is not folded into a tail jump.
 */
#include "shim.h"

__attribute__((noinline)) static int sink(int x) { return x + 1; }

__attribute__((noinline)) static int spin(int n) {
    do {
        n = n >> 1;
    } while (n > 5);
    return sink(n);
}

void _start(void) {
    volatile int seed = 4242;
    long r = spin(seed);
    r += sink(0);
    sys_exit(r);
}
