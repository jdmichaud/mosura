/* Ground-truth repro: a FOR-loop whose CONDITION CARRIES A STATEMENT.
 *
 * The sibling of `loopcomma.c`, on the other emitter. `PrintC::emitForLoop` (printc.cc:2974) sets
 * the SAME `comma_separate` mod around its `condBlock->emit(this)` that
 * `PrintC::emitBlockWhileDo`'s non-overflow arm sets (printc.cc:3046-3054), so a for-header whose
 * condition block holds a statement must print it INSIDE the parentheses, between the two
 * semicolons, joined with `, ` (`emitBlockBasic`, printc.cc:2706-2720) and without its `;`
 * (`emitStatement`, printc.cc:2291). It belongs there because it RE-EXECUTES on every iteration.
 *
 * mosura ported `comma_separate` for the whiledo arm only (e760926) and left `emitForLoop`
 * hoisting the statement ABOVE the `for` line, which runs it exactly once. That is the same wrong
 * code the whiledo fix removed, on a different site: the loop below would load the node's key
 * once, then copy that one value forever while the pointer walks away from it.
 *
 * Expected (Ghidra's shape):   for (p = p; v = p->key, v != want; p = p->next) { ... }
 * Pre-fix mosura:              v = p->key;  for (p = p; v != want; p = p->next) { ... }
 *
 * This is NOT a duplicate of loopcomma: that program deliberately uses a GLOBAL walked pointer to
 * STAY a WhileDo (its property 4), precisely to avoid this emitter. This one is its inverse and
 * exists to reach it.
 *
 * Built by wcc386 like watprog/loopcomma; gated by
 * ground_truth_parity::for_comma_condition_inline.
 */
const char forcomma_banner[] =
    "WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. "
    "All rights reserved.";

struct node {
    struct node *next;
    int key;
};

int forcomma_hits;

/* FOUR properties are required, and dropping any one loses the shape. Three are inherited from
 * `loopcomma.c` (each established there by losing it); the fourth is INVERTED and is the whole
 * point of this program:
 *
 *   1. the test LOADS through the pointer the loop advances, so the load belongs to the
 *      condition block and cannot be lifted above the loop;
 *   2. the loop is TOP-tested with a SINGLE exit, so it structures as a WhileDo before
 *      for-recovery runs. An early `return` in the body adds a second exit and it comes back as
 *      `do {} while (...)`, which never reaches `emitForLoop` at all;
 *   3. the loaded value is USED IN THE BODY. If its only use is the comparison, the compiler
 *      folds it into the test (`while (*p != want)`) and no statement is left to comma-separate;
 *   4. ⭐ the walked pointer is a LOCAL (here a parameter), so the loop IS recovered as a `for`.
 *      This is the exact inverse of loopcomma.c's property 4. Ghidra's `findLoopVariable`
 *      (block.cc:3164) needs a loop-carried MULTIEQUAL in the head; a local pointer has one
 *      across the back-edge and `p = p->next` is a valid tail iterate, so
 *      `BlockWhileDo::finalTransform` converts the loop and printing routes through
 *      `PrintC::emitForLoop`. Swapping in a GLOBAL pointer is what loopcomma.c does and its loop
 *      stays a WhileDo — the gate would then pass vacuously against the already-fixed
 *      `emitBlockWhileDo` and test nothing. That is why the assertion below CHECKS for a `for`
 *      and panics with the whole C if it finds a `while`, rather than trusting this paragraph.
 *
 *      ⚠️ Do NOT read that as "a global cannot be a for-loop". This comment originally said a
 *      global has no register phi so no `for` is formed; that is false — ram is heritaged, and
 *      Ghidra recovers for-loops over global induction variables (WAR2 has five, e.g.
 *      `for (DAT_0008f19b = 0; DAT_0008f19b < 8; DAT_0008f19b = DAT_0008f19b + 1)`). The
 *      local-vs-global swap is a reliable lever ON THESE TWO PROGRAMS, established by measurement
 *      and re-proved by the gates; it is not a general rule, and the mechanism behind it is not
 *      established. See loopcomma.c's property 4 for the same correction.
 *
 * Note the iterate statement `p = p->next` reads `p` DIRECTLY. That matters:
 * `BlockWhileDo::testIterateForm` (block.cc:3287) truncates its operand walk at every explicit
 * Varnode, so an iterate that reached the loop variable only through the explicit `v` would be
 * rejected and the `for` declined (that is what happens in WAR2's FUN_00016764).
 */
int walk(struct node *p, int want) {
    int v = 0;
    while ((v = p->key) != want) {
        forcomma_hits = forcomma_hits + v;
        p = p->next;
    }
    return forcomma_hits;
}

int main(void) {
    static struct node n;
    n.next = 0;
    n.key = (int)forcomma_banner[0];
    return walk(&n, n.key);
}
