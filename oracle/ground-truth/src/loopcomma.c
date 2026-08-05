/* Ground-truth repro: a while-loop whose CONDITION CARRIES A STATEMENT.
 *
 * Ghidra's `PrintC::emitBlockWhileDo` non-overflow arm (printc.cc:3046-3054) does
 * `setMod(comma_separate); condBlock->emit(this);` — the condition block's statements are printed
 * INSIDE the parentheses, joined with `, ` (`emitBlockBasic`, printc.cc:2706-2720) and without
 * their `;` (`emitStatement`, printc.cc:2291). They belong there because they RE-EXECUTE on every
 * iteration.
 *
 * mosura emitted them ABOVE the `while` line instead, which runs them exactly once. That is wrong
 * code, not a formatting difference: in a linked-list walk it hoists the load of the next node
 * above the pointer's own initialization (a use-before-def) and leaves a loop whose test can never
 * change. Fixed by porting `comma_separate`; this gate holds it.
 *
 * `walk` is the minimal shape that forces it: the loop test needs a value loaded from the node,
 * and that load cannot be hoisted out because the node pointer is what the loop advances. The
 * condition block therefore holds a real statement, so the comma form is required rather than
 * incidental.
 *
 * Expected (Ghidra's shape):   while (v = p->key, v != want) { p = p->next; }
 * Pre-fix mosura:              v = p->key;  while (v != want) { ... }     <- runs once, never updates
 *
 * Built by wcc386 like watprog/forphi; gated by ground_truth_parity::loop_comma_condition_inline.
 */
const char loopcomma_banner[] =
    "WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. "
    "All rights reserved.";

struct node {
    struct node *next;
    int key;
};

int loopcomma_hits;

/* FOUR properties are required, and dropping any one loses the shape. Each was established by
 * losing it — keep them if this program is ever edited:
 *
 *   1. the test LOADS through the pointer the loop advances, so the load belongs to the
 *      condition block and cannot be lifted above the loop;
 *   2. the loop is TOP-tested with a SINGLE exit, so it structures as a WhileDo. An early
 *      `return` in the body adds a second exit and it comes back as `do {} while (...)`, whose
 *      condition block holds only the branch — the gate would then pass vacuously;
 *   3. the loaded value is USED IN THE BODY. If its only use is the comparison, the compiler
 *      folds it into the test (`while (*p != want)`) and no statement is left to comma-separate;
 *   4. the walked pointer is a GLOBAL, so the loop is not recovered as a `for`. Ghidra's
 *      for-recovery needs a loop-carried MULTIEQUAL in the head (`findLoopVariable`); a variable
 *      living in memory is re-loaded each iteration and has no register phi, so no `for` is
 *      formed and the loop stays a WhileDo. With a local pointer this compiles to
 *      `for (p = p; ...; p = p->next)` and routes through `PrintC::emitForLoop`
 *      (printc.cc:2974) — a different site whose own comma_separate is not ported yet.
 *      Neither a pointer chase nor reordering the body defeats for-recovery: Watcom schedules
 *      the advance last regardless of source order. Only the global does.
 */
struct node *loopcomma_cur;

int walk(int want) {
    int v = 0;
    while ((v = loopcomma_cur->key) != want) {
        loopcomma_hits = loopcomma_hits + v;
        loopcomma_cur = loopcomma_cur->next;
    }
    return loopcomma_hits;
}

int main(void) {
    static struct node n;
    n.next = 0;
    n.key = (int)loopcomma_banner[0];
    loopcomma_cur = &n;
    return walk(n.key);
}
