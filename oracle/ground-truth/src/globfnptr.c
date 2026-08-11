/* Ground-truth repro: an indirect call through a GLOBAL FUNCTION POINTER.
 *
 * The shape is `call DWORD PTR ds:<addr>` — a single memory-indirect call, 6 bytes, no register
 * load. It is the most common call form in the WAR2 survey: the `indirect_call` smell covers
 * 1193 of the attributable mismatches, and the smallest extent-verified specimen (7 bytes: the
 * call plus a `ret`) shows the defect with nothing else in the way.
 *
 * mosura renders it by casting the global's VALUE to a code pointer — `(*(code *)xRam...)()` —
 * which is a different program: it loads the variable into a register and calls the register.
 * wcc386 emits 8 bytes for that against the original's 7, so the function cannot match however
 * correct the logic is. The faithful rendering types the GLOBAL as a function pointer and calls
 * it directly, which is what produces `call [mem]`.
 *
 * Properties this program depends on — do not "simplify" them away:
 *   1. the pointer is a GLOBAL, not a parameter or local: a parameter arrives in a register and
 *      the call is register-indirect, which is a different encoding and a different defect;
 *   2. `dispatch` does nothing but call it, so the emitted C for that one call is the whole test;
 *   3. `sink` is also called DIRECTLY from main, so the generic ground_truth_parity recall
 *      property (every call-reachable function is recovered) is satisfied without making the
 *      indirect call in `dispatch` reachable-by-name;
 *   4. the pointer is initialised at run time, not statically, so the compiler cannot constant-
 *      fold the indirect call into a direct one.
 */
const char globfnptr_banner[] =
    "WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. "
    "All rights reserved.";

int globfnptr_hits;

void (*globfnptr_slot)(void);

void sink(void) {
    globfnptr_hits = globfnptr_hits + 1;
}

/* The whole test: one memory-indirect call through the global, and return. */
void dispatch(void) {
    globfnptr_slot();
}

int main(void) {
    globfnptr_slot = sink;   /* run-time init: no constant folding into a direct call */
    sink();                  /* keeps `sink` call-reachable for the recall property */
    dispatch();
    return globfnptr_hits + (int)globfnptr_banner[0];
}
