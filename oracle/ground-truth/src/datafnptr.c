/* Ground-truth corpus program (war2-issues-become-source-tests): the source-reduced repro of the
 * SECOND auto-analysis gap the WAR2.EXE function survey exposed — code that is reachable ONLY
 * through a FUNCTION POINTER STORED IN DATA is never disassembled, so neither it nor anything it
 * calls ever becomes a function. Compiled by Open Watcom `wcc386` exactly like watprog/tailjmp
 * into a freestanding ELF32 (x86:LE:32:default). Gated in `ground_truth_parity.rs` (recall) +
 * `::data_pointer_function_discovery`.
 *
 * WHAT IT REPRODUCES — `war2-survey/analysis-gap/REPORT.md` §7: of 815 functions mosura misses on
 * WAR2, 783 have NO reference in mosura's own reference set at all, and mosura never disassembles
 * 24.7% of the code object (109,338 bytes in 23 regions >2KB). Those regions form a subgraph whose
 * members call each other but whose ONLY inbound edges from outside are DATA references — e.g.
 * region 00039bd4 is entered by DATA x11 + CALL x8, and 00010010 is DATA-referenced from 00083436
 * (inside the DATA object, above the code end 0x7C4A0). mosura's analyzer set has no
 * data-reference / address-table analysis, so those subgraphs are unreachable and no amount of
 * call-target or tail-call fixing reaches them.
 *
 * PROPERTIES THIS PROGRAM DEPENDS ON — do not "simplify" any of them away:
 *
 *  1. NOTHING calls tab_h0..tab_h3 or solo_target directly. Their address appears ONLY as the
 *     initializer of a data object. Add one direct call to any of them and plain call-target
 *     discovery creates it and the gate passes vacuously. This is the whole point: contrast with
 *     `fnptr.c`, which deliberately keeps direct calls so its targets stay call-reachable.
 *  2. ARM A is a RUN of four pointers (`g_table`) — the ADDRESS TABLE shape (Ghidra
 *     `AddressTable.getEntry` needs a run of >= minimumTableSize consecutive valid pointers).
 *     Shrinking it below the threshold turns arm A into arm B and stops testing the table path.
 *  3. ARM B is a LONE pointer (`g_solo`) — no run, so no address table can be formed. It is the
 *     single-function-pointer path (Ghidra `OperandReferenceAnalyzer.checkForPointer` ->
 *     `DataOperandReferenceAnalyzer`), which is how WAR2's 00010010 is reached.
 *  4. `deep_helper` is called ONLY from `tab_h0`, i.e. only from inside the data-reachable
 *     subgraph. It is the CASCADE assertion: recovering the pointed-to code must also recover
 *     what that code calls, which is the shape of WAR2's 1547 UNCONDITIONAL_CALL references into
 *     functions mosura never decoded.
 *  5. `g_table` and `g_solo` are NOT const — they live in the writable data section, like WAR2's
 *     tables, not in .rodata next to the code.
 *  6. The dispatch index is opaque to constant propagation (`i & 3` on a parameter), so the
 *     indirect call target cannot be resolved by mosura's existing SymbolicPropogator /
 *     ConstantPropagationAnalyzer path — the only way in is the data reference.
 *  7. Every OTHER function (dispatch, fire_solo, main, _cstart_) is genuinely call-reachable, so
 *     the recall assertion in `ground_truth_parity` isolates the data-only functions.
 *
 * PRE-FIX BEHAVIOUR (mosura `8a13977`): `ground_truth_parity` reports
 *     datafnptr: mosura missed call-reachable functions: [tab_h0..tab_h3, solo_target, deep_helper]
 * because mosura's analyzer set is {demangler, eh_frame, external_jump, noreturn, shared_return,
 * switch} — it has no data-operand-reference or address-table analysis at all. */

int g_acc;

typedef int (*handler)(int);

/* Property 4: reached only from tab_h0, which is itself reached only through the table. */
static int deep_helper(int x) {
    return x * 11 + g_acc;
}

/* --- ARM A: the address table (property 2). None of these four is called directly. --- */
static int tab_h0(int x) {
    g_acc += x;
    return deep_helper(x) + 1;
}
static int tab_h1(int x) {
    g_acc ^= x;
    return x * 3;
}
static int tab_h2(int x) {
    return x - g_acc;
}
static int tab_h3(int x) {
    return x + g_acc * 5;
}

/* Property 5: writable data, not .rodata. Property 2: a run of four pointers. */
static handler g_table[4] = { tab_h0, tab_h1, tab_h2, tab_h3 };

/* Property 6: `i & 3` keeps the selected slot unknown to constant propagation. */
int dispatch(int i, int x) {
    return g_table[i & 3](x);
}

/* --- ARM B: a lone function pointer in data (property 3). --- */
static int solo_target(int x) {
    g_acc -= x;
    return x ^ 0x33;
}

static handler g_solo = solo_target;

int fire_solo(int x) {
    return g_solo(x);
}

int main(void) {
    int a = dispatch(2, 5);
    int b = fire_solo(7);
    return a + b + g_acc;
}
