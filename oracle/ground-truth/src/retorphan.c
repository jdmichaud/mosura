/* Ground-truth corpus program (war2-issues-become-source-tests): the source-reduced repro of the
 * ABOVE-FUNCTION GUARD mis-port fixed in `be85c85` — `checkAlreadyInFunctionAbove` must veto on
 * FALL-THROUGH, not on ADJACENCY, so a function whose prologue sits one byte past someone else's
 * `ret` is still a function. Compiled by Open Watcom `wcc386` into a freestanding ELF32
 * (x86:LE:32:default) and gated by `ground_truth_parity.rs` (recall) +
 * `::above_function_guard_tests_fall_through`.
 *
 * WHAT IT REPRODUCES — Ghidra `FunctionStartAnalyzer.java:512`:
 *
 *     Instruction instr = program.getListing().getInstructionContaining(addrBefore);
 *     if (instr != null && addr.equals(instr.getFallThrough())) { return true; }
 *
 * `getFallThrough()` is null after a `ret`, so Ghidra does not veto. mosura tested only that an
 * instruction ENDED at the address, so it refused every pattern-proposed prologue that merely
 * FOLLOWED an epilogue. Measured on WAR2: 6 tracker functions sit immediately after a
 * `pop…pop; ret` with no function recognised above them, were proposed by the pattern set, and
 * were refused here; the fix moved the run 2900 -> 3018 functions, missing-vs-tracker 42 -> 12,
 * body intrusions unchanged at 3.
 *
 * WHY THE GUARD'S `funcAbove == None` ARM IS HARD TO REACH, and what this program does about it.
 * `checkAlreadyInFunctionAbove` has two arms. When a function IS recognised above, the first arm
 * answers `getFunctionContaining(addr) == funcAbove` and the fall-through test never runs. Only
 * when NOTHING above is a function does control reach :512. So the byte before the candidate must
 * be a DECODED INSTRUCTION THAT BELONGS TO NO FUNCTION — and an earlier attempt at this fixture
 * (`retboundary`) died precisely there: with a single stored function pointer the preceding block
 * is never disassembled at all, `getCodeUnitContaining` is null, the arm never runs, and the
 * orphan is found with the fix and without it. A gate that cannot fail.
 *
 * PROPERTIES THIS PROGRAM DEPENDS ON — do not "simplify" any of them away:
 *
 *  1. `orphan_fn_` is called from NOWHERE and its address is stored NOWHERE. It is not `static`
 *     (wcc386 would drop it) and the asm stub does not name it. Only its prologue BYTES can find
 *     it. Adding any reference makes the gate pass vacuously.
 *
 *  2. IT IS BUILT WITH THE CORPUS DEFAULT `-oc`, NOT `-of+`, and that is the opposite choice from
 *     `fnpattern.c` for the opposite reason. The flag selects which pattern family matches, and
 *     only one of the two routes reaches the guard:
 *
 *       -oc (this)  `56 57 55 83 ec 14`   push esi/edi/ebp ; sub esp,0x14
 *                   matched ONLY by the ESP-frame family, EVERY member of which carries
 *                   `funcstart after="defined"` — and `checkAfterName`'s "defined" arm (:437) is
 *                   what calls `checkAlreadyInFunctionAbove`. This is the route under test.
 *       -of+        `55 89 e5 …`          push ebp ; mov ebp,esp
 *                   matched by the UNGUARDED frame-first family, which has no `after=`, so
 *                   `applyActionToSet` adds the address without ever consulting the guard.
 *
 *     MEASURED, both flags, both sides of the fix — this is not a reasoned claim:
 *
 *                     fix in place        `be85c85` reverted
 *       -oc (this)    recovered           NOT recovered      <- the fixture bites
 *       -of+          recovered           recovered          <- vacuous, measures nothing
 *
 *     The prerequisite IS the test. Rebuild this program with `-of+` and it still passes, still
 *     looks like a function-start gate, and has stopped gating anything.
 *
 *  3. `tab_h0..tab_h3` are reachable ONLY through the 4-entry pointer run `g_table` (the
 *     `datafnptr` shape). `AddressTableAnalyzer` disassembles a table's targets and deliberately
 *     creates NO function at them (AddressTableAnalyzer.java:282 "For Now, Never make functions
 *     from address tables"), which is exactly the decoded-but-not-a-function state the guard's
 *     second arm needs. The RUN is load-bearing: `AddressTable.getEntry` needs
 *     >= minimumTableSize consecutive valid pointers, and a lone pointer takes the
 *     `DataOperandReferenceAnalyzer` path instead, which is what left `retboundary` undecoded.
 *
 *  4. `tab_h3` immediately precedes `orphan_fn` in source order, which wcc386 preserves as
 *     emission order with no padding between functions, so `tab_h3`'s `ret` ends at EXACTLY the
 *     orphan's entry address. Adjacency is the whole premise; anything inserted between them
 *     (another function, alignment filler) turns the preceding byte into something else and the
 *     "defined" prerequisite fails for an unrelated reason.
 *
 *  5. EVERY HANDLER USES ITS OWN GLOBAL (`g0`..`g3`) AND `trail_fn` USES NONE. This is not
 *     cosmetic. Measured while building this fixture: when `tab_h2` (`x - g_acc`) and `trail_fn`
 *     (`x * 3 - g_acc`) shared the trailing `sub g_acc ; ret`, wcc386 folded the tails, the
 *     table's third entry pointed OFFCUT into `trail_fn`, `AddressTable.checkTable` trimmed the
 *     table there, and `tab_h3` was never disassembled — so the orphan was refused even WITH the
 *     fix. Give any two of these functions a common tail and the fixture stops measuring.
 *
 *  6. `tab_h3`'s own prologue (`52 8b 15 …`) matches no pattern in `x86watcom_patterns.xml`, so
 *     the pattern search does not create a function at it. If it did, `funcAbove` would be `Some`
 *     and the run would take the first arm instead — the same silent drift as (2).
 *
 *  7. The orphan's body is long enough to satisfy the ESP-frame family's `validcode="6"`
 *     post-requirement (six valid fall-through instructions); the four spilled locals and the
 *     loop guarantee it.
 *
 *  8. The orphan CALLS `trail_fn`, so "did this become a function?" stays distinguishable from
 *     "were these bytes decoded?".
 *
 * PRE-FIX BEHAVIOUR (`be85c85` reverted, measured on this exact binary): `orphan_fn_` @0804812c
 * is absent from the function set — `ground_truth_parity` reports it as a missed call-reachable
 * function — while `tab_h0..tab_h3` stay decoded-and-in-no-function identically. That is the only
 * difference: the fix changes nothing else about this program.
 */

int g0, g1, g2, g3, g4;

typedef int (*handler)(int);

int trail_fn(int x);

/* --- The address table's four targets (property 3). None is called directly; each has its own
 *     global (property 5) and a prologue no pattern matches (property 6). --- */
static int tab_h0(int x) { return x * 11 + g0; }
static int tab_h1(int x) { return x ^ g1; }
static int tab_h2(int x) { return x - g2; }
/* Property 4: this one's `ret` must land exactly on the orphan's entry. */
static int tab_h3(int x) { return x + g3 * 5; }

/* THE ORPHAN (properties 1, 2, 7, 8). Never called, address never taken, and it begins one byte
 * after `tab_h3`'s `ret` — an instruction that belongs to no function. */
int orphan_fn(int a, int b, int c, int d) {
    int buf[4];
    int i, s = 0;
    buf[0] = a;
    buf[1] = b;
    buf[2] = c;
    buf[3] = d;
    for (i = 0; i < 4; i++) {
        s += buf[i] * (i + 1);
        s ^= trail_fn(buf[i]);
    }
    return s + a * b + c * d + g4;
}

/* Property 3: a RUN of four pointers, in writable data. */
static handler g_table[4] = { tab_h0, tab_h1, tab_h2, tab_h3 };

/* `i & 3` keeps the selected slot opaque to constant propagation, so the only way into the
 * handlers is the data reference. */
int dispatch(int i, int x) { return g_table[i & 3](x); }

/* Property 5: no global, so it cannot share a tail with any handler. */
int trail_fn(int x) { return x * 3; }

int main(void) { return dispatch(1, 2) + trail_fn(3); }
