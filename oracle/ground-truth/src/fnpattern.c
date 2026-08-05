/* Ground-truth corpus program (war2-issues-become-source-tests): the source-reduced repro of the
 * FUNCTION START SEARCH gap — a function that NOTHING references is invisible to every
 * reference-driven analyzer mosura has, and can only be found by recognising its PROLOGUE BYTES.
 * Compiled by Open Watcom `wcc386` into a freestanding ELF32 (x86:LE:32:default), and gated by
 * `ground_truth_parity.rs` (recall) + `::function_start_pattern_search`.
 *
 * WHAT IT REPRODUCES — Ghidra's four `Function Start Search` analyzers
 * (`FunctionStartAnalyzer` + the Pre/AfterCode/AfterData subclasses, driven by
 * `ghidra.util.bytesearch` over `Processors/x86/data/patterns/*.xml`). On WAR2 they are worth 243
 * functions that no other pass reaches. Every other discovery route mosura has needs an inbound
 * edge: a direct call, a shared-return `jmp` (`tailjmp`), a pointer run in data (`datafnptr`), or
 * an LE fixup slot (`lestruct`). `orphan_fn_` has none of those — the ONLY thing that says
 * "a function starts here" is the byte pattern of its prologue.
 *
 * PROPERTIES THIS PROGRAM DEPENDS ON — do not "simplify" any of them away:
 *
 *  1. `-of+` (generate traceable stack frames) is passed instead of the corpus default `-oc`.
 *     That is not a tuning knob — it selects WHICH of Watcom's two prologue shapes the orphan
 *     gets, and only one of them is gateable here. Measured on this exact source, all three
 *     settings:
 *
 *       -of+       `55 89 e5 56 57 83 ec 18`      push ebp; mov ebp,esp; push esi; push edi; sub
 *       -oc (dflt) `56 57 55 83 ec 14`            push/push/push; sub esp   (no `mov ebp,esp`)
 *       -od        `56 57 55 89 e5 81 ec 2c ..`   SAVE-FIRST: pushes, THEN the frame setup
 *
 *     The `-od` shape is WAR2's own (0x16ed4 = `53 51 52 56 57 55 89 e5 83 ec 04`), and it is the
 *     shape that SHIFTS: Ghidra's `x86gcc_patterns.xml` has no pattern starting at a push run, so
 *     its `0x5589e583ec` anchors at the `55`, N bytes past the true entry. That defect is real and
 *     is fixed by mosura's Watcom pattern set (`specs/patterns/x86watcom_patterns.xml`) — but it
 *     CANNOT be gated by this corpus, because no ground-truth binary reaches the `watcom`
 *     compiler spec: mosura detects Watcom from the run-time copyright banner
 *     (`loader/watcom.rs`), and these freestanding ELFs link no Watcom CRT, so their
 *     `CompilerOpinion` is `gcc`. Verified end to end with Ghidra on the `-od` build of this very
 *     program: Ghidra creates a function at `orphan_fn_ + 2` and none at `orphan_fn_`. The shift
 *     is instead gated by a differential over the two real pattern files, in
 *     `analysis::analyzers::function_start::tests::save_first_prologue_marks_the_first_push`.
 *
 *     With `-of+` the orphan is frame-first, which `x86gcc_patterns.xml` marks EXACTLY (its
 *     `0x5589e5 01010... 01010...` and `0x5589e5....83ec` both fire at offset 0), so this fixture
 *     gates the DISCOVERY mechanism — the half that is reachable from here.
 *
 *  2. `orphan_fn_` is called from NOWHERE and its address is stored NOWHERE. It is not `static`
 *     (wcc386 would drop it) and it is not referenced from the asm stub. Adding any reference —
 *     even a data pointer — makes the gate pass vacuously through `datafnptr`'s route.
 *
 *  3. It sits BETWEEN two ordinarily-called functions (`lead_fn_` before, `trail_fn_` after), in
 *     source order, which wcc386 preserves as emission order. So it is not at a block edge where
 *     a linear sweep could stumble into it, and it is preceded by `lead_fn_`'s `ret` — nothing
 *     falls through into it, which is also what Ghidra's `funcstart after="defined"` pre-requisite
 *     needs to see (an instruction, then a new function).
 *
 *  4. Its body is long enough to satisfy the pattern files' `validcode="6"` post-requirement
 *     (six valid fall-through instructions) — the loop and the four spilled locals guarantee that.
 *
 *  5. `orphan_fn_` calls `lead_fn_`, so its body contains a real call: that is what makes the
 *     "did this become a function?" question distinguishable from "were these bytes decoded?".
 *
 * PRE-FIX BEHAVIOUR (mosura `c567bca`): `ground_truth_parity` reports
 * `fnpattern: mosura missed call-reachable functions: ["08048120"]` — the orphan is absent
 * entirely, and its bytes are never even disassembled. The same red state is reproducible at any
 * time with `MOSURA_DISABLE_ANALYZERS="Function Start Pre Search,Function Start Search,Function
 * Start Search After Code,Function Start Search After Data"`.
 */

int g_acc;

int lead_fn(int x);
int orphan_fn(int a, int b, int c, int d);
int trail_fn(int x);

/* Ordinary called function; its `ret` is what immediately precedes the orphan (property 3). */
int lead_fn(int x) {
    g_acc += x;
    return g_acc;
}

/* THE ORPHAN (properties 2-5). Never called, address never taken. */
int orphan_fn(int a, int b, int c, int d) {
    int buf[4];
    int i, s = 0;
    buf[0] = a;
    buf[1] = b;
    buf[2] = c;
    buf[3] = d;
    for (i = 0; i < 4; i++) {
        s += buf[i] * (i + 1);
        s ^= lead_fn(buf[i]);
    }
    return s + a * b + c * d + g_acc;
}

/* Ordinary called function immediately after the orphan (property 3). */
int trail_fn(int x) {
    return x * 3 + g_acc;
}

int main(void) {
    return lead_fn(1) + trail_fn(2);
}
