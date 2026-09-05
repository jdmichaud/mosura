/* Ground-truth corpus program (issues-become-source-tests (subject-profile note)): the source-reduced repro of the
 * NO-FRAME PROLOGUE gap — a callee-save push run followed by neither a frame setup nor a stack
 * adjust, which is what `wcc386` emits BY DEFAULT (`-of+` is what turns the frame pointer ON).
 * Compiled by Open Watcom `wcc386` into a freestanding ELF32 (x86:LE:32:default), gated by
 * `ground_truth_parity.rs` (recall) + `::no_frame_prologue_family`.
 *
 * ⚠️ READ THIS BEFORE ASSUMING THE GAP IS "NO FRAME". It is not. Measured against the committed
 * `x86watcom_patterns.xml` with the real matcher: family (3), the ESP-frame family, ALREADY covers
 * a push run followed by `sub esp` in both encodings — 4 of the 7 the subject entries that motivated this
 * work match it at offset 0, and `retorphan`'s no-frame orphan (`56 57 55 83 ec 14`) is already
 * recovered by it. What is unmodelled is the push run followed by something OTHER than a stack
 * adjust. This program pins exactly those follow-ons and nothing wider.
 *
 * THE THREE ORPHANS, and the shape each one pins (all verified against the emitted bytes):
 *
 *   nf_stackarg   56 57 55 8b 6c 24 10   push esi,edi,ebp ; mov ebp,[esp+0x10]
 *   nf_stackarg2  56 57 8b 7c 24 0c      push esi,edi     ; mov edi,[esp+0xc]
 *   nf_absload    53 51 52 8b 0d <abs32> push ebx,ecx,edx ; mov ecx,[abs32]
 *
 * The first is the subject `0004de58` (`56 57 55 8b 4c 24 10`) to the register nibble; the third is the subject
 * `00064427` (`52 8b 15 <abs32>`) with a longer run. So the corpus reproduces the tracker's own
 * shapes rather than an approximation of them.
 *
 * PROPERTIES THIS PROGRAM DEPENDS ON — do not "simplify" any of them away:
 *
 *  1. REGISTER PRESSURE IS LOAD-BEARING. A naive 5-argument function needs no callee-saves at all
 *     and opens with `imul` — measured, and it is why the first attempt at this fixture produced
 *     no push run whatsoever. Each orphan therefore keeps four or more simultaneously-live
 *     temporaries. Simplify the arithmetic and the prologue disappears along with the test.
 *  2. NO CALLS. A call would force a frame under some settings and would also make the orphan
 *     reachable if the callee were reachable; these are leaf functions on purpose.
 *  3. The orphans are called from NOWHERE and their addresses are stored NOWHERE, and they are not
 *     `static` (wcc386 would drop them). Only their prologue BYTES can find them.
 *  4. BUILT WITH THE CORPUS DEFAULT `-oc` — no `-of+`. That flag is what turns the frame pointer
 *     ON, so passing it replaces every shape here with `55 89 e5 …` and the program stops
 *     reproducing anything. This is the same flag-is-the-test property `retorphan.c` records.
 *  5. `nf_absload` takes NO argument, so its first act is genuinely an absolute load rather than a
 *     register move. Give it a parameter and the compiler opens with `mov` instead.
 *
 * DELIBERATELY NOT COVERED, and this is a decision rather than an oversight:
 *  - A push run followed by a REGISTER-TO-REGISTER `mov` (`56 57 55 89 d6`). It occurs — an
 *    earlier draft of this very program emitted it — but `89 xx` is ubiquitous mid-function, so a
 *    pattern that wide trades precision for recall on a file that has no Ghidra oracle to check it
 *    against. That shape stays missed.
 *  - the subject `00072f08`'s `51 52 c8 1c 00 00` (`enter 0x1c,0`). No Open Watcom v2 build available here
 *    emits `enter`, so it cannot be gated from source; and `enter` IS a frame setup
 *    (`push ebp ; mov ebp,esp ; sub esp,imm`), so it belongs with the framed shapes anyway.
 */

int g0, g1, g2, g3;

/* ORPHAN 1 — 3-push run then a stack-argument load. Five args put the fifth on the stack; the
 * four live temporaries force esi/edi/ebp to be saved (property 1). */
int nf_stackarg(int a, int b, int c, int d, int e) {
    return e * a + e * b + e * c + e * d + (a ^ b) * (c ^ d);
}

/* ORPHAN 2 — the same follow-on behind a SHORTER (2-push) run, so the family is pinned at more
 * than one run length. Six args, two of them on the stack. */
int nf_stackarg2(int a, int b, int c, int d, int e, int f) {
    return e * f + a * b + c * d + (e ^ a) * (f ^ b);
}

/* ORPHAN 3 — push run then an ABSOLUTE load. No parameter (property 5), so nothing arrives in a
 * register and the first act must touch memory. */
int nf_absload(void) {
    return g0 * g1 + g2 * g3 + (g0 ^ g3) * (g1 ^ g2);
}

/* Ordinary called functions, so the orphans sit between real code rather than at a block edge. */
int lead_fn(int x) { g0 += x; return g0; }
int trail_fn(int x) { return x * 3; }

int main(void) { return lead_fn(1) + trail_fn(2); }
