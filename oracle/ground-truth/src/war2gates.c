/* Ground-truth corpus program (war2-issues-become-source-tests): the source-reduced repro of the
 * decompiler PANIC the WAR2.EXE recompilation survey exposed (docs/war2-function-status.md —
 * all 117 DECOMPILE_FAILs were this one bug). Compiled by Open Watcom `wcc386` exactly like
 * watprog/narrowsw into a freestanding ELF32 (x86:LE:32:default). Gated in
 * `ground_truth_parity.rs::war2_trim_shape_no_panic`.
 *
 * PRIMARY — trim_shape — Stage 0 (`b6ec467`, docs/decompiler-bug-merge-indirect-trim-panic.md):
 *   the source-reduced mimic of WAR2 `FUN_00011954` (the survey's first panic): THREE sequential
 *   register-arg calls in one block, two results stored to globals, EDX callee-saved across all
 *   of them. The chained call-guard INDIRECTs force merge-marker's non-MULTIEQUAL trim — the
 *   `Merge::trimOpInput` branch whose partial port panicked (`in_edges[slot]` OOB in the entry
 *   block). PROVEN against the toolchain: pre-fix mosura (`ef65486`) panics at merge.rs:1205 on
 *   exactly this compiled shape; the single-call variant does NOT trigger it. wcc386 lowers it to
 *   WAR2's opcode sequence (push edx / mov+call x3 / mov-to-global x2 / pop edx / ret; only the
 *   10.0a `ebp` frame is absent under ow2).
 *
 * The other two functions are realistic call-graph context that also exercises the Stage-1
 * (`__watcall` register params) and Stage-2 (`in`/`out` -> CALLOTHER userop) code paths, but are
 * NOT output-gated here (isolated per-function decompile of tiny leaf functions is inherently
 * noisy; those two stages carry their own unit-test regressions in merge/printc):
 *   - add3   — three int params -> EAX/EDX/EBX under __watcall.
 *   - port_io — raw port IO via `#pragma aux` -> `in`/`out` SLEIGH userops (CALLOTHER).
 *
 * The Watcom run-time banner below is embedded verbatim because `loader::watcom::detect` keys on
 * it (WAR2 carries it via the CRT; these CRT-less fixtures let the banner constant stand in —
 * same bytes, same detection path). */

/* The exact 10.0a-era banner (loader/watcom.rs test oracle) — DATA, never executed. */
const char watcom_banner[] =
    "WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. "
    "All rights reserved.";

int shared_g1, shared_g2;

extern void take1(int x);
extern int give1(int x);
extern int give2(int x, int y);

/* 1. Stage-0 shape (mimics WAR2 FUN_00011954): three calls, two global stores, one block. */
void trim_shape(void) {
    take1(0x11920);
    shared_g1 = give1(0xfc8);
    shared_g2 = give2(0xfc8, 0x2b);
}

/* 2. Stage-2 shape: raw port IO -> `in`/`out` userops (CALLOTHER). */
unsigned char port_in(unsigned short port);
#pragma aux port_in = "in al,dx" parm [dx] value [al];
void port_out(unsigned short port, unsigned char v);
#pragma aux port_out = "out dx,al" parm [dx] [al];

unsigned char port_io(void) {
    unsigned char v = port_in(0x3da);
    port_out(0x3c8, v);
    return v;
}

/* 3. Stage-1 shape: three int params -> EAX/EDX/EBX under __watcall. */
int add3(int a, int b, int c) {
    return a + b * 2 + c * 3;
}

/* Callees are real (write the globals) so the calls genuinely clobber them. */
void take1(int x) { shared_g1 += x; }
int give1(int x) { return x + shared_g1; }
int give2(int x, int y) { return x * y + shared_g2 + (int)watcom_banner[0]; }

int main(void) {
    shared_g1 = 1;
    trim_shape();
    return shared_g1 + shared_g2 + add3(1, 2, 3) + (int)port_io();
}
