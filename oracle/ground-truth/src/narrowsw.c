/* Ground-truth corpus program (task #3 / war2-issues-become-source-tests). Open Watcom / x86-32
 * column, compiled by wcc386 into a freestanding ELF32 i386 (x86:LE:32:default) exactly like
 * watprog. It is the source-reduced repro of the unrecovered WAR2.EXE protected-mode switch
 * dispatches (`le_war2_analysis`, sites 0x513a8 / 0x58afb / 0x6af52 / 0x199b7): a dense `switch`
 * on a NARROWED (sub-`int`) value.
 *
 * The two functions form a differential control/gap pair Watcom compiles to jump tables:
 *   sw_int   — switch on a full 32-bit `int`   -> `cmp EAX,7; ja; jmp [EAX*4+table]`
 *   sw_short — switch on a narrowed 16-bit value -> `cmp AX,7; ja; movzx EAX,AX; jmp [EAX*4+table]`
 * The ONLY difference is the `movzx`/`and`-narrowing of the switch variable between the guard and
 * the table index — the exact shape WAR2 emits (`AND EAX,0xffff` / `AND EAX,0xff`) for a
 * `switch` on a `short`/`char`. mosura's decompiler recovers `sw_int` but NOT `sw_short` (0
 * jump-table targets); Ghidra's decompiler recovers BOTH (confirmed via the libdecomp oracle on
 * these exact bytes). So `sw_short` is a faithful-port GAP, filed for the decompiler lane in
 * docs/decompiler-bug-narrow-switch.md. The CS: segment prefix WAR2 carries is NOT the cause —
 * this flat ELF32 reproduces the miss without it.
 *
 * Built like watprog (hand-written `_cstart_`, no Watcom C run-time). See build.sh / build_watcom
 * + docs/ground-truth-corpus.md. */
int sw_int(int x) {
    switch (x) {
        case 0: return 11; case 1: return 12; case 2: return 13; case 3: return 14;
        case 4: return 15; case 5: return 16; case 6: return 17; case 7: return 18;
        default: return -1;
    }
}

int sw_short(int xx) {
    short x = (short)xx;
    switch (x) {
        case 0: return 11; case 1: return 12; case 2: return 13; case 3: return 14;
        case 4: return 15; case 5: return 16; case 6: return 17; case 7: return 18;
        default: return -1;
    }
}

int main(void) { return sw_int(3) + sw_short(5); }
