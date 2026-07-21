/* Ground-truth corpus program (task #3), Open Watcom / x86-32 column. Compiled by wcc386 (a
 * non-gcc compiler, register `__watcall` convention), linked into a freestanding 32-bit ELF
 * (EM_386, x86:LE:32:default). A small call graph + a dense switch. The entry is a hand-written
 * `_cstart_` stub (watprog_cstart.asm) that just calls main — no Watcom C run-time is linked, so
 * the truth stays small and reviewable (unlike a full `system linux`/`dos4g` CRT). See
 * docs/ground-truth-corpus.md for the wcc386 + wasm + wlink + objcopy pipeline. */
int op_add(int a, int b) { return a + b; }
int op_mul(int a, int b) { return a * b; }

int classify(int x, int y) {
    switch (x) {
        case 0: return y + 1;
        case 1: return y + 2;
        case 2: return y * 3;
        case 3: return y - 4;
        case 4: return y ^ 5;
        case 5: return y << 1;
        case 6: return y | 6;
        case 7: return y & 7;
        default: return -1;
    }
}

int main(void) {
    int s = 0, i;
    for (i = 0; i < 8; i++) s += classify(i, s) + op_add(i, s) + op_mul(i, s);
    return s;
}
