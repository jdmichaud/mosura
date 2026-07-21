/* Ground-truth corpus program (task #3), Zilog Z80 / CP/M .COM column. sdcc (a non-gcc, 16-bit
 * compiler) + a raw flat image (no ELF container) — mosura loads it via load_com. A small call
 * graph + a dense switch that sdcc lowers to a `jp (hl)` jump table. `main` stores the results
 * to a global so no call becomes a tail-jump (which flow analysis would fold into the caller, as
 * it faithfully does for a `.cold` split). Truth for this column is derived from sdcc's OWN
 * linker map (functions) + relocated listing (the switch dispatch) — nm/objdump don't apply to a
 * raw z80 image; see docs/ground-truth-corpus.md. */
unsigned char helper(unsigned char x) { return (unsigned char)(x + x + 1); }

unsigned char compute(unsigned char *arr, unsigned char n) {
    unsigned char acc = 0, i;
    for (i = 0; i < n; i++) acc += helper(arr[i]);
    return acc;
}

unsigned char classify(unsigned char x, unsigned char y) {
    switch (x) {
        case 0: return y + 1;
        case 1: return y + 2;
        case 2: return y + 3;
        case 3: return y + 4;
        case 4: return y + 5;
        case 5: return y + 6;
        case 6: return y + 7;
        case 7: return y + 8;
        default: return 0;
    }
}

unsigned char data[3] = {1, 2, 3};
unsigned char result;

void main(void) {
    unsigned char r = compute(data, 3);
    r = (unsigned char)(r + classify(data[0], data[1]));
    result = r;
}
