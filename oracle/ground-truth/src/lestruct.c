/* Ground-truth corpus program (issues-become-source-tests (subject-profile note)) — the LE-format MVE for
 * DATA-POINTER SEEDING, and the ONLY fixture in the corpus built as a Linear Executable.
 *
 * WHAT IT REPRODUCES. `datafnptr` covers a RUN of function pointers, which Ghidra's
 * AddressTableAnalyzer finds. This covers the case that no run-of-pointers heuristic can ever
 * find: a pointer stored ALONE, between non-pointer struct fields. Only the linker's fixup
 * table knows it is a pointer — and Ghidra never gets that table for the subject, because the LE->ELF
 * conversion it is fed bakes the patched values in and discards the records.
 *
 * NEGATIVE RESULT THAT MADE THIS FILE NECESSARY — do not "simplify" it back. The obvious MVE
 * (`datafnptr` rebuilt as an LE) PASSES unfixed: the address-table analyzer handles a pointer
 * run in LE memory exactly as it does in ELF. A gate that passes before the fix is decoration.
 * This program closes THREE mechanisms at once so that only the fixup table remains:
 *
 *  1. NO ADJACENT POINTER WORDS. `struct node { int tag; handler fn; }` interleaves each pointer
 *     with a tag, so no two pointer-sized words are ever adjacent and `AddressTable.getEntry`
 *     can never accumulate a run. Verified in the built image:
 *       0b000000 | 10000100 | 16000000 | 1d000100 | 21000000 | 27000100
 *  2. TAGS BELOW `MINIMUM_SAFE_ADDRESS` (1024). 11/22/33 break the run immediately even if the
 *     alignment happened to line up.
 *  3. THE CALL IS OPAQUE TO CONSTANT PROPAGATION. `g_nodes[i & 3].fn(x)` — the slot is chosen at
 *     runtime, so the COMPUTED_CALL path cannot resolve it either (that path is what already
 *     recovers `datafnptr`'s lone `g_solo` pointer).
 *
 * `deep_le` is called ONLY from `h0`, which is itself reachable only through a stored pointer:
 * the CASCADE assertion. It is classed `code` in the truth, so the GENERIC recall gate demands
 * it — that is the assertion that actually matters, since h0/h1/h2 themselves must NOT become
 * functions (see ghidra-never-makes-functions-from-data-pointers / datafnptr.c).
 *
 * The functions are non-static so the Watcom linker map lists them: the LE format carries no
 * symbol table, so the truth is derived from wlink's own map plus the LE object bases, exactly
 * as the z80 column derives its truth from sdcc's map.
 *
 * PRE-FIX BEHAVIOUR (mosura `3002257`): mosura recovers only
 *   [00010000 _cstart_, 0001002e run_, 00010041 main_]  -- 17 code units,
 * with 0x10006..0x1002d (deep_le, h0, h1, h2) entirely undisassembled. */

int g_acc;

typedef int (*handler)(int);

int deep_le(int x);
int h0(int x);
int h1(int x);
int h2(int x);

int deep_le(int x) { return x * 13 + g_acc; }

int h0(int x) { g_acc += x; return deep_le(x) + 1; }
int h1(int x) { g_acc ^= x; return x * 3; }
int h2(int x) { return x - g_acc; }

/* Each pointer is ISOLATED between small non-pointer ints, so no two pointer-sized words are
 * ever adjacent -> no run of >= minimumTableSize pointers -> AddressTable.getEntry can never
 * form a table here. The tags are < MINIMUM_SAFE_ADDRESS (1024), so they break the run. */
struct node {
    int tag;
    handler fn;
};
struct node g_nodes[3] = { { 11, h0 }, { 22, h1 }, { 33, h2 } };

/* Indexed indirect call through the struct array: the selected slot is opaque to constant
 * propagation, so the COMPUTED_CALL path cannot resolve it either. */
int run(int i, int x) { return g_nodes[i & 3].fn(x); }

int main(void) { return run(1, 5) + g_acc; }
