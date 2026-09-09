/* Ground-truth corpus program: the data-held-pointer FOLLOW-ON to item 12
 * (docs/tasklist-2026-09-08.md §12). The second subject's menu/record handlers are reached only
 * table -> record -> field: a code pointer stored as a FIELD inside a data record, indexed at
 * runtime, so no instruction ever carries the field's address and nothing references it. On that
 * subject (an X-32 flat image) there are no relocations either, so neither the address-table
 * analyzer (no run of adjacent pointers), nor the constant propagator (the index is opaque), nor
 * relocation_seed (no fixups) can reach them. Only a scan of the data for a pointer-sized word
 * whose value is valid code finds them — and Ghidra deliberately makes no function from a data
 * pointer, so this needs the `analysis.data-pointer-functions` deviation.
 *
 * This fixture reproduces that on a freestanding Watcom ELF, whose `relocations` table is empty
 * (link-time-resolved, fixed base) — the no-fixup condition that makes it a clean test of the
 * SCAN, not of relocation_seed. Properties, do not simplify away:
 *  1. The handler is a FIELD between non-pointer fields (`{ int tag; handler fn; int arg; }`), so
 *     no two pointer-sized words are adjacent — the address-table run heuristic cannot form here.
 *  2. `tag` is < MINIMUM_SAFE_ADDRESS (1024), breaking any run that did line up.
 *  3. The dispatch indexes the record array (`g_recs[i & 1].fn`), which mosura's constant
 *     propagator does not fold to a specific element — so the COMPUTED_CALL path cannot resolve it
 *     (the path that already recovers datafnptr's lone `g_solo`). No static reference lands on a
 *     field.
 *  4. `deep_ds` is called ONLY from `rec_h0`, which is itself reached only through a stored field:
 *     the cascade — recovering the field's target must recover what it calls.
 *  5. The records are writable data, not .rodata.
 *
 * PRE-FIX: rec_h0, rec_h1, deep_ds are absent (no run, no ref, no fixup, opaque index). With the
 * option on, the scan makes rec_h0/rec_h1 functions and deep_ds follows by the direct-call cascade. */

int g_acc;

typedef int (*handler)(int);

int deep_ds(int x);
int rec_h0(int x);
int rec_h1(int x);

int deep_ds(int x) { return x * 7 + g_acc; }

int rec_h0(int x) { g_acc += x; return deep_ds(x) + 1; }
int rec_h1(int x) { return x * 3; }

/* Property 1: the pointer sits between non-pointer fields, isolated. Property 2: tag < 1024. */
struct rec {
    int tag;
    handler fn;
    int arg;
};

/* Property 5: writable. Nothing calls rec_h0/rec_h1 directly; their address lives only here. */
struct rec g_recs[2] = { { 11, rec_h0, 100 }, { 22, rec_h1, 200 } };

/* Property 3: g_recs[i & 1].fn — an indexed field, opaque to constant propagation. */
int dispatch_ds(int i) { return g_recs[i & 1].fn(g_recs[i & 1].arg); }

int main(void) { return dispatch_ds(g_acc); }
