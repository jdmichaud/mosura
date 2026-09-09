/* Ground-truth corpus program: the second subject's INLINE CODE-POINTER TABLES
 * (docs/tasklist-2026-09-08.md item 12). The whole fixture is src/codetable_cstart.asm — a table
 * of code pointers inside the code segment, called through a scaled index, and an unguarded
 * indexed jump through another — because a C compiler puts its tables in data and guards its
 * switch index, and the shape under test is exactly that it does neither. This file only supplies
 * `main_`, which the entry stub calls last; it must stay trivial so that nothing here becomes a
 * second route to any routine the table owns (property 1 of the .asm). */

int main(void) {
    return 0;
}
