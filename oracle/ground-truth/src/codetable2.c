/* Ground-truth corpus program: the FOLLOW-ON to item 12 — the two closure gaps
 * (docs/tasklist-2026-09-08.md §12) the "Switch Table References" port left once it recovered the
 * tables themselves. The whole fixture is src/codetable2_cstart.asm (a table entry whose first
 * instruction is a call, and a switch nested inside an arm of another switch — neither expressible
 * in C). This file supplies only `main_`, trivial so nothing here becomes a second route to any
 * routine the tables own. */

int main(void) {
    return 0;
}
