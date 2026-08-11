/* Ground-truth repro: a parameter passed ON THE STACK, which mosura recovers as an
 * UNINITIALISED LOCAL instead.
 *
 * Measured on WAR2 FUN_0006aec4, whose whole body is
 *
 *     8b 44 24 04    mov eax,[esp+4]      <- the parameter
 *     8b 00          mov eax,[eax]
 *     c1 e8 08       shr eax,8
 *     c3             ret
 *
 * and which mosura emits as
 *
 *     uint4 FUN_0006aec4(void) { uint4 * puStack00000004; return *puStack00000004 >> 8; }
 *
 * — a read of a local that is never assigned. The name even encodes the stack offset, so the
 * location is known; what is missing is classifying it as a PARAMETER.
 *
 * The convention is not the problem: specs/x86-32-watcom.cspec already declares the stack
 * overflow slot as parameter storage —
 *
 *     <pentry minsize="1" maxsize="500" align="4"><addr offset="4" space="stack"/></pentry>
 *
 * so `possible_param` should accept it. ~100 functions in the WAR2 survey read a `Stack<offset>`
 * value they never assign.
 *
 * Properties this program depends on — do not "simplify" them away:
 *   1. `parm []` on the callee forces the argument ONTO THE STACK. Without it __watcall passes it
 *      in EAX and the register path (which already works) is what gets tested.
 *   2. the parameter must be READ and returned, so a failure shows up as a use of an undefined
 *      value rather than as a missing-but-unused declaration.
 *   3. `take` is called from `main` so the call site exists and the function is not dead.
 */
const char stackarg_banner[] =
    "WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. "
    "All rights reserved.";

int g_sink;

/* `parm []` = every argument on the stack, callee pops (so the body ends `ret 4`). */
int take(int a);
#pragma aux take parm [] modify [eax];

int take(int a) { return a + 1; }

int main(void) {
    g_sink = take((int)stackarg_banner[0]);
    return g_sink;
}
