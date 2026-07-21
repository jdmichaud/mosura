/* Ground-truth corpus (A7 bug-hunt): struct-by-value arguments + struct return (small structs
 * pass/return in registers on the SysV/AAPCS ABIs). */
#include "shim.h"
struct pt { int x, y; };
__attribute__((noinline)) static struct pt mk(int a, int b) { struct pt p = { a, b }; return p; }
__attribute__((noinline)) static int dot(struct pt p, struct pt q) { return p.x * q.x + p.y * q.y; }
void _start(void) {
    struct pt p = mk(3, 4), q = mk(5, 6);
    long r = dot(p, q);
    sys_exit(r);
}
