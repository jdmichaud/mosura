/* A8 bug-hunt: struct bitfields (mask/shift lowering) + union type-punning. */
#include "shim.h"
struct flags { unsigned a : 3, b : 5, c : 8, d : 16; };
union punned { unsigned u; struct flags f; };
__attribute__((noinline)) static int pack(unsigned x) {
    struct flags f;
    f.a = x & 7; f.b = (x >> 3) & 31; f.c = (x >> 8) & 255; f.d = (x >> 16);
    return f.a + f.b * 2 + f.c * 3 + f.d * 4;
}
__attribute__((noinline)) static int pun(unsigned x) {
    union punned u; u.u = x;
    return u.f.a + u.f.c + u.f.d;
}
void _start(void) {
    volatile unsigned v = 0x1234abcd;
    long r = pack(v) + pun(v);
    sys_exit(r);
}
