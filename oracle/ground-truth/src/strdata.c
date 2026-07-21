/* Ground-truth corpus program (task #3): string / data references. A `.rodata` table of string
 * constants + helpers that walk them, so the build carries real string data referenced from code
 * (address-of-string operands). A clean oracle that data references are NOT mis-analyzed as code
 * (0 spurious) while the call graph is fully recovered. Freestanding + per-arch exit shim. */
#include "shim.h"

static const char msg0[] = "alpha";
static const char msg1[] = "bravo";
static const char msg2[] = "charlie";
static const char *const names[3] = { msg0, msg1, msg2 };

__attribute__((noinline)) static int slen(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}
__attribute__((noinline)) static int checksum(const char *s) {
    int c = 0;
    for (int i = 0; s[i]; i++) c += (unsigned char)s[i];
    return c;
}
__attribute__((noinline)) static int total(void) {
    int t = 0;
    for (int i = 0; i < 3; i++) t += slen(names[i]) + checksum(names[i]);
    return t;
}

void _start(void) {
    long r = total();
    sys_exit(r);
}
