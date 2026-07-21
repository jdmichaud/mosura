/* A8 bug-hunt: 64-bit multiply / divide / modulo / rotate (64-bit-wide arithmetic). */
#include "shim.h"
__attribute__((noinline)) static long mul64(long a, long b) { return a * b; }
__attribute__((noinline)) static long divmod64(long a, long b) { return a / b + a % b; }
__attribute__((noinline)) static unsigned long rot64(unsigned long a, int s) { return (a << s) | (a >> (64 - s)); }
void _start(void) {
    volatile long a = 0x123456789L, b = 0x1000L;
    volatile int s = 5;
    long r = mul64(a, b) + divmod64(a, b) + (long)rot64((unsigned long)a, s);
    sys_exit(r);
}
