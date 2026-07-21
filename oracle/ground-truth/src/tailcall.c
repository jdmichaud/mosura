/* Ground-truth corpus (A7 bug-hunt): mutual tail recursion (each call in tail position). */
#include "shim.h"
__attribute__((noinline)) static int is_even(int n);
__attribute__((noinline)) static int is_odd(int n) { return n == 0 ? 0 : is_even(n - 1); }
__attribute__((noinline)) static int is_even(int n) { return n == 0 ? 1 : is_odd(n - 1); }
void _start(void) {
    long r = is_even(20) + is_odd(15);
    sys_exit(r);
}
