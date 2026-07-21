/* A8 bug-hunt: variadic function + va_arg loop (register-save-area / overflow-arg handling). */
#include "shim.h"
#include <stdarg.h>
__attribute__((noinline)) static long vsum(int n, ...) {
    va_list ap;
    va_start(ap, n);
    long s = 0;
    for (int i = 0; i < n; i++) s += va_arg(ap, int);
    va_end(ap);
    return s;
}
void _start(void) {
    volatile int n = 5;
    long r = vsum(n, 10, 20, 30, 40, 50);
    sys_exit(r);
}
