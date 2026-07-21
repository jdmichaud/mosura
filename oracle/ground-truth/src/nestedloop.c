/* A8 bug-hunt: 3-level nested loops with continue + a goto out of the whole nest (break-to-label). */
#include "shim.h"
__attribute__((noinline)) static int nest(int n) {
    int acc = 0;
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            for (int k = 0; k < n; k++) {
                if (k == 2) continue;
                if (i * j * k > 20) goto done;
                acc += i + j + k;
            }
done:
    return acc;
}
void _start(void) {
    volatile int n = 5;
    long r = nest(n);
    sys_exit(r);
}
