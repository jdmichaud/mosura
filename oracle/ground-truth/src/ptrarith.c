/* A8 bug-hunt: pointer/array arithmetic — pointer-increment walk + 2D array indexing. */
#include "shim.h"
static int grid[4][4];
__attribute__((noinline)) static int diag(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += grid[i][i];
    return s;
}
__attribute__((noinline)) static int walk(int *p, int n) {
    int s = 0;
    int *end = p + n;
    while (p < end) { s += *p; p++; }
    return s;
}
void _start(void) {
    volatile int n = 4;
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) grid[i][j] = i * 4 + j;
    long r = diag(n) + walk(&grid[0][0], n * n);
    sys_exit(r);
}
