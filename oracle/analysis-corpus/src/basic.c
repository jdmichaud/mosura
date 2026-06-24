/* A0 oracle corpus: minimal real ELF exercising the facts auto-analysis recovers
 * (functions, call refs, a data ref, a loop). Kept tiny so goldens stay reviewable. */
#include <stdio.h>

static int add(int a, int b) { return a + b; }

static int sum_to(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += i;
    return s;
}

int main(void) {
    int x = add(3, 4);
    int y = sum_to(x);
    printf("%d\n", y);
    return 0;
}
