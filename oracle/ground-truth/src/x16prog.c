/* x86-16 ground-truth probe (FID parity column).
 *
 * Deliberately plain K&R-era C: Turbo C 2.0 (1988) is the compiler, so no prototypes in
 * definitions, no `void` parameter lists in definitions, and nothing from a later standard.
 * A handful of small non-inlinable helpers reachable by direct call from main, so each
 * survives as its own function with a real body — which is all the hash-parity gate needs.
 */
int square(x) int x; { return x * x; }

int cube(x) int x; { return square(x) * x; }

long sum_to(n) int n; {
    long acc; int i;
    acc = 0;
    for (i = 1; i <= n; i++) acc += (long) square(i);
    return acc;
}

int classify(c) unsigned char c; {
    switch (c) {
    case 0: return 1;
    case 1: return 2;
    case 2: return 4;
    default: return 8;
    }
}

int main() {
    int n; long s;
    n = 6;
    s = sum_to(n) + cube(n) + classify((unsigned char) n);
    return (int) (s & 0x7f);
}
