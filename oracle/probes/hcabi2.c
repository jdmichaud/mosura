/* MetaWare High C 386 calling-convention probe, part 2 — the corners hcabi.c left unmeasured.
 *
 * Pins where the struct-return rule actually switches from registers to a hidden pointer, which
 * is what specs/x86-32-highc.cspec's <returnvalue> sizes have to match, plus the 64-bit and
 * unsigned/float returns.
 *
 *   scripts/setup-metaware-dosemu.sh 3.31 --compile oracle/probes/hcabi2.c
 */

struct s1 { char a; };
struct s2 { short a; };
struct s4 { int a; };
struct s5 { int a; char b; };
struct s8 { int a; int b; };
struct s12 { int a; int b; int c; };

struct s1  r1(int x)  { struct s1 r;  r.a = (char)x;                 return r; }
struct s2  r2(int x)  { struct s2 r;  r.a = (short)x;                return r; }
struct s4  r4(int x)  { struct s4 r;  r.a = x;                       return r; }
struct s5  r5(int x)  { struct s5 r;  r.a = x; r.b = (char)x;        return r; }
struct s8  r8(int x)  { struct s8 r;  r.a = x; r.b = x + 1;          return r; }
struct s12 r12(int x) { struct s12 r; r.a = r.b = r.c = x;           return r; }

unsigned       uret(unsigned x)       { return x + 1u; }
unsigned char  ucret(unsigned char x) { return (unsigned char)(x + 1); }
short          sret(short x)          { return (short)(x + 1); }
float          fret(float x)          { return x + 1.0f; }
double         dret(double x)         { return x + 1.0; }

/* 64-bit, if the compiler has it under a name this C89 dialect accepts. */
long lret(long x)          { return x + 1; }
unsigned long ulret(unsigned long x) { return x + 1ul; }

/* varargs with a real walk, not just the fixed argument. */
#include <stdarg.h>
int vsum(int n, ...)
{
    va_list ap;
    int i, t = 0;
    va_start(ap, n);
    for (i = 0; i < n; i++) t += va_arg(ap, int);
    va_end(ap);
    return t;
}

int use(void)
{
    return r1(1).a + r2(2).a + r4(4).a + r5(5).b + r8(8).b + r12(12).c
         + (int)uret(1u) + ucret(2) + sret(3) + (int)fret(1.0f) + (int)dret(1.0)
         + (int)lret(1) + (int)ulret(1ul) + vsum(3, 1, 2, 3);
}
