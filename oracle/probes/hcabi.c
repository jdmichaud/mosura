/* MetaWare High C 386 calling-convention probe — the oracle for specs/x86-32-highc.cspec.
 *
 * The convention is read out of the OMF object this compiles to, so no linker is needed
 * (docs/metaware-highc-support.md). Compile with:
 *
 *   scripts/setup-metaware-dosemu.sh <ver> --compile oracle/probes/highc-abi.c
 *
 * Each function isolates one question a cspec has to answer. Do not "simplify" them: the point
 * is the shape of the generated code, not the arithmetic.
 */

struct two   { int a; int b; };            /* 8 bytes  — fits a register pair */
struct three { int a; int b; int c; };     /* 12 bytes — cannot */

/* How many integer arguments, and where? */
int i1(int a)                                   { return a; }
int i6(int a, int b, int c, int d, int e, int f) { return a + b + c + d + e + f; }

/* Mixed widths and a pointer. */
int mixed(char c, short s, int i, char *p)      { return c + s + i + (int)(*p); }

/* Floating point: argument passing and where the result comes back. */
double dret(double x)                           { return x + 1.0; }
float  fret(float x)                            { return x + 1.0f; }
double dmix(int a, double b, int c)              { return b + a + c; }

/* Struct by value in, struct by value out — the rule that differs from gcc/SysV. */
struct two   sret2(int a)                        { struct two r; r.a = a; r.b = a + 1; return r; }
struct three sret3(int a)                        { struct three r; r.a = r.b = r.c = a; return r; }
int          sarg(struct two s)                  { return s.a + s.b; }

/* Which registers survive a call (callee-saved), and who pops the arguments. */
extern int sink(int);
int clobber(int a, int b) { return sink(a) + sink(b) + a + b; }

/* Varargs. */
int vsum(int n, ...) { return n; }

/* Long long / 64-bit, if the compiler has it. */
long lret(long x) { return x + 1; }

int callall(void)
{
    struct two t; t.a = 1; t.b = 2;
    return i1(1) + i6(1,2,3,4,5,6) + mixed('a', 2, 3, "x") + (int)dret(1.0)
         + (int)fret(1.0f) + (int)dmix(1, 2.0, 3) + sret2(1).a + sret3(1).b
         + sarg(t) + clobber(1,2) + vsum(3,1,2,3) + (int)lret(1);
}
