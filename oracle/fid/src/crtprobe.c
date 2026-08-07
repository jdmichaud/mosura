/* A program whose CRT usage we KNOW, for the Ghidra-free FID recall gate.
 *
 * Every library call here is deliberate: each one pulls a named CRT routine into the
 * statically-linked image, so "did FID name it?" has an answer we derived from the source
 * rather than from any tool. Kept freestanding of stdio formatting variance — the point is
 * which routines get linked, not what the program prints.
 */
#include <string.h>
#include <stdlib.h>

/* MSVC 6 predates C99: it spells the 64-bit type `__int64` and rejects `long long`.
   The same source has to serve the Watcom and gcc columns later, so the type is
   selected here rather than duplicated per compiler. */
#if defined(_MSC_VER) && _MSC_VER < 1300
typedef unsigned __int64 u64;
#define U64C(x) (x##ui64)
#else
typedef unsigned long long u64;
#define U64C(x) (x##ULL)
#endif

static char buf[64];
static char other[64];

int main(int argc, char **argv)
{
    u64 a, b;
    char *heap;
    int n;

    (void) argv;

    memset(buf, 0, sizeof buf);
    strcpy(buf, "mosura fid probe");
    strncpy(other, buf, sizeof other - 1);
    n = (int) strlen(other);
    memcpy(buf, other, (size_t) n);
    if (memcmp(buf, other, (size_t) n) != 0)
        return 1;
    if (strcmp(buf, other) != 0)
        return 2;
    if (strchr(buf, 'f') == 0)
        return 3;

    heap = (char *) malloc(128);
    if (heap == 0)
        return 4;
    memset(heap, 'x', 128);
    free(heap);

    /* 64-bit division and remainder pull in the compiler's __aulldiv/__aullrem helpers. */
    a = (u64) n * U64C(0x100000001) + (u64) argc;
    b = (u64) argc + U64C(3);
    if (b == 0)
        return 5;

    return (int) ((a / b) ^ (a % b)) & 0;
}
