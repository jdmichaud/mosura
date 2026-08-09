/* A program whose CRT usage we KNOW, for the Watcom recall gate — and, deliberately, for the
 * class of defect that gate exists to catch.
 *
 * WHY THIS IS NOT `crtprobe.c`
 *
 * Two reasons, and the second is the interesting one.
 *
 * 1. Watcom 10.0a has no 64-bit integer type at all — neither `__int64` nor `long long` appears
 *    anywhere in its headers — so `crtprobe.c`'s 64-bit section cannot compile here. (Its
 *    committed MSVC binary also cannot be rebuilt on a machine without VC98, so editing that
 *    source would leave the committed binary no longer corresponding to it.)
 *
 * 2. `crtprobe.c`'s call set does not exercise the failure this column actually had. Built with
 *    Watcom and identified against the databases from BEFORE and AFTER the OMF relocation fix,
 *    it named the same 17 functions either way: a gate whose answer was fixed in advance.
 *
 * So the calls below are chosen for what they pull in, not for coverage of the C library. Each
 * one lands a routine whose body reads a STATIC TABLE — a locale array, a day/month name table,
 * a signal-handler vector, a digit string. That is precisely the shape that used to be
 * unidentifiable: in an unlinked object the displacement to such a table is left ZERO, which
 * selects a different SLEIGH addressing form (no displacement operand) than the linked program's,
 * so byte-identical code hashed two different ways and never matched.
 *
 * `strcspn`, `asctime`, `gmtime` and `raise` are all ANSI C, so this stays portable if another
 * column ever wants it. `utoa`/`ultoa` are Watcom spellings and are guarded.
 */
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>

static char buf[64];
static char other[64];
static char digits[64];

int main(int argc, char **argv)
{
    char *heap;
    const char *when;
    time_t now;
    struct tm *utc;
    int n;

    (void) argv;

    /* The plain string/heap set — the same routines `crtprobe.c` covers, so this probe is a
       superset and the Watcom column does not need both linked. */
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

    /* --- the static-table half ------------------------------------------------------------ */

    /* strcspn walks a 256-bit membership bitmap it builds on the stack, but reaches its
       character-class table by absolute address. */
    if (strcspn(buf, "aeiou") == 0)
        return 5;

    /* asctime/gmtime read the day- and month-name tables and the DST rules — several distinct
       static arrays, each reached by a relocated displacement. */
    now = (time_t) 0;
    utc = gmtime(&now);
    if (utc == 0)
        return 6;
    when = asctime(utc);
    if (when == 0 || when[0] == '\0')
        return 7;

    /* raise consults the process-wide signal-handler vector. */
    if (raise(0) != 0)
        return 8;

    /* Integer-to-string conversion indexes a digit table. Watcom spellings, hence the guard;
       the ANSI-only columns simply lose these two names. */
#if defined(__WATCOMC__)
    utoa((unsigned) n, digits, 10);
    ultoa((unsigned long) n, digits + 32, 16);
    if (digits[0] == '\0')
        return 9;
#else
    (void) digits;
#endif

    return (n ^ argc) & 0;
}
