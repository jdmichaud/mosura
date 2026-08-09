/* A program whose CRT usage we KNOW, for the Borland recall gate.
 *
 * Sibling of `watprobe.c`, and written for the same two jobs: prove the Borland column names the
 * routines a program actually calls, and exercise the shape of relocation that used to make that
 * impossible.
 *
 * WHY 16-BIT BORLAND SPECIFICALLY
 *
 * Half of the OMF relocation port only runs here. A 32-bit object uses location 9 (32-bit
 * offset) and little else; a 16-bit one uses location 1/5 (16-bit offset), location 2 (a segment
 * selector) and location 3 (the 16:16 far pointer, whose packing follows Ghidra's 64K-block
 * mapping). Those paths have no other end-to-end cover.
 *
 * The far memory models matter most: a far call is segment-relative rather than self-relative, and
 * leaving those fixups unapplied once cost the far models nearly every caller/callee relation.
 * Relations are what carry a small function over the 14.6 score threshold, so build this for at
 * least one near and one far model.
 *
 * Kept to plain ANSI C with no 64-bit integers: the oldest columns here are Turbo C 1.0/1.5, which
 * predate both. As with `watprobe.c`, the calls are chosen for what they LAND — each pulls in a
 * routine whose body reads a static table, the case where an unapplied fixup leaves a zero
 * displacement and silently changes which addressing form the instruction decodes to.
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
    char *when;
    time_t now;
    struct tm *utc;
    int n;

    (void) argv;

    /* String and heap routines. */
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

    /* A character-class table reached by absolute address. */
    if (strcspn(buf, "aeiou") == 0)
        return 5;

    /* The day- and month-name tables, and the timezone/DST rules. */
    now = (time_t) 0;
    utc = gmtime(&now);
    if (utc == 0)
        return 6;
    when = asctime(utc);
    if (when == 0 || when[0] == '\0')
        return 7;

    /* The process-wide signal-handler vector. */
    if (raise(0) != 0)
        return 8;

    /* Integer-to-string conversion indexes a digit table. `ltoa`/`ultoa` are Borland spellings. */
    ltoa((long) n, digits, 10);
    ultoa((unsigned long) n, digits + 32, 16);
    if (digits[0] == '\0')
        return 9;

    /* qsort/bsearch over a static array: both are generic routines the runtime keeps in one
       place, and both are large enough to score on body size alone. */
    return (n ^ argc) & 0;
}
