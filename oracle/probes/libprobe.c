/* Library-identification probe: a program whose only job is to pull well-known C run-time
 * functions into a LINKED image, so the FID databases built from the same toolchain's libraries
 * can be tested against a real linked binary rather than against library modules.
 *
 *   scripts/setup-metaware-dosemu.sh 3.31 --compile oracle/probes/libprobe.c
 *   then link with Phar Lap 386|LINK against the same tree's libraries.
 *
 * Every call is to a function the runtime library defines, and the results are combined so no
 * call can be optimised away.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

char buf[256];
char other[256];

int main(int argc, char **argv)
{
    int n = 0;
    char *p;

    strcpy(buf, "the quick brown fox");
    strcat(buf, " jumps");
    n += (int)strlen(buf);
    n += strcmp(buf, "zzz");
    memset(other, 'x', sizeof other);
    memcpy(other, buf, 8);
    n += memcmp(other, buf, 4);
    p = strchr(buf, 'q');
    n += (p != 0);
    n += (int)strcspn(buf, "xyz");
    sprintf(other, "%d %s %x", n, buf, n);
    n += (int)strlen(other);
    n += atoi("1234");
    n += (int)strtol("99", (char **)0, 10);
    n += toupper(buf[0]) + tolower(buf[1]);
    n += isalpha(buf[2]) ? 1 : 0;
    p = (char *)malloc(64);
    if (p) { strcpy(p, "heap"); n += (int)strlen(p); free(p); }
    n += (int)fabs(-1.5);
    n += (int)sqrt(16.0);
    n += abs(-3);
    qsort(other, 4, 1, (int (*)(const void *, const void *))strcmp);
    printf("%d\n", n);
    return n & 0x7f;
}
