/* Ground-truth corpus (era-style, 2026-08-23): byte-string routines of the kind a 1990s game
 * carries — an upper-casing copy, a substring search (nested loop with an early exit), a
 * separator-delimited token count, and a checksum over a buffer filled by the three. The data
 * is local char arrays indexed in loops (stack arrays + LoadGuard ranges). Freestanding + shim. */
#include "shim.h"

__attribute__((noinline)) static int str_copy_upper(char *dst, const char *src, int cap) {
    int n = 0;
    while (src[n] != 0 && n < cap - 1) {
        char c = src[n];
        if (c >= 'a' && c <= 'z') c = (char)(c - 32);
        dst[n] = c;
        n++;
    }
    dst[n] = 0;
    return n;
}

__attribute__((noinline)) static int str_find(const char *hay, const char *needle) {
    for (int i = 0; hay[i] != 0; i++) {
        int j = 0;
        while (needle[j] != 0 && hay[i + j] == needle[j]) j++;
        if (needle[j] == 0) return i;
    }
    return -1;
}

__attribute__((noinline)) static int token_count(const char *s, char sep) {
    int count = 0, in_tok = 0;
    for (int i = 0; s[i] != 0; i++) {
        if (s[i] == sep) in_tok = 0;
        else if (!in_tok) { in_tok = 1; count++; }
    }
    return count;
}

__attribute__((noinline)) static unsigned checksum(const char *s, int n) {
    unsigned h = 5381u;
    for (int i = 0; i < n; i++) h = h * 33u + (unsigned char)s[i];
    return h;
}

static const char msg[] = "orc grunt,peon,catapult,grunt";

void _start(void) {
    volatile int seed = 1;
    char buf[40];
    int n = str_copy_upper(buf, msg + seed, (int)sizeof buf);
    long r = n;
    r = r * 32 + str_find(buf, "GRUNT");
    r = r * 8 + token_count(buf, ',');
    r = r * 4 + (long)(checksum(buf, n) & 3u);
    sys_exit(r);
}
