/* Ground-truth corpus (A7 bug-hunt): byte/string loops over .rodata (pointer walks + char tests). */
#include "shim.h"
static const char text[] = "the quick brown fox jumps over the lazy dog";
__attribute__((noinline)) static int count_vowels(const char *p) {
    int c = 0;
    for (; *p; p++) {
        char ch = *p;
        if (ch == 'a' || ch == 'e' || ch == 'i' || ch == 'o' || ch == 'u') c++;
    }
    return c;
}
__attribute__((noinline)) static int word_count(const char *p) {
    int words = 0, in = 0;
    for (; *p; p++) {
        if (*p == ' ') in = 0;
        else if (!in) { in = 1; words++; }
    }
    return words;
}
void _start(void) {
    long r = count_vowels(text) + word_count(text);
    sys_exit(r);
}
