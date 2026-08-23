/* Ground-truth corpus (era-style, 2026-08-23): an intrusive singly-linked list with a GLOBAL
 * head — push (the WAR2 FUN_0002cca0 shape: read old head, write new head, link), pop, find by
 * key, and a length/sum walk; nodes come from a static pool. Exercises global writes ordered
 * against stores through pointers (INDIRECT placement) and pointer phis. Freestanding + shim. */
#include "shim.h"

struct node { int key; int val; struct node *next; };

static struct node pool[12];
static struct node *head;
static int pool_n;

__attribute__((noinline)) static struct node *alloc_node(int key, int val) {
    if (pool_n >= 12) return 0;
    struct node *n = &pool[pool_n++];
    n->key = key; n->val = val; n->next = 0;
    return n;
}

__attribute__((noinline)) static void push(struct node *n) {
    n->next = head;
    head = n;
}

__attribute__((noinline)) static struct node *pop(void) {
    struct node *n = head;
    if (n) head = n->next;
    return n;
}

__attribute__((noinline)) static struct node *find(int key) {
    for (struct node *n = head; n; n = n->next)
        if (n->key == key) return n;
    return 0;
}

__attribute__((noinline)) static int walk(int *len) {
    int s = 0, l = 0;
    for (struct node *n = head; n; n = n->next) { s += n->val; l++; }
    *len = l;
    return s;
}

void _start(void) {
    volatile int seed = 4;
    for (int i = 0; i < 7; i++) push(alloc_node(i * 3 + seed, i * i));
    struct node *p = pop();
    int len = 0;
    long r = p ? p->val : -1;
    struct node *f = find(7);
    r = r * 16 + (f ? f->val : 9);
    r = r * 8 + walk(&len);
    r = r * 4 + len;
    push(alloc_node(99, 5));
    r = r * 4 + walk(&len) + len;
    sys_exit(r);
}
