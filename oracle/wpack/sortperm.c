#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
extern void wpack_qsort(const void*, size_t, size_t, int(*)(const void*,const void*));
static int lenarr[512];
static int cmp(const void *a, const void *b){ return lenarr[*(const int*)a] - lenarr[*(const int*)b]; }
int main(void){
    int n; if(scanf("%d",&n)!=1) return 1;
    int *idx = malloc(n*sizeof(int));
    for(int i=0;i<n;i++){ int s,l; scanf("%d %d",&s,&l); idx[i]=s; lenarr[s]=l; }
    wpack_qsort(idx, n, sizeof(int), cmp);
    for(int i=0;i<n;i++) printf("%d\n", idx[i]);
    return 0;
}
