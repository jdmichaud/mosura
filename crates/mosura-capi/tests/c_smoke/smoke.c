/* The C smoke: the CLI's scenario through the shipped header and shared library, from C.
 * Built and run by tests/c_smoke.rs (opt-in: needs cc). argv[1] = a binary (basic.elf). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mosura.h"

static void die(const char *what, mosura_status s) {
    fprintf(stderr, "%s: status %d: %s\n", what, (int)s, mosura_last_error());
    exit(1);
}

static int str_eq(mosura_view v, const char *s) {
    return v.len == strlen(s) && memcmp(v.ptr, s, v.len) == 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: smoke <binary>\n"); return 2; }
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror(argv[1]); return 2; }
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc((size_t)n);
    if (fread(buf, 1, (size_t)n, fp) != (size_t)n) { perror("read"); return 2; }
    fclose(fp);
    mosura_view bytes = { buf, (size_t)n };

    printf("sizeof(mosura_ctx_config) %zu\n", sizeof(mosura_ctx_config));
    printf("abi %u.%u\n", mosura_abi_version() >> 16, mosura_abi_version() & 0xffff);
    mosura_ctx_config cfg = MOSURA_CTX_CONFIG_INIT;
    mosura_ctx *ctx = NULL;
    mosura_status s = mosura_ctx_new(&cfg, &ctx);
    if (s != MOSURA_OK) die("ctx_new", s);

    /* identify: the language row */
    mosura_table *id = NULL;
    if ((s = mosura_identify(ctx, bytes, &id)) != MOSURA_OK) die("identify", s);
    for (uint64_t r = 0; r < mosura_table_rows(id); r++) {
        mosura_view k, v;
        mosura_table_str(id, r, 0, &k);
        mosura_table_str(id, r, 1, &v);
        if (str_eq(k, "language")) printf("language %.*s\n", (int)v.len, (const char *)v.ptr);
    }
    mosura_release(id);

    /* a session in memory, the program, its analysis, the functions table */
    mosura_session *sess = NULL;
    if ((s = mosura_session_open(ctx, NULL, NULL, &sess)) != MOSURA_OK) die("session_open", s);
    if ((s = mosura_session_add_input(sess, bytes, "basic.elf", NULL)) != MOSURA_OK) die("add_input", s);
    mosura_program *p = NULL;
    if ((s = mosura_program_open(sess, NULL, NULL, &p)) != MOSURA_OK) die("program_open", s);
    if ((s = mosura_program_analyze(p, NULL, NULL, NULL)) != MOSURA_OK) die("analyze", s);
    mosura_table *fns = NULL;
    if ((s = mosura_program_table(p, "functions", &fns)) != MOSURA_OK) die("table", s);
    printf("functions %llu\n", (unsigned long long)mosura_table_rows(fns));
    uint32_t name_col = 0, entry_col = 0;
    mosura_table_column_index(fns, "name", &name_col);
    mosura_table_column_index(fns, "entry", &entry_col);
    uint64_t main_entry = 0;
    for (uint64_t r = 0; r < mosura_table_rows(fns); r++) {
        mosura_view nm;
        mosura_table_str(fns, r, name_col, &nm);
        if (str_eq(nm, "main")) mosura_table_u64(fns, r, entry_col, &main_entry);
    }
    printf("main %#llx\n", (unsigned long long)main_entry);

    /* decompile main, print the first line of its C */
    mosura_function *f = NULL;
    if ((s = mosura_function_decompile(p, main_entry, NULL, &f)) != MOSURA_OK) die("decompile", s);
    mosura_bytes c = { NULL, 0, 0 };
    if ((s = mosura_function_c(f, &c)) != MOSURA_OK) die("function_c", s);
    size_t line = 0;
    while (line < c.len && c.ptr[line] != '\n') line++;
    printf("c %.*s\n", (int)line, (const char *)c.ptr);
    mosura_bytes_dispose(&c);

    /* the boundary: a released handle and a wrong kind are refused with a message */
    int stack_var = 7;
    mosura_release(&stack_var);
    printf("release(foreign) %s\n", strlen(mosura_last_error()) ? "refused" : "silent");
    uint64_t rows = mosura_table_rows((const mosura_table *)sess);
    printf("rows(wrong kind) %llu %s\n", (unsigned long long)rows, strstr(mosura_last_error(), "not a mosura_table") ? "named" : "unnamed");
    mosura_options *o = NULL;
    mosura_options_new(ctx, &o);
    s = mosura_options_set(o, "load.loader", "sideways");
    printf("bad option %d %s\n", (int)s, strstr(mosura_last_error(), "load.loader") ? "doc" : "nodoc");

    mosura_release(o);
    mosura_release(f);
    mosura_release(fns);
    mosura_release(p);
    mosura_release(sess);
    mosura_release(ctx);
    free(buf);
    printf("ok\n");
    return 0;
}
