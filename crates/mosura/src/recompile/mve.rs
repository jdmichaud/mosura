//! THE MVEs — the minimal Watcom-compiled examples behind the self-compiled oracle fixtures, in
//! one place (review R5, commit d): each MVE's C source, the fixture it produces, the base it is
//! placed at, and (part 2) the input set its twin-build driver feeds. Two consumers: the fixture
//! generator (`examples/watcom_mve_fixtures.rs`, which compiles the source with the in-house
//! wcc386 and writes the fixture) and the twin-build oracle (`recompile::twin`, which builds the
//! source and mosura's decompilation of the fixture with gcc -m32 and compares their traces), so
//! "what the MVE is" cannot drift between them. The sources are verbatim from the generator.

const CALLEE_SAVE_SRC: &str = r#"
extern int read16(char *dst, unsigned n);
extern unsigned gsum;
int mve(unsigned n)
{
    char buf[16];
    if (!read16(buf, n))
        return 0;
    gsum = *(unsigned *)(buf + 12);
    return 1;
}
"#;

/// sfile_make_name's frame shape: three killed-register saves (EBX/ECX/EDX, forced by an
/// extern taking four register arguments) stacked ABOVE the EBP frame, and a 12-byte buffer
/// whose address escapes. The saved-EBP slot is the ownership hole that must BOUND the
/// buffer's open range (adjustFit); without it the buffer declares as the whole frame.
const FRAME_EXTENT_SRC: &str = r#"
extern int fmt4(char *dst, unsigned a, unsigned b, unsigned c);
extern void use(char *s);
void mve(unsigned n)
{
    char buf[12];
    fmt4(buf, n, n + 1, n + 2);
    use(buf);
}
"#;

/// attack_can_hit's shape: a guard clause returning early, written FIRST in the source, then
/// the general case. Ghidra's canonical arm order prints the guard as the trailing `else`;
/// the original lays the guard's return directly after the conditional jump.
const GUARD_ORDER_SRC: &str = r#"
extern unsigned char tbl[];
int mve(unsigned flags, unsigned t)
{
    if (flags & 4)
        return tbl[t] & 2;
    if (t > 9)
        return 0;
    return tbl[t] & 1;
}
"#;

/// check_attack / unit_set_target's shape: a 4-byte struct (two shorts) returned in a register
/// and kept as a local, read by field. The restructure sees two 2-byte slots written as halves
/// of one value; the source wrote one `GPOINT pt`.
const SPLIT_LOCAL_SRC: &str = r#"
typedef struct { short x, y; } GPOINT;
extern GPOINT getp(void);
extern int use(int x, int y, int k);
int mve(void)
{
    GPOINT p = getp();
    if (use(p.x, p.y, 1))
        return 1;
    return use(p.x, p.y, 2);
}
"#;

/// A byte-of-word test: the source reads `flags & 0x200` on a 16-bit field. The lifter
/// spells the recovered predicate as `(flags >> 8 & 2) != 0` — the shift-and-mask form the
/// `narrow-tests=rewiden` axis rewrites back to `flags & 0x200`.
const NARROW_TEST_SRC: &str = r#"
extern void act(void);
void mve(unsigned short *p)
{
    if (*p & 0x200)
        act();
}
"#;

/// A global table indexed by a parameter, incremented in place — the scaled-index pointer-temp
/// case N3 inlines. Watcom addresses the RMW with a scaled-index operand (`INC dword ptr
/// [reg*4 + &gtbl]`), so the byte witness accepts it; the axis spells `((int *)&gtbl)[i]++`.
const ARRAY_INDEX_SRC: &str = r#"
extern int gtbl[];
void mve(int i)
{
    gtbl[i]++;
}
"#;

const STACK_PARAM_SRC: &str = r#"
extern void hit(void);
void __cdecl mve(int base, int idx)
{
    if (*(int *)(base + idx * 4 + 0x294) != -1) hit();
    if (*(int *)(base + idx * 4 + 0xd4) != -1) hit();
    if (*(int *)(base + idx * 4 + 0x154) != -1) hit();
    if (*(int *)(base + idx * 4 + 0x214) != -1) hit();
    if (*(int *)(base + idx * 4 + 0x1d4) != -1) hit();
    if (*(int *)(base + idx * 4 + 0x254) != -1) hit();
    if (*(int *)(base + idx * 4 + 0x354) != -1) hit();
    if (*(int *)(base + idx * 4 + 0x394) != -1) hit();
    if (*(int *)(base + idx * 4 + 0x3d4) != -1) hit();
    if (*(int *)(base + idx * 4 + 0x414) != -1) hit();
    if (*(int *)(base + idx * 4 + 0x454) != -1) hit();
    if (*(int *)(base + idx * 4 + 0x494) != -1) hit();
}
"#;


/// W5 (docs/sparse-switch-arm.md): the case set of WAR2 0x14620 — {4, 0xc, 0xd, 0xf, 0x10, 0x11,
/// 0x12, 0x13, 0x14, 0x15, 0x19, 0x1a} on a byte at p+6. Watcom compiles it into the balanced
/// JB/JBE compare tree (pivot 0x11); 0xd is an explicit empty case, 4 and 0x10 share a body,
/// 0x10 and 0x13 are range-pruned singletons. The WAR2 address is provenance only.
const SPARSE_SWITCH_SRC: &str = r#"
extern void f4(unsigned char *p);
extern void fc(unsigned char *q);
extern void ff(unsigned char *q);
extern void f12(unsigned char *p);
extern void f14(unsigned char *p);
extern void f15(unsigned char *p);
extern void f13(unsigned char *q, int k);
extern void f11(int g, unsigned n);
extern void f19(unsigned char k, int v);
extern unsigned char tbl[];
extern char g13;
extern int g11;
void mve(unsigned char *p)
{
    switch (p[6]) {
    case 4: case 0x10: f4(p); return;
    case 0xc: fc(p + 8); return;
    case 0xd: break;
    case 0xf: ff(p + 8); return;
    case 0x11: if (tbl[p[1] * 0x24] == 1) { f11(g11, p[1]); return; } break;
    case 0x12: f12(p); return;
    case 0x13: if (g13 == 0) { f13(p + 8, 0); return; } break;
    case 0x14: f14(p); return;
    case 0x15: f15(p); return;
    case 0x19: f19(p[1], 1); break;
    case 0x1a: f19(p[1], 0); break;
    }
}
"#;

/// W6 (docs/struct-copy-arm.md): two 3-dword struct assignments between globals after a call, the
/// shape of WAR2 0x20258 — Watcom emits `MOV EDI,&dst; MOV ESI,&src; MOVSD x3` (no REP), and
/// heritage re-homes the copies at the block's exit.
const STRUCT_COPY_GLOBALS_SRC: &str = r#"
struct p12 { unsigned a; unsigned b; unsigned c; };
extern struct p12 gsrc0;
extern struct p12 gsrc1;
extern struct p12 gdst0;
extern struct p12 gdst1;
extern void init(int k, void *p, int n);
void mve(void)
{
    init(0, &gdst0, 0x108);
    gdst0 = gsrc0;
    gdst1 = gsrc1;
}
"#;

/// W6: a 2-dword struct assignment from a global into `p + 0xc`, the shape of WAR2 0x40470
/// (`MOV ESI,&g; MOVSD; MOVSD`).
const STRUCT_COPY_PTR_SRC: &str = r#"
struct p8 { unsigned a; unsigned b; };
extern struct p8 gpair;
void mve(char *p)
{
    *(struct p8 *)(p + 0xc) = gpair;
}
"#;

/// W8 (printc `emitBlockSwitch`): a jump-table switch whose case 4 body returns and whose case 6
/// body is an if-with-return followed by more statements — its exit edge goes to the switch's
/// tail, so the case must end with `break;` (WAR2 0x2c00c's shape, case 13/14 there).
const SWITCH_CASE_BREAK_SRC: &str = r#"
extern int b0(int n);
extern void a4(void);
extern void a1(void);
extern int t13(void);
extern void bfin(int r, int k);
extern void bfin2(int k, int r);
void mve(int k)
{
    int r = 0;
    switch (k) {
    case 0: r = b0(1); break;
    case 1: r = b0(2); break;
    case 2: r = b0(3); break;
    case 3: r = b0(4); break;
    case 4: a4(); return;
    case 5: r = b0(5); break;
    case 6: r = b0(6); break;
    case 7: r = b0(7); break;
    case 8: r = b0(8); break;
    case 9: r = b0(9); break;
    case 10: r = b0(10); break;
    case 11: r = b0(11); break;
    case 12: r = b0(12); break;
    case 13: if (t13()) { a1(); return; } r = b0(13); break;
    case 14: r = b0(14); break;
    }
    bfin(r, k);
    bfin2(k, r);
}
"#;

/// W2/W1 (string-ops): `memcpy` of 0x30 bytes into a stack array whose base escapes — Watcom's
/// intrinsic emits the REP MOVSD + REP MOVSB pair (WAR2 0x32c00's shape); the arm collapses the
/// pair to one `memcpy(aiStack_.., param_1, 0x30)`.
const MEMCPY_STACK_SRC: &str = r#"
void *memcpy(void *, const void *, unsigned);
#pragma intrinsic(memcpy);
extern void use(int *q);
void mve(int *src)
{
    int buf[12];
    memcpy(buf, src, 0x30);
    use(buf);
}
"#;

/// W4 (dead store + frame-fill): a 0xd0-byte frame struct of which the source touches a few bytes
/// (0, 6, a short at 8, a short at 0xc from a call result) before passing its address to a call —
/// WAR2 0x2dcd4's shape: the recompile of the 12 declared bytes lost the frame and the store.
const FRAME_STORE_SRC: &str = r#"
struct big { unsigned char b[0xd0]; };
extern short getv(int c, int k);
extern void send(void *p);
void mve(unsigned short a, int unused, int c)
{
    struct big s;
    s.b[0] = 0xf;
    s.b[6] = 0x1f;
    *(unsigned short *)(s.b + 8) = a;
    *(unsigned short *)(s.b + 0xc) = getv(c, 1);
    send(&s);
}
"#;

/// W4b (frame-fill, seam 4): a 0xcc frame holding an int array in the MIDDLE — untouched bytes on
/// both sides — whose base escapes and whose elements are read by constant index and in a loop. The
/// frame-fill gate fires on the slack, the aggregate covers the array, and every element read must
/// render as the field at its slot (the array declaration is gone — WAR2 0x4e06e's `aiStack_2c[0]`
/// read the vanished name in probe w4bp).
const FRAME_INDEX_SRC: &str = r#"
struct big { int pad0[20]; int s[11]; int pad1[20]; };
extern void keep(int *s);
extern void use(int acc);
void mve(int n)
{
    struct big b;
    int i, acc;
    keep(b.s);
    acc = b.s[0];
    for (i = 1; i < n; i++)
        acc += b.s[i];
    use(acc);
}
"#;

/// One MVE: the generator's unit and the twin build's subject.
pub struct Mve {
    /// The generator's compile-unit key.
    pub key: &'static str,
    /// The object symbol of the entry function (`mve_` under the register convention, `_mve` cdecl).
    pub sym: &'static str,
    /// The C source, as compiled.
    pub source: &'static str,
    /// The fixture file the generator writes (under oracle/fixtures).
    pub fixture: &'static str,
    /// The address the function is placed at; callees from `base + 0x1000`, data from `base + 0x2000`
    /// (jump tables from `base + 0x800`). `base_n = 0x100000 + n * 0x10000`: ABOVE 64 KiB, because the
    /// twin build (`recompile::twin`) hosts the fixture's own address space — the arms name the data
    /// by folded address, and a hosted process cannot map anything below `vm.mmap_min_addr` (65536).
    /// (Review R5 d1: the layout was 0x1000..0xe000 before; the bytes moved with the relocations.)
    pub base: u64,
    /// The twin build's INPUT SET: C statements the driver executes in order (part d). Available to
    /// them: `mve` itself; `buf`, a 4 KiB `unsigned char` array the driver pattern-fills before the
    /// set runs; `LOG_RET(expr)` (traces an int result); `LOG_BYTES(p, n)` (traces n bytes the
    /// driver owns and knows to be initialized); every data extern, writable.
    pub inputs: &'static [&'static str],
    /// The sizes a callee stub may WRITE through a pointer parameter, `(callee, param, bytes)` —
    /// the MVE's own guarantee about the object behind that argument, never a convention: a
    /// typed struct pointer defaults to `sizeof`, an unsized pointer without an entry here gets NO
    /// write, a const pointer is never written. (The stub's write makes every value the MVE later
    /// reads through that object defined, identically on both sides.)
    pub writes: &'static [(&'static str, &'static str, usize)],
}

/// Every MVE, in the generator's order.
pub const MVES: &[Mve] = &[
    Mve { key: "CSAVE", sym: "mve_", source: CALLEE_SAVE_SRC, fixture: "x86_watcom_callee_save.xml", base: 0x100000, inputs: &["LOG_RET(mve(0));", "LOG_RET(mve(1));", "LOG_RET(mve(3));", "LOG_RET(mve(16));"], writes: &[("read16", "dst", 16)] },
    Mve { key: "SPARM", sym: "_mve", source: STACK_PARAM_SRC, fixture: "x86_watcom_stack_param_single_var.xml", base: 0x110000, inputs: &["mve((int)buf, 0);", "mve((int)buf, 3);", "mve((int)buf, 7);"], writes: &[] },
    Mve { key: "FRAME", sym: "mve_", source: FRAME_EXTENT_SRC, fixture: "x86_watcom_frame_extent.xml", base: 0x120000, inputs: &["mve(0);", "mve(1);", "mve(9);", "mve(255);"], writes: &[("fmt4", "dst", 12)] },
    Mve { key: "GUARD", sym: "mve_", source: GUARD_ORDER_SRC, fixture: "x86_watcom_guard_order.xml", base: 0x130000, inputs: &["LOG_RET(mve(0, 0));", "LOG_RET(mve(0, 9));", "LOG_RET(mve(0, 10));", "LOG_RET(mve(4, 200));", "LOG_RET(mve(1, 3));"], writes: &[] },
    Mve { key: "SPLIT", sym: "mve_", source: SPLIT_LOCAL_SRC, fixture: "x86_watcom_split_local.xml", base: 0x140000, inputs: &["LOG_RET(mve());", "LOG_RET(mve());"], writes: &[] },
    Mve { key: "NTEST", sym: "mve_", source: NARROW_TEST_SRC, fixture: "x86_watcom_narrow_test.xml", base: 0x150000, inputs: &["{ unsigned short v = 0; mve(&v); v = 0x200; mve(&v); v = 0xffff; mve(&v); v = 0x100; mve(&v); }"], writes: &[] },
    Mve { key: "ARRIDX", sym: "mve_", source: ARRAY_INDEX_SRC, fixture: "x86_watcom_array_index.xml", base: 0x160000, inputs: &["mve(0);", "mve(1);", "mve(5);", "mve(5);", "mve(9);"], writes: &[] },
    Mve { key: "SPARSE", sym: "mve_", source: SPARSE_SWITCH_SRC, fixture: "x86_14620_sparse_switch.xml", base: 0x170000, inputs: &["tbl[0x24] = 1; tbl[0x48] = 1;", "{ static const unsigned char keys[] = { 4, 0xc, 0xd, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x19, 0x1a, 0x1b, 0 }; int k; for (k = 0; k < 14; k++) { buf[6] = keys[k]; buf[1] = (unsigned char)(k & 3); g13 = (char)(k & 1); mve(buf); } }"], writes: &[] },
    Mve { key: "SCOPYG", sym: "mve_", source: STRUCT_COPY_GLOBALS_SRC, fixture: "x86_20258_struct_copy_globals.xml", base: 0x180000, inputs: &["mve();"], writes: &[] },
    Mve { key: "SCOPYP", sym: "mve_", source: STRUCT_COPY_PTR_SRC, fixture: "x86_40470_struct_copy.xml", base: 0x190000, inputs: &["mve((char *)buf); LOG_BYTES(buf, 0x20);"], writes: &[] },
    Mve { key: "SWBRK", sym: "mve_", source: SWITCH_CASE_BREAK_SRC, fixture: "x86_2c00c_switch.xml", base: 0x1a0000, inputs: &["{ int k; for (k = 0; k < 15; k++) mve(k); mve(20); mve(13); }"], writes: &[] },
    Mve { key: "MEMCPY", sym: "mve_", source: MEMCPY_STACK_SRC, fixture: "x86_32c00.xml", base: 0x1b0000, inputs: &["mve((int *)buf);"], writes: &[] },
    Mve { key: "FRAMEST", sym: "mve_", source: FRAME_STORE_SRC, fixture: "x86_2dcd4_frame.xml", base: 0x1c0000, inputs: &["mve(0, 0, 0);", "mve(7, 1, 3);", "mve(0xffff, -1, 255);"], writes: &[] },
    Mve { key: "FRAMEIX", sym: "mve_", source: FRAME_INDEX_SRC, fixture: "x86_4e06e_frame_index.xml", base: 0x1d0000, inputs: &["mve(0);", "mve(1);", "mve(5);", "mve(11);"], writes: &[("keep", "s", 44)] },
];

/// The names an MVE declares `extern`, by kind: a declarator followed by `(` is a function, anything
/// else (scalar, array, struct object) is data. Struct bodies and non-extern prototypes (the
/// intrinsics) are skipped.
pub fn extern_kinds(src: &str) -> (std::collections::HashSet<String>, std::collections::HashSet<String>) {
    // the identifier that ends `s`, behind any `[..]` suffix (`tbl[]`, `arr[40]`)
    let ident_before = |s: &str| -> Option<String> {
        let mut s = s.trim_end();
        while s.ends_with(']') {
            s = s[..s.rfind('[')?].trim_end();
        }
        let start = s.rfind(|c: char| !(c.is_alphanumeric() || c == '_')).map_or(0, |i| i + 1);
        let name = &s[start..];
        (!name.is_empty()).then(|| name.to_string())
    };
    let mut code = std::collections::HashSet::new();
    let mut data = std::collections::HashSet::new();
    for decl in src.split(';') {
        let Some(rest) = decl.trim().strip_prefix("extern ") else { continue };
        match rest.find('(') {
            Some(p) => {
                if let Some(n) = ident_before(&rest[..p]) {
                    code.insert(n);
                }
            }
            None => {
                if let Some(n) = ident_before(rest) {
                    data.insert(n);
                }
            }
        }
    }
    (code, data)
}
