//! Generate the committed watcom fixtures from SELF-COMPILED minimal examples — no game bytes
//! (third-party policy; directive #6). Compiles each MVE with the in-house Watcom 10.0a via the
//! recompile toolchain, extracts the function's code from the OMF object, and prints the fixture
//! XML with the source embedded as a comment. Committed alongside the fixtures it generates, so provenance and regeneration stay in-repo.
//!
//! Usage: watcom_mve_fixtures <WATCOM-dir> <out-dir>
use mosura::recompile::candidate::load_object_function;
use mosura::recompile::toolchain::{CompileUnit, Toolchain, WatcomDos};

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

/// W4b (frame-fill, seam 4): a 0xcc frame holding an int array read by element in a loop — the
/// recovered locals include an indexed symbol the aggregate must not swallow (WAR2 0x4e06e).
const FRAME_INDEX_SRC: &str = r#"
struct big { int pad[40]; int s[11]; };
extern void fill(struct big *b);
extern void use(int acc);
extern void keep(int *s);
void mve(int n)
{
    struct big b;
    int i, acc = 0;
    fill(&b);
    for (i = 0; i < n; i++)
        acc += b.s[i];
    use(acc);
    keep(b.s);
}
"#;

fn main() {
    let mut args = std::env::args().skip(1);
    let watcom = args.next().expect("usage: dumpmve <WATCOM-dir> <out-dir>");
    let out = std::path::PathBuf::from(args.next().expect("usage: dumpmve <WATCOM-dir> <out-dir>"));
    std::fs::create_dir_all(&out).unwrap();
    let work = out.join("work");
    let tc = WatcomDos::new(&watcom, &work, "10.0a").expect("toolchain").owning_work_dir();
    // The watcom_10_0a profile's own flag knowledge (buildconfig.rs): `-d1+` is what makes
    // 10.0a emit the BP frame on WAR2's path — saves pushed BEFORE the frame (`52 55 89e5`),
    // which is the whole point of the callee-save fixture: the saved-EBP slot carves the
    // ownership hole BELOW the register save. `-of`/`-of+` force the other prologue path
    // (frame first) and are evidence-rejected for WAR2.
    let flags: Vec<String> =
        ["-5r", "-fpi87", "-s", "-onatx", "-d1+", "-zq"].iter().map(|s| s.to_string()).collect();
    let units = [
        ("CSAVE", "mve_", CALLEE_SAVE_SRC, "x86_watcom_callee_save.xml", 0x1000u64),
        ("SPARM", "_mve", STACK_PARAM_SRC, "x86_watcom_stack_param_single_var.xml", 0x2000u64),
        ("FRAME", "mve_", FRAME_EXTENT_SRC, "x86_watcom_frame_extent.xml", 0x3000u64),
        ("GUARD", "mve_", GUARD_ORDER_SRC, "x86_watcom_guard_order.xml", 0x4000u64),
        ("SPLIT", "mve_", SPLIT_LOCAL_SRC, "x86_watcom_split_local.xml", 0x5000u64),
        ("NTEST", "mve_", NARROW_TEST_SRC, "x86_watcom_narrow_test.xml", 0x6000u64),
        ("ARRIDX", "mve_", ARRAY_INDEX_SRC, "x86_watcom_array_index.xml", 0x7000u64),
        ("SPARSE", "mve_", SPARSE_SWITCH_SRC, "x86_14620_sparse_switch.xml", 0x8000u64),
        ("SCOPYG", "mve_", STRUCT_COPY_GLOBALS_SRC, "x86_20258_struct_copy_globals.xml", 0x9000u64),
        ("SCOPYP", "mve_", STRUCT_COPY_PTR_SRC, "x86_40470_struct_copy.xml", 0xa000u64),
        ("SWBRK", "mve_", SWITCH_CASE_BREAK_SRC, "x86_2c00c_switch.xml", 0xb000u64),
        ("MEMCPY", "mve_", MEMCPY_STACK_SRC, "x86_32c00.xml", 0xc000u64),
        ("FRAMEST", "mve_", FRAME_STORE_SRC, "x86_2dcd4_frame.xml", 0xd000u64),
        ("FRAMEIX", "mve_", FRAME_INDEX_SRC, "x86_4e06e_frame_index.xml", 0xe000u64),
    ];
    for (key, sym, src, file, base) in units {
        let outp = tc.compile(&CompileUnit {
            key: key.into(),
            source: src.into(),
            flags: flags.clone(),
        });
        let obj = outp.object.unwrap_or_else(|| panic!("{key} failed:\n{}", outp.log));
        // Externs resolve INSIDE the fixture image: code symbols to a RET stub, data to a
        // plain address — an unresolvable (zero) call target aborts flow analysis and the
        // fixture decompiles to nothing.
        let stub = base + 0x1000;
        let data = base + 0x2000;
        // Every extern gets its OWN address (data 0x100 apart, code stubs 0x10 apart, in order
        // of first reference): two globals never alias (a struct copy between aliased globals
        // would be a self-copy) and two callees never merge (identical call bodies would
        // tail-merge into shared labels).
        let seen = std::rc::Rc::new(std::cell::RefCell::new(std::collections::HashMap::<String, u64>::new()));
        let seen_r = seen.clone();
        let resolver = move |sym: &str| {
            let is_data = sym.contains("gsum") || sym.contains("tbl") || sym.contains("gtbl") || sym.starts_with("_g") || sym.starts_with('g');
            let mut m = seen_r.borrow_mut();
            let n_data = m.values().filter(|&&a| a >= data).count() as u64;
            let n_code = m.values().filter(|&&a| a < data).count() as u64;
            Some(*m.entry(sym.to_string()).or_insert(if is_data { data + 0x100 * n_data } else { stub + 0x10 * n_code }))
        };
        let mut cand = load_object_function(&obj, sym, base, &resolver)
            .unwrap_or_else(|e| panic!("{key}: {e}\nlog:\n{}", outp.log));
        // A switch's jump table lives outside the function's extent (Watcom emits it at the front
        // of `_TEXT`): emit each table as its own chunk at `base + 0x800 + ..` and resolve the
        // function's reference to it, so the fixture carries a decodable BRANCHIND.
        let mut extra_chunks = String::new();
        if !cand.tables.is_empty() {
            let tables = cand.tables.clone();
            let mut addrs = Vec::new();
            let mut next = base + 0x800;
            for t in &tables {
                addrs.push(next);
                next += 4 * t.entries_fnrel.len() as u64;
            }
            let entries = |t: &mosura::recompile::candidate::CandTable| -> Vec<u8> {
                t.entries_fnrel.iter().flat_map(|k| ((base + k) as u32).to_le_bytes()).collect()
            };
            cand.resolve_tables(&|bytes| tables.iter().position(|t| entries(t) == bytes).map(|i| addrs[i]));
            for (i, t) in tables.iter().enumerate() {
                let hex: String = entries(t).iter().map(|b| format!("{b:02x}")).collect();
                extra_chunks += &format!("  <bytechunk space=\"ram\" offset=\"{:#x}\" readonly=\"true\">\n{hex}\n  </bytechunk>\n", addrs[i]);
            }
        }
        let hex: String = cand.relinked_bytes().iter().map(|b| format!("{b:02x}")).collect();
        // one RET stub per code extern referenced (plus the default one)
        let mut stubs: Vec<u64> = seen.borrow().values().copied().filter(|&a| a < data).collect();
        stubs.push(stub);
        stubs.sort_unstable();
        stubs.dedup();
        let stub_chunks: String = stubs.iter().map(|a| format!("  <bytechunk space=\"ram\" offset=\"{a:#x}\" readonly=\"true\">\nc3\n  </bytechunk>\n")).collect();
        let src_comment: String = src.trim().lines().map(|l| format!("  {l}\n")).collect();
        let xml = format!(
            "<!-- SELF-COMPILED fixture: wcc386 10.0a (in-house), flags {fl}. No third-party\n\
             \x20    bytes — the source is this comment; regenerate with examples/watcom_mve_fixtures.rs.\n\
             \x20    Externs: code from {stub:#x} (one RET stub per callee, 0x10 apart), data from {data:#x} (0x100 apart).\n\
             {src_comment}-->\n\
             <binaryimage arch=\"x86:LE:32:default:watcom\">\n\
             \x20 <bytechunk space=\"ram\" offset=\"{base:#x}\" readonly=\"true\">\n{hex}\n  </bytechunk>\n\
             {extra_chunks}\
             {stub_chunks}</binaryimage>\n",
            fl = flags.join(" "),
        );
        std::fs::write(out.join(file), xml).unwrap();
        println!("{file}: {} bytes of {sym}", cand.bytes.len());
    }
}
