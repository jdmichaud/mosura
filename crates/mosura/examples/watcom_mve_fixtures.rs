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
        let resolver = move |sym: &str| Some(if sym.contains("gsum") { data } else { stub });
        let cand = load_object_function(&obj, sym, base, &resolver)
            .unwrap_or_else(|e| panic!("{key}: {e}\nlog:\n{}", outp.log));
        let hex: String = cand.relinked_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let src_comment: String = src.trim().lines().map(|l| format!("  {l}\n")).collect();
        let xml = format!(
            "<!-- SELF-COMPILED fixture: wcc386 10.0a (in-house), flags {fl}. No third-party\n\
             \x20    bytes — the source is this comment; regenerate with examples/watcom_mve_fixtures.rs.\n\
             \x20    Externs: code at {stub:#x} (a RET stub), data at {data:#x}.\n\
             {src_comment}-->\n\
             <binaryimage arch=\"x86:LE:32:default:watcom\">\n\
             \x20 <bytechunk space=\"ram\" offset=\"{base:#x}\" readonly=\"true\">\n{hex}\n  </bytechunk>\n\
             \x20 <bytechunk space=\"ram\" offset=\"{stub:#x}\" readonly=\"true\">\nc3\n  </bytechunk>\n</binaryimage>\n",
            fl = flags.join(" "),
        );
        std::fs::write(out.join(file), xml).unwrap();
        println!("{file}: {} bytes of {sym}", cand.bytes.len());
    }
}
