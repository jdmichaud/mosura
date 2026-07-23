//! WAR2 per-function recompile survey — EMIT stage (uncommitted measurement harness).
//!
//! Read-only w.r.t. the decompiler: loads WAR2 via the `--le` path, decompiles every recovered
//! function, and emits (a) a standalone C translation unit per function (prelude + synthesized
//! declarations + the decompiled body) for wcc386, and (b) a manifest with each function's
//! original machine-code bytes (from the fixed-up LE image, over the decompiler's covered
//! instruction extent) so a later compile+diff stage can classify recompilation fidelity.
//!
//! Usage: cargo run -q --release --example war2_survey -- <war2.exe> <out_dir>

use std::collections::{BTreeSet, HashSet};
use std::io::Write;
use std::sync::Mutex;

use mosura::analysis::{self, decompiler::decompile_function};
use mosura::decompile::funcdata::Funcdata;
use mosura::decompile::op::flags;
use mosura::decompile::printc::print_c;
use mosura::decompile::space::Address;

// Sized-int / undefined typedefs a compilable-C emitter would prepend (Ghidra decompiler C).
// Watcom 10.0a is C89: int/long/pointer are 32-bit and there is NO 64-bit integer type
// (`long long` / `__int64` both rejected), so 8-byte and odd-size types map to `double`
// (size-8) / nearest int — those are rare (7 files) and decompiler-imperfect for a 32-bit
// target anyway. Written to <out>/prelude.h so the compile stage can prepend it without a
// full re-emit. Kept out of the baked src files for fast prelude iteration.
const PRELUDE: &str = "\
typedef unsigned char undefined; typedef unsigned char undefined1; typedef unsigned short undefined2;
typedef unsigned int undefined4; typedef double undefined8; typedef unsigned char byte;
typedef unsigned char uint1; typedef unsigned short uint2; typedef unsigned int uint4; typedef double uint8;
typedef signed char int1; typedef short int2; typedef int int4; typedef double int8;
typedef unsigned char xunknown1; typedef unsigned short xunknown2; typedef unsigned int xunknown4; typedef double xunknown8;
typedef unsigned int xunknown3; typedef double xunknown6; typedef unsigned int xunknown5; typedef double xunknown7;
typedef unsigned char undefined3; typedef unsigned int undefined5; typedef double undefined6; typedef double undefined7;
typedef unsigned int uint3; typedef unsigned int int3; typedef unsigned int uint5; typedef unsigned int int5;
typedef void (*code)(); typedef unsigned int pointer;
typedef float float4; typedef double float8; typedef long double float10;
typedef unsigned char uchar; typedef unsigned short ushort; typedef unsigned int uint; typedef unsigned long ulong;
typedef unsigned char bool;
#define true 1
#define false 0
#define SUB41(x,n) ((unsigned char)((unsigned int)(x)>>((n)*8)))
#define SUB42(x,n) ((unsigned short)((unsigned int)(x)>>((n)*8)))
#define SUB21(x,n) ((unsigned char)((unsigned short)(x)>>((n)*8)))
#define SUB44(x,n) (x)
#define CONCAT11(h,l) ((unsigned short)(((unsigned short)(unsigned char)(h)<<8)|(unsigned char)(l)))
#define CONCAT12(h,l) (((unsigned int)(unsigned char)(h)<<16)|(unsigned short)(l))
#define CONCAT13(h,l) (((unsigned int)(unsigned char)(h)<<24)|((unsigned int)(l)&0xffffff))
#define CONCAT21(h,l) (((unsigned int)(unsigned short)(h)<<8)|(unsigned char)(l))
#define CONCAT22(h,l) (((unsigned int)(unsigned short)(h)<<16)|(unsigned short)(l))
#define CONCAT31(h,l) (((unsigned int)(h)<<8)|(unsigned char)(l))
#define CONCAT44(h,l) ((double)(unsigned int)(h)*4294967296.0+(double)(unsigned int)(l))
#define ZEXT11(x) ((unsigned char)(x))
#define ZEXT12(x) ((unsigned short)(unsigned char)(x))
#define ZEXT14(x) ((unsigned int)(unsigned char)(x))
#define ZEXT22(x) ((unsigned short)(x))
#define ZEXT24(x) ((unsigned int)(unsigned short)(x))
#define ZEXT44(x) (x)
#define SEXT14(x) ((int)(signed char)(x))
#define SEXT24(x) ((int)(short)(x))
#define SEXT12(x) ((short)(signed char)(x))
#define SBORROW4(a,b) ((int)((((unsigned int)(a)^(unsigned int)(b))&((unsigned int)(a)^((unsigned int)(a)-(unsigned int)(b))))>>31))
#define SBORROW1(a,b) SBORROW4((int)(signed char)(a),(int)(signed char)(b))
#define SBORROW2(a,b) SBORROW4((int)(short)(a),(int)(short)(b))
#define CARRY4(a,b) ((unsigned int)(a)>(unsigned int)~(unsigned int)(b))
#define CARRY1(a,b) ((((unsigned int)(unsigned char)(a)+(unsigned int)(unsigned char)(b)))>0xffU)
#define POPCOUNT(x) (0)
";

fn main() {
    let mut args = std::env::args().skip(1);
    let bin = args.next().expect("usage: war2_survey <war2.exe> <out_dir>");
    let out = std::path::PathBuf::from(args.next().expect("usage: war2_survey <war2.exe> <out_dir>"));
    std::fs::create_dir_all(out.join("src")).unwrap();
    std::fs::create_dir_all(out.join("raw")).unwrap();
    std::fs::write(out.join("prelude.h"), PRELUDE).unwrap();

    eprintln!("loading WAR2 via analyze_le_file ...");
    let prog = analysis::analyze_le_file(std::path::Path::new(&bin)).expect("analyze_le_file");
    let ram = prog.default_space;
    eprintln!("{} functions", prog.function_manager.function_count());

    // Capture the last panic message+location per function (decompile_function catches internally
    // and returns None; a panic hook lets us distinguish a hard panic from a graceful None).
    let panic_msg: &'static Mutex<Option<String>> = Box::leak(Box::new(Mutex::new(None)));
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let loc = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        *panic_msg.lock().unwrap() = Some(format!("{loc} {msg}"));
    }));
    let _ = &default_hook; // keep silent; we record instead of print

    let mut entries: Vec<(u64, String)> =
        prog.function_manager.functions().map(|f| (f.entry.offset, f.name().to_string())).collect();
    entries.sort_by_key(|e| e.0);
    // Next-entry map (same code object) → function byte extent [entry, next_entry).
    let entry_offs: Vec<u64> = entries.iter().map(|e| e.0).collect();

    let manifest_path = out.join("manifest.tsv");
    let mut mf = std::io::BufWriter::new(std::fs::File::create(&manifest_path).unwrap());
    writeln!(
        mf,
        "idx\tva\tname\tstatus\torig_len\tcov_lo\tcov_hi\tsmells\torig_hex"
    )
    .unwrap();

    let t0 = std::time::Instant::now();
    let (mut ok, mut fail) = (0usize, 0usize);
    for (idx, (va, name)) in entries.iter().enumerate() {
        *panic_msg.lock().unwrap() = None;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            decompile_function(&prog, Address::new(ram, *va))
        }));
        let f: Option<Funcdata> = match outcome {
            Ok(Some(f)) => Some(f),
            _ => None,
        };
        let Some(f) = f else {
            fail += 1;
            let head = panic_msg.lock().unwrap().clone().unwrap_or_else(|| "returned None".into());
            let head = head.replace('\t', " ").replace('\n', " ");
            let head: String = head.chars().take(120).collect();
            writeln!(mf, "{idx:05}\t{va:08x}\t{name}\tDECOMPILE_FAIL\t0\t0\t0\t\t{head}").unwrap();
            continue;
        };
        ok += 1;

        // Decompiler-covered extent (cross-check only): live-op ram instruction starts.
        let mut cov_lo = u64::MAX;
        let mut cov_hi = 0u64;
        for id in f.op_ids() {
            let op = f.op(id);
            if op.flags & (flags::DEAD | flags::MARKER) != 0 {
                continue;
            }
            let pc = op.seqnum.pc;
            if pc.space != ram {
                continue;
            }
            let len = match prog.listing.code_unit_at(pc) {
                Some(mosura::analysis::program::CodeUnit::Instruction { length }) => *length as u64,
                _ => 1,
            };
            cov_lo = cov_lo.min(pc.offset);
            cov_hi = cov_hi.max(pc.offset + len);
        }
        if cov_lo == u64::MAX {
            cov_lo = *va;
            cov_hi = *va;
        }

        // Function byte extent = [entry, next-entry), trailing padding trimmed. This is mosura's
        // own function-boundary view (the authoritative "original bytes"); the compare stage diffs
        // the recompiled object against exactly these bytes at the entry VA.
        let next = entry_offs
            .iter()
            .copied()
            .find(|&o| o > *va)
            .unwrap_or(*va + 512)
            .min(*va + 8192)
            .min(0x7_c4a0); // obj1 (code) end
        let mut end = next.max(*va + 1);
        let mut region = prog.memory.read_window(Address::new(ram, *va), (end - *va) as usize);
        while region.last().is_some_and(|&b| b == 0x00 || b == 0x90 || b == 0xcc) {
            region.pop();
            end -= 1;
        }
        let orig_len = region.len();

        let c = print_c(&f);
        std::fs::write(out.join("raw").join(format!("{va:08x}.c")), &c).unwrap();

        // Synthesize a standalone TU and detect decompiler-artifact "smells".
        let thunk = matches!(region.first(), Some(0xe9) | Some(0xeb)) && orig_len <= 8;
        let (tu, mut smells) = build_tu(&c, *va, false);
        if thunk {
            smells.push("thunk".into());
        }
        std::fs::write(out.join("src").join(format!("{idx:05}.c")), &tu).unwrap();

        let orig_hex: String = region.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(
            mf,
            "{idx:05}\t{va:08x}\t{name}\tOK\t{orig_len}\t{cov_lo:08x}\t{cov_hi:08x}\t{}\t{orig_hex}",
            smells.join(","),
        )
        .unwrap();

        if idx % 200 == 0 {
            eprintln!("  {idx}/{} ok={ok} fail={fail} {:?}", entries.len(), t0.elapsed());
        }
    }
    mf.flush().unwrap();
    eprintln!("EMIT done: ok={ok} fail={fail} in {:?}", t0.elapsed());
    eprintln!("manifest: {}", manifest_path.display());
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Scan the decompiled C for identifier families that need a top-level declaration to form a
/// standalone translation unit, synthesize those declarations + the typedef prelude, and return
/// the full TU text plus a list of decompiler-artifact "smell" tags.
fn build_tu(c: &str, self_va: u64, non_contig: bool) -> (String, Vec<String>) {
    let self_name = format!("FUN_{self_va:08x}");
    let mut funcs: HashSet<String> = HashSet::new(); // func_0x.. / FUN_.. callees -> extern fn
    let mut ptr_idents: HashSet<String> = HashSet::new(); // used with [] -> pointer-typed global
    let mut scalar_idents: HashSet<(String, char)> = HashSet::new(); // (name, type-prefix)
    let mut smells: BTreeSet<String> = BTreeSet::new();

    let b = c.as_bytes();
    // Collect identifiers and whether each is immediately followed by '[' (indexed => pointer).
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_alphabetic() || b[i] == b'_' {
            let s = i;
            while i < b.len() && is_ident(b[i]) {
                i += 1;
            }
            let w = &c[s..i];
            let indexed = i < b.len() && b[i] == b'[';
            classify_ident(w, indexed, &self_name, &mut funcs, &mut ptr_idents, &mut scalar_idents, &mut smells);
        } else {
            i += 1;
        }
    }
    if non_contig {
        smells.insert("non_contig".into());
    }

    let mut decls = String::new();
    let mut fs: Vec<_> = funcs.into_iter().collect();
    fs.sort();
    for f in fs {
        decls.push_str(&format!("extern int {f}();\n"));
    }
    // Ram globals + synthetic register vars. If ever indexed, declare as pointer.
    let mut names: BTreeSet<String> = BTreeSet::new();
    for (n, pfx) in &scalar_idents {
        if ptr_idents.contains(n) {
            continue;
        }
        names.insert(format!("{} {n};", ctype_for(*pfx)));
    }
    for n in &ptr_idents {
        names.insert(format!("int *{n};", ));
    }
    for d in names {
        decls.push_str(&d);
        decls.push('\n');
    }

    // Prelude is prepended at compile time from <out>/prelude.h (fast iteration); src files
    // carry only the synthesized declarations + the decompiled body.
    let tu = format!("{decls}\n{c}");
    (tu, smells.into_iter().collect())
}

fn classify_ident(
    w: &str,
    indexed: bool,
    self_name: &str,
    funcs: &mut HashSet<String>,
    ptr_idents: &mut HashSet<String>,
    scalar_idents: &mut HashSet<(String, char)>,
    smells: &mut BTreeSet<String>,
) {
    // Callees.
    if w.starts_with("func_0x") {
        funcs.insert(w.to_string());
        smells.insert("indirect_call".into());
        return;
    }
    if w.starts_with("FUN_") && w != self_name {
        funcs.insert(w.to_string());
        return;
    }
    // Synthetic register reads (Ghidra warning-class: value from callee / uninitialized reg).
    for (p, tag) in [("extraout_", "extraout"), ("unaff_", "unaff"), ("in_", "in_reg"), ("register0x", "register")] {
        if w.starts_with(p) {
            smells.insert(tag.into());
            if indexed {
                ptr_idents.insert(w.to_string());
            } else {
                scalar_idents.insert((w.to_string(), 'u'));
            }
            return;
        }
    }
    // <prefix>Ram<hex> globals.
    if let Some(pos) = w.find("Ram") {
        if pos >= 1 && pos <= 2 {
            let tail = &w[pos + 3..];
            if tail.len() >= 8 && tail.bytes().all(|c| c.is_ascii_hexdigit()) {
                let pfx = w.as_bytes()[0] as char;
                if indexed || pfx == 'p' {
                    ptr_idents.insert(w.to_string());
                } else {
                    scalar_idents.insert((w.to_string(), pfx));
                }
                if pfx == 'x' {
                    smells.insert("xunknown".into());
                }
                return;
            }
        }
    }
    // DAT_ / _DAT_ globals.
    if w.starts_with("DAT_") || w.starts_with("_DAT_") {
        if indexed {
            ptr_idents.insert(w.to_string());
        } else {
            scalar_idents.insert((w.to_string(), 'u'));
        }
    }
}

fn ctype_for(prefix: char) -> &'static str {
    match prefix {
        'i' => "int",
        'u' => "unsigned int",
        'b' => "unsigned char",
        's' => "short",
        'c' => "char",
        'f' => "float",
        'd' => "double",
        'p' => "void *",
        _ => "int", // x (xunknown) and anything else
    }
}
