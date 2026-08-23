//! The ground-truth recompile loop (`docs/ground-truth-corpus.md`, decompiler level): source we
//! own → the local `gcc` → mosura decompiles every function → the SAME `gcc` recompiles our C →
//! [`verify`] attributes the difference. With the compiler held fixed and the source known, the
//! score measures the decompiler alone, and every divergence can be read against the real source.
//!
//! gcc is the one compiler the development environment requires; its version floats, so nothing
//! here compares against committed bytes — the build and the recompile happen on the same machine
//! with the same compiler, and the gate (`tests/ground_truth_recompile.rs`) is a per-machine
//! baseline.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

use super::verify::{emitted_symbol_address, verify, Subject};
use crate::analysis::{self, decompiler::decompile_function};
use crate::decompile::printc::print_c;
use crate::decompile::space::Address;
use crate::decompile::types::Datatype;

/// The ground-truth build recipe (`oracle/ground-truth/build.sh`, `GCC_FLAGS`): freestanding,
/// static, non-PIC, `-O2`. Used for the build AND the recompile — `-no-pie` is a codegen flag
/// (non-PIC addressing), so it must be present on the `-c` line too.
pub const GCC_FLAGS: &[&str] =
    &["-nostdlib", "-static", "-no-pie", "-O2", "-ffreestanding", "-fno-asynchronous-unwind-tables"];
/// The SLEIGH language of the host gcc column.
pub const LANG: &str = "x86:LE:64:default";

/// One function's result.
#[derive(Debug, Clone)]
pub struct GtFunction {
    /// The ELF symbol (the real source name).
    pub symbol: String,
    pub va: u64,
    /// Original instruction count (the WGSS weight).
    pub weight: usize,
    /// `EXACT` / `SAME_CODE` / `SAME_SHAPE` / `MISMATCH` / `COMPILE_FAIL` / `DECOMPILE_FAIL`.
    pub verdict: String,
    pub similarity: f64,
    pub classes: BTreeMap<String, usize>,
    /// The first compiler error, or a note on how the TU was made to compile.
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct GtReport {
    pub program: String,
    pub functions: Vec<GtFunction>,
    /// Where the emitted TUs and objects were written.
    pub workdir: PathBuf,
}

impl GtReport {
    /// Insn-weighted mean similarity over the functions that decompiled (a function that fails
    /// to compile scores 0 at its weight, as in the corpus census).
    pub fn wgss(&self) -> f64 {
        let w: usize = self.functions.iter().map(|f| f.weight).sum();
        if w == 0 {
            return 0.0;
        }
        self.functions.iter().map(|f| f.similarity * f.weight as f64).sum::<f64>() / w as f64
    }
    pub fn count(&self, verdict: &str) -> usize {
        self.functions.iter().filter(|f| f.verdict == verdict).count()
    }
    pub fn summary(&self) -> String {
        format!(
            "{}: {} fns, weight {}, WGSS {:.4}, EXACT {}, SAME_SHAPE {}, MISMATCH {}, COMPILE_FAIL {}, DECOMPILE_FAIL {}",
            self.program,
            self.functions.len(),
            self.functions.iter().map(|f| f.weight).sum::<usize>(),
            self.wgss(),
            self.count("EXACT"),
            self.count("SAME_SHAPE") + self.count("SAME_CODE"),
            self.count("MISMATCH"),
            self.count("COMPILE_FAIL"),
            self.count("DECOMPILE_FAIL"),
        )
    }
}

/// The ground-truth sources the host gcc column builds (`build.sh`: `ELF_PROGS_ALL` +
/// `ELF_PROGS_A8`): every `src/*.c` without a toolchain-specific start stub
/// (`<name>_cstart.asm` marks a Watcom program), excluding the z80, Borland-16 and `noret`
/// programs whose recipes differ.
pub fn gcc_programs() -> Vec<PathBuf> {
    let dir = crate::paths::ground_truth_dir().join("src");
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    out.retain(|p| {
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else { return false };
        p.extension().is_some_and(|e| e == "c")
            && !dir.join(format!("{stem}_cstart.asm")).exists()
            && !matches!(stem, "z80prog" | "x16prog" | "noret" | "shim")
    });
    out.sort();
    out
}

pub fn gcc_available() -> bool {
    Command::new("gcc").arg("--version").output().is_ok_and(|o| o.status.success())
}

/// `gcc GCC_FLAGS -I<srcdir> -o <out> <src>` — the unstripped program (symbols are the truth).
pub fn build_program(src: &Path, out: &Path) -> Result<(), String> {
    let srcdir = src.parent().unwrap_or(Path::new("."));
    let o = Command::new("gcc")
        .args(GCC_FLAGS)
        .arg("-I")
        .arg(srcdir)
        .arg("-o")
        .arg(out)
        .arg(src)
        .output()
        .map_err(|e| format!("gcc: {e}"))?;
    if !o.status.success() {
        return Err(format!("build failed: {}", String::from_utf8_lossy(&o.stderr)));
    }
    Ok(())
}

struct ElfSymbol {
    name: String,
    addr: u64,
    size: u64,
    is_func: bool,
}

/// Defined symbols of the unstripped build, plus the bytes of every function.
fn elf_symbols(bin: &[u8]) -> Result<(Vec<ElfSymbol>, BTreeMap<u64, Vec<u8>>), String> {
    let file = object::File::parse(bin).map_err(|e| format!("ELF parse: {e}"))?;
    let mut syms = Vec::new();
    let mut bytes = BTreeMap::new();
    for s in file.symbols() {
        let Ok(name) = s.name() else { continue };
        if name.is_empty() || !s.is_definition() {
            continue;
        }
        let is_func = matches!(s.kind(), SymbolKind::Text);
        if is_func && s.size() > 0 {
            if let Some(sec) = s.section_index().and_then(|i| file.section_by_index(i).ok()) {
                if let Ok(data) = sec.data() {
                    let off = (s.address() - sec.address()) as usize;
                    let end = (off + s.size() as usize).min(data.len());
                    if off < end {
                        bytes.insert(s.address(), data[off..end].to_vec());
                    }
                }
            }
        }
        if matches!(s.kind(), SymbolKind::Text | SymbolKind::Data | SymbolKind::Unknown) {
            syms.push(ElfSymbol { name: name.to_string(), addr: s.address(), size: s.size(), is_func });
        }
    }
    Ok((syms, bytes))
}

/// The C type name for a global of the given decompiler type (LP64 host).
fn c_type(dt: &Datatype) -> String {
    match dt {
        Datatype::Int(n) => format!("int{n}"),
        Datatype::Uint(n) => format!("uint{n}"),
        Datatype::Unknown(n) => format!("xunknown{n}"),
        Datatype::Char => "char".into(),
        Datatype::Bool => "uint1".into(),
        Datatype::Float(4) => "float".into(),
        Datatype::Float(_) => "double".into(),
        Datatype::Pointer(..) => "pointer".into(),
        Datatype::Code => "code".into(),
        Datatype::Array(elem, _) => format!("{}[]", c_type(elem)),
        _ => "uint1[]".into(),
    }
}

/// The C type for an emitted `<prefix>Ram<hex>` global from its name stem (Ghidra's
/// `buildVariableName`: `i` int, `u` uint, `x` unknown, `c` char, `b` bool, `f` float, `d` double,
/// `p<T>` pointer to T, `a<T>` array of T) at the varnode's width.
fn prefix_type(prefix: &str, width: u64) -> String {
    let scalar = |c: char, w: u64| -> String {
        match c {
            'i' => format!("int{w}"),
            'u' => format!("uint{w}"),
            'c' => "char".into(),
            'b' => "uint1".into(),
            'f' => "float".into(),
            'd' => "double".into(),
            _ => format!("xunknown{w}"),
        }
    };
    let mut chars = prefix.chars();
    match chars.next() {
        Some('p') => match chars.next() {
            Some('c') => "code *".into(),
            Some('p') => "pointer *".into(),
            Some(c) => format!("{} *", scalar(c, 8)),
            None => "pointer".into(),
        },
        Some('a') => match chars.next() {
            Some('p') => "pointer[]".into(),
            Some(c) => format!("{}[]", scalar(c, width.min(4))),
            None => "uint1[]".into(),
        },
        Some(c) => scalar(c, width),
        None => format!("uint{width}"),
    }
}

/// Integer typedefs for every width the emitter can name, plus the helper vocabulary
/// (`SUB`/`ZEXT`/`SEXT`/`CONCAT`/carry family) generated for 1/2/4/8-byte operands.
pub fn prelude() -> String {
    let mut p = String::from(
        "typedef unsigned char undefined; typedef unsigned char byte; typedef unsigned char bool;\n\
         typedef unsigned char uint1; typedef unsigned short uint2; typedef unsigned int uint4; typedef unsigned long uint8;\n\
         typedef signed char int1; typedef short int2; typedef int int4; typedef long int8;\n\
         typedef unsigned char xunknown1; typedef unsigned short xunknown2; typedef unsigned int xunknown4; typedef unsigned long xunknown8;\n\
         typedef unsigned int uint3; typedef int int3; typedef unsigned int xunknown3;\n\
         typedef unsigned long uint5; typedef unsigned long uint6; typedef unsigned long uint7;\n\
         typedef long int5; typedef long int6; typedef long int7;\n\
         typedef unsigned long xunknown5; typedef unsigned long xunknown6; typedef unsigned long xunknown7;\n\
         typedef unsigned char undefined1; typedef unsigned short undefined2; typedef unsigned int undefined4; typedef unsigned long undefined8;\n\
         typedef unsigned int undefined3; typedef unsigned long undefined5; typedef unsigned long undefined6; typedef unsigned long undefined7;\n\
         typedef int code(); typedef unsigned long pointer; typedef struct mosura_spacebase spacebase;\n\
         typedef float float4; typedef double float8; typedef long double float10; typedef long double float16;\n\
         typedef __int128 int16; typedef unsigned __int128 uint16; typedef unsigned __int128 xunknown16;\n\
         extern long syscall(); extern long swi(int); extern unsigned long rdtsc(); extern unsigned int cpuid(unsigned int);\n\
         #define true 1\n#define false 0\n",
    );
    let u = |n: u32| match n {
        1 => "unsigned char",
        2 => "unsigned short",
        3 | 4 => "unsigned int",
        _ => "unsigned long",
    };
    let s = |n: u32| match n {
        1 => "signed char",
        2 => "short",
        3 | 4 => "int",
        _ => "long",
    };
    let widths = [1u32, 2, 3, 4, 5, 6, 7, 8];
    for &sz in &widths {
        for &o in &widths {
            if o <= sz {
                p += &format!("#define SUB{sz}{o}(x,n) (({})((unsigned long)(x)>>((n)*8)))\n", u(o));
            }
            if o >= sz {
                p += &format!("#define ZEXT{sz}{o}(x) (({})({})(x))\n", u(o), u(sz));
                p += &format!("#define SEXT{sz}{o}(x) (({})({})(x))\n", s(o), s(sz));
            }
        }
    }
    for &h in &widths {
        for &l in &widths {
            if h + l <= 8 {
                p += &format!(
                    "#define CONCAT{h}{l}(h,l) ((({})({})(h)<<({l}*8))|({})(l))\n",
                    u(h + l),
                    u(h),
                    u(l)
                );
            }
        }
    }
    for &n in &[1u32, 2, 4, 8] {
        let (un, sn, bits) = (u(n), s(n), n * 8);
        p += &format!("#define CARRY{n}(a,b) ((({un})(a))>(({un})~(({un})(b))))\n");
        p += &format!(
            "#define SCARRY{n}(a,b) ((int)((unsigned long)((~(({un})(a)^({un})(b)))&(({un})(a)^(({un})(a)+({un})(b))))>>({bits}-1)))\n"
        );
        p += &format!(
            "#define SBORROW{n}(a,b) ((int)((unsigned long)(((({un})(a)^({un})(b)))&(({un})(a)^(({un})(a)-({un})(b))))>>({bits}-1)))\n"
        );
        let _ = sn;
    }
    p
}

/// Identifiers of a C text, in order of first appearance.
fn identifiers(c: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cur = String::new();
    for ch in c.chars().chain(std::iter::once(' ')) {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else if !cur.is_empty() {
            if !cur.chars().next().unwrap().is_ascii_digit() && seen.insert(cur.clone()) {
                out.push(cur.clone());
            }
            cur.clear();
        }
    }
    out
}

/// The definition name and signature line of a decompiled function's C.
fn signature(c: &str) -> Option<(String, String)> {
    let line = c.lines().find(|l| l.contains('(') && !l.trim_start().starts_with("//"))?;
    let head = &line[..line.find('(')?];
    let name = head.split_whitespace().last()?.trim_start_matches('*').to_string();
    Some((name, line.trim_end_matches('{').trim().to_string()))
}

/// Run the loop over one program source; every function gets a verdict.
pub fn recompile_program(src: &Path, workdir: &Path) -> Result<GtReport, String> {
    let program_name = src.file_stem().and_then(|s| s.to_str()).unwrap_or("prog").to_string();
    let dir = workdir.join(&program_name);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let bin_path = dir.join(format!("{program_name}.elf"));
    build_program(src, &bin_path)?;
    let bin = std::fs::read(&bin_path).map_err(|e| e.to_string())?;
    let (syms, fn_bytes) = elf_symbols(&bin)?;
    let symmap: BTreeMap<String, u64> = syms.iter().map(|s| (s.name.clone(), s.addr)).collect();
    let data_syms: BTreeMap<String, u64> =
        syms.iter().filter(|s| !s.is_func).map(|s| (s.name.clone(), s.addr)).collect();
    let data_sizes: BTreeMap<u64, u64> = syms.iter().filter(|s| !s.is_func).map(|s| (s.addr, s.size)).collect();
    let program = analysis::analyze_file(&bin_path).map_err(|e| format!("analyze: {e:?}"))?;
    let ram = program.default_space;

    // Decompile everything first: the callee prototypes come from the callees' own signatures.
    struct Dec {
        sym: ElfSymbol,
        c: Option<String>,
        self_name: String,
        sig: String,
        globals: BTreeMap<u64, (u32, Datatype)>,
    }
    let mut decs: Vec<Dec> = Vec::new();
    for s in syms.into_iter().filter(|s| s.is_func && fn_bytes.contains_key(&s.addr)) {
        let f = decompile_function(&program, Address::new(ram, s.addr));
        let (c, self_name, sig, globals) = match f {
            Some(f) => {
                let c = print_c(&f);
                let (n, sig) = signature(&c).unwrap_or((String::from("func"), String::from("int func()")));
                let mut globals = BTreeMap::new();
                for i in 0..f.num_varnodes() as u32 {
                    let v = f.vn(crate::decompile::varnode::VarnodeId(i));
                    if v.loc.space == ram && !v.is_constant() {
                        let e = globals.entry(v.loc.offset).or_insert((v.size, v.get_type()));
                        if v.size > e.0 {
                            *e = (v.size, v.get_type());
                        }
                    }
                }
                (Some(c), n, sig, globals)
            }
            None => (None, String::new(), String::new(), BTreeMap::new()),
        };
        decs.push(Dec { sym: s, c, self_name, sig, globals });
    }
    let by_addr: BTreeMap<u64, usize> = decs.iter().enumerate().map(|(i, d)| (d.sym.addr, i)).collect();
    let resolver = move |sym: &str| -> Option<u64> {
        symmap.get(sym).copied().or_else(|| emitted_symbol_address(sym))
    };

    let pre = prelude();
    let mut functions = Vec::new();
    for i in 0..decs.len() {
        let d = &decs[i];
        let weight_bytes = fn_bytes[&d.sym.addr].clone();
        let Some(c) = &d.c else {
            functions.push(GtFunction {
                symbol: d.sym.name.clone(),
                va: d.sym.addr,
                weight: 0,
                verdict: "DECOMPILE_FAIL".into(),
                similarity: 0.0,
                classes: BTreeMap::new(),
                note: String::new(),
            });
            continue;
        };
        // Prototypes for every function the body names, under the name the body uses, with the
        // callee's decompiled signature; `kr = true` retries with unprototyped declarations.
        let ids = identifiers(c);
        let make_tu = |kr: bool| -> String {
            let mut tu = pre.clone();
            for id in &ids {
                if *id == d.self_name {
                    continue;
                }
                let callee = resolver(id).and_then(|a| by_addr.get(&a)).map(|&j| &decs[j]);
                if let Some(callee) = callee {
                    // (A self-call spelled `func_0x<own address>` is declared too: the object
                    // then carries an undefined symbol the resolver maps back to the function.)
                    if kr || callee.c.is_none() {
                        tu += &format!("extern int4 {id}();\n");
                    } else {
                        tu += &format!("{};\n", callee.sig.replacen(&callee.self_name, id, 1));
                    }
                    continue;
                }
                // A global: by its emitted address name or its real symbol.
                let addr = data_syms.get(id).copied().or_else(|| {
                    if id.contains("Ram") { emitted_symbol_address(id) } else { None }
                });
                if let Some(a) = addr {
                    let width = d
                        .globals
                        .get(&a)
                        .map(|(w, _)| *w as u64)
                        .or_else(|| data_sizes.get(&a).copied())
                        .filter(|w| matches!(w, 1 | 2 | 4 | 8))
                        .unwrap_or(8);
                    let ty = match id.find("Ram") {
                        // `<prefix>Ram<hex>`: the prefix IS the type the emitter chose
                        // (`ScopeInternal::buildVariableName`'s stem), the width is the varnode's.
                        Some(pos) if pos <= 3 => prefix_type(&id[..pos], width),
                        _ => d.globals.get(&a).map(|(_, dt)| c_type(dt)).unwrap_or_else(|| format!("uint{width}")),
                    };
                    if let Some(elem) = ty.strip_suffix("[]") {
                        tu += &format!("extern {elem} {id}[];\n");
                    } else {
                        tu += &format!("extern {ty} {id};\n");
                    }
                }
            }
            // Synthetic register reads (`extraout_RDX`, `unaff_RBX`, `in_RAX`) — Ghidra's
            // faithful rendering of a value produced by a callee or never written, which Ghidra
            // also leaves undeclared; declared as locals of the register's width, as the survey's
            // TU assembly does (its `extraout`/`unaff`/`in_reg` safety net).
            let mut locals = String::new();
            for id in &ids {
                let Some(reg) = ["extraout_", "unaff_", "in_"].iter().find_map(|p| id.strip_prefix(p)) else { continue };
                let reg = reg.split('_').next().unwrap_or(reg);
                let width = match reg.as_bytes() {
                    [b'R', ..] => 8,
                    [b'E', ..] => 4,
                    [_, b'L'] | [_, b'H'] | [.., b'B'] => 1,
                    [.., b'W'] => 2,
                    [_, _] => 2,
                    _ => 8,
                };
                locals += &format!("  uint{width} {id};\n");
            }
            if locals.is_empty() {
                tu += c;
            } else if let Some(brace) = c.find('{') {
                tu += &c[..=brace];
                tu += "\n";
                tu += &locals;
                tu += &c[brace + 1..];
            } else {
                tu += c;
            }
            tu
        };
        let c_path = dir.join(format!("{}.c", d.sym.name));
        let o_path = dir.join(format!("{}.o", d.sym.name));
        let mut note = String::new();
        let mut obj: Option<Vec<u8>> = None;
        for kr in [false, true] {
            let tu = make_tu(kr);
            std::fs::write(&c_path, &tu).map_err(|e| e.to_string())?;
            // gcc 14 promotes these to errors; they are diagnostics, not codegen, and the
            // emitted C's casts are the decompiler's business, not the instrument's.
            let o = Command::new("gcc")
                .args(GCC_FLAGS)
                .args([
                    "-c",
                    "-w",
                    "-Wno-error=incompatible-pointer-types",
                    "-Wno-error=int-conversion",
                    "-Wno-error=implicit-function-declaration",
                    "-o",
                ])
                .arg(&o_path)
                .arg(&c_path)
                .output()
                .map_err(|e| format!("gcc: {e}"))?;
            if o.status.success() {
                obj = std::fs::read(&o_path).ok();
                if kr {
                    note = "compiled with unprototyped callees".into();
                }
                break;
            }
            let err = String::from_utf8_lossy(&o.stderr);
            note = err.lines().find(|l| l.contains("error:")).unwrap_or("compile failed").trim().to_string();
        }
        let Some(obj) = obj else {
            functions.push(GtFunction {
                symbol: d.sym.name.clone(),
                va: d.sym.addr,
                weight: 0,
                verdict: "COMPILE_FAIL".into(),
                similarity: 0.0,
                classes: BTreeMap::new(),
                note,
            });
            continue;
        };
        let subject = Subject { name: d.self_name.clone(), va: d.sym.addr, len: weight_bytes.len() };
        match verify(LANG, &weight_bytes, &subject, &obj, &resolver) {
            Ok(checked) => {
                let diff = checked.diff;
                functions.push(GtFunction {
                    symbol: d.sym.name.clone(),
                    va: d.sym.addr,
                    weight: diff.orig_insns,
                    verdict: diff.verdict.as_str().to_string(),
                    similarity: diff.similarity,
                    classes: diff.class_counts.iter().map(|(k, v)| (k.as_str().to_string(), *v)).collect(),
                    note,
                });
            }
            Err(e) => functions.push(GtFunction {
                symbol: d.sym.name.clone(),
                va: d.sym.addr,
                weight: 0,
                verdict: "COMPILE_FAIL".into(),
                similarity: 0.0,
                classes: BTreeMap::new(),
                note: format!("verify: {e}"),
            }),
        }
    }
    Ok(GtReport { program: program_name, functions, workdir: dir })
}
