//! THE TWIN BUILD (review R5, commit d): the gcc ground-truth oracle over the arm TUs.
//!
//! For each MVE of [`crate::recompile::mve::MVES`] two programs are built with `gcc -m32` and run:
//! the MVE's own C SOURCE, and mosura's DECOMPILATION of the Watcom fixture the generator made
//! from that source (its real bytes, its real witnesses — the Watcom idioms are in the fixture —
//! rendered under the survey's measured arm configuration and the per-function recovery of
//! `recompile::recovery`). Both link against the same RECORDING STUBS, generated once from the
//! MVE's extern list, and the same DRIVER, which feeds the MVE table's input set. The two
//! programs' traces (stub calls with scalar arguments, `mve`'s return values, the driver-owned
//! buffers it logs, every data extern's final bytes) must be byte-identical. The decompiled side
//! is rendered twice, PLAIN and ARMS, like the gcc column of commit b: a plain mismatch is a
//! decompiler finding, an arms-only mismatch is a WRONG-CODE ARM on exactly the shape the arm
//! exists for.
//!
//! THE STUB RULES (agreed with the reviewer, 2026-08-27): (1) a callee stub traces its SCALAR
//! arguments by value and a pointer argument as `ptr` only — the bytes behind a pointer are
//! different garbage per build when the pointee is an output buffer the MVE has not initialized
//! (CSAVE's `char buf[16]`, FRAMEIX's `b.s`), so tracing them compares nothing; (2) a stub WRITES
//! a deterministic pattern through a pointer parameter only for the size the MVE table declares
//! for that `(callee, param)` (`Mve::writes` — the MVE's own guarantee about the object behind the
//! argument, never a convention): a typed struct pointer defaults to `sizeof`, an unsized pointer
//! without an entry gets NO write, a const pointer is never written; (3) what a pointee held is
//! checked where it is knowable — the DRIVER logs the buffers it owns (`LOG_BYTES`), the stubs
//! dump every data extern's final bytes at exit.
//!
//! THE BINDING (the only textual manipulation of the decompiled text): the decompiled function
//! names its callees `func_0x<addr>` and its globals `<prefix>Ram<addr>`; the fixture's header
//! carries the layout the object was built with (`externs: name=0xaddr ..`, in the object's
//! relocation order), so the twin TU prepends `#define func_0x.. <callee>` for every callee — the
//! callee then resolves to the stub declared with the MVE's REAL signature, so an arity the
//! decompiler recovered wrong is a compile error reported as a finding — and, for every
//! address-named global the text uses, `#define <name> (*(<type> *)((char *)&<data> + <offset>))`
//! (the type from the name's prefix at the varnode's width, as the ground-truth oracle does).
//! Nothing else in the decompiled text is touched; on a mismatch both TUs, both traces and the
//! first differing line are printed. A product without the `externs:` line FAILS loudly.
//!
//! THE ADDRESS SPACE: the arms name their objects by FOLDED ADDRESS (`*(struct p12 *)0x182000`,
//! `*(uint1 *)(t + 0x132000)`) — no identifier to bind — so the twin hosts the fixture's own
//! address space: every data extern is defined in its own section and the link places it at its
//! fixture address (`--section-start`, `-no-pie`), in BOTH programs; that is why the generator's
//! layout sits above 64 KiB (commit d1: a hosted process cannot map below `vm.mmap_min_addr`).
use crate::decompile::emit::EmitChoices;
use crate::decompile::printc::{print_c_recovered, print_c_with, RecoveredChoices};
use crate::decompile::{build, pipeline};
use crate::recompile::groundtruth::{prefix_type, prelude_for, Target};
use crate::recompile::mve::{extern_kinds, Mve};
use crate::recompile::verify::emitted_symbol_address;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One parsed `extern` declaration of an MVE.
#[derive(Debug, Clone)]
pub struct ExternDecl {
    pub name: String,
    /// The declaration text without `extern` and the trailing `;`.
    pub decl: String,
    pub is_fn: bool,
    /// Function externs: the return type text and the parameters.
    pub ret: String,
    pub params: Vec<Param>,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub ty: String,
    pub name: String,
    pub is_ptr: bool,
    pub is_const: bool,
    /// `struct X *` / `X *` for a typedef'd struct: the pointee's type name, for `sizeof`.
    pub pointee: String,
}

/// Every `extern` declaration of `src`, parsed (functions with their parameter lists).
pub fn externs(src: &str) -> Vec<ExternDecl> {
    let mut out = Vec::new();
    for decl in src.split(';') {
        let Some(rest) = decl.trim().strip_prefix("extern ") else { continue };
        let rest = rest.trim();
        let ident_at_end = |s: &str| -> String {
            let mut s = s.trim_end();
            while s.ends_with(']') {
                s = s[..s.rfind('[').unwrap_or(0)].trim_end();
            }
            let start = s.rfind(|c: char| !(c.is_alphanumeric() || c == '_')).map_or(0, |i| i + 1);
            s[start..].to_string()
        };
        match rest.find('(') {
            Some(p) => {
                let head = &rest[..p];
                let name = ident_at_end(head);
                let ret = head[..head.len() - name.len()].trim().to_string();
                let inner = rest[p + 1..].trim_end_matches(')').trim();
                let mut params = Vec::new();
                if !inner.is_empty() && inner != "void" {
                    for pr in inner.split(',') {
                        let pr = pr.trim();
                        let name = ident_at_end(pr);
                        let ty = pr[..pr.len() - name.len()].trim().to_string();
                        let is_ptr = ty.contains('*');
                        let pointee = ty.replace('*', "").replace("const", "").trim().to_string();
                        params.push(Param { ty, name, is_ptr, is_const: pr.contains("const"), pointee });
                    }
                }
                out.push(ExternDecl { name, decl: rest.to_string(), is_fn: true, ret, params });
            }
            None => {
                let name = ident_at_end(rest);
                out.push(ExternDecl { name, decl: rest.to_string(), is_fn: false, ret: String::new(), params: Vec::new() });
            }
        }
    }
    out
}

/// The type-defining lines of an MVE source (`typedef ..;`, `struct X { .. };`), shared by every
/// TU of the twin build.
fn type_lines(src: &str) -> String {
    let mut out = String::new();
    for line in src.lines() {
        let t = line.trim();
        if t.starts_with("typedef ") || (t.starts_with("struct ") && t.contains('{')) {
            out.push_str(t);
            out.push('\n');
        }
    }
    out
}

/// The entry function's prototype (`int mve(unsigned n)`), from its definition line.
fn entry_prototype(src: &str) -> String {
    for line in src.lines() {
        let t = line.trim();
        if t.contains(" mve(") && !t.starts_with("extern") && t.ends_with(')') {
            return t.replace("__cdecl ", "");
        }
    }
    panic!("no `mve(` definition line in the MVE source");
}

/// The stub TU: every extern of the MVE defined once — callees as recording stubs, data as
/// pattern-filled objects — plus the trace helpers and the data dump. Rules (1)-(3) above.
pub fn stubs_c(m: &Mve, layout: &[(String, u64)]) -> String {
    let mut c = String::from("#include <stdio.h>\n#include <string.h>\n");
    c.push_str(&type_lines(m.source));
    c.push_str("static unsigned twin_seq = 1;\nvoid twin_fill(void *p, unsigned n) { unsigned i; unsigned char *b = (unsigned char *)p; for (i = 0; i < n; i++) b[i] = (unsigned char)(i * 7 + 3); }\n");
    let ex = externs(m.source);
    for d in &ex {
        if d.is_fn {
            let plist: Vec<String> = d.params.iter().map(|p| format!("{} {}", p.ty, p.name)).collect();
            let plist = if plist.is_empty() { "void".to_string() } else { plist.join(", ") };
            c.push_str(&format!("{} {}({}) {{\n", d.ret, d.name, plist));
            // the trace: scalars by value, pointers as `ptr`
            let mut fmt = format!("  printf(\"{}(", d.name);
            let mut args = String::new();
            for (i, p) in d.params.iter().enumerate() {
                if i > 0 {
                    fmt.push(',');
                }
                if p.is_ptr {
                    fmt.push_str("ptr");
                } else {
                    fmt.push_str("%ld");
                    args.push_str(&format!(", (long){}", p.name));
                }
            }
            fmt.push_str(")\\n\"");
            c.push_str(&format!("{fmt}{args});\n"));
            // the writes: only what the MVE table declares for this (callee, param)
            for p in &d.params {
                if !p.is_ptr || p.is_const {
                    continue;
                }
                let declared = m.writes.iter().find(|(f, pn, _)| *f == d.name && *pn == p.name).map(|(_, _, n)| *n);
                let n = match declared {
                    Some(n) => Some(format!("{n}")),
                    None if p.pointee.starts_with("struct ") || (!p.pointee.is_empty() && p.pointee != "void" && p.pointee != "char" && p.pointee != "int" && !p.pointee.starts_with("unsigned") && !p.pointee.starts_with("short")) => Some(format!("sizeof({})", p.pointee)),
                    None => None,
                };
                if let Some(n) = n {
                    c.push_str(&format!("  twin_fill({}, {});\n", p.name, n));
                }
            }
            if d.ret != "void" {
                if d.ret.starts_with("struct ") || d.ret.chars().next().is_some_and(|ch| ch.is_uppercase()) {
                    c.push_str(&format!("  {{ {} r; twin_fill(&r, sizeof(r)); twin_seq++; return r; }}\n", d.ret));
                } else {
                    c.push_str(&format!("  return ({})(twin_seq++ % 3);\n", d.ret));
                }
            }
            c.push_str("}\n");
        } else {
            // data: arrays of unknown extent get 256 elements; every object in its own section, so
            // the link places it at its FIXTURE address (`--section-start`): the decompiled text
            // reaches it by folded constant, and the twin hosts the fixture's address space (d1)
            let def = if d.decl.ends_with("[]") { d.decl.replace("[]", "[256]") } else { d.decl.clone() };
            let placed = layout.iter().any(|(n, _)| *n == d.name);
            if placed {
                c.push_str(&format!("__attribute__((section(\".twin.{}\"))) {def};\n", d.name));
            } else {
                c.push_str(&format!("{def};\n"));
            }
        }
    }
    // init: every data extern pattern-filled; dump: every data extern's bytes
    c.push_str("void twin_init_data(void) {\n");
    for d in ex.iter().filter(|d| !d.is_fn) {
        c.push_str(&format!("  twin_fill(&{0}, sizeof({0}));\n", d.name));
    }
    c.push_str("}\nvoid twin_dump_data(void) {\n");
    for d in ex.iter().filter(|d| !d.is_fn) {
        c.push_str(&format!("  {{ unsigned i; const unsigned char *b = (const unsigned char *)&{0}; printf(\"data {0}:\"); for (i = 0; i < sizeof({0}); i++) printf(\" %02x\", b[i]); printf(\"\\n\"); }}\n", d.name));
    }
    c.push_str("}\n");
    c
}

/// The driver TU: the input set of the MVE table, with `buf`, `LOG_RET`, `LOG_BYTES`.
pub fn driver_c(m: &Mve) -> String {
    let mut c = String::from("#include <stdio.h>\n");
    c.push_str(&type_lines(m.source));
    for d in externs(m.source) {
        c.push_str(&format!("extern {};\n", d.decl));
    }
    c.push_str(&format!("{};\n", entry_prototype(m.source)));
    c.push_str("void twin_init_data(void); void twin_dump_data(void); void twin_fill(void *p, unsigned n);\n");
    c.push_str("static unsigned char buf[4096];\n#define LOG_RET(e) printf(\"ret %ld\\n\", (long)(e))\n#define LOG_BYTES(p, n) do { unsigned i_; const unsigned char *b_ = (const unsigned char *)(p); printf(\"bytes\"); for (i_ = 0; i_ < (unsigned)(n); i_++) printf(\" %02x\", b_[i_]); printf(\"\\n\"); } while (0)\n");
    c.push_str("int main(void) {\n  twin_init_data();\n  twin_fill(buf, sizeof(buf));\n");
    for s in m.inputs {
        c.push_str("  ");
        c.push_str(s);
        c.push('\n');
    }
    c.push_str("  twin_dump_data();\n  return 0;\n}\n");
    c
}

/// The layout a product was built with: `externs: name=0xaddr ..` from the fixture's header.
pub fn fixture_externs(fixture_text: &str) -> Option<Vec<(String, u64)>> {
    let line = fixture_text.lines().find(|l| l.trim_start().starts_with("externs:"))?;
    let mut out = Vec::new();
    for tok in line.trim_start().trim_start_matches("externs:").split_whitespace() {
        let (n, a) = tok.split_once('=')?;
        out.push((n.to_string(), u64::from_str_radix(a.trim_start_matches("0x"), 16).ok()?));
    }
    Some(out)
}

/// The decompiled side of one MVE: the fixture rendered plain and arm-enabled (the arm set of
/// `recovery::measured_arms`, the recovery of `recovery::recover` over the fixture's bytes), each
/// as a complete TU bound to the MVE's externs. Returns `(plain_tu, arms_tu)`.
pub fn decompiled_tus(m: &Mve, fixture_text: &str) -> Result<(String, String), String> {
    let dt = crate::datatest::parse_str(fixture_text).map_err(|e| format!("fixture: {e:?}"))?;
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = crate::lang::load_cached(lang_id).ok_or_else(|| format!("lang {lang_id}: SLEIGH tables did not load"))?;
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    let plain = print_c_with(&f, &EmitChoices::default());
    let (choices, rec_choices) = crate::recompile::recovery::measured_arms();
    let insns = crate::recompile::insn::normalize(lang_id, dt.chunks[0].bytes.as_slice(), entry, &crate::recompile::insn::NoReloc).unwrap_or_default();
    // no argument-order recovery: `call_arg_orders` is the survey's cross-function derivation over a
    // whole binary's call sites; an MVE fixture has one function and no such tables (stated absence)
    let recovered: RecoveredChoices = crate::recompile::recovery::recover(&f, &insns, &choices, &rec_choices, |_| Default::default());
    let arms = print_c_recovered(&f, &rec_choices, &recovered);
    // the widths of the address-named globals, from the function's own varnodes (as groundtruth does)
    let ram = f.spaces.by_name("ram");
    let mut widths: BTreeMap<u64, u64> = BTreeMap::new();
    for i in 0..f.num_varnodes() as u32 {
        let v = f.vn(crate::decompile::varnode::VarnodeId(i));
        if Some(v.loc.space) == ram && !v.is_constant() {
            let e = widths.entry(v.loc.offset).or_insert(v.size as u64);
            if (v.size as u64) > *e {
                *e = v.size as u64;
            }
        }
    }
    let layout = fixture_externs(fixture_text).ok_or_else(|| format!("{}: the fixture has no `externs:` header line — regenerate it (review R5 d)", m.fixture))?;
    let (code_names, _data_names) = extern_kinds(m.source);
    let ex = externs(m.source);
    let bind = |text: &str| -> String {
        // hosted build: the string intrinsics the string-ops arm emits come from libc
        let mut tu = String::from("#include <string.h>\n");
        tu.push_str(&prelude_for(Target::Gcc32));
        // the struct-copy arm's synthesized `struct pN` types, DERIVED from the text (N bytes as
        // N/4 unsigned ints — the arm's vocabulary, so the binder cannot outgrow it), unless the
        // MVE defines the same struct itself
        let types = type_lines(m.source);
        let mut pn: Vec<usize> = Vec::new();
        for ident in identifiers(text) {
            if let Some(n) = ident.strip_prefix('p').and_then(|d| d.parse::<usize>().ok()) {
                if text.contains(&format!("struct {ident}")) && n % 4 == 0 && n > 0 && !pn.contains(&n) {
                    pn.push(n);
                }
            }
        }
        pn.sort_unstable();
        for n in pn {
            if !types.contains(&format!("struct p{n} ")) {
                let fields: Vec<String> = (0..n / 4).map(|i| format!("unsigned int f{i};")).collect();
                tu.push_str(&format!("struct p{n} {{ {} }};\n", fields.join(" ")));
            }
        }
        tu.push_str(&types);
        for d in &ex {
            tu.push_str(&format!("extern {};\n", d.decl));
        }
        // the entry: the decompiled function is `func`; it defines `mve` under the driver's name
        tu.push_str("#define func mve\n");
        let mut seen = std::collections::BTreeSet::new();
        for ident in identifiers(text) {
            if !seen.insert(ident.clone()) {
                continue;
            }
            let Some(addr) = emitted_symbol_address(&ident) else { continue };
            if ident.starts_with("func_0x") {
                if let Some((name, _)) = layout.iter().find(|(n, a)| *a == addr && code_names.contains(n)) {
                    tu.push_str(&format!("#define {ident} {name}\n"));
                }
                continue;
            }
            if let Some(stem) = ident.find("Ram").map(|i| &ident[..i]) {
                // the data extern whose slot holds this address
                let Some((name, base)) = layout.iter().filter(|(n, a)| !code_names.contains(n) && *a <= addr).max_by_key(|(_, a)| *a) else { continue };
                let off = addr - base;
                let w = widths.get(&addr).copied().unwrap_or(4);
                let ty = prefix_type(stem, w);
                if let Some(elem) = ty.strip_suffix("[]") {
                    tu.push_str(&format!("#define {ident} ((({elem} *)((char *)&{name} + {off})))\n"));
                } else {
                    tu.push_str(&format!("#define {ident} (*({ty} *)((char *)&{name} + {off}))\n"));
                }
            }
        }
        tu.push_str(text);
        tu
    };
    Ok((bind(&plain), bind(&arms)))
}

fn identifiers(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// One program of the twin: `gcc -m32` over the given TUs, run, stdout + status.
fn build_and_run(dir: &Path, tag: &str, tus: &[(&str, &str)], place: &[String]) -> Result<String, String> {
    // gcc 14 promotes these to errors; they are the decompiler's casts, not codegen (as the
    // ground-truth oracle compiles its TUs)
    let mut args: Vec<String> = ["-m32", "-O1", "-w", "-fno-strict-aliasing", "-fno-pie", "-no-pie", "-D__cdecl=", "-Wno-error=int-conversion", "-Wno-error=incompatible-pointer-types", "-Wno-error=implicit-function-declaration"].iter().map(|s| s.to_string()).collect();
    args.extend(place.iter().cloned());
    args.push("-o".into());
    let exe = dir.join(format!("{tag}.twin"));
    args.push(exe.to_string_lossy().to_string());
    for (name, text) in tus {
        let p = dir.join(format!("{tag}.{name}.c"));
        std::fs::write(&p, text).map_err(|e| e.to_string())?;
        args.push(p.to_string_lossy().to_string());
    }
    let o = Command::new("gcc").args(&args).output().map_err(|e| format!("gcc: {e}"))?;
    if !o.status.success() {
        return Err(format!("{tag}: gcc failed:\n{}", String::from_utf8_lossy(&o.stderr)));
    }
    let r = Command::new(&exe).output().map_err(|e| format!("run: {e}"))?;
    Ok(format!("{}status {}\n", String::from_utf8_lossy(&r.stdout), r.status.code().unwrap_or(-1)))
}

/// The twin build of one MVE.
#[derive(Debug)]
pub struct TwinResult {
    pub key: &'static str,
    pub source_trace: String,
    /// `Ok(trace)` or the compile/run error of the decompiled side.
    pub plain: Result<String, String>,
    pub arms: Result<String, String>,
    pub plain_tu: String,
    pub arms_tu: String,
}

impl TwinResult {
    pub fn plain_matches(&self) -> bool {
        self.plain.as_ref().is_ok_and(|t| *t == self.source_trace)
    }
    pub fn arms_matches(&self) -> bool {
        self.arms.as_ref().is_ok_and(|t| *t == self.source_trace)
    }
    /// The arms trace equals the plain trace (both built, same behaviour) — or NEITHER built: two
    /// build failures compare as "the same way", because the twin cannot judge behaviour it
    /// cannot build (a different gcc message is not evidence that the arm changed behaviour).
    pub fn arms_eq_plain(&self) -> bool {
        matches!((&self.plain, &self.arms), (Ok(p), Ok(a)) if p == a) || matches!((&self.plain, &self.arms), (Err(_), Err(_)))
    }
    /// The three-way classification (reviewer's note, R5 d): source vs plain, source vs arms,
    /// plain vs arms.
    pub fn class(&self) -> &'static str {
        match (self.plain_matches(), self.arms_matches(), self.arms_eq_plain()) {
            (true, true, _) => "SAME/SAME",
            (true, false, _) => "WRONG-CODE ARM (source == plain, source != arms)",
            (false, true, _) => "plain wrong, arms right (an arm repairing a decompiler defect)",
            (false, false, true) => "both wrong, same way (one decompiler finding)",
            (false, false, false) => "both wrong, differently (a decompiler finding AND a probable wrong-code arm on top)",
        }
    }
    /// The first line where `trace` departs from the source trace.
    pub fn first_diff(&self, trace: &Result<String, String>) -> String {
        match trace {
            Err(e) => e.lines().next().unwrap_or("").to_string(),
            Ok(t) => {
                for (i, (a, b)) in self.source_trace.lines().zip(t.lines()).enumerate() {
                    if a != b {
                        return format!("line {}: source `{a}` vs `{b}`", i + 1);
                    }
                }
                format!("lengths differ: source {} lines, twin {} lines", self.source_trace.lines().count(), t.lines().count())
            }
        }
    }
}

/// Build and run the twin of `m`: the MVE source vs its decompilation (plain and arms), all
/// against one compilation of the stubs and the driver.
pub fn twin(m: &Mve, workdir: &Path) -> Result<TwinResult, String> {
    let dir: PathBuf = workdir.join(m.key);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let fixture_text = std::fs::read_to_string(crate::paths::oracle_fixtures_dir().join(m.fixture)).map_err(|e| format!("{}: {e}", m.fixture))?;
    let layout = fixture_externs(&fixture_text).ok_or_else(|| format!("{}: the fixture has no `externs:` header line — regenerate it (review R5 d1)", m.fixture))?;
    let (code_names, _) = extern_kinds(m.source);
    let data_layout: Vec<(String, u64)> = layout.iter().filter(|(n, _)| !code_names.contains(n)).cloned().collect();
    // every data extern at its fixture address, in BOTH programs (one definition, one place)
    let place: Vec<String> = data_layout.iter().map(|(n, a)| format!("-Wl,--section-start=.twin.{n}={a:#x}")).collect();
    let stubs = stubs_c(m, &data_layout);
    let driver = driver_c(m);
    let source_trace = build_and_run(&dir, "source", &[("stubs", &stubs), ("driver", &driver), ("mve", m.source)], &place)?;
    let (plain_tu, arms_tu) = decompiled_tus(m, &fixture_text)?;
    let plain = build_and_run(&dir, "plain", &[("stubs", &stubs), ("driver", &driver), ("mve", &plain_tu)], &place);
    let arms = build_and_run(&dir, "arms", &[("stubs", &stubs), ("driver", &driver), ("mve", &arms_tu)], &place);
    Ok(TwinResult { key: m.key, source_trace, plain, arms, plain_tu, arms_tu })
}
