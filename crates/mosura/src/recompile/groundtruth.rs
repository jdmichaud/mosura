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
use std::time::{Duration, Instant};

use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

use super::verify::{emitted_symbol_address, verify, Subject};
use crate::analysis::program::Program;
use crate::analysis::{self, decompiler::decompile_function};
use crate::decompile::funcdata::Funcdata;
use crate::decompile::space::Address;
use crate::decompile::types::Datatype;

/// The ground-truth build recipe (`oracle/ground-truth/build.sh`, `GCC_FLAGS`): freestanding,
/// static, non-PIC, `-O2`. Used for the build AND the recompile — `-no-pie` is a codegen flag
/// (non-PIC addressing), so it must be present on the `-c` line too.
pub const GCC_FLAGS: &[&str] =
    &["-nostdlib", "-static", "-no-pie", "-O2", "-ffreestanding", "-fno-asynchronous-unwind-tables"];
/// The SLEIGH language of the host gcc column.
pub const LANG: &str = "x86:LE:64:default";
/// The SLEIGH language of the 32-bit gcc column (`-m32`; review R5).
pub const LANG32: &str = "x86:LE:32:default";

/// The gcc column a program is built and measured in (review R5, commit b). `Gcc64` is the host
/// column every ground-truth baseline was taken in; `Gcc32` is the `-m32` column the arms are
/// written for (they read 32-bit x86 facts and Watcom idioms — never a 64-bit build). The i386
/// SysV path through the ELF analysis has never been measured: plain-32 verdicts are REPORTED
/// per program, never asserted against the 64-bit baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Gcc64,
    Gcc32,
}

impl Target {
    /// The build/compile/link flags: `GCC_FLAGS`, plus `-m32` for the 32-bit column.
    pub fn flags(self) -> Vec<&'static str> {
        let mut f = GCC_FLAGS.to_vec();
        if self == Target::Gcc32 {
            f.push("-m32");
        }
        f
    }
    pub fn lang(self) -> &'static str {
        match self {
            Target::Gcc64 => LANG,
            Target::Gcc32 => LANG32,
        }
    }
    /// The workdir suffix of the per-target ANALYSIS dir (the original's build, its symbols, the
    /// decompilation): empty for the host column, so its ELF stays where it always was.
    pub fn dir_suffix(self) -> &'static str {
        match self {
            Target::Gcc64 => "",
            Target::Gcc32 => ".gcc32",
        }
    }
    pub fn tag(self) -> &'static str {
        match self {
            Target::Gcc64 => "gcc64",
            Target::Gcc32 => "gcc32",
        }
    }
}

/// How the oracle renders each function (review R5, commit b): `plain` = the reference rendering
/// (`print_c`, what every existing baseline measured); `arms` = the survey's MEASURED configuration
/// — the canonical arm set, `sum-order=original` on the recovered pass, and the per-function
/// recovery (`recovery::recover`) over the program's own instructions — so the arms' renderings
/// are executed by a compiler that is not Watcom.
#[derive(Debug, Clone)]
pub struct EmitPlan {
    pub name: &'static str,
    /// The arm of the report pass / the plain rendering.
    pub choices: crate::decompile::emit::EmitChoices,
    /// The arm the recovered passes render under.
    pub rec_choices: crate::decompile::emit::EmitChoices,
    /// Recover per-site decisions from the function's instructions and render the recovered text.
    pub recover: bool,
}

impl EmitPlan {
    pub fn plain() -> Self {
        let d = crate::decompile::emit::EmitChoices::default();
        EmitPlan { name: "plain", choices: d.clone(), rec_choices: d, recover: false }
    }
    pub fn arms() -> Self {
        let (mut choices, mut rec_choices) = crate::recompile::recovery::measured_arms();
        // The gcc column's own arm (docs/struct-return-arm.md): the survey's canonical set does not
        // carry it (Watcom's tree is measured without it; the identity emit proves it cannot move).
        choices.set("struct-return", "witness").expect("known axis");
        rec_choices.set("struct-return", "witness").expect("known axis");
        EmitPlan { name: "arms", choices, rec_choices, recover: true }
    }
    /// The workdir suffix that keeps the columns and plans apart; empty for the host plain run,
    /// so every existing path stays where it was.
    pub fn dir_suffix(&self, target: Target) -> String {
        match (target, self.recover) {
            (Target::Gcc64, false) => String::new(),
            _ => format!(".{}.{}", target.tag(), self.name),
        }
    }
}

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
    /// The attributed comparison (aligned original/candidate streams), when one was made.
    pub checked: Option<super::verify::Checked>,
    /// The emitted C (the whole translation unit).
    pub c: String,
    /// The function's own C (what the decompiler printed, before TU assembly).
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct GtReport {
    pub program: String,
    pub functions: Vec<GtFunction>,
    /// Where the emitted TUs and objects were written.
    pub workdir: PathBuf,
    /// Every function's original bytes `(symbol, va, bytes)` — for fixtures.
    pub original_bytes: Vec<(String, u64, Vec<u8>)>,
    /// The functional check: every recompiled function linked into one program and RUN; the
    /// exit status is the program's result. `PASS` (same status as the original), `FAIL(o,n)`,
    /// `FAIL(timeout)` (ours was killed by `timeout 5`), `NOLINK` (an object failed or the link
    /// did), `NORUN` / `NORUN(timeout)` (the original could not be run, or was killed — 124 is
    /// `timeout`'s own status and is never compared as a result).
    pub functional: String,
    /// The column ([`Target::tag`]) and the plan ([`EmitPlan::name`]) this report measured.
    pub target: &'static str,
    pub plan: &'static str,
    /// Where the time went, per stage (the census that sizes the speed work; gt speed, commit 0).
    pub timings: GtTimings,
}

/// Wall time per stage of one `recompile_program` pass. `build` covers the gcc build of the
/// original and its symbol table; `decompile` every `decompile_function`; `render` the C text
/// (plain print or recovery + recovered print); `compile` every per-TU `gcc -c` including the
/// prototype retries; `verify` the SLEIGH alignment; `link` the harness build and the link; `run`
/// the two executions.
#[derive(Debug, Clone, Copy, Default)]
pub struct GtTimings {
    pub build: Duration,
    pub analyze: Duration,
    pub decompile: Duration,
    pub render: Duration,
    pub compile: Duration,
    pub verify: Duration,
    pub link: Duration,
    pub run: Duration,
}

impl GtTimings {
    pub fn add(&mut self, o: &GtTimings) {
        self.build += o.build;
        self.analyze += o.analyze;
        self.decompile += o.decompile;
        self.render += o.render;
        self.compile += o.compile;
        self.verify += o.verify;
        self.link += o.link;
        self.run += o.run;
    }
    pub fn total(&self) -> Duration {
        self.build + self.analyze + self.decompile + self.render + self.compile + self.verify + self.link + self.run
    }
    /// One line, seconds per stage, for a test's summary.
    pub fn line(&self) -> String {
        let s = |d: Duration| d.as_secs_f64();
        format!(
            "build {:.1}s analyze {:.1}s decompile {:.1}s render {:.1}s gcc-c {:.1}s verify {:.1}s link {:.1}s run {:.1}s (stages {:.1}s)",
            s(self.build), s(self.analyze), s(self.decompile), s(self.render), s(self.compile), s(self.verify), s(self.link), s(self.run), s(self.total())
        )
    }
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
            "{}: {} fns, weight {}, WGSS {:.4}, EXACT {}, SAME_SHAPE {}, MISMATCH {}, COMPILE_FAIL {}, DECOMPILE_FAIL {}, functional {}",
            self.program,
            self.functions.len(),
            self.functions.iter().map(|f| f.weight).sum::<usize>(),
            self.wgss(),
            self.count("EXACT"),
            self.count("SAME_SHAPE") + self.count("SAME_CODE"),
            self.count("MISMATCH"),
            self.count("COMPILE_FAIL"),
            self.count("DECOMPILE_FAIL"),
            self.functional,
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

/// `gcc <target flags> -I<srcdir> -o <out> <src>` — the unstripped program (symbols are the truth).
pub fn build_program(src: &Path, out: &Path, target: Target) -> Result<(), String> {
    let srcdir = src.parent().unwrap_or(Path::new("."));
    let o = Command::new("gcc")
        .args(target.flags())
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

/// `size` bytes of the original image at `addr`, when the image covers them.
fn image_bytes(program: &crate::analysis::program::Program, addr: u64, size: u64) -> Option<Vec<u8>> {
    let size = size.clamp(1, 64) as usize;
    let b = program.memory.read_window(Address::new(program.default_space, addr), size);
    if b.len() == size { Some(b) } else { None }
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
pub(crate) fn prefix_type(prefix: &str, width: u64) -> String {
    let scalar = |c: char, w: u64| -> String {
        match c {
            'i' => format!("int{w}"),
            'u' => format!("uint{w}"),
            'c' => "char".into(),
            'b' => "uint1".into(),
            // Ghidra's `TypeFloat::printNameBase` is `f` at EVERY width (float, double, long
            // double); the width decides the type — `fRam0000000000402000` (8 bytes) is a double.
            // Rendering it `float` read the low half of 0.5 as 0.0f (floats' favg/fpoly).
            'f' => format!("float{w}"),
            'd' => format!("float{w}"),
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
/// [`prelude`] for a column: the host prelude, or its 32-bit form — every 8-byte C type is
/// `long long` (an i386 `long` is 4 bytes), `pointer` is 4 bytes, and the `__int128` types go
/// (no such type on i386).
pub fn prelude_for(target: Target) -> String {
    let p = prelude();
    if target == Target::Gcc64 {
        return p;
    }
    let mut q = String::new();
    for line in p.lines() {
        if line.contains("__int128") {
            continue;
        }
        let mut l = line.replace("typedef unsigned long pointer;", "typedef unsigned int pointer;");
        l = l.replace("typedef unsigned long ", "typedef unsigned long long ").replace("typedef long ", "typedef long long ");
        l = l.replace("typedef long long double", "typedef long double");
        q.push_str(&l);
        q.push('\n');
    }
    q
}

/// The emitted C names a function's prototype model when it is not the spec's default
/// (`int4 __regparm3 f(int4 n)`, Ghidra's `printModelInDecl`); the prelude defines every
/// non-default model name a cspec can select as EMPTY, because the harness (`-Dstatic=` makes the
/// original's functions global) calls our interposed definitions with the platform's default
/// convention — the register convention matters only to byte-similarity, not to this oracle's
/// functional verdict.
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
         extern long syscall(void); extern long swi(int); extern unsigned long rdtsc(void); extern unsigned int cpuid(unsigned int);\n\
         #define true 1\n#define false 0\n\
         #define va_start(ap, last) ((ap) = (void *)__builtin_next_arg(last))\n\
         #define __regparm3\n#define __regparm2\n#define __regparm1\n#define __stdcall\n#define __fastcall\n\
         #define __thiscall\n#define __vectorcall\n#define __pascal\n",
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

/// The text of function `name` in a C source (from its signature line to the matching close
/// brace) — the real source, for the three-way read beside our C and the divergence rows.
pub fn source_function(src: &str, name: &str) -> Option<String> {
    let mut start = None;
    for (i, line) in src.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("//") || t.starts_with('#') || t.starts_with('*') {
            continue;
        }
        if let Some(pos) = line.find(name) {
            let after = &line[pos + name.len()..];
            let before = &line[..pos];
            let prev = before.chars().last();
            if after.trim_start().starts_with('(')
                && !before.contains('=')
                && !before.trim_end().ends_with("return")
                && prev.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
                && !line.trim_end().ends_with(';')
            {
                start = Some(i);
                break;
            }
        }
    }
    let start = start?;
    let lines: Vec<&str> = src.lines().collect();
    let mut depth = 0i32;
    let mut seen = false;
    let mut end = start;
    for (i, line) in lines.iter().enumerate().skip(start) {
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
                seen = true;
            } else if ch == '}' {
                depth -= 1;
            }
        }
        if seen && depth <= 0 {
            end = i;
            break;
        }
    }
    Some(lines[start..=end].join("\n"))
}

/// The largest argument count over the calls of `name` in `c` (top-level commas).
fn call_site_arity(c: &str, name: &str) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut search = 0;
    while let Some(pos) = c[search..].find(name) {
        let at = search + pos;
        let before = c[..at].chars().last();
        let after = &c[at + name.len()..];
        if before.is_none_or(|ch| !(ch.is_ascii_alphanumeric() || ch == '_')) && after.trim_start().starts_with('(') {
            let open = at + name.len() + after.find('(')?;
            let mut depth = 0i32;
            let mut commas = 0usize;
            let mut nonblank = false;
            for (i, ch) in c[open..].char_indices() {
                match ch {
                    '(' | '[' => depth += 1,
                    ')' | ']' => {
                        depth -= 1;
                        if depth == 0 {
                            let n = if nonblank { commas + 1 } else { 0 };
                            best = Some(best.map_or(n, |b| b.max(n)));
                            search = open + i + 1;
                            break;
                        }
                    }
                    ',' if depth == 1 => commas += 1,
                    ch if depth >= 1 && !ch.is_whitespace() => nonblank = true,
                    _ => {}
                }
            }
            if search <= at {
                search = at + name.len();
            }
            continue;
        }
        search = at + name.len();
    }
    best
}

/// The struct declarations the struct-return arm prints before a definition: the leading lines
/// of the emitted text of the form `struct sN { .. };` (before the signature line).
fn struct_preamble(c: &str) -> Vec<&str> {
    c.lines().take_while(|l| !l.contains('(')).filter(|l| l.starts_with("struct s") && l.ends_with("};")).collect()
}

/// The parameter declarations of a signature line (`int4 f(int4 a, uint8 b)` → the two).
fn signature_params(sig: &str) -> Vec<String> {
    let Some(open) = sig.find('(') else { return Vec::new() };
    let inner = sig[open + 1..].trim_end_matches(')').trim();
    if inner.is_empty() || inner == "void" {
        return Vec::new();
    }
    inner.split(',').map(|p| p.trim().to_string()).collect()
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
/// One function's plan-independent analysis: the ELF symbol, its decompilation (kept alive so every
/// plan renders from the same `Funcdata`), and the two Funcdata-only walks the TU assembly needs —
/// global widths/types by address, address-of widths by emitted name (see `analyze_program`).
pub struct AnalyzedFn {
    sym: ElfSymbol,
    f: Option<Funcdata>,
    globals: BTreeMap<u64, (u32, Datatype)>,
    /// Address-of references by emitted name (`&xRam…`), at the PTRSUB's pointee width.
    addr_of: BTreeMap<String, (u32, Datatype)>,
}

/// Everything about a program that no emit plan changes (gt speed, commit 1): the gcc build of the
/// original, its symbols, the analysis, every function's decompilation. Built once by
/// [`analyze_program`], rendered and checked per plan by [`render_and_check`] — the arms are
/// emit-time choices and the recovery reads the function's own bytes, so the second plan of the
/// arms oracle used to repeat all of this for nothing.
pub struct Analyzed {
    pub program_name: String,
    pub src: PathBuf,
    pub target: Target,
    /// The original, built in the per-target analysis dir (`workdir/<program><Target::dir_suffix>`).
    pub bin_path: PathBuf,
    program: Program,
    symmap: BTreeMap<String, u64>,
    data_syms: BTreeMap<String, u64>,
    data_sizes: BTreeMap<u64, u64>,
    syms_by_name_sizes: BTreeMap<String, u64>,
    fn_bytes: BTreeMap<u64, Vec<u8>>,
    functions: Vec<AnalyzedFn>,
    /// `build`, `analyze`, `decompile` — the stages this step performed.
    pub timings: GtTimings,
}

/// The plan-independent half of the oracle: build the original, read its symbols, analyze it and
/// decompile every function. See [`Analyzed`].
pub fn analyze_program(src: &Path, workdir: &Path, target: Target) -> Result<Analyzed, String> {
    let program_name = src.file_stem().and_then(|s| s.to_str()).unwrap_or("prog").to_string();
    let adir = workdir.join(format!("{program_name}{}", target.dir_suffix()));
    std::fs::create_dir_all(&adir).map_err(|e| e.to_string())?;
    let bin_path = adir.join(format!("{program_name}.elf"));
    let mut t = GtTimings::default();
    let t0 = Instant::now();
    build_program(src, &bin_path, target)?;
    let bin = std::fs::read(&bin_path).map_err(|e| e.to_string())?;
    let (syms, fn_bytes) = elf_symbols(&bin)?;
    t.build = t0.elapsed();
    let symmap: BTreeMap<String, u64> = syms.iter().map(|s| (s.name.clone(), s.addr)).collect();
    let data_syms: BTreeMap<String, u64> =
        syms.iter().filter(|s| !s.is_func).map(|s| (s.name.clone(), s.addr)).collect();
    let data_sizes: BTreeMap<u64, u64> = syms.iter().filter(|s| !s.is_func).map(|s| (s.addr, s.size)).collect();
    let syms_by_name_sizes: BTreeMap<String, u64> =
        syms.iter().filter(|s| !s.is_func).map(|s| (s.name.clone(), s.size)).collect();
    let t0 = Instant::now();
    let mut program = analysis::analyze_file(&bin_path).map_err(|e| format!("analyze: {e:?}"))?;
    // THE CALLERS' SIDE (Ghidra `ActionDefaultParams`, coreaction.cc:2309-2327): a call whose callee
    // has a recovered prototype copies it, so the call's arguments are the callee's parameters in
    // the callee's model's slot order. Ghidra's decompiler gets those prototypes from the program
    // database, where the Decompiler-Parameter-ID analyzer committed them; mosura's whole-program
    // prototype pass (`analysis::interface::recover_prototypes_for`) is that analyzer — it fills
    // `Program::recovered_protos`, which `record_callee_effects` copies onto every direct call
    // (analysis/decompiler.rs). Over every function of the program; a callee's own prototype does
    // not depend on its callees' (its parameters are its entry reads under its model), so no
    // call-graph order is needed.
    // The program's functions are the ELF's function symbols (what the loop below decompiles), not
    // the analysis' function manager, so the pass takes that list explicitly.
    let entries: Vec<u64> = syms.iter().filter(|s| s.is_func && fn_bytes.contains_key(&s.addr)).map(|s| s.addr).collect();
    program.proto_scope = Some(entries.iter().copied().collect());
    // To a fixpoint: a pass-through chain (deepchain's l1..l8, each handing EAX to the next) needs
    // the callee's prototype known before the caller's own register read counts as used.
    analysis::interface::recover_prototypes_fixpoint(&mut program, entries, 16);
    t.analyze = t0.elapsed();
    let ram = program.default_space;

    // Decompile everything (the callee prototypes come from the callees' own signatures).
    let mut functions: Vec<AnalyzedFn> = Vec::new();
    for s in syms.into_iter().filter(|s| s.is_func && fn_bytes.contains_key(&s.addr)) {
        let t0 = Instant::now();
        let f = decompile_function(&program, Address::new(ram, s.addr));
        t.decompile += t0.elapsed();
        let (f, globals, addr_of) = match f {
            Some(f) => {
                if std::env::var("MOSURA_GT_RAW").is_ok_and(|v| v == s.name) {
                    eprint!("{}", f.print_raw());
                }
                let mut globals = BTreeMap::new();
                let mut addr_of: BTreeMap<String, (u32, Datatype)> = BTreeMap::new();
                for i in 0..f.num_varnodes() as u32 {
                    let v = f.vn(crate::decompile::varnode::VarnodeId(i));
                    if v.loc.space == ram && !v.is_constant() {
                        let e = globals.entry(v.loc.offset).or_insert((v.size, v.get_type()));
                        if v.size > e.0 {
                            *e = (v.size, v.get_type());
                        }
                    }
                }
                // An ADDRESS-OF reference (`ActionConstantPtr`'s `PTRSUB(#spacebase, #addr)`,
                // printed `&xRam…`) has no varnode at the address; its C width is the pointee
                // the PTRSUB carries, because `&x + k` scales by sizeof(x): fnptr's `apply`
                // indexes its table `&xRam402fe0 + (which & 3) * 8` through an `undefined *`,
                // and an 8-byte default declaration made that stride 64 (SIGSEGV).
                for op in f.op_ids() {
                    let o = f.op(op);
                    if o.is_dead() || o.code() != crate::decompile::opcode::OpCode::Ptrsub {
                        continue;
                    }
                    let (Some(b), Some(a), Some(out)) = (o.input(0), o.input(1), o.output) else { continue };
                    if !(f.vn(b).is_constant() && f.vn(b).is_spacebase() && f.vn(a).is_constant()) {
                        continue;
                    }
                    let pointee = f.vn(out).get_type().ptr_to().cloned().unwrap_or(Datatype::Unknown(1));
                    let addr = f.spaces.get(ram).wrap_offset(f.vn(a).constant_value());
                    // Keyed by the NAME the printer emits: the same address reached as a 4-byte
                    // `iRam…` value and as the byte-pointer base `&xRam…` of a PTRADD are two
                    // declarations, each at its own width — one shared width made the byte
                    // walk `&xRam403040 + n * 4` scale by 4 (ptrarith after the `.bss` fix).
                    let name = crate::decompile::varmap::build_internal_variable_name(&f.spaces, ram, addr, &pointee);
                    addr_of.entry(name).or_insert((pointee.size().max(1), pointee.clone()));
                    globals.entry(addr).or_insert((pointee.size().max(1), pointee));
                }
                (Some(f), globals, addr_of)
            }
            None => (None, BTreeMap::new(), BTreeMap::new()),
        };
        functions.push(AnalyzedFn { sym: s, f, globals, addr_of });
    }
    Ok(Analyzed {
        program_name,
        src: src.to_path_buf(),
        target,
        bin_path,
        program,
        symmap,
        data_syms,
        data_sizes,
        syms_by_name_sizes,
        fn_bytes,
        functions,
        timings: t,
    })
}

/// The per-plan half of the oracle: render every function under the plan, assemble and compile
/// the TUs, verify, link and run. The report's `timings` cover this half only (`render` .. `run`);
/// [`recompile_program`] adds the analysis stages. See [`Analyzed`].
pub fn render_and_check(a: &Analyzed, workdir: &Path, plan: &EmitPlan) -> Result<GtReport, String> {
    let program_name = a.program_name.clone();
    let target = a.target;
    let src = a.src.as_path();
    let bin_path = a.bin_path.as_path();
    let program = &a.program;
    let dir = workdir.join(format!("{program_name}{}", plan.dir_suffix(target)));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut t = GtTimings::default();
    let (data_syms, data_sizes, syms_by_name_sizes, fn_bytes) = (&a.data_syms, &a.data_sizes, &a.syms_by_name_sizes, &a.fn_bytes);
    let symmap = a.symmap.clone();
    // The plan's rendering of every function, with what the TU assembly reads of it.
    struct Dec<'a> {
        sym: &'a ElfSymbol,
        c: Option<String>,
        self_name: String,
        sig: String,
        globals: &'a BTreeMap<u64, (u32, Datatype)>,
        addr_of: &'a BTreeMap<String, (u32, Datatype)>,
    }
    let mut decs: Vec<Dec<'_>> = Vec::new();
    for af in &a.functions {
        let s = &af.sym;
        let (c, self_name, sig) = match &af.f {
            Some(f) => {
                let t0 = Instant::now();
                let c = if plan.recover {
                    // the survey's recovery over THIS program's instructions (recompile::recovery)
                    let insns = crate::recompile::insn::normalize(
                        target.lang(),
                        &fn_bytes[&s.addr],
                        s.addr,
                        &crate::recompile::insn::NoReloc,
                    )
                    .unwrap_or_default();
                    // `call_arg_orders` is the survey's CROSS-FUNCTION derivation (its site_orders /
                    // order_excluded / arg_reg_offs tables over the whole binary's call sites); it has
                    // no counterpart over a gcc program, so no argument order is recovered here — a
                    // stated absence, not an omission (review R5 b, fable-b's note).
                    let recovered = crate::recompile::recovery::recover(&f, &insns, &plan.choices, &plan.rec_choices, |_| Default::default());
                    crate::decompile::printc::print_c_recovered(&f, &plan.rec_choices, &recovered)
                } else {
                    crate::decompile::printc::print_c_with(&f, &plan.choices)
                };
                t.render += t0.elapsed();
                let (n, sig) = signature(&c).unwrap_or((String::from("func"), String::from("int func()")));
                (Some(c), n, sig)
            }
            None => (None, String::new(), String::new()),
        };
        decs.push(Dec { sym: s, c, self_name, sig, globals: &af.globals, addr_of: &af.addr_of });
    }
    let by_addr: BTreeMap<u64, usize> = decs.iter().enumerate().map(|(i, d)| (d.sym.addr, i)).collect();
    let sym_addrs: std::collections::BTreeSet<u64> = symmap.values().copied().collect();
    let symmap_has = move |a: &u64| sym_addrs.contains(a);
    let resolver = move |sym: &str| -> Option<u64> {
        symmap.get(sym).copied().or_else(|| emitted_symbol_address(sym))
    };

    let pre = prelude_for(target);
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
                checked: None,
                c: String::new(),
                body: String::new(),
            });
            continue;
        };
        // Prototypes for every function the body names, under the name the body uses, with the
        // callee's decompiled signature; `kr = true` retries with unprototyped declarations.
        let ids = identifiers(c);
        let make_tu = |kr: bool, fixed: &BTreeMap<String, String>| -> String {
            let mut tu = pre.clone();
            for id in &ids {
                if *id == d.self_name {
                    continue;
                }
                let callee = resolver(id).and_then(|a| by_addr.get(&a)).map(|&j| &decs[j]);
                if let Some(callee) = callee {
                    // (A self-call spelled `func_0x<own address>` is declared too: the object
                    // then carries an undefined symbol the resolver maps back to the function.)
                    if let Some(proto) = fixed.get(id) {
                        tu += &format!("{proto};\n");
                    } else if kr || callee.c.is_none() {
                        tu += &format!("extern int4 {id}();\n");
                    } else {
                        // a struct-returning callee's `struct sN { .. };` (the struct-return arm's
                        // preamble) travels with its extern, once per TU, unless this TU's own
                        // text already declares that layout
                        for l in struct_preamble(callee.c.as_deref().unwrap_or("")) {
                            if !c.contains(l) && !tu.contains(l) {
                                tu += l;
                                tu += "\n";
                            }
                        }
                        tu += &format!("{};\n", callee.sig.replacen(&callee.self_name, id, 1));
                    }
                    continue;
                }
                // A global: by its emitted address name or its real symbol.
                let addr = data_syms.get(id).copied().or_else(|| {
                    if id.contains("Ram") { emitted_symbol_address(id) } else { None }
                });
                if let Some(a) = addr {
                    // A global with NO symbol at its address is a compiler-private constant
                    // (a `.rodata` float literal, a string): `extern` cannot link it, so it is
                    // DEFINED here from the original image's bytes, as the original did.
                    let named = data_syms.values().any(|&x| x == a) || symmap_has(&a);
                    if !named {
                        if let Some(bytes) = image_bytes(program, a, d.globals.get(&a).map(|(w, _)| *w as u64).unwrap_or(8)) {
                            let width = bytes.len() as u64;
                            let ty = match id.find("Ram") {
                                Some(pos) if pos <= 3 => prefix_type(&id[..pos], width),
                                _ => format!("uint{width}"),
                            };
                            let mut v = 0u64;
                            for (i, b) in bytes.iter().enumerate().take(8) {
                                v |= (*b as u64) << (8 * i);
                            }
                            let init = match ty.as_str() {
                                "float4" => format!("{:?}f", f32::from_bits(v as u32)),
                                "float8" => format!("{:?}", f64::from_bits(v)),
                                "float10" | "float16" => {
                                    // An x87 extended literal: keep the image bytes verbatim.
                                    let items: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
                                    tu += &format!("static const unsigned char {id}_bytes[] = {{{}}};\n", items.join(","));
                                    tu += &format!("#define {id} (*(const {ty} *){id}_bytes)\n");
                                    continue;
                                }
                                t if t.ends_with("[]") => {
                                    let items: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
                                    format!("{{{}}}", items.join(","))
                                }
                                _ => format!("{v:#x}"),
                            };
                            if let Some(elem) = ty.strip_suffix("[]") {
                                tu += &format!("static const {elem} {id}[] = {init};\n");
                            } else {
                                tu += &format!("static const {ty} {id} = {init};\n");
                            }
                            continue;
                        }
                    }
                    let width = d
                        .addr_of
                        .get(id)
                        .map(|(w, _)| *w as u64)
                        .or_else(|| d.globals.get(&a).map(|(w, _)| *w as u64))
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
            // Callers name this function `func_0x<addr>`; the definition is named by the
            // emitter (`FUN_<addr>`). An alias under the callers' name lets every per-function
            // object link into one program for the functional check.
            let callee_name = format!("func_0x{:08x}", d.sym.addr);
            for alias in [callee_name.as_str(), d.sym.name.as_str()] {
                if d.self_name != alias && d.self_name != "_start" && alias != "_start" && !alias.contains('.') {
                    tu += &format!(
                        "\n{} __attribute__((alias(\"{}\")));\n",
                        d.sig.replacen(&d.self_name, alias, 1),
                        d.self_name
                    );
                }
            }
            tu
        };
        let c_path = dir.join(format!("{}.c", d.sym.name));
        let o_path = dir.join(format!("{}.o", d.sym.name));
        let mut note = String::new();
        let mut obj: Option<Vec<u8>> = None;
        // Prototyped first; when a call site disagrees with the callee's recovered signature
        // on ARITY (a real interface defect — leftover registers read as arguments, or a
        // parameter the callee never reads), re-declare that callee at the call site's arity
        // (the callee's parameter types padded with `uint8` / truncated) so the TU compiles
        // without gcc's unprototyped-call convention (the varargs `XOR EAX,EAX`) masking the
        // defect's true cost. Unprototyped declarations remain the last resort.
        let mut fixed: BTreeMap<String, String> = BTreeMap::new();
        let mut attempts: Vec<(bool, BTreeMap<String, String>)> = vec![(false, BTreeMap::new())];
        let mut first_error = String::new();
        let t0 = Instant::now();
        while let Some((kr, fx)) = attempts.pop() {
            let tu = make_tu(kr, &fx);
            std::fs::write(&c_path, &tu).map_err(|e| e.to_string())?;
            // gcc 14 promotes these to errors; they are diagnostics, not codegen, and the
            // emitted C's casts are the decompiler's business, not the instrument's.
            let o = Command::new("gcc")
                .args(target.flags())
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
                    note = format!("unprototyped callees ({first_error})");
                } else if !fx.is_empty() {
                    note = format!("arity-adjusted callees: {} ({first_error})", fx.keys().cloned().collect::<Vec<_>>().join(","));
                }
                break;
            }
            let err = String::from_utf8_lossy(&o.stderr);
            note = err
                .lines()
                .find(|l| l.contains("error:"))
                .unwrap_or("compile failed")
                .trim()
                .rsplit("error: ")
                .next()
                .unwrap_or("")
                .to_string();
            debug!(crate::debug::Topic::GroundTruth, "{}: attempt kr={kr} fixed={:?} -> {note}", d.sym.name, fx.keys().collect::<Vec<_>>());
            if first_error.is_empty() {
                first_error = note.clone();
            }
            if kr {
                break;
            }
            // `too many/few arguments to function ‘X’` → re-declare X at the call site's arity.
            // `void value not ignored as it ought to be`: a callee whose recovered return is
            // `void` while this caller uses its value — re-declare every void callee in the TU
            // as returning `uint8` (the caller's read decides; a return-recovery defect).
            if note.starts_with("void value not ignored") {
                let mut any = false;
                for id in &ids {
                    if fixed.contains_key(id) {
                        continue;
                    }
                    let Some(callee) = resolver(id).and_then(|a| by_addr.get(&a)).map(|&j| &decs[j]) else { continue };
                    if callee.sig.trim_start().starts_with("void ") && callee.sym.addr != d.sym.addr {
                        let proto = callee.sig.replacen(&callee.self_name, id, 1).replacen("void ", "uint8 ", 1);
                        fixed.insert(id.clone(), proto);
                        any = true;
                    }
                }
                if any {
                    attempts.push((false, fixed.clone()));
                    continue;
                }
            }
            let quoted = |r: &str| -> String {
                let r = r.trim_start_matches(|ch: char| ch == '‘' || ch == '\'' || ch == '`');
                r.split(|ch: char| ch == '’' || ch == '\'' || ch == '`' || ch == ';' || ch.is_whitespace())
                    .next()
                    .unwrap_or("")
                    .to_string()
            };
            let adjusted = note
                .strip_prefix("too many arguments to function ")
                .or_else(|| note.strip_prefix("too few arguments to function "))
                .map(quoted)
                .and_then(|callee_name| {
                    let callee_name = callee_name.as_str();
                    let callee = resolver(callee_name).and_then(|a| by_addr.get(&a)).map(|&j| &decs[j])?;
                    let arity = call_site_arity(c, callee_name)?;
                    let params = signature_params(&callee.sig);
                    let ret = callee.sig[..callee.sig.find(&callee.self_name)?].trim().to_string();
                    let mut ps: Vec<String> = params.into_iter().take(arity).collect();
                    while ps.len() < arity {
                        ps.push(format!("uint8 pad_{}", ps.len()));
                    }
                    let proto = if ps.is_empty() {
                        format!("{ret} {callee_name}(void)")
                    } else {
                        format!("{ret} {callee_name}({})", ps.join(", "))
                    };
                    Some((callee_name.to_string(), proto))
                });
            match adjusted {
                Some((name, proto)) if !fixed.contains_key(&name) => {
                    fixed.insert(name, proto);
                    attempts.push((false, fixed.clone()));
                }
                // Already adjusted once and still wrong: this function calls the callee with
                // DIFFERENT argument counts at different sites (leftover registers at one of
                // them), so no one prototype fits. That callee alone goes unprototyped; its
                // sites then carry gcc's unprototyped-call convention, the cost of the defect.
                Some((name, _)) if !fixed.get(&name).is_some_and(|p| p.ends_with("()")) => {
                    let ret = fixed.get(&name).and_then(|p| p.split_whitespace().next()).unwrap_or("int4").to_string();
                    fixed.insert(name.clone(), format!("{ret} {name}()"));
                    attempts.push((false, fixed.clone()));
                }
                _ => attempts.push((true, BTreeMap::new())),
            }
        }
        t.compile += t0.elapsed();
        let Some(obj) = obj else {
            functions.push(GtFunction {
                symbol: d.sym.name.clone(),
                va: d.sym.addr,
                weight: 0,
                verdict: "COMPILE_FAIL".into(),
                similarity: 0.0,
                classes: BTreeMap::new(),
                note,
                checked: None,
                c: std::fs::read_to_string(&c_path).unwrap_or_default(),
                body: c.clone(),
            });
            continue;
        };
        let subject = Subject { name: d.self_name.clone(), va: d.sym.addr, len: weight_bytes.len() };
        let tu_text = std::fs::read_to_string(&c_path).unwrap_or_default();
        let t0 = Instant::now();
        let verified = verify(target.lang(), &weight_bytes, &subject, &obj, &resolver);
        t.verify += t0.elapsed();
        match verified {
            Ok(checked) => {
                let diff = &checked.diff;
                functions.push(GtFunction {
                    symbol: d.sym.name.clone(),
                    va: d.sym.addr,
                    weight: diff.orig_insns,
                    verdict: diff.verdict.as_str().to_string(),
                    similarity: diff.similarity,
                    classes: diff.class_counts.iter().map(|(k, v)| (k.as_str().to_string(), *v)).collect(),
                    note,
                    c: tu_text,
                    body: c.clone(),
                    checked: Some(checked),
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
                checked: None,
                c: tu_text,
                body: c.clone(),
            }),
        }
    }
    let data_names: Vec<(String, u64)> = data_syms.iter().map(|(n, a)| (n.clone(), *a)).collect();
    let data_name_sizes: BTreeMap<String, u64> = syms_by_name_sizes.clone();
    let (functional, link, run) =
        functional_check(&dir, &program_name, src, bin_path, &functions, &data_names, &data_name_sizes, target);
    t.link = link;
    t.run = run;
    let original_bytes: Vec<(String, u64, Vec<u8>)> =
        decs.iter().map(|d| (d.sym.name.clone(), d.sym.addr, fn_bytes[&d.sym.addr].clone())).collect();
    Ok(GtReport {
        program: program_name,
        functions,
        workdir: dir,
        functional,
        original_bytes,
        target: target.tag(),
        plan: plan.name,
        timings: t,
    })
}

/// The oracle over one program under one plan: [`analyze_program`] then [`render_and_check`], the
/// report carrying every stage's time. The arms oracle analyzes once and renders twice instead.
pub fn recompile_program(src: &Path, workdir: &Path, target: Target, plan: &EmitPlan) -> Result<GtReport, String> {
    let a = analyze_program(src, workdir, target)?;
    let mut r = render_and_check(&a, workdir, plan)?;
    r.timings.add(&a.timings);
    Ok(r)
}

/// One program's results from [`recompile_programs`]: the analysis stages' time and one report per
/// plan, in the plans' order.
pub struct ProgramReports {
    pub analysis: GtTimings,
    pub reports: Vec<GtReport>,
}

/// The worker count the tests use: every core (`available_parallelism`), one program per worker.
pub fn default_workers() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// The oracle over many programs on `workers` threads (gt speed, commit 2): each program is
/// analyzed once and rendered under every plan, in its own directories, and the results come back
/// in program order. Programs are independent of each other: the crate's process-wide state is
/// read-only caches (the language/cspec/spec caches behind `OnceLock` + `Mutex`, the regexes, the
/// debug topics) and its `thread_local!`s are per-run scratch set and read within one decompile
/// (the merge phase, the return-split arm's flag, the analyzers' body cache, the perf accumulator,
/// the trace suppressor). The analysis knobs travel as a value on the program
/// (`switches::Knobs`), so nothing is per-thread configuration any more; `workers = 1` is simply
/// the serial order.
pub fn recompile_programs(
    srcs: &[PathBuf],
    workdir: &Path,
    target: Target,
    plans: &[EmitPlan],
    workers: usize,
) -> Vec<Result<ProgramReports, String>> {
    let workers = workers.max(1).min(srcs.len().max(1));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results: std::sync::Mutex<Vec<Option<Result<ProgramReports, String>>>> =
        std::sync::Mutex::new((0..srcs.len()).map(|_| None).collect());
    std::thread::scope(|sc| {
        for _ in 0..workers {
            sc.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if i >= srcs.len() {
                    break;
                }
                let one = || -> Result<ProgramReports, String> {
                    let a = analyze_program(&srcs[i], workdir, target)?;
                    let mut reports = Vec::with_capacity(plans.len());
                    for plan in plans {
                        reports.push(render_and_check(&a, workdir, plan)?);
                    }
                    Ok(ProgramReports { analysis: a.timings, reports })
                };
                let r = one();
                results.lock().unwrap()[i] = Some(r);
            });
        }
    });
    results.into_inner().unwrap().into_iter().map(|r| r.expect("every program ran")).collect()
}

/// Link every per-function object into one program and run it against the original: the
/// correctness oracle the similarity score cannot be (`sum_to` went from wrong code to right
/// code while its similarity DROPPED). The ground-truth programs are freestanding and report
/// their result through the exit status.
fn functional_check(
    dir: &Path,
    program: &str,
    src: &Path,
    original: &Path,
    functions: &[GtFunction],
    data_syms: &[(String, u64)],
    data_sizes: &BTreeMap<String, u64>,
    target: Target,
) -> (String, Duration, Duration) {
    let t0 = Instant::now();
    let (verdict, run) = functional_verdict(dir, program, src, original, functions, data_syms, data_sizes, target);
    (verdict, t0.elapsed().saturating_sub(run), run)
}

/// The verdict itself; `run` (the two executions) is reported apart from the harness + link time.
#[allow(clippy::too_many_arguments)]
fn functional_verdict(
    dir: &Path,
    program: &str,
    src: &Path,
    original: &Path,
    functions: &[GtFunction],
    data_syms: &[(String, u64)],
    data_sizes: &BTreeMap<String, u64>,
    target: Target,
) -> (String, Duration) {
    if functions.iter().any(|f| f.verdict == "COMPILE_FAIL" || f.verdict == "DECOMPILE_FAIL") {
        return ("NOLINK".into(), Duration::ZERO);
    }
    // The HARNESS: the original source compiled with `static` stripped, so its functions are
    // interposable; it supplies `_start` (whose `syscall` we cannot yet emit), the data, and the
    // source-named calls. Our objects come first and win every function we produced
    // (`--allow-multiple-definition`); our address-named globals map onto the original's data
    // symbols with `--defsym`. `-fno-ipa-ra`: the harness must treat every callee as clobbering
    // the full call-clobbered set — with ipa-ra gcc keeps a value in a register ITS fib never
    // touched, and our interposed fib (correct C, different allocation) clobbers it (recursion's
    // false FAIL(7,55)).
    let harness = dir.join(format!("{program}.harness.o"));
    let h = Command::new("gcc")
        .args(target.flags())
        .args(["-Dstatic=", "-fno-ipa-ra", "-w", "-c", "-I"])
        .arg(src.parent().unwrap_or(Path::new(".")))
        .arg("-o")
        .arg(&harness)
        .arg(src)
        .output();
    if !h.is_ok_and(|o| o.status.success()) {
        return ("NOLINK (harness)".into(), Duration::ZERO);
    }
    let objs: Vec<PathBuf> = functions
        .iter()
        .filter(|f| f.symbol != "_start")
        .map(|f| dir.join(format!("{}.o", f.symbol)))
        .collect();
    // Every `<prefix>Ram<hex>` name our C used, mapped to the original symbol at that address.
    let mut defsyms: Vec<String> = Vec::new();
    for f in functions {
        for id in identifiers(&f.c) {
            if let Some(pos) = id.find("Ram") {
                if pos <= 3 {
                    if let Some(a) = emitted_symbol_address(&id) {
                        // The symbol AT the address, else the data symbol CONTAINING it (a
                        // normalized compare constant like `&iRam403041 <= …` is `grid + 1`).
                        let hit = data_syms
                            .iter()
                            .find(|(_, addr)| *addr == a)
                            .map(|(sym, addr)| (sym.clone(), a - addr))
                            .or_else(|| {
                                data_syms
                                    .iter()
                                    .filter(|(sym, addr)| *addr < a && a < addr + data_sizes.get(sym).copied().unwrap_or(0))
                                    .max_by_key(|(_, addr)| *addr)
                                    .map(|(sym, addr)| (sym.clone(), a - addr))
                            });
                        if let Some((sym, off)) = hit {
                            let d = if off == 0 {
                                format!("-Wl,--defsym,{id}={sym}")
                            } else {
                                format!("-Wl,--defsym,{id}={sym}+{off}")
                            };
                            if !defsyms.contains(&d) {
                                defsyms.push(d);
                            }
                        }
                    }
                }
            }
        }
    }
    let ours = dir.join(format!("{program}.ours"));
    let o = Command::new("gcc")
        .args(target.flags())
        .arg("-Wl,--allow-multiple-definition")
        .args(&defsyms)
        .arg("-o")
        .arg(&ours)
        .args(&objs)
        .arg(&harness)
        .arg("-lgcc")
        .output();
    match o {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            let first = err.lines().find(|l| l.contains("error") || l.contains("undefined")).unwrap_or("").trim();
            return (format!("NOLINK ({})", first.chars().take(80).collect::<String>()), Duration::ZERO);
        }
        Err(_) => return ("NOLINK".into(), Duration::ZERO),
    }
    // `timeout 5`: its own exit status 124 means the program was killed, so 124 is RESERVED — it is
    // never compared as a result. The 32-bit column's exit shim once spun forever and every PASS
    // there was 124 == 124 (gt speed, commit 3); a hang can no longer match a hang.
    let run = |p: &Path| -> Option<i32> {
        Command::new("timeout").arg("5").arg(p).output().ok().map(|o| o.status.code().unwrap_or(-1))
    };
    let t_run = Instant::now();
    let Some(orig_code) = run(original) else { return ("NORUN".into(), t_run.elapsed()) };
    if orig_code == 124 {
        return ("NORUN(timeout)".into(), t_run.elapsed());
    }
    let verdict = match run(&ours) {
        Some(124) => "FAIL(timeout)".into(),
        Some(c) if c == orig_code => "PASS".into(),
        Some(c) => format!("FAIL(orig={orig_code},ours={c})"),
        None => "FAIL(no run)".into(),
    };
    (verdict, t_run.elapsed())
}
