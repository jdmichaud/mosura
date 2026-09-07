//! Is this C a FAITHFUL implementation of that function — regardless of the bytes?
//!
//! `recompile_check` answers "are the bytes the same". That is the right question when the subject
//! was compiled and you are recovering its source. It is the wrong question for a subject written
//! in assembler: there the byte-level differences are register allocation, calling convention and
//! instruction selection, none of which a C source controls, and a candidate can be *provably the
//! same program* while sharing barely a byte.
//!
//! This asks the other question. It runs the ORIGINAL function and the CANDIDATE's compiled code
//! over the same machine state and compares only what a caller could observe:
//!
//!   * every store outside the function's own frame — address, width and value;
//!   * every call, in order, with the arguments that call target's contract names;
//!   * the result register named by the function's own contract — or, for the band of functions
//!     that answer in the CARRY FLAG, the flag a `/*@equiv returns cf in eax */` annotation names
//!     (see [`flag_contracts`], which also covers callees that answer in a flag).
//!
//! Register allocation, frame layout, instruction selection, the order of independent
//! computations, and the function's own entry convention are all free to differ.
//!
//! Method: differential execution under mosura's p-code interpreter ([`sleigh::emu::run_traced`]).
//! Memory that was never written reads as a deterministic function of its address, so a pointer
//! arriving in a register is dereferenceable wherever it points and both runs see the same heap
//! without anyone enumerating it. Calls are events, not entered: the target and its argument
//! registers are recorded, then a deterministic value is written to the clobber set so both runs
//! continue from the same state without either side's return convention being assumed.
//!
//! This is TESTING, not proof: it is sound for finding differences and only ever evidence of
//! sameness. A trace that agrees on N independent random states, with the branch coverage reported,
//! is the claim — never "equivalent" full stop. Read the reported `seeds` and `coverage` before
//! believing a verdict.
//!
//! Usage:
//!   equiv_check <binary> <manifest> <src-dir> <flags-file> <watcom-dir>
//!               [--only <idx>,...] [--seeds N] [--cache <dir>] [--verbose]

use mosura::analysis;
use mosura::decompile::space::Address;
use mosura::recompile::toolchain::{spec, Cached, CompileUnit, CompilerDriver, DriverRole, Toolchain};
use mosura::sleigh::emu::{Effect, FlagReturn, FlagSource, RegReturn, RunConfig};
use std::collections::HashMap;
use std::path::Path;

const LANG: &str = "x86:LE:32:default";

/// x86 register-space offsets of the 32-bit general registers (Ghidra's x86 register space).
const EAX: u64 = 0;
const ECX: u64 = 4;
const EDX: u64 = 8;
const EBX: u64 = 12;
const ESP: u64 = 16;
const EBP: u64 = 20;
const ESI: u64 = 24;
const EDI: u64 = 28;
const GPRS: [(&str, u64); 8] = [
    ("eax", EAX),
    ("ecx", ECX),
    ("edx", EDX),
    ("ebx", EBX),
    ("esp", ESP),
    ("ebp", EBP),
    ("esi", ESI),
    ("edi", EDI),
];

fn reg_by_name(name: &str) -> Option<u64> {
    let n = name.trim().to_ascii_lowercase();
    GPRS.iter().find(|(r, _)| *r == n).map(|(_, o)| *o)
}

/// The one-bit flag registers an annotation may NAME, with their x86 register-space offsets
/// (`ia.sinc:39` — the arithmetic flags are one byte each from 0x200).
///
/// ONLY CF, ZF AND SF, and the list is a MEASUREMENT, not a guess. Counting, over the whole
/// corpus, every conditional jump whose flags come from a `CALL` (no flag-writing instruction in
/// between): CF 201 sites in 106 functions — the `STC`/`CLC` then `JC`/`JNC`/`JB`/`JAE`
/// convention; ZF 32 sites in 24 functions — the `CALL 0x1025d ; JNE` retry loop; SF 3 sites in 1
/// function — `FUN_000166c7`, whose back-face test `FUN_0001682f` ends `ADC ECX,EDX` and whose
/// three `JNS` read the sign of that 64-bit dot product.
///
/// OF, PF and AF are NOT here and should not be added: the same census finds ZERO sites for any of
/// them — not one `JO`/`JNO`/`JP`/`JNP` after a call, and not one signed `JL`/`JGE`/`JG`/`JLE`
/// either, which is the only other way OF could be read. Overflow is an arithmetic side effect,
/// not something a hand-written callee returns, and a name for it would only make it possible to
/// write an annotation that describes nothing.
const NAMED_FLAGS: [(&str, u64); 3] = [("cf", 0x200), ("zf", 0x206), ("sf", 0x207)];

fn flag_by_name(name: &str) -> Option<u64> {
    let n = name.trim().to_ascii_lowercase();
    NAMED_FLAGS.iter().find(|(f, _)| *f == n).map(|(_, o)| *o)
}

/// The stack the candidate and the original both run on. Far from the image, and its window is
/// wide enough for any frame either side builds.
const STACK_TOP: u64 = 0x0f00_0000;
const STACK_WINDOW: (u64, u64) = (STACK_TOP - 0x8000, STACK_TOP + 0x400);

struct Row {
    idx: String,
    va: u64,
    name: String,
    len: usize,
}

fn read_manifest(path: &str) -> Vec<Row> {
    let text = std::fs::read_to_string(path).expect("manifest");
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 5 || f[0] == "idx" {
                return None;
            }
            Some(Row {
                idx: f[0].to_string(),
                va: u64::from_str_radix(f[1], 16).ok()?,
                name: f[2].to_string(),
                len: f[4].parse().ok()?,
            })
        })
        .collect()
}

fn read_flags(path: &str) -> HashMap<String, String> {
    let Ok(text) = std::fs::read_to_string(path) else { return HashMap::new() };
    text.lines()
        .filter_map(|l| l.split_once(char::is_whitespace))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// The source with its comments replaced by spaces, keeping line structure.
///
/// Everything below reads the source as text, and a COMMENT is not source. `returns_void` used to
/// take the first line mentioning the function's name — so an ordinary block comment above the
/// definition ("/* FUN_x(a,b) returns the index */") silently decided its void-ness, and the
/// harness then compared, or refused to compare, the wrong register. Several agents lost a debug
/// cycle each to it. A `#pragma` inside a comment is not a contract either.
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let (mut i, mut block, mut line) = (0usize, false, false);
    while i < b.len() {
        let c = b[i] as char;
        let d = b.get(i + 1).map(|&x| x as char).unwrap_or('\0');
        if block {
            if c == '*' && d == '/' {
                block = false;
                out.push_str("  ");
                i += 2;
                continue;
            }
            out.push(if c == '\n' { '\n' } else { ' ' });
        } else if line {
            if c == '\n' {
                line = false;
                out.push('\n');
            } else {
                out.push(' ');
            }
        } else if c == '/' && d == '*' {
            block = true;
            out.push_str("  ");
            i += 2;
            continue;
        } else if c == '/' && d == '/' {
            line = true;
            out.push_str("  ");
            i += 2;
            continue;
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// The registers a `#pragma aux` clause names, e.g. `modify [eax ecx]` -> `[EAX, ECX]`.
/// The clause ENDS at the next keyword — `parm [eax] modify [ecx]` must not read `ecx` as an
/// argument — and `exact`/`nomemory`/`caller` are modifiers, not registers.
fn pragma_regs(tail: &str, keyword: &str) -> Option<Vec<(u64, u32)>> {
    let at = tail.find(keyword)?;
    let clause = &tail[at + keyword.len()..];
    let end = ["parm ", "value ", "modify ", "aborts", "export", "far", "near"]
        .iter()
        .filter_map(|k| clause.find(k))
        .min()
        .unwrap_or(clause.len());
    let clause = &clause[..end];
    // Only bracket groups count; `modify exact [eax]` has its modifier before the bracket.
    let mut regs = Vec::new();
    for group in clause.split('[').skip(1) {
        let Some(inner) = group.split(']').next() else { break };
        if inner.contains("caller") {
            continue;
        }
        for r in inner.split_whitespace() {
            if let Some(off) = reg_by_name(r) {
                regs.push((off, 4u32));
            }
        }
    }
    Some(regs)
}

/// The callee contracts the candidate's own source declares, as `target VA -> argument registers`.
///
/// `#pragma aux func_0x0001cc88 parm [edi] [eax]` says that callee takes its first argument in EDI
/// and its second in EAX. Both sides are compared through the SAME contract, so a call is compared
/// by the values it passes rather than by which registers happen to hold them — and a candidate
/// that renames a register inside itself is unaffected, while one that passes a different VALUE is
/// caught.
type Contracts = (HashMap<u64, Vec<(u64, u32)>>, std::collections::HashSet<u64>, HashMap<u64, Vec<(u64, u32)>>);
fn callee_contracts(src: &str) -> Contracts {
    let mut out = HashMap::new();
    let mut modifies: HashMap<u64, Vec<(u64, u32)>> = HashMap::new();
    let mut stack: std::collections::HashSet<u64> = Default::default();
    for line in src.lines() {
        let l = line.trim();
        let Some(rest) = l.strip_prefix("#pragma aux ") else { continue };
        let Some((name, tail)) = rest.split_once(' ') else { continue };
        let Some(parm) = tail.find("parm ") else { continue };
        let Some(hex) = name.strip_prefix("func_0x").or_else(|| name.strip_prefix("FUN_")) else { continue };
        let Some(va) = u64::from_str_radix(hex.trim_end_matches('_'), 16).ok() else { continue };
        // `parm [edi] [eax] [ebx]` — one register per bracket group, in argument order. The clause
        // ENDS at the next keyword: `#pragma aux f parm [eax] value [ebx] modify [ecx]` has one
        // argument register, and reading on would take `ebx` and `ecx` for arguments too.
        let clause = &tail[parm..];
        let end = ["value ", "modify ", "aborts", "export", "far", "near"]
            .iter()
            .filter_map(|k| clause.find(k))
            .min()
            .unwrap_or(clause.len());
        let mut regs = Vec::new();
        for group in clause[..end].split('[').skip(1) {
            let Some(inner) = group.split(']').next() else { break };
            if inner.contains("caller") || inner.trim().is_empty() {
                continue;
            }
            for r in inner.split_whitespace() {
                if let Some(off) = reg_by_name(r) {
                    regs.push((off, 4u32));
                }
            }
        }
        if regs.is_empty() {
            // `parm caller []` / `parm []` — the arguments go on the stack.
            stack.insert(va);
        } else {
            out.insert(va, regs);
        }
        // What this callee says it DESTROYS. Absent means "the compiler's default", which is the
        // harness's own fixed clobber set — so only a declared clause is recorded here. The result
        // register (`value [ebx]`) is modified by definition, declared or not.
        if let Some(mut m) = pragma_regs(tail, "modify ") {
            for v in pragma_regs(tail, "value ").unwrap_or_default() {
                if !m.contains(&v) {
                    m.push(v);
                }
            }
            modifies.insert(va, m);
        }
    }
    (out, stack, modifies)
}

/// Does the candidate declare this function `void`? A void function's result register is scratch:
/// comparing it would fail two implementations that agree on everything a caller can see.
fn returns_void(src: &str, name: &str) -> bool {
    // The DEFINITION is `<return type> name ( ... ) {` — the only occurrence of the name followed
    // by a parameter list and then a brace. A prototype ends in `;`, a `#pragma` is not a
    // declaration, and (after `strip_comments`) prose that happens to mention the name is gone.
    let src = strip_comments(src);
    let b = src.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(name) {
        let at = from + rel;
        from = at + name.len();
        // a whole identifier, not a suffix of a longer one
        let before_ok = at == 0 || !(b[at - 1] as char).is_alphanumeric() && b[at - 1] != b'_';
        let mut j = from;
        while j < b.len() && (b[j] as char).is_whitespace() {
            j += 1;
        }
        if !before_ok || b.get(j) != Some(&b'(') {
            continue;
        }
        // walk to the matching ')' and require a '{' after it: this is a definition
        let (mut depth, mut k) = (0i32, j);
        while k < b.len() {
            match b[k] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            k += 1;
        }
        let mut m = k + 1;
        while m < b.len() && (b[m] as char).is_whitespace() {
            m += 1;
        }
        if b.get(m) != Some(&b'{') {
            continue;
        }
        // the return type is what precedes the name, back to the end of the previous statement
        let head_start = src[..at].rfind([';', '}', '{']).map_or(0, |p| p + 1);
        let head = src[head_start..at].trim();
        // `void *f(){...}` returns a pointer, not void.
        return head == "void" || head.split_whitespace().next_back() == Some("void");
    }
    false
}

/// The result register the candidate's own contract names (`value [ebx]`), defaulting to EAX.
fn result_register(src: &str, name: &str) -> u64 {
    let src = strip_comments(src);
    for line in src.lines() {
        let l = line.trim();
        if !l.starts_with("#pragma aux ") || !l.contains(name) {
            continue;
        }
        if let Some(v) = l.find("value ") {
            if let Some(inner) = l[v..].split('[').nth(1).and_then(|g| g.split(']').next()) {
                if let Some(off) = reg_by_name(inner) {
                    return off;
                }
            }
        }
    }
    EAX
}

/// What a source's flag annotations declare: which callees answer in a flag, and whether the
/// SUBJECT itself does.
#[derive(Default)]
struct FlagContracts {
    /// callee VA -> the flag it answers in and the register this source models that answer in.
    callee: HashMap<u64, FlagReturn>,
    /// The address of ONE `CALL` instruction in the ORIGINAL -> the same, for calls that cannot be
    /// named by callee because they have no static target.
    site: HashMap<u64, FlagReturn>,
    /// The subject's own answer: the flag the ORIGINAL leaves at `RET`, and the register the
    /// CANDIDATE returns it in.
    result: Option<FlagReturn>,
    /// callee VA -> the REGISTER that callee leaves its answer in, and the register this source
    /// reads that answer out of instead (`sleigh::emu::RegReturn`).
    callee_reg: HashMap<u64, RegReturn>,
    /// The same, keyed by ONE `CALL` instruction in the ORIGINAL — the only key an indirect call
    /// has, and the case the register form exists for.
    site_reg: HashMap<u64, RegReturn>,
}

/// The flag-valued contracts the candidate's source declares — in COMMENTS.
///
/// Watcom 10.0a has no spelling for a flag result: `#pragma aux f value [cf]` is rejected outright
/// ("invalid register name"), and no C construct reads the flags a call left. So this contract
/// cannot live in a pragma — the compiler must never see it — and it is a magic comment instead,
/// read from the RAW source. (Everything else here reads `strip_comments`ed text, precisely
/// because a comment is not a contract; this one thing is a contract that has nowhere else to go,
/// which is why it is marked so distinctively.)
///
/// Two forms, one per line, anywhere in the file:
///
/// ```text
/// /*@equiv callee 0x000018b4 returns cf in eax */
/// ```
/// The CALLEE at that VA answers in CF; this source models it as answering in EAX. After such a
/// call the ORIGINAL run finds the answer in CF and the CANDIDATE run finds the SAME bit in EAX
/// (`sleigh::emu::FlagReturn`), so the original's `JB` and the candidate's `if (f())` are asked
/// the same question. Declare the callee `value [eax]` as well, or Watcom will not read its result
/// from there.
///
/// ```text
/// /*@equiv returns cf in eax */
/// ```
/// The SUBJECT answers in CF (`STC`/`CLC` before `RET`); this source returns that answer in EAX.
/// The original's flag at `RET` is then compared against the truth of the candidate's EAX. Without
/// this the function has to be declared `void` and its actual answer is not checked at all.
///
/// ```text
/// /*@equiv site 0x00014118 returns cf in eax */
/// ```
/// The CALL INSTRUCTION at that address answers in CF. This is the key an INDIRECT call needs:
/// `CALL dword ptr [0x45320] ; JAE` has no static target — nothing writes 0x45320, so the
/// interpreter fills it and the runtime target is a different word on every seed — and there is
/// therefore no `callee` line that could describe it. The named address must be a `CALL` in this
/// function's own extent, and the call it names must not ALSO be named by a `callee` line.
///
/// A site is an address in the ORIGINAL's text, which the candidate's compiled code does not
/// share, so the correspondence between the two runs is the call's ORDINAL: the original's run
/// reports which calls the site turned out to be and the candidate's run is handed those ordinals
/// (`sleigh::emu::Machine::flag_return_ordinals`). That is the same correspondence the verdict
/// itself uses — effect traces are compared element by element — so it cannot make a differing
/// candidate agree: if the two traces line up at all, the candidate's k-th call is the original's
/// k-th call, and if they do not, the seed is already counted as a disagreement.
///
/// ```text
/// /*@equiv callee 0x0001025d returns zf from eax */
/// ```
/// `from` instead of `in` says the callee's answer is not an invisible boolean but a PREDICATE ON
/// THE VALUE IT RETURNS — the callee ends `TEST EAX,EAX ; RET`, so ZF is `EAX == 0` and SF is its
/// sign bit. Nothing is then delivered in a register: the flag is computed, on BOTH runs, from a
/// register both runs already hold the same value in. It is the only form that fits a callee which
/// answers in a flag AND leaves a value the caller reads — `FUN_0001025d` returns the key in EAX
/// and its ZF says whether there was one — because with `in` the register would have to carry the
/// flag instead of the key. Only `zf` and `sf` may be used with `from`: they are the two
/// predicates `TEST` leaves, and `TEST` clears CF and OF outright.
///
/// ```text
/// /*@equiv site 0x00020e00 returns register ebx in edx */
/// ```
/// The call at that address leaves its answer in the ORIGINAL's EBX, and this source reads that
/// answer as the call's EDX. This is the OTHER half of the indirect-call wall: a `code *` call
/// returns `int` in EAX and that is the only register C can name at one, so when the callee hands
/// back something in EBX — `FUN_00020dba`'s boundary-push routine returns the clipped point as X
/// in EAX and Y in EBX, and publishes both with `XCHG mem,reg` — no `#pragma aux` can reach it.
/// A `double (*)(void)` call buys a second register (under `-fpc` a double comes back in EDX:EAX),
/// and this line says which of the original's registers that second channel stands in for. After
/// such a call the ORIGINAL's EBX and the CANDIDATE's EDX hold ONE value, from one
/// `sleigh::emu::call_clobber_fill` at EBX's offset.
///
/// Both registers must be in that call's clobber set, and they must differ — see
/// `sleigh::emu::RegReturn` for why each of those is a hard stop rather than a warning. The
/// `callee <va> returns register ...` form works the same way for a DIRECT call, though a direct
/// call can usually just be declared `value [...]` instead.
///
/// `//@equiv ...` works too; the annotation runs to the end of the line or to `*/`. The target may
/// be written `0x18b4`, `func_0x000018b4` or `FUN_000018b4`; the flag is `cf`, `zf` or `sf`
/// ([`NAMED_FLAGS`]) and a register is any of the eight GPRs ([`GPRS`]).
///
/// ANY line containing `@equiv` must parse. An annotation quietly ignored would leave the
/// candidate compared against a model that still tosses a coin at that branch, and the failure
/// would look like an arithmetic bug — the exact shape of defect this harness has produced seven
/// times. So a malformed one is a panic, not a warning. Do not write `@equiv` in prose.
fn flag_contracts(src: &str, idx: &str) -> FlagContracts {
    let mut out = FlagContracts::default();
    for line in src.lines() {
        let Some(at) = line.find("@equiv") else { continue };
        let text = &line[at + "@equiv".len()..];
        let text = text.split("*/").next().unwrap_or(text);
        let t: Vec<&str> = text.split_whitespace().collect();
        let bad = |why: &str| -> ! { panic!("{idx}: {why} in @equiv annotation: {}", line.trim()) };
        // `in` = the answer exists only in the flag and is handed to the candidate in a register;
        // `from` = the answer IS a predicate on the value the callee returns in that register.
        let flag_reg = |f: &str, how: &str, r: &str| -> FlagReturn {
            let Some(flag) = flag_by_name(f) else { bad("unknown flag (cf, zf or sf)") };
            let Some(reg) = reg_by_name(r) else { bad("unknown register") };
            let from = match how {
                "in" => FlagSource::Bit,
                "from" if f.eq_ignore_ascii_case("zf") => FlagSource::IsZero,
                "from" if f.eq_ignore_ascii_case("sf") => FlagSource::IsNegative,
                "from" => bad("only zf and sf can be derived `from` a register — they are the two predicates `TEST reg,reg` leaves"),
                _ => bad("expected `in` or `from`"),
            };
            FlagReturn { flag: (flag, 1), reg: (reg, 4), from }
        };
        // `returns register <src> in <dst>`: WHERE the original's callee leaves its answer, and
        // where this source reads it. Naming one register on both sides would deliver nothing —
        // both runs already hold that register's clobber fill — so it is a stop, not a no-op.
        let reg_pair = |sr: &str, dr: &str| -> RegReturn {
            let Some(src) = reg_by_name(sr) else { bad("unknown source register") };
            let Some(dst) = reg_by_name(dr) else { bad("unknown destination register") };
            if src == dst {
                bad(
                    "the same register on both sides — the model already gives both runs that register's \
                     fill, so the contract would deliver nothing",
                );
            }
            RegReturn { src: (src, 4), dst: (dst, 4) }
        };
        let address = |a: &str, what: &str| -> u64 {
            let hex =
                a.trim_start_matches("func_").trim_start_matches("FUN_").trim_start_matches("0x").trim_end_matches('_');
            match u64::from_str_radix(hex, 16) {
                Ok(va) => va,
                Err(_) => bad(what),
            }
        };
        match t.as_slice() {
            // @equiv callee <target> returns register <src> in <dst>
            ["callee", target, "returns", "register", sr, "in", dr] => {
                let va = address(target, "unreadable callee address");
                if out.callee_reg.insert(va, reg_pair(sr, dr)).is_some() {
                    bad("a second register contract for the same callee");
                }
            }
            // @equiv site <call address> returns register <src> in <dst>
            ["site", at, "returns", "register", sr, "in", dr] => {
                let va = address(at, "unreadable call-site address");
                if out.site_reg.insert(va, reg_pair(sr, dr)).is_some() {
                    bad("a second register contract for the same call site");
                }
            }
            // @equiv callee <target> returns <flag> in|from <reg>
            ["callee", target, "returns", f, how @ ("in" | "from"), r] => {
                let va = address(target, "unreadable callee address");
                if out.callee.insert(va, flag_reg(f, how, r)).is_some() {
                    bad("a second flag contract for the same callee");
                }
            }
            // @equiv site <call address> returns <flag> in|from <reg>
            ["site", at, "returns", f, how @ ("in" | "from"), r] => {
                let va = address(at, "unreadable call-site address");
                if out.site.insert(va, flag_reg(f, how, r)).is_some() {
                    bad("a second flag contract for the same call site");
                }
            }
            // @equiv returns <flag> in <reg>
            ["returns", f, "in", r] => {
                if out.result.is_some() {
                    bad("a second flag result for this function");
                }
                out.result = Some(flag_reg(f, "in", r));
            }
            // A register form that did not match above is malformed; say so about REGISTERS
            // rather than complaining that "register" is not the name of a flag.
            ["callee" | "site", ..] if t.get(3) == Some(&"register") => {
                bad("expected `callee|site <va> returns register <src-register> in <dst-register>`")
            }
            _ => bad(
                "unrecognised form (`callee <va> returns <flag> in|from <reg>`, \
                 `site <va> returns <flag> in|from <reg>`, `returns <flag> in <reg>`, or \
                 `callee|site <va> returns register <src> in <dst>`)",
            ),
        }
    }
    out
}

/// Is `at` the address of a `CALL` in `insns`, and — when the call is DIRECT — what does it call?
///
/// `None` means the address is not the start of a call instruction at all: a `site` annotation
/// naming it describes nothing, and a contract that describes nothing is exactly the shape of
/// defect that makes a wrong answer look like agreement, so the caller stops the run.
/// `Some(None)` is an INDIRECT call (the case the site key exists for); `Some(Some(t))` a direct
/// one, which the `callee` form can name and where `t` is what it names.
///
/// Read off the LIFTED p-code rather than the mnemonic text, so it is the same notion of "a call"
/// the interpreter itself acts on (`sleigh::emu::run_traced`'s `"CALL" | "CALLIND"` arm), and the
/// direct target is extracted exactly as that arm extracts it.
fn call_site(insns: &[mosura::sleigh::Instruction], at: u64) -> Option<Option<u64>> {
    use mosura::sleigh::pcode::{opcode_name, PArg};
    let insn = insns.iter().find(|i| i.address == at)?;
    insn.ops.iter().find_map(|op| match opcode_name(op.opcode) {
        "CALLIND" => Some(None),
        "CALL" => Some(op.ins.first().and_then(PArg::as_var).filter(|v| !v.is_const()).map(|v| v.offset)),
        _ => None,
    })
}

fn main() {
    let a = mosura::debug::from_args(std::env::args().skip(1).collect()).unwrap_or_else(|e| panic!("--debug: {e}"));
    let a = mosura::resources::from_args(a).unwrap_or_else(|e| panic!("{e}"));
    let mut pos: Vec<String> = Vec::new();
    let (mut only, mut seeds, mut cache_dir, mut verbose) = (Vec::new(), 128usize, None, false);
    let mut it = a.into_iter();
    while let Some(x) = it.next() {
        match x.as_str() {
            "--only" => only = it.next().expect("--only <idx>,...").split(',').map(str::to_string).collect(),
            "--seeds" => seeds = it.next().expect("--seeds N").parse().expect("N"),
            "--cache" => cache_dir = it.next(),
            "--verbose" => verbose = true,
            _ => pos.push(x),
        }
    }
    if pos.len() < 5 {
        panic!("usage: equiv_check <binary> <manifest> <src-dir> <flags-file> <watcom-dir> [--only i,..] [--seeds N]");
    }
    let (bin, manifest, srcdir, flagsfile, watcom) = (&pos[0], &pos[1], &pos[2], &pos[3], &pos[4]);

    let rows = read_manifest(manifest);
    let recover_flags = flagsfile == "recover";
    let flags = if recover_flags { HashMap::new() } else { read_flags(flagsfile) };
    let prelude = std::fs::read_to_string(Path::new(srcdir).join("../prelude.h")).unwrap_or_default();

    let data = std::fs::read(Path::new(bin)).expect("read binary");
    let prog = analysis::load_native(&data).expect("load binary");
    let space = prog.default_space;

    // The language's spec AND its initial context. Without the context the x86 decoder runs in
    // 16-bit mode and every instruction is nonsense — the first thing to check if a verdict looks
    // impossible.
    let (spec_sleigh, ctx) = mosura::lang::load_cached(LANG).expect("language tables for x86:LE:32:default");

    let work = std::env::temp_dir().join(format!("mosura-equiv-{}", std::process::id()));
    let cache = cache_dir.unwrap_or_else(|| work.join("cache").to_string_lossy().into_owned());
    let wcc = CompilerDriver::new(spec::watcom_10_0a_dos(&prelude), watcom, &work, DriverRole::Validation)
        .expect("work dir")
        .owning_work_dir();
    let tc = Cached::new(wcc, &cache).expect("cache dir");

    let profile = mosura::recompile::buildconfig::watcom_10_0a();
    // The half of the site-keyed channel each run does NOT use (see `FlagContracts::site`).
    let no_flag_returns: HashMap<u64, FlagReturn> = HashMap::new();
    let no_reg_returns: HashMap<u64, RegReturn> = HashMap::new();
    let sp = (ESP, 4u32);
    let fp = (EBP, 4u32);

    let mut units = Vec::new();
    let mut kept: Vec<(&Row, String)> = Vec::new();
    for r in &rows {
        if !only.is_empty() && !only.contains(&r.idx) {
            continue;
        }
        let path = Path::new(srcdir).join(format!("{}.c", r.idx));
        let Ok(source) = std::fs::read_to_string(&path) else { continue };
        let mut obytes = Vec::with_capacity(r.len);
        for k in 0..r.len {
            match prog.memory.byte_at(Address::new(space, r.va + k as u64)) {
                Some(b) => obytes.push(b),
                None => break,
            }
        }
        let table_says_recover = flags.get(&r.idx).map(|f| f.trim() == "recover").unwrap_or(false);
        let unit_flags: Vec<String> = if recover_flags || table_says_recover {
            let insns = mosura::recompile::insn::normalize(LANG, &obytes, r.va, &mosura::recompile::insn::NoReloc)
                .expect("language tables");
            profile.flags_for(&mosura::recompile::buildconfig::detect(&insns, sp, fp))
        } else {
            flags
                .get(&r.idx)
                .cloned()
                .unwrap_or_else(|| "-5r -fpi87 -s -onatx".to_string())
                .split_whitespace()
                .map(str::to_string)
                .collect()
        };
        units.push(CompileUnit { key: r.idx.clone(), source: source.clone(), flags: unit_flags });
        kept.push((r, source));
    }
    let outs = tc.compile_batch(&units);

    let mut same = 0usize;
    let mut differ = 0usize;
    let mut unusable = 0usize;
    for ((r, source), out) in kept.iter().zip(outs.iter()) {
        let Some(object) = out.object.as_ref() else {
            println!("{}\t{}\tCOMPILE_FAIL", r.idx, r.name);
            unusable += 1;
            continue;
        };
        let mut obytes = Vec::with_capacity(r.len);
        for k in 0..r.len {
            match prog.memory.byte_at(Address::new(space, r.va + k as u64)) {
                Some(b) => obytes.push(b),
                None => break,
            }
        }
        let subject = mosura::recompile::Subject { name: r.name.clone(), va: r.va, len: r.len };
        let checked = match mosura::recompile::verify(
            LANG,
            &obytes,
            &subject,
            object,
            &mosura::recompile::emitted_symbol_address,
        ) {
            Ok(c) => c,
            Err(e) => {
                println!("{}\t{}\tOBJ_ERROR\t{e}", r.idx, r.name);
                unusable += 1;
                continue;
            }
        };
        let cand_bytes = checked.relinked.relinked_bytes();

        if verbose {
            // What the emulator is actually running, on both sides — the first thing to check when
            // a verdict looks impossible.
            for (label, bytes) in [("orig", &obytes), ("cand", &cand_bytes)] {
                eprintln!("  -- {label}");
                // No cap: the instruction being diagnosed is as likely to be the last as the
                // first, and a truncated stream hid exactly the one the verdict was about.
                for i in spec_sleigh.disassemble_ctx(bytes, r.va, ctx).iter() {
                    eprintln!("     {:08x}  {} {}", i.address, i.mnemonic, i.body);
                }
            }
        }
        // The pool of interesting values: every constant the ORIGINAL mentions, its neighbours, and
        // the usual boundaries. Uniform random words never hit a threshold; these do.
        let mut pool: Vec<u64> = vec![0, 1, 2, 0xffff_ffff, 0xffff_fffe, 0x7fff_ffff, 0x8000_0000, 0x100, 0xffff, 0xff];
        if let Ok(insns) = mosura::recompile::insn::normalize(LANG, &obytes, r.va, &mosura::recompile::insn::NoReloc) {
            for i in &insns {
                for c in &i.consts {
                    let c = *c & 0xffff_ffff;
                    for d in [c, c.wrapping_sub(1) & 0xffff_ffff, c.wrapping_add(1) & 0xffff_ffff] {
                        if !pool.contains(&d) {
                            pool.push(d);
                        }
                    }
                }
            }
        }
        let stripped = strip_comments(source);
        let (contracts, stack_targets, modifies) = callee_contracts(&stripped);
        let result_reg = result_register(source, &r.name);
        let void = returns_void(source, &r.name);
        let default_args = [(EAX, 4u32), (EDX, 4), (EBX, 4), (ECX, 4)];
        let clobbers = [(EAX, 4u32), (ECX, 4), (EDX, 4), (EBX, 4)];
        // The x86 arithmetic flags (`ia.sinc:39` — one byte each from 0x200): CF PF AF ZF SF OF.
        // A call leaves every one of them undefined, so they are clobbered like the scratch
        // registers. DF (0x20a) is deliberately NOT here: the ABI requires it clear at a call
        // boundary and the callee must restore it, so it survives a call and clobbering it would
        // break correct string-instruction code.
        let flag_clobbers = [(0x200u64, 1u32), (0x202, 1), (0x204, 1), (0x206, 1), (0x207, 1), (0x20b, 1)];
        // Flag-valued contracts, declared in comments the compiler never sees (`flag_contracts`).
        let ann = flag_contracts(source, &r.idx);
        // A flag-returning callee's answer is delivered to the CANDIDATE in a general register,
        // and to the original in a flag. That is sound only while the register is one the callee
        // DESTROYS anyway: writing a register the original still holds live would make the two
        // runs differ for a reason that has nothing to do with the candidate — and a source could
        // "fix" a divergence by parking a value in a register the model then quietly overwrites on
        // one side. Held to the callee's own declared `modify` clause, or the default set.
        // ...and the same holds when the answer is DERIVED from that register rather than
        // delivered into it: the flag is then computed from what the register holds, which is only
        // the same question on both runs while the register is one the callee deterministically
        // destroys. A register the caller still holds live would hold two different values.
        let held_to_clobber_set = |what: &str, target: Option<u64>, fr: &FlagReturn| {
            let clob = target.and_then(|t| modifies.get(&t)).map(|v| v.as_slice()).unwrap_or(&clobbers[..]);
            if !clob.iter().any(|&(off, _)| off == fr.reg.0) {
                let name = GPRS.iter().find(|(_, o)| *o == fr.reg.0).map(|(n, _)| *n).unwrap_or("?");
                panic!(
                    "{}: @equiv {what} names {name}, but {name} is not in that callee's clobber set — \
                     declare it (`modify [... {name}]`, or `value [{name}]`)",
                    r.idx
                );
            }
        };
        for (target, fr) in &ann.callee {
            held_to_clobber_set(&format!("callee {target:#x}"), Some(*target), fr);
        }
        // A SITE annotation names ONE call instruction in the original's own extent. An address
        // that is not a call there describes nothing at all, and a call whose target is ALREADY
        // named by a `callee` line would be described twice, by two contracts that need not agree.
        // Both stop the run, exactly as the guards above do.
        let extent = spec_sleigh.disassemble_ctx(&obytes, r.va, ctx);
        for (at, fr) in &ann.site {
            let Some(direct) = call_site(&extent, *at) else {
                panic!(
                    "{}: @equiv site {at:#x} is not the address of a CALL instruction in this function's \
                     extent ({:#x}..{:#x})",
                    r.idx,
                    r.va,
                    r.va + r.len as u64
                );
            };
            if let Some(t) = direct {
                if ann.callee.contains_key(&t) {
                    panic!(
                        "{}: @equiv site {at:#x} names a DIRECT call to {t:#x}, which already has a \
                         `callee` contract — one call, two contracts",
                        r.idx
                    );
                }
            }
            held_to_clobber_set(&format!("site {at:#x}"), direct, fr);
        }
        // A REGISTER contract has TWO registers to hold to the clobber set, for two different
        // reasons, and both are hard stops for the same overriding reason the flag guards are:
        // every defect this harness has shipped made a WRONG answer look like agreement.
        //
        //  * the SOURCE — the register the ORIGINAL's callee leaves its answer in. Unless the call
        //    destroys it, what the original holds there after the call is the CALLER's own live
        //    value, and the fill handed to the candidate would model nothing that happened.
        //  * the DESTINATION — the register the CANDIDATE reads that answer out of. Writing one
        //    the original still holds live would make the two runs differ for a reason that is not
        //    about the candidate, and would let a source "fix" a divergence by parking a value in
        //    a register the model then overwrites on one side only.
        let reg_held_to_clobber_set = |what: &str, target: Option<u64>, rr: &RegReturn| {
            let clob = target.and_then(|t| modifies.get(&t)).map(|v| v.as_slice()).unwrap_or(&clobbers[..]);
            for (off, role, why) in [
                (rr.src.0, "source", "so the original keeps the CALLER's live value there, not the callee's answer"),
                (rr.dst.0, "destination", "so delivering there would overwrite a value the original still holds"),
            ] {
                if !clob.iter().any(|&(o, _)| o == off) {
                    let name = GPRS.iter().find(|(_, o)| *o == off).map(|(n, _)| *n).unwrap_or("?");
                    panic!(
                        "{}: @equiv {what} names {name} as its {role} register, but {name} is not in that \
                         callee's clobber set — {why}. Declare it (`modify [... {name}]`) or name a register \
                         the callee really destroys",
                        r.idx
                    );
                }
            }
        };
        // ...and the register a FLAG contract for the SAME call already claims. `Bit` writes it on
        // the candidate's side and `from` derives the flag from what it holds; a register delivery
        // into it would silently overwrite one with the other. Every key that can fire at the call
        // is checked, not just the one this contract is written under.
        let flag_regs_at = |site: Option<u64>, target: Option<u64>| -> Vec<u64> {
            let mut v = Vec::new();
            if let Some(a) = site {
                v.extend(ann.site.get(&a).map(|f| f.reg.0));
            }
            if let Some(t) = target {
                v.extend(ann.callee.get(&t).map(|f| f.reg.0));
                v.extend(
                    ann.site.iter().filter(|(a, _)| call_site(&extent, **a) == Some(Some(t))).map(|(_, f)| f.reg.0),
                );
            }
            v
        };
        let no_flag_clash = |what: &str, site: Option<u64>, target: Option<u64>, rr: &RegReturn| {
            if flag_regs_at(site, target).contains(&rr.dst.0) {
                let name = GPRS.iter().find(|(_, o)| *o == rr.dst.0).map(|(n, _)| *n).unwrap_or("?");
                panic!(
                    "{}: @equiv {what} delivers into {name}, which a flag contract for the same call already \
                     claims — one register, two contracts",
                    r.idx
                );
            }
        };
        for (target, rr) in &ann.callee_reg {
            reg_held_to_clobber_set(&format!("callee {target:#x} returns register"), Some(*target), rr);
            no_flag_clash(&format!("callee {target:#x} returns register"), None, Some(*target), rr);
        }
        for (at, rr) in &ann.site_reg {
            let what = format!("site {at:#x} returns register");
            let Some(direct) = call_site(&extent, *at) else {
                panic!(
                    "{}: @equiv site {at:#x} is not the address of a CALL instruction in this function's \
                     extent ({:#x}..{:#x})",
                    r.idx,
                    r.va,
                    r.va + r.len as u64
                );
            };
            if let Some(t) = direct {
                if ann.callee_reg.contains_key(&t) {
                    panic!(
                        "{}: @equiv site {at:#x} names a DIRECT call to {t:#x}, which already has a \
                         `callee ... returns register` contract — one call, two contracts",
                        r.idx
                    );
                }
            }
            reg_held_to_clobber_set(&what, direct, rr);
            no_flag_clash(&what, Some(*at), direct, rr);
        }
        // The subject's own flag result names the register the CANDIDATE returns it in, and that
        // must be the register its own contract already returns in — otherwise two different
        // registers would both claim to be the result and the ordinary comparison would run on a
        // register that holds nothing.
        if let Some(fr) = ann.result {
            if void {
                panic!("{}: @equiv returns ... names a result register, but the function is declared void", r.idx);
            }
            if fr.reg.0 != result_reg {
                panic!(
                    "{}: @equiv returns ... names a register that is not this function's own result register \
                     (`value [...]`, default eax)",
                    r.idx
                );
            }
        }

        let mut agree = 0usize;
        let mut first_diff: Option<String> = None;
        let mut first_cause: Option<&'static str> = None;
        let mut both_finished = 0usize;
        // How many DISTINCT effect traces the seeds produced. One trace means every seed drove the
        // function down the same path, so agreement is nearly worthless as evidence; it is reported
        // rather than hidden.
        let mut traces: std::collections::HashSet<String> = std::collections::HashSet::new();
        // Any p-code op the interpreter does not model makes the run worthless as evidence.
        let mut unmodeled = 0usize;
        // ...and WHICH ops those were, so a blocked function says what would unblock it.
        let mut unmodeled_ops: std::collections::BTreeSet<String> = Default::default();
        for s in 0..seeds {
            let seed = 0x5eed_0000_0000_0000 ^ (s as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            // Entry state: every general register a function of the seed, ESP at the stack top.
            let vals: Vec<(&str, u64, u64, u32)> = GPRS
                .iter()
                .map(|&(_, off)| {
                    let v = if off == ESP {
                        STACK_TOP
                    } else {
                        let h = seed.rotate_left(off as u32 + 7) ^ off.wrapping_mul(0x1234_5678);
                        if h % 3 != 0 { pool[(h >> 8) as usize % pool.len()] } else { h & 0xffff_ffff }
                    };
                    ("register", off, v, 4u32)
                })
                .collect();
            let cfg = RunConfig {
                seed,
                scratch: STACK_WINDOW,
                call_args: &contracts,
                default_args: &default_args,
                call_clobbers: &clobbers,
                call_modifies: &modifies,
                call_flag_clobbers: &flag_clobbers,
                call_flag_returns: &ann.callee,
                // The ORIGINAL run: it owns the text the `site` annotations name, and it is the
                // run that resolves them to call ordinals for the candidate.
                site_flag_returns: &ann.site,
                ordinal_flag_returns: &no_flag_returns,
                call_reg_returns: &ann.callee_reg,
                // ...and the same for a callee that answers in a REGISTER the candidate cannot
                // name: the site map belongs to the run whose text the sites are addresses in.
                site_reg_returns: &ann.site_reg,
                ordinal_reg_returns: &no_reg_returns,
                // A flag-returning callee's answer stays in the flag, which is where its `JC`
                // reads it, and a register-returning one stays in the register the original's own
                // instructions read.
                is_candidate_run: false,
                // The original's bytes are the memory image BOTH runs read as data — the candidate
                // is judged in the original's environment, not in one made of its own opcodes.
                image: &[(r.va, &obytes)],
                stack_targets: &stack_targets,
                sp: (ESP, 4),
                max_steps: 20_000_000,
                pool: &pool,
                max_effects: 4_000,
            };
            let (mo, fo) = mosura::sleigh::emu::run_traced(spec_sleigh, &obytes, r.va, ctx, &vals, &cfg);
            // Which CALLS the site annotations turned out to name, as ordinals — the candidate's
            // text has no address in common with the original's, and the ordinal is the
            // correspondence the effect comparison already uses.
            let by_ordinal: HashMap<u64, FlagReturn> = mo.flag_return_ordinals.iter().copied().collect();
            let reg_by_ordinal: HashMap<u64, RegReturn> = mo.reg_return_ordinals.iter().copied().collect();
            // ...and the CANDIDATE run, which differs in exactly one thing: the SAME bit — and the
            // SAME register fill — is also delivered where this source models the callee's answer
            // as living.
            let cand_cfg = RunConfig {
                is_candidate_run: true,
                site_flag_returns: &no_flag_returns,
                ordinal_flag_returns: &by_ordinal,
                site_reg_returns: &no_reg_returns,
                ordinal_reg_returns: &reg_by_ordinal,
                ..cfg
            };
            let (mc, fc) = mosura::sleigh::emu::run_traced(spec_sleigh, &cand_bytes, r.va, ctx, &vals, &cand_cfg);
            if fo && fc {
                both_finished += 1;
            }
            unmodeled += mo.unmodeled + mc.unmodeled;
            unmodeled_ops.extend(mo.unmodeled_ops.iter().cloned());
            unmodeled_ops.extend(mc.unmodeled_ops.iter().cloned());
            // The subject's own result. When it answers in a FLAG the comparison is bit against
            // bit: the flag the ORIGINAL leaves at `RET`, against the TRUTH of the register the
            // candidate returns it in — a flag carries one bit, and C's own notion of a returned
            // condition is "nonzero", so `1` and `0x40` are the same answer while `0` is not. That
            // register's ordinary exact comparison is superseded: the original leaves nothing
            // defined there. Without this the function had to be declared `void` and its answer
            // was not checked at all.
            let (ro, rc) = match ann.result {
                Some(fr) => (mo.read("register", fr.flag.0, 1) & 1, u64::from(mc.read("register", fr.reg.0, 4) != 0)),
                None if void => (0, 0),
                None => (mo.read("register", result_reg, 4), mc.read("register", result_reg, 4)),
            };
            traces.insert(format!("{:?}|{ro:x}", mo.effects));
            // When NEITHER run reached its RETURN — both were still going when the budget ran out —
            // only the common prefix of what they did is evidence. Comparing the tails would
            // penalise whichever side got further, which is not a difference in behaviour.
            let (eo, ec): (&[Effect], &[Effect]) = if !fo && !fc {
                let n = mo.effects.len().min(mc.effects.len());
                (&mo.effects[..n], &mc.effects[..n])
            } else {
                (&mo.effects, &mc.effects)
            };
            // After a trap the result register holds nothing defined, so it is not compared.
            let faulted = matches!(mo.effects.last(), Some(Effect::Fault));
            let result_ok = (!fo && !fc) || faulted || ro == rc;
            if eo == ec && result_ok {
                agree += 1;
            } else if first_diff.is_none() {
                first_cause = Some(classify(eo, ec, ro, rc, ann.result.is_some()));
                first_diff = Some(describe(&mo.effects, &mc.effects, ro, rc, seed));
            }
        }

        if unmodeled > 0 {
            // Not a verdict: the interpreter met operations it does not implement (the float
            // family, mostly), so neither agreement nor disagreement means anything here.
            println!(
                "{}\t{}\tUNMODELED\tops={unmodeled}\twhich={}",
                r.idx,
                r.name,
                unmodeled_ops.iter().cloned().collect::<Vec<_>>().join(",")
            );
            unusable += 1;
            continue;
        }
        if agree == seeds {
            let weak = if traces.len() < 2 { "\tWEAK(one path)" } else { "" };
            println!(
                "{}\t{}\tSAME\tseeds={seeds} finished={both_finished}/{seeds} traces={}{weak}{}",
                r.idx,
                r.name,
                traces.len(),
                if stack_targets.is_empty() {
                    String::new()
                } else {
                    format!("\tstack-arg callees compared by target only: {}", stack_targets.len())
                }
            );
            same += 1;
        } else {
            println!(
                "{}\t{}\tDIFFERS\tagreed={agree}/{seeds}\t{}",
                r.idx,
                r.name,
                first_cause.unwrap_or("unknown")
            );
            if verbose {
                if let Some(d) = first_diff {
                    println!("{d}");
                }
            }
            differ += 1;
        }
    }
    eprintln!("equiv_check: {same} same, {differ} differ, {unusable} unusable");
}

/// What KIND of difference this is — the first thing to know when a hundred functions differ and
/// you are looking for the one repair that fixes forty of them.
fn classify(o: &[Effect], c: &[Effect], ro: u64, rc: u64, result_is_flag: bool) -> &'static str {
    for i in 0..o.len().max(c.len()) {
        match (o.get(i), c.get(i)) {
            (Some(a), Some(b)) if a == b => continue,
            (Some(Effect::Store(_, aa, asz, _)), Some(Effect::Store(_, ba, bsz, _))) => {
                return if aa != ba {
                    "store-address"
                } else if asz != bsz {
                    "store-width"
                } else {
                    "store-value"
                }
            }
            (Some(Effect::Call(at, aargs)), Some(Effect::Call(bt, bargs))) => {
                return if at != bt {
                    "call-target"
                } else if aargs.len() != bargs.len() {
                    "call-arity"
                } else {
                    "call-arguments"
                }
            }
            (Some(Effect::Port(aw, ap, asz, _)), Some(Effect::Port(bw, bp, bsz, _))) => {
                return if aw != bw {
                    "port-direction"
                } else if ap != bp {
                    "port-number"
                } else if asz != bsz {
                    "port-width"
                } else {
                    "port-value"
                }
            }
            (Some(Effect::Swi(an, aargs)), Some(Effect::Swi(bn, bargs))) => {
                return if an != bn { "interrupt-number" } else if aargs != bargs { "interrupt-registers" } else { "unknown" }
            }
            (Some(Effect::Fault), _) | (_, Some(Effect::Fault)) => return "fault-mismatch",
            // Two effects of DIFFERENT kinds at the same point: one side did something the other
            // did somewhere else.
            (Some(_), Some(_)) => return "effect-order",
            (Some(Effect::Store(..)), None) => return "store-missing",
            (Some(Effect::Call(..)), None) => return "call-missing",
            (Some(Effect::Port(..)), None) => return "port-missing",
            (Some(Effect::Swi(..)), None) => return "interrupt-missing",
            (None, Some(Effect::Store(..))) => return "store-extra",
            (None, Some(Effect::Call(..))) => return "call-extra",
            (None, Some(Effect::Port(..))) => return "port-extra",
            (None, Some(Effect::Swi(..))) => return "interrupt-extra",
            (None, None) => break,
        }
    }
    if ro != rc {
        // The two are told apart because they are repaired differently: a wrong result REGISTER is
        // arithmetic, a wrong result FLAG is usually a branch arm that was never taken.
        if result_is_flag {
            "result-flag"
        } else {
            "result-register"
        }
    } else {
        "unknown"
    }
}

fn describe(o: &[Effect], c: &[Effect], ro: u64, rc: u64, seed: u64) -> String {
    let mut s = format!("  first divergence (seed {seed:#x}):\n");
    let n = o.len().max(c.len());
    // A WINDOW around the first disagreement. Printing the first 24 effects showed the divergence
    // only when it happened to be near the start; on a function with a long trace the tool
    // reported a difference and then printed a screen of agreement.
    const CONTEXT: usize = 6;
    const WINDOW: usize = 24;
    let first = (0..n).find(|&i| o.get(i) != c.get(i)).unwrap_or(0);
    let lo = first.saturating_sub(CONTEXT);
    let hi = (lo + WINDOW).min(n);
    if lo > 0 {
        s.push_str(&format!("   … {lo} earlier effects agreed\n"));
    }
    for i in lo..hi {
        let (a, b) = (o.get(i), c.get(i));
        let mark = if a == b { ' ' } else { '!' };
        s.push_str(&format!("   {mark} {i:<4} {:<44} | {}\n", show(a), show(b)));
    }
    if hi < n {
        s.push_str(&format!("   … {} more\n", n - hi));
    }
    if ro != rc {
        s.push_str(&format!("   ! result {ro:#010x} | {rc:#010x}\n"));
    }
    s
}

fn show(e: Option<&Effect>) -> String {
    match e {
        Some(Effect::Store(sp, a, sz, v)) => format!("store {sp}:{a:#x} <{sz}> = {v:#x}"),
        Some(Effect::Fault) => "fault (divide by zero)".to_string(),
        Some(Effect::Port(true, p, sz, v)) => format!("out port {p:#x} <{sz}> = {v:#x}"),
        Some(Effect::Port(false, p, sz, v)) => format!("in  port {p:#x} <{sz}> -> {v:#x}"),
        Some(Effect::Swi(n, args)) => {
            format!("int {n:#x}({})", args.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>().join(","))
        }
        Some(Effect::Call(t, args)) => {
            format!("call {t:#x}({})", args.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>().join(","))
        }
        None => "-".to_string(),
    }
}
