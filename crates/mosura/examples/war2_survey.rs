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
use mosura::decompile::opcode::OpCode;
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::{print_c_with};
use mosura::decompile::space::Address;

// Sized-int / undefined typedefs a compilable-C emitter would prepend (Ghidra decompiler C).
// Watcom 10.0a is C89: int/long/pointer are 32-bit and there is NO 64-bit integer type
// (`long long` / `__int64` both rejected), so 8-byte and odd-size types map to `double`
// (size-8) / nearest int — those are rare (7 files) and decompiler-imperfect for a 32-bit
// target anyway. Written to <out>/prelude.h so the compile stage can prepend it without a
// full re-emit. Kept out of the baked src files for fast prelude iteration.
//
// ⚠️ THIS CONSTANT IS THE SOURCE OF TRUTH — every EMIT overwrites <out>/prelude.h from it. Editing
// the generated prelude.h by hand "works" until the next EMIT silently reverts it. That happened:
// the `code` typedef below was hand-fixed in the generated file, measured (COMPILE_FAIL 75 -> 29),
// and recorded in docs + commit 26db108 as if it were the state of the tree — while this constant
// still said `void`. The next EMIT restored `void`, the 47 E1052 failures came back, and they were
// re-adjudicated as a decompiler ceiling. Change the prelude HERE, never there.
//
// ⚠️ WHICH ODD WIDTHS BELONG HERE — the line is Ghidra's `max_basetype_size` (10,
// architecture.cc:1422). At or below it, `TypeFactory::getBase` (type.cc:3652) really does hand back
// a base type of that width, and Ghidra's own WAR2 output contains `uint6` x8, `uint3` x19,
// `int3` x50, `undefined6` x6 — so those names are FAITHFUL and their absence from a C compiler is
// the prelude's problem, which is what the prelude exists for. ABOVE it `getBase` returns
// `undefined1[N]` instead, so a `uint12`/`uint20`/`xunknown12` in our output is OUR defect (an
// unported piece of heritage refinement). DO NOT add typedefs for those: it would make a
// wrong-code-adjacent gap compile, which is the "adaptation masking its own absence" trap this
// project keeps paying for. They stay COMPILE_FAIL so they stay visible.
//
// ⚠️ `code` IS THE FUNCTION TYPE, NOT A POINTER TO ONE. Ghidra's `TypeCode` (TYPE_CODE) is
// executable code itself; a call target is `code *`. Declaring `typedef int (*code)()` here made
// `code *` a pointer-to-function-POINTER, so `(*p)()` compiled to `mov eax,[p]; call [eax]` —
// two dereferences, 8 bytes — where the original `call DWORD PTR ds:<addr>` is 7. The emitted C
// was correct and the bytes were still wrong, which no amount of decompiler work would have
// fixed. With `typedef int code();` the same C compiles to `ff 15 <abs32>` + `c3`, byte-identical
// to the original modulo the relocation. Measured on oracle/ground-truth/src/globfnptr.c.
//
// Integer metatypes take the widest integer wcc386 has (`unsigned int`/`int`) rather than the
// width-matching `double` the unknown metatypes take, because they are USED as integers: both
// `uint6` sites shift (`uStack_1e >> 0x10`), and shifting a double is `E1079: Expression must be
// integral`. Every mapping here lies about width; this one at least lies compilably.
const PRELUDE: &str = "\
typedef unsigned char undefined; typedef unsigned char undefined1; typedef unsigned short undefined2;
typedef unsigned int undefined4; typedef unsigned char byte;
/* Integer widths the target CANNOT hold (Watcom 10.0a x86-32 has no 64-bit integer type).
   These used to be `typedef double ...` so the C compiled -- into x87 FLOAT arithmetic where the
   subject computes in integers, which is ALWAYS WRONG and never fails. An incomplete struct makes
   every declaration, cast, and operation on these types a loud compile error naming the problem
   (Phase 1 of docs/compilable-c-remediation.md: better an honest COMPILE_FAIL than a silent
   miscompile; measured: zero byte-exact functions use any of them). */
struct mosura_no_such_integer_width_on_this_target;
typedef struct mosura_no_such_integer_width_on_this_target undefined8;
typedef struct mosura_no_such_integer_width_on_this_target uint8;
typedef struct mosura_no_such_integer_width_on_this_target int8;
typedef struct mosura_no_such_integer_width_on_this_target xunknown8;
typedef struct mosura_no_such_integer_width_on_this_target xunknown6;
typedef struct mosura_no_such_integer_width_on_this_target xunknown7;
typedef struct mosura_no_such_integer_width_on_this_target undefined6;
typedef struct mosura_no_such_integer_width_on_this_target undefined7;
typedef unsigned char uint1; typedef unsigned short uint2; typedef unsigned int uint4;
typedef signed char int1; typedef short int2; typedef int int4;
typedef unsigned char xunknown1; typedef unsigned short xunknown2; typedef unsigned int xunknown4;
typedef unsigned int xunknown3;
typedef struct mosura_no_such_integer_width_on_this_target xunknown5;
typedef unsigned char undefined3;
typedef struct mosura_no_such_integer_width_on_this_target undefined5;
typedef unsigned int uint3; typedef unsigned int int3;
/* Wrong-WIDTH integer stand-ins retired (Phase 2): 5/6/10-byte integers do not exist on this
   target, and `unsigned int` silently truncated them. 3-byte values FIT their 4-byte container
   (sub-register pieces), so uint3/int3 stay. */
typedef struct mosura_no_such_integer_width_on_this_target uint5;
typedef struct mosura_no_such_integer_width_on_this_target int5;
typedef struct mosura_no_such_integer_width_on_this_target uint6;
typedef struct mosura_no_such_integer_width_on_this_target int6;
typedef struct mosura_no_such_integer_width_on_this_target uint10;
typedef struct mosura_no_such_integer_width_on_this_target int10;
typedef int code(); typedef unsigned int pointer;
/* CALLOTHER intrinsics. Ghidra renders an unmodelled instruction as a call to a named user-op, and
   the x86 SLEIGH spec names the software interrupt `swi`, the port read `in`, and `cpuid`.
   `printc` emits the software interrupt as `(*swi(3))()` — a call THROUGH the user-op's result —
   so `swi` has to return a function pointer or the dereference is `E1029: Expression must be
   'pointer to ...'` and the whole translation unit fails to compile. It was undeclared: 74 of the
   156 COMPILE_FAIL functions were this one missing line, the single largest cause.
   The pointed-to function returns INT, not void: printc emits `iVar1 = (*swi(0x21))(...)` — a DOS
   interrupt call whose result is used — and declaring it void gave `E1052: Expression has void
   type` on 24 TUs, trading one compile failure for another.
   These declarations make the C compile; they do not make an `int 3` reproducible from C. */
extern int (*swi(int))(); extern unsigned int in(unsigned int); extern unsigned int cpuid(unsigned int);
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
/* CONCAT44 builds a 64-bit value -- unrepresentable here (see the incomplete-struct note
   above); the old double-arithmetic definition compiled into wrong code. Loud now. */
#define CONCAT44(h,l) (sizeof(struct mosura_no_such_integer_width_on_this_target))
#define ZEXT11(x) ((unsigned char)(x))
#define ZEXT12(x) ((unsigned short)(unsigned char)(x))
#define ZEXT14(x) ((unsigned int)(unsigned char)(x))
#define ZEXT22(x) ((unsigned short)(x))
#define ZEXT24(x) ((unsigned int)(unsigned short)(x))
#define ZEXT44(x) (x)
#define SEXT14(x) ((int)(signed char)(x))
#define SEXT24(x) ((int)(short)(x))
#define SEXT12(x) ((short)(signed char)(x))
/* The CLOSED in-contract vocabulary, completed (Phase 2). Ghidra's emitter is open-ended over
   width pairs; the header used to be an enumeration that could miss a member (one missing
   declaration once accounted for 74 of 156 compile failures). Below are the in-contract
   combinations the proven set above does not cover, derived mechanically: SUB<s><o> for source
   s<=4; ZEXT/SEXT<s><o> for s<o<=4 (3-byte operands live in their 4-byte container, masked or
   shift-extended where the container lies); CARRY/SCARRY/SBORROW over 1/2/4. Anything outside
   this grammar is out of contract and stays a tripwire. `build_prelude()` asserts the closure. */
#define SUB31(x,n) ((unsigned char)((unsigned int)(x)>>((n)*8)))
#define SUB32(x,n) ((unsigned short)((unsigned int)(x)>>((n)*8)))
#define SUB43(x,n) ((unsigned int)((unsigned int)(x)>>((n)*8))&0xffffff)
#define SUB22(x,n) (x)
#define SUB33(x,n) (x)
#define SUB11(x,n) (x)
#define ZEXT13(x) ((unsigned int)(unsigned char)(x))
#define ZEXT23(x) ((unsigned int)(unsigned short)(x))
#define ZEXT34(x) ((unsigned int)(x)&0xffffff)
#define ZEXT33(x) ((unsigned int)(x)&0xffffff)
#define SEXT13(x) ((int)(signed char)(x))
#define SEXT23(x) ((int)(short)(x))
#define SEXT34(x) (((int)((unsigned int)(x)<<8))>>8)
#define CARRY2(a,b) ((((unsigned int)(unsigned short)(a)+(unsigned int)(unsigned short)(b)))>0xffffU)
#define SCARRY4(a,b) ((int)(((~((unsigned int)(a)^(unsigned int)(b)))&((unsigned int)(a)^((unsigned int)(a)+(unsigned int)(b))))>>31))
#define SCARRY1(a,b) SCARRY4((int)(signed char)(a),(int)(signed char)(b))
#define SCARRY2(a,b) SCARRY4((int)(short)(a),(int)(short)(b))
#define SBORROW4(a,b) ((int)((((unsigned int)(a)^(unsigned int)(b))&((unsigned int)(a)^((unsigned int)(a)-(unsigned int)(b))))>>31))
#define SBORROW1(a,b) SBORROW4((int)(signed char)(a),(int)(signed char)(b))
#define SBORROW2(a,b) SBORROW4((int)(short)(a),(int)(short)(b))
#define CARRY4(a,b) ((unsigned int)(a)>(unsigned int)~(unsigned int)(b))
#define CARRY1(a,b) ((((unsigned int)(unsigned char)(a)+(unsigned int)(unsigned char)(b)))>0xffU)
/* POPCOUNT(x) was `(0)` -- always wrong, never failing. Loud now (Phase 1). */
#define POPCOUNT(x) (sizeof(struct mosura_popcount_not_modelled))
";

/// The commit that produced an emit: `<short-sha>` or `<short-sha>-dirty`. Falls back to
/// `nogit` only if git is unavailable — an unstamped artifact is still marked as unstamped
/// rather than silently claiming to be reproducible.
/// Whether a function is the subject's own code or the toolchain's.
///
/// A recompilation denominator must not count library code. `memset`, `printf` and the CRT
/// startup are reproduced by LINKING the Watcom libraries, not by decompiling them, so counting
/// them measures the toolchain rather than the port -- and their verdicts are not the port's to
/// claim either way. Measured on WAR2: 5 of 131 library functions are byte-exact (3.8%) against
/// 534 of 2892 of the subject's own (18.5%), so excluding them RAISES the ratio -- they were
/// dragging it down, not flattering it, which is the opposite of what was assumed here first.
///
/// The classification is the program's own: analysis names an unrecognised entry `FUN_<addr>`,
/// and on a stripped image the only thing that replaces that placeholder is FID matching the
/// function against a known library. So "was it identified" IS "is it library code" here, and it
/// is asked through [`Function::name_is_default`] so this file does not carry a second copy of
/// the placeholder format.
/// Phase 2 of docs/compilable-c-remediation.md — the emit-time REPRESENTABILITY CONTRACT.
/// Scan a rendered TU for constructs whose integer width the target cannot hold (Watcom 10.0a
/// x86-32: no integer wider than 4 bytes) and return them, deduplicated. `CONCAT<h><l>` is
/// out when h+l > 4; `SUB<src><out>`/`ZEXT`/`SEXT` when the SOURCE width exceeds 4 (the result
/// may fit, but the operand it extracts from cannot exist); the impossible-width typedefs and
/// `POPCOUNT` always. Multi-digit width pairs are parsed longest-source-first, matching
/// Ghidra's `CONCAT102` = (10,2), never (1,02) — widths are printed without padding.
///
/// This is the generator-as-detector design (plan open question 1): the emitter itself reports
/// what it produced outside the contract, in its own manifest, at emit time — the prelude's
/// incomplete-struct tripwire (Phase 1) remains only as the backstop behind it. Off-band
/// handling per the plan: the TU is still written and still fails loudly; nothing is hidden.
/// Assemble the prelude, asserting the CLOSED in-contract helper vocabulary is fully defined —
/// every SUB/ZEXT/SEXT over sources <= 4 bytes, every CONCAT with h+l <= 4, and the
/// carry/borrow family over 1/2/4 must have a `#define`; and no in-contract name may alias the
/// out-of-contract tripwire. The assertion is what makes the header a CONTRACT rather than an
/// enumeration that can silently miss a member (docs/compilable-c-remediation.md, Phase 2).
fn build_prelude() -> &'static str {
    let defined: std::collections::HashSet<&str> = PRELUDE
        .lines()
        .filter_map(|l| l.strip_prefix("#define "))
        .filter_map(|l| l.split('(').next())
        .collect();
    let mut expected: Vec<String> = Vec::new();
    for s in 1..=4u32 {
        for o in 1..=s {
            expected.push(format!("SUB{s}{o}"));
        }
        for o in s..=4u32 {
            expected.push(format!("ZEXT{s}{o}"));
            if s < o || s == o {
                // SEXT identity (s==o) is never emitted; extension only
            }
            if s < o {
                expected.push(format!("SEXT{s}{o}"));
            }
        }
    }
    for h in 1..=3u32 {
        for l in 1..=3u32 {
            if h + l <= 4 {
                expected.push(format!("CONCAT{h}{l}"));
            }
        }
    }
    for n in [1u32, 2, 4] {
        expected.push(format!("CARRY{n}"));
        expected.push(format!("SCARRY{n}"));
        expected.push(format!("SBORROW{n}"));
    }
    for name in &expected {
        assert!(defined.contains(name.as_str()), "in-contract helper {name} is not defined in the prelude");
        let def_line = PRELUDE.lines().find(|l| l.starts_with(&format!("#define {name}("))).unwrap();
        assert!(
            !def_line.contains("mosura_no_such_integer_width"),
            "in-contract helper {name} aliases the out-of-contract tripwire"
        );
    }
    PRELUDE
}

fn contract_violations(tu: &str) -> Vec<String> {
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let split_pair = |d: &str| -> Option<(u32, u32)> {
        // widths are 1..=2 digits each, source first; prefer the 2-digit source on ambiguity
        for cut in [2usize, 1] {
            if d.len() > cut {
                if let (Ok(a), Ok(b)) = (d[..cut].parse(), d[cut..].parse()) {
                    // no width is printed with a leading zero
                    if !d[cut..].starts_with('0') {
                        return Some((a, b));
                    }
                }
            }
        }
        None
    };
    let mut i = 0;
    let b = tu.as_bytes();
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    while i < b.len() {
        if !is_ident(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && is_ident(b[i]) {
            i += 1;
        }
        let w = &tu[start..i];
        if start > 0 && is_ident(b[start - 1]) {
            continue;
        }
        let bad = if let Some(d) = w.strip_prefix("CONCAT") {
            split_pair(d).is_some_and(|(h, l)| h + l > 4)
        } else if let Some(d) =
            w.strip_prefix("SUB").or_else(|| w.strip_prefix("ZEXT")).or_else(|| w.strip_prefix("SEXT"))
        {
            split_pair(d).is_some_and(|(src, _)| src > 4)
        } else if w == "POPCOUNT" {
            true
        } else if w.starts_with("MOSURA_") || w == "spacebase" {
            // Phase 5: internal names escaping into C. `MOSURA_*` are printc's own explicit
            // placeholders (unrenderable op / unrecovered switch index); `spacebase` is the
            // TYPE_SPACEBASE datatype name reaching a declaration (upstream type-assignment
            // question — Ghidra's own C for the specimen is equally non-compiling, rendering
            // the raw stack pointer as `register0x00000010`).
            true
        } else {
            matches!(
                w,
                "int8" | "uint8" | "xunknown8" | "xunknown6" | "xunknown7" | "undefined6"
                    | "undefined7" | "undefined8" | "int5" | "uint5" | "int6" | "uint6"
                    | "int10" | "uint10" | "xunknown5" | "undefined5"
            )
        };
        if bad {
            out.insert(w.to_string());
        }
    }
    out.into_iter().collect()
}

fn kind_of(name: &str) -> &'static str {
    if mosura::analysis::program::function::Function::name_is_default(name) {
        "user"
    } else {
        "library"
    }
}

/// The subject's language. WAR2 is a 32-bit protected-mode DOS image.
const SURVEY_LANG: &str = "x86:LE:32:default";

fn git_stamp() -> String {
    // The stamp must name the commit of the code that PRODUCED this emit, and that is not
    // whatever repository the process happens to be standing in. Running the survey from the
    // data directory once that directory became a git repository of its own stamped every
    // artifact with the DATA repo's commit — a plausible-looking sha that attributes the emit to
    // the wrong tree entirely, and one that the compile stage's staleness gate then compares
    // against mosura's HEAD and rejects. `CARGO_MANIFEST_DIR` is baked in at build time and
    // points into the source tree this binary was built from, which is the thing being stamped.
    let src_dir = env!("CARGO_MANIFEST_DIR");
    let sha = std::process::Command::new("git")
        .args(["-C", src_dir, "rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(sha) = sha else { return "nogit".to_string() };
    let dirty = std::process::Command::new("git")
        .args(["-C", src_dir, "status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    if dirty { format!("{sha}-dirty") } else { sha }
}

/// Point an unsuffixed name (`src`, `raw`, `manifest.tsv`) at the current stamp, so the
/// consumers keep working while the stamped artifact is what actually persists.
///
/// A pre-existing REAL file or directory is MOVED ASIDE to `<name>.pre-stamping`, never deleted
/// and never left in place. Deleting it would destroy the baseline this change exists to protect;
/// leaving it in place would be worse than the old behaviour, because compile.sh reads the
/// unsuffixed `src/` and would silently keep compiling the stale copy.
fn link_latest(link: &std::path::Path, target: &str) {
    match std::fs::symlink_metadata(link) {
        Ok(m) if m.file_type().is_symlink() => std::fs::remove_file(link).unwrap(),
        Ok(_) => {
            let aside = link.with_file_name(format!(
                "{}.pre-stamping",
                link.file_name().unwrap().to_string_lossy()
            ));
            assert!(
                !aside.exists(),
                "{} already exists — resolve it by hand; refusing to overwrite a baseline",
                aside.display()
            );
            std::fs::rename(link, &aside).unwrap();
            eprintln!("note: moved pre-stamping {} -> {}", link.display(), aside.display());
        }
        Err(_) => {}
    }
    std::os::unix::fs::symlink(target, link).unwrap();
}

/// Watcom register names for the parameter storage the decompiler recovered, keyed by SLEIGH
/// register offset. Built once from the language spec rather than hardcoded, so a register that
/// moves in the spec cannot silently mis-map.
fn watcom_reg_table() -> Vec<(u64, u32, &'static str)> {
    let Some(spec) = mosura::lang::load_cached("x86:LE:32:default") else { return Vec::new() };
    let mut t = Vec::new();
    // The watcall argument registers, in convention order, with the sub-register Watcom uses for a
    // narrow argument (open-watcom-v2 `owflat.h`: a byte argument travels in AL/DL/BL/CL).
    // (32-bit name, 16-bit name, 8-bit low, 8-bit high). ESI/EDI/EBP have NO 8-bit forms on x86:
    // naming one produces a pragma Watcom rejects, and a rejected pragma is not a local failure —
    // `E1122` aborted a whole dosemu batch once already and cost an entire measurement.
    for (e, w, b, hi) in [
        ("EAX", "ax", Some("al"), Some("ah")),
        ("EDX", "dx", Some("dl"), Some("dh")),
        ("EBX", "bx", Some("bl"), Some("bh")),
        ("ECX", "cx", Some("cl"), Some("ch")),
        // Not watcall argument registers, but a function whose parameters demonstrably arrive in
        // them is using a custom convention, and `#pragma aux ... parm [esi] [edi]` is how Watcom
        // is told so. `recover_input_params`' custom-register branch recovers these.
        ("ESI", "si", None, None),
        ("EDI", "di", None, None),
        ("EBP", "bp", None, None),
    ] {
        let Some(off) = spec.0.register_offset(e) else { continue };
        t.push((off, 4, Box::leak(e.to_lowercase().into_boxed_str()) as &'static str));
        t.push((off, 2, w));
        if let Some(b) = b {
            t.push((off, 1, b));
        }
        if let Some(hi) = hi {
            t.push((off + 1, 1, hi));
        }
    }
    t
}

/// The `parm [..]` list to declare, or `None` when the recovered storage already IS what Watcom
/// would assign by position — in which case the pragma would be a no-op and is left off.
///
/// Only all-register prototypes are handled: a mixed register/stack prototype needs the overflow
/// form and is left to the default, and an unmappable storage returns `None` rather than guessing.
fn nondefault_parm_regs(
    f: &mosura::decompile::funcdata::Funcdata,
    table: &[(u64, u32, &'static str)],
) -> Option<String> {
    let slots = mosura::decompile::printc::rendered_param_slots(f);
    if slots.is_empty() {
        return None;
    }
    let reg = f.spaces.by_name("register")?;
    let mut storages = Vec::new();
    for s in &slots {
        if s.addr.space != reg {
            return None;
        }
        storages.push((s.addr.offset, s.size));
    }
    nondefault_parm_from_storages(&storages, table)
}

/// The storage-list core of [`nondefault_parm_regs`], shared with the CALLER-side extern
/// pragmas: the `parm [..]` list for an ordered register-storage list, or `None` when the
/// list is exactly Watcom's positional default (the pragma would be a no-op), a register is
/// not in the table, or EBP/ESP appears.
fn nondefault_parm_from_storages(
    storages: &[(u64, u32)],
    table: &[(u64, u32, &'static str)],
) -> Option<String> {
    if storages.is_empty() {
        return None;
    }
    let mut names = Vec::new();
    for &(off, size) in storages {
        let n = table.iter().find(|&&(o, sz, _)| o == off && sz == size)?;
        // The frame and stack pointers are not argument storage under any Watcom convention, and
        // naming one in a `parm` list is rejected outright: `E1122: Illegal register modified by
        // '<name>' #pragma`, which fails the whole translation unit. Recovering a parameter in EBP
        // means the recovery is wrong, so drop the DECLARATION rather than emit a list that cannot
        // compile — a partial list would silently re-map the other parameters.
        if n.2 == "ebp" || n.2 == "esp" {
            return None;
        }
        names.push(n.2);
    }
    // What Watcom assigns by position, for these same sizes.
    let order = ["a", "d", "b", "c"];
    let default: Vec<String> = storages
        .iter()
        .enumerate()
        .map(|(i, s)| match (order.get(i), s.1) {
            (Some(p), 4) => format!("e{p}x"),
            (Some(p), 2) => format!("{p}x"),
            (Some(p), 1) => format!("{p}l"),
            _ => String::new(),
        })
        .collect();
    if default.iter().zip(&names).all(|(d, n)| d == n) {
        return None;
    }
    Some(names.iter().map(|n| format!("[{n}]")).collect::<Vec<_>>().join(" "))
}

/// The function's own Watcom contract — its `parm` list where the recovered storage is not what
/// Watcom would assign by position, and its `modify` list where the decompiler established which
/// registers the function destroys. `None` when neither is needed.
///
/// The `modify` half is the expensive one to omit. Without it Watcom preserves every register it
/// uses that the default convention does not let it destroy, so a function whose original freely
/// clobbers EDX comes back with a `push edx`/`pop edx` pair around the whole body. Measured on
/// FUN_0002266c: 31 bytes against the original's 29, and with `modify [eax edx]` it matches
/// instruction for instruction. Across the survey the same shape shows up in aggregate as `pop`
/// -428 and `push` -207 against the originals — 39% of the entire instruction deficit.
///
/// `modify` (additive) rather than `modify exact`: the exact form also strips the SEGMENT registers
/// from the preserved set and Watcom starts saving GS.
fn own_contract(
    f: &mosura::decompile::funcdata::Funcdata,
    table: &[(u64, u32, &'static str)],
    stack_convention: bool,
    cleanup: Option<u32>,
) -> Option<String> {
    let mut parts = Vec::new();
    // A STACK-BASED prototype is `parm []`. It used to short-circuit the whole declaration, so
    // these functions never got their `modify` list — the two are independent facts about the
    // contract and both belong in the same pragma.
    //
    // WHO POPS is a third, independent fact, and it is not a choice: Watcom's default is
    // callee-pops (`parm routine`), and a function whose original ends in a bare `RET` after
    // reading `[ESP+4]` is caller-pops. Emitting the default regardless put a `RET 4` where the
    // original has `RET` in 101 WAR2 functions — 13 of them one instruction from exact and
    // nothing else wrong. `recompile::callee_stack_cleanup` reads the contract off the function's
    // own return instruction; where it cannot tell (no return, or returns that disagree) the
    // default stands, because a guess here is wrong code in every caller.
    if stack_convention {
        parts.push(match cleanup {
            Some(0) => "parm caller []".to_string(),
            _ => "parm []".to_string(),
        });
    } else if let Some(p) = nondefault_parm_regs(f, table) {
        parts.push(format!("parm {p}"));
    }
    // Only 4-byte general registers, named through the same spec-built table as `parm`.
    // M34 measured this list net-negative (15 regressions, 3 gains) because it OVER-DECLARED:
    // FUN_00010d70's original saves EBX, ECX, EDX and EBP, and we emitted `modify [eax ebx edx]`,
    // so Watcom skipped two saves and the function compiled 4 bytes short. The cause was a
    // sub-register offset mismatch in `callee_writes_cfg` — `mov ah,..` writes offset 1 while
    // `pop eax` restores offset 0, so a high-byte write slipped past the saved-and-restored filter
    // and was reported as destroying the whole register. Writes are normalized to their containing
    // register before that filter now, and this function's list is `[eax]`, which is right.
    if let Some(m) = f.own_modify.as_ref() {
        let regs: Vec<&str> = m
            .iter()
            // A SUB-REGISTER write modifies its containing 32-bit register: `mov ah,1` destroys
            // EAX, `xor dl,dl` destroys EDX. Requiring an exact 4-byte match dropped those from the
            // list entirely — FUN_00011ab8 writes AH and DL and declared only `modify [eax]`, so
            // Watcom still preserved EDX. Map an 8/16-bit offset back to the register that
            // contains it (AH sits at base+1, so try base and base-1).
            .filter_map(|off| {
                table
                    .iter()
                    .find(|&&(o, sz, _)| o == *off && sz == 4)
                    .or_else(|| table.iter().find(|&&(o, sz, _)| o + 1 == *off && sz == 4))
                    .map(|t| t.2)
            })
            // Watcom REJECTS the frame and stack pointers in a `modify` list —
            // `E1122: Illegal register modified by '<name>' #pragma` — and one such TU aborts the
            // whole dosemu batch, leaving every later function with a stale object.
            .filter(|r| *r != "ebp" && *r != "esp")
            .fold(Vec::new(), |mut acc, r| {
                // Dedup: a register and its sub-registers now map to the same name, and
                // `modify [eax eax]` is not something to hand a compiler.
                if !acc.contains(&r) {
                    acc.push(r);
                }
                acc
            });
        if !regs.is_empty() {
            parts.push(format!("modify [{}]", regs.join(" ")));
        }
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

fn main() {
    let mut args = std::env::args().skip(1);
    let first = args.next().expect("usage: war2_survey [--prelude-only] <war2.exe> <out_dir>");
    // `--prelude-only <out_dir>` rewrites <out>/prelude.h from PRELUDE and exits. It exists so a
    // prelude change never has to be hand-applied to the generated file (see PRELUDE's warning):
    // the compile stage's header is always regenerated from the constant, in seconds, without a
    // 6-minute re-emit.
    if first == "--prelude-only" {
        let out = std::path::PathBuf::from(
            args.next().expect("usage: war2_survey --prelude-only <out_dir>"),
        );
        std::fs::write(out.join("prelude.h"), build_prelude()).unwrap();
        println!("wrote {}", out.join("prelude.h").display());
        return;
    }
    let bin = first;
    let out = std::path::PathBuf::from(args.next().expect("usage: war2_survey <war2.exe> <out_dir>"));
    let rest: Vec<String> = args.collect();
    let force = rest.iter().any(|a| a == "--force");
    // `--only <va>[,<va>...]` emits JUST those functions and prints each TU to stdout instead of
    // running the whole 3023-function survey. A single function's C is what an MVE-first loop needs
    // to see after a decompiler change, and re-emitting the corpus to read one signature is the
    // long-running step that loop exists to avoid. Writes nothing, so it can be run while a real
    // survey is in flight.
    let only: Vec<u64> = rest
        .iter()
        .position(|a| a == "--only")
        .and_then(|i| rest.get(i + 1))
        .map(|v| {
            v.split(',')
                .map(|t| u64::from_str_radix(t.trim().trim_start_matches("0x"), 16).expect("hex va"))
                .collect()
        })
        .unwrap_or_default();

    // `--arms <θ>[;<θ>...]` emits the corpus under several EMISSION CHOICE VECTORS in ONE pass —
    // e.g. `--arms 'default;return-width=storage'`. Each θ is a different rendering of the SAME
    // recovered program (see `decompile::emit::EmitChoices` for the rules that keep that true), so
    // this is the generate half of the byte-exact search: which rendering the original compiler was
    // given is not derivable from the IR, and the compiler in the loop is what decides it.
    //
    // One pass rather than one run per arm, because decompiling is θ-independent and is essentially
    // the whole cost: a second arm adds a `print_c_with` per function (milliseconds) instead of a
    // second 50-second analysis. Arm 0 writes the ordinary `src.<stamp>/`, so a run without
    // `--arms` is byte-for-byte the run that existed before this option.
    let arms: Vec<EmitChoices> = rest
        .iter()
        .position(|a| a == "--arms")
        .and_then(|i| rest.get(i + 1))
        .map(|v| {
            v.split(';')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(|t| EmitChoices::parse(t).unwrap_or_else(|e| panic!("--arms: {e}")))
                .collect()
        })
        .unwrap_or_else(|| vec![EmitChoices::default()]);
    // Like the loop-overflow branch form below: this survey's output exists to be RECOMPILED,
    // and the target's shift instructions perform the `& 0x1f` count mask themselves, so every
    // arm elides the lifter's hardware mask (`EmitChoices` shift-mask=hardware; the axis doc in
    // decompile/emit.rs carries the measured probe — under the faithful rendering 64 functions
    // gained a materialized `AND CL,0x1f` the originals never had).
    let recovered_dir: Option<std::path::PathBuf> = rest
        .iter()
        .position(|a| a == "--recovered")
        .and_then(|i| rest.get(i + 1))
        .map(std::path::PathBuf::from);
    if let Some(d) = &recovered_dir {
        std::fs::create_dir_all(d).unwrap();
    }
    let arms: Vec<EmitChoices> = arms
        .into_iter()
        .map(|mut a| {
            a.shift_mask = mosura::decompile::emit::ShiftMask::Hardware;
            a
        })
        .collect();

    // Artifacts are STAMPED with the commit that produced them: `src.<stamp>/`, `raw.<stamp>/`,
    // `manifest.<stamp>.tsv`, with the unsuffixed names as symlinks to the current stamp.
    //
    // This exists because the emit used to write those three paths directly and truncate them, so
    // every measurement destroyed the state it would have been compared against. The only defence
    // was the operator remembering to copy a snapshot aside first — and the evidence that it does
    // not work is still in war2-survey/: 21 hand-made snapshot directories in five different
    // naming conventions, of which 8 (`src.prev`, `src.base`, `src.b2-half`, …) name no commit at
    // all and are therefore useless as a baseline for any claim.
    //
    // A `-dirty` stamp marks an emit no commit can reproduce. That is the whole point: it is the
    // class those 8 orphans belong to, made visible in the filename instead of discovered later.
    let stamp = git_stamp();
    let src_dir = out.join(format!("src.{stamp}"));
    let raw_dir = out.join(format!("raw.{stamp}"));
    let manifest_path = out.join(format!("manifest.{stamp}.tsv"));
    // Arm 0 IS `src.<stamp>/`; every further arm gets its own stamped directory named by its θ, so
    // two arms can never be blended into one directory that is a snapshot of neither.
    let arm_dirs: Vec<std::path::PathBuf> = arms
        .iter()
        .enumerate()
        .map(|(i, t)| if i == 0 { src_dir.clone() } else { out.join(format!("src-{}.{stamp}", t.tag())) })
        .collect();

    // `--only` is a READ-ONLY probe. Everything below this point rewrites the survey's working
    // state — it clears the stamped src/raw directories, regenerates prelude.h, repoints the
    // `src`/`raw`/`manifest` symlinks and truncates a manifest — so a one-function probe run while
    // a real survey is in flight would destroy that survey's inputs mid-run. (Overlapping runs
    // have already cost this project one measurement.) Probing must be free of that.
    let probing = !only.is_empty();

    // A re-emit at the same clean commit is a no-op, not a silent rewrite. `-dirty` is exempt: an
    // uncommitted tree is expected to be re-emitted repeatedly while iterating.
    if !probing && src_dir.exists() && !stamp.ends_with("-dirty") && !force {
        eprintln!(
            "{} already exists — that commit has been emitted.\n\
             Re-run with --force to overwrite it, or commit first for a new stamp.",
            src_dir.display()
        );
        std::process::exit(2);
    }

    // CLEAR the stamped dirs first. `create_dir_all` alone leaves earlier files in place, so a
    // re-emit that produces fewer functions — or renumbers them — blends two runs into one
    // directory that is a snapshot of neither. That is not hypothetical: the pre-stamping
    // `war2-survey/src/` held .c files spanning 2026-08-03 to 2026-08-05 from separate emits.
    // Only reachable for a new stamp (nothing to clear), a `-dirty` stamp, or --force.
    if !probing {
        for d in arm_dirs.iter().chain([&raw_dir]) {
            if d.exists() {
                std::fs::remove_dir_all(d).unwrap();
            }
        }
        for d in &arm_dirs {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::create_dir_all(&raw_dir).unwrap();
        std::fs::write(out.join("prelude.h"), build_prelude()).unwrap();
    }
    // compile.sh reads <out>/src/$n.c and <out>/manifest.tsv; compare.py reads <out>/manifest.tsv.
    // Pointing the bare names at the current stamp keeps both working unchanged.
    if !probing {
        link_latest(&out.join("src"), &format!("src.{stamp}"));
        for (t, d) in arms.iter().zip(&arm_dirs).skip(1) {
            let name = d.file_name().unwrap().to_string_lossy().to_string();
            link_latest(&out.join(format!("src-{}", t.tag())), &name);
        }
        link_latest(&out.join("raw"), &format!("raw.{stamp}"));
        link_latest(&out.join("manifest.tsv"), &format!("manifest.{stamp}.tsv"));
    }

    // The stack pointer's register-space offset, from the language tables rather than a constant.
    let esp_off = mosura::lang::load_cached(SURVEY_LANG).and_then(|(spec, _)| spec.register_offset("ESP"));

    eprintln!("loading WAR2 via analyze_le_file ...");
    let mut prog = analysis::analyze_le_file(std::path::Path::new(&bin)).expect("analyze_le_file");
    // The byte-exact emitter models Ghidra's STANDALONE global-scope context (no auto-resolved
    // symbols, ActionConstantPtr silent): the binary is this tool's oracle, its source wrote
    // plain address constants, and the application context's anchored `(&xRam..)[..]` forms cost
    // 89 EXACT + 16 new COMPILE_FAILs when measured (sb25). Both contexts are real Ghidra; this
    // selects the one whose output reproduces. See `Program::global_scope_all_loaded`.
    prog.global_scope_all_loaded = false;
    // PASS 1 — recover every function's prototype, so pass 2's callers can consult the callee
    // instead of guessing it from one call site. Costs one decompile per function; the emit that
    // follows is the second.
    //
    // OFF BY DEFAULT, on a measurement. Over the whole corpus it costs 26 byte-exact functions
    // (420 -> 394): `missing` falls by 87, exactly as intended, and `extra` rises by 105. Trading
    // one for the other is not progress, and the plan named that trade in advance as the thing to
    // watch.
    //
    // The DIAGNOSIS is not "the prototypes are wrong" — they are right. `FUN_0005a48c` really does
    // take a pointer in EAX, and its caller really does pass one: the original leaves the previous
    // call's result in EAX and calls straight through, so the argument costs no instruction at all.
    // What fails is the argument's VALUE. A declared parameter the call site has no varnode for
    // takes the `unref` path in `build_input_from_trials`, which creates a FRESH varnode at the
    // parameter's storage — and heritage has already run, so that varnode can never be linked to
    // the value reaching the call. It renders as a constant, and the caller emits `XOR EAX,EAX` to
    // produce a zero the original never wanted.
    //
    // So the missing piece is binding a propagated parameter to the value live in its storage at
    // the call, which is a heritage-ordering problem rather than a prototype problem.
    // `MOSURA_PROTO_PASS=1` enables the pass for work on exactly that.
    if std::env::var("MOSURA_PROTO_PASS").as_deref() == Ok("1") {
        let t = std::time::Instant::now();
        prog.recovered_protos = analysis::interface::recover_prototypes(&prog);
        eprintln!(
            "prototype pass: {} functions in {:.1}s",
            prog.recovered_protos.len(),
            t.elapsed().as_secs_f64()
        );
    }
    let prog = prog;
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

    // The decompiler-independent bounds on a function's extent.
    //
    // `next` is the upper bound: the next function's entry, or the end of the memory block
    // containing it, whichever comes first. Both are facts the loader established.
    //
    // This replaces three invented constants, each of which would have truncated silently:
    //   * `.min(*va + 8192)` -- no function may exceed 8 KB. Nothing checks this, and a larger
    //     function would simply have been compared against its first 8 KB and reported as a
    //     decompiler failure. Zero functions in WAR2 reach it, so it never fired; it was a
    //     tripwire waiting for a bigger subject.
    //   * `.min(0x7_c4a0)` -- this binary's code-section end, hardcoded into a tool that is
    //     supposed to work on any binary. Correct here by coincidence, wrong everywhere else.
    //   * `.unwrap_or(*va + 512)` -- an arbitrary extent for the LAST function, which has no
    //     next entry. WAR2's last function is 207 bytes, so this never fired either.
    //
    // The block end answers the same question the constants were guessing at, and answers it
    // for whatever binary is loaded.
    //
    // The second bound is the function manager's own recorded body end, when it has one.
    //
    // Factored out of the OK path so the DECOMPILE_FAIL row records a real extent too: a
    // failed function still weighs its full size in any corpus-level aggregate (the global
    // similarity), and a recorded 0 reads as "excluded" downstream.
    let extent_bounds = |va: u64| -> (u64, Option<u64>) {
        let block_end = prog.memory.block_at(Address::new(ram, va)).map(|b| b.end().offset + 1);
        let next_entry = entry_offs.iter().copied().find(|&o| o > va);
        let next = match (next_entry, block_end) {
            (Some(n), Some(b)) => n.min(b),
            (Some(n), None) => n,
            (None, Some(b)) => b,
            (None, None) => va + 1,
        };
        let body_end = prog
            .function_manager
            .function_at(Address::new(ram, va))
            .and_then(|f| f.body().max_address())
            .map(|a| a.offset + 1);
        (next, body_end)
    };

    let mut mf: std::io::BufWriter<Box<dyn std::io::Write>> = std::io::BufWriter::new(if probing {
        Box::new(std::io::sink())
    } else {
        Box::new(std::fs::File::create(&manifest_path).unwrap())
    });
    // Stamp the manifest itself, so a .tsv that has been copied away from its directory still
    // says which tree produced it. Both consumers skipped exactly one line (compile.sh's
    // `tail -n +2`, compare.py's `header = next(fh)`), so they were changed to drop `#` lines
    // first — otherwise this line pushes the column header into the data.
    writeln!(mf, "# war2_survey emit @ {stamp}").unwrap();
    writeln!(
        mf,
        "idx\tva\tname\tstatus\torig_len\tcov_lo\tcov_hi\tsmells\torig_hex\tir_calls\tblocks_cfg\tblocks_reached\tkind\tcontract"
    )
    .unwrap();
    let mut contract_bad = 0usize;
    // va -> the function's own nondefault `parm [..]` list (None = default order). Filled by
    // the emit loop, consumed by the caller-side pragma post-pass below it.
    let mut parm_map: std::collections::BTreeMap<u64, Option<(String, Vec<u32>)>> = Default::default();
    // caller idx -> (callee va -> argument count at the caller's call sites, None on
    // disagreement between sites). The post-pass applies a callee's pragma only where the
    // caller's arity matches the pragma's parameter count: the callee's rendered params are
    // its USED slots only, and a pragma shorter than the caller's argument list makes
    // Watcom overflow the extra arguments to the stack (measured: FUN_000345f4 passes
    // three args to a callee whose only USED param is BX — `parm [bx]` turned two
    // register moves into three PUSHes).
    let mut caller_calls: std::collections::BTreeMap<u64, std::collections::BTreeMap<u64, Option<Vec<u32>>>> =
        Default::default();
    let mut contract_counts: std::collections::BTreeMap<String, usize> = Default::default();
    let mut contract_hist: std::collections::BTreeMap<String, usize> = Default::default();
    let _ = &contract_hist;

    // RECOMPILATION RENDERING. Ghidra picks between `while (a = a-1, a != -1)` and
    // `while( true ) { a = a-1; if (a == -1) break; }` on a READABILITY threshold
    // (BlockBasic::isComplex). The two are semantically identical and do NOT compile the same:
    // Watcom cannot short-circuit a comma-operator condition into a branch, so it materializes the
    // truth value (`setne al ; and eax,0xff ; je` for a single `je`). This survey's output exists
    // to be RECOMPILED, so it takes the branch form always. Measured on FUN_000458ec: 35 bytes
    // with the comma condition against the original's 27, and all 27 — instruction for
    // instruction — with this on.
    mosura::decompile::structure::set_force_loop_overflow(true);
    let watreg = watcom_reg_table();
    let t0 = std::time::Instant::now();
    let (mut ok, mut fail) = (0usize, 0usize);
    for (idx, (va, name)) in entries.iter().enumerate() {
        if !only.is_empty() && !only.contains(va) {
            continue;
        }
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
            let head = head.replace(['\t', '\n'], " ");
            let head: String = head.chars().take(120).collect();
            // Extent from the decompiler-independent bounds alone -- no coverage to clamp
            // with and no padding trim. This is the row's WEIGHT downstream, not a diff
            // extent: there is no candidate to diff against.
            let (next, body_end) = extent_bounds(*va);
            let flen = match body_end {
                Some(b) => next.min(b),
                None => next,
            }
            .max(*va + 1)
                - *va;
            writeln!(mf, "{idx:05}\t{va:08x}\t{name}\tDECOMPILE_FAIL\t{flen}\t0\t0\t\t{head}\t0\t0\t0\t{}\t", kind_of(name)).unwrap();
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
                Some(mosura::analysis::program::CodeUnit::Instruction { length, .. }) => *length as u64,
                _ => 1,
            };
            cov_lo = cov_lo.min(pc.offset);
            cov_hi = cov_hi.max(pc.offset + len);
        }
        if cov_lo == u64::MAX {
            cov_lo = *va;
            cov_hi = *va;
        }

        // The function's extent is mosura's OWN recorded body, not the gap to the next entry.
        //
        // `[entry, next-entry)` attributes to a function everything the linker happened to place
        // after it, and what follows a function is very often DATA. Measured on WAR2: the body is
        // smaller than the gap for 2140 of 3023 functions, totalling 49,359 bytes of data counted
        // as code. The worst is `FUN_00075801` -- a 48-byte comparator followed by a 7,727-byte
        // table -- which was compared as 2591 instructions against the 20 it really has, and read
        // as a catastrophic decompiler failure when the decompilation is exactly right.
        //
        // The body is clamped on both sides rather than trusted outright, because neither bound is
        // free:
        //   * never past `next` -- 11 functions have bodies that run beyond the following entry,
        //     which would make two functions claim the same bytes;
        //   * never below `cov_hi` -- if body computation ever UNDER-states a function, truncating
        //     the original would hide a real failure by comparing against less than the function.
        // Both bounds are facts already established above, so this only ever pulls the end IN from
        // the heuristic, never pushes it out.
        let (next, body_end) = extent_bounds(*va);
        let mut end = match body_end {
            Some(b) => next.min(b.max(cov_hi)).max(*va + 1),
            None => next.max(*va + 1),
        };
        // INSTRUMENT (`MOSURA_EXTENT=1`): the three candidate answers to "where does this
        // function end" -- the next-entry heuristic actually used, mosura's own recorded body, and
        // the decompiler's instruction coverage -- so the choice between them is a measurement.
        if std::env::var("MOSURA_EXTENT").is_ok() {
            println!(
                "EXTENT\t{:08x}\t{}\t{}\t{}",
                *va,
                end - *va,
                body_end.map(|b| b.saturating_sub(*va) as i64).unwrap_or(-1),
                cov_hi.saturating_sub(*va)
            );
        }
        let mut region = prog.memory.read_window(Address::new(ram, *va), (end - *va) as usize);
        // Trim trailing padding, but NEVER below the end of the last decoded instruction. The
        // trimmer used to strip any trailing 0x00/0x90/0xcc, and the last byte of a real operand is
        // very often 0x00 — `e9 0c610100` (a 5-byte `jmp rel32` tail-call shim) came back as 4
        // bytes with its displacement cut, and `b0 01 c2 0400` (`mov al,1 ; ret 4`) likewise. The
        // function was then compared against a truncated original, and the row read as a decompiler
        // failure. Measured against the tracker's true sizes: 39 extents short, 28 of them by
        // exactly one byte.
        //
        // `cov_hi` is the end of the highest instruction the decompiled function actually covers,
        // so it is the floor for trimming: padding is what lies AFTER the code, never inside it.
        let floor = cov_hi.max(*va + 1);
        while end > floor && region.last().is_some_and(|&b| b == 0x00 || b == 0x90 || b == 0xcc) {
            region.pop();
            end -= 1;
        }
        let orig_len = region.len();

        // CALLS PRESENT IN THE FINAL IR. The absolute call gauge counts calls in the RENDER, which
        // cannot distinguish "the decompiler never recovered it" from "the decompiler recovered it and
        // the emitter lost it". Those are different defects in different layers, and the gauge — our
        // BLOCKING gate — has been charging the second to the first: FUN_00077dcb's missing call is
        // LIVE in its final IR at 0x77e0a, sitting in a basic block `structure()` never places. So the
        // manifest carries the IR count too, and a deficit row classifies itself:
        //     ir_calls == rendered  -> the shortfall is upstream of the emitter (decompiler)
        //     ir_calls >  rendered  -> the emitter lost a recovered call
        // Counted the same way the gauge counts: live CALL/CALLIND ops only.
        let ir_calls = f
            .op_ids()
            .filter(|&id| {
                let op = f.op(id);
                op.flags & (flags::DEAD | flags::MARKER) == 0
                    && matches!(op.code(), OpCode::Call | OpCode::Callind)
            })
            .count();

        // BLOCKS: how many basic blocks the CFG has vs how many the structured tree REACHES.
        // `reached < cfg` means blocks are never emitted — wrong code, and the ONLY gate that sees the
        // silent case (a dropped block with no surviving in-edge produces no dangling goto and no
        // compiler error; the C just compiles the wrong program). See
        // `decompile::structure::reached_basic_blocks`.
        let blocks_cfg = f.num_blocks();
        let blocks_reached =
            mosura::decompile::structure::reached_basic_blocks(&mosura::decompile::structure::structure(&f))
                .len();

        // Decompiling is θ-independent and dominates the cost, so every rendering the caller asked
        // for is printed from this one Funcdata. That is what makes a multi-arm emit cost a print
        // per arm instead of a whole second analysis.
        let c = print_c_with(&f, &arms[0]);
        if !probing {
            std::fs::write(raw_dir.join(format!("{va:08x}.c")), &c).unwrap();
        }

        // Synthesize a standalone TU and detect decompiler-artifact "smells".
        let thunk = matches!(region.first(), Some(0xe9) | Some(0xeb)) && orig_len <= 8;
        // GLOBAL WIDTHS, from the decompiler rather than from the name. The emitter used to pick a
        // Ram global's C type from its name prefix alone, which carries kind but not SIZE, so every
        // scalar global came out `int`. A one-byte global then compiles to a 4-byte store:
        // FUN_0003ca48's original is `mov [0x95435],al` (`a2`), and `int xRam00095435;` turns that
        // into a dword store — wrong opcode, wrong length. 3083 globals are declared `int` today.
        // The decompiled function knows each varnode's width, so ask it.
        let ram_dec = f.spaces.by_name("ram");
        let mut gsizes: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
        for i in 0..f.num_varnodes() as u32 {
            let vn = f.vn(mosura::decompile::varnode::VarnodeId(i));
            // `Processor` covers ram AND register, so select the data space by NAME — the
            // decompiler's space ids differ from the analysis Program's and must not be carried
            // across that boundary.
            if Some(vn.loc.space) != ram_dec {
                continue;
            }
            // Narrowest access wins: a byte store is what fixes the declaration, and a wider
            // access at the same address is a different (adjacent or overlapping) object.
            gsizes
                .entry(vn.loc.offset)
                .and_modify(|e| *e = (*e).min(vn.size))
                .or_insert(vn.size);
        }
        // STACK-BASED CONVENTION. A function whose recovered parameters all live on the STACK is
        // not using default __watcall — Watcom spells that `#pragma aux <name> parm []`, and
        // warcraft2-re's proven sources use exactly that form. Without the declaration the emitted
        // C is compiled as a register-convention function: the argument arrives in EAX instead of
        // at [ebp+8] and the body ends `ret` instead of `ret 4`. Measured on FUN_00030da8, whose
        // original is
        //     55 89e5 8b4508 e8...... 5d c2 0400
        //     push ebp ; mov ebp,esp ; mov eax,[ebp+8] ; call ; pop ebp ; ret 4
        // Recovering the parameter WITHOUT declaring the convention is inert, which is exactly
        // what an earlier measurement of the recovery half alone showed.
        //
        // `parm []` and not `parm caller []`: the caller-pop form leaves a bare `ret`, and the
        // callee-pop default is what produces the `ret N` these functions carry.
        let proto = mosura::decompile::fspec::recover_func_proto(&f);
        let stack_convention = !proto.params.is_empty()
            && proto.params.iter().all(|p| {
                f.spaces.get(p.addr.space).kind == mosura::decompile::space::SpaceKind::Spacebase
            });
        // The callee's stack-cleanup contract, read from its own return instruction. Lifting the
        // already-decoded bytes again costs a disassembly per function, which is nothing beside the
        // decompile that just ran, and keeps this a property of the SUBJECT rather than of our IR.
        let cleanup = esp_off.and_then(|sp| {
            mosura::sleigh::disassemble(SURVEY_LANG, &region, *va)
                .ok()
                .and_then(|insns| mosura::recompile::callee_stack_cleanup(&insns, sp))
        });
        let contract = own_contract(&f, &watreg, stack_convention, cleanup);
        // CALLER-SIDE REGISTER CONTRACTS, definition-side truth. The `parm [..]` pragma
        // below tells Watcom the callee's true argument registers — but only in the callee's
        // own TU; a caller compiles against a bare `extern int func_0xNNN();` and Watcom
        // binds the argument list POSITIONALLY to the default order, inverting every call to
        // a callee whose recovered storage is nonstandard (measured: FUN_0003925c passed its
        // table index in EAX where the original — and the callee's own pragma,
        // FUN_00038828 `parm [edx] [eax]` — take it in EDX; 155 callees carry a nondefault
        // order). The pragma each caller needs is EXACTLY the one the callee's own TU
        // declares, so it is collected here per function and PREPENDED to every TU that
        // externs the callee in a post-pass after the loop, when the map is complete —
        // deriving it caller-side from `CallSpec::reads` was measured wrong (reads is the
        // read-before-write evidence SET, not slot-ordered parameter storage: sb48's first
        // cut broke 8 EXACT callers whose callees' own recovery says default order).
        parm_map.insert(
            *va,
            nondefault_parm_regs(&f, &watreg).map(|decl| {
                let sizes = mosura::decompile::printc::rendered_param_slots(&f)
                    .iter()
                    .map(|sl| sl.size)
                    .collect();
                (decl, sizes)
            }),
        );
        {
            let m = caller_calls.entry(*va).or_default();
            for opid in f.op_ids() {
                let op = f.op(opid);
                if op.code() != OpCode::Call || op.flags & (flags::DEAD | flags::MARKER) != 0 {
                    continue;
                }
                let Some(t) = op.input(0) else { continue };
                let callee = f.vn(t).loc.offset;
                let sizes: Vec<u32> =
                    (1..op.num_inputs()).filter_map(|i| op.input(i)).map(|v| f.vn(v).size).collect();
                match m.entry(callee) {
                    std::collections::btree_map::Entry::Occupied(mut e) => {
                        if e.get().as_ref() != Some(&sizes) {
                            e.insert(None);
                        }
                    }
                    std::collections::btree_map::Entry::Vacant(v_) => {
                        v_.insert(Some(sizes));
                    }
                }
            }
        }

        // Arms past the first: same function, same declarations, a different rendering of the body.
        for (ai, theta) in arms.iter().enumerate().skip(1) {
            let ac = print_c_with(&f, theta);
            let (atu, _) = build_tu(&ac, *va, false, &gsizes);
            let atu = match &contract {
                Some(decl) => format!("#pragma aux {name} {decl};\n{atu}"),
                None => atu,
            };
            if only.is_empty() {
                std::fs::write(arm_dirs[ai].join(format!("{idx:05}.c")), &atu).unwrap();
            }
        }
        // RECOVERED emission (`--recovered <dir>`): the field path — per-site choices decided
        // from evidence in the ORIGINAL's own instructions by the target profile, with no
        // compiler and no search. Emitted alongside the searched arms only so the two can be
        // compared; in the field this is the single emission.
        if let Some(dir) = &recovered_dir {
            let (_, report) = mosura::decompile::printc::print_c_report(&f, &arms[0]);
            let insns = mosura::recompile::insn::normalize(
                SURVEY_LANG,
                &region,
                *va,
                &mosura::recompile::insn::NoReloc,
            )
            .unwrap_or_default();
            let widen = mosura::recompile::buildconfig::widened_sites_from_evidence(
                &report.local_width_candidates,
                &report.tier2_candidates,
                &insns,
            );
            let recovered = mosura::decompile::printc::RecoveredChoices {
                complement_sites: mosura::recompile::buildconfig::complement_compares_from_evidence(
                    &report.compare_sites,
                    &insns,
                ),
                return_split_sites: mosura::recompile::buildconfig::split_returns_from_evidence(
                    &report.return_split_candidates,
                    &insns,
                ),
                nested_sites: mosura::recompile::buildconfig::nested_conds_from_evidence(
                    &report.cond_nest_candidates,
                    &insns,
                ),
                narrow_return: mosura::recompile::buildconfig::narrow_return_from_evidence(
                    &report.return_width_candidates,
                    &insns,
                ),
                widen_local_reps: widen.0,
                tier2_sites: widen.1,
            };
            let rc = mosura::decompile::printc::print_c_recovered(&f, &arms[0], &recovered);
            let (rtu, _) = build_tu(&rc, *va, false, &gsizes);
            let rtu = match &contract {
                Some(decl) => format!("#pragma aux {name} {decl};\n{rtu}"),
                None => rtu,
            };
            if only.is_empty() {
                std::fs::write(dir.join(format!("{idx:05}.c")), &rtu).unwrap();
            } else {
                println!("/* ===== RECOVERED (no-compiler field path) ===== */");
                println!("{rtu}");
            }
        }
        let (tu, mut smells) = build_tu(&c, *va, false, &gsizes);
        let tu = if let Some(decl) = contract.clone() {
            // REGISTER CONVENTION THAT IS NOT THE DEFAULT PREFIX. The decompiler recovers each
            // parameter's true STORAGE (Ghidra's `ParameterPieces::addr`), but a C signature can
            // only express POSITION — Watcom then assigns position 1 to EAX, 2 to EDX, and so on.
            // Whenever the recovered storage is not exactly that default assignment, the signature
            // alone compiles the arguments into the wrong registers, and `#pragma aux ... parm [..]`
            // is how Watcom is told the real one. This is the same mechanism as the `parm []`
            // stack case above, generalised to registers.
            format!("#pragma aux {name} {decl};\n{tu}")
        } else {
            tu
        };
        if thunk {
            smells.push("thunk".into());
        }
        if !only.is_empty() {
            // The post-pipeline IR, on request. A question about what the C says is often really a
            // question about what the op graph holds — here, whether a value the original widens is
            // still four bytes wide by the time the printer sees it. Answering that from the C is
            // guesswork; the graph states it.
            if std::env::var("MOSURA_RAW_IR").is_ok() {
                println!("{}", f.print_raw());
            }
            // The recovered parameter STORAGE alongside the C, so a signature question ("why is
            // this argument in the wrong register?") is answered by the same one-function run.
            let slots = mosura::decompile::printc::rendered_param_slots(&f);
            let store: Vec<String> = slots
                .iter()
                .map(|s| {
                    let sp = f.spaces.get(s.addr.space);
                    format!("{}+{:#x}/{}{}", sp.name, s.addr.offset, s.size, if s.vn.is_none() { "*" } else { "" })
                })
                .collect();
            // Every INPUT varnode, so "the prototype is missing a parameter" can be told apart
            // from "the value was never an input in the first place".
            let mut ins: Vec<String> = Vec::new();
            for i in 0..f.num_varnodes() as u32 {
                let vn = f.vn(mosura::decompile::varnode::VarnodeId(i));
                if vn.is_input() {
                    ins.push(format!(
                        "{}+{:#x}/{}{}",
                        f.spaces.get(vn.loc.space).name,
                        vn.loc.offset,
                        vn.size,
                        if vn.descend.is_empty() { "(dead)" } else { "" }
                    ));
                }
            }
            println!("   inputs:       {}", ins.join(" "));
            let raw: Vec<String> = proto
                .params
                .iter()
                .map(|s| format!("{}+{:#x}/{}", f.spaces.get(s.addr.space).name, s.addr.offset, s.size))
                .collect();
            println!(
                "/* ===== {idx:05} {name} @ {va:08x} orig_len={orig_len}\n   proto.params: {}\n   rendered:     {}   (* = materialized hole)\n===== */\n{tu}",
                raw.join(" "),
                store.join(" "),
            );
            continue;
        }
        std::fs::write(src_dir.join(format!("{idx:05}.c")), &tu).unwrap();

        let violations = contract_violations(&tu);
        if !violations.is_empty() {
            contract_hist.entry(violations.join(",")).or_insert(0usize);
            for v in &violations {
                *contract_counts.entry(v.clone()).or_insert(0usize) += 1;
            }
            contract_bad += 1;
        }
        let orig_hex: String = region.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(
            mf,
            "{idx:05}\t{va:08x}\t{name}\tOK\t{orig_len}\t{cov_lo:08x}\t{cov_hi:08x}\t{}\t{orig_hex}\t{ir_calls}\t{blocks_cfg}\t{blocks_reached}\t{}\t{}",
            smells.join(","),
            kind_of(name),
            if violations.is_empty() { "ok".to_string() } else { format!("wide:{}", violations.join("+")) },
        )
        .unwrap();

        if idx % 200 == 0 {
            eprintln!("  {idx}/{} ok={ok} fail={fail} {:?}", entries.len(), t0.elapsed());
        }
    }
    mf.flush().unwrap();
    // CALLER-SIDE PRAGMA POST-PASS (see the parm_map comment in the loop): now that every
    // function's own `parm [..]` recovery is known, prepend to each written TU the pragma
    // for every nonstandard callee it externs. Textual, after the fact, because a caller can
    // be emitted before its callee's contract exists; the extern lines name the callees.
    // `--only` probe prints are not patched (they never hit disk).
    if only.is_empty() {
        // idx (the file stem) -> va, to find each TU's own call-arity map.
        let idx_va: std::collections::HashMap<String, u64> =
            entries.iter().enumerate().map(|(i, (va, _))| (format!("{i:05}"), *va)).collect();
        let ext_re = |src: &str| -> Vec<u64> {
            let mut out = Vec::new();
            for line in src.lines() {
                if let Some(rest) = line.strip_prefix("extern ") {
                    if let Some(pos) = rest.find("func_0x") {
                        if let Ok(va) = u64::from_str_radix(
                            rest[pos + 7..].split(|c: char| !c.is_ascii_hexdigit()).next().unwrap_or(""),
                            16,
                        ) {
                            out.push(va);
                        }
                    }
                }
            }
            out
        };
        let mut patched = 0usize;
        // the recovered tree externs the same callees and needs the same contracts — its
        // omission cost EXACT verdicts that looked like evidence-rule failures (the sb71
        // "12 lw-only wins" turned out partly to be TUs missing their callee pragmas)
        let mut all_dirs = arm_dirs.clone();
        if let Some(d) = &recovered_dir {
            all_dirs.push(d.clone());
        }
        for d in &all_dirs {
            let Ok(entries) = std::fs::read_dir(d) else { continue };
            for e in entries.flatten() {
                let path = e.path();
                if path.extension().and_then(|x| x.to_str()) != Some("c") {
                    continue;
                }
                let Ok(src) = std::fs::read_to_string(&path) else { continue };
                let caller_va = path
                    .file_stem()
                    .and_then(|st| st.to_str())
                    .and_then(|st| idx_va.get(st));
                let lines: String = ext_re(&src)
                    .into_iter()
                    .filter_map(|cva| {
                        let (decl, psizes) = parm_map.get(&cva).and_then(|d| d.as_ref())?;
                        // arity AND width gate: every call site in this TU must pass exactly
                        // the pragma's parameter count, each argument at the parameter's own
                        // width. A width mismatch is as fatal as an arity one — a 16-bit
                        // `parm [bx]` meeting a 4-byte argument overflows it to the STACK
                        // (measured: FUN_0002c8xx's `PUSH 0xc` where the original loads EBX).
                        let asizes = caller_va
                            .and_then(|va| caller_calls.get(va))
                            .and_then(|m| m.get(&cva))
                            .cloned()
                            .flatten()?;
                        // Per slot the pragma register must be AT LEAST the argument's width:
                        // a narrower argument binds the register's low part (measured EXACT —
                        // the byte index into `parm [edx]`), while a narrower REGISTER
                        // overflows the argument to the stack (the `parm [bx]` failure above).
                        (asizes.len() == psizes.len()
                            && asizes.iter().zip(psizes).all(|(a, p)| a <= p))
                        .then(|| format!("#pragma aux func_0x{cva:08x} parm {decl};\n"))
                    })
                    .collect();
                if !lines.is_empty() {
                    std::fs::write(&path, format!("{lines}{src}")).unwrap();
                    patched += 1;
                }
            }
        }
        eprintln!("caller-side parm pragmas: {patched} TU(s) patched");
    }
    eprintln!("EMIT done: ok={ok} fail={fail} in {:?}", t0.elapsed());
    if contract_bad > 0 {
        let mut top: Vec<_> = contract_counts.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1));
        let head: Vec<String> = top.iter().take(10).map(|(k, v)| format!("{k}x{v}")).collect();
        eprintln!(
            "CONTRACT: {contract_bad} TU(s) carry constructs the target cannot represent \
             (manifest column `contract`, docs/compilable-c-remediation.md Phase 2): {}",
            head.join(" ")
        );
    }
    eprintln!("manifest: {}", manifest_path.display());
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The exact unsigned integer type of a given byte width, or `None` when the prelude has no type
/// that is *exactly* that wide. Deliberately excludes `uint8` — the prelude maps it to `double`
/// (Watcom 10.0a is C89 with no 64-bit integer), and storing through a `double *` is not a
/// width-preserving integer write.
fn exact_uint(size: u32) -> Option<&'static str> {
    match size {
        1 => Some("uint1"),
        2 => Some("uint2"),
        4 => Some("uint4"),
        _ => None,
    }
}

/// Parse a partial-symbol field suffix `._<off>_<size>_` at `i`, returning `(off, size, end)`.
fn parse_field_suffix(b: &[u8], mut i: usize) -> Option<(u64, u32, usize)> {
    if i + 1 >= b.len() || b[i] != b'.' || b[i + 1] != b'_' {
        return None;
    }
    i += 2;
    let num = |i: &mut usize| -> Option<u64> {
        let s = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        if *i == s || *i >= b.len() || b[*i] != b'_' {
            return None;
        }
        let v = std::str::from_utf8(&b[s..*i]).ok()?.parse().ok()?;
        *i += 1;
        Some(v)
    };
    let off = num(&mut i)?;
    let size = num(&mut i)?;
    Some((off, size as u32, i))
}

/// Rewrite the decompiler's partial-symbol accessors into compilable C.
///
/// `base._<off>_<size>_` is Ghidra's own artificial field name for a `VariablePiece` that does not
/// span its `VariableGroup` (`PrintLanguage::unnamedField`, printlanguage.cc:719, via
/// `PrintC::pushPartialSymbol`, printc.cc:1947). The decompiler emitting it is FAITHFUL and is not
/// the thing to change — but Ghidra's C was never intended to compile, and recompiling is this
/// survey's entire purpose. Faithful and compilable are separate axes, and closing the gap belongs
/// here in the emitter. wcc386 rejects the accessor with `E1032: Expression for '.' must be a
/// 'structure' or 'union'`.
///
/// The replacement addresses exactly the same bytes: `*(uintN *)((char *)&base + off)`. Preserving
/// the WIDTH is the entire point — the accessor exists because a 1-byte store must not be rendered
/// as a 4-byte assignment, and a rewrite that widened the access would put that value drop straight
/// back. A size with no exactly-matching type is left untouched so it fails loudly at compile time
/// rather than silently widening.
fn compilable_partial_symbols(c: &str) -> String {
    let b = c.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if !(b[i].is_ascii_alphabetic() || b[i] == b'_') {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let s = i;
        while i < b.len() && is_ident(b[i]) {
            i += 1;
        }
        match parse_field_suffix(b, i).and_then(|(off, size, end)| {
            exact_uint(size).map(|ty| (off, ty, end))
        }) {
            Some((off, ty, end)) => {
                let base = &c[s..i];
                out.extend_from_slice(
                    format!("(*({ty} *)((char *)&{base} + {off}))").as_bytes(),
                );
                i = end;
            }
            None => out.extend_from_slice(&b[s..i]),
        }
    }
    String::from_utf8(out).expect("ASCII in, ASCII out")
}

/// Scan the decompiled C for identifier families that need a top-level declaration to form a
/// standalone translation unit, synthesize those declarations + the typedef prelude, and return
/// the full TU text plus a list of decompiler-artifact "smell" tags.
fn build_tu(
    c: &str,
    self_va: u64,
    non_contig: bool,
    gsizes: &std::collections::HashMap<u64, u32>,
) -> (String, Vec<String>) {
    // Make the faithful partial-symbol accessors compilable BEFORE the identifier scan, so the
    // base of each accessor is still seen and declared (it appears as `&base`, which is not a
    // pointer use, so it keeps its scalar declaration).
    let c = &compilable_partial_symbols(c);
    let self_name = format!("FUN_{self_va:08x}");
    let mut funcs: HashSet<String> = HashSet::new(); // func_0x.. / FUN_.. callees -> extern fn
    let mut ptr_idents: HashSet<String> = HashSet::new(); // used with [] -> pointer-typed global
    let mut scalar_idents: HashSet<(String, char)> = HashSet::new(); // (name, type-prefix)
    let mut smells: BTreeSet<String> = BTreeSet::new();

    let b = c.as_bytes();
    // Collect identifiers and whether each is used as a POINTER — either indexed (`ident[`) or
    // dereferenced (`*ident`). Both forms must promote the synthesized declaration to a pointer;
    // recognizing only the indexed form declared `unsigned int extraout_RCX;` and then compiled
    // `*extraout_RCX = ...` into a spurious `E1029: Expression must be 'pointer to ...'` — a
    // harness artifact counted against the decompiler (the IR types that varnode a pointer).
    //
    // The deref test is "immediately preceded by `*` with no space", which is exact for this
    // emitter: printc writes a unary dereference tight (`*ptr`) and every binary operator spaced
    // (` * `), so a multiplication can never match.
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_alphabetic() || b[i] == b'_' {
            let s = i;
            while i < b.len() && is_ident(b[i]) {
                i += 1;
            }
            let w = &c[s..i];
            let ptr_use = (i < b.len() && b[i] == b'[') || (s > 0 && b[s - 1] == b'*');
            classify_ident(w, ptr_use, &self_name, &mut funcs, &mut ptr_idents, &mut scalar_idents, &mut smells);
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
    // Names printc ALREADY declares as locals inside the body must not also be synthesized as
    // globals: the file then declares the same identifier twice and the local shadows a global that
    // has no business existing. Measured on 52 functions — e.g. FUN_0006aec4 reads a stack
    // parameter `puStack00000004` and got both `int *puStack00000004;` at file scope and
    // `uint4 * puStack00000004;` as a local.
    let body_start = c.find("\n{").map(|i| i + 1).unwrap_or(0);
    let declared_locals: HashSet<&str> = c[body_start..]
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let name = l.strip_suffix(';')?.rsplit(|ch: char| ch == ' ' || ch == '*').next()?;
            // A declaration line is `<type> [*]<name>;` — reject statements, which carry an
            // operator or a call.
            if l.contains('=') || l.contains('(') || !l.contains(' ') {
                return None;
            }
            // …and reject a STATEMENT that happens to have neither. `return param_1 - iRam00090630;`
            // has a space, no `=` and no `(`, so it parsed as a declaration OF `iRam00090630` — and
            // the emitter then skipped declaring that global, leaving the translation unit
            // referencing an undeclared symbol and failing to build. FUN_00033d84 lost its
            // byte-clean status to exactly this, and it is the largest remaining `E1011` block.
            let first = l.split_whitespace().next()?;
            if matches!(
                first,
                "return" | "break" | "continue" | "goto" | "case" | "default" | "do" | "else"
            ) {
                return None;
            }
            is_ident_start(name).then_some(name)
        })
        .collect();

    let mut names: BTreeSet<String> = BTreeSet::new();
    for (n, pfx) in &scalar_idents {
        if ptr_idents.contains(n) || declared_locals.contains(n.as_str()) {
            continue;
        }
        // Prefer the width the decompiler recovered for this address over the prefix's default.
        let ty = ram_addr_of(n)
            .and_then(|a| gsizes.get(&a).copied())
            .and_then(|sz| sized_ctype(*pfx, sz))
            .unwrap_or_else(|| ctype_for(*pfx).to_string());
        names.insert(format!("{ty} {n};"));
    }
    // SAFETY NET: every `<prefix>Ram<hex>` global the body references MUST be declared, or the
    // translation unit does not compile at all. The identifier scan above misses some — FUN_00074744
    // references `iRam000a8288` and `iRam000a82cc` in one expression and only the first was
    // declared, and the same shape cost FUN_00033d84 its byte-clean status. The cause of the miss is
    // not yet understood; this pass makes the invariant hold regardless, and a declaration can only
    // let a TU build, never change what it compiles to.
    {
        let mut extra: Vec<String> = Vec::new();
        for cap in c.split(|ch: char| !is_ident(ch as u8)) {
            if cap.len() < 9 || !cap.contains("Ram") {
                continue;
            }
            let pos = cap.find("Ram").unwrap();
            if !(1..=2).contains(&pos) {
                continue;
            }
            let tail = &cap[pos + 3..];
            if tail.len() < 6 || !tail.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            if declared_locals.contains(cap)
                || ptr_idents.contains(cap)
                || names.iter().any(|d| d.split_whitespace().any(|t| t.trim_end_matches(';') == cap))
            {
                continue;
            }
            let pfx = cap.as_bytes()[0] as char;
            let ty = ram_addr_of(cap)
                .and_then(|a| gsizes.get(&a).copied())
                .and_then(|sz| sized_ctype(pfx, sz))
                .unwrap_or_else(|| ctype_for(pfx).to_string());
            extra.push(format!("{ty} {cap};"));
        }
        names.extend(extra);
    }
    for n in &ptr_idents {
        if declared_locals.contains(n.as_str()) {
            continue;
        }
        // mosura's name prefixes carry the recovered type: `p` is a pointer, and the SECOND letter
        // is what it points at — `pc` is pointer-to-CODE. Declaring one as `int *` makes
        // `(*pcRamNNN)()` a call through a data pointer, so wcc386 loads it into a register and
        // calls the register (8 bytes) where the original is one memory-indirect `call` (7):
        // `ff 15 <abs32>`. That is exactly the defect the globfnptr ground-truth gate pins, fixed in
        // the decompiler but still mis-declared here — the emitter threw the recovered type away.
        // The prelude's `typedef int code();` makes `code *` the function-pointer type.
        // `pc` is AMBIGUOUS in mosura's naming — it is pointer-to-char as often as
        // pointer-to-code (printc emits `char * pcVar1;` for the former). So do not key on the
        // prefix: key on whether this global is actually CALLED through, which is unambiguous and
        // is the only case where the distinction changes the emitted instruction.
        let called = c.contains(&format!("(*{n})("));
        let ty = if called { "code *" } else { "int *" };
        names.insert(format!("{ty}{n};"));
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
    // The identifier is used as a pointer here — indexed (`ident[`) or dereferenced (`*ident`).
    ptr_use: bool,
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
            if ptr_use {
                ptr_idents.insert(w.to_string());
            } else {
                scalar_idents.insert((w.to_string(), 'u'));
            }
            return;
        }
    }
    // `<prefix>Stack<hex>` — an UNMAPPED stack address, Ghidra `ScopeInternal::buildVariableName`'s
    // addrtied form (database.cc:2483): stem, capitalized space name, `2*addrSize` hex digits, NO
    // separator. It is the same family as the synthetic reads above — a faithful rendering that
    // Ghidra also leaves undeclared and that therefore does not compile on its own — so it gets the
    // same synthesized declaration. Distinguished from a MAPPED local (`xStack_18`, always declared
    // by the decompiler) precisely by the missing `_`.
    if let Some(pos) = w.find("Stack") {
        if (1..=2).contains(&pos) {
            let tail = &w[pos + 5..];
            if tail.len() >= 8 && tail.bytes().all(|c| c.is_ascii_hexdigit()) {
                smells.insert("unmapped-stack".into());
                let pfx = w.as_bytes()[0] as char;
                if ptr_use || pfx == 'p' {
                    ptr_idents.insert(w.to_string());
                } else {
                    scalar_idents.insert((w.to_string(), pfx));
                }
                return;
            }
        }
    }
    // <prefix>Ram<hex> globals.
    if let Some(pos) = w.find("Ram") {
        if (1..=2).contains(&pos) {
            let tail = &w[pos + 3..];
            if tail.len() >= 8 && tail.bytes().all(|c| c.is_ascii_hexdigit()) {
                let pfx = w.as_bytes()[0] as char;
                if ptr_use || pfx == 'p' {
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
        if ptr_use {
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

/// The RAM address a `<prefix>Ram<hex>` identifier names, if it is one.
fn ram_addr_of(name: &str) -> Option<u64> {
    let pos = name.find("Ram")?;
    if !(1..=2).contains(&pos) {
        return None;
    }
    let tail = &name[pos + 3..];
    if tail.len() < 8 || !tail.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(tail, 16).ok()
}

/// A C type of exactly `size` bytes, keeping the kind the name prefix implies. `None` when the
/// prefix's own type is already right (4 bytes) or the width has no C scalar, in which case the
/// caller keeps [`ctype_for`] — the emitter must never invent a type it cannot spell.
fn sized_ctype(prefix: char, size: u32) -> Option<String> {
    let signed = matches!(prefix, 'i' | 's' | 'c');
    Some(match (size, signed) {
        (1, true) => "char".into(),
        (1, false) => "unsigned char".into(),
        (2, true) => "short".into(),
        (2, false) => "unsigned short".into(),
        (4, _) => return None, // the prefix already yields a 4-byte type
        (8, _) if matches!(prefix, 'f' | 'd') => "double".into(),
        _ => return None,
    })
}

/// Does this token look like a C identifier (so a candidate declared name)?
fn is_ident_start(s: &str) -> bool {
    let mut it = s.bytes();
    it.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_') && s.bytes().all(is_ident)
}
