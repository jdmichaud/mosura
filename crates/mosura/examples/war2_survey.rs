//! WAR2 per-function recompile survey — EMIT stage (uncommitted measurement harness).
//!
//! Read-only w.r.t. the decompiler: loads WAR2 via the `--le` path, decompiles every recovered
//! function, and emits (a) a standalone C translation unit per function (prelude + synthesized
//! declarations + the decompiled body) for wcc386, and (b) a manifest with each function's
//! original machine-code bytes (from the fixed-up LE image, over the decompiler's covered
//! instruction extent) so a later compile+diff stage can classify recompilation fidelity.
//!
//! Usage: cargo run -q --release --example war2_survey -- <war2.exe> <out_dir>

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::sync::Mutex;

use mosura::analysis::{self, decompiler::decompile_function};
use mosura::decompile::funcdata::Funcdata;
use mosura::decompile::op::flags;
use mosura::decompile::opcode::OpCode;
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::{print_c, print_c_with};
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
/* INT3 inlined as its literal byte (the `swi=int3` emission arm): the retail assert-trap
   idiom and app_fatal's body. parm []/modify exact [] = touches nothing. */
void __int3(void);
#pragma aux __int3 = 0xcc parm [] modify exact [];
/* memcpy/memset/memcmp/strlen intrinsics (the string-ops=intrinsic emission arm): a witnessed REP MOVS/STOS/CMPS/SCAS
   renders as the library call the source wrote, and Watcom's -oi (via -ox in -onatx) re-inlines it
   back to REP MOVS -- recovering the bytes. Plain prototypes; -oi makes them intrinsic. */
void *memcpy(void *, const void *, unsigned);
void *memset(void *, int, unsigned);
int memcmp(const void *, const void *, unsigned);
unsigned strlen(const char *);
#pragma intrinsic(memcpy,memset,memcmp,strlen);
/* struct-copy=assign: a run of k plain MOVSD is Watcom's struct assignment below the unroll
   threshold; these are the k-dword aggregate types the arm assigns through. */
struct p8 { unsigned int a; unsigned int b; };
struct p12 { unsigned int a; unsigned int b; unsigned int c; };
struct p16 { unsigned int a; unsigned int b; unsigned int c; unsigned int d; };
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
/* Ghidra's internal TypeSpacebase — the stack-pointer's pointee. Never a value type in
   real output, but a pointer to it can reach a declaration (stack-switching code stores
   ESP-derived pointers; FUN_00060270). An incomplete struct keeps the pointer declarable
   and every cast legal while staying loud and greppable, like the xunknown widths above. */
typedef struct mosura_spacebase spacebase;
/* Variadic recovery (decompile/varargs.rs): `va_start(ap, last)` assigns the address of the
   first anonymous argument — under Watcom's stack convention the slot after `last`, which is
   exactly the `lea` the original executes. A raw-pointer `va_list`, so the value can be stored
   and passed like the originals do (the `v*printf` wrappers keep it in a struct field). */
#define va_start(ap, last) ((ap) = (void *)((char *)&(last) + ((sizeof(last) + 3) & ~3)))
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

/// The manifest `kind`, with the not-C classification: a default-named function whose
/// ORIGINAL instructions carry hand-assembly signatures (`buildconfig::looks_hand_written`
/// — calibrated: zero EXACT/SAME_SHAPE functions trip it) is `asm`, and the measurement
/// excludes it exactly as it excludes `library` — un-recompilable from C by construction,
/// so keeping it in the denominator misstates the C-recompilation target.
fn kind_of_insns(name: &str, insns: &[mosura::recompile::insn::NormInsn]) -> &'static str {
    let k = kind_of(name);
    if k == "user" && mosura::recompile::buildconfig::looks_hand_written(insns) {
        return "asm";
    }
    k
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
/// The callees this decompile UNDER-CALLS: a live CALL to a callee whose whole-program
/// recovered prototype is REGISTER-ONLY with N parameters, passing fewer than N inputs.
/// This is the cross-TU contradiction of the consistency doctrine (JD 2026-08-24): the
/// callee's own TU declares those parameters, so a caller that omits them links into a
/// program that reads garbage — invisible to per-function byte comparison by construction.
fn under_called_register_callees(
    f: &mosura::decompile::funcdata::Funcdata,
    pp: &mosura::analysis::program::Program,
) -> Vec<(u64, usize)> {
    let Some(reg) = f.spaces.by_name("register") else { return Vec::new() };
    let mut out: Vec<(u64, usize)> = Vec::new();
    for op in f.op_ids() {
        let o = f.op(op);
        if o.code() != OpCode::Call || o.flags & (flags::DEAD | flags::MARKER) != 0 {
            continue;
        }
        let Some(t) = o.input(0) else { continue };
        let callee = f.vn(t).loc.offset;
        if callee == 0 {
            continue;
        }
        let Some(proto) = pp.recovered_protos.get(&callee) else { continue };
        // The register-only domain, mirroring `locked_register_inputs`: a prototype naming
        // stack storage keeps the trial path and is not this contradiction class.
        if proto.params.is_empty() || !proto.params.iter().all(|s| s.addr.space == reg) {
            continue;
        }
        // UNDER-called only (the callee reads a register the caller never set). The over-call
        // direction (A6) is reverted: its clamp dropped constant arguments the original genuinely
        // pushes when the callee's use-based prototype under-states its arity (0x5fb24: the `0`
        // at a callee that ignores its 3rd param), a wrong-code loss the byte-witness the clamp
        // cannot see would prevent — refiled for the survey side where the bytes exist.
        if o.num_inputs() - 1 < proto.params.len() && !out.iter().any(|&(c, _)| c == callee) {
            out.push((callee, proto.params.len()));
        }
    }
    out
}

/// Does the candidate decompile RESOLVE every named contradiction — each call to the callee
/// carries at least the declared register arity, every declared-parameter input holding a
/// REAL bound value (a constant, a written varnode, or a function input)? A manufactured
/// free varnode — the historical `XOR reg,reg`-from-nowhere class — fails the test: that is
/// a wrong program of a different kind, held as a bug rather than emitted.
fn resolves_contradictions(
    f2: &mosura::decompile::funcdata::Funcdata,
    contradicted: &[(u64, usize)],
) -> bool {
    for op in f2.op_ids() {
        let o = f2.op(op);
        if o.code() != OpCode::Call || o.flags & (flags::DEAD | flags::MARKER) != 0 {
            continue;
        }
        let Some(t) = o.input(0) else { continue };
        let callee = f2.vn(t).loc.offset;
        let Some(&(_, arity)) = contradicted.iter().find(|&&(c, _)| c == callee) else { continue };
        if o.num_inputs() - 1 < arity {
            return false; // the candidate still under-calls it
        }
        for i in 1..=arity {
            let Some(v) = o.input(i) else { return false };
            let vn = f2.vn(v);
            // An INDIRECT-creation constant is a killedbycall zero manufactured by the
            // decompiler, not a value the caller places — 12c58's `(0, 0)` by name.
            if vn.is_constant() && vn.is_indirect_creation() {
                return false;
            }
            if !(vn.is_constant() || vn.is_written() || vn.is_input()) {
                return false; // unbound (manufactured) value — the XOR-zero bug class
            }
        }
    }
    true
}

/// Every call's SHAPE must be stable between the landed decompile and the surgical candidate —
/// argument count, output presence, output width — except argument GROWTH at the contradicted
/// callees (the adoption's whole purpose). Matched by instruction address, indirect calls
/// included. This subsumes the monotone rule ("propagation removed an argument" was measured as
/// a near-perfect regression predictor; zc52's 0x11b9c, and zc53's 0x2d360 where a CALLIND lost
/// its buffer argument) and catches the collateral type ripple (zc53's 0x2247c: an unrelated
/// call's return width drifted 1 → 4 and re-rendered with a cast).
/// FIRST-TOUCH evidence for the watcall argument registers in a callee's ENTRY BLOCK, read from
/// the callee's OWN bytes — the arbiter our `recovered_protos` is only testimony about (Order Y,
/// and X(3)'s rule that `PUSH`/`POP` are the save prologue, not reads):
///
///   `Some(true)`  read (or read-modified) before any write — the callee takes it as an input;
///   `Some(false)` written before any read — it CANNOT be an input (`0x4fe64`'s
///                 `mov edx,[0x99594]`, `0x678ec`'s `xor ebx,ebx`, `0x67b44`'s `mov eax,0x64`);
///   `None`        untouched before the first call or branch, so the entry block does not decide
///                 — `0x50480`'s EAX passes through to its nested call and is a real input.
///
/// The gate built on this REFUSES only `Some(false)`: undecided is not evidence against.
fn callee_input_evidence(
    insns: &[mosura::recompile::insn::NormInsn],
    arg_regs: &[u64],
) -> Vec<Option<bool>> {
    use mosura::recompile::insn::SemArg;
    let mut v = vec![None; arg_regs.len()];
    for x in insns {
        if x.is_branch || x.is_call {
            break;
        }
        if x.mnemonic == "PUSH" || x.mnemonic == "POP" {
            continue;
        }
        // `XOR r,r` / `SUB r,r` is the zero idiom: it writes r, it does not read it.
        let zero_idiom = matches!(x.mnemonic.as_str(), "XOR" | "SUB")
            && x.sem.iter().any(|o| {
                matches!((o.out.as_ref(), o.ins.first()), (Some(SemArg::Reg(a, _)), Some(SemArg::Reg(b, _))) if a == b)
            });
        for (i, &r) in arg_regs.iter().enumerate() {
            if v[i].is_some() {
                continue;
            }
            let reads = !zero_idiom
                && x.sem.iter().any(|o| {
                    o.ins.iter().any(|a| matches!(a, SemArg::Reg(o2, _) if o2 & !3 == r))
                });
            let writes = x
                .sem
                .iter()
                .any(|o| matches!(o.out, Some(SemArg::Reg(o2, _)) if o2 & !3 == r));
            if reads {
                v[i] = Some(true);
            } else if writes {
                v[i] = Some(false);
            }
        }
    }
    v
}

fn call_shapes_stable(
    fl: &mosura::decompile::funcdata::Funcdata,
    fx: &mosura::decompile::funcdata::Funcdata,
    contradicted: &[(u64, usize)],
    // CONTRACT-DIRECTED DRIFT (`MOSURA_CONS_REACH=1`, Order Y): the callee's own recovered
    // prototype — the arity its BODY shows it reads — may license a drift the flat rule refuses.
    // Measured on the 14 arity-defect TUs: every drifting site moves TOWARD the callee's
    // register-only recovered arity and none moves away (0x59404 3->1 with proto 1, whose entry
    // `PUSH EBX/ECX/EDX` and single `MOV ECX,EAX` read make 1 the byte truth). `None` = the
    // landed flat rule.
    protos: Option<&std::collections::HashMap<u64, mosura::decompile::fspec::FuncProto>>,
    // The callee's OWN entry-block testimony per argument register ([`callee_input_evidence`]):
    // a drift may never drop a register the callee is byte-proven to READ, and may never land on
    // an arity whose registers the callee is byte-proven to WRITE first.
    evidence: &HashMap<u64, Vec<Option<bool>>>,
) -> bool {
    // (args, output width, direct-callee va or 0, the output is consumed by something)
    type Shape = (usize, Option<u32>, u64, bool);
    let shapes = |f: &mosura::decompile::funcdata::Funcdata| -> HashMap<u64, Shape> {
        let mut m = HashMap::new();
        for op in f.op_ids() {
            let o = f.op(op);
            if !matches!(o.code(), OpCode::Call | OpCode::Callind)
                || o.flags & (flags::DEAD | flags::MARKER) != 0
            {
                continue;
            }
            let callee = if o.code() == OpCode::Call {
                o.input(0).map_or(0, |t| f.vn(t).loc.offset)
            } else {
                0
            };
            let outw = o.output.map(|v| f.vn(v).size);
            let out_used = o.output.is_some_and(|v| !f.vn(v).descend.is_empty());
            m.insert(o.seqnum.pc.offset, (o.num_inputs() - 1, outw, callee, out_used));
        }
        m
    };
    let (l, x) = (shapes(fl), shapes(fx));
    let reg = fx.spaces.by_name("register");
    l.iter().all(|(pc, &(n, outw, callee, _))| {
        x.get(pc).is_some_and(|&(m, outw2, _, out_used2)| {
            let grows_ok = contradicted.iter().any(|&(c, _)| c == callee);
            // The candidate lands EXACTLY on a register-only recovered contract the landed world
            // missed: the drift is that callee's own testimony, not churn. Output width still has
            // to hold — a materialized return is a different class and is not licensed here.
            let ev = evidence.get(&callee);
            let byte_ok = ev.is_some_and(|e| {
                // Nothing the new arity passes may be byte-refuted, and every register it DROPS
                // must be byte-REFUTED — undecided is not permission. `None` means the entry block
                // does not decide, and `0x50480`'s EAX is the standing proof that a `None` register
                // can be a real input (untouched before the nested call it passes through to).
                // Undecided is therefore treated the SAME on both sides: growth keeps it because it
                // might be read, so a drop must keep it for the identical reason. Dropping one is
                // this thread's own wrong code with the sign reversed — and a score round cannot
                // catch it, since the wrong-code gate keys on memory writes, not on an argument
                // that stops being passed.
                (0..m).all(|i| e.get(i).copied().flatten() != Some(false))
                    && (m..n).all(|i| e.get(i).copied().flatten() == Some(false))
            });
            let contract_ok = callee != 0
                && m != n
                && byte_ok
                && protos.and_then(|p| p.get(&callee)).is_some_and(|p| {
                    !p.params.is_empty()
                        && p.params.iter().all(|s| Some(s.addr.space) == reg)
                        && p.params.len() == m
                        && p.params.len() != n
                });
            // A return value the candidate MATERIALIZES but never consumes prints the same
            // call statement as no return at all — the callee's prototype says it returns,
            // nothing in this function reads it. Only the unused case is licensed; a consumed
            // materialized return stays the different class it always was (JD's decision 2,
            // 2026-09-04: adopt the callee's arity site by site — FUN_00033668's `-2`, whose
            // five contracted drifts all land on their callees' arities and were held by
            // exactly this width change on three of them).
            let outw_ok = outw2 == outw || (outw.is_none() && outw2.is_some() && !out_used2);
            outw_ok && (contract_ok || if grows_ok { m >= n } else { m == n })
        })
    })
}

/// The per-site half of the consistency adoption (JD decision 2, 2026-09-04): the landed
/// calls whose candidate counterpart passes MORE arguments, every extra one a CONSTANT, where
/// the drift is licensed exactly as [`call_shapes_stable`] licenses one — the callee's
/// register-only recovered arity is the candidate's count and the callee's entry block refutes
/// none of the passed registers — but WITHOUT the output-width condition (the call's return is
/// not what is adopted). Returns `(landed call op, [(input slot, value, size)])` per site, the
/// slots in ascending order so insertion keeps the candidate's argument order.
///
/// The SITE's own bytes decide (JD's design): each extra constant must be MATERIALIZED into
/// its parameter register right before the call — the first write of that register walking
/// back from the call is `MOV r,imm` of that value (or `XOR r,r` for 0), with no call and no
/// branch crossed. A constant that reaches the call from an earlier write across other calls
/// (the Y-series' `func_0x00050108(0x3c, 0x1cc, 0x21330)`, FUN_00040490) is real to the
/// callee but not to the bytes: this compiler re-materializes an explicit argument, and the
/// function lost EXACT to it in round e41.
fn constant_arg_sites(
    fl: &mosura::decompile::funcdata::Funcdata,
    fx: &mosura::decompile::funcdata::Funcdata,
    contradicted: &[(u64, usize)],
    protos: Option<&std::collections::HashMap<u64, mosura::decompile::fspec::FuncProto>>,
    evidence: &HashMap<u64, Vec<Option<bool>>>,
    insns: &[mosura::recompile::insn::NormInsn],
) -> Vec<(mosura::decompile::op::OpId, Vec<(usize, u64, u32)>)> {
    use mosura::recompile::insn::SemArg;
    // the first write of register `r` (container) walking back from instruction `ci`, if it
    // is a materialization of `value` and nothing crossed is a call or a branch
    let materialized_before = |ci: usize, r: u64, value: u64, size: u32| -> bool {
        let mask = if size >= 8 { u64::MAX } else { (1u64 << (8 * size)) - 1 };
        for x in insns[..ci].iter().rev() {
            if x.is_call || x.is_branch {
                return false;
            }
            let writes_r = x.sem.iter().any(|op| matches!(op.out, Some(SemArg::Reg(o, _)) if o & !3 == r & !3));
            if !writes_r {
                continue;
            }
            let mov_imm = x.mnemonic == "MOV"
                && x.sem.iter().any(|op| {
                    matches!(op.out, Some(SemArg::Reg(o, _)) if o & !3 == r & !3)
                        && matches!(op.ins.as_slice(), [SemArg::Const(c, _)] if c & mask == value & mask)
                });
            let xor_zero = x.mnemonic == "XOR" && value & mask == 0 && x.regs.iter().all(|&(o, _)| o & !3 == r & !3);
            return mov_imm || xor_zero;
        }
        false
    };
    let reg = fx.spaces.by_name("register");
    let calls = |f: &mosura::decompile::funcdata::Funcdata| -> HashMap<u64, mosura::decompile::op::OpId> {
        f.op_ids()
            .filter(|&op| f.op(op).code() == OpCode::Call && f.op(op).flags & (flags::DEAD | flags::MARKER) == 0)
            .map(|op| (f.op(op).seqnum.pc.offset, op))
            .collect()
    };
    let (l, x) = (calls(fl), calls(fx));
    let mut out = Vec::new();
    let mut pcs: Vec<&u64> = l.keys().collect();
    pcs.sort();
    for pc in pcs {
        let lop = l[pc];
        let Some(&xop) = x.get(pc) else { continue };
        let (lo, xo) = (fl.op(lop), fx.op(xop));
        let Some(t) = lo.input(0) else { continue };
        let callee = fl.vn(t).loc.offset;
        if callee == 0 || xo.input(0).map(|t2| fx.vn(t2).loc.offset) != Some(callee) {
            continue;
        }
        let (n, m) = (lo.num_inputs() - 1, xo.num_inputs() - 1);
        if m <= n || !contradicted.iter().any(|&(c, _)| c == callee) {
            continue;
        }
        let byte_ok = evidence.get(&callee).is_some_and(|e| (0..m).all(|i| e.get(i).copied().flatten() != Some(false)));
        let contract_ok = byte_ok
            && protos.and_then(|p| p.get(&callee)).is_some_and(|p| {
                !p.params.is_empty() && p.params.iter().all(|s| Some(s.addr.space) == reg) && p.params.len() == m
            });
        if !contract_ok {
            continue;
        }
        // the landed prefix must be the candidate's prefix (same values), and every extra a constant
        let same_prefix = (1..=n).all(|i| match (lo.input(i), xo.input(i)) {
            (Some(a), Some(b)) => {
                let (va, vb) = (fl.vn(a), fx.vn(b));
                va.loc == vb.loc && va.size == vb.size && (!va.is_constant() || va.constant_value() == vb.constant_value())
            }
            _ => false,
        });
        if !same_prefix {
            continue;
        }
        let Some(ci) = insns.iter().position(|x| x.addr == *pc) else { continue };
        let params = protos.and_then(|p| p.get(&callee)).map(|p| &p.params);
        let mut consts = Vec::new();
        for i in (n + 1)..=m {
            let Some(v) = xo.input(i) else { break };
            let vn = fx.vn(v);
            if !vn.is_constant() {
                break;
            }
            // the parameter register of slot `i` (the candidate's order is the prototype's)
            let Some(r) = params.and_then(|ps| ps.get(i - 1)).map(|s| s.addr.offset) else { break };
            if !materialized_before(ci, r, vn.constant_value(), vn.size) {
                break;
            }
            consts.push((i, vn.constant_value(), vn.size));
        }
        if consts.len() == m - n {
            out.push((lop, consts));
        }
    }
    out
}

/// An argument CARRIED across a call (2026-09-04): a register the landed function passes to call
/// `from` BEYOND that callee's own recovered arity, which the callee's recovered clobber set
/// preserves, and which the NEXT call `to` consumes — `to`'s own arity names the register at the
/// same positional slot and the landed site does not pass that slot. The decompiler attributes a
/// register set up before a call to that call; the bytes attribute it to the consumer: the value
/// is placed before `from` (a constant by `MOV r,k` / `XOR r,r` in the pre-call window), the
/// register is never written between the two calls, and `from` preserves it. `f1(x, 8, 0x14);
/// f2();` is `f2(f1(x), 8, 0x14);` — FUN_00030ca0, FUN_0004c364; `f1(x, g); f2(k);` is
/// `f1(x); f2(k, g);` — FUN_00034370. Probed EXACT on all three before the rule was written.
///
/// `fill`: the consumer's slot 1 when the landed consumer passes nothing — `Return` when `from`
/// clobbers EAX (its value at `to` is whatever `from` returned: the nested form), `Same(v)` when
/// `from` preserves EAX (the consumer receives `from`'s own first argument).
enum CarryFill {
    None,
    Return,
}
struct CarrySite {
    from: mosura::decompile::op::OpId,
    to: mosura::decompile::op::OpId,
    /// (positional slot, the landed varnode at `from`), ascending
    slots: Vec<(usize, mosura::decompile::varnode::VarnodeId)>,
    fill: CarryFill,
}

fn carry_arg_sites(
    fl: &mosura::decompile::funcdata::Funcdata,
    protos: &std::collections::HashMap<u64, mosura::decompile::fspec::FuncProto>,
    // each direct callee's own entry-block testimony per argument register ([`callee_input_evidence`])
    evidence: &HashMap<u64, Vec<Option<bool>>>,
    insns: &[mosura::recompile::insn::NormInsn],
    arg_reg_offs: &[u64],
) -> Vec<CarrySite> {
    use mosura::recompile::insn::{NormInsn, SemArg};
    let Some(reg) = fl.spaces.by_name("register") else { return Vec::new() };
    // register-only AND positional: slot k lives in the convention's k-th register, so a slot
    // beyond the recovered arity has one register too
    let positional = |p: &mosura::decompile::fspec::FuncProto| -> bool {
        !p.params.is_empty()
            && p.params.len() <= arg_reg_offs.len()
            && p.params.iter().enumerate().all(|(k, s)| s.addr.space == reg && s.addr.offset == arg_reg_offs[k])
    };
    let writes = |x: &NormInsn, r: u64| -> bool {
        x.sem.iter().any(|op| matches!(op.out, Some(SemArg::Reg(o, _)) if o & !3 == r & !3))
    };
    let mut calls: Vec<(u64, mosura::decompile::op::OpId, u64)> = fl
        .op_ids()
        .filter(|&op| fl.op(op).code() == OpCode::Call && fl.op(op).flags & (flags::DEAD | flags::MARKER) == 0)
        .filter_map(|op| fl.op(op).input(0).map(|t| (fl.op(op).seqnum.pc.offset, op, fl.vn(t).loc.offset)))
        .filter(|&(_, _, c)| c != 0)
        .collect();
    calls.sort();
    let mut out = Vec::new();
    for w in calls.windows(2) {
        let ((pc1, c1, a), (pc2, c2, b)) = (w[0], w[1]);
        if fl.op(c1).parent.is_none() || fl.op(c1).parent != fl.op(c2).parent {
            continue;
        }
        let (Some(pa), Some(pb)) = (protos.get(&a), protos.get(&b)) else { continue };
        // `from`'s own parameters positional, so its extra slots have positional registers too;
        // `to` register-only — the CALLER renders its call positionally (a K&R extern without a
        // `parm` clause), whatever register names its own prototype recovered
        if !positional(pa) || pb.params.is_empty() || !pb.params.iter().all(|s| s.addr.space == reg) {
            continue;
        }
        // the consumer's arity, witnessed: its use-based proto is routinely UNDER-recovered
        // (0x16bdc's body reads eax/edx/ebx, its proto shows 2), so take the widest count the
        // LANDED function itself passes to this callee anywhere as the floor. A callee the
        // program only ever calls with N args does not silently take an (N+1)th here — that is
        // 0x40490's `func_0x0004fe64(0x1cc, 4)`, whose `ebx` set before the PRIOR call is that
        // call's own third argument, not a carry.
        let nb_wit = fl
            .op_ids()
            .filter(|&op| fl.op(op).code() == OpCode::Call && fl.op(op).flags & (flags::DEAD | flags::MARKER) == 0)
            .filter(|&op| fl.op(op).input(0).map(|t| fl.vn(t).loc.offset) == Some(b))
            .map(|op| fl.op(op).num_inputs() - 1)
            .max()
            .unwrap_or(0)
            .max(pb.params.len());
        let (n1, n2) = (fl.op(c1).num_inputs() - 1, fl.op(c2).num_inputs() - 1);
        let na = pa.params.len();
        if n1 <= na {
            continue;
        }
        let Some(modify) = fl.call_specs.get(&c1).and_then(|cs| cs.cdecl_modify.as_ref()) else { continue };
        let preserved = |r: u64| !modify.iter().any(|&c| c & !3 == r & !3);
        let (Some(ca), Some(cb)) = (
            insns.iter().position(|x| x.is_call && x.addr == pc1),
            insns.iter().position(|x| x.is_call && x.addr == pc2),
        ) else {
            continue;
        };
        if ca >= cb {
            continue;
        }
        let between = &insns[ca + 1..cb];
        // Between the two calls, only ARGUMENT-REGISTER SETUP is allowed: every instruction
        // writes an argument register and touches no memory. A store between them (0x12360's
        // `mov [0x81288],eax`, consuming the prior return) means the second call is NOT reusing
        // the first's register environment — the args are separately set up and this is not a
        // carry. Nothing between (0x30ca0) or a plain `mov argreg,K` (0x34370) is the carry shape.
        let arg_set: std::collections::HashSet<u64> = arg_reg_offs.iter().map(|&r| r & !3).collect();
        let clean_between = between.iter().all(|x| {
            // writes ONLY argument registers (a `mov argreg,K`, `lea argreg,[..]`, `mov argreg,[g]`
            // consumer-arg setup) and writes NO memory. A store — 0x12360's `mov [0x81288],eax`
            // consuming the prior return — means the second call is not reusing the first's
            // register environment, so it is not a carry. Address computation and loads into an
            // arg register are the consumer setting up its own arguments and are fine.
            let is_store = x.mnemonic == "MOV" && x.sem.iter().any(|op| matches!(op.out, Some(SemArg::Mem(..)) | Some(SemArg::Space(..))));
            !x.is_call
                && !x.is_branch
                && !is_store
                && x.sem.iter().all(|op| match op.out {
                    Some(SemArg::Reg(o, _)) => arg_set.contains(&(o & !3)),
                    None => true,
                    _ => false,
                })
                && x.sem.iter().any(|op| matches!(op.out, Some(SemArg::Reg(o, _)) if arg_set.contains(&(o & !3))))
        });
        if !clean_between {
            continue;
        }
        // a SUFFIX of `from`'s extra slots (removing a middle slot would shift the ones above it
        // into other registers), each consumed at the same positional slot of `to`: the slot
        // exists in `to`'s arity, the landed consumer does not pass it, `to`'s entry block does
        // not refute the register and `from`'s does not claim it
        let (ea, eb) = (evidence.get(&a), evidence.get(&b));
        let claimed = |e: Option<&Vec<Option<bool>>>, i: usize| e.and_then(|v| v.get(i - 1).copied().flatten()) == Some(true);
        let refuted = |e: Option<&Vec<Option<bool>>>, i: usize| e.and_then(|v| v.get(i - 1).copied().flatten()) == Some(false);
        let mut slots = Vec::new();
        for i in ((na + 1)..=n1).rev() {
            // bounded by the consumer's WITNESSED arity (nb_wit), not its under-recovered
            // proto: a slot beyond every landed call to this callee is the FROM call's own
            // argument, not a carry
            if i > nb_wit || i <= n2 || claimed(ea, i) || refuted(eb, i) {
                break;
            }
            // the caller renders `to` POSITIONALLY: the emitted extern carries a `modify` pragma
            // only (the callee's own `parm [..]` clause lives in its own TU, not the caller's), so
            // argument i lands in the i-th positional register. 0x1755c's `0x17530` is in EBX =
            // slot 3's positional register, matching the original `mov ebx,0x17530`.
            let r = arg_reg_offs[i - 1];
            if !preserved(r) || between.iter().any(|x| writes(x, r)) {
                break;
            }
            let Some(vn) = fl.op(c1).input(i) else { break };
            let v = fl.vn(vn);
            if v.is_constant() {
                // the constant is placed right before `from`: the first write of r walking back
                // is `MOV r,k` (or `XOR r,r` for 0), no call and no branch crossed
                let k = v.constant_value();
                let mask = if v.size >= 8 { u64::MAX } else { (1u64 << (8 * v.size)) - 1 };
                let mut placed = false;
                for x in insns[..ca].iter().rev() {
                    if x.is_call || x.is_branch {
                        break;
                    }
                    if !writes(x, r) {
                        continue;
                    }
                    placed = (x.mnemonic == "MOV"
                        && x.sem.iter().any(|op| {
                            matches!(op.out, Some(SemArg::Reg(o, _)) if o & !3 == r & !3)
                                && matches!(op.ins.as_slice(), [SemArg::Const(c, _)] if c & mask == k & mask)
                        }))
                        || (x.mnemonic == "XOR" && k & mask == 0 && x.regs.iter().all(|&(o, _)| o & !3 == r & !3));
                    break;
                }
                if !placed {
                    break;
                }
            }
            slots.push((i, vn));
        }
        if slots.is_empty() {
            continue;
        }
        slots.reverse();
        // the consumer's slots stay contiguous from its landed count up to the highest carried
        // one; slot 1 may be filled when the landed consumer passes nothing
        let max = slots.iter().map(|s| s.0).max().unwrap();
        let mut fill = CarryFill::None;
        let eax = arg_reg_offs[0];
        let contiguous = (n2 + 1..=max).all(|s| {
            if slots.iter().any(|t| t.0 == s) {
                return true;
            }
            // slot 1 only, and only as the FROM call's RETURN (from clobbers eax, passes nothing
            // of its own there): the nested form `to(from(..), ..)`. The `Same` fill — reusing
            // from's own first argument — was removed: 0x2a6e0 rendered `f(param_1, param_1)`,
            // an argument the original never places.
            if s == 1 && n2 == 0 && !between.iter().any(|x| writes(x, eax)) && !preserved(eax) && fl.op(c1).output.is_none() {
                fill = CarryFill::Return;
                return true;
            }
            false
        });
        if !contiguous {
            continue;
        }
        out.push(CarrySite { from: c1, to: c2, slots, fill });
    }
    out
}

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
    // A FAR return (`RETF`, `Funcdata::far_return` from the original's bytes): `far` first.
    if f.far_return {
        parts.push("far".to_string());
    }
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

    // `--arms <θ>[;<θ>...]` — INVESTIGATION TOOL, NOT A PRODUCT OPTION (JD, 2026-08-18): it
    // emits the corpus under several EMISSION CHOICE VECTORS in one pass so multiple rendering
    // hypotheses can be validated against the compiler in one run — the generate half of the
    // byte-exact search that CALIBRATES the recovered evidence rules. The product path has no
    // arms: the flagless run emits `src/` (reference) and `recovered/` (the canonical,
    // field-shipped emission), and nothing selects among renderings. Each θ is a different
    // rendering of the SAME recovered program (see `decompile::emit::EmitChoices`).
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
        .unwrap_or_else(|| vec![mosura::recompile::recovery::canonical_arm()]);
    // `--arms-off cmp-sign,load-hoist`: the named arms' witnessed decisions are dropped after
    // recovery (review F2: one generic switch on the registry, `Recovered::switch_off`), so the
    // recovered tree prints those sites as the port does — per-arm isolation and re-measurement
    // without reverting code. The tree says so: the manifest's `arms:` line carries the names.
    let arms_off: Vec<String> = rest
        .iter()
        .position(|a| a == "--arms-off")
        .and_then(|i| rest.get(i + 1))
        .map(|v| v.split(',').map(str::trim).filter(|t| !t.is_empty()).map(|t| t.replace('-', "_")).collect())
        .unwrap_or_default();
    for a in &arms_off {
        if !mosura::decompile::emit::arms::registry::Recovered::ARMS.contains(&a.as_str()) {
            panic!("--arms-off: unknown arm `{a}` (switchable: {})", mosura::decompile::emit::arms::registry::Recovered::ARMS.join(", "));
        }
    }
    // Like the loop-overflow branch form below: this survey's output exists to be RECOMPILED,
    // and the target's shift instructions perform the `& 0x1f` count mask themselves, so every
    // arm elides the lifter's hardware mask (`EmitChoices` shift-mask=hardware; the axis doc in
    // decompile/emit.rs carries the measured probe — under the faithful rendering 64 functions
    // gained a materialized `AND CL,0x1f` the originals never had).
    // The RECOVERED tree is the PRODUCT: one emission whose per-site choices are read from
    // the original's own instructions by the target profile — what a compilerless field run
    // ships, and since the union's retirement (docs/war2-recompile-remeasure.md) also the
    // canonical measurement. Emitted ALWAYS, to `<out>/recovered` unless `--recovered <dir>`
    // overrides; `--no-recovered` skips it (probe/diagnostic runs).
    let recovered_dir: Option<std::path::PathBuf> = if rest.iter().any(|a| a == "--no-recovered")
    {
        None
    } else {
        Some(
            rest.iter()
                .position(|a| a == "--recovered")
                .and_then(|i| rest.get(i + 1))
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| out.join("recovered")),
        )
    };
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
    // The RECOVERED emit's choices: the canonical arm plus `sum-order=original` — the term order
    // was `RecoveredChoices::sum_order` (default on) until review R2b commit 4 made it an axis; it
    // applied only where recovery applied, so raw/ and the report pass keep the reference order.
    let rec_arm = {
        let mut c = arms[0].clone();
        c.set("sum-order", "original").expect("known axis");
        c
    };

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
    // Functions whose own returns disagree about the pop — a region-boundary symptom, counted so
    // it cannot be silent. Zero is the expected reading; a nonzero one is a finding to chase.
    let mut cleanup_undecided = 0usize;

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
    // DEFAULT-ON since the checker-gated landing at 746 (set MOSURA_PROTO_PASS=0 to get
    // the bare landed world): the whole-program prototype pass feeds per-TU upgrades that
    // the gate stack (scheduler fixed-point, allowed-set, collision, network, signature)
    // adopts only where the models prove the original's placements survive.
    if std::env::var("MOSURA_PROTO_PASS").as_deref() != Ok("0") {
        let t = std::time::Instant::now();
        // A `--only` probe restricts the pass to the probed functions' DIRECT STATIC CALLEES
        // (see `recover_prototypes_for`): scan each probed extent's original bytes for CALL
        // targets that are known function entries. The probed functions themselves are
        // included (harmless, and a probed function calling another probed one is covered
        // regardless of scan order).
        let probe_scope: Option<std::collections::HashSet<u64>> = if only.is_empty()
            || std::env::var("MOSURA_PROBE_FULL").as_deref() == Ok("1")
        {
            None
        } else {
            let entry_offs: std::collections::BTreeSet<u64> =
                prog.function_manager.functions().map(|f| f.entry.offset).collect();
            let mut scope: std::collections::HashSet<u64> = only.iter().copied().collect();
            for &va in &only {
                let end = entry_offs.range(va + 1..).next().copied().unwrap_or(va + 0x1000);
                let region = prog
                    .memory
                    .read_window(Address::new(prog.default_space, va), (end - va) as usize);
                let insns = mosura::recompile::insn::normalize(
                    SURVEY_LANG,
                    &region,
                    va,
                    &mosura::recompile::insn::NoReloc,
                )
                .unwrap_or_default();
                scope.extend(
                    insns
                        .iter()
                        .filter(|i| i.is_call)
                        .filter_map(|i| i.target)
                        .filter(|t| entry_offs.contains(t)),
                );
            }
            Some(scope)
        };
        // TAIL RETURN WRITE MARK (`Program::tail_return_writes`, decided from every
        // function's own bytes ahead of its decompile — a pre-pipeline mark, unlike the
        // post-decompile ones below): every return path writes EAX from a register right
        // before the epilogue (`buildconfig::tail_return_write_from_evidence`).
        {
            let entry_offs: std::collections::BTreeSet<u64> =
                prog.function_manager.functions().map(|f| f.entry.offset).collect();
            for &va in &entry_offs {
                // the function's OWN body (its recorded extent), never the gap to the next
                // entry: a neighbour's returns would veto the mark
                let next = entry_offs.range(va + 1..).next().copied().unwrap_or(va + 0x1000);
                let end = prog
                    .function_manager
                    .function_at(Address::new(prog.default_space, va))
                    .and_then(|f| f.body().max_address())
                    .map_or(next, |a| (a.offset + 1).min(next))
                    .max(va + 1);
                let region = prog
                    .memory
                    .read_window(Address::new(prog.default_space, va), (end - va) as usize);
                let insns = mosura::recompile::insn::normalize(
                    SURVEY_LANG,
                    &region,
                    va,
                    &mosura::recompile::insn::NoReloc,
                )
                .unwrap_or_default();
                if mosura::recompile::buildconfig::tail_return_write_from_evidence(&insns) {
                    prog.tail_return_writes.insert(va);
                }
                if only.contains(&va) {
                    let tail: Vec<&str> = insns.iter().rev().take(6).map(|x| x.text.as_str()).collect();
                    eprintln!("[survey] tail-return-write {va:#x}: {} — last insns (reversed): {tail:?}", prog.tail_return_writes.contains(&va));
                }
            }
            eprintln!("[survey] tail-return-write mark: {} functions", prog.tail_return_writes.len());
        }
        prog.recovered_protos = match &probe_scope {
            None => analysis::interface::recover_prototypes(&prog),
            Some(scope) => analysis::interface::recover_prototypes_for(&prog, scope),
        };
        eprintln!(
            "prototype pass: {} functions in {:.1}s{}",
            prog.recovered_protos.len(),
            t.elapsed().as_secs_f64(),
            if probe_scope.is_some() { " (probe scope: direct callees only)" } else { "" }
        );
    }
    // THE PER-SITE ZAP CHECKER's world order: the LANDED (prototype-less) program is
    // PRIMARY — every function decompiles from it first, and every definition-side global
    // map (the caller-side parm network, caller_calls, param-order evidence) is built from
    // those landed funcdatas, so the prototype pass cannot leak into fallen-back TUs
    // through OTHER functions' changed signatures (measured: 12360 fell back yet drifted
    // SAME_SHAPE because its PREPENDED caller-side pragmas came from pp-shaped callee
    // definitions). The pp decompile is a per-TU UPGRADE, adopted only when (a) the
    // scheduler model keeps every call-bearing window of the original a fixed point under
    // the candidate declarations, and (b) the function's OWN parameter signature is
    // unchanged (its definition-side row stays the landed one).
    let prog_pp: Option<analysis::program::Program> = if prog.recovered_protos.is_empty() {
        None
    } else {
        let base = prog.clone(); // carries the recovered prototypes
        prog.recovered_protos = std::collections::HashMap::new(); // the landed world
        Some(base)
    };
    let prog = prog;
    // The surgical-injection world (memory `consistency-over-score`): the LANDED program plus
    // the recovered prototypes, consulted only through `proto_scope` — set per forced function
    // to exactly its contradicted callees, cleared after each use.
    let mut prog_cons: Option<analysis::program::Program> = prog_pp.as_ref().map(|pp| {
        let mut c = prog.clone();
        c.recovered_protos = pp.recovered_protos.clone();
        c.proto_scope = Some(std::collections::HashSet::new()); // consult NOTHING until scoped
        c
    });
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
    // The arm set this tree was MEASURED with (the recovered emit's choices, every axis spelled
    // out), so a tree or a copied manifest is self-describing about its arm set (code review
    // 2026-08-27: measurement documents carry their arm set). `#` lines are skipped by every reader.
    let off_stamp = if arms_off.is_empty() { String::new() } else { format!("; off: {}", arms_off.join(",")) };
    writeln!(mf, "# arms: {rec_arm}{off_stamp}").unwrap();
    eprintln!("arms (recovered emit): {rec_arm}{off_stamp}");
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

    // PARAMETER-ORDER EVIDENCE, a pre-pass over the ORIGINAL bytes (docs/byte-exact-families.md,
    // the permutation family). The compiler materializes register arguments in REVERSE declared
    // order, so the setup sequence at each original call site is a readout of the parameter
    // order its source declared — a PER-SITE recovered choice our slot-order rendering gets
    // wrong wherever the source's order was not storage order. Probe-verified byte-exact on
    // FUN_0004d0f8 (`parm [edx] [ebx] [eax]`, arguments permuted to keep each value in its
    // original register). Per site, not per callee: the first cut's per-callee consensus broke
    // two EXACT callers whose own sites read slot order (sb94 first measure) — different TUs
    // may carry different declaration orders for one callee, because the pragma and the
    // permutation are emitted together per TU and every TU's bindings are internally correct.
    //
    // Callees whose own recovered storage is nondefault are EXCLUDED: their callers get the
    // contract pragma from the post-pass below, one pragma per callee per TU, and the two
    // mechanisms must not both claim it. The exclusion needs each such callee's decompile,
    // which its own emit will repeat — a few seconds of duplicate work over ~a hundred callees.
    let arg_reg_offs: Vec<u64> = ["eax", "edx", "ebx", "ecx"]
        .iter()
        .filter_map(|n| watreg.iter().find(|&&(_, sz, nm)| sz == 4 && nm == *n).map(|&(o, ..)| o))
        .collect();
    let mut order_excluded: std::collections::HashSet<u64> = Default::default();
    // The evidence is a pure function of the ORIGINAL binary and the code that reads it, so
    // it is cached beside the manifest keyed by the emit stamp. The exclusion set costs a
    // mini-decompile of every claimed callee (~170 on WAR2 — minutes), which a full emit
    // amortizes but which made every `--only` PROBE pay the whole pre-pass: JD measured a
    // single-function probe at five minutes. A probe at the same stamp now loads in
    // milliseconds; a stamp change re-derives.
    let order_cache = out.join(format!("param-orders.{stamp}.tsv"));
    let cached_orders: Option<(
        std::collections::HashMap<u64, Vec<u64>>,
        std::collections::HashSet<u64>,
        std::collections::HashSet<u64>,
    )> =
        std::fs::read_to_string(&order_cache).ok().map(|s| {
            let mut m = std::collections::HashMap::new();
            let mut ex = std::collections::HashSet::new();
            let mut net = std::collections::HashSet::new();
            for line in s.lines() {
                let mut it = line.split('\t');
                match (it.next(), it.next()) {
                    (Some("X"), Some(va)) => {
                        if let Ok(v) = u64::from_str_radix(va, 16) {
                            ex.insert(v);
                            net.insert(v);
                        }
                    }
                    // "C\t<callee>" — an order-claimed callee (the upgrade gate's network;
                    // rows added when the zap checker landed, re-derived on stamp change).
                    (Some("C"), Some(va)) => {
                        if let Ok(v) = u64::from_str_radix(va, 16) {
                            net.insert(v);
                        }
                    }
                    (Some(addr), Some(rest)) => {
                        if let Ok(a) = u64::from_str_radix(addr, 16) {
                            let p: Vec<u64> = rest
                                .split(',')
                                .filter_map(|x| u64::from_str_radix(x, 16).ok())
                                .collect();
                            m.insert(a, p);
                        }
                    }
                    _ => {}
                }
            }
            (m, ex, net)
        });
    let mut order_networked: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let site_orders: std::collections::HashMap<u64, Vec<u64>> = if let Some((m, ex, net)) = cached_orders {
        order_excluded = ex;
        order_networked = net;
        eprintln!("param-order evidence: {} sites (cached at {stamp})", m.len());
        m
    } else if arg_reg_offs.len() == 4 {
        let t = std::time::Instant::now();
        let entry_set: std::collections::HashSet<u64> = entries.iter().map(|e| e.0).collect();
        let mut sites = Vec::new();
        for (va, _) in &entries {
            let (next, body_end) = extent_bounds(*va);
            let end = match body_end {
                Some(b) => next.min(b),
                None => next,
            }
            .max(*va + 1);
            let region = prog.memory.read_window(Address::new(ram, *va), (end - *va) as usize);
            let insns = mosura::recompile::insn::normalize(
                SURVEY_LANG,
                &region,
                *va,
                &mosura::recompile::insn::NoReloc,
            )
            .unwrap_or_default();
            sites.extend(
                mosura::recompile::buildconfig::call_setup_sites(&insns, &arg_reg_offs)
                    .into_iter()
                    .filter(|s| entry_set.contains(&s.callee)),
            );
        }
        let mut orders = mosura::recompile::buildconfig::param_orders_from_evidence(&sites);
        // An order that IS the convention's slot order renders identically — drop the no-ops.
        orders.retain(|_, p| p.as_slice() != &arg_reg_offs[..p.len().min(arg_reg_offs.len())]);
        // The callees still claimed by at least one site, for the nondefault exclusion.
        let claimed: std::collections::HashSet<u64> = sites
            .iter()
            .filter(|s| orders.contains_key(&s.call_addr))
            .map(|s| s.callee)
            .collect();
        order_networked.extend(claimed.iter().copied());
        // excluded callees are equally order-networked (their storage is nondefault)
        for callee in claimed {
            let nondefault = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                decompile_function(&prog, Address::new(ram, callee))
            }))
            .ok()
            .flatten()
            .map(|f| nondefault_parm_regs(&f, &watreg).is_some())
            .unwrap_or(true);
            if nondefault {
                order_excluded.insert(callee);
            }
        }
        eprintln!(
            "param-order evidence: {} sites with a recovered nondefault declaration order \
             ({} callees excluded: nondefault storage or no decompile) in {:.1}s",
            orders.len(),
            order_excluded.len(),
            t.elapsed().as_secs_f64()
        );
        if !probing || !order_cache.exists() {
            let mut body = String::new();
            for (a, p) in &orders {
                let hx: Vec<String> = p.iter().map(|x| format!("{x:x}")).collect();
                body.push_str(&format!("{a:x}\t{}\n", hx.join(",")));
            }
            for x in &order_excluded {
                body.push_str(&format!("X\t{x:x}\n"));
            }
            for c in &order_networked {
                if !order_excluded.contains(c) {
                    body.push_str(&format!("C\t{c:x}\n"));
                }
            }
            let _ = std::fs::write(&order_cache, body);
        }
        orders
    } else {
        Default::default()
    };

    // GLOBAL WIDTHS FROM THE ORIGINAL'S OWN INSTRUCTIONS (`MOSURA_GLOBAL_WIDTH=witnessed`).
    //
    // `gsizes` below declares a Ram global at the NARROWEST access the decompiled function makes,
    // which is exactly right for a byte-only global -- FUN_0003ca48's `mov [0x95435],al` must not
    // become a dword store -- and wrong when one function touches an address at two widths: the
    // narrow declaration then TRUNCATES a store the original makes wide, and the high bytes are
    // never written by our C at all.  Measured: 24 addresses, 21 of them READ wider elsewhere in
    // the image than we store, so a reader sees bytes our C never writes.
    //
    // The original's own STORE width is the evidence that separates the two cases, and it is
    // corpus-wide (one function's byte read is another function's dword store), so it is collected
    // here, once, from the same normalized instruction stream the rest of the survey uses.  Both
    // conditions below are byte evidence: widen only where the original STORES wider than we would
    // AND READS wider than we would store -- the second is the wrong-code criterion and keeps the
    // arm off addresses that are merely accessed at two widths.
    //
    // DEFAULT-ON since the round on 92db550: COMPILE_FAIL unchanged (the one pre-existing
    // FUN_0007449c), 877 -> 878 EXACT, WGSS 0.5618 -> 0.5625, a single UP flip (FUN_00011098's
    // byte increment of a dword global now recompiles byte-exact), 18 movers of which the 6 downs
    // are form with no verdict change, stable at two on byte-identical TSVs.
    // `MOSURA_GLOBAL_WIDTH=recovered` restores the narrowest-access declaration, the way
    // `MOSURA_KERNEL_NET=0` and `MOSURA_CONS_REACH=0` restore theirs.
    let global_width_arm = std::env::var("MOSURA_GLOBAL_WIDTH").as_deref() != Ok("recovered");
    let (ram_store_w, ram_read_w) = if global_width_arm {
        let t = std::time::Instant::now();
        let mut sw: HashMap<u64, u32> = HashMap::new();
        let mut rw: HashMap<u64, u32> = HashMap::new();
        for (va, _) in &entries {
            let (next, body_end) = extent_bounds(*va);
            let end = match body_end {
                Some(b) => next.min(b),
                None => next,
            }
            .max(*va + 1);
            let region = prog.memory.read_window(Address::new(ram, *va), (end - *va) as usize);
            let insns = mosura::recompile::insn::normalize(
                SURVEY_LANG,
                &region,
                *va,
                &mosura::recompile::insn::NoReloc,
            )
            .unwrap_or_default();
            for x in &insns {
                for op in &x.sem {
                    if let Some(mosura::recompile::insn::SemArg::Mem(_, a, sz)) = &op.out {
                        let e = sw.entry(*a).or_insert(0);
                        *e = (*e).max(*sz);
                    }
                    for i in &op.ins {
                        if let mosura::recompile::insn::SemArg::Mem(_, a, sz) = i {
                            let e = rw.entry(*a).or_insert(0);
                            *e = (*e).max(*sz);
                        }
                    }
                }
            }
        }
        eprintln!(
            "global-width witness: {} stored addresses, {} read, in {:.1}s",
            sw.len(),
            rw.len(),
            t.elapsed().as_secs_f64()
        );
        (sw, rw)
    } else {
        (HashMap::new(), HashMap::new())
    };
    let order_excluded = order_excluded;

    let t0 = std::time::Instant::now();
    let (mut ok, mut fail) = (0usize, 0usize);
    // Sorted-entry extents for the zap checker's ORIGINAL-instruction windows (the gap to
    // the next entry, the pre-pass's own fallback extent).
    let next_entry: HashMap<u64, u64> = entries
        .windows(2)
        .map(|w| (w[0].0, w[1].0))
        .chain(entries.last().map(|l| (l.0, l.0 + 0x1000)))
        .collect();
    // Memoized landed-world answer to "does this callee declare NONDEFAULT parameter
    // storage?" — the definition-side network the caller-side parm post-pass keys on. An
    // upgraded arg list at such a callee can flip that post-pass's arity/width gates
    // (0x3925c's `parm [edx] [eax]` callee), so upgrades refuse those TUs precisely.
    let mut nondefault_storage: HashMap<u64, bool> = HashMap::new();
    // Per-callee entry-block byte testimony, computed once per callee ([`callee_input_evidence`]).
    let mut callee_ev_cache: HashMap<u64, Vec<Option<bool>>> = HashMap::new();
    for (idx, (va, name)) in entries.iter().enumerate() {
        if !only.is_empty() && !only.contains(va) {
            continue;
        }
        *panic_msg.lock().unwrap() = None;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            decompile_function(&prog, Address::new(ram, *va))
        }));
        // which world produced the final `f`: the landed program, or the prototype-injected
        // probe program (`prog_pp`) after a kernel adoption — the shared-return arm re-decompiles
        // the SAME world.
        let mut f_from_pp = false;
        let mut f: Option<Funcdata> = match outcome {
            Ok(Some(f)) => Some(f),
            _ => None,
        };
        // PER-TU UPGRADE under the zap checker (see `prog_pp` above): try the
        // prototype-informed decompile; adopt it only if the scheduler model accepts the
        // candidate call effects AND the function's own parameter signature is unchanged.
        if let (Some(fl), Some(pp)) = (f.as_ref(), prog_pp.as_ref()) {
            let ext = next_entry.get(va).copied().unwrap_or(*va + 0x1000).saturating_sub(*va);
            let reg_bytes = prog.memory.read_window(Address::new(ram, *va), ext as usize);
            let insns = mosura::recompile::insn::normalize(
                SURVEY_LANG,
                &reg_bytes,
                *va,
                &mosura::recompile::insn::NoReloc,
            )
            .unwrap_or_default();
            let outcome2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                decompile_function(pp, Address::new(ram, *va))
            }));
            if let Ok(Some(mut f2)) = outcome2 {
                let cand = candidate_call_effects(&f2);
                // Signature gate: NONDEFAULT-storage stability only. A full count+storage
                // comparison was measured to refuse every upgrade — own-arity growth IS the
                // recovery working (the gains carry it too); judging which growths are
                // allocation-safe (entry liveness, re-homing) is the phase-2 allocator
                // cost-model's job (regalloc.c CalcSavings/GiveBestReg), recorded in the
                // thread memory. Until then the allocation gate below covers the
                // call-crossing half, and the own-params half rides the corpus verdict.
                // Signature stability, three conditions (the first was the original gate;
                // the residual-defect census after the zero-cost kernel named the others):
                //   1. nondefault-storage stability (full count+storage equality was a
                //      measured dead end — every gain grows its own signature);
                //   2. EXISTING params stay verbatim — storage AND size. The prototype
                //      pass widened FUN_00034fe0's `char param_3` to `xunknown4` (the
                //      injected 4-byte call-slot width coarsened the type) and the
                //      re-typed TU compiles differently;
                //   3. a STACK-convention function stays stack: FUN_00073338 (own
                //      `parm caller []`, one stack param) grew FIVE register params —
                //      an injected callee arity manufactured phantom own-params from
                //      entry-reaching register reads. Register growth on a stack-param
                //      landed signature contradicts the recovered convention.
                let sig_stable_vs = |cand: &Funcdata| -> bool {
                    let lp = mosura::decompile::printc::rendered_param_slots(fl);
                    let cp = mosura::decompile::printc::rendered_param_slots(cand);
                    let prefix_ok = cp.len() >= lp.len()
                        && lp.iter().zip(cp.iter()).all(|(a, b)| a.addr == b.addr && a.size == b.size);
                    let reg_space = cand.spaces.by_name("register");
                    let landed_has_stack = lp.iter().any(|sl| Some(sl.addr.space) != reg_space);
                    let grows_registers =
                        cp.len() > lp.len() && cp[lp.len()..].iter().any(|sl| Some(sl.addr.space) == reg_space);
                    nondefault_parm_regs(cand, &watreg) == nondefault_parm_regs(fl, &watreg)
                        && prefix_ok
                        && !(landed_has_stack && grows_registers)
                };
                let sig_stable = sig_stable_vs(&f2);
                // The parm-pragma network gate, PRESENCE FORM — deliberately blunt: any
                // call into a NONDEFAULT-STORAGE callee refuses the upgrade. The precise
                // form (refuse only on CHANGED ordered arg signatures at such callees) was
                // measured and does NOT land: it released ~300 more adoptions for ZERO
                // gains and two fresh EXACT losses (0x1da00, 0x2d1f0) — the census's
                // 122-function "network pool" of near-misses does not resolve through
                // arity alone, and the relaxation only buys risk. (The ordered-signature
                // hazard it did catch — the locked-prototype arg order inverting the
                // positional pairing under a `parm [..]` pragma at 0x3925c — is subsumed
                // by presence-refusal.)
                let mut networked = false;
                for op in f2.op_ids() {
                    let o = f2.op(op);
                    if o.code() != OpCode::Call || o.flags & (flags::DEAD | flags::MARKER) != 0 {
                        continue;
                    }
                    let Some(t) = o.input(0) else { continue };
                    let callee = f2.vn(t).loc.offset;
                    if callee == 0 {
                        continue;
                    }
                    let nd = *nondefault_storage.entry(callee).or_insert_with(|| {
                        order_networked.contains(&callee)
                            || std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                decompile_function(&prog, Address::new(ram, callee))
                            }))
                            .ok()
                            .flatten()
                            .map(|cf| nondefault_parm_regs(&cf, &watreg).is_some())
                            .unwrap_or(true)
                    });
                    if nd {
                        networked = true;
                        break;
                    }
                }
                // PHASE-2 HYPOTHESIS (allocator model): an ADDED own-parameter whose
                // register the original body WRITES with ordinary instructions (not the
                // calls' convention effects, not the PUSH/POP save pair) is a live-in
                // COLLIDING with the body's own register usage — the FUN_0005ed78 shape.
                let no_collision = {
                    let slots = |f: &Funcdata| -> Vec<u64> {
                        let reg = f.spaces.by_name("register");
                        mosura::decompile::printc::rendered_param_slots(f)
                            .iter()
                            .filter(|sl| Some(sl.addr.space) == reg)
                            .map(|sl| sl.addr.offset & !3)
                            .collect()
                    };
                    let old_slots = slots(fl);
                    let added: Vec<u64> =
                        slots(&f2).into_iter().filter(|r| !old_slots.contains(r)).collect();
                    if added.is_empty() {
                        true
                    } else {
                        let mut body_writes: std::collections::HashSet<u64> =
                            std::collections::HashSet::new();
                        for x in &insns {
                            if x.is_call || x.mnemonic == "PUSH" || x.mnemonic == "POP" {
                                continue;
                            }
                            for op in &x.sem {
                                if let Some(mosura::recompile::insn::SemArg::Reg(o, _)) = op.out {
                                    if o < 0x20 {
                                        body_writes.insert(o & !3);
                                    }
                                }
                            }
                        }
                        !added.iter().any(|r| body_writes.contains(r))
                    }
                };
                let other_ok = sig_stable
                    && !networked
                    && !cand.is_empty()
                    && !insns.is_empty()
                    && !mosura::recompile::watsched::order_regressed(&insns, &cand);
                // The allocation gate (register-allocator model, phase 1): a candidate
                // that kills a register the original visibly carries across the call
                // would have re-homed that value (FUN_00034fe0's PUSH EDI shape).
                let alloc_ok = no_collision
                    && !mosura::recompile::watsched::allocation_regressed(&insns, &cand);
                let mut ok = other_ok && alloc_ok;
                let mut passthrough = false;
                let mut consistency_forced = false;
                // DEFAULT-ON since the round-2 landing (targeted 299: 121/121 EXACT held,
                // +5, zero losses). MOSURA_KERNEL_NET=0 restores the refusal.
                let net_kernel = std::env::var("MOSURA_KERNEL_NET").as_deref() != Ok("0");
                if other_ok && !alloc_ok {
                    // Allocator model phase 2, the ZERO-COST kernel (see `pass_through_only`):
                    // a collision/allocation refusal whose whole delta is appended
                    // self-move pass-throughs cannot change the allocator's assignment.
                    let lt = print_c(fl);
                    let ct = print_c(&f2);
                    let sig_of2 = |t: &str| t.lines().find(|l| l.contains(&format!("FUN_{va:08x}("))).map(str::to_string);
                    if pass_through_only(&lt, &ct, *va) {
                        ok = true;
                        passthrough = true;
                    } else {
                        // STACK-APPEND kernel (stack-args frontier): a refusal whose whole
                        // delta is appended args is admitted when every arbitrary-expression
                        // element is backed by at least that many PUSH insns in the
                        // original's 12-insn pre-call window (the const-evidence pattern)
                        // and the signature line is untouched. Landed under the WGSS-first
                        // bar (2026-08-22): the evidence-gated pool is 2 TUs, micro-round
                        // 36b30 sim 0.471→0.586, 6d680 unchanged, no verdict regressions.
                        // MOSURA_KERNEL_STACKAPP=0 restores the refusal.
                        let stack_kernel = std::env::var("MOSURA_KERNEL_STACKAPP").as_deref() != Ok("0");
                        let mut consts2: Vec<(u64, u32, u64)> = Vec::new();
                        let mut stacks: Vec<(u64, u32)> = Vec::new();
                        if (stack_kernel || mosura::debug::on(mosura::debug::Topic::Survey))
                            && pass_through_report(&lt, &ct, *va, Some(&mut consts2), Some(&mut stacks))
                            && !stacks.is_empty()
                        {
                            let mut push_ev = std::collections::HashMap::new();
                            for (i, x) in insns.iter().enumerate() {
                                if x.is_call {
                                    if let Some(t) = x.target {
                                        let pushes = insns[..i]
                                            .iter()
                                            .rev()
                                            .take(12)
                                            .take_while(|y| !y.is_call && !y.is_branch)
                                            .filter(|y| y.mnemonic == "PUSH")
                                            .count();
                                        let e = push_ev.entry(t).or_insert(0usize);
                                        *e = (*e).max(pushes);
                                    }
                                }
                            }
                            let mut need = std::collections::HashMap::new();
                            for &(c, _) in &stacks {
                                *need.entry(c).or_insert(0usize) += 1;
                            }
                            if need.iter().all(|(c, n)| push_ev.get(c).copied().unwrap_or(0) >= *n)
                                && sig_of2(&lt) == sig_of2(&ct)
                            {
                                mosura::debug!(mosura::debug::Topic::Survey, "shadow-stack {name} appends {:?}", need.iter().map(|(c, n)| (format!("{c:#x}"), *n)).collect::<Vec<_>>());
                                if stack_kernel {
                                    ok = true;
                                    passthrough = true;
                                }
                            }
                        }
                    }
                }
                // SHADOW CENSUS (MOSURA_KERNEL_SHADOW=1; missing-args thread): would the
                // zero-cost kernel, extended to NETWORK refusals under a tightened guard,
                // adopt this TU? Counted only — nothing adopts. The tightening beyond
                // pass_through_only: a changed callee pragma may not touch anything BEFORE
                // its `modify` clause (its `parm [..]`/`parm caller []` half must be
                // verbatim), killing the 3925c order-inversion hazard that sank the old
                // precise-network relaxation (1da00/2d1f0).
                if (mosura::debug::on(mosura::debug::Topic::Survey) || net_kernel)
                    && !ok
                    && sig_stable
                    && networked
                    && !cand.is_empty()
                    && !insns.is_empty()
                    && !mosura::recompile::watsched::order_regressed(&insns, &cand)
                {
                    let lt = print_c(fl);
                    let ct = print_c(&f2);
                    // ROUND-2 TIGHTENING (measured separation on the round-1 gain/loss sets):
                    //   - callee pragmas fully VERBATIM — round 1's nine EXACT losses all
                    //     carried `modify` → `modify exact` deltas (the exactness keyword's
                    //     caller-side codegen, −11 solo in the ledger); the six gains had
                    //     zero pragma deltas;
                    //   - the OWN signature identical (no arity growth);
                    //   - every appended CONSTANT must have its materializing write in the
                    //     ORIGINAL bytes (`MOV reg,K` / `XOR reg,reg` for 0) — gains restore
                    //     an instruction the original HAS (237dc's `MOV ECX,0x1`), losses
                    //     invented one it lacks (12c58's `(0, 0)`).
                    let mut appended_consts: Vec<(u64, u32, u64)> = Vec::new();
                    // The TU's pragma lines are assembled from call_specs AFTER the loop
                    // (callee_aux), so a render comparison cannot see them — 1da00's only
                    // delta was `modify` → `modify exact` and a text check was vacuous.
                    // Compare the SPECS: per callee, (caller_cleans, cdecl_modify,
                    // cdecl_exact) must agree between the landed and candidate decompiles.
                    // DETERMINISTIC per-callee view (second leak of the run-to-run jitter,
                    // found by the full double-emit after d45c4ed): the old fold inserted
                    // per site over the HashMap, last-writer-wins, so `pragmas_equal` below
                    // was a random draw whenever a callee had two sites with different
                    // specs — the network kernel then adopted or refused by hash order
                    // (FUN_0004ac88 / callee 0x5dd14: `adopted:passthrough` vs
                    // `refused:network` across runs). The view now merges exactly as the
                    // TU's pragma emission does (caller_cleans from any site, modify = union,
                    // exact from any site), so equality of views is equality of the pragmas
                    // that would be emitted.
                    let spec_view = |f: &Funcdata| -> std::collections::BTreeMap<u64, (Option<u32>, Option<std::collections::BTreeSet<u64>>, bool)> {
                        let mut m: std::collections::BTreeMap<u64, (Option<u32>, Option<std::collections::BTreeSet<u64>>, bool)> =
                            std::collections::BTreeMap::new();
                        for (&op, cs) in f.call_specs.iter() {
                            let Some(t) = f.op(op).input(0) else { continue };
                            let cva = f.vn(t).loc.offset;
                            if cva == 0 {
                                continue;
                            }
                            let e = m.entry(cva).or_default();
                            // the pop count: the largest any site recovered (None < Some)
                            e.0 = e.0.max(cs.caller_cleans.filter(|&n| n > 0));
                            if let Some(mm) = cs.cdecl_modify.as_ref() {
                                e.1.get_or_insert_with(Default::default).extend(mm.iter().copied());
                            }
                            e.2 |= cs.cdecl_exact;
                        }
                        m
                    };
                    let ops_input0: std::collections::HashMap<mosura::decompile::op::OpId, u64> = f2
                        .call_specs
                        .keys()
                        .filter_map(|&op| {
                            let t = f2.op(op).input(0)?;
                            let va = f2.vn(t).loc.offset;
                            (va != 0).then_some((op, va))
                        })
                        .collect();
                    let (sv_l, sv_c) = (spec_view(fl), spec_view(&f2));
                    let pragmas_equal = sv_l == sv_c;
                    if mosura::debug::on(mosura::debug::Topic::Survey) && !pragmas_equal {
                        for (k, v) in &sv_c {
                            if sv_l.get(k) != Some(v) {
                                mosura::debug!(mosura::debug::Topic::Survey, "shadow-diff {name} callee {k:#x} landed {:?} cand {:?}", sv_l.get(k), v);
                                break;
                            }
                        }
                    }
                    let sig_of = |t: &str| t.lines().find(|l| l.contains(&format!("FUN_{va:08x}("))).map(str::to_string);
                    // Byte evidence, WINDOWED at the call: the appended constant's
                    // materializing write must sit within the 12 instructions before a call
                    // to that callee (stopping at intervening calls/branches) — an extent-
                    // wide search whitelisted 157a0's distant `XOR EDX,EDX` for a zero the
                    // original never materializes at this site.
                    let const_evidence = |appends: &[(u64, u32, u64)]| -> bool {
                        appends.iter().all(|&(callee, pos, k)| {
                            if callee == 0 {
                                return false;
                            }
                            let Some(&r) = arg_reg_offs.get(pos as usize) else { return false };
                            insns.iter().enumerate().filter(|(_, x)| x.is_call && x.target == Some(callee)).any(|(ci, _)| {
                                insns[..ci]
                                    .iter()
                                    .rev()
                                    .take(12)
                                    .take_while(|x| !x.is_call && !x.is_branch)
                                    .any(|x| {
                                        x.sem.iter().any(|op| {
                                            matches!(op.out, Some(mosura::recompile::insn::SemArg::Reg(o, _)) if o & !3 == r)
                                                && (op.ins.iter().any(|i| matches!(i, mosura::recompile::insn::SemArg::Const(v, _) if *v == k))
                                                    || (k == 0
                                                        && x.mnemonic == "XOR"
                                                        && x.sem.iter().any(|op| matches!(op.out, Some(mosura::recompile::insn::SemArg::Reg(o, _)) if o & !3 == r))))
                                        })
                                    })
                            })
                        })
                    };
                    if pass_through_report(&lt, &ct, *va, Some(&mut appended_consts), None)
                        && pragmas_equal
                        && sig_of(&lt) == sig_of(&ct)
                        && const_evidence(&appended_consts)
                    {
                        if net_kernel {
                            // Landed via the round-2 targeted measurement. The adoption's
                            // PURPOSE is the appended arguments; the pragma-relevant spec
                            // fields stay the LANDED ones BY CONSTRUCTION — the gate asserts
                            // spec equality, but 1da00's `modify exact` still drifted in
                            // post-gate emission state during the first full round, so the
                            // invariant is enforced rather than assumed.
                            let landed_specs = spec_view(fl);
                            for (&op, cs) in f2.call_specs.iter_mut() {
                                let Some(t) = ops_input0.get(&op) else { continue };
                                if let Some((cleans, modify, exact)) = landed_specs.get(t) {
                                    cs.caller_cleans = *cleans;
                                    cs.cdecl_modify = modify.as_ref().map(|s| s.iter().copied().collect());
                                    cs.cdecl_exact = *exact;
                                }
                            }
                            ok = true;
                            passthrough = true;
                        } else {
                            mosura::debug!(mosura::debug::Topic::Survey, "{name} network-eligible consts={}", appended_consts.len());
                        }
                    } else if pragmas_equal && sig_of(&lt) == sig_of(&ct) {
                        // ORDER-ONLY deltas stay REFUSED — measured 2026-08-21: the whole
                        // pool is 6 TUs (one callee, 0x38828), the LANDED pairing already
                        // follows the byte-derived site-order evidence (`parm [edx] [eax]`,
                        // original `XOR EDX,EDX; MOV DL,AL; MOV EAX,const`), and adopting
                        // the prototype-ordered permutation changed renders with sims
                        // UNMOVED at 0.636 — the recorded 3925c inversion wart, confirmed
                        // live. The census classifier stays for future shadow runs.
                        if mosura::debug::on(mosura::debug::Topic::Survey) {
                            if let Some(cs2) = order_only_delta(&lt, &ct) {
                                let list: Vec<String> = cs2.iter().map(|c| format!("{c:#x}")).collect();
                                mosura::debug!(mosura::debug::Topic::Survey, "shadow-order {name} callees [{}]", list.join(" "));
                            }
                        }
                    }
                }
                // CONSISTENCY OVERRIDE (JD 2026-08-24; memory consistency-over-score):
                // cross-TU argument consistency outranks the byte-gates. When the LANDED
                // decompile under-calls a register-prototype callee — the callee's own TU
                // declares parameters these calls do not pass, so the linked program would
                // read garbage — and the candidate resolves every such call with genuinely
                // bound values, the candidate is adopted even where the scheduler/network/
                // allocation gates refused. Own-signature instability (`sig_stable` false)
                // still blocks: width coarsening and phantom own-params are the collateral
                // bug class, not the lottery. Score losses from these adoptions are
                // CLASSIFIED in the round report (lottery vs bug), not vetoed.
                // MOSURA_CONSISTENCY=0 restores the pure gate stack for A/B measurement.
                let mut f_forced: Option<Funcdata> = None;
                if !ok && std::env::var("MOSURA_CONSISTENCY").as_deref() != Ok("0") {
                    // DEFAULT-ON since the Order Y round (878 EXACT / WGSS 0.56212 on base
                    // 38f1c72's 875 / 0.56115: +3, 4 flips up, 1 classified correct-code form
                    // down, stable at two on byte-identical TSVs). `MOSURA_CONS_REACH=0`
                    // restores the 12-instruction call-stopped witness and the flat shape
                    // rule, the way `MOSURA_KERNEL_NET=0` and `MOSURA_CONSISTENCY=0` restore
                    // theirs — the A/B every round on this gate has needed.
                    let reach_mode = std::env::var("MOSURA_CONS_REACH").as_deref() != Ok("0");
                    // The callee's own entry block, for every direct callee of this function.
                    let mut evidence: HashMap<u64, Vec<Option<bool>>> = HashMap::new();
                    for op in fl.op_ids() {
                        let o = fl.op(op);
                        if o.code() != OpCode::Call || o.flags & (flags::DEAD | flags::MARKER) != 0 {
                            continue;
                        }
                        let Some(t) = o.input(0) else { continue };
                        let c = fl.vn(t).loc.offset;
                        if c == 0 || evidence.contains_key(&c) {
                            continue;
                        }
                        let e = callee_ev_cache
                            .entry(c)
                            .or_insert_with(|| {
                                let ext = next_entry
                                    .get(&c)
                                    .copied()
                                    .unwrap_or(c + 0x100)
                                    .saturating_sub(c)
                                    .min(0x100);
                                let b = prog.memory.read_window(Address::new(ram, c), ext as usize);
                                let ci = mosura::recompile::insn::normalize(
                                    SURVEY_LANG,
                                    &b,
                                    c,
                                    &mosura::recompile::insn::NoReloc,
                                )
                                .unwrap_or_default();
                                callee_input_evidence(&ci, &arg_reg_offs)
                            })
                            .clone();
                        evidence.insert(c, e);
                    }
                    // NO GROWTH-SIDE REFUSAL, and the reason is measured (Order Y): refusing a
                    // contradiction whose claimed register the callee writes-before-reading was
                    // built, run over the corpus, and REFUTED on its own criterion — it removed 4
                    // benign extra-argument sites and created 4 sites that DROP a register the
                    // callee's bytes say it READS. The asymmetry is real: in a positional
                    // convention an UNUSED parameter slot is legal, so `written before read` does
                    // not disprove parameterhood; passing a value the callee ignores is score
                    // noise, while failing to pass one it reads is wrong code. The byte evidence
                    // is therefore applied only where the harm is (in `call_shapes_stable`: never
                    // drop a byte-proven read).
                    let contradicted = under_called_register_callees(fl, pp);
                    if !contradicted.is_empty() {
                        let list: Vec<String> =
                            contradicted.iter().map(|&(c, n)| format!("{c:#x}/{n}")).collect();
                        // SURGICAL INJECTION (zc52's lesson): do NOT adopt the pp world's
                        // decompile wholesale — its call_specs shift every pragma
                        // (`modify` → `modify exact`, order pragmas lost) and its other
                        // locked calls can LOSE arguments (0x11b9c), the measured bug-class
                        // losses. Re-decompile the LANDED world with only the contradicted
                        // callees' prototypes visible (`Program::proto_scope`), so the
                        // adoption carries exactly the missing arguments.
                        let f3 = prog_cons.as_mut().and_then(|pc| {
                            pc.proto_scope =
                                Some(contradicted.iter().map(|&(c, _)| c).collect());
                            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                decompile_function(pc, Address::new(ram, *va))
                            }))
                            .ok()
                            .flatten();
                            pc.proto_scope = Some(std::collections::HashSet::new());
                            r
                        });
                        // BYTE EVIDENCE for constant arguments (the net-kernel's measured
                        // gate, reused): a constant an injected call carries must have its
                        // materializing write in the ORIGINAL's 12-instruction pre-call
                        // window (`MOV reg,K`, or `XOR reg,reg` for 0). The indirect-zero
                        // flag does not survive constant cloning and dead-iop collapse, so
                        // 12c58's `(0, 0)` — zeros the original never places — arrives as
                        // plain constants; the original's own instruction stream is the
                        // reliable witness.
                        // (B) REACHING WITNESS (`MOSURA_CONS_REACH=1`, Order Y) — the landed window
                        // stops at the first intervening CALL, and this defect class is DEFINED by
                        // a materializing write that sits before one: `MOV EBX,0x28a0` at 0x22e61,
                        // `CALL 0x59404` at 0x22e66, `CALL 0x50480` at 0x22e81. The walk crosses a
                        // call only when that call's own recovered contract preserves the register
                        // — the same `cdecl_modify` set our `#pragma aux .. modify [..]` already
                        // asserts in the emitted C, so the witness never claims more than the
                        // program we print (0x59404 saves EBX/ECX/EDX at entry: byte-confirmed).
                        let preserves = |pc: u64, r: u64| -> bool {
                            fl.op_ids()
                                .find(|&op| {
                                    let o = fl.op(op);
                                    matches!(o.code(), OpCode::Call | OpCode::Callind)
                                        && o.seqnum.pc.offset == pc
                                })
                                .and_then(|op| fl.call_specs.get(&op))
                                .and_then(|cs| cs.cdecl_modify.as_ref())
                                .is_some_and(|m| !m.iter().any(|&c| c & !3 == r))
                        };
                        let reach_witness = |callee: u64, r: u64, k: u64| -> bool {
                            insns
                                .iter()
                                .enumerate()
                                .filter(|(_, x)| x.is_call && x.target == Some(callee))
                                .any(|(ci, _)| {
                                    for x in insns[..ci].iter().rev() {
                                        if x.is_branch {
                                            return false;
                                        }
                                        let writes_r = x.sem.iter().any(|sop| {
                                            matches!(sop.out, Some(mosura::recompile::insn::SemArg::Reg(o2, _)) if o2 & !3 == r)
                                        });
                                        if writes_r {
                                            return x.sem.iter().any(|sop| {
                                                matches!(sop.out, Some(mosura::recompile::insn::SemArg::Reg(o2, _)) if o2 & !3 == r)
                                                    && (sop.ins.iter().any(|ii| matches!(ii, mosura::recompile::insn::SemArg::Const(vv, _) if *vv == k))
                                                        || (k == 0 && x.mnemonic == "XOR"))
                                            });
                                        }
                                        if x.is_call && !preserves(x.addr, r) {
                                            return false;
                                        }
                                    }
                                    false
                                })
                        };
                        let consts_witnessed = |f3: &Funcdata| -> bool {
                            for op in f3.op_ids() {
                                let o = f3.op(op);
                                if o.code() != OpCode::Call
                                    || o.flags & (flags::DEAD | flags::MARKER) != 0
                                {
                                    continue;
                                }
                                let Some(t) = o.input(0) else { continue };
                                let callee = f3.vn(t).loc.offset;
                                let Some(&(_, arity)) =
                                    contradicted.iter().find(|&&(c, _)| c == callee)
                                else {
                                    continue;
                                };
                                for i in 1..=arity.min(o.num_inputs() - 1) {
                                    let Some(v) = o.input(i) else { return false };
                                    let vn = f3.vn(v);
                                    if !vn.is_constant() {
                                        continue;
                                    }
                                    let k = vn.loc.offset;
                                    let Some(&r) = arg_reg_offs.get(i - 1) else { return false };
                                    let witnessed = if reach_mode {
                                        reach_witness(callee, r, k)
                                    } else {
                                        insns
                                        .iter()
                                        .enumerate()
                                        .filter(|(_, x)| x.is_call && x.target == Some(callee))
                                        .any(|(ci, _)| {
                                            insns[..ci]
                                                .iter()
                                                .rev()
                                                .take(12)
                                                .take_while(|x| !x.is_call && !x.is_branch)
                                                .any(|x| {
                                                    x.sem.iter().any(|sop| {
                                                        matches!(sop.out, Some(mosura::recompile::insn::SemArg::Reg(o2, _)) if o2 & !3 == r)
                                                            && (sop.ins.iter().any(|ii| matches!(ii, mosura::recompile::insn::SemArg::Const(vv, _) if *vv == k))
                                                                || (k == 0 && x.mnemonic == "XOR"))
                                                    })
                                                })
                                        })
                                    };
                                    if !witnessed {
                                        return false;
                                    }
                                }
                            }
                            true
                        };
                        // ==== ORDER Y PROBE (unlanded, MOSURA_CONS_PROBE=1) ====
                        // The HELD message names four conditions at once. This splits them, and
                        // for the constant-witness half re-runs the search with the intervening-
                        // CALL stop REMOVED — reporting the reaching write, how many calls it had
                        // to cross, and each crossed callee, so the design reads bytes not guesses.
                        if std::env::var("MOSURA_CONS_PROBE").as_deref() == Ok("1") {
                            match f3.as_ref() {
                                None => eprintln!("[cons-probe] {name}: f3=NONE callees [{}]", list.join(" ")),
                                Some(fx) => {
                                    let r1 = resolves_contradictions(fx, &contradicted);
                                    let r2 = call_shapes_stable(fl, fx, &contradicted, reach_mode.then_some(&pp.recovered_protos), &evidence);
                                    let r3 = sig_stable_vs(fx);
                                    let r4 = consts_witnessed(fx);
                                    eprintln!(
                                        "[cons-probe] {name}: resolves={r1} shapes={r2} sig={r3} consts={r4} callees [{}]",
                                        list.join(" ")
                                    );
                                    if !r3 {
                                        // WHICH of the three tests wearing the `sig_stable` name
                                        let lp = mosura::decompile::printc::rendered_param_slots(fl);
                                        let cp = mosura::decompile::printc::rendered_param_slots(fx);
                                        let reg = fx.spaces.by_name("register");
                                        let prefix_ok = cp.len() >= lp.len()
                                            && lp.iter().zip(cp.iter()).all(|(a, b)| a.addr == b.addr && a.size == b.size);
                                        let landed_has_stack = lp.iter().any(|sl| Some(sl.addr.space) != reg);
                                        let grows_registers = cp.len() > lp.len()
                                            && cp[lp.len()..].iter().any(|sl| Some(sl.addr.space) == reg);
                                        eprintln!(
                                            "[cons-sig] {name} parm_regs_eq={} prefix_ok={prefix_ok} stack_to_reg={} landed={:?} cand={:?}",
                                            nondefault_parm_regs(fx, &watreg) == nondefault_parm_regs(fl, &watreg),
                                            landed_has_stack && grows_registers,
                                            lp.iter().map(|s| (s.addr.offset, s.size)).collect::<Vec<_>>(),
                                            cp.iter().map(|s| (s.addr.offset, s.size)).collect::<Vec<_>>()
                                        );
                                    }
                                    if !r2 {
                                        // WHICH call drifted, and in which direction — a GROWTH at
                                        // a non-contradicted callee and a LOSS are different risks.
                                        let shapes = |f: &Funcdata| -> HashMap<u64, (usize, Option<u32>, u64)> {
                                            let mut m = HashMap::new();
                                            for op in f.op_ids() {
                                                let o = f.op(op);
                                                if !matches!(o.code(), OpCode::Call | OpCode::Callind)
                                                    || o.flags & (flags::DEAD | flags::MARKER) != 0
                                                {
                                                    continue;
                                                }
                                                let callee = if o.code() == OpCode::Call {
                                                    o.input(0).map_or(0, |t| f.vn(t).loc.offset)
                                                } else {
                                                    0
                                                };
                                                m.insert(
                                                    o.seqnum.pc.offset,
                                                    (o.num_inputs() - 1, o.output.map(|v| f.vn(v).size), callee),
                                                );
                                            }
                                            m
                                        };
                                        let (sl, sx) = (shapes(fl), shapes(fx));
                                        let mut pcs: Vec<&u64> = sl.keys().collect();
                                        pcs.sort();
                                        for pc in pcs {
                                            let (n, ow, callee) = sl[pc];
                                            match sx.get(pc) {
                                                None => eprintln!("[cons-shape] {name} {pc:#x} callee {callee:#x} GONE (landed {n} args)"),
                                                Some(&(m, ow2, _)) if m != n || ow2 != ow => {
                                                    let cont = contradicted.iter().any(|&(c, _)| c == callee);
                                                    // the callee's OWN byte-derived contract, the
                                                    // arbiter for whether a drift is a correction
                                                    let pr = pp.recovered_protos.get(&callee);
                                                    let reg = fx.spaces.by_name("register");
                                                    let parity = pr.map(|p| p.params.len());
                                                    let regonly = pr.map(|p| {
                                                        !p.params.is_empty()
                                                            && p.params.iter().all(|s| Some(s.addr.space) == reg)
                                                    });
                                                    let out_used2 = fx.op_ids().find(|&o| fx.op(o).seqnum.pc.offset == *pc && matches!(fx.op(o).code(), OpCode::Call | OpCode::Callind)).and_then(|o| fx.op(o).output).map(|v| fx.vn(v).descend.len());
                                                    eprintln!("[cons-shape]   evidence {:?} cand-out-uses {:?}", evidence.get(&callee), out_used2);
                                                    eprintln!(
                                                        "[cons-shape] {name} {pc:#x} callee {callee:#x} args {n}->{m} outw {ow:?}->{ow2:?} contradicted={cont} proto_arity={parity:?} regonly={regonly:?}"
                                                    );
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                    for op in fx.op_ids() {
                                        let o = fx.op(op);
                                        if o.code() != OpCode::Call
                                            || o.flags & (flags::DEAD | flags::MARKER) != 0
                                        {
                                            continue;
                                        }
                                        let Some(t) = o.input(0) else { continue };
                                        let callee = fx.vn(t).loc.offset;
                                        let Some(&(_, arity)) =
                                            contradicted.iter().find(|&&(c, _)| c == callee)
                                        else {
                                            continue;
                                        };
                                        let pc = o.seqnum.pc.offset;
                                        for i in 1..=arity.min(o.num_inputs() - 1) {
                                            let Some(v) = o.input(i) else { continue };
                                            let vn = fx.vn(v);
                                            if !vn.is_constant() {
                                                continue;
                                            }
                                            let k = vn.loc.offset;
                                            let Some(&r) = arg_reg_offs.get(i - 1) else { continue };
                                            let Some(ci) = insns
                                                .iter()
                                                .position(|x| x.is_call && x.addr == pc)
                                            else {
                                                eprintln!("[cons-site] {name} {pc:#x} callee {callee:#x} arg{i} k={k:#x} NO-INSN");
                                                continue;
                                            };
                                            // reaching write of r, crossing calls, stopping at the
                                            // first write of r (that write is the value's origin)
                                            let mut crossed: Vec<String> = Vec::new();
                                            let mut verdict = "no-write".to_string();
                                            let mut dist = 0usize;
                                            for (d, x) in insns[..ci].iter().rev().enumerate() {
                                                if x.is_branch {
                                                    verdict = format!("branch@{:#x}", x.addr);
                                                    dist = d;
                                                    break;
                                                }
                                                let writes_r = x.sem.iter().any(|sop| {
                                                    matches!(sop.out, Some(mosura::recompile::insn::SemArg::Reg(o2, _)) if o2 & !3 == r)
                                                });
                                                if writes_r {
                                                    let mats = x.sem.iter().any(|sop| {
                                                        matches!(sop.out, Some(mosura::recompile::insn::SemArg::Reg(o2, _)) if o2 & !3 == r)
                                                            && (sop.ins.iter().any(|ii| matches!(ii, mosura::recompile::insn::SemArg::Const(vv, _) if *vv == k))
                                                                || (k == 0 && x.mnemonic == "XOR"))
                                                    });
                                                    verdict = format!(
                                                        "{}@{:#x}:{}",
                                                        if mats { "MATCH" } else { "other-write" },
                                                        x.addr,
                                                        x.mnemonic
                                                    );
                                                    dist = d;
                                                    break;
                                                }
                                                if x.is_call {
                                                    crossed.push(match x.target {
                                                        Some(t) => format!("{t:#x}"),
                                                        None => "ind".to_string(),
                                                    });
                                                }
                                            }
                                            eprintln!(
                                                "[cons-site] {name} {pc:#x} callee {callee:#x} arg{i} reg{r} k={k:#x} reach={verdict} dist={dist} crossed=[{}]",
                                                crossed.join(" ")
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        let carry = carry_arg_sites(fl, &pp.recovered_protos, &evidence, &insns, &arg_reg_offs);
                        match f3 {
                            Some(f3)
                                if resolves_contradictions(&f3, &contradicted)
                                    && call_shapes_stable(fl, &f3, &contradicted, reach_mode.then_some(&pp.recovered_protos), &evidence)
                                    && sig_stable_vs(&f3)
                                    && consts_witnessed(&f3) =>
                            {
                                // The adoption's PURPOSE is the arguments; the pragma-relevant
                                // spec fields stay the LANDED ones BY CONSTRUCTION — the same
                                // invariant the network kernel enforces. Without it the scoped
                                // callee's exactness re-derives under the injected arity and
                                // flips its clause (`modify [eax]` → `modify exact [eax]`),
                                // and one memset-class callee re-declared exact moved a caller
                                // 0.900 → 0.320 (zc54's 0x1fdbc, −140w — the round's entire
                                // down mass in one function).
                                let mut f3 = f3;
                                let landed: HashMap<u64, (Option<u32>, Option<Vec<u64>>, bool)> = fl
                                    .call_specs
                                    .iter()
                                    .filter_map(|(&op, cs)| {
                                        let t = fl.op(op).input(0)?;
                                        let cva = fl.vn(t).loc.offset;
                                        (cva != 0).then(|| {
                                            (cva, (cs.caller_cleans, cs.cdecl_modify.clone(), cs.cdecl_exact))
                                        })
                                    })
                                    .collect();
                                let ops_callee: Vec<(mosura::decompile::op::OpId, u64)> = f3
                                    .call_specs
                                    .keys()
                                    .filter_map(|&op| {
                                        let t = f3.op(op).input(0)?;
                                        let cva = f3.vn(t).loc.offset;
                                        (cva != 0).then_some((op, cva))
                                    })
                                    .collect();
                                for (op, cva) in ops_callee {
                                    if let Some((cleans, modify, exact)) = landed.get(&cva) {
                                        let cs = f3.call_specs.get_mut(&op).unwrap();
                                        cs.caller_cleans = *cleans;
                                        cs.cdecl_modify = modify.clone();
                                        cs.cdecl_exact = *exact;
                                    }
                                }
                                ok = true;
                                consistency_forced = true;
                                eprintln!(
                                    "[consistency] {name}: FORCED — under-called callees [{}]",
                                    list.join(" ")
                                );
                                f_forced = Some(f3);
                            }
                            // PER-SITE CONSTANT-ARGUMENT ADOPTION (JD decision 2, 2026-09-04): the
                            // candidate is sound everywhere but its call shapes — it also
                            // materializes a return the next call consumes, or widens one — so the
                            // whole function stays HELD, but a call whose extra arguments are all
                            // CONSTANTS, licensed the way `call_shapes_stable` licenses a drift (the
                            // callee's register-only recovered arity, its entry block not refuting
                            // the register), takes just those constants into the LANDED function:
                            // FUN_00033668's `func_0x000596b0(g, -2)`, the `MOV EDX,-2` its bytes
                            // carry and the landed world dropped. The constants are the candidate's
                            // witnessed values (`consts_witnessed`); nothing else of the candidate
                            // crosses over — the return widths, the other calls, the signature.
                            Some(f3)
                                if resolves_contradictions(&f3, &contradicted)
                                    && sig_stable_vs(&f3)
                                    && consts_witnessed(&f3)
                                    && !constant_arg_sites(fl, &f3, &contradicted, reach_mode.then_some(&pp.recovered_protos), &evidence, &insns).is_empty() =>
                            {
                                let sites = constant_arg_sites(fl, &f3, &contradicted, reach_mode.then_some(&pp.recovered_protos), &evidence, &insns);
                                let mut fp = fl.clone();
                                let mut added: Vec<String> = Vec::new();
                                for (op, consts) in &sites {
                                    for &(slot, value, size) in consts {
                                        let c = fp.new_const(size, value);
                                        fp.op_insert_input(*op, slot, c);
                                    }
                                    added.push(format!("{:#x}+{}", fp.op(*op).seqnum.pc.offset, consts.len()));
                                }
                                ok = true;
                                consistency_forced = true;
                                eprintln!("[consistency] {name}: PER-SITE constant arguments adopted at [{}]", added.join(" "));
                                f_forced = Some(fp);
                            }
                            // ARGUMENT CARRY (2026-09-04): the register arguments the landed
                            // function passes to a call beyond that callee's own arity, which the
                            // callee preserves and the NEXT call's arity names, move to the next
                            // call — `f1(x, 8, 0x14); f2();` becomes `f2(f1(x), 8, 0x14);`. Decided
                            // from the landed function and the bytes alone ([`carry_arg_sites`]);
                            // nothing else of any candidate crosses over.
                            _ if !carry.is_empty() => {
                                let mut fp = fl.clone();
                                let mut moved: Vec<String> = Vec::new();
                                for site in &carry {
                                    for &(slot, _) in site.slots.iter().rev() {
                                        fp.op_remove_input(site.from, slot);
                                    }
                                    match site.fill {
                                        CarryFill::None => {}
                                        CarryFill::Return => {
                                            let v = fp.new_unique(4);
                                            fp.op_set_output(site.from, v);
                                            fp.op_insert_input(site.to, 1, v);
                                        }
                                    }
                                    for &(slot, vn) in &site.slots {
                                        let v = if fp.vn(vn).is_constant() {
                                            let (sz, k) = (fp.vn(vn).size, fp.vn(vn).constant_value());
                                            fp.new_const(sz, k)
                                        } else {
                                            vn
                                        };
                                        fp.op_insert_input(site.to, slot, v);
                                    }
                                    moved.push(format!(
                                        "{:#x}->{:#x}+{}{}",
                                        fp.op(site.from).seqnum.pc.offset,
                                        fp.op(site.to).seqnum.pc.offset,
                                        site.slots.len(),
                                        match site.fill { CarryFill::None => "", CarryFill::Return => "r" }
                                    ));
                                }
                                ok = true;
                                consistency_forced = true;
                                eprintln!("[consistency] {name}: CARRY adopted [{}]", moved.join(" "));
                                f_forced = Some(fp);
                            }
                            _ => {
                                eprintln!(
                                    "[consistency] {name}: HELD (unbound/unwitnessed value, call-shape drift, or unstable signature) — callees [{}]",
                                    list.join(" ")
                                );
                            }
                        }
                    }
                }
                if mosura::debug::on(mosura::debug::Topic::Watsched) {
                    let reason = if consistency_forced {
                        "adopted:consistency"
                    } else if passthrough {
                        "adopted:passthrough"
                    } else if ok {
                        "adopted"
                    } else if !sig_stable {
                        "refused:signature"
                    } else if !no_collision {
                        "refused:collision"
                    } else if networked {
                        "refused:network"
                    } else if cand.is_empty() || insns.is_empty() {
                        "refused:no-candidate"
                    } else if mosura::recompile::watsched::order_regressed(&insns, &cand) {
                        "refused:scheduler"
                    } else {
                        "refused:allocation"
                    };
                    mosura::debug!(mosura::debug::Topic::Watsched, "zapcheck {name}: {reason}");
                }
                if ok {
                    f = Some(f_forced.unwrap_or(f2));
                    f_from_pp = true;
                }
            }
        }
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
        if mosura::debug::on(mosura::debug::Topic::Survey) {
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
        // DROPPED PARAMETERS (a convention fact from the function's own saves, applied by the
        // port as the `dropped_params` mark): a register this function pushes at entry and pops
        // before its returns is not an argument register — the last parameter the decompiler
        // recovered in it, when it only flows into callees, is the caller's preserved value
        // (`buildconfig::phantom_params_from_evidence`).
        let f = {
            let mut f = f;
            let insns = mosura::recompile::insn::normalize(SURVEY_LANG, &region, *va, &mosura::recompile::insn::NoReloc).unwrap_or_default();
            f.dropped_params = mosura::recompile::buildconfig::phantom_params_from_evidence(&f, &insns);
            // a `RETF` return declares the function `far`; a `RET n` popping slots no parameter
            // reads declares the popped slots as unused stack parameters
            f.far_return = mosura::recompile::buildconfig::far_return_from_evidence(&insns);
            // a parameter the original copies into a byte register at entry and the IR only
            // masks is declared at that width
            f.narrow_params = mosura::recompile::buildconfig::narrow_params_from_evidence(&f, &insns);
            f.extra_stack_params = mosura::recompile::buildconfig::dummy_stack_params(&f);
            f
        };

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
        // ram addresses THIS FUNCTION STORES, read from its OWN BYTES.  Two IR-side tests were
        // tried and both failed: `is_written()` is true for a purely read global (heritage gives it
        // an INDIRECT across every call and a phi at every join), and excluding INDIRECT/MULTIEQUAL
        // defs still let the return-guard COPY through -- 54 read-only TUs were widened either way.
        // The instruction stream has no such ambiguity: a store is a memory operand in the output.
        let own_norm = if global_width_arm {
            mosura::recompile::insn::normalize(SURVEY_LANG, &region, *va, &mosura::recompile::insn::NoReloc).unwrap_or_default()
        } else {
            Vec::new()
        };
        let gwrote: std::collections::HashSet<u64> = own_norm
            .iter()
            .flat_map(|x| x.sem.iter())
            .filter_map(|op| match &op.out {
                Some(mosura::recompile::insn::SemArg::Mem(_, a, _)) => Some(*a),
                _ => None,
            })
            .collect();
        // the widest GENUINE read of each absolute address in this function's own bytes: a
        // dword read followed by `SAR r,0x10` is this compiler's sign-extension of the SHORT two
        // bytes above (the dword trick), not a four-byte object at that address (measured: the
        // trick's reads widened three array bases to `int`, round e28)
        let mut own_read_w: std::collections::HashMap<u64, u32> = Default::default();
        for (k, x) in own_norm.iter().enumerate() {
            // the trick's `SAR` may sit a couple of instructions after its load (scheduled)
            let trick = x.text.strip_prefix("MOV E").and_then(|r| r.split(',').next()).is_some_and(|reg| {
                let sar = format!("SAR E{reg},0x10");
                own_norm[k + 1..(k + 4).min(own_norm.len())].iter().any(|y| y.text == sar)
            });
            if trick {
                continue;
            }
            for op in &x.sem {
                for arg in &op.ins {
                    if let mosura::recompile::insn::SemArg::Mem(_, a, sz) = arg {
                        let e = own_read_w.entry(*a).or_insert(0);
                        *e = (*e).max(*sz);
                    }
                }
            }
        }
        let mut gsizes_max: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
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
            gsizes_max
                .entry(vn.loc.offset)
                .and_modify(|e| *e = (*e).max(vn.size))
                .or_insert(vn.size);
        }
        // ARM (`MOSURA_GLOBAL_WIDTH=witnessed`): the narrowest-access rule above truncates a
        // store the original makes wide whenever one function touches an address at two widths.
        // Widen back to the original's own STORE width, but only where the image also READS it
        // wider than we would store -- the wrong-code criterion, and the condition that keeps this
        // off addresses that are merely accessed at two widths.  Never narrows: `max` only.
        //
        // AND ONLY WHERE THIS FUNCTION WRITES THE ADDRESS.  Measured on the first armed emit: without
        // this the arm widened the declaration in every TU that merely READS the global, and the
        // widened type then propagated through type inference into local declarations and even
        // comparison rendering -- 138 TUs changed where only 27 had a truncated store to fix.  A
        // read-only TU has nothing to repair: its byte read of a byte it uses is already right.
        if global_width_arm {
            for (a, w) in gsizes.iter_mut() {
                // A READ-ONLY global this function reads at two IR widths, its own bytes reading
                // it at the wider one (`MOV BX,word ptr [g]` for the divisor, `MOV AL,[g]` for the
                // byte factor, WAR2 FUN_000377a4): declared at the wider width, the narrower reads
                // print as casts of the same bytes — probed EXACT. The same-function two-width
                // gate keeps this off the 138 read-only TUs the blanket widening moved.
                if let (Some(&mx), Some(&rw)) = (gsizes_max.get(a), own_read_w.get(a)) {
                    if mx > *w && rw >= mx && !gwrote.contains(a) {
                        *w = mx;
                        continue;
                    }
                }
                if !gwrote.contains(a) {
                    continue;
                }
                let sw = ram_store_w.get(a).copied().unwrap_or(0);
                let rw = ram_read_w.get(a).copied().unwrap_or(0);
                if sw > *w && rw > *w {
                    *w = sw;
                }
            }
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
        let stack_convention = (!proto.params.is_empty()
            && proto.params.iter().all(|p| {
                f.spaces.get(p.addr.space).kind == mosura::decompile::space::SpaceKind::Spacebase
            }))
            || f.extra_stack_params > 0;
        // The callee's stack-cleanup contract, read from its own return instruction — and read
        // the SAME WAY THE CALLERS READ IT, which is the whole point of using `ret_pop` here.
        //
        // This used to lift the function's own byte region and scan it linearly for a `RET`. A
        // caller decides the same fact with `analysis::decompiler::callee_cleanup`, which walks
        // the callee's CFG from its entry — so for a function whose epilogue is a tail `JMP` into
        // a SHARED epilogue the two disagreed: the linear scan finds no return at all and the
        // callee-pops DEFAULT stood, while the walk follows the jump, finds the bare `RET`, and
        // the caller emits `parm caller []` plus its `ADD ESP,n`. BOTH SIDES THEN POP, and every
        // such call unbalances the stack by 4n bytes — emitted wrong code, in 55 of the 77
        // functions declaring `parm []` (152 caller TUs), unanimous per callee.
        //
        // `Funcdata::ret_pop` is that same CFG walk's answer for THIS function, already computed
        // in the decompile that just ran — so consulting it closes the disagreement at its source.
        //
        // But the walk is the FALLBACK, not the replacement, and that ordering is measured rather
        // than assumed. Reading `ret_pop` alone also flipped 8 functions the other way, and their
        // originals end in a bare `RET` while the walk had them popping: `FUN_00069980` got
        // `RET 0x4`, `FUN_0006cfd0` `RET 0x8`, `FUN_00079130` `RET 0x18`. All 8 are shared-epilogue
        // library code, where following control flow out of the function reaches a return that is
        // not this function's contract. A return in the function's OWN body is direct evidence and
        // outranks it.
        //
        // So: the function's own returns decide when it has any; the walk answers only when the
        // body is SILENT, which is exactly the tail-JMP case that produced the defect. The two
        // sides can then still differ in principle — but only where the definition has evidence the
        // caller's reading lacks, which is the direction that is safe.
        //
        // SILENT is not the same as UNDECIDED, and the difference is load-bearing.
        // `callee_stack_cleanup` answers `None` both for a body with no return at all and for one
        // whose returns DISAGREE — and a single function has a single pop-contract, so disagreement
        // is not two contracts, it is the region boundary having swallowed a neighbour's `RET`.
        // That is the same boundary error that made the walk wrong above, so it must not fall
        // through to the walk: an undecided body declares nothing and is counted, which turns a
        // silent mis-attribution into a visible one.
        let own = esp_off
            .zip(mosura::sleigh::disassemble(SURVEY_LANG, &region, *va).ok())
            .map(|(sp, insns)| mosura::recompile::own_pop_contract(&insns, sp))
            .unwrap_or(mosura::recompile::OwnPopContract::Silent);
        if own == mosura::recompile::OwnPopContract::Undecided {
            cleanup_undecided += 1;
        }
        let cleanup = mosura::recompile::declared_pop_contract(own, f.ret_pop);
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
        // A STACK-CONVENTION callee (`parm []`, every recovered parameter on the stack) needs the
        // same clause in every caller: without it the caller compiles the call under the register
        // convention and passes in EAX what the original PUSHes (measured: FUN_00030dc8's
        // `func_0x00060ad0(0)` — `XOR EAX,EAX ; CALL` for the original's `PUSH 0 ; CALL`). The
        // callee's own clause is `parm []` or `parm caller []` by its pop contract; the caller's
        // `parm caller []` comes from its own call spec (`cs.caller_cleans`), so only the
        // callee-pops form is propagated here — the existing-clause rule in the post-pass keeps a
        // caller-cleaned line as it is.
        let stack_decl = (stack_convention && !matches!(cleanup, Some(0))).then(|| "[]".to_string());
        parm_map.insert(
            *va,
            nondefault_parm_regs(&f, &watreg).or(stack_decl).map(|decl| {
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
            let (atu, _) = build_tu(&ac, *va, false, &gsizes, &Default::default(), &Default::default(), &[]);
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
            // The whole recovered rendering, as a function of the Funcdata, so the shared-return
            // arm below can render an alternative decompile of the same world under identical
            // per-site decisions and choose between the two texts.
            let render = |f: &Funcdata| -> String {
            let insns = mosura::recompile::insn::normalize(
                SURVEY_LANG,
                &region,
                *va,
                &mosura::recompile::insn::NoReloc,
            )
            .unwrap_or_default();
            let mut order_parms: std::collections::BTreeMap<u64, String> = Default::default();
            // PER-FUNCTION RECOVERY (recompile::recovery, review R5 commit a): the report pass, the
            // `*_from_evidence` witnesses over this function's instructions and the second evidence
            // round, one library fn shared with the gcc ground-truth oracle. The argument-order
            // derivation stays here as the closure: it reads the survey's cross-function tables
            // (site_orders, order_excluded, arg_reg_offs, watreg) and fills `order_parms`.
            let recovered = mosura::recompile::recovery::recover(&f, &insns, &arms[0], &rec_arm, |report| {
                // ARGUMENT-ORDER RECOVERY: apply each site's own recovered declaration order.
                // The rendered argument list permutes and the TU declares the matching
                // `parm [..]` pragma. The pragma rebinds EVERY call to that callee in the TU,
                // so all of a callee's sites here must derive the SAME order and every one
                // must qualify (its own evidence present, arity matching, every argument
                // reorder-safe) — one failing site vetoes the callee for the whole TU.
                let mut call_arg_orders: std::collections::HashMap<u64, Vec<usize>> = Default::default();
                // Per-callee `parm [..]` clauses from param-order recovery — merged below with the
                // caller-pops and modify clauses into ONE `#pragma aux` per callee: Watcom treats a
                // second `#pragma aux` for the same symbol as a REPLACEMENT, so split emission
                // would silently drop whichever clause came first.
                {
                    let mut by_callee: std::collections::BTreeMap<u64, Vec<(u64, &Vec<bool>)>> =
                        Default::default();
                    for (addr, callee, safe) in &report.port.call_order_candidates {
                        by_callee.entry(*callee).or_default().push((*addr, safe));
                    }
                    for (callee, csites) in by_callee {
                        if callee == *va || order_excluded.contains(&callee) {
                            continue;
                        }
                        let mut tu_p: Option<&Vec<u64>> = None;
                        let ok = csites.iter().all(|(addr, safe)| {
                            let Some(p) = site_orders.get(addr) else { return false };
                            let n = p.len();
                            if n > arg_reg_offs.len() || safe.len() != n || !safe.iter().all(|&s| s) {
                                return false;
                            }
                            let mut sp: Vec<u64> = p.clone();
                            sp.sort_unstable();
                            let mut sd: Vec<u64> = arg_reg_offs[..n].to_vec();
                            sd.sort_unstable();
                            if sp != sd {
                                return false;
                            }
                            match tu_p {
                                None => {
                                    tu_p = Some(p);
                                    true
                                }
                                Some(q) => q == p,
                            }
                        });
                        let Some(p) = tu_p else { continue };
                        if !ok {
                            continue;
                        }
                        let n = p.len();
                        let default = &arg_reg_offs[..n];
                        let perm: Vec<usize> =
                            p.iter().map(|r| default.iter().position(|d| d == r).unwrap()).collect();
                        for (addr, _) in &csites {
                            call_arg_orders.insert(*addr, perm.clone());
                        }
                        let names: Vec<&str> = p
                            .iter()
                            .filter_map(|r| {
                                watreg.iter().find(|&&(o, sz, _)| o == *r && sz == 4).map(|t| t.2)
                            })
                            .collect();
                        if names.len() == n {
                            order_parms.insert(callee, format!("parm [{}]", names.join("] [")));
                        }
                    }
                }
                call_arg_orders
            });
            let recovered = {
                let mut r = recovered;
                for a in &arms_off {
                    r.switch_off(a).expect("--arms-off names were checked at startup");
                }
                r
            };
            // the interleave census (was `MOSURA_ILV_CENSUS`): a diagnostic, so under the facility's
            // `recover` topic like its siblings (review R6, commit 3b); it also reports the orders the
            // parked lever would apply -- printc::interleave_orders keeps its caller here since the
            // blind form's switch went
            if mosura::debug::on(mosura::debug::Topic::Recover) {
                for (pa, pb, k) in mosura::decompile::printc::interleave_census(&f, &insns) {
                    mosura::debug!(mosura::debug::Topic::Recover, "ilv {name} {pa:#x} {pb:#x} {k}");
                }
                let mut orders: Vec<_> = mosura::decompile::printc::interleave_orders(&f, &insns).into_iter().collect();
                orders.sort_by_key(|(op, _)| op.0);
                for (op, order) in orders {
                    mosura::debug!(mosura::debug::Topic::Recover, "ilv {name} order at op {} -> {:?}", op.0, order.iter().map(|o| o.0).collect::<Vec<_>>());
                }
            }
            let rc = mosura::decompile::printc::print_c_recovered(&f, &rec_arm, &recovered);
            // VOLATILE RECOVERY: globals whose original store sites show the blocked order
            // (see buildconfig::volatile_globals_from_evidence) declare volatile in this TU.
            let volatiles =
                mosura::recompile::buildconfig::volatile_globals_from_evidence(&insns);
            // VARARG CALLEES: targets of calls the decompiler recovered as caller-cleaned
            // (`CallSpec::caller_cleans` — evidence: the callee's RET pops nothing AND the
            // original fallthrough is `ADD ESP,n`), each with its own recovered modify set
            // (`CallSpec::cdecl_modify`). The pragma is pre-rendered here because the register
            // NAMES come from the same spec-built table as every other contract
            // (`own_contract`'s); a blanket kill set was measured wrong in BOTH directions —
            // without `modify` Watcom assumes preserves-all and drops the 191b8 family's
            // prologue saves; with a uniform `modify [eax ebx ecx edx]` it invents saves the
            // 0x31c60 family's originals do not have (6 EXACT lost). Per-callee evidence is the
            // only shape that fits both.
            // ONE `#pragma aux` spec per callee, merging every recovered contract clause:
            //   parm [..]        — param-order recovery (order_parms above), register callees;
            //   parm caller []   — caller-cleaned (cdecl/vararg) callees;
            //   modify [..]      — the callee's own recovered clobber set, EVERY callee that
            //                      has one (`CallSpec::cdecl_modify`): a bare extern under
            //                      Watcom's default (save = HW_FULL) claims preserves-all, and
            //                      the recompiler hoists argument setups across calls the
            //                      original could not (FUN_00011b9c / callee 0x1f734).
            let mut callee_aux: HashMap<u64, (Option<String>, Option<String>)> = HashMap::new();
            // EXACTNESS (contract-design Increment 2): recovered in the analysis
            // (CallSpec::cdecl_exact — an argument register surviving its own call on the
            // raw CFG, arity from the whole-program prototype recovery). One site's
            // testimony covers the TU's single declaration.
            let exact_callees: std::collections::HashSet<u64> = f
                .call_specs
                .iter()
                .filter(|(_, cs)| cs.cdecl_exact)
                .filter_map(|(&op, _)| {
                    let t = f.op(op).input(0)?;
                    let va = f.vn(t).loc.offset;
                    (va != 0).then_some(va)
                })
                .collect();
            // DETERMINISTIC per-callee merge. `f.call_specs` is a HashMap, and the old
            // last-writer-wins fold made the TU's single pragma a RANDOM DRAW whenever two
            // sites of one callee carried different recovered specs (caller 0x3342c's
            // 0x63be5: one site caller_cleans+6-reg blanket, one site 5-reg transitive —
            // emitted `modify exact [eax]` or `[eax ecx]` depending on hash order; the
            // standing few-function jitter between byte-identical rounds). Merge instead:
            // sites in sorted op order, caller_cleans from ANY site that has it (cdecl
            // evidence anywhere is cdecl everywhere), modify = UNION of the sites' sets —
            // the one declaration must be sound for every site it covers.
            let mut merged: HashMap<u64, (bool, Option<std::collections::BTreeSet<u64>>)> =
                HashMap::new();
            let mut sites: Vec<u32> = f.call_specs.keys().map(|op| op.0).collect();
            sites.sort_unstable();
            for opi in sites {
                let op = mosura::decompile::op::OpId(opi);
                let cs = &f.call_specs[&op];
                let Some(t) = f.op(op).input(0) else { continue };
                let va = f.vn(t).loc.offset;
                if va == 0 {
                    continue;
                }
                mosura::debug!(mosura::debug::Topic::Survey, "callee {va:#x} caller_cleans={:?} cdecl_modify={:?}", cs.caller_cleans, cs.cdecl_modify.as_ref().map(|m| m.len()));
                let e = merged.entry(va).or_default();
                e.0 |= cs.caller_cleans.unwrap_or(0) > 0;
                if let Some(m) = cs.cdecl_modify.as_ref() {
                    e.1.get_or_insert_with(Default::default).extend(m.iter().copied());
                }
            }
            for (va, (cleans, modify)) in merged {
                let e = callee_aux.entry(va).or_default();
                if cleans {
                    e.0 = Some("parm caller []".to_string());
                }
                if let Some(m) = modify {
                    let mut regs: Vec<&str> = m
                        .iter()
                        .filter_map(|off| {
                            watreg.iter().find(|&&(o, sz, _)| o == *off && sz == 4).map(|t| t.2)
                        })
                        .filter(|r| *r != "ebp" && *r != "esp")
                        .collect();
                    // EAX is the return register — always in the contract even for a callee
                    // whose body the walk saw writing nothing else.
                    if !regs.contains(&"eax") {
                        regs.push("eax");
                    }
                    regs.sort();
                    regs.dedup();
                    let kw = if exact_callees.contains(&va) { "modify exact" } else { "modify" };
                    e.1 = Some(format!("{kw} [{}]", regs.join(" ")));
                }
            }
            // A callee can carry a recovered param order without any CallSpec entry (the
            // contract walks all failed) — its pragma must still be emitted.
            let mut callee_aux = callee_aux;
            for &va in order_parms.keys() {
                callee_aux.entry(va).or_default();
            }
            let vararg_callees: HashMap<u64, String> = callee_aux
                .into_iter()
                .filter_map(|(va, (cleans, modify))| {
                    let parm = cleans.or_else(|| order_parms.get(&va).cloned());
                    let spec = match (parm, modify) {
                        (Some(p), Some(m)) => format!("{p} {m}"),
                        (Some(p), None) => p,
                        (None, Some(m)) => m,
                        (None, None) => return None,
                    };
                    Some((va, spec))
                })
                .collect();
            let (rc, aggregates) = aggregate_ram_globals(&rc, &insns, &gsizes, &volatiles);
            if mosura::debug::on(mosura::debug::Topic::Survey) && !aggregates.is_empty() {
                for (_, d) in &aggregates {
                    mosura::debug!(mosura::debug::Topic::Survey, "agg {name}: {d}");
                }
            }
            let (rtu, _) = build_tu(&rc, *va, false, &gsizes, &volatiles, &vararg_callees, &aggregates);
            let rtu = match &contract {
                Some(decl) => format!("#pragma aux {name} {decl};\n{rtu}"),
                None => rtu,
            };
            // The permuted argument order is value-identical only under its pragma — the two
            // are one decision, emitted together (see call_arg_orders above).
            // order_parms are folded into the per-callee pragma inside build_tu now.
            rtu
            };
            let rtu = render(&f);
            // SHARED-RETURN ARM (allocator thread; re-earns the ActionReturnSplit doctrine
            // trade): where Ghidra's split fired, render the same world WITHOUT the split and
            // keep that rendering iff it is fully structured (no goto, no label). The split is
            // Ghidra's goto elimination — where the unsplit form already has no goto the split
            // only deforms structure (do-while -> while(true)+returns; 3e038/6fd88 lost EXACT/
            // SAME_SHAPE to it), and where the unsplit form needs gotos the split repairs it
            // (1ea4c/462d0/463fc gained EXACT from it). Measured on the six trade members:
            // the rule separates 5 of 6; the sixth (4d0f8) is the recorded do-while
            // structuring gap. MOSURA_SHARED_RET=0 disables.
            let rtu = if f.return_splits > 0 && std::env::var("MOSURA_SHARED_RET").as_deref() != Ok("0") {
                mosura::decompile::blockjoin::set_skip_return_split(true);
                let alt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    match (f_from_pp, prog_pp.as_ref()) {
                        (true, Some(pp)) => decompile_function(pp, Address::new(ram, *va)),
                        _ => decompile_function(&prog, Address::new(ram, *va)),
                    }
                }));
                mosura::decompile::blockjoin::set_skip_return_split(false);
                match alt {
                    Ok(Some(fa)) => {
                        let t = render(&fa);
                        let structured = !t.contains("goto ") && !t.contains("LAB_");
                        mosura::debug!(mosura::debug::Topic::Survey, "sharedret {name}: splits={} unsplit structured={structured} -> {}", f.return_splits, if structured { "UNSPLIT" } else { "split" });
                        if structured { t } else { rtu }
                    }
                    _ => rtu,
                }
            } else {
                rtu
            };
            if only.is_empty() {
                std::fs::write(dir.join(format!("{idx:05}.c")), &rtu).unwrap();
            } else {
                println!("/* ===== RECOVERED (no-compiler field path) ===== */");
                println!("{rtu}");
            }
        }
        let (tu, mut smells) = build_tu(&c, *va, false, &gsizes, &Default::default(), &Default::default(), &[]);
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
            if mosura::debug::on(mosura::debug::Topic::RawIr) {
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
        // the not-C classification reads the original's decoded instructions (see kind_of_insns)
        let norm_insns_for_kind =
            mosura::recompile::insn::normalize(SURVEY_LANG, &region, *va, &mosura::recompile::insn::NoReloc)
                .unwrap_or_default();
        writeln!(
            mf,
            "{idx:05}\t{va:08x}\t{name}\tOK\t{orig_len}\t{cov_lo:08x}\t{cov_hi:08x}\t{}\t{orig_hex}\t{ir_calls}\t{blocks_cfg}\t{blocks_reached}\t{}\t{}",
            smells.join(","),
            kind_of_insns(name, &norm_insns_for_kind),
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
                // A TU may ALREADY declare `#pragma aux` for this callee (build_tu's
                // recovered contract clauses: `parm caller []` and/or `modify [..]`). Watcom
                // treats a SECOND `#pragma aux` for the same symbol as a REPLACEMENT, so the
                // parm clause must be MERGED INTO the existing line, never prepended beside
                // it — the prepended form silently destroyed the order recovery of every
                // modify-annotated callee (measured: the nine-sibling 0x392xx family lost
                // EXACT, FUN_0003925c's `parm [edx] [eax]` replaced by `modify [eax edx]`).
                // An existing line that already carries a `parm` clause wins outright (the
                // per-site order recovery and the caller-cleaned contract both outrank the
                // definition-side default order).
                let mut prepend = String::new();
                let mut merges: Vec<(String, String)> = Vec::new();
                for cva in ext_re(&src) {
                    let Some((decl, psizes)) = parm_map.get(&cva).and_then(|d| d.as_ref())
                    else {
                        continue;
                    };
                    // arity AND width gate: every call site in this TU must pass exactly
                    // the pragma's parameter count, each argument at the parameter's own
                    // width. A width mismatch is as fatal as an arity one — a 16-bit
                    // `parm [bx]` meeting a 4-byte argument overflows it to the STACK
                    // (measured: FUN_0002c8xx's `PUSH 0xc` where the original loads EBX).
                    let Some(asizes) = caller_va
                        .and_then(|va| caller_calls.get(va))
                        .and_then(|m| m.get(&cva))
                        .cloned()
                        .flatten()
                    else {
                        continue;
                    };
                    // Per slot the pragma register must be AT LEAST the argument's width:
                    // a narrower argument binds the register's low part (measured EXACT —
                    // the byte index into `parm [edx]`), while a narrower REGISTER
                    // overflows the argument to the stack (the `parm [bx]` failure above).
                    // A STACK-convention callee (`parm []`) takes every argument in a
                    // 4-byte slot: the caller pushes the promoted value and the callee reads
                    // its own width off the slot, so a `char` parameter meeting a 4-byte
                    // argument is the normal case, not an overflow (FUN_00030dc8's `PUSH 0`
                    // for FUN_00060ad0's byte parameter, one row from EXACT without the
                    // clause) — arity gates, width does not.
                    let stack_slots = decl == "[]";
                    if !(asizes.len() == psizes.len()
                        && (stack_slots || asizes.iter().zip(psizes).all(|(a, p)| a <= p)))
                    {
                        continue;
                    }
                    let tag = format!("#pragma aux func_0x{cva:08x} ");
                    match src.lines().find(|l| l.starts_with(&tag)) {
                        Some(l) if l.contains(" parm ") => {}
                        Some(l) => merges.push((
                            l.to_string(),
                            format!("{tag}parm {decl} {}", &l[tag.len()..]),
                        )),
                        None => {
                            prepend.push_str(&format!("#pragma aux func_0x{cva:08x} parm {decl};\n"))
                        }
                    }
                }
                if !prepend.is_empty() || !merges.is_empty() {
                    let mut out = src.clone();
                    for (from, to) in &merges {
                        out = out.replacen(from.as_str(), to.as_str(), 1);
                    }
                    std::fs::write(&path, format!("{prepend}{out}")).unwrap();
                    patched += 1;
                }
            }
        }
        eprintln!("caller-side parm pragmas: {patched} TU(s) patched");
    }
    eprintln!("EMIT done: ok={ok} fail={fail} in {:?}", t0.elapsed());
    if cleanup_undecided > 0 {
        eprintln!(
            "stack-cleanup UNDECIDED: {cleanup_undecided} function(s) whose own returns disagree \
             about the pop — a single function has one contract, so this is the region boundary \
             taking in a neighbour's RET. They declare no convention rather than guess one."
        );
    }
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
    // R4: the corpus gates over what was just written (`recompile::gates`) — a violation FAILS the
    // round, and the tree stays on disk as the evidence. Gates 1–3 on any emit; 4–6 only on a full
    // one (a `--only` probe's partial tree would misfire the corpus-level bars and sets); the scope
    // for the string-ops bar is the manifest's `kind`. `--no-gates` for diagnostics only.
    if let Some(dir) = &recovered_dir {
        if !rest.iter().any(|a| a == "--no-gates") {
            use mosura::recompile::gates;
            let baseline = gates::Baseline::load(&mosura::paths::corpus_gates_file()).unwrap_or_else(|e| {
                eprintln!("corpus gates baseline: {e}");
                std::process::exit(2)
            });
            let tus = gates::load_tree(&manifest_path, dir).unwrap_or_else(|e| {
                eprintln!("corpus gates: {e}");
                std::process::exit(2)
            });
            let reports = gates::run_text_gates(&tus, &gates::kind_is_user, &baseline, !probing);
            eprint!("{}", gates::render(&reports));
            if gates::any_failed(&reports) {
                eprintln!("corpus gates: FAIL — the tree stays at {} for the read", dir.display());
                std::process::exit(1);
            }
            eprintln!("corpus gates: OK ({} TUs)", tus.len());
        }
    }
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
/// The candidate per-call register effects for the zap checker: for each direct call with
/// a recovered contract, OW `CallZap`'s arithmetic (i86reg.c:256) under the candidate
/// declarations — writes = kill set ∪ (parm.used ∪ EAX unless `exact`), reads = parm.used
/// (this call's register-located argument inputs). Calls without a contract get no entry
/// and keep the model's conservative fixed behavior.
fn candidate_call_effects(f: &Funcdata) -> mosura::recompile::watsched::CallEffects {
    let mut out = mosura::recompile::watsched::CallEffects::new();
    let Some(reg) = f.spaces.by_name("register") else { return out };
    for opid in f.op_ids() {
        let o = f.op(opid);
        if o.code() != OpCode::Call || o.flags & (flags::DEAD | flags::MARKER) != 0 {
            continue;
        }
        let Some(cs) = f.call_specs.get(&opid) else { continue };
        let Some(kill) = cs.cdecl_modify.as_ref() else { continue };
        let parms: Vec<(u64, u32)> = (1..o.num_inputs())
            .filter_map(|i| o.input(i))
            .filter_map(|v| {
                let vn = f.vn(v);
                (vn.loc.space == reg && vn.loc.offset < 0x20)
                    .then_some((vn.loc.offset, vn.size))
            })
            .collect();
        let mut writes: Vec<(u64, u32)> =
            kill.iter().filter(|&&k| k < 0x20).map(|&k| (k & !3, 4)).collect();
        if !cs.cdecl_exact {
            for &(p, sz) in &parms {
                writes.push((p, sz));
            }
            writes.push((0, 4));
        }
        writes.sort_unstable();
        writes.dedup();
        out.insert(o.seqnum.pc.offset, (parms, writes));
    }
    out
}

/// The allocator cost kernel's ZERO-COST special case (phase 2 of the register-allocator
/// model; OW regalloc.c GiveBestReg/CountRegMoves grounding): an upgrade whose ONLY effect
/// is appending pass-through arguments in their own arrival registers adds no
/// register-register moves and no conflict-graph edges, so the allocator's assignment is
/// provably unchanged — CalcSavings needn't be computed when its delta is zero. Decided on
/// the RENDERED text of the landed vs candidate decompiles, line-zipped strictly:
///
///   - callee `#pragma aux func_0x...` lines may differ (they ARE the arity/exactness
///     recovery being adopted);
///   - the own signature may only APPEND `xunknown4 param_N` parameters (an existing
///     param's storage or TYPE changing — 34fe0's char→xunknown4 — refuses);
///   - a call may only APPEND `param_N` arguments, each at argument position N−1: the
///     position IS the register (Watcom slots args by position), and position N−1 means
///     the value is consumed in the register it arrives in — a self-move. A duplicated or
///     displaced param (5ed78's `(p1,p2,p3,p1)`), a reordered prefix (659ec, 73338), or
///     any other body change refuses. A CONSTANT literal may append at any position: the
///     prototype pass binds it from the ORIGINAL's own dataflow, so the materializing
///     `MOV imm` already exists in the original bytes (6b4e0's `(0xa8744, 4)`) — declaring
///     it moves nothing;
///   - the own `#pragma aux FUN_...` line must be IDENTICAL (73338's upgrade silently
///     dropped its `parm caller []` fact);
///   - any other differing line, or a line-count change, refuses.
///
/// Measured on the force-adoption census (x-alloc round, 2026-08-22): adopts exactly the
/// 3 gains {26b18, 294dc, 6b4e0}, refuses all 6 protected EXACTs.
/// Shadow-census tightening: every callee-pragma line that CHANGES between the landed
/// and candidate renders must keep everything before its `modify` clause verbatim — the
/// `parm [..]` / `parm caller []` half is the caller-side marshalling contract, and a
/// changed one re-pairs positional arguments (the 3925c inversion wart).
fn parm_clauses_stable(landed: &str, cand: &str) -> bool {
    let ll: Vec<&str> = landed.lines().collect();
    let cl: Vec<&str> = cand.lines().collect();
    if ll.len() != cl.len() {
        return false;
    }
    for (l, c) in ll.iter().zip(cl.iter()) {
        if l == c || !l.starts_with("#pragma aux func_0x") {
            continue;
        }
        let head = |x: &str| x.split(" modify").next().unwrap_or(x).to_string();
        if head(l) != head(c) {
            return false;
        }
    }
    true
}

/// Order-changing census (missing-args thread): the render delta consists ONLY of call
/// lines whose top-level argument lists hold the SAME multiset in a DIFFERENT order —
/// every other line verbatim. Returns the callees of the permuted calls.
fn order_only_delta(landed: &str, cand: &str) -> Option<Vec<u64>> {
    let ll: Vec<&str> = landed.lines().collect();
    let cl: Vec<&str> = cand.lines().collect();
    if ll.len() != cl.len() {
        return None;
    }
    let args_of = |line: &str| -> Option<(u64, Vec<String>)> {
        let i = line.find("func_0x")?;
        let callee = u64::from_str_radix(line.get(i + 7..i + 15)?, 16).ok()?;
        let open = line[i..].find('(')? + i;
        let mut depth = 0i32;
        let mut end = None;
        for (j, ch) in line[open..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + j);
                        break;
                    }
                }
                _ => {}
            }
        }
        let inner = &line[open + 1..end?];
        let mut args = Vec::new();
        let (mut d, mut start) = (0i32, 0usize);
        for (j, ch) in inner.char_indices() {
            match ch {
                '(' | '[' => d += 1,
                ')' | ']' => d -= 1,
                ',' if d == 0 => {
                    args.push(inner[start..j].trim().to_string());
                    start = j + 1;
                }
                _ => {}
            }
        }
        if !inner[start..].trim().is_empty() {
            args.push(inner[start..].trim().to_string());
        }
        Some((callee, args))
    };
    let mut callees = Vec::new();
    for (l, c) in ll.iter().zip(cl.iter()) {
        if l == c {
            continue;
        }
        let (Some((k1, mut a1)), Some((k2, mut a2))) = (args_of(l), args_of(c)) else { return None };
        if k1 != k2 || a1.len() != a2.len() || a1 == a2 {
            return None;
        }
        // outside the arg lists the lines must agree
        let strip = |line: &str, args: &[String]| -> String {
            let mut t = line.to_string();
            for a in args {
                t = t.replacen(a.as_str(), "", 1);
            }
            t
        };
        if strip(l, &a1) != strip(c, &a2) {
            return None;
        }
        a1.sort();
        a2.sort();
        if a1 != a2 {
            return None; // different multiset — not a pure permutation
        }
        callees.push(k1);
    }
    if callees.is_empty() { None } else { Some(callees) }
}

fn pass_through_only(landed: &str, cand: &str, va: u64) -> bool {
    pass_through_report(landed, cand, va, None, None)
}

fn pass_through_report(landed: &str, cand: &str, va: u64, mut consts: Option<&mut Vec<(u64, u32, u64)>>, mut stack_appends: Option<&mut Vec<(u64, u32)>>) -> bool {
    let fun = format!("FUN_{va:08x}");
    let own_pragma = format!("#pragma aux {fun}");
    let ll: Vec<&str> = landed.lines().collect();
    let cl: Vec<&str> = cand.lines().collect();
    if ll.len() != cl.len() {
        return false;
    }
    let param_at = |args: &str, from: usize| -> Option<u32> {
        // the appended text at `from` must be `param_<N>` up to `,` or `)`
        let rest = &args[from..];
        let rest = rest.strip_prefix(", ").unwrap_or(rest);
        let num = rest.strip_prefix("param_")?;
        let digits: String = num.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse().ok()
    };
    for (l, c) in ll.iter().zip(cl.iter()) {
        if l == c {
            continue;
        }
        if l.starts_with(&own_pragma) || c.starts_with(&own_pragma) {
            return false; // own contract facts must survive verbatim
        }
        if l.starts_with("#pragma aux func_0x") && c.starts_with("#pragma aux func_0x") {
            continue; // the callee-contract recovery itself
        }
        // First divergence: the candidate may only INSERT `param_N` arguments where the
        // landed line closes an argument list.
        let d = l.bytes().zip(c.bytes()).take_while(|(a, b)| a == b).count();
        let (ltail, ctail) = (&l[d..], &c[d..]);
        // signature growth out of `(void)`
        let is_sig = l.contains(&format!(" {fun}("));
        if is_sig && ltail.starts_with("void)") && ctail.starts_with("xunknown4 param_") {
            // candidate params must be exactly `xunknown4 param_1..param_K)`+same suffix
            let suffix = &ltail["void".len()..];
            let Some(body) = ctail.strip_suffix(suffix) else { return false };
            let mut k = 1u32;
            let mut rest = body;
            loop {
                let Some(r) = rest.strip_prefix(&format!("xunknown4 param_{k}")) else { return false };
                if r.is_empty() {
                    break;
                }
                let Some(r) = r.strip_prefix(", ") else { return false };
                rest = r;
                k += 1;
            }
            continue;
        }
        // appended text: candidate tail = inserted + landed tail, inserted at a `)` boundary
        if !ctail.ends_with(ltail) {
            return false;
        }
        let inserted = &ctail[..ctail.len() - ltail.len()];
        if inserted.is_empty() {
            return false;
        }
        if is_sig {
            // appended params: `, xunknown4 param_N`* closing where the landed list closed
            if !ltail.starts_with(')') {
                return false;
            }
            let mut rest = inserted;
            while !rest.is_empty() {
                let Some(r) = rest.strip_prefix(", xunknown4 param_") else { return false };
                let digits: String = r.chars().take_while(|ch| ch.is_ascii_digit()).collect();
                if digits.is_empty() {
                    return false;
                }
                rest = &r[digits.len()..];
            }
            continue;
        }
        // appended call args at the close of an argument list
        if !ltail.starts_with(')') {
            return false;
        }
        // argument position of the first appended arg = top-level commas before `d` since
        // the call's opening paren (nesting-aware), or 0 straight after `(`
        let head = &l[..d];
        let open = {
            let mut depth = 0i32;
            let mut open = None;
            for (i, ch) in head.char_indices() {
                match ch {
                    '(' => {
                        depth += 1;
                        if depth == 1 {
                            open = Some(i);
                        }
                    }
                    ')' => depth -= 1,
                    _ => {}
                }
            }
            // the innermost still-open paren nearest `d`
            let mut depth = 0i32;
            let mut last_open = open;
            for (i, ch) in head.char_indices() {
                match ch {
                    '(' => {
                        depth += 1;
                        last_open = Some(i);
                    }
                    ')' => {
                        depth -= 1;
                    }
                    _ => {}
                }
            }
            let _ = depth;
            last_open
        };
        let Some(open) = open else { return false };
        let mut pos = 0u32;
        let mut depth = 0i32;
        let arg_head = &head[open + 1..];
        let empty_list = arg_head.trim().is_empty();
        for ch in arg_head.chars() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => pos += 1,
                _ => {}
            }
        }
        if !empty_list {
            pos += 1; // the appended arg comes after the existing ones
        }
        let mut at = 0usize;
        let mut rest = inserted;
        let is_const = |t: &str| -> bool {
            let t = t.strip_prefix('-').unwrap_or(t);
            if let Some(h) = t.strip_prefix("0x") {
                !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit())
            } else {
                !t.is_empty() && t.chars().all(|c| c.is_ascii_digit())
            }
        };
        while !rest.is_empty() {
            let elem = {
                let r = rest.strip_prefix(", ").unwrap_or(rest);
                let end = r.find([',', ')']).unwrap_or(r.len());
                &r[..end]
            };
            if !is_const(elem) && !elem.starts_with("param_") && stack_appends.is_some() {
                // STACK-APPEND class (stack-args frontier): an arbitrary expression element
                // is acceptable only when byte evidence backs it — the caller checks that
                // the original site PUSHes at least as many values as appended (the
                // const-evidence pattern, PUSH form). Reported for that check.
                let callee = l
                    .find("func_0x")
                    .and_then(|i| u64::from_str_radix(l.get(i + 7..i + 15)?, 16).ok())
                    .unwrap_or(0);
                if callee == 0 {
                    return false;
                }
                if let Some(out) = stack_appends.as_deref_mut() {
                    out.push((callee, pos));
                }
                let step = if at == 0 && empty_list { elem.to_string() } else { format!(", {elem}") };
                let Some(r) = rest.strip_prefix(&step) else { return false };
                rest = r;
                at += step.len();
                pos += 1;
                continue;
            }
            if is_const(elem) {
                // bound from the original's own dataflow — the MOV imm already exists
                if let Some(out) = consts.as_deref_mut() {
                    let t = elem.strip_prefix('-').unwrap_or(elem);
                    let v = if let Some(h) = t.strip_prefix("0x") {
                        u64::from_str_radix(h, 16).unwrap_or(0)
                    } else {
                        t.parse().unwrap_or(0)
                    };
                    let v = if elem.starts_with('-') { (v as i64).wrapping_neg() as u64 } else { v };
                    // The callee, for windowed byte-evidence: only direct `func_0x...` call
                    // lines qualify (an appended const on any other line form refuses).
                    let callee = l
                        .find("func_0x")
                        .and_then(|i| u64::from_str_radix(l.get(i + 7..i + 15)?, 16).ok())
                        .unwrap_or(0);
                    out.push((callee, pos, v));
                }
            } else {
                let Some(n) = param_at(inserted, at) else { return false };
                if n == 0 || n - 1 != pos {
                    return false; // not a self-move: value would need a register move
                }
            }
            let step = if at == 0 && empty_list { elem.to_string() } else { format!(", {elem}") };
            let Some(r) = rest.strip_prefix(&step) else { return false };
            rest = r;
            at += step.len();
            pos += 1;
        }
    }
    true
}


fn build_tu(
    c: &str,
    self_va: u64,
    non_contig: bool,
    gsizes: &std::collections::HashMap<u64, u32>,
    // Globals to declare `volatile` — a RECOVERED qualifier (buildconfig::
    // volatile_globals_from_evidence); empty for every rendering but the recovered one.
    volatiles: &HashSet<u64>,
    // Callees to declare VARARG (`extern int f(int, ...);`) — a RECOVERED linkage fact from the
    // decompiler's per-call model selection (`CallSpec::caller_cleans`: the original caller pops
    // this callee's arguments while the callee's own RET pops none). OW 1.0 cfeinfo.c:668 gives
    // a vararg function `CALLER_POPS | HAS_VARARGS` on top of the DEFAULT (watcall) aux info —
    // parms DefaultVarParms={0} (all on the stack), watcall save set, watcall `name_` objname —
    // so the ellipsis prototype alone reproduces the original's push/call/`add esp,K` sequence
    // and register saves, with linkage unchanged. Empty for every rendering but the recovered
    // one.
    vararg_callees: &HashMap<u64, String>,
    // Aggregated-global array declarations (`aggregate_ram_globals`): (base_name, decl_line).
    // The base name appears indexed in the body, so it must be declared as the array here and
    // kept out of the pointer/scalar classification; empty for every rendering but the
    // recovered one.
    aggregates: &[(String, String)],
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
        // The recovered caller-pops contract, by callee VA parsed back out of the rendered
        // name — expressed as a PRAGMA on the unprototyped declaration, NOT as an
        // `(int, ...)` prototype: `parm caller []` (empty register set = every argument on
        // the stack, `caller` = caller pops) reproduces OW's vararg call class
        // (CALLER_POPS|HAS_VARARGS over the default aux info, cfeinfo.c:668) while leaving
        // the call UNPROTOTYPED, so a pointer first argument stays legal. The prototype form
        // was measured first: its fixed `int` parameter made Watcom reject every TU whose
        // first argument is a pointer (E1071, 42 TUs — e.g. FUN_00011c98's
        // `func_0x0005a824(pxRam0008128c, ...)`).
        let va = f
            .strip_prefix("func_0x")
            .or_else(|| f.strip_prefix("FUN_"))
            .and_then(|h| u64::from_str_radix(h, 16).ok());
        if let Some(spec) = va.and_then(|va| vararg_callees.get(&va)) {
            decls.push_str(&format!("#pragma aux {f} {spec};\n"));
        }
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
    // Aggregated arrays declare here verbatim; their base names index into the body text, so
    // they would otherwise classify as pointer globals.
    let agg_names: HashSet<&str> = aggregates.iter().map(|(n, _)| n.as_str()).collect();
    for (_, d) in aggregates {
        names.insert(d.clone());
    }
    for (n, pfx) in &scalar_idents {
        if ptr_idents.contains(n) || declared_locals.contains(n.as_str()) || agg_names.contains(n.as_str()) {
            continue;
        }
        // Prefer the width the decompiler recovered for this address over the prefix's default.
        let ty = ram_addr_of(n)
            .and_then(|a| gsizes.get(&a).copied())
            .and_then(|sz| sized_ctype(*pfx, sz))
            .unwrap_or_else(|| ctype_for(*pfx).to_string());
        let vq = if ram_addr_of(n).is_some_and(|a| volatiles.contains(&a)) { "volatile " } else { "" };
        names.insert(format!("{vq}{ty} {n};"));
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
                || agg_names.contains(cap)
                || names.iter().any(|d| d.split_whitespace().any(|t| t.trim_end_matches(';') == cap))
            {
                continue;
            }
            let pfx = cap.as_bytes()[0] as char;
            let ty = ram_addr_of(cap)
                .and_then(|a| gsizes.get(&a).copied())
                .and_then(|sz| sized_ctype(pfx, sz))
                .unwrap_or_else(|| ctype_for(pfx).to_string());
            let vq = if ram_addr_of(cap).is_some_and(|a| volatiles.contains(&a)) { "volatile " } else { "" };
            extra.push(format!("{vq}{ty} {cap};"));
        }
        names.extend(extra);
    }
    for n in &ptr_idents {
        if declared_locals.contains(n.as_str()) || agg_names.contains(n.as_str()) {
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

/// GLOBAL AGGREGATION (allocator thread, lever 2): adjacent same-type scalar Ram globals that
/// the ORIGINAL's own instruction stream accesses as one object allocate DIFFERENTLY as
/// separate extern symbols than as one array — Watcom's conflict-tie machinery keys on symbol
/// structure. Measured with 10.0a probes: FUN_00045aa4's EAX/EDX role swap vanishes under
/// `short v[4]` (byte-exact shape), FUN_00031c0c's AX/CX likewise (5 rows + a spurious ECX
/// save → 1 row, with the statement-interleave residue a separate lever). The rewrite indexes
/// the run's BASE symbol (`iRam<base>[k]`), whose `<pfx>Ram<hex>` name keeps relocation
/// resolution unchanged; element addresses and widths are identical, so the transform is
/// semantics-preserving by construction.
///
/// Gates: adjacency runs (addr + size == next, same elem type, members evidenced in the
/// original bytes — own address or the dword-widened addr-(4-size) appearing in some
/// original instruction, none volatile, none used with `[`/`.`) are detected broadly, but
/// the TU aggregates only when EVERY detected run is a SHORT (size-2) run of >=3 — the
/// pure configuration the corpus measured safe. MOSURA_AGG=0 disables.
///
/// WHY THIS NARROW: the full corpus A/B (zc19 -> zc20, gate = any adjacent same-type run
/// of >=2) measured the transform as a TIE-RESHUFFLER, not a recovery — 403 TUs fired,
/// winners and losers in comparable numbers in every shape class (5 EXACT lost / 1 gained,
/// net -1.8 weighted sim). Access patterns CANNOT distinguish array-source from
/// adjacent-scalars-source (both compile to identical bytes when the allocation happens to
/// agree), so a static byte gate cannot call the coin flip. The one class that measured
/// strictly safe and net-positive is short runs of >=3 (16 pure TUs: +6.3 weighted,
/// zero verdict regressions, FUN_00045aa4 SAME_SHAPE->EXACT). The abandoned ~235 weighted
/// positive mass in coin-flip TUs is harvestable only by measured per-TU selection — an
/// arms-style architecture decision, recorded in the allocator-model thread.
fn aggregate_ram_globals(
    c: &str,
    insns: &[mosura::recompile::insn::NormInsn],
    gsizes: &std::collections::HashMap<u64, u32>,
    volatiles: &HashSet<u64>,
) -> (String, Vec<(String, String)>) {
    if std::env::var("MOSURA_AGG").as_deref() == Ok("0") {
        return (c.to_string(), Vec::new());
    }
    // Ram identifiers in the text, with per-name exclusion when any occurrence is followed by
    // `[` (already indexed / pointer-classified downstream) or `.` (partial-symbol accessor).
    let bytes = c.as_bytes();
    let mut names: std::collections::HashMap<String, (u64, bool)> = std::collections::HashMap::new();
    let mut i = 0;
    while i < bytes.len() {
        if !is_ident(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_ident(bytes[i]) {
            i += 1;
        }
        let tok = &c[start..i];
        let Some(addr) = ram_addr_of(tok) else { continue };
        let excluded = matches!(bytes.get(i), Some(b'[') | Some(b'.'));
        let e = names.entry(tok.to_string()).or_insert((addr, false));
        e.1 |= excluded;
    }
    // Candidate members: recovered scalar size, spellable type, not volatile.
    let mut members: Vec<(u64, u32, String, String)> = Vec::new(); // (addr, size, elem_ty, name)
    for (name, &(addr, excluded)) in &names {
        if excluded || volatiles.contains(&addr) {
            continue;
        }
        let Some(&size) = gsizes.get(&addr) else { continue };
        if !matches!(size, 1 | 2 | 4) {
            continue;
        }
        let pfx = name.chars().next().unwrap_or('x');
        if pfx == 'p' {
            continue;
        }
        let ty = sized_ctype(pfx, size).unwrap_or_else(|| ctype_for(pfx).to_string());
        members.push((addr, size, ty, name.clone()));
    }
    members.sort();
    // Byte evidence: the member's address — or its dword-widened load address — appears in the
    // original instruction stream.
    let evidenced = |addr: u64, size: u32| -> bool {
        let own = format!("0x{addr:x}");
        let widened = (size < 4).then(|| format!("0x{:x}", addr.saturating_sub((4 - size) as u64)));
        insns.iter().any(|x| {
            x.text.contains(&own) || widened.as_deref().is_some_and(|w| x.text.contains(w))
        })
    };
    // PURITY: runs are detected under the broad criteria (any scalar size, length >=2,
    // loose evidence) exactly as the zc20 full-fire round did; the TU aggregates ONLY when
    // every detected run is a tight one (size-2, length >=3). A mixed TU — tight runs next
    // to rejected siblings — is an UNMEASURED hybrid, and the zc21 partial round measured
    // the 21 such TUs net NEGATIVE; the pure-16 configuration is the one that measured
    // +6.3 weighted with zero verdict regressions.
    let mut runs: Vec<(usize, usize)> = Vec::new(); // [k, end)
    let mut k = 0;
    while k < members.len() {
        let (base_addr, size, ref ty, _) = members[k];
        let mut end = k + 1;
        while end < members.len() {
            let (a, s, ref t, _) = members[end];
            if s == size && t == ty && a == base_addr + ((end - k) as u64) * size as u64 {
                end += 1;
            } else {
                break;
            }
        }
        if end - k >= 2 && (k..end).all(|j| evidenced(members[j].0, members[j].1)) {
            runs.push((k, end));
        }
        k = end;
    }
    let mut rename: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut decls: Vec<(String, String)> = Vec::new();
    if !runs.is_empty() && runs.iter().all(|&(k, end)| members[k].1 == 2 && end - k >= 3) {
        for &(k, end) in &runs {
            let base = members[k].3.clone();
            let ty = &members[k].2;
            for (slot, j) in (k..end).enumerate() {
                rename.insert(members[j].3.clone(), format!("{base}[{slot}]"));
            }
            decls.push((base.clone(), format!("{ty} {base}[{}];", end - k)));
        }
    }
    if rename.is_empty() {
        return (c.to_string(), Vec::new());
    }
    // Token-wise rewrite: member -> base[k]. Single pass, so the inserted base name is never
    // itself re-visited.
    let mut out = String::with_capacity(c.len() + 64);
    let mut i = 0;
    while i < bytes.len() {
        if !is_ident(bytes[i]) {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_ident(bytes[i]) {
            i += 1;
        }
        let tok = &c[start..i];
        match rename.get(tok) {
            Some(r) => out.push_str(r),
            None => out.push_str(tok),
        }
    }
    (out, decls)
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
