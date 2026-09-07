//! Translation-unit synthesis for the recompile: the C89 prelude a Watcom 10.0a target needs,
//! the emit-time representability contract, and `build_tu` — how one function's decompiled C
//! becomes a standalone translation unit (extern declarations for its callees and RAM globals,
//! synthetic register variables, aggregated arrays, per-callee pragmas). Moved verbatim out of the
//! corpus emit driver (plan WP7 P0 c1, 2026-09-05); the driver and the ground-truth oracle call it.
//! Nothing here reads a file, the environment or a program: text in, text out.
//!
//! The prelude is NOT baked into a TU — the compile stage prepends `prelude.h`, written from
//! [`build_prelude`] by the front-end, so a prelude change never needs a re-emit.

use std::collections::{BTreeSet, HashMap, HashSet};

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
// a base type of that width, and Ghidra's own the subject output contains `uint6` x8, `uint3` x19,
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
pub const PRELUDE: &str = "\
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
#define SCARRY1(a,b) ((int)((((~((unsigned char)(a)^(unsigned char)(b)))&((unsigned char)(a)^(unsigned char)((unsigned char)(a)+(unsigned char)(b))))>>7)&1))
#define SCARRY2(a,b) ((int)((((~((unsigned short)(a)^(unsigned short)(b)))&((unsigned short)(a)^(unsigned short)((unsigned short)(a)+(unsigned short)(b))))>>15)&1))
#define SBORROW4(a,b) ((int)((((unsigned int)(a)^(unsigned int)(b))&((unsigned int)(a)^((unsigned int)(a)-(unsigned int)(b))))>>31))
#define SBORROW1(a,b) ((int)(((((unsigned char)(a)^(unsigned char)(b))&((unsigned char)(a)^(unsigned char)((unsigned char)(a)-(unsigned char)(b))))>>7)&1))
#define SBORROW2(a,b) ((int)(((((unsigned short)(a)^(unsigned short)(b))&((unsigned short)(a)^(unsigned short)((unsigned short)(a)-(unsigned short)(b))))>>15)&1))
#define CARRY4(a,b) ((unsigned int)(a)>(unsigned int)~(unsigned int)(b))
#define CARRY1(a,b) ((((unsigned int)(unsigned char)(a)+(unsigned int)(unsigned char)(b)))>0xffU)
/* POPCOUNT(x) was `(0)` -- always wrong, never failing. Loud now (Phase 1). */
#define POPCOUNT(x) (sizeof(struct mosura_popcount_not_modelled))
";

/// Assemble the prelude, asserting the CLOSED in-contract helper vocabulary is fully defined —
/// every SUB/ZEXT/SEXT over sources <= 4 bytes, every CONCAT with h+l <= 4, and the
/// carry/borrow family over 1/2/4 must have a `#define`; and no in-contract name may alias the
/// out-of-contract tripwire. The assertion is what makes the header a CONTRACT rather than an
/// enumeration that can silently miss a member (docs/compilable-c-remediation.md, Phase 2).
pub fn build_prelude() -> &'static str {
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
pub fn contract_violations(tu: &str) -> Vec<String> {
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

pub fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The exact unsigned integer type of a given byte width, or `None` when the prelude has no type
/// that is *exactly* that wide. Deliberately excludes `uint8` — the prelude maps it to `double`
/// (Watcom 10.0a is C89 with no 64-bit integer), and storing through a `double *` is not a
/// width-preserving integer write.
pub fn exact_uint(size: u32) -> Option<&'static str> {
    match size {
        1 => Some("uint1"),
        2 => Some("uint2"),
        4 => Some("uint4"),
        _ => None,
    }
}

/// Parse a partial-symbol field suffix `._<off>_<size>_` at `i`, returning `(off, size, end)`.
pub fn parse_field_suffix(b: &[u8], mut i: usize) -> Option<(u64, u32, usize)> {
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
pub fn compilable_partial_symbols(c: &str) -> String {
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
pub fn build_tu(
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
        // `aRam<hex>`: a TABLE the table-base arm names by its base (emit/arms/table_base.rs) —
        // an extern array of unknown size, so the symbol is an address and never a load
        if *pfx == 'a' {
            names.insert(format!("extern char {n}[];"));
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
                || names.iter().any(|d| d.split_whitespace().any(|t| t.trim_end_matches(';').trim_end_matches("[]") == cap))
            {
                continue;
            }
            let pfx = cap.as_bytes()[0] as char;
            if pfx == 'a' {
                extra.push(format!("extern char {cap}[];"));
                continue;
            }
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

pub fn classify_ident(
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
/// pure configuration the corpus measured safe. `--arms-off frame-agg` disables.
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
pub fn aggregate_ram_globals(
    c: &str,
    insns: &[crate::recompile::insn::NormInsn],
    gsizes: &std::collections::HashMap<u64, u32>,
    volatiles: &HashSet<u64>,
    agg_on: bool,
) -> (String, Vec<(String, String)>) {
    if !agg_on {
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

pub fn ctype_for(prefix: char) -> &'static str {
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
pub fn ram_addr_of(name: &str) -> Option<u64> {
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
pub fn sized_ctype(prefix: char, size: u32) -> Option<String> {
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
pub fn is_ident_start(s: &str) -> bool {
    let mut it = s.bytes();
    it.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_') && s.bytes().all(is_ident)
}

/// Prefix a translation unit with its function's own `#pragma aux` declaration, when it has one.
///
/// REGISTER CONVENTION THAT IS NOT THE DEFAULT PREFIX. The decompiler recovers each parameter's
/// true STORAGE (Ghidra's `ParameterPieces::addr`), but a C signature can only express POSITION —
/// Watcom then assigns position 1 to EAX, 2 to EDX, and so on. Whenever the recovered storage is
/// not exactly that default assignment, the signature alone compiles the arguments into the wrong
/// registers, and `#pragma aux ... parm [..]` is how Watcom is told the real one. This is the same
/// mechanism as the `parm []` stack case, generalised to registers. The declaration text is the
/// function's `own_contract`; the three emissions (reference, extra arms, recovered) all prefix it
/// the same way, which is why it is one function.
pub fn with_contract(name: &str, contract: Option<&str>, tu: String) -> String {
    match contract {
        Some(decl) => format!("#pragma aux {name} {decl};\n{tu}"),
        None => tu,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SCARRY1/2 and SBORROW1/2 test the SIGNED OVERFLOW at the operand's own width, not by
    /// delegating to the 32-bit helper on sign-extended operands — two values sign-extended from
    /// 8 or 16 bits can never overflow a 32-bit signed add, so the old form was identically zero
    /// (wrong C, silent). Pins the fix re-landed from `faithful-c-equivalence` against regression;
    /// the exhaustive value check (that the macro agrees with `emu`'s INT_SCARRY at bytes/words)
    /// is a dev-tier gcc test, since it needs a C compiler.
    #[test]
    fn narrow_signed_overflow_macros_are_not_identically_zero() {
        let p = PRELUDE;
        // the zero-form (delegate to SCARRY4 on a sign-extended narrow operand) must be gone
        assert!(!p.contains("SCARRY4((int)(signed char)"), "SCARRY1 must not delegate to the 32-bit helper");
        assert!(!p.contains("SCARRY4((int)(short)"), "SCARRY2 must not delegate to the 32-bit helper");
        assert!(!p.contains("SBORROW4((int)(signed char)"), "SBORROW1 must not delegate to the 32-bit helper");
        assert!(!p.contains("SBORROW4((int)(short)"), "SBORROW2 must not delegate to the 32-bit helper");
        // and each narrow macro must test overflow at its own width (bit 7 for byte, 15 for word)
        assert!(p.contains("#define SCARRY1(a,b)") && p.contains(">>7)&1"), "SCARRY1 tests bit 7");
        assert!(p.contains("#define SCARRY2(a,b)") && p.contains(">>15)&1"), "SCARRY2 tests bit 15");
        assert!(p.contains("#define SBORROW1(a,b)"));
        assert!(p.contains("#define SBORROW2(a,b)"));
    }

    /// The prelude's closure assertion runs (a missing in-contract helper would panic here), and
    /// the function type is the FUNCTION, not a pointer to one (the globfnptr byte finding).
    #[test]
    fn prelude_is_closed_and_types_code_as_a_function() {
        let p = build_prelude();
        assert_eq!(p, PRELUDE);
        assert!(p.contains("typedef int code();"), "code is the function type");
        assert!(p.contains("#define CONCAT22("), "an in-contract helper is defined");
        assert!(
            p.contains("#define CONCAT44(h,l) (sizeof(struct mosura_no_such_integer_width_on_this_target))"),
            "an out-of-contract width is defined as the LOUD tripwire, never as a value"
        );
    }

    /// Width violations: `CONCAT<h><l>` with h+l > 4, `SUB/ZEXT/SEXT` with a source above 4, the
    /// impossible-width typedef names, `POPCOUNT`, printc's `MOSURA_*` placeholders and `spacebase`;
    /// not the in-contract forms. Deduplicated and sorted.
    #[test]
    fn contract_violations_flag_widths_the_target_cannot_hold() {
        let tu = "x = CONCAT44(a, b) + CONCAT44(c, d); y = CONCAT22(c, d); z = SUB84(q, 0); w = SUB43(r, 1);\n\
                  POPCOUNT(v); uint8 t; uint3 u; MOSURA_X; spacebase s; ZEXT816(m); SEXT48(n); int i = xunknown6_not;";
        assert_eq!(
            contract_violations(tu),
            vec!["CONCAT44", "MOSURA_X", "POPCOUNT", "SUB84", "ZEXT816", "spacebase", "uint8"],
            "flagged once each, sorted; CONCAT22/SUB43/SEXT48/uint3 are in contract; a longer identifier is not a typedef"
        );
        assert!(contract_violations("int4 f(void) { return 1; }").is_empty());
    }

    /// The faithful partial-symbol accessor `b._4_2_` becomes a compilable width-preserving cast;
    /// a width with no exactly-matching type is left alone so it fails at compile time.
    #[test]
    fn partial_symbols_become_casts_only_at_exact_widths() {
        assert_eq!(compilable_partial_symbols("x = b._4_2_ + 1;"), "x = (*(uint2 *)((char *)&b + 4)) + 1;");
        assert_eq!(compilable_partial_symbols("x = b._0_1_;"), "x = (*(uint1 *)((char *)&b + 0));");
        assert_eq!(compilable_partial_symbols("y = c._0_8_;"), "y = c._0_8_;", "size 8 has no exact type");
        assert_eq!(compilable_partial_symbols("plain = other;"), "plain = other;");
        assert_eq!(parse_field_suffix(b"._12_4_x", 0), Some((12, 4, 7)));
        assert_eq!(parse_field_suffix(b"._12_4", 0), None, "the closing underscore is required");
        assert_eq!(exact_uint(3), None);
    }

    fn classify(w: &str, ptr_use: bool) -> (Vec<String>, Vec<String>, Vec<(String, char)>, Vec<String>) {
        let (mut f, mut p, mut s, mut sm) = (HashSet::new(), HashSet::new(), HashSet::new(), BTreeSet::new());
        classify_ident(w, ptr_use, "FUN_00001000", &mut f, &mut p, &mut s, &mut sm);
        let mut fv: Vec<_> = f.into_iter().collect();
        fv.sort();
        let mut pv: Vec<_> = p.into_iter().collect();
        pv.sort();
        let mut sv: Vec<_> = s.into_iter().collect();
        sv.sort();
        (fv, pv, sv, sm.into_iter().collect())
    }

    /// The identifier families and where each lands: callees (an indirect one smells), the
    /// function's own name never, synthetic register reads, unmapped stack names (no `_`), RAM
    /// globals by prefix (a `p` prefix or a pointer use makes a pointer), `DAT_`.
    #[test]
    fn classify_ident_sorts_every_family() {
        assert_eq!(classify("func_0x00002000", false), (vec!["func_0x00002000".into()], vec![], vec![], vec!["indirect_call".into()]));
        assert_eq!(classify("FUN_00003000", false), (vec!["FUN_00003000".into()], vec![], vec![], vec![]));
        assert_eq!(classify("FUN_00001000", false), (vec![], vec![], vec![], vec![]), "the function itself is not a callee");
        assert_eq!(classify("extraout_EAX", false), (vec![], vec![], vec![("extraout_EAX".into(), 'u')], vec!["extraout".into()]));
        assert_eq!(classify("unaff_EBX", true), (vec![], vec!["unaff_EBX".into()], vec![], vec!["unaff".into()]));
        assert_eq!(classify("in_ECX", false).3, vec!["in_reg".to_string()]);
        assert_eq!(classify("uStack00000004", false), (vec![], vec![], vec![("uStack00000004".into(), 'u')], vec!["unmapped-stack".into()]));
        assert_eq!(classify("uStack_18", false), (vec![], vec![], vec![], vec![]), "a mapped local is declared by the decompiler");
        assert_eq!(classify("iRam000a8288", false), (vec![], vec![], vec![("iRam000a8288".into(), 'i')], vec![]));
        assert_eq!(classify("pcRam000a8290", false), (vec![], vec!["pcRam000a8290".into()], vec![], vec![]), "a p prefix is a pointer");
        assert_eq!(classify("uRam000a8290", true), (vec![], vec!["uRam000a8290".into()], vec![], vec![]), "a pointer use promotes");
        assert_eq!(classify("xRam000a8290", false).3, vec!["xunknown".to_string()]);
        assert_eq!(classify("DAT_000a8290", false), (vec![], vec![], vec![("DAT_000a8290".into(), 'u')], vec![]));
        assert_eq!(classify("param_1", false), (vec![], vec![], vec![], vec![]));
    }

    /// One hand-written body through the whole synthesis: sorted extern callees (with the vararg
    /// pragma before its callee), RAM globals typed by prefix or by the recovered width, `volatile`
    /// where recovered, a pointer global, a synthetic register read, an aggregated array declared
    /// verbatim, a declared local not re-declared, the `aRam` table as an extern array — and the
    /// prelude NOT in the TU.
    #[test]
    fn build_tu_synthesizes_the_declarations_a_standalone_unit_needs() {
        let c = "int4 FUN_00001000(int4 param_1)\n{\n  int4 iVar1;\n  \n  iVar1 = func_0x00002000(param_1);\n  \
                 iRam000a8288 = iVar1 + uRam000a8290;\n  puRam000a82a0[1] = 5;\n  bRam000a82b0 = extraout_EAX;\n  \
                 sRam00080000[2] = 1;\n  cRam000a82c0 = *((char *)(aRam00090000 + iVar1));\n  return FUN_00003000(iVar1);\n}\n";
        let gsizes: HashMap<u64, u32> = [(0xa8290u64, 2u32), (0xa82b0, 1)].into_iter().collect();
        let volatiles: HashSet<u64> = [0xa8288u64].into_iter().collect();
        let vararg: HashMap<u64, String> = [(0x2000u64, "parm caller []".to_string())].into_iter().collect();
        let aggregates = vec![("sRam00080000".to_string(), "short sRam00080000[3];".to_string())];
        let (tu, smells) = build_tu(c, 0x1000, true, &gsizes, &volatiles, &vararg, &aggregates);
        let expected_decls = "\
extern int FUN_00003000();
#pragma aux func_0x00002000 parm caller [];
extern int func_0x00002000();
extern char aRam00090000[];
short sRam00080000[3];
unsigned char bRam000a82b0;
unsigned int extraout_EAX;
unsigned short uRam000a8290;
volatile int iRam000a8288;
char cRam000a82c0;
int *puRam000a82a0;
";
        let decls_end = tu.find("\nint4 FUN_00001000").expect("the body follows the declarations");
        let mut got: Vec<&str> = tu[..decls_end].lines().collect();
        let mut want: Vec<&str> = expected_decls.lines().collect();
        got.sort();
        want.sort();
        assert_eq!(got, want, "every declaration, and nothing for the local iVar1 or the parameter");
        assert!(tu.ends_with(c), "the body is appended verbatim");
        assert!(!tu.contains("typedef"), "the prelude is prepended by the compile stage, never baked in");
        assert_eq!(smells, vec!["extraout", "indirect_call", "non_contig"]);
        // `bRam` keeps its 1-byte prefix type; a width the prefix already spells changes nothing
        assert_eq!(sized_ctype('b', 1), Some("unsigned char".into()));
        assert_eq!(sized_ctype('i', 4), None);
        assert_eq!(sized_ctype('u', 8), None, "no 8-byte integer on this target");
        assert_eq!(sized_ctype('d', 8), Some("double".into()));
        assert_eq!(ctype_for('p'), "void *");
        assert_eq!(ram_addr_of("iRam000a8288"), Some(0xa8288));
        assert_eq!(ram_addr_of("Ram000a8288"), None, "the prefix is one or two letters");
        assert_eq!(ram_addr_of("iRam00a8"), None, "at least eight hex digits");
        assert!(is_ident_start("_x1") && !is_ident_start("1x") && !is_ident_start("a-b"));
    }

    /// The `#pragma aux` prefix: one line before the unit when the function has a contract.
    #[test]
    fn with_contract_prefixes_the_pragma_or_leaves_the_unit_alone() {
        assert_eq!(with_contract("FUN_00001000", Some("parm [edx] [eax]"), "int x;\n".into()), "#pragma aux FUN_00001000 parm [edx] [eax];\nint x;\n");
        assert_eq!(with_contract("FUN_00001000", None, "int x;\n".into()), "int x;\n");
    }

    fn lift(hex: &str) -> Vec<crate::recompile::insn::NormInsn> {
        let bytes: Vec<u8> = (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap()).collect();
        crate::recompile::insn::normalize("x86:LE:32:default", &bytes, 0x1000, &crate::recompile::insn::NoReloc).expect("language tables")
    }

    /// Aggregation fires only for the measured-safe configuration: every detected run is a
    /// size-2 run of three or more, each member evidenced in the original's instructions; a
    /// size-4 run, a mixed unit, a `[`/`.` use or a volatile member leave the text alone.
    #[test]
    fn aggregation_rewrites_only_pure_short_runs_with_byte_evidence() {
        // MOV AX,[0x80000]; MOV AX,[0x80002]; MOV AX,[0x80004]  (66 a1 moffs32) — the evidence
        let insns = lift("66a10000080066a10200080066a104000800");
        assert!(insns.iter().any(|x| x.text.contains("0x80000")), "the probe reads the addresses: {:?}", insns.iter().map(|x| x.text.clone()).collect::<Vec<_>>());
        let sizes2: HashMap<u64, u32> = [(0x80000u64, 2u32), (0x80002, 2), (0x80004, 2)].into_iter().collect();
        let c = "sRam00080000 = 1;\nsRam00080002 = sRam00080000;\nsRam00080004 = 3;\n";
        let (out, decls) = aggregate_ram_globals(c, &insns, &sizes2, &HashSet::new(), true);
        assert_eq!(out, "sRam00080000[0] = 1;\nsRam00080000[1] = sRam00080000[0];\nsRam00080000[2] = 3;\n");
        assert_eq!(decls, vec![("sRam00080000".to_string(), "short sRam00080000[3];".to_string())]);
        // the arm off: nothing
        assert_eq!(aggregate_ram_globals(c, &insns, &sizes2, &HashSet::new(), false).0, c);
        // a volatile member breaks the run
        let vol: HashSet<u64> = [0x80002u64].into_iter().collect();
        assert_eq!(aggregate_ram_globals(c, &insns, &sizes2, &vol, true).0, c);
        // no evidence for one member (neither its own address nor its dword-widened one): no run
        let one = lift("66a104000800"); // only 0x80004 — 0x80000's widened form is 0x7fffe, absent
        assert_eq!(aggregate_ram_globals(c, &one, &sizes2, &HashSet::new(), true).0, c);
        // a size-4 run of two (evidenced) is not the pure configuration
        let insns4 = lift("a100000800a104000800"); // MOV EAX,[0x80000]; MOV EAX,[0x80004]
        let sizes4: HashMap<u64, u32> = [(0x80000u64, 4u32), (0x80004, 4)].into_iter().collect();
        let c4 = "iRam00080000 = iRam00080004;\n";
        assert_eq!(aggregate_ram_globals(c4, &insns4, &sizes4, &HashSet::new(), true).0, c4);
        // an indexed use excludes the member
        let ci = "sRam00080000[1] = 1;\nsRam00080002 = 2;\nsRam00080004 = 3;\n";
        assert_eq!(aggregate_ram_globals(ci, &insns, &sizes2, &HashSet::new(), true).0, ci);
    }
}
