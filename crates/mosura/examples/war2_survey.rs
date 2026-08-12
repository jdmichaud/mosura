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
use mosura::decompile::printc::print_c;
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
typedef unsigned int undefined4; typedef double undefined8; typedef unsigned char byte;
typedef unsigned char uint1; typedef unsigned short uint2; typedef unsigned int uint4; typedef double uint8;
typedef signed char int1; typedef short int2; typedef int int4; typedef double int8;
typedef unsigned char xunknown1; typedef unsigned short xunknown2; typedef unsigned int xunknown4; typedef double xunknown8;
typedef unsigned int xunknown3; typedef double xunknown6; typedef unsigned int xunknown5; typedef double xunknown7;
typedef unsigned char undefined3; typedef unsigned int undefined5; typedef double undefined6; typedef double undefined7;
typedef unsigned int uint3; typedef unsigned int int3; typedef unsigned int uint5; typedef unsigned int int5;
typedef unsigned int uint6; typedef int int6; typedef unsigned int uint10; typedef int int10;
typedef int code(); typedef unsigned int pointer;
/* CALLOTHER intrinsics. Ghidra renders an unmodelled instruction as a call to a named user-op, and
   the x86 SLEIGH spec names the software interrupt `swi`, the port read `in`, and `cpuid`.
   `printc` emits the software interrupt as `(*swi(3))()` — a call THROUGH the user-op's result —
   so `swi` has to return a function pointer or the dereference is `E1029: Expression must be
   'pointer to ...'` and the whole translation unit fails to compile. It was undeclared: 74 of the
   156 COMPILE_FAIL functions were this one missing line, the single largest cause.
   These declarations make the C compile; they do not make an `int 3` reproducible from C. */
extern void (*swi(int))(); extern unsigned int in(unsigned int); extern unsigned int cpuid(unsigned int);
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

/// The commit that produced an emit: `<short-sha>` or `<short-sha>-dirty`. Falls back to
/// `nogit` only if git is unavailable — an unstamped artifact is still marked as unstamped
/// rather than silently claiming to be reproducible.
fn git_stamp() -> String {
    let sha = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(sha) = sha else { return "nogit".to_string() };
    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
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
    let mut names = Vec::new();
    for s in &slots {
        if s.addr.space != reg {
            return None;
        }
        let n = table.iter().find(|&&(o, sz, _)| o == s.addr.offset && sz == s.size)?;
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
    let default: Vec<String> = slots
        .iter()
        .enumerate()
        .map(|(i, s)| match (order.get(i), s.size) {
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
) -> Option<String> {
    let mut parts = Vec::new();
    // A STACK-BASED prototype is `parm []`. It used to short-circuit the whole declaration, so
    // these functions never got their `modify` list — the two are independent facts about the
    // contract and both belong in the same pragma.
    if stack_convention {
        parts.push("parm []".to_string());
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
        std::fs::write(out.join("prelude.h"), PRELUDE).unwrap();
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
    // `war2-survey/src/` holds .c files spanning 2026-08-03 to 2026-08-05 from separate emits.
    // Only reachable for a new stamp (nothing to clear), a `-dirty` stamp, or --force.
    if !probing {
        for d in [&src_dir, &raw_dir] {
            if d.exists() {
                std::fs::remove_dir_all(d).unwrap();
            }
        }
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::create_dir_all(&raw_dir).unwrap();
        std::fs::write(out.join("prelude.h"), PRELUDE).unwrap();
    }
    // compile.sh reads <out>/src/$n.c and <out>/manifest.tsv; compare.py reads <out>/manifest.tsv.
    // Pointing the bare names at the current stamp keeps both working unchanged.
    if !probing {
        link_latest(&out.join("src"), &format!("src.{stamp}"));
        link_latest(&out.join("raw"), &format!("raw.{stamp}"));
        link_latest(&out.join("manifest.tsv"), &format!("manifest.{stamp}.tsv"));
    }

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
        "idx\tva\tname\tstatus\torig_len\tcov_lo\tcov_hi\tsmells\torig_hex\tir_calls\tblocks_cfg\tblocks_reached"
    )
    .unwrap();

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
            writeln!(mf, "{idx:05}\t{va:08x}\t{name}\tDECOMPILE_FAIL\t0\t0\t0\t\t{head}\t0\t0\t0").unwrap();
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

        let c = print_c(&f);
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
        let (tu, mut smells) = build_tu(&c, *va, false, &gsizes);
        let tu = if let Some(decl) = own_contract(&f, &watreg, stack_convention) {
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

        let orig_hex: String = region.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(
            mf,
            "{idx:05}\t{va:08x}\t{name}\tOK\t{orig_len}\t{cov_lo:08x}\t{cov_hi:08x}\t{}\t{orig_hex}\t{ir_calls}\t{blocks_cfg}\t{blocks_reached}",
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
