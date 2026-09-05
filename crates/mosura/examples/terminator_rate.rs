//! **The population instrument** — do the functions we recovered *end like functions*?
//!
//! For every function in an analyzed program this asks one question of the computed body: does
//! its last instruction TERMINATE the flow (`ret` / `retf` / `jmp rel` / `jmp indirect`)? Real
//! functions do. An entry minted inside a data table, or inside the middle of another function,
//! generally does not.
//!
//! ```text
//! cargo run -q --release --example terminator_rate -- <program> --truth <file> [options]
//! ```
//!
//! # ⚠️ THE CONTROL IS THE INSTRUMENT — read this before quoting any number it prints
//!
//! Standalone, *"99.9% of these end in a `ret`"* is very nearly vacuous: most runs of bytes reach
//! a `c3` eventually. The measure means something **only** because the same code, in the same run,
//! also scores a population that an external source has already corroborated — that control is
//! what establishes what "real" looks like on this binary, and it is the thing a bare rate has no
//! way to convey.
//!
//! So this tool **requires `--truth` and always prints both arms.** It will not emit one alone.
//! That is deliberate: an instrument that *can* print a bare number will eventually have its bare
//! number quoted, and this one has already changed a decision that a bare number could not have.
//!
//! Calibration, the subject @ `6abd1ae` (the run this tool was extracted from):
//!
//! ```text
//!   corroborated (expert tracker)   2111/2118   99.7%
//!   uncorroborated (pattern-only)     899/900   99.9%
//!   a rejected pattern family's 53     14/53    26.4%   <- caught here, backed out in 50bea92
//! ```
//!
//! Two populations at ~99.8% and a candidate at 26% is what a real signal looks like here.
//!
//! # What it does NOT tell you — each of these cost us something to learn
//!
//! 1. **It is a DETECTOR, not an ESTIMATOR.** The failures are *not independent across nearby
//!    entries*. False positives cluster, because the thing that produces them usually repeats: the
//!    population that exposed this was one 16-byte idiom inlined at dozens of sites in a single
//!    ~3 KB region. A handful of sites can therefore dominate the rate. Read a low number as
//!    "something is wrong in here", never as "N% of these entries are wrong".
//! 2. **A `jmp indirect` COUNTS as a terminator, and must keep counting.** Removing it would make
//!    the instrument look sharper while making it wrong — it is what closes the otherwise-tempting
//!    benign story that "these bodies were merely truncated at an unresolved computed jump". A
//!    body that stops at a `BRANCHIND` scores as terminating, so a low rate cannot be explained
//!    that way.
//! 3. **It says these entries are FUNCTIONS. It says nothing about whether their BOUNDARIES are
//!    right.** A function recovered at the wrong entry, or with an extent that stops short, can
//!    still end in a `ret` and score perfectly. Extent correctness is a separate measurement and
//!    is still open.
//! 4. **No truth column, no control, no verdict.** Hence the hard requirement above.
//! 5. **Trustworthy as a DIFFERENTIAL, shaky as an ABSOLUTE.** Both arms are measured by the same
//!    code in the same run, so a systematic bias in the predicate cancels between them — which is
//!    what made 26% vs 99.8% safe to act on. A single arm quoted on its own carries the full bias.
//!    This is not hypothetical: the scratch harness this tool replaces read the body's LAST BYTE
//!    as an opcode when the listing had no code unit there, so a body ending `e9 xx xx xx xx` was
//!    tested on its final displacement byte and failed spuriously. Its absolute figures
//!    (2111/2118, 899/900) are therefore its own, not ground truth — this tool decodes forward to
//!    find the real last instruction instead, and supersedes them.
//!
//! # Truth sources
//!
//! * a corpus `.truth` file — `func <hex> <size> <name> <class>` lines;
//! * the the RE tracker tracker CSV — a `va` column of `0x…` addresses.
//!
//! ⚠️ **Nothing here reads the truth file's SIZE column.** The Watcom column of the ground-truth
//! corpus carries `size 0` for every symbol (`nm` emits no sizes for Watcom objects), so any
//! containment logic keyed on truth sizes is silently inert on exactly the fixtures we use most.
//! Corroboration is by ADDRESS only.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use mosura::analysis;
use mosura::decompile::opcode::OpCode;
use mosura::decompile::space::Address;

/// The flow-ending opcodes. Expressed as p-code so the tool is arch-neutral — on x86 this is
/// `c3`/`c2` (ret), `cb`/`ca` (retf), `e9`/`eb` (jmp rel) and `ff /4` (jmp indirect), but the same
/// binary works on the corpus's aarch64/riscv/m68k columns without a second encoding table.
fn is_terminator(op: Option<OpCode>) -> bool {
    matches!(op, Some(OpCode::Return | OpCode::Branch | OpCode::Branchind))
}

struct Args {
    program: PathBuf,
    truth: PathBuf,
    cspec: Option<String>,
    le: bool,
    shift: u64,
    list_failures: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: terminator_rate <program> --truth <file.truth|tracker.csv> \\\n\
         \x20         [--cspec <id>] [--le] [--shift N] [--list-failures]\n\
         \n\
         --truth is REQUIRED: without a control population the rate is not interpretable.\n\
         --le              load a bound MZ+LE image through the native LE loader (the subject)\n\
         --shift N         corroboration window in bytes (default 8); the expert tracker anchors\n\
         \x20                 save-first functions mid-prologue at the `push ebp`, so exact-address\n\
         \x20                 matching understates the corroborated arm\n\
         --list-failures   print each non-terminating entry with its body extent and last insn"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let mut it = std::env::args().skip(1);
    let mut program = None;
    let (mut truth, mut cspec, mut le, mut shift, mut list) = (None, None, false, 8u64, false);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--truth" => truth = it.next().map(PathBuf::from),
            "--cspec" => cspec = it.next(),
            "--le" => le = true,
            "--shift" => shift = it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage()),
            "--list-failures" => list = true,
            "-h" | "--help" => usage(),
            _ if program.is_none() => program = Some(PathBuf::from(a)),
            _ => usage(),
        }
    }
    match (program, truth) {
        (Some(program), Some(truth)) => Args { program, truth, cspec, le, shift, list_failures: list },
        // The refusal that keeps the control attached to the number.
        _ => usage(),
    }
}

/// Addresses from either supported truth source. Sizes are deliberately not read (see the header).
fn read_truth(path: &Path) -> BTreeSet<u64> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("truth source {}: {e}", path.display()));
    let mut out = BTreeSet::new();
    for line in text.lines() {
        // corpus `.truth`: "func 08048106 0 name class"
        if let Some(rest) = line.strip_prefix("func ") {
            if let Some(tok) = rest.split_whitespace().next() {
                if let Ok(v) = u64::from_str_radix(tok, 16) {
                    out.insert(v);
                    continue;
                }
            }
        }
        // tracker CSV: first column `0x0001000a`
        let first = line.split(',').next().unwrap_or("");
        if let Some(hex) = first.trim().strip_prefix("0x") {
            if let Ok(v) = u64::from_str_radix(hex, 16) {
                out.insert(v);
            }
        }
    }
    assert!(!out.is_empty(), "no addresses parsed from {} — wrong truth format?", path.display());
    out
}

fn main() {
    let args = parse_args();

    let program = if args.le {
        analysis::analyze_le_file(&args.program).expect("analyze (LE)")
    } else {
        analysis::analyze_file_as(&args.program, args.cspec.as_deref()).expect("analyze")
    };
    let truth = read_truth(&args.truth);
    let ram = program.default_space;
    let Some((spec, ctx)) = mosura::lang::load_cached(&program.language_id) else {
        eprintln!("no SLEIGH tables for {}", program.language_id);
        std::process::exit(1);
    };

    // (corroborated, uncorroborated) x (total, terminating)
    let mut arms = [[0usize; 2]; 2];
    let mut failures: Vec<String> = Vec::new();
    let (mut misaligned, mut listing_blind) = (0usize, 0usize);

    for f in program.function_manager.functions() {
        let entry = f.entry_point().offset;
        // Corroborated when a truth address lies within `shift` bytes AT OR AFTER the entry: the
        // tracker anchors save-first functions mid-prologue, so its address is >= the true entry.
        let corroborated = truth.range(entry..=entry.saturating_add(args.shift)).next().is_some()
            || truth.contains(&entry);
        let arm = usize::from(!corroborated);

        // The last instruction of the body: decode forward through the highest range.
        let Some(last_range) = f.body().ranges().max_by_key(|r| r.max) else { continue };
        let (mut cursor, mut last) = (last_range.min, None);
        while cursor <= last_range.max {
            let w = program.memory.read_window(Address::new(ram, cursor), 16);
            let Some(insn) = spec.disassemble_ctx(&w, cursor, ctx).into_iter().next() else { break };
            let len = insn.bytes.len() as u64;
            if len == 0 {
                break;
            }
            last = Some((cursor, insn));
            cursor += len;
        }

        // CALIBRATION DIAGNOSTICS. The first the subject run of this tool did NOT reproduce the harness
        // it was extracted from (3 failures vs 8, same 3018 total), so it reports the two ways a
        // re-decoding instrument can disagree with a listing-based one:
        //   * misaligned — decoding forward from the range start does not land exactly on its end,
        //     so the "last instruction" is being read from a mis-synchronised stream;
        //   * listing-blind — the body's last byte has NO defined code unit, i.e. the region was
        //     never disassembled (see the §9 listing-population finding). A LISTING-based tool
        //     scores these as failures; a re-decoding one finds a terminator and passes them,
        //     which is exactly the direction of the observed discrepancy.
        if cursor != last_range.max + 1 {
            misaligned += 1;
        }
        if program.listing.code_unit_containing(Address::new(ram, last_range.max), 16).is_none() {
            listing_blind += 1;
        }
        arms[arm][0] += 1;
        match &last {
            Some((_, insn)) if is_terminator(insn.ops.last().and_then(|o| OpCode::from_u32(o.opcode))) => {
                arms[arm][1] += 1;
            }
            _ => {
                if args.list_failures {
                    // Limit 3's open question — why a failing entry failed — is answered by its
                    // extent and last instruction, so the tool emits them rather than needing a
                    // separate investigation each time it fires.
                    let (la, mnem) = match &last {
                        Some((a, i)) => (*a, i.mnemonic.clone()),
                        None => (last_range.max, "<undecodable>".to_string()),
                    };
                    failures.push(format!(
                        "  {entry:08x}  body {:08x}..{:08x} ({} bytes)  last {la:08x} {mnem}  [{}]",
                        last_range.min,
                        last_range.max,
                        last_range.max - last_range.min + 1,
                        if corroborated { "corroborated" } else { "uncorroborated" }
                    ));
                }
            }
        }
    }

    // An empty arm prints "--", never a number: a rate over zero entries is not a rate, and
    // NaN in a report is an invitation to read it as one.
    let pct = |[t, ok]: [usize; 2]| -> String {
        if t == 0 { "    --".to_string() } else { format!("{:6.1}%", 100.0 * ok as f64 / t as f64) }
    };
    println!("program : {}", args.program.display());
    println!("truth   : {} ({} addresses)", args.truth.display(), truth.len());
    println!("shift   : {} bytes", args.shift);
    println!();
    // BOTH arms, always — see the header. The control is what makes the subject readable.
    println!("  corroborated (CONTROL)  {:5}/{:<5} {}", arms[0][1], arms[0][0], pct(arms[0]));
    println!("  uncorroborated          {:5}/{:<5} {}", arms[1][1], arms[1][0], pct(arms[1]));
    println!();
    println!("  [diag] misaligned last-range decode: {misaligned}   body end with NO listing unit: {listing_blind}");
    println!();
    println!(
        "Read the second line ONLY against the first. A detector, not an estimator: failures \
         cluster, so a\nfew repeated sites can dominate a rate. Says these are functions; says \
         nothing about their extents."
    );
    if args.list_failures && !failures.is_empty() {
        println!("\nnon-terminating entries ({}):", failures.len());
        for l in &failures {
            println!("{l}");
        }
    }
}
