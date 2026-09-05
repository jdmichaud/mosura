//! the subject per-function recompile survey — EMIT stage (uncommitted measurement harness).
//!
//! Read-only w.r.t. the decompiler: loads the subject via the `--le` path, decompiles every recovered
//! function, and emits (a) a standalone C translation unit per function (prelude + synthesized
//! declarations + the decompiled body) for wcc386, and (b) a manifest with each function's
//! original machine-code bytes (from the fixed-up LE image, over the decompiler's covered
//! instruction extent) so a later compile+diff stage can classify recompilation fidelity.
//!
//! Usage: cargo run -q --release --example corpus_emit -- <the subject.exe> <out_dir>

use std::collections::HashMap;
use std::io::Write;
use std::sync::Mutex;

use mosura::analysis::{self, decompiler::decompile_function};
use mosura::decompile::funcdata::Funcdata;
use mosura::decompile::op::flags;
use mosura::decompile::opcode::OpCode;
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::print_c_with;
use mosura::decompile::space::Address;
use mosura::switches::{Knobs, Switch};
use mosura::recompile::tu::{aggregate_ram_globals, build_prelude, build_tu, contract_violations, with_contract};
use mosura::recompile::pragma::{nondefault_parm_regs, own_contract, WatcomRegs};
use mosura::recompile::manifest;
use mosura::recompile::passes;
use mosura::recompile::upgrade;

/// The subject's language. the subject is a 32-bit protected-mode DOS image.
const SURVEY_LANG: &str = "x86:LE:32:default";

/// The commit that produced an emit: `<short-sha>` or `<short-sha>-dirty`. Falls back to
/// `nogit` only if git is unavailable — an unstamped artifact is still marked as unstamped
/// rather than silently claiming to be reproducible.
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

fn main() {
    // `--debug <spec>` configures the diagnostics of this process (`mosura::debug`, grammar in its
    // module doc); nothing is read from the environment.
    let argv = mosura::debug::from_args(std::env::args().skip(1).collect()).unwrap_or_else(|e| panic!("--debug: {e}"));
    let argv = mosura::resources::from_args(argv).unwrap_or_else(|e| panic!("{e}"));
    let mut args = argv.into_iter();
    let first = args.next().expect("usage: corpus_emit [--prelude-only] <subject.exe> <out_dir>");
    // `--prelude-only <out_dir>` rewrites <out>/prelude.h from PRELUDE and exits. It exists so a
    // prelude change never has to be hand-applied to the generated file (see PRELUDE's warning):
    // the compile stage's header is always regenerated from the constant, in seconds, without a
    // 6-minute re-emit.
    if first == "--prelude-only" {
        let out = std::path::PathBuf::from(
            args.next().expect("usage: corpus_emit --prelude-only <out_dir>"),
        );
        std::fs::write(out.join("prelude.h"), build_prelude()).unwrap();
        println!("wrote {}", out.join("prelude.h").display());
        return;
    }
    let bin = first;
    let out = std::path::PathBuf::from(args.next().expect("usage: corpus_emit <subject.exe> <out_dir>"));
    let rest: Vec<String> = args.collect();
    let force = rest.iter().any(|a| a == "--force");
    // `--cons-probe`: the Order-Y constant-witness probe prints its reaching-write census (below).
    let cons_probe = rest.iter().any(|a| a == "--cons-probe");
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
    // ONE name space over two mechanisms: a render arm switches off by clearing its typed `Sites`
    // in the registry, everything else by not running at all (`switches`). The lists are joined
    // here and authored nowhere twice.
    // THE KNOBS — one value for the run (`switches::Knobs`): the switches `--arms-off` names, a
    // `--cspec <id>` declaration of the x86-32 compiler spec, a `--disable-analyzers <list>`
    // ablation. Carried on the program from the load on and on every Funcdata it decompiles; the
    // manifest stamp below is derived from this same value. Nothing is read from the environment.
    let mut knobs = Knobs::default();
    for a in &arms_off {
        let is_arm = mosura::decompile::emit::arms::registry::Recovered::ARMS.contains(&a.as_str());
        if !is_arm && knobs.turn_off(a).is_err() {
            panic!(
                "--arms-off: unknown name `{a}` (arms: {}; switches: {})",
                mosura::decompile::emit::arms::registry::Recovered::ARMS.join(", "),
                mosura::switches::Switch::ALL.iter().map(|s| s.name()).collect::<Vec<_>>().join(", ")
            );
        }
    }
    knobs.x86_32_cspec = rest.iter().position(|a| a == "--cspec").and_then(|i| rest.get(i + 1)).cloned();
    knobs.disabled_analyzers =
        rest.iter().position(|a| a == "--disable-analyzers").and_then(|i| rest.get(i + 1)).cloned();
    // Like the loop-overflow branch form below: this survey's output exists to be RECOMPILED,
    // and the target's shift instructions perform the `& 0x1f` count mask themselves, so every
    // arm elides the lifter's hardware mask (`EmitChoices` shift-mask=hardware; the axis doc in
    // decompile/emit.rs carries the measured probe — under the faithful rendering 64 functions
    // gained a materialized `AND CL,0x1f` the originals never had).
    // The RECOVERED tree is the PRODUCT: one emission whose per-site choices are read from
    // the original's own instructions by the target profile — what a compilerless field run
    // ships, and since the union's retirement (docs/corpus-round-runbook.md) also the
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
    // not work is still in <subject-survey>/: 21 hand-made snapshot directories in five different
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
    // `<subject-survey>/src/` held .c files spanning 2026-08-03 to 2026-08-05 from separate emits.
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
    let regs = WatcomRegs::for_lang(SURVEY_LANG);
    let esp_off = regs.esp_off;
    // Functions whose own returns disagree about the pop — a region-boundary symptom, counted so
    // it cannot be silent. Zero is the expected reading; a nonzero one is a finding to chase.
    let mut cleanup_undecided = 0usize;

    eprintln!("loading the subject via analyze_le_file ...");
    let mut prog = analysis::analyze_le_file_with(std::path::Path::new(&bin), &knobs).expect("analyze_le_file");
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
    // The `proto-pass` switch enables the pass for work on exactly that.
    // DEFAULT-ON since the checker-gated landing at 746 (`--arms-off proto-pass` to get
    // the bare landed world): the whole-program prototype pass feeds per-TU upgrades that
    // the gate stack (scheduler fixed-point, allowed-set, collision, network, signature)
    // adopts only where the models prove the original's placements survive.
    if knobs.on(Switch::ProtoPass) {
        let t = std::time::Instant::now();
        // A `--only` probe restricts the pass to the probed functions' DIRECT STATIC CALLEES
        // (see `recover_prototypes_for`): scan each probed extent's original bytes for CALL
        // targets that are known function entries. The probed functions themselves are
        // included (harmless, and a probed function calling another probed one is covered
        // regardless of scan order).
        let probe_scope: Option<std::collections::HashSet<u64>> = if only.is_empty()
            || rest.iter().any(|a| a == "--probe-full")
        {
            None
        } else {
            Some(analysis::interface::probe_scope(&prog, SURVEY_LANG, &only))
        };
        let marks = analysis::interface::mark_tail_return_writes(&mut prog, SURVEY_LANG, &only);
        for (va, marked, tail) in &marks.probed {
            eprintln!("[survey] tail-return-write {va:#x}: {marked} — last insns (reversed): {tail:?}");
        }
        eprintln!("[survey] tail-return-write mark: {} functions", marks.marked);
        let n_protos = analysis::interface::install_prototypes(&mut prog, probe_scope.as_ref());
        eprintln!(
            "prototype pass: {} functions in {:.1}s{}",
            n_protos,
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
    let passes::Worlds { landed: prog, pp: prog_pp, cons: mut prog_cons } = passes::Worlds::split(prog);
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

    let ents = passes::Entries::of(&prog);
    let entries: Vec<(u64, String)> = ents.list.clone();
    let extent_bounds = |va: u64| -> (u64, Option<u64>) { ents.extent_bounds(&prog, va) };

    let mut mf: std::io::BufWriter<Box<dyn std::io::Write>> = std::io::BufWriter::new(if probing {
        Box::new(std::io::sink())
    } else {
        Box::new(std::fs::File::create(&manifest_path).unwrap())
    });
    // Stamp the manifest itself, so a .tsv that has been copied away from its directory still
    // says which tree produced it. Both consumers skipped exactly one line (compile.sh's
    // `tail -n +2`, compare.py's `header = next(fh)`), so they were changed to drop `#` lines
    // first — otherwise this line pushes the column header into the data.
    let off_names = manifest::off_names(&arms_off, &knobs);
    let [stamp_line, arms_line] = manifest::stamp_lines(&stamp, &rec_arm, &off_names);
    writeln!(mf, "{stamp_line}").unwrap();
    writeln!(mf, "{arms_line}").unwrap();
    eprintln!("arms (recovered emit): {rec_arm}{}", manifest::off_stamp(&off_names));
    writeln!(mf, "{}", manifest::COLUMNS).unwrap();
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
    let watreg = regs.table.clone();

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
    let arg_reg_offs: Vec<u64> = regs.arg_reg_offs.clone();
    // The evidence is a pure function of the ORIGINAL binary and the code that reads it, so
    // it is cached beside the manifest keyed by the emit stamp. The exclusion set costs a
    // mini-decompile of every claimed callee (~170 on the subject — minutes), which a full emit
    // amortizes but which made every `--only` PROBE pay the whole pre-pass: JD measured a
    // single-function probe at five minutes. A probe at the same stamp now loads in
    // milliseconds; a stamp change re-derives.
    let order_cache = out.join(format!("param-orders.{stamp}.tsv"));
    let orders = match std::fs::read_to_string(&order_cache).ok().map(|s| passes::ParamOrders::parse(&s)) {
        Some(po) => {
            eprintln!("param-order evidence: {} sites (cached at {stamp})", po.site_orders.len());
            po
        }
        None => {
            let t = std::time::Instant::now();
            match passes::ParamOrders::collect(&prog, SURVEY_LANG, &ents, &regs) {
                Some(po) => {
                    eprintln!(
                        "param-order evidence: {} sites with a recovered nondefault declaration order \
                         ({} callees excluded: nondefault storage or no decompile) in {:.1}s",
                        po.site_orders.len(),
                        po.excluded.len(),
                        t.elapsed().as_secs_f64()
                    );
                    if !probing || !order_cache.exists() {
                        let _ = std::fs::write(&order_cache, po.render());
                    }
                    po
                }
                None => Default::default(),
            }
        }
    };
    let passes::ParamOrders { site_orders, excluded: order_excluded, networked: order_networked } = orders;

    // GLOBAL WIDTHS FROM THE ORIGINAL'S OWN INSTRUCTIONS (the `global-width` switch, on by default).
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
    // `--arms-off global-width` restores the narrowest-access declaration, the way
    // `--arms-off kernel-net` and `--arms-off cons-reach` restore theirs.
    let global_width_arm = knobs.on(Switch::GlobalWidth);
    let (ram_store_w, ram_read_w) = if global_width_arm {
        let t = std::time::Instant::now();
        let gw = passes::GlobalWidths::collect(&prog, SURVEY_LANG, &ents);
        eprintln!(
            "global-width witness: {} stored addresses, {} read, in {:.1}s",
            gw.store_w.len(),
            gw.read_w.len(),
            t.elapsed().as_secs_f64()
        );
        (gw.store_w, gw.read_w)
    } else {
        (HashMap::new(), HashMap::new())
    };
    let order_excluded = order_excluded;

    let t0 = std::time::Instant::now();
    let (mut ok, mut fail) = (0usize, 0usize);
    // Sorted-entry extents for the zap checker's ORIGINAL-instruction windows (the gap to
    // the next entry, the pre-pass's own fallback extent).
    let next_entry: HashMap<u64, u64> = ents.next.clone();
    // Memoized landed-world answer to "does this callee declare NONDEFAULT parameter
    // storage?" — the definition-side network the caller-side parm post-pass keys on. An
    // upgraded arg list at such a callee can flip that post-pass's arity/width gates
    // (0x3925c's `parm [edx] [eax]` callee), so upgrades refuse those TUs precisely.
    let mut caches = upgrade::UpgradeCaches::default();
    // Per-callee entry-block byte testimony, computed once per callee ([`callee_input_evidence`]).
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
            let mut ctx = upgrade::UpgradeCtx {
                landed: &prog,
                pp,
                cons: &mut prog_cons,
                lang: SURVEY_LANG,
                next_entry: &next_entry,
                regs: &regs,
                order_networked: &order_networked,
                knobs: &knobs,
                cons_probe,
            };
            let mut notes = Vec::new();
            let upgraded = upgrade::upgrade(&mut ctx, &mut caches, fl, *va, name, &mut notes);
            for n in &notes {
                eprintln!("{n}");
            }
            if let Some(f2) = upgraded {
                f = Some(f2);
                f_from_pp = true;
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
            writeln!(mf, "{}", manifest::ManifestRow::decompile_fail(idx, *va, name, flen, manifest::kind_of(name), &head).render()).unwrap();
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
        // after it, and what follows a function is very often DATA. Measured on the subject: the body is
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
        // ARM (the `global-width` switch): the narrowest-access rule above truncates a
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
                // byte factor, the subject's FUN_000377a4): declared at the wider width, the narrower reads
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
        // the RE tracker's proven sources use exactly that form. Without the declaration the emitted
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
            let atu = with_contract(name, contract.as_deref(), atu);
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
            // CALLER-SIDE CLOBBER WITNESS (`buildconfig::saved_for_callees`): a register this
            // function saves in its prologue and restores before its returns without ever
            // touching it was preserved for a callee DECLARED to clobber it — the declaration
            // the original compiled against, which the callee's own recovered clobber set
            // cannot show. Every callee of this TU with a clobber clause takes the register
            // (a caller's saves cannot say which callee); a TU with no clause at all gives
            // it to every callee. the subject's FUN_0004f850: EXACT with `ebx` in its callee's clause.
            let saved = if !knobs.on(Switch::CalleeClobbers) {
                Vec::new()
            } else {
                mosura::recompile::buildconfig::saved_for_callees(&insns)
            };
            let any_modify = merged.values().any(|(_, m)| m.is_some());
            let mut merged = merged;
            if !saved.is_empty() {
                for (_, modify) in merged.values_mut() {
                    if modify.is_some() || !any_modify {
                        modify.get_or_insert_with(Default::default).extend(saved.iter().copied());
                    }
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
            let (rc, aggregates) = aggregate_ram_globals(&rc, &insns, &gsizes, &volatiles, knobs.on(Switch::Agg));
            if mosura::debug::on(mosura::debug::Topic::Survey) && !aggregates.is_empty() {
                for (_, d) in &aggregates {
                    mosura::debug!(mosura::debug::Topic::Survey, "agg {name}: {d}");
                }
            }
            let (rtu, _) = build_tu(&rc, *va, false, &gsizes, &volatiles, &vararg_callees, &aggregates);
            let rtu = with_contract(name, contract.as_deref(), rtu);
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
            // structuring gap. `--arms-off shared-ret` disables.
            let rtu = if f.return_splits > 0 && knobs.on(Switch::SharedRet) {
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
        let tu = with_contract(name, contract.as_deref(), tu);
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
        let row = manifest::ManifestRow {
            idx,
            va: *va,
            name: name.to_string(),
            status: manifest::Status::Ok,
            orig_len: orig_len as u64,
            cov_lo: cov_lo as u64,
            cov_hi: cov_hi as u64,
            smells: smells.clone(),
            orig_hex,
            ir_calls,
            blocks_cfg,
            blocks_reached,
            kind: manifest::kind_of_insns(name, &norm_insns_for_kind),
            contract: if violations.is_empty() { "ok".to_string() } else { format!("wide:{}", violations.join("+")) },
        };
        writeln!(mf, "{}", row.render()).unwrap();

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
        // The gates' bars and sets are the SUBJECT's — its profile's `corpus-gates.tsv` (dev-config
        // `[[subject]]`); a binary with no configured profile emits with no corpus gates and says so.
        let gates_file = mosura::devcfg::subject_for(std::path::Path::new(&bin)).and_then(|s| s.file("corpus-gates.tsv"));
        let no_gates = rest.iter().any(|a| a == "--no-gates");
        if !no_gates && gates_file.is_none() {
            eprintln!("corpus gates: no configured subject profile carries corpus-gates.tsv for {bin}; gates skipped");
        }
        if let (false, Some(gates_file)) = (no_gates, gates_file) {
            use mosura::recompile::gates;
            let baseline = gates::Baseline::load(&gates_file).unwrap_or_else(|e| {
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
