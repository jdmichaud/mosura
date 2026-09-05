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

use mosura_core::analysis;
use mosura_core::decompile::emit::EmitChoices;
use mosura_core::switches::{Knobs, Switch};
use mosura_core::recompile::tu::build_prelude;
use mosura_core::recompile::pragma::WatcomRegs;
use mosura_core::recompile::manifest;
use mosura_core::recompile::passes;
use mosura_core::recompile::round;

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
    // `--debug <spec>` configures the diagnostics of this process (`mosura_core::debug`, grammar in its
    // module doc); nothing is read from the environment.
    let argv = mosura_core::debug::from_args(std::env::args().skip(1).collect()).unwrap_or_else(|e| panic!("--debug: {e}"));
    let argv = mosura_core::resources::from_args(argv).unwrap_or_else(|e| panic!("{e}"));
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
        .unwrap_or_else(|| vec![mosura_core::recompile::recovery::canonical_arm()]);
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
        let is_arm = mosura_core::decompile::emit::arms::registry::Recovered::ARMS.contains(&a.as_str());
        if !is_arm && knobs.turn_off(a).is_err() {
            panic!(
                "--arms-off: unknown name `{a}` (arms: {}; switches: {})",
                mosura_core::decompile::emit::arms::registry::Recovered::ARMS.join(", "),
                mosura_core::switches::Switch::ALL.iter().map(|s| s.name()).collect::<Vec<_>>().join(", ")
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
            a.shift_mask = mosura_core::decompile::emit::ShiftMask::Hardware;
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
    // Functions whose own returns disagree about the pop — a region-boundary symptom, counted so
    // it cannot be silent. Zero is the expected reading; a nonzero one is a finding to chase.

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
    let passes::Worlds { landed: prog, pp: prog_pp, cons: prog_cons } = passes::Worlds::split(prog);
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
    // caller idx -> (callee va -> argument count at the caller's call sites, None on
    // disagreement between sites). The post-pass applies a callee's pragma only where the
    // caller's arity matches the pragma's parameter count: the callee's rendered params are
    // its USED slots only, and a pragma shorter than the caller's argument list makes
    // Watcom overflow the extra arguments to the stack (measured: FUN_000345f4 passes
    // three args to a callee whose only USED param is BX — `parm [bx]` turned two
    // register moves into three PUSHes).
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
    mosura_core::decompile::structure::set_force_loop_overflow(true);

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
    let widths = if global_width_arm {
        let t = std::time::Instant::now();
        let gw = passes::GlobalWidths::collect(&prog, SURVEY_LANG, &ents);
        eprintln!(
            "global-width witness: {} stored addresses, {} read, in {:.1}s",
            gw.store_w.len(),
            gw.read_w.len(),
            t.elapsed().as_secs_f64()
        );
        gw
    } else {
        passes::GlobalWidths { store_w: HashMap::new(), read_w: HashMap::new() }
    };

    let t0 = std::time::Instant::now();
    let (mut ok, mut fail) = (0usize, 0usize);
    // Sorted-entry extents for the zap checker's ORIGINAL-instruction windows (the gap to
    // the next entry, the pre-pass's own fallback extent).
    // Memoized landed-world answer to "does this callee declare NONDEFAULT parameter
    // storage?" — the definition-side network the caller-side parm post-pass keys on. An
    // upgraded arg list at such a callee can flip that post-pass's arity/width gates
    // (0x3925c's `parm [edx] [eax]` callee), so upgrades refuse those TUs precisely.
    // Per-callee entry-block byte testimony, computed once per callee ([`callee_input_evidence`]).
    let mut st = round::EmitState::new(
        round::ProgramFacts {
            lang: SURVEY_LANG,
            knobs: knobs.clone(),
            worlds: passes::Worlds { landed: prog, pp: prog_pp, cons: prog_cons },
            entries: ents,
            regs,
            orders,
            widths,
        },
        round::EmitOpts { arms: arms.clone(), rec_arm, arms_off: arms_off.clone(), recovered: recovered_dir.is_some(), cons_probe },
    );
    for (idx, (va, name)) in entries.iter().enumerate() {
        if !only.is_empty() && !only.contains(va) {
            continue;
        }
        *panic_msg.lock().unwrap() = None;
        let e = match st.emit_function(idx, *va, name) {
            Ok(e) => e,
            Err(failed) => {
                fail += 1;
                let head = panic_msg.lock().unwrap().clone().unwrap_or_else(|| "returned None".into());
                let head = head.replace(['\t', '\n'], " ");
                let head: String = head.chars().take(120).collect();
                writeln!(mf, "{}", manifest::ManifestRow::decompile_fail(idx, *va, name, failed.weight, manifest::kind_of(name), &head).render()).unwrap();
                continue;
            }
        };
        for n in &e.notes {
            eprintln!("{n}");
        }
        ok += 1;
        // INSTRUMENT (`--debug survey`): the three candidate answers to "where does this function
        // end" -- the next-entry heuristic actually used, mosura's own recorded body, and the
        // decompiler's instruction coverage -- so the choice between them is a measurement.
        if mosura_core::debug::on(mosura_core::debug::Topic::Survey) {
            println!(
                "EXTENT\t{:08x}\t{}\t{}\t{}",
                *va,
                e.extent.end_untrimmed - *va,
                e.extent.body_end.map(|b| b.saturating_sub(*va) as i64).unwrap_or(-1),
                e.extent.cov_hi.saturating_sub(*va)
            );
        }
        if !probing {
            std::fs::write(raw_dir.join(format!("{va:08x}.c")), &e.reference_c).unwrap();
        }
        // Arms past the first: same function, same declarations, a different rendering of the body.
        for (ai, atu) in e.arm_tus.iter().enumerate() {
            if only.is_empty() {
                std::fs::write(arm_dirs[ai + 1].join(format!("{idx:05}.c")), atu).unwrap();
            }
        }
        // RECOVERED emission (`--recovered <dir>`): written, or printed under `--only`.
        if let (Some(dir), Some(rtu)) = (&recovered_dir, &e.recovered_tu) {
            if only.is_empty() {
                std::fs::write(dir.join(format!("{idx:05}.c")), rtu).unwrap();
            } else {
                println!("/* ===== RECOVERED (no-compiler field path) ===== */");
                println!("{rtu}");
            }
        }
        let f = &e.f;
        let tu = &e.reference_tu;
        let orig_len = e.extent.region.len();
        if !only.is_empty() {
            // The post-pipeline IR, on request. A question about what the C says is often really a
            // question about what the op graph holds — here, whether a value the original widens is
            // still four bytes wide by the time the printer sees it. Answering that from the C is
            // guesswork; the graph states it.
            if mosura_core::debug::on(mosura_core::debug::Topic::RawIr) {
                println!("{}", f.print_raw());
            }
            // The recovered parameter STORAGE alongside the C, so a signature question ("why is
            // this argument in the wrong register?") is answered by the same one-function run.
            let slots = mosura_core::decompile::printc::rendered_param_slots(f);
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
                let vn = f.vn(mosura_core::decompile::varnode::VarnodeId(i));
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
            let raw: Vec<String> = e
                .proto
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
        std::fs::write(src_dir.join(format!("{idx:05}.c")), tu).unwrap();

        if !e.violations.is_empty() {
            contract_hist.entry(e.violations.join(",")).or_insert(0usize);
            for v in &e.violations {
                *contract_counts.entry(v.clone()).or_insert(0usize) += 1;
            }
            contract_bad += 1;
        }
        writeln!(mf, "{}", e.row.render()).unwrap();

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
                    .and_then(|st| idx_va.get(st))
                    .copied();
                if let Some(out) = st.contracts.patch_caller(&src, caller_va) {
                    std::fs::write(&path, out).unwrap();
                    patched += 1;
                }
            }
        }
        eprintln!("caller-side parm pragmas: {patched} TU(s) patched");
    }
    eprintln!("EMIT done: ok={ok} fail={fail} in {:?}", t0.elapsed());
    let cleanup_undecided = st.cleanup_undecided;
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
        let gates_file = mosura_core::devcfg::subject_for(std::path::Path::new(&bin)).and_then(|s| s.file("corpus-gates.tsv"));
        let no_gates = rest.iter().any(|a| a == "--no-gates");
        if !no_gates && gates_file.is_none() {
            eprintln!("corpus gates: no configured subject profile carries corpus-gates.tsv for {bin}; gates skipped");
        }
        if let (false, Some(gates_file)) = (no_gates, gates_file) {
            use mosura_core::recompile::gates;
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
