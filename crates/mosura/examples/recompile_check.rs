//! Verify emitted C against the original bytes, one function at a time, through the real compiler.
//!
//! This is the development loop for byte-exactness. The alternative — re-emit the whole survey,
//! compile three thousand translation units, then score — takes about half an hour and answers
//! per function rather than per defect, which is far too slow to iterate a decompiler change
//! against. Here one function costs about a second, and repeats cost nothing because the compiler
//! driver caches on source content.
//!
//! It is also the whole measurement path in one program: source in, compiler, symbolic relink,
//! instruction-level diff, verdict. Nothing is shelled out to, so there is no way for the emit,
//! the objects and the manifest to drift apart between stages — which is the failure that has
//! silently invalidated batteries before.
//!
//! Usage:
//!   recompile_check <binary> <manifest> <src-dir> <flags-file> <watcom-dir>
//!                   [--only <idx|0xva>,...] [--cache <dir>] [--verbose] [--out <tsv>] [--divergences <tsv>]
//!
//! `<flags-file>` maps a function stem to its compiler flags, one per line (`<stem> <flags...>`).
//! Which flags the original build used is a recovery problem of its own; this tool consumes the
//! answer rather than guessing it.
use mosura::analysis;
use mosura::decompile::space::Address;
use mosura::recompile::toolchain::{Cached, CompileUnit, Toolchain, WatcomDos};
use mosura::recompile::{
    emitted_symbol_address, ByteVerdict, DivergenceClass, FnKey, Subject, Verdict,
    DIVERGENCE_HEADER,
};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 5 {
        eprintln!(
            "usage: recompile_check <binary> <manifest> <src-dir> <flags-file> <watcom-dir> \
             [--only ids] [--cache dir] [--verbose] [--include-library] [--out tsv] [--divergences tsv]"
        );
        std::process::exit(2);
    }
    let (bin, manifest, srcdir, flagsfile, watcom) = (&a[0], &a[1], &a[2], &a[3], &a[4]);
    let mut only: Vec<String> = Vec::new();
    let mut cache_dir = std::env::temp_dir().join("mosura-recompile-cache");
    let mut verbose = false;
    let mut include_library = false;
    let mut out_path: Option<String> = None;
    let mut div_path: Option<String> = None;
    let mut i = 5;
    while i < a.len() {
        match a[i].as_str() {
            "--only" => {
                i += 1;
                only = a[i].split(',').map(|s| s.trim().to_string()).collect();
            }
            "--cache" => {
                i += 1;
                cache_dir = std::path::PathBuf::from(&a[i]);
            }
            "--verbose" => verbose = true,
            "--include-library" => include_library = true,
            "--out" => {
                i += 1;
                out_path = Some(a[i].clone());
            }
            "--divergences" => {
                i += 1;
                div_path = Some(a[i].clone());
            }
            o => panic!("unknown argument {o}"),
        }
        i += 1;
    }

    let rows = read_manifest(manifest);
    // `recover` derives the per-function options from each original function's own prologue
    // instead of reading a table. That is the general path: a second binary has no table.
    let recover_flags = flagsfile == "recover";
    let flags = if recover_flags { HashMap::new() } else { read_flags(flagsfile) };
    let prelude = std::fs::read_to_string(Path::new(srcdir).join("../prelude.h"))
        .or_else(|_| std::fs::read_to_string("prelude.h"))
        .unwrap_or_default();

    let data = std::fs::read(Path::new(bin)).expect("read binary");
    let prog = analysis::loader::load_le(&data).expect("load binary");
    let space = prog.default_space;

    let work = std::env::temp_dir().join(format!("mosura-check-{}", std::process::id()));
    let wcc = WatcomDos::new(watcom, &work, "10.0a").expect("work dir").with_prelude(prelude).owning_work_dir();
    let tc = Cached::new(wcc, &cache_dir).expect("cache dir");

    // Select the functions to check, then compile them all in one pass so a whole-corpus run is
    // one batched sweep rather than three thousand emulator sessions.
    // Library code is EXCLUDED by default. `memset`, `printf` and the CRT startup are reproduced
    // by linking the Watcom libraries, not by decompiling them, so counting them measures the
    // toolchain rather than the port. Measured on WAR2: 5 of 131 library functions are byte-exact
    // (3.8%) against 534 of 2892 of the subject's own (18.5%), so excluding them RAISES the ratio.
    // They were dragging it down, not flattering it. `--include-library` restores them for anyone
    // measuring the identification itself.
    //
    // An explicit `--only` overrides the exclusion: naming a function is a request for it, and
    // silently returning nothing would look like a broken filter.
    let excluded: Vec<&Row> =
        rows.iter().filter(|r| !include_library && only.is_empty() && (r.kind == "library" || r.kind == "asm")).collect();
    let selected: Vec<&Row> = rows
        .iter()
        .filter(|r| include_library || !only.is_empty() || (r.kind != "library" && r.kind != "asm"))
        .filter(|r| {
            only.is_empty()
                || only.iter().any(|o| {
                    o == &r.idx
                        || o.trim_start_matches("0x").eq_ignore_ascii_case(&format!("{:x}", r.va))
                        || o == &r.name
                })
        })
        .collect();
    if selected.is_empty() {
        eprintln!("no functions matched");
        std::process::exit(1);
    }

    // The stack and frame pointers, by name for this language. A general driver would read the
    // stack pointer from the compiler spec's `<stackpointer>`; there is no declaration of a frame
    // pointer anywhere, so it is named here and passed in, which is why `buildconfig::detect`
    // takes both as parameters rather than assuming an architecture.
    let (sp, fp) = mosura::lang::load_cached(LANG)
        .and_then(|(spec, _)| Some(((spec.register_offset("ESP")?, 4u32), (spec.register_offset("EBP")?, 4u32))))
        .expect("stack/frame pointer registers");
    let profile = mosura::recompile::buildconfig::watcom_10_0a();

    let mut units = Vec::new();
    let mut kept: Vec<&Row> = Vec::new();
    let mut emit_failed: Vec<&Row> = Vec::new();
    for r in &selected {
        let path = Path::new(srcdir).join(format!("{}.c", r.idx));
        let Ok(source) = std::fs::read_to_string(&path) else {
            eprintln!("{}: no source at {}", r.name, path.display());
            emit_failed.push(r);
            continue;
        };
        let unit_flags: Vec<String> = if recover_flags {
            // A short read means the recorded extent runs past readable memory. Truncating
            // silently would compare the candidate against FEWER original bytes than the function
            // has, which reads as agreement about bytes that were never examined -- the failure
            // mode is a false EXACT, so it has to be audible.
            let mut obytes = Vec::with_capacity(r.len);
            for k in 0..r.len {
                match prog.memory.byte_at(Address::new(space, r.va + k as u64)) {
                    Some(b) => obytes.push(b),
                    None => {
                        eprintln!(
                            "{}: extent runs past readable memory -- {} of {} bytes readable from {:#x}; \
                             verdict covers only what was read",
                            r.name,
                            obytes.len(),
                            r.len,
                            r.va
                        );
                        break;
                    }
                }
            }
            let insns = mosura::recompile::insn::normalize(
                LANG,
                &obytes,
                r.va,
                &mosura::recompile::insn::NoReloc,
            )
            .expect("language tables");
            profile.flags_for(&mosura::recompile::buildconfig::detect(&insns, sp, fp))
        } else {
            flags
                .get(&r.idx)
                .cloned()
                .unwrap_or_else(|| DEFAULT_FLAGS.to_string())
                .split_whitespace()
                .map(str::to_string)
                .collect()
        };
        units.push(CompileUnit { key: r.idx.clone(), source, flags: unit_flags });
        kept.push(r);
    }

    let t0 = std::time::Instant::now();
    let outs = tc.compile_batch(&units);
    let (hits, misses) = tc.stats();
    eprintln!(
        "compiled {} units in {:.1}s ({hits} cached, {misses} fresh)",
        units.len(),
        t0.elapsed().as_secs_f64()
    );

    let resolver = emitted_symbol_address;

    // The weight a candidate-less row carries in the global similarity: its original
    // instruction count, from lifting the recorded extent.
    let orig_insns_of = |row: &Row| -> usize {
        let mut obytes = Vec::with_capacity(row.len);
        for k in 0..row.len {
            match prog.memory.byte_at(Address::new(space, row.va + k as u64)) {
                Some(b) => obytes.push(b),
                None => break,
            }
        }
        mosura::recompile::insn::normalize(LANG, &obytes, row.va, &mosura::recompile::insn::NoReloc)
            .expect("language tables")
            .len()
    };

    let mut census: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut causes: BTreeMap<&'static str, usize> = BTreeMap::new();
    let (mut identical, mut reloc_only) = (0usize, 0usize);
    // Global similarity: the micro-average over instructions, sum(equal) / sum(max(orig,cand)),
    // so a function weighs what it is worth in code and a candidate that bloats past the
    // original weighs its bloat. This surfaces progress that the EXACT count cannot: on this
    // corpus the byte-exact functions are 20% of the population but 5% of the code bytes, so
    // an unweighted mean is flattered by small trivial functions. Functions that produced no
    // candidate at all (emit failure, compile failure, unreadable object) count as ZERO with
    // their full original weight, never excluded -- excluding them would make "it finally
    // compiles, but mismatches" LOWER the score. The unweighted mean is reported as a
    // secondary, being more sensitive to progress on small functions. Either number is a
    // trend diagnostic between verdict transitions, not a target: alignment can rise while
    // semantics diverge, so the verdicts stay the ground truth.
    let (mut agg_equal, mut agg_denom) = (0u64, 0u64);
    let (mut sim_sum, mut sim_n) = (0f64, 0usize);
    let mut tsv =
        String::from("idx\tva\tname\tverdict\tbytes\tprimary\tsim\tequal\torig_n\tcand_n\tclasses\n");
    let mut divs = String::from(DIVERGENCE_HEADER);
    for (row, out) in kept.iter().zip(outs.iter()) {
        if !out.ok() {
            *census.entry("COMPILE_FAIL").or_default() += 1;
            let n = orig_insns_of(row);
            agg_denom += n as u64;
            sim_n += 1;
            if verbose {
                println!("=== {} : COMPILE_FAIL ===\n{}", row.name, out.log.trim());
            }
            tsv.push_str(&format!(
                "{}\t{:08x}\t{}\tCOMPILE_FAIL\t\t\t\t0\t{n}\t0\t\n",
                row.idx, row.va, row.name
            ));
            continue;
        }
        let mut obytes = Vec::with_capacity(row.len);
        for k in 0..row.len {
            match prog.memory.byte_at(Address::new(space, row.va + k as u64)) {
                Some(b) => obytes.push(b),
                None => break,
            }
        }
        let subject = Subject { name: row.name.clone(), va: row.va, len: row.len };
        // Table-correspondence search window: the original's jump tables sit near the
        // function (WAR2 places them in the inter-function gap right before the entry).
        // Nearest match to the function wins if the same content appears more than once.
        let win_lo = row.va.saturating_sub(0x2_0000);
        let win = prog.memory.read_window(Address::new(space, win_lo), (0x4_0000 + row.len).min(0x10_0000));
        let find_near = |needle: &[u8]| -> Option<u64> {
            if needle.is_empty() {
                return None;
            }
            let mut best: Option<u64> = None;
            let mut pos = 0usize;
            while pos + needle.len() <= win.len() {
                match win[pos..].windows(needle.len()).position(|w| w == needle) {
                    Some(rel) => {
                        let p = win_lo + (pos + rel) as u64;
                        let better = match best {
                            None => true,
                            Some(b) => p.abs_diff(row.va) < b.abs_diff(row.va),
                        };
                        if better {
                            best = Some(p);
                        }
                        pos += rel + 1;
                    }
                    None => break,
                }
            }
            best
        };
        let checked = match mosura::recompile::verify_with_image(LANG, &obytes, &subject, out.object.as_ref().unwrap(), &resolver, Some(&find_near)) {
            Ok(c) => c,
            Err(e) => {
                *census.entry("OBJ_ERROR").or_default() += 1;
                let n = orig_insns_of(row);
                agg_denom += n as u64;
                sim_n += 1;
                tsv.push_str(&format!(
                    "{}\t{:08x}\t{}\tOBJ_ERROR\t\t\t\t0\t{n}\t0\t\n",
                    row.idx, row.va, row.name
                ));
                eprintln!("{}: {e}", row.name);
                continue;
            }
        };
        let (diff, orig, cnorm) = (&checked.diff, &checked.original, &checked.candidate);
        match checked.bytes {
            ByteVerdict::Identical => identical += 1,
            ByteVerdict::IdenticalOutsideRelocations => reloc_only += 1,
            ByteVerdict::Different => {}
        }
        *census.entry(diff.verdict.as_str()).or_default() += 1;
        agg_equal += diff.equal_insns as u64;
        agg_denom += diff.orig_insns.max(diff.cand_insns) as u64;
        sim_sum += diff.similarity;
        sim_n += 1;
        if let Some(p) = diff.primary {
            *causes.entry(p.as_str()).or_default() += 1;
        }
        let classes = diff
            .class_counts
            .iter()
            .filter(|(c, _)| **c != DivergenceClass::Equal)
            .map(|(c, n)| format!("{}={}", c.as_str(), n))
            .collect::<Vec<_>>()
            .join(",");
        tsv.push_str(&format!(
            "{}\t{:08x}\t{}\t{}\t{:?}\t{}\t{:.3}\t{}\t{}\t{}\t{}\n",
            row.idx,
            row.va,
            row.name,
            diff.verdict.as_str(),
            checked.bytes,
            diff.primary.map(|p| p.as_str()).unwrap_or(""),
            diff.similarity,
            diff.equal_insns,
            diff.orig_insns,
            diff.cand_insns,
            classes
        ));
        if div_path.is_some() {
            let key = FnKey { idx: row.idx.clone(), va: row.va, name: row.name.clone() };
            mosura::recompile::write_divergence_rows(&mut divs, &key, diff, orig, cnorm);
        }
        if verbose {
            println!("=== {} @ {:08x} : {} ===", row.name, row.va, diff.verdict.as_str());
            for op in &diff.ops {
                match op {
                    mosura::recompile::AlignOp::Pair { oi, ci, class } => println!(
                        "{} {:08x}  {:<36} | {:<36} {}",
                        if *class == DivergenceClass::Equal { " " } else { "~" },
                        orig[*oi].addr,
                        orig[*oi].text,
                        cnorm[*ci].text,
                        if *class == DivergenceClass::Equal { String::new() } else { format!("[{}]", class.as_str()) }
                    ),
                    mosura::recompile::AlignOp::OrigOnly { oi } => {
                        println!("- {:08x}  {:<36} | {:<36} [missing]", orig[*oi].addr, orig[*oi].text, "")
                    }
                    mosura::recompile::AlignOp::CandOnly { ci } => {
                        println!("+ {:08x}  {:<36} | {:<36} [extra]", cnorm[*ci].addr, "", cnorm[*ci].text)
                    }
                }
            }
        }
    }

    // A selected function with no emitted source never reached the compiler, but it is still
    // part of the corpus being measured: it scores zero at its full weight, same as a compile
    // failure, and gets a row so the global number is recomputable from the TSV alone.
    for row in &emit_failed {
        *census.entry("EMIT_FAIL").or_default() += 1;
        let n = orig_insns_of(row);
        agg_denom += n as u64;
        sim_n += 1;
        tsv.push_str(&format!(
            "{}\t{:08x}\t{}\tEMIT_FAIL\t\t\t\t0\t{n}\t0\t\n",
            row.idx, row.va, row.name
        ));
    }

    eprintln!("\n=== byte-clean ===");
    eprintln!("{identical:6}  identical (relocations resolved AND matching)");
    eprintln!("{reloc_only:6}  identical outside relocation sites, but a site disagrees");
    eprintln!("{:6}  TOTAL byte-clean under the permissive reading", identical + reloc_only);
    if !excluded.is_empty() {
        eprintln!(
            "\n{:6}  library functions excluded (identified by signature matching; \
             --include-library to measure them)",
            excluded.len()
        );
    }
    eprintln!("\n=== verdicts ===");
    for (k, v) in &census {
        eprintln!("{v:6}  {k}");
    }
    if sim_n > 0 {
        eprintln!("=== global similarity ===");
        eprintln!(
            "{:.4}  insn-weighted ({agg_equal}/{agg_denom} instructions over {sim_n} functions)",
            agg_equal as f64 / agg_denom.max(1) as f64
        );
        eprintln!("{:.4}  unweighted mean of per-function sim", sim_sum / sim_n as f64);
    }
    if !causes.is_empty() {
        eprintln!("=== dominant cause ===");
        let mut c: Vec<_> = causes.iter().collect();
        c.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
        for (k, v) in c {
            eprintln!("{v:6}  {k}");
        }
    }
    if let Some(p) = out_path {
        std::fs::write(&p, tsv).expect("write");
        eprintln!("rows written to {p}");
    }
    if let Some(p) = div_path {
        let n = divs.lines().count().saturating_sub(1);
        std::fs::write(&p, divs).expect("write");
        eprintln!("{n} divergence rows written to {p}");
    }
    eprintln!("recompile_check: COMPLETE");
    // A non-zero exit when nothing reached EXACT makes this usable as a gate on one function.
    if only.len() == 1 && census.get(Verdict::Exact.as_str()).copied().unwrap_or(0) == 0 {
        std::process::exit(1);
    }
}

const LANG: &str = "x86:LE:32:default";
const DEFAULT_FLAGS: &str = "-4r -fpi87 -s -onatx";

struct Row {
    idx: String,
    va: u64,
    name: String,
    len: usize,
    /// `user` or `library`, from the manifest's `kind` column. Manifests emitted before that
    /// column existed have no opinion, and are read as `user` so an old file still measures
    /// everything it used to rather than silently losing rows.
    kind: String,
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
                kind: f.get(12).unwrap_or(&"user").to_string(),
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
