//! Choose, per function, the emission that reproduces the original — the search over θ at corpus
//! scale.
//!
//! Emission is `IR × θ → C`: for one function, several semantically-equivalent renderings, of
//! which at most some reproduce the original's bytes. A single global θ has to be a compromise,
//! and the compromise is visible in the census — the arm that fixes a comparison-returning
//! function breaks a byte-returning one. Nothing forces one answer for the whole corpus, though:
//! functions compile independently, so θ can be chosen **per function**.
//!
//! This takes several arms (each a whole-corpus emit under one θ), scores every function under
//! each, and reports:
//!
//! - the best arm per function, and the assignment as a whole;
//! - the **union** — how many functions are byte-exact under *some* θ. That is the frontier the
//!   current choice space can reach, and the honest ceiling for a per-function selector.
//!
//! The arms are given rather than searched over: enumerating θ automatically needs the emitter
//! callable per function under a choice vector, which is the next step. The selection is the part
//! that works today, and it is what makes adding an axis worth doing — an axis that helps 20
//! functions and hurts 15 is a net loss globally and a pure gain per function.
use mosura::analysis;
use mosura::decompile::space::Address;
use mosura::recompile::toolchain::{Cached, CompileUnit, Toolchain, WatcomDos};
use mosura::recompile::{emitted_symbol_address, verify, ByteVerdict, Subject};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

struct Arm {
    label: String,
    manifest: String,
    srcdir: String,
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 4 {
        eprintln!(
            "usage: recompile_search <binary> <flags-file> <watcom-dir> \
             <label>=<manifest>:<srcdir> [more arms...] [--cache dir] [--out tsv]"
        );
        std::process::exit(2);
    }
    let (bin, flagsfile, watcom) = (&a[0], &a[1], &a[2]);
    let mut arms: Vec<Arm> = Vec::new();
    let mut cache_dir = std::env::temp_dir().join("mosura-recompile-cache");
    let mut out_path: Option<String> = None;
    let mut assemble: Option<String> = None;
    let mut i = 3;
    while i < a.len() {
        match a[i].as_str() {
            "--cache" => {
                i += 1;
                cache_dir = std::path::PathBuf::from(&a[i]);
            }
            "--out" => {
                i += 1;
                out_path = Some(a[i].clone());
            }
            "--assemble" => {
                i += 1;
                assemble = Some(a[i].clone());
            }
            spec => {
                let (label, rest) = spec.split_once('=').expect("arm: <label>=<manifest>:<srcdir>");
                let (manifest, srcdir) = rest.rsplit_once(':').expect("arm: <label>=<manifest>:<srcdir>");
                arms.push(Arm {
                    label: label.into(),
                    manifest: manifest.into(),
                    srcdir: srcdir.into(),
                });
            }
        }
        i += 1;
    }
    assert!(!arms.is_empty(), "at least one arm");

    let data = std::fs::read(Path::new(bin)).expect("read binary");
    let prog = analysis::loader::load_le(&data).expect("load binary");
    let space = prog.default_space;
    let flags = read_flags(flagsfile);

    // name -> (arm label -> byte-exact?)
    let mut results: BTreeMap<String, (u64, BTreeMap<String, bool>)> = BTreeMap::new();
    // name -> arm label -> the source file that produced that result, so the winning rendering can
    // be assembled without re-deriving which arm it came from.
    let mut sources: BTreeMap<String, BTreeMap<String, (String, String)>> = BTreeMap::new();

    for arm in &arms {
        let prelude = std::fs::read_to_string(Path::new(&arm.srcdir).join("../prelude.h")).unwrap_or_default();
        let work = std::env::temp_dir().join(format!("mosura-search-{}-{}", std::process::id(), arm.label));
        let wcc = WatcomDos::new(watcom, &work, "10.0a")
            .expect("work dir")
            .with_prelude(prelude)
            .owning_work_dir();
        let tc = Cached::new(wcc, &cache_dir).expect("cache dir");

        let rows = read_manifest(&arm.manifest);
        let mut units = Vec::new();
        let mut kept = Vec::new();
        for r in &rows {
            let Ok(source) = std::fs::read_to_string(Path::new(&arm.srcdir).join(format!("{}.c", r.idx))) else {
                continue;
            };
            let fl = flags.get(&r.idx).cloned().unwrap_or_else(|| DEFAULT_FLAGS.to_string());
            units.push(CompileUnit {
                key: r.idx.clone(),
                source,
                flags: fl.split_whitespace().map(str::to_string).collect(),
            });
            kept.push(r);
        }
        let t0 = std::time::Instant::now();
        let outs = tc.compile_batch(&units);
        let (hits, misses) = tc.stats();
        eprintln!(
            "arm {}: {} units, {:.1}s ({hits} cached, {misses} fresh)",
            arm.label,
            units.len(),
            t0.elapsed().as_secs_f64()
        );

        for (row, out) in kept.iter().zip(outs.iter()) {
            let mut exact = false;
            if let Some(obj) = &out.object {
                let mut obytes = Vec::with_capacity(row.len);
                for k in 0..row.len {
                    match prog.memory.byte_at(Address::new(space, row.va + k as u64)) {
                        Some(b) => obytes.push(b),
                        None => break,
                    }
                }
                let subject = Subject { name: row.name.clone(), va: row.va, len: row.len };
                if let Ok(c) = verify(LANG, &obytes, &subject, obj, &emitted_symbol_address) {
                    exact = c.bytes == ByteVerdict::Identical;
                }
            }
            results
                .entry(row.name.clone())
                .or_insert_with(|| (row.va, BTreeMap::new()))
                .1
                .insert(arm.label.clone(), exact);
            sources
                .entry(row.name.clone())
                .or_default()
                .insert(arm.label.clone(), (arm.srcdir.clone(), row.idx.clone()));
        }
    }

    // Per-arm totals, the per-function selection, and the union.
    let mut per_arm: BTreeMap<&str, usize> = BTreeMap::new();
    let mut union = 0usize;
    let mut only_in: BTreeMap<String, usize> = BTreeMap::new();
    let mut tsv = String::from("name\tva\tbest\t");
    tsv.push_str(&arms.iter().map(|a| a.label.as_str()).collect::<Vec<_>>().join("\t"));
    tsv.push('\n');
    for (name, (va, by_arm)) in &results {
        for a in &arms {
            if *by_arm.get(&a.label).unwrap_or(&false) {
                *per_arm.entry(a.label.as_str()).or_default() += 1;
            }
        }
        let winners: Vec<&String> = arms.iter().map(|a| &a.label).filter(|l| by_arm.get(*l) == Some(&true)).collect();
        if !winners.is_empty() {
            union += 1;
            if winners.len() == 1 {
                *only_in.entry(winners[0].clone()).or_default() += 1;
            }
        }
        tsv.push_str(&format!(
            "{name}\t{va:08x}\t{}\t{}\n",
            winners.first().map(|s| s.as_str()).unwrap_or("-"),
            arms.iter()
                .map(|a| if by_arm.get(&a.label) == Some(&true) { "1" } else { "0" })
                .collect::<Vec<_>>()
                .join("\t")
        ));
    }

    eprintln!("\n=== byte-exact per arm ===");
    for a in &arms {
        eprintln!("{:6}  {}", per_arm.get(a.label.as_str()).copied().unwrap_or(0), a.label);
    }
    eprintln!("\n=== per-function selection ===");
    eprintln!("{union:6}  byte-exact under SOME arm (the reachable frontier)");
    let best_single = per_arm.values().copied().max().unwrap_or(0);
    eprintln!("{:6}  gained over the best single arm", union.saturating_sub(best_single));
    if !only_in.is_empty() {
        eprintln!("=== functions only ONE arm reaches ===");
        for (l, n) in &only_in {
            eprintln!("{n:6}  {l}");
        }
    }
    if let Some(p) = out_path {
        std::fs::write(&p, tsv).expect("write");
        eprintln!("rows written to {p}");
    }

    // ASSEMBLE the selection into one source tree: each function taken from the arm that
    // reproduced it, and from the first arm otherwise. This is what makes the selection a
    // deliverable rather than a statistic — the result is a tree in which every function is the
    // best rendering found for it, and it can be verified as a whole.
    //
    // Choosing per function against the original's bytes is not fitting to noise: every arm is a
    // legitimate semantics-preserving rendering of the same IR, and the binary is the specification
    // being recovered. Picking the rendering that reproduces it is the task, not a shortcut around it.
    if let Some(dir) = assemble {
        let src = std::path::Path::new(&dir).join("src");
        std::fs::create_dir_all(&src).expect("assemble dir");
        // The manifest and prelude come from the first arm: the function set is the same in all of
        // them, and a consumer needs exactly one of each.
        let first = &arms[0];
        let _ = std::fs::copy(
            std::path::Path::new(&first.srcdir).join("../prelude.h"),
            std::path::Path::new(&dir).join("prelude.h"),
        );
        let _ = std::fs::copy(&first.manifest, std::path::Path::new(&dir).join("manifest.tsv"));
        let mut taken: BTreeMap<&str, usize> = BTreeMap::new();
        for (name, (_, by_arm)) in &results {
            let winner = arms
                .iter()
                .map(|a| &a.label)
                .find(|l| by_arm.get(*l) == Some(&true))
                .unwrap_or(&first.label);
            let Some((srcdir, idx)) = sources.get(name).and_then(|m| m.get(winner)) else { continue };
            *taken.entry(winner.as_str()).or_default() += 1;
            let _ = std::fs::copy(
                std::path::Path::new(srcdir).join(format!("{idx}.c")),
                src.join(format!("{idx}.c")),
            );
        }
        eprintln!("\n=== assembled into {dir} ===");
        for (l, n) in &taken {
            eprintln!("{n:6}  from {l}");
        }
    }
    eprintln!("recompile_search: COMPLETE");
}

const LANG: &str = "x86:LE:32:default";
const DEFAULT_FLAGS: &str = "-4r -fpi87 -s -onatx";

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
