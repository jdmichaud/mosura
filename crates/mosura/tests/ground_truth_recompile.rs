//! Ground-truth recompile gate (`docs/ground-truth-corpus.md`, decompiler level): every program
//! in `oracle/ground-truth/src` is built with the local gcc, decompiled, recompiled with the same
//! gcc, and each function's verdict/similarity is compared against a PER-MACHINE baseline
//! (`build/gt-recompile/baseline.tsv`). gcc is a development-environment requirement; its version
//! floats, so nothing here is compared against committed bytes — the first run on a machine writes
//! the baseline, later runs fail on any verdict regression (per function, and the per-program
//! FUNCTIONAL verdict: our functions linked into the program and run against the original) or a
//! WGSS drop over 0.01, and `MOSURA_GT_BASELINE=update` rewrites it after an accepted change.
use std::collections::BTreeMap;

use mosura::recompile::groundtruth::{gcc_available, gcc_programs, recompile_program, EmitPlan, GtReport, Target};

fn rank(v: &str) -> u8 {
    match v {
        "EXACT" | "PASS" => 5,
        "SAME_CODE" => 4,
        "SAME_SHAPE" => 3,
        "MISMATCH" => 2,
        "COMPILE_FAIL" => 1,
        v if v.starts_with("FAIL") => 1,
        _ => 0,
    }
}

#[test]
fn decompile_recompile_does_not_regress_against_the_local_baseline() {
    assert!(gcc_available(), "gcc is required by the development environment (ground-truth recompile gate)");
    let workdir = mosura::paths::workspace_root().join("build/gt-recompile");
    std::fs::create_dir_all(&workdir).unwrap();
    let mut reports: Vec<GtReport> = Vec::new();
    for src in gcc_programs() {
        reports.push(
            recompile_program(&src, &workdir, Target::Gcc64, &EmitPlan::plain())
                .unwrap_or_else(|e| panic!("{}: {e}", src.display())),
        );
    }
    let mut current: BTreeMap<(String, String), (String, f64, usize)> = BTreeMap::new();
    for r in &reports {
        println!("{}", r.summary());
        for f in &r.functions {
            current.insert((r.program.clone(), f.symbol.clone()), (f.verdict.clone(), f.similarity, f.weight));
        }
        // The functional verdict (the program linked from our functions, RUN against the
        // original): a PASS that becomes a FAIL is wrong code, the regression that matters most.
        let functional = r.functional.split('(').next().unwrap_or("").trim().to_string();
        current.insert((r.program.clone(), "@functional".into()), (functional, 0.0, 0));
    }
    let wgss = |m: &BTreeMap<(String, String), (String, f64, usize)>| {
        let w: usize = m.values().map(|v| v.2).sum();
        if w == 0 { 0.0 } else { m.values().map(|v| v.1 * v.2 as f64).sum::<f64>() / w as f64 }
    };
    let baseline_path = workdir.join("baseline.tsv");
    let serialize = |m: &BTreeMap<(String, String), (String, f64, usize)>| {
        let mut s = String::from("program\tsymbol\tverdict\tsim\tweight\n");
        for ((p, f), (v, sim, w)) in m {
            s += &format!("{p}\t{f}\t{v}\t{sim:.4}\t{w}\n");
        }
        s
    };
    let update = std::env::var("MOSURA_GT_BASELINE").as_deref() == Ok("update");
    let Some(text) = std::fs::read_to_string(&baseline_path).ok().filter(|_| !update) else {
        std::fs::write(&baseline_path, serialize(&current)).unwrap();
        println!("baseline written: {} (WGSS {:.4})", baseline_path.display(), wgss(&current));
        return;
    };
    let mut baseline: BTreeMap<(String, String), (String, f64, usize)> = BTreeMap::new();
    for line in text.lines().skip(1) {
        let c: Vec<&str> = line.split('\t').collect();
        if c.len() >= 5 {
            baseline.insert((c[0].into(), c[1].into()), (c[2].into(), c[3].parse().unwrap_or(0.0), c[4].parse().unwrap_or(0)));
        }
    }
    let mut regressions = Vec::new();
    for (k, (v, _, _)) in &baseline {
        if let Some((nv, _, _)) = current.get(k) {
            if rank(nv) < rank(v) {
                regressions.push(format!("{}/{}: {v} -> {nv}", k.0, k.1));
            }
        }
    }
    let (b, c) = (wgss(&baseline), wgss(&current));
    println!("WGSS baseline {b:.4} -> current {c:.4}");
    if c < b - 0.01 {
        regressions.push(format!("WGSS dropped {b:.4} -> {c:.4}"));
    }
    assert!(regressions.is_empty(), "ground-truth recompile regressions (MOSURA_GT_BASELINE=update to accept):\n  {}", regressions.join("\n  "));
}
