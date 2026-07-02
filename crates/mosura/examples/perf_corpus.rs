//! Perf harness: run the faithful pipeline over the x86-64 datatests (no oracle spawns) and
//! report per-fixture wall time, worst first, plus phase totals. With `MOSURA_PERF=1` also
//! dumps the per-action / per-rule time accounting accumulated by `action::perf`.
//! Usage: `MOSURA_PERF=1 cargo run -q --example perf_corpus [fixture-stem]`.
use mosura::decompile::{action, build, pipeline, printc};
use mosura::sleigh::engine::Spec;
use mosura::{datatest, paths};
use std::time::Instant;

fn main() {
    let only: Option<String> = std::env::args().nth(1);
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    let t0 = Instant::now();
    let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
    let spec_ms = t0.elapsed().as_secs_f64() * 1e3;
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);

    let mut entries: Vec<_> = std::fs::read_dir(paths::datatests_dir())
        .map(|d| d.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    entries.sort();

    let mut times: Vec<(String, f64, f64, f64)> = Vec::new(); // name, build ms, decompile ms, print ms
    for path in entries {
        if path.extension().map(|e| e != "xml").unwrap_or(true) {
            continue;
        }
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        if let Some(o) = &only {
            if &name != o {
                continue;
            }
        }
        if !std::fs::read_to_string(&path).unwrap_or_default().contains("x86:LE:64") {
            continue;
        }
        let Ok(dt) = datatest::parse_file(&path) else { continue };
        if dt.chunks.is_empty() {
            continue;
        }
        let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
        let entry = dt.chunks[0].offset;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let t0 = Instant::now();
            let mut f = build::raw_funcdata_flow_image(&spec, "func", &image, entry, &ctx);
            let t1 = Instant::now();
            pipeline::decompile(&mut f);
            let t2 = Instant::now();
            printc::print_c(&f);
            let t3 = Instant::now();
            (
                (t1 - t0).as_secs_f64() * 1e3,
                (t2 - t1).as_secs_f64() * 1e3,
                (t3 - t2).as_secs_f64() * 1e3,
            )
        }));
        if let Ok((b, d, p)) = r {
            times.push((name, b, d, p));
        }
    }

    times.sort_by(|a, b| (b.1 + b.2 + b.3).partial_cmp(&(a.1 + a.2 + a.3)).unwrap());
    let (mut tb, mut td, mut tp) = (0.0, 0.0, 0.0);
    println!("{:>9} {:>9} {:>9} {:>9}  fixture", "total", "build", "decomp", "print");
    for (n, b, d, p) in &times {
        tb += b;
        td += d;
        tp += p;
        println!("{:>7.1}ms {:>7.1}ms {:>7.1}ms {:>7.1}ms  {n}", b + d + p, b, d, p);
    }
    println!(
        "\nspec load {spec_ms:.1}ms; {} fixtures: total {:.1}ms (build {tb:.1} + decompile {td:.1} + print {tp:.1})",
        times.len(),
        tb + td + tp
    );
    if action::perf::enabled() {
        eprintln!("\n=== per-action / per-rule totals ===");
        action::perf::dump();
    }
}
