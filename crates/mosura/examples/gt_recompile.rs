//! Ground-truth recompile loop, as a report: source we own → local gcc → decompile → the same gcc
//! → attributed verdict per function (`recompile::groundtruth`). The compiler is held fixed, so
//! the score is the decompiler's alone, and every divergence can be read against the source.
//!
//! Usage: cargo run -q --release --example gt_recompile [-- <program> ...]   (default: all)
//! Output: a per-function table, the per-program summary, and `build/gt-recompile/report.tsv`.
use mosura::recompile::groundtruth::{gcc_available, gcc_programs, recompile_program};

fn main() {
    if !gcc_available() {
        eprintln!("gcc is required (development-environment requirement)");
        std::process::exit(2);
    }
    let wanted: Vec<String> = std::env::args().skip(1).collect();
    let progs: Vec<_> = gcc_programs()
        .into_iter()
        .filter(|p| wanted.is_empty() || wanted.iter().any(|w| p.file_stem().is_some_and(|s| s == w.as_str())))
        .collect();
    let workdir = mosura::paths::workspace_root().join("build/gt-recompile");
    std::fs::create_dir_all(&workdir).ok();
    let mut tsv = String::from("program\tsymbol\tva\tverdict\tsim\tweight\tclasses\tnote\n");
    let (mut tw, mut ts) = (0usize, 0f64);
    for src in progs {
        let rep = match recompile_program(&src, &workdir) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{}: {e}", src.display());
                continue;
            }
        };
        for f in &rep.functions {
            let classes: Vec<String> = f.classes.iter().map(|(k, v)| format!("{k}={v}")).collect();
            println!(
                "  {:<28} {:>8x} {:<14} {:.3} w={:<4} {} {}",
                f.symbol, f.va, f.verdict, f.similarity, f.weight, classes.join(","), f.note
            );
            tsv += &format!(
                "{}\t{}\t{:x}\t{}\t{:.4}\t{}\t{}\t{}\n",
                rep.program, f.symbol, f.va, f.verdict, f.similarity, f.weight, classes.join(","), f.note
            );
            tw += f.weight;
            ts += f.similarity * f.weight as f64;
        }
        println!("== {}", rep.summary());
    }
    if tw > 0 {
        println!("== ALL: weight {tw}, WGSS {:.4}", ts / tw as f64);
    }
    std::fs::write(workdir.join("report.tsv"), tsv).ok();
}
