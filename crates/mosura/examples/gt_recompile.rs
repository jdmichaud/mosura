//! Ground-truth recompile loop, as a report: source we own → local gcc → decompile → the same gcc
//! → attributed verdict per function (`recompile::groundtruth`). The compiler is held fixed, so
//! the score is the decompiler's alone, and every divergence can be read against the source.
//!
//! Usage: cargo run -q --release --example gt_recompile [-- <program> ...]   (default: all)
//! Output: a per-function table, the per-program summary, and `build/gt-recompile/report.tsv`.
use mosura::recompile::align::{AlignOp, DivergenceClass};
use mosura::recompile::groundtruth::{gcc_available, gcc_programs, recompile_program, source_function};
use mosura::recompile::report::{write_divergence_rows, FnKey};

fn main() {
    if !gcc_available() {
        eprintln!("gcc is required (development-environment requirement)");
        std::process::exit(2);
    }
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // `--fixture <dir>`: also write every function's original bytes as a datatest fixture
    // (`gt_<program>_<symbol>.xml`, arch x86:LE:64:default) into <dir>, for the oracle recipe
    // (`oracle/capture --c`, `dumpc`, `trace-diff.sh`) — Ghidra's reading of the same bytes.
    let fixture_dir = args.iter().position(|a| a == "--fixture").map(|i| {
        let d = args.get(i + 1).cloned().unwrap_or_default();
        args.drain(i..=i + 1);
        std::path::PathBuf::from(d)
    });
    let wanted: Vec<String> = args;
    let progs: Vec<_> = gcc_programs()
        .into_iter()
        .filter(|p| wanted.is_empty() || wanted.iter().any(|w| p.file_stem().is_some_and(|s| s == w.as_str())))
        .collect();
    let workdir = mosura::paths::workspace_root().join("build/gt-recompile");
    std::fs::create_dir_all(&workdir).ok();
    let mut tsv = String::from("program\tsymbol\tva\tverdict\tsim\tweight\tclasses\tnote\n");
    // recompile_check's two table formats, so scripts/war2-mechanism-census.py runs unchanged.
    let mut rec = String::from("idx\tva\tname\tverdict\tbytes\tprimary\tsim\tequal\torig_n\tcand_n\tclasses\n");
    let mut div = String::from(
        "idx\tfn_va\tclass\taddr\toi\tci\torig_n\tcand_n\torig_mn\tcand_mn\torig_regs\tcand_regs\torig_text\tcand_text\n",
    );
    let mut idx = 0usize;
    let (mut tw, mut ts) = (0usize, 0f64);
    for src in progs {
        let source = std::fs::read_to_string(&src).unwrap_or_default();
        let rep = match recompile_program(&src, &workdir) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{}: {e}", src.display());
                continue;
            }
        };
        if let Some(dir) = &fixture_dir {
            std::fs::create_dir_all(dir).ok();
            for (sym, va, bytes) in &rep.original_bytes {
                let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                let xml = format!(
                    "<binaryimage arch=\"x86:LE:64:default:gcc\">\n  <bytechunk space=\"ram\" offset=\"{va:#x}\" readonly=\"true\">\n{hex}\n  </bytechunk>\n</binaryimage>\n"
                );
                std::fs::write(dir.join(format!("gt_{}_{}.xml", rep.program, sym.replace('.', "_"))), xml).ok();
            }
        }
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
            let name = format!("{}/{}", rep.program, f.symbol);
            let key = FnKey { idx: format!("{idx:05}"), va: f.va, name: name.clone() };
            idx += 1;
            let (primary, equal, orig_n, cand_n, bytes) = match &f.checked {
                Some(ch) => (
                    ch.diff.primary.map(|c| c.as_str().to_string()).unwrap_or_default(),
                    ch.diff.equal_insns,
                    ch.diff.orig_insns,
                    ch.diff.cand_insns,
                    format!("{:?}", ch.bytes),
                ),
                None => (String::new(), 0, 0, 0, String::new()),
            };
            rec += &format!(
                "{}\t{:08x}\t{}\t{}\t{}\t{}\t{:.3}\t{}\t{}\t{}\t{}\n",
                key.idx, f.va, name, f.verdict, bytes, primary, f.similarity, equal, orig_n, cand_n, classes.join(",")
            );
            if let Some(ch) = &f.checked {
                write_divergence_rows(&mut div, &key, &ch.diff, &ch.original, &ch.candidate);
            }
            // The three-way read: the real source, our C, and the aligned rows.
            let mut three = String::new();
            three += &format!("==== {name} @{:x}: {} sim={:.3} weight={}\n", f.va, f.verdict, f.similarity, f.weight);
            three += "---- original source\n";
            three += &source_function(&source, &f.symbol).unwrap_or_else(|| "(not found by name)".into());
            three += "\n---- our C (the function only)\n";
            three += &f.body;
            three += "\n---- aligned instructions (original | ours | class)\n";
            if let Some(ch) = &f.checked {
                for op in &ch.diff.ops {
                    let (o, c, cls) = match op {
                        AlignOp::Pair { oi, ci, class } => (Some(&ch.original[*oi]), Some(&ch.candidate[*ci]), class.as_str()),
                        AlignOp::OrigOnly { oi } => (Some(&ch.original[*oi]), None, DivergenceClass::Missing.as_str()),
                        AlignOp::CandOnly { ci } => (None, Some(&ch.candidate[*ci]), DivergenceClass::Extra.as_str()),
                    };
                    three += &format!(
                        "{:<44} | {:<44} | {}\n",
                        o.map(|x| x.text.trim().to_string()).unwrap_or_default(),
                        c.map(|x| x.text.trim().to_string()).unwrap_or_default(),
                        if cls == "equal" { "" } else { cls }
                    );
                }
            } else {
                three += &f.note;
                three += "\n";
            }
            std::fs::write(rep.workdir.join(format!("{}.3way.txt", f.symbol)), three).ok();
        }
        println!("== {}", rep.summary());
    }
    if tw > 0 {
        println!("== ALL: weight {tw}, WGSS {:.4}", ts / tw as f64);
    }
    std::fs::write(workdir.join("report.tsv"), tsv).ok();
    std::fs::write(workdir.join("rec.tsv"), rec).ok();
    std::fs::write(workdir.join("div.tsv"), div).ok();
}
