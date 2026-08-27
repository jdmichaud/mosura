//! Re-run the corpus gates (`recompile::gates`, review R4) on an existing survey tree — the same
//! functions `war2_survey` runs post-emit (gates 1–6) and `recompile_check` post-verdict (7–8).
//!
//! usage: corpus_gates <tree> [--rec <round>-rec.tsv] [--prev <previous>-rec.tsv]
//!                     [--baseline <tsv>] [--partial]
//!
//! `<tree>` holds `manifest.tsv` and `recovered/`; `--rec` enables gates 7–8 (8 also needs
//! `--prev`); `--partial` marks a `--only` tree (gates 4–6 skip, 7 skips absent guards). Scope for
//! gate 4 = the manifest's `kind` (`gates::kind_is_user`). Exit 1 on any FAIL.
use mosura::recompile::gates;
use std::path::PathBuf;

fn main() {
    const USAGE: &str = "usage: corpus_gates <tree> [--rec <tsv>] [--prev <tsv>] [--baseline <tsv>] [--partial]";
    let a: Vec<String> = std::env::args().skip(1).collect();
    let tree = PathBuf::from(a.first().expect(USAGE));
    let mut rec: Option<PathBuf> = None;
    let mut prev: Option<PathBuf> = None;
    let mut baseline = mosura::paths::corpus_gates_file();
    let mut partial = false;
    let mut i = 1;
    while i < a.len() {
        match a[i].as_str() {
            "--rec" => {
                i += 1;
                rec = Some(PathBuf::from(&a[i]));
            }
            "--prev" => {
                i += 1;
                prev = Some(PathBuf::from(&a[i]));
            }
            "--baseline" => {
                i += 1;
                baseline = PathBuf::from(&a[i]);
            }
            "--partial" => partial = true,
            other => {
                eprintln!("unknown argument {other}\n{USAGE}");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    let baseline = gates::Baseline::load(&baseline).unwrap_or_else(|e| {
        eprintln!("baseline: {e}");
        std::process::exit(2);
    });
    let tus = gates::load_tree(&tree.join("manifest.tsv"), &tree.join("recovered")).unwrap_or_else(|e| {
        eprintln!("tree: {e}");
        std::process::exit(2);
    });
    let mut reports = gates::run_text_gates(&tus, &gates::kind_is_user, &baseline, !partial);
    match rec {
        Some(rec) => {
            let read = |p: &PathBuf| -> std::collections::BTreeMap<u64, gates::VerdictRow> {
                let text = std::fs::read_to_string(p).unwrap_or_else(|e| {
                    eprintln!("{}: {e}", p.display());
                    std::process::exit(2);
                });
                gates::parse_verdicts(&text).unwrap_or_else(|e| {
                    eprintln!("{}: {e}", p.display());
                    std::process::exit(2);
                })
            };
            let cur = read(&rec);
            let prev = prev.as_ref().map(read);
            reports.extend(gates::run_verdict_gates(&cur, prev.as_ref(), &baseline, partial));
        }
        None => {
            reports.push(gates::GateReport::skip("7 guard-sets-EXACT", "no --rec"));
            reports.push(gates::GateReport::skip("8 verdict-regressions", "no --rec"));
        }
    }
    print!("{}", gates::render(&reports));
    println!("corpus gates: {} TUs in the tree, {}", tus.len(), if gates::any_failed(&reports) { "FAIL" } else { "OK" });
    if gates::any_failed(&reports) {
        std::process::exit(1);
    }
}
