//! Choose, per function, the emitted rendering that reassembles to the original's bytes.
//!
//! The emit stage produces several *arms* — the same recovered program printed under different
//! emission choice vectors (`decompile::emit::EmitChoices`). Which arm the original compiler was
//! given is not derivable from the IR, so each is compiled and byte-verified and the answer is
//! whichever one reassembles exactly. This is the select half of that search.
//!
//! Two things this deliberately does **not** do, because both would turn a search into overfitting:
//!
//! - It selects on the **verdict**, never on a similarity score. An arm is chosen because the
//!   function's bytes are reproduced, not because it scored better; a scored selection would
//!   optimize the instrument instead of the goal.
//! - It writes the winning sources out as a tree. A per-function claim that "some arm matched" is
//!   not checkable; a directory that can be recompiled is. `--out-src` materializes it, and the
//!   arm that won each function is recorded alongside so the result is reproducible rather than
//!   merely asserted.
//!
//! Usage:
//!   recompile_select <tag>=<verdicts.tsv>:<srcdir> ... [--out <tsv>] [--out-src <dir>]
//!
//! Each verdict TSV is a `recompile_check --out` file. Arms are tried in the order given, so the
//! leftmost arm wins a tie — put the reference rendering first and a function is only attributed to
//! a non-default choice when the default genuinely does not reproduce it.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

struct Arm {
    tag: String,
    src: PathBuf,
    /// idx -> (verdict, va, name)
    rows: BTreeMap<String, (String, String, String)>,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut arms: Vec<Arm> = Vec::new();
    let mut out_tsv: Option<String> = None;
    let mut out_src: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out_tsv = Some(args[i].clone());
            }
            "--out-src" => {
                i += 1;
                out_src = Some(args[i].clone());
            }
            spec => {
                let (tag, rest) = spec.split_once('=').unwrap_or_else(|| usage("expected <tag>=<tsv>:<srcdir>"));
                let (tsv, src) = rest.rsplit_once(':').unwrap_or_else(|| usage("expected <tsv>:<srcdir>"));
                arms.push(Arm { tag: tag.to_string(), src: PathBuf::from(src), rows: read_verdicts(tsv) });
            }
        }
        i += 1;
    }
    if arms.is_empty() {
        usage::<()>("give at least one arm");
    }

    // Every function any arm knows about — an arm that failed to emit one is simply absent for it,
    // which must not silently shrink the denominator.
    let mut all: BTreeMap<String, ()> = BTreeMap::new();
    for a in &arms {
        for k in a.rows.keys() {
            all.insert(k.clone(), ());
        }
    }

    if let Some(d) = &out_src {
        std::fs::create_dir_all(d).expect("create --out-src dir");
    }

    let mut per_arm_wins: BTreeMap<&str, usize> = BTreeMap::new();
    let mut exact = 0usize;
    let mut tsv = String::from("idx\tva\tname\tarm\tverdict\n");
    let mut unresolved: BTreeMap<String, usize> = BTreeMap::new();
    for idx in all.keys() {
        // First arm reaching EXACT wins; arms are tried in the order given.
        let win = arms.iter().find(|a| a.rows.get(idx).is_some_and(|(v, _, _)| v == "EXACT"));
        // Nothing reached EXACT: report the leftmost arm that has an opinion at all, so the row
        // still names a verdict to work on rather than vanishing.
        let fallback = arms.iter().find(|a| a.rows.contains_key(idx));
        let chosen = win.or(fallback).expect("idx came from some arm");
        let (verdict, va, name) = chosen.rows.get(idx).cloned().unwrap_or_default();
        if win.is_some() {
            exact += 1;
            *per_arm_wins.entry(chosen.tag.as_str()).or_default() += 1;
        } else {
            *unresolved.entry(verdict.clone()).or_default() += 1;
        }
        tsv.push_str(&format!("{idx}\t{va}\t{name}\t{}\t{verdict}\n", chosen.tag));
        if let Some(d) = &out_src {
            let from = chosen.src.join(format!("{idx}.c"));
            if let Ok(text) = std::fs::read(&from) {
                std::fs::write(Path::new(d).join(format!("{idx}.c")), text).expect("write selected source");
            }
        }
    }

    eprintln!("=== per-function arm selection ===");
    for a in &arms {
        let n = per_arm_wins.get(a.tag.as_str()).copied().unwrap_or(0);
        eprintln!("{n:6}  {} (of {} emitted)", a.tag, a.rows.len());
    }
    eprintln!("{exact:6}  TOTAL byte-exact over {} functions", all.len());
    if !unresolved.is_empty() {
        eprintln!("=== not reproduced by any arm, by best verdict ===");
        let mut u: Vec<_> = unresolved.iter().collect();
        u.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
        for (k, n) in u {
            eprintln!("{n:6}  {}", if k.is_empty() { "(absent)" } else { k });
        }
    }
    if let Some(p) = out_tsv {
        std::fs::write(&p, tsv).expect("write --out");
        eprintln!("selection written to {p}");
    }
    if let Some(d) = out_src {
        eprintln!("winning sources written to {d}");
    }
}

fn usage<T>(msg: &str) -> T {
    eprintln!(
        "recompile_select: {msg}\n\
         usage: recompile_select <tag>=<verdicts.tsv>:<srcdir> ... [--out <tsv>] [--out-src <dir>]"
    );
    std::process::exit(2);
}

/// Read a `recompile_check --out` file: `idx va name verdict ...`.
fn read_verdicts(path: &str) -> BTreeMap<String, (String, String, String)> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("recompile_select: {path}: {e}");
        std::process::exit(2);
    });
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 4 || f[0] == "idx" {
                return None;
            }
            Some((f[0].to_string(), (f[3].to_string(), f[1].to_string(), f[2].to_string())))
        })
        .collect()
}
