//! `dev.groundtruth.recompile` — the ground-truth recompile loop as a report: source we own →
//! local gcc → decompile → the same gcc → attributed verdict per function
//! (`recompile::groundtruth`). The compiler is held fixed, so the score is the decompiler's
//! alone, and every divergence can be read against the source. Writes `report.tsv`, `rec.tsv`,
//! `div.tsv` (recompile_check's two table formats, so `scripts/corpus-mechanism-census.py` runs
//! unchanged) and one `<symbol>.3way.txt` per function under `dev.out` (default
//! `<workspace>/build/gt-recompile`). (Was `examples/gt_recompile.rs`.)

use std::path::PathBuf;

use mosura_api::ops::{Cache, Op, Progress, Tier};
use mosura_api::{Error, Options, Result, Session, Table, TableBuilder};
use mosura_core::recompile::align::{AlignOp, DivergenceClass};
use mosura_core::recompile::groundtruth::{gcc_available, gcc_programs, recompile_program, source_function, EmitPlan, Target};
use mosura_core::recompile::report::{write_divergence_rows, FnKey};

use crate::keys;
use crate::schemas::GT_REPORT;

pub static RECOMPILE: Op = Op {
    name: "dev.groundtruth.recompile",
    doc: "the ground-truth recompile loop (source → gcc → decompile → gcc → verdict per function): one row per function, a *summary* row per program, an ALL row; dev.m32, dev.arms, dev.programs (stems), dev.fixture (write the originals as datatests); files under dev.out (report.tsv rec.tsv div.tsv, <symbol>.3way.txt)",
    since: "0.1",
    tier: Tier::Dev,
    params: &[keys::DEV_M32, keys::DEV_ARMS, keys::DEV_PROGRAMS, keys::DEV_FIXTURE, keys::DEV_OUT],
    result: "gt_report",
    cache: Cache::Transient,
    run: recompile,
};

fn write(path: &std::path::Path, text: &str) -> Result<()> {
    std::fs::write(path, text).map_err(|e| Error::io(e, path.to_path_buf()))
}

fn recompile(_s: &mut Session, o: &Options, p: &mut dyn Progress) -> Result<Table> {
    if !gcc_available() {
        return Err(Error::Unsupported("gcc is required (a development-environment requirement)".into()));
    }
    let target = if crate::flag(o, keys::DEV_M32)? { Target::Gcc32 } else { Target::Gcc64 };
    let plan = if crate::flag(o, keys::DEV_ARMS)? { EmitPlan::arms() } else { EmitPlan::plain() };
    let fixture_dir = o.get(keys::DEV_FIXTURE)?;
    let fixture_dir = (!fixture_dir.is_empty()).then(|| PathBuf::from(fixture_dir));
    let wanted = crate::list(o, keys::DEV_PROGRAMS)?;
    let out = o.get(keys::DEV_OUT)?;
    let workdir = if out.is_empty() { mosura_core::paths::workspace_root().join("build/gt-recompile") } else { PathBuf::from(out) };
    std::fs::create_dir_all(&workdir).map_err(|e| Error::io(e, workdir.clone()))?;
    let progs: Vec<PathBuf> = gcc_programs().into_iter().filter(|p| wanted.is_empty() || wanted.iter().any(|w| p.file_stem().is_some_and(|s| s == w.as_str()))).collect();
    if progs.is_empty() {
        return Err(Error::NotFound(format!("no ground-truth program matches {wanted:?}")));
    }
    let mut t = TableBuilder::new(&GT_REPORT);
    let mut tsv = String::from("program\tsymbol\tva\tverdict\tsim\tweight\tclasses\tnote\n");
    let mut rec = String::from("idx\tva\tname\tverdict\tbytes\tprimary\tsim\tequal\torig_n\tcand_n\tclasses\n");
    let mut div = String::from("idx\tfn_va\tclass\taddr\toi\tci\torig_n\tcand_n\torig_mn\tcand_mn\torig_regs\tcand_regs\torig_text\tcand_text\n");
    let mut idx = 0usize;
    let (mut tw, mut ts) = (0usize, 0f64);
    let total = progs.len() as u64;
    for (i, src) in progs.iter().enumerate() {
        if !p.report(RECOMPILE.name, i as u64, total) {
            return Err(Error::Cancelled);
        }
        let source = std::fs::read_to_string(src).unwrap_or_default();
        let stem = src.file_stem().unwrap_or_default().to_string_lossy().to_string();
        let rep = match recompile_program(src, &workdir, target, &plan) {
            Ok(r) => r,
            Err(e) => {
                t.row().str(&stem).str("*error*").u64(0).str("").f64(0.0).u64(0).str("").str(&e);
                continue;
            }
        };
        if let Some(dir) = &fixture_dir {
            std::fs::create_dir_all(dir).map_err(|e| Error::io(e, dir.clone()))?;
            for (sym, va, bytes) in &rep.original_bytes {
                let hex = crate::hex_bytes(bytes);
                let xml = format!("<binaryimage arch=\"{}:gcc\">\n  <bytechunk space=\"ram\" offset=\"{va:#x}\" readonly=\"true\">\n{hex}\n  </bytechunk>\n</binaryimage>\n", target.lang());
                write(&dir.join(format!("gt_{}_{}.xml", rep.program, sym.replace('.', "_"))), &xml)?;
            }
        }
        for f in &rep.functions {
            let classes: Vec<String> = f.classes.iter().map(|(k, v)| format!("{k}={v}")).collect();
            let classes = classes.join(",");
            t.row().str(&rep.program).str(&f.symbol).u64(f.va).str(&f.verdict).f64(f.similarity).u64(f.weight as u64).str(&classes).str(&f.note);
            tsv += &format!("{}\t{}\t{:x}\t{}\t{:.4}\t{}\t{}\t{}\n", rep.program, f.symbol, f.va, f.verdict, f.similarity, f.weight, classes, f.note);
            tw += f.weight;
            ts += f.similarity * f.weight as f64;
            let name = format!("{}/{}", rep.program, f.symbol);
            let key = FnKey { idx: format!("{idx:05}"), va: f.va, name: name.clone() };
            idx += 1;
            let (primary, equal, orig_n, cand_n, bytes) = match &f.checked {
                Some(ch) => (ch.diff.primary.map(|c| c.as_str().to_string()).unwrap_or_default(), ch.diff.equal_insns, ch.diff.orig_insns, ch.diff.cand_insns, format!("{:?}", ch.bytes)),
                None => (String::new(), 0, 0, 0, String::new()),
            };
            rec += &format!("{}\t{:08x}\t{}\t{}\t{}\t{}\t{:.3}\t{}\t{}\t{}\t{}\n", key.idx, f.va, name, f.verdict, bytes, primary, f.similarity, equal, orig_n, cand_n, classes);
            if let Some(ch) = &f.checked {
                write_divergence_rows(&mut div, &key, &ch.diff, &ch.original, &ch.candidate);
            }
            // the three-way read: the real source, our C, the aligned rows
            let mut three = String::new();
            three += &format!("==== {name} @{:x}: {} sim={:.3} weight={}\n", f.va, f.verdict, f.similarity, f.weight);
            three += "---- original source\n";
            three += &source_function(&source, &f.symbol).unwrap_or_else(|| "(not found by name)".into());
            three += "\n---- our C (the function only)\n";
            three += &f.body;
            three += "\n---- aligned instructions (original | ours | class)\n";
            if let Some(ch) = &f.checked {
                for op in &ch.diff.ops {
                    let (orig, cand, cls) = match op {
                        AlignOp::Pair { oi, ci, class } => (Some(&ch.original[*oi]), Some(&ch.candidate[*ci]), class.as_str()),
                        AlignOp::OrigOnly { oi } => (Some(&ch.original[*oi]), None, DivergenceClass::Missing.as_str()),
                        AlignOp::CandOnly { ci } => (None, Some(&ch.candidate[*ci]), DivergenceClass::Extra.as_str()),
                    };
                    three += &format!("{:<44} | {:<44} | {}\n", orig.map(|x| x.text.trim().to_string()).unwrap_or_default(), cand.map(|x| x.text.trim().to_string()).unwrap_or_default(), if cls == "equal" { "" } else { cls });
                }
            } else {
                three += &f.note;
                three += "\n";
            }
            write(&rep.workdir.join(format!("{}.3way.txt", f.symbol)), &three)?;
        }
        t.row().str(&rep.program).str("*summary*").u64(0).str("").f64(rep.wgss()).u64(rep.functions.iter().map(|f| f.weight as u64).sum()).str("").str(&rep.summary());
    }
    if tw > 0 {
        t.row().str("ALL").str("*summary*").u64(0).str("").f64(ts / tw as f64).u64(tw as u64).str("").str(&format!("weight {tw}, WGSS {:.4}", ts / tw as f64));
    }
    write(&workdir.join("report.tsv"), &tsv)?;
    write(&workdir.join("rec.tsv"), &rec)?;
    write(&workdir.join("div.tsv"), &div)?;
    Ok(t.finish(false))
}
