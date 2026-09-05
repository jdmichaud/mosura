//! `dev.oracle.sweep` — the oracle sweep: every `kind=user` function of the current program's
//! emission as a standalone fixture (its bytes as the survey's extent has them), Ghidra's own C
//! (`oracle/capture --c`, cached by `oraclecache`) beside mosura's pure-pipeline C (the same
//! bytes, no landed world, no recovered arms — apples to apples with the context-poor oracle),
//! scored with `ccompare::similarity`. Ranks the corpus by Ghidra-divergence so the remaining
//! printer/structure gaps surface at once instead of one hand-found specimen at a time. (Was
//! `examples/oracle_sweep.rs`; the row columns are its `sweep.tsv` columns — `--format tsv` is
//! that file; `scripts/corpus-osweep-rank.py` reads it.)
//!
//! Writes `<dev.out>/fixtures/<idx>.xml`, `ghidra/<idx>.c`, `mosura/<idx>.c`. The oracle runs
//! only where the workspace's `oracle/capture` and its Ghidra root exist (`dev-config.toml`);
//! a missing capture is an `ORACLE_FAIL` row, a mosura panic or 90 s timeout a `MOSURA_*` row.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use mosura_api::ops::program::program_of;
use mosura_api::ops::{dispatch_inner, Cache, Op, Progress, Tier};
use mosura_api::{Error, Options, Result, Session, Table, TableBuilder};
use mosura_core::decompile::printc::print_c;
use mosura_core::decompile::{build, pipeline};
use mosura_core::{ccompare, datatest, oraclecache};

use crate::keys;
use crate::schemas::ORACLE_SWEEP;

pub static SWEEP: Op = Op {
    name: "dev.oracle.sweep",
    doc: "the oracle sweep over the current program's emission: every user function's bytes as a fixture, Ghidra's C (oracle/capture, cached) vs mosura's pure-pipeline C, scored by ccompare; files under dev.out (fixtures/ ghidra/ mosura/); dev.only = emit indices or hex addresses, dev.limit = stop after N",
    since: "0.1",
    tier: Tier::Dev,
    params: &["program", keys::DEV_OUT, keys::DEV_ONLY, keys::DEV_LIMIT, "knobs.off", "decompile.global-scope", "decompile.proto-scope", "emit.arms-off", "emit.*"],
    result: "oracle_sweep",
    cache: Cache::Transient,
    run: sweep,
};

/// Ghidra annotates its C with `/* WARNING: ... */` comments (unrecovered tables, indirect jumps
/// treated as calls, stack warnings) that `ccompare::normalize` tokenizes like code, so they
/// depress the score of functions whose code is otherwise identical. Score without them.
pub fn strip_comments(c: &str) -> String {
    let mut out = String::with_capacity(c.len());
    let mut rest = c;
    while let Some(i) = rest.find("/*") {
        out.push_str(&rest[..i]);
        match rest[i..].find("*/") {
            Some(j) => rest = &rest[i + j + 2..],
            None => rest = "",
        }
    }
    out.push_str(rest);
    out
}

/// Is the row selected by `dev.only` (an emit index, or a hex address with or without `0x`)?
pub fn selected(only: &[String], idx: u32, va: u64) -> bool {
    only.is_empty() || only.iter().any(|o| o.parse::<u32>().ok() == Some(idx) || u64::from_str_radix(o.trim_start_matches("0x"), 16).ok() == Some(va))
}

/// mosura's pure-pipeline C of a fixture, on its own thread: a panic is `PANIC`, 90 s is `TIMEOUT`.
fn mosura_c(fixture: PathBuf) -> std::result::Result<String, String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = std::panic::catch_unwind(|| {
            let dt = datatest::parse_file(&fixture).map_err(|e| format!("parse: {e}"))?;
            let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
            let (spec, ctx) = mosura_core::lang::load_cached(lang_id).ok_or("language")?;
            let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
            let entry = dt.chunks[0].offset;
            let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
            pipeline::decompile(&mut f);
            Ok::<String, String>(print_c(&f))
        });
        let _ = tx.send(match r {
            Ok(x) => x,
            Err(_) => Err("PANIC".into()),
        });
    });
    match rx.recv_timeout(Duration::from_secs(90)) {
        Ok(x) => x,
        Err(_) => Err("TIMEOUT".into()),
    }
}

fn write(path: &Path, text: &str) -> Result<()> {
    std::fs::File::create(path).and_then(|mut f| f.write_all(text.as_bytes())).map_err(|e| Error::io(e, path.to_path_buf()))
}

fn sweep(s: &mut Session, o: &Options, p: &mut dyn Progress) -> Result<Table> {
    let (_, program) = program_of(s, o)?;
    // the fixture arch = the program's language + its compiler spec (`x86:LE:32:default:watcom`)
    let arch = format!("{}:{}", program.language_id, program.compiler_spec_id);
    let emission = dispatch_inner(s, "program.emit", o)?;
    let work = crate::out_dir(s, o, "sweep")?;
    for d in ["fixtures", "ghidra", "mosura"] {
        let d = work.join(d);
        std::fs::create_dir_all(&d).map_err(|e| Error::io(e, d.clone()))?;
    }
    let only = crate::list(o, keys::DEV_ONLY)?;
    let limit = o.get(keys::DEV_LIMIT)?.trim().parse::<u64>().unwrap_or(u64::MAX);
    let (c_idx, c_va, c_name, c_kind, c_row) = (emission.col("idx").unwrap(), emission.col("va").unwrap(), emission.col("name").unwrap(), emission.col("kind").unwrap(), emission.col("row").unwrap());
    let mut b = TableBuilder::new(&ORACLE_SWEEP);
    let total = emission.rows();
    let mut done = 0u64;
    for r in 0..total {
        if !p.report(SWEEP.name, r, total) {
            return Err(Error::Cancelled);
        }
        if emission.str(r, c_kind)? != "user" {
            continue;
        }
        let (idx, va, name) = (emission.u64(r, c_idx)? as u32, emission.u64(r, c_va)?, emission.str(r, c_name)?);
        if !selected(&only, idx, va) {
            continue;
        }
        if done >= limit {
            break;
        }
        // the legacy manifest row: idx va name status orig_len cov_lo cov_hi smells orig_hex …
        let cols: Vec<&str> = emission.str(r, c_row)?.split('\t').collect();
        let hex = cols.get(8).copied().unwrap_or("");
        if hex.is_empty() {
            b.row().u32(idx).u64(va).str(name).str("NO_BYTES").f64(0.0).u64(0).u64(0);
            done += 1;
            continue;
        }
        let fixture = work.join("fixtures").join(format!("{idx:05}.xml"));
        if !fixture.exists() {
            write(&fixture, &format!("<binaryimage arch=\"{arch}\">\n  <bytechunk space=\"ram\" offset=\"0x{va:x}\" readonly=\"true\">{hex}</bytechunk>\n</binaryimage>\n"))?;
        }
        let ghidra = oraclecache::capture(&fixture, &["--c"]).filter(|t| t.contains('{'));
        let ours = mosura_c(fixture.clone());
        let (status, score, ml, gl) = match (&ghidra, &ours) {
            (Some(g), Ok(m)) => {
                write(&work.join("ghidra").join(format!("{idx:05}.c")), g)?;
                write(&work.join("mosura").join(format!("{idx:05}.c")), m)?;
                let (ms, gs) = (strip_comments(m), strip_comments(g));
                let gl = gs.lines().filter(|l| !l.trim().is_empty()).count() as u64;
                let ml = ms.lines().filter(|l| !l.trim().is_empty()).count() as u64;
                ("OK".to_string(), ccompare::similarity(&ms, &gs), ml, gl)
            }
            (None, _) => ("ORACLE_FAIL".to_string(), 0.0, 0, 0),
            (Some(_), Err(e)) => (format!("MOSURA_{e}"), 0.0, 0, 0),
        };
        b.row().u32(idx).u64(va).str(name).str(&status).f64(score).u64(ml).u64(gl);
        done += 1;
    }
    Ok(b.finish(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_are_stripped_and_selection_reads_indices_or_addresses() {
        assert_eq!(strip_comments("a /* WARNING: x */ b /* unterminated"), "a  b ");
        assert_eq!(strip_comments("no comment"), "no comment");
        assert!(selected(&[], 7, 0x1000));
        let only = vec!["7".to_string(), "0x2000".to_string(), "3000".to_string()];
        assert!(selected(&only, 7, 0x1000));
        assert!(selected(&only, 1, 0x2000));
        assert!(selected(&only, 1, 0x3000), "a bare hex address");
        assert!(!selected(&only, 1, 0x1000));
    }
}
