//! the subject ORACLE SWEEP — every corpus function's bytes as a standalone fixture, Ghidra's own C
//! (`oracle/capture --c`, cached by `oraclecache`) beside mosura's pure-pipeline C (the same
//! bytes, no landed world, no recovered arms — apples to apples with the context-poor oracle),
//! scored with `ccompare::similarity`. The output ranks the corpus by Ghidra-divergence so the
//! remaining printer/structure gaps surface at once instead of one hand-found specimen at a
//! time (the do-while condition port, zc29, was worth +181 insn-sim and was invisible until one
//! function was compared by hand).
//!
//! Usage: oracle_sweep <manifest.tsv> <workdir> [--limit N] [--only idx,idx,...]
//!   writes <workdir>/fixtures/<idx>.xml, <workdir>/ghidra/<idx>.c, <workdir>/mosura/<idx>.c,
//!   and <workdir>/sweep.tsv: idx  va  name  status  score  mosura_lines  ghidra_lines
//!
//! A FULL sweep (no `--only`) DEFINES sweep.tsv and truncates it; a PARTIAL sweep (`--only`)
//! CONTRIBUTES to it and appends. The doc used to promise appending while the code truncated
//! unconditionally, which silently destroyed the previous chunk's rows on every chunk of a
//! resumable run -- 100 functions lost before a spin-guard noticed. Repeated `--only` runs
//! accumulate rows rather than replacing them, so a chunked driver should derive its next
//! chunk from the indices already in the file (that is exactly what makes it resumable), and
//! anything wanting a clean partial re-measurement should use a fresh workdir.
//! Env: GHIDRA_SRC must resolve a sleigh home for the oracle (a tree with Ghidra/Processors).
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use mosura::decompile::printc::print_c;
use mosura::decompile::{build, pipeline};
use mosura::{ccompare, datatest, oraclecache};

const ARCH: &str = "x86:LE:32:default:watcom";

/// Ghidra annotates its C with `/* WARNING: ... */` comments (unrecovered tables, indirect
/// jumps treated as calls, stack warnings) that `ccompare::normalize` tokenizes like code, so
/// they depress the score of functions whose code is otherwise identical. Score without them.
fn strip_comments(c: &str) -> String {
    let mut out = String::with_capacity(c.len());
    let mut rest = c;
    while let Some(i) = rest.find("/*") {
        out.push_str(&rest[..i]);
        match rest[i..].find("*/") {
            Some(j) => rest = &rest[i + j + 2..],
            None => {
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn mosura_c(fixture: PathBuf) -> Result<String, String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = std::panic::catch_unwind(|| {
            let dt = datatest::parse_file(&fixture).map_err(|e| format!("parse: {e}"))?;
            let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
            let (spec, ctx) = mosura::lang::load_cached(lang_id).ok_or("language")?;
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

/// Open `<work>/sweep.tsv`. A full sweep DEFINES the file (truncate); a partial `--only` sweep
/// CONTRIBUTES to it (append), which is what lets a chunked run resume without destroying the
/// chunks before it.
fn open_tsv(work: &Path, partial: bool) -> std::fs::File {
    let p = work.join("sweep.tsv");
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(partial)
        .truncate(!partial)
        .open(p)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression: every `--only` chunk used to truncate the file, so a resumable run kept
    /// only its last chunk. A partial sweep must preserve what is already there; a full sweep
    /// must still define the file.
    #[test]
    fn a_partial_sweep_appends_and_a_full_sweep_truncates() {
        use std::io::Write as _;
        let d = std::env::temp_dir().join(format!("mosura-osweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        writeln!(open_tsv(&d, false), "first").unwrap();
        writeln!(open_tsv(&d, true), "second").unwrap();
        let both = std::fs::read_to_string(d.join("sweep.tsv")).unwrap();
        assert_eq!(both, "first\nsecond\n", "a partial sweep must keep the earlier chunk");
        writeln!(open_tsv(&d, false), "fresh").unwrap();
        let after = std::fs::read_to_string(d.join("sweep.tsv")).unwrap();
        assert_eq!(after, "fresh\n", "a full sweep still defines the file");
        let _ = std::fs::remove_dir_all(&d);
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let manifest = a.first().expect("manifest.tsv");
    let work = PathBuf::from(a.get(1).expect("workdir"));
    let mut limit = usize::MAX;
    let mut only: Vec<String> = Vec::new();
    let mut i = 2;
    while i < a.len() {
        match a[i].as_str() {
            "--limit" => {
                i += 1;
                limit = a[i].parse().expect("--limit N");
            }
            "--only" => {
                i += 1;
                only = a[i].split(',').map(|s| s.trim().to_string()).collect();
            }
            o => panic!("unknown argument {o}"),
        }
        i += 1;
    }
    for d in ["fixtures", "ghidra", "mosura"] {
        std::fs::create_dir_all(work.join(d)).unwrap();
    }
    let mut tsv = open_tsv(&work, !only.is_empty());
    let text = std::fs::read_to_string(manifest).expect("manifest");
    let mut done = 0usize;
    let mut oracle_fail = 0usize;
    let mut ours_fail = 0usize;
    for line in text.lines() {
        if line.starts_with('#') || line.starts_with("idx\t") {
            continue;
        }
        let c: Vec<&str> = line.split('\t').collect();
        if c.len() < 13 || c[12] != "user" {
            continue;
        }
        let (idx, va, name, hex) = (c[0], c[1], c[2], c[8]);
        if !only.is_empty() && !only.iter().any(|o| o == idx || o.trim_start_matches("0x").eq_ignore_ascii_case(va.trim_start_matches('0'))) {
            continue;
        }
        if done >= limit {
            break;
        }
        let fixture = work.join("fixtures").join(format!("{idx}.xml"));
        if !fixture.exists() {
            let va_n = u64::from_str_radix(va, 16).unwrap();
            std::fs::write(
                &fixture,
                format!("<binaryimage arch=\"{ARCH}\">\n  <bytechunk space=\"ram\" offset=\"0x{va_n:x}\" readonly=\"true\">{hex}</bytechunk>\n</binaryimage>\n"),
            )
            .unwrap();
        }
        let ghidra = oraclecache::capture(&fixture, &["--c"]).filter(|t| t.contains('{'));
        let ours = mosura_c(fixture.clone());
        let (status, score, ml, gl) = match (&ghidra, &ours) {
            (Some(g), Ok(m)) => {
                std::fs::write(work.join("ghidra").join(format!("{idx}.c")), g).unwrap();
                std::fs::write(work.join("mosura").join(format!("{idx}.c")), m).unwrap();
                let (ms, gs) = (strip_comments(m), strip_comments(g));
                let gl = gs.lines().filter(|l| !l.trim().is_empty()).count();
                let ml = ms.lines().filter(|l| !l.trim().is_empty()).count();
                ("OK".to_string(), ccompare::similarity(&ms, &gs), ml, gl)
            }
            (None, _) => {
                oracle_fail += 1;
                ("ORACLE_FAIL".to_string(), 0.0, 0, 0)
            }
            (Some(_), Err(e)) => {
                ours_fail += 1;
                (format!("MOSURA_{e}"), 0.0, 0, 0)
            }
        };
        writeln!(tsv, "{idx}\t{va}\t{name}\t{status}\t{score:.4}\t{ml}\t{gl}").unwrap();
        done += 1;
        if done % 100 == 0 {
            eprintln!("  {done} done (oracle fails {oracle_fail}, mosura fails {ours_fail})");
        }
    }
    eprintln!("SWEEP done: {done} functions, oracle fails {oracle_fail}, mosura fails {ours_fail}");
}
