//! Workspace automation: `cargo xtask <cmd>`.
//!
//! `baseline` regenerates the disasm/p-code goldens from `oracle/fixtures/*.xml`
//! using the offline capture tool, against the pinned Ghidra source tree. It does
//! not touch the network and needs no external Ghidra install.

use std::path::{Path, PathBuf};
use std::process::{exit, Command};

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <workspace>/crates/xtask
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("manifest has >= 2 ancestors")
        .to_path_buf()
}

fn ghidra_src(ws: &Path) -> PathBuf {
    std::env::var("GHIDRA_SRC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| ws.parent().expect("workspace parent").join("ghidra"))
}

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("xtask: error: {}", msg.as_ref());
    exit(1);
}

fn baseline() {
    let ws = workspace_root();
    let capture = ws.join("oracle/capture");
    if !capture.exists() {
        die(format!(
            "capture tool not built at {} — run `scripts/setup-oracle.sh` first",
            capture.display()
        ));
    }
    let sleighdir = ghidra_src(&ws);
    let fixtures = ws.join("oracle/fixtures");
    let out_dir = ws.join("goldens/disasm");
    std::fs::create_dir_all(&out_dir).unwrap_or_else(|e| die(e.to_string()));

    let mut entries: Vec<PathBuf> = std::fs::read_dir(&fixtures)
        .unwrap_or_else(|e| die(format!("read {}: {e}", fixtures.display())))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("xml"))
        .collect();
    entries.sort();
    if entries.is_empty() {
        die(format!("no fixtures in {}", fixtures.display()));
    }

    let mut n = 0;
    for fx in &entries {
        let stem = fx.file_stem().and_then(|s| s.to_str()).unwrap();
        let out = out_dir.join(format!("{stem}.golden"));
        let result = Command::new(&capture)
            .arg(&sleighdir)
            .arg(fx)
            .output()
            .unwrap_or_else(|e| die(format!("running capture: {e}")));
        if !result.status.success() {
            die(format!(
                "capture failed for {}:\n{}",
                fx.display(),
                String::from_utf8_lossy(&result.stderr)
            ));
        }
        std::fs::write(&out, &result.stdout).unwrap_or_else(|e| die(e.to_string()));
        println!("captured {} -> {}", stem, out.display());
        n += 1;
    }
    println!("baseline: regenerated {n} disasm golden(s) against {}", sleighdir.display());
}

/// `cargo xtask fid-build` — build a FID signature database from a runtime library.
///
/// Full recipe, per compiler column: `docs/fid-building-databases.md`.
fn fid_build() {
    let args: Vec<String> = std::env::args().skip(2).collect();
    let mut family = String::from("Unknown");
    let mut version = String::from("0");
    let mut variant = String::from("Release");
    let mut common: Vec<String> = Vec::new();
    let mut out: Option<PathBuf> = None;
    let mut inputs: Vec<PathBuf> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let take = |i: &mut usize| -> String {
            *i += 1;
            args.get(*i).cloned().unwrap_or_else(|| die("missing value"))
        };
        match args[i].as_str() {
            "--family" => family = take(&mut i),
            "--version" => version = take(&mut i),
            "--variant" => variant = take(&mut i),
            "--out" => out = Some(PathBuf::from(take(&mut i))),
            "--common-symbols" => {
                let path = take(&mut i);
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| die(format!("{path}: {e}")));
                common = mosura::analysis::fid::build::parse_common_symbols(&text);
            }
            "--dir" => {
                let dir = take(&mut i);
                let mut found: Vec<PathBuf> = std::fs::read_dir(&dir)
                    .unwrap_or_else(|e| die(format!("{dir}: {e}")))
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_file())
                    .collect();
                found.sort();
                inputs.extend(found);
            }
            other if other.starts_with("--") => die(format!("unknown option {other}")),
            _ => inputs.push(PathBuf::from(&args[i])),
        }
        i += 1;
    }

    let Some(out) = out else { die("--out <file.mfid> is required") };
    if inputs.is_empty() {
        die("no input files (pass paths, or --dir <directory>)");
    }

    println!("fid-build: {} input file(s) -> {}", inputs.len(), out.display());
    let spec = mosura::analysis::fid::build::BuildSpec {
        family,
        version,
        variant,
        common_symbols: common,
    };
    match mosura::analysis::fid::build::build_to_file(&inputs, &spec, &out) {
        Ok(result) => {
            println!("  ingested  {}", result.ingested);
            println!("  relations {}", result.relations);
            let mut excluded: Vec<_> = result.excluded.iter().collect();
            excluded.sort();
            for (why, n) in excluded {
                println!("  excluded  {n:<6} {why:?}");
            }
        }
        Err(e) => die(e),
    }
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("baseline") => baseline(),
        Some("fid-build") => fid_build(),
        other => {
            eprintln!("usage: cargo xtask <baseline|fid-build>");
            eprintln!();
            eprintln!("  fid-build --family <name> --version <v> --variant <Release|Debug>");
            eprintln!("            [--common-symbols <file>] --out <db.mfid>");
            eprintln!("            (--dir <directory> | <file> ...)");
            if other.is_some() {
                exit(2);
            }
        }
    }
}
