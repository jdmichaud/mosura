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

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("baseline") => baseline(),
        other => {
            eprintln!("usage: cargo xtask baseline");
            if other.is_some() {
                exit(2);
            }
        }
    }
}
