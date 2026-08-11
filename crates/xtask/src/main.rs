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
    let mut symbol_map = std::collections::HashMap::new();
    let mut out: Option<PathBuf> = None;
    let mut language: Option<String> = None;
    let mut compiler_spec: Option<String> = None;
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
            // Pin the language instead of letting the first module pick it. A vendor runtime
            // that mixes 16- and 32-bit modules otherwise silently discards the ones you want.
            "--language" => language = Some(take(&mut i)),
            // Declare the compiler spec: an OMF module does not say who produced it, but the
            // operator naming the library does. FID selects databases by language AND spec.
            "--cspec" => compiler_spec = Some(take(&mut i)),
            "--out" => out = Some(PathBuf::from(take(&mut i))),
            "--common-symbols" => {
                let path = take(&mut i);
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| die(format!("{path}: {e}")));
                common = mosura::analysis::fid::build::parse_common_symbols(&text);
            }
            "--map" => {
                let path = take(&mut i);
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| die(format!("{path}: {e}")));
                symbol_map = mosura::analysis::fid::build::parse_linker_map(&text);
                println!("  linker map: {} named addresses", symbol_map.len());
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
        language,
        compiler_spec,
        symbol_map,
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

/// `cargo xtask omf-uber <library.lib> <out.c>` — emit an "uber program" that references
/// every public symbol in an OMF library.
///
/// Why: a library's object modules are UNLINKED, so a cross-module call still reads
/// `call 0000:0000` — the real target lives in a FIXUPP record only a linker consumes. Rather
/// than patch relocations ourselves, we let the vendor's own linker do its job: compile this
/// file, link it against the library, and analyze the resulting executable. Every call is then
/// resolved by the tool meant to resolve it, auto-analysis sees the true call graph, and the
/// bytes are still the vendor's own — so the signatures stay valid.
///
/// The linker only pulls in modules something references, which is exactly what this forces.
fn omf_uber() {
    let lib = std::env::args().nth(2).unwrap_or_else(|| die("usage: omf-uber <lib> <out.c>"));
    let out = std::env::args().nth(3).unwrap_or_else(|| die("usage: omf-uber <lib> <out.c>"));
    let data = std::fs::read(&lib).unwrap_or_else(|e| die(format!("{lib}: {e}")));

    let members = mosura::analysis::loader::omf::split_library(&data);
    let mut names: Vec<String> = Vec::new();
    for m in &members {
        let module = mosura::analysis::loader::omf::parse_module(m);
        for (name, seg, _) in &module.publics {
            // Only code-segment publics: a data symbol pulls its module in just as well, but
            // referencing it as a function is what keeps the generated C uniform.
            if module.segments.get(seg.wrapping_sub(1)).is_some_and(|s| s.is_code()) {
                names.push(name.clone());
            }
        }
    }
    names.sort();
    names.dedup();

    // A C-callable symbol is emitted by the compiler with a leading underscore, so the source
    // identifier is the PUBDEF name minus that underscore. Names that are not legal C
    // identifiers (C++ mangling, `@`-decorated internals) cannot be referenced this way and are
    // skipped — they are reachable only from assembly, which is a later refinement.
    let mut refs: Vec<String> = Vec::new();
    for n in &names {
        let Some(ident) = n.strip_prefix('_') else { continue };
        if ident.is_empty()
            || !ident.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            || !ident.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        refs.push(ident.to_string());
    }
    refs.sort();
    refs.dedup();

    let mut src = String::new();
    src.push_str("/* GENERATED by `cargo xtask omf-uber` - do not edit.\n");
    src.push_str(" *\n");
    src.push_str(" * References every C-callable public symbol of a runtime library, so the\n");
    src.push_str(" * vendor's linker pulls all of them into one executable with every call\n");
    src.push_str(" * resolved. That linked image is what FID ingest analyzes.\n");
    src.push_str(" */\n");
    for r in &refs {
        src.push_str(&format!("extern int {r}();\n"));
    }
    src.push_str("\nvoid *uber_table[] = {\n");
    for r in &refs {
        src.push_str(&format!("  (void *) {r},\n"));
    }
    src.push_str("};\n\nint main(void) { return (int) (long) uber_table[0]; }\n");

    std::fs::write(&out, src).unwrap_or_else(|e| die(format!("{out}: {e}")));
    println!(
        "omf-uber: {} members, {} code publics, {} referenced -> {out}",
        members.len(),
        names.len(),
        refs.len()
    );
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("baseline") => baseline(),
        Some("fid-build") => fid_build(),
        Some("omf-uber") => omf_uber(),
        other => {
            eprintln!("usage: cargo xtask <baseline|fid-build|omf-uber>");
            eprintln!();
            eprintln!("  fid-build --family <name> --version <v> --variant <Release|Debug>");
            eprintln!("            [--common-symbols <file>] [--map <linker.map>] --out <db.mfid>");
            eprintln!("            (--dir <directory> | <file> ...)");
            if other.is_some() {
                exit(2);
            }
        }
    }
}
