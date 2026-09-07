//! Decompile every function of a binary opened through a native loader and write one C file per
//! function — a readability companion to the listing, not a recompilation input.
//!
//! ```text
//! cargo run --release --example native_decompile -- <binary> <out_dir> [--cspec <id>] [--only <hex>,...]
//! ```
use mosura::decompile::printc::print_c;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut pos: Vec<String> = Vec::new();
    let mut knobs = mosura::switches::Knobs::default();
    let mut only: Option<Vec<u64>> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cspec" => { i += 1; knobs.x86_32_cspec = args.get(i).cloned(); }
            "--only" => { i += 1; only = Some(args[i].split(',').map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()).collect()); }
            a => pos.push(a.to_string()),
        }
        i += 1;
    }
    let path = std::path::PathBuf::from(pos.get(0).expect("usage: native_decompile <binary> <out_dir>"));
    let out = std::path::PathBuf::from(pos.get(1).expect("usage: native_decompile <binary> <out_dir>"));
    std::fs::create_dir_all(&out).unwrap();
    let prog = mosura::analysis::analyze_native_file_with(&path, &knobs).expect("analyze");
    let mut entries: Vec<(u64, String)> = prog.function_manager.functions().map(|f| (f.entry_point().offset, f.name().to_string())).collect();
    entries.sort();
    let (mut ok, mut fail) = (0, 0);
    let skip_existing = args.iter().any(|a| a == "--skip-existing");
    let index_path = out.join("index.tsv");
    let mut index = std::fs::OpenOptions::new().create(true).append(true).open(&index_path).unwrap();
    use std::io::Write;
    for (entry, name) in entries {
        if let Some(o) = &only { if !o.contains(&entry) { continue; } }
        if skip_existing && (out.join(format!("{name}.c")).exists() || out.join(format!("{name}.failed")).exists()) { continue; }
        // mark as in progress: a crash (stack overflow aborts the process) leaves the marker behind
        std::fs::write(out.join(format!("{name}.failed")), "aborted\n").unwrap();
        eprintln!("decompiling {name}");
        let addr = mosura::decompile::space::Address::new(prog.default_space, entry);
        let start = std::time::Instant::now();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mosura::analysis::decompiler::decompile_function(&prog, addr).map(|f| print_c(&f))
        }));
        let secs = start.elapsed().as_secs_f32();
        match res {
            Ok(Some(c)) => {
                std::fs::write(out.join(format!("{name}.c")), &c).unwrap();
                let _ = std::fs::remove_file(out.join(format!("{name}.failed")));
                writeln!(index, "{entry:08x}\t{name}\tok\t{secs:.2}").unwrap(); ok += 1;
            }
            Ok(None) => { writeln!(index, "{entry:08x}\t{name}\tnone\t{secs:.2}").unwrap(); fail += 1; }
            Err(_) => { writeln!(index, "{entry:08x}\t{name}\tpanic\t{secs:.2}").unwrap(); fail += 1; }
        }
    }
    eprintln!("decompiled {ok}, failed {fail}");
}
