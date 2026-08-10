//! Absolute WAR2 native-LE discovery probe — the number the analysis docs quote.
//!
//! Prints the discovered function count, then checks the addresses named on the command
//! line: `+hex` must be PRESENT (a tracker function we are chasing), `-hex` must be ABSENT
//! (a known invention). Default with no args: the open-task set — `+67f40` (the last
//! shared-return miss, docs/analysis-open-tasks.md #3) and `-51e12 -53254 -78039` (the
//! refuted per-function-invocation repair's inventions).
//!
//! `cargo run --release -p mosura --example le_funcs [--dump] [±hex ...]`
//! `--dump` prints every function entry (hex, one per line) for set-diffing runs.

fn main() {
    let path = mosura::paths::war2_exe();
    if !path.exists() {
        eprintln!("WAR2.EXE absent at {} (set MOSURA_WAR2_EXE)", path.display());
        std::process::exit(2);
    }
    let prog = mosura::analysis::analyze_le_file(&path).expect("analyze WAR2.EXE");
    let entries: std::collections::BTreeSet<u64> =
        prog.function_manager.functions().map(|f| f.entry_point().offset).collect();
    println!("functions: {}", entries.len());

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut checks: Vec<String> = args.iter().filter(|a| *a != "--dump").cloned().collect();
    if checks.is_empty() {
        checks = ["+67f40", "-51e12", "-53254", "-78039"].map(String::from).to_vec();
    }
    let mut fail = false;
    for c in &checks {
        let (want, hex) = match c.split_at(1) {
            ("+", h) => (true, h),
            ("-", h) => (false, h),
            _ => (true, c.as_str()),
        };
        let addr = u64::from_str_radix(hex, 16).expect("hex address");
        let present = entries.contains(&addr);
        let ok = present == want;
        fail |= !ok;
        println!(
            "{} {:>8x}: {} ({})",
            if ok { "ok  " } else { "FAIL" },
            addr,
            if present { "present" } else { "absent" },
            if want { "want present" } else { "want absent" },
        );
    }
    if args.iter().any(|a| a == "--dump") {
        for e in &entries {
            println!("{e:x}");
        }
    }
    std::process::exit(if fail { 1 } else { 0 });
}
