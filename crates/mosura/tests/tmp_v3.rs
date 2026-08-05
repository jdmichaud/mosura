use mosura::{analysis, paths};
#[test]
fn dump() {
    let p = paths::war2_exe();
    if !p.exists() { eprintln!("ABSENT"); return; }
    let prog = analysis::analyze_le_file(&p).expect("analyze");
    let mut v: Vec<u64> = prog.function_manager.functions().map(|f| f.entry_point().offset).collect();
    v.sort_unstable();
    eprintln!("MOSURA_COUNT {}", v.len());
    std::fs::write("/tmp/mosura5.va", v.iter().map(|a| format!("{a:08x}\n")).collect::<String>()).unwrap();
}
