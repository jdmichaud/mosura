//! Dump the converged listing of a binary opened through a beyond-Ghidra native loader
//! (`analyze_native_file`): blocks, functions with their bodies, every code unit with its length
//! and flow, defined data, references and symbols — one line each, sorted by address.
//!
//! The consumer is a source generator that needs the code/data partition and the reference
//! graph mosura's analysis decided, not a re-derivation of it.
//!
//! ```text
//! cargo run --release --example native_listing -- <binary> [--cspec <id>] > listing.txt
//! ```
use mosura::analysis::program::CodeUnit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut path: Option<std::path::PathBuf> = None;
    let mut knobs = mosura::switches::Knobs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cspec" => {
                i += 1;
                knobs.x86_32_cspec = args.get(i).cloned();
            }
            a => path = Some(std::path::PathBuf::from(a)),
        }
        i += 1;
    }
    let path = path.expect("usage: native_listing <binary> [--cspec <id>]");
    let prog = mosura::analysis::analyze_native_file_with(&path, &knobs).expect("analyze");
    println!(
        "# native-listing lang={} cspec={} base={:#x}",
        prog.language_id, prog.compiler_spec_id, prog.image_base.offset
    );
    for b in prog.memory.blocks() {
        println!("block {:08x} {:08x} {}", b.start.offset, b.end.offset, b.name);
    }
    for e in &prog.entry_points {
        println!("entry {:08x}", e.offset);
    }
    let mut funcs: Vec<_> = prog.function_manager.functions().collect();
    funcs.sort_by_key(|f| f.entry_point().offset);
    for f in funcs {
        let mut line = format!("func {:08x} {}", f.entry_point().offset, f.name());
        for r in f.body().ranges() {
            line.push_str(&format!(" {:08x}:{:08x}", r.min, r.max));
        }
        println!("{line}");
    }
    let mut units: Vec<_> = prog.listing.code_units().collect();
    units.sort_by_key(|(a, _)| a.offset);
    for (a, u) in units {
        match u {
            CodeUnit::Instruction { length, flow } => {
                let mut line = format!("insn {:08x} {} {:?} ef={}", a.offset, length, flow.kind, flow.ends_flow as u8);
                for t in &flow.flows {
                    line.push_str(&format!(" ->{t:08x}"));
                }
                if let Some(c) = flow.call_target {
                    line.push_str(&format!(" call={c:08x}"));
                }
                println!("{line}");
            }
            CodeUnit::Data { length, type_name } => {
                println!("data {:08x} {} {}", a.offset, length, type_name);
            }
        }
    }
    for (a, t, l) in &prog.defined_data {
        println!("defdata {:08x} {} {}", a.offset, l, t);
    }
    let mut refs: Vec<_> = prog.reference_manager.references().collect();
    refs.sort_by_key(|r| (r.from.offset, r.to.offset));
    for r in refs {
        println!("ref {:08x} {:08x} {} op={}", r.from.offset, r.to.offset, r.ref_type.name(), r.op_index);
    }
    let mut syms: Vec<_> = prog.symbol_table.symbols().collect();
    syms.sort_by_key(|s| s.address().offset);
    for s in syms {
        println!("sym {:08x} {} {:?} primary={}", s.address().offset, s.name(), s.symbol_type(), s.is_primary());
    }
    let mut ib: Vec<_> = prog.indirect_branches.iter().copied().collect();
    ib.sort_unstable();
    for a in ib {
        println!("branchind {a:08x}");
    }
}
