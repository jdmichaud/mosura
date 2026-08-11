//! Scratch probe: war2 MZ no-return state around the 13a56 inline-parameter dispatcher —
//! is it detected, and are its call sites overridden?

use mosura::decompile::space::Address;

fn main() {
    let data = std::fs::read(mosura::paths::war2_exe()).unwrap();
    let mut prog = mosura::analysis::loader::load(&data).unwrap();
    mosura::analysis::analyze(&mut prog);
    let ram = prog.default_space;
    println!("noreturn count: {}", prog.noreturn_functions.len());
    for off in [0x13a56u64, 0x1f0f4] {
        println!("noreturn {:x}: {}", off, prog.noreturn_functions.contains(&(ram.0, off)));
    }
    for off in [0x13a38u64, 0x13a3d, 0x13a42, 0x13a47, 0x13a4c, 0x13a51] {
        let a = Address::new(ram, off);
        println!(
            "site {:x}: unit={:?} override={:?} refs_to_13a56={}",
            off,
            prog.listing.instruction_at(a).map(|(l, _)| l),
            prog.flow_override_at(a),
            prog.reference_manager.refs_from(a).any(|r| r.to.offset == 0x13a56),
        );
    }
    let mut nr: Vec<u64> =
        prog.noreturn_functions.iter().filter(|(s, _)| *s == ram.0).map(|(_, o)| *o).collect();
    nr.sort_unstable();
    let hex: Vec<String> = nr.iter().map(|o| format!("{o:x}")).collect();
    println!("noreturn set: [{}]", hex.join(","));
}
