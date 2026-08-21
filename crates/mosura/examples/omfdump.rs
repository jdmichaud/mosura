//! Dump an OMF object's structure as mosura's parser sees it — segments, publics, data extents.
//! Diagnostic for the candidate loader: what `load_object_function` slices is only as good as
//! this parse.
use mosura::analysis::loader::omf;

fn main() {
    let path = std::env::args().nth(1).expect("usage: omfdump <obj>");
    let data = std::fs::read(&path).expect("read object");
    let m = omf::parse_module(&data);
    println!("segments:");
    for (i, s) in m.segments.iter().enumerate() {
        println!("  {}: name={:?} code={} data.len()={}", i + 1, s.name, s.is_code(), s.data.len());
    }
    println!("publics:");
    for (n, seg, off) in &m.publics {
        println!("  {n} seg={seg} off={off:#x}");
    }
    println!("fixups: {}", m.fixups.len());
    for f in &m.fixups {
        if m.segments.get(f.segment - 1).map(|s| s.is_code()).unwrap_or(false) {
            println!(
                "  seg={} off={:#x} loc={} wide={} selfrel={} target={:?} disp={:#x}",
                f.segment, f.offset, f.location, f.wide, f.self_relative, f.target, f.displacement
            );
        }
    }
    if let Some(s1) = m.segments.first() {
        print!("_TEXT[0..0x20]: ");
        for b in s1.data.iter().take(0x20) { print!("{b:02x} "); }
        println!();
    }
    println!("externals: {}", m.externals.len());

    // The extraction the checker performs, on the same object.
    if let Some(name) = std::env::args().nth(2) {
        let base = u64::from_str_radix(&std::env::args().nth(3).unwrap_or_default().trim_start_matches("0x"), 16).unwrap_or(0);
        let resolver = |_: &str| -> Option<u64> { Some(0xdead_0000) };
        match mosura::recompile::candidate::load_object_function(&data, &name, base, &resolver) {
            Ok(c) => {
                println!("candidate: {} bytes, {} fixups, {} unresolved", c.bytes.len(), c.fixups.len(), c.unresolved.len());
                let rl = c.relinked_bytes();
                print!("first 24 relinked bytes: ");
                for b in rl.iter().take(24) { print!("{b:02x} "); }
                println!();
                match mosura::recompile::insn::normalize("x86:LE:32:default", &rl, base, &mosura::recompile::insn::NoReloc) {
                    Ok(insns) => {
                        println!("normalize: {} instructions", insns.len());
                        for i in insns.iter().take(6) { println!("  {:#x} {}", i.addr, i.text); }
                    }
                    Err(e) => println!("normalize error: {e:?}"),
                }
            }
            Err(e) => println!("load_object_function: {e}"),
        }
    }
}
