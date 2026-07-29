//! Throwaway grounding tool: print bytes from the LOADED (LE-fixup-applied) WAR2 image at a VA.
//!
//! The reference-sides rule (task #3) says every byte comparison must state which image it reads.
//! The survey manifest's `orig_hex` is capped at 512 bytes per function, so settling a call site
//! past that cap needs the loaded image itself — which is exactly the image mosura decompiled
//! (`load_le` applies LE fixups, `cbd6295`), and therefore the right reference.
//!
//! Usage: `cargo run -q --release --example bytesat -- <war2.exe> <va-hex> [len]`
use mosura::analysis;
use mosura::decompile::space::Address;

fn main() {
    let mut args = std::env::args().skip(1);
    let bin = args.next().expect("war2.exe path");
    let va = u64::from_str_radix(args.next().expect("va-hex").trim_start_matches("0x"), 16)
        .expect("hex va");
    let len: usize = args.next().map(|s| s.parse().expect("len")).unwrap_or(16);
    let prog = analysis::analyze_le_file(std::path::Path::new(&bin)).expect("analyze_le_file");
    let ram = prog.default_space;
    let mut out = String::new();
    for i in 0..len {
        match prog.memory.byte_at(Address::new(ram, va + i as u64)) {
            Some(b) => out.push_str(&format!("{b:02x}")),
            None => out.push_str("??"),
        }
    }
    println!("{out}");
}
