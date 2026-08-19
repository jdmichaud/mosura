//! Big-endian decompilation — the regression home for the endianness port.
//!
//! Every byte-ordering decision in the decompiler is supposed to branch on the space's
//! endianness (Ghidra `AddrSpace::isBigEndian`, 132 conditionals in its C++). mosura assumed
//! little-endian throughout until the 2026-08-18 sweep; these tests exist so the big-endian
//! arms have something that actually executes them, since no other test in the tree decompiles
//! a big-endian target. The remaining un-ported sites are listed in TODO.md — as they land,
//! extend the shapes here (sub-register access, PIECE/SUBPIECE values, lanes).
use mosura::decompile::{build, pipeline, printc};

/// The processor spec's endianness must reach the SPACE model — that is what every
/// byte-ordering branch reads.
#[test]
fn big_endian_language_marks_its_spaces_big_endian() {
    for id in ["PowerPC:BE:32:default", "MIPS:BE:32:default", "68000:BE:32:Coldfire"] {
        let Some((spec, _)) = mosura::lang::load_cached(id) else {
            eprintln!("skip: {id} unavailable");
            continue;
        };
        assert!(spec.big_endian, "{id}: spec endianness");
        let bytes = [0x4e, 0x80, 0x00, 0x20u8];
        let image: Vec<(u64, &[u8])> = vec![(0x1000, &bytes[..])];
        let f = build::raw_funcdata_flow_image_arch(spec, "e", &image, 0x1000, mosura::lang::load_cached(id).unwrap().1, &format!("{id}:default"));
        for name in ["ram", "register", "stack", "unique"] {
            let Some(s) = f.spaces.by_name(name) else { continue };
            assert!(f.spaces.is_big_endian(s), "{id}: {name} space endianness");
        }
    }
}

/// A big-endian function decompiles end to end.
#[test]
fn big_endian_function_decompiles() {
    let Some((spec, ctx)) = mosura::lang::load_cached("PowerPC:BE:32:default") else {
        eprintln!("skip: PowerPC unavailable");
        return;
    };
    // li r3,5 ; blr
    let bytes = [0x38u8, 0x60, 0x00, 0x05, 0x4e, 0x80, 0x00, 0x20];
    let image: Vec<(u64, &[u8])> = vec![(0x1000, &bytes[..])];
    let mut f =
        build::raw_funcdata_flow_image_arch(spec, "be", &image, 0x1000, ctx, "PowerPC:BE:32:default:default");
    pipeline::decompile(&mut f);
    let c = printc::print_c(&f);
    assert!(c.contains("return 5;"), "big-endian decompile:\n{c}");
}

/// Ghidra `Address::justifiedContain` (address.cc:131): offset 0 means the ranges' LEAST
/// significant bytes coincide — the low address on a little-endian space, the HIGH address on
/// a big-endian one. The flip is the whole point of the primitive.
#[test]
fn justified_contain_flips_with_endianness() {
    use mosura::decompile::space::{Address, SpaceManager};
    let mut m = SpaceManager::standard();
    let ram = m.by_name("ram").unwrap();
    let base = Address::new(ram, 0x100);
    let low = Address::new(ram, 0x100); // first byte of a 4-byte container
    let high = Address::new(ram, 0x103); // last byte

    assert!(!m.is_big_endian(ram), "standard manager is little-endian");
    assert_eq!(m.justified_contain(base, 4, low, 1, false), Some(0), "LE: low byte is offset 0");
    assert_eq!(m.justified_contain(base, 4, high, 1, false), Some(3));

    m.set_big_endian(true);
    assert_eq!(m.justified_contain(base, 4, high, 1, false), Some(0), "BE: HIGH byte is offset 0");
    assert_eq!(m.justified_contain(base, 4, low, 1, false), Some(3));
    // forceleft is Ghidra's escape hatch: little-endian reading regardless
    assert_eq!(m.justified_contain(base, 4, low, 1, true), Some(0), "forceleft ignores endianness");

    // not contained
    assert_eq!(m.justified_contain(base, 4, Address::new(ram, 0x104), 1, false), None);
}
