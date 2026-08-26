//! W1 (wc2src-reconciliation-4): a 32-bit `PTRSUB(ESP, off)` output must be typed as a pointer to
//! the mapped frame symbol. The offset constant is pointer-width and held zero-extended in a u64,
//! so it must be sign-extended from the pointer width before the frame-symbol lookup; without that
//! every stack pointer fell to `Pointer(undefined1)` and RulePtrArith built a byte-element PTRADD
//! over a dword array — `axStack + i*0x10`, which C scales by 4: wrong code. Ghidra prints
//! `axStack_20[param_1 * 4]` (the oracle on this fixture), and so do we now.
use mosura::decompile::printc::print_c;
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn byte_offset_into_dword_stack_array_is_an_element_index() {
    let path = paths::oracle_fixtures_dir().join("x86_local_byte_offset.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("x86 SLEIGH tables load");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    let c = print_c(&f);
    assert!(c.contains("[param_1 * 4]"), "element-indexed access:\n{c}");
    assert!(!c.contains("param_1 * 0x10"), "no raw byte offset on the typed array:\n{c}");
}
