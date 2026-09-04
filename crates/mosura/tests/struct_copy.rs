//! `struct-copy=assign` (docs/wc2src-reconciliation-4.md W6): a run of k plain `MOVSD` (no REP,
//! no ECX) after an ESI/EDI setup is Watcom's struct assignment at or below its unroll threshold;
//! Ghidra prints k dword copies, which recompile as k MOV pairs. The arm prints
//! `*(struct pN *)dst = *(struct pN *)src` at the sites the MOVSD-run witness names — by pc for
//! a load/store run, by shape (k consecutive `ram[A+4i] = ram[B+4i]`) for a global-to-global run
//! that heritage re-homes at the block's exit.
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::{print_c_recovered, print_c_report, RecoveredChoices};
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

fn render(fixture: &str) -> (String, String) {
    let path = paths::oracle_fixtures_dir().join(fixture);
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("x86 SLEIGH tables load");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    let (reference, _) = print_c_report(&f, &EmitChoices::default());
    let mut choices = EmitChoices::default();
    choices.set("struct-copy", "assign").unwrap();
    let insns = mosura::recompile::insn::normalize(lang_id, dt.chunks[0].bytes.as_slice(), entry, &mosura::recompile::insn::NoReloc).unwrap_or_default();
    let recovered = RecoveredChoices { struct_copy: mosura::decompile::emit::arms::struct_copy::Sites { runs: mosura::recompile::buildconfig::movsd_runs_from_evidence(&insns), ..Default::default() }, ..Default::default() };
    assert!(!recovered.struct_copy.runs.is_empty(), "the witness saw the MOVSD run(s)");
    (reference, print_c_recovered(&f, &choices, &recovered))
}

#[test]
fn movsd_run_into_a_pointer_prints_the_struct_assignment() {
    let (reference, c) = render("x86_40470_struct_copy.xml");
    assert!(!reference.contains("struct p8"), "the reference rendering is the dword copies:\n{reference}");
    assert!(c.contains("*(struct p8 *)(param_1 + 0xc) = *(struct p8 *)0x192000;"), "the 2-dword run is one assignment:\n{c}");
    assert_eq!(c.matches("0x192004").count(), 0, "the second dword copy is folded into the assignment:\n{c}");
}

#[test]
fn global_to_global_runs_print_the_struct_assignments() {
    let (reference, c) = render("x86_20258_struct_copy_globals.xml");
    assert!(!reference.contains("struct p12"), "the reference rendering is the dword copies:\n{reference}");
    assert!(c.contains("*(struct p12 *)0x182000 = *(struct p12 *)0x182100;"), "the first 3-dword run:\n{c}");
    assert!(c.contains("*(struct p12 *)0x182200 = *(struct p12 *)0x182300;"), "the second 3-dword run:\n{c}");
    assert!(!c.contains("xRam00182004 = "), "no per-dword copies remain:\n{c}");
}
