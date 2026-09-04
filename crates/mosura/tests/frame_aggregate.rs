//! `frame-fill=aggregate` (docs/compilable-c-remediation.md Phase 10b): a frame the original opens
//! with `SUB ESP,0xd0` but whose recovered locals total 14 bytes declares as ONE byte aggregate at the
//! frame bottom, every slot a field at its byte offset — fable-b's srcform12 form, EXACT on WAR2
//! 0x2dcd4 (the biased-EBP prologue included).
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::{print_c_recovered, print_c_report, RecoveredChoices};
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn under_sized_frame_declares_one_aggregate_with_field_offsets() {
    let path = paths::oracle_fixtures_dir().join("x86_2dcd4_frame.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("x86 SLEIGH tables load");
    let image: Vec<(u64, &[u8])> =
        dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);

    let mut choices = EmitChoices::default();
    choices.set("frame-fill", "aggregate").unwrap();
    // unwitnessed: the reference per-symbol declarations
    let (reference, _) = print_c_report(&f, &choices);
    assert!(reference.contains("xunknown1 axStack_d8 [6];"), "reference keeps the symbols:\n{reference}");
    // witnessed: PUSH ESI; PUSH EBP; SUB ESP,0xd0 → frame 0xd0 below 2 pushes
    let recovered = RecoveredChoices { frame_fill: mosura::decompile::emit::arms::frame_fill::Sites { frame: Some((0xd0, 2)), ..Default::default() }, ..Default::default() };
    let c = print_c_recovered(&f, &choices, &recovered);
    assert!(c.contains("xunknown1 axStack_d8 [208];"), "one aggregate sized to the frame:\n{c}");
    assert!(!c.contains("xStack_d0;") && !c.contains("xStack_cc;"), "no sibling scalar declarations:\n{c}");
    assert!(c.contains("*(xunknown2 *)(axStack_d8 + 8) = param_1;"), "field store at +8:\n{c}");
    assert!(c.contains("*(xunknown2 *)(axStack_d8 + 0xc) = func_0x001c1000(param_3, 1);"), "the kept call-result store at +0xc:\n{c}");
    assert!(c.contains("axStack_d8[6] = 0x1f;") && c.contains("axStack_d8[0] = 0xf;"), "byte fields index the aggregate:\n{c}");
    assert!(c.contains("func_0x001c1010(axStack_d8);"), "the escaping base decays to the aggregate:\n{c}");
}

/// Seam 4/5 (probe w4bp, fable-b's hold): an element read of a symbol the aggregate swallowed
/// (`aiStack_2c[0]` at WAR2 0x4e06e) must render as the field at its slot, never by the vanished
/// name — every stack symbol the C references must be declared. The MVE puts an int array in the
/// MIDDLE of a 0xcc frame (80 untouched bytes on each side), lets its base escape to a callee, and
/// reads one element by constant index and the rest in a loop: the gate fires on the slack, the
/// aggregate covers the array, and every element read is the field at its slot.
#[test]
fn swallowed_symbol_elements_render_as_fields() {
    let path = paths::oracle_fixtures_dir().join("x86_4e06e_frame_index.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("x86 SLEIGH tables load");
    let image: Vec<(u64, &[u8])> =
        dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    let mut choices = EmitChoices::default();
    choices.set("frame-fill", "aggregate").unwrap();
    // PUSH EBX/ECX/EDX/EBP; SUB ESP,0xcc → frame 0xcc under 4 pushes (the aggregate at -0xdc)
    let recovered = RecoveredChoices { frame_fill: mosura::decompile::emit::arms::frame_fill::Sites { frame: Some((0xcc, 4)), ..Default::default() }, ..Default::default() };
    let c = print_c_recovered(&f, &choices, &recovered);
    assert!(c.contains("xunknown1 axStack_dc [204];"), "one aggregate sized to the frame:\n{c}");
    // seam 4: the constant-index element read is the field at its slot, not the vanished array
    assert!(c.contains("*(int4 *)(axStack_dc + 0x50)"), "the element read renders as the field at +0x50:\n{c}");
    assert!(c.contains("func_0x001d1000((int4 *)(axStack_dc + 0x50));"), "the escaping array base is the field's address:\n{c}");
    assert!(c.contains("(int4 *)(axStack_dc + 0x50) + iVar"), "the indexed element read goes through the field's address:\n{c}");
    let stack_decls = c
        .lines()
        .filter(|l| l.contains("Stack_") && l.trim_end().ends_with(';') && !l.contains('=') && !l.contains('('))
        .count();
    assert_eq!(stack_decls, 1, "no stack declaration besides the aggregate:\n{c}");
    let declared: std::collections::HashSet<&str> = c
        .lines()
        .filter(|l| l.trim_end().ends_with(';') && !l.contains('=') && !l.contains('('))
        .filter_map(|l| l.split_whitespace().find(|w| w.contains("Stack_")))
        .map(|w| w.trim_start_matches('*').split('[').next().unwrap())
        .collect();
    let mut undeclared = Vec::new();
    for tok in c.split(|ch: char| !(ch.is_alphanumeric() || ch == '_')) {
        if tok.contains("Stack_") && !declared.contains(tok) && !undeclared.contains(&tok) {
            undeclared.push(tok);
        }
    }
    assert!(undeclared.is_empty(), "stack symbols referenced but not declared: {undeclared:?}\n{c}");
}
