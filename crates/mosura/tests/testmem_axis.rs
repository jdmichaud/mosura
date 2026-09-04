//! `testmem=witness|off` — the masked-narrow-load deref width, ON AN AXIS.
//!
//! The arm prints a witnessed narrow load's dereference at the target's `int` width, because the
//! ORIGINAL tests that memory directly at that width (`TEST dword [..], imm`) and the mask makes
//! the two reads value-identical. Until Order Q it was gated on the witness set ALONE — which is
//! evidence, not a switch: it fired under every choice vector, so its 196 TUs / 320 int-width
//! deref tokens of the canonical tree could be neither turned off nor priced. This pins both
//! halves of that repair.
//!
//! SELF-COMPILED fixture (examples/watcom_mve_fixtures.rs): `x86_watcom_guard_order`, whose body
//! masks a byte global and tests it against zero — the arm's exact shape.
use mosura::decompile::emit::{EmitChoices, TestMem};
use mosura::decompile::funcdata::Funcdata;
use mosura::decompile::opcode::OpCode;
use mosura::decompile::printc::{print_c, print_c_recovered, RecoveredChoices};
use mosura::decompile::varnode::VarnodeId;
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

fn decompiled() -> Funcdata {
    let path = paths::oracle_fixtures_dir().join("x86_watcom_guard_order.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id)
        .expect("the vendored x86 SLEIGH tables load (third_party/ghidra/Processors/x86)");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    f
}

/// The arm's own candidate shape, found the way the survey's census finds it: a sub-int load whose
/// value feeds a mask. The test does not hard-code a varnode id, so it cannot silently stop
/// testing the site it means to when the pipeline renumbers.
fn masked_narrow_load(f: &Funcdata) -> VarnodeId {
    for op in f.op_ids() {
        let o = f.op(op);
        if o.is_dead() || o.code() != OpCode::Load {
            continue;
        }
        let Some(out) = o.output else { continue };
        if f.vn(out).size == 0 || f.vn(out).size >= f.size_of_int() {
            continue;
        }
        let uses: Vec<_> = f.vn(out).descend.iter().copied().filter(|&u| !f.op(u).is_dead()).collect();
        if uses.len() == 1 && f.op(uses[0]).code() == OpCode::IntAnd {
            return out;
        }
    }
    panic!("the fixture is supposed to carry a masked narrow load");
}

fn witnessed(f: &Funcdata) -> RecoveredChoices {
    let mut r = RecoveredChoices::default();
    r.testmem.sites.insert(masked_narrow_load(f));
    r
}

/// `witness` is the default and the landed behaviour: the deref renders at int width.
#[test]
fn the_witnessed_site_renders_at_int_width() {
    let f = decompiled();
    let c = print_c_recovered(&f, &EmitChoices::default(), &witnessed(&f));
    assert!(
        c.contains("*(uint4 *)"),
        "a witnessed masked narrow load derefs at int width:\n{c}"
    );
}

/// `off` is the reference rendering: the varnode really is one byte, and that is what Ghidra
/// prints.
#[test]
fn the_axis_turns_the_arm_off() {
    let f = decompiled();
    let mut off = EmitChoices::default();
    off.set("testmem", "off").unwrap();
    assert_eq!(off.testmem, TestMem::Off);
    let c = print_c_recovered(&f, &off, &witnessed(&f));
    assert!(
        !c.contains("*(uint4 *)"),
        "with the arm off the deref is the varnode's own type:\n{c}"
    );
}

/// The two renderings differ ONLY in the access type — the arm is value-preserving by
/// construction (the mask discards the bytes the wider read adds), and an arm that rewrote
/// anything else would be a bug with a switch on it (see `emit`'s rule 1).
#[test]
fn the_axis_changes_nothing_but_the_access_type() {
    let f = decompiled();
    let mut off = EmitChoices::default();
    off.set("testmem", "off").unwrap();
    // Parens go too, not laziness: `*(uint4 *)x` and `*x` bracket their operand differently, so
    // the paren is part of the cast's SPELLING and removing the cast without it leaves a
    // difference that is not a difference. The three tests above pin the actual behaviour; this
    // one asks only whether anything ELSE moved.
    let strip = |c: &str| {
        c.replace("(uint4 *)", "")
            .replace("(uint1 *)", "")
            .replace(['(', ')', ' '], "")
    };
    assert_eq!(
        strip(&print_c_recovered(&f, &EmitChoices::default(), &witnessed(&f))),
        strip(&print_c_recovered(&f, &off, &witnessed(&f))),
        "only the access type moves"
    );
}

/// The reason `Witness` can be the DEFAULT without breaking `EmitChoices::default()`'s promise to
/// be the reference rendering: the arm answers only for a site in the recovered witness set, and
/// the reference path carries no recovered evidence at all. With an empty set the default prints
/// exactly what `print_c` prints.
#[test]
fn the_default_is_still_the_reference_rendering_without_evidence() {
    let f = decompiled();
    assert_eq!(
        print_c_recovered(&f, &EmitChoices::default(), &RecoveredChoices::default()),
        print_c(&f),
        "no witness, no arm"
    );
}
