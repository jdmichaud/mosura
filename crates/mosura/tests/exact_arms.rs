//! The arms of the EXACT push (2026-09-03, docs/exact-arms.md): each fixture is a self-compiled
//! Watcom MVE (`recompile::mve`) carrying the byte witness its arm reads. The reference rendering
//! is the port's own; the recovered one is what the survey emits, decided by the same recovery
//! the survey runs (`recompile::recovery::recover` over the fixture's own bytes).
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::funcdata::Funcdata;
use mosura::decompile::printc::{print_c_recovered, print_c_report, RecoveredChoices};
use mosura::decompile::{build, pipeline};
use mosura::recompile::insn::{normalize, NoReloc, NormInsn};
use mosura::recompile::recovery::{measured_arms, recover};
use mosura::{datatest, paths};

fn decompiled(fixture: &str) -> (Funcdata, Vec<NormInsn>) {
    let path = paths::oracle_fixtures_dir().join(fixture);
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("x86 SLEIGH tables load");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    let insns = normalize(lang_id, dt.chunks[0].bytes.as_slice(), entry, &NoReloc).unwrap_or_default();
    (f, insns)
}

/// The survey's recovered rendering of the fixture: the measured arms, the witnesses read off
/// the fixture's own bytes.
fn recovered_print(f: &Funcdata, insns: &[NormInsn]) -> (String, RecoveredChoices) {
    let (choices, rec_choices) = measured_arms();
    let recovered = recover(f, insns, &choices, &rec_choices, |_| Default::default());
    (print_c_recovered(f, &rec_choices, &recovered), recovered)
}

fn reference_print(f: &Funcdata) -> String {
    print_c_report(f, &EmitChoices::default()).0
}

/// The one-case 16-bit switch: the reference prints the if; the recovered rendering prints the
/// nested one-case switches the 16-bit register compares witness.
#[test]
fn narrow_switch_prints_the_one_case_switches() {
    let (f, insns) = decompiled("x86_watcom_narrow_switch.xml");
    let reference = reference_print(&f);
    assert!(!reference.contains("switch ("), "the reference rendering is the if:\n{reference}");
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(!recovered.sparse_cmp_sites.is_empty(), "the witness saw the compares");
    assert!(c.contains("switch (*param_2) {") && c.contains("case 9:"), "the outer one-case switch:\n{c}");
    assert!(c.contains("switch (param_2[1]) {") && c.contains("case 0:"), "the inner one-case switch:\n{c}");
}

/// `cmp-order`: the reference prints Ghidra's canonical `field <= table`; the CMP's operand
/// order says the source wrote `table >= field`.
#[test]
fn cmp_order_mirrors_the_compare_the_cmp_wrote() {
    let (f, insns) = decompiled("x86_watcom_cmp_order.xml");
    let reference = reference_print(&f);
    assert!(reference.contains(" <= "), "the reference is the canonical form:\n{reference}");
    let (c, recovered) = recovered_print(&f, &insns);
    let texts: Vec<&str> = insns.iter().map(|i| i.text.as_str()).collect();
    let (choices, _) = measured_arms();
    let cands = print_c_report(&f, &choices).1.cmp_order_candidates;
    assert!(!recovered.cmp_order_sites.is_empty(), "the witness read the CMP: candidates {cands:?} insns {texts:?}\n{c}");
    assert!(c.contains(" >= "), "the mirrored compare:\n{c}");
}

/// `return-width`: every return site writes `AL`, so the declaration is one byte although the
/// IR's value is a full-width constant.
#[test]
fn byte_return_declares_the_witnessed_width() {
    let (f, insns) = decompiled("x86_watcom_byte_return.xml");
    let reference = reference_print(&f);
    let sig = |c: &str| c.lines().find(|l| l.contains(" func(")).map(str::to_string).unwrap_or_default();
    assert!(!sig(&reference).starts_with("xunknown1 ") && !sig(&reference).starts_with("uint1 "), "the reference declares the IR's width:\n{reference}");
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(recovered.narrow_return && recovered.narrow_return_width == 1, "the witness: {recovered:?}");
    assert!(sig(&c).starts_with("xunknown1 ") || sig(&c).starts_with("uint1 "), "the byte declaration:\n{c}");
}

/// The stack twin of the store order: the parameter's store prints first, where the original
/// wrote it, not after the constants where the pipeline's snipped COPY sits.
#[test]
fn stack_store_order_follows_the_original() {
    let (f, insns) = decompiled("x86_watcom_stack_order.xml");
    let (c, recovered) = recovered_print(&f, &insns);
    let (choices, _) = measured_arms();
    let runs = print_c_report(&f, &choices).1.stack_store_runs;
    let texts: Vec<&str> = insns.iter().map(|i| i.text.as_str()).collect();
    let pos = |s: &str| c.find(s).unwrap_or_else(|| panic!("{s} in:\n{c}"));
    assert!(pos("= param_1;") < pos("= 0xe;") && pos("= 0xe;") < pos("= 9;"), "the original's store order: runs {runs:?} orders {:?} insns {texts:?}\n{c}", recovered.store_orders);
}

/// The narrow zero-extension keeps its `(uint2)` cast under `ext-cast=promotion` where the
/// original's `XOR AH,AH` witnesses the 16-bit width, and only there.
#[test]
fn narrow_zext_cast_follows_the_witness() {
    let (f, insns) = decompiled("x86_watcom_narrow_zext.xml");
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(!recovered.narrow_zext_sites.is_empty(), "the witness saw the high-byte zero");
    assert!(c.contains("(uint2)"), "the cast stands:\n{c}");
    let (_, rec_choices) = measured_arms();
    let bare = print_c_recovered(&f, &rec_choices, &RecoveredChoices::default());
    assert!(!bare.contains("(uint2)"), "without the witness the promotion arm prints bare:\n{bare}");
}

/// `mask-cast`: the reference passes the sum bare (Ghidra dropped the redundant mask); the
/// original's `AND EAX,0xffff` before the call witnesses the `(uint2)` cast.
#[test]
fn masked_call_argument_prints_the_witnessed_cast() {
    let (f, insns) = decompiled("x86_watcom_mask_arg.xml");
    let reference = reference_print(&f);
    assert!(!reference.contains("(uint2)("), "the reference passes the sum bare:\n{reference}");
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(!recovered.mask_sites.is_empty(), "the witness read the AND: {:?}\n{c}", insns.iter().map(|i| i.text.as_str()).collect::<Vec<_>>());
    assert!(c.contains("(uint2)("), "the masked argument:\n{c}");
}

/// A sign-extension of an unsigned-typed piece re-signs the operand at its own width: the
/// split local's high half is `(int4)(int2)` like its low half, never a zero-extending `(int4)`
/// of the unsigned accessor.
#[test]
fn sign_extension_re_signs_an_unsigned_operand() {
    let (f, insns) = decompiled("x86_watcom_split_local.xml");
    let (c, _) = recovered_print(&f, &insns);
    assert!(c.matches("(int4)(int2)").count() >= 2, "both halves sign-extend from a signed narrow cast:\n{c}");
}
