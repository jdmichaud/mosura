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
    let insns = normalize(lang_id, dt.chunks[0].bytes.as_slice(), entry, &NoReloc).unwrap_or_default();
    // the survey's one PRE-pipeline mark, decided from the fixture's own bytes as the survey
    // decides it from the original's (`Program::tail_return_writes`)
    f.tail_return_write = mosura::recompile::buildconfig::tail_return_write_from_evidence(&insns);
    pipeline::decompile(&mut f);
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
    assert!(!recovered.sparse_switch.sites.is_empty(), "the witness saw the compares");
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
    let cands = print_c_report(&f, &choices).1.cmp_order.candidates;
    assert!(!recovered.cmp_order.sites.is_empty(), "the witness read the CMP: candidates {cands:?} insns {texts:?}\n{c}");
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
    assert!(recovered.port.narrow_return && recovered.port.narrow_return_width == 1, "the witness: {recovered:?}");
    assert!(sig(&c).starts_with("xunknown1 ") || sig(&c).starts_with("uint1 "), "the byte declaration:\n{c}");
}

/// The stack twin of the store order: the parameter's store prints first, where the original
/// wrote it, not after the constants where the pipeline's snipped COPY sits.
#[test]
fn stack_store_order_follows_the_original() {
    let (f, insns) = decompiled("x86_watcom_stack_order.xml");
    let (c, recovered) = recovered_print(&f, &insns);
    let (choices, _) = measured_arms();
    let runs = print_c_report(&f, &choices).1.port.stack_store_runs;
    let texts: Vec<&str> = insns.iter().map(|i| i.text.as_str()).collect();
    let pos = |s: &str| c.find(s).unwrap_or_else(|| panic!("{s} in:\n{c}"));
    assert!(pos("= param_1;") < pos("= 0xe;") && pos("= 0xe;") < pos("= 9;"), "the original's store order: runs {runs:?} orders {:?} insns {texts:?}\n{c}", recovered.port.store_orders);
}

/// The narrow zero-extension keeps its `(uint2)` cast under `ext-cast=promotion` where the
/// original's `XOR AH,AH` witnesses the 16-bit width, and only there.
#[test]
fn narrow_zext_cast_follows_the_witness() {
    let (f, insns) = decompiled("x86_watcom_narrow_zext.xml");
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(!recovered.ext_cast.sites.is_empty(), "the witness saw the high-byte zero");
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
    assert!(!recovered.mask_cast.sites.is_empty(), "the witness read the AND: {:?}\n{c}", insns.iter().map(|i| i.text.as_str()).collect::<Vec<_>>());
    assert!(c.contains("(uint2)("), "the masked argument:\n{c}");
}

/// `return-split`, the constant-phi shape: the reference merges the two returns into a phi
/// (`x = 0; if (..) { ..; x = 1; } return x;`); the original's own-path `XOR EAX,EAX ; RET`
/// witnesses the per-path returns.
#[test]
fn const_phi_tail_returns_per_path() {
    let (f, insns) = decompiled("x86_watcom_const_phi.xml");
    let reference = reference_print(&f);
    assert!(reference.contains(" = 0;") && reference.contains(" = 1;"), "the reference merges the returns:\n{reference}");
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(!recovered.return_split.const_phi.is_empty(), "the witness read the exit: {:?}\n{c}", insns.iter().map(|i| i.text.as_str()).collect::<Vec<_>>());
    assert!(c.contains("return 1;") && c.contains("return 0;") && !c.contains(" = 0;"), "per-path returns, no merged variable:\n{c}");
}

/// `return-widen`: a widened return of a signed short (the reference returns it bare, which C
/// would sign-extend) prints the `(uint2)` cast the original's `XOR EAX,EAX ; MOV AX` performs.
#[test]
fn widened_return_of_a_signed_short_zero_extends() {
    let (f, insns) = decompiled("x86_watcom_return_zx.xml");
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(recovered.return_widen.zero_widened || c.contains("(uint2)"), "the widening is witnessed or the IR keeps the ZEXT: {:?}\n{c}", insns.iter().map(|i| i.text.as_str()).collect::<Vec<_>>());
    assert!(c.contains("return (uint2)"), "the returned short is re-signed:\n{c}");
}

/// `cmp-sign`: a short field compared zero-extended prints its `(uint2)` cast from the
/// original's `AND EAX,0xffff` ahead of the compare.
#[test]
fn compare_operand_the_original_zero_extends_prints_the_cast() {
    let (f, insns) = decompiled("x86_watcom_cmp_sign.xml");
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(!recovered.cmp_sign.sites.is_empty(), "the witness read the AND: {:?}\n{c}", insns.iter().map(|i| i.text.as_str()).collect::<Vec<_>>());
    assert!(c.contains("(uint2)"), "the compared short is re-signed:\n{c}");
}

/// `ptr-offset`: a field read at a constant offset from a pointer prints as byte-pointer
/// arithmetic where the original folds the displacement into the access.
#[test]
fn pointer_offset_deref_prints_byte_pointer_arithmetic() {
    let (f, insns) = decompiled("x86_watcom_ptr_offset.xml");
    let reference = reference_print(&f);
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(!recovered.ptr_offset.sites.is_empty(), "the witness read the displacement: {:?}\n{c}", insns.iter().map(|i| i.text.as_str()).collect::<Vec<_>>());
    assert!(c.contains("(char *)"), "the recovered rendering folds:\n{c}\nreference:\n{reference}");
}

/// The dummy stack parameter: a `RET 4` with no recovered parameter declares one unused stack
/// parameter, and the signature carries it.
#[test]
fn ret_n_without_parameters_declares_dummy_stack_parameters() {
    let (mut f, insns) = decompiled("x86_watcom_dummy_param.xml");
    assert!(insns.iter().any(|x| x.text == "RET 0x4"), "the fixture pops its argument: {:?}", insns.iter().map(|i| i.text.as_str()).collect::<Vec<_>>());
    f.ret_pop = Some(4); // the survey's flow analysis reads it off the `RET n`
    assert_eq!(mosura::recompile::buildconfig::dummy_stack_params(&f), 1);
    f.extra_stack_params = 1;
    let c = reference_print(&f);
    assert!(c.contains("func(xunknown4 param_1)"), "the signature declares the popped slot:\n{c}");
}

/// The far return: every return a `RETF`.
#[test]
fn far_return_is_witnessed_by_retf() {
    let (_f, insns) = decompiled("x86_watcom_far_return.xml");
    assert!(insns.iter().any(|x| x.text == "RETF"), "{:?}", insns.iter().map(|i| i.text.as_str()).collect::<Vec<_>>());
    assert!(mosura::recompile::buildconfig::far_return_from_evidence(&insns));
}

/// `cmp-order` on globals: the memory operand of the original's `CMP` names the source's
/// right-hand side, so the normalized `a <= b` mirrors back to `b >= a`.
#[test]
fn global_compare_mirrors_to_the_cmp_memory_operand() {
    let (f, insns) = decompiled("x86_watcom_cmp_mem.xml");
    let reference = reference_print(&f);
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(!recovered.cmp_order.sites.is_empty(), "the witness read the memory operand: {:?}\n{reference}", insns.iter().map(|i| i.text.as_str()).collect::<Vec<_>>());
    assert!(c.contains(">="), "mirrored:\n{c}\nreference:\n{reference}");
}

/// `load-hoist`: the element load becomes the explicit value and the pointer temp is inlined,
/// so the subscript folds into the access at the load's own position.
#[test]
fn load_through_a_pointer_temp_hoists_to_a_value() {
    let (f, insns) = decompiled("x86_watcom_load_hoist.xml");
    let reference = reference_print(&f);
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(!recovered.load_hoist.sites.is_empty(), "the witness read the scaled frame index: {:?}\n{reference}", insns.iter().map(|i| i.text.as_str()).collect::<Vec<_>>());
    assert!(!c.contains("Stack_28 + ") && !c.contains("Stack_24 + ") && c.contains("[iVar"), "the value is loaded at its position, no pointer temp:\n{c}\nreference:\n{reference}");
}

/// `return-split`, the branch form: a lone `return x != 0;` the original branched over prints
/// `if (x != 0) { return 1; } return 0;`.
#[test]
fn lone_bool_return_prints_its_branch_form() {
    let (f, insns) = decompiled("x86_watcom_branch_ret.xml");
    let reference = reference_print(&f);
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(!recovered.return_split.branch_return.is_empty() || !recovered.return_split.const_phi.is_empty(), "the witness read the branch: {:?}\n{reference}", insns.iter().map(|i| i.text.as_str()).collect::<Vec<_>>());
    assert!(c.contains("return 1;") && c.contains("return 0;") && !c.contains("return iVar1 != 0;"), "split:\n{c}\nreference:\n{reference}");
}

/// `store-forward`: the argument that is the value just stored to a global names the stored
/// global where the original reloads it.
#[test]
fn stored_global_is_named_at_the_call_the_original_reloads() {
    let (f, insns) = decompiled("x86_watcom_store_fwd.xml");
    let reference = reference_print(&f);
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(!recovered.store_forward.sites.is_empty(), "the witness read the reload: {:?}\n{reference}", insns.iter().map(|i| i.text.as_str()).collect::<Vec<_>>());
    let store = c.lines().find(|l| l.contains(" = ") && l.trim().starts_with("uRam") || l.contains(" = ") && l.trim().starts_with("xRam")).expect("the store statement");
    let stored = store.trim().split(" = ").next().unwrap().trim();
    assert!(c.contains(&format!("({stored})")), "the call names the stored global `{stored}`:\n{c}\nreference:\n{reference}");
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

/// `sparse-switch`, the tail clause: the reference prints the three tests as one `if`; the
/// recovered rendering prints the two witnessed 16-bit compares as the switch nest and the byte
/// global's test as an `if` inside the innermost case.
#[test]
fn narrow_switch_prints_a_memory_tail_clause_as_the_inner_if() {
    let (f, insns) = decompiled("x86_watcom_switch_tail.xml");
    let reference = reference_print(&f);
    assert!(!reference.contains("switch ("), "the reference rendering is the if:\n{reference}");
    let (c, _) = recovered_print(&f, &insns);
    assert!(c.contains("switch (*param_2) {") && c.contains("case 9:"), "the outer one-case switch:\n{c}");
    assert!(c.contains("switch (param_2[1]) {") && c.contains("case 5:"), "the inner one-case switch:\n{c}");
    let inner = c.find("case 5:").map(|i| &c[i..]).unwrap_or("");
    let next = inner.lines().nth(1).unwrap_or("").trim_start();
    assert!(next.starts_with("if ("), "the tail clause is the inner if:\n{c}");
}

/// `sparse-switch`, the range case list: `CMP r16,1 ; JA` lifts as `*p < 2`, which the reference
/// prints as the `if`; the recovered rendering prints `case 0: case 1:`.
#[test]
fn narrow_switch_prints_a_small_range_as_the_case_list() {
    let (f, insns) = decompiled("x86_watcom_switch_range.xml");
    let reference = reference_print(&f);
    assert!(!reference.contains("switch (") && reference.contains(" < 2)"), "the reference rendering is the if:\n{reference}");
    let (c, _) = recovered_print(&f, &insns);
    assert!(c.contains("switch (*param_2) {") && c.contains("case 0:\n") && c.contains("case 1:\n"), "the two-label case:\n{c}");
    assert!(!c.contains(" < 2)"), "no if remains:\n{c}");
}

/// `return-split`, the early-return shape: the reference merges the two `return 0;` into
/// `if (n != 0) { .. } return 0;`; the original's `JZ` past the shared `XOR EAX,EAX` says the
/// source returned early, and the recovered rendering prints that.
#[test]
fn early_return_prints_the_test_as_the_early_return() {
    let (f, insns) = decompiled("x86_watcom_early_return.xml");
    let reference = reference_print(&f);
    assert!(reference.contains("!= 0) {") && !reference.contains("== 0) {\n    return 0;"), "the reference is the merged form:\n{reference}");
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(!recovered.return_split.early_return.is_empty(), "the witness saw the jump past the load");
    assert!(c.contains("== 0) {\n    return 0;\n  }\n"), "the early return, its test flipped through the copy Ghidra's negate token descends:\n{c}");
    assert_eq!(c.matches("return 0;").count(), 2, "two returns of 0, the early one and the tail:\n{c}");
}

/// `counted-loop`: the reference prints the do-while with the increment as its last
/// statement; the original's `CALL ; INC ; CMP ; JLE` says the source wrote the `for`.
#[test]
fn counted_do_while_prints_as_the_for_loop() {
    let (f, insns) = decompiled("x86_watcom_counted_loop.xml");
    let reference = reference_print(&f);
    assert!(reference.contains("do {") && reference.contains("} while ("), "the reference is the do-while:\n{reference}");
    let (c, recovered) = recovered_print(&f, &insns);
    assert!(!recovered.counted_loop.sites.is_empty(), "the witness saw the iterate after the call");
    assert!(c.contains("for (") && c.contains("= 1; ") && c.contains(" + 1) {"), "the for loop:\n{c}");
    assert!(!c.contains("do {"), "no do-while remains:\n{c}");
}

/// The tail-return-write mark: the original's `MOV EAX,EDX` before the epilogue keeps the
/// EAX return trial the port's `ancestorOpUse` gate would discard (the buffer is also filled),
/// so the function returns the buffer instead of printing `void`.
#[test]
fn tail_return_write_keeps_the_discarded_return() {
    let (f, _insns) = decompiled("x86_watcom_dead_return.xml");
    assert!(f.tail_return_write, "the witness saw the tail write of EAX");
    let c = reference_print(&f);
    assert!(!c.starts_with("void "), "the function returns its buffer:\n{c}");
    assert!(c.contains("return "), "a return statement:\n{c}");
}
