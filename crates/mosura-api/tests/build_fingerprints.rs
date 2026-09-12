#[allow(dead_code)]
#[path = "../build.rs"]
mod build;

#[test]
fn emission_dependencies_invalidate_cached_translation_units() {
    let base = [("analysis/program.rs", b"program".as_slice())];
    let initial = build::source_fingerprints(base);
    for path in ["recompile/tu.rs", "recompile/pragma.rs", "recompile/round.rs",
        "recompile/passes.rs", "recompile/function.rs", "recompile/upgrade.rs",
        "recompile/new_emission_dependency.rs"]
    {
        let before = build::source_fingerprints(base.into_iter().chain([(path, b"old".as_slice())]));
        let after = build::source_fingerprints(base.into_iter().chain([(path, b"new".as_slice())]));
        assert_ne!(before.1, after.1, "{path}: edited emission source must invalidate the TU");
        assert_ne!(initial.1, after.1, "{path}: adding an emission dependency must invalidate the TU");
        assert_eq!(before.0, after.0, "{path}: retain cached input analysis");
        assert_ne!(before.2, after.2, "{path}: recompilation also reads this subtree");
    }
}

#[test]
fn emit_arm_changes_do_not_invalidate_input_analysis() {
    let before = build::source_fingerprints([("decompile/emit/arms/cast.rs", b"old".as_slice())]);
    let after = build::source_fingerprints([("decompile/emit/arms/cast.rs", b"new".as_slice())]);
    assert_eq!(before.0, after.0);
    assert_ne!(before.1, after.1);
    assert_eq!(before.2, after.2);
}
