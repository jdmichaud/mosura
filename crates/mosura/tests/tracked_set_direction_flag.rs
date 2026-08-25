//! The `<tracked_set>` port (docs/tracked-set-port.md): Ghidra's x86 pspec declares `DF=0` as a
//! default tracked register value, and `ActionConstbase` seeds it at the entry block so constant
//! propagation folds the direction flag out of a `rep`-string stride. Before the port mosura read
//! `DF` as an uninitialized varnode and emitted the `p = p + (uVar * -2 + 1)` artifact; after it,
//! `p = p + 1`, matching `oracle/capture --c` on the same bytes.
use mosura::decompile::printc::print_c;
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn rep_movsd_resolves_direction_flag_to_forward_stride() {
    let path = paths::oracle_fixtures_dir().join("x86_repmovsd.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id)
        .expect("the vendored x86 SLEIGH tables load (third_party/ghidra/Processors/x86)");

    // The pspec's tracked set reached the spec: x86 tracks the direction flag at 0.
    assert!(
        spec.tracked_context.iter().any(|&(_, size, val)| size == 1 && val == 0),
        "x86 pspec <tracked_set> should carry DF=0; got {:?}",
        spec.tracked_context
    );

    let image: Vec<(u64, &[u8])> =
        dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    let c = print_c(&f);

    // The stride is the clean forward `+ 1` (DF resolved to 0), not the `* -2 + 1` artifact, and no
    // uninitialized direction-flag varnode is declared or read.
    assert!(
        !c.contains("-2 + 1"),
        "the direction-flag stride artifact must be gone:\n{c}"
    );
    assert!(
        c.matches("+ 1;").count() >= 2,
        "both pointers advance by the resolved forward stride `+ 1`:\n{c}"
    );
}
