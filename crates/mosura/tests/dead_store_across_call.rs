//! A store into an address-taken stack aggregate between two calls must survive dead-code removal
//! (WAR2 0x2dcd4, wc2src-reconciliation-4 W4; oracle: `xStack_cc = func_0x000422b8(param_3,1);`).
//! Three faithful pieces make it so: `Heritage::guardCalls`' `holdind` is `queryProperties`'
//! `addrtied` — true for every stack/ram range, so the passthrough INDIRECT at the second call is
//! addr-forced; `RuleStoreVarnode` marks its COPY output `stack_store`; and `ActionDirectWrite`
//! treats a stack store whose source is a marker (the callee's `AX` indirect creation) as a direct
//! write, so the deadcode addrforce-clear leaves the chain alone and `ActionActiveReturn` then finds
//! the live creation and gives the call its output.
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::print_c_report;
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn store_of_call_result_into_escaping_frame_is_kept() {
    let path = paths::oracle_fixtures_dir().join("x86_2dcd4_frame.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("x86 SLEIGH tables load");
    let image: Vec<(u64, &[u8])> =
        dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    let (c, _) = print_c_report(&f, &EmitChoices::default());
    assert!(c.contains("xStack_cc = func_0x0000f000(param_3, 1);"), "the store of the call result must be kept (oracle form):\n{c}");
    assert!(c.contains("xunknown2 xStack_cc;"), "the stored slot is declared:\n{c}");
    // the return-address pushes must not surface as kept stores
    assert!(!c.contains("= 0xd0"), "no return-address store leaked:\n{c}");
}
