//! A dedicated COPY into a call's argument register is *solid movement* into the parameter, and
//! the argument survives even when the COPY's source is a value that passed through an earlier
//! call.
//!
//! Ghidra `AncestorRealistic::enterNode` (funcdata_varnode.cc:2079-2104): for a COPY that is not
//! to a temporary, not incidental and not between the same storage, the walk only rules out an
//! unaffected / non-direct-write input along the COPY chain and pops `pop_solid` — it never
//! enters whatever defines the chain's head, so the killed-by-call rejection of a call
//! passthrough INDIRECT (:2093) is reachable only when the trial is defined by the INDIRECT
//! itself. mosura's flattened walk used to recurse through the COPY into the ESP passthrough
//! INDIRECT (`mov eax,esp` feeding the call) and reject the argument; the pre-call marker store
//! then flowed through the call, the post-call test constant-folded, and the subject's FUN_00066da8
//! lost its whole body (61 lines → three calls). The fixture is that function's bytes; the
//! expected shape is Ghidra's own (`oracle/capture --c` on the same fixture): the stack buffer is
//! passed to the call and tested afterwards.
use mosura::decompile::printc::print_c;
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn dedicated_copy_into_argument_register_is_solid_movement() {
    let path = paths::oracle_fixtures_dir().join("x86_watcom_ancestor_copy_solid.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id)
        .expect("the vendored x86 SLEIGH tables load (third_party/ghidra/Processors/x86)");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    let c = print_c(&f);
    let call = c
        .lines()
        .find(|l| l.contains("func_0x00066c90("))
        .unwrap_or_else(|| panic!("no call to func_0x00066c90 in:\n{c}"));
    assert!(
        call.contains("func_0x00066c90(aiStack_24"),
        "the stack buffer's address (a dedicated `mov eax,esp` COPY) is the call's first argument, got:\n{call}\n\nfull:\n{c}"
    );
    assert!(
        c.contains("aiStack_24[0] == 0x4f"),
        "the post-call test of the buffer survives (the pre-call marker store must not flow through the call):\n{c}"
    );
    assert!(
        c.lines().count() > 40,
        "the body must not collapse to the three calls it was reduced to ({} lines):\n{c}",
        c.lines().count()
    );
}
