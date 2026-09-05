//! A do-while whose body list ends in a short-circuit condition prints the condition's second
//! operand — statements and all — inside `while (...)`.
//!
//! Ghidra `PrintC::emitBlockDoWhile` re-emits the body block under `only_branch`, and
//! `PrintC::emitBlockLs` under `only_branch` emits ONLY the list's last sub-block (printc.cc:2787);
//! when that block is a `BlockCondition`, `emitBlockCondition` prints `(a) || (stmt, b)` with the
//! second operand under `comma_separate`. mosura's `render_cond_expr` used to treat the body list
//! as a leaf and read one CBRANCH off its exit basic, which dropped the second operand entirely —
//! the subject's FUN_0004d0f8 lost its `func_0x000123dc` call from the output. The fixture is that
//! function's bytes; the expected shape is Ghidra's own (`oracle/capture --c` on the same fixture):
//!
//! ```text
//!   } while ((iVar1 == 0) ||
//!           (iVar1 = func_0x000123dc(*(xunknown2 *)((uint4)uRam00097510 * 10 + 0x87e90)), iVar1 == 0
//!           ));
//! ```
use mosura::decompile::printc::print_c;
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn dowhile_body_list_ending_in_condor_prints_both_operands() {
    let path = paths::oracle_fixtures_dir().join("x86_watcom_dowhile_or.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id)
        .expect("the vendored x86 SLEIGH tables load (third_party/ghidra/Processors/x86)");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    let c = print_c(&f);
    let tail = c
        .lines()
        .find(|l| l.trim_start().starts_with("} while ("))
        .unwrap_or_else(|| panic!("no do-while tail in:\n{c}"));
    assert!(
        tail.contains("||") && tail.contains("func_0x000123dc("),
        "the condition's second operand (the call) must print inside `while (...)`, got:\n{tail}\n\nfull:\n{c}"
    );
    assert_eq!(
        c.matches("func_0x000123dc(").count(),
        1,
        "the call prints exactly once, inside the condition:\n{c}"
    );
}
