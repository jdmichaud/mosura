//! The entry block must have no incoming edges — Ghidra's `FlowInfo::generateBlocks`
//! (`flow.cc:833`) front-block insertion.
//!
//! When a function's entry block is also a loop head, the entry has a back-edge into itself and
//! the invariant every downstream consumer assumes is violated: `dominator.rs` documents "block 0
//! is the entry", and `merge.rs` carries a regression comment reading "block 0 — the entry block,
//! in_edges == []". Nothing established it. Ghidra guarantees it by inserting an empty block in
//! front of the entry whenever the entry has in-edges:
//!
//! ```c
//! if (startblock->sizeIn() != 0) {          // Make sure the entry block has no incoming edges
//!   BlockBasic *newfront = bblocks.newBlockBasic(&data);
//!   bblocks.addEdge(newfront,startblock);
//!   bblocks.setStartBlock(newfront);
//!   data.setBasicBlockRange(newfront, data.getAddress(), data.getAddress());
//! }
//! ```
//!
//! The consequence of the missing clause is a data-flow defect, not a cosmetic one: the
//! dominance-frontier walk never adds block 0 to its own frontier, so a value defined in the entry
//! loop head gets no merge node at all and every read re-links to the function-input value — the
//! loop's updates disappear from the output.
//!
//! Both directions are pinned here: a function whose entry is a loop head gains the front block,
//! and an ordinary function does not gain a spurious one.
use mosura_core::decompile::{build, pipeline, printc};

const ARCH: &str = "x86:LE:32:default:gcc";
const LANG: &str = "x86:LE:32:default";
const ENTRY: u64 = 0x1000;

/// `do { n >>= 1; } while (n > 5);` as gcc `-O2` lays it out: the loop head IS the entry, with no
/// guard block in front of it. (A `while` loop does not reproduce this — gcc rotates it and emits
/// a guard block, which gives the entry a clean in-edge-free head. That is why the shape here is a
/// do-while and must stay one.)
///
/// ```text
/// 1000  d1 f8        sar eax,1
/// 1002  83 f8 05     cmp eax,5
/// 1005  7f f9        jg  0x1000     <- back to the ENTRY
/// 1007  c3           ret
/// ```
const ENTRY_LOOP_HEAD: &[u8] = &[0xd1, 0xf8, 0x83, 0xf8, 0x05, 0x7f, 0xf9, 0xc3];

/// A straight-line function: no back edge, so no front block should be inserted.
///
/// ```text
/// 1000  d1 f8        sar eax,1
/// 1002  c3           ret
/// ```
const STRAIGHT_LINE: &[u8] = &[0xd1, 0xf8, 0xc3];

fn lift(bytes: &'static [u8]) -> Option<mosura_core::decompile::funcdata::Funcdata> {
    let (spec, ctx) = mosura_core::lang::load_cached(LANG)?;
    let image: Vec<(u64, &[u8])> = vec![(ENTRY, bytes)];
    Some(build::raw_funcdata_flow_image_arch(spec, "func", &image, ENTRY, ctx, ARCH))
}

/// The CFG alone, exactly as the pipeline's first action builds it (`pipeline.rs:50`, on a
/// function with no blocks yet).
fn cfg_of(bytes: &'static [u8]) -> Option<mosura_core::decompile::funcdata::Funcdata> {
    let mut f = lift(bytes)?;
    mosura_core::decompile::cfg::build_cfg(&mut f);
    Some(f)
}

/// The invariant itself, straight off the CFG.
#[test]
fn the_entry_block_has_no_in_edges_when_it_is_a_loop_head() {
    let Some(f) = cfg_of(ENTRY_LOOP_HEAD) else {
        eprintln!("skip: {LANG} unavailable");
        return;
    };
    let blocks = f.blocks();
    assert!(blocks.len() >= 2, "expected a multi-block CFG, got {}", blocks.len());
    assert!(
        blocks[0].in_edges.is_empty(),
        "block 0 (the entry) has in-edges {:?} — Ghidra's flow.cc:833 front block was not inserted",
        blocks[0].in_edges
    );
    // the front block is empty and flows to the old entry, which keeps the loop's back edge
    assert!(blocks[0].ops.is_empty(), "the inserted front block carries no ops");
    assert_eq!(blocks[0].out_edges.len(), 1, "the front block flows only to the old entry");
    let old_entry = blocks[0].out_edges[0].0 as usize;
    assert!(
        blocks[old_entry].in_edges.len() >= 2,
        "the old entry keeps its back edge plus the new front edge, got {:?}",
        blocks[old_entry].in_edges
    );
}

/// An ordinary function must NOT grow a front block: the clause is conditional on the entry
/// actually having in-edges, and a spurious empty block 0 would change every later block index.
#[test]
fn a_straight_line_function_gains_no_front_block() {
    let Some(f) = cfg_of(STRAIGHT_LINE) else {
        eprintln!("skip: {LANG} unavailable");
        return;
    };
    let blocks = f.blocks();
    assert!(blocks[0].in_edges.is_empty(), "a straight-line entry has no in-edges to begin with");
    assert!(
        !blocks[0].ops.is_empty(),
        "block 0 should still be the real entry block, not an inserted empty one"
    );
}

/// The payoff: with the entry's merge node built, the loop's update survives into the output.
/// Before the fix the body renders empty with an unassigned variable.
#[test]
fn the_entry_loop_head_keeps_its_update() {
    let Some(mut f) = lift(ENTRY_LOOP_HEAD) else {
        eprintln!("skip: {LANG} unavailable");
        return;
    };
    pipeline::decompile(&mut f);
    let c = printc::print_c(&f);
    // Before the fix this rendered with an EMPTY body and the condition reading the function
    // input, so the iteration never accumulated:
    //     do { } while (5 < param_1 >> 1);
    // The `>>` was present either way, in the condition — so the assertion has to be that the
    // loop BODY carries the update, not that the shift appears somewhere.
    let body = c
        .split_once("do {")
        .and_then(|(_, rest)| rest.split_once("} while"))
        .map(|(body, _)| body.to_string())
        .unwrap_or_else(|| panic!("expected a do-while rendering:\n{c}"));
    assert!(
        body.contains('='),
        "the entry loop head's update is missing from the loop body:\n{c}"
    );
    // and the condition tests the accumulated value, not the raw input
    assert!(c.contains("while (5 < param_1)"), "the condition should test the carried value:\n{c}");
}
