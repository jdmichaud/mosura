//! A6 gate: the faithfully recovered jump tables (`Funcdata::jump_tables`) the analysis-track
//! switch analyzer reads back must match Ghidra's recovered case targets exactly.
//!
//! Validated here against the build-time table read (which matches Ghidra for these functions) for
//! the canonical 0-based switch form. Offset/range switches (ifswitch, switchhide) need the
//! CircleRange range-pullback, and switchmulti needs the addrtied heritage guards — those forms
//! are tracked under A6-1 and are not yet asserted.

use mosura_core::decompile::build::{raw_funcdata_flow_image, raw_funcdata_flow_image_arch};
use mosura_core::decompile::pipeline;
use mosura_core::{datatest, paths};

/// Decompile a datatest and return (faithfully-recovered tables, build-time heuristic targets).
// (recovered tables, heuristic targets) tuple of table lists; clear as a local test helper type
#[allow(clippy::type_complexity)]
fn tables(name: &str) -> Option<(Vec<Vec<u64>>, Vec<Vec<u64>>)> {
    let sla = paths::language_dir("x86").join("x86-64.sla");
    if !sla.exists() {
        return None;
    }
    let spec = mosura_core::speccache::get(&sla).unwrap();
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    let dt = datatest::parse_file(&paths::datatests_dir().join(format!("{name}.xml"))).unwrap();
    let img: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let mut f = raw_funcdata_flow_image_arch(spec, "func", &img, dt.chunks[0].offset, &ctx, &dt.arch);
    let mut heur: Vec<Vec<u64>> = f.switch_targets.values().cloned().collect();
    heur.sort();
    pipeline::decompile(&mut f);
    let mut faithful: Vec<Vec<u64>> = f.jump_tables().into_iter().map(|t| t.targets).collect();
    faithful.sort();
    Some((faithful, heur))
}

#[test]
fn switchind_recovers_eleven_targets() {
    let Some((faithful, heur)) = tables("switchind") else { return };
    assert_eq!(faithful.len(), 1);
    assert_eq!(faithful[0].len(), 11, "11 case targets");
    assert_eq!(faithful, heur, "faithful recovery matches the (Ghidra-matching) build-time table");
}

#[test]
fn switchloop_recovers_nine_targets() {
    let Some((faithful, heur)) = tables("switchloop") else { return };
    assert_eq!(faithful.len(), 1);
    assert_eq!(faithful[0].len(), 9);
    assert_eq!(faithful, heur);
}

#[test]
fn declines_where_ghidra_declines() {
    // Ghidra cannot recover switchmulti ("Too many branches" → treats the indirect jump as a call)
    // and switchreturn has no switch — the faithful recovery must likewise produce no table (the
    // build heuristic wrongly invents 7 targets for switchmulti).
    if let Some((faithful, _)) = tables("switchmulti") {
        assert!(faithful.is_empty(), "switchmulti is an indirect call in Ghidra, not a jump table");
    }
    if let Some((faithful, _)) = tables("switchreturn") {
        assert!(faithful.is_empty(), "switchreturn has no jump table");
    }
}

#[test]
fn switchhide_recovers_via_alias_guarded_local() {
    // switchhide's index is a stack local set through a pointer passed to a call. It recovers only
    // once that local is guarded — which requires the AliasChecker to mark it aliased (its address
    // escapes to the call) and guardCalls to keep its value across the call. 16-entry table.
    let Some((faithful, heur)) = tables("switchhide") else { return };
    assert_eq!(faithful.len(), 1, "switchhide's switch must recover (needs the alias-guarded local)");
    assert_eq!(faithful[0].len(), 16);
    assert_eq!(faithful, heur);
}

#[test]
fn ifswitch_offset_switch_recovers_twentyone_targets() {
    // An offset switch (index = param_1, cases up to 0x14 in Ghidra ⇒ table indices 0..20).
    // The faithful guard-range recovery gets 21; the build-time heuristic over-reads one entry
    // past the guard bound (its 22 is wrong) — so we assert the Ghidra-correct count, not a match.
    let Some((faithful, _heur)) = tables("ifswitch") else { return };
    assert_eq!(faithful.len(), 1);
    assert_eq!(faithful[0].len(), 21, "Ghidra's ifswitch table is indices 0..0x14 = 21 entries");
}

#[test]
fn switch_o2_register_guard_with_cold_block_below_entry() {
    // gcc -O2 relative jump table (oracle/fixtures/x86_64_switch_o2.xml): the switch index lives in
    // a register (edi), the guard is `cmp $6,%edi; ja .cold`, and gcc places `classify.cold` at
    // 0x401000 — *below* the entry 0x401010, so the entry is not the lowest-address block.
    // Reachability must root at the entry, else the whole body (incl. the BRANCHIND) is pruned and
    // recovery declines. Ghidra recovers 7 COMPUTED_JUMP targets from 0x401029.
    let sla = paths::language_dir("x86").join("x86-64.sla");
    if !sla.exists() {
        return;
    }
    let spec = mosura_core::speccache::get(&sla).unwrap();
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_switch_o2.xml")).unwrap();
    let img: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let mut f = raw_funcdata_flow_image(spec, "classify", &img, 0x401010, &ctx);
    pipeline::decompile(&mut f);
    let jts = f.jump_tables();
    assert_eq!(jts.len(), 1, "the -O2 register-guard switch must recover");
    assert_eq!(jts[0].op_addr, 0x401029);
    assert_eq!(
        jts[0].targets,
        vec![0x401030, 0x401040, 0x401050, 0x401058, 0x401060, 0x401068, 0x401070],
        "7 COMPUTED_JUMP targets, matching Ghidra analyzeHeadless"
    );
}

/// Ghidra recovers a jump table only if its normalized range holds at most `max_jumptable_size`
/// = 1024 values (architecture.cc:1433; `JumpBasic::recoverModel` rejects a larger `jrange`).
/// `and edi,MASK; jmp [rdi*8+0x3000]` over 2048 pointers to distinct `ret`s, decompiled as the switch analyzer does
/// (a loaded raw program): MASK 0x3ff is 1024 cases and is recovered, MASK 0x7ff is 2048 and is
/// not. (mosura capped at 4096, and a 68000 dispatcher whose range came out at 2048 became a
/// 2048-case switch that took minutes to decompile, once per extent.)
#[test]
fn a_jump_table_over_1024_entries_is_declined() {
    use mosura_core::analysis::{decompiler::decompile_function, loader::raw::load_raw_at};
    use mosura_core::decompile::space::Address;
    let cases = |mask: u16| {
        let mut image = vec![0u8; 0x3000 + 2048 * 8];
        image[0x1000..0x100d].copy_from_slice(&[0x81, 0xe7, mask as u8, (mask >> 8) as u8, 0x00, 0x00, 0xff, 0x24, 0xfd, 0x00, 0x30, 0x00, 0x00]);
        // every case its own `ret`, so no two cases merge
        image[0x1100..0x1100 + 2048].fill(0xc3);
        for i in 0..2048 {
            image[0x3000 + 8 * i..0x3008 + 8 * i].copy_from_slice(&(0x1100 + i as u64).to_le_bytes());
        }
        let mut p = load_raw_at(&image, "x86:LE:64:default", 0, &[0x1000]).unwrap();
        mosura_core::analysis::analyze(&mut p);
        let mut f = decompile_function(&p, Address::new(p.default_space, 0x1000)).expect("decompiles");
        f.jump_tables().into_iter().map(|t| t.targets.len()).collect::<Vec<_>>()
    };
    assert_eq!(cases(0xf), [16], "the shape is recovered");
    assert_eq!(cases(0x3ff), [1024], "1024 cases: recovered");
    assert_eq!(cases(0x7ff), Vec::<usize>::new(), "2048 cases: over Ghidra's maximum, declined");
}

/// Two computed jumps into `bra.w` tables that share their cases (a 68000 music driver's command
/// dispatch): each index is `(x & 0xff) << 2`, so each recovers 256 targets over the same code, and
/// structuring traces ~770 edges. `TraceDAG::pushBranches` converges in ~133k steps; the port's
/// linear safety cap (~8k) cut it off and the function was skipped. Ghidra has no cap.
#[test]
fn two_switches_sharing_their_cases_are_structured() {
    use mosura_core::analysis::{decompiler::decompile_function, loader::raw::load_raw_at};
    use mosura_core::decompile::space::Address;
    let mut image = vec![0u8; 0x800];
    image[0..8].copy_from_slice(&[0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00]);
    // 100: andi.w #$ff,d5; lsl.w #2,d5; tst.b (1,a3); bmi.b 110
    // 10c: jmp (114,pc,d5.w)   110: jmp (124,pc,d5.w)
    // 114: bra.w A,SELF,B,C    124: bra.w B,SELF,C,A
    // 134: SELF bra.b SELF     136: A rts     138: B moveq #1,d1; rts     13c: C moveq #2,d1; rts
    let code: [u8; 64] = [
        0x02, 0x45, 0x00, 0xff, 0xe5, 0x4d, 0x4a, 0x2b, 0x00, 0x01, 0x6b, 0x04, 0x4e, 0xfb, 0x50, 0x06, 0x4e, 0xfb, 0x50, 0x12, 0x60, 0x00,
        0x00, 0x20, 0x60, 0x00, 0x00, 0x1a, 0x60, 0x00, 0x00, 0x1a, 0x60, 0x00, 0x00, 0x1a, 0x60, 0x00, 0x00, 0x12, 0x60, 0x00, 0x00, 0x0a,
        0x60, 0x00, 0x00, 0x0e, 0x60, 0x00, 0x00, 0x04, 0x60, 0xfe, 0x4e, 0x75, 0x72, 0x01, 0x4e, 0x75, 0x72, 0x02, 0x4e, 0x75,
    ];
    image[0x100..0x140].copy_from_slice(&code);
    let mut p = load_raw_at(&image, "68000:BE:32:default", 0, &[0x100]).unwrap();
    mosura_core::analysis::analyze(&mut p);
    let mut f = decompile_function(&p, Address::new(p.default_space, 0x100)).expect("structured, not skipped");
    let sizes: Vec<usize> = f.jump_tables().into_iter().map(|t| t.targets.len()).collect();
    assert_eq!(sizes, [256, 256]);
    // Under a time limit (Ghidra's analysis decompiles run under one), a decompile that reaches it
    // stops and answers nothing: here the limit is already spent when the pipeline starts.
    use mosura_core::analysis::decompiler::decompile_function_within;
    let entry = Address::new(p.default_space, 0x100);
    assert!(decompile_function_within(&p, entry, Some(std::time::Duration::ZERO)).is_none(), "a spent limit stops the decompile");
    assert!(decompile_function_within(&p, entry, Some(std::time::Duration::from_secs(600))).is_some(), "an ample one does not");
}

/// A byte index in a big-endian register: on the 68000 `D0b` is `D0`'s LEAST significant byte
/// (register offset +3). `moveq #0,d0; move.b (a0),d0; cmpi.b #$e0/#$e4 guards; subi.b #$e0,d0;
/// lsl.w #2,d0; jmp (T,pc,d0.w)` is a 4-way switch (cases 0xE0-0xE3, stride 4), as Ghidra recovers
/// it. Heritage placed the byte by little-endian offset — at the TOP of `D0w` — and the table came
/// out at stride 0x400, or not at all (Ghidra `Varnode::overlap` / `concatPieces` / `splitPieces`
/// big-endian arms).
#[test]
fn a_big_endian_byte_index_recovers_its_switch() {
    use mosura_core::analysis::{decompiler::decompile_function, loader::raw::load_raw_at};
    use mosura_core::decompile::space::Address;
    let mut image = vec![0u8; 0x300];
    image[0..8].copy_from_slice(&[0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x02, 0x00]);
    // 200 moveq #0,d0; move.b (a0),d0; cmpi.b #$e0,d0; bcs $21a; cmpi.b #$e4,d0; bcc $21a;
    // subi.b #$e0,d0; lsl.w #2,d0; jmp (4,pc,d0.w) -> $21c; 21a rts; 21c 4 x bra.w
    let code = [
        0x70, 0x00, 0x10, 0x10, 0x0c, 0x00, 0x00, 0xe0, 0x65, 0x10, 0x0c, 0x00, 0x00, 0xe4, 0x64, 0x0a, 0x04, 0x00, 0x00, 0xe0, 0xe5, 0x48, 0x4e, 0xfb,
        0x00, 0x04, 0x4e, 0x75,
    ];
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    for (i, t) in [0x230u16, 0x234, 0x238, 0x23c].iter().enumerate() {
        let at = 0x21c + 4 * i;
        let disp = (*t as i32 - (at as i32 + 2)) as i16;
        image[at..at + 4].copy_from_slice(&[0x60, 0x00, (disp >> 8) as u8, disp as u8]);
        image[*t as usize..*t as usize + 4].copy_from_slice(&[0x72, i as u8, 0x4e, 0x75]);
    }
    let mut p = load_raw_at(&image, "68000:BE:32:default", 0, &[0x200]).unwrap();
    mosura_core::analysis::analyze(&mut p);
    let mut f = decompile_function(&p, Address::new(p.default_space, 0x200)).expect("decompiles");
    let targets: Vec<Vec<u64>> = f.jump_tables().into_iter().map(|t| t.targets).collect();
    assert_eq!(targets, [vec![0x21c, 0x220, 0x224, 0x228]]);
}
