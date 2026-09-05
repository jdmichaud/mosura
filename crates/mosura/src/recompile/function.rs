//! One function's byte-and-IR facts for the recompile — moved verbatim out of the corpus emit
//! driver (plan WP7 P0 c7, 2026-09-05): the extent of the ORIGINAL bytes to compare against (the
//! function's own recorded body clamped by the decompiler's coverage and the next entry, trailing
//! padding trimmed but never below the last covered instruction), the convention marks applied
//! from the original's own instructions, the IR/CFG metrics the manifest carries, the per-function
//! global widths, and the function's own Watcom contract. Usable on any `Funcdata` + its bytes;
//! nothing here reads a file or the environment.

use std::collections::HashMap;

use crate::analysis::program::Program;
use crate::decompile::funcdata::Funcdata;
use crate::decompile::op::flags;
use crate::decompile::opcode::OpCode;
use crate::recompile::insn::NormInsn;
use crate::recompile::passes::{Entries, GlobalWidths};
use crate::recompile::pragma::WatcomRegs;

/// The original bytes of one function and how their end was decided: `cov_lo..cov_hi` = the live
/// instruction coverage of the decompile, `body_end` = the function manager's recorded body end,
/// `end_untrimmed` = the clamped end before the padding trim, `end` = after it, `region` = the
/// bytes `[va, end)`.
pub struct Extent {
    pub cov_lo: u64,
    pub cov_hi: u64,
    pub end: u64,
    pub end_untrimmed: u64,
    pub body_end: Option<u64>,
    pub region: Vec<u8>,
}

/// Trim trailing padding (`0x00`, `0x90`, `0xcc`), but NEVER below `floor` — the end of the last
/// decoded instruction. The trimmer used to strip any trailing 0x00/0x90/0xcc, and the last byte of
/// a real operand is very often 0x00 — `e9 0c610100` (a 5-byte `jmp rel32` tail-call shim) came
/// back as 4 bytes with its displacement cut, and `b0 01 c2 0400` (`mov al,1 ; ret 4`) likewise.
/// Measured against the tracker's true sizes: 39 extents short, 28 of them by exactly one byte.
/// `cov_hi` is the floor: padding is what lies AFTER the code, never inside it.
pub fn trim_trailing_padding(region: &mut Vec<u8>, end: &mut u64, floor: u64) {
    while *end > floor && region.last().is_some_and(|&b| b == 0x00 || b == 0x90 || b == 0xcc) {
        region.pop();
        *end -= 1;
    }
}

/// The function's extent: its own recorded body, clamped never past the next entry and never below
/// the decompiler's coverage, trailing padding trimmed (see [`trim_trailing_padding`]).
pub fn extent(prog: &Program, entries: &Entries, f: &Funcdata, va: u64) -> Extent {
    // Decompiler-covered extent (cross-check only): live-op ram instruction starts.
    let mut cov_lo = u64::MAX;
    let mut cov_hi = 0u64;
    for id in f.op_ids() {
        let op = f.op(id);
        if op.flags & (flags::DEAD | flags::MARKER) != 0 {
            continue;
        }
        let pc = op.seqnum.pc;
        if pc.space != prog.default_space {
            continue;
        }
        let len = match prog.listing.code_unit_at(pc) {
            Some(crate::analysis::program::CodeUnit::Instruction { length, .. }) => *length as u64,
            _ => 1,
        };
        cov_lo = cov_lo.min(pc.offset);
        cov_hi = cov_hi.max(pc.offset + len);
    }
    if cov_lo == u64::MAX {
        cov_lo = va;
        cov_hi = va;
    }

    // The function's extent is mosura's OWN recorded body, not the gap to the next entry.
    //
    // `[entry, next-entry)` attributes to a function everything the linker happened to place
    // after it, and what follows a function is very often DATA. Measured on the subject: the body is
    // smaller than the gap for 2140 of 3023 functions, totalling 49,359 bytes of data counted
    // as code. The worst is `FUN_00075801` -- a 48-byte comparator followed by a 7,727-byte
    // table -- which was compared as 2591 instructions against the 20 it really has, and read
    // as a catastrophic decompiler failure when the decompilation is exactly right.
    //
    // The body is clamped on both sides rather than trusted outright, because neither bound is
    // free:
    //   * never past `next` -- 11 functions have bodies that run beyond the following entry,
    //     which would make two functions claim the same bytes;
    //   * never below `cov_hi` -- if body computation ever UNDER-states a function, truncating
    //     the original would hide a real failure by comparing against less than the function.
    // Both bounds are facts already established above, so this only ever pulls the end IN from
    // the heuristic, never pushes it out.
    let (next, body_end) = entries.extent_bounds(prog, va);
    let mut end = match body_end {
        Some(b) => next.min(b.max(cov_hi)).max(va + 1),
        None => next.max(va + 1),
    };
    let end_untrimmed = end;
    let mut region = prog.memory.read_window(crate::decompile::space::Address::new(prog.default_space, va), (end - va) as usize);
    // Trim trailing padding, but NEVER below the end of the last decoded instruction. The
    // trimmer used to strip any trailing 0x00/0x90/0xcc, and the last byte of a real operand is
    // very often 0x00 — `e9 0c610100` (a 5-byte `jmp rel32` tail-call shim) came back as 4
    // bytes with its displacement cut, and `b0 01 c2 0400` (`mov al,1 ; ret 4`) likewise. The
    // function was then compared against a truncated original, and the row read as a decompiler
    // failure. Measured against the tracker's true sizes: 39 extents short, 28 of them by
    // exactly one byte.
    //
    // `cov_hi` is the end of the highest instruction the decompiled function actually covers,
    // so it is the floor for trimming: padding is what lies AFTER the code, never inside it.
    let floor = cov_hi.max(va + 1);
    trim_trailing_padding(&mut region, &mut end, floor);
    Extent { cov_lo, cov_hi, end, end_untrimmed, body_end, region }
}

/// The convention marks the decompiler cannot see from the IR alone, applied from the function's
/// own instructions before any rendering: DROPPED PARAMETERS (a register this function pushes at
/// entry and pops before its returns is not an argument register — the last parameter recovered in
/// it, when it only flows into callees, is the caller's preserved value), a `RETF` return declaring
/// the function `far`, parameters the original copies into a byte register at entry (declared at
/// that width), and the stack slots a `RET n` pops that no parameter reads.
pub fn apply_marks(f: &mut Funcdata, insns: &[NormInsn]) {
    f.dropped_params = crate::recompile::buildconfig::phantom_params_from_evidence(&f, &insns);
    // a `RETF` return declares the function `far`; a `RET n` popping slots no parameter
    // reads declares the popped slots as unused stack parameters
    f.far_return = crate::recompile::buildconfig::far_return_from_evidence(&insns);
    // a parameter the original copies into a byte register at entry and the IR only
    // masks is declared at that width
    f.narrow_params = crate::recompile::buildconfig::narrow_params_from_evidence(&f, &insns);
    f.extra_stack_params = crate::recompile::buildconfig::dummy_stack_params(&f);
}

/// The manifest's IR/CFG metrics: live CALL/CALLIND ops in the final IR (so a deficit row can say
/// whether the decompiler never recovered a call or the emitter lost one), the CFG's basic blocks
/// versus the blocks the structured tree REACHES (`reached < cfg` is wrong code, and the only gate
/// that sees the silent case), and the thunk shape (a short JMP body).
pub struct Metrics {
    pub ir_calls: usize,
    pub blocks_cfg: usize,
    pub blocks_reached: usize,
    pub thunk: bool,
}

pub fn metrics(f: &Funcdata, region: &[u8]) -> Metrics {
    let ir_calls = f
        .op_ids()
        .filter(|&id| {
            let op = f.op(id);
            op.flags & (flags::DEAD | flags::MARKER) == 0
                && matches!(op.code(), OpCode::Call | OpCode::Callind)
        })
        .count();

    // BLOCKS: how many basic blocks the CFG has vs how many the structured tree REACHES.
    // `reached < cfg` means blocks are never emitted — wrong code, and the ONLY gate that sees the
    // silent case (a dropped block with no surviving in-edge produces no dangling goto and no
    // compiler error; the C just compiles the wrong program). See
    // `decompile::structure::reached_basic_blocks`.
    let blocks_cfg = f.num_blocks();
    let blocks_reached =
        crate::decompile::structure::reached_basic_blocks(&crate::decompile::structure::structure(&f))
            .len();
    let thunk = matches!(region.first(), Some(0xe9) | Some(0xeb)) && region.len() <= 8;
    Metrics { ir_calls, blocks_cfg, blocks_reached, thunk }
}

/// GLOBAL WIDTHS for this function's RAM globals, from the decompiler rather than the name (a
/// prefix carries kind, not SIZE): the narrowest access wins, and the `global-width` arm widens
/// back — only where this function WRITES the address — to the original's own store width where the
/// image also reads it wider, or to the function's wider IR width where its own bytes read it that
/// wide. `corpus` = the corpus-wide store/read widths ([`GlobalWidths`]).
pub fn global_widths(f: &Funcdata, lang: &str, region: &[u8], va: u64, corpus: &GlobalWidths, arm_on: bool) -> HashMap<u64, u32> {
    let ram_dec = f.spaces.by_name("ram");
    let mut gsizes: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
    // ram addresses THIS FUNCTION STORES, read from its OWN BYTES.  Two IR-side tests were
    // tried and both failed: `is_written()` is true for a purely read global (heritage gives it
    // an INDIRECT across every call and a phi at every join), and excluding INDIRECT/MULTIEQUAL
    // defs still let the return-guard COPY through -- 54 read-only TUs were widened either way.
    // The instruction stream has no such ambiguity: a store is a memory operand in the output.
    let own_norm = if arm_on {
        crate::recompile::insn::normalize(lang, &region, va, &crate::recompile::insn::NoReloc).unwrap_or_default()
    } else {
        Vec::new()
    };
    let gwrote: std::collections::HashSet<u64> = own_norm
        .iter()
        .flat_map(|x| x.sem.iter())
        .filter_map(|op| match &op.out {
            Some(crate::recompile::insn::SemArg::Mem(_, a, _)) => Some(*a),
            _ => None,
        })
        .collect();
    // the widest GENUINE read of each absolute address in this function's own bytes: a
    // dword read followed by `SAR r,0x10` is this compiler's sign-extension of the SHORT two
    // bytes above (the dword trick), not a four-byte object at that address (measured: the
    // trick's reads widened three array bases to `int`, round e28)
    let mut own_read_w: std::collections::HashMap<u64, u32> = Default::default();
    for (k, x) in own_norm.iter().enumerate() {
        // the trick's `SAR` may sit a couple of instructions after its load (scheduled)
        let trick = x.text.strip_prefix("MOV E").and_then(|r| r.split(',').next()).is_some_and(|reg| {
            let sar = format!("SAR E{reg},0x10");
            own_norm[k + 1..(k + 4).min(own_norm.len())].iter().any(|y| y.text == sar)
        });
        if trick {
            continue;
        }
        for op in &x.sem {
            for arg in &op.ins {
                if let crate::recompile::insn::SemArg::Mem(_, a, sz) = arg {
                    let e = own_read_w.entry(*a).or_insert(0);
                    *e = (*e).max(*sz);
                }
            }
        }
    }
    let mut gsizes_max: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
    for i in 0..f.num_varnodes() as u32 {
        let vn = f.vn(crate::decompile::varnode::VarnodeId(i));
        // `Processor` covers ram AND register, so select the data space by NAME — the
        // decompiler's space ids differ from the analysis Program's and must not be carried
        // across that boundary.
        if Some(vn.loc.space) != ram_dec {
            continue;
        }
        // Narrowest access wins: a byte store is what fixes the declaration, and a wider
        // access at the same address is a different (adjacent or overlapping) object.
        gsizes
            .entry(vn.loc.offset)
            .and_modify(|e| *e = (*e).min(vn.size))
            .or_insert(vn.size);
        gsizes_max
            .entry(vn.loc.offset)
            .and_modify(|e| *e = (*e).max(vn.size))
            .or_insert(vn.size);
    }
    // ARM (the `global-width` switch): the narrowest-access rule above truncates a
    // store the original makes wide whenever one function touches an address at two widths.
    // Widen back to the original's own STORE width, but only where the image also READS it
    // wider than we would store -- the wrong-code criterion, and the condition that keeps this
    // off addresses that are merely accessed at two widths.  Never narrows: `max` only.
    //
    // AND ONLY WHERE THIS FUNCTION WRITES THE ADDRESS.  Measured on the first armed emit: without
    // this the arm widened the declaration in every TU that merely READS the global, and the
    // widened type then propagated through type inference into local declarations and even
    // comparison rendering -- 138 TUs changed where only 27 had a truncated store to fix.  A
    // read-only TU has nothing to repair: its byte read of a byte it uses is already right.
    if arm_on {
        for (a, w) in gsizes.iter_mut() {
            // A READ-ONLY global this function reads at two IR widths, its own bytes reading
            // it at the wider one (`MOV BX,word ptr [g]` for the divisor, `MOV AL,[g]` for the
            // byte factor, the subject's FUN_000377a4): declared at the wider width, the narrower reads
            // print as casts of the same bytes — probed EXACT. The same-function two-width
            // gate keeps this off the 138 read-only TUs the blanket widening moved.
            if let (Some(&mx), Some(&rw)) = (gsizes_max.get(a), own_read_w.get(a)) {
                if mx > *w && rw >= mx && !gwrote.contains(a) {
                    *w = mx;
                    continue;
                }
            }
            if !gwrote.contains(a) {
                continue;
            }
            let sw = corpus.store_w.get(a).copied().unwrap_or(0);
            let rw = corpus.read_w.get(a).copied().unwrap_or(0);
            if sw > *w && rw > *w {
                *w = sw;
            }
        }
    }
    gsizes
}

/// The function's own contract: its recovered prototype, whether every parameter lives on the
/// STACK (`parm []`), the pop contract read from its own returns (`own`) and the declared cleanup
/// after the CFG-walk fallback, the merged `#pragma aux` text ([`crate::recompile::pragma::own_contract`]),
/// and the `stack_decl` the caller-side table propagates (`Some("[]")` for a callee-pops
/// stack-convention function).
pub struct OwnContract {
    pub proto: crate::decompile::fspec::FuncProto,
    pub stack_convention: bool,
    pub own: crate::recompile::OwnPopContract,
    pub cleanup: Option<u32>,
    pub contract: Option<String>,
    pub stack_decl: Option<String>,
}

pub fn own_contract(f: &Funcdata, region: &[u8], va: u64, lang: &str, regs: &WatcomRegs) -> OwnContract {
    let proto = crate::decompile::fspec::recover_func_proto(f);
    let stack_convention = (!proto.params.is_empty()
        && proto.params.iter().all(|p| {
            f.spaces.get(p.addr.space).kind == crate::decompile::space::SpaceKind::Spacebase
        }))
        || f.extra_stack_params > 0;
    // The callee's stack-cleanup contract, read from its own return instruction — and read
    // the SAME WAY THE CALLERS READ IT, which is the whole point of using `ret_pop` here.
    //
    // This used to lift the function's own byte region and scan it linearly for a `RET`. A
    // caller decides the same fact with `analysis::decompiler::callee_cleanup`, which walks
    // the callee's CFG from its entry — so for a function whose epilogue is a tail `JMP` into
    // a SHARED epilogue the two disagreed: the linear scan finds no return at all and the
    // callee-pops DEFAULT stood, while the walk follows the jump, finds the bare `RET`, and
    // the caller emits `parm caller []` plus its `ADD ESP,n`. BOTH SIDES THEN POP, and every
    // such call unbalances the stack by 4n bytes — emitted wrong code, in 55 of the 77
    // functions declaring `parm []` (152 caller TUs), unanimous per callee.
    //
    // `Funcdata::ret_pop` is that same CFG walk's answer for THIS function, already computed
    // in the decompile that just ran — so consulting it closes the disagreement at its source.
    //
    // But the walk is the FALLBACK, not the replacement, and that ordering is measured rather
    // than assumed. Reading `ret_pop` alone also flipped 8 functions the other way, and their
    // originals end in a bare `RET` while the walk had them popping: `FUN_00069980` got
    // `RET 0x4`, `FUN_0006cfd0` `RET 0x8`, `FUN_00079130` `RET 0x18`. All 8 are shared-epilogue
    // library code, where following control flow out of the function reaches a return that is
    // not this function's contract. A return in the function's OWN body is direct evidence and
    // outranks it.
    //
    // So: the function's own returns decide when it has any; the walk answers only when the
    // body is SILENT, which is exactly the tail-JMP case that produced the defect. The two
    // sides can then still differ in principle — but only where the definition has evidence the
    // caller's reading lacks, which is the direction that is safe.
    //
    // SILENT is not the same as UNDECIDED, and the difference is load-bearing.
    // `callee_stack_cleanup` answers `None` both for a body with no return at all and for one
    // whose returns DISAGREE — and a single function has a single pop-contract, so disagreement
    // is not two contracts, it is the region boundary having swallowed a neighbour's `RET`.
    // That is the same boundary error that made the walk wrong above, so it must not fall
    // through to the walk: an undecided body declares nothing and is counted, which turns a
    // silent mis-attribution into a visible one.
    let own = regs.esp_off
        .zip(crate::sleigh::disassemble(lang, &region, va).ok())
        .map(|(sp, insns)| crate::recompile::own_pop_contract(&insns, sp))
        .unwrap_or(crate::recompile::OwnPopContract::Silent);
    let cleanup = crate::recompile::declared_pop_contract(own, f.ret_pop);
    let contract = crate::recompile::pragma::own_contract(f, &regs.table, stack_convention, cleanup);
    let stack_decl = (stack_convention && !matches!(cleanup, Some(0))).then(|| "[]".to_string());
    OwnContract { proto, stack_convention, own, cleanup, contract, stack_decl }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Padding is trimmed only ABOVE the floor: a `jmp rel32` whose displacement ends in 0x00 keeps
    /// its five bytes when the floor is its end; trailing `int3` fill above the floor goes.
    #[test]
    fn padding_trim_never_cuts_below_the_last_instruction() {
        let mut region = vec![0xe9, 0x0c, 0x61, 0x01, 0x00];
        let mut end = 0x1005;
        trim_trailing_padding(&mut region, &mut end, 0x1005);
        assert_eq!((region.len(), end), (5, 0x1005), "the displacement's 0x00 is code");
        let mut region = vec![0xb0, 0x01, 0xc2, 0x04, 0x00, 0xcc, 0xcc, 0x90, 0x00];
        let mut end = 0x1009;
        trim_trailing_padding(&mut region, &mut end, 0x1005);
        assert_eq!((region.clone(), end), (vec![0xb0, 0x01, 0xc2, 0x04, 0x00], 0x1005), "fill above the floor is trimmed, the operand byte at the floor is not");
        let mut region = vec![0xc3, 0x00];
        let mut end = 0x1002;
        trim_trailing_padding(&mut region, &mut end, 0x1001);
        assert_eq!((region.len(), end), (1, 0x1001));
    }

    /// The metrics on a real decompile: every CFG block is reached by the structured tree, the
    /// call count is the live CALL/CALLIND count, a long body is no thunk.
    #[test]
    fn metrics_count_live_calls_and_reached_blocks() {
        let path = crate::paths::analysis_corpus_dir().join("basic.elf");
        let Ok(mut prog) = crate::analysis::analyze_file(&path) else { eprintln!("skip: {} absent", path.display()); return };
        prog.global_scope_all_loaded = false;
        let ents = Entries::of(&prog);
        let mut seen = 0;
        for &(va, _) in ents.list.iter().take(6) {
            let Some(f) = crate::analysis::decompiler::decompile_function(&prog, crate::decompile::space::Address::new(prog.default_space, va)) else { continue };
            let e = extent(&prog, &ents, &f, va);
            assert!(e.cov_lo >= va && e.cov_hi >= e.cov_lo && e.end <= e.end_untrimmed && e.region.len() as u64 == e.end - va);
            let m = metrics(&f, &e.region);
            assert_eq!(m.blocks_reached, m.blocks_cfg, "{va:#x}: every block reached");
            assert!(m.blocks_cfg >= 1);
            let live_calls = f.op_ids().filter(|&id| { let op = f.op(id); op.flags & (flags::DEAD | flags::MARKER) == 0 && matches!(op.code(), OpCode::Call | OpCode::Callind) }).count();
            assert_eq!(m.ir_calls, live_calls);
            seen += 1;
        }
        assert!(seen > 0, "some function decompiled");
    }

    /// The own contract on a bare `ret`: nothing to declare; with recovered stack parameters the
    /// stack convention is declared, `parm []` with the callee-pops default.
    #[test]
    fn own_contract_declares_the_stack_convention_only_when_recovered() {
        let (spec, ctx) = crate::lang::load_cached("x86:LE:32:default").expect("language tables");
        let regs = WatcomRegs::for_lang("x86:LE:32:default");
        let mut f = crate::decompile::build::raw_funcdata(spec, "f", &[0xc3], 0x1000, ctx);
        let oc = own_contract(&f, &[0xc3], 0x1000, "x86:LE:32:default", &regs);
        assert!(!oc.stack_convention && oc.contract.is_none() && oc.stack_decl.is_none());
        f.extra_stack_params = 1;
        let oc = own_contract(&f, &[0xc3], 0x1000, "x86:LE:32:default", &regs);
        assert!(oc.stack_convention);
        assert!(oc.contract.as_deref().is_some_and(|c| c.starts_with("parm")), "{:?}", oc.contract);
        assert_eq!(oc.stack_decl.is_some(), !matches!(oc.cleanup, Some(0)), "the callee-pops form propagates to callers");
    }
}
