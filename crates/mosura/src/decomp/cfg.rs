//! Decompiler D0: `Funcdata` + control-flow graph from lifted p-code.
//!
//! Flatten a function's instructions into a single p-code op stream, then split it
//! into basic blocks (leaders at branch targets and the ops following control-flow
//! ops) and wire successor/predecessor edges — the substrate SSA (D1) builds on.
//! Mirrors Ghidra's `BlockBasic`/`Funcdata` CFG construction.

use crate::sleigh::engine::Spec;
use crate::sleigh::pcode::{PArg, PcodeOp, Varnode};
use std::collections::{BTreeSet, HashMap};

// CPUI opcodes with control-flow meaning.
const BRANCH: u32 = 4;
const CBRANCH: u32 = 5;
const BRANCHIND: u32 = 6;
const CALL: u32 = 7;
const CALLIND: u32 = 8;
const RETURN: u32 = 10;

fn is_branch(oc: u32) -> bool {
    matches!(oc, BRANCH | CBRANCH | BRANCHIND)
}
fn ends_block(oc: u32) -> bool {
    matches!(oc, BRANCH | CBRANCH | BRANCHIND | CALL | CALLIND | RETURN)
}

/// Minimal stack-variable recovery for `-O0` frames: rewrite RBP-relative memory
/// into a heritaged `stack` space. `INT_ADD(RBP, k)` marks a unique as the address
/// of stack slot `k`; LOAD/STORE through it become COPY from/to `(stack, k)`. The
/// now-dead address arithmetic and prologue/epilogue fall to dead-code elimination.
fn recover_stack(ops: &mut [FuncOp]) {
    const RBP: u64 = 0x28; // x86-64 frame pointer
    const COPY: u32 = 1;
    const LOAD: u32 = 2;
    const STORE: u32 = 3;
    const INT_ADD: u32 = 19;
    let stack_off = |ptr: &Varnode, addr: &HashMap<(String, u64), u64>| -> Option<u64> {
        if ptr.space == "register" && ptr.offset == RBP {
            Some(0)
        } else {
            addr.get(&(ptr.space.clone(), ptr.offset)).copied()
        }
    };
    let mut addr: HashMap<(String, u64), u64> = HashMap::new();
    for fo in ops.iter_mut() {
        match fo.op.opcode {
            INT_ADD => {
                let mut rbp = false;
                let mut off = None;
                for a in &fo.op.ins {
                    if let PArg::Var(v) = a {
                        if v.space == "register" && v.offset == RBP {
                            rbp = true;
                        } else if v.is_const() {
                            off = Some(v.offset);
                        }
                    }
                }
                if let (true, Some(k), Some(out)) = (rbp, off, fo.op.out.clone()) {
                    addr.insert((out.space, out.offset), k);
                    continue;
                }
            }
            LOAD => {
                if let Some(PArg::Var(ptr)) = fo.op.ins.get(1).cloned() {
                    if let Some(k) = stack_off(&ptr, &addr) {
                        let sz = fo.op.out.as_ref().map_or(0, |o| o.size);
                        fo.op.opcode = COPY;
                        fo.op.ins = vec![PArg::Var(Varnode { space: "stack".into(), offset: k, size: sz })];
                        continue;
                    }
                }
            }
            STORE => {
                if let (Some(PArg::Var(ptr)), Some(value)) = (fo.op.ins.get(1).cloned(), fo.op.ins.get(2).cloned()) {
                    if let Some(k) = stack_off(&ptr, &addr) {
                        let sz = value.as_var().map_or(0, |v| v.size);
                        fo.op.opcode = COPY;
                        fo.op.out = Some(Varnode { space: "stack".into(), offset: k, size: sz });
                        fo.op.ins = vec![value];
                        continue;
                    }
                }
            }
            _ => {}
        }
        if let Some(out) = &fo.op.out {
            addr.remove(&(out.space.clone(), out.offset));
        }
    }
}

/// Recognize calls — an x86 `CALL` lifts to `push inst_next` (`STORE` of a const)
/// then `BRANCH target`. Rewrite that `BRANCH` into a `CALL` op that defines the
/// return register (`EAX`) and reads the SysV argument registers, so the CFG falls
/// through to the return rather than inlining the callee (minimal `ActionFuncLink`).
fn recover_calls(ops: &mut [FuncOp]) {
    const STORE: u32 = 3;
    const BRANCH: u32 = 4;
    const CALL: u32 = 7;
    const CALLIND: u32 = 8;
    const ARGS: [u64; 6] = [0x38, 0x30, 0x10, 0x08, 0x80, 0x88]; // RDI,RSI,RDX,RCX,R8,R9
    // most recent definition width per register offset, so each argument register is
    // read at the width it was actually written (RDI=8 for a pointer, EDI=4 for int).
    let mut last: HashMap<u64, u32> = HashMap::new();
    let make_args = |last: &HashMap<u64, u32>| -> Vec<PArg> {
        ARGS.iter()
            .map(|&r| PArg::Var(Varnode { space: "register".into(), offset: r, size: *last.get(&r).unwrap_or(&4) }))
            .collect()
    };
    let eax = || Some(Varnode { space: "register".to_string(), offset: 0, size: 4 });
    let mut i = 0;
    while i < ops.len() {
        let addr = ops[i].addr;
        let mut j = i;
        let mut pushed_const = false;
        while j < ops.len() && ops[j].addr == addr {
            if ops[j].op.opcode == STORE {
                if let Some(PArg::Var(v)) = ops[j].op.ins.get(2) {
                    pushed_const |= v.is_const();
                }
            }
            j += 1;
        }
        if pushed_const && j > i && ops[j - 1].op.opcode == BRANCH {
            // PC-relative call (raw `.o`): rewrite the `push; BRANCH` into a CALL
            let target = ops[j - 1].op.ins.first().cloned();
            let call = &mut ops[j - 1].op;
            call.opcode = CALL;
            call.out = eax();
            call.ins = target.into_iter().chain(make_args(&last)).collect();
        } else {
            // a call that already lifted to CALL/CALLIND (resolved target) but has no
            // convention attached — inject the return + argument registers
            for k in i..j {
                if matches!(ops[k].op.opcode, CALL | CALLIND) && ops[k].op.out.is_none() {
                    let target = ops[k].op.ins.first().cloned();
                    ops[k].op.out = eax();
                    ops[k].op.ins = target.into_iter().chain(make_args(&last)).collect();
                }
            }
        }
        // record this instruction's register-def widths for later argument sizing
        for k in i..j {
            if let Some(o) = &ops[k].op.out {
                if o.space == "register" {
                    last.insert(o.offset, o.size);
                }
            }
        }
        i = j;
    }
}

/// One p-code op in a function, tagged with its instruction address.
#[derive(Debug, Clone)]
pub struct FuncOp {
    pub addr: u64,
    pub op: PcodeOp,
}

/// A basic block — a maximal straight-line run of ops `[start, end)` (global op
/// indices), with edges to other blocks.
#[derive(Debug, Default, Clone)]
pub struct Block {
    pub start: usize,
    pub end: usize,
    pub succ: Vec<usize>,
    pub pred: Vec<usize>,
}

/// A recovered `switch`: the block ending in the `BRANCHIND`, the index value, and the
/// `(case value, target block)` pairs (only cases whose target resolved to a block —
/// a target that mosura's linear disassembly mis-aligned on is dropped).
#[derive(Debug, Clone)]
pub struct SwitchInfo {
    pub block: usize,
    pub index: super::ssa::Def,
    pub cases: Vec<(u64, usize)>,
}

/// A function's flattened p-code and its control-flow graph.
pub struct Funcdata {
    pub entry: u64,
    pub ops: Vec<FuncOp>,
    pub blocks: Vec<Block>,
    /// Jump tables recovered from `BRANCHIND`s (S2) — drives switch structuring (S3).
    pub switches: Vec<SwitchInfo>,
}

/// Branch target of op `i` as an op index: a p-code-relative const, or an address.
fn branch_target(i: usize, ops: &[FuncOp], addr_index: &HashMap<u64, usize>) -> Option<usize> {
    match ops[i].op.ins.first().and_then(PArg::as_var) {
        Some(v) if v.is_const() => Some((i as i64 + v.offset as i64) as usize),
        Some(v) => addr_index.get(&v.offset).copied(),
        None => None,
    }
}

/// The static block leaders: entry, branch targets, and ops after a control-flow op.
fn static_leaders(ops: &[FuncOp], addr_index: &HashMap<u64, usize>) -> BTreeSet<usize> {
    let n = ops.len();
    let mut leaders: BTreeSet<usize> = BTreeSet::new();
    if n > 0 {
        leaders.insert(0);
    }
    for i in 0..n {
        let oc = ops[i].op.opcode;
        if is_branch(oc) {
            if let Some(t) = branch_target(i, ops, addr_index) {
                if t < n {
                    leaders.insert(t);
                }
            }
        }
        if ends_block(oc) && i + 1 < n {
            leaders.insert(i + 1);
        }
    }
    leaders
}

/// Cut blocks at `leaders` and wire successor/predecessor edges. `switch_edges` maps a
/// `BRANCHIND` op index to its recovered jump-table target op indices.
fn cut_and_wire(ops: &[FuncOp], leaders: &BTreeSet<usize>, addr_index: &HashMap<u64, usize>, switch_edges: &HashMap<usize, Vec<usize>>) -> Vec<Block> {
    let n = ops.len();
    let starts: Vec<usize> = leaders.iter().copied().collect();
    let mut blocks: Vec<Block> = Vec::new();
    let mut block_of: HashMap<usize, usize> = HashMap::new();
    for (b, &start) in starts.iter().enumerate() {
        let end = starts.get(b + 1).copied().unwrap_or(n);
        block_of.insert(start, b);
        blocks.push(Block { start, end, succ: Vec::new(), pred: Vec::new() });
    }
    for b in 0..blocks.len() {
        let (start, end) = (blocks[b].start, blocks[b].end);
        if end == start {
            continue;
        }
        let last = end - 1;
        let mut succ: Vec<usize> = Vec::new();
        match ops[last].op.opcode {
            RETURN => {}
            BRANCHIND => {
                // jump table: successors are the recovered case targets (deduped)
                for &t in switch_edges.get(&last).map(Vec::as_slice).unwrap_or(&[]) {
                    if let Some(&tb) = block_of.get(&t) {
                        if !succ.contains(&tb) {
                            succ.push(tb);
                        }
                    }
                }
            }
            BRANCH => {
                if let Some(t) = branch_target(last, ops, addr_index).and_then(|t| block_of.get(&t).copied()) {
                    succ.push(t);
                }
            }
            CBRANCH => {
                if let Some(t) = branch_target(last, ops, addr_index).and_then(|t| block_of.get(&t).copied()) {
                    succ.push(t);
                }
                if let Some(&fall) = block_of.get(&end) {
                    succ.push(fall);
                }
            }
            _ => {
                if let Some(&fall) = block_of.get(&end) {
                    succ.push(fall);
                }
            }
        }
        blocks[b].succ = succ;
    }
    for b in 0..blocks.len() {
        for s in blocks[b].succ.clone() {
            blocks[s].pred.push(b);
        }
    }
    blocks
}

impl Funcdata {
    /// Disassemble + lift `bytes`, then build the CFG.
    pub fn build(spec: &Spec, bytes: &[u8], base: u64, context: &[u32]) -> Funcdata {
        Self::build_image(spec, bytes, base, context, &[])
    }

    /// Like [`build`](Self::build), but with a view of the whole binary `image` (every
    /// `(base, bytes)` segment) so jump tables — which live in a separate segment from
    /// the code — can be recovered (S2): the `BRANCHIND` targets become block leaders
    /// and the switch edges are wired.
    pub fn build_image(spec: &Spec, bytes: &[u8], base: u64, context: &[u32], image: &super::jumptable::Image) -> Funcdata {
        // 1. Flatten all instructions' ops; remember each instruction's first op index.
        let mut ops: Vec<FuncOp> = Vec::new();
        let mut addr_index: HashMap<u64, usize> = HashMap::new();
        for insn in spec.disassemble_ctx(bytes, base, context) {
            addr_index.entry(insn.address).or_insert(ops.len());
            for op in insn.ops {
                ops.push(FuncOp { addr: insn.address, op });
            }
        }
        recover_stack(&mut ops); // model RBP-relative locals as a heritaged stack space
        recover_calls(&mut ops); // recognize `push; BRANCH` calls; model the convention

        // 2. Static block leaders (entry, branch targets, ops after a control-flow op).
        let mut leaders = static_leaders(&ops, &addr_index);
        let mut switch_edges: HashMap<usize, Vec<usize>> = HashMap::new(); // BRANCHIND op → target ops

        // 3. Recover jump tables: a scratch CFG/SSA lets the recognizer trace each
        //    BRANCHIND; the targets become extra leaders, then the blocks are re-cut.
        let has_indirect = ops.iter().any(|o| o.op.opcode == BRANCHIND);
        // (branchind op, index, [(case value, target op)]) — only cases whose target is
        // an instruction start (mosura's linear disasm may mis-align on a case that is
        // not also reached by fall-through; such a case is dropped).
        let mut raw_switches: Vec<(usize, super::ssa::Def, Vec<(u64, usize)>)> = Vec::new();
        let scratch = Funcdata { entry: base, ops: ops.clone(), blocks: cut_and_wire(&ops, &leaders, &addr_index, &switch_edges), switches: Vec::new() };
        // Only recover switches in loop-free functions: a switch inside a loop produces
        // cyclic case bodies the structurer can't yet handle, and wiring its edges would
        // only break the (partial) loop decompilation. Such functions keep their old CFG.
        if !image.is_empty() && has_indirect && !scratch.has_back_edge() {
            let ssa = scratch.ssa(&[]);
            for (i, o) in ops.iter().enumerate() {
                if o.op.opcode == BRANCHIND {
                    if let Some(jt) = super::jumptable::recover(&scratch, &ssa, image, i) {
                        let valid: Vec<(u64, usize)> =
                            jt.targets.iter().enumerate().filter_map(|(c, a)| addr_index.get(a).map(|&oi| (c as u64, oi))).collect();
                        let distinct: BTreeSet<usize> = valid.iter().map(|&(_, oi)| oi).collect();
                        if distinct.len() >= 2 {
                            for &t in &distinct {
                                leaders.insert(t);
                            }
                            switch_edges.insert(i, distinct.into_iter().collect());
                            raw_switches.push((i, jt.index, valid));
                        }
                    }
                }
            }
        }

        // 4. Cut blocks (with any jump-table targets as leaders) and wire all edges.
        let blocks = cut_and_wire(&ops, &leaders, &addr_index, &switch_edges);

        // 5. Resolve each recovered switch's ops → block ids.
        let block_of_op = |oi: usize| blocks.iter().position(|b| oi >= b.start && oi < b.end);
        let switches: Vec<SwitchInfo> = raw_switches
            .into_iter()
            .filter_map(|(branchind, index, valid)| {
                let block = block_of_op(branchind)?;
                let cases: Vec<(u64, usize)> = valid.iter().filter_map(|&(cv, oi)| block_of_op(oi).map(|b| (cv, b))).collect();
                Some(SwitchInfo { block, index, cases })
            })
            .collect();

        Funcdata { entry: base, ops, blocks, switches }
    }

    /// A block has a back-edge if any successor begins at or before it (a loop).
    pub fn has_back_edge(&self) -> bool {
        self.blocks.iter().enumerate().any(|(b, blk)| blk.succ.iter().any(|&s| s <= b))
    }
}
