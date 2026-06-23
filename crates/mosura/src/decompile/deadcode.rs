//! Dead-code elimination — Ghidra's `ActionDeadCode` (`coreaction.cc`).
//!
//! Liveness is seeded from side-effecting ops (returns, branches, stores, calls all
//! consume their inputs) and propagated backward: a consumed varnode keeps its defining
//! op, whose inputs are in turn consumed. Ops that are never reached — dead computations,
//! and the ops the rule pool collapsed — are removed.
//!
//! Ghidra tracks *which bits* are consumed (so an op computing only unused bits can go);
//! this is the whole-varnode core (consume = all-or-nothing). The consume-bits refinement
//! and addrtied/persistent live-out roots are later additions.

use super::block::BlockId;
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::varnode::VarnodeId;

/// Does this op have a side effect that makes it (and its inputs) live regardless of
/// whether its output is used?
fn is_sink(code: OpCode) -> bool {
    use OpCode::*;
    matches!(
        code,
        Return | Branch | Cbranch | Branchind | Store | Call | Callind | Callother
    )
}

/// Remove ops whose results are never consumed.
pub fn dead_code(f: &mut Funcdata) {
    let n_ops = f.num_ops();
    let mut live_op = vec![false; n_ops];
    let mut live_vn = vec![false; f.num_varnodes()];
    let mut worklist: Vec<VarnodeId> = Vec::new();

    // seed: side-effecting ops are live and consume all their inputs
    for i in 0..n_ops as u32 {
        let op = OpId(i);
        if is_sink(f.op(op).code()) {
            live_op[i as usize] = true;
            for &v in &f.op(op).inrefs {
                if !live_vn[v.0 as usize] {
                    live_vn[v.0 as usize] = true;
                    worklist.push(v);
                }
            }
        }
    }

    // Interim live-out roots: a function's return value reaches the caller in a
    // return-convention register, but it is not yet wired as an input to RETURN (that is
    // ActionReturnRecovery, P6). Until then, treat the SysV return registers — RAX (0x0)
    // and XMM0 (0x1200) — as consumed at exit so the return computation is kept. (This is
    // x86-specific and over-keeps intermediate writes; P6 / addrtied liveness replaces it.)
    if let Some(reg) = f.spaces.by_name("register") {
        for i in 0..f.num_varnodes() as u32 {
            let vn = f.vn(VarnodeId(i));
            if vn.is_written() && vn.loc.space == reg && matches!(vn.loc.offset, 0x0 | 0x1200) {
                if !live_vn[i as usize] {
                    live_vn[i as usize] = true;
                    worklist.push(VarnodeId(i));
                }
            }
        }
    }

    // propagate backward: a consumed varnode keeps its def op, whose inputs are consumed
    while let Some(vn) = worklist.pop() {
        let Some(def) = f.vn(vn).def else { continue };
        if live_op[def.0 as usize] {
            continue;
        }
        live_op[def.0 as usize] = true;
        for &v in &f.op(def).inrefs {
            if !live_vn[v.0 as usize] {
                live_vn[v.0 as usize] = true;
                worklist.push(v);
            }
        }
    }

    // remove the dead ops from their blocks and detach them from the graph
    for b in 0..f.num_blocks() as u32 {
        let blk = BlockId(b);
        let (kept, dead): (Vec<OpId>, Vec<OpId>) =
            f.block(blk).ops.iter().partition(|&&op| live_op[op.0 as usize]);
        f.set_block_ops(blk, kept);
        for op in dead {
            f.op_destroy(op);
        }
    }
}

/// The pipeline action wrapper (Ghidra's `ActionDeadCode`).
pub struct ActionDeadCode;

impl super::action::Action for ActionDeadCode {
    fn name(&self) -> &str {
        "deadcode"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let before = (0..data.num_ops() as u32).filter(|&i| !data.op(OpId(i)).is_dead()).count();
        dead_code(data);
        let after = (0..data.num_ops() as u32).filter(|&i| !data.op(OpId(i)).is_dead()).count();
        (before - after) as u32
    }
}
