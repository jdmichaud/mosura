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
    // Ghidra clears the `addrforce` attribute of any varnode that is not a direct write at the top
    // of every `ActionDeadCode::apply` (coreaction.cc:3944) — so a value forced into its storage
    // stays auto-live only if a legitimate input feeds it. mosura runs this only on the deadcode
    // immediately following an `ActionDirectWrite` pass (the flag), because its rotated pipeline has
    // extra deadcodes Ghidra lacks (see `Funcdata::directwrite_pending_clear`). Persistent effect:
    // once stripped, the varnode is no longer auto-live below.
    if f.directwrite_pending_clear {
        for i in 0..f.num_varnodes() as u32 {
            let vn = f.vn(VarnodeId(i));
            if vn.is_addr_force() && !vn.is_direct_write() {
                f.vn_mut(VarnodeId(i)).clear_addr_force();
            }
        }
        f.directwrite_pending_clear = false;
    }

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

    // The return value reaches the caller through the RETURN op (ActionReturnRecovery wired
    // it as an input), so the RETURN sink above already keeps it — no live-out register seed.

    // Persistent live-out roots: a write to a global (ram) location is a side effect visible
    // to the caller, so it is kept even when nothing in this function reads it back. This is
    // Ghidra's `persist`/addrtied liveness for global symbols. (Stack slots are in the stack
    // space after recovery, and scratch registers/uniques are not persistent.)
    if let Some(ram) = f.spaces.by_name("ram") {
        for i in 0..f.num_varnodes() as u32 {
            let vn = f.vn(VarnodeId(i));
            if vn.is_written() && vn.loc.space == ram && !live_vn[i as usize] {
                live_vn[i as usize] = true;
                worklist.push(VarnodeId(i));
            }
        }
    }

    // Auto-live roots (Ghidra `Varnode::isAutoLive` = addrforce | autolive_hold): a varnode forced
    // into its storage is exempt from removal even when nothing reads it. `Heritage::guardCalls`
    // sets addrforce on the INDIRECT that carries an aliased *mapped* stack local across a call;
    // seeding it here keeps that INDIRECT chain, and the backward consume preserves the write-only
    // spill store feeding it — the precise gate that distinguishes a real local from the
    // return-address / call-mechanism pushes (which are below the alias boundary, never guarded).
    for i in 0..f.num_varnodes() as u32 {
        let vn = f.vn(VarnodeId(i));
        if vn.is_written() && vn.is_auto_live() && !live_vn[i as usize] {
            live_vn[i as usize] = true;
            worklist.push(VarnodeId(i));
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
