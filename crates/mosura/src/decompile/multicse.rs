//! Ghidra `ActionMultiCse` (`coreaction.cc:822`, `apply` :879), registered in `actstackstall`
//! immediately after `ActionLaneDivide` (`coreaction.cc:5653`).
//!
//! Common-subexpression elimination over the MULTIEQUALs at the top of a basic block: two phis
//! merging the same values from the same predecessors are the same value, so one is replaced by
//! the other and destroyed. Without this pass a block keeps two distinct variables for one merge,
//! and every later stage — merging, naming, the C printer — carries the duplicate through.

use super::fasthash::FxHashSet;

use super::action::Action;
use super::block::BlockId;
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::SpaceKind;
use super::varnode::VarnodeId;

/// Ghidra `ActionMultiCse` (`coreaction.hh:163`).
pub struct ActionMultiCse;

/// Ghidra's "Allow for differences in copy propagation": read a MULTIEQUAL input through a
/// defining COPY, so two phis that differ only in whether an input was copy-propagated still
/// compare equal.
fn thru_copy(data: &Funcdata, vn: VarnodeId) -> VarnodeId {
    let v = data.vn(vn);
    if v.is_written() {
        let def = v.def.expect("is_written");
        if data.op(def).code() == OpCode::Copy {
            if let Some(in0) = data.op(def).input(0) {
                return in0;
            }
        }
    }
    vn
}

/// Ghidra `ActionMultiCse::preferredOutput` (`coreaction.cc:794`): true when `out2` should
/// survive and `out1` be replaced.
fn preferred_output(data: &Funcdata, out1: VarnodeId, out2: VarnodeId) -> bool {
    // Prefer the output that is used in a CPUI_RETURN
    if data.vn(out1).descend.iter().any(|&op| data.op(op).code() == OpCode::Return) {
        return false;
    }
    if data.vn(out2).descend.iter().any(|&op| data.op(op).code() == OpCode::Return) {
        return true;
    }
    // Prefer addrtied over register over unique. Ghidra writes this as nested ifs that both
    // `return true`; flattened to one condition here (identical semantics) because the nested
    // form is an `if_same_then_else` lint.
    !data.vn(out1).is_addrtied()
        && (data.vn(out2).is_addrtied()
            || (data.spaces.get(data.vn(out1).loc.space).kind == SpaceKind::Internal
                && data.spaces.get(data.vn(out2).loc.space).kind != SpaceKind::Internal))
}

/// Ghidra `ActionMultiCse::findMatch` (`coreaction.cc:838`): scan the block from the top for an
/// op, before `target`, whose inputs are pairwise equivalent to `target`'s.
fn find_match(data: &Funcdata, bl: BlockId, target: OpId, input: VarnodeId) -> Option<OpId> {
    let ops = data.block(bl).ops.clone();
    for op in ops {
        if op == target {
            // Caught up with target, nothing else before it
            return None;
        }
        let numinput = data.op(op).num_inputs();
        // Ghidra indexes `target->getIn(j)` with `op`'s arity. Every op the caller can reach here
        // is a COPY or a MULTIEQUAL at the top of the block, and in well-formed SSA the block's
        // phis all have the in-edge count — so in Ghidra the two arities agree wherever the loop
        // actually runs. Rust cannot read out of bounds, so state the invariant instead of
        // relying on it: a differing arity is not a redundancy.
        if numinput != data.op(target).num_inputs() {
            continue;
        }
        let touches = (0..numinput).any(|i| {
            data.op(op).input(i).map(|vn| thru_copy(data, vn)) == Some(input)
        });
        if !touches {
            continue;
        }
        let all_equal = (0..numinput).all(|j| {
            let Some(in1) = data.op(op).input(j).map(|vn| thru_copy(data, vn)) else {
                return false;
            };
            let Some(in2) = data.op(target).input(j).map(|vn| thru_copy(data, vn)) else {
                return false;
            };
            in1 == in2 || super::rules::functional_equality_level(data, in1, in2) == 0
        });
        if all_equal {
            // We have found a redundancy
            return Some(op);
        }
    }
    None
}

/// Ghidra `ActionMultiCse::processBlock` (`coreaction.cc:822`). Returns true when a redundant
/// MULTIEQUAL was eliminated, in which case the caller re-scans the block.
fn process_block(data: &mut Funcdata, bl: BlockId) -> bool {
    // Ghidra marks the varnodes it has seen with `setMark`/`clearMark` and clears them on the way
    // out. A per-call set is the same thing without the mutable varnode flag: it holds exactly the
    // inputs of the MULTIEQUALs already scanned in this block, and dies with the call.
    let mut seen: FxHashSet<VarnodeId> = FxHashSet::default();
    let mut found: Option<(OpId, OpId)> = None; // (targetop, pairop)

    for op in data.block(bl).ops.clone() {
        let opc = data.op(op).code();
        if opc == OpCode::Copy {
            continue;
        }
        if opc != OpCode::Multiequal {
            break;
        }
        let numinput = data.op(op).num_inputs();
        let mut this_op: Vec<VarnodeId> = Vec::with_capacity(numinput);
        let mut hit: Option<OpId> = None;
        for i in 0..numinput {
            let Some(raw) = data.op(op).input(i) else { continue };
            let vn = thru_copy(data, raw);
            this_op.push(vn);
            if seen.contains(&vn) {
                // If we've seen this varnode before
                if let Some(pairop) = find_match(data, bl, op, vn) {
                    hit = Some(pairop);
                    break;
                }
            }
        }
        if let Some(pairop) = hit {
            found = Some((op, pairop));
            break;
        }
        // Mark that we have seen this varnode — only once the op completed without a match, so a
        // MULTIEQUAL can never match itself on a repeated input.
        seen.extend(this_op);
    }

    let Some((targetop, pairop)) = found else { return false };
    let out1 = data.op(pairop).output;
    let out2 = data.op(targetop).output;
    let (Some(out1), Some(out2)) = (out1, out2) else { return false };
    if preferred_output(data, out1, out2) {
        // Replace pairop and out1 in favor of targetop and out2
        data.total_replace(out1, out2);
        data.op_destroy(pairop);
    } else {
        data.total_replace(out2, out1);
        data.op_destroy(targetop);
    }
    true
}

impl Action for ActionMultiCse {
    fn name(&self) -> &str {
        "multicse"
    }

    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // Ghidra's `apply` returns 0 but bumps the Action's `count` member per elimination, and
        // `Action::perform` (`action.cc`) returns THAT count to the enclosing group — so the
        // change signal that drives `actstackstall`'s restart is the elimination count, which is
        // what this returns.
        let mut count = 0;
        for b in 0..data.num_blocks() {
            let bl = BlockId(b as u32);
            while process_block(data, bl) {
                count += 1;
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::block::BlockBasic;
    use crate::decompile::op::SeqNum;
    use crate::decompile::space::{Address, SpaceManager};

    /// Two MULTIEQUALs merging the same two values from the same predecessors are one value.
    /// Ghidra eliminates the redundant one and rewrites its readers (`processBlock`,
    /// `coreaction.cc:822`).
    #[test]
    fn multicse_eliminates_a_duplicate_phi() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let s = |u: u32| SeqNum { pc: Address::new(ram, u as u64), uniq: u };

        // Two predecessors each supplying a value... (register inputs: a constant is never shared
        // between two ops — `opSetInput` clones it — so two phis of "the same" constants are not
        // the same value to `processBlock`'s identity marks, exactly as in Ghidra)
        let a = f.new_input(4, Address::new(reg, 0x20));
        let b = f.new_input(4, Address::new(reg, 0x28));
        let br0 = f.new_op(OpCode::Branch, s(0), vec![]);
        let br1 = f.new_op(OpCode::Branch, s(1), vec![]);
        // ...merged TWICE at the join, into two different outputs.
        let phi1 = f.new_op(OpCode::Multiequal, s(2), vec![a, b]);
        let v1 = f.new_output(phi1, 4, Address::new(reg, 0));
        let phi2 = f.new_op(OpCode::Multiequal, s(3), vec![a, b]);
        let v2 = f.new_output(phi2, 4, Address::new(reg, 8));
        // A reader of the second output, so the replacement is observable.
        let use2 = f.new_op(OpCode::IntAdd, s(4), vec![v2, a]);
        f.new_output(use2, 4, Address::new(reg, 16));
        let ret = f.new_op(OpCode::Return, s(5), vec![]);

        let blocks = vec![
            BlockBasic { ops: vec![br0], in_edges: vec![], out_edges: vec![BlockId(2)] },
            BlockBasic { ops: vec![br1], in_edges: vec![], out_edges: vec![BlockId(2)] },
            BlockBasic {
                ops: vec![phi1, phi2, use2, ret],
                in_edges: vec![BlockId(0), BlockId(1)],
                out_edges: vec![],
            },
        ];
        for (bi, blk) in blocks.iter().enumerate() {
            for &opid in &blk.ops {
                f.op_mut(opid).parent = Some(BlockId(bi as u32));
            }
        }
        f.set_blocks(blocks);

        let n = ActionMultiCse.apply(&mut f);
        assert_eq!(n, 1, "exactly one redundant phi eliminated");
        assert!(f.op(phi2).is_dead(), "the duplicate is destroyed");
        assert!(!f.op(phi1).is_dead(), "the survivor stays");
        assert_eq!(
            f.op(use2).input(0),
            Some(v1),
            "the reader is rewritten onto the surviving phi's output",
        );
    }
}


/// Ghidra `ActionShadowVar` (coreaction.cc:892, group `analysis`, slot :5654): eliminate a
/// MULTIEQUAL that merely *shadows* an earlier one — same inputs, same block, same branch order —
/// by making it a COPY of the earlier one's output.
///
/// The scan is Ghidra's, including the two subtleties that look like they could be simplified and
/// cannot. It walks ALL ops at the block's start address rather than stopping at the first
/// non-MULTIEQUAL, because `multi_collapse` lets other ops creep into the phi run. And it flags
/// candidates by marking the FIRST input: a repeated first input is the cheap necessary condition,
/// after which the full input-by-input comparison runs against each earlier MULTIEQUAL.
pub struct ActionShadowVar;

impl super::action::Action for ActionShadowVar {
    fn name(&self) -> &str {
        "shadowvar"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let mut oplist: Vec<OpId> = Vec::new();
        for b in 0..data.num_blocks() {
            let bl = super::block::BlockId(b as u32);
            let ops = data.block(bl).ops.clone();
            let Some(&first) = ops.first() else { continue };
            let startoffset = data.op(first).seqnum.pc.offset;
            let mut marked: Vec<VarnodeId> = Vec::new();
            for op in ops {
                // Ghidra breaks at the first op NOT at the block's start address; ops after that
                // are not part of the phi run.
                if data.op(op).seqnum.pc.offset != startoffset {
                    break;
                }
                if data.op(op).code() != OpCode::Multiequal {
                    continue; // other ops creep in via multi_collapse
                }
                let Some(vn) = data.op(op).input(0) else { continue };
                if data.vn(vn).is_mark() {
                    oplist.push(op);
                } else {
                    data.vn_mut(vn).set_mark();
                    marked.push(vn);
                }
            }
            for vn in marked {
                data.vn_mut(vn).clear_mark();
            }
        }
        let mut count = 0;
        for op in oplist {
            // Ghidra walks BACK through the block from `op` looking for a MULTIEQUAL whose inputs
            // match slot for slot — the branch order must agree, not just the set.
            let Some(bl) = data.op(op).parent else { continue };
            let ops = data.block(bl).ops.clone();
            let Some(pos) = ops.iter().position(|&o| o == op) else { continue };
            for &op2 in ops[..pos].iter().rev() {
                if data.op(op2).code() != OpCode::Multiequal {
                    continue;
                }
                if data.op(op2).num_inputs() != data.op(op).num_inputs() {
                    continue;
                }
                let same = (0..data.op(op).num_inputs())
                    .all(|i| data.op(op).input(i) == data.op(op2).input(i));
                if !same {
                    continue; // all branches did not match
                }
                let Some(out2) = data.op(op2).output else { continue };
                data.op_set_opcode(op, OpCode::Copy);
                data.op_set_all_input(op, &[out2]);
                count += 1;
                break;
            }
        }
        count
    }
}
