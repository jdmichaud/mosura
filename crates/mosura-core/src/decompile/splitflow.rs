//! Splitting artificially-joined values — a port of Ghidra's `SplitFlow` + `RuleSplitFlow`
//! (`subflow.cc:1754-2088`, declared `subflow.hh:221`/`:239`). When a wide value is built by a
//! `PIECE` that then flows through INDIRECTs/MULTIEQUALs and is read back by a high `SUBPIECE`, the
//! two halves are logically independent; `SplitFlow` traces the split through the data-flow and
//! rewrites each half as its own explicit Varnode. Built on the generic
//! [`TransformManager`](super::transform::TransformManager) base, the same one
//! [`LaneDivide`](super::lanedivide) uses.
//!
//! Unlike `LaneDivide`, this is a plain [`Rule`] (triggered on `SUBPIECE`), not tied to the
//! architecture's laned-register metadata — it fires on any `SUBPIECE`-of-`PIECE`-through-a-join.
//! The motivating case is the x86-64 double-in-XMM0 return: a `movsd` writes `XMM0_Qa` (8 bytes)
//! and zeroes `XMM0_Qb`, heritage joins them into a 16-byte `PIECE(#0, Qa)`, and the return
//! decomposition reads it back — `SplitFlow` narrows the flow to the 8-byte lane so the return is
//! built as `CONCAT44(...)` on the 8-byte value instead of a 16-byte `(xunknown8)CONCAT124`.
//!
//! Always a 2-lane (low / high) split at the `SUBPIECE`/`PIECE` boundary. Little-endian only
//! (x86-64), the same convention as [`super::transform`]/[`super::lanedivide`].

use super::action::Rule;
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::transform::{LaneDescription, TVarId, TransformManager};
use super::varnode::VarnodeId;

/// Splits an artificially-joined wide value into its two logical halves (Ghidra `SplitFlow`,
/// subflow.hh:221). Composes a [`TransformManager`] (Ghidra inherits it).
pub struct SplitFlow<'a> {
    tm: TransformManager<'a>,
    /// The two-lane (low, high) split of the root value.
    lane_description: LaneDescription,
    /// Low-lane placeholders still to be pushed through the data-flow (Ghidra's `worklist`).
    worklist: Vec<TVarId>,
}

impl<'a> SplitFlow<'a> {
    /// Start a split of `root` at byte boundary `low_size` (Ghidra ctor, subflow.cc:2011).
    pub fn new(fd: &'a mut Funcdata, root: VarnodeId, low_size: i32) -> SplitFlow<'a> {
        let whole = fd.vn(root).size as i32;
        let desc = LaneDescription::two(whole, low_size, whole - low_size);
        let mut sf = SplitFlow { tm: TransformManager::new(fd), lane_description: desc, worklist: Vec::new() };
        sf.set_replacement(root);
        sf
    }

    /// The input index at which `vn` appears in `op`, or -1 (Ghidra `PcodeOp::getSlot`).
    fn get_slot(&self, op: OpId, vn: VarnodeId) -> i32 {
        let n = self.tm.fd.op(op).num_inputs();
        for i in 0..n {
            if self.tm.fd.op(op).input(i) == Some(vn) {
                return i as i32;
            }
        }
        -1
    }

    /// Find or build the low/high placeholder pair for `vn`; `None` if it cannot be split (Ghidra
    /// `setReplacement`, subflow.cc:1754). The pair is contiguous: low = base, high = base+1.
    fn set_replacement(&mut self, vn: VarnodeId) -> Option<TVarId> {
        if self.tm.fd.vn(vn).is_mark() {
            // Already seen before.
            return Some(self.tm.get_split(vn, &self.lane_description, 2, 0));
        }
        // Ghidra rejects a typelocked value unless its type is TYPE_PARTIALSTRUCT. mosura has no
        // TypePartialStruct metatype (P4/P8 debt), so any typelock is rejected.
        if self.tm.fd.vn(vn).is_typelock() {
            return None;
        }
        if self.tm.fd.vn(vn).is_input() {
            return None; // Right now we can't split inputs.
        }
        if self.tm.fd.vn(vn).is_free() && !self.tm.fd.vn(vn).is_constant() {
            return None; // Abort.
        }
        let res = self.tm.new_split(vn, &self.lane_description, 2, 0);
        self.tm.fd.vn_mut(vn).set_mark();
        if !self.tm.fd.vn(vn).is_constant() {
            self.worklist.push(res);
        }
        Some(res)
    }

    /// Split `op` (a logical binary/COPY/INDIRECT with an output) into a low op and a high op, all
    /// inputs and the output split into their pairs (Ghidra `addOp`, subflow.cc:1787). `slot == -1`
    /// means the known param `rvn` is the output; otherwise it is input `slot`.
    fn add_op(&mut self, op: OpId, rvn: TVarId, slot: i32) -> bool {
        let outvn = if slot == -1 {
            rvn
        } else {
            let Some(out) = self.tm.fd.op(op).output else { return false };
            let Some(v) = self.set_replacement(out) else { return false };
            v
        };
        if self.tm.var(outvn).def.is_some() {
            return true; // Already traversed.
        }
        let code = self.tm.fd.op(op).code();
        let num_input = self.tm.fd.op(op).num_inputs();
        let lo_op = self.tm.new_op_replace(num_input, code, op);
        let hi_op = self.tm.new_op_replace(num_input, code, op);
        let mut num_param = num_input;
        if code == OpCode::Indirect {
            // mosura's INDIRECT is 1-input + a `guarded_op` field (Ghidra threads its iop via
            // input(1) + newIop). Carry the guarded op onto both lane INDIRECTs (as LaneDivide does).
            let guard = self.tm.fd.op(op).guarded_op();
            self.tm.op_set_guarded(lo_op, guard);
            self.tm.op_set_guarded(hi_op, guard);
            self.tm.inherit_indirect(lo_op, op);
            self.tm.inherit_indirect(hi_op, op);
            num_param = 1;
        }
        for i in 0..num_param {
            let invn = if i as i32 == slot {
                rvn
            } else {
                let Some(inp) = self.tm.fd.op(op).input(i) else { return false };
                let Some(v) = self.set_replacement(inp) else { return false };
                v
            };
            self.tm.op_set_input(lo_op, invn, i); // Low piece with low op.
            self.tm.op_set_input(hi_op, TVarId(invn.0 + 1), i); // High piece with high op.
        }
        self.tm.op_set_output(lo_op, outvn);
        self.tm.op_set_output(hi_op, TVarId(outvn.0 + 1));
        true
    }

    /// Push the split forward through every op reading `rvn`'s original (Ghidra `traceForward`,
    /// subflow.cc:1834).
    fn trace_forward(&mut self, rvn: TVarId) -> bool {
        let origvn = self.tm.var(rvn).vn.expect("worklisted var has an original");
        let descends = self.tm.fd.vn(origvn).descend.clone();
        for op in descends {
            let outvn = self.tm.fd.op(op).output;
            if let Some(o) = outvn {
                if self.tm.fd.vn(o).is_mark() {
                    continue;
                }
            }
            match self.tm.fd.op(op).code() {
                OpCode::Copy
                | OpCode::Multiequal
                | OpCode::Indirect
                | OpCode::IntAnd
                | OpCode::IntOr
                | OpCode::IntXor => {
                    let slot = self.get_slot(op, origvn);
                    if !self.add_op(op, rvn, slot) {
                        return false;
                    }
                }
                OpCode::Subpiece => {
                    let out = outvn.unwrap();
                    if self.tm.fd.vn(out).is_precis_lo() || self.tm.fd.vn(out).is_precis_hi() {
                        return false; // value comes from double-precision pieces
                    }
                    let val =
                        self.tm.fd.vn(self.tm.fd.op(op).input(1).unwrap()).constant_value() as i32;
                    let out_size = self.tm.fd.vn(out).size as i32;
                    if val == 0 && out_size == self.lane_description.size(0) {
                        let rop = self.tm.new_preexisting_op(1, OpCode::Copy, op); // grabs the low piece
                        self.tm.op_set_input(rop, rvn, 0);
                    } else if val == self.lane_description.size(0)
                        && out_size == self.lane_description.size(1)
                    {
                        let rop = self.tm.new_preexisting_op(1, OpCode::Copy, op); // grabs the high piece
                        self.tm.op_set_input(rop, TVarId(rvn.0 + 1), 0);
                    } else {
                        return false;
                    }
                }
                OpCode::IntLeft => {
                    let sh = self.tm.fd.op(op).input(1).unwrap();
                    if !self.tm.fd.vn(sh).is_constant() {
                        return false;
                    }
                    let (sh_size, sh_val) =
                        { let v = self.tm.fd.vn(sh); (v.size as i32, v.constant_value()) };
                    if (sh_val as i32) < self.lane_description.size(1) * 8 {
                        return false; // must obliterate all high bits
                    }
                    let rop = self.tm.new_preexisting_op(2, OpCode::IntLeft, op); // keep original shift
                    let zextrop = self.tm.new_op(1, OpCode::IntZext, rop);
                    self.tm.op_set_input(zextrop, rvn, 0); // input is just the low piece
                    let uq = self.tm.new_unique(self.lane_description.whole_size());
                    self.tm.op_set_output(zextrop, uq);
                    self.tm.op_set_input(rop, uq, 0);
                    let c = self.tm.new_constant(sh_size, 0, sh_val); // original shift amount
                    self.tm.op_set_input(rop, c, 1);
                }
                code @ (OpCode::IntSright | OpCode::IntRight) => {
                    let sh = self.tm.fd.op(op).input(1).unwrap();
                    if !self.tm.fd.vn(sh).is_constant() {
                        return false;
                    }
                    let (sh_size, sh_val) =
                        { let v = self.tm.fd.vn(sh); (v.size as i32, v.constant_value()) };
                    let val = sh_val as i32;
                    if val < self.lane_description.size(0) * 8 {
                        return false;
                    }
                    let ext_opcode =
                        if code == OpCode::IntRight { OpCode::IntZext } else { OpCode::IntSext };
                    if val == self.lane_description.size(0) * 8 {
                        // Shift of exactly loSize bytes: the result is an extension of the high piece.
                        let rop = self.tm.new_preexisting_op(1, ext_opcode, op);
                        self.tm.op_set_input(rop, TVarId(rvn.0 + 1), 0);
                    } else {
                        let remain_shift = (val - self.lane_description.size(0) * 8) as u64;
                        let rop = self.tm.new_preexisting_op(2, code, op);
                        let extrop = self.tm.new_op(1, ext_opcode, rop);
                        self.tm.op_set_input(extrop, TVarId(rvn.0 + 1), 0); // input is the high piece
                        let uq = self.tm.new_unique(self.lane_description.whole_size());
                        self.tm.op_set_output(extrop, uq);
                        self.tm.op_set_input(rop, uq, 0);
                        let c = self.tm.new_constant(sh_size, 0, remain_shift); // remaining bits
                        self.tm.op_set_input(rop, c, 1);
                    }
                }
                _ => return false,
            }
        }
        true
    }

    /// Pull the split back through `rvn`'s defining op (Ghidra `traceBackward`, subflow.cc:1927).
    fn trace_backward(&mut self, rvn: TVarId) -> bool {
        let origvn = self.tm.var(rvn).vn.expect("worklisted var has an original");
        let Some(op) = self.tm.fd.vn(origvn).def else {
            return true; // vn is an input
        };
        match self.tm.fd.op(op).code() {
            OpCode::Copy
            | OpCode::Multiequal
            | OpCode::IntAnd
            | OpCode::IntOr
            | OpCode::IntXor
            | OpCode::Indirect => {
                if !self.add_op(op, rvn, -1) {
                    return false;
                }
            }
            OpCode::Piece => {
                let in0 = self.tm.fd.op(op).input(0).unwrap(); // most significant
                let in1 = self.tm.fd.op(op).input(1).unwrap(); // least significant
                if self.tm.fd.vn(in0).size as i32 != self.lane_description.size(1) {
                    return false;
                }
                if self.tm.fd.vn(in1).size as i32 != self.lane_description.size(0) {
                    return false;
                }
                let lo_pre = self.tm.get_preexisting_varnode(in1);
                let lo_op = self.tm.new_op_replace(1, OpCode::Copy, op);
                self.tm.op_set_input(lo_op, lo_pre, 0);
                self.tm.op_set_output(lo_op, rvn); // least sig -> low
                let hi_pre = self.tm.get_preexisting_varnode(in0);
                let hi_op = self.tm.new_op_replace(1, OpCode::Copy, op);
                self.tm.op_set_input(hi_op, hi_pre, 0);
                self.tm.op_set_output(hi_op, TVarId(rvn.0 + 1)); // most sig -> high
            }
            OpCode::IntZext => {
                let in0 = self.tm.fd.op(op).input(0).unwrap();
                let out = self.tm.fd.op(op).output.unwrap();
                if self.tm.fd.vn(in0).size as i32 != self.lane_description.size(0) {
                    return false;
                }
                if self.tm.fd.vn(out).size as i32 != self.lane_description.whole_size() {
                    return false;
                }
                let lo_pre = self.tm.get_preexisting_varnode(in0);
                let lo_op = self.tm.new_op_replace(1, OpCode::Copy, op);
                self.tm.op_set_input(lo_op, lo_pre, 0);
                self.tm.op_set_output(lo_op, rvn); // ZEXT input -> low
                let hi_op = self.tm.new_op_replace(1, OpCode::Copy, op);
                let c = self.tm.new_constant(self.lane_description.size(1), 0, 0);
                self.tm.op_set_input(hi_op, c, 0);
                self.tm.op_set_output(hi_op, TVarId(rvn.0 + 1)); // zero -> high
            }
            OpCode::IntLeft => {
                let cvn = self.tm.fd.op(op).input(1).unwrap();
                if !self.tm.fd.vn(cvn).is_constant() {
                    return false;
                }
                if self.tm.fd.vn(cvn).constant_value() as i32 != self.lane_description.size(0) * 8 {
                    return false;
                }
                let invn0 = self.tm.fd.op(op).input(0).unwrap();
                let Some(zext_op) = self.tm.fd.vn(invn0).def else {
                    return false; // input must be written
                };
                if self.tm.fd.op(zext_op).code() != OpCode::IntZext {
                    return false;
                }
                let invn = self.tm.fd.op(zext_op).input(0).unwrap();
                if self.tm.fd.vn(invn).size as i32 != self.lane_description.size(1) {
                    return false;
                }
                if self.tm.fd.vn(invn).is_free() {
                    return false;
                }
                let lo_op = self.tm.new_op_replace(1, OpCode::Copy, op);
                let c = self.tm.new_constant(self.lane_description.size(0), 0, 0);
                self.tm.op_set_input(lo_op, c, 0);
                self.tm.op_set_output(lo_op, rvn); // zero -> low
                let hi_pre = self.tm.get_preexisting_varnode(invn);
                let hi_op = self.tm.new_op_replace(1, OpCode::Copy, op);
                self.tm.op_set_input(hi_op, hi_pre, 0);
                self.tm.op_set_output(hi_op, TVarId(rvn.0 + 1)); // invn -> high
            }
            _ => return false,
        }
        true
    }

    /// Trace the top work-list value back through its def, then forward through its uses (Ghidra
    /// `processNextWork`, subflow.cc:2000).
    fn process_next_work(&mut self) -> bool {
        let rvn = self.worklist.pop().expect("non-empty work list");
        if !self.trace_backward(rvn) {
            return false;
        }
        self.trace_forward(rvn)
    }

    /// Push the split around, building the transform (Ghidra `doTrace`, subflow.cc:2021). Returns
    /// `true` if a full transform was constructed.
    pub fn do_trace(&mut self) -> bool {
        if self.worklist.is_empty() {
            return false; // nothing to do
        }
        let mut retval = true;
        while !self.worklist.is_empty() {
            if !self.process_next_work() {
                retval = false;
                break;
            }
        }
        self.tm.clear_varnode_marks();
        retval
    }

    /// Apply the constructed split transform to the function.
    pub fn apply(&mut self) {
        self.tm.apply();
    }
}

/// Detect and split artificially-joined Varnodes (Ghidra `RuleSplitFlow`, subflow.cc:2039). Fires on
/// a `SUBPIECE` taking the high part of a value that comes from a `PIECE` reached through
/// INDIRECT(s) and/or a MULTIEQUAL — the two pieces are independent, so split their data-flows.
pub struct RuleSplitFlow;

impl Rule for RuleSplitFlow {
    fn name(&self) -> &str {
        "splitflow"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let lo_size = data.vn(data.op(op).input(1).unwrap()).constant_value() as i32;
        if lo_size == 0 {
            return 0; // SUBPIECE must not take the least significant part
        }
        let vn = data.op(op).input(0).unwrap();
        if !data.vn(vn).is_written() {
            return 0;
        }
        if data.vn(vn).is_precis_lo() || data.vn(vn).is_precis_hi() {
            return 0;
        }
        let out = data.op(op).output.unwrap();
        if data.vn(out).size as i32 + lo_size != data.vn(vn).size as i32 {
            return 0; // SUBPIECE must take the most significant part
        }
        // The PIECE may come through INDIRECT(s).
        let mut multi_op = data.vn(vn).def.unwrap();
        while data.op(multi_op).code() == OpCode::Indirect {
            let tmpvn = data.op(multi_op).input(0).unwrap();
            if !data.vn(tmpvn).is_written() {
                return 0;
            }
            multi_op = data.vn(tmpvn).def.unwrap();
        }
        let mut concat_op: Option<OpId> = None;
        if data.op(multi_op).code() == OpCode::Piece {
            // Only when the PIECE was reached through an INDIRECT (not vn's direct def).
            if data.vn(vn).def != Some(multi_op) {
                concat_op = Some(multi_op);
            }
        } else if data.op(multi_op).code() == OpCode::Multiequal {
            // Otherwise the PIECE comes through a MULTIEQUAL input.
            let n = data.op(multi_op).num_inputs();
            for i in 0..n {
                let invn = data.op(multi_op).input(i).unwrap();
                if !data.vn(invn).is_written() {
                    continue;
                }
                let tmp_op = data.vn(invn).def.unwrap();
                if data.op(tmp_op).code() == OpCode::Piece {
                    concat_op = Some(tmp_op);
                    break;
                }
            }
        }
        let Some(concat_op) = concat_op else {
            return 0; // didn't find the concatenate
        };
        if data.vn(data.op(concat_op).input(1).unwrap()).size as i32 != lo_size {
            return 0;
        }
        let mut split_flow = SplitFlow::new(data, vn, lo_size);
        if !split_flow.do_trace() {
            return 0;
        }
        split_flow.apply();
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::block::{BlockBasic, BlockId};
    use super::super::op::{OpId, SeqNum};
    use super::super::space::{Address, SpaceManager};

    /// The floatcast core: an 8-byte value zero-joined into a 16-byte register through a MULTIEQUAL,
    /// read back by a high SUBPIECE, splits into low/high 8-byte lanes — the high lane is constant
    /// zero, so the high SUBPIECE resolves to a COPY of it. Exercises RuleSplitFlow::apply_op end to
    /// end (trigger detection + SplitFlow trace through PIECE/MULTIEQUAL + the TransformManager apply).
    #[test]
    fn rule_splits_a_joined_value_read_by_a_high_subpiece() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = |u| SeqNum { pc: Address::new(ram, 0), uniq: u };
        // lo:8 = COPY src ; whole:16 = PIECE(#0:8, lo) ; phi:16 = MULTIEQUAL(whole, whole) ;
        // hi:8 = SUBPIECE(phi, #8)   — the trigger (high half of a joined value).
        let src = f.new_input(8, Address::new(ram, 0x100080));
        let copyop = f.new_op(OpCode::Copy, seq(0), vec![src]);
        let lo = f.new_output(copyop, 8, Address::new(reg, 0x1200));
        let zhi = f.new_const(8, 0);
        let piece = f.new_op(OpCode::Piece, seq(1), vec![zhi, lo]);
        let whole = f.new_output(piece, 16, Address::new(reg, 0x1200));
        let phi = f.new_op(OpCode::Multiequal, seq(2), vec![whole, whole]);
        let phivn = f.new_output(phi, 16, Address::new(reg, 0x1200));
        let eight = f.new_const(4, 8);
        let sub = f.new_op(OpCode::Subpiece, seq(3), vec![phivn, eight]);
        let hi = f.new_output(sub, 8, Address::new(reg, 0x1208));
        // Keep the high lane live so it survives (a use outside the split).
        let sink = f.new_op(OpCode::Copy, seq(4), vec![hi]);
        f.new_output(sink, 8, Address::new(reg, 0x1300));
        f.set_blocks(vec![BlockBasic { ops: vec![copyop, piece, phi, sub, sink], ..Default::default() }]);
        for op in [copyop, piece, phi, sub, sink] {
            f.op_mut(op).parent = Some(BlockId(0));
        }

        let n = RuleSplitFlow.apply_op(sub, &mut f);
        assert_eq!(n, 1, "RuleSplitFlow fires on the high SUBPIECE of the joined value");

        // The original 16-byte PIECE and MULTIEQUAL are destroyed (split into lanes).
        assert!(f.op(piece).is_dead(), "the wide PIECE is split away");
        assert!(f.op(phi).is_dead(), "the wide MULTIEQUAL is split into lanes");
        // The high SUBPIECE is rewritten in place (Ghidra newPreexistingOp) as a COPY of the high
        // 8-byte lane — the op survives, now reading an 8-byte value, not the 16-byte register.
        assert_eq!(f.op(sub).code(), OpCode::Copy, "the high SUBPIECE becomes a COPY of the high lane");
        let sub_in = f.op(sub).input(0).unwrap();
        assert_eq!(f.vn(sub_in).size, 8, "the rewritten SUBPIECE reads an 8-byte lane");
        // The sink still reads the (now 8-byte-lane-fed) result.
        let sink_in = f.op(sink).input(0).unwrap();
        assert_eq!(f.vn(sink_in).size, 8, "the sink reads an 8-byte lane, not the 16-byte register");
        // No live 16-byte register op survives the split.
        let wide = (0..f.num_ops() as u32)
            .map(OpId)
            .filter(|&o| !f.op(o).is_dead())
            .filter(|&o| f.op(o).output.map(|v| f.vn(v).size == 16).unwrap_or(false))
            .count();
        assert_eq!(wide, 0, "no 16-byte register value remains after the split");
    }
}
