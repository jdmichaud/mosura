//! Laned-vector splitting — a port of Ghidra's `LaneDivide` (`subflow.cc:3518-4128`, declared
//! `subflow.hh:426`). Given a laned register Varnode (an XMM/YMM/ZMM the architecture marks with
//! `vector_lane_sizes`), trace whether the surrounding data-flow treats it as disjoint logical
//! lanes and, if so, rewrite the flow so each lane is an explicit Varnode. Built on the generic
//! [`TransformManager`](super::transform::TransformManager) base.
//!
//! Driven by `ActionLaneDivide` (task #6 S3). The stackstring fixture is the motivating case: a
//! 16-byte `movaps` store of a laned XMM splits into two 8-byte stack stores.
//!
//! Little-endian only (x86-64): Ghidra's big-endian lane reordering in build{Store,Load} is an
//! identity here (mosura's spaces are byte-addressable LE), the same convention as
//! [`super::transform`]/[`super::subvarflow`].

use super::op::OpId;
use super::opcode::OpCode;
use super::transform::{LaneDescription, TVarId, TransformManager};
use super::varnode::VarnodeId;
use super::funcdata::Funcdata;

/// A large Varnode still to be traced (Ghidra `LaneDivide::WorkNode`, subflow.hh:428).
struct WorkNode {
    /// Lane placeholders for the underlying Varnode.
    lanes: TVarId,
    /// Number of lanes in this particular Varnode.
    num_lanes: i32,
    /// Number of lanes to skip in the global description.
    skip_lanes: i32,
}

/// Splits a laned register and its data-flow into explicit lanes (Ghidra `LaneDivide`,
/// subflow.hh:426). Composes a [`TransformManager`] (Ghidra inherits it).
pub struct LaneDivide<'a> {
    tm: TransformManager<'a>,
    /// Global description of the lanes that need to be split.
    description: LaneDescription,
    /// Varnodes still left to trace.
    work_list: Vec<WorkNode>,
    /// Allow a lane to be cast (via SUBPIECE) to a smaller integer size.
    allow_subpiece_terminator: bool,
}

impl<'a> LaneDivide<'a> {
    /// Start tracing lanes from `root`, split per `desc` (Ghidra ctor, subflow.cc:4102).
    /// `allow_downcast` treats a SUBPIECE truncating below a lane as terminating.
    pub fn new(
        fd: &'a mut Funcdata,
        root: VarnodeId,
        desc: LaneDescription,
        allow_downcast: bool,
    ) -> LaneDivide<'a> {
        let num_lanes = desc.num_lanes();
        let mut ld = LaneDivide {
            tm: TransformManager::new(fd),
            description: desc,
            work_list: Vec::new(),
            allow_subpiece_terminator: allow_downcast,
        };
        ld.set_replacement(root, num_lanes, 0);
        ld
    }

    /// Find or build placeholders splitting `vn` into `num_lanes` lanes starting at `skip_lanes`;
    /// `None` if it cannot be acceptably split (Ghidra `setReplacement`, subflow.cc:3518).
    fn set_replacement(&mut self, vn: VarnodeId, num_lanes: i32, skip_lanes: i32) -> Option<TVarId> {
        if self.tm.fd.vn(vn).is_mark() {
            // Already seen before.
            return Some(self.tm.get_split(vn, &self.description, num_lanes, skip_lanes));
        }
        if self.tm.fd.vn(vn).is_constant() {
            return Some(self.tm.new_split(vn, &self.description, num_lanes, skip_lanes));
        }
        // Free varnodes are allowed to split (Ghidra's isFree() reject is commented out).
        if self.tm.fd.vn(vn).is_typelock() {
            // Don't split a typelocked non-array: a primitive/pointer (mosura metatype < Array) or a
            // struct/union (Ghidra subflow.cc:3532, `meta > TYPE_ARRAY` / STRUCT / UNION — mosura's
            // metatype ordering is reversed, so primitives are below Array=6, Struct=7).
            const ARRAY_META: u8 = 6;
            const STRUCT_META: u8 = 7;
            let meta = self.tm.fd.vn(vn).get_type().metatype();
            if meta < ARRAY_META || meta == STRUCT_META {
                return None;
            }
        }
        self.tm.fd.vn_mut(vn).set_mark();
        let res = self.tm.new_split(vn, &self.description, num_lanes, skip_lanes);
        if !self.tm.fd.vn(vn).is_free() {
            self.work_list.push(WorkNode { lanes: res, num_lanes, skip_lanes });
        }
        Some(res)
    }

    /// Build `num_lanes` unary ops of `opc` across the lanes (Ghidra `buildUnaryOp`, subflow.cc:3559).
    fn build_unary_op(&mut self, opc: OpCode, op: OpId, in_vars: TVarId, out_vars: TVarId, num_lanes: i32) {
        for i in 0..num_lanes as u32 {
            let rop = self.tm.new_op_replace(1, opc, op);
            self.tm.op_set_output(rop, TVarId(out_vars.0 + i));
            self.tm.op_set_input(rop, TVarId(in_vars.0 + i), 0);
        }
    }

    /// Build `num_lanes` binary ops of `opc` across the lanes (Ghidra `buildBinaryOp`, subflow.cc:3578).
    fn build_binary_op(
        &mut self,
        opc: OpCode,
        op: OpId,
        in0_vars: TVarId,
        in1_vars: TVarId,
        out_vars: TVarId,
        num_lanes: i32,
    ) {
        for i in 0..num_lanes as u32 {
            let rop = self.tm.new_op_replace(2, opc, op);
            self.tm.op_set_output(rop, TVarId(out_vars.0 + i));
            self.tm.op_set_input(rop, TVarId(in0_vars.0 + i), 0);
            self.tm.op_set_input(rop, TVarId(in1_vars.0 + i), 1);
        }
    }

    /// Model a CPUI_PIECE as lane COPYs (Ghidra `buildPiece`, subflow.cc:3599).
    fn build_piece(&mut self, op: OpId, out_vars: TVarId, num_lanes: i32, skip_lanes: i32) -> bool {
        let high_vn = self.tm.fd.op(op).input(0).unwrap();
        let low_vn = self.tm.fd.op(op).input(1).unwrap();
        let low_size = self.tm.fd.vn(low_vn).size as i32;
        let high_size = self.tm.fd.vn(high_vn).size as i32;
        let Some((high_lanes, high_skip)) =
            self.description.restriction(num_lanes, skip_lanes, low_size, high_size)
        else {
            return false;
        };
        let Some((low_lanes, low_skip)) =
            self.description.restriction(num_lanes, skip_lanes, 0, low_size)
        else {
            return false;
        };
        if high_lanes == 1 {
            let high_rvn = self.tm.get_preexisting_varnode(high_vn);
            let rop = self.tm.new_op_replace(1, OpCode::Copy, op);
            self.tm.op_set_input(rop, high_rvn, 0);
            self.tm.op_set_output(rop, TVarId(out_vars.0 + (num_lanes - 1) as u32));
        } else {
            let Some(high_rvn) = self.set_replacement(high_vn, high_lanes, high_skip) else {
                return false;
            };
            let out_high_start = num_lanes - high_lanes;
            for i in 0..high_lanes as u32 {
                let rop = self.tm.new_op_replace(1, OpCode::Copy, op);
                self.tm.op_set_input(rop, TVarId(high_rvn.0 + i), 0);
                self.tm.op_set_output(rop, TVarId(out_vars.0 + out_high_start as u32 + i));
            }
        }
        if low_lanes == 1 {
            let low_rvn = self.tm.get_preexisting_varnode(low_vn);
            let rop = self.tm.new_op_replace(1, OpCode::Copy, op);
            self.tm.op_set_input(rop, low_rvn, 0);
            self.tm.op_set_output(rop, out_vars);
        } else {
            let Some(low_rvn) = self.set_replacement(low_vn, low_lanes, low_skip) else {
                return false;
            };
            for i in 0..low_lanes as u32 {
                let rop = self.tm.new_op_replace(1, OpCode::Copy, op);
                self.tm.op_set_input(rop, TVarId(low_rvn.0 + i), 0);
                self.tm.op_set_output(rop, TVarId(out_vars.0 + i));
            }
        }
        true
    }

    /// Model a MULTIEQUAL as per-lane MULTIEQUALs (Ghidra `buildMultiequal`, subflow.cc:3654).
    fn build_multiequal(&mut self, op: OpId, out_vars: TVarId, num_lanes: i32, skip_lanes: i32) -> bool {
        let num_input = self.tm.fd.op(op).num_inputs();
        let mut in_var_sets: Vec<TVarId> = Vec::with_capacity(num_input);
        for i in 0..num_input {
            let inp = self.tm.fd.op(op).input(i).unwrap();
            let Some(in_vn) = self.set_replacement(inp, num_lanes, skip_lanes) else {
                return false;
            };
            in_var_sets.push(in_vn);
        }
        for i in 0..num_lanes as u32 {
            let rop = self.tm.new_op_replace(num_input, OpCode::Multiequal, op);
            self.tm.op_set_output(rop, TVarId(out_vars.0 + i));
            for (j, &set) in in_var_sets.iter().enumerate() {
                self.tm.op_set_input(rop, TVarId(set.0 + i), j);
            }
        }
        true
    }

    /// Model an INDIRECT as per-lane INDIRECTs sharing the guarded op (Ghidra `buildIndirect`,
    /// subflow.cc:3681). mosura's INDIRECT is 1-input + a `guarded_op` field (not Ghidra's iop
    /// input(1)), so each lane INDIRECT carries the original's guarded op.
    fn build_indirect(&mut self, op: OpId, out_vars: TVarId, num_lanes: i32, skip_lanes: i32) -> bool {
        let in0 = self.tm.fd.op(op).input(0).unwrap();
        let Some(in_vn) = self.set_replacement(in0, num_lanes, skip_lanes) else {
            return false;
        };
        let guard = self.tm.fd.op(op).guarded_op();
        for i in 0..num_lanes as u32 {
            let rop = self.tm.new_op_replace(1, OpCode::Indirect, op);
            self.tm.op_set_output(rop, TVarId(out_vars.0 + i));
            self.tm.op_set_input(rop, TVarId(in_vn.0 + i), 0);
            self.tm.op_set_guarded(rop, guard);
            self.tm.inherit_indirect(rop, op);
        }
        true
    }

    /// Split a STORE into per-lane STOREs, each with its own offset pointer (Ghidra `buildStore`,
    /// subflow.cc:3704). Little-endian lane order (count = lane index).
    fn build_store(&mut self, op: OpId, num_lanes: i32, skip_lanes: i32) -> bool {
        let in2 = self.tm.fd.op(op).input(2).unwrap();
        let Some(in_vars) = self.set_replacement(in2, num_lanes, skip_lanes) else {
            return false;
        };
        let in0 = self.tm.fd.op(op).input(0).unwrap();
        let space_const = self.tm.fd.vn(in0).constant_value();
        let space_const_size = self.tm.fd.vn(in0).size as i32;
        let orig_ptr = self.tm.fd.op(op).input(1).unwrap();
        if self.tm.fd.vn(orig_ptr).is_free() && !self.tm.fd.vn(orig_ptr).is_constant() {
            return false;
        }
        let base_ptr = self.tm.get_preexisting_varnode(orig_ptr);
        let ptr_size = self.tm.fd.vn(orig_ptr).size as i32;
        let mut byte_pos: i64 = 0; // smallest pointer offset (LE: least to most significant)
        for count in 0..num_lanes {
            let i = count; // little-endian
            let rop_store = self.tm.new_op_replace(3, OpCode::Store, op);
            let ptr_vn = if byte_pos == 0 {
                base_ptr
            } else {
                let ptr_vn = self.tm.new_unique(ptr_size);
                let add_op = self.tm.new_op(2, OpCode::IntAdd, rop_store);
                self.tm.op_set_output(add_op, ptr_vn);
                self.tm.op_set_input(add_op, base_ptr, 0);
                let c = self.tm.new_constant(ptr_size, 0, byte_pos as u64);
                self.tm.op_set_input(add_op, c, 1);
                ptr_vn
            };
            let sc = self.tm.new_constant(space_const_size, 0, space_const);
            self.tm.op_set_input(rop_store, sc, 0);
            self.tm.op_set_input(rop_store, ptr_vn, 1);
            self.tm.op_set_input(rop_store, TVarId(in_vars.0 + i as u32), 2);
            byte_pos += self.description.size(skip_lanes + i) as i64;
        }
        true
    }

    /// Split a LOAD into per-lane LOADs, each with its own offset pointer (Ghidra `buildLoad`,
    /// subflow.cc:3753). Little-endian lane order.
    fn build_load(&mut self, op: OpId, out_vars: TVarId, num_lanes: i32, skip_lanes: i32) -> bool {
        let in0 = self.tm.fd.op(op).input(0).unwrap();
        let space_const = self.tm.fd.vn(in0).constant_value();
        let space_const_size = self.tm.fd.vn(in0).size as i32;
        let orig_ptr = self.tm.fd.op(op).input(1).unwrap();
        if self.tm.fd.vn(orig_ptr).is_free() && !self.tm.fd.vn(orig_ptr).is_constant() {
            return false;
        }
        let base_ptr = self.tm.get_preexisting_varnode(orig_ptr);
        let ptr_size = self.tm.fd.vn(orig_ptr).size as i32;
        let mut byte_pos: i64 = 0;
        for count in 0..num_lanes {
            let rop_load = self.tm.new_op_replace(2, OpCode::Load, op);
            let i = count; // little-endian
            let ptr_vn = if byte_pos == 0 {
                base_ptr
            } else {
                let ptr_vn = self.tm.new_unique(ptr_size);
                let add_op = self.tm.new_op(2, OpCode::IntAdd, rop_load);
                self.tm.op_set_output(add_op, ptr_vn);
                self.tm.op_set_input(add_op, base_ptr, 0);
                let c = self.tm.new_constant(ptr_size, 0, byte_pos as u64);
                self.tm.op_set_input(add_op, c, 1);
                ptr_vn
            };
            let sc = self.tm.new_constant(space_const_size, 0, space_const);
            self.tm.op_set_input(rop_load, sc, 0);
            self.tm.op_set_input(rop_load, ptr_vn, 1);
            self.tm.op_set_output(rop_load, TVarId(out_vars.0 + i as u32));
            byte_pos += self.description.size(skip_lanes + i) as i64;
        }
        true
    }

    /// Model an INT_RIGHT as lane COPYs (whole-lane shift) + zero fills (Ghidra `buildRightShift`,
    /// subflow.cc:3800).
    fn build_right_shift(&mut self, op: OpId, out_vars: TVarId, num_lanes: i32, skip_lanes: i32) -> bool {
        let sh = self.tm.fd.op(op).input(1).unwrap();
        if !self.tm.fd.vn(sh).is_constant() {
            return false;
        }
        let shift_size = self.tm.fd.vn(sh).constant_value() as i32;
        if (shift_size & 7) != 0 {
            return false; // not a multiple of 8
        }
        let shift_size = shift_size / 8;
        let start_pos = shift_size + self.description.position(skip_lanes);
        let start_lane = self.description.get_boundary(start_pos);
        if start_lane < 0 {
            return false; // shift does not end on a lane boundary
        }
        let mut src_lane = start_lane;
        let mut dest_lane = skip_lanes;
        while src_lane - skip_lanes < num_lanes {
            if self.description.size(src_lane) != self.description.size(dest_lane) {
                return false;
            }
            src_lane += 1;
            dest_lane += 1;
        }
        let in0 = self.tm.fd.op(op).input(0).unwrap();
        let Some(in_vars) = self.set_replacement(in0, num_lanes, skip_lanes) else {
            return false;
        };
        self.build_unary_op(
            OpCode::Copy,
            op,
            TVarId(in_vars.0 + (start_lane - skip_lanes) as u32),
            out_vars,
            num_lanes - (start_lane - skip_lanes),
        );
        for zero_lane in (num_lanes - (start_lane - skip_lanes))..num_lanes {
            let rop = self.tm.new_op_replace(1, OpCode::Copy, op);
            self.tm.op_set_output(rop, TVarId(out_vars.0 + zero_lane as u32));
            let c = self.tm.new_constant(self.description.size(zero_lane), 0, 0);
            self.tm.op_set_input(rop, c, 0);
        }
        true
    }

    /// Model an INT_LEFT as zero fills + lane COPYs (Ghidra `buildLeftShift`, subflow.cc:3837).
    fn build_left_shift(&mut self, op: OpId, out_vars: TVarId, num_lanes: i32, skip_lanes: i32) -> bool {
        let sh = self.tm.fd.op(op).input(1).unwrap();
        if !self.tm.fd.vn(sh).is_constant() {
            return false;
        }
        let shift_size = self.tm.fd.vn(sh).constant_value() as i32;
        if (shift_size & 7) != 0 {
            return false;
        }
        let shift_size = shift_size / 8;
        let start_pos = shift_size + self.description.position(skip_lanes);
        let start_lane = self.description.get_boundary(start_pos);
        if start_lane < 0 {
            return false;
        }
        let mut dest_lane = start_lane;
        let mut src_lane = skip_lanes;
        while dest_lane - skip_lanes < num_lanes {
            if self.description.size(src_lane) != self.description.size(dest_lane) {
                return false;
            }
            src_lane += 1;
            dest_lane += 1;
        }
        let in0 = self.tm.fd.op(op).input(0).unwrap();
        let Some(in_vars) = self.set_replacement(in0, num_lanes, skip_lanes) else {
            return false;
        };
        for zero_lane in 0..(start_lane - skip_lanes) {
            let rop = self.tm.new_op_replace(1, OpCode::Copy, op);
            self.tm.op_set_output(rop, TVarId(out_vars.0 + zero_lane as u32));
            let c = self.tm.new_constant(self.description.size(zero_lane), 0, 0);
            self.tm.op_set_input(rop, c, 0);
        }
        self.build_unary_op(
            OpCode::Copy,
            op,
            in_vars,
            TVarId(out_vars.0 + (start_lane - skip_lanes) as u32),
            num_lanes - (start_lane - skip_lanes),
        );
        true
    }

    /// Model an INT_ZEXT as lane COPYs + zero fills (Ghidra `buildZext`, subflow.cc:3875).
    fn build_zext(&mut self, op: OpId, out_vars: TVarId, num_lanes: i32, skip_lanes: i32) -> bool {
        let invn = self.tm.fd.op(op).input(0).unwrap();
        let in_size = self.tm.fd.vn(invn).size as i32;
        let Some((in_lanes, in_skip)) =
            self.description.restriction(num_lanes, skip_lanes, 0, in_size)
        else {
            return false;
        };
        // in_skip should always come back equal to skip_lanes.
        if in_lanes == 1 {
            let in_var = self.tm.get_preexisting_varnode(invn);
            let rop = self.tm.new_op_replace(1, OpCode::Copy, op);
            self.tm.op_set_input(rop, in_var, 0);
            self.tm.op_set_output(rop, out_vars);
        } else {
            let Some(in_rvn) = self.set_replacement(invn, in_lanes, in_skip) else {
                return false;
            };
            for i in 0..in_lanes as u32 {
                let rop = self.tm.new_op_replace(1, OpCode::Copy, op);
                self.tm.op_set_input(rop, TVarId(in_rvn.0 + i), 0);
                self.tm.op_set_output(rop, TVarId(out_vars.0 + i));
            }
        }
        for i in 0..(num_lanes - in_lanes) as u32 {
            let rop = self.tm.new_op_replace(1, OpCode::Copy, op);
            let c = self.tm.new_constant(self.description.size(skip_lanes + in_lanes + i as i32), 0, 0);
            self.tm.op_set_input(rop, c, 0);
            self.tm.op_set_output(rop, TVarId(out_vars.0 + in_lanes as u32 + i));
        }
        true
    }

    /// Push lanes forward through every op reading `rvn` (Ghidra `traceForward`, subflow.cc:3916).
    fn trace_forward(&mut self, rvn: TVarId, num_lanes: i32, skip_lanes: i32) -> bool {
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
                OpCode::Subpiece => {
                    let byte_pos = self.tm.fd.op(op).input(1).map(|c| self.tm.fd.vn(c).constant_value() as i32).unwrap_or(0);
                    let out = outvn.unwrap();
                    let out_size = self.tm.fd.vn(out).size as i32;
                    match self.description.restriction(num_lanes, skip_lanes, byte_pos, out_size) {
                        Some((out_lanes, out_skip)) => {
                            if out_lanes == 1 {
                                let rop = self.tm.new_preexisting_op(1, OpCode::Copy, op);
                                self.tm.op_set_input(rop, TVarId(rvn.0 + (out_skip - skip_lanes) as u32), 0);
                            } else {
                                // Don't create the placeholder ops; traceBackward makes them.
                                if self.set_replacement(out, out_lanes, out_skip).is_none() {
                                    return false;
                                }
                            }
                        }
                        None => {
                            if self.allow_subpiece_terminator {
                                let lane_index = self.description.get_boundary(byte_pos);
                                if lane_index < 0 || lane_index >= self.description.num_lanes() {
                                    return false; // piece does not start on a lane boundary
                                }
                                if self.description.size(lane_index) <= out_size {
                                    return false; // piece is not smaller than a lane
                                }
                                // Treat SUBPIECE as terminating.
                                let rop = self.tm.new_preexisting_op(2, OpCode::Subpiece, op);
                                self.tm.op_set_input(rop, TVarId(rvn.0 + (lane_index - skip_lanes) as u32), 0);
                                let c = self.tm.new_constant(4, 0, 0);
                                self.tm.op_set_input(rop, c, 1);
                            } else {
                                return false;
                            }
                        }
                    }
                }
                OpCode::Piece => {
                    let out = outvn.unwrap();
                    let out_size = self.tm.fd.vn(out).size as i32;
                    let in0 = self.tm.fd.op(op).input(0).unwrap();
                    let byte_pos = if in0 == origvn {
                        self.tm.fd.vn(self.tm.fd.op(op).input(1).unwrap()).size as i32
                    } else {
                        0
                    };
                    let Some((out_lanes, out_skip)) =
                        self.description.extension(num_lanes, skip_lanes, byte_pos, out_size)
                    else {
                        return false;
                    };
                    if self.set_replacement(out, out_lanes, out_skip).is_none() {
                        return false;
                    }
                    // Don't create the placeholder ops; traceBackward makes them.
                }
                OpCode::Copy
                | OpCode::IntNegate
                | OpCode::IntAnd
                | OpCode::IntOr
                | OpCode::IntXor
                | OpCode::Multiequal
                | OpCode::Indirect => {
                    let out = outvn.unwrap();
                    if self.set_replacement(out, num_lanes, skip_lanes).is_none() {
                        return false;
                    }
                }
                OpCode::IntRight => {
                    let sh = self.tm.fd.op(op).input(1).unwrap();
                    if !self.tm.fd.vn(sh).is_constant() {
                        return false; // trace must come through input(0)
                    }
                    let out = outvn.unwrap();
                    if self.set_replacement(out, num_lanes, skip_lanes).is_none() {
                        return false;
                    }
                }
                OpCode::Store => {
                    if self.tm.fd.op(op).input(2) != Some(origvn) {
                        return false; // can only propagate through the value being stored
                    }
                    if !self.build_store(op, num_lanes, skip_lanes) {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }

    /// Pull lanes back through `rvn`'s defining op (Ghidra `traceBackward`, subflow.cc:4012).
    fn trace_backward(&mut self, rvn: TVarId, num_lanes: i32, skip_lanes: i32) -> bool {
        let origvn = self.tm.var(rvn).vn.expect("worklisted var has an original");
        let Some(op) = self.tm.fd.vn(origvn).def else {
            return true; // vn is an input
        };
        match self.tm.fd.op(op).code() {
            OpCode::IntNegate | OpCode::Copy => {
                let code = self.tm.fd.op(op).code();
                let in0 = self.tm.fd.op(op).input(0).unwrap();
                let Some(in_vars) = self.set_replacement(in0, num_lanes, skip_lanes) else {
                    return false;
                };
                self.build_unary_op(code, op, in_vars, rvn, num_lanes);
            }
            OpCode::IntAnd | OpCode::IntOr | OpCode::IntXor => {
                let code = self.tm.fd.op(op).code();
                let in0 = self.tm.fd.op(op).input(0).unwrap();
                let Some(in0_vars) = self.set_replacement(in0, num_lanes, skip_lanes) else {
                    return false;
                };
                let in1 = self.tm.fd.op(op).input(1).unwrap();
                let Some(in1_vars) = self.set_replacement(in1, num_lanes, skip_lanes) else {
                    return false;
                };
                self.build_binary_op(code, op, in0_vars, in1_vars, rvn, num_lanes);
            }
            OpCode::Multiequal => {
                if !self.build_multiequal(op, rvn, num_lanes, skip_lanes) {
                    return false;
                }
            }
            OpCode::Indirect => {
                if !self.build_indirect(op, rvn, num_lanes, skip_lanes) {
                    return false;
                }
            }
            OpCode::Subpiece => {
                let in_vn = self.tm.fd.op(op).input(0).unwrap();
                let byte_pos = self.tm.fd.vn(self.tm.fd.op(op).input(1).unwrap()).constant_value() as i32;
                let in_size = self.tm.fd.vn(in_vn).size as i32;
                let Some((in_lanes, in_skip)) =
                    self.description.extension(num_lanes, skip_lanes, byte_pos, in_size)
                else {
                    return false;
                };
                let Some(in_vars) = self.set_replacement(in_vn, in_lanes, in_skip) else {
                    return false;
                };
                self.build_unary_op(OpCode::Copy, op, TVarId(in_vars.0 + (skip_lanes - in_skip) as u32), rvn, num_lanes);
            }
            OpCode::Piece => {
                if !self.build_piece(op, rvn, num_lanes, skip_lanes) {
                    return false;
                }
            }
            OpCode::Load => {
                if !self.build_load(op, rvn, num_lanes, skip_lanes) {
                    return false;
                }
            }
            OpCode::IntRight => {
                if !self.build_right_shift(op, rvn, num_lanes, skip_lanes) {
                    return false;
                }
            }
            OpCode::IntLeft => {
                if !self.build_left_shift(op, rvn, num_lanes, skip_lanes) {
                    return false;
                }
            }
            OpCode::IntZext => {
                if !self.build_zext(op, rvn, num_lanes, skip_lanes) {
                    return false;
                }
            }
            _ => return false,
        }
        true
    }

    /// Process the top work-list Varnode: pull back through its def, push forward through its uses
    /// (Ghidra `processNextWork`, subflow.cc:4085).
    fn process_next_work(&mut self) -> bool {
        let WorkNode { lanes, num_lanes, skip_lanes } = self.work_list.pop().expect("non-empty work list");
        if !self.trace_backward(lanes, num_lanes, skip_lanes) {
            return false;
        }
        self.trace_forward(lanes, num_lanes, skip_lanes)
    }

    /// Trace lanes as far as possible from the root (Ghidra `doTrace`, subflow.cc:4112). Returns
    /// `true` if a full lane transform was constructed.
    pub fn do_trace(&mut self) -> bool {
        if self.work_list.is_empty() {
            return false; // nothing to do
        }
        let mut retval = true;
        while !self.work_list.is_empty() {
            if !self.process_next_work() {
                retval = false;
                break;
            }
        }
        self.tm.clear_varnode_marks();
        retval
    }

    /// Apply the constructed lane transform to the function (Ghidra `ActionLaneDivide` calls
    /// `laneDivide.apply()` after a successful `doTrace`, coreaction.cc:577).
    pub fn apply(&mut self) {
        self.tm.apply();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::block::{BlockBasic, BlockId};
    use super::super::op::{OpId, SeqNum};
    use super::super::space::{Address, SpaceManager};

    /// stackstring's core: a 16-byte laned XMM (`xmm = COPY src`; `STORE(ram, ptr, xmm)`) traces
    /// into two 8-byte lanes — the store splits into `STORE(ram, ptr, lo)` + `STORE(ram, ptr+8, hi)`
    /// and the COPY into two 8-byte lane COPYs. Exercises trace_backward(COPY) + trace_forward(STORE)
    /// + buildStore + the full TransformManager apply.
    #[test]
    fn traces_and_splits_a_laned_xmm_store() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        // xmm:16@reg0x1200 = COPY src:16@ram0x100250 ; STORE(ram, ptr:8@reg0x100, xmm)
        let src = f.new_input(16, Address::new(ram, 0x100250));
        let copyop = f.new_op(OpCode::Copy, seq, vec![src]);
        let xmm = f.new_output(copyop, 16, Address::new(reg, 0x1200));
        let sid = f.new_const(8, ram.0 as u64);
        let ptr = f.new_input(8, Address::new(reg, 0x100));
        let store = f.new_op(OpCode::Store, seq, vec![sid, ptr, xmm]);
        f.set_blocks(vec![BlockBasic { ops: vec![copyop, store], ..Default::default() }]);
        f.op_mut(copyop).parent = Some(BlockId(0));
        f.op_mut(store).parent = Some(BlockId(0));

        let desc = LaneDescription::uniform(16, 8);
        {
            let mut ld = LaneDivide::new(&mut f, xmm, desc, false);
            assert!(ld.do_trace(), "the laned store traces successfully");
            ld.apply();
        }

        // The original wide COPY and STORE are gone.
        assert!(f.op(copyop).is_dead());
        assert!(f.op(store).is_dead());
        // Two 8-byte STOREs remain.
        let stores: Vec<OpId> = (0..f.num_ops() as u32)
            .map(OpId)
            .filter(|&o| !f.op(o).is_dead() && f.op(o).code() == OpCode::Store)
            .collect();
        assert_eq!(stores.len(), 2, "one STORE per 8-byte lane");
        for &s in &stores {
            let val = f.op(s).input(2).unwrap();
            assert_eq!(f.vn(val).size, 8, "each lane store writes 8 bytes");
        }
        // Exactly one INT_ADD (+8) builds the high lane's pointer; the low lane uses the base ptr.
        let adds: Vec<OpId> = (0..f.num_ops() as u32)
            .map(OpId)
            .filter(|&o| !f.op(o).is_dead() && f.op(o).code() == OpCode::IntAdd)
            .collect();
        assert_eq!(adds.len(), 1, "one offset pointer for the high lane");
        let off = f.op(adds[0]).input(1).unwrap();
        assert_eq!(f.vn(off).constant_value(), 8, "high lane pointer = base + 8");
        // Two 8-byte lane COPYs replace the wide COPY.
        let copies: Vec<OpId> = (0..f.num_ops() as u32)
            .map(OpId)
            .filter(|&o| !f.op(o).is_dead() && f.op(o).code() == OpCode::Copy)
            .collect();
        assert_eq!(copies.len(), 2, "one COPY per 8-byte lane");
        for &c in &copies {
            assert_eq!(f.vn(f.op(c).output.unwrap()).size, 8);
        }
    }

    /// A downcast SUBPIECE below a lane terminates the trace only when `allow_downcast` is set
    /// (mode-1 behaviour, Ghidra subflow.cc:3934). Without it the trace fails.
    #[test]
    fn subpiece_below_lane_needs_downcast() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        // xmm:16@reg = COPY src ; u:4@reg = SUBPIECE(xmm, 0)  — a 4-byte truncation (below the 8-byte lane)
        let build = |allow: bool| -> bool {
            let mut f = Funcdata::new("t", Address::new(ram, 0), spaces.clone());
            let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
            let src = f.new_input(16, Address::new(ram, 0x100250));
            let copyop = f.new_op(OpCode::Copy, seq, vec![src]);
            let xmm = f.new_output(copyop, 16, Address::new(reg, 0x1200));
            let z = f.new_const(4, 0);
            let sub = f.new_op(OpCode::Subpiece, seq, vec![xmm, z]);
            f.new_output(sub, 4, Address::new(reg, 0x40));
            f.set_blocks(vec![BlockBasic { ops: vec![copyop, sub], ..Default::default() }]);
            f.op_mut(copyop).parent = Some(BlockId(0));
            f.op_mut(sub).parent = Some(BlockId(0));
            let desc = LaneDescription::uniform(16, 8);
            let mut ld = LaneDivide::new(&mut f, xmm, desc, allow);
            ld.do_trace()
        };
        assert!(!build(false), "a sub-lane truncation blocks the trace without downcast");
        assert!(build(true), "allow_downcast treats the truncation as terminating");
    }
}
