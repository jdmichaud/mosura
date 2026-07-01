//! SubVariableFlow — Ghidra's `SubvariableFlow` (`subflow.cc`): shrink a big Varnode that only
//! carries a smaller logical value down to that logical size.
//!
//! Given a root Varnode and a `mask` selecting the bits of the logical sub-value, this traces the
//! flow of the logical value through the SSA graph and builds a *shadow subgraph* of placeholder
//! nodes ([`ReplaceVarnode`]/[`ReplaceOp`]) plus [`PatchRecord`]s. [`SubvariableFlow::do_trace`]
//! builds it; [`SubvariableFlow::do_replacement`] materializes it, creating narrow ops that operate
//! on the logical value and turning the wide byte-packing (`(zext(hi)<<k | zext(lo))`, `(X&k1)|(X&k2)`)
//! into explicit PIECE/CONCAT/zext — the forms whose absence blocks RuleSubZext / RulePiece2Zext /
//! RuleAndDistribute downstream.
//!
//! mosura is index-based (no raw pointers), so Ghidra's `map<Varnode*,ReplaceVarnode>` +
//! `list<ReplaceOp>` + pointer cross-links become arena `Vec`s indexed by `usize`: [`varmap`] maps a
//! traced original Varnode to its [`rvnodes`] index; [`rops`] holds the op placeholders; cross-links
//! (`def`, `output`, `input`) are `Option<usize>` indices. Constants and new outputs live in
//! `rvnodes` too but are not in `varmap` (matching Ghidra's separate `newvarlist`).
//!
//! STAGE 1 (this file): the subgraph machinery + `do_replacement`. The forward/backward tracers
//! ([`SubvariableFlow::trace_forward`] etc.) are Stage-2 stubs that return `false`, so `do_trace`
//! cannot yet succeed and no rule is wired to this subsystem — it is entirely inert (corpus-neutral)
//! until Stage 2/3.

// Stage 1 lands the subgraph machinery; the forward/backward tracers (Stage 2) and the driving
// rules (Stage 3) are the callers of createOp/createNewOut/the PatchRecord variants/etc. Until they
// land, those items are only exercised by unit tests, so the non-test build sees them as unused.
// Remove this allow when Stage 2 wires the tracers.
#![allow(dead_code)]

use std::collections::HashMap;

use super::funcdata::Funcdata;
use super::nzmask::{calc_mask, leastsigbit_set, mostsigbit_set, sign_extend_mask};
use super::op::OpId;
use super::opcode::OpCode;
use super::space::Address;
use super::varnode::VarnodeId;

/// Placeholder for a Varnode holding a smaller logical value (Ghidra `SubvariableFlow::ReplaceVarnode`).
#[derive(Clone)]
struct ReplaceVarnode {
    /// Original Varnode being shrunk (`None` for a brand-new constant or op output).
    vn: Option<VarnodeId>,
    /// The materialized narrow Varnode (filled by [`SubvariableFlow::get_replace_varnode`]).
    replacement: Option<VarnodeId>,
    /// Bits making up the logical sub-variable within `vn`.
    mask: u64,
    /// Value of the constant (when this node stands for a constant), already shifted down.
    val: u64,
    /// Defining [`ReplaceOp`] index for a new Varnode.
    def: Option<usize>,
}

/// Placeholder for a PcodeOp operating on smaller logical values (Ghidra `SubvariableFlow::ReplaceOp`).
#[derive(Clone)]
struct ReplaceOp {
    /// The original op being paralleled.
    op: OpId,
    /// The new op (filled by [`SubvariableFlow::do_replacement`]).
    replacement: Option<OpId>,
    /// Opcode of the new op.
    opc: OpCode,
    /// Number of parameters in the new op.
    numparams: i32,
    /// Output variable node index.
    output: Option<usize>,
    /// Input variable node indices.
    input: Vec<Option<usize>>,
}

/// The kinds of terminal patches on ops at the subgraph boundary (Ghidra `PatchRecord::patchtype`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PatchType {
    /// Turn op into a COPY of the logical value.
    Copy,
    /// Turn compare op inputs into logical values.
    Compare,
    /// Convert a CALL/CALLIND/RETURN/BRANCHIND parameter into the logical value.
    Parameter,
    /// Convert op into a copy/extension of the logical value, adding zero bits.
    Extension,
    /// Convert an operator output to the logical value.
    Push,
    /// Zero-extend the logical value into a FLOAT_INT2FLOAT operator.
    Int2Float,
}

/// An op patched at the subgraph boundary (Ghidra `SubvariableFlow::PatchRecord`).
#[derive(Clone)]
struct PatchRecord {
    ty: PatchType,
    patch_op: OpId,
    in1: Option<usize>,
    in2: Option<usize>,
    slot: i32,
}

/// The SubVariableFlow transform over a single logical value (Ghidra `SubvariableFlow`).
pub struct SubvariableFlow<'a> {
    fd: &'a mut Funcdata,
    /// `false` once the transform aborts (Ghidra sets `fd = NULL`).
    valid: bool,
    flowsize: u32,
    bitsize: i32,
    /// Have we tried to flow the logical value across RETURNs (Stage 4). Read only by tryReturnPull.
    #[allow(dead_code)]
    returns_traversed: bool,
    aggressive: bool,
    sextrestrictions: bool,
    varmap: HashMap<VarnodeId, usize>,
    rvnodes: Vec<ReplaceVarnode>,
    rops: Vec<ReplaceOp>,
    patchlist: Vec<PatchRecord>,
    worklist: Vec<usize>,
    pullcount: i32,
}

impl<'a> SubvariableFlow<'a> {
    /// Ghidra `SubvariableFlow::SubvariableFlow` (`subflow.cc:1372`): set up the transform for the
    /// logical value described by `mask` within `root`. `aggr` relaxes the trace tests, `sext`
    /// assumes sign-extension into the container, `big` allows 8-byte logical values.
    pub fn new(
        fd: &'a mut Funcdata,
        root: VarnodeId,
        mask: u64,
        aggr: bool,
        sext: bool,
        big: bool,
    ) -> SubvariableFlow<'a> {
        let mut s = SubvariableFlow {
            fd,
            valid: true,
            flowsize: 0,
            bitsize: 0,
            returns_traversed: false,
            aggressive: aggr,
            sextrestrictions: sext,
            varmap: HashMap::new(),
            rvnodes: Vec::new(),
            rops: Vec::new(),
            patchlist: Vec::new(),
            worklist: Vec::new(),
            pullcount: 0,
        };
        if mask == 0 {
            s.valid = false;
            return s;
        }
        s.bitsize = (mostsigbit_set(mask) - leastsigbit_set(mask)) + 1;
        if s.bitsize <= 8 {
            s.flowsize = 1;
        } else if s.bitsize <= 16 {
            s.flowsize = 2;
        } else if s.bitsize <= 24 {
            s.flowsize = 3;
        } else if s.bitsize <= 32 {
            s.flowsize = 4;
        } else if s.bitsize <= 64 {
            if !big {
                s.valid = false;
                return s;
            }
            s.flowsize = 8;
        } else {
            s.valid = false;
            return s;
        }
        s.create_link(None, mask, 0, root);
        s
    }

    /// Ghidra `SubvariableFlow::setReplacement` (`subflow.cc:66`): add `vn` (holding the logical
    /// value described by `mask`) to the subgraph, returning `Some((index, inworklist))` or `None`
    /// to abort. `inworklist` is `true` when the new node must be traced further.
    fn set_replacement(&mut self, vn: VarnodeId, mask: u64) -> Option<(usize, bool)> {
        if self.fd.vn(vn).is_mark() {
            // Already seen before.
            let idx = *self.varmap.get(&vn).unwrap();
            if self.rvnodes[idx].mask != mask {
                return None;
            }
            return Some((idx, false));
        }

        if self.fd.vn(vn).is_constant() {
            if self.sextrestrictions {
                // Check that -vn- is a sign extension of its logical size.
                let cval = self.fd.vn(vn).constant_value();
                let smallval = cval & mask;
                let sextval = sign_extend_mask(smallval, self.flowsize, self.fd.vn(vn).size);
                if sextval != cval {
                    return None;
                }
            }
            let idx = self.add_constant(None, mask, 0, vn);
            return Some((idx, false));
        }

        if self.fd.vn(vn).is_free() {
            return None; // Abort
        }

        if self.fd.vn(vn).is_addr_force() && self.fd.vn(vn).size != self.flowsize {
            return None;
        }

        if self.sextrestrictions {
            if self.fd.vn(vn).size != self.flowsize {
                if !self.aggressive && self.fd.vn(vn).is_input() {
                    return None; // Cannot assume input is sign extended
                }
                if self.fd.vn(vn).is_persist() {
                    return None;
                }
            }
            if self.fd.vn(vn).is_typelock() {
                // mosura does not model TYPE_PARTIALSTRUCT, so Ghidra's exclusion of it always holds.
                if self.fd.vn(vn).get_type().size() != self.flowsize {
                    return None;
                }
            }
        } else {
            if self.bitsize >= 8 {
                // Not a flag: don't consider multiple variables packed into one location.
                if !self.aggressive && (self.fd.vn(vn).get_consume() & !mask) != 0 {
                    // Some use of the value outside the logical variable → probably a whole variable.
                    return None;
                }
                if self.fd.vn(vn).is_typelock() && self.fd.vn(vn).get_type().size() != self.flowsize {
                    return None;
                }
            }

            if self.fd.vn(vn).is_input() {
                // Inputs must come in from the right register/memory.
                if self.bitsize < 8 {
                    return None; // Don't create input flag
                }
                if (mask & 1) == 0 {
                    return None; // Don't create unique input
                }
            }
        }

        let idx = self.rvnodes.len();
        self.rvnodes.push(ReplaceVarnode {
            vn: Some(vn),
            replacement: None,
            mask,
            val: 0,
            def: None,
        });
        self.varmap.insert(vn, idx);
        self.fd.vn_mut(vn).set_mark();
        let mut inworklist = true;
        // Check if vn already represents the logical variable being traced.
        if self.fd.vn(vn).size == self.flowsize {
            if mask == calc_mask(self.flowsize) {
                inworklist = false;
                self.rvnodes[idx].replacement = Some(vn);
            } else if mask == 1 {
                let def = self.fd.vn(vn).def;
                if self.fd.vn(vn).is_written() && self.fd.op(def.unwrap()).is_bool_output() {
                    inworklist = false;
                    self.rvnodes[idx].replacement = Some(vn);
                }
            }
        }
        Some((idx, inworklist))
    }

    /// Ghidra `SubvariableFlow::createOp` (`subflow.cc:159`): create an op placeholder given its
    /// output variable node; returns the existing def if `outrvn` already has one.
    fn create_op(&mut self, opc: OpCode, numparam: i32, outrvn: usize) -> usize {
        if let Some(d) = self.rvnodes[outrvn].def {
            return d;
        }
        let rop = self.rops.len();
        self.rvnodes[outrvn].def = Some(rop);
        self.rops.push(ReplaceOp {
            op: self.fd.vn(self.rvnodes[outrvn].vn.unwrap()).def.unwrap(),
            replacement: None,
            opc,
            numparams: numparam,
            output: Some(outrvn),
            input: Vec::new(),
        });
        rop
    }

    /// Ghidra `SubvariableFlow::createOpDown` (`subflow.cc:184`): create an op placeholder given one
    /// of its input variable nodes (the original op `op`, at input `slot`).
    fn create_op_down(&mut self, opc: OpCode, numparam: i32, op: OpId, inrvn: usize, slot: usize) -> usize {
        let rop = self.rops.len();
        let mut input: Vec<Option<usize>> = Vec::new();
        while input.len() <= slot {
            input.push(None);
        }
        input[slot] = Some(inrvn);
        self.rops.push(ReplaceOp { op, replacement: None, opc, numparams: numparam, output: None, input });
        rop
    }

    /// Ghidra `SubvariableFlow::createLink` (`subflow.cc:1022`): add `vn` (with `mask`) as a node in
    /// the subgraph and link it into op `rop` at `slot` (`-1` = output). Returns false to abort.
    fn create_link(&mut self, rop: Option<usize>, mask: u64, slot: i32, vn: VarnodeId) -> bool {
        let Some((rep, inworklist)) = self.set_replacement(vn, mask) else { return false };

        if let Some(rop) = rop {
            if slot == -1 {
                self.rops[rop].output = Some(rep);
                self.rvnodes[rep].def = Some(rop);
            } else {
                let slot = slot as usize;
                while self.rops[rop].input.len() <= slot {
                    self.rops[rop].input.push(None);
                }
                self.rops[rop].input[slot] = Some(rep);
            }
        }

        if inworklist {
            self.worklist.push(rep);
        }
        true
    }

    /// Ghidra `SubvariableFlow::addConstant` (`subflow.cc:1080`): add a constant node for `constvn`,
    /// linked into `rop` at `slot`; the stored `val` is the masked constant shifted down.
    fn add_constant(&mut self, rop: Option<usize>, mask: u64, slot: usize, constvn: VarnodeId) -> usize {
        let sa = leastsigbit_set(mask).max(0) as u32;
        let val = (mask & self.fd.vn(constvn).constant_value()) >> sa;
        let idx = self.rvnodes.len();
        self.rvnodes.push(ReplaceVarnode { vn: Some(constvn), replacement: None, mask, val, def: None });
        if let Some(rop) = rop {
            while self.rops[rop].input.len() <= slot {
                self.rops[rop].input.push(None);
            }
            self.rops[rop].input[slot] = Some(idx);
        }
        idx
    }

    /// Ghidra `SubvariableFlow::createNewOut` (`subflow.cc:1132`): create a new, non-shadowing
    /// output node for `rop` describing the logical value `mask`.
    fn create_new_out(&mut self, rop: usize, mask: u64) -> usize {
        let idx = self.rvnodes.len();
        self.rvnodes.push(ReplaceVarnode { vn: None, replacement: None, mask, val: 0, def: Some(rop) });
        self.rops[rop].output = Some(idx);
        idx
    }

    /// Ghidra `SubvariableFlow::useSameAddress` (`subflow.cc:1274`): may the logical Varnode reuse
    /// the original's storage bytes, or must it get a fresh temporary?
    fn use_same_address(&self, rvn: usize) -> bool {
        let vn = self.rvnodes[rvn].vn.unwrap();
        if self.fd.vn(vn).is_input() {
            return true;
        }
        // Trimming an addrtied Varnode risks conflicting forms for one variable through merges.
        if self.fd.vn(vn).is_addrtied() {
            return false;
        }
        if (self.rvnodes[rvn].mask & 1) == 0 {
            return false; // Not aligned
        }
        if self.bitsize >= 8 {
            return true;
        }
        if self.aggressive {
            return true;
        }
        // Decide if this is the ONLY subvariable passing through the container.
        let bitmask: u64 = (1u64 << self.bitsize) - 1;
        let mut mask = self.fd.vn(vn).get_consume();
        mask |= bitmask;
        mask == self.rvnodes[rvn].mask
    }

    /// Ghidra `SubvariableFlow::getReplacementAddress` (`subflow.cc:1297`): storage address of the
    /// narrow replacement Varnode. mosura targets are little-endian (x86-64), so the big-endian
    /// container-offset branch and `renormalize` (identity for byte-addressable spaces) are omitted.
    fn get_replacement_address(&self, rvn: usize) -> Address {
        let vn = self.rvnodes[rvn].vn.unwrap();
        let addr = self.fd.vn(vn).loc;
        let sa = (leastsigbit_set(self.rvnodes[rvn].mask).max(0) / 8) as u64; // bytes shifted into container
        Address::new(addr.space, addr.offset + sa)
    }

    /// Ghidra `SubvariableFlow::replaceInput` (`subflow.cc:1258`): swap an input Varnode for a fresh
    /// temporary input to avoid overlapping-input errors.
    fn replace_input(&mut self, rvn: usize) {
        let old = self.rvnodes[rvn].vn.unwrap();
        let sz = self.fd.vn(old).size;
        let newvn = self.fd.new_unique(sz);
        let newvn = self.fd.set_input_varnode(newvn);
        self.fd.total_replace(old, newvn);
        self.fd.delete_varnode(old);
        self.rvnodes[rvn].vn = Some(newvn);
    }

    /// Ghidra `SubvariableFlow::getReplaceVarnode` (`subflow.cc:1316`): materialize the actual narrow
    /// Varnode for a subgraph node, creating it if needed.
    fn get_replace_varnode(&mut self, rvn: usize) -> VarnodeId {
        if let Some(r) = self.rvnodes[rvn].replacement {
            return r;
        }
        if self.rvnodes[rvn].vn.is_none() {
            if self.rvnodes[rvn].def.is_none() {
                // A constant that did not come from an original Varnode.
                return self.fd.new_const(self.flowsize, self.rvnodes[rvn].val);
            }
            let u = self.fd.new_unique(self.flowsize);
            self.rvnodes[rvn].replacement = Some(u);
            return u;
        }
        let vn = self.rvnodes[rvn].vn.unwrap();
        if self.fd.vn(vn).is_constant() {
            // (Ghidra copySymbolIfValid: mosura has no per-Varnode symbol here, omitted.)
            return self.fd.new_const(self.flowsize, self.rvnodes[rvn].val);
        }

        let isinput = self.fd.vn(vn).is_input();
        if self.use_same_address(rvn) {
            let addr = self.get_replacement_address(rvn);
            if isinput {
                self.replace_input(rvn); // Replace input to avoid overlap errors
            }
            let nv = self.fd.new_varnode(self.flowsize, addr);
            self.rvnodes[rvn].replacement = Some(nv);
        } else {
            let nv = self.fd.new_unique(self.flowsize);
            self.rvnodes[rvn].replacement = Some(nv);
        }
        if isinput {
            let r = self.rvnodes[rvn].replacement.unwrap();
            let ni = self.fd.set_input_varnode(r);
            self.rvnodes[rvn].replacement = Some(ni);
        }
        self.rvnodes[rvn].replacement.unwrap()
    }

    /// Ghidra `SubvariableFlow::processNextWork` (`subflow.cc:1351`): extend the subgraph from the
    /// next worklist node by tracing one level backward then forward.
    fn process_next_work(&mut self) -> bool {
        let rvn = self.worklist.pop().unwrap();
        if self.sextrestrictions {
            if !self.trace_backward_sext(rvn) {
                return false;
            }
            return self.trace_forward_sext(rvn);
        }
        if !self.trace_backward(rvn) {
            return false;
        }
        self.trace_forward(rvn)
    }

    // --- Stage 2 tracers (stubs) ------------------------------------------------------------
    // The forward/backward opcode tracing lands in Stage 2; until then these abort the trace, so
    // `do_trace` always returns false and the subsystem makes no change.

    fn trace_forward(&mut self, _rvn: usize) -> bool {
        false
    }
    fn trace_backward(&mut self, _rvn: usize) -> bool {
        false
    }
    fn trace_forward_sext(&mut self, _rvn: usize) -> bool {
        false
    }
    fn trace_backward_sext(&mut self, _rvn: usize) -> bool {
        false
    }

    /// Ghidra `SubvariableFlow::doTrace` (`subflow.cc:1410`): trace the logical value through the
    /// data-flow, building the transform. Returns `true` if a full transform was constructed.
    /// Always clears the `mark` bits it set, whether or not it succeeded.
    pub fn do_trace(&mut self) -> bool {
        self.pullcount = 0;
        let mut retval = false;
        if self.valid {
            retval = true;
            while !self.worklist.is_empty() {
                if !self.process_next_work() {
                    retval = false;
                    break;
                }
            }
        }

        // Clear marks.
        let keys: Vec<VarnodeId> = self.varmap.keys().copied().collect();
        for vn in keys {
            self.fd.vn_mut(vn).clear_mark();
        }

        if !retval {
            return false;
        }
        if self.pullcount == 0 {
            return false;
        }
        true
    }

    /// Ghidra `SubvariableFlow::doReplacement` (`subflow.cc:1435`): materialize the discovered
    /// transform, making logical values explicit in the real SSA graph.
    pub fn do_replacement(&mut self) {
        // Up-front processing of the call-return push patches, which sit at the front of the list.
        let mut pidx = 0;
        while pidx < self.patchlist.len() && self.patchlist[pidx].ty == PatchType::Push {
            let push_op = self.patchlist[pidx].patch_op;
            let in1 = self.patchlist[pidx].in1.unwrap();
            let new_vn = self.get_replace_varnode(in1);
            let old_vn = self.fd.op(push_op).output.unwrap();
            self.fd.op_set_output(push_op, new_vn);

            // Placeholder defining op for the old Varnode, until dead code cleans it up.
            let seq = self.fd.op(push_op).seqnum;
            let new_zext = self.fd.new_op(OpCode::IntZext, seq, vec![new_vn]);
            self.fd.op_set_output(new_zext, old_vn);
            self.fd.op_insert_after(new_zext, push_op);
            pidx += 1;
        }

        // Define all the new op outputs first.
        for i in 0..self.rops.len() {
            let op_orig = self.rops[i].op;
            let opc = self.rops[i].opc;
            let seq = self.fd.op(op_orig).seqnum;
            let newop = self.fd.new_op(opc, seq, Vec::new());
            self.rops[i].replacement = Some(newop);
            let rout = self.rops[i].output.expect("subgraph op has an output");
            let out_vid = self.get_replace_varnode(rout);
            self.fd.op_set_output(newop, out_vid);
            self.fd.op_insert_after(newop, op_orig);
        }

        // Set all the new op inputs.
        for i in 0..self.rops.len() {
            let newop = self.rops[i].replacement.unwrap();
            let in_rvns = self.rops[i].input.clone();
            let mut inputs: Vec<VarnodeId> = Vec::with_capacity(in_rvns.len());
            for r in in_rvns {
                let vid = self.get_replace_varnode(r.expect("subgraph op input filled"));
                inputs.push(vid);
            }
            self.fd.op_set_all_input(newop, &inputs);
        }

        // Boundary patches carrying the small value into an existing full-size variable.
        for pi in pidx..self.patchlist.len() {
            let pullop = self.patchlist[pi].patch_op;
            match self.patchlist[pi].ty {
                PatchType::Copy => {
                    while self.fd.op(pullop).num_inputs() > 1 {
                        let last = self.fd.op(pullop).num_inputs() - 1;
                        self.fd.op_remove_input(pullop, last);
                    }
                    let v = self.get_replace_varnode(self.patchlist[pi].in1.unwrap());
                    self.fd.op_set_input(pullop, 0, v);
                    self.fd.op_set_opcode(pullop, OpCode::Copy);
                }
                PatchType::Compare => {
                    let v1 = self.get_replace_varnode(self.patchlist[pi].in1.unwrap());
                    let v2 = self.get_replace_varnode(self.patchlist[pi].in2.unwrap());
                    self.fd.op_set_input(pullop, 0, v1);
                    self.fd.op_set_input(pullop, 1, v2);
                }
                PatchType::Parameter => {
                    let v = self.get_replace_varnode(self.patchlist[pi].in1.unwrap());
                    self.fd.op_set_input(pullop, self.patchlist[pi].slot as usize, v);
                }
                PatchType::Extension => {
                    // Flow the small value into a bigger variable, with the remaining bits zero.
                    let sa = self.patchlist[pi].slot;
                    let in_vn = self.get_replace_varnode(self.patchlist[pi].in1.unwrap());
                    let out_size = self.fd.vn(self.fd.op(pullop).output.unwrap()).size;
                    if sa == 0 {
                        let opc = if self.fd.vn(in_vn).size == out_size {
                            OpCode::Copy
                        } else {
                            OpCode::IntZext
                        };
                        self.fd.op_set_opcode(pullop, opc);
                        self.fd.op_set_all_input(pullop, &[in_vn]);
                    } else {
                        let widened = if self.fd.vn(in_vn).size != out_size {
                            let seq = self.fd.op(pullop).seqnum;
                            let zextop = self.fd.new_op(OpCode::IntZext, seq, vec![in_vn]);
                            let zout = self.fd.new_output_unique(zextop, out_size);
                            self.fd.op_insert_before(zextop, pullop);
                            zout
                        } else {
                            in_vn
                        };
                        let c = self.fd.new_const(4, sa as u64);
                        self.fd.op_set_all_input(pullop, &[widened, c]);
                        self.fd.op_set_opcode(pullop, OpCode::IntLeft);
                    }
                }
                PatchType::Push => {} // Handled earlier.
                PatchType::Int2Float => {
                    let seq = self.fd.op(pullop).seqnum;
                    let invn = self.get_replace_varnode(self.patchlist[pi].in1.unwrap());
                    let zext_op = self.fd.new_op(OpCode::IntZext, seq, vec![invn]);
                    let sizeout = preferred_zext_size(self.fd.vn(invn).size);
                    let outvn = self.fd.new_output_unique(zext_op, sizeout);
                    self.fd.op_insert_before(zext_op, pullop);
                    self.fd.op_set_input(pullop, 0, outvn);
                }
            }
        }
    }
}

/// Ghidra `TypeOpFloatInt2Float::preferredZextSize` (`typeop.cc`).
fn preferred_zext_size(in_size: u32) -> u32 {
    if in_size < 4 {
        4
    } else if in_size < 8 {
        8
    } else {
        in_size + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::block::{BlockBasic, BlockId};
    use super::super::op::SeqNum;
    use super::super::space::{Address, SpaceManager};

    fn mkfd() -> (Funcdata, super::super::space::SpaceId, super::super::space::SpaceId) {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let f = Funcdata::new("t", Address::new(ram, 0), spaces);
        (f, reg, ram)
    }

    /// Set every op's parent to block 0 (the CFG normally does this; the tests build blocks by hand).
    fn parent_all_to_block0(f: &mut Funcdata) {
        let ops: Vec<OpId> = f.block(BlockId(0)).ops.clone();
        for op in ops {
            f.op_mut(op).parent = Some(BlockId(0));
        }
    }

    #[test]
    fn constructor_sizes_the_flow() {
        // Distinct roots per construction: `mark` is a per-Funcdata Varnode flag that `do_trace`
        // clears; these tests build without do_trace, so a reused marked root would collide.
        let (mut f, reg, _) = mkfd();
        // mask 0xff → 8-bit logical value → 1-byte flow.
        let x0 = f.new_input(4, Address::new(reg, 0x10));
        let s = SubvariableFlow::new(&mut f, x0, 0xff, false, false, false);
        assert!(s.valid);
        assert_eq!(s.bitsize, 8);
        assert_eq!(s.flowsize, 1);

        // mask 0xff00 → still an 8-bit span, but shifted → 1-byte flow (flowsize is set even though
        // an input with an unaligned mask isn't itself added).
        let x1 = f.new_input(4, Address::new(reg, 0x18));
        let s = SubvariableFlow::new(&mut f, x1, 0xff00, false, false, false);
        assert_eq!(s.bitsize, 8);
        assert_eq!(s.flowsize, 1);

        // mask 0xffff → 16-bit → 2-byte flow.
        let x2 = f.new_input(4, Address::new(reg, 0x1c));
        let s = SubvariableFlow::new(&mut f, x2, 0xffff, false, false, false);
        assert_eq!(s.flowsize, 2);

        // 8-byte logical value requires `big`.
        let y = f.new_input(8, Address::new(reg, 0x20));
        let s = SubvariableFlow::new(&mut f, y, u64::MAX, false, false, false);
        assert!(!s.valid); // rejected without big
        let y2 = f.new_input(8, Address::new(reg, 0x28));
        let s = SubvariableFlow::new(&mut f, y2, u64::MAX, false, false, true);
        assert!(s.valid);
        assert_eq!(s.flowsize, 8);

        // mask 0 → invalid.
        let x3 = f.new_input(4, Address::new(reg, 0x30));
        let s = SubvariableFlow::new(&mut f, x3, 0, false, false, false);
        assert!(!s.valid);
    }

    #[test]
    fn set_replacement_handles_root_constant_and_reject() {
        let (mut f, reg, _) = mkfd();
        // A 1-byte root whose full byte is the logical value: replacement == vn, not worklisted.
        let b = f.new_input(1, Address::new(reg, 0x10));
        let s = SubvariableFlow::new(&mut f, b, 0xff, false, false, false);
        assert!(s.valid);
        let idx = *s.varmap.get(&b).unwrap();
        assert_eq!(s.rvnodes[idx].replacement, Some(b)); // already the logical value
        assert!(s.worklist.is_empty()); // inworklist == false
        assert!(s.fd.vn(b).is_mark());
        drop(s);
        f.vn_mut(b).clear_mark();

        // A wide var whose consume extends beyond the mask → reject (whole-variable), returns None.
        let seq = SeqNum { pc: Address::new(f.spaces.by_name("ram").unwrap(), 0), uniq: 0 };
        let x = f.new_input(4, Address::new(reg, 0x20));
        let c = f.new_const(4, 0);
        let op = f.new_op(OpCode::IntAnd, seq, vec![x, c]);
        let out = f.new_output(op, 4, Address::new(reg, 0x28));
        f.set_blocks(vec![BlockBasic { ops: vec![op], ..Default::default() }]);
        // Give `out` consume beyond mask 0xff.
        f.vn_mut(out).consume = 0xffff;
        let mut s = SubvariableFlow::new(&mut f, out, 0xff, false, false, false);
        // The constructor's create_link → set_replacement should have rejected: invalid trace state
        // is not signalled by `valid` (only mask/size are), but the node is not added.
        assert!(s.varmap.get(&out).is_none());
        let _ = s.do_trace(); // clears marks, returns false (pullcount 0)
    }

    #[test]
    fn add_constant_shifts_value_down() {
        let (mut f, reg, _) = mkfd();
        let x = f.new_input(4, Address::new(reg, 0x10));
        let mut s = SubvariableFlow::new(&mut f, x, 0xff00, false, false, false);
        // Constant 0x3400 within mask 0xff00 → logical value 0x34.
        let c = s.fd.new_const(4, 0x3400);
        let idx = s.add_constant(None, 0xff00, 0, c);
        assert_eq!(s.rvnodes[idx].val, 0x34);
    }

    #[test]
    fn do_trace_is_inert_and_clears_marks() {
        // With Stage-2 tracers stubbed, a worklisted root can't be traced: do_trace returns false
        // and leaves no marks behind.
        let (mut f, reg, _) = mkfd();
        let seq = SeqNum { pc: Address::new(f.spaces.by_name("ram").unwrap(), 0), uniq: 0 };
        let x = f.new_input(4, Address::new(reg, 0x10));
        let c = f.new_const(4, 0xff);
        let op = f.new_op(OpCode::IntAnd, seq, vec![x, c]);
        let out = f.new_output(op, 4, Address::new(reg, 0x20));
        f.set_blocks(vec![BlockBasic { ops: vec![op], ..Default::default() }]);
        let mut s = SubvariableFlow::new(&mut f, out, 0xff, false, false, false);
        assert!(!s.worklist.is_empty()); // root worklisted for tracing
        assert!(!s.do_trace()); // stub tracer aborts
        assert!(!f.vn(out).is_mark()); // marks cleared
    }

    #[test]
    fn do_replacement_builds_narrow_ops_from_a_hand_built_subgraph() {
        // Hand-build the subgraph a trace WOULD produce for:  y = (a & 0xff) ... used narrowly.
        // `a` is a WRITTEN var (COPY output, not an input) so get_replace_varnode avoids the input
        // path. op1 pulls y out and the transform turns it into a COPY of the 1-byte value.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let inp = f.new_input(4, Address::new(reg, 0x08));
        let op_a = f.new_op(OpCode::Copy, seq, vec![inp]);
        let a = f.new_output(op_a, 4, Address::new(reg, 0x10));
        let c = f.new_const(4, 0xff);
        let op0 = f.new_op(OpCode::IntAnd, seq, vec![a, c]);
        let y = f.new_output(op0, 4, Address::new(reg, 0x20));
        let z0 = f.new_const(4, 0);
        let op1 = f.new_op(OpCode::Subpiece, seq, vec![y, z0]);
        let p = f.new_output(op1, 1, Address::new(reg, 0x28));
        let sid = f.new_const(8, ram.0 as u64);
        let ptr = f.new_input(8, Address::new(reg, 0x30));
        let store = f.new_op(OpCode::Store, seq, vec![sid, ptr, p]);
        f.set_blocks(vec![BlockBasic { ops: vec![op_a, op0, op1, store], ..Default::default() }]);
        parent_all_to_block0(&mut f);

        let mut s = SubvariableFlow::new(&mut f, y, 0xff, false, false, false);
        // Node for a's low byte, and the logical output node for y (already seeded by the ctor).
        let arvn = s.set_replacement(a, 0xff).unwrap().0;
        let yrvn = s.set_replacement(y, 0xff).unwrap().0;
        // ReplaceOp: narrow INT_AND paralleling op0, output = the logical y node.
        let rop = s.create_op(OpCode::IntAnd, 2, yrvn);
        s.rops[rop].input = vec![Some(arvn), None];
        let _ = s.add_constant(Some(rop), 0xff, 1, c);
        // copy_patch: op1 becomes a COPY of the logical y.
        s.patchlist.push(PatchRecord { ty: PatchType::Copy, patch_op: op1, in1: Some(yrvn), in2: None, slot: 0 });
        s.pullcount = 1;

        s.do_replacement();

        // op1 is now a COPY with a single 1-byte input.
        assert_eq!(f.op(op1).code(), OpCode::Copy);
        assert_eq!(f.op(op1).num_inputs(), 1);
        let cin = f.op(op1).input(0).unwrap();
        assert_eq!(f.vn(cin).size, 1);
        // A new narrow INT_AND op was created (paralleling op0) with 1-byte output.
        let new_and = (0..f.num_ops() as u32)
            .map(OpId)
            .find(|&o| !f.op(o).is_dead() && f.op(o).code() == OpCode::IntAnd && o != op0)
            .expect("narrow AND created");
        let ao = f.op(new_and).output.unwrap();
        assert_eq!(f.vn(ao).size, 1);
        // and it lives after op0 in the block.
        let ops = &f.block(BlockId(0)).ops;
        let pos0 = ops.iter().position(|&o| o == op0).unwrap();
        let posn = ops.iter().position(|&o| o == new_and).unwrap();
        assert!(posn > pos0);
    }

    #[test]
    fn do_replacement_extension_patch_zext() {
        // extension_patch with sa==0 and differing sizes → INT_ZEXT. `a` is a written (non-input)
        // var so get_replace_varnode uses the same-address (register) path.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let inp = f.new_input(4, Address::new(reg, 0x08));
        let op_a = f.new_op(OpCode::Copy, seq, vec![inp]);
        let a = f.new_output(op_a, 4, Address::new(reg, 0x10));
        let op = f.new_op(OpCode::IntZext, seq, vec![a]);
        let out = f.new_output(op, 4, Address::new(reg, 0x20));
        let sid = f.new_const(8, ram.0 as u64);
        let ptr = f.new_input(8, Address::new(reg, 0x30));
        let store = f.new_op(OpCode::Store, seq, vec![sid, ptr, out]);
        f.set_blocks(vec![BlockBasic { ops: vec![op_a, op, store], ..Default::default() }]);
        parent_all_to_block0(&mut f);

        let mut s = SubvariableFlow::new(&mut f, a, 0xff, false, false, false);
        // logical 1-byte node standing in as the small value flowing into `op`.
        let rvn = s.set_replacement(a, 0xff).unwrap().0;
        s.patchlist.push(PatchRecord { ty: PatchType::Extension, patch_op: op, in1: Some(rvn), in2: None, slot: 0 });
        s.pullcount = 1;
        s.do_replacement();
        // sa==0, input 1-byte vs output 4-byte → INT_ZEXT.
        assert_eq!(f.op(op).code(), OpCode::IntZext);
        assert_eq!(f.op(op).num_inputs(), 1);
        let zin = f.op(op).input(0).unwrap();
        assert_eq!(f.vn(zin).size, 1);
    }
}
