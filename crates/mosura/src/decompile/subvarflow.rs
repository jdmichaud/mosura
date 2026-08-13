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
//! [`SubvariableFlow::trace_forward`] and [`SubvariableFlow::trace_backward`] now cover EVERY opcode
//! arm of Ghidra's `traceForward`/`traceBackward` (`subflow.cc:373`/`665`). They did not always: the
//! arithmetic arms (INT_ADD/MULT/DIV/REM), the comparisons, the boolean/CBRANCH edges, and the
//! BRANCHIND/FLOAT_INT2FLOAT/call-return pulls were once left to the `default` abort, and that gap —
//! not the type model — is what pinned mosura's 1-byte values at 4 bytes.
//!
//! The sign-extension tracers ([`SubvariableFlow::trace_forward_sext`]/
//! [`SubvariableFlow::trace_backward_sext`]) and their driving `RuleSubvarSext` are ported and
//! registered too, so the subsystem is complete. The one thing Ghidra has here that mosura does not
//! is `Varnode::isPtrFlow`, which supplies `RuleSubvarZext`'s `aggressive` argument — and that is a
//! verified equivalence, not a gap: the rule that sets the flag has an empty oplist on any target
//! whose data space is not truncated, which is every x86 target. The certificate, with the condition
//! that would revive it, is on the SubVariableFlow rule block in `rules.rs`.

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
    /// Number of parameters in the new op. Ghidra pre-sizes `newOp` with this (`subflow.cc:1459`);
    /// mosura's `do_replacement` instead sets inputs from [`input`](Self::input), so it is only kept
    /// for parity with Ghidra's `ReplaceOp`.
    #[allow(dead_code)]
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
    /// Zero-extend the logical value into a FLOAT_INT2FLOAT operator. Produced only by the deferred
    /// `tryInt2FloatPull` (Stage 4); `do_replacement` already handles it.
    #[allow(dead_code)]
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
        subvar_debug(&format!(
            "SUBVAR seed root={} mask={mask:#x} bitsize={} flowsize={} aggr={aggr} sext={sext} big={big}",
            s.fd.vn_str(root),
            s.bitsize,
            s.flowsize,
        ));
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
        subvar_debug_node(self.fd, "work", rvn, &self.rvnodes);
        if self.sextrestrictions {
            if !self.trace_backward_sext(rvn) {
                subvar_debug("  ABORT trace_backward_sext (unported stage-4 stub)");
                return false;
            }
            let ok = self.trace_forward_sext(rvn);
            if !ok {
                subvar_debug("  ABORT trace_forward_sext (unported stage-4 stub)");
            }
            return ok;
        }
        if !self.trace_backward(rvn) {
            subvar_debug("  ABORT in trace_backward");
            return false;
        }
        let ok = self.trace_forward(rvn);
        if !ok {
            subvar_debug("  ABORT in trace_forward");
        }
        ok
    }

    // --- Stage 2 helpers used by the tracers -----------------------------------------------

    /// Ghidra `SubvariableFlow::doesOrSet` (`subflow.cc:26`): slot of the constant if the INT_OR
    /// sets all bits in `mask`, else -1.
    fn does_or_set(&self, orop: OpId, mask: u64) -> i32 {
        let in1 = self.fd.op(orop).input(1).unwrap();
        let index: i32 = if self.fd.vn(in1).is_constant() { 1 } else { 0 };
        let inx = self.fd.op(orop).input(index as usize).unwrap();
        if !self.fd.vn(inx).is_constant() {
            return -1;
        }
        let orval = self.fd.vn(inx).constant_value();
        if (mask & !orval) == 0 {
            return index;
        }
        -1
    }

    /// Ghidra `SubvariableFlow::doesAndClear` (`subflow.cc:43`): slot of the constant if the INT_AND
    /// clears all bits in `mask`, else -1.
    fn does_and_clear(&self, andop: OpId, mask: u64) -> i32 {
        let in1 = self.fd.op(andop).input(1).unwrap();
        let index: i32 = if self.fd.vn(in1).is_constant() { 1 } else { 0 };
        let inx = self.fd.op(andop).input(index as usize).unwrap();
        if !self.fd.vn(inx).is_constant() {
            return -1;
        }
        let andval = self.fd.vn(inx).constant_value();
        if (mask & andval) == 0 {
            return index;
        }
        -1
    }

    /// Ghidra `SubvariableFlow::addNewConstant` (`subflow.cc:1108`): a fresh constant node (not tied
    /// to any original Varnode) as input `slot` of `rop`.
    fn add_new_constant(&mut self, rop: Option<usize>, slot: usize, val: u64) -> usize {
        let idx = self.rvnodes.len();
        self.rvnodes.push(ReplaceVarnode { vn: None, replacement: None, mask: 0, val, def: None });
        if let Some(rop) = rop {
            while self.rops[rop].input.len() <= slot {
                self.rops[rop].input.push(None);
            }
            self.rops[rop].input[slot] = Some(idx);
        }
        idx
    }

    /// Ghidra `SubvariableFlow::addPush` (`subflow.cc:1151`): mark an op that produces (but does not
    /// manipulate) the logical value. Pushed to the *front* of the patch list.
    fn add_push(&mut self, push_op: OpId, rvn: usize) {
        self.patchlist.insert(
            0,
            PatchRecord { ty: PatchType::Push, patch_op: push_op, in1: Some(rvn), in2: None, slot: 0 },
        );
    }

    /// Ghidra `SubvariableFlow::addTerminalPatch` (`subflow.cc:1167`): op naturally copies the logical
    /// value out; it becomes a COPY. A true terminal modification.
    fn add_terminal_patch(&mut self, pullop: OpId, rvn: usize) {
        self.patchlist.push(PatchRecord { ty: PatchType::Copy, patch_op: pullop, in1: Some(rvn), in2: None, slot: 0 });
        self.pullcount += 1;
    }

    /// Ghidra `SubvariableFlow::addTerminalPatchSameOp` (`subflow.cc:1185`): op naturally pulls the
    /// logical value; the opcode stays, only input `slot` changes. A true terminal modification.
    fn add_terminal_patch_same_op(&mut self, pullop: OpId, rvn: usize, slot: i32) {
        self.patchlist.push(PatchRecord { ty: PatchType::Parameter, patch_op: pullop, in1: Some(rvn), in2: None, slot });
        self.pullcount += 1;
    }

    /// Ghidra `SubvariableFlow::tryReturnPull` (`subflow.cc:238`): the logical value flows into a
    /// RETURN. If the return value isn't output-locked, add a parameter patch letting the RETURN take
    /// the smaller logical value — first propagating the logical size to every other RETURN so the
    /// function keeps a single return type. mosura adaptations: `FuncProto` has no output-lock model,
    /// so the `isOutputLocked` gate (subflow.cc:242) is always false here and is omitted; and there is
    /// no halt-type model, so every RETURN is treated as real (Ghidra skips artificial halts).
    fn try_return_pull(&mut self, op: OpId, rvn: usize, slot: usize) -> bool {
        if slot == 0 {
            return false; // slot 0 is the return-address container, not a value
        }
        let mask = self.rvnodes[rvn].mask;
        if !self.aggressive {
            let vn = self.rvnodes[rvn].vn.expect("real varnode");
            if (self.fd.vn(vn).get_consume() & !mask) != 0 {
                return false; // something outside the mask is consumed — don't truncate
            }
        }
        if !self.returns_traversed {
            // Truncating a return means every RETURN must carry the same logical size, so there is a
            // single return value type. Propagate the replacement to each RETURN's value in this slot.
            let rets: Vec<OpId> =
                self.fd.op_ids().filter(|&o| self.fd.op(o).code() == OpCode::Return).collect();
            for retop in rets {
                let Some(retvn) = self.fd.op(retop).input(slot) else {
                    continue; // this RETURN carries no value in this slot
                };
                let is_const = self.fd.vn(retvn).is_constant();
                let Some((rep, inworklist)) = self.set_replacement(retvn, mask) else {
                    return false;
                };
                if inworklist {
                    self.worklist.push(rep);
                } else if is_const && retop != op {
                    // The trace won't revisit this RETURN, so generate its patch now.
                    self.add_terminal_patch_same_op(retop, rep, slot as i32);
                }
            }
            self.returns_traversed = true;
        }
        self.add_terminal_patch_same_op(op, rvn, slot as i32);
        true
    }

    /// Ghidra `SubvariableFlow::tryCallPull` (`subflow.cc:208`): the logical value flows into a CALL/
    /// CALLIND as an input parameter. If the call's params aren't in active recovery, add a parameter
    /// patch letting the CALL take the smaller logical value. mosura adaptations: `getCallSpecs()==null`
    /// (subflow.cc:216) cannot hold for a CALL/CALLIND op — only CALLOTHER (`isCallWithoutSpec`, a
    /// different opcode) lacks a spec — and mosura models no input-lock/`isDotdotdot` on calls, so that
    /// gate (subflow.cc:218) is omitted; `isInputActive()` maps to an `active_inputs` entry.
    fn try_call_pull(&mut self, op: OpId, rvn: usize, slot: i32) -> bool {
        if slot == 0 {
            return false; // slot 0 is the call target, not a parameter
        }
        if !self.aggressive {
            let vn = self.rvnodes[rvn].vn.expect("real varnode");
            let mask = self.rvnodes[rvn].mask;
            if (self.fd.vn(vn).get_consume() & !mask) != 0 {
                return false; // something outside the mask is consumed — don't truncate
            }
        }
        if self.fd.is_input_active(op) {
            return false; // don't trim while param recovery is mid-flight (isInputActive)
        }
        self.add_terminal_patch_same_op(op, rvn, slot);
        true
    }

    /// Ghidra `PcodeOp::getRepeatSlot` (`op.cc:93`): in the rare case the same Varnode feeds this op in
    /// multiple input slots, map the current descend-iteration position (`idx` into the cloned descend
    /// list) to the corresponding slot; `first_slot` is its first occurrence. Returns -1 if not found
    /// (as Ghidra). The descend list holds `op` once per referencing slot (`Funcdata::new_op`), matching
    /// Ghidra's `beginDescend`.
    fn get_repeat_slot(&self, op: OpId, vn: VarnodeId, first_slot: usize, idx: usize, descend: &[OpId]) -> i32 {
        let mut count = 1;
        for &o in &descend[..idx] {
            if o == op {
                count += 1;
            }
        }
        if count == 1 {
            return first_slot as i32;
        }
        let mut recount = 1;
        let inrefs = &self.fd.op(op).inrefs;
        // faithful port of Ghidra's numbered-input scan; `i` is the returned slot index
        #[allow(clippy::needless_range_loop)]
        for i in (first_slot + 1)..inrefs.len() {
            if inrefs[i] == vn {
                recount += 1;
                if recount == count {
                    return i as i32;
                }
            }
        }
        -1
    }

    /// Ghidra `Varnode::isZeroExtended` (`varnode.cc:958`): can we prove the bytes above the low
    /// `base_size` are zero? Lives here rather than on `Varnode` because it is the only caller; the
    /// `size > sizeof(uintb)` arm asks the defining op, since an over-8-byte varnode has no nzmask.
    fn is_zero_extended(&self, vn: VarnodeId, base_size: u32) -> bool {
        let size = self.fd.vn(vn).size;
        if base_size >= size {
            return false;
        }
        if size > 8 {
            let Some(def) = self.fd.vn(vn).def else { return false };
            if self.fd.op(def).code() != OpCode::IntZext {
                return false;
            }
            let in0 = self.fd.op(def).input(0).unwrap();
            return self.fd.vn(in0).size <= base_size;
        }
        (self.fd.vn(vn).get_nzmask() >> (8 * base_size)) == 0
    }

    /// Ghidra `SubvariableFlow::addBooleanPatch` (`subflow.cc:1203`): a bit of the logical value flows
    /// into an operator taking a boolean input. Terminates the subgraph along that edge, leaving the
    /// operator itself untouched — deliberately NOT counted as a modification, so a trace made only of
    /// boolean patches still fails `do_trace`'s `pullcount == 0` test.
    fn add_boolean_patch(&mut self, pullop: OpId, rvn: usize, slot: i32) {
        self.patchlist.push(PatchRecord { ty: PatchType::Parameter, patch_op: pullop, in1: Some(rvn), in2: None, slot });
    }

    /// Ghidra `SubvariableFlow::trySwitchPull` (`subflow.cc:319`): the logical value is a BRANCHIND's
    /// switch variable — trim it to its logical size. Ghidra's comment mentions querying the JumpTable
    /// but the code does not; the test is purely on the mask and the consumed bits.
    fn try_switch_pull(&mut self, op: OpId, rvn: usize) -> bool {
        let vn = self.rvnodes[rvn].vn.expect("real varnode");
        let mask = self.rvnodes[rvn].mask;
        if (mask & 1) == 0 {
            return false; // Logical value must be justified
        }
        if (self.fd.vn(vn).get_consume() & !mask) != 0 {
            return false; // Something outside the mask is consumed — can't trim
        }
        self.patchlist.push(PatchRecord { ty: PatchType::Parameter, patch_op: op, in1: Some(rvn), in2: None, slot: 0 });
        self.pullcount += 1; // A true terminal modification
        true
    }

    /// Ghidra `SubvariableFlow::tryInt2FloatPull` (`subflow.cc:341`): the logical value is zero-padded
    /// into a FLOAT_INT2FLOAT, making the conversion unsigned. Keep the conversion but record a patch
    /// that re-inserts an INT_ZEXT so it stays unsigned. When the existing `INT_ZEXT -> FLOAT_INT2FLOAT`
    /// pair already has the preferred shape this is NOT counted as a modification, so the trace needs
    /// another terminal patch to be worth doing.
    fn try_int2float_pull(&mut self, op: OpId, rvn: usize) -> bool {
        let vn = self.rvnodes[rvn].vn.expect("real varnode");
        let mask = self.rvnodes[rvn].mask;
        if (mask & 1) == 0 {
            return false; // Logical value must be justified
        }
        if (self.fd.vn(vn).get_nzmask() & !mask) != 0 {
            return false; // Everything outside the logical value must be zero
        }
        if self.fd.vn(vn).size == self.flowsize {
            return false; // There must be some (zero) extension
        }
        let mut pull_modification = true;
        if let Some(def) = self.fd.vn(vn).def {
            if self.fd.op(def).code() == OpCode::IntZext
                && self.fd.vn(vn).size == preferred_zext_size(self.flowsize)
                && self.fd.lone_descend(vn) == Some(op)
            {
                pull_modification = false;
            }
        }
        self.patchlist.push(PatchRecord { ty: PatchType::Int2Float, patch_op: op, in1: Some(rvn), in2: None, slot: 0 });
        if pull_modification {
            self.pullcount += 1;
        }
        true
    }

    /// Ghidra `SubvariableFlow::tryCallReturnPush` (`subflow.cc:293`): the logical value is the return
    /// value of a CALL/CALLIND — push the narrow value out of the call itself.
    ///
    /// mosura adaptations, both established in-tree: `getCallSpecs()==null` cannot hold for a
    /// CALL/CALLIND op (only CALLOTHER lacks a spec, and it is a different opcode), and mosura models
    /// no output lock on calls — the same two gates `try_call_pull` already omits. Ghidra's
    /// `isOutputActive()` gate ("don't trim while figuring out the return value") maps to *the call
    /// having no output yet*: `resolve_call_output` skips a call once `output.is_some()`, which is the
    /// documented stand-in for Ghidra's cleared `isOutputActive`. Reaching this arm at all means the
    /// call IS the def of a varnode, i.e. it already has an output, so the gate is satisfied by
    /// construction rather than merely dropped.
    fn try_call_return_push(&mut self, op: OpId, rvn: usize) -> bool {
        let vn = self.rvnodes[rvn].vn.expect("real varnode");
        let mask = self.rvnodes[rvn].mask;
        if !self.aggressive && (self.fd.vn(vn).get_consume() & !mask) != 0 {
            return false; // Something outside the mask is consumed — don't truncate
        }
        if (mask & 1) == 0 {
            return false; // The logical value must be the least significant part
        }
        if self.bitsize < 8 {
            return false; // The logical value must be at least a byte
        }
        if self.fd.op(op).output.is_none() {
            return false; // isOutputActive — return-value recovery still in flight
        }
        self.add_push(op, rvn);
        // No `pullcount` bump: this is a push, NOT a pull (subflow.cc:308).
        true
    }

    /// Ghidra `SubvariableFlow::addExtensionPatch` (`subflow.cc:1221`): op pads the logical value with
    /// zero bits, shifted left by `sa` (bits); `sa == -1` means shift by the mask's least-set bit.
    /// Not a true modification (the output keeps the expanded size).
    fn add_extension_patch(&mut self, rvn: usize, pushop: OpId, sa: i32) {
        let sa = if sa == -1 { leastsigbit_set(self.rvnodes[rvn].mask) } else { sa };
        self.patchlist.push(PatchRecord { ty: PatchType::Extension, patch_op: pushop, in1: Some(rvn), in2: None, slot: sa });
    }

    /// Ghidra `SubvariableFlow::addComparePatch` (`subflow.cc:1241`): the two logical values flow into
    /// a comparison done on the wider containers. A true terminal modification.
    fn add_compare_patch(&mut self, in1: usize, in2: usize, op: OpId) {
        self.patchlist.push(PatchRecord { ty: PatchType::Compare, patch_op: op, in1: Some(in1), in2: Some(in2), slot: 0 });
        self.pullcount += 1;
    }

    /// Ghidra `SubvariableFlow::createCompareBridge` (`subflow.cc:1056`): extend the subgraph through a
    /// comparison, adding the other side as a logical value and a compare patch.
    fn create_compare_bridge(&mut self, op: OpId, inrvn: usize, slot: usize, othervn: VarnodeId) -> bool {
        let inmask = self.rvnodes[inrvn].mask;
        let Some((rep, inworklist)) = self.set_replacement(othervn, inmask) else { return false };
        if slot == 0 {
            self.add_compare_patch(inrvn, rep, op);
        } else {
            self.add_compare_patch(rep, inrvn, op);
        }
        if inworklist {
            self.worklist.push(rep);
        }
        true
    }

    // --- The tracers -----------------------------------------------------------------------

    /// Ghidra `SubvariableFlow::traceForward` (`subflow.cc:373`): trace the logical value through its
    /// descendant ops one level, extending the subgraph. Returns false to abort the whole transform.
    /// Every arm of Ghidra's switch is covered; `default` aborts as it does there.
    fn trace_forward(&mut self, rvn: usize) -> bool {
        let vn = self.rvnodes[rvn].vn.expect("traced node shadows a real Varnode");
        let mask = self.rvnodes[rvn].mask;
        let mut dcount = 0i32;
        let mut hcount = 0i32;
        let mut callcount = 0i32;

        let descend = self.fd.vn(vn).descend.clone();
        for idx in 0..descend.len() {
            let op = descend[idx];
            let out_opt = self.fd.op(op).output;
            if let Some(o) = out_opt {
                if self.fd.vn(o).is_mark() && !self.fd.op(op).is_call() {
                    continue;
                }
            }
            dcount += 1; // Count this descendant
            let slot = self.fd.op(op).inrefs.iter().position(|&v| v == vn).unwrap();
            let opc = self.fd.op(op).code();
            subvar_debug(&format!("  fwd  {}", self.fd.op_str(op)));
            match opc {
                OpCode::Copy | OpCode::Multiequal | OpCode::IntNegate | OpCode::IntXor => {
                    let outvn = out_opt.expect("op has output");
                    let n = self.fd.op(op).num_inputs() as i32;
                    let rop = self.create_op_down(opc, n, op, rvn, slot);
                    if !self.create_link(Some(rop), mask, -1, outvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::IntOr => {
                    if self.does_or_set(op, mask) != -1 {
                        continue; // Subvar set to 1s, truncate flow
                    }
                    let outvn = out_opt.expect("op has output");
                    let rop = self.create_op_down(OpCode::IntOr, 2, op, rvn, slot);
                    if !self.create_link(Some(rop), mask, -1, outvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::IntAnd => {
                    let outvn = out_opt.expect("op has output");
                    let in1 = self.fd.op(op).input(1).unwrap();
                    if self.fd.vn(in1).is_constant() && self.fd.vn(in1).constant_value() == mask {
                        if self.fd.vn(outvn).size == self.flowsize && (mask & 1) != 0 {
                            self.add_terminal_patch(op, rvn);
                            hcount += 1;
                            continue;
                        }
                        // Is the small variable getting zero padded into something fully consumed?
                        let out_consume = self.fd.vn(outvn).get_consume();
                        if !self.aggressive && (out_consume & mask) != out_consume {
                            self.add_extension_patch(rvn, op, -1);
                            hcount += 1;
                            continue;
                        }
                    }
                    if self.does_and_clear(op, mask) != -1 {
                        continue; // Subvar set to zero, truncate flow
                    }
                    let rop = self.create_op_down(OpCode::IntAnd, 2, op, rvn, slot);
                    if !self.create_link(Some(rop), mask, -1, outvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::IntZext | OpCode::IntSext => {
                    let outvn = out_opt.expect("op has output");
                    let rop = self.create_op_down(OpCode::Copy, 1, op, rvn, 0);
                    if !self.create_link(Some(rop), mask, -1, outvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::IntMult => {
                    if (mask & 1) == 0 {
                        return false; // Cannot account for carry
                    }
                    let outvn = out_opt.expect("op has output");
                    let othervn = self.fd.op(op).input(1 - slot).unwrap();
                    // The other multiplicand's trailing zeroes shift the logical value left.
                    // Ghidra reads `leastsigbit_set(nzmask)` straight, which is -1 for a provably-zero
                    // operand and then shifts by a negative amount — undefined in C++ and unreachable
                    // in practice (a zero nzmask means the product is zero, which the nzmask rules
                    // collapse first). mosura floors it at 0 like `add_constant` already does, so the
                    // degenerate case is a plain unshifted trace instead of a garbage mask.
                    let sa = leastsigbit_set(self.fd.vn(othervn).get_nzmask()).max(0) & !7;
                    if self.bitsize + sa > 8 * self.fd.vn(vn).size as i32 {
                        return false;
                    }
                    let rop = self.create_op_down(OpCode::IntMult, 2, op, rvn, slot);
                    if !self.create_link(Some(rop), mask << (sa as u32), -1, outvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::IntDiv | OpCode::IntRem => {
                    if (mask & 1) == 0 {
                        return false; // Logical value must be least sig bits
                    }
                    if (self.bitsize & 7) != 0 {
                        return false; // Must be a whole number of bytes
                    }
                    let outvn = out_opt.expect("op has output");
                    let in0 = self.fd.op(op).input(0).unwrap();
                    let in1 = self.fd.op(op).input(1).unwrap();
                    if !self.is_zero_extended(in0, self.flowsize) {
                        return false;
                    }
                    if !self.is_zero_extended(in1, self.flowsize) {
                        return false;
                    }
                    let rop = self.create_op_down(opc, 2, op, rvn, slot);
                    if !self.create_link(Some(rop), mask, -1, outvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::IntAdd => {
                    if (mask & 1) == 0 {
                        return false; // Cannot account for carry
                    }
                    let outvn = out_opt.expect("op has output");
                    let rop = self.create_op_down(OpCode::IntAdd, 2, op, rvn, slot);
                    if !self.create_link(Some(rop), mask, -1, outvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::IntLeft => {
                    let outvn = out_opt.expect("op has output");
                    if slot == 1 {
                        // Logical flow is into the shift amount.
                        if (mask & 1) == 0 {
                            return false;
                        }
                        if self.bitsize < 8 {
                            return false;
                        }
                        self.add_terminal_patch_same_op(op, rvn, slot as i32);
                        hcount += 1;
                        continue;
                    }
                    let in1 = self.fd.op(op).input(1).unwrap();
                    if !self.fd.vn(in1).is_constant() {
                        return false; // Dynamic shift
                    }
                    let sa = self.fd.vn(in1).constant_value() as i64;
                    if sa >= 64 {
                        return false; // Beyond precision of mask
                    }
                    let out_size = self.fd.vn(outvn).size;
                    let newmask = (mask << (sa as u32)) & calc_mask(out_size);
                    if newmask == 0 {
                        continue; // Subvar cleared, truncate flow
                    }
                    if mask != (newmask >> (sa as u32)) {
                        return false; // subvar is clipped
                    }
                    let out_consume = self.fd.vn(outvn).get_consume();
                    if (mask & 1) != 0
                        && (sa + self.bitsize as i64) == 8 * out_size as i64
                        && (out_consume & !newmask) != 0
                    {
                        self.add_extension_patch(rvn, op, sa as i32);
                        hcount += 1;
                        continue;
                    }
                    let rop = self.create_op_down(OpCode::Copy, 1, op, rvn, 0);
                    if !self.create_link(Some(rop), newmask, -1, outvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::IntRight | OpCode::IntSright => {
                    let outvn = out_opt.expect("op has output");
                    if slot == 1 {
                        // Logical flow is into the shift amount.
                        if (mask & 1) == 0 {
                            return false;
                        }
                        if self.bitsize < 8 {
                            return false;
                        }
                        self.add_terminal_patch_same_op(op, rvn, slot as i32);
                        hcount += 1;
                        continue;
                    }
                    let in1 = self.fd.op(op).input(1).unwrap();
                    if !self.fd.vn(in1).is_constant() {
                        return false;
                    }
                    let sa = self.fd.vn(in1).constant_value() as i64;
                    let newmask = if sa >= 64 { 0 } else { mask >> (sa as u32) };
                    if newmask == 0 {
                        if opc == OpCode::IntRight {
                            continue; // subvar does not pass thru, truncate flow
                        }
                        return false;
                    }
                    if mask != (newmask << (sa as u32)) {
                        return false;
                    }
                    let in0 = self.fd.op(op).input(0).unwrap();
                    let in0_nz = self.fd.vn(in0).get_nzmask();
                    let out_size = self.fd.vn(outvn).size;
                    if out_size == self.flowsize && (newmask & 1) == 1 && in0_nz == mask {
                        self.add_terminal_patch(op, rvn);
                        hcount += 1;
                        continue;
                    }
                    let out_consume = self.fd.vn(outvn).get_consume();
                    if (newmask & 1) == 1
                        && (sa + self.bitsize as i64) == 8 * out_size as i64
                        && (out_consume & !newmask) != 0
                    {
                        self.add_extension_patch(rvn, op, 0);
                        hcount += 1;
                        continue;
                    }
                    let rop = self.create_op_down(OpCode::Copy, 1, op, rvn, 0);
                    if !self.create_link(Some(rop), newmask, -1, outvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::Subpiece => {
                    let outvn = out_opt.expect("op has output");
                    let in1 = self.fd.op(op).input(1).unwrap();
                    let sa = self.fd.vn(in1).constant_value() as i64 * 8;
                    if sa >= 64 {
                        continue;
                    }
                    let out_size = self.fd.vn(outvn).size;
                    let newmask = (mask >> (sa as u32)) & calc_mask(out_size);
                    if newmask == 0 {
                        continue; // subvar is set to zero, truncate flow
                    }
                    if mask != (newmask << (sa as u32)) {
                        // Some kind of truncation of the logical value.
                        if (self.flowsize as i64) > (sa / 8 + out_size as i64) && (mask & 1) != 0 {
                            // Only a piece of the logical value remains.
                            self.add_terminal_patch_same_op(op, rvn, 0);
                            hcount += 1;
                            continue;
                        }
                        return false;
                    }
                    if (newmask & 1) != 0 && out_size == self.flowsize {
                        self.add_terminal_patch(op, rvn);
                        hcount += 1;
                        continue;
                    }
                    let rop = self.create_op_down(OpCode::Copy, 1, op, rvn, 0);
                    if !self.create_link(Some(rop), newmask, -1, outvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::Piece => {
                    let outvn = out_opt.expect("op has output");
                    let in0 = self.fd.op(op).input(0).unwrap();
                    let newmask = if vn == in0 {
                        let in1 = self.fd.op(op).input(1).unwrap();
                        let sh = 8 * self.fd.vn(in1).size;
                        if sh >= 64 { 0 } else { mask << sh }
                    } else {
                        mask
                    };
                    let rop = self.create_op_down(OpCode::Copy, 1, op, rvn, 0);
                    if !self.create_link(Some(rop), newmask, -1, outvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::IntLess | OpCode::IntLessequal => {
                    let othervn = self.fd.op(op).input(1 - slot).unwrap(); // OTHER side of comparison
                    let vn_nz = self.fd.vn(vn).get_nzmask();
                    if !self.aggressive && (vn_nz | mask) != mask {
                        return false; // Everything but the logical variable must definitely be zero
                    }
                    if self.fd.vn(othervn).is_constant() {
                        if (mask | self.fd.vn(othervn).constant_value()) != mask {
                            return false; // Must compare only bits of the logical variable
                        }
                    } else {
                        let oth_nz = self.fd.vn(othervn).get_nzmask();
                        if !self.aggressive && (mask | oth_nz) != mask {
                            return false; // unused bits of the other side must be zero
                        }
                    }
                    if !self.create_compare_bridge(op, rvn, slot, othervn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::IntNotequal | OpCode::IntEqual => {
                    let othervn = self.fd.op(op).input(1 - slot).unwrap(); // OTHER side of comparison
                    if self.bitsize != 1 {
                        let vn_nz = self.fd.vn(vn).get_nzmask();
                        if !self.aggressive && (vn_nz | mask) != mask {
                            return false; // Everything but logical variable must be zero
                        }
                        if self.fd.vn(othervn).is_constant() {
                            if (mask | self.fd.vn(othervn).constant_value()) != mask {
                                return false; // Not comparing to just bits of the logical variable
                            }
                        } else {
                            let oth_nz = self.fd.vn(othervn).get_nzmask();
                            if !self.aggressive && (mask | oth_nz) != mask {
                                return false; // unused bits of otherside must be zero
                            }
                        }
                        if !self.create_compare_bridge(op, rvn, slot, othervn) {
                            return false;
                        }
                    } else {
                        // Movement of boolean variables.
                        if !self.fd.vn(othervn).is_constant() {
                            return false;
                        }
                        let newmask = self.fd.vn(vn).get_nzmask();
                        if newmask != mask {
                            return false;
                        }
                        let othoff = self.fd.vn(othervn).constant_value();
                        let mut booldir = if othoff == 0 {
                            true
                        } else if othoff == newmask {
                            false
                        } else {
                            return false;
                        };
                        if opc == OpCode::IntEqual {
                            booldir = !booldir;
                        }
                        if booldir {
                            self.add_terminal_patch(op, rvn);
                        } else {
                            let rop = self.create_op_down(OpCode::BoolNegate, 1, op, rvn, 0);
                            let outidx = self.create_new_out(rop, 1);
                            self.add_terminal_patch(op, outidx);
                        }
                    }
                    hcount += 1;
                }
                // CALL/CALLIND: pull the logical value into the call parameter (Ghidra traceForward,
                // subflow.cc:616-623). A value passed in 2+ slots of one call is disambiguated by
                // `get_repeat_slot` (Ghidra getRepeatSlot, op.cc:93) once callcount > 1.
                OpCode::Call | OpCode::Callind => {
                    callcount += 1;
                    let slot = if callcount > 1 {
                        self.get_repeat_slot(op, vn, slot, idx, &descend)
                    } else {
                        slot as i32
                    };
                    if !self.try_call_pull(op, rvn, slot) {
                        return false;
                    }
                    hcount += 1;
                }
                // RETURN: pull the logical value out of the return (Ghidra traceForward, subflow.cc:624).
                OpCode::Return => {
                    if !self.try_return_pull(op, rvn, slot) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::Branchind => {
                    if !self.try_switch_pull(op, rvn) {
                        return false;
                    }
                    hcount += 1;
                }
                // A bit flowing into a boolean operator: patch the edge but do NOT count it as a
                // handled descendant — Ghidra omits the `hcount += 1` here deliberately
                // (subflow.cc:632-639, addBooleanPatch "this is not a true modification"), unlike
                // the CBRANCH arm below which does count.
                OpCode::BoolNegate | OpCode::BoolAnd | OpCode::BoolOr | OpCode::BoolXor => {
                    if self.bitsize != 1 {
                        return false;
                    }
                    if mask != 1 {
                        return false;
                    }
                    self.add_boolean_patch(op, rvn, slot as i32);
                }
                OpCode::FloatInt2float => {
                    if !self.try_int2float_pull(op, rvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::Cbranch => {
                    if self.bitsize != 1 || slot != 1 {
                        return false;
                    }
                    if mask != 1 {
                        return false;
                    }
                    self.add_boolean_patch(op, rvn, 1);
                    hcount += 1;
                }
                _ => return false,
            }
        }
        if dcount != hcount {
            // Must account for all descendants of an input.
            if self.fd.vn(vn).is_input() {
                return false;
            }
        }
        true
    }

    /// Ghidra `SubvariableFlow::traceBackward` (`subflow.cc:665`): trace the logical value backward
    /// through its defining op one level. Returns true if traced (or `vn` is an input), false to
    /// abort. Every arm of Ghidra's switch is covered; `default` aborts as it does there. Ghidra's
    /// `break` and its `return false` both land on the same trailing `return false`, so both map to
    /// `false` here.
    fn trace_backward(&mut self, rvn: usize) -> bool {
        let vn = self.rvnodes[rvn].vn.expect("traced node shadows a real Varnode");
        let mask = self.rvnodes[rvn].mask;
        let Some(op) = self.fd.vn(vn).def else {
            return true; // If vn is input
        };
        let opc = self.fd.op(op).code();
        subvar_debug(&format!("  back {}", self.fd.op_str(op)));
        match opc {
            OpCode::Copy | OpCode::Multiequal | OpCode::IntNegate | OpCode::IntXor => {
                let n = self.fd.op(op).num_inputs() as i32;
                let rop = self.create_op(opc, n, rvn);
                for i in 0..n as usize {
                    let ini = self.fd.op(op).input(i).unwrap();
                    if !self.create_link(Some(rop), mask, i as i32, ini) {
                        return false;
                    }
                }
                true
            }
            OpCode::IntAnd => {
                let sa = self.does_and_clear(op, mask);
                if sa != -1 {
                    let rop = self.create_op(OpCode::Copy, 1, rvn);
                    let cvn = self.fd.op(op).input(sa as usize).unwrap();
                    self.add_constant(Some(rop), mask, 0, cvn);
                } else {
                    let rop = self.create_op(OpCode::IntAnd, 2, rvn);
                    let in0 = self.fd.op(op).input(0).unwrap();
                    let in1 = self.fd.op(op).input(1).unwrap();
                    if !self.create_link(Some(rop), mask, 0, in0) {
                        return false;
                    }
                    if !self.create_link(Some(rop), mask, 1, in1) {
                        return false;
                    }
                }
                true
            }
            OpCode::IntOr => {
                let sa = self.does_or_set(op, mask);
                if sa != -1 {
                    let rop = self.create_op(OpCode::Copy, 1, rvn);
                    let cvn = self.fd.op(op).input(sa as usize).unwrap();
                    self.add_constant(Some(rop), mask, 0, cvn);
                } else {
                    let rop = self.create_op(OpCode::IntOr, 2, rvn);
                    let in0 = self.fd.op(op).input(0).unwrap();
                    let in1 = self.fd.op(op).input(1).unwrap();
                    if !self.create_link(Some(rop), mask, 0, in0) {
                        return false;
                    }
                    if !self.create_link(Some(rop), mask, 1, in1) {
                        return false;
                    }
                }
                true
            }
            OpCode::IntZext | OpCode::IntSext => {
                let in0 = self.fd.op(op).input(0).unwrap();
                let in0_size = self.fd.vn(in0).size;
                if (mask & calc_mask(in0_size)) != mask {
                    if (mask & 1) != 0 && self.flowsize > in0_size {
                        self.add_push(op, rvn);
                        return true;
                    }
                    return false; // Check if subvariable comes through extension
                }
                let rop = self.create_op(OpCode::Copy, 1, rvn);
                if !self.create_link(Some(rop), mask, 0, in0) {
                    return false;
                }
                true
            }
            OpCode::IntAdd => {
                if (mask & 1) == 0 {
                    return false; // Cannot account for carry
                }
                // A single-bit add is an XOR.
                let opc = if mask == 1 { OpCode::IntXor } else { OpCode::IntAdd };
                let rop = self.create_op(opc, 2, rvn);
                let in0 = self.fd.op(op).input(0).unwrap();
                let in1 = self.fd.op(op).input(1).unwrap();
                if !self.create_link(Some(rop), mask, 0, in0) {
                    return false;
                }
                if !self.create_link(Some(rop), mask, 1, in1) {
                    return false;
                }
                true
            }
            OpCode::IntMult => {
                let in0 = self.fd.op(op).input(0).unwrap();
                let in1 = self.fd.op(op).input(1).unwrap();
                let sa = leastsigbit_set(mask);
                if sa != 0 {
                    let sa2 = leastsigbit_set(self.fd.vn(in1).get_nzmask());
                    if sa2 < sa {
                        return false; // Cannot deal with carries into the logical multiply
                    }
                    let newmask = mask >> (sa as u32);
                    let rop = self.create_op(OpCode::IntMult, 2, rvn);
                    if !self.create_link(Some(rop), newmask, 0, in0) {
                        return false;
                    }
                    if !self.create_link(Some(rop), mask, 1, in1) {
                        return false;
                    }
                } else {
                    // A single-bit multiply is an AND.
                    let opc = if mask == 1 { OpCode::IntAnd } else { OpCode::IntMult };
                    let rop = self.create_op(opc, 2, rvn);
                    if !self.create_link(Some(rop), mask, 0, in0) {
                        return false;
                    }
                    if !self.create_link(Some(rop), mask, 1, in1) {
                        return false;
                    }
                }
                true
            }
            OpCode::IntDiv | OpCode::IntRem => {
                if (mask & 1) == 0 {
                    return false;
                }
                if (self.bitsize & 7) != 0 {
                    return false; // Must be a whole number of bytes
                }
                let in0 = self.fd.op(op).input(0).unwrap();
                let in1 = self.fd.op(op).input(1).unwrap();
                if !self.is_zero_extended(in0, self.flowsize) {
                    return false;
                }
                if !self.is_zero_extended(in1, self.flowsize) {
                    return false;
                }
                let rop = self.create_op(opc, 2, rvn);
                if !self.create_link(Some(rop), mask, 0, in0) {
                    return false;
                }
                if !self.create_link(Some(rop), mask, 1, in1) {
                    return false;
                }
                true
            }
            OpCode::Call | OpCode::Callind => self.try_call_return_push(op, rvn),
            OpCode::IntLeft => {
                let in1 = self.fd.op(op).input(1).unwrap();
                if !self.fd.vn(in1).is_constant() {
                    return false; // Dynamic shift
                }
                let sa = self.fd.vn(in1).constant_value() as i64;
                let newmask = if sa >= 64 { 0 } else { mask >> (sa as u32) };
                if newmask == 0 {
                    // Subvariable filled with shifted zero.
                    let rop = self.create_op(OpCode::Copy, 1, rvn);
                    self.add_new_constant(Some(rop), 0, 0);
                    return true;
                }
                if (newmask << (sa as u32)) == mask {
                    let rop = self.create_op(OpCode::Copy, 1, rvn);
                    let in0 = self.fd.op(op).input(0).unwrap();
                    if !self.create_link(Some(rop), newmask, 0, in0) {
                        return false;
                    }
                    return true;
                }
                if (mask & 1) == 0 {
                    return false; // Can't assume zeroes are shifted into least sig bits
                }
                let rop = self.create_op(OpCode::IntLeft, 2, rvn);
                let in0 = self.fd.op(op).input(0).unwrap();
                if !self.create_link(Some(rop), mask, 0, in0) {
                    return false;
                }
                let in1sz = self.fd.vn(in1).size;
                self.add_constant(Some(rop), calc_mask(in1sz), 1, in1); // Preserve the shift amount
                true
            }
            OpCode::IntRight => {
                let in1 = self.fd.op(op).input(1).unwrap();
                if !self.fd.vn(in1).is_constant() {
                    return false; // Dynamic shift
                }
                let sa = self.fd.vn(in1).constant_value() as i64;
                if sa >= 64 {
                    return false; // Beyond precision of mask
                }
                let in0 = self.fd.op(op).input(0).unwrap();
                let in0_size = self.fd.vn(in0).size;
                let newmask = (mask << (sa as u32)) & calc_mask(in0_size);
                if newmask == 0 {
                    // Subvariable filled with shifted zero.
                    let rop = self.create_op(OpCode::Copy, 1, rvn);
                    self.add_new_constant(Some(rop), 0, 0);
                    return true;
                }
                if (newmask >> (sa as u32)) != mask {
                    return false; // subvariable is truncated by shift
                }
                let rop = self.create_op(OpCode::Copy, 1, rvn);
                if !self.create_link(Some(rop), newmask, 0, in0) {
                    return false;
                }
                true
            }
            // Identical to INT_RIGHT except for the `newmask == 0` shortcut, which INT_SRIGHT must
            // NOT have: an arithmetic shift fills the vacated bits with the sign bit, not zero.
            OpCode::IntSright => {
                let in1 = self.fd.op(op).input(1).unwrap();
                if !self.fd.vn(in1).is_constant() {
                    return false; // Dynamic shift
                }
                let sa = self.fd.vn(in1).constant_value() as i64;
                if sa >= 64 {
                    return false; // Beyond precision of mask
                }
                let in0 = self.fd.op(op).input(0).unwrap();
                let in0_size = self.fd.vn(in0).size;
                let newmask = (mask << (sa as u32)) & calc_mask(in0_size);
                if (newmask >> (sa as u32)) != mask {
                    return false; // subvariable is truncated by shift
                }
                let rop = self.create_op(OpCode::Copy, 1, rvn);
                if !self.create_link(Some(rop), newmask, 0, in0) {
                    return false;
                }
                true
            }
            OpCode::Subpiece => {
                let in1 = self.fd.op(op).input(1).unwrap();
                let sa = self.fd.vn(in1).constant_value() as i64 * 8;
                let newmask = if sa >= 64 { 0 } else { mask << (sa as u32) };
                let rop = self.create_op(OpCode::Copy, 1, rvn);
                let in0 = self.fd.op(op).input(0).unwrap();
                if !self.create_link(Some(rop), newmask, 0, in0) {
                    return false;
                }
                true
            }
            OpCode::Piece => {
                let in1 = self.fd.op(op).input(1).unwrap();
                let in1_size = self.fd.vn(in1).size;
                if (mask & calc_mask(in1_size)) == mask {
                    let rop = self.create_op(OpCode::Copy, 1, rvn);
                    if !self.create_link(Some(rop), mask, 0, in1) {
                        return false;
                    }
                    return true;
                }
                let sa = (in1_size * 8) as i64;
                let newmask = if sa >= 64 { 0 } else { mask >> (sa as u32) };
                let back = if sa >= 64 { 0 } else { newmask << (sa as u32) };
                if back == mask {
                    let rop = self.create_op(OpCode::Copy, 1, rvn);
                    let in0 = self.fd.op(op).input(0).unwrap();
                    if !self.create_link(Some(rop), newmask, 0, in0) {
                        return false;
                    }
                    return true;
                }
                false
            }
            OpCode::IntEqual
            | OpCode::IntNotequal
            | OpCode::IntSless
            | OpCode::IntSlessequal
            | OpCode::IntLess
            | OpCode::IntLessequal
            | OpCode::IntCarry
            | OpCode::IntScarry
            | OpCode::IntSborrow
            | OpCode::BoolNegate
            | OpCode::BoolXor
            | OpCode::BoolAnd
            | OpCode::BoolOr
            | OpCode::FloatEqual
            | OpCode::FloatNotequal
            | OpCode::FloatLessequal
            | OpCode::FloatNan => {
                // Mask won't be 1, because setReplacement takes care of it.
                if (mask & 1) == 1 {
                    return false; // Not normal variable flow
                }
                // Variable is filled with zero.
                let rop = self.create_op(OpCode::Copy, 1, rvn);
                self.add_new_constant(Some(rop), 0, 0);
                true
            }
            _ => false,
        }
    }

    // --- The sign-extension tracers ---------------------------------------------------------
    // The `sextrestrictions` mode, reached only from `RuleSubvarSext`. The logical value is assumed
    // (and checked) to be SIGN-extended into its container rather than zero-extended, which changes
    // which ops preserve it: INT_SRIGHT now does, and the comparisons all do at both widths.

    /// Ghidra `SubvariableFlow::traceForwardSext` (`subflow.cc:867`).
    fn trace_forward_sext(&mut self, rvn: usize) -> bool {
        let vn = self.rvnodes[rvn].vn.expect("traced node shadows a real Varnode");
        let mask = self.rvnodes[rvn].mask;
        let mut dcount = 0i32;
        let mut hcount = 0i32;
        let mut callcount = 0i32;

        let descend = self.fd.vn(vn).descend.clone();
        for idx in 0..descend.len() {
            let op = descend[idx];
            let out_opt = self.fd.op(op).output;
            if let Some(o) = out_opt {
                if self.fd.vn(o).is_mark() && !self.fd.op(op).is_call() {
                    continue;
                }
            }
            dcount += 1;
            let slot = self.fd.op(op).inrefs.iter().position(|&v| v == vn).unwrap();
            let opc = self.fd.op(op).code();
            subvar_debug(&format!("  fwdS {}", self.fd.op_str(op)));
            match opc {
                OpCode::Copy
                | OpCode::Multiequal
                | OpCode::IntNegate
                | OpCode::IntXor
                | OpCode::IntOr
                | OpCode::IntAnd => {
                    let outvn = out_opt.expect("op has output");
                    let n = self.fd.op(op).num_inputs() as i32;
                    let rop = self.create_op_down(opc, n, op, rvn, slot);
                    if !self.create_link(Some(rop), mask, -1, outvn) {
                        return false;
                    }
                    hcount += 1;
                }
                // The logical value extended into an even larger container.
                OpCode::IntSext => {
                    let outvn = out_opt.expect("op has output");
                    let rop = self.create_op_down(OpCode::Copy, 1, op, rvn, 0);
                    if !self.create_link(Some(rop), mask, -1, outvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::IntSright => {
                    let in1 = self.fd.op(op).input(1).unwrap();
                    if !self.fd.vn(in1).is_constant() {
                        return false; // Only constant shifts, as Ghidra
                    }
                    let outvn = out_opt.expect("op has output");
                    let rop = self.create_op_down(OpCode::IntSright, 2, op, rvn, 0);
                    if !self.create_link(Some(rop), mask, -1, outvn) {
                        return false; // Keep the same mask size
                    }
                    let in1sz = self.fd.vn(in1).size;
                    self.add_constant(Some(rop), calc_mask(in1sz), 1, in1); // Preserve the shift amount
                    hcount += 1;
                }
                OpCode::Subpiece => {
                    let in1 = self.fd.op(op).input(1).unwrap();
                    if self.fd.vn(in1).constant_value() != 0 {
                        return false; // Only allow proper truncation
                    }
                    let outvn = out_opt.expect("op has output");
                    let outsz = self.fd.vn(outvn).size;
                    if outsz > self.flowsize {
                        return false;
                    }
                    if outsz == self.flowsize {
                        self.add_terminal_patch(op, rvn); // Flow ends: SUBPIECE becomes a COPY
                    } else {
                        self.add_terminal_patch_same_op(op, rvn, 0); // SUBPIECE truncates even more
                    }
                    hcount += 1;
                }
                // On sign-extended values the unsigned comparisons are equivalent at both sizes,
                // and everything else works because both sides are sign extended.
                OpCode::IntLess
                | OpCode::IntLessequal
                | OpCode::IntSless
                | OpCode::IntSlessequal
                | OpCode::IntEqual
                | OpCode::IntNotequal => {
                    let othervn = self.fd.op(op).input(1 - slot).unwrap();
                    if !self.create_compare_bridge(op, rvn, slot, othervn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::Call | OpCode::Callind => {
                    callcount += 1;
                    let slot = if callcount > 1 {
                        self.get_repeat_slot(op, vn, slot, idx, &descend)
                    } else {
                        slot as i32
                    };
                    if !self.try_call_pull(op, rvn, slot) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::Return => {
                    if !self.try_return_pull(op, rvn, slot) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::Branchind => {
                    if !self.try_switch_pull(op, rvn) {
                        return false;
                    }
                    hcount += 1;
                }
                _ => return false,
            }
        }
        if dcount != hcount {
            // Must account for all descendants of an input.
            if self.fd.vn(vn).is_input() {
                return false;
            }
        }
        true
    }

    /// Ghidra `SubvariableFlow::traceBackwardSext` (`subflow.cc:960`).
    fn trace_backward_sext(&mut self, rvn: usize) -> bool {
        let vn = self.rvnodes[rvn].vn.expect("traced node shadows a real Varnode");
        let mask = self.rvnodes[rvn].mask;
        let Some(op) = self.fd.vn(vn).def else {
            return true; // If vn is input
        };
        let opc = self.fd.op(op).code();
        subvar_debug(&format!("  backS {}", self.fd.op_str(op)));
        match opc {
            OpCode::Copy
            | OpCode::Multiequal
            | OpCode::IntNegate
            | OpCode::IntXor
            | OpCode::IntAnd
            | OpCode::IntOr => {
                let n = self.fd.op(op).num_inputs() as i32;
                let rop = self.create_op(opc, n, rvn);
                for i in 0..n as usize {
                    let ini = self.fd.op(op).input(i).unwrap();
                    if !self.create_link(Some(rop), mask, i as i32, ini) {
                        return false; // Same inputs and mask
                    }
                }
                true
            }
            OpCode::IntZext => {
                let in0 = self.fd.op(op).input(0).unwrap();
                if self.fd.vn(in0).size < self.flowsize {
                    // A zero extension from a SMALLER size still acts as a signed extension.
                    self.add_push(op, rvn);
                    return true;
                }
                false
            }
            OpCode::IntSext => {
                let in0 = self.fd.op(op).input(0).unwrap();
                if self.flowsize != self.fd.vn(in0).size {
                    return false;
                }
                let rop = self.create_op(OpCode::Copy, 1, rvn);
                self.create_link(Some(rop), mask, 0, in0)
            }
            OpCode::IntSright => {
                // A sign-extended logical value arithmetically right-shifted is the logical value
                // shifted by the same amount.
                let in1 = self.fd.op(op).input(1).unwrap();
                if !self.fd.vn(in1).is_constant() {
                    return false;
                }
                let rop = self.create_op(OpCode::IntSright, 2, rvn);
                let in0 = self.fd.op(op).input(0).unwrap();
                if !self.create_link(Some(rop), mask, 0, in0) {
                    return false; // Keep the same mask
                }
                if self.rops[rop].input.len() == 1 {
                    let in1sz = self.fd.vn(in1).size;
                    self.add_constant(Some(rop), calc_mask(in1sz), 1, in1); // Preserve the shift amount
                }
                true
            }
            OpCode::Call | OpCode::Callind => self.try_call_return_push(op, rvn),
            _ => false,
        }
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
            subvar_debug("SUBVAR result=ABORT");
            return false;
        }
        if self.pullcount == 0 {
            subvar_debug("SUBVAR result=NO-PULL (traced clean but no terminal modification)");
            return false;
        }
        subvar_debug(&format!(
            "SUBVAR result=OK flowsize={} nodes={} ops={} patches={} pulls={}",
            self.flowsize,
            self.rvnodes.len(),
            self.rops.len(),
            self.patchlist.len(),
            self.pullcount
        ));
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

/// `MOSURA_SUBVAR=1` — trace every `SubvariableFlow` attempt: the seed (root/mask/flowsize), each
/// op the tracer dispatches on, and the outcome (`OK` / `NO-PULL` / `ABORT`, with the direction).
///
/// ⚠️ THIS IS A ONE-SIDED PROBE AND THAT IS DELIBERATE. Ghidra has no `SubvariableFlow` debug
/// channel; `OPACTION_DEBUG` logs only p-code mutations that actually happened, so a flow that
/// ABORTS is invisible in it — on either side. The question "how far did the narrowing get before
/// it gave up, and on which op" is therefore not answerable by a trace diff at all, which is why
/// the width divergence survived two instruments that both correctly named this subsystem. Ghidra's
/// side is read from the transform it *did* perform (the `subvar_zext` block in its trace names
/// every replacement varnode); this names the op mosura stopped at.
fn subvar_debug(msg: &str) {
    if subvar_debug_on() {
        eprintln!("{msg}");
    }
}

fn subvar_debug_node(fd: &Funcdata, tag: &str, rvn: usize, rvnodes: &[ReplaceVarnode]) {
    if !subvar_debug_on() {
        return;
    }
    let node = &rvnodes[rvn];
    match node.vn {
        Some(v) => eprintln!(" {tag} {} mask={:#x}", fd.vn_str(v), node.mask),
        None => eprintln!(" {tag} <new> mask={:#x}", node.mask),
    }
}

fn subvar_debug_on() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("MOSURA_SUBVAR").is_some())
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

    /// Establish the pipeline's precondition for the consume-gated paths (`set_replacement`
    /// subflow.cc:112, the call/return pulls): fresh varnodes default to *fully consumed*
    /// (Ghidra Varnode constructor, varnode.cc:586), and the pipeline always runs
    /// `ActionConsume` before anything reads `consume` — so a hand-built graph must run the
    /// same analysis or the gates reject everything.
    fn recompute_consume(f: &mut Funcdata) {
        super::super::consume::calc_consume(f);
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
        recompute_consume(&mut f);
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
        assert!(!s.varmap.contains_key(&out));
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
        recompute_consume(&mut f);
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
        recompute_consume(&mut f);

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
        // The hand-built graph stores the FULL zext output (so `calc_consume` would report `a`
        // fully used); the patch scenario under test is narrow use — set the precondition directly.
        f.vn_mut(a).consume = 0xff;

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

    // --- Stage 2 tracer tests --------------------------------------------------------------
    // Each drives `trace_backward`/`trace_forward` on a hand-built graph and inspects the shadow
    // subgraph (rops/patchlist/varmap) it produces, mirroring one arm of subflow.cc.

    #[test]
    fn trace_backward_copy_and_multiequal() {
        // z = COPY(y): shadow COPY, y linked with the same mask.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let y = f.new_input(4, Address::new(reg, 0x10));
        let opz = f.new_op(OpCode::Copy, seq, vec![y]);
        let z = f.new_output(opz, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, z, 0xff, false, false, false);
        let zrvn = *s.varmap.get(&z).unwrap();
        assert!(s.trace_backward(zrvn));
        assert_eq!(s.rops.len(), 1);
        assert_eq!(s.rops[0].opc, OpCode::Copy);
        let yrvn = *s.varmap.get(&y).expect("input linked backward");
        assert_eq!(s.rvnodes[yrvn].mask, 0xff);
        drop(s);

        // m = MULTIEQUAL(p, q): shadow MULTIEQUAL, both inputs linked.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let p = f.new_input(4, Address::new(reg, 0x10));
        let q = f.new_input(4, Address::new(reg, 0x14));
        let opm = f.new_op(OpCode::Multiequal, seq, vec![p, q]);
        let m = f.new_output(opm, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, m, 0xff, false, false, false);
        let mrvn = *s.varmap.get(&m).unwrap();
        assert!(s.trace_backward(mrvn));
        assert_eq!(s.rops[0].opc, OpCode::Multiequal);
        assert!(s.varmap.contains_key(&p) && s.varmap.contains_key(&q));
    }

    #[test]
    fn trace_backward_and_normal_vs_clear() {
        // Normal AND (const does not clear the mask): shadow INT_AND over both inputs.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let c = f.new_const(4, 0xf0f0);
        let opy = f.new_op(OpCode::IntAnd, seq, vec![a, c]);
        let y = f.new_output(opy, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, y, 0xff, false, false, false);
        let yrvn = *s.varmap.get(&y).unwrap();
        assert!(s.trace_backward(yrvn));
        assert_eq!(s.rops[0].opc, OpCode::IntAnd);
        assert!(s.varmap.contains_key(&a));
        drop(s);

        // Clearing AND (const zeroes the mask): shadow COPY of a masked-to-zero constant.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let c = f.new_const(4, 0xff00);
        let opy = f.new_op(OpCode::IntAnd, seq, vec![a, c]);
        let y = f.new_output(opy, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, y, 0xff, false, false, false);
        let yrvn = *s.varmap.get(&y).unwrap();
        assert!(s.trace_backward(yrvn));
        assert_eq!(s.rops[0].opc, OpCode::Copy);
        let cin = s.rops[0].input[0].expect("constant input");
        assert_eq!(s.rvnodes[cin].val, 0); // 0xff & 0xff00 == 0
    }

    #[test]
    fn trace_backward_or_set() {
        // OR whose const sets all of the mask: shadow COPY of the constant (value == mask).
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let c = f.new_const(4, 0xff);
        let opy = f.new_op(OpCode::IntOr, seq, vec![a, c]);
        let y = f.new_output(opy, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, y, 0xff, false, false, false);
        let yrvn = *s.varmap.get(&y).unwrap();
        assert!(s.trace_backward(yrvn));
        assert_eq!(s.rops[0].opc, OpCode::Copy);
        let cin = s.rops[0].input[0].expect("constant input");
        assert_eq!(s.rvnodes[cin].val, 0xff);
    }

    #[test]
    fn trace_backward_zext_copy_vs_push() {
        // Logical value fits within the pre-extension size: shadow COPY, link the narrow input.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let b = f.new_input(1, Address::new(reg, 0x10));
        let opy = f.new_op(OpCode::IntZext, seq, vec![b]);
        let y = f.new_output(opy, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, y, 0xff, false, false, false);
        let yrvn = *s.varmap.get(&y).unwrap();
        assert!(s.trace_backward(yrvn));
        assert_eq!(s.rops[0].opc, OpCode::Copy);
        assert!(s.varmap.contains_key(&b));
        drop(s);

        // Logical value straddles the extension boundary: a push_patch at the front of the list.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let b = f.new_input(2, Address::new(reg, 0x10));
        let opy = f.new_op(OpCode::IntZext, seq, vec![b]);
        let y = f.new_output(opy, 4, Address::new(reg, 0x18));
        // mask 0x1ffff → 17-bit logical value (flowsize 3) wider than b's 2 bytes.
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, y, 0x1ffff, false, false, false);
        let yrvn = *s.varmap.get(&y).unwrap();
        assert!(s.trace_backward(yrvn));
        assert_eq!(s.patchlist.len(), 1);
        assert_eq!(s.patchlist[0].ty, PatchType::Push);
    }

    #[test]
    fn trace_backward_subpiece_shifts_mask_up() {
        // y = SUBPIECE(w, 1): tracing y's low byte pulls w's mask 0xff << 8.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let w0 = f.new_input(4, Address::new(reg, 0x08));
        let opw = f.new_op(OpCode::Copy, seq, vec![w0]);
        let w = f.new_output(opw, 4, Address::new(reg, 0x10)); // written, so mask 0xff00 is allowed
        let c1 = f.new_const(4, 1);
        let opy = f.new_op(OpCode::Subpiece, seq, vec![w, c1]);
        let y = f.new_output(opy, 1, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, y, 0xff, false, false, false);
        let yrvn = *s.varmap.get(&y).unwrap();
        assert!(s.trace_backward(yrvn));
        assert_eq!(s.rops[0].opc, OpCode::Copy);
        let wrvn = *s.varmap.get(&w).expect("w linked");
        assert_eq!(s.rvnodes[wrvn].mask, 0xff00);
    }

    #[test]
    fn trace_backward_piece_low_part() {
        // y = PIECE(hi, lo): tracing a low byte follows the low input, mask unchanged.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let hi = f.new_input(2, Address::new(reg, 0x10));
        let lo = f.new_input(2, Address::new(reg, 0x14));
        let opy = f.new_op(OpCode::Piece, seq, vec![hi, lo]);
        let y = f.new_output(opy, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, y, 0xff, false, false, false);
        let yrvn = *s.varmap.get(&y).unwrap();
        assert!(s.trace_backward(yrvn));
        assert_eq!(s.rops[0].opc, OpCode::Copy);
        let lorvn = *s.varmap.get(&lo).expect("low part linked");
        assert_eq!(s.rvnodes[lorvn].mask, 0xff);
    }

    #[test]
    fn trace_backward_left_and_right_shift() {
        // y = a << 8: tracing mask 0xff00 pulls a's mask 0xff via a plain COPY.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let c8 = f.new_const(4, 8);
        let opy = f.new_op(OpCode::IntLeft, seq, vec![a, c8]);
        let y = f.new_output(opy, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, y, 0xff00, false, false, false);
        let yrvn = *s.varmap.get(&y).unwrap();
        assert!(s.trace_backward(yrvn));
        assert_eq!(s.rops[0].opc, OpCode::Copy);
        let arvn = *s.varmap.get(&a).expect("a linked");
        assert_eq!(s.rvnodes[arvn].mask, 0xff);
        drop(s);

        // y = a >> 8: tracing mask 0xff pulls a's mask 0xff00 (written a, unaligned mask).
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a0 = f.new_input(4, Address::new(reg, 0x08));
        let opa = f.new_op(OpCode::Copy, seq, vec![a0]);
        let a = f.new_output(opa, 4, Address::new(reg, 0x10));
        let c8 = f.new_const(4, 8);
        let opy = f.new_op(OpCode::IntRight, seq, vec![a, c8]);
        let y = f.new_output(opy, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, y, 0xff, false, false, false);
        let yrvn = *s.varmap.get(&y).unwrap();
        assert!(s.trace_backward(yrvn));
        assert_eq!(s.rops[0].opc, OpCode::Copy);
        let arvn = *s.varmap.get(&a).expect("a linked");
        assert_eq!(s.rvnodes[arvn].mask, 0xff00);
    }

    #[test]
    fn trace_forward_subpiece_terminal() {
        // y --SUBPIECE 0--> p (1 byte == flowsize): a terminal copy_patch.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let y = f.new_input(4, Address::new(reg, 0x10));
        let z0 = f.new_const(4, 0);
        let op1 = f.new_op(OpCode::Subpiece, seq, vec![y, z0]);
        let _p = f.new_output(op1, 1, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, y, 0xff, false, false, false);
        let yrvn = *s.varmap.get(&y).unwrap();
        assert!(s.trace_forward(yrvn));
        assert_eq!(s.patchlist.len(), 1);
        assert_eq!(s.patchlist[0].ty, PatchType::Copy);
        assert_eq!(s.pullcount, 1);
    }

    #[test]
    fn trace_forward_and_terminal_and_extension() {
        // y --AND 0xff--> out (1 byte == flowsize, mask justified): terminal copy_patch.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let y = f.new_input(4, Address::new(reg, 0x10));
        let c = f.new_const(4, 0xff);
        let op = f.new_op(OpCode::IntAnd, seq, vec![y, c]);
        let _out = f.new_output(op, 1, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, y, 0xff, false, false, false);
        let yrvn = *s.varmap.get(&y).unwrap();
        assert!(s.trace_forward(yrvn));
        assert_eq!(s.patchlist[0].ty, PatchType::Copy);
        drop(s);

        // y --AND 0xff--> out (4 bytes, consumes beyond the mask): a zero-padding extension_patch.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let y = f.new_input(4, Address::new(reg, 0x10));
        let c = f.new_const(4, 0xff);
        let op = f.new_op(OpCode::IntAnd, seq, vec![y, c]);
        let out = f.new_output(op, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        f.vn_mut(out).consume = 0xffff; // consumed beyond the logical byte
        let mut s = SubvariableFlow::new(&mut f, y, 0xff, false, false, false);
        let yrvn = *s.varmap.get(&y).unwrap();
        assert!(s.trace_forward(yrvn));
        assert_eq!(s.patchlist[0].ty, PatchType::Extension);
        assert_eq!(s.patchlist[0].slot, 0); // leastsigbit_set(0xff)
        assert_eq!(s.pullcount, 0); // extension is not a true modification
    }

    #[test]
    fn trace_forward_zext_becomes_copy() {
        // y --ZEXT--> out: shadow COPY into the widened output node.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let y = f.new_input(4, Address::new(reg, 0x10));
        let op = f.new_op(OpCode::IntZext, seq, vec![y]);
        let out = f.new_output(op, 8, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, y, 0xff, false, false, false);
        let yrvn = *s.varmap.get(&y).unwrap();
        assert!(s.trace_forward(yrvn));
        assert_eq!(s.rops[0].opc, OpCode::Copy);
        assert!(s.varmap.contains_key(&out));
    }

    #[test]
    fn trace_forward_equal_compare_bridge() {
        // y == const(0x12): a compare_patch bridging both sides (bitsize != 1).
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let y = f.new_input(4, Address::new(reg, 0x10));
        f.vn_mut(y).nzm = 0xff; // logical value confined to the mask
        let other = f.new_const(4, 0x12);
        let op = f.new_op(OpCode::IntEqual, seq, vec![y, other]);
        let _b = f.new_output(op, 1, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, y, 0xff, false, false, false);
        let yrvn = *s.varmap.get(&y).unwrap();
        assert!(s.trace_forward(yrvn));
        assert_eq!(s.patchlist[0].ty, PatchType::Compare);
        assert_eq!(s.pullcount, 1);
    }

    #[test]
    fn trace_forward_piece_high_and_low() {
        // Tracing the low input of a PIECE keeps the mask (fresh graph per part: the direct trace_*
        // calls don't clear the `mark` bits that do_trace would).
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let hi = f.new_input(2, Address::new(reg, 0x10));
        let lo = f.new_input(2, Address::new(reg, 0x14));
        let opy = f.new_op(OpCode::Piece, seq, vec![hi, lo]);
        let y = f.new_output(opy, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, lo, 0xff, false, false, false);
        let lorvn = *s.varmap.get(&lo).unwrap();
        assert!(s.trace_forward(lorvn));
        let yrvn = *s.varmap.get(&y).expect("output linked");
        assert_eq!(s.rvnodes[yrvn].mask, 0xff); // low part, unchanged

        // Tracing the high input shifts the mask up by 8*size(lo).
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let hi = f.new_input(2, Address::new(reg, 0x10));
        let lo = f.new_input(2, Address::new(reg, 0x14));
        let opy = f.new_op(OpCode::Piece, seq, vec![hi, lo]);
        let y = f.new_output(opy, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, hi, 0xff, false, false, false);
        let hirvn = *s.varmap.get(&hi).unwrap();
        assert!(s.trace_forward(hirvn));
        let yrvn = *s.varmap.get(&y).expect("output linked");
        assert_eq!(s.rvnodes[yrvn].mask, 0xff << 16);
    }

    /// `sum = <opc>(a, b)` where `a`/`b` are 4-byte COPY outputs, not function inputs. That detail is
    /// load-bearing: `set_replacement` refuses a sub-byte logical value on an INPUT varnode
    /// (subflow.cc:112, "Dont create input flag") and refuses any input whose mask excludes bit 0, so
    /// building the operands as inputs would make every assertion here pass or fail for the wrong
    /// reason. Each assertion needs its OWN graph — `trace_*` leaves `mark` bits behind (only
    /// `do_trace` clears them), so a reused one would poison the next trace.
    fn arith_flow(opc: OpCode) -> (Funcdata, VarnodeId, VarnodeId, VarnodeId) {
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let ain = f.new_input(4, Address::new(reg, 0x10));
        let bin = f.new_input(4, Address::new(reg, 0x14));
        let acp = f.new_op(OpCode::Copy, seq, vec![ain]);
        let a = f.new_output(acp, 4, Address::new(reg, 0x20));
        let bcp = f.new_op(OpCode::Copy, seq, vec![bin]);
        let b = f.new_output(bcp, 4, Address::new(reg, 0x24));
        let op = f.new_op(opc, seq, vec![a, b]);
        let sum = f.new_output(op, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        (f, a, b, sum)
    }

    #[test]
    fn arithmetic_arms_trace_both_directions() {
        // INT_ADD backward keeps the ADD for a multi-bit logical value (subflow.cc:720).
        let (mut f, a, b, sum) = arith_flow(OpCode::IntAdd);
        let mut s = SubvariableFlow::new(&mut f, sum, 0xff, false, false, false);
        let srvn = *s.varmap.get(&sum).unwrap();
        assert!(s.trace_backward(srvn));
        assert_eq!(s.rops[s.rvnodes[srvn].def.unwrap()].opc, OpCode::IntAdd);
        assert_eq!(s.rvnodes[*s.varmap.get(&a).unwrap()].mask, 0xff);
        assert_eq!(s.rvnodes[*s.varmap.get(&b).unwrap()].mask, 0xff);

        // On a SINGLE BIT the add becomes an XOR — nothing can carry out of one bit.
        let (mut f, _, _, sum) = arith_flow(OpCode::IntAdd);
        let mut s = SubvariableFlow::new(&mut f, sum, 1, false, false, false);
        let srvn = *s.varmap.get(&sum).unwrap();
        assert!(s.trace_backward(srvn));
        assert_eq!(s.rops[s.rvnodes[srvn].def.unwrap()].opc, OpCode::IntXor);

        // By the same argument a single-bit multiply is an AND (subflow.cc:781).
        let (mut f, _, _, sum) = arith_flow(OpCode::IntMult);
        let mut s = SubvariableFlow::new(&mut f, sum, 1, false, false, false);
        let srvn = *s.varmap.get(&sum).unwrap();
        assert!(s.trace_backward(srvn));
        assert_eq!(s.rops[s.rvnodes[srvn].def.unwrap()].opc, OpCode::IntAnd);

        // INT_ADD forward from an operand reaches the sum at the same mask (subflow.cc:456).
        let (mut f, a, _, sum) = arith_flow(OpCode::IntAdd);
        let mut s = SubvariableFlow::new(&mut f, a, 0xff, false, false, false);
        let arvn = *s.varmap.get(&a).unwrap();
        assert!(s.trace_forward(arvn));
        assert_eq!(s.rvnodes[*s.varmap.get(&sum).expect("output linked")].mask, 0xff);
    }

    #[test]
    fn sext_tracers_follow_sign_extension() {
        // traceBackwardSext INT_SEXT (subflow.cc:985): the flow reaches the pre-extension value,
        // but ONLY when the extension is from exactly the logical size.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let x = f.new_input(1, Address::new(reg, 0x10));
        let op = f.new_op(OpCode::IntSext, seq, vec![x]);
        let w = f.new_output(op, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, w, 0xff, false, true, false);
        let wrvn = *s.varmap.get(&w).unwrap();
        assert!(s.trace_backward_sext(wrvn));
        assert_eq!(s.rops[s.rvnodes[wrvn].def.unwrap()].opc, OpCode::Copy);
        assert_eq!(s.rvnodes[*s.varmap.get(&x).expect("pre-extension value linked")].mask, 0xff);

        // A sign-extended value arithmetically right-shifted keeps BOTH the logical value and the
        // shift amount (subflow.cc:991) — INT_SRIGHT survives as itself, unlike in the zext mode
        // where the same op has to be re-masked.
        // `v` must NOT be a function input: `set_replacement` refuses to assume an input is sign
        // extended into a wider container (subflow.cc:97, "Cannot assume input is sign extended"),
        // so an input operand would make this decline for a reason that has nothing to do with the
        // arm under test.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let vin = f.new_input(4, Address::new(reg, 0x10));
        let vcp = f.new_op(OpCode::Copy, seq, vec![vin]);
        let v = f.new_output(vcp, 4, Address::new(reg, 0x20));
        let amt = f.new_const(4, 3);
        let op = f.new_op(OpCode::IntSright, seq, vec![v, amt]);
        let r = f.new_output(op, 4, Address::new(reg, 0x18));
        recompute_consume(&mut f);
        let mut s = SubvariableFlow::new(&mut f, r, 0xff, false, true, false);
        let rrvn = *s.varmap.get(&r).unwrap();
        assert!(s.trace_backward_sext(rrvn));
        let rop = s.rvnodes[rrvn].def.unwrap();
        assert_eq!(s.rops[rop].opc, OpCode::IntSright);
        assert_eq!(s.rops[rop].input.len(), 2, "the shift amount must be preserved as input 1");
    }

    #[test]
    fn add_arms_refuse_when_logical_value_is_not_least_significant() {
        // subflow.cc:457/721 — a mask excluding bit 0 cannot account for the carry coming in from
        // below, so both directions decline.
        let (mut f, a, _, _) = arith_flow(OpCode::IntAdd);
        let mut s = SubvariableFlow::new(&mut f, a, 0xff00, false, false, false);
        let arvn = *s.varmap.get(&a).unwrap();
        assert!(!s.trace_forward(arvn));

        let (mut f, _, _, sum) = arith_flow(OpCode::IntAdd);
        let mut s = SubvariableFlow::new(&mut f, sum, 0xff00, false, false, false);
        let srvn = *s.varmap.get(&sum).unwrap();
        assert!(!s.trace_backward(srvn));
    }

    #[test]
    fn do_trace_and_replace_dissolves_and_subpiece() {
        // End-to-end: p = SUBPIECE((a & 0xff), 0) seeded like RuleSubvarSubpiece would.
        // do_trace builds the subgraph; do_replacement turns SUBPIECE into a COPY of a 1-byte AND.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let c = f.new_const(4, 0xff);
        let op0 = f.new_op(OpCode::IntAnd, seq, vec![a, c]);
        let y = f.new_output(op0, 4, Address::new(reg, 0x20));
        let z0 = f.new_const(4, 0);
        let op1 = f.new_op(OpCode::Subpiece, seq, vec![y, z0]);
        let p = f.new_output(op1, 1, Address::new(reg, 0x28));
        let sid = f.new_const(8, ram.0 as u64);
        let ptr = f.new_input(8, Address::new(reg, 0x30));
        let store = f.new_op(OpCode::Store, seq, vec![sid, ptr, p]);
        f.set_blocks(vec![BlockBasic { ops: vec![op0, op1, store], ..Default::default() }]);
        parent_all_to_block0(&mut f);
        recompute_consume(&mut f);

        // Seed root = y with mask calc_mask(1) << 0 == 0xff (the SUBPIECE's logical value).
        let mut s = SubvariableFlow::new(&mut f, y, 0xff, false, false, false);
        assert!(s.do_trace());
        // Exactly one shadow op — the narrow AND (the forward pass skips it via the mark check).
        assert_eq!(s.rops.len(), 1);
        assert_eq!(s.rops[0].opc, OpCode::IntAnd);
        assert_eq!(s.patchlist.len(), 1);
        assert_eq!(s.patchlist[0].ty, PatchType::Copy);
        s.do_replacement();
        drop(s);

        // SUBPIECE is now a COPY of a fresh 1-byte value.
        assert_eq!(f.op(op1).code(), OpCode::Copy);
        assert_eq!(f.op(op1).num_inputs(), 1);
        let cin = f.op(op1).input(0).unwrap();
        assert_eq!(f.vn(cin).size, 1);
        // A narrow 1-byte INT_AND was materialized (paralleling the original).
        let narrow = (0..f.num_ops() as u32)
            .map(OpId)
            .find(|&o| !f.op(o).is_dead() && f.op(o).code() == OpCode::IntAnd && o != op0)
            .expect("narrow AND created");
        let ao = f.op(narrow).output.unwrap();
        assert_eq!(f.vn(ao).size, 1);
    }

    #[test]
    fn subvar_zext_narrows_a_zext_fed_return() {
        // RAX:8 = ZEXT(u:4); RETURN(retaddr, RAX:8). RuleSubvarZext seeds the flow on the ZEXT
        // output; try_return_pull lets the RETURN take the 4-byte logical value → int4-width return.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let u = f.new_input(4, Address::new(reg, 0x10));
        let op_z = f.new_op(OpCode::IntZext, seq, vec![u]);
        let rax = f.new_output(op_z, 8, Address::new(reg, 0x0));
        let retaddr = f.new_input(8, Address::new(reg, 0x288));
        let ret = f.new_op(OpCode::Return, seq, vec![retaddr, rax]);
        f.set_blocks(vec![BlockBasic { ops: vec![op_z, ret], ..Default::default() }]);
        parent_all_to_block0(&mut f);
        // ActionNonzeroMask precedes ActionConsume in the pipeline: nzm(RAX) = 0xffffffff for the
        // ZEXT 4→8, and `gather_consumed_return` seeds the RETURN value with minimalmask(nzm) —
        // which is exactly what makes a ZEXT-padded return narrowable in Ghidra.
        f.vn_mut(rax).nzm = 0xffffffff;
        recompute_consume(&mut f);

        // Seed as RuleSubvarZext does: root = ZEXT output, mask = calc_mask(input size) = 0xffffffff.
        let mut s = SubvariableFlow::new(&mut f, rax, 0xffffffff, false, false, false);
        assert!(s.do_trace());
        s.do_replacement();
        drop(s);
        // The RETURN's value input (slot 1) is now the 4-byte logical value, not the 8-byte ZEXT.
        let v = f.op(ret).input(1).unwrap();
        assert_eq!(f.vn(v).size, 4);
    }

    #[test]
    fn try_return_pull_refuses_when_upper_bytes_consumed() {
        // If bits outside the logical mask are consumed (the full 8-byte register is used), the
        // return must NOT be truncated (Ghidra subflow.cc:243-245). do_trace aborts, RETURN unchanged.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let u = f.new_input(4, Address::new(reg, 0x10));
        let op_z = f.new_op(OpCode::IntZext, seq, vec![u]);
        let rax = f.new_output(op_z, 8, Address::new(reg, 0x0));
        let retaddr = f.new_input(8, Address::new(reg, 0x288));
        let ret = f.new_op(OpCode::Return, seq, vec![retaddr, rax]);
        f.set_blocks(vec![BlockBasic { ops: vec![op_z, ret], ..Default::default() }]);
        parent_all_to_block0(&mut f);
        f.vn_mut(rax).consume = u64::MAX; // upper 4 bytes consumed → outside mask 0xffffffff

        let mut s = SubvariableFlow::new(&mut f, rax, 0xffffffff, false, false, false);
        assert!(!s.do_trace()); // try_return_pull refuses; trace aborts
        assert_eq!(f.vn(f.op(ret).input(1).unwrap()).size, 8); // RETURN value unchanged
    }

    #[test]
    fn try_return_pull_refuses_return_address_slot() {
        // A value flowing into slot 0 is the return-address container, not a return value — refuse
        // (Ghidra subflow.cc:241). do_trace aborts.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let u = f.new_input(4, Address::new(reg, 0x10));
        let op_z = f.new_op(OpCode::IntZext, seq, vec![u]);
        let rax = f.new_output(op_z, 8, Address::new(reg, 0x0));
        let ret = f.new_op(OpCode::Return, seq, vec![rax]); // rax at slot 0
        f.set_blocks(vec![BlockBasic { ops: vec![op_z, ret], ..Default::default() }]);
        parent_all_to_block0(&mut f);
        let mut s = SubvariableFlow::new(&mut f, rax, 0xffffffff, false, false, false);
        assert!(!s.do_trace());
    }

    #[test]
    fn try_call_pull_narrows_a_call_argument() {
        // RAX:8 = ZEXT(u:4); CALL(target, RAX:8). RuleSubvarZext seeds the flow on the ZEXT output;
        // try_call_pull (Ghidra subflow.cc:208) lets the CALL take the 4-byte logical value.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let u = f.new_input(4, Address::new(reg, 0x10));
        let op_z = f.new_op(OpCode::IntZext, seq, vec![u]);
        let rax = f.new_output(op_z, 8, Address::new(reg, 0x0));
        let target = f.new_const(8, 0x400440);
        let call = f.new_op(OpCode::Call, seq, vec![target, rax]);
        f.set_blocks(vec![BlockBasic { ops: vec![op_z, call], ..Default::default() }]);
        parent_all_to_block0(&mut f);
        // nzm(RAX) = 0xffffffff (ZEXT 4→8); `mark_consumed_parameters` seeds the CALL argument
        // with minimalmask(nzm) → only the low 4 bytes consumed → truncatable.
        f.vn_mut(rax).nzm = 0xffffffff;
        recompute_consume(&mut f);

        let mut s = SubvariableFlow::new(&mut f, rax, 0xffffffff, false, false, false);
        assert!(s.do_trace());
        s.do_replacement();
        drop(s);
        // The CALL's parameter (slot 1) is now the 4-byte logical value, not the 8-byte ZEXT.
        assert_eq!(f.vn(f.op(call).input(1).unwrap()).size, 4);
    }

    #[test]
    fn try_call_pull_refuses_while_input_active() {
        // While the call's parameters are in active recovery (Ghidra isInputActive, subflow.cc:217),
        // don't trim. do_trace aborts, the CALL argument stays 8-byte.
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let u = f.new_input(4, Address::new(reg, 0x10));
        let op_z = f.new_op(OpCode::IntZext, seq, vec![u]);
        let rax = f.new_output(op_z, 8, Address::new(reg, 0x0));
        let target = f.new_const(8, 0x400440);
        let call = f.new_op(OpCode::Call, seq, vec![target, rax]);
        f.set_blocks(vec![BlockBasic { ops: vec![op_z, call], ..Default::default() }]);
        parent_all_to_block0(&mut f);
        f.vn_mut(rax).consume = 0xffffffff;
        f.active_inputs.insert(call, super::super::fspec::ParamActive::new(None));

        let mut s = SubvariableFlow::new(&mut f, rax, 0xffffffff, false, false, false);
        assert!(!s.do_trace()); // try_call_pull refuses; trace aborts
        assert_eq!(f.vn(f.op(call).input(1).unwrap()).size, 8); // CALL argument unchanged
    }

    #[test]
    fn try_call_pull_refuses_call_target_slot() {
        // A value flowing into slot 0 is the call target, not a parameter — refuse (subflow.cc:210).
        let (mut f, reg, ram) = mkfd();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let u = f.new_input(4, Address::new(reg, 0x10));
        let op_z = f.new_op(OpCode::IntZext, seq, vec![u]);
        let rax = f.new_output(op_z, 8, Address::new(reg, 0x0));
        let call = f.new_op(OpCode::Call, seq, vec![rax]); // rax at slot 0 (the call target)
        f.set_blocks(vec![BlockBasic { ops: vec![op_z, call], ..Default::default() }]);
        parent_all_to_block0(&mut f);
        f.vn_mut(rax).consume = 0xffffffff;
        let mut s = SubvariableFlow::new(&mut f, rax, 0xffffffff, false, false, false);
        assert!(!s.do_trace());
    }
}
