//! Pointer-arithmetic recovery — a faithful port of Ghidra's `RulePtrArith` and its helper
//! `AddTreeState` (`ruleaction.cc`). A string of `INT_ADD`s rooted on a pointer-typed base is
//! rewritten into `PTRADD(base, index, elemsize)` / `PTRSUB(base, offset)` ops, so the printer can
//! render `base[i]` (array indexing) and `base->field` (struct access) instead of `*(T *)(p + k)`.
//!
//! Gated on `Funcdata::has_type_recovery_started` and run after `ActionInferTypes` has committed
//! data-types onto varnodes (`Varnode::get_type`). The pointer type is the read-facing type
//! (`getTypeReadFacing`), which for mosura's primitive lattice equals the committed type.
//!
//! Faithfully deferred (Ghidra has them; not reached by the primitive-lattice corpus): the
//! `TypePointerRel` relative-pointer alternate form (`initAlternateForm`); the
//! `distributeIntMultAdd`/`collapseIntMultMult` distribution path (declined when needed); the
//! `nearestArrayedComponent` array-hint refinement inside a struct (falls back to `getSubType`);
//! and the union `inheritResolution`/`isTypeRecoveryExceeded`/`setStopTypePropagation` bookkeeping.

use super::action::Rule;
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::types::Datatype;
use super::varnode::VarnodeId;

/// `calc_mask(size)` — a low `size`-byte all-ones mask.
fn calc_mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * size)) - 1
    }
}

/// Ghidra `sign_extend(val, bit)` — sign-extend the value treating bit index `bit` as the sign.
fn sign_extend(val: u64, bit: u32) -> i64 {
    if bit >= 63 {
        val as i64
    } else {
        let sh = 63 - bit;
        ((val << sh) as i64) >> sh
    }
}

/// Ghidra `uintb_negate(in, size)` — bitwise-NOT masked to `size` bytes.
fn uintb_negate(val: u64, size: u32) -> u64 {
    (!val) & calc_mask(size)
}

/// The read-facing data-type of a varnode (Ghidra `Varnode::getTypeReadFacing`). For the
/// primitive lattice this is the committed type; unions/resolution are not modelled.
fn type_read_facing(f: &Funcdata, v: VarnodeId) -> Datatype {
    f.vn(v).get_type()
}

/// The input slot at which `vn` appears in `op` (Ghidra `PcodeOp::getSlot`).
fn get_slot(f: &Funcdata, op: OpId, vn: VarnodeId) -> usize {
    f.op(op).inrefs.iter().position(|&v| v == vn).unwrap_or(0)
}

/// Ghidra's `RulePtrArith` (`ruleaction.cc`): convert integer arithmetic on a pointer into
/// `PTRADD`/`PTRSUB`.
pub struct RulePtrArith;

impl Rule for RulePtrArith {
    fn name(&self) -> &str {
        "ptrarith"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAdd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if !data.has_type_recovery_started() {
            return 0;
        }
        // Search for a pointer-typed input
        let mut slot = None;
        for s in 0..data.op(op).num_inputs() {
            let v = data.op(op).input(s).unwrap();
            if type_read_facing(data, v).is_pointer() {
                slot = Some(s);
                break;
            }
        }
        let Some(slot) = slot else { return 0 };
        if evaluate_pointer_expression(data, op, slot) != 2 {
            return 0;
        }
        if !verify_preferred_pointer(data, op, slot) {
            return 0;
        }
        let mut state = AddTreeState::new(data, op, slot);
        if state.apply(data) {
            return 1;
        }
        if state.init_alternate_form() && state.apply(data) {
            return 1;
        }
        0
    }
}

/// Ghidra `RulePushPtr` (ruleaction.cc:6834): push a pointer-typed Varnode to the bottom of its
/// additive expression, so the pointer is added *last* onto the offset calculation. This normalizes
/// `INT_ADD(INT_ADD(ptr, a), b)` into `INT_ADD(ptr, INT_ADD(a, b))` so the later `RulePtrArith` can
/// root the pointer arithmetic directly at the pointer. It is the piece that lets a shared frame
/// base (`RSP - k`, itself `INT_ADD(RSP_input, -k)`) feeding a variable-indexed array LOAD
/// `framebase + i*elem` reroot at `RSP_input`, so the whole tree folds to `PTRSUB(RSP, array) + i`.
/// Fires only when `evaluatePointerExpression` returns 1 (a push is needed). Registered before
/// `RulePtrArith` (Ghidra `actprop2`, coreaction.cc:5664).
pub struct RulePushPtr;

impl Rule for RulePushPtr {
    fn name(&self) -> &str {
        "pushptr"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAdd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if !data.has_type_recovery_started() {
            return 0;
        }
        // Search for a pointer-typed input.
        let mut slot = None;
        for s in 0..data.op(op).num_inputs() {
            let v = data.op(op).input(s).unwrap();
            if type_read_facing(data, v).is_pointer() {
                slot = Some(s);
                break;
            }
        }
        let Some(slot) = slot else { return 0 };
        if evaluate_pointer_expression(data, op, slot) != 1 {
            return 0;
        }

        let vni = data.op(op).input(slot).unwrap(); // the pointer
        let vnadd2 = data.op(op).input(1 - slot).unwrap(); // the addend pushed down past the pointer
        let vn = data.op(op).output.unwrap();

        // Ghidra's collectDuplicateNeeds/duplicateNeed CSE (for a shared, multi-descendant push) is
        // omitted: `splitUses` gives each frame base a single descendant, so the push has a lone
        // consumer and the duplicate path is unreached. Each descendant `decop = INT_ADD(vn, vnadd1)`
        // is rewritten to `INT_ADD(vni, INT_ADD(vnadd1, vnadd2))`.
        while let Some(decop) = data.vn(vn).descend.first().copied() {
            let j = get_slot(data, decop, vn);
            let vnadd1 = data.op(decop).input(1 - j).unwrap();
            // newop = INT_ADD(vnadd1, vnadd2), a fresh unique sized like vnadd1 (Ghidra newUniqueOut).
            let newop = data.new_op_before(decop, OpCode::IntAdd, vec![vnadd1, vnadd2]);
            let newout = data.op(newop).output.unwrap();
            data.op_set_input(decop, 0, vni); // pointer added last
            data.op_set_input(decop, 1, newout);
        }
        if !data.vn(vn).is_auto_live() {
            data.op_destroy(op);
        }
        1
    }
}

/// Ghidra `RulePtrArith::evaluatePointerExpression`: is the expression rooted at this INT_ADD
/// ready for conversion? Returns 0 (no action), 1 (a push is needed first), or 2 (convert now).
fn evaluate_pointer_expression(f: &Funcdata, op: OpId, slot: usize) -> i32 {
    let mut res = 1; // Assume we are going to push
    let mut count = 0;
    let ptr_base = f.op(op).input(slot).unwrap();
    if f.vn(ptr_base).is_free() && !f.vn(ptr_base).is_constant() {
        return 0;
    }
    let other = f.op(op).input(1 - slot).unwrap();
    if type_read_facing(f, other).is_pointer() {
        res = 2;
    }
    let out_vn = f.op(op).output.unwrap();
    for dec_op in f.vn(out_vn).descend.clone() {
        count += 1;
        let opc = f.op(dec_op).code();
        if opc == OpCode::IntAdd {
            let dslot = get_slot(f, dec_op, out_vn);
            let other_vn = f.op(dec_op).input(1 - dslot).unwrap();
            if f.vn(other_vn).is_free() && !f.vn(other_vn).is_constant() {
                return 0; // No action if the data-flow isn't fully linked
            }
            if type_read_facing(f, other_vn).is_pointer() {
                res = 2; // Do not push in the presence of other pointers
            }
        } else if (opc == OpCode::Load || opc == OpCode::Store)
            && f.op(dec_op).input(1) == Some(out_vn)
        {
            if f.vn(ptr_base).is_spacebase()
                && (f.vn(ptr_base).is_input() || f.vn(ptr_base).is_constant())
                && f.vn(other).is_constant()
            {
                return 0;
            }
            res = 2;
        } else {
            res = 2; // Any other op besides ADD, do not push
        }
    }
    if count == 0 {
        return 0;
    }
    if count > 1 && f.vn(out_vn).is_spacebase() {
        return 0; // For the RESULT to be a spacebase pointer it must have only 1 descendant
    }
    res
}

/// Ghidra `RulePtrArith::verifyPreferredPointer`: does `slot` hold the preferred base pointer (vs
/// an earlier pointer further down the ADD tree that should be the base instead)?
fn verify_preferred_pointer(f: &Funcdata, op: OpId, slot: usize) -> bool {
    let vn = f.op(op).input(slot).unwrap();
    if !f.vn(vn).is_written() {
        return true;
    }
    let pre_op = f.vn(vn).def.unwrap();
    if f.op(pre_op).code() != OpCode::IntAdd {
        return true;
    }
    let mut preslot = 0;
    if !type_read_facing(f, f.op(pre_op).input(0).unwrap()).is_pointer() {
        preslot = 1;
        if !type_read_facing(f, f.op(pre_op).input(1).unwrap()).is_pointer() {
            return true;
        }
    }
    evaluate_pointer_expression(f, pre_op, preslot) != 1
}

/// Ghidra `TypeSpacebase::getSubType` (type.cc:2947) over the recovered `ScopeLocal` table: the
/// symbol containing frame offset `off`, with the residual into it. `None` when no symbol is mapped
/// (Ghidra returns a `TYPE_UNKNOWN`/0 stand-in there; callers treat `None` accordingly).
fn sb_get_subtype(syms: &[super::varmap::StackSymbol], off: i64) -> Option<(Datatype, i64)> {
    syms.iter()
        .find(|s| s.start <= off && off < s.start + s.size as i64)
        .map(|s| (s.ty.clone(), off - s.start))
}

/// Ghidra `TypeSpacebase::nearestArrayedComponentBackward` (type.cc:3020): if the symbol the offset
/// lands inside is an ARRAY, return `(element_size, residual_into_it, array_size)`.
fn sb_nearest_backward(syms: &[super::varmap::StackSymbol], off: i64) -> Option<(u64, i64, i64)> {
    let (ty, newoff) = sb_get_subtype(syms, off)?;
    if let Datatype::Array(elem, _) = &ty {
        return Some((elem.align_size() as u64, newoff, ty.size() as i64));
    }
    None
}

/// Ghidra `TypeSpacebase::nearestArrayedComponentForward` (type.cc:2971): find the nearest ARRAY
/// symbol *after* `off`. Returns `(element_size, residual = off - array_start)` (the residual is
/// negative because the array starts after the offset). The symbol at the next boundary must start
/// there (Ghidra's `getOffset() != 0` reject).
fn sb_nearest_forward(syms: &[super::varmap::StackSymbol], off: i64) -> Option<(u64, i64)> {
    // The boundary to look past: the end of the symbol starting exactly at `off`, else a fixed
    // window (Ghidra `addr + 32`).
    let next_addr = match syms.iter().find(|s| s.start == off) {
        Some(s) => s.start + s.size as i64,
        None => off + 32,
    };
    if next_addr < off {
        return None; // don't let the address wrap
    }
    let sym = syms.iter().find(|s| s.start == next_addr)?;
    if let Datatype::Array(elem, _) = &sym.ty {
        return Some((elem.align_size() as u64, off - sym.start));
    }
    None
}

/// Ghidra `AddTreeState` — the analysis + rewrite state for one pointer-rooted ADD tree. Read-only
/// while spanning the tree; mutates the graph only in `build_tree`.
struct AddTreeState {
    base_op: OpId,
    ptr: VarnodeId,
    ct: Datatype,        // the pointer data-type
    base_type: Datatype, // the type being pointed at
    ptrsize: u32,
    size: i64, // size of the pointed-at type (address units), 0 = open-ended
    base_slot: usize,
    biggest_non_mult_coeff: u64,
    ptrmask: u64,
    offset: u64,  // bytes we dig into the base data-type
    correct: u64, // bytes being double counted
    multiple: Vec<VarnodeId>,
    coeff: Vec<i64>,
    nonmult: Vec<VarnodeId>,
    distribute_op: Option<OpId>,
    multsum: u64,
    nonmultsum: u64,
    prevent_distribution: bool,
    is_distribute_used: bool,
    is_subtype: bool,
    valid: bool,
    is_degenerate: bool,
}

impl AddTreeState {
    fn new(f: &Funcdata, op: OpId, slot: usize) -> AddTreeState {
        let ptr = f.op(op).input(slot).unwrap();
        let ct = type_read_facing(f, ptr);
        let ptrsize = f.vn(ptr).size;
        let ptrmask = calc_mask(ptrsize);
        let base_type = ct.ptr_to().cloned().unwrap_or(Datatype::Unknown(1));
        // mosura models no variable-length or relative pointers (pRelType is always null).
        let size = base_type.align_size() as i64;
        let unitsize = 1i64; // x86 ram is byte-addressable: addressToByteInt(1) == 1
        let is_degenerate = size <= unitsize && size > 0;
        AddTreeState {
            base_op: op,
            ptr,
            ct,
            base_type,
            ptrsize,
            size,
            base_slot: slot,
            biggest_non_mult_coeff: 0,
            ptrmask,
            offset: 0,
            correct: 0,
            multiple: Vec::new(),
            coeff: Vec::new(),
            nonmult: Vec::new(),
            distribute_op: None,
            multsum: 0,
            nonmultsum: 0,
            prevent_distribution: false,
            is_distribute_used: false,
            is_subtype: false,
            valid: true,
            is_degenerate,
        }
    }

    /// Ghidra `AddTreeState::clear` — reset the accumulators for a fresh tree traversal.
    fn clear(&mut self) {
        self.multsum = 0;
        self.nonmultsum = 0;
        self.biggest_non_mult_coeff = 0;
        self.multiple.clear();
        self.coeff.clear();
        self.nonmult.clear();
        self.correct = 0;
        self.offset = 0;
        self.valid = true;
        self.is_distribute_used = false;
        self.is_subtype = false;
        self.distribute_op = None;
    }

    /// mosura has no relative pointers, so there is no alternate form (Ghidra returns false when
    /// `pRelType` is null).
    fn init_alternate_form(&mut self) -> bool {
        false
    }

    /// Ghidra `AddTreeState::checkMultTerm`: examine an INT_MULT in the middle of the tree.
    fn check_mult_term(&mut self, f: &Funcdata, vn: VarnodeId, op: OpId, tree_coeff: u64) -> bool {
        let vnconst = f.op(op).input(1).unwrap();
        let vnterm = f.op(op).input(0).unwrap();
        if f.vn(vnterm).is_free() {
            self.valid = false;
            return false;
        }
        if f.vn(vnconst).is_constant() {
            let val = f.vn(vnconst).constant_value().wrapping_mul(tree_coeff) & self.ptrmask;
            let sval = sign_extend(val, f.vn(vn).size * 8 - 1);
            let rem = if self.size == 0 { sval } else { sval % self.size };
            if rem != 0 {
                if val >= self.size as u64 && self.size != 0 {
                    self.valid = false; // Size is too big: pointer type must be wrong
                    return false;
                }
                if !self.prevent_distribution {
                    if let Some(def) = f.vn(vnterm).def {
                        if f.op(def).code() == OpCode::IntAdd {
                            if self.distribute_op.is_none() {
                                self.distribute_op = Some(op);
                            }
                            return self.span_add_tree(f, def, val);
                        }
                    }
                }
                let vncoeff = if sval < 0 { (-sval) as u64 } else { sval as u64 };
                if vncoeff > self.biggest_non_mult_coeff {
                    self.biggest_non_mult_coeff = vncoeff;
                }
                return true;
            }
            if tree_coeff != 1 {
                self.is_distribute_used = true;
            }
            self.multiple.push(vnterm);
            self.coeff.push(sval);
            return false;
        }
        if tree_coeff > self.biggest_non_mult_coeff {
            self.biggest_non_mult_coeff = tree_coeff;
        }
        true
    }

    /// Ghidra `AddTreeState::checkTerm`: classify one term of the tree, recursing into sub-ADDs.
    fn check_term(&mut self, f: &Funcdata, vn: VarnodeId, tree_coeff: u64) -> bool {
        if vn == self.ptr {
            return false;
        }
        if f.vn(vn).is_constant() {
            let val = f.vn(vn).constant_value().wrapping_mul(tree_coeff);
            let sval = sign_extend(val, f.vn(vn).size * 8 - 1);
            let rem = if self.size == 0 { sval } else { sval % self.size };
            if rem != 0 {
                // constant is not a multiple of size
                if tree_coeff != 1
                    && matches!(self.base_type, Datatype::Array(..) | Datatype::Struct(..))
                {
                    self.is_distribute_used = true;
                }
                self.nonmultsum = self.nonmultsum.wrapping_add(val) & self.ptrmask;
                return true;
            }
            if tree_coeff != 1 {
                self.is_distribute_used = true;
            }
            self.multsum = self.multsum.wrapping_add(val) & self.ptrmask;
            return false;
        }
        if f.vn(vn).is_written() {
            let def = f.vn(vn).def.unwrap();
            match f.op(def).code() {
                OpCode::IntAdd => return self.span_add_tree(f, def, tree_coeff),
                OpCode::Copy => {
                    self.valid = false; // Not finished reducing yet
                    return false;
                }
                OpCode::IntMult => return self.check_mult_term(f, vn, def, tree_coeff),
                _ => {}
            }
        } else if f.vn(vn).is_free() {
            self.valid = false;
            return false;
        }
        if tree_coeff > self.biggest_non_mult_coeff {
            self.biggest_non_mult_coeff = tree_coeff;
        }
        true
    }

    /// Ghidra `AddTreeState::spanAddTree`: walk the sub-tree under `op` accumulating multiples and
    /// non-multiples. Returns true if the sub-tree contains no multiple of the base size.
    fn span_add_tree(&mut self, f: &Funcdata, op: OpId, tree_coeff: u64) -> bool {
        let in0 = f.op(op).input(0).unwrap();
        let in1 = f.op(op).input(1).unwrap();
        let one_is_non = self.check_term(f, in0, tree_coeff);
        if !self.valid {
            return false;
        }
        let two_is_non = self.check_term(f, in1, tree_coeff);
        if !self.valid {
            return false;
        }
        // pRelType is null in mosura → no relative-pointer guard
        if one_is_non && two_is_non {
            return true;
        }
        if one_is_non {
            self.nonmult.push(in0);
        }
        if two_is_non {
            self.nonmult.push(in1);
        }
        false
    }

    /// Ghidra `AddTreeState::hasMatchingSubType` (ruleaction.cc:6064): find the sub-component nearest
    /// `off`, returning the residual offset into it (`newoff`) or `None` if there is no match. For a
    /// `TYPE_SPACEBASE` base the lookup goes through the recovered `ScopeLocal` symbol table
    /// (`recover_scope`): with no array index (`array_hint == 0`) `getSubType` is never null so it
    /// always matches; with an index it resolves the nearest ARRAY component (backward = the array the
    /// offset lands inside, forward = the next array after it) whose element size matches the index
    /// coefficient, so the `PTRSUB` folds to the array's base with the residual folded back into the
    /// additive tail (Ghidra `TypeSpacebase::nearestArrayedComponent{Backward,Forward}`, type.cc:2971).
    fn has_matching_sub_type(&self, f: &Funcdata, off: i64, array_hint: u64) -> Option<i64> {
        if matches!(self.base_type, Datatype::Spacebase(_)) {
            let syms = super::varmap::recover_scope(f);
            if array_hint == 0 {
                // getSubType is never null for a spacebase (TYPE_UNKNOWN when no symbol) — always match.
                return Some(sb_get_subtype(&syms, off).map(|(_, no)| no).unwrap_or(0));
            }
            // Ghidra hasMatchingSubType (ruleaction.cc:6064): backward (the array the offset lands in),
            // with an early return when its element size matches and the offset is in-bounds.
            let before = sb_nearest_backward(&syms, off);
            if let Some((el_before, off_before, arr_size)) = before {
                if (array_hint == 1 || el_before == array_hint) && off_before >= 0 && off_before < arr_size
                {
                    return Some(off_before);
                }
            }
            // Otherwise consider the array forward of the offset, and pick the nearer of the two.
            let after = sb_nearest_forward(&syms, off);
            return match (before, after) {
                (None, None) => sb_get_subtype(&syms, off).map(|(_, no)| no),
                (None, Some((_, noa))) => Some(noa),
                (Some((_, nob, _)), None) => Some(nob),
                (Some((elb, nob, _)), Some((ela, noa))) => {
                    // Pick the nearer array; a non-matching element size is penalised (Ghidra +0x1000).
                    let mut db = nob.unsigned_abs();
                    let mut da = noa.unsigned_abs();
                    if array_hint != 1 {
                        if elb != array_hint {
                            db += 0x1000;
                        }
                        if ela != array_hint {
                            da += 0x1000;
                        }
                    }
                    Some(if da < db { noa } else { nob })
                }
            };
        }
        self.base_type.get_subtype(off).map(|(_, newoff)| newoff)
    }

    /// Ghidra `AddTreeState::calcSubtype`: settle the sub-type offset (→ a PTRSUB) vs. a plain
    /// element index (→ a PTRADD).
    fn calc_subtype(&mut self, f: &Funcdata) {
        let tmpoff = self.multsum.wrapping_add(self.nonmultsum) & self.ptrmask;
        if self.size == 0 || tmpoff < self.size as u64 {
            self.offset = tmpoff;
        } else {
            let stmpoff = sign_extend(tmpoff, self.ptrsize * 8 - 1) % self.size;
            if stmpoff >= 0 {
                self.offset = stmpoff as u64;
            } else if matches!(self.base_type, Datatype::Struct(..))
                && self.biggest_non_mult_coeff != 0
                && self.multsum == 0
            {
                self.offset = tmpoff;
            } else {
                self.offset = (stmpoff + self.size) as u64;
            }
        }
        self.correct = self.nonmultsum; // Non-multiple constants are double counted
        self.multsum = tmpoff.wrapping_sub(self.offset) & self.ptrmask; // extra multiples of size
        if self.nonmult.is_empty() {
            if self.multsum == 0 && self.multiple.is_empty() {
                self.valid = false; // Is there anything at all?
                return;
            }
            self.is_subtype = false; // No offsets INTO the pointer
        } else if matches!(self.base_type, Datatype::Spacebase(..)) {
            // Ghidra `AddTreeState::calcSubtype` TYPE_SPACEBASE arm (ruleaction.cc:6286): a spacebase
            // pointee always has a matching sub-type (`getSubType` is never null — TYPE_UNKNOWN when no
            // symbol), so any offset off the stack pointer folds into a `PTRSUB`. `hasMatchingSubType`
            // returns the residual into the mapped ScopeLocal variable: for a variable-indexed array it
            // resolves the array's base (via `nearestArrayedComponent`) and folds the residual back into
            // the additive tail, so `PTRSUB(RSP, array_start) + index` renders `axStack_N[index]`.
            let offsetbytes = sign_extend(self.offset, self.ptrsize * 8 - 1); // wordsize 1 → identity
            let extra = match self.has_matching_sub_type(f, offsetbytes, self.biggest_non_mult_coeff) {
                Some(e) => e,
                None => {
                    self.valid = false; // Cannot find mapped variable but nonmult is non-empty
                    return;
                }
            };
            self.offset = self.offset.wrapping_sub(extra as u64) & self.ptrmask;
            self.correct = self.correct.wrapping_sub(extra as u64) & self.ptrmask;
            self.is_subtype = true;
        } else if matches!(self.base_type, Datatype::Struct(..)) {
            let soffset = sign_extend(self.offset, self.ptrsize * 8 - 1);
            let offsetbytes = soffset; // wordsize 1 → byteToAddressInt is identity
            let extra = match self.has_matching_sub_type(f, offsetbytes, self.biggest_non_mult_coeff) {
                Some(e) => e,
                None => {
                    if offsetbytes < 0 || offsetbytes >= self.base_type.size() as i64 {
                        self.valid = false; // Out of structure's bounds
                        return;
                    }
                    0 // No field, but pretend there is something there
                }
            };
            self.offset = self.offset.wrapping_sub(extra as u64) & self.ptrmask;
            self.correct = self.correct.wrapping_sub(extra as u64) & self.ptrmask;
            self.is_subtype = true;
        } else if matches!(self.base_type, Datatype::Array(..)) {
            self.is_subtype = true;
            self.correct = self.correct.wrapping_sub(self.offset) & self.ptrmask;
            self.offset = 0;
        } else {
            // No struct or array, but nonmult is non-empty: substructure we don't know about
            self.valid = false;
        }
        // pRelType is null → no final relative-pointer adjustment
    }

    /// Ghidra `AddTreeState::buildMultiples`: build the sub-tree that is a multiple of the base
    /// size (the PTRADD index). Returns the index Varnode, or null if there are no multiples.
    fn build_multiples(&mut self, f: &mut Funcdata) -> Option<VarnodeId> {
        let smultsum = sign_extend(self.multsum, self.ptrsize * 8 - 1);
        let const_coeff = if self.size == 0 {
            0
        } else {
            ((smultsum / self.size) as u64) & self.ptrmask
        };
        let mut res = if const_coeff == 0 {
            None
        } else {
            Some(f.new_const(self.ptrsize, const_coeff))
        };
        for i in 0..self.multiple.len() {
            let final_coeff = if self.size == 0 {
                0
            } else {
                ((self.coeff[i] / self.size) as u64) & self.ptrmask
            };
            let mut vn = self.multiple[i];
            if final_coeff != 1 {
                let c = f.new_const(self.ptrsize, final_coeff);
                let op = f.new_op_before(self.base_op, OpCode::IntMult, vec![vn, c]);
                vn = f.op(op).output.unwrap();
            }
            res = match res {
                None => Some(vn),
                Some(r) => {
                    let op = f.new_op_before(self.base_op, OpCode::IntAdd, vec![vn, r]);
                    Some(f.op(op).output.unwrap())
                }
            };
        }
        res
    }

    /// Ghidra `AddTreeState::buildExtra`: sum the terms that are not multiples of the base size,
    /// correcting for double-counted constants.
    fn build_extra(&mut self, f: &mut Funcdata) -> Option<VarnodeId> {
        let mut res: Option<VarnodeId> = None;
        for i in 0..self.nonmult.len() {
            let vn = self.nonmult[i];
            if f.vn(vn).is_constant() {
                self.correct = self.correct.wrapping_sub(f.vn(vn).constant_value());
                continue;
            }
            res = match res {
                None => Some(vn),
                Some(r) => {
                    let op = f.new_op_before(self.base_op, OpCode::IntAdd, vec![vn, r]);
                    Some(f.op(op).output.unwrap())
                }
            };
        }
        self.correct &= self.ptrmask;
        if self.correct != 0 {
            let c = f.new_const(self.ptrsize, uintb_negate(self.correct.wrapping_sub(1), self.ptrsize));
            res = match res {
                None => Some(c),
                Some(r) => {
                    let op = f.new_op_before(self.base_op, OpCode::IntAdd, vec![c, r]);
                    Some(f.op(op).output.unwrap())
                }
            };
        }
        res
    }

    /// Ghidra `AddTreeState::buildDegenerate`: a unit-sized base type makes every offset a
    /// multiple, so the ADD becomes a single PTRADD.
    fn build_degenerate(&mut self, f: &mut Funcdata) -> bool {
        if (self.base_type.align_size() as i64) < 1 {
            // size really less than scale → padding; don't transform
            return false;
        }
        let out = f.op(self.base_op).output.unwrap();
        if !f.vn(out).get_type().is_pointer() {
            return false; // Make sure pointer propagates thru INT_ADD
        }
        let other = f.op(self.base_op).input(1 - self.base_slot).unwrap();
        let one = f.new_const(self.ct.size(), 1);
        f.op_set_all_input(self.base_op, &[self.ptr, other, one]);
        f.op_set_opcode(self.base_op, OpCode::Ptradd);
        true
    }

    /// Ghidra `AddTreeState::buildTree`: rewrite the analysed ADD tree into PTRADD/PTRSUB + any
    /// remaining additive terms, handing the original op's output to the new tail op.
    fn build_tree(&mut self, f: &mut Funcdata) {
        let mult_node = self.build_multiples(f);
        let extra_node = self.build_extra(f);
        let mut newop: Option<OpId> = None;

        // PTRADD portion
        let mut node = match mult_node {
            Some(mn) => {
                let sz = f.new_const(self.ptrsize, self.size as u64);
                let op = f.new_op_before(self.base_op, OpCode::Ptradd, vec![self.ptr, mn, sz]);
                newop = Some(op);
                f.op(op).output.unwrap()
            }
            None => self.ptr, // Zero multiple terms
        };

        // PTRSUB portion (a sub-type offset)
        if self.is_subtype {
            let off = f.new_const(self.ptrsize, self.offset);
            let op = f.new_op_before(self.base_op, OpCode::Ptrsub, vec![node, off]);
            newop = Some(op);
            node = f.op(op).output.unwrap();
        }

        // Add back any remaining terms
        if let Some(en) = extra_node {
            let op = f.new_op_before(self.base_op, OpCode::IntAdd, vec![node, en]);
            newop = Some(op);
        }

        let Some(newop) = newop else {
            return; // This should never happen
        };
        let base_out = f.op(self.base_op).output.unwrap();
        f.op_set_output(newop, base_out);
        f.op_destroy(self.base_op);
    }

    /// Ghidra `AddTreeState::apply`: drive the analysis and rewrite. The distribution path is
    /// faithfully deferred — declined rather than running `distributeIntMultAdd`.
    fn apply(&mut self, f: &mut Funcdata) -> bool {
        if self.is_degenerate {
            return self.build_degenerate(f);
        }
        self.span_add_tree(f, self.base_op, 1);
        if !self.valid {
            return false;
        }
        if self.distribute_op.is_some() && !self.is_distribute_used {
            self.clear();
            self.prevent_distribution = true;
            self.span_add_tree(f, self.base_op, 1);
        }
        self.calc_subtype(f);
        if !self.valid {
            return false;
        }
        if self.distribute_op.is_some() {
            // Ghidra would distributeIntMultAdd + collapseIntMultMult here; deferred → decline.
            return false;
        }
        self.build_tree(f);
        true
    }
}
