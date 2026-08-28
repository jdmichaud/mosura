//! Pointer-arithmetic recovery — a faithful port of Ghidra's `RulePtrArith` and its helper
//! `AddTreeState` (`ruleaction.cc`). A string of `INT_ADD`s rooted on a pointer-typed base is
//! rewritten into `PTRADD(base, index, elemsize)` / `PTRSUB(base, offset)` ops, so the printer can
//! render `base[i]` (array indexing) and `base->field` (struct access) instead of `*(T *)(p + k)`.
//!
//! Gated on `Funcdata::has_type_recovery_started` and run after `ActionInferTypes` has committed
//! data-types onto varnodes (`Varnode::get_type`). The pointer type is the read-facing type
//! (`getTypeReadFacing`), which equals the committed type here.
//!
//! ⚠️ **AUDITED — THIS PARAGRAPH USED TO BUNDLE FOUR DEFERRALS UNDER ONE REASON, AND THREE OF THE
//! FOUR WERE WRONG.** The original, kept verbatim so the error stays legible and the reader can
//! calibrate the rest of this file: *"Faithfully deferred (Ghidra has them; not reached by the
//! primitive-lattice corpus): the `TypePointerRel` relative-pointer alternate form
//! (`initAlternateForm`); the `distributeIntMultAdd`/`collapseIntMultMult` distribution path
//! (declined when needed); the `nearestArrayedComponent` array-hint refinement inside a struct
//! (falls back to `getSubType`); and the union
//! `inheritResolution`/`isTypeRecoveryExceeded`/`setStopTypePropagation` bookkeeping."*
//!
//! **The shared reason was itself false when written.** `Datatype::Array` and `Datatype::Struct`
//! landed in `154b022` at 15:15 on 2026-06-25; this header is `86bd58f`, 19:20 the same day — four
//! hours later, with `154b022` an ancestor. The lattice was not "primitive" at the time of writing.
//!
//! Split, one item per line, verified against the tree:
//!
//!   - **`TypePointerRel` / `initAlternateForm` — ACCURATE, genuinely deferred.** There is no
//!     `TypePointerRel` variant, so [`AddTreeState::init_alternate_form`] is a stub returning false
//!     and says so at its definition; Ghidra's call-site scaffold IS ported (the second `apply`
//!     attempt below). Its real reason is a missing variant, not corpus reach.
//!     *Revival:* a relative-pointer variant in [`Datatype`].
//!   - **`distributeIntMultAdd` — ⚠️ PORTED AND LIVE, just not from here.**
//!     `rules.rs::distribute_int_mult_add` (funcdata_op.cc:1071) exists and is called from a rule
//!     (rules.rs:738/741) — Ghidra calls it from three places (ruleaction.cc:131/133 and :6458) and
//!     mosura ported the rule callers, not the `AddTreeState` one. What is deferred is
//!     `AddTreeState`'s *use* of the distribution path — a WIRING decision, not a missing port.
//!     **CENSUSED and INERT:** across the 79 datatests and WAR2's 1303 functions the path is a
//!     candidate exactly **once** (one WAR2 function) and **declines zero times** — the
//!     `preventDistribution` retry resolves it without the deferred code. So the original
//!     parenthetical "(declined when needed)" describes something that has never once been needed.
//!     `MOSURA_DISTRIB=1` counts both the candidate and the decline; a zero at the decline site
//!     alone would not distinguish "never needed" from "never a candidate".
//!     ⚠️ **AND `collapseIntMultMult` IS NOT A SEPARABLE ITEM** — an error in this audit's own
//!     follow-up filing, which listed it as one. Its ONLY caller in Ghidra is inside the
//!     `while (valid && distributeOp != 0)` loop (ruleaction.cc:6463/6464), where it exists purely
//!     to collapse `(x * #c) * #d` produced by the distribute. Porting it alone would be dead code.
//!     The distribution path and its collapse are ONE item; see AGENT.md on over-splitting.
//!   - **`nearestArrayedComponent` — ⚠️ HALF PORTED, IN THIS FILE.** Ghidra has TWO pairs:
//!     `TypeStruct` (type.cc:1669/1698) and `TypeSpacebase` (type.cc:2971/3020). The **spacebase**
//!     pair is ported as `sb_nearest_backward`/`sb_nearest_forward` below and is LIVE (called from
//!     `apply`). Only the `TypeStruct` pair is unported.
//!     ⚠️ **CORRECTION to this line's own first draft**, which said "and since `Datatype::Struct`
//!     exists, it is not lattice-blocked either, merely unwritten." That read the existence of a
//!     VARIANT as the existence of a lattice. `Datatype::Struct` is **never constructed anywhere**
//!     — declared at types.rs:42, consumed in five modules, built by none — so the `TypeStruct`
//!     pair would be **inert** if ported, exactly like `findTruncation` (see `cast.rs`). It IS
//!     blocked, just not by the missing variant everyone kept naming. Revival: something must
//!     PRODUCE a struct type.
//!   - **union bookkeeping — ⚠️ ONE OF THREE PORTED, AND MIS-GROUPED.**
//!     `isTypeRecoveryExceeded`/`setTypeRecoveryExceeded` are ported (`funcdata.rs`) and LIVE
//!     (`pipeline.rs`), and in Ghidra they are a general type-recovery pass counter, not union
//!     bookkeeping at all. `inheritResolution` and `setStopTypePropagation` are genuinely absent,
//!     and those two really are gated on a union metatype, which does not exist here.
//!
//! Two of the three refutations sit in THIS FILE, 250 and 340 lines below the sentence that denied
//! them. That is the bundling failure's signature: a multi-item note is written once and never
//! revisited, so it fossilises at its commit no matter what lands afterwards — including in the
//! same file. See AGENT.md's bundling rule.
//!
//! **Dated per item, which separates the two failure modes rather than lumping them** (this header
//! is `86bd58f`, 2026-06-25 19:20):
//!
//! | claim | ported by | verdict |
//! |---|---|---|
//! | `distributeIntMultAdd` | `cd0fd9e` 2026-07-07 (+12d) | accurate when written, **fossilised** |
//! | `nearestArrayedComponent` (spacebase) | `8d29ed8` 2026-07-12 (+17d) | accurate when written, **fossilised** |
//! | `isTypeRecoveryExceeded` | `cde89ac` 2026-07-12 (+17d) | accurate when written, **fossilised** |
//! | "primitive-lattice" (the shared reason) | — | **FALSE WHEN WRITTEN**, by 4 hours |
//!
//! So the three *items* were honest and decayed; only the *shared reason* was born wrong — and it
//! is the one that characterises the LATTICE rather than naming a function. That is the general
//! split now recorded in AGENT.md: substrate claims can be false immediately, function claims decay.

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
/// Ghidra `RulePushPtr::buildVarnodeOut` (ruleaction.cc:6800): an output varnode for a duplicated
/// op — in the original storage when that storage is a real, non-tied location, otherwise a fresh
/// unique. Address-tied storage cannot be duplicated into, because two ops would then define the
/// same tied location.
fn build_varnode_out(data: &mut Funcdata, vn: VarnodeId, op: OpId) -> VarnodeId {
    let size = data.vn(vn).size;
    let internal =
        data.spaces.get(data.vn(vn).loc.space).kind == super::space::SpaceKind::Internal;
    if data.vn(vn).is_addrtied() || internal {
        return data.new_output_unique(op, size);
    }
    let loc = data.vn(vn).loc;
    data.new_output(op, size, loc)
}

/// Ghidra `RulePushPtr::duplicateNeed` (ruleaction.cc:6812): give every reader of this op's output
/// its own copy of the op, then destroy the original. The point is to un-share a value whose single
/// definition would otherwise force a temporary into the output: once each reader has its own
/// extension (or multiply), the operation can be folded into each reader's expression and printed
/// inline.
///
/// Used by [`RuleExtensionPush`](super::rules::RuleExtensionPush) and, in Ghidra, by `RulePushPtr`
/// itself via `collectDuplicateNeeds`.
pub fn duplicate_need(data: &mut Funcdata, op: OpId) {
    let Some(out_vn) = data.op(op).output else { return };
    let Some(in_vn) = data.op(op).input(0) else { return };
    let num = data.op(op).num_inputs();
    let opc = data.op(op).code();
    let in1 = if num > 1 { data.op(op).input(1) } else { None };
    let out_ty = data.vn(out_vn).ty.clone();
    while let Some(dec_op) = data.vn(out_vn).descend.first().copied() {
        let slot = get_slot(data, dec_op, out_vn);
        // Duplicate the op at the ORIGINAL address (Ghidra `op->getAddr()`), inserted before the
        // reader so its result is defined where it is used.
        let pc = data.op(op).seqnum.pc;
        let uniq = data.num_ops() as u32;
        let new_op = data.new_op(opc, super::op::SeqNum { pc, uniq }, vec![in_vn]);
        if let Some(v1) = in1 {
            data.op_set_all_input(new_op, &[in_vn, v1]);
        }
        let new_out = build_varnode_out(data, out_vn, new_op);
        if let Some(ct) = out_ty.clone() {
            data.vn_mut(new_out).update_type(ct);
        }
        data.op_set_input(dec_op, slot, new_out);
        data.op_insert_before(new_op, dec_op);
    }
    data.op_destroy(op);
}

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
                                // `MOSURA_DISTRIB=1` also counts the CANDIDATE, not just the
                                // decline. A zero at the decline site means nothing on its own —
                                // it could equally mean the mechanism is never a candidate. Both
                                // numbers together say which.
                                debug!(crate::debug::Topic::Pointers, "distrib\t{}\tcandidate", f.name);
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
                // Ghidra falls back to `getSubType` here (ruleaction.cc:6086), and for a
                // TYPE_SPACEBASE that is never null — `TypeSpacebase::getSubType` returns
                // `getBase(1,TYPE_UNKNOWN)` at newoff 0 when no symbol is mapped (type.cc:2965). So an
                // indexed access at an UNMAPPED frame offset still folds to `PTRSUB(sp, off)` instead
                // of leaving the raw spacebase pointer in the expression.
                (None, None) => Some(sb_get_subtype(&syms, off).map(|(_, no)| no).unwrap_or(0)),
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
            // `MOSURA_DISTRIB=1` counts this decline per function, READ-ONLY. A decline here means
            // RulePtrArith returns 0 and the pointer arithmetic is NOT converted, so the C renders
            // `*(T *)(p + k)` where Ghidra would reach `p[i]` / `p->field` — that is the deferral's
            // actual cost, and it is invisible in any gate we run.
            debug!(crate::debug::Topic::Pointers, "distrib\t{}\tdecline", f.name);
            return false;
        }
        self.build_tree(f);
        true
    }
}

/// Ghidra `RulePtrsubUndo::DEPTH_LIMIT` (ruleaction.cc:6929): how deep the additive expression
/// below a PTRSUB is followed, both when collecting constants and when removing them.
const PTRSUB_UNDO_DEPTH_LIMIT: i32 = 8;

/// Ghidra `TypePointer::testForArraySlack` (type.cc:1103): an offset outside the component is still
/// acceptable when the component is an array, or when an arrayed component lies near enough in the
/// direction of the offset — array indexing legitimately runs past the nominal component bounds.
///
/// Ghidra dispatches to `TypeStruct::nearestArrayedComponent*` or the `TypeSpacebase` pair. Only the
/// spacebase pair exists here ([`sb_nearest_backward`]/[`sb_nearest_forward`]); the struct pair is
/// unported and would be **inert** if written, because `Datatype::Struct` is never constructed (see
/// this file's header). So the struct arm answers `false`, which is what Ghidra answers when no
/// arrayed component is found.
fn test_for_array_slack(
    syms: &[super::varmap::StackSymbol],
    dt: &Datatype,
    off: i64,
    spacebase: bool,
) -> bool {
    if matches!(dt, Datatype::Array(..)) {
        return true;
    }
    if !spacebase {
        return false; // struct pair unported-and-inert
    }
    if off < 0 {
        sb_nearest_forward(syms, off).is_some()
    } else {
        sb_nearest_backward(syms, off).is_some()
    }
}

/// Ghidra `TypePointer::isPtrsubMatching` (type.cc:1123): is this data-type suitable as the base of
/// a PTRSUB at offset `off`, with `extra` further constant offset and an index `multiplier` below
/// it? A PTRSUB must address a *component*, so the answer is no unless the pointee is structured.
///
/// The SPACEBASE arm reads the recovered `ScopeLocal` table (mosura's `TypeSpacebase::getSubType`,
/// [`sb_get_subtype`]) and is LIVE — it is the arm that matters on x86-64, where every stack access
/// is a PTRSUB off the spacebase. The ARRAY arm is direct. The STRUCT arm is ported faithfully but
/// is unreachable today, since nothing constructs `Datatype::Struct`; the UNION arm is Ghidra's
/// unconditional `false` and needs no metatype to express. Everything else is "not a pointer to a
/// structured data-type" — also `false`.
///
/// Ghidra's `addressToByteInt(x, wordsize)` conversions are identities here: every space mosura
/// loads has `wordSize` 1.
fn is_ptrsub_matching(
    f: &Funcdata,
    dt: &Datatype,
    off: i64,
    extra: i64,
    multiplier: i64,
) -> bool {
    let Datatype::Pointer(_, ptrto) = dt else {
        return false; // not a pointer to a structured data-type
    };
    match &**ptrto {
        Datatype::Spacebase(_) => {
            let syms = super::varmap::recover_scope(f);
            // Ghidra `TypeSpacebase::getSubType` (type.cc:2947) does NOT fail when the offset maps
            // to no symbol: it answers `undefined1` at offset 0 (`getBase(1,TYPE_UNKNOWN)`), so an
            // unmapped frame offset still MATCHES — only `extra` has to stay inside that 1-byte
            // stand-in. [`sb_get_subtype`] returns `None` there, which is why the stand-in is
            // supplied here rather than treated as a mismatch.
            //
            // This is load-bearing, not a detail: returning "no match" for an unmapped offset made
            // this rule undo a PTRSUB that `RulePtrArith` (actprop2) immediately rebuilt, and the
            // pool ping-ponged forever — the pair only converges because Ghidra's spacebase arm is
            // this permissive.
            let (sub_type, newoff) =
                sb_get_subtype(&syms, off).unwrap_or((Datatype::Unknown(1), 0));
            if newoff != 0 {
                return false;
            }
            if extra < 0 || extra >= sub_type.size() as i64 {
                // The offset lands outside the symbol: only array slack excuses it.
                if !test_for_array_slack(&syms, &sub_type, extra, true) {
                    return false;
                }
            }
            true
        }
        Datatype::Array(..) => {
            if off != 0 {
                return false;
            }
            multiplier < ptrto.align_size() as i64
        }
        Datatype::Struct(..) => {
            let typesize = ptrto.size() as i64;
            if multiplier >= ptrto.align_size() as i64 {
                return false;
            }
            match ptrto.get_subtype(off) {
                Some((sub_type, newoff)) => {
                    if newoff != 0 {
                        return false;
                    }
                    if extra < 0 || extra >= sub_type.size() as i64 {
                        return test_for_array_slack(&[], &sub_type, extra, false);
                    }
                    true
                }
                None => {
                    // Ghidra lumps the unresolved residual into `extra` and range-checks it.
                    !((extra < 0 || extra >= typesize) && typesize != 0)
                }
            }
        }
        _ => false,
    }
}

/// Sign-extend a constant of `size` bytes to `i64` — Ghidra's implicit `uintb` → `int8` read of a
/// PTRSUB's offset, which is negative for every stack local.
fn sext_const(v: u64, size: u32) -> i64 {
    if size >= 8 {
        v as i64
    } else {
        let sh = 64 - 8 * size;
        ((v << sh) as i64) >> sh
    }
}

/// Ghidra `RulePtrsubUndo::getConstOffsetBack` (ruleaction.cc:6836): total the constant contribution
/// reaching `vn` through an additive expression, and separately report the largest index
/// `multiplier` seen — an INT_MULT by a constant scales an index, so it bounds how far below the
/// PTRSUB a component reference could still be valid. Depth-limited exactly as Ghidra is.
fn get_const_offset_back(f: &Funcdata, vn: VarnodeId, max_level: i32) -> (i64, i64) {
    let mut multiplier = 0i64;
    if f.vn(vn).is_constant() {
        return (f.vn(vn).constant_value() as i64, multiplier);
    }
    if !f.vn(vn).is_written() {
        return (0, multiplier);
    }
    let max_level = max_level - 1;
    if max_level < 0 {
        return (0, multiplier);
    }
    let op = f.vn(vn).def.unwrap();
    let mut retval = 0i64;
    match f.op(op).code() {
        OpCode::IntAdd => {
            for slot in 0..2 {
                let Some(in_vn) = f.op(op).input(slot) else { continue };
                let (val, submultiplier) = get_const_offset_back(f, in_vn, max_level);
                retval += val;
                if submultiplier > multiplier {
                    multiplier = submultiplier;
                }
            }
        }
        OpCode::IntMult => {
            let Some(cvn) = f.op(op).input(1) else { return (0, 0) };
            if !f.vn(cvn).is_constant() {
                return (0, 0);
            }
            multiplier = f.vn(cvn).constant_value() as i64;
            if let Some(in0) = f.op(op).input(0) {
                let (_, submultiplier) = get_const_offset_back(f, in0, max_level);
                if submultiplier > 0 {
                    multiplier *= submultiplier; // only contribute to the multiplier
                }
            }
        }
        _ => {}
    }
    (retval, multiplier)
}

/// Ghidra `RulePtrsubUndo::getExtraOffset` (ruleaction.cc:6872): walk the *lone-descendant* chain
/// below the PTRSUB, accumulating any further constant offset and the largest index multiplier.
/// This is what tells [`is_ptrsub_matching`] whether the PTRSUB's offset plus everything added
/// below it still lands inside a component.
fn get_extra_offset(f: &Funcdata, op: OpId) -> (i64, i64) {
    let mut extra = 0i64;
    let mut multiplier = 0i64;
    let Some(mut outvn) = f.op(op).output else { return (0, 0) };
    let mut cur = f.lone_descend(outvn);
    while let Some(op) = cur {
        match f.op(op).code() {
            OpCode::IntAdd => {
                let slot = get_slot(f, op, outvn);
                if let Some(other) = f.op(op).input(1 - slot) {
                    let (val, submultiplier) =
                        get_const_offset_back(f, other, PTRSUB_UNDO_DEPTH_LIMIT);
                    extra += val;
                    if submultiplier > multiplier {
                        multiplier = submultiplier;
                    }
                }
            }
            OpCode::Ptrsub => {
                if let Some(c) = f.op(op).input(1) {
                    extra += f.vn(c).constant_value() as i64;
                }
            }
            OpCode::Ptradd => {
                if f.op(op).input(0) != Some(outvn) {
                    break;
                }
                let mut ptraddmult = f.op(op).input(2).map_or(0, |v| f.vn(v).constant_value() as i64);
                let Some(invn) = f.op(op).input(1) else { break };
                if f.vn(invn).is_constant() {
                    // Only contribute to the extra if the index is constant.
                    extra += ptraddmult * f.vn(invn).constant_value() as i64;
                }
                let (_, submultiplier) = get_const_offset_back(f, invn, PTRSUB_UNDO_DEPTH_LIMIT);
                if submultiplier != 0 {
                    ptraddmult *= submultiplier;
                }
                if ptraddmult > multiplier {
                    multiplier = ptraddmult;
                }
            }
            _ => break,
        }
        let Some(next) = f.op(op).output else { break };
        outvn = next;
        cur = f.lone_descend(outvn);
    }
    let bits = 8 * f.vn(outvn).size;
    let extra = if bits >= 64 {
        extra
    } else {
        let sh = 64 - bits;
        (extra << sh) >> sh
    };
    (extra, multiplier)
}

/// Ghidra `RulePtrsubUndo::removeLocalAddRecurse` (ruleaction.cc:6817): strip constant addends out
/// of the additive expression below a PTRSUB that turned out to be invalid, returning their total so
/// the caller can lump it into the PTRSUB's own offset. A value used anywhere else is left alone.
fn remove_local_add_recurse(data: &mut Funcdata, op: OpId, slot: usize, max_level: i32) -> i64 {
    let Some(vn) = data.op(op).input(slot) else { return 0 };
    if !data.vn(vn).is_written() {
        return 0;
    }
    if data.lone_descend(vn) != Some(op) {
        return 0; // varnode must not be used anywhere else
    }
    let max_level = max_level - 1;
    if max_level < 0 {
        return 0;
    }
    let op = data.vn(vn).def.unwrap();
    let mut retval = 0i64;
    if data.op(op).code() == OpCode::IntAdd {
        let in1 = data.op(op).input(1);
        if in1.is_some_and(|v| data.vn(v).is_constant()) {
            retval += data.vn(in1.unwrap()).constant_value() as i64;
            data.op_remove_input(op, 1);
            data.op_set_opcode(op, OpCode::Copy);
        } else {
            retval += remove_local_add_recurse(data, op, 0, max_level);
            retval += remove_local_add_recurse(data, op, 1, max_level);
        }
    }
    retval
}

/// Ghidra `RulePtrsubUndo::removeLocalAdds` (ruleaction.cc:6789): once a PTRSUB is known to be
/// invalid, the PTRSUBs and PTRADDs stacked below it are invalid too — they were built on the same
/// wrong type. Collapse each to a COPY (constant cases) or undo the scaling ([`Funcdata::
/// op_undo_ptradd`]), returning the total constant offset removed.
fn remove_local_adds(data: &mut Funcdata, vn: VarnodeId) -> i64 {
    let mut extra = 0i64;
    let mut vn = vn;
    while let Some(op) = data.lone_descend(vn) {
        match data.op(op).code() {
            OpCode::IntAdd => {
                let slot = get_slot(data, op, vn);
                let in1 = data.op(op).input(1);
                if slot == 0 && in1.is_some_and(|v| data.vn(v).is_constant()) {
                    extra += data.vn(in1.unwrap()).constant_value() as i64;
                    data.op_remove_input(op, 1);
                    data.op_set_opcode(op, OpCode::Copy);
                } else {
                    // Get any constants from the other input.
                    extra += remove_local_add_recurse(data, op, 1 - slot, PTRSUB_UNDO_DEPTH_LIMIT);
                }
            }
            OpCode::Ptrsub => {
                if let Some(c) = data.op(op).input(1) {
                    extra += data.vn(c).constant_value() as i64;
                }
                data.op_remove_input(op, 1);
                data.op_set_opcode(op, OpCode::Copy);
            }
            OpCode::Ptradd => {
                if data.op(op).input(0) != Some(vn) {
                    break;
                }
                // The PTRADD is associated with the invalid PTRSUB, so it becomes an INT_ADD or
                // a COPY.
                let ptraddmult =
                    data.op(op).input(2).map_or(0, |v| data.vn(v).constant_value() as i64);
                let Some(invn) = data.op(op).input(1) else { break };
                if data.vn(invn).is_constant() {
                    extra += ptraddmult * data.vn(invn).constant_value() as i64;
                    data.op_remove_input(op, 2);
                    data.op_remove_input(op, 1);
                    data.op_set_opcode(op, OpCode::Copy);
                } else {
                    data.op_undo_ptradd(op, false);
                    extra += remove_local_add_recurse(data, op, 1, PTRSUB_UNDO_DEPTH_LIMIT);
                }
            }
            _ => break,
        }
        let Some(next) = data.op(op).output else { break };
        vn = next;
    }
    extra
}

/// Ghidra `RulePtrsubUndo` (ruleaction.cc:6931, coreaction.cc:5639): the PTRSUB counterpart of
/// [`RulePtraddUndo`] — "remove PTRSUB operations with mismatched data-type information". A PTRSUB
/// asserts that its base type has a component at the given offset; when type recovery later says
/// otherwise, the assertion is wrong and the op must go back to being an INT_ADD.
///
/// The offset it checks is not just the PTRSUB's own: [`get_extra_offset`] walks the lone-descendant
/// chain below it, so a PTRSUB whose component is only exceeded *after* further additions is caught
/// too. When the PTRSUB does go, everything built on the same wrong type goes with it
/// ([`remove_local_adds`]), and the constants they contributed are lumped back into the INT_ADD.
///
/// Ghidra also calls `clearStopTypePropagation` here. mosura models no `stop_type_propagation` flag
/// (this file's header records it as genuinely absent, gated on a union metatype that does not
/// exist), so nothing sets it and clearing it is vacuous — omitted rather than faked.
pub struct RulePtrsubUndo;

impl Rule for RulePtrsubUndo {
    fn name(&self) -> &str {
        "ptrsub_undo"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Ptrsub]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if !data.has_type_recovery_started() {
            return 0;
        }
        let Some(basevn) = data.op(op).input(0) else { return 0 };
        let Some(cvn) = data.op(op).input(1) else { return 0 };
        // SIGN-EXTEND the offset. Stack locals live at NEGATIVE frame offsets, and the constant is
        // stored unsigned: reading `0xffffffe6` as 4294967270 instead of -26 makes the symbol
        // lookup miss, so a perfectly good PTRSUB is judged invalid, converted to an INT_ADD, and
        // rebuilt by RulePtrArith on the next pass — the pool then never reaches a fixpoint (WAR2
        // FUN_00024a88). Ghidra reads the same field into a SIGNED `int8` (ruleaction.cc:6935).
        let val = sext_const(data.vn(cvn).constant_value(), data.vn(cvn).size);
        let (extra, multiplier) = get_extra_offset(data, op);
        let base_ty = type_read_facing(data, basevn);
        if is_ptrsub_matching(data, &base_ty, val, extra, multiplier) {
            return 0;
        }
        data.op_set_opcode(op, OpCode::IntAdd);
        let Some(outvn) = data.op(op).output else { return 1 };
        let extra = remove_local_adds(data, outvn);
        if extra != 0 {
            // Lump the extra into the additive offset.
            let size = data.vn(cvn).size;
            let newval = (val + extra) as u64 & calc_mask(size);
            let newc = data.new_const(size, newval);
            data.op_set_input(op, 1, newc);
        }
        1
    }
}

/// Ghidra's `RulePtraddUndo` (ruleaction.cc:6910): "Remove PTRADD operations with mismatched
/// data-type information." A Varnode can be given an incorrect type mid-simplification, producing
/// an incorrect PTRADD conversion; once the right type is found the PTRADD must go back to an
/// INT_ADD.
///
/// The guard has three exits into [`Funcdata::op_undo_ptradd`], and they are not one class:
///   - the base is **not a pointer** at all;
///   - it is a pointer whose **pointee size disagrees** with the element size in slot 2;
///   - it **fits**, but the index is a **constant zero** (`ptr + 0*elem`).
/// The first two are the mis-scaling class the dead-last `ActionSetCasts` refit also catches
/// (`8d9e42c`); the third is unique to this rule.
///
/// ⚠️ **THIS DOES NOT CLOSE A MEASURED GAP AND MUST NOT BE DESCRIBED AS DOING SO.** Measured
/// read-only before it was written, with a rule-shaped probe in this exact pool slot: **0 firings
/// across all 79 x86-64 datatests**, and on WAR2 **32 firings in 4 functions** (20 not-a-pointer,
/// 12 size-mismatch, **zero** constant-zero-index) — and all 4 functions are already among the 14
/// the `ActionSetCasts` refit rewrites, a strict subset. Since that refit repairs these before
/// printing, the rendered C may not move at all.
///
/// What is NOT a subset is the **timing**, and that is the reason to port it: this runs in the
/// **mainloop**, so the recovered INT_ADD/INT_MULT goes on to participate in simplification and
/// type propagation, whereas the refit rewrites only for rendering. Ghidra runs both, and the two
/// compose rather than race: for a size-mismatch the base is still a pointer, so `RulePtrArith`
/// (actprop2, coreaction.cc:5666) may rebuild a PTRADD — carrying the **correct** element size read
/// from the current type, which is the repair; where the base is not a pointer `RulePtrArith`
/// declines and the integer form stands.
pub struct RulePtraddUndo;

impl Rule for RulePtraddUndo {
    fn name(&self) -> &str {
        "ptradd_undo"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Ptradd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if !data.has_type_recovery_started() {
            return 0;
        }
        let size = data.vn(data.op(op).input(2).unwrap()).constant_value();
        let dt = type_read_facing(data, data.op(op).input(0).unwrap());
        // Ghidra compares `getAlignSize()` against `addressToByteInt(size, wordSize)`. Both are
        // identities here: `alignSize == size` for every type mosura models (the base `Datatype`
        // constructor, type.hh:215 — only composites round up and there is no composite metatype),
        // and `wordSize` is 1 on every space mosura loads.
        if let Datatype::Pointer(_, pt) = &dt {
            if pt.size() as u64 == size {
                // Still a pointer, and of the correct size — keep it unless the index is a
                // constant zero, which makes the PTRADD a no-op scaling nothing.
                let ind = data.op(op).input(1).unwrap();
                if !data.vn(ind).is_constant() || data.vn(ind).constant_value() != 0 {
                    return 0;
                }
            }
        }
        data.op_undo_ptradd(op, false);
        1
    }
}

#[cfg(test)]
mod ptrsub_undo_tests {
    use super::*;
    use crate::decompile::action::Rule;
    use crate::decompile::op::SeqNum;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::BlockBasic;
    use crate::decompile::block::BlockId;

    /// A Funcdata with type recovery started (the rule's first gate).
    fn fd() -> (Funcdata, Address) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        f.start_type_recovery();
        (f, Address::new(ram, 0))
    }

    #[test]
    fn ptrsub_undo_converts_when_base_is_not_a_pointer() {
        // The base type is an integer, so it has no component at any offset — the PTRSUB's
        // assertion is wrong and it goes back to an INT_ADD (ruleaction.cc:6931).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let base = f.new_input(8, Address::new(reg, 0x10));
        f.vn_mut(base).update_type(Datatype::Uint(8));
        let off = f.new_const(8, 0x10);
        let sub = f.new_op(OpCode::Ptrsub, seq, vec![base, off]);
        f.new_output_unique(sub, 8);
        f.set_blocks(vec![BlockBasic { ops: vec![sub], ..Default::default() }]);
        f.op_mut(sub).parent = Some(BlockId(0));
        assert_eq!(RulePtrsubUndo.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::IntAdd);
        // The offset is untouched when nothing below contributed.
        assert_eq!(f.vn(f.op(sub).input(1).unwrap()).constant_value(), 0x10);
    }

    #[test]
    fn sext_const_reads_a_stack_offset_as_negative() {
        // The bug that made this rule fight RulePtrArith forever: a PTRSUB's offset is stored
        // unsigned, but stack locals live at NEGATIVE frame offsets.
        assert_eq!(sext_const(0xffff_ffe6, 4), -26, "0xffffffe6 is -26, not 4294967270");
        assert_eq!(sext_const(0x10, 4), 16);
        assert_eq!(sext_const(0xffff_ffff_ffff_ffe6, 8), -26);
    }

    #[test]
    fn ptrsub_undo_declines_a_negative_stack_offset() {
        // The WAR2 FUN_00024a88 shape: PTRSUB off the stack spacebase at a negative offset. Read
        // unsigned, the symbol lookup misses and the rule wrongly undoes a PTRSUB that
        // RulePtrArith rebuilds on the next pass — the pool then never converges.
        let (mut f, ram) = fd();
        let spaces_stack = f.spaces.by_name("stack").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let base = f.new_input(4, Address::new(f.spaces.by_name("register").unwrap(), 0x20));
        f.vn_mut(base)
            .update_type(Datatype::Pointer(4, Box::new(Datatype::Spacebase(spaces_stack))));
        let off = f.new_const(4, 0xffff_ffe6); // -26
        let sub = f.new_op(OpCode::Ptrsub, seq, vec![base, off]);
        f.new_output_unique(sub, 4);
        f.set_blocks(vec![BlockBasic { ops: vec![sub], ..Default::default() }]);
        f.op_mut(sub).parent = Some(BlockId(0));
        assert_eq!(RulePtrsubUndo.apply_op(sub, &mut f), 0, "a negative frame offset is valid");
        assert_eq!(f.op(sub).code(), OpCode::Ptrsub);
    }

    #[test]
    fn ptrsub_undo_declines_before_type_recovery() {
        // Ghidra's first gate: the types are not yet meaningful, so no mismatch can be concluded.
        let spaces = SpaceManager::standard();
        let ram_space = spaces.by_name("ram").unwrap();
        let ram = Address::new(ram_space, 0);
        let mut f = Funcdata::new("t", ram, spaces); // type recovery NOT started
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let base = f.new_input(8, Address::new(reg, 0x10));
        f.vn_mut(base).update_type(Datatype::Uint(8));
        let off = f.new_const(8, 0x10);
        let sub = f.new_op(OpCode::Ptrsub, seq, vec![base, off]);
        f.new_output_unique(sub, 8);
        f.set_blocks(vec![BlockBasic { ops: vec![sub], ..Default::default() }]);
        f.op_mut(sub).parent = Some(BlockId(0));
        assert_eq!(RulePtrsubUndo.apply_op(sub, &mut f), 0);
        assert_eq!(f.op(sub).code(), OpCode::Ptrsub);
    }

    #[test]
    fn ptrsub_undo_lumps_the_constant_added_below_it() {
        // `PTRSUB(base, #0x10)` feeding `INT_ADD #4`: the add was built on the same wrong type, so
        // it collapses to a COPY and its constant is lumped into the recovered INT_ADD's offset
        // (removeLocalAdds, ruleaction.cc:6789).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let base = f.new_input(8, Address::new(reg, 0x10));
        f.vn_mut(base).update_type(Datatype::Uint(8));
        let off = f.new_const(8, 0x10);
        let sub = f.new_op(OpCode::Ptrsub, seq(0), vec![base, off]);
        let sub_out = f.new_output_unique(sub, 8);
        let four = f.new_const(8, 4);
        let add = f.new_op(OpCode::IntAdd, seq(1), vec![sub_out, four]);
        f.new_output_unique(add, 8);
        f.set_blocks(vec![BlockBasic { ops: vec![sub, add], ..Default::default() }]);
        f.op_mut(sub).parent = Some(BlockId(0));
        f.op_mut(add).parent = Some(BlockId(0));
        assert_eq!(RulePtrsubUndo.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::IntAdd);
        assert_eq!(f.vn(f.op(sub).input(1).unwrap()).constant_value(), 0x14);
        // The add below became a COPY of the recovered value.
        assert_eq!(f.op(add).code(), OpCode::Copy);
        assert_eq!(f.op(add).num_inputs(), 1);
    }
}
