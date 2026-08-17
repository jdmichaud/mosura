//! Simplification rules — ports of Ghidra's `ruleaction.cc` `Rule`s, applied to a fixpoint
//! by an [`ActionPool`](super::action::ActionPool). This is the start of P2; more rules
//! slot in the same way Ghidra's pool grows.

use super::action::Rule;
use super::circlerange::CircleRange;
use super::space::{Address, SpaceId};
use super::block::BlockId;
use super::dominator::Dominators;
use super::funcdata::Funcdata;
use super::op::{OpId, SeqNum};
use super::opcode::OpCode;
use super::varnode::VarnodeId;

fn mask(v: u64, size: u32) -> u64 {
    if size >= 8 {
        v
    } else {
        v & ((1u64 << (8 * size)) - 1)
    }
}

fn sext(v: u64, size: u32) -> u64 {
    if size == 0 || size >= 8 {
        v
    } else {
        let sh = 64 - 8 * size;
        (((v << sh) as i64) >> sh) as u64
    }
}

/// Evaluate an op whose inputs are all constants, mirroring the (parity-validated) p-code
/// semantics in `sleigh::emu`. Returns the masked result, or `None` for ops that are not
/// purely-functional constant computations (memory, control flow, markers).
pub fn eval_const(opcode: OpCode, inputs: &[(u64, u32)], out_size: u32) -> Option<u64> {
    use OpCode::*;
    let a = |i: usize| inputs.get(i).map_or(0, |&(v, s)| mask(v, s));
    let sa = |i: usize| inputs.get(i).map_or(0, |&(v, s)| sext(v, s));
    let res: u64 = match opcode {
        Copy => a(0),
        IntAdd => a(0).wrapping_add(a(1)),
        IntSub => a(0).wrapping_sub(a(1)),
        IntMult => a(0).wrapping_mul(a(1)),
        IntAnd => a(0) & a(1),
        IntOr => a(0) | a(1),
        IntXor => a(0) ^ a(1),
        IntLeft => a(0).checked_shl(a(1) as u32).unwrap_or(0),
        IntRight => a(0).checked_shr(a(1) as u32).unwrap_or(0),
        IntSright => sa(0) >> (a(1) as u32).min(63),
        IntNegate => !a(0),
        Int2comp => a(0).wrapping_neg(),
        IntZext => a(0),
        IntSext => sa(0),
        Subpiece => a(0).checked_shr(a(1).saturating_mul(8) as u32).unwrap_or(0),
        IntEqual => (a(0) == a(1)) as u64,
        IntNotequal => (a(0) != a(1)) as u64,
        IntLess => (a(0) < a(1)) as u64,
        IntLessequal => (a(0) <= a(1)) as u64,
        IntSless => ((sa(0) as i64) < (sa(1) as i64)) as u64,
        IntSlessequal => ((sa(0) as i64) <= (sa(1) as i64)) as u64,
        BoolNegate => (a(0) == 0) as u64,
        BoolAnd => (a(0) & 1) & (a(1) & 1),
        BoolOr => (a(0) & 1) | (a(1) & 1),
        BoolXor => (a(0) & 1) ^ (a(1) & 1),
        Popcount => a(0).count_ones() as u64,
        Lzcount => a(0).leading_zeros() as u64,
        // Floating-point ops fold via IEEE arithmetic on the host `f64` (Ghidra's per-op
        // `OpBehaviorFloat*::evaluate`, which likewise round-trips through the host float): decode
        // each operand at its own width, compute, re-encode at the output width. `0.0 / 0.0` folds
        // to a NaN pattern, exactly as Ghidra collapses the division to a constant.
        FloatAdd | FloatSub | FloatMult | FloatDiv | FloatNeg | FloatAbs | FloatSqrt
        | FloatFloat2float | FloatInt2float | FloatTrunc | FloatEqual | FloatNotequal | FloatLess
        | FloatLessequal | FloatNan => {
            let insz = |i: usize| inputs.get(i).map_or(1, |&(_, s)| s);
            let raw = |i: usize| inputs.get(i).map_or(0, |&(v, _)| v);
            let fin = |i: usize| super::float::to_host(raw(i), insz(i));
            let enc = |h: f64| super::float::encode(h, out_size);
            match opcode {
                FloatAdd => enc(fin(0) + fin(1)),
                FloatSub => enc(fin(0) - fin(1)),
                FloatMult => enc(fin(0) * fin(1)),
                FloatDiv => enc(fin(0) / fin(1)),
                FloatNeg => enc(-fin(0)),
                FloatAbs => enc(fin(0).abs()),
                FloatSqrt => enc(fin(0).sqrt()),
                FloatFloat2float => enc(fin(0)),
                FloatInt2float => enc(sa(0) as i64 as f64),
                FloatTrunc => fin(0) as i64 as u64,
                FloatEqual => (fin(0) == fin(1)) as u64,
                FloatNotequal => (fin(0) != fin(1)) as u64,
                FloatLess => (fin(0) < fin(1)) as u64,
                FloatLessequal => (fin(0) <= fin(1)) as u64,
                FloatNan => fin(0).is_nan() as u64,
                _ => unreachable!(),
            }
        }
        _ => return None, // LOAD/STORE/branches/calls/markers: not const-foldable
    };
    Some(mask(res, out_size))
}

/// Collapse an op whose inputs are all constants — a port of Ghidra's `RuleCollapseConstants`
/// (`ruleaction.cc`). The op is rewritten *in place* as `out = COPY <collapsed const>` (link the
/// new constant as input 0, drop the rest, change the opcode to COPY), rather than replacing every
/// use of `out`. RulePropagateCopy then propagates the COPY everywhere it is allowed; its marker
/// guard deliberately leaves the COPY in place where a constant must not be folded into a
/// MULTIEQUAL/INDIRECT. That is what lets an addrtied stack store survive as a renderable
/// `xStack_NN = const` feeding the across-call INDIRECT (instead of the constant vanishing into it).
/// (Ghidra computes the same value via per-op `OpBehavior::evaluate`; the IR is identical.)
pub struct RuleConstFold;

impl Rule for RuleConstFold {
    fn name(&self) -> &str {
        "constfold"
    }
    fn oplist(&self) -> Vec<OpCode> {
        Vec::new() // every op; eval_const screens out the non-foldable ones
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let code = data.op(op).code();
        // A COPY of a constant is already in the collapsed `out = COPY const` form (Ghidra leaves it
        // for RulePropagateCopy/dead-code); re-collapsing it would loop, so skip it.
        if code == OpCode::Copy {
            return 0;
        }
        let Some(out) = data.op(op).output else { return 0 };
        let inrefs = data.op(op).inrefs.clone();
        if inrefs.is_empty() {
            return 0;
        }
        let mut inputs = Vec::with_capacity(inrefs.len());
        for v in &inrefs {
            let vn = data.vn(*v);
            if !vn.is_constant() {
                return 0;
            }
            inputs.push((vn.constant_value(), vn.size));
        }
        let out_size = data.vn(out).size;
        // Ghidra `PcodeOp::isCollapsible` (op.cc:115) refuses to collapse an op whose output exceeds
        // `sizeof(uintb)` (8 bytes); `RuleCollapseConstants` (ruleaction.cc:3854) gates on it. mosura
        // constants carry a u64 value (`constant_value()`), so folding a wider output would silently
        // drop the high bits — e.g. `INT_SEXT` of a top-bit-set 8-byte magic would become a 16-byte
        // constant with a zero high word (an effective zero-extension). Leave the op in place so the
        // width-aware readers (`is_constant_extended`) see the real `INT_SEXT`.
        if out_size > 8 {
            return 0;
        }
        let Some(val) = eval_const(code, &inputs, out_size) else { return 0 };
        // Rewrite in place as `out = COPY const` (Ghidra `RuleCollapseConstants`): unlink the old
        // constant inputs, link the collapsed constant as input 0, become a COPY.
        let c = data.new_const(out_size, val);
        for slot in (1..inrefs.len()).rev() {
            data.op_remove_input(op, slot);
        }
        data.op_set_input(op, 0, c);
        data.op_set_opcode(op, OpCode::Copy);
        1
    }
}

/// `x OP x` identities — a port of Ghidra's `RuleTrivialArith`. With both inputs the same
/// varnode, comparisons/booleans collapse to a constant and `x & x`/`x | x` collapse to
/// `x`; the op becomes a COPY.
pub struct RuleTrivialArith;

impl Rule for RuleTrivialArith {
    fn name(&self) -> &str {
        "trivialarith"
    }
    fn oplist(&self) -> Vec<OpCode> {
        use OpCode::*;
        vec![
            IntNotequal, IntSless, IntLess, BoolXor, IntEqual, IntSlessequal, IntLessequal,
            IntXor, IntAnd, IntOr, BoolAnd, BoolOr,
        ]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        use OpCode::*;
        let o = data.op(op);
        if o.num_inputs() != 2 || o.input(0) != o.input(1) {
            return 0; // only the syntactically-identical case (CSE-match is RuleSelectCse)
        }
        let out_size = o.output.map_or(1, |v| data.vn(v).size);
        // the constant the op collapses to, or None to keep input 0 (`x & x` → x)
        let cval: Option<(u32, u64)> = match o.code() {
            IntNotequal | IntSless | IntLess | BoolXor => Some((1, 0)),
            IntEqual | IntSlessequal | IntLessequal => Some((1, 1)),
            IntXor => Some((out_size, 0)),
            IntAnd | IntOr | BoolAnd | BoolOr => None,
            _ => return 0,
        };
        data.op_remove_input(op, 1);
        data.op_set_opcode(op, Copy);
        if let Some((sz, v)) = cval {
            let c = data.new_const(sz, v);
            data.op_set_input(op, 0, c);
        }
        1
    }
}

/// Ghidra `RuleEarlyRemoval` (`ruleaction.cc:25`, oppool1's first rule): destroy any non-call op
/// whose output is dead — no readers, not auto-live — right inside the rule pool. This is Ghidra's
/// per-op early dead-code removal; keeping the graph clean mid-pool (rather than only at the heavier
/// `ActionDeadCode` sweeps) changes which later rules fire (a `loneDescend`/`hasNoDescend` check sees
/// the pruned graph). Applies to every opcode (empty oplist).
/// Ghidra `RuleLoadVarnode::correctSpacebase` (ruleaction.cc:4173): if `vn` is a spacebase register,
/// return the space it is the spacebase of — provided that space's container is the load/store space
/// `spc`. A *constant* spacebase is the ram-global pseudo-spacebase, associated with the load space
/// directly. The STRICT boundary: a non-input written value (a `COPY`-of-RSP, a `MULTIEQUAL`-of-RSP,
/// an indexed pointer) is DECLINED — only the RSP *input* is the true stack spacebase, so a value
/// merely derived from it stays an indirect access (this is exactly why Ghidra keeps varcross's loop
/// `*pxVar1 = 0` and partialsplit's `*puVar3` stores indirect where mosura's pre-pool `stackvars`
/// symbolic tracker over-resolves them to fixed slots).
fn correct_spacebase(data: &Funcdata, vn: super::varnode::VarnodeId, spc: SpaceId) -> Option<SpaceId> {
    if !data.vn(vn).is_spacebase() {
        return None;
    }
    if data.vn(vn).is_constant() {
        return Some(spc); // global pseudo-spacebase → the load space itself
    }
    if !data.vn(vn).is_input() {
        return None; // only the RSP input, never a derived (COPY/phi/indexed) value
    }
    let assoc = data.spaces.space_by_spacebase(data.vn(vn).loc, data.vn(vn).size)?;
    if data.spaces.get(assoc).contain != Some(spc) {
        return None; // loading off a data space this spacebase does not contain
    }
    Some(assoc)
}

/// Ghidra `RuleLoadVarnode::vnSpacebase` (ruleaction.cc:4194): recognize a `spacebase [+ const]`
/// pointer, returning the associated space and the constant offset. The stack pointer itself is
/// offset 0; an `INT_ADD(RSP_input, const)` (either operand order) contributes the constant.
fn vn_spacebase(data: &Funcdata, vn: super::varnode::VarnodeId, spc: SpaceId) -> Option<(SpaceId, u64)> {
    if let Some(rs) = correct_spacebase(data, vn, spc) {
        return Some((rs, 0));
    }
    if !data.vn(vn).is_written() {
        return None;
    }
    let def = data.vn(vn).def?;
    if data.op(def).code() != OpCode::IntAdd {
        return None;
    }
    let vn1 = data.op(def).input(0)?;
    let vn2 = data.op(def).input(1)?;
    if let Some(rs) = correct_spacebase(data, vn1, spc) {
        // spacebase + vn2: a fixed slot only when the addend is constant, else decline (Ghidra
        // returns null here rather than also trying vn2).
        return data.vn(vn2).is_constant().then(|| (rs, data.vn(vn2).loc.offset));
    }
    if let Some(rs) = correct_spacebase(data, vn2, spc) {
        return data.vn(vn1).is_constant().then(|| (rs, data.vn(vn1).loc.offset));
    }
    None
}

/// Ghidra `RuleLoadVarnode::checkSpacebase` (ruleaction.cc:4236): the shared LOAD/STORE address
/// analysis. `op` is a LOAD or STORE; return the resolved `(space, offset)` of a bare-constant pointer
/// (ram-global) or a `spacebase [+ const]` pointer (stack), or `None` to decline. Ghidra's SEGMENTOP
/// unwrap is omitted — mosura's x86-64 lift emits no `CPUI_SEGMENTOP` on this path; it re-enables
/// faithfully when a segmented target is added. (Byte offsets: every mosura space has `wordSize` 1, so
/// Ghidra's `addressToByte` is the identity here.)
fn check_spacebase(data: &Funcdata, op: OpId) -> Option<(SpaceId, u64)> {
    let offvn = data.op(op).input(1)?;
    let loadspace = SpaceId(data.vn(data.op(op).input(0)?).loc.offset as u32);
    if data.vn(offvn).is_constant() {
        return Some((loadspace, data.vn(offvn).loc.offset)); // ram-global const branch
    }
    vn_spacebase(data, offvn, loadspace)
}

/// Ghidra `RuleLoadVarnode` (ruleaction.cc:4277, registered in `actprop2`/`stackvars` at :5668):
/// convert a LOAD whose pointer is a *bare constant* (ram-global) or a *spacebase register `[+ const]`*
/// (stack) into a COPY of the direct varnode at that address in the resolved space, via
/// [`check_spacebase`]. So `u = LOAD #space #addr` becomes `u = COPY <space:addr>`, unifying the access
/// with the space's other (already-lifted) varnode reads so it names as `iRam/fRam/xRam<addr>` (ram) or
/// resolves to a `stack`-space slot instead of `*<addr>`.
///
/// The spacebase-register (stack) branch is LIVE (task #22-B Brick 2 cancelled `stackvars::
/// recover_stack`'s general LOAD/STORE conversion, so `RSP [+ const]` accesses reach this pool):
/// a stack LOAD converts to a COPY of the direct `stack`-space varnode inside the mainloop, and
/// the next iteration's `ActionHeritage` re-entry gives the slot SSA form — Ghidra's exact
/// in-pool resolution. The `isSpacebasePlaceholder` → `resolveSpacebaseRelative` trigger
/// (ruleaction.cc:4295-4302) is LIVE: it is how a call site learns its stack-pointer offset, without
/// which `Heritage::guardCalls` cannot register any stack range as a parameter trial.
pub struct RuleLoadVarnode;
impl Rule for RuleLoadVarnode {
    fn name(&self) -> &str {
        "loadvarnode"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Load]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(out) = data.op(op).output else {
            return 0;
        };
        let Some((space, off)) = check_spacebase(data, op) else {
            return 0;
        };
        let size = data.vn(out).size;
        let newvn = data.new_varnode(size, Address::new(space, off));
        data.op_set_input(op, 0, newvn);
        data.op_remove_input(op, 1);
        data.op_set_opcode(op, OpCode::Copy);
        // ruleaction.cc:4295-4302 — the stack-pointer placeholder trigger. This LOAD may be the
        // artificial one `FuncCallSpecs::createPlaceholder` hung off a CALL; if so, the COPY just
        // formed reads the fixed stack varnode the call's stack pointer resolved to, so its offset IS
        // the stack-pointer delta at that call site. Read it out, then the subsystem removes itself.
        // The flag is cleared first and unconditionally: it is a one-shot trigger, not a property.
        if data.vn(out).is_spacebase_placeholder() {
            data.vn_mut(out).clear_spacebase_placeholder();
            if let Some(place_op) = lone_descend(data, out) {
                // Ghidra `data.getCallSpecs(placeOp)` returns non-null exactly for a call site it
                // holds a spec for; mosura's equivalent test is that the reader is a CALL/CALLIND.
                if matches!(data.op(place_op).code(), OpCode::Call | OpCode::Callind) {
                    super::fspec::resolve_spacebase_relative(data, place_op, out);
                }
            }
        }
        1
    }
}

/// Ghidra `RuleStoreVarnode` (ruleaction.cc:4319, `actprop2`/`stackvars` at :5669): the STORE
/// counterpart of [`RuleLoadVarnode`], sharing [`check_spacebase`]. A STORE off a bare-constant
/// (ram-global) or `spacebase [+ const]` (stack) pointer becomes a COPY whose output is the direct
/// varnode at that address: `STORE #space #addr val` → `<space:addr> = COPY val`.
///
/// Ghidra also `setStackStore`s the resolved output (a marker for later stack-store analysis) and
/// `markNotMapped`s an unmapped store; both are omitted here — mosura models no stack-store analysis
/// and the raw-decompile path has no local scope to mark, exactly as the ram-global const branch has
/// always omitted them. Neither affects naming. The stack branch is LIVE (task #22-B Brick 2; see
/// [`RuleLoadVarnode`]).
pub struct RuleStoreVarnode;
impl Rule for RuleStoreVarnode {
    fn name(&self) -> &str {
        "storevarnode"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Store]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(valvn) = data.op(op).input(2) else {
            return 0;
        };
        let Some((space, off)) = check_spacebase(data, op) else {
            return 0;
        };
        let size = data.vn(valvn).size;
        data.new_output(op, size, Address::new(space, off));
        // COPY takes the stored value (STORE input 2) as its sole input.
        data.op_remove_input(op, 1);
        data.op_remove_input(op, 0);
        data.op_set_opcode(op, OpCode::Copy);
        1
    }
}

pub struct RuleEarlyRemoval;

impl Rule for RuleEarlyRemoval {
    fn name(&self) -> &str {
        "earlyremoval"
    }
    fn oplist(&self) -> Vec<OpCode> {
        Vec::new() // every op
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).is_call() {
            return 0; // functions are automatically consumed
        }
        // Ghidra `ruleaction.cc:31`. No longer vacuous: the dead-code consume sweep now marks the op
        // an INDIRECT guards (`consume::indirect_source`), so destroying it here would strand a live
        // INDIRECT. The flag is recomputed on every sweep, so it never keeps a no-longer-guarded op.
        if data.op(op).is_indirect_source() {
            return 0;
        }
        let Some(out) = data.op(op).output else {
            return 0; // no output (side-effecting op: STORE/BRANCH/RETURN) — keep
        };
        // Ghidra's `isPersist` guard here is commented out because its persist globals stay alive
        // through descendants (block-end copies). mosura instead keeps a written `ram` global alive
        // as a live-out root in `deadcode::dead_code` (not via SSA descendants), so the guard is
        // load-bearing here: without it the pool early-removes a global store that is dead in SSA but
        // a real side effect. mosura flags globals `persist` only after type recovery, so use the
        // `ram`-space proxy — exactly `dead_code`'s persistent live-out predicate.
        if data.spaces.by_name("ram") == Some(data.vn(out).loc.space) {
            return 0;
        }
        if !data.vn(out).descend.is_empty() {
            return 0; // output still has readers
        }
        if data.vn(out).is_auto_live() {
            return 0; // addrforce / autolive_hold — exempt
        }
        // Ghidra ruleaction.cc:38-41 — `if (doesDeadcode(spc) && !deadRemovalAllowedSeen(spc))
        // return 0`. This guard USED to be dropped, on the premise that "mosura heritages every
        // dead-code space to completion before the pool runs, so it never blocks". That premise was
        // retired along with the heritage-to-completion prime (the placeholder needs a rule pool
        // between the register and stack passes), and the guard is now load-bearing: during mainloop
        // iteration 1 the ram/stack spaces have NOT been heritaged, so their Varnodes are still free
        // and "no descendants" means "SSA is not built yet", not "dead". Without it the pool early-
        // removed floatcast's ram-global loads and the whole function body went with them.
        //
        // Ghidra uses the `…Seen` variant here (ruleaction.cc:39), which additionally LATCHES
        // `info->deadremoved = 1`. That latch is not a diagnostic: it is what makes
        // `bumpDeadcodeDelay` — and so the whole-decompile restart — reachable when a range is
        // later re-heritaged after this space has had Varnodes eliminated.
        let spc = data.vn(out).loc.space;
        if !super::heritage::dead_removal_allowed_seen(data, spc) {
            return 0;
        }
        data.op_destroy(op);
        1
    }
}

/// Move a constant to the second input of a commutative op (Ghidra's `RuleTermOrder`), so
/// the identity/collapse rules can assume the constant is in slot 1.
pub struct RuleTermOrder;

impl Rule for RuleTermOrder {
    fn name(&self) -> &str {
        "termorder"
    }
    fn oplist(&self) -> Vec<OpCode> {
        use OpCode::*;
        vec![
            IntEqual, IntNotequal, IntAdd, IntCarry, IntScarry, IntXor, IntAnd, IntOr,
            IntMult, BoolXor, BoolAnd, BoolOr, FloatEqual, FloatNotequal, FloatAdd, FloatMult,
        ]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let in0 = data.op(op).input(0).unwrap();
        let in1 = data.op(op).input(1).unwrap();
        if data.vn(in0).is_constant() && !data.vn(in1).is_constant() {
            data.op_swap_input(op, 0, 1);
            return 1;
        }
        0
    }
}

/// Identity elements (Ghidra's `RuleIdentityEl`): `x+0`, `x^0`, `x|0` → `x`; `x*1` → `x`;
/// `x*0` → `0`. Assumes the constant is in slot 1 (`RuleTermOrder`).
pub struct RuleIdentityEl;

impl Rule for RuleIdentityEl {
    fn name(&self) -> &str {
        "identityel"
    }
    fn oplist(&self) -> Vec<OpCode> {
        use OpCode::*;
        vec![IntAdd, IntXor, IntOr, BoolXor, BoolOr, IntMult]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let val = data.vn(in1).constant_value();
        let code = data.op(op).code();
        if val == 0 && code != OpCode::IntMult {
            data.op_set_opcode(op, OpCode::Copy);
            data.op_remove_input(op, 1);
            return 1;
        }
        if code != OpCode::IntMult {
            return 0;
        }
        match val {
            1 => {
                data.op_set_opcode(op, OpCode::Copy);
                data.op_remove_input(op, 1);
                1
            }
            0 => {
                data.op_set_opcode(op, OpCode::Copy);
                data.op_remove_input(op, 0); // keep the constant 0
                1
            }
            _ => 0,
        }
    }
}

/// Shift identities (Ghidra's `RuleTrivialShift`): `x << 0` → `x`; a logical shift by ≥ the
/// operand width → `0` (an arithmetic right shift by ≥ width is left alone).
pub struct RuleTrivialShift;

impl Rule for RuleTrivialShift {
    fn name(&self) -> &str {
        "trivialshift"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntLeft, OpCode::IntRight, OpCode::IntSright]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let val = data.vn(in1).constant_value();
        if val != 0 {
            let in0_size = data.vn(data.op(op).input(0).unwrap()).size;
            if val < 8 * in0_size as u64 || data.op(op).code() == OpCode::IntSright {
                return 0;
            }
            let zero = data.new_const(in0_size, 0);
            data.op_set_input(op, 0, zero);
        }
        data.op_remove_input(op, 1);
        data.op_set_opcode(op, OpCode::Copy);
        1
    }
}

/// `RuleShift2Mult` (Ghidra): `V << c` → `V * 2^c`, but only when the shift is involved in an
/// arithmetic expression (its operand's def, or one of its uses, is INT_ADD/INT_SUB/INT_MULT) — so
/// a left-shift that is really a scaled multiply joins the surrounding arithmetic and combines:
/// `(q * 0xf) << 2` → `q * 0xf * 4` → (`RuleAddMultCollapse`) `q * 0x3c`, which `RuleModOpt` folds.
/// A shift by ≥ 32 is left alone (anything that big is unlikely to be an arithmetic multiply).
pub struct RuleShift2Mult;

impl Rule for RuleShift2Mult {
    fn name(&self) -> &str {
        "shift2mult"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntLeft]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let val = data.vn(in1).constant_value();
        if val >= 32 {
            return 0; // arbitrary (Ghidra): bigger is probably not an arithmetic multiply
        }
        // Involved in arithmetic? the shifted operand's def, or any use of the result.
        let is_arith = |c: OpCode| matches!(c, OpCode::IntAdd | OpCode::IntSub | OpCode::IntMult);
        let in0 = data.op(op).input(0).unwrap();
        let input_arith = data.vn(in0).def.is_some_and(|d| is_arith(data.op(d).code()));
        let out = data.op(op).output;
        let desc_arith =
            out.is_some_and(|o| data.vn(o).descend.iter().any(|&d| is_arith(data.op(d).code())));
        if !input_arith && !desc_arith {
            return 0;
        }
        let out_size = data.vn(out.unwrap()).size;
        let nc = data.new_const(out_size, 1u64 << val);
        data.op_set_input(op, 1, nc);
        data.op_set_opcode(op, OpCode::IntMult);
        1
    }
}

/// Ghidra `RuleCollectTerms::getMultCoeff` (ruleaction.cc:82): if `vn = INT_MULT(base, c)` with `c`
/// constant, return `(base, c)`; otherwise `(vn, 1)`.
fn get_mult_coeff(data: &Funcdata, vn: VarnodeId) -> (VarnodeId, u64) {
    if let Some(def) = data.vn(vn).def {
        if data.op(def).code() == OpCode::IntMult {
            if let Some(c) = data.op(def).input(1) {
                if data.vn(c).is_constant() {
                    return (data.op(def).input(0).unwrap(), data.vn(c).constant_value());
                }
            }
        }
    }
    (vn, 1)
}

/// Ghidra `Varnode::termOrder` (varnode.cc:1153): order two additive terms — constants sort last,
/// non-constants by their base varnode's storage address (peeling an `INT_MULT`-by-constant
/// coefficient first, so `x*c` and `x` compare equal). Basis of `TermOrder::additiveCompare`.
fn term_order(data: &Funcdata, this: VarnodeId, op: VarnodeId) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let peel = |vn: VarnodeId| -> VarnodeId {
        if let Some(def) = data.vn(vn).def {
            if data.op(def).code() == OpCode::IntMult
                && data.op(def).input(1).is_some_and(|c| data.vn(c).is_constant())
            {
                return data.op(def).input(0).unwrap();
            }
        }
        vn
    };
    if data.vn(this).is_constant() {
        if !data.vn(op).is_constant() {
            return Ordering::Greater;
        }
        return Ordering::Equal;
    }
    if data.vn(op).is_constant() {
        return Ordering::Less;
    }
    let a = data.vn(peel(this)).loc;
    let b = data.vn(peel(op)).loc;
    (a.space.0, a.offset).cmp(&(b.space.0, b.offset))
}

/// One additive term of an `INT_ADD` tree: the op adding it, the input slot, and the optional
/// distributing `INT_MULT` coefficient (Ghidra `AdditiveEdge`, expression.hh:106).
struct AdditiveEdge {
    op: OpId,
    slot: usize,
    mult: Option<OpId>,
}

/// Ghidra `TermOrder::collect` (expression.cc:236): gather every additive term of the `INT_ADD` tree
/// rooted at `root`. A term is a leaf varnode (unwritten, multiply-used, or not an INT_ADD); an
/// `INT_MULT(INT_ADD(..), c)` with a lone-descendant inner ADD is descended into, carrying the MULT
/// as a distributing multiplier.
fn collect_terms(data: &Funcdata, root: OpId) -> Vec<AdditiveEdge> {
    let mut terms = Vec::new();
    let mut stack: Vec<(OpId, Option<OpId>)> = vec![(root, None)];
    while let Some((curop, multop)) = stack.pop() {
        for i in 0..data.op(curop).num_inputs() {
            let curvn = data.op(curop).input(i).unwrap();
            if !data.vn(curvn).is_written() || data.vn(curvn).descend.len() != 1 {
                terms.push(AdditiveEdge { op: curop, slot: i, mult: multop });
                continue;
            }
            let subop = data.vn(curvn).def.unwrap();
            if data.op(subop).code() != OpCode::IntAdd {
                if data.op(subop).code() == OpCode::IntMult
                    && data.op(subop).input(1).is_some_and(|c| data.vn(c).is_constant())
                {
                    if let Some(addop) = data.op(subop).input(0).and_then(|v| data.vn(v).def) {
                        if data.op(addop).code() == OpCode::IntAdd
                            && data.op(addop).output.is_some_and(|o| data.vn(o).descend.len() == 1)
                        {
                            stack.push((addop, Some(subop)));
                            continue;
                        }
                    }
                }
                terms.push(AdditiveEdge { op: curop, slot: i, mult: multop });
                continue;
            }
            stack.push((subop, multop));
        }
    }
    terms
}

/// Ghidra `Funcdata::distributeIntMultAdd` (funcdata_op.cc:1071): rewrite `INT_MULT(INT_ADD(a,b), c)`
/// (c constant) into `INT_ADD(a*c, b*c)` so the coefficient reaches the inner terms.
fn distribute_int_mult_add(data: &mut Funcdata, op: OpId) -> bool {
    let addop = data.vn(data.op(op).input(0).unwrap()).def.unwrap();
    let vn0 = data.op(addop).input(0).unwrap();
    let vn1 = data.op(addop).input(1).unwrap();
    if data.vn(vn0).is_free() && !data.vn(vn0).is_constant() {
        return false;
    }
    if data.vn(vn1).is_free() && !data.vn(vn1).is_constant() {
        return false;
    }
    let coeff = data.vn(data.op(op).input(1).unwrap()).constant_value();
    let sz = data.vn(data.op(op).output.unwrap()).size;
    let mk = |data: &mut Funcdata, vn: VarnodeId| -> VarnodeId {
        if data.vn(vn).is_constant() {
            let val = coeff.wrapping_mul(data.vn(vn).constant_value()) & super::nzmask::calc_mask(sz);
            data.new_const(sz, val)
        } else {
            let newc = data.new_const(sz, coeff);
            let newop = data.new_op_before_sized(op, OpCode::IntMult, vec![vn, newc], sz);
            data.op(newop).output.unwrap()
        }
    };
    let newvn0 = mk(data, vn0);
    let newvn1 = mk(data, vn1);
    data.op_set_input(op, 0, newvn0);
    data.op_set_input(op, 1, newvn1);
    data.op_set_opcode(op, OpCode::IntAdd);
    true
}

/// Collect like additive terms (Ghidra's `RuleCollectTerms`, ruleaction.cc:107): gather all terms of
/// an `INT_ADD` tree, sort them so like terms are adjacent, then combine `a*c1 + a*c2 => a*(c1+c2)`
/// (dropping the term when the coefficient reaches 0 — this is what cancels a division's
/// `+ (x s>> k) - (x s>> k)` sign correction), or lump multiple constant addends into one. Runs only
/// at the root of the ADD tree; operates on `INT_ADD` only (negation arrives as `*-1` via
/// [`RuleSub2Add`]).
pub struct RuleCollectTerms;

impl Rule for RuleCollectTerms {
    fn name(&self) -> &str {
        "collectterms"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAdd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        // Only fire at the root of an ADD tree.
        let out = data.op(op).output.unwrap();
        if data.vn(out).descend.len() == 1 && data.op(data.vn(out).descend[0]).code() == OpCode::IntAdd
        {
            return 0;
        }
        let terms = collect_terms(data, op);
        // `order` is the sorted permutation of term positions (Ghidra's `getSort()`); `order[k]`
        // indexes into `terms`. `tvn(k)` is the term varnode at sorted position `k`.
        let tvn = |data: &Funcdata, t: &AdditiveEdge| data.op(t.op).input(t.slot).unwrap();
        let mut order: Vec<usize> = (0..terms.len()).collect();
        order.sort_by(|&a, &b| term_order(data, tvn(data, &terms[a]), tvn(data, &terms[b])));

        // Combine the first pair of adjacent non-constant terms with equal base.
        let mut i = 0usize;
        if !order.is_empty() && !data.vn(tvn(data, &terms[order[0]])).is_constant() {
            i = 1;
            while i < order.len() {
                let vn2raw = tvn(data, &terms[order[i]]);
                if data.vn(vn2raw).is_constant() {
                    break;
                }
                let (vn1, coef1) = get_mult_coeff(data, tvn(data, &terms[order[i - 1]]));
                let (vn2, coef2) = get_mult_coeff(data, vn2raw);
                if vn1 == vn2 {
                    let prev = &terms[order[i - 1]];
                    let cur = &terms[order[i]];
                    if let Some(m) = prev.mult {
                        return if distribute_int_mult_add(data, m) { 1 } else { 0 };
                    }
                    if let Some(m) = cur.mult {
                        return if distribute_int_mult_add(data, m) { 1 } else { 0 };
                    }
                    let sz = data.vn(vn1).size;
                    let newcoef = coef1.wrapping_add(coef2) & super::nzmask::calc_mask(sz);
                    let (pop, pslot) = (prev.op, prev.slot);
                    let (cop, cslot) = (cur.op, cur.slot);
                    let zerocoeff = data.new_const(sz, 0);
                    data.op_set_input(pop, pslot, zerocoeff);
                    if newcoef == 0 {
                        let newcoeff = data.new_const(sz, 0);
                        data.op_set_input(cop, cslot, newcoeff);
                    } else {
                        let newcoeff = data.new_const(sz, newcoef);
                        let nextop =
                            data.new_op_before_sized(cop, OpCode::IntMult, vec![vn1, newcoeff], sz);
                        let vn2out = data.op(nextop).output.unwrap();
                        data.op_set_input(cop, cslot, vn2out);
                    }
                    return 1;
                }
                i += 1;
            }
        }

        // Lump multiple constant addends (those without a multiplier) into one. Positions are the
        // sorted order (constants sort last); `lastconst` is the earliest such position.
        let mut coef1: u64 = 0;
        let mut nonzerocount = 0;
        let mut lastconst = 0usize;
        for pos in (i..order.len()).rev() {
            let t = &terms[order[pos]];
            if t.mult.is_some() {
                continue;
            }
            let val = data.vn(tvn(data, t)).constant_value();
            if val != 0 {
                nonzerocount += 1;
                coef1 = coef1.wrapping_add(val);
                lastconst = pos;
            }
        }
        if nonzerocount <= 1 {
            return 0;
        }
        let sz = data.vn(tvn(data, &terms[order[lastconst]])).size;
        coef1 &= super::nzmask::calc_mask(sz);
        for pos in (lastconst + 1)..order.len() {
            let t = &terms[order[pos]];
            if t.mult.is_none() {
                let (top, tslot) = (t.op, t.slot);
                let z = data.new_const(sz, 0);
                data.op_set_input(top, tslot, z);
            }
        }
        let (lop, lslot) = { let t = &terms[order[lastconst]]; (t.op, t.slot) };
        let c = data.new_const(sz, coef1);
        data.op_set_input(lop, lslot, c);
        1
    }
}

/// Copy propagation (Ghidra's `RulePropagateCopy`): if an op reads `vn` where
/// `vn = COPY(invn)`, read `invn` directly. The COPY's output loses this use and dead-code
/// removes it. Applied to every op. (Skips propagating a constant *into* a marker so phis
/// keep their structure; the addrtied/addrforce guards await those flags.)
pub struct RulePropagateCopy;

impl Rule for RulePropagateCopy {
    fn name(&self) -> &str {
        "propagatecopy"
    }
    fn oplist(&self) -> Vec<OpCode> {
        Vec::new() // every op
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        // Ghidra `RulePropagateCopy::applyOp` (ruleaction.cc:3933): `if (op->isReturnCopy()) return 0;`.
        // `TypeOpReturn` sets `return_copy` as a default opflag (typeop.cc:878), so every CPUI_RETURN
        // op is a "return copy" — copies are never propagated into a RETURN's inputs, keeping the
        // returned register in place. `Heritage::guardReturns` also marks its global-holding COPY
        // (heritage.cc:1686) — bailing on it keeps that COPY reading the store version directly (else
        // propagatecopy would replace its input with the store's own source, stripping the reader).
        if data.op(op).code() == OpCode::Return || data.op(op).is_return_copy() {
            return 0;
        }
        for i in 0..data.op(op).num_inputs() {
            let vn = data.op(op).input(i).unwrap();
            let Some(def) = data.vn(vn).def else { continue };
            if data.op(def).code() != OpCode::Copy {
                continue;
            }
            let invn = data.op(def).input(0).unwrap();
            if invn == vn || data.vn(invn).is_free() {
                continue; // self-copy, or source not heritage-known
            }
            if data.op(op).is_marker() && data.vn(invn).is_constant() {
                continue; // don't fold a constant into a MULTIEQUAL/INDIRECT
            }
            data.op_set_input(op, i, invn);
            return 1;
        }
        0
    }
}

fn is_const0(data: &Funcdata, v: VarnodeId) -> bool {
    data.vn(v).is_constant() && data.vn(v).constant_value() == 0
}

/// Whether two varnodes denote the same value — the same id, or equal-valued constants.
/// (Constants aren't interned, so distinct constant varnodes can share a value; Ghidra's
/// `*vn` comparison treats them as equal.)
fn same_value(data: &Funcdata, a: VarnodeId, b: VarnodeId) -> bool {
    a == b || {
        let (va, vb) = (data.vn(a), data.vn(b));
        va.is_constant() && vb.is_constant() && va.size == vb.size
            && va.constant_value() == vb.constant_value()
    }
}

/// Ghidra `AddExpression` (expression.hh:141): lightweight matcher for an additive expression — up
/// to two non-constant terms (a varnode + multiplicative coefficient) plus a collected constant.
/// [`AddExpression::gather`] walks INT_ADD (recursively, depth-limited) and INT_MULT-by-constant
/// (folding the coefficient), so `a - b` written as `a + b*(-1)` (post-[`RuleSub2Add`]) compares
/// equal to the direct subtraction — which is what keeps `RuleSborrow`/`RuleScarry` firing once
/// subtraction is canonicalized to the additive form.
struct AddExpression {
    constval: u64,
    terms: Vec<(VarnodeId, u64)>, // up to 2 (varnode, coefficient)
}

impl AddExpression {
    fn new() -> Self {
        AddExpression { constval: 0, terms: Vec::new() }
    }
    fn add(&mut self, vn: VarnodeId, coeff: u64) {
        if self.terms.len() < 2 {
            self.terms.push((vn, coeff));
        }
    }
    fn gather(&mut self, data: &Funcdata, vn: VarnodeId, coeff: u64, depth: i32) {
        if data.vn(vn).is_constant() {
            let m = super::nzmask::calc_mask(data.vn(vn).size);
            self.constval =
                self.constval.wrapping_add(coeff.wrapping_mul(data.vn(vn).constant_value())) & m;
            return;
        }
        if data.vn(vn).is_written() {
            let op = data.vn(vn).def.unwrap();
            if data.op(op).code() == OpCode::IntAdd && data.op(op).num_inputs() == 2 {
                let mut d = depth;
                if !data.vn(data.op(op).input(1).unwrap()).is_constant() {
                    d -= 1;
                }
                if d >= 0 {
                    self.gather(data, data.op(op).input(0).unwrap(), coeff, d);
                    self.gather(data, data.op(op).input(1).unwrap(), coeff, d);
                    return;
                }
            } else if data.op(op).code() == OpCode::IntMult && data.op(op).num_inputs() == 2 {
                let c1 = data.op(op).input(1).unwrap();
                if data.vn(c1).is_constant() {
                    let m = super::nzmask::calc_mask(data.vn(vn).size);
                    let c = coeff.wrapping_mul(data.vn(c1).constant_value()) & m;
                    self.gather(data, data.op(op).input(0).unwrap(), c, depth);
                    return;
                }
            }
        }
        self.add(vn, coeff);
    }
    fn gather_two_terms_subtract(&mut self, data: &Funcdata, a: VarnodeId, b: VarnodeId) {
        let depth = if data.vn(a).is_constant() || data.vn(b).is_constant() { 1 } else { 0 };
        self.gather(data, a, 1, depth);
        self.gather(data, b, super::nzmask::calc_mask(data.vn(b).size), depth);
    }
    fn gather_two_terms_add(&mut self, data: &Funcdata, a: VarnodeId, b: VarnodeId) {
        let depth = if data.vn(a).is_constant() || data.vn(b).is_constant() { 1 } else { 0 };
        self.gather(data, a, 1, depth);
        self.gather(data, b, 1, depth);
    }
    fn gather_two_terms_root(&mut self, data: &Funcdata, root: VarnodeId) {
        self.gather(data, root, 1, 1);
    }
    fn is_equivalent(&self, data: &Funcdata, other: &AddExpression) -> bool {
        if self.constval != other.constval || self.terms.len() != other.terms.len() {
            return false;
        }
        let te = |t1: (VarnodeId, u64), t2: (VarnodeId, u64)| {
            t1.1 == t2.1 && functional_equality(data, t1.0, t2.0)
        };
        match self.terms.len() {
            1 => te(self.terms[0], other.terms[0]),
            2 => {
                (te(self.terms[0], other.terms[0]) && te(self.terms[1], other.terms[1]))
                    || (te(self.terms[0], other.terms[1]) && te(self.terms[1], other.terms[0]))
            }
            _ => false, // Ghidra returns false for 0 terms (pure constants)
        }
    }
}

/// Does `xvn` compute `avn - bvn`? Uses Ghidra's [`AddExpression`] functional comparison, so it holds
/// whether the difference is an `INT_SUB` or the canonical `avn + bvn*(-1)` additive form.
fn subtract_matches(data: &Funcdata, xvn: VarnodeId, avn: VarnodeId, bvn: VarnodeId) -> bool {
    let mut expr1 = AddExpression::new();
    expr1.gather_two_terms_subtract(data, avn, bvn);
    let mut expr2 = AddExpression::new();
    expr2.gather_two_terms_root(data, xvn);
    expr1.is_equivalent(data, &expr2)
}

/// Does `xvn` compute `avn + bvn`? The additive-sum counterpart of [`subtract_matches`] used by
/// [`RuleScarry`] (Ghidra `AddExpression::gatherTwoTermsAdd`).
fn add_matches(data: &Funcdata, xvn: VarnodeId, avn: VarnodeId, bvn: VarnodeId) -> bool {
    let mut expr1 = AddExpression::new();
    expr1.gather_two_terms_add(data, avn, bvn);
    let mut expr2 = AddExpression::new();
    expr2.gather_two_terms_root(data, xvn);
    expr1.is_equivalent(data, &expr2)
}

/// Simplify signed comparisons built from `INT_SBORROW` (Ghidra's `RuleSborrow`). The x86
/// signed-compare flag idiom `sborrow(V,W) != ((V-W) s< 0)` is exactly `V s< W` (and the
/// `0 s< (V-W)` / `INT_EQUAL` variants give the swapped operands and `s<=`); also
/// `sborrow(V,0) => false`.
pub struct RuleSborrow;

impl Rule for RuleSborrow {
    fn name(&self) -> &str {
        "sborrow"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSborrow]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let avn = data.op(op).input(0).unwrap();
        let bvn = data.op(op).input(1).unwrap();
        if is_const0(data, bvn) {
            let z = data.new_const(1, 0);
            data.op_set_opcode(op, OpCode::Copy);
            data.op_set_all_input(op, &[z]);
            return 1;
        }
        let Some(svn) = data.op(op).output else { return 0 };
        for compop in data.vn(svn).descend.clone() {
            let cc = data.op(compop).code();
            if (cc != OpCode::IntEqual && cc != OpCode::IntNotequal) || data.op(compop).num_inputs() != 2 {
                continue;
            }
            let (i0, i1) = (data.op(compop).input(0).unwrap(), data.op(compop).input(1).unwrap());
            let cvn = if i0 == svn { i1 } else { i0 };
            let Some(signdef) = data.vn(cvn).def else { continue };
            if data.op(signdef).code() != OpCode::IntSless || data.op(signdef).num_inputs() != 2 {
                continue;
            }
            let (s0, s1) = (data.op(signdef).input(0).unwrap(), data.op(signdef).input(1).unwrap());
            let zside = if is_const0(data, s0) {
                0
            } else if is_const0(data, s1) {
                1
            } else {
                continue;
            };
            let xvn = if zside == 0 { s1 } else { s0 };
            if !subtract_matches(data, xvn, avn, bvn) {
                continue;
            }
            // NOTEQUAL ⇒ V s< W (avn at 1-zside); EQUAL ⇒ V s<= W (avn at zside)
            let (newcode, slot_a) = if cc == OpCode::IntNotequal {
                (OpCode::IntSless, 1 - zside)
            } else {
                (OpCode::IntSlessequal, zside)
            };
            let mut inputs = [avn; 2];
            inputs[slot_a] = avn;
            inputs[1 - slot_a] = bvn;
            data.op_set_opcode(compop, newcode);
            data.op_set_all_input(compop, &inputs);
            return 1;
        }
        0
    }
}

/// Simplify signed comparisons built from `INT_SCARRY` (Ghidra's `RuleScarry`) — the additive
/// sibling of [`RuleSborrow`]. Trivial `scarry(V,0) => false`. Otherwise, when one operand is a
/// constant `c`, the flag idiom comparing `scarry(V,c)` against the sign of `V + c`
/// (`INT_SLESS` vs 0) is a signed compare of `V` against `-c`: `INT_NOTEQUAL => V s< -c`,
/// `INT_EQUAL => V s<= -c` (with the `0 s< (V+c)` variant giving the swapped operands). The rule
/// requires a constant operand and skips the integer minimum (whose negation is a no-op).
pub struct RuleScarry;

impl Rule for RuleScarry {
    fn name(&self) -> &str {
        "scarry"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntScarry]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let mut avn = data.op(op).input(0).unwrap();
        let mut bvn = data.op(op).input(1).unwrap();
        // Trivial: either operand is const 0 → the sum never carries.
        if is_const0(data, avn) || is_const0(data, bvn) {
            let z = data.new_const(1, 0);
            data.op_set_opcode(op, OpCode::Copy);
            data.op_set_all_input(op, &[z]);
            return 1;
        }
        // One side must be constant; swap so `bvn` holds it. Skip the integer minimum — negating it
        // is a no-op, so the `-c` rewrite would be wrong.
        if !data.vn(bvn).is_constant() {
            if !data.vn(avn).is_constant() {
                return 0;
            }
            std::mem::swap(&mut avn, &mut bvn);
            let size = data.vn(bvn).size;
            let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
            let intmin = mask ^ (mask >> 1);
            if intmin == data.vn(bvn).constant_value() {
                return 0;
            }
        }
        let Some(svn) = data.op(op).output else { return 0 };
        for compop in data.vn(svn).descend.clone() {
            let cc = data.op(compop).code();
            if (cc != OpCode::IntEqual && cc != OpCode::IntNotequal) || data.op(compop).num_inputs() != 2 {
                continue;
            }
            let (i0, i1) = (data.op(compop).input(0).unwrap(), data.op(compop).input(1).unwrap());
            let cvn = if i0 == svn { i1 } else { i0 };
            let Some(signdef) = data.vn(cvn).def else { continue };
            if data.op(signdef).code() != OpCode::IntSless || data.op(signdef).num_inputs() != 2 {
                continue;
            }
            let (s0, s1) = (data.op(signdef).input(0).unwrap(), data.op(signdef).input(1).unwrap());
            let zside = if is_const0(data, s0) {
                0
            } else if is_const0(data, s1) {
                1
            } else {
                continue;
            };
            let xvn = if zside == 0 { s1 } else { s0 };
            if !add_matches(data, xvn, avn, bvn) {
                continue;
            }
            let size = data.vn(bvn).size;
            let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
            let newval = data.vn(bvn).constant_value().wrapping_neg() & mask;
            let newc = data.new_const(size, newval);
            let mut inputs = [avn; 2];
            // NOTEQUAL ⇒ V s< -c (avn at 1-zside); EQUAL ⇒ V s<= -c (avn at zside).
            if cc == OpCode::IntNotequal {
                data.op_set_opcode(compop, OpCode::IntSless);
                inputs[1 - zside] = avn;
                inputs[zside] = newc;
            } else {
                data.op_set_opcode(compop, OpCode::IntSlessequal);
                inputs[zside] = avn;
                inputs[1 - zside] = newc;
            }
            data.op_set_all_input(compop, &inputs);
            return 1;
        }
        0
    }
}

/// Compare against zero through a subtraction (Ghidra's `RuleEqual2Zero`): `(a - b) == 0`
/// → `a == b`, and `(a + c) == 0` → `a == -c` for a constant `c` (likewise INT_NOTEQUAL).
/// Normalises the flag-derived equality so [`RuleLessEqual`] can match it against the less.
pub struct RuleEqual2Zero;

impl Rule for RuleEqual2Zero {
    fn name(&self) -> &str {
        "equal2zero"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntEqual, OpCode::IntNotequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let (i0, i1) = (data.op(op).input(0).unwrap(), data.op(op).input(1).unwrap());
        let other = if is_const0(data, i1) {
            i0
        } else if is_const0(data, i0) {
            i1
        } else {
            return 0;
        };
        // DEBT (Task #20): Ghidra's RuleEqual2Zero (ruleaction.cc:~8xx) guards here — it fires only
        // when EVERY descendant of the sum is a bool-output op (`for (iter : addvn->beginDescend())
        // if (!boolop->isBoolOutput()) return 0;`). That guard is deliberately OMITTED: adding it
        // suppresses an equal2zero firing switchloop's jumptable recovery depends on, because
        // mosura's switch-path IR gives the guard sum a non-bool use Ghidra's doesn't (a separate
        // switch-path divergence). Per no-adaptation-grandfathered this omission is CANCELED the
        // moment that divergence is fixed — restore the guard then and re-verify switchloop.
        let Some(def) = data.vn(other).def else { return 0 };
        if data.op(def).num_inputs() != 2 {
            return 0;
        }
        let (a, b) = (data.op(def).input(0).unwrap(), data.op(def).input(1).unwrap());
        match data.op(def).code() {
            OpCode::IntSub => {
                data.op_set_all_input(op, &[a, b]);
                1
            }
            OpCode::IntAdd if data.vn(b).is_constant() => {
                let size = data.vn(b).size;
                // Mask the negated constant to the operand size — a `uintb` constant is always the
                // masked value (Ghidra `calc_mask`). Without this, `-c` computed in 64 bits leaves the
                // high bits set (e.g. `-0xfffffff6` → `0xffffffff0000000a` in a 4-byte const), which
                // then fails to match the sibling INT_LESS's clean constant in `RuleLessEqual`.
                let neg = data.vn(b).constant_value().wrapping_neg() & super::nzmask::calc_mask(size);
                let nc = data.new_const(size, neg);
                data.op_set_all_input(op, &[a, nc]);
                1
            }
            OpCode::IntAdd => {
                // `(posvn + x*(-1)) == 0  =>  posvn == x` — the post-RuleSub2Add subtraction form.
                let mult_neg1 = |data: &Funcdata, v: VarnodeId| -> Option<VarnodeId> {
                    let d = data.vn(v).def?;
                    if data.op(d).code() != OpCode::IntMult {
                        return None;
                    }
                    let unneg = data.op(d).input(0)?;
                    let m = data.op(d).input(1)?;
                    (data.vn(m).is_constant()
                        && data.vn(m).constant_value() == super::nzmask::calc_mask(data.vn(unneg).size))
                    .then_some(unneg)
                };
                let (posvn, unnegvn) = if let Some(u) = mult_neg1(data, a) {
                    (b, u)
                } else if let Some(u) = mult_neg1(data, b) {
                    (a, u)
                } else {
                    return 0;
                };
                if !data.vn(posvn).is_heritage_known() || !data.vn(unnegvn).is_heritage_known() {
                    return 0;
                }
                data.op_set_all_input(op, &[posvn, unnegvn]);
                1
            }
            _ => 0,
        }
    }
}

/// Combine a less-than and an equality into less-than-or-equal (Ghidra's `RuleLessEqual`):
/// `V < W || V == W` → `V <= W`, and `V < W || V != W` → `V != W`. Handles signed and
/// unsigned, operands in either order. This collapses the x86 `jle`/`jbe` flag idiom (the
/// `ZF || (SF != OF)` pair) into a single comparison.
pub struct RuleLessEqual;

impl Rule for RuleLessEqual {
    fn name(&self) -> &str {
        "lessequal"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolOr]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let i0 = data.op(op).input(0).unwrap();
        let i1 = data.op(op).input(1).unwrap();
        let code_of = |v: VarnodeId| data.vn(v).def.map(|d| data.op(d).code());
        let is_less = |c: Option<OpCode>| matches!(c, Some(OpCode::IntLess | OpCode::IntSless));
        let is_eq = |c: Option<OpCode>| matches!(c, Some(OpCode::IntEqual | OpCode::IntNotequal));
        let (less_v, equal_v) = if is_less(code_of(i0)) && is_eq(code_of(i1)) {
            (i0, i1)
        } else if is_less(code_of(i1)) && is_eq(code_of(i0)) {
            (i1, i0)
        } else {
            return 0;
        };
        let less_op = data.vn(less_v).def.unwrap();
        let equal_op = data.vn(equal_v).def.unwrap();
        if data.op(less_op).num_inputs() != 2 || data.op(equal_op).num_inputs() != 2 {
            return 0;
        }
        let (l0, l1) = (data.op(less_op).input(0).unwrap(), data.op(less_op).input(1).unwrap());
        let (e0, e1) = (data.op(equal_op).input(0).unwrap(), data.op(equal_op).input(1).unwrap());
        let matches = (same_value(data, l0, e0) && same_value(data, l1, e1))
            || (same_value(data, l0, e1) && same_value(data, l1, e0));
        if !matches {
            return 0;
        }
        if data.op(equal_op).code() == OpCode::IntNotequal {
            // V < W || V != W  =>  V != W
            let eqout = data.op(equal_op).output.unwrap();
            data.op_set_opcode(op, OpCode::Copy);
            data.op_set_all_input(op, &[eqout]);
        } else {
            let newcode = if data.op(less_op).code() == OpCode::IntSless {
                OpCode::IntSlessequal
            } else {
                OpCode::IntLessequal
            };
            data.op_set_opcode(op, newcode);
            data.op_set_all_input(op, &[l0, l1]);
        }
        1
    }
}

/// Combine a less-than-or-equal and an inequality into less-than (Ghidra's `RuleLessNotEqual`,
/// ruleaction.cc): `(V <= W) && (V != W)  =>  V < W` (signed and unsigned, operands in either
/// order). Once [`RuleSub2Add`] canonicalizes the `!=` operand, `RuleEqual2Zero` reduces
/// `(V - W) != 0` to `V != W`, and this rule collapses the loop guard `i <= n && i != n` to `i < n`.
pub struct RuleLessNotEqual;

impl Rule for RuleLessNotEqual {
    fn name(&self) -> &str {
        "lessnotequal"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let vnout1 = data.op(op).input(0).unwrap();
        let vnout2 = data.op(op).input(1).unwrap();
        if !data.vn(vnout1).is_written() || !data.vn(vnout2).is_written() {
            return 0;
        }
        let is_le = |c: OpCode| matches!(c, OpCode::IntLessequal | OpCode::IntSlessequal);
        let mut op_less = data.vn(vnout1).def.unwrap();
        let mut opc = data.op(op_less).code();
        let op_equal;
        if !is_le(opc) {
            op_equal = op_less;
            op_less = data.vn(vnout2).def.unwrap();
            opc = data.op(op_less).code();
            if !is_le(opc) {
                return 0;
            }
        } else {
            op_equal = data.vn(vnout2).def.unwrap();
        }
        if data.op(op_equal).code() != OpCode::IntNotequal
            || data.op(op_less).num_inputs() != 2
            || data.op(op_equal).num_inputs() != 2
        {
            return 0;
        }
        let compvn1 = data.op(op_less).input(0).unwrap();
        let compvn2 = data.op(op_less).input(1).unwrap();
        if !data.vn(compvn1).is_heritage_known() || !data.vn(compvn2).is_heritage_known() {
            return 0;
        }
        let (e0, e1) = (data.op(op_equal).input(0).unwrap(), data.op(op_equal).input(1).unwrap());
        let matches = (same_value(data, compvn1, e0) && same_value(data, compvn2, e1))
            || (same_value(data, compvn1, e1) && same_value(data, compvn2, e0));
        if !matches {
            return 0;
        }
        let newcode = if opc == OpCode::IntSlessequal { OpCode::IntSless } else { OpCode::IntLess };
        data.op_set_opcode(op, newcode);
        data.op_set_all_input(op, &[compvn1, compvn2]);
        1
    }
}

/// Ghidra `RuleRangeMeld` (ruleaction.cc:1348, oppool1 @101 coreaction.cc:5612): merge two range
/// conditions of the form `V s< c`, `c s< V`, `V == c`, `V != c` combined by BOOL_AND / BOOL_OR
/// into a single comparison. Each side is pulled back to a common Varnode `A` as a [`CircleRange`]
/// (Ghidra `CircleRange::pullBack`); the two ranges are then intersected (for `&&`) or unioned
/// (for `||`) and [`CircleRange::translate2_op`] re-expresses the result as one comparison against
/// a constant (or a constant `true`/`false`). This collapses the x86 signed-compare flag
/// reconstructions: the `jg` form `(x != c) && (c-1 s< x)` folds to `c s< x`, and the `jle` form
/// `(x == c) || (x s< c)` folds to `x s<= c` (which [`RuleIntLessEqual`] then normalizes to
/// `x s< c+1`). mosura previously leaned on [`RuleLessNotEqual`] for the `&&` case, but that needs
/// the SLESSEQUAL form; once RuleIntLessEqual @10 converts SLESSEQUAL to SLESS, this rule is what
/// recovers the fold.
pub struct RuleRangeMeld;

impl Rule for RuleRangeMeld {
    fn name(&self) -> &str {
        "rangemeld"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolOr, OpCode::BoolAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let vn1 = data.op(op).input(0).unwrap();
        let vn2 = data.op(op).input(1).unwrap();
        if !data.vn(vn1).is_written() || !data.vn(vn2).is_written() {
            return 0;
        }
        let sub1 = data.vn(vn1).def.unwrap();
        let sub2 = data.vn(vn2).def.unwrap();
        if !data.op(sub1).is_bool_output() || !data.op(sub2).is_bool_output() {
            return 0;
        }

        // Pull the {true} range back through each side's defining comparison to a base Varnode.
        let mut range1 = CircleRange::from_bool(true);
        let Some(mut a1) = range1.pull_back(data, sub1, false) else {
            return 0;
        };
        let mut range2 = CircleRange::from_bool(true);
        let Some(mut a2) = range2.pull_back(data, sub2, false) else {
            return 0;
        };
        // An extra pull-back if the last step was a boolean negate `!`.
        if data.op(sub1).code() == OpCode::BoolNegate {
            if !data.vn(a1).is_written() {
                return 0;
            }
            let d = data.vn(a1).def.unwrap();
            match range1.pull_back(data, d, false) {
                Some(x) => a1 = x,
                None => return 0,
            }
        }
        if data.op(sub2).code() == OpCode::BoolNegate {
            if !data.vn(a2).is_written() {
                return 0;
            }
            let d = data.vn(a2).def.unwrap();
            match range2.pull_back(data, d, false) {
                Some(x) => a2 = x,
                None => return 0,
            }
        }

        if !functional_equality(data, a1, a2) {
            // Different base Varnodes — Ghidra allows one more pull-back on the wider side (a size
            // mismatch resolving through a zext/sext step) and then requires identity.
            if data.vn(a2).size == data.vn(a1).size {
                return 0;
            }
            if data.vn(a1).size < data.vn(a2).size && data.vn(a2).is_written() {
                let d = data.vn(a2).def.unwrap();
                match range2.pull_back(data, d, false) {
                    Some(x) => a2 = x,
                    None => return 0,
                }
            } else if data.vn(a1).is_written() {
                let d = data.vn(a1).def.unwrap();
                match range1.pull_back(data, d, false) {
                    Some(x) => a1 = x,
                    None => return 0,
                }
            }
            if a1 != a2 {
                return 0;
            }
        }
        if !data.vn(a1).is_heritage_known() {
            return 0;
        }

        let mut restype = if data.op(op).code() == OpCode::BoolAnd {
            range1.intersect(&range2)
        } else {
            range1.circle_union(&range2)
        };

        if restype == 0 {
            let (t, opc, resc, resslot) = range1.translate2_op();
            if t == 0 {
                let size = data.vn(a1).size;
                let newconst = data.new_const(size, resc);
                data.op_set_opcode(op, opc);
                data.op_set_input(op, (1 - resslot) as usize, a1);
                data.op_set_input(op, resslot as usize, newconst);
                return 1;
            }
            restype = t;
        }

        if restype == 2 {
            return 0; // Cannot represent as a single comparison
        }
        if restype == 1 {
            // Pieces cover every value → the condition is always true.
            data.op_set_opcode(op, OpCode::Copy);
            data.op_remove_input(op, 1);
            let one = data.new_const(1, 1);
            data.op_set_input(op, 0, one);
        } else if restype == 3 {
            // Nothing left in the intersection → the condition is always false.
            data.op_set_opcode(op, OpCode::Copy);
            data.op_remove_input(op, 1);
            let zero = data.new_const(1, 0);
            data.op_set_input(op, 0, zero);
        }
        1
    }
}

/// Ghidra `PcodeOp::getCseHash` (`op.cc:130`): a hash of output size + opcode + input identities,
/// the primary duplicate-calculation test for [`cse_eliminate_list`]. Returns 0 (unhashable) for
/// `COPY` (`op.cc:135`, "let copy propagation deal with this"). Ghidra's eval-type unary|binary
/// guard (`op.cc:134`) is subsumed here: [`RuleSelectCse`] only feeds this SUBPIECE/INT_SRIGHT ops,
/// both binary. Input identity: a constant hashes its value, a non-constant its varnode id (Ghidra
/// hashes `getCreateIndex()` — mosura's `VarnodeId` is the equivalent stable per-varnode id).
fn cse_hash(f: &Funcdata, op: OpId) -> u32 {
    let o = f.op(op);
    if o.code() == OpCode::Copy {
        return 0;
    }
    let Some(out) = o.output else { return 0 };
    let mut hash: u32 = ((f.vn(out).size) << 8) | (o.code() as u32);
    for i in 0..o.num_inputs() {
        let vn = o.input(i).unwrap();
        hash = hash.rotate_left(8);
        let v = f.vn(vn);
        hash ^= if v.is_constant() { v.constant_value() as u32 } else { vn.0 };
    }
    hash
}

/// Ghidra `PcodeOp::isCseMatch` (`op.cc:153`): the full test that two ops compute the identical
/// value — same output size, same opcode (never `COPY`), same input count, and each input pair is
/// the same varnode or two constants with equal value (constant *size* is NOT compared — a shift
/// amount `#0x3f:8` and `#0x3f:4` are the same value, which is what lets RuleDivOpt's sign
/// correction `x s>> (w-1)` merge with the compiler's own). The eval-type guard (`op.cc:156`) is
/// subsumed by the SUBPIECE/INT_SRIGHT opcode filter.
fn is_cse_match(f: &Funcdata, op1: OpId, op2: OpId) -> bool {
    let (o1, o2) = (f.op(op1), f.op(op2));
    let (Some(out1), Some(out2)) = (o1.output, o2.output) else { return false };
    if f.vn(out1).size != f.vn(out2).size {
        return false;
    }
    if o1.code() != o2.code() || o1.code() == OpCode::Copy {
        return false;
    }
    if o1.num_inputs() != o2.num_inputs() {
        return false;
    }
    (0..o1.num_inputs()).all(|i| {
        let (a, b) = (o1.input(i).unwrap(), o2.input(i).unwrap());
        a == b
            || (f.vn(a).is_constant()
                && f.vn(b).is_constant()
                && f.vn(a).constant_value() == f.vn(b).constant_value())
    })
}

/// Ghidra `Funcdata::cseElimination` (`funcdata_op.cc:1356`): assuming `op1` and `op2` are a
/// depth-1 common subexpression, eliminate the redundancy and return the surviving (dominating)
/// op. If one op's block dominates the other's, the dominating op is kept; if neither dominates,
/// a fresh copy of the op is built at the end of their common dominator and BOTH are eliminated.
/// The other op's output uses are repointed via `total_replace`. `dom` is the dominator tree.
fn cse_elimination(f: &mut Funcdata, op1: OpId, op2: OpId, dom: &Dominators) -> OpId {
    let p1 = f.op(op1).parent.expect("cse op has a parent");
    let p2 = f.op(op2).parent.expect("cse op has a parent");
    let out1 = f.op(op1).output.expect("cse op has output");
    let out2 = f.op(op2).output.expect("cse op has output");

    let replace = if p1 == p2 {
        // Same block: keep whichever appears first (Ghidra compares getSeqNum().getOrder()).
        let ops = &f.block(p1).ops;
        let pos = |o: OpId| ops.iter().position(|&x| x == o).unwrap_or(usize::MAX);
        if pos(op1) < pos(op2) { op1 } else { op2 }
    } else {
        // Cross-block: the common dominator decides (Ghidra FlowBlock::findCommonBlock, block.cc:736,
        // reused from the condconst port). common==one parent => that op dominates; else build anew.
        let common = super::condconst::find_common_block(dom, &[p1.0 as usize, p2.0 as usize]);
        if common == p1.0 as usize {
            op1
        } else if common == p2.0 as usize {
            op2
        } else {
            build_cse_at_common(f, op1, BlockId(common as u32))
        }
    };

    if replace != op1 {
        let rout = f.op(replace).output.unwrap();
        f.total_replace(out1, rout);
        f.op_destroy(op1);
    }
    if replace != op2 {
        let rout = f.op(replace).output.unwrap();
        f.total_replace(out2, rout);
        f.op_destroy(op2);
    }
    replace
}

/// Build a fresh copy of `template`'s op at the end of `common` (the neither-dominates arm of
/// Ghidra `cseElimination`, `funcdata_op.cc:1374`): same opcode, the output at `template`'s output
/// size and address, and each input carried over (constants rebuilt via `new_const`, as Ghidra
/// does with `newConstant`). Inserted before `common`'s terminating branch (the `place_copy`
/// insertion discipline).
fn build_cse_at_common(f: &mut Funcdata, template: OpId, common: BlockId) -> OpId {
    let opc = f.op(template).code();
    let out_size = f.vn(f.op(template).output.unwrap()).size;
    let out_addr = f.vn(f.op(template).output.unwrap()).loc;
    let inputs: Vec<VarnodeId> = (0..f.op(template).num_inputs())
        .map(|i| {
            let v = f.op(template).input(i).unwrap();
            if f.vn(v).is_constant() {
                f.new_const(f.vn(v).size, f.vn(v).constant_value())
            } else {
                v
            }
        })
        .collect();
    let last = f.block(common).ops.last().copied();
    let branch_last = last.filter(|&o| f.op(o).code().terminates_block());
    let seq_pc = match (last, branch_last) {
        (_, Some(b)) => f.op(b).seqnum.pc,
        (Some(l), None) => f.op(l).seqnum.pc,
        (None, None) => f.op(template).seqnum.pc,
    };
    let newop = f.new_op(opc, SeqNum { pc: seq_pc, uniq: 0 }, inputs);
    f.new_output(newop, out_size, out_addr);
    match (branch_last, last) {
        (Some(b), _) => f.op_insert_before(newop, b),
        (None, Some(l)) => f.op_insert_after(newop, l),
        (None, None) => f.op_insert_begin(newop, common),
    }
    newop
}

/// Ghidra `Funcdata::cseEliminateList` (`funcdata_op.cc:1418`): the `list` is (hash, op) pairs of
/// descendants of a single varnode. Sort by hash so duplicate calculations are adjacent, then walk
/// adjacent pairs and, on a hash match that survives the full `is_cse_match` test, eliminate the
/// redundancy via [`cse_elimination`]. Returns the varnodes produced by the surviving ops.
///
/// Ghidra's `isHeritaged(outvn)` guard (`funcdata_op.cc:1436`) is omitted: it is `heritagePass(addr)
/// >= 0`, always true for these SUBPIECE/INT_SRIGHT outputs which are minted during/after heritage,
/// > and mosura's pre-existing same-block RuleSelectCse never carried it.
fn cse_eliminate_list(f: &mut Funcdata, mut list: Vec<(u32, OpId)>, dom: &Dominators) -> Vec<VarnodeId> {
    let mut outlist = Vec::new();
    if list.is_empty() {
        return outlist;
    }
    list.sort_by_key(|&(h, _)| h); // stable; matches Ghidra stable_sort(compareCseHash)
    for i in 0..list.len() - 1 {
        let (h1, op1) = list[i];
        let (h2, op2) = list[i + 1];
        if h1 == h2 && !f.op(op1).is_dead() && !f.op(op2).is_dead() && is_cse_match(f, op1, op2) {
            let resop = cse_elimination(f, op1, op2, dom);
            outlist.push(f.op(resop).output.unwrap());
        }
    }
    outlist
}

/// `RuleSelectCse` (`ruleaction.cc:178`): common-subexpression elimination over the duplicated
/// ops that heritage's read-size normalization (and div-correction) produce — `SUBPIECE` and
/// `INT_SRIGHT`. Collects the descendants of the op's first input that share its opcode and, via
/// [`cse_eliminate_list`] → [`cse_elimination`], collapses depth-1 functionally-equal siblings to
/// one — INCLUDING across blocks (keeping the dominating op, or hoisting to the common dominator).
/// So later rules (signed-compare idioms, `x&x`, `x^x`) and the explicit/implied-varnode marker see
/// the *same* varnode instead of equal-but-distinct copies in each branch (impliedfield's union
/// field never formed while the two `SUBPIECE(param_1,4)` copies stayed distinct).
pub struct RuleSelectCse;

impl Rule for RuleSelectCse {
    fn name(&self) -> &str {
        "selectcse"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece, OpCode::IntSright]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(vn) = data.op(op).input(0) else { return 0 };
        let opc = data.op(op).code();
        // Collect the descendants of in(0) that share this opcode and are cse-hashable (Ghidra
        // RuleSelectCse::applyOp, ruleaction.cc:198).
        let mut list: Vec<(u32, OpId)> = Vec::new();
        for other in data.vn(vn).descend.clone() {
            if data.op(other).code() != opc {
                continue;
            }
            let hash = cse_hash(data, other);
            if hash == 0 {
                continue;
            }
            list.push((hash, other));
        }
        if list.len() <= 1 {
            return 0;
        }
        // Only reached when in(0) has >1 same-opcode descendant (a real duplicate), so the
        // dominator computation is transient — it disappears once the duplicates are collapsed.
        let dom = super::dominator::compute(data);
        let vlist = cse_eliminate_list(data, list, &dom);
        if vlist.is_empty() {
            0
        } else {
            1
        }
    }
}

/// Ghidra `RulePullsubMulti::minMaxUse` (`ruleaction.cc`): the byte range of `vn` actually used by
/// its descendants. If every descendant is a SUBPIECE, returns the `[minByte, maxByte]` envelope of
/// those truncations; any other reader means all bytes are used (`maxByte = size-1, minByte = 0`).
/// Shared by [`RulePullsubMulti`] and [`RulePullsubIndirect`].
fn pullsub_min_max_use(data: &Funcdata, vn: VarnodeId) -> (i32, i32) {
    let in_size = data.vn(vn).size as i32;
    let mut max_byte: i32 = -1;
    let mut min_byte: i32 = in_size;
    for &op in &data.vn(vn).descend {
        if data.op(op).code() == OpCode::Subpiece {
            let min = data.vn(data.op(op).input(1).unwrap()).constant_value() as i32;
            let max = min + data.vn(data.op(op).output.unwrap()).size as i32 - 1;
            if min < min_byte {
                min_byte = min;
            }
            if max > max_byte {
                max_byte = max;
            }
        } else {
            // By default assume all bytes are used.
            return (in_size - 1, 0);
        }
    }
    (max_byte, min_byte)
}

/// Ghidra `RulePullsubMulti::acceptableSize` (`ruleaction.cc`): only pull to a power-of-two-ish
/// truncation size (1/2/4, or anything >= 8).
fn pullsub_acceptable_size(size: i32) -> bool {
    if size == 0 {
        return false;
    }
    if size >= 8 {
        return true;
    }
    matches!(size, 1 | 2 | 4)
}

/// Ghidra `RulePullsubMulti::findSubpiece` (`ruleaction.cc`): a pre-existing `SUBPIECE(basevn, shift)`
/// of exactly `outsize`, defined in the same block as `basevn`'s def — so pulling the truncation up
/// the MULTIEQUAL reuses it instead of adding a redundant one (Ghidra's exponential-split guard).
fn pullsub_find_subpiece(data: &Funcdata, basevn: VarnodeId, outsize: u32, shift: u64) -> Option<VarnodeId> {
    for &prevop in &data.vn(basevn).descend {
        if data.op(prevop).code() != OpCode::Subpiece {
            continue;
        }
        // Make sure output is defined in same block as basevn.
        if data.vn(basevn).is_input() && data.op(prevop).parent.map(|b| b.0) != Some(0) {
            continue;
        }
        if !data.vn(basevn).is_written() {
            continue;
        }
        let def = data.vn(basevn).def.unwrap();
        if data.op(def).parent != data.op(prevop).parent {
            continue;
        }
        // Make sure subpiece matches form.
        if data.op(prevop).input(0) == Some(basevn)
            && data.vn(data.op(prevop).output.unwrap()).size == outsize
            && data.vn(data.op(prevop).input(1).unwrap()).constant_value() == shift
        {
            return data.op(prevop).output;
        }
    }
    None
}

/// Ghidra `RulePullsubMulti::buildSubpiece` (`ruleaction.cc`): build a fresh `SUBPIECE(basevn, shift)`
/// of `outsize` near `basevn`'s definition. The join-address partition path (double-precision pieces)
/// is not reached in mosura's model — those varnodes never appear here — so this is the non-join case;
/// a join base falls back to a `unique` output (Ghidra's `usetmp`).
fn pullsub_build_subpiece(data: &mut Funcdata, basevn: VarnodeId, outsize: u32, shift: u64) -> VarnodeId {
    let is_input = data.vn(basevn).is_input();
    let base_addr = data.vn(basevn).loc;
    let usetmp = data.spaces.by_name("join") == Some(base_addr.space);
    // The new SUBPIECE sits at basevn's definition (or block-0 start for an input).
    let seq = if is_input {
        let b0 = data.block(BlockId(0));
        b0.ops.first().map(|&o| data.op(o).seqnum).unwrap_or_else(|| data.op(data.op_ids().next().unwrap()).seqnum)
    } else {
        data.op(data.vn(basevn).def.unwrap()).seqnum
    };
    let new_op = data.new_op(OpCode::Subpiece, seq, Vec::new());
    let outvn = if usetmp {
        data.new_output_unique(new_op, outsize)
    } else {
        // little-endian: the low piece starts at addr + shift
        data.new_output(new_op, outsize, Address::new(base_addr.space, base_addr.offset + shift))
    };
    let c = data.new_const(4, shift);
    data.op_set_all_input(new_op, &[basevn, c]);
    if is_input {
        data.op_insert_begin(new_op, BlockId(0));
    } else {
        let def = data.vn(basevn).def.unwrap();
        data.op_insert_after(new_op, def);
    }
    outvn
}

/// Ghidra `RulePullsubMulti::replaceDescendants` (`ruleaction.cc`): after the truncation has been
/// pulled up into a new narrow MULTIEQUAL `newVn`, rewrite each SUBPIECE descendant of the wide `origVn`
/// to read `newVn` — collapsing to a COPY when the widths match, or re-basing the truncation offset
/// otherwise. `minMaxUse` guarantees every descendant is a SUBPIECE.
fn pullsub_replace_descendants(data: &mut Funcdata, orig_vn: VarnodeId, new_vn: VarnodeId, min_byte: i32) {
    let new_size = data.vn(new_vn).size as i32;
    for op in data.vn(orig_vn).descend.clone() {
        debug_assert_eq!(data.op(op).code(), OpCode::Subpiece, "replaceDescendants saw a non-SUBPIECE");
        let trunc_amount = data.vn(data.op(op).input(1).unwrap()).constant_value() as i32;
        let out_size = data.vn(data.op(op).output.unwrap()).size as i32;
        data.op_set_input(op, 0, new_vn);
        if new_size == out_size {
            debug_assert_eq!(trunc_amount, min_byte, "replaceDescendants width match but offset != minByte");
            data.op_set_opcode(op, OpCode::Copy);
            data.op_remove_input(op, 1);
        } else if new_size > out_size {
            let new_trunc = trunc_amount - min_byte;
            debug_assert!(new_trunc >= 0, "replaceDescendants negative truncation");
            if new_trunc != trunc_amount {
                let c = data.new_const(4, new_trunc as u64);
                data.op_set_input(op, 1, c);
            }
        }
    }
}

/// Ghidra `FlowBlock::hasLoopIn` (`block.cc:428`): does `block` have any incoming loop back-edge.
/// Ghidra reads a precomputed `f_loop_edge` flag; mosura has no such flag before structuring, so a
/// back-edge is detected structurally — an in-edge from a predecessor the block dominates (the
/// natural-loop definition, same test as [`super::nzmask`]'s `is_loop_in`; exact for reducible CFGs).
fn block_has_loop_in(data: &Funcdata, block: BlockId, dom: &Dominators) -> bool {
    data.block(block)
        .in_edges
        .iter()
        .any(|pred| dom.dominates(block.0 as usize, pred.0 as usize))
}

/// Ghidra `RulePullsubMulti` (`ruleaction.cc`, registered `coreaction.cc:5516` in `oppool1`). Pull a
/// SUBPIECE truncation up through a MULTIEQUAL: `SUBPIECE(phi(a, b, ...), off)` becomes a narrow
/// `phi(SUBPIECE(a, off), SUBPIECE(b, off), ...)`, replacing the wide phi's SUBPIECE readers. This is
/// the faithful clean phi-narrowing mosura lacked — on a dual-width switch selector heritaged wide,
/// it narrows the switch-merge phis in one step (loop-header phis are skipped by the `hasLoopIn` guard,
/// matching Ghidra). Missing-rule port; feeds the SubVariableFlow family.
pub struct RulePullsubMulti;

impl Rule for RulePullsubMulti {
    fn name(&self) -> &str {
        "pullsub_multi"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn = data.op(op).input(0).unwrap();
        if !data.vn(vn).is_written() {
            return 0;
        }
        let mult = data.vn(vn).def.unwrap();
        if data.op(mult).code() != OpCode::Multiequal {
            return 0;
        }
        let (max_byte, min_byte) = pullsub_min_max_use(data, vn);
        let new_size = max_byte - min_byte + 1;
        if max_byte < min_byte || new_size >= data.vn(vn).size as i32 {
            // If all or none is getting used, nothing to do.
            return 0;
        }
        if !pullsub_acceptable_size(new_size) {
            return 0;
        }
        let outvn = data.op(op).output.unwrap();
        if data.vn(outvn).is_precis_lo() || data.vn(outvn).is_precis_hi() {
            return 0; // Don't pull apart a double precision object.
        }
        // Make sure we don't add new SUBPIECE ops that aren't going to cancel in some way.
        if min_byte > 8 {
            return 0;
        }
        let consume = if min_byte < 8 {
            !(super::nzmask::calc_mask(new_size as u32) << (8 * min_byte))
        } else {
            !0u64
        };
        let branches = data.op(mult).num_inputs();
        for i in 0..branches {
            let in_vn = data.op(mult).input(i).unwrap();
            if consume & data.vn(in_vn).get_consume() != 0 {
                // Bits outside the truncation are still used — unless an extension matches the
                // truncation, so the new SUBPIECE cancels it anyway.
                let mut ok = false;
                if min_byte == 0 && data.vn(in_vn).is_written() {
                    let def_op = data.vn(in_vn).def.unwrap();
                    let opc = data.op(def_op).code();
                    if (opc == OpCode::IntZext || opc == OpCode::IntSext)
                        && new_size == data.vn(data.op(def_op).input(0).unwrap()).size as i32
                    {
                        ok = true; // matching extension — new SUBPIECE will cancel
                    }
                }
                if !ok {
                    return 0;
                }
            }
        }
        // All cheap structural checks pass; the dominator-based loop guard is the last gate (Ghidra
        // checks it early, but it is the one expensive test — mirror RuleSelectCse and compute the
        // dominators only when a pull is otherwise viable).
        let dom = super::dominator::compute(data);
        let parent = data.op(mult).parent.unwrap();
        if block_has_loop_in(data, parent, &dom) {
            // We only pull up, do not pull "down" to bottom of loop.
            return 0;
        }
        let base_addr = data.vn(vn).loc;
        let smalladdr2 = Address::new(base_addr.space, base_addr.offset + min_byte as u64);
        let mut params: Vec<VarnodeId> = Vec::with_capacity(branches);
        for i in 0..branches {
            let vn_piece = data.op(mult).input(i).unwrap();
            // Wary of exponential splittings: reuse a previous SUBPIECE if one exists.
            let vn_sub = pullsub_find_subpiece(data, vn_piece, new_size as u32, min_byte as u64)
                .unwrap_or_else(|| pullsub_build_subpiece(data, vn_piece, new_size as u32, min_byte as u64));
            params.push(vn_sub);
        }
        // Build the new narrow MULTIEQUAL near the original.
        let seq = data.op(mult).seqnum;
        let new_multi = data.new_op(OpCode::Multiequal, seq, Vec::new());
        let new_vn = data.new_output(new_multi, new_size as u32, smalladdr2);
        data.op_set_all_input(new_multi, &params);
        data.op_insert_begin(new_multi, parent);

        pullsub_replace_descendants(data, vn, new_vn, min_byte);
        1
    }
}

/// Ghidra `RulePullsubIndirect` (`ruleaction.cc`, registered `coreaction.cc:5517` in `oppool1`). The
/// INDIRECT analogue of [`RulePullsubMulti`]: pull a SUBPIECE truncation up through an INDIRECT, so a
/// call/store effect on a wide storage range that is only read narrowly becomes a narrow INDIRECT.
/// Ghidra reads the causing op from the INDIRECT's `input(1)` IOP annotation; mosura carries that in the
/// op's `guarded_op` (its 1-input INDIRECT model, see [`Funcdata::new_indirect_op`]). Missing-rule port.
pub struct RulePullsubIndirect;

impl Rule for RulePullsubIndirect {
    fn name(&self) -> &str {
        "pullsub_indirect"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn = data.op(op).input(0).unwrap();
        if !data.vn(vn).is_written() {
            return 0;
        }
        if data.vn(vn).size > 8 {
            return 0;
        }
        let indir = data.vn(vn).def.unwrap();
        if data.op(indir).code() != OpCode::Indirect {
            return 0;
        }
        // Ghidra: in(1) must be an IPTR_IOP annotation. mosura carries the causing op in guarded_op.
        let Some(targ_op) = data.op(indir).guarded_op() else {
            return 0;
        };
        if data.op(targ_op).is_dead() {
            return 0;
        }
        if data.vn(vn).is_addr_force() {
            return 0;
        }
        let (max_byte, min_byte) = pullsub_min_max_use(data, vn);
        let new_size = max_byte - min_byte + 1;
        if max_byte < min_byte || new_size >= data.vn(vn).size as i32 {
            return 0;
        }
        if !pullsub_acceptable_size(new_size) {
            return 0;
        }
        let outvn = data.op(op).output.unwrap();
        if data.vn(outvn).is_precis_lo() || data.vn(outvn).is_precis_hi() {
            return 0; // Don't pull apart a double precision object.
        }
        // The wide INDIRECT's incoming value (in(0)) must not use the bits outside the truncation.
        let consume = !(super::nzmask::calc_mask(new_size as u32) << (8 * min_byte));
        let basevn = data.op(indir).input(0).unwrap();
        if consume & data.vn(basevn).get_consume() != 0 {
            return 0;
        }
        let base_addr = data.vn(vn).loc;
        let smalladdr2 = Address::new(base_addr.space, base_addr.offset + min_byte as u64);
        let small2: VarnodeId;
        if data.vn(vn).is_indirect_creation() {
            // The clobber has no realistic incoming value — build a narrow indirect creation
            // (Ghidra `Funcdata::newIndirectCreation`; mosura's 1-input creation = INDIRECT(#0) with
            // guarded_op set and the output marked indirect-creation, as heritage's own version does).
            let possibleout = !is_indirect_zero(data, basevn);
            let seq = data.op(targ_op).seqnum;
            let zero = data.new_const(new_size as u32, 0);
            let new_ind = data.new_op(OpCode::Indirect, seq, vec![zero]);
            data.op_mut(new_ind).guarded_op = Some(targ_op);
            small2 = data.new_output(new_ind, new_size as u32, smalladdr2);
            if !possibleout {
                data.vn_mut(zero).set_indirect_creation();
            }
            data.vn_mut(small2).set_indirect_creation();
            data.op_insert_before(new_ind, targ_op);
        } else {
            let small1 = pullsub_find_subpiece(data, basevn, new_size as u32, min_byte as u64)
                .unwrap_or_else(|| pullsub_build_subpiece(data, basevn, new_size as u32, min_byte as u64));
            // Create the new narrow INDIRECT near the original.
            let seq = data.op(indir).seqnum;
            let new_ind = data.new_op(OpCode::Indirect, seq, vec![small1]);
            data.op_mut(new_ind).guarded_op = Some(targ_op);
            small2 = data.new_output(new_ind, new_size as u32, smalladdr2);
            data.op_insert_before(new_ind, indir);
        }
        pullsub_replace_descendants(data, vn, small2, min_byte);
        1
    }
}

/// Ghidra `Varnode::isIndirectZero` (`varnode.hh`): the constant-0 IOP-zero input of an indirect
/// creation (a constant also flagged `indirect_creation`).
fn is_indirect_zero(data: &Funcdata, vn: VarnodeId) -> bool {
    data.vn(vn).is_constant() && data.vn(vn).is_indirect_creation()
}

/// Ghidra `RulePushMulti::findSubstitute` (`ruleaction.cc`): find an existing op that already computes
/// the merge of `in1`/`in2` in block `bb` — either a MULTIEQUAL(in1, in2) already present, or (when
/// `in1`/`in2` are functionally equal one level down) a CSE of their shared defining op — so the push
/// reuses it instead of building a duplicate.
fn push_multi_find_substitute(
    data: &Funcdata,
    in1: VarnodeId,
    in2: VarnodeId,
    bb: BlockId,
    earliest: Option<OpId>,
) -> Option<OpId> {
    for &op in &data.vn(in1).descend {
        if data.op(op).parent != Some(bb) {
            continue;
        }
        if data.op(op).code() != OpCode::Multiequal {
            continue;
        }
        if data.op(op).input(0) != Some(in1) || data.op(op).input(1) != Some(in2) {
            continue;
        }
        return Some(op);
    }
    if in1 == in2 {
        return None;
    }
    if !functional_equality(data, in1, in2) {
        return None;
    }
    // in1 and in2 must be written (not equal but functionally equal) — find matching inputs to their
    // defining ops and search for a CSE of the first op in bb.
    let op1 = data.vn(in1).def.unwrap();
    let op2 = data.vn(in2).def.unwrap();
    for i in 0..data.op(op1).num_inputs() {
        let vn = data.op(op1).input(i).unwrap();
        if data.vn(vn).is_constant() {
            continue;
        }
        if data.op(op2).input(i) == Some(vn) {
            return cse_find_in_block(data, op1, vn, bb, earliest);
        }
    }
    None
}

/// Ghidra `RulePushMulti` (`ruleaction.cc`, registered `coreaction.cc:5518` "nodejoin" in `oppool1`).
/// Push a 2-input MULTIEQUAL down through a functional operation shared by both inputs: when the two
/// phi inputs are the same op applied to (mostly) the same operands, replace the phi with that single
/// op, merging the one differing operand pair into a smaller MULTIEQUAL. Also collapses a phi of two
/// shadowing COPYs. Missing-rule port (mosura had zero); SubVariableFlow-family node-join.
pub struct RulePushMulti;

impl Rule for RulePushMulti {
    fn name(&self) -> &str {
        "push_multi"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Multiequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let in1 = data.op(op).input(0).unwrap();
        let in2 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_written() || !data.vn(in2).is_written() {
            return 0;
        }
        if data.vn(in1).is_spacebase() || data.vn(in2).is_spacebase() {
            return 0;
        }
        let (res, pair) = functional_equality_level_pair(data, in1, in2);
        if !(0..=1).contains(&res) {
            return 0;
        }
        let op1 = data.vn(in1).def.unwrap();
        if data.op(op1).code() == OpCode::Subpiece {
            return 0; // SUBPIECE is pulled, not pushed.
        }
        let bl = data.op(op).parent.unwrap();
        let outvn = data.op(op).output.unwrap();
        let earliest = earliest_use(data, outvn, bl);
        if data.op(op1).code() == OpCode::Copy {
            // Special case: MERGE of 2 shadowing varnodes.
            if res == 0 {
                return 0;
            }
            let (b1, b2) = pair.unwrap();
            let Some(substitute) = push_multi_find_substitute(data, b1, b2, bl, earliest) else {
                return 0;
            };
            let sub_out = data.op(substitute).output.unwrap();
            data.total_replace(outvn, sub_out);
            data.op_destroy(op);
            return 1;
        }
        let op2 = data.vn(in2).def.unwrap();
        // in1/in2 must each feed only this MULTIEQUAL (Ghidra loneDescend).
        if data.vn(in1).descend.len() != 1 || data.vn(in1).descend[0] != op {
            return 0;
        }
        if data.vn(in2).descend.len() != 1 || data.vn(in2).descend[0] != op {
            return 0;
        }
        // Move the MULTIEQUAL output to op1, which becomes the unified op moved into the merge block.
        data.op_set_output(op1, outvn);
        data.op_uninsert(op1);
        if res == 1 {
            let (b1, b2) = pair.unwrap();
            let slot1 = data.op(op1).inrefs.iter().position(|&v| v == b1).expect("buf1[0] is an input of op1");
            let substitute_out = match push_multi_find_substitute(data, b1, b2, bl, earliest) {
                Some(sub) => data.op(sub).output.unwrap(),
                None => {
                    let seq = data.op(op).seqnum;
                    let substitute = data.new_op(OpCode::Multiequal, seq, Vec::new());
                    // Preserve the storage location if the inputs share it and it isn't addrtied.
                    let b1_addr = data.vn(b1).loc;
                    let b1_size = data.vn(b1).size;
                    let sout = if data.vn(b1).loc == data.vn(b2).loc && !data.vn(b1).is_addrtied() {
                        data.new_output(substitute, b1_size, b1_addr)
                    } else {
                        data.new_output_unique(substitute, b1_size)
                    };
                    data.op_set_all_input(substitute, &[b1, b2]);
                    data.op_insert_begin(substitute, bl);
                    sout
                }
            };
            data.op_set_input(op1, slot1, substitute_out);
            let sub_def = data.vn(substitute_out).def.unwrap();
            data.op_insert_after(op1, sub_def);
        } else {
            data.op_insert_begin(op1, bl);
        }
        data.op_destroy(op);
        data.op_destroy(op2);
        1
    }
}

/// `RuleSubExtComm` (`ruleaction.cc:4402`): push a `SUBPIECE` through a `ZEXT`/`SEXT`. When the
/// piece never reaches the extended bits (`out_size + subcut <= invn_size`) it is a piece of
/// the pre-extension value directly — and when it exactly covers that value it collapses to a
/// `COPY`. This cancels the `SUBPIECE(ZEXT(reg:4))` round-trips that heritage's sub-register
/// canonicalization introduces (the bulk of the IR-op gap vs Ghidra).
///
/// A piece that STRADDLES the extension boundary is split (ruleaction.cc:4423-4439): unless the
/// cut starts at/past the pre-extension value (`subcut >= in_size`, decline), rewrite
/// `SUB(ext(V), c)` as `ext(SUB(V, c))` with a fresh inner `SUBPIECE` of size `in_size - subcut`
/// (or `V` itself at offset 0). Ghidra's return-collapse chain rides this: the split feeds
/// `RuleConcatZext`, collapsing floatcast's 16-byte `CONCAT124` return into the 8-byte
/// `CONCAT44` (task #21(a); safe for switch recovery since the #31 table lifecycle landed).
pub struct RuleSubExtComm;

impl Rule for RuleSubExtComm {
    fn name(&self) -> &str {
        "subextcomm"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(base), Some(cut_v), Some(out)) =
            (data.op(op).input(0), data.op(op).input(1), data.op(op).output)
        else {
            return 0;
        };
        let Some(subcut) = data.vn(cut_v).is_constant().then(|| data.vn(cut_v).constant_value()) else {
            return 0;
        };
        let Some(extop) = data.vn(base).def else { return 0 };
        let ec = data.op(extop).code();
        if !matches!(ec, OpCode::IntZext | OpCode::IntSext) {
            return 0;
        }
        let Some(invn) = data.op(extop).input(0) else { return 0 };
        if data.vn(invn).is_constant() {
            return 0;
        }
        let out_size = data.vn(out).size as u64;
        let in_size = data.vn(invn).size as u64;
        if out_size + subcut <= in_size {
            // the piece never touches the extended bits — it's a piece of `invn` directly
            data.op_set_input(op, 0, invn);
            if in_size == out_size {
                data.op_remove_input(op, 1);
                data.op_set_opcode(op, OpCode::Copy);
            }
            return 1;
        }
        // The piece straddles the extension boundary (ruleaction.cc:4423-4439): decline only when
        // the cut starts at/past the pre-extension value; otherwise split — a fresh inner SUBPIECE
        // of the unextended value (size in_size - subcut) at a nonzero offset, the value itself at
        // offset 0 — and commute the extension outward.
        if subcut >= in_size {
            return 0;
        }
        let newvn = if subcut != 0 {
            let cut_size = data.vn(cut_v).size;
            let c = data.new_const(cut_size, subcut);
            let newop =
                data.new_op_before_sized(op, OpCode::Subpiece, vec![invn, c], (in_size - subcut) as u32);
            data.op(newop).output.unwrap()
        } else {
            invn
        };
        data.op_remove_input(op, 1);
        data.op_set_opcode(op, ec);
        data.op_set_input(op, 0, newvn);
        1
    }
}

/// `RuleHumptyDumpty` (`ruleaction.cc:5214`): simplify break-and-rejoin —
/// `concat(sub(V,c), sub(V,0)) => V`, and the partial variant `concat(sub(V,c), sub(V,d)) =>
/// sub(V,d)`. This rejoins the SUBPIECE pieces that heritage refinement (`refine_overlaps`) splits
/// an overlapping SIMD/sub-register write into — the high `PIECE` input is `sub(V,c)`, the low is
/// `sub(V,d)`, and when they tile `V` exactly the whole thing collapses back to `V`.
pub struct RuleHumptyDumpty;

impl Rule for RuleHumptyDumpty {
    fn name(&self) -> &str {
        "humptydumpty"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        // PIECE in0 is the most-significant ("put together") part, in1 the least.
        let (Some(vn1), Some(vn2)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        let (Some(sub1), Some(sub2)) = (data.vn(vn1).def, data.vn(vn2).def) else {
            return 0;
        };
        if data.op(sub1).code() != OpCode::Subpiece || data.op(sub2).code() != OpCode::Subpiece {
            return 0;
        }
        let (Some(root), Some(root2)) = (data.op(sub1).input(0), data.op(sub2).input(0)) else {
            return 0;
        };
        if root != root2 {
            return 0; // pieces of the same whole
        }
        let (Some(pos1v), Some(pos2v)) = (data.op(sub1).input(1), data.op(sub2).input(1)) else {
            return 0;
        };
        if !data.vn(pos1v).is_constant() || !data.vn(pos2v).is_constant() {
            return 0;
        }
        let pos1 = data.vn(pos1v).constant_value();
        let pos2 = data.vn(pos2v).constant_value();
        let size1 = data.vn(vn1).size as u64;
        let size2 = data.vn(vn2).size as u64;
        if pos1 != pos2 + size2 {
            return 0; // pieces do not match up
        }
        if pos2 == 0 && size1 + size2 == data.vn(root).size as u64 {
            // pieced together the whole thing → COPY(root)
            data.op_remove_input(op, 1);
            data.op_set_input(op, 0, root);
            data.op_set_opcode(op, OpCode::Copy);
        } else {
            // pieced together a larger part of the whole → SUBPIECE(root, pos2)
            let pos2_size = data.vn(pos2v).size;
            data.op_set_input(op, 0, root);
            let c = data.new_const(pos2_size, pos2);
            data.op_set_input(op, 1, c);
            data.op_set_opcode(op, OpCode::Subpiece);
        }
        1
    }
}

/// `RuleDumptyHump` (`ruleaction.cc:5265`): simplify join-then-break — `sub(concat(V,W), c)` draws
/// from whichever piece the slice falls in: `sub(concat(V,W), 0) => W`, `sub(concat(V,W), |W|) => V`,
/// or `sub(V, c)` for an interior slice. This is what cleans up a SUBPIECE (or a cast, a low slice)
/// taken of a PIECE that heritage refinement built — e.g. `(uint4)CONCAT(hi, value) => value` for a
/// SIMD scalar move through a vector register.
pub struct RuleDumptyHump;

impl Rule for RuleDumptyHump {
    fn name(&self) -> &str {
        "dumptyhump"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(base) = data.op(op).input(0) else { return 0 };
        let Some(pieceop) = data.vn(base).def else { return 0 };
        if data.op(pieceop).code() != OpCode::Piece {
            return 0;
        }
        let Some(offv) = data.op(op).input(1) else { return 0 };
        if !data.vn(offv).is_constant() {
            return 0;
        }
        let mut offset = data.vn(offv).constant_value();
        let outsize = data.vn(data.op(op).output.unwrap()).size as u64;
        // PIECE in0 = high part, in1 = low part.
        let (Some(vn1), Some(vn2)) = (data.op(pieceop).input(0), data.op(pieceop).input(1)) else {
            return 0;
        };
        let v2size = data.vn(vn2).size as u64;
        let vn = if offset < v2size {
            // the slice draws from the low piece
            if offset + outsize > v2size {
                return 0; // ... and also from the high piece — can't simplify
            }
            vn2
        } else {
            offset -= v2size; // offset relative to the high piece
            vn1
        };
        if data.vn(vn).is_free() && !data.vn(vn).is_constant() {
            return 0;
        }
        if offset == 0 && outsize == data.vn(vn).size as u64 {
            // eliminate SUBPIECE and PIECE altogether → COPY(vn)
            data.op_remove_input(op, 1);
            data.op_set_input(op, 0, vn);
            data.op_set_opcode(op, OpCode::Copy);
        } else {
            // eliminate the PIECE, adjust the SUBPIECE offset → SUBPIECE(vn, offset)
            data.op_set_input(op, 0, vn);
            let c = data.new_const(4, offset);
            data.op_set_input(op, 1, c);
        }
        1
    }
}

// `RuleIdempotent` (mosura invention: `a&a`/`a|a` -> `a`, `a^a`/`a-a` -> `0`) was deleted here.
// Ghidra does all of this in `RuleTrivialArith` (ruleaction.cc:2362), whose oplist already carries
// INT_AND, INT_OR, BOOL_AND, BOOL_OR and INT_XOR with identical semantics, and which mosura ports
// above. The invention added exactly one opcode Ghidra does not fold: INT_SUB — and Ghidra does not
// fold it by DECISION, not omission, since `case CPUI_INT_SUB:` sits commented out in that switch
// (ruleaction.cc:2394) right beside the INT_XOR case that is live.
//
// The redundancy was MEASURED, not argued: restricting this rule to `[IntSub]` alone left all 1303
// WAR2 functions byte-identical, which is what proves RuleTrivialArith already covered the other
// five opcodes.
//
// AND THE INT_SUB HALF WAS NOT IDLE — the deletion commit's message said it "never fires on WAR2",
// which was WRONG. A non-transforming observer probe counted it: `INT_SUB(a,a)` occurs 90 times
// across 32 WAR2 functions. Deleting it is still byte-identical because `RuleSub2Add`
// (ruleaction.cc:4012) rewrites EVERY subtraction `V - W` into `V + W*-1` unconditionally, so
// `a - a` becomes `a + a*-1` and the term-collection rules fold it to 0 down the faithful path.
// A trace of FUN_000601f8 names `sub2add` as the consumer of those ops, so this is measured too.
// That is very likely WHY Ghidra can leave `case CPUI_INT_SUB:` commented out: with RuleSub2Add
// eliminating INT_SUB up front, the case would be dead code in Ghidra's own pipeline. The lesson
// is the general one -- "removing X changes no output" does NOT license "X never ran"; those are
// different claims and only the first one was measured.
//
// Ghidra's RuleTrivialArith is also STRICTLY WIDER than what was deleted: it folds the comparison
// opcodes to boolean constants, and it accepts CSE-equivalent inputs via `isCseMatch`, not only
// syntactically identical ones. mosura's port takes the identical-inputs case only and leaves the
// CSE case to RuleSelectCse (see the note in RuleTrivialArith); the four FLOAT_* comparison opcodes
// of Ghidra's oplist are likewise not yet ported. Both are pre-existing port gaps in the faithful
// rule, and both are the right place to close this family — not a second rule alongside it.

// `RuleMultMult` (mosura invention, `(x*c1)*c2` -> `x*(c1*c2)`) was deleted here. Ghidra does this
// fold in `RuleAddMultCollapse` (ruleaction.cc:4093), whose oplist is `{ CPUI_INT_ADD,
// CPUI_INT_MULT }` and which computes the product through `OpBehaviorIntMult::evaluateBinary` —
// `(in1*in2) & calc_mask(sizeout)`, opbehavior.cc:495. mosura already ports that rule faithfully,
// mask included. The invention was a second, UNMASKED copy: it built its constant with a bare
// `wrapping_mul` at u64 width, so `(x*0xff)*0xff` in a 1-byte INT_MULT became `x * 0xfe01` — a
// constant varnode that cannot fit its own size (correct is 0xfe01 & 0xff = 1, the identity).
// Measured before deletion: the sole creator of oversized constants in 136 of 1303 WAR2 functions.
// The lesson worth keeping is that it was invisible for as long as it was because the rule NAMED
// itself after no Ghidra class; `scripts/trace-names.py` now reports exactly that as ADAPTATION.

/// `RuleBoolNegate`: a negated comparison is the complementary comparison —
/// `!(a == b)` → `a != b`, `!(a < b)` → `b <= a`, etc. Comparisons are 0/1, so the rewrite
/// is exact; it un-nests negations the structurer can't reach (inside `BOOL_AND`/`BOOL_OR`).
/// Ghidra's `RuleBoolNegate` supports the signed and floating-point comparison variants too — the
/// float ones flip the `ucomisd`-derived `!(a <= b)` into `b < a` (matching Ghidra) once
/// `RuleIgnoreNan`/`RuleFloatRange` have collapsed the NaN-guarded web.
pub struct RuleBoolNegate;

impl Rule for RuleBoolNegate {
    fn name(&self) -> &str {
        "boolnegate"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolNegate]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(cmp) = data.op(op).input(0).and_then(|v| data.vn(v).def) else { return 0 };
        let (flipped, swap) = match data.op(cmp).code() {
            OpCode::IntEqual => (OpCode::IntNotequal, false),
            OpCode::IntNotequal => (OpCode::IntEqual, false),
            OpCode::IntLess => (OpCode::IntLessequal, true),
            OpCode::IntLessequal => (OpCode::IntLess, true),
            OpCode::IntSless => (OpCode::IntSlessequal, true),
            OpCode::IntSlessequal => (OpCode::IntSless, true),
            OpCode::FloatEqual => (OpCode::FloatNotequal, false),
            OpCode::FloatNotequal => (OpCode::FloatEqual, false),
            OpCode::FloatLess => (OpCode::FloatLessequal, true),
            OpCode::FloatLessequal => (OpCode::FloatLess, true),
            _ => return 0,
        };
        let (a, b) = (data.op(cmp).input(0).unwrap(), data.op(cmp).input(1).unwrap());
        data.op_set_opcode(op, flipped);
        let ins = if swap { [b, a] } else { [a, b] };
        data.op_set_all_input(op, &ins);
        1
    }
}

/// Ghidra `PcodeOp::booloutput` — the opcodes whose output is a 1-bit boolean value (the `TypeOp`
/// constructors that set `PcodeOp::booloutput`, typeop.cc): the integer/float comparisons, the
/// carry/borrow flag ops, and the `BOOL_*` / `FLOAT_NAN` ops.
fn is_booloutput(opc: OpCode) -> bool {
    use OpCode::*;
    matches!(
        opc,
        IntEqual
            | IntNotequal
            | IntLess
            | IntLessequal
            | IntSless
            | IntSlessequal
            | IntCarry
            | IntScarry
            | IntSborrow
            | BoolNegate
            | BoolXor
            | BoolAnd
            | BoolOr
            | FloatEqual
            | FloatNotequal
            | FloatLess
            | FloatLessequal
            | FloatNan
    )
}

/// Ghidra `Varnode::isBooleanValue` (varnode.cc:942) + `PcodeOp::isCalculatedBool` (op.hh:211): a
/// written Varnode holds a boolean iff its defining op produces a 1-bit boolean output. Ghidra's
/// `isCalculatedBool` is `(calculated_bool | booloutput) != 0`; mosura does not track the dynamic
/// `calculated_bool` flag, so we test the static `booloutput` opcode set ([`is_booloutput`]). For an
/// unwritten Varnode Ghidra returns true only for a typelocked 1-byte `bool` input when type
/// recovery is on (`useAnnotation`); the simplification pool runs before type recovery starts, so we
/// mirror the `false` result there.
fn is_boolean_value(data: &Funcdata, vn: VarnodeId) -> bool {
    let v = data.vn(vn);
    if !v.is_written() {
        return false;
    }
    is_booloutput(data.op(v.def.unwrap()).code())
}

/// Ghidra `RuleLogic2Bool` (ruleaction.cc:3118): convert a logical (bitwise) operator on boolean
/// inputs to the boolean operator — `V & W => V && W`, `V | W => V || W`, `V ^ W => V != W` (BOOL_XOR).
/// Both inputs must be booleans ([`is_boolean_value`]); a constant `0`/`1` on the second input also
/// counts (a larger constant rules it out). The rewrite is exact (booleans are 0/1) and lets the
/// structurer and downstream bool rules see `||`/`&&` instead of the bit-smeared flag web.
pub struct RuleLogic2Bool;

impl Rule for RuleLogic2Bool {
    fn name(&self) -> &str {
        "logic2bool"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd, OpCode::IntOr, OpCode::IntXor]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(in0), Some(in1)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        if !is_boolean_value(data, in0) {
            return 0;
        }
        if data.vn(in1).is_constant() {
            if data.vn(in1).constant_value() > 1 {
                return 0;
            }
        } else if !is_boolean_value(data, in1) {
            return 0;
        }
        let bool_opc = match data.op(op).code() {
            OpCode::IntAnd => OpCode::BoolAnd,
            OpCode::IntOr => OpCode::BoolOr,
            OpCode::IntXor => OpCode::BoolXor,
            _ => return 0,
        };
        data.op_set_opcode(op, bool_opc);
        1
    }
}

/// Ghidra `RuleBoolZext` (ruleaction.cc:2995): simplify boolean expressions built as `zext(V) * -1`
/// — an extended boolean smeared to all-ones.
///   - `(zext(V) * -1) + 1               =>  zext( !V )`
///   - `(zext(V) * -1) == -1`/`!= -1`    =>  `V == true`/`V != true`  (and `== 0`/`!= 0` => `V == false`/`!= false`)
///   - `(zext(V) * -1) & (zext(W) * -1)  =>  zext(V && W) * -1`
///   - `(zext(V) * -1) | (zext(W) * -1)  =>  zext(V || W) * -1`
///   - `(zext(V) * -1) ^ (zext(W) * -1)  =>  zext(V ^^ W) * -1`
///
/// Registered on `INT_ZEXT`: `V` (and `W`) must be booleans ([`is_boolean_value`]) and the multiplier
/// the all-ones mask ([`super::nzmask::calc_mask`]). The logical cases pull the bit-smeared flag
/// arithmetic back to bare `!`/`&&`/`||` on the underlying booleans.
pub struct RuleBoolZext;

impl Rule for RuleBoolZext {
    fn name(&self) -> &str {
        "boolzext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntZext]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(bool_vn1) = data.op(op).input(0) else { return 0 };
        if !is_boolean_value(data, bool_vn1) {
            return 0;
        }
        let Some(zext_out) = data.op(op).output else { return 0 };
        // The extended boolean must be Multiplied by -1 (the all-ones mask)
        let Some(multop1) = lone_descend(data, zext_out) else { return 0 };
        if data.op(multop1).code() != OpCode::IntMult {
            return 0;
        }
        let Some(m1c) = data.op(multop1).input(1) else { return 0 };
        if !data.vn(m1c).is_constant() {
            return 0;
        }
        let coeff = data.vn(m1c).constant_value();
        if coeff != super::nzmask::calc_mask(data.vn(m1c).size) {
            return 0;
        }
        let mult_out = data.op(multop1).output.unwrap();
        let size = data.vn(mult_out).size;

        // The operation consuming the extended boolean
        let Some(actionop) = lone_descend(data, mult_out) else { return 0 };
        let opc = match data.op(actionop).code() {
            OpCode::IntAdd => {
                // (zext(V) * -1) + 1  =>  zext( !V )
                let Some(addc) = data.op(actionop).input(1) else { return 0 };
                if !data.vn(addc).is_constant() {
                    return 0;
                }
                if data.vn(addc).constant_value() != 1 {
                    return 0;
                }
                let neg = data.new_op_before_sized(op, OpCode::BoolNegate, vec![bool_vn1], 1);
                let neg_out = data.op(neg).output.unwrap();
                data.op_set_input(op, 0, neg_out); // the ZEXT now extends !V
                data.op_remove_input(actionop, 1); // eliminate the INT_ADD's +1
                data.op_set_opcode(actionop, OpCode::Copy);
                data.op_set_input(actionop, 0, zext_out); // COPY propagates past the INT_MULT
                return 1;
            }
            OpCode::IntEqual | OpCode::IntNotequal => {
                // compare of extended boolean to 0/-1  =>  compare of bare boolean to 0/1
                let Some(cmpc) = data.op(actionop).input(1) else { return 0 };
                if !data.vn(cmpc).is_constant() {
                    return 0;
                }
                let val = data.vn(cmpc).constant_value();
                let val = if val == coeff {
                    1
                } else if val != 0 {
                    return 0; // not comparing with 0 or -1
                } else {
                    0
                };
                let one = data.new_const(1, val);
                data.op_set_input(actionop, 0, bool_vn1);
                data.op_set_input(actionop, 1, one);
                return 1;
            }
            OpCode::IntAnd => OpCode::BoolAnd,
            OpCode::IntOr => OpCode::BoolOr,
            OpCode::IntXor => OpCode::BoolXor,
            _ => return 0,
        };

        // Logical op with an extended boolean: the other operand must also be zext(W) * -1
        let (Some(in0), Some(in1)) = (data.op(actionop).input(0), data.op(actionop).input(1)) else {
            return 0;
        };
        let other = if data.vn(in0).def == Some(multop1) { in1 } else { in0 };
        let Some(multop2) = data.vn(other).def else { return 0 };
        if data.op(multop2).code() != OpCode::IntMult {
            return 0;
        }
        let Some(m2c) = data.op(multop2).input(1) else { return 0 };
        if !data.vn(m2c).is_constant() {
            return 0;
        }
        if data.vn(m2c).constant_value() != super::nzmask::calc_mask(size) {
            return 0;
        }
        let Some(m2_in0) = data.op(multop2).input(0) else { return 0 };
        let Some(zextop2) = data.vn(m2_in0).def else { return 0 };
        if data.op(zextop2).code() != OpCode::IntZext {
            return 0;
        }
        let Some(bool_vn2) = data.op(zextop2).input(0) else { return 0 };
        if !is_boolean_value(data, bool_vn2) {
            return 0;
        }

        // Do the boolean calculation on the unextended booleans, then re-extend and re-scale by -1
        let newop = data.new_op_before_sized(actionop, opc, vec![bool_vn1, bool_vn2], 1);
        let newres = data.op(newop).output.unwrap();
        let newzext = data.new_op_before_sized(actionop, OpCode::IntZext, vec![newres], size);
        let newzout = data.op(newzext).output.unwrap();
        data.op_set_opcode(actionop, OpCode::IntMult);
        data.op_set_input(actionop, 0, newzout);
        let cc = data.new_const(size, super::nzmask::calc_mask(size));
        data.op_set_input(actionop, 1, cc);
        1
    }
}

/// Ghidra `RuleZextSless` (ruleaction.cc:2564): `zext(V) s< c  =>  V < c` (and the SLESSEQUAL and
/// reversed-operand `c s< zext(V)` forms). Registered on INT_SLESS / INT_SLESSEQUAL: one operand is a
/// zero-extension and the other a constant whose sign bit (within the pre-extension width) is clear,
/// so the extension is unnecessary and the signed compare is equivalent to the unsigned one on the
/// narrow value.
pub struct RuleZextSless;

impl Rule for RuleZextSless {
    fn name(&self) -> &str {
        "zextsless"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSless, OpCode::IntSlessequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(in0), Some(in1)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        // Find which operand is the INT_ZEXT (prefer slot 0, else slot 1)
        let (zext_vn, other_vn, zextslot, otherslot) = if data.vn(in1).is_written()
            && data.op(data.vn(in1).def.unwrap()).code() == OpCode::IntZext
        {
            (in1, in0, 1usize, 0usize)
        } else if data.vn(in0).is_written()
            && data.op(data.vn(in0).def.unwrap()).code() == OpCode::IntZext
        {
            (in0, in1, 0usize, 1usize)
        } else {
            return 0;
        };
        if !data.vn(other_vn).is_constant() {
            return 0;
        }
        let zext = data.vn(zext_vn).def.unwrap();
        let small_vn = data.op(zext).input(0).unwrap();
        if !data.vn(small_vn).is_heritage_known() {
            return 0;
        }
        let smallsize = data.vn(small_vn).size;
        let val = data.vn(other_vn).constant_value();
        // The zero extension must be unnecessary: the sign bit of the narrow value must be 0.
        if (val >> (8 * smallsize - 1)) != 0 {
            return 0;
        }
        let newvn = data.new_const(smallsize, val);
        data.op_set_input(op, zextslot, small_vn);
        data.op_set_input(op, otherslot, newvn);
        let newopc = if data.op(op).code() == OpCode::IntSless {
            OpCode::IntLess
        } else {
            OpCode::IntLessequal
        };
        data.op_set_opcode(op, newopc);
        1
    }
}

/// Ghidra `RuleAndOrLump` (ruleaction.cc:413): collapse a constant through a same-opcode parent —
/// `(V & c) & d => V & (c & d)`, and likewise for INT_OR (`|`) and INT_XOR (`^`).
pub struct RuleAndOrLump;

impl Rule for RuleAndOrLump {
    fn name(&self) -> &str {
        "andorlump"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd, OpCode::IntOr, OpCode::IntXor]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let opc = data.op(op).code();
        let (Some(in0), Some(in1)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        if !data.vn(in1).is_constant() {
            return 0;
        }
        if !data.vn(in0).is_written() {
            return 0;
        }
        let op2 = data.vn(in0).def.unwrap();
        if data.op(op2).code() != opc {
            return 0; // Must be same op
        }
        let (Some(basevn), Some(c2)) = (data.op(op2).input(0), data.op(op2).input(1)) else {
            return 0;
        };
        if !data.vn(c2).is_constant() {
            return 0;
        }
        if data.vn(basevn).is_free() {
            return 0;
        }
        let val = data.vn(in1).constant_value();
        let val2 = data.vn(c2).constant_value();
        let combined = match opc {
            OpCode::IntAnd => val & val2,
            OpCode::IntOr => val | val2,
            OpCode::IntXor => val ^ val2,
            _ => return 0,
        };
        let c = data.new_const(data.vn(basevn).size, combined);
        data.op_set_input(op, 0, basevn);
        data.op_set_input(op, 1, c);
        1
    }
}

/// Ghidra `RuleRightShiftAnd` (ruleaction.cc:580): drop an INT_AND mask rendered unnecessary by a
/// following right shift — `(V & 0xf000) >> 24 => V >> 24` (and the arithmetic `s>>` form) — when
/// every bit the mask clears is shifted out anyway (the mask, shifted right by the shift amount,
/// covers the whole surviving field).
pub struct RuleRightShiftAnd;

impl Rule for RuleRightShiftAnd {
    fn name(&self) -> &str {
        "rightshiftand"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntRight, OpCode::IntSright]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(in0), Some(constvn)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        if !data.vn(constvn).is_constant() {
            return 0;
        }
        if !data.vn(in0).is_written() {
            return 0;
        }
        let and_op = data.vn(in0).def.unwrap();
        if data.op(and_op).code() != OpCode::IntAnd {
            return 0;
        }
        let (Some(root_vn), Some(mask_vn)) = (data.op(and_op).input(0), data.op(and_op).input(1))
        else {
            return 0;
        };
        if !data.vn(mask_vn).is_constant() {
            return 0;
        }
        let sa = data.vn(constvn).constant_value() as u32;
        let mask = data.vn(mask_vn).constant_value().checked_shr(sa).unwrap_or(0);
        let full = super::nzmask::calc_mask(data.vn(root_vn).size).checked_shr(sa).unwrap_or(0);
        if full != mask {
            return 0;
        }
        if data.vn(root_vn).is_free() {
            return 0;
        }
        data.op_set_input(op, 0, root_vn); // Bypass the INT_AND
        1
    }
}

/// Ghidra `RuleSubCancel` (ruleaction.cc:5119): simplify a SUBPIECE whose input is an INT_ZEXT,
/// INT_SEXT, or masking INT_AND that the truncation partially or wholly cancels:
///   - `sub(zext(V),0)` / `sub(sext(V),0)` => `V` (COPY, total), `sub(V)` (narrower SUBPIECE), or a
///     narrower `zext(V)`/`sext(V)` when the SUBPIECE lands between the pre-extension and output width
///   - `sub(V & 0xffff, 0)` => `sub(V)` when the mask equals the output's full mask
///   - `sub(zext(V),c)` => `0` when `c` skips past the whole original value
///
/// NB: mosura's `is_free` treats a constant as *not* free (Ghidra's `isFree` treats it as free), so
/// the offset-0 free branch is only entered for genuinely undefined varnodes here; the big-constant
/// (`insize > 8`) sub-case is structurally preserved but unreachable in mosura (a `zext(const)` is
/// folded upstream before reaching this rule).
pub struct RuleSubCancel;

impl Rule for RuleSubCancel {
    fn name(&self) -> &str {
        "subcancel"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(base) = data.op(op).input(0) else { return 0 };
        if !data.vn(base).is_written() {
            return 0;
        }
        let extop = data.vn(base).def.unwrap();
        let mut opc = data.op(extop).code();
        if opc != OpCode::IntZext && opc != OpCode::IntSext && opc != OpCode::IntAnd {
            return 0;
        }
        let offset = data.vn(data.op(op).input(1).unwrap()).constant_value();
        let outsize = data.vn(data.op(op).output.unwrap()).size;

        if opc == OpCode::IntAnd {
            let Some(cvn) = data.op(extop).input(1) else { return 0 };
            if offset == 0
                && data.vn(cvn).is_constant()
                && data.vn(cvn).constant_value() == super::nzmask::calc_mask(outsize)
            {
                let thruvn = data.op(extop).input(0).unwrap();
                if !data.vn(thruvn).is_free() {
                    data.op_set_input(op, 0, thruvn);
                    return 1;
                }
            }
            return 0;
        }

        let insize = data.vn(base).size;
        let far = data.op(extop).input(0).unwrap();
        let farinsize = data.vn(far).size;
        let mut thruvn = far;
        if offset == 0 {
            // SUBPIECE of least-significant part — something still comes through
            if data.vn(thruvn).is_free() {
                if data.vn(thruvn).is_constant() && insize > 8 && outsize == farinsize {
                    // Constant too big to represent, total elimination — remake the constant
                    opc = OpCode::Copy;
                    thruvn = data.new_const(data.vn(thruvn).size, data.vn(thruvn).constant_value());
                } else {
                    return 0; // original is constant or undefined — don't proceed
                }
            } else if outsize == farinsize {
                opc = OpCode::Copy; // Total elimination of the extension
            } else if outsize < farinsize {
                opc = OpCode::Subpiece;
            }
            // else outsize > farinsize: the (narrowed) extension still applies — opc stays ZEXT/SEXT
        } else if opc == OpCode::IntZext && (farinsize as u64) <= offset {
            // Output contains nothing of the original input — nothing but zero comes through
            opc = OpCode::Copy;
            thruvn = data.new_const(outsize, 0);
        } else {
            return 0;
        }

        data.op_set_opcode(op, opc);
        data.op_set_input(op, 0, thruvn);
        if opc != OpCode::Subpiece {
            data.op_remove_input(op, 1); // ZEXT / SEXT / COPY has only 1 input
        }
        1
    }
}

/// Ghidra `RuleShiftSub` (ruleaction.cc:5191): a SUBPIECE of a byte-granular left shift is itself a
/// SUBPIECE at a shifted offset — `sub(V << 8*k, c) => sub(V, c-k)` — when the window `[c-k, c-k+out)`
/// falls entirely within `V` (a natural truncation). The shift must be a multiple of 8 bits.
pub struct RuleShiftSub;

impl Rule for RuleShiftSub {
    fn name(&self) -> &str {
        "shiftsub"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(base) = data.op(op).input(0) else { return 0 };
        if !data.vn(base).is_written() {
            return 0;
        }
        let shiftop = data.vn(base).def.unwrap();
        if data.op(shiftop).code() != OpCode::IntLeft {
            return 0;
        }
        let Some(sa_vn) = data.op(shiftop).input(1) else { return 0 };
        if !data.vn(sa_vn).is_constant() {
            return 0;
        }
        let n = data.vn(sa_vn).constant_value();
        if (n & 7) != 0 {
            return 0; // Must shift by a multiple of 8 bits
        }
        let cvn = data.op(op).input(1).unwrap();
        let c = data.vn(cvn).constant_value();
        let vn = data.op(shiftop).input(0).unwrap();
        if data.vn(vn).is_free() {
            return 0;
        }
        let insize = data.vn(vn).size as i64;
        let outsize = data.vn(data.op(op).output.unwrap()).size as i64;
        let c = c as i64 - (n / 8) as i64;
        if c < 0 || c + outsize > insize {
            return 0; // Not a natural truncation
        }
        let csize = data.vn(cvn).size;
        data.op_set_input(op, 0, vn);
        let newc = data.new_const(csize, c as u64);
        data.op_set_input(op, 1, newc);
        1
    }
}

/// Ghidra `Varnode::loneDescend` (varnode.cc): the single op reading `vn`, or `None` if it has
/// zero or more than one reader. (Descendant lists are kept exact by the op-mutation helpers, so a
/// rewritten-away or removed reader no longer counts.)
fn lone_descend(data: &Funcdata, vn: VarnodeId) -> Option<OpId> {
    let d = &data.vn(vn).descend;
    (d.len() == 1).then(|| d[0])
}

/// Ghidra `RuleOrCompare` (ruleaction.cc:10785): simplify an `INT_OR` that feeds only
/// comparisons against constant 0.
///   - `(V | W) == 0`  =>  `(V == 0) && (W == 0)`
///   - `(V | W) != 0`  =>  `(V != 0) || (W != 0)`
///
/// Fires only when every use of the OR output is an `==`/`!=` whose second input is the constant 0,
/// and both `V` and `W` are in SSA form (not free). Each such compare is rewritten into a
/// BOOL_AND / BOOL_OR of the two per-operand compares. This breaks a bit-packed
/// `(a*2 | b<<7) != 0` flag-smear into the independent comparisons — the foundation for recovering
/// `a || b` (with [`RuleShiftCompare`], [`RuleZextEliminate`], [`RuleBooleanNegate`]).
/// Ghidra `RuleFloatRange` (`ruleaction.cc`): collapse two floating-point comparisons of the same
/// operands, combined by a boolean op, into one comparison — `(a < b) || (a == b)` → `a <= b`, and
/// `(a <= b) && (a != b)` → `a < b`. This is what turns the `ucomisd` flag idiom (mosura lifts it
/// to a `BOOL_OR`/`BOOL_AND` of separate `FLOAT_LESS`/`FLOAT_EQUAL`/`FLOAT_NOTEQUAL` compares) into
/// a single `<=`/`<`, as Ghidra prints.
pub struct RuleFloatRange;

impl Rule for RuleFloatRange {
    fn name(&self) -> &str {
        "floatrange"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolAnd, OpCode::BoolOr]
    }
    // faithful port of ruleaction.cc:1505-1508: the `cvn1 != matchvn` and `cvn1->isFree()` guards
    // both return 0 but test distinct conditions — kept as Ghidra's else-if cascade
    #[allow(clippy::if_same_then_else)]
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn1 = data.op(op).input(0).unwrap();
        if !data.vn(vn1).is_written() {
            return 0;
        }
        let vn2 = data.op(op).input(1).unwrap();
        if !data.vn(vn2).is_written() {
            return 0;
        }
        // cmp1 must be the LESS/LESSEQUAL operator; cmp2 is the "other". Swap if it started reversed.
        let mut cmp1 = data.vn(vn1).def.unwrap();
        let mut cmp2 = data.vn(vn2).def.unwrap();
        let mut opccmp1 = data.op(cmp1).code();
        if opccmp1 != OpCode::FloatLess && opccmp1 != OpCode::FloatLessequal {
            cmp1 = data.vn(vn2).def.unwrap();
            cmp2 = data.vn(vn1).def.unwrap();
            opccmp1 = data.op(cmp1).code();
        }
        let opc_op = data.op(op).code();
        let resultopc = match opccmp1 {
            OpCode::FloatLess
                if data.op(cmp2).code() == OpCode::FloatEqual && opc_op == OpCode::BoolOr =>
            {
                OpCode::FloatLessequal
            }
            OpCode::FloatLessequal
                if data.op(cmp2).code() == OpCode::FloatNotequal && opc_op == OpCode::BoolAnd =>
            {
                OpCode::FloatLess
            }
            _ => return 0,
        };

        // Make sure both operators are comparing the same two things.
        let mut slot1 = 0usize;
        let mut nvn1 = data.op(cmp1).input(0).unwrap();
        if data.vn(nvn1).is_constant() {
            slot1 = 1;
            nvn1 = data.op(cmp1).input(1).unwrap();
            if data.vn(nvn1).is_constant() {
                return 0;
            }
        }
        if data.vn(nvn1).is_free() {
            return 0;
        }
        let cvn1 = data.op(cmp1).input(1 - slot1).unwrap();
        let slot2 = if nvn1 == data.op(cmp2).input(0).unwrap() {
            0
        } else if nvn1 == data.op(cmp2).input(1).unwrap() {
            1
        } else {
            return 0;
        };
        let matchvn = data.op(cmp2).input(1 - slot2).unwrap();
        if data.vn(cvn1).is_constant() {
            if !data.vn(matchvn).is_constant() {
                return 0;
            }
            if data.vn(matchvn).constant_value() != data.vn(cvn1).constant_value() {
                return 0;
            }
        } else if cvn1 != matchvn {
            return 0;
        } else if data.vn(cvn1).is_free() {
            return 0;
        }

        // Collapse the two comparisons into one.
        data.op_set_opcode(op, resultopc);
        data.op_set_input(op, slot1, nvn1);
        if data.vn(cvn1).is_constant() {
            let (sz, val) = (data.vn(cvn1).size, data.vn(cvn1).constant_value());
            let c = data.new_const(sz, val);
            data.op_set_input(op, 1 - slot1, c);
        } else {
            data.op_set_input(op, 1 - slot1, cvn1);
        }
        1
    }
}

/// Ghidra `RuleFloatCast` (`ruleaction.cc`, oppool1 @5634 "floatprecision"): replace
/// `(casttosmall)(casttobig)V` with the identity or a single cast. Matches a `FLOAT_FLOAT2FLOAT`
/// or `FLOAT_TRUNC` whose input is itself defined by a `FLOAT_FLOAT2FLOAT` or `FLOAT_INT2FLOAT`,
/// and rewrites the op in place to consume the inner cast's source directly, dropping the
/// redundant intermediate conversion.
pub struct RuleFloatCast;

impl Rule for RuleFloatCast {
    fn name(&self) -> &str {
        "floatcast"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::FloatFloat2float, OpCode::FloatTrunc]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn1 = data.op(op).input(0).unwrap();
        if !data.vn(vn1).is_written() {
            return 0;
        }
        let castop = data.vn(vn1).def.unwrap();
        let opc2 = data.op(castop).code();
        if opc2 != OpCode::FloatFloat2float && opc2 != OpCode::FloatInt2float {
            return 0;
        }
        let opc1 = data.op(op).code();
        let vn2 = data.op(castop).input(0).unwrap();
        let insize1 = data.vn(vn1).size;
        let insize2 = data.vn(vn2).size;
        let outsize = data.vn(data.op(op).output.unwrap()).size;

        if data.vn(vn2).is_free() {
            return 0; // Don't propagate free
        }

        if opc2 == OpCode::FloatFloat2float && opc1 == OpCode::FloatFloat2float {
            if insize1 > outsize {
                // op is superfluous
                data.op_set_input(op, 0, vn2);
                if outsize == insize2 {
                    data.op_set_opcode(op, OpCode::Copy); // We really have the identity
                }
                return 1;
            } else if insize2 < insize1 {
                // Convert two increases -> one combined increase
                data.op_set_input(op, 0, vn2);
                return 1;
            }
        } else if opc2 == OpCode::FloatInt2float && opc1 == OpCode::FloatFloat2float {
            // Convert integer straight into final float size
            data.op_set_input(op, 0, vn2);
            data.op_set_opcode(op, OpCode::FloatInt2float);
            return 1;
        } else if opc2 == OpCode::FloatFloat2float && opc1 == OpCode::FloatTrunc {
            // Convert float straight into final integer
            data.op_set_input(op, 0, vn2);
            return 1;
        }

        0
    }
}

/// The input slot at which `vn` is read by `op` (Ghidra `PcodeOp::getSlot`).
fn slot_of(data: &Funcdata, op: OpId, vn: VarnodeId) -> usize {
    data.op(op).inrefs.iter().position(|&v| v == vn).unwrap_or(0)
}

/// Ghidra `TypeOp::isFloatingPointOp` — the p-code ops whose `TypeOp` is a floating-point one.
fn is_float_op(opc: OpCode) -> bool {
    use OpCode::*;
    matches!(
        opc,
        FloatEqual | FloatNotequal | FloatLess | FloatLessequal | FloatNan | FloatAdd | FloatSub
            | FloatMult | FloatDiv | FloatNeg | FloatAbs | FloatSqrt | FloatInt2float
            | FloatFloat2float | FloatTrunc | FloatCeil | FloatFloor | FloatRound
    )
}

/// Ghidra `RuleIgnoreNan::checkBackForCompare`: does the boolean `root` come from a floating-point
/// comparison of `float_var` (directly, or one level down a BOOL_AND/OR, through an optional
/// BOOL_NEGATE)?
fn check_back_for_compare(float_var: VarnodeId, root: VarnodeId, data: &Funcdata) -> bool {
    if !data.vn(root).is_written() {
        return false;
    }
    let mut def1 = data.vn(root).def.unwrap();
    if !data.op(def1).is_bool_output() {
        return false;
    }
    if data.op(def1).code() == OpCode::BoolNegate {
        let vn = data.op(def1).input(0).unwrap();
        if !data.vn(vn).is_written() {
            return false;
        }
        def1 = data.vn(vn).def.unwrap();
    }
    if is_float_op(data.op(def1).code()) {
        if data.op(def1).num_inputs() != 2 {
            return false;
        }
        return functional_equality(data, float_var, data.op(def1).input(0).unwrap())
            || functional_equality(data, float_var, data.op(def1).input(1).unwrap());
    }
    let opc = data.op(def1).code();
    if opc != OpCode::BoolAnd && opc != OpCode::BoolOr {
        return false;
    }
    for i in 0..2 {
        let vn = data.op(def1).input(i).unwrap();
        if !data.vn(vn).is_written() {
            continue;
        }
        let def2 = data.vn(vn).def.unwrap();
        if !data.op(def2).is_bool_output() || !is_float_op(data.op(def2).code()) {
            continue;
        }
        if data.op(def2).num_inputs() != 2 {
            continue;
        }
        if functional_equality(data, float_var, data.op(def2).input(0).unwrap())
            || functional_equality(data, float_var, data.op(def2).input(1).unwrap())
        {
            return true;
        }
    }
    false
}

/// Ghidra `RuleIgnoreNan::isAnotherNan`: is `vn` (possibly through a BOOL_NEGATE) another
/// `FLOAT_NAN`, so the NaN-check chain continues one level deeper?
fn is_another_nan(vn: VarnodeId, data: &Funcdata) -> bool {
    if !data.vn(vn).is_written() {
        return false;
    }
    let mut op = data.vn(vn).def.unwrap();
    if data.op(op).code() == OpCode::BoolNegate {
        let vn2 = data.op(op).input(0).unwrap();
        if !data.vn(vn2).is_written() {
            return false;
        }
        op = data.vn(vn2).def.unwrap();
    }
    data.op(op).code() == OpCode::FloatNan
}

/// Ghidra `RuleIgnoreNan::testForComparison`: at a boolean use `op` of the NaN result, if the other
/// operand is a comparison of `float_var` the NaN check is redundant — rewrite `op` to drop it
/// (BOOL_OR/AND → a COPY of the comparison; INT_EQUAL/NOTEQUAL → fold the NaN slot to a constant).
/// Returns the output to keep descending through when the other operand is itself another NaN check.
/// The `CPUI_CBRANCH` case (a NaN guard spread across two branches) is deferred.
fn test_for_comparison(
    float_var: VarnodeId,
    op: OpId,
    slot: usize,
    match_code: OpCode,
    count: &mut i32,
    data: &mut Funcdata,
) -> Option<VarnodeId> {
    let opc = data.op(op).code();
    if opc == match_code {
        let vn = data.op(op).input(1 - slot).unwrap();
        if check_back_for_compare(float_var, vn, data) {
            data.op_set_opcode(op, OpCode::Copy);
            data.op_remove_input(op, 1);
            data.op_set_input(op, 0, vn);
            *count += 1;
        } else if is_another_nan(vn, data) {
            return data.op(op).output;
        }
    } else if opc == OpCode::IntEqual || opc == OpCode::IntNotequal {
        let vn = data.op(op).input(1 - slot).unwrap();
        if check_back_for_compare(float_var, vn, data) {
            let val = if match_code == OpCode::BoolOr { 0 } else { 1 };
            let c = data.new_const(1, val);
            data.op_set_input(op, slot, c);
            *count += 1;
        }
    }
    // (Ghidra's CPUI_CBRANCH branch — a NaN guard split across two CBRANCHes — is deferred.)
    None
}

/// Ghidra `RuleIgnoreNan` (`ruleaction.cc`, oppool1 @5635 "floatprecision"): a `NAN(x)` check OR'd
/// (or, negated, AND'd) with a comparison of the same `x` is redundant — the ordered comparison
/// already handles the unordered/NaN case — so drop the NaN check. This dissolves the `ucomisd`
/// NaN-guard idiom, letting [`RuleFloatRange`] then collapse the bare ordered compares.
pub struct RuleIgnoreNan;

impl Rule for RuleIgnoreNan {
    fn name(&self) -> &str {
        "ignorenan"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::FloatNan]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        // (mosura has no `nan_ignore_all` architecture flag — that always-false branch is skipped.)
        let float_var = data.op(op).input(0).unwrap();
        if data.vn(float_var).is_free() {
            return 0;
        }
        let out1 = data.op(op).output.unwrap();
        let mut count = 0;
        // Snapshot each descend list before mutating — a rewrite changes the live descend edges.
        for bool_read1 in data.vn(out1).descend.clone() {
            let (match_code, out2) = if data.op(bool_read1).code() == OpCode::BoolNegate {
                (OpCode::BoolAnd, data.op(bool_read1).output)
            } else {
                let slot = slot_of(data, bool_read1, out1);
                let o2 = test_for_comparison(float_var, bool_read1, slot, OpCode::BoolOr, &mut count, data);
                (OpCode::BoolOr, o2)
            };
            let Some(out2) = out2 else { continue };
            for bool_read2 in data.vn(out2).descend.clone() {
                let slot = slot_of(data, bool_read2, out2);
                let Some(out3) = test_for_comparison(float_var, bool_read2, slot, match_code, &mut count, data)
                else {
                    continue;
                };
                for bool_read3 in data.vn(out3).descend.clone() {
                    let slot = slot_of(data, bool_read3, out3);
                    test_for_comparison(float_var, bool_read3, slot, match_code, &mut count, data);
                }
            }
        }
        if count > 0 {
            1
        } else {
            0
        }
    }
}

pub struct RuleOrCompare;

impl Rule for RuleOrCompare {
    fn name(&self) -> &str {
        "orcompare"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntOr]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(outvn) = data.op(op).output else { return 0 };
        let descend = data.vn(outvn).descend.clone();
        // hasCompares: at least one use, and every use is `==`/`!=` against constant 0
        if descend.is_empty() {
            return 0;
        }
        for &comp in &descend {
            let opc = data.op(comp).code();
            if opc != OpCode::IntEqual && opc != OpCode::IntNotequal {
                return 0;
            }
            let Some(c) = data.op(comp).input(1) else { return 0 };
            if !is_const0(data, c) {
                return 0;
            }
        }
        let (Some(v), Some(w)) = (data.op(op).input(0), data.op(op).input(1)) else { return 0 };
        // make sure V and W are in SSA form
        if data.vn(v).is_free() || data.vn(w).is_free() {
            return 0;
        }
        let (vsize, wsize) = (data.vn(v).size, data.vn(w).size);
        for comp in descend {
            let opc = data.op(comp).code();
            let pc = data.op(comp).seqnum.pc;
            let zero_v = data.new_const(vsize, 0);
            let zero_w = data.new_const(wsize, 0);
            let uniq = data.num_ops() as u32;
            let eq_v = data.new_op(opc, SeqNum { pc, uniq }, vec![v, zero_v]);
            let eq_v_out = data.new_output_unique(eq_v, 1);
            let uniq = data.num_ops() as u32;
            let eq_w = data.new_op(opc, SeqNum { pc, uniq }, vec![w, zero_w]);
            let eq_w_out = data.new_output_unique(eq_w, 1);
            // make sure the comparisons' output is already defined (inserted before the compare)
            data.op_insert_before(eq_v, comp);
            data.op_insert_before(eq_w, comp);
            // INT_EQUAL becomes BOOL_AND; INT_NOTEQUAL becomes BOOL_OR
            let conn = if opc == OpCode::IntEqual { OpCode::BoolAnd } else { OpCode::BoolOr };
            data.op_set_opcode(comp, conn);
            data.op_set_all_input(comp, &[eq_v_out, eq_w_out]);
        }
        1
    }
}

/// Ghidra `RuleShiftCompare` (ruleaction.cc:2044): strip a shift/scale from a comparison when it
/// loses no information.
///   - `V >> c == d`  =>  `V == (d << c)` (and likewise `V / 2^k`)
///   - `V << c == d`  =>  `V == (d >> c)`, or — if the left-shift would lose high bits — an
///     `(V & mask) == (d >> c)` (and likewise `V * 2^k`)
///
/// Works on both `INT_EQUAL` and `INT_NOTEQUAL`. The non-zero mask of the shifted value
/// ([`Varnode::get_nzmask`]) is what proves no information is lost. This collapses the
/// `(a==10)*2 == 0` / `(b==0x14)<<7 == 0` forms that `RuleOrCompare` leaves behind into bare
/// `(a==10) == 0` / `(b==0x14) == 0` compares.
pub struct RuleShiftCompare;

impl Rule for RuleShiftCompare {
    fn name(&self) -> &str {
        "shiftcompare"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntEqual, OpCode::IntNotequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(shiftvn), Some(constvn)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        if !data.vn(constvn).is_constant() {
            return 0;
        }
        if !data.vn(shiftvn).is_written() {
            return 0;
        }
        let shiftop = data.vn(shiftvn).def.unwrap();
        let opc = data.op(shiftop).code();
        let Some(savn) = data.op(shiftop).input(1) else { return 0 };
        let (isleft, sa): (bool, u32) = match opc {
            OpCode::IntLeft => {
                if !data.vn(savn).is_constant() {
                    return 0;
                }
                (true, data.vn(savn).constant_value() as u32)
            }
            OpCode::IntRight => {
                if !data.vn(savn).is_constant() {
                    return 0;
                }
                // A right shift is a likely shift out of a bitfield, which we want to keep — only
                // apply when we know we will eliminate the shifted variable.
                if lone_descend(data, shiftvn) != Some(op) {
                    return 0;
                }
                (false, data.vn(savn).constant_value() as u32)
            }
            OpCode::IntMult => {
                if !data.vn(savn).is_constant() {
                    return 0;
                }
                let val = data.vn(savn).constant_value();
                let s = val.trailing_zeros();
                if (val >> s) != 1 {
                    return 0; // not multiplying by a power of 2
                }
                (true, s)
            }
            OpCode::IntDiv => {
                if !data.vn(savn).is_constant() {
                    return 0;
                }
                let val = data.vn(savn).constant_value();
                let s = val.trailing_zeros();
                if (val >> s) != 1 {
                    return 0; // not dividing by a power of 2
                }
                if lone_descend(data, shiftvn) != Some(op) {
                    return 0;
                }
                (false, s)
            }
            _ => return 0,
        };
        if sa == 0 {
            return 0;
        }
        let mainvn = data.op(shiftop).input(0).unwrap();
        if data.vn(mainvn).is_free() {
            return 0;
        }
        if data.vn(mainvn).size > 8 {
            return 0; // uintb is 64-bit (Ghidra's `sizeof(uintb)` guard)
        }
        let constval = data.vn(constvn).constant_value();
        let nzmask = data.vn(mainvn).get_nzmask();
        let shiftsize = data.vn(shiftvn).size;
        let constsize = data.vn(constvn).size;
        let smask = super::nzmask::calc_mask(shiftsize);
        let newconst: u64;
        if isleft {
            newconst = constval >> sa;
            if (newconst << sa) != constval {
                return 0; // information lost in constval
            }
            let tmp = (nzmask << sa) & smask;
            if (tmp >> sa) != nzmask {
                // information is lost in main: replace the LEFT with an AND mask. This must be the
                // lone use of the shift.
                if lone_descend(data, shiftvn) != Some(op) {
                    return 0;
                }
                let sa2 = 8 * shiftsize - sa;
                let m = 1u64.checked_shl(sa2).unwrap_or(0).wrapping_sub(1);
                let newmask = data.new_const(constsize, m);
                let pc = data.op(op).seqnum.pc;
                let uniq = data.num_ops() as u32;
                let newop = data.new_op(OpCode::IntAnd, SeqNum { pc, uniq }, vec![mainvn, newmask]);
                let newtmp = data.new_output_unique(newop, constsize);
                data.op_insert_before(newop, shiftop);
                let nc = data.new_const(constsize, newconst);
                data.op_set_input(op, 0, newtmp);
                data.op_set_input(op, 1, nc);
                return 1;
            }
        } else {
            if ((nzmask >> sa) << sa) != nzmask {
                return 0; // information is lost in main
            }
            newconst = (constval << sa) & smask;
            if (newconst >> sa) != constval {
                return 0; // information is lost in constval
            }
        }
        let nc = data.new_const(constsize, newconst);
        data.op_set_input(op, 0, mainvn);
        data.op_set_input(op, 1, nc);
        1
    }
}

/// Ghidra `RuleZextEliminate` (ruleaction.cc:2471): eliminate an `INT_ZEXT` in a comparison when
/// the constant operand loses no non-zero bits.
///   - `zext(V) == c`  =>  `V == c`   (and `!=`, `<`, `<=`)
///
/// The zero-extension must be the lone use of the comparison's input. This drops the
/// `zext(a==10) == 0` widening that `RuleShiftCompare` exposes, leaving `(a==10) == 0`.
pub struct RuleZextEliminate;

impl Rule for RuleZextEliminate {
    fn name(&self) -> &str {
        "zexteliminate"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntEqual, OpCode::IntNotequal, OpCode::IntLess, OpCode::IntLessequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(in0), Some(in1)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        let is_zext = |d: &Funcdata, v: VarnodeId| {
            d.vn(v).is_written() && d.op(d.vn(v).def.unwrap()).code() == OpCode::IntZext
        };
        // vn1 is the ZEXTed input, vn2 the other; prefer slot 1 (Ghidra checks getIn(1) first).
        let (vn1, vn2, zextslot, otherslot) = if is_zext(data, in1) {
            (in1, in0, 1usize, 0usize)
        } else if is_zext(data, in0) {
            (in0, in1, 0usize, 1usize)
        } else {
            return 0;
        };
        if !data.vn(vn2).is_constant() {
            return 0;
        }
        let zext = data.vn(vn1).def.unwrap();
        let zin = data.op(zext).input(0).unwrap();
        if !data.vn(zin).is_heritage_known() {
            return 0;
        }
        if lone_descend(data, vn1) != Some(op) {
            return 0; // extension must not be used for anything else
        }
        let smallsize = data.vn(zin).size;
        let val = data.vn(vn2).constant_value();
        // is the zero extension unnecessary? (the constant fits in the small width)
        if smallsize < 8 && (val >> (8 * smallsize)) != 0 {
            return 0;
        }
        let newvn = data.new_const(smallsize, val);
        data.op_set_input(op, zextslot, zin);
        data.op_set_input(op, otherslot, newvn);
        1
    }
}

/// Ghidra `RuleBooleanNegate` (ruleaction.cc:2937): simplify a comparison of a boolean value with
/// `false`/`true`.
///   - `V == false`  =>  `!V`        `V == true`   =>  `V`
///   - `V != false`  =>  `V`         `V != true`   =>  `!V`
///
/// The compared value must be a boolean ([`is_boolean_value`]) and the constant must be 0 or 1. The
/// op is rewritten in place as a BOOL_NEGATE or COPY. This collapses the `(a==10) == 0` form (left
/// by [`RuleZextEliminate`]) into `!(a==10)` — which [`RuleBoolNegate`] then renders as the
/// complementary `a != 10`, so a De-Morgan'd `BOOL_AND` prints as `a || b`.
pub struct RuleBooleanNegate;

impl Rule for RuleBooleanNegate {
    fn name(&self) -> &str {
        "booleannegate"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntNotequal, OpCode::IntEqual]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let opc = data.op(op).code();
        let (Some(subbool), Some(constvn)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        if !data.vn(constvn).is_constant() {
            return 0;
        }
        let val = data.vn(constvn).constant_value();
        if val != 0 && val != 1 {
            return 0;
        }
        let mut negate = opc == OpCode::IntNotequal;
        if val == 0 {
            negate = !negate;
        }
        if !is_boolean_value(data, subbool) {
            return 0;
        }
        data.op_remove_input(op, 1); // remove the constant
        data.op_set_input(op, 0, subbool); // keep the original boolean parameter
        data.op_set_opcode(op, if negate { OpCode::BoolNegate } else { OpCode::Copy });
        1
    }
}

/// Ghidra `RuleShiftPiece` (ruleaction.cc:3753): convert a "shift and add" into a PIECE (CONCAT).
///   `(ext(V) << 8*|W|) {INT_OR|INT_XOR|INT_ADD} ext(W)  =>  CONCAT(V, W)`
/// where the high operand is zero/sign-extended and shifted left by exactly the low operand's bit
/// width. If the extension is wider than the concatenation, the PIECE is re-extended (ZEXT/SEXT).
/// Also folds the CDQ:IDIV self-sign-extension form
///   `(zext(SUB(big,0) s>> (|low|*8-1)) << |low|*8) + zext(SUB(big,0))  =>  sext(SUB(big,0))`.
/// This collapses bit-packed struct assembly (piecestruct's `(a<<0x10)|b` → `CONCAT22(a,b)`).
pub struct RuleShiftPiece;

impl Rule for RuleShiftPiece {
    fn name(&self) -> &str {
        "shiftpiece"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntOr, OpCode::IntXor, OpCode::IntAdd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(a0), Some(a1)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        if !data.vn(a0).is_written() || !data.vn(a1).is_written() {
            return 0;
        }
        let mut shiftop = data.vn(a0).def.unwrap();
        let mut zextloop = data.vn(a1).def.unwrap();
        // The INT_LEFT input is the high piece; if it is the other operand, swap.
        if data.op(shiftop).code() != OpCode::IntLeft {
            if data.op(zextloop).code() != OpCode::IntLeft {
                return 0;
            }
            std::mem::swap(&mut shiftop, &mut zextloop);
        }
        let Some(sav) = data.op(shiftop).input(1) else { return 0 };
        if !data.vn(sav).is_constant() {
            return 0;
        }
        let hiv = data.op(shiftop).input(0).unwrap();
        if !data.vn(hiv).is_written() {
            return 0;
        }
        let zexthiop = data.vn(hiv).def.unwrap();
        let hicode = data.op(zexthiop).code();
        if hicode != OpCode::IntZext && hicode != OpCode::IntSext {
            return 0;
        }
        let vn1 = data.op(zexthiop).input(0).unwrap(); // pre-extension high value
        if data.vn(vn1).is_constant() {
            if data.vn(vn1).size < 8 {
                return 0; // let ZEXT of a small constant collapse naturally
            }
        } else if data.vn(vn1).is_free() {
            return 0;
        }
        let sa = data.vn(sav).constant_value() as u32;
        let vn1_size = data.vn(vn1).size;
        let concatsize = sa + 8 * vn1_size;
        let out = data.op(op).output.unwrap();
        let out_size = data.vn(out).size;
        if out_size * 8 < concatsize {
            return 0;
        }
        if data.op(zextloop).code() != OpCode::IntZext {
            // CDQ:IDIV special case: the high piece is the sign-extension `SUB(big,0) s>> (sz*8-1)`
            // of the low piece, so the whole expression is a sign-extension of the low part.
            if !data.vn(vn1).is_written() {
                return 0;
            }
            let rshift = data.vn(vn1).def.unwrap();
            if data.op(rshift).code() != OpCode::IntSright {
                return 0;
            }
            let Some(rsav) = data.op(rshift).input(1) else { return 0 };
            if !data.vn(rsav).is_constant() {
                return 0;
            }
            let vn2 = data.op(rshift).input(0).unwrap();
            if !data.vn(vn2).is_written() {
                return 0;
            }
            let subop = data.vn(vn2).def.unwrap();
            if data.op(subop).code() != OpCode::Subpiece {
                return 0; // SUBPIECE connects the high and low parts
            }
            let Some(subc) = data.op(subop).input(1) else { return 0 };
            if !(data.vn(subc).is_constant() && data.vn(subc).constant_value() == 0) {
                return 0; // must be the low part
            }
            let bigvn = data.op(zextloop).output.unwrap();
            if data.op(subop).input(0) != Some(bigvn) {
                return 0; // verify the link through SUBPIECE with the low part
            }
            let rsa = data.vn(rsav).constant_value() as u32;
            let vn2_size = data.vn(vn2).size;
            if rsa != vn2_size * 8 - 1 {
                return 0; // arithmetic shift must copy the sign bit through the whole high part
            }
            if (data.vn(bigvn).get_nzmask() >> sa) != 0 {
                return 0; // the original most significant bytes must be zero
            }
            if sa != 8 * vn2_size {
                return 0;
            }
            data.op_set_opcode(op, OpCode::IntSext);
            data.op_set_input(op, 0, vn2);
            data.op_remove_input(op, 1);
            return 1;
        }
        let vn2 = data.op(zextloop).input(0).unwrap(); // low value
        if data.vn(vn2).is_free() {
            return 0;
        }
        let vn2_size = data.vn(vn2).size;
        if sa != 8 * vn2_size {
            return 0;
        }
        if concatsize == out_size * 8 {
            data.op_set_opcode(op, OpCode::Piece);
            data.op_set_input(op, 0, vn1);
            data.op_set_input(op, 1, vn2);
        } else {
            // Extension is wider than the concatenation: build the PIECE, then re-extend it.
            let pc = data.op(op).seqnum.pc;
            let uniq = data.num_ops() as u32;
            let newop = data.new_op(OpCode::Piece, SeqNum { pc, uniq }, vec![vn1, vn2]);
            let newout = data.new_output_unique(newop, concatsize / 8);
            data.op_insert_before(newop, op);
            data.op_set_opcode(op, hicode);
            data.op_remove_input(op, 1);
            data.op_set_input(op, 0, newout);
        }
        1
    }
}

/// Ghidra `RuleAndMask` (ruleaction.cc:302): collapse an unnecessary `INT_AND`.
///   - `V & W  =>  0`  when `nzm(V) & nzm(W) == 0` (the AND can produce no nonzero bit)
///   - `V & c  =>  V`  when the constant `c` covers every nonzero bit of `V` (`nzm(V) & c == nzm(V)`)
/// Uses the non-zero mask to prove the mask is a no-op (e.g. `(uint)char_val & 0xff => char_val`).
/// (Ghidra's third arm — `nzm & getConsume() == 0` — needs per-bit consume tracking, which mosura's
/// whole-varnode dead-code analysis does not model, so it is omitted; that arm only ever removes
/// *more*.)
pub struct RuleAndMask;

impl Rule for RuleAndMask {
    fn name(&self) -> &str {
        "andmask"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        // Re-check the live shape: the pool dispatches on a cached opcode that an earlier rule this
        // pass may have rewritten away from INT_AND.
        if data.op(op).code() != OpCode::IntAnd || data.op(op).num_inputs() != 2 {
            return 0;
        }
        let Some(out) = data.op(op).output else { return 0 };
        let size = data.vn(out).size;
        if size > 8 {
            return 0; // uintb is 64-bit
        }
        let (i0, i1) = (data.op(op).input(0).unwrap(), data.op(op).input(1).unwrap());
        let mask1 = data.vn(i0).get_nzmask();
        let andmask = if mask1 == 0 { 0 } else { mask1 & data.vn(i1).get_nzmask() };
        let vn = if andmask == 0 {
            data.new_const(size, 0)
        } else if andmask == mask1 {
            if !data.vn(i1).is_constant() {
                return 0;
            }
            i0 // the AND keeps every nonzero bit of input(0)
        } else {
            return 0;
        };
        if !data.vn(vn).is_heritage_known() {
            return 0;
        }
        data.op_set_opcode(op, OpCode::Copy);
        data.op_remove_input(op, 1);
        data.op_set_input(op, 0, vn);
        1
    }
}

/// Ghidra `RuleAndZext` (ruleaction.cc:1696): convert `INT_AND` to `INT_ZEXT` where the mask keeps
/// exactly the low bytes of a sign-extension or concatenation:
///   - `sext(X) & mask  =>  zext(X)`   (mask == all-ones over `|X|` bytes)
///   - `concat(Y, X) & mask  =>  zext(X)`
/// This drops the `movsx`+`and` idiom for a packed byte (`(int)char_val & 0xff => (uint)char_val`),
/// exposing the bare extension that [`RuleShiftPiece`] needs to fold the byte into a CONCAT.
pub struct RuleAndZext;

impl Rule for RuleAndZext {
    fn name(&self) -> &str {
        "andzext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(i0), Some(cvn1)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        if !data.vn(cvn1).is_constant() {
            return 0;
        }
        if !data.vn(i0).is_written() {
            return 0;
        }
        let otherop = data.vn(i0).def.unwrap();
        let rootvn = match data.op(otherop).code() {
            OpCode::IntSext => data.op(otherop).input(0).unwrap(),
            OpCode::Piece => data.op(otherop).input(1).unwrap(), // little-endian low part
            _ => return 0,
        };
        let mask = super::nzmask::calc_mask(data.vn(rootvn).size);
        if mask != data.vn(cvn1).constant_value() {
            return 0;
        }
        if data.vn(rootvn).is_free() {
            return 0;
        }
        if data.vn(rootvn).size > 8 {
            return 0;
        }
        data.op_set_opcode(op, OpCode::IntZext);
        data.op_remove_input(op, 1);
        data.op_set_input(op, 0, rootvn);
        1
    }
}

/// Ghidra `RuleSlessToLess` (ruleaction.cc:2530): convert a signed comparison to an unsigned one when
/// both operands are provably non-negative — `V s< W  =>  V < W` (and `s<=` → `<=`). The non-zero
/// mask proves the sign bit is clear on each operand, so the signed and unsigned orderings agree.
pub struct RuleSlessToLess;

impl Rule for RuleSlessToLess {
    fn name(&self) -> &str {
        "slesstoless"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSless, OpCode::IntSlessequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        // An earlier rule this pass may have rewritten `op` while the pool's cached opcode stayed
        // INT_SLESS/INT_SLESSEQUAL (the pool dispatches on the stale code). Re-check the live shape.
        let new_op = match data.op(op).code() {
            OpCode::IntSless => OpCode::IntLess,
            OpCode::IntSlessequal => OpCode::IntLessequal,
            _ => return 0,
        };
        let vn = data.op(op).input(0).unwrap();
        let sz = data.vn(vn).size;
        if super::nzmask::signbit_negative(data.vn(vn).get_nzmask(), sz) {
            return 0;
        }
        let vn1 = data.op(op).input(1).unwrap();
        if super::nzmask::signbit_negative(data.vn(vn1).get_nzmask(), sz) {
            return 0;
        }
        data.op_set_opcode(op, new_op);
        1
    }
}

/// Ghidra `RulePopcountBoolXor::getBooleanResult` (ruleaction.cc:10399): follow the boolean bit at
/// `bit_pos` back through the shift/extend/concat/mask operations that combined it, returning the
/// single boolean Varnode that produces it. Returns `(None, const_res)`, where `const_res` is 0/1 if
/// the bit resolves to a constant and `-1` when no unique boolean Varnode can be isolated.
fn popcount_boolean_result(
    data: &Funcdata,
    mut vn: VarnodeId,
    mut bit_pos: i32,
) -> (Option<VarnodeId>, i32) {
    let mut mask: u64 = 1u64.checked_shl(bit_pos as u32).unwrap_or(0);
    loop {
        if data.vn(vn).is_constant() {
            let const_res =
                (data.vn(vn).constant_value().checked_shr(bit_pos as u32).unwrap_or(0) & 1) as i32;
            return (None, const_res);
        }
        if !data.vn(vn).is_written() {
            return (None, -1);
        }
        if bit_pos == 0 && data.vn(vn).size == 1 && data.vn(vn).get_nzmask() == mask {
            return (Some(vn), -1);
        }
        let def = data.vn(vn).def.unwrap();
        match data.op(def).code() {
            OpCode::IntAnd => {
                let i1 = data.op(def).input(1).unwrap();
                if !data.vn(i1).is_constant() {
                    return (None, -1);
                }
                vn = data.op(def).input(0).unwrap();
            }
            OpCode::IntXor | OpCode::IntOr => {
                let vn0 = data.op(def).input(0).unwrap();
                let vn1 = data.op(def).input(1).unwrap();
                if data.vn(vn0).get_nzmask() & mask != 0 {
                    if data.vn(vn1).get_nzmask() & mask != 0 {
                        return (None, -1); // no unique path to the bit
                    }
                    vn = vn0;
                } else if data.vn(vn1).get_nzmask() & mask != 0 {
                    vn = vn1;
                } else {
                    return (None, -1);
                }
            }
            OpCode::IntZext | OpCode::IntSext => {
                vn = data.op(def).input(0).unwrap();
                if bit_pos >= data.vn(vn).size as i32 * 8 {
                    return (None, -1);
                }
            }
            OpCode::Subpiece => {
                let sa = data.vn(data.op(def).input(1).unwrap()).constant_value() as i32 * 8;
                bit_pos += sa;
                mask = mask.checked_shl(sa as u32).unwrap_or(0);
                vn = data.op(def).input(0).unwrap();
            }
            OpCode::Piece => {
                let vn0 = data.op(def).input(0).unwrap(); // high half
                let vn1 = data.op(def).input(1).unwrap(); // low half
                let sa = data.vn(vn1).size as i32 * 8;
                if bit_pos >= sa {
                    vn = vn0;
                    bit_pos -= sa;
                    mask = mask.checked_shr(sa as u32).unwrap_or(0);
                } else {
                    vn = vn1;
                }
            }
            OpCode::IntLeft => {
                let vn1 = data.op(def).input(1).unwrap();
                if !data.vn(vn1).is_constant() {
                    return (None, -1);
                }
                let sa = data.vn(vn1).constant_value() as i32;
                if sa > bit_pos {
                    return (None, -1);
                }
                bit_pos -= sa;
                mask = mask.checked_shr(sa as u32).unwrap_or(0);
                vn = data.op(def).input(0).unwrap();
            }
            OpCode::IntRight | OpCode::IntSright => {
                let vn1 = data.op(def).input(1).unwrap();
                if !data.vn(vn1).is_constant() {
                    return (None, -1);
                }
                let sa = data.vn(vn1).constant_value() as i32;
                vn = data.op(def).input(0).unwrap();
                bit_pos += sa;
                if bit_pos >= data.vn(vn).size as i32 * 8 {
                    return (None, -1);
                }
                mask = mask.checked_shl(sa as u32).unwrap_or(0);
            }
            _ => return (None, -1),
        }
    }
}

/// Ghidra `RulePopcountBoolXor` (ruleaction.cc:10273): reduce a POPCOUNT parity check over shifted
/// booleans to the boolean(s) themselves:
///   - `popcount(b1 << #pos) & 1              =>  b1`
///   - `popcount((b1 << #pos1) | (b2 << #pos2)) & 1  =>  b1 ^ b2`
/// The `& 1` masks the low bit (parity), and the non-zero mask of the POPCOUNT input has one or two
/// set bits, each traced back to a boolean by [`popcount_boolean_result`].
pub struct RulePopcountBoolXor;

impl Rule for RulePopcountBoolXor {
    fn name(&self) -> &str {
        "popcountboolxor"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Popcount]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        // Guard against an earlier rule this pass having rewritten `op` (the pool dispatches on the
        // cached opcode, which may be a stale CPUI_POPCOUNT).
        if data.op(op).code() != OpCode::Popcount {
            return 0;
        }
        let Some(out) = data.op(op).output else { return 0 };
        for base_op in data.vn(out).descend.clone() {
            if data.op(base_op).code() != OpCode::IntAnd {
                continue;
            }
            let Some(tmp_vn) = data.op(base_op).input(1) else { continue };
            if !data.vn(tmp_vn).is_constant() {
                continue;
            }
            if data.vn(tmp_vn).constant_value() != 1 {
                continue; // masking 1 bit means we are checking parity of the POPCOUNT input
            }
            if data.vn(tmp_vn).size != 1 {
                continue; // must be boolean-sized output
            }
            let in_vn = data.op(op).input(0).unwrap();
            if !data.vn(in_vn).is_written() {
                return 0;
            }
            let nzm = data.vn(in_vn).get_nzmask();
            let count = nzm.count_ones();
            if count == 1 {
                let least_pos = super::nzmask::leastsigbit_set(nzm);
                let (b1, _) = popcount_boolean_result(data, in_vn, least_pos);
                let Some(b1) = b1 else { continue };
                // Recognized  popcount( b1 << #pos ) & 1  →  COPY(b1)
                data.op_set_opcode(base_op, OpCode::Copy);
                data.op_remove_input(base_op, 1);
                data.op_set_input(base_op, 0, b1);
                return 1;
            }
            if count == 2 {
                let pos0 = super::nzmask::leastsigbit_set(nzm);
                let pos1 = super::nzmask::mostsigbit_set(nzm);
                let (b1, const_res0) = popcount_boolean_result(data, in_vn, pos0);
                if b1.is_none() && const_res0 != 1 {
                    continue;
                }
                let (b2, const_res1) = popcount_boolean_result(data, in_vn, pos1);
                if b2.is_none() && const_res1 != 1 {
                    continue;
                }
                if b1.is_none() && b2.is_none() {
                    continue;
                }
                let b1 = b1.unwrap_or_else(|| data.new_const(1, 1));
                let b2 = b2.unwrap_or_else(|| data.new_const(1, 1));
                // Recognized  popcount( b1 << #pos1 | b2 << #pos2 ) & 1  →  b1 ^ b2
                data.op_set_opcode(base_op, OpCode::IntXor);
                data.op_set_input(base_op, 0, b1);
                data.op_set_input(base_op, 1, b2);
                return 1;
            }
        }
        0
    }
}

/// Ghidra `RuleOrCollapse` (ruleaction.cc:384): `V | c  =>  c` when every bit not set in the
/// constant `c` is also provably 0 in `V` (`nzm(V) | c == c`) — the OR turns on no bit that `c`
/// does not already have, so the result is just `c`.
pub struct RuleOrCollapse;

impl Rule for RuleOrCollapse {
    fn name(&self) -> &str {
        "orcollapse"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntOr]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntOr {
            return 0;
        }
        let Some(out) = data.op(op).output else { return 0 };
        if data.vn(out).size > 8 {
            return 0; // matches Ghidra's `size > sizeof(uintb)` guard
        }
        let Some(cvn) = data.op(op).input(1) else { return 0 };
        if !data.vn(cvn).is_constant() {
            return 0;
        }
        let mask = data.vn(data.op(op).input(0).unwrap()).get_nzmask();
        let val = data.vn(cvn).constant_value();
        if (mask | val) != val {
            return 0; // input(0) could turn on other bits
        }
        data.op_set_opcode(op, OpCode::Copy);
        data.op_remove_input(op, 0); // keep the constant
        1
    }
}

/// Ghidra `RuleXorCollapse` (ruleaction.cc:4050): eliminate an INT_XOR inside an equality compare —
///   - `(V ^ W) == 0   =>  V == W`      (move the term to the other side)
///   - `(V ^ c) == d   =>  V == (c ^ d)`
/// Works for INT_EQUAL and INT_NOTEQUAL.
pub struct RuleXorCollapse;

impl Rule for RuleXorCollapse {
    fn name(&self) -> &str {
        "xorcollapse"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntEqual, OpCode::IntNotequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let code = data.op(op).code();
        if code != OpCode::IntEqual && code != OpCode::IntNotequal {
            return 0;
        }
        let cvn = data.op(op).input(1).unwrap();
        if !data.vn(cvn).is_constant() {
            return 0;
        }
        let xin = data.op(op).input(0).unwrap();
        let Some(xorop) = data.vn(xin).def else { return 0 };
        if data.op(xorop).code() != OpCode::IntXor {
            return 0;
        }
        if lone_descend(data, xin).is_none() {
            return 0; // the XOR output must have exactly one use
        }
        let coeff1 = data.vn(cvn).constant_value();
        let xorvn = data.op(xorop).input(1).unwrap();
        let xor0 = data.op(xorop).input(0).unwrap();
        if data.vn(xor0).is_free() {
            return 0; // this will be propagated
        }
        if !data.vn(xorvn).is_constant() {
            if coeff1 != 0 || data.vn(xorvn).is_free() {
                return 0;
            }
            data.op_set_input(op, 1, xorvn); // move the term to the other side
            data.op_set_input(op, 0, xor0);
            return 1;
        }
        let coeff2 = data.vn(xorvn).constant_value();
        if coeff2 == 0 {
            return 0;
        }
        let constvn = data.new_const(data.vn(cvn).size, coeff1 ^ coeff2);
        data.op_set_input(op, 1, constvn);
        data.op_set_input(op, 0, xor0);
        1
    }
}

/// Ghidra `RuleHighOrderAnd` (ruleaction.cc:1196): simplify an INT_AND with a high-order mask
/// (`0xff..00`) applied to an aligned INT_ADD — `(V + c) & 0xfff0  =>  V + (c & 0xfff0)` when `V` is
/// already zero in the masked-off low bits (`nzm(V) & mask == nzm(V)`). Also the nested aligned form
/// `((V + c) + W) & 0xfff0  =>  (V + (c & 0xfff0)) + W`.
pub struct RuleHighOrderAnd;

impl Rule for RuleHighOrderAnd {
    fn name(&self) -> &str {
        "highorderand"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntAnd {
            return 0;
        }
        let cvn1 = data.op(op).input(1).unwrap();
        if !data.vn(cvn1).is_constant() {
            return 0;
        }
        let in0 = data.op(op).input(0).unwrap();
        if !data.vn(in0).is_written() {
            return 0;
        }
        let addop = data.vn(in0).def.unwrap();
        if data.op(addop).code() != OpCode::IntAdd {
            return 0;
        }
        let mut val = data.vn(cvn1).constant_value();
        let size = data.vn(cvn1).size;
        // Mask must have the form 0b11..0..0 (a run of high bits set, low bits clear).
        if (val.wrapping_sub(1) | val) != super::nzmask::calc_mask(size) {
            return 0;
        }
        let cvn2 = data.op(addop).input(1).unwrap();
        if data.vn(cvn2).is_constant() {
            let xalign = data.op(addop).input(0).unwrap();
            if data.vn(xalign).is_free() {
                return 0;
            }
            let mask1 = data.vn(xalign).get_nzmask();
            if (mask1 & val) != mask1 {
                return 0; // input(0) must be unaffected by the AND
            }
            data.op_set_opcode(op, OpCode::IntAdd);
            data.op_set_input(op, 0, xalign);
            val &= data.vn(cvn2).constant_value();
            let c = data.new_const(size, val);
            data.op_set_input(op, 1, c);
            return 1;
        }
        // Nested form: the AND's INT_ADD combines an already-aligned term with another INT_ADD.
        let addout = data.op(addop).output.unwrap();
        if lone_descend(data, addout) != Some(op) {
            return 0;
        }
        for i in 0..2 {
            let zerovn = data.op(addop).input(i).unwrap();
            if (data.vn(zerovn).get_nzmask() & val) != data.vn(zerovn).get_nzmask() {
                continue; // zerovn must be unaffected by the AND
            }
            let nonzerovn = data.op(addop).input(1 - i).unwrap();
            if !data.vn(nonzerovn).is_written() {
                continue;
            }
            let addop2 = data.vn(nonzerovn).def.unwrap();
            if data.op(addop2).code() != OpCode::IntAdd {
                continue;
            }
            if lone_descend(data, nonzerovn) != Some(addop) {
                continue;
            }
            let cvn2 = data.op(addop2).input(1).unwrap();
            if !data.vn(cvn2).is_constant() {
                continue;
            }
            let xalign = data.op(addop2).input(0).unwrap();
            if (data.vn(xalign).get_nzmask() & val) != data.vn(xalign).get_nzmask() {
                continue;
            }
            val &= data.vn(cvn2).constant_value();
            let c = data.new_const(size, val);
            data.op_set_input(addop2, 1, c);
            data.op_remove_input(op, 1);
            data.op_set_opcode(op, OpCode::Copy);
            return 1;
        }
        0
    }
}

/// Ghidra `RuleNotDistribute` (ruleaction.cc:1147): distribute a BOOL_NEGATE over a short-circuit
/// boolean — De Morgan: `!(V && W)  =>  !V || !W` and `!(V || W)  =>  !V && !W`.
///
/// Faithful port (see the unit test), but **not wired into [`default_rule_pool`]** yet: the trace
/// diff shows mosura fires it 7× on `nan` where Ghidra fires it only 3×, because mosura's ucomisd
/// flag-tangle is still unsimplified upstream (the known `nan` gap) so its boolean graph has more
/// `!(BOOL_AND/OR)` sites than Ghidra's — over-applying De Morgan there diverges from Ghidra's C
/// (nan 0.378→0.308). Wire it once the `nan` flag-simplification (**Task #4**) makes the two graphs
/// match; the rule itself is correct. (Confirmed by measurement after Ghidra's per-op rule priority
/// landed [Task #7, `c88ff35`]: the over-fire is unchanged at 7×-vs-3×, so priority was never the
/// blocker — this is an upstream graph-shape divergence, Task #4.)
pub struct RuleNotDistribute;

impl Rule for RuleNotDistribute {
    fn name(&self) -> &str {
        "notdistribute"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolNegate]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::BoolNegate {
            return 0;
        }
        let inv = data.op(op).input(0).unwrap();
        let Some(compop) = data.vn(inv).def else { return 0 };
        let opc = match data.op(compop).code() {
            OpCode::BoolAnd => OpCode::BoolOr,
            OpCode::BoolOr => OpCode::BoolAnd,
            _ => return 0,
        };
        // BOOL_AND/BOOL_OR operands are boolean (size 1), so new_op_before's input(0)-derived
        // output size is 1 (Ghidra's newUniqueOut(1,...)).
        let (c0, c1) = (data.op(compop).input(0).unwrap(), data.op(compop).input(1).unwrap());
        let neg1 = data.new_op_before(op, OpCode::BoolNegate, vec![c0]);
        let out1 = data.op(neg1).output.unwrap();
        let neg2 = data.new_op_before(op, OpCode::BoolNegate, vec![c1]);
        let out2 = data.op(neg2).output.unwrap();
        data.op_set_opcode(op, opc);
        data.op_set_input(op, 0, out1);
        data.op_append_input(op, out2);
        1
    }
}

/// Ghidra `RuleAndCompare` (ruleaction.cc:1745): push an INT_AND mask through an INT_ZEXT/SUBPIECE
/// inside a compare-against-zero, widening the AND to the base value:
///   - `zext(V) & c == 0   =>  V & (c & mask) == 0`
///   - `sub(V, k) & d == 0  =>  V & (d << k*8) == 0`
/// Works for INT_EQUAL and INT_NOTEQUAL.
///
/// Faithful port (unit-tested), but **not wired into [`default_rule_pool`]** yet: the trace diff
/// shows mosura fires it where Ghidra does not (e.g. 3× on forloop_varused vs Ghidra's 0×, regressing
/// it 0.984→0.970). Ghidra's per-op rule priority landed (**Task #7**, `c88ff35`) and the over-fire is
/// UNCHANGED — so priority was not the blocker. The real cause (trace-diff Ghidra-only list): Ghidra
/// fires `addmultcollapse`/`sub2add` in its MAIN rule loop, while mosura runs them in a separate
/// `ptrarith_pool`, so mosura's intermediate graph reaches an `(V&mask)==0` shape Ghidra never has.
/// Wire it once those rules run in the main loop (**Task #8**).
pub struct RuleAndCompare;

impl Rule for RuleAndCompare {
    fn name(&self) -> &str {
        "andcompare"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntEqual, OpCode::IntNotequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let code = data.op(op).code();
        if code != OpCode::IntEqual && code != OpCode::IntNotequal {
            return 0;
        }
        let cmpc = data.op(op).input(1).unwrap();
        if !data.vn(cmpc).is_constant() || data.vn(cmpc).constant_value() != 0 {
            return 0;
        }
        let andvn = data.op(op).input(0).unwrap();
        if !data.vn(andvn).is_written() {
            return 0;
        }
        let andop = data.vn(andvn).def.unwrap();
        if data.op(andop).code() != OpCode::IntAnd {
            return 0;
        }
        let andc = data.op(andop).input(1).unwrap();
        if !data.vn(andc).is_constant() {
            return 0;
        }
        let subvn = data.op(andop).input(0).unwrap();
        if !data.vn(subvn).is_written() {
            return 0;
        }
        let subop = data.vn(subvn).def.unwrap();
        let base_const = data.vn(andc).constant_value();
        let (basevn, andconst) = match data.op(subop).code() {
            OpCode::Subpiece => {
                let bv = data.op(subop).input(0).unwrap();
                if data.vn(bv).size > 8 {
                    return 0;
                }
                let off = data.vn(data.op(subop).input(1).unwrap()).constant_value();
                (bv, base_const.checked_shl((off * 8) as u32).unwrap_or(0))
            }
            OpCode::IntZext => {
                let bv = data.op(subop).input(0).unwrap();
                (bv, base_const & super::nzmask::calc_mask(data.vn(bv).size))
            }
            _ => return 0,
        };
        if base_const == super::nzmask::calc_mask(data.vn(andvn).size) {
            return 0; // degenerate AND
        }
        if data.vn(basevn).is_free() {
            return 0;
        }
        let bsize = data.vn(basevn).size;
        let constvn = data.new_const(bsize, andconst);
        // New wider AND(basevn, constvn), then compare it against 0.
        let newop = data.new_op_before(andop, OpCode::IntAnd, vec![basevn, constvn]);
        let newout = data.op(newop).output.unwrap();
        let zero = data.new_const(bsize, 0);
        data.op_set_input(op, 0, newout);
        data.op_set_input(op, 1, zero);
        1
    }
}

/// Ghidra `RuleZextShiftZext` (ruleaction.cc:4865): fold redundant INT_ZEXT —
///   - `zext(zext(V))       =>  zext(V)`
///   - `zext(zext(V) << c)  =>  zext(V) << c`   (widen once, at the outer width, when `c` keeps all bits)
pub struct RuleZextShiftZext;

impl Rule for RuleZextShiftZext {
    fn name(&self) -> &str {
        "zextshiftzext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntZext]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntZext {
            return 0;
        }
        let invn = data.op(op).input(0).unwrap();
        if !data.vn(invn).is_written() {
            return 0;
        }
        let shiftop = data.vn(invn).def.unwrap();
        if data.op(shiftop).code() == OpCode::IntZext {
            // ZEXT(ZEXT(a))  =>  ZEXT(a)  — only when the inner zext is used solely here.
            let vn = data.op(shiftop).input(0).unwrap();
            if data.vn(vn).is_free() || lone_descend(data, invn) != Some(op) {
                return 0;
            }
            data.op_set_input(op, 0, vn);
            return 1;
        }
        if data.op(shiftop).code() != OpCode::IntLeft {
            return 0;
        }
        let shsa = data.op(shiftop).input(1).unwrap();
        if !data.vn(shsa).is_constant() {
            return 0;
        }
        let shin0 = data.op(shiftop).input(0).unwrap();
        if !data.vn(shin0).is_written() {
            return 0;
        }
        let zext2op = data.vn(shin0).def.unwrap();
        if data.op(zext2op).code() != OpCode::IntZext {
            return 0;
        }
        let rootvn = data.op(zext2op).input(0).unwrap();
        if data.vn(rootvn).is_free() {
            return 0;
        }
        let sa = data.vn(shsa).constant_value();
        let z2out = data.op(zext2op).output.unwrap();
        if sa > 8 * (data.vn(z2out).size as u64 - data.vn(rootvn).size as u64) {
            return 0; // shift might lose bits off the top
        }
        let outsize = data.vn(data.op(op).output.unwrap()).size;
        // newzext = ZEXT(rootvn) at the outer width; op becomes  newzext << sa.
        let newop = data.new_op_before_sized(op, OpCode::IntZext, vec![rootvn], outsize);
        let newout = data.op(newop).output.unwrap();
        data.op_set_opcode(op, OpCode::IntLeft);
        data.op_set_input(op, 0, newout);
        let sac = data.new_const(4, sa);
        data.op_append_input(op, sac);
        1
    }
}

/// Ghidra `RuleSubZext` (ruleaction.cc:5039): simplify INT_ZEXT of a truncation —
///   - `zext( sub(V, 0) )      =>  V & mask`
///   - `zext( sub(V, k) )      =>  (V >> k*8) & mask`
///   - `zext( sub(V, k) >> d )  =>  (V >> (k*8+d)) & mask`
/// where the truncate-then-extend returns to `V`'s original width (`|sub base| == |zext out|`).
///
/// Faithful port, **WIRED** into [`default_rule_pool`] at slot 74 (Ghidra `coreaction.cc:5585`,
/// between RuleConcatLeftShift and RuleSubCancel). It was held for 16 sessions because it over-fired
/// where mosura's own rules already matched Ghidra; those regressors were all wide-return divergences
/// that the iterating mainloop + const-0 fold + `RuleSubvarZext` return-narrowing + `RulePiece2Zext`
/// have since cleared (the piecestruct/namespace/orcompare/floatconv family is byte-identical with
/// this on). Its SubVariableFlow siblings (slots 110-116) now consume the extra IntZext forms as
/// Ghidra intends. The remaining forloop_varused/noforloop_iterused dip is the missing
/// induction-phi narrowing (**Task #24**) — the faithful-exposes-gap diagnostic, not a mis-port.
pub struct RuleSubZext;

impl Rule for RuleSubZext {
    fn name(&self) -> &str {
        "subzext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntZext]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntZext {
            return 0;
        }
        let subvn = data.op(op).input(0).unwrap();
        if !data.vn(subvn).is_written() {
            return 0;
        }
        let subop = data.vn(subvn).def.unwrap();
        let outsize = data.vn(data.op(op).output.unwrap()).size;
        match data.op(subop).code() {
            OpCode::Subpiece => {
                let basevn = data.op(subop).input(0).unwrap();
                if data.vn(basevn).is_free() {
                    return 0;
                }
                if data.vn(basevn).size != outsize || data.vn(basevn).size > 8 {
                    return 0; // truncating then extending to a different width
                }
                let basesize = data.vn(basevn).size;
                let subc = data.op(subop).input(1).unwrap();
                if data.vn(subc).constant_value() != 0 {
                    // Truncating from the middle: turn the SUBPIECE into a shift of the full value.
                    if lone_descend(data, subvn) != Some(op) {
                        return 0;
                    }
                    let newvn = data.new_unique(basesize);
                    let right_val = data.vn(subc).constant_value() * 8;
                    let rc = data.new_const(data.vn(subc).size, right_val);
                    data.op_set_input(op, 0, newvn);
                    data.op_set_opcode(subop, OpCode::IntRight);
                    data.op_set_input(subop, 1, rc);
                    data.op_set_output(subop, newvn);
                } else {
                    data.op_set_input(op, 0, basevn); // bypass the truncation entirely
                }
                let mask = super::nzmask::calc_mask(data.vn(subvn).size);
                let constvn = data.new_const(basesize, mask);
                data.op_set_opcode(op, OpCode::IntAnd);
                data.op_append_input(op, constvn);
                1
            }
            OpCode::IntRight => {
                let shiftop = subop;
                let shc = data.op(shiftop).input(1).unwrap();
                if !data.vn(shc).is_constant() {
                    return 0;
                }
                let midvn = data.op(shiftop).input(0).unwrap();
                if !data.vn(midvn).is_written() {
                    return 0;
                }
                let subop2 = data.vn(midvn).def.unwrap();
                if data.op(subop2).code() != OpCode::Subpiece {
                    return 0;
                }
                let basevn = data.op(subop2).input(0).unwrap();
                if data.vn(basevn).is_free() {
                    return 0;
                }
                if data.vn(basevn).size != outsize || data.vn(basevn).size > 8 {
                    return 0;
                }
                if lone_descend(data, midvn) != Some(shiftop) || lone_descend(data, subvn) != Some(op)
                {
                    return 0;
                }
                let basesize = data.vn(basevn).size;
                let mut val = super::nzmask::calc_mask(data.vn(midvn).size);
                let sa = data.vn(shc).constant_value();
                val = val.checked_shr(sa as u32).unwrap_or(0);
                let total = sa + data.vn(data.op(subop2).input(1).unwrap()).constant_value() * 8;
                let newvn = data.new_unique(basesize);
                let tc = data.new_const(data.vn(shc).size, total);
                data.op_set_input(op, 0, newvn);
                data.op_set_input(shiftop, 0, basevn); // shift the full value
                data.op_set_input(shiftop, 1, tc); // by the combined amount
                data.op_set_output(shiftop, newvn);
                let constvn = data.new_const(basesize, val);
                data.op_set_opcode(op, OpCode::IntAnd);
                data.op_append_input(op, constvn);
                1
            }
            _ => 0,
        }
    }
}

/// Ghidra `RulePiece2Zext` (ruleaction.cc:219): concatenation with a zero high part is a zero
/// extension — `concat(#0, W)  =>  zext(W)`.
///
/// Faithful port (unit-tested), **not wired into [`default_rule_pool`]** (lead ruled it stays held):
/// the trace diff shows it CONVERGES on floatcast (mosura 4× = Ghidra 4×, floatcast 0.796→0.840) and
/// helps nan/varcross, but OVER-fires by one on floatconv (mosura 2× vs Ghidra 1×, floatconv
/// 0.578→0.512) for a net corpus of only ≈+0.0001. Ghidra's per-op rule priority landed (**Task #7**,
/// `c88ff35`) and the floatconv over-fire is UNCHANGED — so priority was not the blocker; it is the
/// same SubVariableFlow gap as [`RuleSubZext`]. Wire it once that lands (**Task #9**). Not wired for
/// the marginal net gain — that would be gauge-chasing with a real floatconv regression.
pub struct RulePiece2Zext;

impl Rule for RulePiece2Zext {
    fn name(&self) -> &str {
        "piece2zext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::Piece {
            return 0;
        }
        let cvn = data.op(op).input(0).unwrap(); // most-significant half
        if !data.vn(cvn).is_constant() || data.vn(cvn).constant_value() != 0 {
            return 0;
        }
        data.op_remove_input(op, 0);
        data.op_set_opcode(op, OpCode::IntZext);
        1
    }
}

/// Ghidra `RulePiece2Sext` (ruleaction.cc:232): concatenation with sign bits is a sign extension —
/// `concat(V s>> #0x1f, V)  =>  sext(V)` (the shift amount must smear the sign across the whole
/// high part, `8*|V| - 1`). This is the x86 `cdq; idiv` dividend form once RuleSubExtComm has
/// rewritten the SUB84-of-SEXT high half into `V s>> 0x1f`: the PIECE becomes `SEXT(V)`, which
/// RuleSubCommute's INT_SDIV/SREM arm + RuleSubExtComm then narrow to the 4-byte division
/// (`(int4)x / 10`), matching Ghidra's chain on switchloop case 4.
pub struct RulePiece2Sext;

impl Rule for RulePiece2Sext {
    fn name(&self) -> &str {
        "piece2sext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let shiftout = data.op(op).input(0).unwrap(); // most-significant half
        if !data.vn(shiftout).is_written() {
            return 0;
        }
        let shiftop = data.vn(shiftout).def.unwrap();
        if data.op(shiftop).code() != OpCode::IntSright {
            return 0;
        }
        let sa = data.op(shiftop).input(1).unwrap();
        if !data.vn(sa).is_constant() {
            return 0;
        }
        let n = data.vn(sa).constant_value();
        let x = data.op(shiftop).input(0).unwrap();
        if Some(x) != data.op(op).input(1) {
            return 0;
        }
        if n != (8 * data.vn(x).size - 1) as u64 {
            return 0; // the arithmetic shift must copy the sign bit through the whole high part
        }
        data.op_remove_input(op, 0);
        data.op_set_opcode(op, OpCode::IntSext);
        1
    }
}

// ---------------------------------------------------------------------------
// SubVariableFlow driving rules — Ghidra `subflow.cc:1547-1721`. Each spots a
// seed (a wide Varnode from which only a narrow logical sub-value is used),
// builds a `SubvariableFlow`, then `do_trace()` + `do_replacement()` to shrink
// the flow.
//
// ⭐ `aggressive` IS FALSE FOR THE ZEXT-SIDE RULES ON EVERY TARGET GHIDRA WOULD RUN THEM ON, and
// that is a verified equivalence rather than a gap. Ghidra passes `Varnode::isPtrFlow()`, a flag
// set ONLY by `RulePtrFlow` (ruleaction.cc:9038) — whose `getOpList` returns EMPTY unless
// `glb->getDefaultDataSpace()->isTruncated()` (:9047, "Only stick ourselves into pool if
// aggresiveness is turned on"). A space is truncated only via `<truncate_space>` in a processor's
// `.ldefs`, which in the pinned tree appears for exactly three families — AARCH64, PowerPC and
// MIPS, the same three that carry `<aggressivetrim>`, because both exist for 32-bit ABIs on 64-bit
// registers. NO x86 `.ldefs` truncates a space, so on `x86:LE:64` and `x86:LE:32` RulePtrFlow never
// enters a pool, `isPtrFlow` is never set, and Ghidra's own argument is `false`.
// ⇒ Porting RulePtrFlow today would add a rule with an empty oplist plus a Varnode flag nothing
//   sets. DEATH CERTIFICATE, and here is what revives it: the first target mosura builds whose
//   `.ldefs` carries `<truncate_space>`. At that point this constant becomes WRONG and RulePtrFlow
//   must land with it. `RuleSubvarSext` is the opposite case and shows the contrast — its
//   `aggressive` comes from a spec attribute that exists today, so it reads it.
// ---------------------------------------------------------------------------

/// Ghidra `RuleSubvarAnd` (subflow.cc:1553): `V & c` where the AND output is consumed exactly by the
/// constant mask `c` and the low bit is live — the AND is pulling a narrow field out of `V`.
pub struct RuleSubvarAnd;

impl Rule for RuleSubvarAnd {
    fn name(&self) -> &str {
        "subvar_and"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let vn = data.op(op).input(0).unwrap();
        let outvn = data.op(op).output.unwrap();
        let consume = data.vn(outvn).get_consume();
        if consume != data.vn(in1).constant_value() {
            return 0;
        }
        if (consume & 1) == 0 {
            return 0;
        }
        let cmask: u64 = if consume == 1 {
            1
        } else {
            let mut cm = super::nzmask::calc_mask(data.vn(vn).size) >> 8;
            while cm != 0 {
                if cm == consume {
                    break;
                }
                cm >>= 8;
            }
            cm
        };
        if cmask == 0 {
            return 0;
        }
        if data.vn(outvn).descend.is_empty() {
            return 0;
        }
        let mut subflow = super::subvarflow::SubvariableFlow::new(data, vn, cmask, false, false, false);
        if !subflow.do_trace() {
            return 0;
        }
        subflow.do_replacement();
        1
    }
}

/// Ghidra `RuleSubvarSubpiece` (subflow.cc:1590): a SUBPIECE truncation whose full input is only ever
/// consumed within the truncated field — seed the flow with `mask = calc_mask(outsize) << 8*sa`.
pub struct RuleSubvarSubpiece;

impl Rule for RuleSubvarSubpiece {
    fn name(&self) -> &str {
        "subvar_subpiece"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn = data.op(op).input(0).unwrap();
        let outvn = data.op(op).output.unwrap();
        let flowsize = data.vn(outvn).size;
        let sa_c = data.vn(data.op(op).input(1).unwrap()).constant_value();
        if flowsize as u64 + sa_c > 8 {
            return 0; // mask must fit in u64 precision (Ghidra: > sizeof(uintb))
        }
        let sa = sa_c as u32;
        let mask = super::nzmask::calc_mask(flowsize) << (8 * sa);
        // Ghidra: `outvn->isPtrFlow()`. False on every x86 target — see the certificate on the
        // SubVariableFlow rule block above; it names the condition that would make it wrong.
        let aggressive = false;
        if !aggressive {
            if (data.vn(vn).get_consume() & mask) != data.vn(vn).get_consume() {
                return 0;
            }
            if data.vn(outvn).descend.is_empty() {
                return 0;
            }
        }
        // Vector-register inputs truncated to the used lanes — let the flow handle the 8-byte case.
        let big = flowsize >= 8 && data.vn(vn).is_input() && lone_descend(data, vn) == Some(op);
        let mut subflow = super::subvarflow::SubvariableFlow::new(data, vn, mask, aggressive, false, big);
        if !subflow.do_trace() {
            return 0;
        }
        subflow.do_replacement();
        1
    }
}

/// Ghidra `RuleSubvarCompZero` (subflow.cc:1628): a single-bit equality test `(V & bit) == 0` — trace
/// the one live bit out of `V` (guarded so it looks like a status-flag bit, not a wide field).
pub struct RuleSubvarCompZero;

impl Rule for RuleSubvarCompZero {
    fn name(&self) -> &str {
        "subvar_compzero"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntNotequal, OpCode::IntEqual]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let vn = data.op(op).input(0).unwrap();
        let mask = data.vn(vn).get_nzmask();
        let bitnum = super::nzmask::leastsigbit_set(mask);
        if bitnum == -1 {
            return 0;
        }
        if (mask >> (bitnum as u32)) != 1 {
            return 0; // only one bit active
        }
        let off = data.vn(in1).constant_value();
        if off != mask && off != 0 {
            return 0; // the active bit must be the one being tested
        }
        let outvn = data.op(op).output.unwrap();
        if data.vn(outvn).descend.is_empty() {
            return 0;
        }
        // Basic check that the stream the bit is pulled from is not fully consumed (status-reg heuristic).
        if data.vn(vn).is_written() {
            let andop = data.vn(vn).def.unwrap();
            let Some(vn0) = data.op(andop).input(0) else {
                return 0;
            };
            match data.op(andop).code() {
                OpCode::IntAnd | OpCode::IntOr | OpCode::IntRight => {
                    if data.vn(vn0).is_constant() {
                        return 0;
                    }
                    let mask0 = data.vn(vn0).get_consume() & data.vn(vn0).get_nzmask();
                    let wholemask = super::nzmask::calc_mask(data.vn(vn0).size) & mask0;
                    if (wholemask & 0xff) == 0xff {
                        return 0;
                    }
                    if (wholemask & 0xff00) == 0xff00 {
                        return 0;
                    }
                }
                _ => {}
            }
        }
        let mut subflow = super::subvarflow::SubvariableFlow::new(data, vn, mask, false, false, false);
        if !subflow.do_trace() {
            return 0;
        }
        subflow.do_replacement();
        1
    }
}

/// Ghidra `RuleSubvarShift` (subflow.cc:1686): a single bit pulled from a 1-byte value by `V >> sa` —
/// trace that bit out of `V`.
pub struct RuleSubvarShift;

impl Rule for RuleSubvarShift {
    fn name(&self) -> &str {
        "subvar_shift"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntRight]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn = data.op(op).input(0).unwrap();
        if data.vn(vn).size != 1 {
            return 0;
        }
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let sa = data.vn(in1).constant_value() as u32;
        let mask = data.vn(vn).get_nzmask();
        let shifted = mask.checked_shr(sa).unwrap_or(0);
        if shifted != 1 {
            return 0; // pulling out a single bit
        }
        let mask = shifted.checked_shl(sa).unwrap_or(0);
        let outvn = data.op(op).output.unwrap();
        if data.vn(outvn).descend.is_empty() {
            return 0;
        }
        let mut subflow = super::subvarflow::SubvariableFlow::new(data, vn, mask, false, false, false);
        if !subflow.do_trace() {
            return 0;
        }
        subflow.do_replacement();
        1
    }
}

/// Ghidra `RuleSubvarZext` (subflow.cc:1710): the output of `INT_ZEXT(v)` is a narrow value padded to
/// a wide register — trace the logical `v`-width value forward. This is the rule that narrows a
/// zero-extension-padded return (`RAX:8 = ZEXT(v:4)` → `return v:4`, via `try_return_pull`).
pub struct RuleSubvarZext;

impl Rule for RuleSubvarZext {
    fn name(&self) -> &str {
        "subvar_zext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntZext]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn = data.op(op).output.unwrap();
        let invn = data.op(op).input(0).unwrap();
        let mask = super::nzmask::calc_mask(data.vn(invn).size);
        let mut subflow = super::subvarflow::SubvariableFlow::new(data, vn, mask, false, false, false);
        if !subflow.do_trace() {
            return 0;
        }
        subflow.do_replacement();
        1
    }
}

/// Ghidra `RuleSubvarSext` (subflow.cc:1723): the twin of [`RuleSubvarZext`] for SIGN extension —
/// the output of `INT_SEXT(v)` is a narrow value sign-padded into a wide register, so trace the
/// logical `v`-width value with `sextrestrictions` set. That mode is what makes INT_SRIGHT and the
/// signed comparisons preserve the logical value, which the zero-extension mode cannot assume.
///
/// `aggressive` comes from the compiler spec's `<aggressivetrim signext=>` via
/// `RuleSubvarSext::reset` (subflow.cc:1742) — `false` on every x86 target, but read rather than
/// assumed (see [`crate::analysis::cspec::aggressive_ext_trim`]). Unlike `RuleSubvarZext`, whose
/// `aggressive` argument is `Varnode::isPtrFlow` and therefore still blocked on `RulePtrFlow`, this
/// one's source is available, so the rule lands with Ghidra's real argument rather than a constant.
pub struct RuleSubvarSext;

impl Rule for RuleSubvarSext {
    fn name(&self) -> &str {
        "subvar_sext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSext]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn = data.op(op).output.unwrap();
        let invn = data.op(op).input(0).unwrap();
        let mask = super::nzmask::calc_mask(data.vn(invn).size);
        let aggressive = data.aggressive_ext_trim;
        let mut subflow = super::subvarflow::SubvariableFlow::new(data, vn, mask, aggressive, true, false);
        if !subflow.do_trace() {
            return 0;
        }
        subflow.do_replacement();
        1
    }
}

/// Ghidra `RuleLessEqual2Zero` (ruleaction.cc:5601): simplify INT_LESSEQUAL against an extremal
/// constant (0 or all-ones), which an unsigned `<=` makes trivially true or an equality:
///   - `0 <= V     =>  true`      - `V <= 0     =>  V == 0`
///   - `mask <= V  =>  mask == V`  - `V <= mask  =>  true`
pub struct RuleLessEqual2Zero;

impl Rule for RuleLessEqual2Zero {
    fn name(&self) -> &str {
        "lessequal2zero"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntLessequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntLessequal {
            return 0;
        }
        let lvn = data.op(op).input(0).unwrap();
        let rvn = data.op(op).input(1).unwrap();
        if data.vn(lvn).is_constant() {
            let lv = data.vn(lvn).constant_value();
            if lv == 0 {
                data.op_set_opcode(op, OpCode::Copy); // 0 <= V is always true
                data.op_remove_input(op, 1);
                let one = data.new_const(1, 1);
                data.op_set_input(op, 0, one);
                return 1;
            } else if lv == super::nzmask::calc_mask(data.vn(lvn).size) {
                data.op_set_opcode(op, OpCode::IntEqual); // only -1 satisfies mask <= V
                return 1;
            }
        } else if data.vn(rvn).is_constant() {
            let rv = data.vn(rvn).constant_value();
            if rv == 0 {
                data.op_set_opcode(op, OpCode::IntEqual); // only 0 satisfies V <= 0
                return 1;
            } else if rv == super::nzmask::calc_mask(data.vn(rvn).size) {
                data.op_set_opcode(op, OpCode::Copy); // V <= mask is always true
                data.op_remove_input(op, 1);
                let one = data.new_const(1, 1);
                data.op_set_input(op, 0, one);
                return 1;
            }
        }
        0
    }
}

/// Ghidra `RuleShiftBitops` (ruleaction.cc:490): when a shift/truncate/multiply discards all the
/// non-zero bits of one side of an inner logical/arithmetic op, drop that side:
///   - `(V & 0xf000) << 4  =>  #0 << 4`    (AND/MULT: the surviving side is 0 → whole thing 0)
///   - `(V + 0xf000) << 4  =>  V << 4`     (ADD/XOR/OR: the discarded addend contributes nothing)
/// The outer op is INT_LEFT/INT_RIGHT/SUBPIECE/INT_MULT (by a power of two).
pub struct RuleShiftBitops;

impl Rule for RuleShiftBitops {
    fn name(&self) -> &str {
        "shiftbitops"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntLeft, OpCode::IntRight, OpCode::Subpiece, OpCode::IntMult]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let code = data.op(op).code();
        // The pool dispatches on a cached opcode a prior rule may have rewritten (e.g. INT_MULT→COPY);
        // re-check the live opcode is one of our binary target ops before reading input(1).
        if !matches!(
            code,
            OpCode::IntLeft | OpCode::IntRight | OpCode::Subpiece | OpCode::IntMult
        ) {
            return 0;
        }
        let constvn = data.op(op).input(1).unwrap();
        if !data.vn(constvn).is_constant() {
            return 0;
        }
        let vn = data.op(op).input(0).unwrap();
        if !data.vn(vn).is_written() || data.vn(vn).size > 8 {
            return 0;
        }
        let cval = data.vn(constvn).constant_value();
        let (sa, leftshift) = match code {
            OpCode::IntLeft => (cval as u32, true),
            OpCode::IntRight => (cval as u32, false),
            OpCode::Subpiece => (cval as u32 * 8, false),
            OpCode::IntMult => {
                let s = super::nzmask::leastsigbit_set(cval);
                if s == -1 {
                    return 0;
                }
                (s as u32, true)
            }
            _ => return 0,
        };
        let bitop = data.vn(vn).def.unwrap();
        match data.op(bitop).code() {
            OpCode::IntAnd | OpCode::IntOr | OpCode::IntXor => {}
            OpCode::IntMult | OpCode::IntAdd if leftshift => {}
            _ => return 0,
        }
        let outmask = super::nzmask::calc_mask(data.vn(data.op(op).output.unwrap()).size);
        let ninput = data.op(bitop).num_inputs();
        let mut found = None;
        for i in 0..ninput {
            let nzm0 = data.vn(data.op(bitop).input(i).unwrap()).get_nzmask();
            let nzm = if leftshift {
                nzm0.checked_shl(sa).unwrap_or(0)
            } else {
                nzm0.checked_shr(sa).unwrap_or(0)
            };
            if (nzm & outmask) == 0 {
                found = Some(i);
                break;
            }
        }
        let Some(i) = found else { return 0 };
        match data.op(bitop).code() {
            OpCode::IntMult | OpCode::IntAnd => {
                let zero = data.new_const(data.vn(vn).size, 0); // result is zero
                data.op_set_input(op, 0, zero);
            }
            OpCode::IntAdd | OpCode::IntXor | OpCode::IntOr => {
                let other = data.op(bitop).input(1 - i).unwrap();
                if !data.vn(other).is_heritage_known() {
                    return 0;
                }
                data.op_set_input(op, 0, other);
            }
            _ => return 0,
        }
        1
    }
}

/// Ghidra `RuleHumptyOr` (ruleaction.cc:5332): recombine masked pieces OR'd together —
/// `(V & W) | (V & X)  =>  V & (W|X)`, and when `W|X` covers every bit of `V`, `=> V`.
pub struct RuleHumptyOr;

impl Rule for RuleHumptyOr {
    fn name(&self) -> &str {
        "humptyor"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntOr]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntOr {
            return 0;
        }
        let vn1 = data.op(op).input(0).unwrap();
        let vn2 = data.op(op).input(1).unwrap();
        if !data.vn(vn1).is_written() || !data.vn(vn2).is_written() {
            return 0;
        }
        let and1 = data.vn(vn1).def.unwrap();
        let and2 = data.vn(vn2).def.unwrap();
        if data.op(and1).code() != OpCode::IntAnd || data.op(and2).code() != OpCode::IntAnd {
            return 0;
        }
        // a is the operand common to both ANDs; b, c are the respective other operands.
        let mut a = data.op(and1).input(0).unwrap();
        let mut b = data.op(and1).input(1).unwrap();
        let mut c = data.op(and2).input(0).unwrap();
        let d = data.op(and2).input(1).unwrap();
        if a == c {
            c = d;
        } else if a == d {
            // c already the non-matching operand of and2
        } else if b == c {
            b = a;
            a = c;
            c = d;
        } else if b == d {
            b = a;
            a = d;
        } else {
            return 0;
        }
        if data.vn(b).is_constant() && data.vn(c).is_constant() {
            let totalbits = data.vn(b).constant_value() | data.vn(c).constant_value();
            if totalbits == super::nzmask::calc_mask(data.vn(a).size) {
                data.op_set_opcode(op, OpCode::Copy); // every bit of `a` is covered
                data.op_remove_input(op, 1);
                data.op_set_input(op, 0, a);
            } else {
                data.op_set_opcode(op, OpCode::IntAnd);
                let nc = data.new_const(data.vn(a).size, totalbits);
                data.op_set_input(op, 0, a);
                data.op_set_input(op, 1, nc);
            }
        } else {
            if !data.vn(b).is_heritage_known() || !data.vn(c).is_heritage_known() {
                return 0;
            }
            let amask = data.vn(a).get_nzmask();
            // RuleAndDistribute would reverse us if either side shares no bits with `a`.
            if (data.vn(b).get_nzmask() & amask) == 0 || (data.vn(c).get_nzmask() & amask) == 0 {
                return 0;
            }
            let new_or = data.new_op_before(op, OpCode::IntOr, vec![b, c]);
            let or_vn = data.op(new_or).output.unwrap();
            data.op_set_input(op, 0, a);
            data.op_set_input(op, 1, or_vn);
            data.op_set_opcode(op, OpCode::IntAnd);
        }
        1
    }
}

/// Ghidra `RuleAndPiece` (ruleaction.cc:1640): when an INT_AND masks a PIECE and one half of the
/// PIECE is entirely masked off, collapse it — `V & concat(W,X)  =>  zext(X)` (high part masked off)
/// or `V & concat(W,X)  =>  V & concat(#0,X)` (low part masked off), by the non-zero masks.
pub struct RuleAndPiece;

impl Rule for RuleAndPiece {
    fn name(&self) -> &str {
        "andpiece"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntAnd {
            return 0;
        }
        let size = data.vn(data.op(op).output.unwrap()).size;
        let full = super::nzmask::calc_mask(size);
        let mut chosen: Option<(usize, OpCode, VarnodeId, VarnodeId)> = None; // (i, opc, high, low)
        for i in 0..2 {
            let piecevn = data.op(op).input(i).unwrap();
            if !data.vn(piecevn).is_written() {
                continue;
            }
            let pieceop = data.vn(piecevn).def.unwrap();
            if data.op(pieceop).code() != OpCode::Piece {
                continue;
            }
            let othervn = data.op(op).input(1 - i).unwrap();
            let othermask = data.vn(othervn).get_nzmask();
            if othermask == full || othermask == 0 {
                continue; // full: no-op; zero: RuleAndMask handles it
            }
            let highvn = data.op(pieceop).input(0).unwrap();
            let lowvn = data.op(pieceop).input(1).unwrap();
            if !data.vn(highvn).is_heritage_known() || !data.vn(lowvn).is_heritage_known() {
                continue;
            }
            let maskhigh = data.vn(highvn).get_nzmask();
            let masklow = data.vn(lowvn).get_nzmask();
            let lowbits = data.vn(lowvn).size * 8;
            if (maskhigh & othermask.checked_shr(lowbits).unwrap_or(0)) == 0 {
                if maskhigh == 0 && data.vn(highvn).is_constant() {
                    continue; // RulePiece2Zext handles this
                }
                chosen = Some((i, OpCode::IntZext, highvn, lowvn));
                break;
            } else if (masklow & othermask) == 0 {
                if data.vn(lowvn).is_constant() {
                    continue; // nothing to do
                }
                chosen = Some((i, OpCode::Piece, highvn, lowvn));
                break;
            }
        }
        let Some((i, opc, highvn, lowvn)) = chosen else { return 0 };
        let newvn = if opc == OpCode::IntZext {
            // PIECE(high, low) & mask  =>  ZEXT(low)  (high part is masked off)
            let newop = data.new_op_before_sized(op, OpCode::IntZext, vec![lowvn], size);
            data.op(newop).output.unwrap()
        } else {
            // low part masked off: PIECE(high, low)  =>  PIECE(high, #0)
            let zero = data.new_const(data.vn(lowvn).size, 0);
            let newop = data.new_op_before_sized(op, OpCode::Piece, vec![highvn, zero], size);
            data.op(newop).output.unwrap()
        };
        data.op_set_input(op, i, newvn);
        1
    }
}

/// Ghidra `RuleAndDistribute` (ruleaction.cc:1254): distribute an INT_AND through an INT_OR when it
/// simplifies — `(A|B) & C  =>  (A&C) | (B&C)`, gated on the non-zero masks so a term cancels or
/// becomes trivial.
///
/// Faithful port (unit-tested; guards verified byte-for-byte against ruleaction.cc), but **not wired
/// into [`default_rule_pool`]** — it is the mirror image of [`RuleHumptyOr`] and the pool HANGS: a
/// real inverse cycle `humptyor → termorder → anddistribute → humptyor` on the byte-mask form
/// `(X&k1)|(X&k2)`. Ghidra's per-op rule priority landed (**Task #7**, `c88ff35`) and it STILL hangs,
/// so priority is not the fix (the two rules are on different opcodes — INT_OR vs INT_AND — so
/// priority never orders them against each other). Root cause (verified via Ghidra's own trace, which
/// fires anddistribute/humptyor 0× on piecestruct): Ghidra never reaches this form because its
/// SubVariableFlow dissolves the byte-packing first; and even if it arose, Ghidra's fresh nzmasks let
/// the higher-priority [`RuleAndMask`] collapse the intermediate `X & 0xff` identity. mosura's
/// freshly-created OR varnode carries a stale full nzmask, so AndMask can't break the cycle. PRIMARY
/// blocker = **Task #9** (SubVariableFlow — makes the cycle form never arise, the same fix as SubZext /
/// Piece2Zext); **Task #10** (nzmask refreshed mid-pool) is a secondary safety-net that would let
/// AndMask break the cycle if the form ever did arise. Do NOT wire it alongside RuleHumptyOr before then.
pub struct RuleAndDistribute;

impl Rule for RuleAndDistribute {
    fn name(&self) -> &str {
        "anddistribute"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntAnd {
            return 0;
        }
        let size = data.vn(data.op(op).output.unwrap()).size;
        if size > 8 {
            return 0;
        }
        let fullmask = super::nzmask::calc_mask(size);
        let mut chosen: Option<(usize, VarnodeId, VarnodeId, VarnodeId)> = None; // (i, o0, o1, other)
        for i in 0..2 {
            let othervn = data.op(op).input(1 - i).unwrap();
            if !data.vn(othervn).is_heritage_known() {
                continue;
            }
            let orvn = data.op(op).input(i).unwrap();
            let Some(orop) = data.vn(orvn).def else { continue };
            if data.op(orop).code() != OpCode::IntOr {
                continue;
            }
            let o0 = data.op(orop).input(0).unwrap();
            let o1 = data.op(orop).input(1).unwrap();
            if !data.vn(o0).is_heritage_known() || !data.vn(o1).is_heritage_known() {
                continue;
            }
            let othermask = data.vn(othervn).get_nzmask();
            if othermask == 0 || othermask == fullmask {
                continue;
            }
            let ormask1 = data.vn(o0).get_nzmask();
            let ormask2 = data.vn(o1).get_nzmask();
            // Distribute only when it makes a term cancel (mask disjoint) or, for a constant mask,
            // become trivial (mask covers the term). Otherwise distributing gains nothing.
            let beneficial = (ormask1 & othermask) == 0
                || (ormask2 & othermask) == 0
                || (data.vn(othervn).is_constant()
                    && ((ormask1 & othermask) == ormask1 || (ormask2 & othermask) == ormask2));
            if beneficial {
                chosen = Some((i, o0, o1, othervn));
                break;
            }
        }
        let Some((_i, o0, o1, othervn)) = chosen else { return 0 };
        let and1 = data.new_op_before(op, OpCode::IntAnd, vec![o0, othervn]);
        let v1 = data.op(and1).output.unwrap();
        let and2 = data.new_op_before(op, OpCode::IntAnd, vec![o1, othervn]);
        let v2 = data.op(and2).output.unwrap();
        // Ghidra replaces both inputs (slots 0 and 1) regardless of which held the OR.
        data.op_set_input(op, 0, v1);
        data.op_set_input(op, 1, v2);
        data.op_set_opcode(op, OpCode::IntOr);
        1
    }
}

/// Ghidra `RuleOrMask` (ruleaction.cc:284): `V | mask  =>  mask` when the constant operand has every
/// bit of the output set. An OR can only set bits, so an all-ones constant determines the result
/// regardless of `V`; the op collapses to a COPY of the constant. (switchmulti's `extraout_R8 | -1`
/// → `-1`, which also drops the dead `extraout_R8`.)
pub struct RuleOrMask;

impl Rule for RuleOrMask {
    fn name(&self) -> &str {
        "ormask"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntOr]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(out) = data.op(op).output else { return 0 };
        let size = data.vn(out).size;
        if size as usize > 8 {
            return 0; // matches Ghidra's `size > sizeof(uintb)` guard
        }
        let Some(c) = data.op(op).input(1) else { return 0 };
        if !data.vn(c).is_constant() {
            return 0;
        }
        let allones = mask(u64::MAX, size);
        if mask(data.vn(c).constant_value(), size) != allones {
            return 0;
        }
        data.op_set_opcode(op, OpCode::Copy);
        data.op_set_all_input(op, &[c]);
        1
    }
}

/// Ghidra `RuleSub2Add` (`ruleaction.cc:4012`, the "analysis" group): eliminate INT_SUB —
/// `V - W  =>  V + W * -1`. `getOpList` is `{INT_SUB}` and it fires *unconditionally* on every
/// subtraction (not scoped to a pointer base). The canonical additive form lets the
/// pointer-arithmetic / division rules reason about a single shape; the cleanup pool
/// (`RuleMultNegOne`/`Rule2Comp2Sub`/`RuleAddUnsigned`) turns the non-pointer results back into
/// `V - W` so the printer renders subtractions. A frame `RSP - c` becomes `INT_ADD(RSP, -c)`, which
/// the printer recognises as a stack-local address (`&Stack_c`).
pub struct RuleSub2Add;

impl Rule for RuleSub2Add {
    fn name(&self) -> &str {
        "sub2add"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSub]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn = data.op(op).input(1).unwrap(); // the value being subtracted (W)
        let size = data.vn(vn).size;
        // newop = INT_MULT(W, calc_mask(size)) — i.e. W * -1 — inserted just before op.
        let negone = data.new_const(size, mask(!0, size));
        let newop = data.new_op_before(op, OpCode::IntMult, vec![vn, negone]);
        let newvn = data.op(newop).output.unwrap();
        data.op_set_input(op, 1, newvn); // replace W's reference with the product
        data.op_set_opcode(op, OpCode::IntAdd);
        1
    }
}

/// Ghidra `RuleAddMultCollapse` (`ruleaction.cc`, the "analysis" group): collapse constants in an
/// additive or multiplicative expression. Forms:
///  - `((V + c) + d)  =>  V + (c+d)`
///  - `((V * c) * d)  =>  V * (c*d)`
///  - `((stackbase + c1) + othervn) + c0  =>  (stackbase + (c0+c1)) + othervn`
///
/// The simple form flattens a chained stack-frame base — `(RSP + -8) + -0x70 => RSP + -0x78` — so a
/// multi-level frame escape resolves to a single offset. (The equate/symbol bookkeeping in Ghidra
/// does not apply: mosura models no equate symbols. The spacebase form needs an `isSpacebase()`
/// input, which mosura does not yet flag, so it is dormant — ported for faithfulness.)
pub struct RuleAddMultCollapse;

impl Rule for RuleAddMultCollapse {
    fn name(&self) -> &str {
        "addmultcollapse"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAdd, OpCode::IntMult]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let opc = data.op(op).code();
        // The pool dispatches on a snapshot opcode; an earlier rule may have already rewritten this
        // op (e.g. RuleConstFold → COPY). Re-check the live shape before touching inputs.
        if !matches!(opc, OpCode::IntAdd | OpCode::IntMult) || data.op(op).num_inputs() != 2 {
            return 0;
        }
        // The constant is in c0 (input 1, after RuleTermOrder); the other input is `sub`.
        let c0 = data.op(op).input(1).unwrap();
        if !data.vn(c0).is_constant() {
            return 0;
        }
        let sub = data.op(op).input(0).unwrap();
        if !data.vn(sub).is_written() {
            return 0;
        }
        let subop = data.vn(sub).def.unwrap();
        if data.op(subop).code() != opc {
            return 0; // must be the exact same operation one level down
        }
        let c1 = data.op(subop).input(1).unwrap();
        if !data.vn(c1).is_constant() {
            // ((stackbase + c1) + othervn) + c0  =>  (stackbase + (c0+c1)) + othervn — collapse two
            // constant offsets even with an extra term AND a multiply-used intermediate sum.
            if opc != OpCode::IntAdd {
                return 0;
            }
            for i in 0..2 {
                let othervn = data.op(subop).input(i).unwrap();
                if data.vn(othervn).is_constant() || data.vn(othervn).is_free() {
                    continue;
                }
                let sub2 = data.op(subop).input(1 - i).unwrap();
                if !data.vn(sub2).is_written() {
                    continue;
                }
                let baseop = data.vn(sub2).def.unwrap();
                if data.op(baseop).code() != OpCode::IntAdd {
                    continue;
                }
                let c1b = data.op(baseop).input(1).unwrap();
                if !data.vn(c1b).is_constant() {
                    continue;
                }
                let basevn = data.op(baseop).input(0).unwrap();
                // only for a base pointer (this adds a new add op, so guard it tightly)
                if !data.vn(basevn).is_spacebase() || !data.vn(basevn).is_input() {
                    continue;
                }
                let size = data.vn(c0).size;
                let val = mask(
                    data.vn(c0).constant_value().wrapping_add(data.vn(c1b).constant_value()),
                    size,
                );
                let newvn = data.new_const(size, val);
                let newop = data.new_op_before(op, OpCode::IntAdd, vec![basevn, newvn]);
                let newout = data.op(newop).output.unwrap();
                data.op_set_input(op, 0, newout);
                data.op_set_input(op, 1, othervn);
                return 1;
            }
            return 0;
        }
        let sub2 = data.op(subop).input(0).unwrap();
        if data.vn(sub2).is_free() {
            return 0;
        }
        let size = data.vn(c0).size;
        let (v0, v1) = (data.vn(c0).constant_value(), data.vn(c1).constant_value());
        let val = match opc {
            OpCode::IntAdd => v0.wrapping_add(v1),
            OpCode::IntMult => v0.wrapping_mul(v1),
            _ => return 0,
        };
        let newvn = data.new_const(size, mask(val, size));
        data.op_set_input(op, 1, newvn); // c0 => c0+c1 (or c0*c1)
        data.op_set_input(op, 0, sub2); // sub => sub2
        1
    }
}

/// Ghidra `RuleMultNegOne` (`ruleaction.cc`): `a * -1  =>  -a` (an `INT_2COMP`). The cleanup
/// counterpart of `RuleSub2Add` for the non-constant case: a subtraction `V - W` canonicalised to
/// `V + W*-1` has its `W*-1` reduced to `INT_2COMP(W)` here, which `Rule2Comp2Sub` then folds into
/// `V - W`.
pub struct RuleMultNegOne;

impl Rule for RuleMultNegOne {
    fn name(&self) -> &str {
        "multnegone"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntMult]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(constvn) = data.op(op).input(1) else { return 0 };
        let cvn = data.vn(constvn);
        if !cvn.is_constant() || cvn.constant_value() != mask(!0, cvn.size) {
            return 0;
        }
        data.op_set_opcode(op, OpCode::Int2comp);
        data.op_remove_input(op, 1);
        1
    }
}

/// Ghidra `RuleAddUnsigned` (`ruleaction.cc`): a cleanup that converts `V + 0xff...` to
/// `V - 0x00...` when the additive constant reads as an unsigned integer whose top quarter of bits
/// are all ones (i.e. it is "really" a small negative). Now that `ActionInferTypes` commits a type
/// onto constant varnodes, a constant read in unsigned context reads as `TYPE_UINT` and this rule
/// fires as in Ghidra. (The equate-symbol and enum guards in Ghidra do not apply: mosura models
/// neither.)
pub struct RuleAddUnsigned;

impl Rule for RuleAddUnsigned {
    fn name(&self) -> &str {
        "addunsigned"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAdd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(constvn) = data.op(op).input(1) else { return 0 };
        let cvn = data.vn(constvn);
        if !cvn.is_constant() {
            return 0;
        }
        // getTypeReadFacing(op): the committed type of the constant. Only a plain unsigned integer
        // qualifies (Ghidra also excludes char-printing types, which mosura never assigns here).
        if !matches!(cvn.get_type(), super::types::Datatype::Uint(_)) {
            return 0;
        }
        let size = cvn.size;
        let val = cvn.constant_value();
        let m = mask(!0, size);
        let sa = size * 6; // 1/4 less than the full bit-size
        let quarter = (m >> sa) << sa;
        if (val & quarter) != quarter {
            return 0; // the first quarter of bits must all be 1's
        }
        let negated = val.wrapping_neg() & m;
        data.op_set_opcode(op, OpCode::IntSub);
        let cnew = data.new_const(size, negated);
        data.op_set_input(op, 1, cnew);
        1
    }
}

/// Ghidra `Rule2Comp2Sub` (`ruleaction.cc`): `V + -W  =>  V - W`. Folds an `INT_2COMP` feeding an
/// `INT_ADD` into a single `INT_SUB`, completing the round-trip of a non-constant subtraction that
/// `RuleSub2Add`/`RuleMultNegOne` canonicalised.
pub struct Rule2Comp2Sub;

impl Rule for Rule2Comp2Sub {
    fn name(&self) -> &str {
        "twocomp2sub"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Int2comp]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(out) = data.op(op).output else { return 0 };
        // loneDescend: the single op that reads the 2COMP output (none if 0 or >1 uses).
        let descend = &data.vn(out).descend;
        if descend.len() != 1 {
            return 0;
        }
        let addop = descend[0];
        if data.op(addop).code() != OpCode::IntAdd {
            return 0;
        }
        let w = data.op(op).input(0).unwrap(); // the value being negated
        if data.op(addop).input(0) == Some(out) {
            // the 2COMP result is in slot 0 — move the other addend down to slot 0
            let other = data.op(addop).input(1).unwrap();
            data.op_set_input(addop, 0, other);
        }
        data.op_set_input(addop, 1, w);
        data.op_set_opcode(addop, OpCode::IntSub);
        data.op_destroy(op); // completely remove the 2COMP
        1
    }
}

/// Ghidra's commutative p-code opcodes (`TypeOp` ctors that set `PcodeOp::commutative`). The
/// functional-equality matcher uses this to try the swapped operand ordering.
fn is_commutative(opc: OpCode) -> bool {
    use OpCode::*;
    matches!(
        opc,
        IntEqual | IntNotequal | IntAdd | IntCarry | IntScarry | IntXor | IntAnd | IntOr | IntMult
            | BoolXor | BoolAnd | BoolOr | FloatEqual | FloatNotequal | FloatAdd | FloatMult
    )
}

/// Ghidra `functionalEqualityLevel0` (expression.cc): the one-level comparison.
///   - `0`  ⇒ `vn1` and `vn2` must hold the same value,
///   - `-1` ⇒ they definitely don't, and
///   - `1`  ⇒ same-value-ness depends on the ops writing them.
fn functional_equality_level0(data: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) -> i32 {
    if vn1 == vn2 {
        return 0;
    }
    let a = data.vn(vn1);
    let b = data.vn(vn2);
    if a.size != b.size {
        return -1;
    }
    if a.is_constant() {
        if b.is_constant() {
            return if a.constant_value() == b.constant_value() { 0 } else { -1 };
        }
        return -1;
    }
    if a.is_free() || b.is_free() {
        return -1;
    }
    1
}

/// Ghidra `functionalEqualityLevel` (expression.cc): try to determine whether `vn1` and `vn2`
/// hold the same value. Returns `0` (do), `-1` (don't / can't tell), or `>0` (contingent on
/// further varnode pairs). Both call sites here (and Ghidra's) only test the `== 0` case, so —
/// unlike Ghidra — we don't thread the contingent pairs back out; the recursion structure that
/// decides whether `0` is reachable is reproduced exactly.
pub(super) fn functional_equality_level(data: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) -> i32 {
    let testval = functional_equality_level0(data, vn1, vn2);
    if testval != 1 {
        return testval;
    }
    if !data.vn(vn1).is_written() || !data.vn(vn2).is_written() {
        return -1; // Did not find at least one level of match
    }
    let op1 = data.vn(vn1).def.unwrap();
    let op2 = data.vn(vn2).def.unwrap();
    let opc = data.op(op1).code();
    if opc != data.op(op2).code() {
        return -1;
    }
    let mut num = data.op(op1).num_inputs();
    if num != data.op(op2).num_inputs() {
        return -1;
    }
    if data.op(op1).is_marker() {
        return -1;
    }
    if data.op(op2).is_call() {
        return -1;
    }
    if opc == OpCode::Load {
        // Assume two loads produce the same result only if address + instruction match.
        if data.op(op1).seqnum.pc != data.op(op2).seqnum.pc {
            return -1;
        }
    }
    if num >= 3 {
        if opc != OpCode::Ptradd {
            return -1;
        }
        let e1 = data.op(op1).input(2).unwrap();
        let e2 = data.op(op2).input(2).unwrap();
        if data.vn(e1).constant_value() != data.vn(e2).constant_value() {
            return -1; // elsize constant must be equal
        }
        num = 2; // otherwise treat as having 2 inputs
    }
    let r1: Vec<VarnodeId> = (0..num).map(|i| data.op(op1).input(i).unwrap()).collect();
    let r2: Vec<VarnodeId> = (0..num).map(|i| data.op(op2).input(i).unwrap()).collect();

    let testval = functional_equality_level0(data, r1[0], r2[0]);
    if testval == 0 {
        // A match locks in this comparison ordering.
        if num == 1 {
            return 0;
        }
        let t = functional_equality_level0(data, r1[1], r2[1]);
        if t == 0 {
            return 0;
        }
        if t < 0 {
            return -1;
        }
        return 1; // match contingent on the second pair (res1[0]=res1[1], res2[0]=res2[1])
    }
    if num == 1 {
        return testval;
    }
    let testval2 = functional_equality_level0(data, r1[1], r2[1]);
    if testval2 == 0 {
        return testval; // locks in this ordering
    }
    let unmatchsize = if testval == 1 && testval2 == 1 { 2 } else { -1 };
    if !is_commutative(opc) {
        return unmatchsize;
    }
    // unmatchsize is 2 or -1 here on a commutative operator; try flipping.
    let comm1 = functional_equality_level0(data, r1[0], r2[1]);
    let comm2 = functional_equality_level0(data, r1[1], r2[0]);
    if comm1 == 0 && comm2 == 0 {
        return 0;
    }
    if comm1 < 0 || comm2 < 0 {
        return unmatchsize;
    }
    if comm1 == 0 {
        return 1; // leftover unmatch is res1[1]/res2[0]
    }
    if comm2 == 0 {
        return 1; // leftover unmatch is res1[0]/res2[1]
    }
    2 // both contingent (callers only test == 0, so the preferred ordering is immaterial)
}

/// Ghidra `functionalEquality` (expression.cc): are `vn1` and `vn2` provably the same value?
pub(super) fn functional_equality(data: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) -> bool {
    functional_equality_level(data, vn1, vn2) == 0
}

/// Ghidra `functionalEqualityLevel` (expression.cc) with the leftover-unmatch pair (`res1[0]`,
/// `res2[0]`) exposed — the plain [`functional_equality_level`] discards it. Used by [`RulePushMulti`]:
/// a return of `1` means the two values match contingent on that single differing sub-pair, which the
/// rule merges into one MULTIEQUAL. The pair is meaningful only for a return of `0`/`1` (after descent);
/// callers that only test `== 0` use the plain variant.
fn functional_equality_level_pair(
    data: &Funcdata,
    vn1: VarnodeId,
    vn2: VarnodeId,
) -> (i32, Option<(VarnodeId, VarnodeId)>) {
    let testval = functional_equality_level0(data, vn1, vn2);
    if testval != 1 {
        return (testval, None);
    }
    if !data.vn(vn1).is_written() || !data.vn(vn2).is_written() {
        return (-1, None);
    }
    let op1 = data.vn(vn1).def.unwrap();
    let op2 = data.vn(vn2).def.unwrap();
    let opc = data.op(op1).code();
    if opc != data.op(op2).code() {
        return (-1, None);
    }
    let mut num = data.op(op1).num_inputs();
    if num != data.op(op2).num_inputs() {
        return (-1, None);
    }
    if data.op(op1).is_marker() {
        return (-1, None);
    }
    if data.op(op2).is_call() {
        return (-1, None);
    }
    if opc == OpCode::Load && data.op(op1).seqnum.pc != data.op(op2).seqnum.pc {
        return (-1, None);
    }
    if num >= 3 {
        if opc != OpCode::Ptradd {
            return (-1, None);
        }
        let e1 = data.op(op1).input(2).unwrap();
        let e2 = data.op(op2).input(2).unwrap();
        if data.vn(e1).constant_value() != data.vn(e2).constant_value() {
            return (-1, None);
        }
        num = 2;
    }
    let r1: Vec<VarnodeId> = (0..num).map(|i| data.op(op1).input(i).unwrap()).collect();
    let r2: Vec<VarnodeId> = (0..num).map(|i| data.op(op2).input(i).unwrap()).collect();

    let testval = functional_equality_level0(data, r1[0], r2[0]);
    if testval == 0 {
        if num == 1 {
            return (0, Some((r1[0], r2[0])));
        }
        let t = functional_equality_level0(data, r1[1], r2[1]);
        if t == 0 {
            return (0, Some((r1[0], r2[0])));
        }
        if t < 0 {
            return (-1, None);
        }
        return (1, Some((r1[1], r2[1]))); // contingent on the second pair
    }
    if num == 1 {
        return (testval, Some((r1[0], r2[0])));
    }
    let testval2 = functional_equality_level0(data, r1[1], r2[1]);
    if testval2 == 0 {
        return (testval, Some((r1[0], r2[0])));
    }
    let unmatchsize = if testval == 1 && testval2 == 1 { 2 } else { -1 };
    if !is_commutative(opc) {
        return (unmatchsize, Some((r1[0], r2[0])));
    }
    let comm1 = functional_equality_level0(data, r1[0], r2[1]);
    let comm2 = functional_equality_level0(data, r1[1], r2[0]);
    if comm1 == 0 && comm2 == 0 {
        return (0, Some((r1[0], r2[0])));
    }
    if comm1 < 0 || comm2 < 0 {
        return (unmatchsize, Some((r1[0], r2[0])));
    }
    if comm1 == 0 {
        return (1, Some((r1[1], r2[0]))); // leftover unmatch res1[1]/res2[0]
    }
    if comm2 == 0 {
        return (1, Some((r1[0], r2[1]))); // leftover unmatch res1[0]/res2[1]
    }
    (2, Some((r1[0], r2[0])))
}

/// Ghidra `BlockBasic::earliestUse`: the earliest op in `block` that reads `vid`. We order ops by
/// their position in the block's op list (mosura's faithful analogue of Ghidra's `SeqNum` order).
fn earliest_use(data: &Funcdata, vid: VarnodeId, block: BlockId) -> Option<OpId> {
    let blk_ops = &data.block(block).ops;
    let mut best: Option<(usize, OpId)> = None;
    for &user in &data.vn(vid).descend {
        if data.op(user).parent != Some(block) {
            continue;
        }
        let Some(pos) = blk_ops.iter().position(|&o| o == user) else { continue };
        if best.is_none_or(|(bp, _)| pos < bp) {
            best = Some((pos, user));
        }
    }
    best.map(|(_, o)| o)
}

/// Ghidra `Funcdata::cseFindInBlock`: find an op in `block` (other than `op`, at or before
/// `earliest`) that reads `vid` and whose output is functionally equal to `op`'s output — i.e.
/// `op`'s computation already exists there. Block-list position stands in for `SeqNum` order.
fn cse_find_in_block(
    data: &Funcdata,
    op: OpId,
    vid: VarnodeId,
    block: BlockId,
    earliest: Option<OpId>,
) -> Option<OpId> {
    let blk_ops = &data.block(block).ops;
    let earliest_pos = earliest.and_then(|e| blk_ops.iter().position(|&o| o == e));
    let outvn1 = data.op(op).output?;
    for &res in &data.vn(vid).descend {
        if res == op {
            continue;
        }
        if data.op(res).parent != Some(block) {
            continue;
        }
        let Some(res_pos) = blk_ops.iter().position(|&o| o == res) else { continue };
        if let Some(ep) = earliest_pos {
            if ep < res_pos {
                continue; // must occur earlier than (or at) earliest
            }
        }
        let Some(outvn2) = data.op(res).output else { continue };
        if functional_equality_level(data, outvn1, outvn2) == 0 {
            return Some(res);
        }
    }
    None
}

/// Ghidra `RuleIndirectCollapse` (`ruleaction.cc:3157`, oppool1 slot 40 — registered between
/// `RuleMultiCollapse` and `Rule2Comp2Mult`, `coreaction.cc:5551`): remove an INDIRECT whose
/// indirect effect is gone.
///
/// An INDIRECT models "the op I point at (my `iop`) may modify this storage". Whenever that stops
/// being true the INDIRECT is pointless and must go, or it strands: its output stays read while the
/// op it names is destroyed, and a marker-only block full of such INDIRECTs trips
/// `block_remove_internal_preserving`'s "deleting op with descendants" assert (Ghidra throws the
/// same at funcdata_block.cc:311).
///
/// The effect is gone when the `iop` op is **dead** — the `if (!indop.is_dead())` test below is
/// simply skipped and control reaches the collapse — or when it has been resolved to a **COPY**:
///   * identical storage (`characterizeOverlap == 2`) — the INDIRECT *is* that copy, so become a COPY;
///   * INDIRECT's output properly contained in the COPY's (`contains == 0`) — become a SUBPIECE;
///   * partial overlap — Ghidra warns and declines;
///   * **no overlap at all** — the COPY cannot affect the guarded storage, so fall through and
///     collapse. This is the case mosura's stack-pointer recovery produces in bulk: `recover_stack`
///     rewrites a prologue `push` into a COPY into a `stack` slot while `guardStores` INDIRECTs
///     around it guard `ram` globals, so the two never overlap.
///
/// The `hasNoLocalAlias` and `usesSpacebasePtr` arms are reachable code evaluated over the
/// attributes mosura produces; both attributes currently have no producer here (see
/// [`Varnode::has_no_local_alias`](super::varnode::Varnode::has_no_local_alias) and
/// [`flags::SPACEBASE_PTR`](super::op::flags::SPACEBASE_PTR)), which sends a live non-COPY `iop`
/// down Ghidra's own `else return 0` — the conservative arm, never a collapse mosura invents.
pub struct RuleIndirectCollapse;

impl Rule for RuleIndirectCollapse {
    fn name(&self) -> &str {
        "indirectcollapse"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Indirect]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        // Ghidra: `in(1)` must be an IPTR_IOP annotation, then `getOpFromConst` recovers the op.
        // mosura's 1-input INDIRECT carries the same reference in `guarded_op`, so a missing one is
        // exactly Ghidra's non-IOP `in(1)`.
        let Some(indop) = data.op(op).guarded_op() else {
            return 0;
        };
        let out = data.op(op).output.expect("INDIRECT has an output");
        // Is the indirect effect gone?
        if !data.op(indop).is_dead() {
            if data.op(indop).code() == OpCode::Copy {
                // STORE resolved to a COPY.
                let vn1 = data.op(indop).output.expect("COPY has an output");
                let res = super::mergesnip::characterize_overlap(data, vn1, out);
                if res > 0 {
                    // The copy has an effect of some sort.
                    if res == 2 {
                        // Same storage: convert the INDIRECT to a COPY of the copied value.
                        data.op_uninsert(op);
                        data.op_set_input(op, 0, vn1);
                        // Ghidra `opRemoveInput(op,1)` drops the iop annotation varnode; mosura's
                        // 1-input form has no such slot, so dropping `guarded_op` is that removal.
                        data.op_mut(op).guarded_op = None;
                        data.op_set_opcode(op, OpCode::Copy);
                        data.op_insert_after(op, indop);
                        return 1;
                    }
                    let is_const = data.spaces.get(data.vn(vn1).loc.space).is_constant();
                    if data.vn(vn1).contains(data.vn(out), is_const) == 0 {
                        // INDIRECT output is properly contained in the COPY output: become a SUBPIECE.
                        // Little-endian truncation amount. mosura's decompile-layer `Space` carries
                        // no endianness, so Ghidra's `isBigEndian` arm is omitted exactly as in
                        // `double.rs:219`.
                        let trunc = data.vn(out).loc.offset - data.vn(vn1).loc.offset;
                        let k = data.new_const(4, trunc);
                        data.op_uninsert(op);
                        data.op_set_input(op, 0, vn1);
                        // Ghidra `opSetInput(op, newConstant(4,trunc), 1)` overwrites the iop slot;
                        // mosura's 1-input form grows the slot and drops `guarded_op` instead.
                        data.op_insert_input(op, 1, k);
                        data.op_mut(op).guarded_op = None;
                        data.op_set_opcode(op, OpCode::Subpiece);
                        data.op_insert_after(op, indop);
                        return 1;
                    }
                    // Ghidra: `warning("Ignoring partial resolution of indirect")` — mosura has no
                    // per-function warning stream, so the decline is the whole behaviour.
                    return 0;
                }
                // res == 0: no overlap, so the COPY cannot touch this storage — fall through.
            // ⚠️ INERT TODAY — DO NOT "SIMPLIFY AWAY". This arm and the next are faithful Ghidra
            // code whose *guard attributes have no producer in mosura yet*, so control currently
            // always falls past them to the `else return 0` below — which is precisely what Ghidra
            // does with those attributes unset. They are live code awaiting their producer, not
            // dead branches.
            //
            // `nolocalalias` (varnode.rs `flags::NOLOCALALIAS`) is set by Ghidra in
            // `ScopeLocal`'s unaliased-symbol marking (varmap.cc:1375); mosura's `varnodeprops`
            // models only that marking's net effect on `addrtied`/`addrforce` and never stores the
            // attribute, so this reads `false` everywhere.
            } else if data.vn(out).has_no_local_alias() {
                // Ghidra tests the op-level `indirect_creation`; mosura records that property on the
                // INDIRECT's output varnode instead (`Funcdata::mark_indirect_creation`).
                if data.vn(out).is_indirect_creation() || data.op(op).no_indirect_collapse() {
                    return 0;
                }
            // `spacebase_ptr` is set by Ghidra's `discoverIndexedStackPointers`/`LoadGuard`
            // subsystem (heritage.cc, via `Funcdata::opMarkSpacebasePtr` funcdata.hh:487), which
            // mosura does not model (documented at heritage.rs:1392 and varmap.rs:447), so nothing
            // ever sets it and this reads `false` everywhere.
            } else if data.op(indop).uses_spacebase_ptr() {
                if data.op(indop).code() == OpCode::Store {
                    // Ghidra consults the STORE's `LoadGuard` here and declines in both arms (a
                    // guarded address, or a marked-but-unguarded STORE that should still become a
                    // COPY). mosura records no load guards, so the unguarded arm is the one that
                    // applies and it also declines — the two agree.
                    return 0;
                }
            } else {
                return 0;
            }
        }

        let in0 = data.op(op).input(0).expect("INDIRECT has in(0)");
        data.total_replace(out, in0);
        data.op_destroy(op); // Get rid of the INDIRECT
        1
    }
}

/// Ghidra `RuleMultiCollapse` (ruleaction.cc): collapse a MULTIEQUAL whose inputs all trace to the
/// same value. A varnode that recurs in a loop (the phi reaching itself) is skipped — treated as
/// equal to every other branch. Inputs may match by *absolute* equality (same varnode) or by
/// *functional* equality (a `functionalEquality` computation, e.g. two `COPY const`); nested
/// MULTIEQUAL branches get one last chance by expanding their inputs into the match list. On the
/// functional-equality path, each collapsed op is rewritten to recompute the matched expression
/// (reusing an existing in-block copy when one dominates, via `cseFindInBlock`).
pub struct RuleMultiCollapse;

impl Rule for RuleMultiCollapse {
    fn name(&self) -> &str {
        "multicollapse"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Multiequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let num0 = data.op(op).num_inputs();
        // Everything must be heritaged before collapse.
        for i in 0..num0 {
            let inp = data.op(op).input(i).unwrap();
            if !data.vn(inp).is_heritage_known() {
                return 0;
            }
        }

        let mut func_eq = false; // start assuming absolute equality of branches
        let mut nofunc = false; // functional equalities initially allowed
        let mut defcopyr: Option<VarnodeId> = None;
        let mut matchlist: Vec<VarnodeId> =
            (0..num0).map(|i| data.op(op).input(i).unwrap()).collect();

        // Find the base branch to match: the first input not written by a MULTIEQUAL.
        let is_multi_written = |data: &Funcdata, v: VarnodeId| -> bool {
            let vn = data.vn(v);
            vn.is_written() && vn.def.is_some_and(|d| data.op(d).code() == OpCode::Multiequal)
        };
        for &copyr in &matchlist {
            if !is_multi_written(data, copyr) {
                defcopyr = Some(copyr);
                // An unwritten (constant/free) base branch cannot be recomputed by functional
                // equality, so mark `nofunc` — the same guard the None-branch applies below — or the
                // `func_eq` collapse path would dereference its (nonexistent) def. Ghidra reaches the
                // first loop only for a written non-MULTIEQUAL base; a constant base arises once
                // `consume::never_consumed` folds a MULTIEQUAL input to 0 and the now-dead marker has
                // not yet been swept (Ghidra removes it in the same combined ActionDeadCode pass).
                if !data.vn(copyr).is_written() {
                    nofunc = true;
                }
                break;
            }
        }

        let mut success = true;
        let outvn = data.op(op).output.unwrap();
        data.vn_mut(outvn).set_mark();
        let mut skiplist: Vec<VarnodeId> = vec![outvn];
        let mut j = 0;
        while j < matchlist.len() {
            let copyr = matchlist[j];
            j += 1;
            if data.vn(copyr).is_mark() {
                continue; // a varnode we've seen — a loop recurrence; treat as equal, skip it
            }
            match defcopyr {
                None => {
                    // This is now the defining branch; all others must match it.
                    defcopyr = Some(copyr);
                    let vn = data.vn(copyr);
                    if vn.is_written() {
                        if vn.def.is_some_and(|d| data.op(d).code() == OpCode::Multiequal) {
                            nofunc = true; // MULTIEQUAL cannot match by functional equality
                        }
                    } else {
                        nofunc = true; // unwritten cannot match by functional equality
                    }
                }
                Some(dc) if dc == copyr => continue, // a matching branch
                Some(dc) if !nofunc && functional_equality(data, dc, copyr) => {
                    func_eq = true; // now matching by functional equality
                    continue;
                }
                Some(_) if is_multi_written(data, copyr) => {
                    // The non-matching branch is a MULTIEQUAL — give it one last chance and add
                    // its inputs to the list of things to match.
                    let newop = data.vn(copyr).def.unwrap();
                    skiplist.push(copyr);
                    data.vn_mut(copyr).set_mark();
                    let nin = data.op(newop).num_inputs();
                    for i in 0..nin {
                        matchlist.push(data.op(newop).input(i).unwrap());
                    }
                }
                Some(_) => {
                    success = false; // a non-matching branch
                    break;
                }
            }
        }

        // `defcopyr` is always set for a real MULTIEQUAL (≥1 non-self input); guard the
        // pathological all-self-loop case rather than unwrap-panic.
        if let (true, Some(defc)) = (success, defcopyr) {
            for &copyr in &skiplist {
                data.vn_mut(copyr).clear_mark();
                let cur_op = data.vn(copyr).def.unwrap(); // Ghidra: op = copyr->getDef()
                if func_eq {
                    // Functional equality: recompute the matched expression at this location.
                    let parent = data.op(cur_op).parent.unwrap();
                    let earliest = earliest_use(data, copyr, parent);
                    let newop = data.vn(defc).def.unwrap(); // copy newop (defcopyr's def)
                    let nin = data.op(newop).num_inputs();
                    let mut substitute: Option<OpId> = None;
                    for i in 0..nin {
                        let invn = data.op(newop).input(i).unwrap();
                        if !data.vn(invn).is_constant() {
                            // Has newop already been copied in this block?
                            substitute = cse_find_in_block(data, newop, invn, parent, earliest);
                            break;
                        }
                    }
                    if let Some(sub) = substitute {
                        // Already copied — reuse that copy's output.
                        let sub_out = data.op(sub).output.unwrap();
                        data.total_replace(copyr, sub_out);
                        data.op_destroy(cur_op);
                    } else {
                        // Otherwise create a copy by rewriting cur_op into newop's computation.
                        let needsreinsert = data.op(cur_op).code() == OpCode::Multiequal;
                        let parms: Vec<VarnodeId> =
                            (0..nin).map(|i| data.op(newop).input(i).unwrap()).collect();
                        data.op_set_all_input(cur_op, &parms);
                        let newcode = data.op(newop).code();
                        data.op_set_opcode(cur_op, newcode);
                        if needsreinsert {
                            // No longer a MULTIEQUAL — move it out of the leading-MULTIEQUAL region.
                            let bl = data.op(cur_op).parent.unwrap();
                            data.op_uninsert(cur_op);
                            data.op_insert_begin(cur_op, bl);
                        }
                    }
                } else {
                    // Absolute equality: replace all refs to copyr with defcopyr.
                    data.total_replace(copyr, defc);
                    data.op_destroy(cur_op);
                }
            }
            return 1;
        }

        for &copyr in &skiplist {
            data.vn_mut(copyr).clear_mark();
        }
        0
    }
}

/// Ghidra `RulePositiveDiv` (ruleaction.cc:7799; getOpList 7792): signed division of positive
/// values is unsigned division. If the sign bit of both the numerator and denominator of a signed
/// division (or remainder) is known-zero — proven via the non-zero mask ([`Varnode::get_nzmask`]) —
/// convert `INT_SDIV`/`INT_SREM` to the unsigned `INT_DIV`/`INT_REM`.
pub struct RulePositiveDiv;

impl Rule for RulePositiveDiv {
    fn name(&self) -> &str {
        "positivediv"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSdiv, OpCode::IntSrem]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(out) = data.op(op).output else { return 0 };
        let mut sa = data.vn(out).size;
        if sa > 8 {
            return 0; // Ghidra: sa > sizeof(uintb)
        }
        sa = sa * 8 - 1;
        let in0 = data.op(op).input(0).unwrap();
        if ((data.vn(in0).get_nzmask() >> sa) & 1) != 0 {
            return 0; // Input 0 may be negative
        }
        let in1 = data.op(op).input(1).unwrap();
        if ((data.vn(in1).get_nzmask() >> sa) & 1) != 0 {
            return 0; // Input 1 may be negative
        }
        let opc = if data.op(op).code() == OpCode::IntSdiv {
            OpCode::IntDiv
        } else {
            OpCode::IntRem
        };
        data.op_set_opcode(op, opc);
        1
    }
}

/// Ghidra `RuleAndCommute` (ruleaction.cc:1532; doc at 1520): commute `INT_AND` with `INT_LEFT` /
/// `INT_RIGHT`: `(V << c) & d  =>  (V & (d >> c)) << c` (and the right-shift dual). This makes sense
/// when `c` is constant and the shift has no other use, or when the mask is likely to cancel with a
/// specific `INT_OR` / `PIECE` feeding the shift. The constant-mask guard on the `INT_LEFT` fast
/// path is required: without it (Ghidra's comment at 1577) the commute would loop forever.
pub struct RuleAndCommute;

impl Rule for RuleAndCommute {
    fn name(&self) -> &str {
        "andcommute"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(out) = data.op(op).output else { return 0 };
        let size = data.vn(out).size;
        if size > 8 {
            return 0; // FIXME: uintb should be arbitrary precision (Ghidra's `size > sizeof(uintb)`)
        }
        let fullmask = super::nzmask::calc_mask(size);

        // Ghidra breaks out of the 2-iteration loop with (opc, savn, othervn, orvn) captured; if it
        // falls through both operands (`i == 2`) it returns 0.
        let mut matched: Option<(OpCode, VarnodeId, VarnodeId, VarnodeId)> = None;
        for i in 0..2usize {
            let shiftvn = data.op(op).input(i).unwrap();
            let Some(shiftop) = data.vn(shiftvn).def else { continue };
            let opc = data.op(shiftop).code();
            if opc != OpCode::IntLeft && opc != OpCode::IntRight {
                continue;
            }
            let savn = data.op(shiftop).input(1).unwrap();
            if !data.vn(savn).is_constant() {
                continue;
            }
            let sa = data.vn(savn).constant_value() as u32;

            let othervn = data.op(op).input(1 - i).unwrap();
            if !data.vn(othervn).is_heritage_known() {
                continue;
            }
            let mut othermask = data.vn(othervn).get_nzmask();
            // Check if the AND is only zeroing bits which are already zeroed by the shift, in which
            // case `andmask` takes care of it; otherwise compute the mask as it will be after the
            // commute.
            // `sa` is a constant shift amount that may exceed the value width (e.g. a degenerate
            // `#0x0 >> #0xffffffff` a prior fold left behind). Ghidra shifts a `uintb` by `(int4)sa`
            // with raw C++ `>>`/`<<`; on the x86-64 oracle that masks the count mod 64, so mosura uses
            // `wrapping_shr`/`wrapping_shl` (identical to `>>`/`<<` for `sa < 64`) to match rather than
            // panic on the Rust debug shift-overflow check.
            if opc == OpCode::IntRight {
                if fullmask.wrapping_shr(sa) == othermask {
                    continue;
                }
                othermask = othermask.wrapping_shl(sa);
            } else {
                // NOTE: ported verbatim — Ghidra's source is `((fullmask<<sa)&&fullmask)` with a
                // logical `&&` (an apparent Ghidra typo for bitwise `&`); kept faithful.
                if ((((fullmask.wrapping_shl(sa)) != 0) && (fullmask != 0)) as u64) == othermask {
                    continue;
                }
                othermask = othermask.wrapping_shr(sa);
            }
            if othermask == 0 {
                continue; // Handled by andmask
            }
            if othermask == fullmask {
                continue;
            }

            let orvn = data.op(shiftop).input(0).unwrap();
            if opc == OpCode::IntLeft && data.vn(othervn).is_constant() {
                // `(v & #c) << #sa` is preferred to `(v << #sa) & #(c << sa)` because the mask is
                // right-justified. NOTE: the constant-mask check above is what stops an infinite
                // transform loop. If the shift has no other use, always commute.
                if lone_descend(data, shiftvn) == Some(op) {
                    matched = Some((opc, savn, othervn, orvn));
                    break;
                }
            }

            if !data.vn(orvn).is_written() {
                continue;
            }
            let orop = data.vn(orvn).def.unwrap();
            let orcode = data.op(orop).code();
            // Ghidra breaks (commutes) as soon as any operand's non-zero bits cancel against
            // `othermask`; the individual `break`s combine into this single predicate (all reads,
            // no side effects, so evaluating them all is equivalent to Ghidra's short-circuit).
            let commute = if orcode == OpCode::IntOr {
                let a0 = data.op(orop).input(0).unwrap();
                let a1 = data.op(orop).input(1).unwrap();
                let ormask1 = data.vn(a0).get_nzmask();
                let ormask2 = data.vn(a1).get_nzmask();
                (ormask1 & othermask) == 0
                    || (ormask2 & othermask) == 0
                    || (data.vn(othervn).is_constant()
                        && ((ormask1 & othermask) == ormask1 || (ormask2 & othermask) == ormask2))
            } else if orcode == OpCode::Piece {
                let lowvn = data.op(orop).input(1).unwrap(); // Low part of piece
                let highvn = data.op(orop).input(0).unwrap(); // High part
                let ormask1 = data.vn(lowvn).get_nzmask();
                let lowsize = data.vn(lowvn).size;
                let ormask2 = data.vn(highvn).get_nzmask() << (lowsize * 8);
                (ormask1 & othermask) == 0 || (ormask2 & othermask) == 0
            } else {
                continue;
            };
            if commute {
                matched = Some((opc, savn, othervn, orvn));
                break;
            }
            // OR/PIECE present but nothing cancels — Ghidra falls through to the next operand.
        }

        let Some((opc, savn, othervn, orvn)) = matched else {
            return 0;
        };

        // Do the commute.
        let opp = if opc == OpCode::IntLeft { OpCode::IntRight } else { OpCode::IntLeft };
        let newop1 = data.new_op_before_sized(op, opp, vec![othervn, savn], size);
        let newvn1 = data.op(newop1).output.unwrap();
        let newop2 = data.new_op_before_sized(op, OpCode::IntAnd, vec![orvn, newvn1], size);
        let newvn2 = data.op(newop2).output.unwrap();
        data.op_set_input(op, 0, newvn2);
        data.op_set_input(op, 1, savn);
        data.op_set_opcode(op, opc);
        1
    }
}

/// Ghidra `RuleShiftAnd` (`ruleaction.cc`, oppool1 @5582 "analysis"): a left/right shift — or a
/// power-of-two `INT_MULT`, treated as a left shift — applied to `(V & mask)` drops the AND to a
/// COPY when, after the same shift is applied to `mask` and to V's non-zero mask, the surviving
/// mask bits already cover every possibly-nonzero bit of V (`(mask & nzm) == nzm`). The AND was
/// redundant given V's non-zero mask, so `V & mask` becomes just `V`.
pub struct RuleShiftAnd;

impl Rule for RuleShiftAnd {
    fn name(&self) -> &str {
        "shiftand"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntRight, OpCode::IntLeft, OpCode::IntMult]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let cvn = data.op(op).input(1).unwrap();
        if !data.vn(cvn).is_constant() {
            return 0;
        }
        let shiftin = data.op(op).input(0).unwrap();
        if !data.vn(shiftin).is_written() {
            return 0;
        }
        let andop = data.vn(shiftin).def.unwrap();
        if data.op(andop).code() != OpCode::IntAnd {
            return 0;
        }
        if lone_descend(data, shiftin) != Some(op) {
            return 0;
        }
        let maskvn = data.op(andop).input(1).unwrap();
        if !data.vn(maskvn).is_constant() {
            return 0;
        }
        let mut mask = data.vn(maskvn).constant_value();
        let invn = data.op(andop).input(0).unwrap();
        if data.vn(invn).is_free() {
            return 0;
        }

        let mut opc = data.op(op).code();
        // For a shift the count is the constant directly; for INT_MULT only a power-of-two constant
        // is really a shift (Ghidra `leastsigbit_set` == the sole set bit).
        let sa: u32;
        if opc == OpCode::IntRight || opc == OpCode::IntLeft {
            sa = data.vn(cvn).constant_value() as u32;
        } else {
            let lsb = super::nzmask::leastsigbit_set(data.vn(cvn).constant_value());
            if lsb <= 0 {
                return 0;
            }
            if (1u64 << (lsb as u32)) != data.vn(cvn).constant_value() {
                return 0;
            }
            sa = lsb as u32;
            opc = OpCode::IntLeft; // Treat INT_MULT as INT_LEFT
        }

        let mut nzm = data.vn(invn).get_nzmask();
        let fullmask = super::nzmask::calc_mask(data.vn(invn).size);
        // Ghidra shifts `uintb` masks with raw C++ `>>`/`<<`; on the x86-64 oracle that masks the
        // count mod 64, so `wrapping_shr`/`wrapping_shl` matches (see [`RuleAndCommute`]).
        if opc == OpCode::IntRight {
            nzm = nzm.wrapping_shr(sa);
            mask = mask.wrapping_shr(sa);
        } else {
            nzm = nzm.wrapping_shl(sa) & fullmask;
            mask = mask.wrapping_shl(sa) & fullmask;
        }
        if (mask & nzm) != nzm {
            return 0;
        }
        // AND effectively does nothing, so change it to a COPY.
        data.op_set_opcode(andop, OpCode::Copy);
        data.op_remove_input(andop, 1);
        1
    }
}

/// Ghidra `RuleConcatCommute` (`ruleaction.cc`, oppool1 @5578 "analysis"): commute a PIECE with a
/// bitwise `INT_AND`/`INT_OR`/`INT_XOR` on one of its inputs, pulling the concatenation inside so a
/// later rule can act on the whole value:
///   - `concat(V & c, W)  =>  concat(V,W) & (c<<8|W| | mask(|W|))`
///   - `concat(V, W | c)  =>  concat(V,W) | c`
/// The mask/offset bookkeeping keeps the low `lo` (or high `hi`) lane untouched by the widened op.
pub struct RuleConcatCommute;

impl Rule for RuleConcatCommute {
    fn name(&self) -> &str {
        "concatcommute"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(out) = data.op(op).output else { return 0 };
        let outsz = data.vn(out).size;
        if outsz > 8 {
            return 0; // FIXME: precision problem for constants (Ghidra's `outsz > sizeof(uintb)`)
        }
        for i in 0..2usize {
            let vn = data.op(op).input(i).unwrap();
            if !data.vn(vn).is_written() {
                continue;
            }
            let logicop = data.vn(vn).def.unwrap();
            let opc = data.op(logicop).code();
            // Gate on the opcode BEFORE reading getIn(1): only INT_OR/XOR/AND are guaranteed binary.
            if opc != OpCode::IntOr && opc != OpCode::IntXor && opc != OpCode::IntAnd {
                continue;
            }
            let cvn = data.op(logicop).input(1).unwrap();
            let hi;
            let lo;
            let val: u64;
            if opc == OpCode::IntOr || opc == OpCode::IntXor {
                if !data.vn(cvn).is_constant() {
                    continue;
                }
                let mut v = data.vn(cvn).constant_value();
                if i == 0 {
                    hi = data.op(logicop).input(0).unwrap();
                    lo = data.op(op).input(1).unwrap();
                    v <<= 8 * data.vn(lo).size;
                } else {
                    hi = data.op(op).input(0).unwrap();
                    lo = data.op(logicop).input(0).unwrap();
                }
                val = v;
            } else {
                // opc == OpCode::IntAnd
                if !data.vn(cvn).is_constant() {
                    continue;
                }
                let mut v = data.vn(cvn).constant_value();
                if i == 0 {
                    hi = data.op(logicop).input(0).unwrap();
                    lo = data.op(op).input(1).unwrap();
                    v <<= 8 * data.vn(lo).size;
                    v |= super::nzmask::calc_mask(data.vn(lo).size);
                } else {
                    hi = data.op(op).input(0).unwrap();
                    lo = data.op(logicop).input(0).unwrap();
                    v |= super::nzmask::calc_mask(data.vn(hi).size) << (8 * data.vn(lo).size);
                }
                val = v;
            }
            if data.vn(hi).is_free() {
                continue;
            }
            if data.vn(lo).is_free() {
                continue;
            }
            // Create the earlier concat(hi, lo), then rewrite this op into the bitwise op over it.
            let newconcat = data.new_op_before_sized(op, OpCode::Piece, vec![hi, lo], outsz);
            let newvn = data.op(newconcat).output.unwrap();
            let c = data.new_const(outsz, val);
            data.op_set_opcode(op, opc);
            data.op_set_input(op, 0, newvn);
            data.op_set_input(op, 1, c);
            return 1;
        }
        0
    }
}

/// Ghidra `RuleConcatZext` (`ruleaction.cc`, oppool1 @5579 "analysis"): pull a zero-extension out of
/// a concatenation — `concat(zext(V), W)  =>  zext(concat(V,W))`. The concat of the *unextended* V
/// with W is built first (a smaller PIECE), then the original op becomes the single ZEXT of it.
pub struct RuleConcatZext;

impl Rule for RuleConcatZext {
    fn name(&self) -> &str {
        "concatzext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let mut hi = data.op(op).input(0).unwrap();
        if !data.vn(hi).is_written() {
            return 0;
        }
        let zextop = data.vn(hi).def.unwrap();
        if data.op(zextop).code() != OpCode::IntZext {
            return 0;
        }
        hi = data.op(zextop).input(0).unwrap();
        let lo = data.op(op).input(1).unwrap();
        if data.vn(hi).is_free() {
            return 0;
        }
        if data.vn(lo).is_free() {
            return 0;
        }
        // Create the earlier concat(hi, lo) out of the unextended hi and lo...
        let sz = data.vn(hi).size + data.vn(lo).size;
        let newconcat = data.new_op_before_sized(op, OpCode::Piece, vec![hi, lo], sz);
        let newvn = data.op(newconcat).output.unwrap();
        // ...then change the original op into a ZEXT of it.
        data.op_remove_input(op, 1);
        data.op_set_input(op, 0, newvn);
        data.op_set_opcode(op, OpCode::IntZext);
        1
    }
}

/// Ghidra `RuleZextCommute` (`ruleaction.cc`, oppool1 @5580 "analysis"): commute INT_ZEXT with
/// INT_RIGHT — `zext(V) >> W  =>  zext(V >> W)`. The shift moves onto the unextended value (the
/// high zeros of the zext carry no information for a logical right shift), then a single ZEXT.
pub struct RuleZextCommute;

impl Rule for RuleZextCommute {
    fn name(&self) -> &str {
        "zextcommute"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntRight]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let zextvn = data.op(op).input(0).unwrap();
        if !data.vn(zextvn).is_written() {
            return 0;
        }
        let zextop = data.vn(zextvn).def.unwrap();
        if data.op(zextop).code() != OpCode::IntZext {
            return 0;
        }
        let zextin = data.op(zextop).input(0).unwrap();
        if data.vn(zextin).is_free() {
            return 0;
        }
        let savn = data.op(op).input(1).unwrap();
        if !data.vn(savn).is_constant() && data.vn(savn).is_free() {
            return 0;
        }
        // New (earlier) shift of the unextended value, then this op becomes the ZEXT of it.
        let sz = data.vn(zextin).size;
        let newop = data.new_op_before_sized(op, OpCode::IntRight, vec![zextin, savn], sz);
        let newout = data.op(newop).output.unwrap();
        data.op_remove_input(op, 1);
        data.op_set_input(op, 0, newout);
        data.op_set_opcode(op, OpCode::IntZext);
        1
    }
}

/// Ghidra `RuleConcatZero` (`ruleaction.cc`, oppool1 @5595 "analysis"): simplify concatenation with
/// zero — `concat(V, 0)  =>  zext(V) << c`, where `c = 8 * |0-operand|` bits.
pub struct RuleConcatZero;

impl Rule for RuleConcatZero {
    fn name(&self) -> &str {
        "concatzero"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let lo = data.op(op).input(1).unwrap();
        if !data.vn(lo).is_constant() {
            return 0;
        }
        if data.vn(lo).constant_value() != 0 {
            return 0;
        }
        let sa = (8 * data.vn(lo).size) as u64;
        let highvn = data.op(op).input(0).unwrap();
        let outsz = data.vn(data.op(op).output.unwrap()).size;
        // New ZEXT of the high part, then this op becomes the left shift.
        let newop = data.new_op_before_sized(op, OpCode::IntZext, vec![highvn], outsz);
        let outvn = data.op(newop).output.unwrap();
        let c = data.new_const(4, sa);
        data.op_set_opcode(op, OpCode::IntLeft);
        data.op_set_input(op, 0, outvn);
        data.op_set_input(op, 1, c);
        1
    }
}

/// Ghidra `RuleConcatLeftShift` (`ruleaction.cc`, oppool1 @5596 "analysis"): simplify concatenation
/// of an extended, byte-aligned, top-justified value —
/// `concat(V, zext(W) << c)  =>  concat( concat(V,W), 0)` — when `zext(W) << c` places W exactly at
/// the most-significant boundary (`c/8 + |W| == |zext(W)|`).
pub struct RuleConcatLeftShift;

impl Rule for RuleConcatLeftShift {
    fn name(&self) -> &str {
        "concatleftshift"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn2 = data.op(op).input(1).unwrap();
        if !data.vn(vn2).is_written() {
            return 0;
        }
        let shiftop = data.vn(vn2).def.unwrap();
        if data.op(shiftop).code() != OpCode::IntLeft {
            return 0;
        }
        let shiftamt = data.op(shiftop).input(1).unwrap();
        if !data.vn(shiftamt).is_constant() {
            return 0; // Must be a constant shift
        }
        let mut sa = data.vn(shiftamt).constant_value();
        if (sa & 7) != 0 {
            return 0; // Not a multiple of 8
        }
        let tmpvn = data.op(shiftop).input(0).unwrap();
        if !data.vn(tmpvn).is_written() {
            return 0;
        }
        let zextop = data.vn(tmpvn).def.unwrap();
        if data.op(zextop).code() != OpCode::IntZext {
            return 0;
        }
        let b = data.op(zextop).input(0).unwrap();
        if data.vn(b).is_free() {
            return 0;
        }
        let vn1 = data.op(op).input(0).unwrap();
        if data.vn(vn1).is_free() {
            return 0;
        }
        sa /= 8; // bits to bytes
        if sa + data.vn(b).size as u64 != data.vn(tmpvn).size as u64 {
            return 0; // Must shift to most sig boundary
        }
        let newout_sz = data.vn(vn1).size + data.vn(b).size;
        let newop = data.new_op_before_sized(op, OpCode::Piece, vec![vn1, b], newout_sz);
        let newout = data.op(newop).output.unwrap();
        let outsz = data.vn(data.op(op).output.unwrap()).size;
        let c = data.new_const(outsz - newout_sz, 0);
        data.op_set_input(op, 0, newout);
        data.op_set_input(op, 1, c);
        1
    }
}

/// Ghidra `RuleDoubleSub` (`ruleaction.cc`, oppool1 @5542 "analysis"): collapse chained SUBPIECE —
/// `sub( sub(V,c), d)  =>  sub(V, c+d)` — skipping the intermediate truncation.
pub struct RuleDoubleSub;

impl Rule for RuleDoubleSub {
    fn name(&self) -> &str {
        "doublesub"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn = data.op(op).input(0).unwrap();
        if !data.vn(vn).is_written() {
            return 0;
        }
        let op2 = data.vn(vn).def.unwrap();
        if data.op(op2).code() != OpCode::Subpiece {
            return 0;
        }
        // SUBPIECE's truncation offset (input 1) is always a constant.
        let offset1 = data.vn(data.op(op).input(1).unwrap()).constant_value();
        let offset2 = data.vn(data.op(op2).input(1).unwrap()).constant_value();
        let base = data.op(op2).input(0).unwrap();
        data.op_set_input(op, 0, base); // Skip middleman
        let c = data.new_const(4, offset1 + offset2);
        data.op_set_input(op, 1, c);
        1
    }
}

/// Ghidra `RuleDoubleShift` (`ruleaction.cc`, oppool1 @5543 "analysis"): combine or cancel chained
/// INT_LEFT/INT_RIGHT (INT_MULT by a power of two counts as a left shift). Same direction combines
/// the shift amounts (`(V<<c)<<d => V<<(c+d)`, or COPY 0 if it shifts the whole word out); equal
/// opposite shifts become a mask (`(V<<c)>>c => V & mask`).
pub struct RuleDoubleShift;

impl Rule for RuleDoubleShift {
    fn name(&self) -> &str {
        "doubleshift"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntLeft, OpCode::IntRight, OpCode::IntMult]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let secvn = data.op(op).input(0).unwrap();
        if !data.vn(secvn).is_written() {
            return 0;
        }
        let secop = data.vn(secvn).def.unwrap();
        let mut opc2 = data.op(secop).code();
        if opc2 != OpCode::IntLeft && opc2 != OpCode::IntRight && opc2 != OpCode::IntMult {
            return 0;
        }
        let secop_in1 = data.op(secop).input(1).unwrap();
        if !data.vn(secop_in1).is_constant() {
            return 0;
        }
        let mut opc1 = data.op(op).code();
        let size = data.vn(secvn).size;
        let secop_in0 = data.op(secop).input(0).unwrap();
        if !data.vn(secop_in0).is_heritage_known() {
            return 0;
        }

        let sa1: i32;
        if opc1 == OpCode::IntMult {
            let val = data.vn(in1).constant_value();
            let lsb = super::nzmask::leastsigbit_set(val);
            if val.wrapping_shr(lsb as u32) != 1 {
                return 0; // Not multiplying by a power of 2
            }
            sa1 = lsb;
            opc1 = OpCode::IntLeft;
        } else {
            sa1 = data.vn(in1).constant_value() as i32;
        }
        let sa2: i32;
        if opc2 == OpCode::IntMult {
            let val = data.vn(secop_in1).constant_value();
            let lsb = super::nzmask::leastsigbit_set(val);
            if val.wrapping_shr(lsb as u32) != 1 {
                return 0; // Not multiplying by a power of 2
            }
            sa2 = lsb;
            opc2 = OpCode::IntLeft;
        } else {
            sa2 = data.vn(secop_in1).constant_value() as i32;
        }

        if opc1 == opc2 {
            if sa1 + sa2 < 8 * size as i32 {
                let c = data.new_const(4, (sa1 + sa2) as u32 as u64);
                data.op_set_opcode(op, opc1);
                data.op_set_input(op, 0, secop_in0);
                data.op_set_input(op, 1, c);
            } else {
                let c = data.new_const(size, 0);
                data.op_set_opcode(op, OpCode::Copy);
                data.op_set_input(op, 0, c);
                data.op_remove_input(op, 1);
            }
        } else if sa1 == sa2 && size <= 8 {
            // The u64 mask shift matches Ghidra's x86-64 masked-count shift (see RuleAndCommute).
            let mut mask = super::nzmask::calc_mask(size);
            if opc1 == OpCode::IntLeft {
                // A left shift is likely a multiply; don't collapse to AND if the intermediate is reused.
                if lone_descend(data, secvn).is_none() {
                    return 0;
                }
                mask = mask.wrapping_shl(sa1 as u32) & mask;
            } else {
                mask = mask.wrapping_shr(sa1 as u32) & mask;
            }
            let c = data.new_const(size, mask);
            data.op_set_opcode(op, OpCode::IntAnd);
            data.op_set_input(op, 0, secop_in0);
            data.op_set_input(op, 1, c);
        } else {
            return 0;
        }
        1
    }
}

/// Ghidra `RuleDoubleArithShift` (`ruleaction.cc`, oppool1 @5544 "analysis"): combine two sequential
/// signed right shifts — `(x s>> c) s>> d  =>  x s>> saturate(c + d)` — saturating the total shift at
/// the point the sign bit has filled the whole result (division optimization produces these chains).
pub struct RuleDoubleArithShift;

impl Rule for RuleDoubleArithShift {
    fn name(&self) -> &str {
        "doublearithshift"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSright]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let const_d = data.op(op).input(1).unwrap();
        if !data.vn(const_d).is_constant() {
            return 0;
        }
        let shiftin = data.op(op).input(0).unwrap();
        if !data.vn(shiftin).is_written() {
            return 0;
        }
        let shift2op = data.vn(shiftin).def.unwrap();
        if data.op(shift2op).code() != OpCode::IntSright {
            return 0;
        }
        let const_c = data.op(shift2op).input(1).unwrap();
        if !data.vn(const_c).is_constant() {
            return 0;
        }
        let in_vn = data.op(shift2op).input(0).unwrap();
        if data.vn(in_vn).is_free() {
            return 0;
        }
        let max = data.vn(data.op(op).output.unwrap()).size as i32 * 8 - 1; // Maximum possible shift.
        let mut sa =
            data.vn(const_c).constant_value() as i32 + data.vn(const_d).constant_value() as i32;
        if sa <= 0 {
            return 0; // Something is wrong
        }
        if sa > max {
            sa = max; // Shift amount has saturated
        }
        data.op_set_input(op, 0, in_vn);
        let c = data.new_const(4, sa as u64);
        data.op_set_input(op, 1, c);
        1
    }
}

/// Ghidra `RuleConcatShift` (`ruleaction.cc`, oppool1 @5545 "analysis"): a right shift that discards
/// the least-significant component of a concatenation cancels it — `concat(V,W) >> c  =>  ext(V)`,
/// zero-extension for INT_RIGHT and sign-extension for INT_SRIGHT. Any residual shift beyond `|W|`
/// is re-applied to the extended most-significant part.
pub struct RuleConcatShift;

impl Rule for RuleConcatShift {
    fn name(&self) -> &str {
        "concatshift"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntRight, OpCode::IntSright]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let shiftin = data.op(op).input(0).unwrap();
        if !data.vn(shiftin).is_written() {
            return 0;
        }
        let concat = data.vn(shiftin).def.unwrap();
        if data.op(concat).code() != OpCode::Piece {
            return 0;
        }
        let mut sa = data.vn(in1).constant_value() as i64;
        let leastsize = data.vn(data.op(concat).input(1).unwrap()).size as i64 * 8;
        if sa < leastsize {
            return 0; // Does the shift throw away the least significant part?
        }
        let mainin = data.op(concat).input(0).unwrap();
        if data.vn(mainin).is_free() {
            return 0;
        }
        sa -= leastsize;
        let extcode = if data.op(op).code() == OpCode::IntRight {
            OpCode::IntZext
        } else {
            OpCode::IntSext
        };
        if sa == 0 {
            // Exact cancellation: the shift becomes a plain extension of the most-significant part.
            data.op_remove_input(op, 1);
            data.op_set_opcode(op, extcode);
            data.op_set_input(op, 0, mainin);
        } else {
            // Extend the most-significant part, then apply the residual shift.
            let sz = data.vn(shiftin).size;
            let extop = data.new_op_before_sized(op, extcode, vec![mainin], sz);
            let newvn = data.op(extop).output.unwrap();
            data.op_set_input(op, 0, newvn);
            let c = data.new_const(data.vn(in1).size, sa as u64);
            data.op_set_input(op, 1, c);
        }
        1
    }
}

/// Ghidra `RuleSignForm` (`ruleaction.cc`, oppool1 @5597 "analysis"): normalize a sign extraction —
/// `sub(sext(V), c)  =>  V s>> (8*|V|-1)` — when the SUBPIECE takes a byte at or above V's width (so
/// it is extracting the replicated sign bit of the extension).
pub struct RuleSignForm;

impl Rule for RuleSignForm {
    fn name(&self) -> &str {
        "signform"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let sextout = data.op(op).input(0).unwrap();
        if !data.vn(sextout).is_written() {
            return 0;
        }
        let sextop = data.vn(sextout).def.unwrap();
        if data.op(sextop).code() != OpCode::IntSext {
            return 0;
        }
        let a = data.op(sextop).input(0).unwrap();
        let c = data.vn(data.op(op).input(1).unwrap()).constant_value(); // SUBPIECE byte offset
        if (c as i64) < data.vn(a).size as i64 {
            return 0;
        }
        if data.vn(a).is_free() {
            return 0;
        }
        data.op_set_input(op, 0, a);
        let n = (8 * data.vn(a).size - 1) as u64;
        let cn = data.new_const(4, n);
        data.op_set_input(op, 1, cn);
        data.op_set_opcode(op, OpCode::IntSright);
        1
    }
}

/// Ghidra `RuleSignShift` (`ruleaction.cc:3524`, INT_RIGHT): normalize a logical sign-bit
/// extraction into an arithmetic one when it feeds arithmetic/comparison —
/// `V >> (8|V|-1)  =>  (V s>> (8|V|-1)) * -1`. Landed HELD (UNWIRED) — Task #9/#20 de-fusion
/// (sign-normalization the fused RuleDivOpt can't re-collapse; wire with the keystone).
pub struct RuleSignShift;

impl Rule for RuleSignShift {
    fn name(&self) -> &str {
        "signshift"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntRight]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let const_vn = data.op(op).input(1).unwrap();
        if !data.vn(const_vn).is_constant() {
            return 0;
        }
        let val = data.vn(const_vn).constant_value();
        let in_vn = data.op(op).input(0).unwrap();
        let in_size = data.vn(in_vn).size;
        if val != (8 * in_size - 1) as u64 || data.vn(in_vn).is_free() {
            return 0;
        }
        // Only convert if the result is involved in an arithmetic expression or a comparison.
        let out_vn = data.op(op).output.unwrap();
        let mut do_conversion = false;
        for &arith_op in &data.vn(out_vn).descend.clone() {
            match data.op(arith_op).code() {
                OpCode::IntEqual | OpCode::IntNotequal => {
                    if data.vn(data.op(arith_op).input(1).unwrap()).is_constant() {
                        do_conversion = true;
                    }
                }
                OpCode::IntAdd | OpCode::IntMult => do_conversion = true,
                _ => {}
            }
            if do_conversion {
                break;
            }
        }
        if !do_conversion {
            return 0;
        }
        let shift_op = data.new_op_before_sized(op, OpCode::IntSright, vec![in_vn, const_vn], in_size);
        let unique_vn = data.op(shift_op).output.unwrap();
        data.op_set_input(op, 0, unique_vn);
        let negone = data.new_const(in_size, super::nzmask::calc_mask(in_size));
        data.op_set_input(op, 1, negone);
        data.op_set_opcode(op, OpCode::IntMult);
        1
    }
}

/// Ghidra `RuleTestSign` (`ruleaction.cc:3582`, INT_SRIGHT): rewrite a sign-bit test as a signed
/// comparison — `(V s>> (8|V|-1)) != 0  =>  V s< 0` (and `== 0  =>  0 s<= V`), for each `INT_EQUAL`
/// / `INT_NOTEQUAL` descendant taking the sign bit against 0 or -1. Landed HELD (UNWIRED) —
/// Task #9/#20 de-fusion (same sign-normalization class; wire with the keystone).
pub struct RuleTestSign;

impl RuleTestSign {
    /// Ghidra `RuleTestSign::findComparisons` (:3596): the `INT_EQUAL`/`INT_NOTEQUAL` descendants of
    /// `vn` that test it against a constant.
    fn find_comparisons(data: &Funcdata, vn: VarnodeId) -> Vec<OpId> {
        let mut res = Vec::new();
        for &op in &data.vn(vn).descend {
            let opc = data.op(op).code();
            if (opc == OpCode::IntEqual || opc == OpCode::IntNotequal)
                && data.vn(data.op(op).input(1).unwrap()).is_constant()
            {
                res.push(op);
            }
        }
        res
    }
}

impl Rule for RuleTestSign {
    fn name(&self) -> &str {
        "testsign"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSright]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let const_vn = data.op(op).input(1).unwrap();
        if !data.vn(const_vn).is_constant() {
            return 0;
        }
        let val = data.vn(const_vn).constant_value();
        let in_vn = data.op(op).input(0).unwrap();
        if val != (8 * data.vn(in_vn).size - 1) as u64 {
            return 0;
        }
        let out_vn = data.op(op).output.unwrap();
        if data.vn(in_vn).is_free() {
            return 0;
        }
        let compare_ops = Self::find_comparisons(data, out_vn);
        let mut result = 0;
        for compare_op in compare_ops {
            let comp_vn = data.op(compare_op).input(0).unwrap();
            let comp_size = data.vn(comp_vn).size;
            let offset = data.vn(data.op(compare_op).input(1).unwrap()).constant_value();
            let mut sgn = if offset == 0 {
                1
            } else if offset == super::nzmask::calc_mask(comp_size) {
                -1
            } else {
                continue;
            };
            if data.op(compare_op).code() == OpCode::IntNotequal {
                sgn = -sgn; // Complement the domain
            }
            let zero_vn = data.new_const(data.vn(in_vn).size, 0);
            if sgn == 1 {
                data.op_set_input(compare_op, 1, in_vn);
                data.op_set_input(compare_op, 0, zero_vn);
                data.op_set_opcode(compare_op, OpCode::IntSlessequal);
            } else {
                data.op_set_input(compare_op, 0, in_vn);
                data.op_set_input(compare_op, 1, zero_vn);
                data.op_set_opcode(compare_op, OpCode::IntSless);
            }
            result = 1;
        }
        result
    }
}

/// Ghidra `RuleSignForm2` (`ruleaction.cc:8476`, INT_SRIGHT): normalize a sign extraction through a
/// non-overflowing multiply — `sub(sext(V) * small, c) s>> (8|out|-1)  =>  V s>> (8|out|-1)`.
/// Landed HELD (UNWIRED) — Task #9/#20 de-fusion. FAITHFUL QUIRK: Ghidra repoints the shift input to
/// `V` then `return 0` (reports no-change though it mutated the graph); the port replicates that.
pub struct RuleSignForm2;

impl Rule for RuleSignForm2 {
    fn name(&self) -> &str {
        "signform2"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSright]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let const_vn = data.op(op).input(1).unwrap();
        if !data.vn(const_vn).is_constant() {
            return 0;
        }
        let in_vn = data.op(op).input(0).unwrap();
        let sizeout = data.vn(in_vn).size;
        if data.vn(const_vn).constant_value() != (sizeout * 8 - 1) as u64 {
            return 0;
        }
        if !data.vn(in_vn).is_written() {
            return 0;
        }
        let sub_op = data.vn(in_vn).def.unwrap();
        if data.op(sub_op).code() != OpCode::Subpiece {
            return 0;
        }
        let c = data.vn(data.op(sub_op).input(1).unwrap()).constant_value() as u32;
        let mult_out = data.op(sub_op).input(0).unwrap();
        let mult_size = data.vn(mult_out).size;
        if c + sizeout != mult_size {
            return 0; // Must be extracting the high part
        }
        if !data.vn(mult_out).is_written() {
            return 0;
        }
        let mult_op = data.vn(mult_out).def.unwrap();
        if data.op(mult_op).code() != OpCode::IntMult {
            return 0;
        }
        let mut slot = 2;
        let mut sext_op = None;
        for s in 0..2 {
            let vn = data.op(mult_op).input(s).unwrap();
            if !data.vn(vn).is_written() {
                continue;
            }
            let so = data.vn(vn).def.unwrap();
            if data.op(so).code() == OpCode::IntSext {
                slot = s;
                sext_op = Some(so);
                break;
            }
        }
        if slot > 1 {
            return 0;
        }
        let a = data.op(sext_op.unwrap()).input(0).unwrap();
        if data.vn(a).is_free() || data.vn(a).size != sizeout {
            return 0;
        }
        let other_vn = data.op(mult_op).input(1 - slot).unwrap();
        // otherVn must be positive and small enough that the INT_MULT can't overflow into the sign bit
        if data.vn(other_vn).is_constant() {
            if data.vn(other_vn).constant_value() > super::nzmask::calc_mask(sizeout) {
                return 0;
            }
            if 2 * sizeout > mult_size {
                return 0;
            }
        } else if data.vn(other_vn).is_written() {
            let zext_op = data.vn(other_vn).def.unwrap();
            if data.op(zext_op).code() != OpCode::IntZext {
                return 0;
            }
            if data.vn(data.op(zext_op).input(0).unwrap()).size + sizeout > mult_size {
                return 0;
            }
        } else {
            return 0;
        }
        data.op_set_input(op, 0, a);
        0 // faithful: Ghidra mutates then returns 0
    }
}

/// Ghidra `RuleTrivialBool` (`ruleaction.cc`, oppool1 @5523 "analysis"): simplify a boolean op with a
/// constant operand — `V&&false=>false`, `V&&true=>V`, `V||false=>V`, `V||true=>true`,
/// `V^^true=>!V`, `V^^false=>V`.
pub struct RuleTrivialBool;

impl Rule for RuleTrivialBool {
    fn name(&self) -> &str {
        "trivialbool"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolAnd, OpCode::BoolOr, OpCode::BoolXor]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vnconst = data.op(op).input(1).unwrap();
        if !data.vn(vnconst).is_constant() {
            return 0;
        }
        let val = data.vn(vnconst).constant_value();
        let (opc, vn) = match data.op(op).code() {
            OpCode::BoolXor => {
                let opc = if val == 1 { OpCode::BoolNegate } else { OpCode::Copy };
                (opc, data.op(op).input(0).unwrap())
            }
            OpCode::BoolAnd => {
                if val == 1 {
                    (OpCode::Copy, data.op(op).input(0).unwrap())
                } else {
                    (OpCode::Copy, data.new_const(1, 0)) // Copy false
                }
            }
            OpCode::BoolOr => {
                if val == 1 {
                    (OpCode::Copy, data.new_const(1, 1)) // Copy true
                } else {
                    (OpCode::Copy, data.op(op).input(0).unwrap())
                }
            }
            _ => return 0,
        };
        data.op_remove_input(op, 1);
        data.op_set_opcode(op, opc);
        data.op_set_input(op, 0, vn);
        1
    }
}

/// Ghidra `Rule2Comp2Mult` (ruleaction.cc:3967): rewrite arithmetic negation as multiplication by
/// -1 — `-V => V * -1` — so the term-collection / multiply rules can treat it uniformly. The
/// cleanup pool's [`RuleMultNegOne`] restores `-V` for printing (the two live in separate pools, so
/// they never ping-pong).
pub struct Rule2Comp2Mult;

impl Rule for Rule2Comp2Mult {
    fn name(&self) -> &str {
        "2comp2mult"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Int2comp]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        data.op_set_opcode(op, OpCode::IntMult);
        let size = data.vn(data.op(op).input(0).unwrap()).size;
        let negone = data.new_const(size, super::nzmask::calc_mask(size));
        data.op_insert_input(op, 1, negone);
        1
    }
}

/// Ghidra `RuleCarryElim` (ruleaction.cc:3988): rewrite `INT_CARRY(V, c)` against a constant as a
/// comparison — `carry(V, c) => (-c) <= V` — with the special case `carry(V, 0) => false`.
pub struct RuleCarryElim;

impl Rule for RuleCarryElim {
    fn name(&self) -> &str {
        "carryelim"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntCarry]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn2 = data.op(op).input(1).unwrap();
        if !data.vn(vn2).is_constant() {
            return 0;
        }
        let vn1 = data.op(op).input(0).unwrap();
        if data.vn(vn1).is_free() {
            return 0;
        }
        let off = data.vn(vn2).constant_value();
        if off == 0 {
            // carry(V, 0) is always false
            data.op_remove_input(op, 1);
            let f = data.new_const(1, 0);
            data.op_set_input(op, 0, f);
            data.op_set_opcode(op, OpCode::Copy);
            return 1;
        }
        // Take the twos-complement of the constant: -c
        let off = off.wrapping_neg() & super::nzmask::calc_mask(data.vn(vn2).size);
        data.op_set_opcode(op, OpCode::IntLessequal);
        data.op_set_input(op, 1, vn1); // Move V to second position
        let c = data.new_const(data.vn(vn1).size, off);
        data.op_set_input(op, 0, c); // Put -c in first position
        1
    }
}

/// Ghidra `RuleBxor2NotEqual` (ruleaction.cc:269): `V ^^ W => V != W` — a boolean XOR is boolean
/// inequality. A pure opcode swap.
pub struct RuleBxor2NotEqual;

impl Rule for RuleBxor2NotEqual {
    fn name(&self) -> &str {
        "bxor2notequal"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolXor]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        data.op_set_opcode(op, OpCode::IntNotequal);
        1
    }
}

/// The LESSEQUAL variant of a LESS opcode (Ghidra's `(OpCode)(lessform+1)` — the p-code enum places
/// each `_LESSEQUAL` immediately after its `_LESS`). Only LESS/SLESS/FLOAT_LESS reach here.
fn lessequal_form(lessform: OpCode) -> OpCode {
    match lessform {
        OpCode::IntLess => OpCode::IntLessequal,
        OpCode::IntSless => OpCode::IntSlessequal,
        OpCode::FloatLess => OpCode::FloatLessequal,
        other => other,
    }
}

/// Ghidra `RuleThreeWayCompare::testCompareEquivalence` (ruleaction.cc:9942): given the putative LESS
/// and LESSEQUAL ops of a three-way, verify their operands match (a LESSEQUAL may have been converted
/// to a LESS against an off-by-one constant). Returns 0 (correct), 1 (correct but swap the roles), or
/// -1 (not a match).
fn three_way_test_compare_equivalence(data: &Funcdata, lessop: OpId, lessequalop: OpId) -> i32 {
    let less_code = data.op(lessop).code();
    let le_code = data.op(lessequalop).code();
    let mut two_less_than;
    match less_code {
        OpCode::IntLess => {
            if le_code == OpCode::IntLessequal {
                two_less_than = false;
            } else if le_code == OpCode::IntLess {
                two_less_than = true;
            } else {
                return -1;
            }
        }
        OpCode::IntSless => {
            if le_code == OpCode::IntSlessequal {
                two_less_than = false;
            } else if le_code == OpCode::IntSless {
                two_less_than = true;
            } else {
                return -1;
            }
        }
        OpCode::FloatLess => {
            if le_code == OpCode::FloatLessequal {
                two_less_than = false;
            } else {
                return -1; // No partial form for floating-point comparison
            }
        }
        _ => return -1,
    }
    let a1 = data.op(lessop).input(0).unwrap();
    let a2 = data.op(lessequalop).input(0).unwrap();
    let b1 = data.op(lessop).input(1).unwrap();
    let b2 = data.op(lessequalop).input(1).unwrap();
    let mut res = 0;
    if a1 != a2 {
        // Make sure a1 and a2 are equivalent
        if !data.vn(a1).is_constant() || !data.vn(a2).is_constant() {
            return -1;
        }
        let (o1, o2) = (data.vn(a1).constant_value(), data.vn(a2).constant_value());
        if o1 != o2 && two_less_than {
            if o2.wrapping_add(1) == o1 {
                two_less_than = false; // -lessequalop- is LESSTHAN, equivalent to LESSEQUAL
            } else if o1.wrapping_add(1) == o2 {
                two_less_than = false; // -lessop- is LESSTHAN, equivalent to LESSEQUAL
                res = 1; // we need to swap
            } else {
                return -1;
            }
        }
    }
    if b1 != b2 {
        // Make sure b1 and b2 are equivalent
        if !data.vn(b1).is_constant() || !data.vn(b2).is_constant() {
            return -1;
        }
        let (o1, o2) = (data.vn(b1).constant_value(), data.vn(b2).constant_value());
        if o1 != o2 && two_less_than {
            if o1.wrapping_add(1) == o2 {
                two_less_than = false;
            } else if o2.wrapping_add(1) == o1 {
                two_less_than = false;
                res = 1; // we need to swap
            }
        } else {
            return -1;
        }
    }
    if two_less_than {
        return -1; // Did not compensate for two LESSTHANs with differing constants
    }
    res
}

/// Ghidra `RuleThreeWayCompare::detectThreeWay` (ruleaction.cc:10017): match a three-way calculation
/// `zext(V < W) + zext(V <= W) - 1` (in one of three add/const permutations) rooted at `op` (an
/// INT_ADD). Returns `(lessop, is_partial)` where `lessop` is the LESS op, or `None`. `is_partial` is
/// set when only the `zext + zext` (no `- 1`) prefix was found.
fn three_way_detect(data: &Funcdata, op: OpId) -> Option<(OpId, bool)> {
    let mut is_partial = false;
    let vn2 = data.op(op).input(1).unwrap();
    let zext1: OpId;
    let zext2: OpId;
    if data.vn(vn2).is_constant() {
        // Form 1 :  (z + z) - 1
        let mask = super::nzmask::calc_mask(data.vn(vn2).size);
        if mask != data.vn(vn2).constant_value() {
            return None; // Match the -1
        }
        let vn1 = data.op(op).input(0).unwrap();
        if !data.vn(vn1).is_written() {
            return None;
        }
        let addop = data.vn(vn1).def.unwrap();
        if data.op(addop).code() != OpCode::IntAdd {
            return None; // Match the add
        }
        let t0 = data.op(addop).input(0).unwrap();
        if !data.vn(t0).is_written() {
            return None;
        }
        zext1 = data.vn(t0).def.unwrap();
        if data.op(zext1).code() != OpCode::IntZext {
            return None; // Match the first zext
        }
        let t1 = data.op(addop).input(1).unwrap();
        if !data.vn(t1).is_written() {
            return None;
        }
        zext2 = data.vn(t1).def.unwrap();
        if data.op(zext2).code() != OpCode::IntZext {
            return None; // Match the second zext
        }
    } else if data.vn(vn2).is_written() {
        let tmpop = data.vn(vn2).def.unwrap();
        let tmpcode = data.op(tmpop).code();
        if tmpcode == OpCode::IntZext {
            // Form 2 : (z - 1) + z
            zext2 = tmpop; // Second zext is already matched
            let vn1 = data.op(op).input(0).unwrap();
            if !data.vn(vn1).is_written() {
                return None;
            }
            let addop = data.vn(vn1).def.unwrap();
            if data.op(addop).code() != OpCode::IntAdd {
                // Partial form:  (z + z)
                zext1 = addop;
                if data.op(zext1).code() != OpCode::IntZext {
                    return None; // Match the first zext
                }
                is_partial = true;
            } else {
                let t1 = data.op(addop).input(1).unwrap();
                if !data.vn(t1).is_constant() {
                    return None;
                }
                let mask = super::nzmask::calc_mask(data.vn(t1).size);
                if mask != data.vn(t1).constant_value() {
                    return None; // Match the -1
                }
                let t0 = data.op(addop).input(0).unwrap();
                if !data.vn(t0).is_written() {
                    return None;
                }
                zext1 = data.vn(t0).def.unwrap();
                if data.op(zext1).code() != OpCode::IntZext {
                    return None; // Match the first zext
                }
            }
        } else if tmpcode == OpCode::IntAdd {
            // Form 3 : z + (z - 1)
            let addop = tmpop; // Matched the add
            let vn1 = data.op(op).input(0).unwrap();
            if !data.vn(vn1).is_written() {
                return None;
            }
            zext1 = data.vn(vn1).def.unwrap();
            if data.op(zext1).code() != OpCode::IntZext {
                return None; // Match the first zext
            }
            let t1 = data.op(addop).input(1).unwrap();
            if !data.vn(t1).is_constant() {
                return None;
            }
            let mask = super::nzmask::calc_mask(data.vn(t1).size);
            if mask != data.vn(t1).constant_value() {
                return None; // Match the -1
            }
            let t0 = data.op(addop).input(0).unwrap();
            if !data.vn(t0).is_written() {
                return None;
            }
            zext2 = data.vn(t0).def.unwrap();
            if data.op(zext2).code() != OpCode::IntZext {
                return None; // Match the second zext
            }
        } else {
            return None;
        }
    } else {
        return None;
    }
    let v1 = data.op(zext1).input(0).unwrap();
    if !data.vn(v1).is_written() {
        return None;
    }
    let v2 = data.op(zext2).input(0).unwrap();
    if !data.vn(v2).is_written() {
        return None;
    }
    let mut lessop = data.vn(v1).def.unwrap();
    let mut lessequalop = data.vn(v2).def.unwrap();
    let opc = data.op(lessop).code();
    if opc != OpCode::IntLess && opc != OpCode::IntSless && opc != OpCode::FloatLess {
        // Make sure first zext is the less-than
        std::mem::swap(&mut lessop, &mut lessequalop);
    }
    let form = three_way_test_compare_equivalence(data, lessop, lessequalop);
    if form < 0 {
        return None;
    }
    if form == 1 {
        std::mem::swap(&mut lessop, &mut lessequalop);
    }
    Some((lessop, is_partial))
}

/// Ghidra `RuleThreeWayCompare` (ruleaction.cc:10128): simplify a secondary comparison of a
/// \e three-way value `X = zext(V < W) + zext(V <= W) - 1` (which is -1/0/1 for less/equal/greater)
/// against a small constant back into a single direct comparison of `V` and `W`. The `form` integer
/// packs (const value, partial-ness, const operand position, base compare op) and selects the
/// resulting op/operand order via the 24-case table.
pub struct RuleThreeWayCompare;

impl Rule for RuleThreeWayCompare {
    fn name(&self) -> &str {
        "threewaycomp"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![
            OpCode::IntSless,
            OpCode::IntSlessequal,
            OpCode::IntEqual,
            OpCode::IntNotequal,
        ]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let mut const_slot = 0usize;
        let mut tmpvn = data.op(op).input(const_slot).unwrap();
        if !data.vn(tmpvn).is_constant() {
            // One of the two inputs must be a constant
            const_slot = 1;
            tmpvn = data.op(op).input(const_slot).unwrap();
            if !data.vn(tmpvn).is_constant() {
                return 0;
            }
        }
        // Encode const value (-1, 0, 1, 2) as (0, 1, 2, 3)
        let val = data.vn(tmpvn).constant_value();
        let mut form: i32 = if val <= 2 {
            val as i32 + 1
        } else if val == super::nzmask::calc_mask(data.vn(tmpvn).size) {
            0
        } else {
            return 0;
        };

        let other = data.op(op).input(1 - const_slot).unwrap();
        if !data.vn(other).is_written() {
            return 0;
        }
        let otherdef = data.vn(other).def.unwrap();
        if data.op(otherdef).code() != OpCode::IntAdd {
            return 0;
        }
        let Some((lessop, is_partial)) = three_way_detect(data, otherdef) else {
            return 0;
        };
        if is_partial {
            // Only found a partial three-way
            if form == 0 {
                return 0; // -1 const value is now out of range
            }
            form -= 1; // Subtract 1 from both sides to complete the three-way form
        }
        form <<= 1;
        if const_slot == 1 {
            form += 1; // Encode const position as next bit
        }
        let lessform = data.op(lessop).code(); // INT_LESS, INT_SLESS, or FLOAT_LESS
        form <<= 2;
        match data.op(op).code() {
            OpCode::IntSlessequal => form += 1,
            OpCode::IntEqual => form += 2,
            OpCode::IntNotequal => form += 3,
            _ => {} // INT_SLESS => +0
        }

        // First param to LESSTHAN is the second param of the cmp3way function, and vice versa
        let bvn = data.op(lessop).input(0).unwrap();
        let avn = data.op(lessop).input(1).unwrap();
        if !data.vn(avn).is_constant() && data.vn(avn).is_free() {
            return 0;
        }
        if !data.vn(bvn).is_constant() && data.vn(bvn).is_free() {
            return 0;
        }
        match form {
            1 | 21 => {
                // -1 s<= threeway  /  threeway s<= 1  =>  always true
                data.op_set_opcode(op, OpCode::IntEqual);
                let z0 = data.new_const(1, 0);
                data.op_set_input(op, 0, z0);
                let z1 = data.new_const(1, 0);
                data.op_set_input(op, 1, z1);
            }
            4 | 16 => {
                // threeway s< -1  /  1 s< threeway  =>  always false
                data.op_set_opcode(op, OpCode::IntNotequal);
                let z0 = data.new_const(1, 0);
                data.op_set_input(op, 0, z0);
                let z1 = data.new_const(1, 0);
                data.op_set_input(op, 1, z1);
            }
            2 | 5 | 6 | 12 => {
                // a < b
                data.op_set_opcode(op, lessform);
                data.op_set_input(op, 0, avn);
                data.op_set_input(op, 1, bvn);
            }
            13 | 19 | 20 | 23 => {
                // a <= b
                data.op_set_opcode(op, lessequal_form(lessform));
                data.op_set_input(op, 0, avn);
                data.op_set_input(op, 1, bvn);
            }
            8 | 17 | 18 | 22 => {
                // a > b
                data.op_set_opcode(op, lessform);
                data.op_set_input(op, 0, bvn);
                data.op_set_input(op, 1, avn);
            }
            0 | 3 | 7 | 9 => {
                // a >= b
                data.op_set_opcode(op, lessequal_form(lessform));
                data.op_set_input(op, 0, bvn);
                data.op_set_input(op, 1, avn);
            }
            10 | 14 => {
                // a == b
                let eqform = if lessform == OpCode::FloatLess {
                    OpCode::FloatEqual
                } else {
                    OpCode::IntEqual
                };
                data.op_set_opcode(op, eqform);
                data.op_set_input(op, 0, avn);
                data.op_set_input(op, 1, bvn);
            }
            11 | 15 => {
                // a != b
                let neform = if lessform == OpCode::FloatLess {
                    OpCode::FloatNotequal
                } else {
                    OpCode::IntNotequal
                };
                data.op_set_opcode(op, neform);
                data.op_set_input(op, 0, avn);
                data.op_set_input(op, 1, bvn);
            }
            _ => return 0,
        }
        1
    }
}

/// Ghidra `RuleBitUndistribute` (ruleaction.cc:2614): pull a common extension or shift out of both
/// operands of a bitwise op — `zext(V) & zext(W) => zext(V & W)`, `(V >> X) | (W >> X) => (V | W) >> X`
/// — for INT_ZEXT/INT_SEXT and INT_LEFT/INT_RIGHT/INT_SRIGHT (the shift amounts must match). A new
/// inner bitwise op is built on the un-extended/un-shifted values and the outer op becomes the ext/shift.
pub struct RuleBitUndistribute;

impl Rule for RuleBitUndistribute {
    fn name(&self) -> &str {
        "bitundistribute"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd, OpCode::IntOr, OpCode::IntXor]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn1 = data.op(op).input(0).unwrap();
        let vn2 = data.op(op).input(1).unwrap();
        if !data.vn(vn1).is_written() || !data.vn(vn2).is_written() {
            return 0;
        }
        let def1 = data.vn(vn1).def.unwrap();
        let def2 = data.vn(vn2).def.unwrap();
        let opc = data.op(def1).code();
        if data.op(def2).code() != opc {
            return 0;
        }
        let orig_opc = data.op(op).code(); // the bitwise op, captured before op is repurposed
        let in1: VarnodeId;
        let in2: VarnodeId;
        match opc {
            OpCode::IntZext | OpCode::IntSext => {
                // Test for full equality of the extension operation
                in1 = data.op(def1).input(0).unwrap();
                if data.vn(in1).is_free() {
                    return 0;
                }
                in2 = data.op(def2).input(0).unwrap();
                if data.vn(in2).is_free() {
                    return 0;
                }
                if data.vn(in1).size != data.vn(in2).size {
                    return 0;
                }
                data.op_remove_input(op, 1);
            }
            OpCode::IntLeft | OpCode::IntRight | OpCode::IntSright => {
                // Test for full equality of the shift operation
                let s1 = data.op(def1).input(1).unwrap();
                let s2 = data.op(def2).input(1).unwrap();
                let vnextra: VarnodeId;
                if data.vn(s1).is_constant() && data.vn(s2).is_constant() {
                    if data.vn(s1).constant_value() != data.vn(s2).constant_value() {
                        return 0;
                    }
                    vnextra = data.new_const(data.vn(s1).size, data.vn(s1).constant_value());
                } else if s1 != s2 {
                    return 0;
                } else {
                    if data.vn(s1).is_free() {
                        return 0;
                    }
                    vnextra = s1;
                }
                in1 = data.op(def1).input(0).unwrap();
                if data.vn(in1).is_free() {
                    return 0;
                }
                in2 = data.op(def2).input(0).unwrap();
                if data.vn(in2).is_free() {
                    return 0;
                }
                data.op_set_input(op, 1, vnextra);
            }
            _ => return 0,
        }

        let in1_size = data.vn(in1).size;
        let newext = data.new_op_before_sized(op, orig_opc, vec![in1, in2], in1_size);
        let smalllogic = data.op(newext).output.unwrap();
        data.op_set_opcode(op, opc);
        data.op_set_input(op, 0, smalllogic);
        1
    }
}

/// Ghidra `RuleBooleanUndistribute::isMatch` (ruleaction.cc:2698): test if the two given Varnodes
/// are matching boolean expressions. If the expressions are complementary, `true` is still
/// returned, but `right_flip` is flipped.
fn boolean_undistribute_is_match(
    data: &Funcdata,
    left_vn: VarnodeId,
    right_vn: VarnodeId,
    right_flip: &mut bool,
) -> bool {
    use super::expression::BooleanMatch;
    let val = super::expression::evaluate(data, left_vn, right_vn, 1);
    if val == BooleanMatch::Same {
        return true;
    }
    if val == BooleanMatch::Complementary {
        *right_flip = !*right_flip;
        return true;
    }
    false
}

/// Ghidra `RuleBooleanUndistribute` (ruleaction.cc:2677): undo distributed BOOL_AND through
/// INT_NOTEQUAL —
///  - `A && B != A && C  =>   A && (B != C)`
///  - `A || B == A || C  =>   A || (B == C)`
///  - `A && B == A && C  =>  !A || (B == C)`
pub struct RuleBooleanUndistribute;

impl Rule for RuleBooleanUndistribute {
    fn name(&self) -> &str {
        "booleanundistribute"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntEqual, OpCode::IntNotequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn0 = data.op(op).input(0).unwrap();
        if !data.vn(vn0).is_written() {
            return 0;
        }
        let vn1 = data.op(op).input(1).unwrap();
        if !data.vn(vn1).is_written() {
            return 0;
        }
        let op0 = data.vn(vn0).def.unwrap();
        let opc0 = data.op(op0).code();
        if opc0 != OpCode::BoolAnd && opc0 != OpCode::BoolOr {
            return 0;
        }
        let op1 = data.vn(vn1).def.unwrap();
        let opc1 = data.op(op1).code();
        if opc1 != OpCode::BoolAnd && opc1 != OpCode::BoolOr {
            return 0;
        }
        let ins = [
            data.op(op0).input(0).unwrap(),
            data.op(op0).input(1).unwrap(),
            data.op(op1).input(0).unwrap(),
            data.op(op1).input(1).unwrap(),
        ];
        if data.vn(ins[0]).is_free()
            || data.vn(ins[1]).is_free()
            || data.vn(ins[2]).is_free()
            || data.vn(ins[3]).is_free()
        {
            return 0;
        }
        let mut isflipped = [false; 4];
        let mut central_equal = data.op(op).code() == OpCode::IntEqual;
        if opc0 == OpCode::BoolOr {
            isflipped[0] = !isflipped[0];
            isflipped[1] = !isflipped[1];
            central_equal = !central_equal;
        }
        if opc1 == OpCode::BoolOr {
            isflipped[2] = !isflipped[2];
            isflipped[3] = !isflipped[3];
            central_equal = !central_equal;
        }
        let left_slot: usize;
        let right_slot: usize;
        if boolean_undistribute_is_match(data, ins[0], ins[2], &mut isflipped[2]) {
            left_slot = 0;
            right_slot = 2;
        } else if boolean_undistribute_is_match(data, ins[0], ins[3], &mut isflipped[3]) {
            left_slot = 0;
            right_slot = 3;
        } else if boolean_undistribute_is_match(data, ins[1], ins[2], &mut isflipped[2]) {
            left_slot = 1;
            right_slot = 2;
        } else if boolean_undistribute_is_match(data, ins[1], ins[3], &mut isflipped[3]) {
            left_slot = 1;
            right_slot = 3;
        } else {
            return 0;
        }
        if isflipped[left_slot] != isflipped[right_slot] {
            return 0;
        }
        let combine_opc: OpCode;
        if central_equal {
            combine_opc = OpCode::BoolOr;
            isflipped[left_slot] = !isflipped[left_slot];
        } else {
            combine_opc = OpCode::BoolAnd;
        }
        let mut final_a = ins[left_slot];
        if isflipped[left_slot] {
            final_a = data.op_bool_negate(final_a, op, false);
        }
        if isflipped[1 - left_slot] {
            central_equal = !central_equal;
        }
        if isflipped[5 - right_slot] {
            central_equal = !central_equal;
        }
        let final_b = ins[1 - left_slot];
        let final_c = ins[5 - right_slot];
        let eq_op = data.new_op_before_sized(
            op,
            if central_equal { OpCode::IntEqual } else { OpCode::IntNotequal },
            vec![final_b, final_c],
            1,
        );
        let tmp1 = data.op(eq_op).output.unwrap();
        data.op_set_opcode(op, combine_opc);
        data.op_set_input(op, 1, tmp1);
        data.op_set_input(op, 0, final_a);
        1
    }
}

/// Ghidra `RuleBooleanDedup::isMatch` (ruleaction.cc:2817): determine if the two given boolean
/// Varnodes always contain matching values. `is_flip` passes back `false` if the values are
/// always equal or `true` if they are complements; returns `false` if uncorrelated.
fn boolean_dedup_is_match(
    data: &Funcdata,
    left_vn: VarnodeId,
    right_vn: VarnodeId,
    is_flip: &mut bool,
) -> bool {
    use super::expression::BooleanMatch;
    let val = super::expression::evaluate(data, left_vn, right_vn, 1);
    if val == BooleanMatch::Same {
        *is_flip = false;
        return true;
    }
    if val == BooleanMatch::Complementary {
        *is_flip = true;
        return true;
    }
    false
}

/// Ghidra `RuleBooleanDedup` (ruleaction.cc:2792): remove duplicate clauses in boolean
/// expressions —
///  - `(A && B) || (A && C)   =>  A && (B || C)`
///  - `(A || B) && (A || C)   =>  A || (B && C)`
///  - `(A || B) || (!A && C)  =>  A || (B || C)`
///  - `(A && B) && (A && C)   =>  A && (B && C)`
///  - `(A || B) || (A || C)   =>  A || (B || C)`
pub struct RuleBooleanDedup;

impl Rule for RuleBooleanDedup {
    fn name(&self) -> &str {
        "booleandedup"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolAnd, OpCode::BoolOr]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn0 = data.op(op).input(0).unwrap();
        if !data.vn(vn0).is_written() {
            return 0;
        }
        let vn1 = data.op(op).input(1).unwrap();
        if !data.vn(vn1).is_written() {
            return 0;
        }
        let op0 = data.vn(vn0).def.unwrap();
        let opc0 = data.op(op0).code();
        if opc0 != OpCode::BoolAnd && opc0 != OpCode::BoolOr {
            return 0;
        }
        let op1 = data.vn(vn1).def.unwrap();
        let opc1 = data.op(op1).code();
        if opc1 != OpCode::BoolAnd && opc1 != OpCode::BoolOr {
            return 0;
        }
        let ins = [
            data.op(op0).input(0).unwrap(),
            data.op(op0).input(1).unwrap(),
            data.op(op1).input(0).unwrap(),
            data.op(op1).input(1).unwrap(),
        ];
        if data.vn(ins[0]).is_free()
            || data.vn(ins[1]).is_free()
            || data.vn(ins[2]).is_free()
            || data.vn(ins[3]).is_free()
        {
            return 0;
        }
        let mut isflipped = false;
        let left_a: VarnodeId;
        let right_a: VarnodeId;
        let left_o: VarnodeId;
        let right_o: VarnodeId;
        if boolean_dedup_is_match(data, ins[0], ins[2], &mut isflipped) {
            left_a = ins[0];
            right_a = ins[2];
            left_o = ins[1];
            right_o = ins[3];
        } else if boolean_dedup_is_match(data, ins[0], ins[3], &mut isflipped) {
            left_a = ins[0];
            right_a = ins[3];
            left_o = ins[1];
            right_o = ins[2];
        } else if boolean_dedup_is_match(data, ins[1], ins[2], &mut isflipped) {
            left_a = ins[1];
            right_a = ins[2];
            left_o = ins[0];
            right_o = ins[3];
        } else if boolean_dedup_is_match(data, ins[1], ins[3], &mut isflipped) {
            left_a = ins[1];
            right_a = ins[3];
            left_o = ins[0];
            right_o = ins[2];
        } else {
            return 0;
        }
        let central_opc = data.op(op).code();
        let bc_opc: OpCode;
        let final_opc: OpCode;
        let final_a: VarnodeId;
        if isflipped {
            if central_opc == OpCode::BoolAnd
                && opc0 == OpCode::BoolAnd
                && opc1 == OpCode::BoolAnd
            {
                // (A && B) && (!A && C)
                data.op_set_opcode(op, OpCode::Copy);
                data.op_remove_input(op, 1);
                let zero = data.new_const(1, 0);
                data.op_set_input(op, 0, zero); // Whole expression is false
                return 1;
            }
            if central_opc == OpCode::BoolOr && opc0 == OpCode::BoolOr && opc1 == OpCode::BoolOr {
                // (A || B) || (!A || C)
                data.op_set_opcode(op, OpCode::Copy);
                data.op_remove_input(op, 1);
                let one = data.new_const(1, 1);
                data.op_set_input(op, 0, one); // Whole expression is true
                return 1;
            }
            if central_opc == OpCode::BoolOr && opc0 != opc1 {
                // (A || B) || (!A && C)
                final_a = if opc0 == OpCode::BoolOr { left_a } else { right_a };
                final_opc = OpCode::BoolOr;
                bc_opc = OpCode::BoolOr;
            } else {
                return 0;
            }
        } else if central_opc == opc0 && central_opc == opc1 {
            // (A && B) && (A && C)    or   (A || B) || (A || C)
            final_a = left_a;
            final_opc = central_opc;
            bc_opc = central_opc;
        } else if opc0 == opc1 && central_opc != opc0 {
            // (A && B) || (A && C)    or   (A || B) && (A || C)
            final_a = left_a;
            final_opc = opc0;
            bc_opc = central_opc;
        } else {
            return 0;
        }
        let bc_op = data.new_op_before_sized(op, bc_opc, vec![left_o, right_o], 1);
        let tmp = data.op(bc_op).output.unwrap();
        data.op_set_opcode(op, final_opc);
        data.op_set_input(op, 0, final_a);
        data.op_set_input(op, 1, tmp);
        1
    }
}

/// Ghidra `RuleSubRight` (ruleaction.cc:7251, CLEANUP pool — `actcleanup`, coreaction.cc:5700):
/// convert truncation to cast — `sub(V,c) => sub(V >> c*8, 0)`. If the lone descendant of the
/// SUBPIECE is an INT_RIGHT/INT_SRIGHT by a constant and the SUBPIECE takes the "hi" piece, the
/// shift is lumped in too. This is what re-expands RuleSubNormal's non-zero-offset SUBPIECEs into
/// the shift + least-sig-truncation shape the printer renders as `(int2)(x >> 0x30)`.
///
/// Ghidra first checks `doesSpecialPrinting()`/`isPieceStructured()` to preserve structure-field
/// extractions for field printing; mosura has no TypePartialStruct/special-print machinery (P4/P8
/// debt), so that guard is vacuously absent. Ghidra also types the new shift output
/// (uint for `>>`, int for `s>>`); mosura varnodes carry no datatype at rule time.
pub struct RuleSubRight;

impl Rule for RuleSubRight {
    fn name(&self) -> &str {
        "subright"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let c = data.vn(data.op(op).input(1).unwrap()).constant_value();
        if c == 0 {
            return 0; // SUBPIECE is not least sig
        }
        let a = data.op(op).input(0).unwrap();
        let outvn = data.op(op).output.unwrap();
        if data.vn(outvn).is_addrtied() && data.vn(a).is_addrtied() {
            // Ghidra `outvn->overlap(*a) == c` (Varnode::overlap, little-endian: the byte offset
            // of outvn's start within a's range, or -1 if disjoint / different space). This
            // SUBPIECE should get converted to a marker by ActionCopyMarker, so don't convert it.
            let ol = data.vn(outvn).loc;
            let al = data.vn(a).loc;
            if ol.space == al.space
                && ol.offset >= al.offset
                && ol.offset - al.offset < data.vn(a).size as u64
                && ol.offset - al.offset == c
            {
                return 0;
            }
        }
        let mut op = op;
        let mut opc = OpCode::IntRight; // Default shift type
        let mut d = c as i64 * 8; // Convert to bit shift
        // Search for lone right shift descendant
        if let Some(lone) = lone_descend(data, outvn) {
            let opc2 = data.op(lone).code();
            if opc2 == OpCode::IntRight || opc2 == OpCode::IntSright {
                let sa = data.op(lone).input(1).unwrap();
                if data.vn(sa).is_constant() {
                    // Shift by constant
                    if data.vn(outvn).size as i64 + c as i64 == data.vn(a).size as i64 {
                        // If SUB is "hi" lump the SUB and shift together
                        d += data.vn(sa).constant_value() as i64;
                        if d >= data.vn(a).size as i64 * 8 {
                            if opc2 == OpCode::IntRight {
                                return 0; // Result should have been 0
                            }
                            d = data.vn(a).size as i64 * 8 - 1; // sign extraction
                        }
                        // Ghidra opUnlink: unset inputs/output + remove from the basic block
                        data.op_destroy(op);
                        data.op_uninsert(op);
                        op = lone;
                        data.op_set_opcode(op, OpCode::Subpiece);
                        opc = opc2;
                    }
                }
            }
        }
        // Create shift BEFORE the SUBPIECE happens
        let a_size = data.vn(a).size;
        let dvn = data.new_const(4, d as u64);
        let shiftop = data.new_op_before_sized(op, opc, vec![a, dvn], a_size);
        let newout = data.op(shiftop).output.unwrap();
        // Change SUBPIECE into a least sig SUBPIECE
        data.op_set_input(op, 0, newout);
        let zero = data.new_const(4, 0);
        data.op_set_input(op, 1, zero);
        1
    }
}

/// Ghidra `RuleSubNormal` (ruleaction.cc:7714): pull a SUBPIECE back through an INT_RIGHT/INT_SRIGHT
/// so the truncation happens before the shift — `sub(V >> n, c) => sub(V, c + n/8) >> (n mod 8)`, or
/// `=> ext(sub(V, c'))` when the shift is byte-aligned and the surviving field runs a whole
/// power-of-two past the input's end. Normalizes byte-granular right shifts into SUBPIECEs. All the
/// size arithmetic is signed (Ghidra `int4`).
pub struct RuleSubNormal;

impl Rule for RuleSubNormal {
    fn name(&self) -> &str {
        "subnormal"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let shiftout = data.op(op).input(0).unwrap();
        if !data.vn(shiftout).is_written() {
            return 0;
        }
        let shiftop = data.vn(shiftout).def.unwrap();
        let opc = data.op(shiftop).code();
        if opc != OpCode::IntRight && opc != OpCode::IntSright {
            return 0;
        }
        let sa = data.op(shiftop).input(1).unwrap();
        if !data.vn(sa).is_constant() {
            return 0;
        }
        let a = data.op(shiftop).input(0).unwrap();
        if data.vn(a).is_free() {
            return 0;
        }
        let outvn = data.op(op).output.unwrap();
        if data.vn(outvn).is_precis_hi() || data.vn(outvn).is_precis_lo() {
            return 0;
        }
        let mut n = data.vn(sa).constant_value() as i64;
        let mut c = data.vn(data.op(op).input(1).unwrap()).constant_value() as i64;
        let mut k = n / 8;
        let insize = data.vn(a).size as i64;
        let outsize = data.vn(outvn).size as i64;

        // Total shift + outsize must reach the size of the input (unless the shift is byte-aligned)
        if n + 8 * c + 8 * outsize < 8 * insize && n != k * 8 {
            return 0;
        }

        // If the cut window would extend past the original input
        if k + c + outsize > insize {
            let trunc_size = insize - c - k;
            if n == k * 8 && trunc_size > 0 && (trunc_size as u64).count_ones() == 1 {
                // We need an additional extension
                c += k;
                let ext_opc = if opc == OpCode::IntSright {
                    OpCode::IntSext
                } else {
                    OpCode::IntZext
                };
                let cconst = data.new_const(4, c as u64);
                let newop = data.new_op_before_sized(
                    op,
                    OpCode::Subpiece,
                    vec![a, cconst],
                    trunc_size as u32,
                );
                let newout = data.op(newop).output.unwrap();
                data.op_set_input(op, 0, newout);
                data.op_remove_input(op, 1);
                data.op_set_opcode(op, ext_opc);
                return 1;
            } else {
                k = insize - c - outsize; // Or we can shrink the cut
            }
        }

        // If n == k*8, the shift is unnecessary
        c += k;
        n -= k * 8;
        if n == 0 {
            data.op_set_input(op, 0, a);
            let cconst = data.new_const(4, c as u64);
            data.op_set_input(op, 1, cconst);
            return 1;
        } else if n >= outsize * 8 {
            n = outsize * 8; // Can only shift so far
            if opc == OpCode::IntSright {
                n -= 1;
            }
        }

        let cconst = data.new_const(4, c as u64);
        let newop = data.new_op_before_sized(op, OpCode::Subpiece, vec![a, cconst], outsize as u32);
        let newout = data.op(newop).output.unwrap();
        data.op_set_input(op, 0, newout);
        let nconst = data.new_const(4, n as u64);
        data.op_set_input(op, 1, nconst);
        data.op_set_opcode(op, opc);
        1
    }
}

/// Ghidra `RuleNegateIdentity` (ruleaction.cc:452): apply INT_NEGATE identities against a logical op
/// that reads both the negation output and its input — `V & ~V => 0`, `V | ~V => -1`, `V ^ ~V => -1`.
/// The reading AND/OR/XOR collapses to a COPY of the constant.
pub struct RuleNegateIdentity;

impl Rule for RuleNegateIdentity {
    fn name(&self) -> &str {
        "negateidentity"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntNegate]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn = data.op(op).input(0).unwrap();
        let out_vn = data.op(op).output.unwrap();
        for logic_op in data.vn(out_vn).descend.clone() {
            let opc = data.op(logic_op).code();
            if opc != OpCode::IntAnd && opc != OpCode::IntOr && opc != OpCode::IntXor {
                continue;
            }
            let slot = slot_of(data, logic_op, out_vn);
            if data.op(logic_op).input(1 - slot).unwrap() != vn {
                continue; // The other operand must be the un-negated value
            }
            // AND identity yields 0; OR/XOR identities yield the all-ones mask
            let value = if opc != OpCode::IntAnd {
                super::nzmask::calc_mask(data.vn(vn).size)
            } else {
                0
            };
            let c = data.new_const(data.vn(vn).size, value);
            data.op_set_input(logic_op, 0, c);
            data.op_remove_input(logic_op, 1);
            data.op_set_opcode(logic_op, OpCode::Copy);
            return 1;
        }
        0
    }
}

/// Ghidra `Funcdata::replaceLessequal` (funcdata_op.cc:1029): rewrite a `<=` comparison against a
/// constant as a `<` — `V <= c => V < (c+1)`, `c <= V => (c-1) < V` — for both the unsigned
/// (INT_LESSEQUAL→INT_LESS) and signed (INT_SLESSEQUAL→INT_SLESS) forms, adjusting the constant by
/// ±1. Bails when that would overflow (signed overflow for the signed form; the extremal
/// `<= 0`/`<= max` cases for the unsigned form). Returns whether it fired.
///
/// (Ghidra also `copySymbol`s the data-type/Symbol onto the new constant; mosura has no per-Varnode
/// symbol, so that is omitted — same as the subvarflow port.)
pub(crate) fn replace_lessequal(data: &mut Funcdata, op: OpId) -> bool {
    let in0 = data.op(op).input(0).unwrap();
    let in1 = data.op(op).input(1).unwrap();
    let (vn, diff, i) = if data.vn(in0).is_constant() {
        (in0, -1i64, 0usize)
    } else if data.vn(in1).is_constant() {
        (in1, 1i64, 1usize)
    } else {
        return false;
    };
    let size = data.vn(vn).size;
    let val = sign_extend_val(data.vn(vn).constant_value(), size, 8) as i64;
    if data.op(op).code() == OpCode::IntSlessequal {
        let vpd = val.wrapping_add(diff);
        if val < 0 && vpd > 0 {
            return false; // Check for sign overflow
        }
        if val > 0 && vpd < 0 {
            return false;
        }
        data.op_set_opcode(op, OpCode::IntSless);
    } else {
        // Check for unsigned overflow
        if diff == -1 && val == 0 {
            return false;
        }
        if diff == 1 && val == -1 {
            return false;
        }
        data.op_set_opcode(op, OpCode::IntLess);
    }
    let res = val.wrapping_add(diff) as u64 & super::nzmask::calc_mask(size);
    let newvn = data.new_const(size, res);
    data.op_set_input(op, i, newvn);
    true
}

/// Ghidra `RuleIntLessEqual` (ruleaction.cc:602): convert a `<=` comparison against a constant to a
/// `<` via [`replace_lessequal`] — `V <= c => V < (c+1)` (and the `c <= V` / signed forms).
pub struct RuleIntLessEqual;

impl Rule for RuleIntLessEqual {
    fn name(&self) -> &str {
        "intlessequal"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntLessequal, OpCode::IntSlessequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        u32::from(replace_lessequal(data, op))
    }
}

/// Ghidra `RuleCondNegate` (ruleaction.cc:5474, oppool1 @5607 "analysis"): flip a CBRANCH condition
/// to match the branch sense the structurer chose. When the structurer marks a CBRANCH
/// [`boolean_flip`](super::op::flags::BOOLEAN_FLIP) — meaning the branch is taken on the \e false
/// condition — this rule materializes that inversion in the IR: it inserts `BOOL_NEGATE(cond)`,
/// repoints the CBRANCH at the negated value, and flips the flag ([`op_flip_condition`]). The
/// fall-through block's true/false status is unchanged (`fallthru_true` stays). Downstream
/// [`RuleBoolNegate`] then absorbs the BOOL_NEGATE into the complementary comparison, so the printed
/// condition reads directly off the (now positive) IR — instead of being negated at print time.
///
/// [`op_flip_condition`]: Funcdata::op_flip_condition
pub struct RuleCondNegate;

impl Rule for RuleCondNegate {
    fn name(&self) -> &str {
        "condnegate"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Cbranch]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if !data.op(op).is_boolean_flip() {
            return 0;
        }
        let vn = data.op(op).input(1).unwrap();
        // Build BOOL_NEGATE(vn) just before the CBRANCH; the new unique output is the flipped value.
        let outvn = data.op_bool_negate(vn, op, false);
        data.op_set_input(op, 1, outvn);
        data.op_flip_condition(op); // Flip meaning of condition; fall-thru status unchanged.
        1
    }
}

/// Ghidra `RuleLess2Zero` (`ruleaction.cc`, oppool1 @5573 "analysis"): simplify INT_LESS against
/// extremal constants — `0 < V => 0 != V`, `V < 0 => false`, `-1(max) < V => false`,
/// `V < -1(max) => V != -1`.
pub struct RuleLess2Zero;

impl Rule for RuleLess2Zero {
    fn name(&self) -> &str {
        "less2zero"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntLess]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let lvn = data.op(op).input(0).unwrap();
        let rvn = data.op(op).input(1).unwrap();
        if data.vn(lvn).is_constant() {
            if data.vn(lvn).constant_value() == 0 {
                // All values except 0 are greater -> NOT_EQUAL
                data.op_set_opcode(op, OpCode::IntNotequal);
                return 1;
            } else if data.vn(lvn).constant_value() == super::nzmask::calc_mask(data.vn(lvn).size) {
                // max < V is always false
                let z = data.new_const(1, 0);
                data.op_set_opcode(op, OpCode::Copy);
                data.op_remove_input(op, 1);
                data.op_set_input(op, 0, z);
                return 1;
            }
        } else if data.vn(rvn).is_constant() {
            if data.vn(rvn).constant_value() == 0 {
                // V < 0 is always false
                let z = data.new_const(1, 0);
                data.op_set_opcode(op, OpCode::Copy);
                data.op_remove_input(op, 1);
                data.op_set_input(op, 0, z);
                return 1;
            } else if data.vn(rvn).constant_value() == super::nzmask::calc_mask(data.vn(rvn).size) {
                // All values except max are less -> NOT_EQUAL
                data.op_set_opcode(op, OpCode::IntNotequal);
                return 1;
            }
        }
        0
    }
}

/// Ghidra `RuleSLess2Zero::getHiBit` (ruleaction.cc:5641): if `op` (INT_ADD/INT_OR/INT_XOR) pieces
/// together two Varnodes only one of which can set the high (sign) bit, return that Varnode.
fn get_hi_bit(data: &Funcdata, op: OpId) -> Option<VarnodeId> {
    let opc = data.op(op).code();
    if opc != OpCode::IntAdd && opc != OpCode::IntOr && opc != OpCode::IntXor {
        return None;
    }
    let vn1 = data.op(op).input(0)?;
    let vn2 = data.op(op).input(1)?;
    let full = super::nzmask::calc_mask(data.vn(vn1).size);
    let mask = full ^ (full >> 1); // Only the high bit is set
    let nzmask1 = data.vn(vn1).get_nzmask();
    if nzmask1 != mask && (nzmask1 & mask) != 0 {
        return None; // vn1 sets the high bit AND some other bit
    }
    let nzmask2 = data.vn(vn2).get_nzmask();
    if nzmask2 != mask && (nzmask2 & mask) != 0 {
        return None;
    }
    if nzmask1 == mask {
        return Some(vn1);
    }
    if nzmask2 == mask {
        return Some(vn2);
    }
    None
}

/// Ghidra `RuleSLess2Zero` (ruleaction.cc:5693): simplify INT_SLESS against 0 or -1 by peeling off an
/// operation that only affects the sign bit. Each form has a mirror against the other extremum:
///   - `-1 s< SUB(V,#hi)  =>  -1 s< V`      /  `SUB(V,#hi) s< 0  =>  V s< 0`   (SUBPIECE of the top piece)
///   - `-1 s< ~V          =>  V s< 0`       /  `~V s< 0          =>  -1 s< V`
///   - `-1 s< (V & 0x8..) =>  -1 s< V`      /  `(V & 0x8..) s< 0 =>  V s< 0`   (mask keeps only the sign bit)
///   - `-1 s< CONCAT(V,W) =>  -1 s< V`      /  `CONCAT(V,W) s< 0 =>  V s< 0`   (V is the most-significant piece)
///   - `-1 s< (hi ^ lo)   =>  0 == hi`      /  `(hi ^ lo) s< 0   =>  hi != 0`  (via [`get_hi_bit`])
///   - `-1 s< (bool << 8*sz-1)  =>  !bool`
///
/// NB (same divergence as [`RuleSubCancel`]): mosura's `is_free` treats a constant as *not* free
/// (Ghidra's `isFree` treats it as free), so the `avn->isFree()` bail-outs behave identically for the
/// only reachable case (a genuinely undefined feed varnode) — a constant `avn` would already have been
/// const-folded before reaching a sign-only op here.
pub struct RuleSLess2Zero;

impl Rule for RuleSLess2Zero {
    fn name(&self) -> &str {
        "sless2zero"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSless]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let lvn = data.op(op).input(0).unwrap();
        let rvn = data.op(op).input(1).unwrap();

        if data.vn(lvn).is_constant() {
            if !data.vn(rvn).is_written() {
                return 0;
            }
            if data.vn(lvn).constant_value() != super::nzmask::calc_mask(data.vn(lvn).size) {
                return 0; // lvn is a constant, but not -1
            }
            // We have  -1 s< rvn
            let feed_op = data.vn(rvn).def.unwrap();
            let feed_code = data.op(feed_op).code();
            if let Some(hibit) = get_hi_bit(data, feed_op) {
                // -1 s< (hi ^ lo)  =>  0 == hi
                if data.vn(hibit).is_constant() {
                    let c = data.new_const(data.vn(hibit).size, data.vn(hibit).constant_value());
                    data.op_set_input(op, 1, c);
                } else {
                    data.op_set_input(op, 1, hibit);
                }
                data.op_set_opcode(op, OpCode::IntEqual);
                let z = data.new_const(data.vn(hibit).size, 0);
                data.op_set_input(op, 0, z);
                return 1;
            } else if feed_code == OpCode::Subpiece {
                let avn = data.op(feed_op).input(0).unwrap();
                if data.vn(avn).is_free() || data.vn(avn).size > 8 {
                    return 0; // Don't create a comparison bigger than 8 bytes
                }
                let hi_off = data.vn(data.op(feed_op).input(1).unwrap()).constant_value();
                if data.vn(rvn).size as u64 + hi_off == data.vn(avn).size as u64 {
                    // -1 s< SUB(avn,#hi)  =>  -1 s< avn
                    data.op_set_input(op, 1, avn);
                    let c = data.new_const(
                        data.vn(avn).size,
                        super::nzmask::calc_mask(data.vn(avn).size),
                    );
                    data.op_set_input(op, 0, c);
                    return 1;
                }
            } else if feed_code == OpCode::IntNegate {
                // -1 s< ~avn  =>  avn s< 0
                let avn = data.op(feed_op).input(0).unwrap();
                if data.vn(avn).is_free() {
                    return 0;
                }
                data.op_set_input(op, 0, avn);
                let z = data.new_const(data.vn(avn).size, 0);
                data.op_set_input(op, 1, z);
                return 1;
            } else if feed_code == OpCode::IntAnd {
                let avn = data.op(feed_op).input(0).unwrap();
                if data.vn(avn).is_free() || lone_descend(data, rvn).is_none() {
                    return 0;
                }
                let mask_vn = data.op(feed_op).input(1).unwrap();
                if data.vn(mask_vn).is_constant() {
                    // Fetch the sign bit of the mask
                    let mask = data
                        .vn(mask_vn)
                        .constant_value()
                        .checked_shr(8 * data.vn(avn).size - 1)
                        .unwrap_or(0);
                    if (mask & 1) != 0 {
                        // -1 s< (avn & 0x8..)  =>  -1 s< avn
                        data.op_set_input(op, 1, avn);
                        return 1;
                    }
                }
            } else if feed_code == OpCode::Piece {
                // -1 s< CONCAT(V,W)  =>  -1 s< V   (V = most-significant piece)
                let avn = data.op(feed_op).input(0).unwrap();
                if data.vn(avn).is_free() {
                    return 0;
                }
                data.op_set_input(op, 1, avn);
                let c = data.new_const(
                    data.vn(avn).size,
                    super::nzmask::calc_mask(data.vn(avn).size),
                );
                data.op_set_input(op, 0, c);
                return 1;
            } else if feed_code == OpCode::IntLeft {
                let coeff = data.op(feed_op).input(1).unwrap();
                if !data.vn(coeff).is_constant()
                    || data.vn(coeff).constant_value() != data.vn(lvn).size as u64 * 8 - 1
                {
                    return 0;
                }
                let avn = data.op(feed_op).input(0).unwrap();
                if !data.vn(avn).is_written()
                    || !data.op(data.vn(avn).def.unwrap()).is_bool_output()
                {
                    return 0;
                }
                // -1 s< (bool << #8*sz-1)  =>  !bool
                data.op_set_opcode(op, OpCode::BoolNegate);
                data.op_remove_input(op, 1);
                data.op_set_input(op, 0, avn);
                return 1;
            }
        } else if data.vn(rvn).is_constant() {
            if !data.vn(lvn).is_written() {
                return 0;
            }
            if data.vn(rvn).constant_value() != 0 {
                return 0;
            }
            // We have  lvn s< 0
            let feed_op = data.vn(lvn).def.unwrap();
            let feed_code = data.op(feed_op).code();
            if let Some(hibit) = get_hi_bit(data, feed_op) {
                // (hi ^ lo) s< 0  =>  hi != 0
                if data.vn(hibit).is_constant() {
                    let c = data.new_const(data.vn(hibit).size, data.vn(hibit).constant_value());
                    data.op_set_input(op, 0, c);
                } else {
                    data.op_set_input(op, 0, hibit);
                }
                data.op_set_opcode(op, OpCode::IntNotequal);
                return 1;
            } else if feed_code == OpCode::Subpiece {
                let avn = data.op(feed_op).input(0).unwrap();
                if data.vn(avn).is_free() || data.vn(avn).size > 8 {
                    return 0; // Don't create a comparison greater than 8 bytes
                }
                let hi_off = data.vn(data.op(feed_op).input(1).unwrap()).constant_value();
                if data.vn(lvn).size as u64 + hi_off == data.vn(avn).size as u64 {
                    // SUB(avn,#hi) s< 0  =>  avn s< 0
                    data.op_set_input(op, 0, avn);
                    let z = data.new_const(data.vn(avn).size, 0);
                    data.op_set_input(op, 1, z);
                    return 1;
                }
            } else if feed_code == OpCode::IntNegate {
                // ~avn s< 0  =>  -1 s< avn
                let avn = data.op(feed_op).input(0).unwrap();
                if data.vn(avn).is_free() {
                    return 0;
                }
                data.op_set_input(op, 1, avn);
                let c = data.new_const(
                    data.vn(avn).size,
                    super::nzmask::calc_mask(data.vn(avn).size),
                );
                data.op_set_input(op, 0, c);
                return 1;
            } else if feed_code == OpCode::IntAnd {
                let avn = data.op(feed_op).input(0).unwrap();
                if data.vn(avn).is_free() || lone_descend(data, lvn).is_none() {
                    return 0;
                }
                let mask_vn = data.op(feed_op).input(1).unwrap();
                if data.vn(mask_vn).is_constant() {
                    // Fetch the sign bit of the mask
                    let mask = data
                        .vn(mask_vn)
                        .constant_value()
                        .checked_shr(8 * data.vn(avn).size - 1)
                        .unwrap_or(0);
                    if (mask & 1) != 0 {
                        // (avn & 0x8..) s< 0  =>  avn s< 0
                        data.op_set_input(op, 0, avn);
                        return 1;
                    }
                }
            } else if feed_code == OpCode::Piece {
                // CONCAT(V,W) s< 0  =>  V s< 0   (V = most-significant piece)
                let avn = data.op(feed_op).input(0).unwrap();
                if data.vn(avn).is_free() {
                    return 0;
                }
                data.op_set_input(op, 0, avn);
                let z = data.new_const(data.vn(avn).size, 0);
                data.op_set_input(op, 1, z);
                return 1;
            }
        }
        0
    }
}

/// Ghidra `RuleOrConsume` (`ruleaction.cc`, oppool1 @5530 "analysis"): drop an OR/XOR input whose
/// non-zero bits are all unconsumed downstream — `A | B => B` (or `A`) when `nzm(other) & consume(out)
/// == 0`. The op becomes a COPY of the surviving input.
pub struct RuleOrConsume;

impl Rule for RuleOrConsume {
    fn name(&self) -> &str {
        "orconsume"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntOr, OpCode::IntXor]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(outvn) = data.op(op).output else { return 0 };
        let size = data.vn(outvn).size;
        if size > 8 {
            return 0; // FIXME: uintb should be arbitrary precision (Ghidra's `size > sizeof(uintb)`)
        }
        let consume = data.vn(outvn).get_consume();
        let in0 = data.op(op).input(0).unwrap();
        let in1 = data.op(op).input(1).unwrap();
        if (consume & data.vn(in0).get_nzmask()) == 0 {
            data.op_remove_input(op, 0);
            data.op_set_opcode(op, OpCode::Copy);
            1
        } else if (consume & data.vn(in1).get_nzmask()) == 0 {
            data.op_remove_input(op, 1);
            data.op_set_opcode(op, OpCode::Copy);
            1
        } else {
            0
        }
    }
}

/// Ghidra `RuleEqual2Constant` (`ruleaction.cc`, oppool1 @5555 "analysis"): fold a constant through an
/// arithmetic operand of INT_EQUAL/INT_NOTEQUAL — `V*-1 == c => V == -c`, `V+c == d => V == d-c`,
/// `~V == c => V == ~c` — provided `V` is only used in similar constant comparisons.
pub struct RuleEqual2Constant;

impl Rule for RuleEqual2Constant {
    fn name(&self) -> &str {
        "equal2constant"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntEqual, OpCode::IntNotequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let cvn = data.op(op).input(1).unwrap();
        if !data.vn(cvn).is_constant() {
            return 0;
        }
        let lhs = data.op(op).input(0).unwrap();
        if !data.vn(lhs).is_written() {
            return 0;
        }
        let leftop = data.vn(lhs).def.unwrap();
        let opc = data.op(leftop).code();
        let cval = data.vn(cvn).constant_value();
        let newconst: u64 = if opc == OpCode::IntAdd {
            let otherconst = data.op(leftop).input(1).unwrap();
            if !data.vn(otherconst).is_constant() {
                return 0;
            }
            cval.wrapping_sub(data.vn(otherconst).constant_value())
                & super::nzmask::calc_mask(data.vn(cvn).size)
        } else if opc == OpCode::IntMult {
            // The only multiply we transform is multiply by -1.
            let otherconst = data.op(leftop).input(1).unwrap();
            if !data.vn(otherconst).is_constant() {
                return 0;
            }
            if data.vn(otherconst).constant_value() != super::nzmask::calc_mask(data.vn(otherconst).size) {
                return 0;
            }
            cval.wrapping_neg() & super::nzmask::calc_mask(data.vn(otherconst).size)
        } else if opc == OpCode::IntNegate {
            !cval & super::nzmask::calc_mask(data.vn(lhs).size)
        } else {
            return 0;
        };

        let a = data.op(leftop).input(0).unwrap();
        if data.vn(a).is_free() {
            return 0;
        }
        // Make sure the transformed form of `a` is only used in comparisons of similar form.
        for dop in data.vn(lhs).descend.clone() {
            if dop == op {
                continue;
            }
            let dc = data.op(dop).code();
            if dc != OpCode::IntEqual && dc != OpCode::IntNotequal {
                return 0;
            }
            if !data.vn(data.op(dop).input(1).unwrap()).is_constant() {
                return 0;
            }
        }

        let asize = data.vn(a).size;
        data.op_set_input(op, 0, a);
        let c = data.new_const(asize, newconst);
        data.op_set_input(op, 1, c);
        1
    }
}

/// Ghidra `sign_extend(uintb in, int4 sizein, int4 sizeout)` (address.cc): treat `val` as a
/// `sizein`-byte value, sign-extend it, and truncate the result to `sizeout` bytes. Only used with
/// `sizein <= 8` here (the SDIV/SREM constant-divisor check).
fn sign_extend_val(val: u64, sizein: u32, sizeout: u32) -> u64 {
    let bit = sizein * 8;
    let sval = if bit == 0 || bit >= 64 {
        val
    } else {
        (((val << (64 - bit)) as i64) >> (64 - bit)) as u64
    };
    sval & super::nzmask::calc_mask(sizeout)
}

/// Ghidra `RuleSubCommute::shortenExtension` (ruleaction.cc:4463): replace the output of an
/// INT_ZEXT/INT_SEXT `ext_op` with a `max_size`-byte truncation at the same address. mosura is
/// little-endian (x86-64), so the output stays at the same address — Ghidra's big-endian
/// `addr + (size - maxSize)` adjustment never applies. Returns the new smaller output Varnode.
/// (`new_output` unsets the extension's old output, matching Ghidra's `opUnsetOutput`.)
fn shorten_extension(data: &mut Funcdata, ext_op: OpId, max_size: u32) -> VarnodeId {
    let orig_out = data.op(ext_op).output.unwrap();
    let addr = data.vn(orig_out).loc;
    data.new_output(ext_op, max_size, addr)
}

/// Ghidra `RuleSubCommute::cancelExtensions` (ruleaction.cc:4483): eliminate the input extensions on
/// binary `longform` (a DIV/REM/SDIV/SREM whose two inputs are ZEXT/SEXT) whose output is truncated
/// by `sub_op`. This is the PARTIAL commute — the SUBPIECE stays but the extensions are removed and
/// `longform` is narrowed to the larger of the two pre-extension operand sizes. Returns true when it
/// modified the graph.
fn cancel_extensions(
    data: &mut Funcdata,
    longform: OpId,
    sub_op: OpId,
    mut ext0_in: VarnodeId,
    mut ext1_in: VarnodeId,
) -> bool {
    let outvn = data.op(longform).output.unwrap();
    if lone_descend(data, outvn) != Some(sub_op) {
        return false; // Must be exactly one output to SUBPIECE
    }
    let (s0, s1) = (data.vn(ext0_in).size, data.vn(ext1_in).size);
    let max_size;
    if s0 == s1 {
        max_size = s0;
        if data.vn(ext0_in).is_free() || data.vn(ext1_in).is_free() {
            return false; // Must be able to propagate inputs
        }
    } else if s0 < s1 {
        max_size = s1;
        if data.vn(ext1_in).is_free() {
            return false;
        }
        let lin0 = data.op(longform).input(0).unwrap();
        if lone_descend(data, lin0) != Some(longform) {
            return false;
        }
        ext0_in = shorten_extension(data, data.vn(lin0).def.unwrap(), max_size);
    } else {
        max_size = s0;
        if data.vn(ext0_in).is_free() {
            return false;
        }
        let lin1 = data.op(longform).input(1).unwrap();
        if lone_descend(data, lin1) != Some(longform) {
            return false;
        }
        ext1_in = shorten_extension(data, data.vn(lin1).def.unwrap(), max_size);
    }
    // Create the truncated form of longform's output (new_output_unique unsets the old output).
    let newout = data.new_output_unique(longform, max_size);
    data.op_set_input(longform, 0, ext0_in);
    data.op_set_input(longform, 1, ext1_in);
    data.op_set_input(sub_op, 0, newout);
    true
}

/// Ghidra `RuleSubCommute` (ruleaction.cc:4514): commute a SUBPIECE with the operation defining its
/// input, pushing the truncation earlier in the expression tree (preferring short forms of ops) so
/// it can run into a constant / INT_ZEXT / INT_SEXT and cancel. Commutes with INT_LEFT (offset 0,
/// shifted value a ZEXT/PIECE), INT_DIV/REM (zero-extended inputs), INT_SDIV/SREM (sign-extended
/// inputs), INT_ADD/MULT (least-significant SUBPIECE only), and the bitwise INT_NEGATE/XOR/AND/OR
/// (any offset). The DIV/REM families additionally support a PARTIAL commute via [`cancel_extensions`]
/// when the extensions are wider than the SUBPIECE output.
pub struct RuleSubCommute;

impl Rule for RuleSubCommute {
    fn name(&self) -> &str {
        "subcommute"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    // `new_vn.unwrap()` mirrors Ghidra's non-null `newvn` deref; the compound `|| new_vn.is_none()`
    // guard makes the else branch reachable only when `new_vn` is Some (faithful null-pointer idiom)
    #[allow(clippy::unnecessary_unwrap)]
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let base = data.op(op).input(0).unwrap();
        if !data.vn(base).is_written() {
            return 0;
        }
        let offset = data.vn(data.op(op).input(1).unwrap()).constant_value();
        let outvn = data.op(op).output.unwrap();
        if data.vn(outvn).is_precis_lo() || data.vn(outvn).is_precis_hi() {
            return 0;
        }
        let outsize = data.vn(outvn).size;
        let insize = data.vn(base).size;
        let longform = data.vn(base).def.unwrap();
        let mut j: i64 = -1;
        match data.op(longform).code() {
            OpCode::IntLeft => {
                j = 1; // Special processing for shift amount param
                if offset != 0 {
                    return 0;
                }
                let lin0 = data.op(longform).input(0).unwrap();
                if data.vn(lin0).is_written() {
                    let opc = data.op(data.vn(lin0).def.unwrap()).code();
                    if opc != OpCode::IntZext && opc != OpCode::Piece {
                        return 0;
                    }
                } else {
                    return 0;
                }
            }
            OpCode::IntRem | OpCode::IntDiv => {
                // Only commutes if inputs are zero extended
                if offset != 0 {
                    return 0;
                }
                let lin0 = data.op(longform).input(0).unwrap();
                if !data.vn(lin0).is_written() {
                    return 0;
                }
                let zext0 = data.vn(lin0).def.unwrap();
                if data.op(zext0).code() != OpCode::IntZext {
                    return 0;
                }
                let zext0_in = data.op(zext0).input(0).unwrap();
                let lin1 = data.op(longform).input(1).unwrap();
                if data.vn(lin1).is_written() {
                    let zext1 = data.vn(lin1).def.unwrap();
                    if data.op(zext1).code() != OpCode::IntZext {
                        return 0;
                    }
                    let zext1_in = data.op(zext1).input(0).unwrap();
                    if data.vn(zext1_in).size > outsize || data.vn(zext0_in).size > outsize {
                        // Special case: SUBPIECE cancels the ZEXTs but some SUBPIECE remains
                        if cancel_extensions(data, longform, op, zext0_in, zext1_in) {
                            return 1; // Leave SUBPIECE intact
                        }
                        return 0;
                    }
                    // If ZEXT sizes are both not bigger, go ahead and commute (fallthru)
                } else if data.vn(lin1).is_constant() && data.vn(zext0_in).size <= outsize {
                    let val = data.vn(lin1).constant_value();
                    let smallval = val & super::nzmask::calc_mask(outsize);
                    if val != smallval {
                        return 0;
                    }
                } else {
                    return 0;
                }
            }
            OpCode::IntSrem | OpCode::IntSdiv => {
                // Only commutes if inputs are sign extended
                if offset != 0 {
                    return 0;
                }
                let lin0 = data.op(longform).input(0).unwrap();
                if !data.vn(lin0).is_written() {
                    return 0;
                }
                let sext0 = data.vn(lin0).def.unwrap();
                if data.op(sext0).code() != OpCode::IntSext {
                    return 0;
                }
                let sext0_in = data.op(sext0).input(0).unwrap();
                let lin1 = data.op(longform).input(1).unwrap();
                if data.vn(lin1).is_written() {
                    let sext1 = data.vn(lin1).def.unwrap();
                    if data.op(sext1).code() != OpCode::IntSext {
                        return 0;
                    }
                    let sext1_in = data.op(sext1).input(0).unwrap();
                    if data.vn(sext1_in).size > outsize || data.vn(sext0_in).size > outsize {
                        // Special case: SUBPIECE cancels the SEXTs but some SUBPIECE remains
                        if cancel_extensions(data, longform, op, sext0_in, sext1_in) {
                            return 1; // Leave SUBPIECE intact
                        }
                        return 0;
                    }
                    // If SEXT sizes are both not bigger, go ahead and commute (fallthru)
                } else if data.vn(lin1).is_constant() && data.vn(sext0_in).size <= outsize {
                    let val = data.vn(lin1).constant_value();
                    let smallval = val & super::nzmask::calc_mask(outsize);
                    let smallval = sign_extend_val(smallval, outsize, insize);
                    if val != smallval {
                        return 0;
                    }
                } else {
                    return 0;
                }
            }
            OpCode::IntAdd => {
                if offset != 0 {
                    return 0; // Only commutes with least significant SUBPIECE
                }
                if data.vn(data.op(longform).input(0).unwrap()).is_spacebase() {
                    return 0; // Deconflict with RulePtrArith
                }
            }
            OpCode::IntMult => {
                if offset != 0 {
                    return 0; // Only commutes with least significant SUBPIECE
                }
            }
            // Bitwise ops, type of subpiece doesn't matter
            OpCode::IntNegate | OpCode::IntXor | OpCode::IntAnd | OpCode::IntOr => {}
            _ => return 0, // Most ops don't commute
        }

        // Make sure no other piece of base is getting used
        if lone_descend(data, base) != Some(op) {
            return 0;
        }

        if offset == 0 {
            // Look for overlap with RuleSubZext
            if let Some(nextop) = lone_descend(data, outvn) {
                if data.op(nextop).code() == OpCode::IntZext
                    && data.vn(data.op(nextop).output.unwrap()).size == insize
                {
                    return 0;
                }
            }
        }

        let mut last_in: Option<VarnodeId> = None;
        let mut new_vn: Option<VarnodeId> = None;
        let ninput = data.op(longform).num_inputs();
        for i in 0..ninput {
            let vn = data.op(longform).input(i).unwrap();
            if i as i64 != j {
                if last_in != Some(vn) || new_vn.is_none() {
                    // Don't duplicate the SUBPIECE if consecutive inputs are the same varnode
                    let off_c = data.new_const(4, offset);
                    let newsub =
                        data.new_op_before_sized(longform, OpCode::Subpiece, vec![vn, off_c], outsize);
                    let nv = data.op(newsub).output.unwrap();
                    data.op_set_input(longform, i, nv);
                    new_vn = Some(nv);
                } else {
                    data.op_set_input(longform, i, new_vn.unwrap());
                }
            }
            last_in = Some(vn);
        }
        data.op_set_output(longform, outvn); // longform now produces the truncated value
        data.op_destroy(op); // Get rid of old SUBPIECE
        1
    }
}

/// Ghidra `TypeOp::floatSignManipulation` (typeop.cc:153): recognize the integer bit-twiddle a
/// compiler emits to manipulate an IEEE sign bit, returning the float op it really is. An
/// `INT_AND` with the all-but-the-top-bit mask clears the sign — `FLOAT_ABS`; an `INT_XOR` with
/// the top-bit-only mask flips it — `FLOAT_NEG`. Returns `None` (Ghidra's `CPUI_MAX`) otherwise.
///
/// Shared by [`RuleFloatSign`] and `RuleFloatSignCleanup`, exactly as in Ghidra. (Ghidra's other
/// two callers are `TypeOpIntXor::propagateType`/`TypeOpIntAnd::propagateType` (typeop.cc:1428/
/// 1461), which let a float type propagate through the manipulation — not ported yet, so a
/// float-typed operand does not yet reach these ops through type inference.)
pub fn float_sign_manipulation(data: &Funcdata, op: OpId) -> Option<OpCode> {
    let opc = data.op(op).code();
    let cvn = data.op(op).input(1)?;
    if !data.vn(cvn).is_constant() {
        return None;
    }
    let full = super::nzmask::calc_mask(data.vn(cvn).size);
    match opc {
        OpCode::IntAnd if (full >> 1) == data.vn(cvn).constant_value() => Some(OpCode::FloatAbs),
        OpCode::IntXor if (full ^ (full >> 1)) == data.vn(cvn).constant_value() => {
            Some(OpCode::FloatNeg)
        }
        _ => None,
    }
}

/// Ghidra `RuleLessOne` (ruleaction.cc:2233, coreaction.cc:5611): a comparison against the
/// boundary of the unsigned range has only one possible non-trivial answer — `V < 1` and
/// `V <= 0` both mean `V == 0`. Rewrite to `INT_EQUAL`, replacing the constant with zero for
/// the `INT_LESS` form.
pub struct RuleLessOne;

impl Rule for RuleLessOne {
    fn name(&self) -> &str {
        "lessone"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntLess, OpCode::IntLessequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(constvn) = data.op(op).input(1) else { return 0 };
        if !data.vn(constvn).is_constant() {
            return 0;
        }
        let val = data.vn(constvn).constant_value();
        if data.op(op).code() == OpCode::IntLess && val != 1 {
            return 0;
        }
        if data.op(op).code() == OpCode::IntLessequal && val != 0 {
            return 0;
        }
        data.op_set_opcode(op, OpCode::IntEqual);
        if val != 0 {
            let size = data.vn(constvn).size;
            let zero = data.new_const(size, 0);
            data.op_set_input(op, 1, zero);
        }
        1
    }
}

/// Ghidra `RuleXorSwap` (ruleaction.cc:6055, coreaction.cc:5617): undo the XOR swap idiom —
/// `V ^ (V ^ W)` is `W`. Either input may hold the inner XOR, and either of the inner XOR's
/// operands may be the shared one; the surviving operand must not be free, so the COPY has a
/// definition to read.
pub struct RuleXorSwap;

impl Rule for RuleXorSwap {
    fn name(&self) -> &str {
        "xorswap"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntXor]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        for i in 0..2 {
            let Some(vn) = data.op(op).input(i) else { continue };
            if !data.vn(vn).is_written() {
                continue;
            }
            let op2 = data.vn(vn).def.unwrap();
            if data.op(op2).code() != OpCode::IntXor {
                continue;
            }
            let othervn = data.op(op).input(1 - i);
            let (Some(vn0), Some(vn1)) = (data.op(op2).input(0), data.op(op2).input(1)) else {
                continue;
            };
            let keep = if othervn == Some(vn0) && !data.vn(vn1).is_free() {
                vn1
            } else if othervn == Some(vn1) && !data.vn(vn0).is_free() {
                vn0
            } else {
                continue;
            };
            data.op_remove_input(op, 1);
            data.op_set_opcode(op, OpCode::Copy);
            data.op_set_input(op, 0, keep);
            return 1;
        }
        0
    }
}

/// Ghidra `RuleLzcountShiftBool` (ruleaction.cc:6100, coreaction.cc:5618): a shifted count of
/// leading zeros used as a boolean is an equality test. `LZCOUNT(V) >> k == 1` exactly when `V`
/// is zero, provided `8*|V|` — lzcount's maximum — is a power of two and `max >> k == 1`.
/// Rewrite the shift's input to a fresh `V == 0` and keep the shift op as the width adapter:
/// a COPY when its output is already boolean-sized, an `INT_ZEXT` otherwise.
///
/// The power-of-two guard is Ghidra's own (a 24-bit maximum would make both `16 >> 4` and
/// `24 >> 4` equal 1, so the test would not mean "zero").
pub struct RuleLzcountShiftBool;

impl Rule for RuleLzcountShiftBool {
    fn name(&self) -> &str {
        "lzcountshiftbool"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Lzcount]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(outvn) = data.op(op).output else { return 0 };
        let Some(invn) = data.op(op).input(0) else { return 0 };
        let insize = data.vn(invn).size;
        let max_return = 8u64 * insize as u64;
        if max_return.count_ones() != 1 {
            return 0;
        }
        for base_op in data.vn(outvn).descend.clone() {
            let opc = data.op(base_op).code();
            if opc != OpCode::IntRight && opc != OpCode::IntSright {
                continue;
            }
            let Some(vn1) = data.op(base_op).input(1) else { continue };
            if !data.vn(vn1).is_constant() {
                continue;
            }
            let shift = data.vn(vn1).constant_value();
            if shift >= 64 || (max_return >> shift) != 1 {
                continue;
            }
            let pc = data.op(base_op).seqnum.pc;
            let uniq = data.num_ops() as u32;
            let zero = data.new_const(insize, 0);
            let new_op = data.new_op(OpCode::IntEqual, SeqNum { pc, uniq }, vec![invn, zero]);
            // INT_EQUAL must produce a 1-byte boolean result.
            let eq_res = data.new_output_unique(new_op, 1);
            data.op_insert_before(new_op, base_op);
            // The shift's readers expect the old output width, so the shift op stays as the
            // adapter: COPY when that width is already 1, INT_ZEXT otherwise.
            data.op_remove_input(base_op, 1);
            let out_size = data.op(base_op).output.map(|o| data.vn(o).size).unwrap_or(0);
            let adapt = if out_size == 1 { OpCode::Copy } else { OpCode::IntZext };
            data.op_set_opcode(base_op, adapt);
            data.op_set_input(base_op, 0, eq_res);
            return 1;
        }
        0
    }
}

/// Ghidra `RuleFloatSign` (ruleaction.cc:10716, coreaction.cc:5619): once a value is known to be
/// floating point — because a float op reads or writes it — an integer sign manipulation on that
/// value is really `FLOAT_ABS`/`FLOAT_NEG`. Convert every such neighbour of a float op:
/// the ops defining its inputs (except for `FLOAT_INT2FLOAT`, whose input is an integer) and the
/// ops reading its output (unless the output is boolean or the op is `FLOAT_TRUNC`, whose output
/// is an integer). See [`float_sign_manipulation`] for the two recognized forms.
pub struct RuleFloatSign;

impl Rule for RuleFloatSign {
    fn name(&self) -> &str {
        "floatsign"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![
            OpCode::FloatEqual,
            OpCode::FloatNotequal,
            OpCode::FloatLess,
            OpCode::FloatLessequal,
            OpCode::FloatNan,
            OpCode::FloatAdd,
            OpCode::FloatDiv,
            OpCode::FloatMult,
            OpCode::FloatSub,
            OpCode::FloatNeg,
            OpCode::FloatAbs,
            OpCode::FloatSqrt,
            OpCode::FloatFloat2float,
            OpCode::FloatCeil,
            OpCode::FloatFloor,
            OpCode::FloatRound,
            OpCode::FloatInt2float,
            OpCode::FloatTrunc,
        ]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let mut res = 0;
        let opc = data.op(op).code();
        if opc != OpCode::FloatInt2float {
            let mut slots = vec![0usize];
            if data.op(op).num_inputs() == 2 {
                slots.push(1);
            }
            for slot in slots {
                let Some(vn) = data.op(op).input(slot) else { continue };
                if !data.vn(vn).is_written() {
                    continue;
                }
                let sign_op = data.vn(vn).def.unwrap();
                if let Some(res_code) = float_sign_manipulation(data, sign_op) {
                    data.op_remove_input(sign_op, 1);
                    data.op_set_opcode(sign_op, res_code);
                    res = 1;
                }
            }
        }
        if data.op(op).is_bool_output() || opc == OpCode::FloatTrunc {
            return res;
        }
        let Some(outvn) = data.op(op).output else { return res };
        for read_op in data.vn(outvn).descend.clone() {
            if let Some(res_code) = float_sign_manipulation(data, read_op) {
                data.op_remove_input(read_op, 1);
                data.op_set_opcode(read_op, res_code);
                res = 1;
            }
        }
        res
    }
}

/// Ghidra `RuleNegateNegate` (ruleaction.cc:9040, coreaction.cc:5629): `~~V` is `V`. The inner
/// operand must not be free, so the COPY has a definition to read.
pub struct RuleNegateNegate;

impl Rule for RuleNegateNegate {
    fn name(&self) -> &str {
        "negatenegate"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntNegate]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(vn1) = data.op(op).input(0) else { return 0 };
        if !data.vn(vn1).is_written() {
            return 0;
        }
        let neg2 = data.vn(vn1).def.unwrap();
        if data.op(neg2).code() != OpCode::IntNegate {
            return 0;
        }
        let Some(vn2) = data.op(neg2).input(0) else { return 0 };
        if data.vn(vn2).is_free() {
            return 0;
        }
        data.op_set_input(op, 0, vn2);
        data.op_set_opcode(op, OpCode::Copy);
        1
    }
}

/// Ghidra `RuleFuncPtrEncoding` (ruleaction.cc:9905, coreaction.cc:5632): on a target whose
/// function pointers are aligned, the compiler masks off the low bits before an indirect call —
/// those bits encode something else (ARM/THUMB's instruction-set selector, say), not part of the
/// address. The mask is noise in the decompiled output, so drop it.
///
/// Fires only when the compiler spec sets `<funcptr align=>` (see
/// [`crate::analysis::cspec::funcptr_align`]) — never on x86, where the element is absent and
/// `funcptr_align` is 0. Faithfully inert there rather than absent.
pub struct RuleFuncPtrEncoding;

impl Rule for RuleFuncPtrEncoding {
    fn name(&self) -> &str {
        "funcptrencoding"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Callind]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let align = data.funcptr_align;
        if align == 0 {
            return 0;
        }
        let Some(vn) = data.op(op).input(0) else { return 0 };
        if !data.vn(vn).is_written() {
            return 0;
        }
        let andop = data.vn(vn).def.unwrap();
        if data.op(andop).code() != OpCode::IntAnd {
            return 0;
        }
        let Some(maskvn) = data.op(andop).input(1) else { return 0 };
        if !data.vn(maskvn).is_constant() {
            return 0;
        }
        let val = data.vn(maskvn).constant_value();
        let testmask = super::nzmask::calc_mask(data.vn(maskvn).size);
        let slide = u64::MAX << align;
        if (testmask & slide) == val {
            // 1-bit encoding: eliminate the mask.
            data.op_remove_input(andop, 1);
            data.op_set_opcode(andop, OpCode::Copy);
            return 1;
        }
        0
    }
}

/// Ghidra `TypeOpFloatInt2Float::preferredZextSize` (typeop.cc:1911): the integer width to zero-
/// extend to before an unsigned int-to-float conversion, so the conversion's input has a spare
/// sign bit. Duplicated from [`super::subvarflow::preferred_zext_size`]'s private copy at the two
/// call sites Ghidra has (RuleUnsigned2Float, RuleInt2FloatCollapse).
fn preferred_zext_size(in_size: u32) -> u32 {
    if in_size < 4 {
        4
    } else if in_size < 8 {
        8
    } else {
        in_size + 1
    }
}

/// Ghidra `RuleUnsigned2Float` (ruleaction.cc:10554, coreaction.cc:5636): recognize the
/// unsigned-to-float idiom a compiler emits when the hardware only converts SIGNED integers. For a
/// value with the high bit possibly set, it halves (rounding toward the odd bit), converts, and
/// doubles:
///
/// ```text
/// x = (V >> 1) | (V & 1)        // halve, keeping the low bit so rounding is correct
/// f = (float)x                  // signed conversion, now safe
/// f + f                         // double it back
/// ```
///
/// Collapse the whole thing to a single unsigned conversion — `FLOAT_INT2FLOAT(ZEXT(V))`, the form
/// the printer renders as an unsigned cast. The AND may be reached through an `INT_ZEXT`, and the
/// shift's operand through a zero-offset `SUBPIECE`; both indirections are Ghidra's.
pub struct RuleUnsigned2Float;

impl Rule for RuleUnsigned2Float {
    fn name(&self) -> &str {
        "unsigned2float"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::FloatInt2float]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(invn) = data.op(op).input(0) else { return 0 };
        if !data.vn(invn).is_written() {
            return 0;
        }
        let orop = data.vn(invn).def.unwrap();
        if data.op(orop).code() != OpCode::IntOr {
            return 0;
        }
        let (Some(or0), Some(or1)) = (data.op(orop).input(0), data.op(orop).input(1)) else {
            return 0;
        };
        if !data.vn(or0).is_written() || !data.vn(or1).is_written() {
            return 0;
        }
        let mut shiftop = data.vn(or0).def.unwrap();
        let mut andop = data.vn(or1).def.unwrap();
        if data.op(shiftop).code() != OpCode::IntRight {
            andop = shiftop;
            shiftop = data.vn(or1).def.unwrap();
        }
        if data.op(shiftop).code() != OpCode::IntRight {
            return 0;
        }
        // Shift to the right by 1 exactly, to clear the high bit.
        if !constant_match(data, data.op(shiftop).input(1), 1) {
            return 0;
        }
        let Some(basevn) = data.op(shiftop).input(0) else { return 0 };
        if data.vn(basevn).is_free() {
            return 0;
        }
        if data.op(andop).code() == OpCode::IntZext {
            let Some(zin) = data.op(andop).input(0) else { return 0 };
            if !data.vn(zin).is_written() {
                return 0;
            }
            andop = data.vn(zin).def.unwrap();
        }
        if data.op(andop).code() != OpCode::IntAnd {
            return 0;
        }
        // Mask off the least significant bit.
        if !constant_match(data, data.op(andop).input(1), 1) {
            return 0;
        }
        let Some(mut vn) = data.op(andop).input(0) else { return 0 };
        if basevn != vn {
            if !data.vn(vn).is_written() {
                return 0;
            }
            let subop = data.vn(vn).def.unwrap();
            if data.op(subop).code() != OpCode::Subpiece {
                return 0;
            }
            let Some(off) = data.op(subop).input(1) else { return 0 };
            if data.vn(off).constant_value() != 0 {
                return 0;
            }
            let Some(sub_in) = data.op(subop).input(0) else { return 0 };
            vn = sub_in;
            if basevn != vn {
                return 0;
            }
        }
        let Some(outvn) = data.op(op).output else { return 0 };
        for addop in data.vn(outvn).descend.clone() {
            if data.op(addop).code() != OpCode::FloatAdd {
                continue;
            }
            if data.op(addop).input(0) != Some(outvn) || data.op(addop).input(1) != Some(outvn) {
                continue;
            }
            let pc = data.op(addop).seqnum.pc;
            let uniq = data.num_ops() as u32;
            let zextop = data.new_op(OpCode::IntZext, SeqNum { pc, uniq }, vec![basevn]);
            let zextout =
                data.new_output_unique(zextop, preferred_zext_size(data.vn(basevn).size));
            data.op_set_opcode(addop, OpCode::FloatInt2float);
            data.op_remove_input(addop, 1);
            data.op_set_input(addop, 0, zextout);
            data.op_insert_before(zextop, addop);
            return 1;
        }
        0
    }
}

/// Ghidra `Varnode::constantMatch` (varnode.cc:1268): the varnode is a constant with this value.
fn constant_match(data: &Funcdata, vn: Option<VarnodeId>, val: u64) -> bool {
    vn.is_some_and(|v| data.vn(v).is_constant() && data.vn(v).constant_value() == val)
}

/// Ghidra `FlowBlock::findCondition` (block.cc:557): given two edges arriving at a join, walk each
/// back through single-exit blocks to the conditional block that chose between them, returning it
/// and the out-slot of that block leading to the first edge (`slot1`). `None` when the walk hits a
/// block that is neither a pass-through nor the shared condition.
fn find_condition(
    data: &Funcdata,
    mut bl1: BlockId,
    mut edge1: usize,
    mut bl2: BlockId,
    mut edge2: usize,
) -> Option<(BlockId, usize)> {
    let mut cond = *data.block(bl1).in_edges.get(edge1)?;
    while data.block(cond).out_edges.len() != 2 {
        if data.block(cond).out_edges.len() != 1 {
            return None;
        }
        bl1 = cond;
        edge1 = 0;
        cond = *data.block(bl1).in_edges.first()?;
    }
    while Some(&cond) != data.block(bl2).in_edges.get(edge2) {
        bl2 = *data.block(bl2).in_edges.get(edge2)?;
        if data.block(bl2).out_edges.len() != 1 {
            return None;
        }
        edge2 = 0;
    }
    // Ghidra `bl1->getInRevIndex(edge1)` — the out-slot of `cond` that reaches `bl1`. Ghidra
    // stores the reverse index on the edge itself; mosura's edge is a plain BlockId, so it is
    // recovered by position, the same idiom determinedbranch.rs and structure.rs already use.
    // Both loops maintain `in_edges[edge1] == cond`, which is what makes the lookup well-posed;
    // it differs from Ghidra only for a conditional whose two out-edges share a target, where
    // the reverse index distinguishes them and a position lookup cannot.
    debug_assert_eq!(data.block(bl1).in_edges.get(edge1), Some(&cond));
    let slot1 = data.block(cond).out_edges.iter().position(|&o| o == bl1)?;
    Some((cond, slot1))
}

/// Ghidra `RuleInt2FloatCollapse` (ruleaction.cc:10637, coreaction.cc:5637): the *branching* form
/// of the same unsigned-to-float idiom [`RuleUnsigned2Float`] collapses. Here the compiler tests
/// the sign and picks between two conversions:
///
/// ```text
/// f = (V < 0) ? (float)(unsigned)V : (float)V
/// ```
///
/// which arrives as a MULTIEQUAL joining a signed `FLOAT_INT2FLOAT` with an unsigned one over the
/// same input. Redefine the MULTIEQUAL itself as the unsigned conversion `FLOAT_INT2FLOAT(ZEXT(V))`
/// and the branch disappears. The guard checks the condition really is the sign test and that the
/// true branch goes the right way — accepting both `V s< 0` and `-1 s< V`, with the direction
/// requirement inverted between them.
pub struct RuleInt2FloatCollapse;

impl Rule for RuleInt2FloatCollapse {
    fn name(&self) -> &str {
        "int2floatcollapse"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::FloatInt2float]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(invn) = data.op(op).input(0) else { return 0 };
        if !data.vn(invn).is_written() {
            return 0;
        }
        let zextop = data.vn(invn).def.unwrap();
        // The original FLOAT_INT2FLOAT must be the unsigned form.
        if data.op(zextop).code() != OpCode::IntZext {
            return 0;
        }
        let Some(basevn) = data.op(zextop).input(0) else { return 0 };
        if data.vn(basevn).is_free() {
            return 0;
        }
        let Some(outvn) = data.op(op).output else { return 0 };
        let Some(multiop) = lone_descend(data, outvn) else { return 0 };
        // Output comes together with exactly 1 other flow.
        if data.op(multiop).code() != OpCode::Multiequal || data.op(multiop).num_inputs() != 2 {
            return 0;
        }
        let Some(slot) = (0..2).find(|&i| data.op(multiop).input(i) == Some(outvn)) else {
            return 0;
        };
        let Some(otherout) = data.op(multiop).input(1 - slot) else { return 0 };
        if !data.vn(otherout).is_written() {
            return 0;
        }
        let op2 = data.vn(otherout).def.unwrap();
        // The other flow must be a signed FLOAT_INT2FLOAT taking the same input.
        if data.op(op2).code() != OpCode::FloatInt2float || data.op(op2).input(0) != Some(basevn) {
            return 0;
        }
        let Some(outbl) = data.op(multiop).parent else { return 0 };
        // `dir2unsigned` is Ghidra's out-of-parameter: the control path to the unsigned conversion.
        let Some((cond, dir2unsigned)) = find_condition(data, outbl, slot, outbl, 1 - slot) else {
            return 0;
        };
        let Some(&cbranch) = data.block(cond).ops.last() else { return 0 };
        if data.op(cbranch).code() != OpCode::Cbranch {
            return 0;
        }
        let Some(boolvn) = data.op(cbranch).input(1) else { return 0 };
        if !data.vn(boolvn).is_written() || data.op(cbranch).is_boolean_flip() {
            return 0;
        }
        let compare = data.vn(boolvn).def.unwrap();
        if data.op(compare).code() != OpCode::IntSless {
            return 0;
        }
        if constant_match(data, data.op(compare).input(1), 0) {
            // Condition is `basevn s< 0`: the TRUE branch must be the unsigned conversion.
            if data.op(compare).input(0) != Some(basevn) || dir2unsigned != 1 {
                return 0;
            }
        } else if constant_match(
            data,
            data.op(compare).input(0),
            super::nzmask::calc_mask(data.vn(basevn).size),
        ) {
            // Condition is `-1 s< basevn`: the TRUE branch must be the SIGNED conversion.
            if data.op(compare).input(1) != Some(basevn) || dir2unsigned == 1 {
                return 0;
            }
        } else {
            return 0;
        }
        data.op_uninsert(multiop);
        // Redefine the MULTIEQUAL as the unsigned FLOAT_INT2FLOAT.
        data.op_set_opcode(multiop, OpCode::FloatInt2float);
        data.op_remove_input(multiop, 0);
        let pc = data.op(multiop).seqnum.pc;
        let uniq = data.num_ops() as u32;
        let newzext = data.new_op(OpCode::IntZext, SeqNum { pc, uniq }, vec![basevn]);
        let newout = data.new_output_unique(newzext, preferred_zext_size(data.vn(basevn).size));
        data.op_set_input(multiop, 0, newout);
        // Reinsert the modified MULTIEQUAL after any other MULTIEQUAL.
        data.op_insert_begin(multiop, outbl);
        data.op_insert_before(newzext, multiop);
        1
    }
}

/// Ghidra `RuleFloatSignCleanup` (ruleaction.cc:10771, coreaction.cc:5700): the cleanup-pool twin
/// of [`RuleFloatSign`]. By this point type inference has run, so a sign manipulation whose result
/// is *typed* float can be recognized on its own — no neighbouring float op needed. Same two forms
/// (see [`float_sign_manipulation`]): mask off the sign bit is `FLOAT_ABS`, flip it is `FLOAT_NEG`.
pub struct RuleFloatSignCleanup;

impl Rule for RuleFloatSignCleanup {
    fn name(&self) -> &str {
        "floatsigncleanup"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd, OpCode::IntXor]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(out) = data.op(op).output else { return 0 };
        if !matches!(data.vn(out).get_type(), super::types::Datatype::Float(_)) {
            return 0;
        }
        let Some(opc) = float_sign_manipulation(data, op) else { return 0 };
        data.op_remove_input(op, 1);
        data.op_set_opcode(op, opc);
        1
    }
}

/// Ghidra `RuleDumptyHumpLate` (subflow.cc:3006, coreaction.cc:5698): a truncation of a
/// concatenation that lands inside one component reads that component directly — `SUB(PIECE(a,b),k)`
/// becomes a read of `a` or `b`. ("Humpty Dumpty": the pieces were put together and are now being
/// taken apart again.) The backtrack repeats through nested PIECEs, stopping when the truncation
/// would straddle two components or the component is reached exactly.
///
/// Three outcomes, all Ghidra's: the component is bigger than the output, so the SUBPIECE stays but
/// re-roots onto the component with an adjusted offset; the sizes match but the output is
/// address-tied (`autolive`), so the SUBPIECE becomes a COPY; or the sizes match and the output is
/// free, so the output is replaced by the component outright. Whatever op is left dangling is
/// destroyed recursively (see [`Funcdata::op_destroy_recursive`]).
pub struct RuleDumptyHumpLate;

impl Rule for RuleDumptyHumpLate {
    fn name(&self) -> &str {
        "dumptyhumplate"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(in0) = data.op(op).input(0) else { return 0 };
        let mut vn = in0;
        if !data.vn(vn).is_written() {
            return 0;
        }
        let mut piece_op = data.vn(vn).def.unwrap();
        if data.op(piece_op).code() != OpCode::Piece {
            return 0;
        }
        let Some(out) = data.op(op).output else { return 0 };
        let out_size = data.vn(out).size;
        let Some(off_vn) = data.op(op).input(1) else { return 0 };
        let mut trunc = data.vn(off_vn).constant_value() as u32;
        // Ghidra's `for(;;)` with five exits; hoisting the first into a `while let` header would
        // hide the other four, so the loop keeps its shape.
        #[allow(clippy::while_let_loop)]
        loop {
            // Try to backtrack through the PIECE to the component vn is truncated from. Assume the
            // least significant component first.
            let Some(mut trial_vn) = data.op(piece_op).input(1) else { break };
            let mut trial_trunc = trunc;
            if trunc >= data.vn(trial_vn).size {
                // Truncation is from the most significant part.
                trial_trunc -= data.vn(trial_vn).size;
                let Some(hi) = data.op(piece_op).input(0) else { break };
                trial_vn = hi;
            }
            if out_size + trial_trunc > data.vn(trial_vn).size {
                break; // vn crosses both components
            }
            vn = trial_vn; // commit to this component
            trunc = trial_trunc;
            if data.vn(vn).size == out_size {
                break; // found the matching component
            }
            if !data.vn(vn).is_written() {
                break;
            }
            piece_op = data.vn(vn).def.unwrap();
            if data.op(piece_op).code() != OpCode::Piece {
                break;
            }
        }
        if vn == in0 {
            return 0; // didn't backtrack through any PIECE
        }
        if data.vn(vn).is_written() {
            let def = data.vn(vn).def.unwrap();
            if data.op(def).code() == OpCode::Copy {
                if let Some(src) = data.op(def).input(0) {
                    vn = src;
                }
            }
        }
        let remove_op;
        if out_size != data.vn(vn).size {
            // Component does not match the size exactly — preserve the SUBPIECE.
            remove_op = data.vn(in0).def.unwrap();
            if data.vn(data.op(op).input(1).unwrap()).constant_value() != trunc as u64 {
                let newoff = data.new_const(4, trunc as u64);
                data.op_set_input(op, 1, newoff);
            }
            data.op_set_input(op, 0, vn);
        } else if data.vn(out).is_auto_live() {
            // Exact match but the output address is fixed — change the SUBPIECE to a COPY.
            remove_op = data.vn(in0).def.unwrap();
            data.op_remove_input(op, 1);
            data.op_set_opcode(op, OpCode::Copy);
            data.op_set_input(op, 0, vn);
        } else {
            // Exact match — replace the output with the component outright.
            remove_op = op;
            data.total_replace(out, vn);
        }
        let rem_out = data.op(remove_op).output;
        if let Some(ro) = rem_out {
            if data.vn(ro).descend.is_empty() && !data.vn(ro).is_auto_live() {
                data.op_destroy_recursive(remove_op);
            }
        }
        1
    }
}

/// Ghidra `RuleExtensionPush` (ruleaction.cc:10827, coreaction.cc:5703): an extension feeding
/// several pointer-arithmetic readers is duplicated into each of them, so it can be printed inline
/// at each use instead of forcing a named temporary. It fires only when every reader is a PTRADD,
/// or an INT_ADD whose own lone reader is a PTRADD — i.e. when the extension is about to be hidden
/// inside an array index anyway — and only when there are at least two such readers.
///
/// The locked/tied guards are Ghidra's: neither the input nor the output may be address-tied,
/// address-forced, or name/type locked, because duplicating a definition into fixed storage would
/// give that storage two definitions. See [`super::ptrarith::duplicate_need`] for the duplication.
pub struct RuleExtensionPush;

impl Rule for RuleExtensionPush {
    fn name(&self) -> &str {
        "extensionpush"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntZext, OpCode::IntSext]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(in_vn) = data.op(op).input(0) else { return 0 };
        if data.vn(in_vn).is_constant() || data.vn(in_vn).is_addr_force() || data.vn(in_vn).is_addrtied()
        {
            return 0;
        }
        let Some(out_vn) = data.op(op).output else { return 0 };
        if data.vn(out_vn).is_typelock() || data.vn(out_vn).is_namelock() {
            return 0;
        }
        if data.vn(out_vn).is_addr_force() || data.vn(out_vn).is_addrtied() {
            return 0;
        }
        let mut addcount = 0; // number of INT_ADD descendants
        let mut ptrcount = 0; // number of PTRADD descendants
        for dec_op in data.vn(out_vn).descend.clone() {
            match data.op(dec_op).code() {
                OpCode::Ptradd => ptrcount += 1, // this extension will likely be hidden
                OpCode::IntAdd => {
                    let Some(add_out) = data.op(dec_op).output else { return 0 };
                    let Some(sub_op) = lone_descend(data, add_out) else { return 0 };
                    if data.op(sub_op).code() != OpCode::Ptradd {
                        return 0;
                    }
                    addcount += 1;
                }
                _ => return 0,
            }
        }
        if addcount + ptrcount <= 1 {
            return 0;
        }
        if addcount > 0 && lone_descend(data, in_vn).is_some() {
            return 0;
        }
        // Duplicate the extension to all result descendants.
        super::ptrarith::duplicate_need(data, op);
        1
    }
}

/// Ghidra `RuleConditionalMove::checkBoolean` (ruleaction.cc:9259): the varnode carries a boolean —
/// either it is written by an op with boolean output, or it is a COPY of the constant 0 or 1. In the
/// constant case the CONSTANT is returned, not the copy, which is what lets `applyOp` distinguish
/// "this branch supplies a literal" from "this branch supplies a condition".
fn cm_check_boolean(data: &Funcdata, vn: VarnodeId) -> Option<VarnodeId> {
    if !data.vn(vn).is_written() {
        return None;
    }
    let op = data.vn(vn).def.unwrap();
    if data.op(op).is_bool_output() {
        return Some(vn);
    }
    if data.op(op).code() == OpCode::Copy {
        let src = data.op(op).input(0)?;
        if data.vn(src).is_constant() {
            let val = data.vn(src).constant_value();
            if val & !1u64 == 0 {
                return Some(src);
            }
        }
    }
    None
}

/// Ghidra `RuleConditionalMove::gatherExpression` (ruleaction.cc:9287): can the expression rooted at
/// `vn` be propagated out of the conditional branch? Ops that live *inside* the branch are collected
/// into `ops` for later duplication; anything formed before the branch needs no work.
///
/// The refusals are Ghidra's: a free (non-constant) or address-tied value, a `special` eval-type op
/// (LOAD/STORE/CALL/MULTIEQUAL/INDIRECT/… — see [`super::op::PcodeOp::is_special_eval`]), an inner
/// result with more than one use, and an expression of more than 4 ops.
fn cm_gather_expression(
    data: &Funcdata,
    vn: VarnodeId,
    ops: &mut Vec<OpId>,
    root: BlockId,
    branch: BlockId,
) -> bool {
    if data.vn(vn).is_constant() {
        return true; // constants can always be propagated
    }
    if data.vn(vn).is_free() || data.vn(vn).is_addrtied() {
        return false;
    }
    if root == branch {
        return true; // can always propagate if there is no branch
    }
    if !data.vn(vn).is_written() {
        return true;
    }
    let op = data.vn(vn).def.unwrap();
    if data.op(op).parent != Some(branch) {
        return true; // value formed before the branch
    }
    ops.push(op);
    let mut pos = 0;
    while pos < ops.len() {
        let op = ops[pos];
        pos += 1;
        if data.op(op).is_special_eval() {
            return false;
        }
        for i in 0..data.op(op).num_inputs() {
            let Some(in0) = data.op(op).input(i) else { continue };
            if data.vn(in0).is_free() && !data.vn(in0).is_constant() {
                return false;
            }
            if data.vn(in0).is_written()
                && data.op(data.vn(in0).def.unwrap()).parent == Some(branch)
            {
                if data.vn(in0).is_addrtied() {
                    return false; // don't pull out results that can be indirectly addressed
                }
                if lone_descend(data, in0) != Some(op) {
                    return false; // don't pull out results with more than one use
                }
                if ops.len() >= 4 {
                    return false;
                }
                ops.push(data.vn(in0).def.unwrap());
            }
        }
    }
    true
}

/// Ghidra `CloneBlockOps::cloneExpression` (funcdata_block.cc:1024), restricted to the case
/// `RuleConditionalMove` can reach: duplicate each op of a small expression before `follow_op`,
/// rewiring inputs to the clones as they are built, and return the last clone's output.
///
/// Ghidra's `patchInputs` has arms for MULTIEQUAL, INDIRECT and CALL — all unreachable from here,
/// because [`cm_gather_expression`] refuses any op whose eval type is `special`, which is exactly
/// that set. The remaining arm is ported: a constant input is shared, an annotation is rebuilt as a
/// code ref, a free input is impossible (already refused), and a written input maps to its clone
/// when one exists.
fn cm_clone_expression(data: &mut Funcdata, ops: &[OpId], follow_op: OpId) -> Option<VarnodeId> {
    let mut orig_to_clone: Vec<(OpId, OpId)> = Vec::new();
    let mut last_clone = None;
    for &orig in ops {
        if data.op(orig).code().is_branch() {
            continue; // Ghidra's buildOpClone returns null for a branch
        }
        let inputs: Vec<VarnodeId> = (0..data.op(orig).num_inputs())
            .filter_map(|i| data.op(orig).input(i))
            .collect();
        let pc = data.op(orig).seqnum.pc;
        let uniq = data.num_ops() as u32;
        let opc = data.op(orig).code();
        let clone = data.new_op(opc, SeqNum { pc, uniq }, inputs);
        // buildVarnodeOutput (funcdata_block.cc:1046): the clone's output lives at the original's
        // address, carrying the storage-describing flags across.
        if let Some(opvn) = data.op(orig).output {
            let size = data.vn(opvn).size;
            let loc = data.vn(opvn).loc;
            let keep = super::varnode::flags::EXTERNREF
                | super::varnode::flags::VOLATILE
                | super::varnode::flags::READONLY
                | super::varnode::flags::PERSIST
                | super::varnode::flags::ADDRTIED
                | super::varnode::flags::ADDRFORCE
                | super::varnode::flags::NOLOCALALIAS
                | super::varnode::flags::SPACEBASE
                | super::varnode::flags::INDIRECT_CREATION;
            let vflags = data.vn(opvn).flags & keep;
            let newvn = data.new_output(clone, size, loc);
            data.vn_mut(newvn).flags |= vflags;
        }
        data.op_insert_before(clone, follow_op);
        orig_to_clone.push((orig, clone));
        last_clone = Some(clone);
    }
    // patchInputs (funcdata_block.cc:1049), ordinary-op arm only.
    for &(orig, clone) in &orig_to_clone {
        for i in 0..data.op(clone).num_inputs() {
            let Some(orig_vn) = data.op(orig).input(i) else { continue };
            let clone_vn = if data.vn(orig_vn).is_constant() {
                orig_vn
            } else if data.vn(orig_vn).is_written() {
                let def = data.vn(orig_vn).def.unwrap();
                match orig_to_clone.iter().find(|&&(o, _)| o == def) {
                    Some(&(_, c)) => match data.op(c).output {
                        Some(o) => o,
                        None => orig_vn,
                    },
                    None => orig_vn,
                }
            } else {
                orig_vn
            };
            data.op_set_input(clone, i, clone_vn);
        }
    }
    let last = last_clone?;
    data.op(last).output
}

/// Ghidra `RuleConditionalMove::constructBool` (ruleaction.cc:9328): reuse the existing boolean when
/// nothing has to move, otherwise rebuild the expression at the merge point. Ghidra sorts `ops` by
/// `compareOp` (sequence order) before cloning so definitions precede uses; the same order is what
/// `cm_gather_expression` produces walking the worklist backwards, reversed here.
fn cm_construct_bool(
    data: &mut Funcdata,
    vn: VarnodeId,
    insertop: OpId,
    ops: &mut [OpId],
) -> VarnodeId {
    if ops.is_empty() {
        return vn;
    }
    // Ghidra `compareOp` (ruleaction.hh:1433) orders by `SeqNum::getOrder()` — the
    // within-address sequence counter, which is mosura's `SeqNum::uniq`.
    ops.sort_by_key(|&o| (data.op(o).seqnum.pc.offset, data.op(o).seqnum.uniq));
    cm_clone_expression(data, ops, insertop).unwrap_or(vn)
}

/// Ghidra `RuleConditionalMove` (ruleaction.cc:9372, coreaction.cc:5630): recognize a conditional
/// move — a two-input MULTIEQUAL whose arms both carry booleans — and replace the control flow with
/// an expression.
///
/// ```text
/// if (c) res0 = 1; else res1 = 0;   res = ?res0:res1   =>   res = zext(c)
/// if (c) res0 = c; else res1 = d;   res = ?res0:res1   =>   res = c || d
/// ```
///
/// All of Ghidra's cases are ported: both arms constant and equal (a plain COPY), both constant and
/// different (COPY/BOOL_NEGATE at boolean width, INT_ZEXT above it), one arm constant (BOOL_OR or
/// BOOL_AND against the branch condition), and neither constant (BOOL_OR/BOOL_AND when one arm *is*
/// the condition, possibly through a BOOL_NEGATE). `path0istrue` accounts for which incoming edge is
/// the true one and for `boolean_flip` on the CBRANCH.
pub struct RuleConditionalMove;

impl Rule for RuleConditionalMove {
    fn name(&self) -> &str {
        "conditionalmove"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Multiequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0; // MULTIEQUAL must have exactly 2 inputs
        }
        let (Some(in0), Some(in1)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        let Some(bool0) = cm_check_boolean(data, in0) else { return 0 };
        let Some(bool1) = cm_check_boolean(data, in1) else { return 0 };

        // Look for the situation
        //               inblock0
        //             /         |
        // rootblock ->            bb
        //             |         /
        //               inblock1
        // Either inblock0 or inblock1 can be empty.
        let Some(bb) = data.op(op).parent else { return 0 };
        if data.block(bb).in_edges.len() != 2 {
            return 0;
        }
        let inblock0 = data.block(bb).in_edges[0];
        let rootblock0 = if data.block(inblock0).out_edges.len() == 1 {
            if data.block(inblock0).in_edges.len() != 1 {
                return 0;
            }
            data.block(inblock0).in_edges[0]
        } else {
            inblock0
        };
        let inblock1 = data.block(bb).in_edges[1];
        let rootblock1 = if data.block(inblock1).out_edges.len() == 1 {
            if data.block(inblock1).in_edges.len() != 1 {
                return 0;
            }
            data.block(inblock1).in_edges[0]
        } else {
            inblock1
        };
        if rootblock0 != rootblock1 {
            return 0;
        }
        // rootblock must end in CBRANCH, which gives the boolean for the conditional move.
        let Some(&cbranch) = data.block(rootblock0).ops.last() else { return 0 };
        if data.op(cbranch).code() != OpCode::Cbranch {
            return 0;
        }
        let mut op_list0 = Vec::new();
        if !cm_gather_expression(data, bool0, &mut op_list0, rootblock0, inblock0) {
            return 0;
        }
        let mut op_list1 = Vec::new();
        if !cm_gather_expression(data, bool1, &mut op_list1, rootblock0, inblock1) {
            return 0;
        }
        // Ghidra `FlowBlock::getTrueOut` (block.hh:328) is `getOut(1)` — the second out-edge.
        let true_out = data.block(rootblock0).out_edges.get(1).copied();
        let mut path0istrue = if rootblock0 != inblock0 {
            true_out == Some(inblock0)
        } else {
            true_out != Some(inblock1)
        };
        if data.op(cbranch).is_boolean_flip() {
            path0istrue = !path0istrue;
        }
        let Some(boolvn) = data.op(cbranch).input(1) else { return 0 };

        if !data.vn(bool0).is_constant() && !data.vn(bool1).is_constant() {
            // Neither arm is a literal: one of them must BE the branch condition (possibly negated),
            // and the merge becomes a short-circuit || or &&.
            let (first_is_zero_arm, mut andorselect) = if inblock0 == rootblock0 {
                (true, path0istrue)
            } else if inblock1 == rootblock0 {
                (false, !path0istrue)
            } else {
                return 0;
            };
            let forced = if first_is_zero_arm { in0 } else { in1 };
            if boolvn != forced {
                if !data.vn(boolvn).is_written() {
                    return 0;
                }
                let negop = data.vn(boolvn).def.unwrap();
                if data.op(negop).code() != OpCode::BoolNegate
                    || data.op(negop).input(0) != Some(forced)
                {
                    return 0;
                }
                andorselect = !andorselect;
            }
            let opc = if andorselect { OpCode::BoolOr } else { OpCode::BoolAnd };
            data.op_uninsert(op);
            data.op_set_opcode(op, opc);
            data.op_insert_begin(op, bb);
            let (va, vb, la, lb) = if first_is_zero_arm {
                (bool0, bool1, &mut op_list0, &mut op_list1)
            } else {
                (bool1, bool0, &mut op_list1, &mut op_list0)
            };
            let firstvn = cm_construct_bool(data, va, op, la);
            let secondvn = cm_construct_bool(data, vb, op, lb);
            data.op_set_input(op, 0, firstvn);
            data.op_set_input(op, 1, secondvn);
            return 1;
        }

        // Below here some change is being made.
        data.op_uninsert(op); // changing from MULTIEQUAL, this should be reinserted
        let sz = data.op(op).output.map(|o| data.vn(o).size).unwrap_or(0);
        if data.vn(bool0).is_constant() && data.vn(bool1).is_constant() {
            let val0 = data.vn(bool0).constant_value();
            let val1 = data.vn(bool1).constant_value();
            if val0 == val1 {
                data.op_remove_input(op, 1);
                data.op_set_opcode(op, OpCode::Copy);
                let c = data.new_const(sz, val0);
                data.op_set_input(op, 0, c);
                data.op_insert_begin(op, bb);
            } else {
                data.op_remove_input(op, 1);
                let needcomplement = (val0 == 0) == path0istrue;
                if sz == 1 {
                    let opc =
                        if needcomplement { OpCode::BoolNegate } else { OpCode::Copy };
                    data.op_set_opcode(op, opc);
                    data.op_insert_begin(op, bb);
                    data.op_set_input(op, 0, boolvn);
                } else {
                    data.op_set_opcode(op, OpCode::IntZext);
                    data.op_insert_begin(op, bb);
                    let mut bvn = boolvn;
                    if needcomplement {
                        bvn = data.op_bool_negate(bvn, op, false);
                    }
                    data.op_set_input(op, 0, bvn);
                }
            }
        } else if data.vn(bool0).is_constant() {
            let val0 = data.vn(bool0).constant_value();
            let needcomplement = path0istrue != (val0 != 0);
            let opc = if val0 != 0 { OpCode::BoolOr } else { OpCode::BoolAnd };
            data.op_set_opcode(op, opc);
            data.op_insert_begin(op, bb);
            let mut bvn = boolvn;
            if needcomplement {
                bvn = data.op_bool_negate(bvn, op, false);
            }
            let body1 = cm_construct_bool(data, bool1, op, &mut op_list1);
            data.op_set_input(op, 0, bvn);
            data.op_set_input(op, 1, body1);
        } else {
            // bool1 must be constant
            let val1 = data.vn(bool1).constant_value();
            let needcomplement = path0istrue == (val1 != 0);
            let opc = if val1 != 0 { OpCode::BoolOr } else { OpCode::BoolAnd };
            data.op_set_opcode(op, opc);
            data.op_insert_begin(op, bb);
            let mut bvn = boolvn;
            if needcomplement {
                bvn = data.op_bool_negate(bvn, op, false);
            }
            let body0 = cm_construct_bool(data, bool0, op, &mut op_list0);
            data.op_set_input(op, 0, bvn);
            data.op_set_input(op, 1, body0);
        }
        1
    }
}

/// Ghidra `RuleSwitchSingle` (ruleaction.cc:2136, coreaction.cc:5606): a recovered switch whose
/// every case goes to the same place is not a switch. When the BRANCHIND's block has exactly one
/// out-edge and the jump table has recovered labels, convert the BRANCHIND to a plain BRANCH at that
/// one destination and forget the table, so the output is a straight jump rather than a one-armed
/// `switch`.
///
/// Ghidra also emits a warning header ("Switch with 1 destination removed at …") whenever the
/// removal is not fully confirmed — i.e. unless the switch variable is itself constant — because the
/// situation can indicate a recovery problem rather than a genuine single-destination switch. mosura
/// has no warning-comment surface in its printer at all, so that half is omitted; it is output
/// annotation, not IR, and the omission is recorded here rather than silently dropped.
pub struct RuleSwitchSingle;

impl Rule for RuleSwitchSingle {
    fn name(&self) -> &str {
        "switchsingle"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Branchind]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(bb) = data.op(op).parent else { return 0 };
        if data.block(bb).out_edges.len() != 1 {
            return 0;
        }
        let Some(jt_idx) = data.find_jump_table(op) else { return 0 };
        let jt = &data.jumptables[jt_idx];
        if jt.targets.is_empty() {
            return 0;
        }
        // Labels must be recovered — as Ghidra puts it, this is what discovers multistage issues.
        if jt.labels.is_empty() {
            return 0;
        }
        let addr = jt.targets[0];
        // Convert the BRANCHIND to just a branch, with the coderef of the single jumptable entry.
        let space = data.op(op).seqnum.pc.space;
        data.op_set_opcode(op, OpCode::Branch);
        let coderef = data.new_code_ref(Address::new(space, addr));
        data.op_set_input(op, 0, coderef);
        data.remove_jump_table(jt_idx);
        1
    }
}

/// Ghidra `RuleExpandLoad::checkAndComparison` (ruleaction.cc:10860): every reader of the LOAD's
/// output is `(v & #mask) == #const` (or `!=`). In that shape the LOAD can be widened without
/// inserting a truncation, because the masks and comparison constants can simply be shifted instead.
fn expand_load_check_and_comparison(data: &Funcdata, vn: VarnodeId) -> bool {
    for op in &data.vn(vn).descend {
        let op = *op;
        if data.op(op).code() != OpCode::IntAnd {
            return false;
        }
        if !data.op(op).input(1).is_some_and(|v| data.vn(v).is_constant()) {
            return false;
        }
        let Some(out) = data.op(op).output else { return false };
        let Some(comp_op) = lone_descend(data, out) else { return false };
        let opc = data.op(comp_op).code();
        if opc != OpCode::IntEqual && opc != OpCode::IntNotequal {
            return false;
        }
        if !data.op(comp_op).input(1).is_some_and(|v| data.vn(v).is_constant()) {
            return false;
        }
    }
    true
}

/// Ghidra `RuleExpandLoad::modifyAndComparison` (ruleaction.cc:10886): re-point each
/// `(v & #mask) == #const` reader at the widened LOAD, shifting both constants left by the byte
/// offset the narrow LOAD used to start at.
fn expand_load_modify_and_comparison(
    data: &mut Funcdata,
    old_vn: VarnodeId,
    new_vn: VarnodeId,
    dt: &super::types::Datatype,
    offset: u32,
) {
    let shift = 8 * offset; // convert to a shift amount
    let size = dt.size();
    for and_op in data.vn(old_vn).descend.clone() {
        let Some(and_out) = data.op(and_op).output else { continue };
        let Some(comp_op) = lone_descend(data, and_out) else { continue };
        let new_off = data.vn(data.op(and_op).input(1).unwrap()).constant_value() << shift;
        let vn = data.new_const(size, new_off);
        data.vn_mut(vn).update_type(dt.clone());
        data.op_set_input(and_op, 0, new_vn);
        data.op_set_input(and_op, 1, vn);
        let new_off = data.vn(data.op(comp_op).input(1).unwrap()).constant_value() << shift;
        let vn = data.new_const(size, new_off);
        data.vn_mut(vn).update_type(dt.clone());
        data.op_set_input(comp_op, 1, vn);
    }
}

/// Ghidra `RuleExpandLoad` (ruleaction.cc:10909, cleanup slot :5701): a LOAD that reads only part of
/// what its pointer points at is widened to the full pointed-to value, with the original narrow
/// value recovered by a SUBPIECE — or, in the mask-and-compare shape, by shifting the masks instead.
/// The point is that `*ptr` reads better than a truncation of an unrelated-looking load, once the
/// pointer's type says how big the thing really is.
///
/// The pointer may be reached through a small constant `INT_ADD` (≤16, single-use), which is folded
/// away and becomes the LOAD's byte offset into the value.
///
/// mosura reads the varnode's committed type for both of Ghidra's `getTypeReadFacing` and
/// `getTypeDefFacing`: this pool runs BEFORE the merge actions here, so there are no HighVariables
/// to face yet — the same stand-in `ptrarith::type_read_facing` already uses.
pub struct RuleExpandLoad;

impl Rule for RuleExpandLoad {
    fn name(&self) -> &str {
        "expandload"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Load]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        use super::types::Datatype;
        let Some(out_vn) = data.op(op).output else { return 0 };
        let out_size = data.vn(out_vn).size;
        let Some(mut root_ptr) = data.op(op).input(1) else { return 0 };
        let mut add_op = None;
        let mut offset = 0u32;
        let el_type = if data.vn(root_ptr).is_written() {
            let def_op = data.vn(root_ptr).def.unwrap();
            let in1_const = data.op(def_op).input(1).is_some_and(|v| data.vn(v).is_constant());
            if data.op(def_op).code() == OpCode::IntAdd && in1_const {
                let off = data.vn(data.op(def_op).input(1).unwrap()).constant_value();
                if off > 16 {
                    return 0; // INT_ADD offset must be small
                }
                let Some(add_out) = data.op(def_op).output else { return 0 };
                if lone_descend(data, add_out).is_none() {
                    return 0; // INT_ADD must be used only once
                }
                add_op = Some(def_op);
                root_ptr = data.op(def_op).input(0).unwrap();
                offset = off as u32;
            }
            data.vn(root_ptr).get_type()
        } else {
            data.vn(root_ptr).get_type()
        };
        let Datatype::Pointer(_, el_type) = el_type else { return 0 };
        let el_type = (*el_type).clone();
        let el_size = el_type.size();
        if el_size <= out_size || el_size < out_size + offset {
            return 0; // pointer data-type must be bigger than the LOAD, and contain it
        }
        if matches!(el_type, Datatype::Unknown(_)) {
            return 0;
        }
        let add_form = expand_load_check_and_comparison(data, out_vn);
        // Every space mosura loads is little-endian; Ghidra's big-endian arm cuts from the other end.
        let lsb_cut = if add_form { offset } else { 0 };
        if !add_form {
            // Check for natural integer truncation.
            if !matches!(el_type, Datatype::Int(_) | Datatype::Uint(_) | Datatype::Char) {
                return 0;
            }
            let out_meta = data.vn(out_vn).get_type();
            if !matches!(
                out_meta,
                Datatype::Int(_) | Datatype::Uint(_) | Datatype::Char | Datatype::Unknown(_) | Datatype::Bool
            ) {
                return 0;
            }
            // Check that the LOAD is grabbing the least significant bytes.
            if offset != 0 {
                return 0;
            }
        }
        // Modify the LOAD.
        let new_out = data.new_unique(el_size);
        data.vn_mut(new_out).update_type(el_type.clone());
        data.op_set_output(op, new_out);
        if let Some(add_op) = add_op {
            data.op_set_input(op, 1, root_ptr);
            data.op_destroy(add_op);
        }
        if add_form {
            let dt = match el_type {
                Datatype::Int(_) | Datatype::Uint(_) | Datatype::Char => el_type,
                other => Datatype::Uint(other.size()),
            };
            expand_load_modify_and_comparison(data, out_vn, new_out, &dt, lsb_cut);
        } else {
            let pc = data.op(op).seqnum.pc;
            let uniq = data.num_ops() as u32;
            let zero = data.new_const(4, 0);
            let sub_op = data.new_op(OpCode::Subpiece, SeqNum { pc, uniq }, vec![new_out, zero]);
            // The original LOAD output is now defined by the SUBPIECE that truncates the wider load.
            data.op_set_output(sub_op, out_vn);
            data.op_insert_after(sub_op, op);
        }
        1
    }
}

/// Ghidra `RulePiecePathology::isPathology` (ruleaction.cc:10440): does this value trace back to a
/// source whose upper bytes are *garbage* rather than data? Two sources qualify, and both mean "the
/// register was never fully written": a function INPUT that is not persistent, and the output of a
/// CALL whose return storage is not being actively recovered.
///
/// The walk chases COPYs, queues MULTIEQUALs (marked so each is visited once), and reads an
/// INDIRECT's `iop` back to the op it guards. Ghidra's `isOutputActive` has no per-CALL analogue in
/// mosura — call-output trials are not modelled — so that arm reduces to "defined by a CALL that has
/// a call spec", which is Ghidra's answer whenever output recovery is not in flight. It makes the
/// test slightly more willing than Ghidra's during the recovery window.
fn piece_pathology_is_pathology(data: &mut Funcdata, vn: VarnodeId) -> bool {
    let mut worklist: Vec<OpId> = Vec::new();
    let mut pos = 0usize;
    let mut slot = 0usize;
    let mut res = false;
    let mut vn = vn;
    loop {
        if data.vn(vn).is_input() && !data.vn(vn).is_persist() {
            res = true;
            break;
        }
        let mut cur = data.vn(vn).def;
        while !res {
            let Some(op) = cur else { break };
            match data.op(op).code() {
                OpCode::Copy => {
                    let Some(in0) = data.op(op).input(0) else { break };
                    vn = in0;
                    cur = data.vn(vn).def;
                }
                OpCode::Multiequal => {
                    if !data.op(op).is_mark() {
                        data.op_mut(op).set_mark();
                        worklist.push(op);
                    }
                    cur = None;
                }
                OpCode::Indirect => {
                    // Ghidra reads the iop annotation back to the guarded op; mosura carries the
                    // same reference on the op itself.
                    if let Some(call_op) = data.op(op).guarded_op() {
                        if data.op(call_op).is_call() && data.call_specs.contains_key(&call_op) {
                            res = true;
                        }
                    }
                    cur = None;
                }
                OpCode::Call | OpCode::Callind => {
                    if data.call_specs.contains_key(&op) {
                        res = true;
                    }
                    break;
                }
                _ => cur = None,
            }
        }
        if res {
            break;
        }
        if pos >= worklist.len() {
            break;
        }
        let op = worklist[pos];
        if slot < data.op(op).num_inputs() {
            let Some(next) = data.op(op).input(slot) else { break };
            vn = next;
            slot += 1;
        } else {
            pos += 1;
            if pos >= worklist.len() {
                break;
            }
            let Some(next) = data.op(worklist[pos]).input(0) else { break };
            vn = next;
            slot = 1;
        }
    }
    for op in worklist {
        data.op_mut(op).clear_mark();
    }
    res
}

/// Ghidra `RulePiecePathology::tracePathologyForward` (ruleaction.cc:10497): having established that
/// a concatenation's upper half is garbage, follow the value forward through COPY/INDIRECT/
/// MULTIEQUAL to every place it is *used*, and record there that only the lower bytes are real —
/// on a CALL as that argument's consumed width, on a RETURN as the function's returned width.
///
/// Those two records are the rule's entire effect: they are read back by the dead-code consume
/// sweep ([`super::consume`]), which is what makes the garbage bytes drop out of the output.
fn piece_pathology_trace_forward(data: &mut Funcdata, op: OpId) -> u32 {
    let mut count = 0u32;
    let bytes_consumed = match data.op(op).input(1) {
        Some(v) => data.vn(v).size,
        None => return 0,
    };
    let mut worklist = vec![op];
    let mut pos = 0usize;
    data.op_mut(op).set_mark();
    while pos < worklist.len() {
        let cur_op = worklist[pos];
        pos += 1;
        let Some(out_vn) = data.op(cur_op).output else { continue };
        for read_op in data.vn(out_vn).descend.clone() {
            match data.op(read_op).code() {
                OpCode::Copy | OpCode::Indirect | OpCode::Multiequal => {
                    if !data.op(read_op).is_mark() {
                        data.op_mut(read_op).set_mark();
                        worklist.push(read_op);
                    }
                }
                OpCode::Call | OpCode::Callind => {
                    // Ghidra also requires !isInputActive() && !isInputLocked(); mosura has no
                    // input lock, and active input recovery is an entry in `active_inputs`.
                    if data.call_specs.contains_key(&read_op)
                        && !data.is_input_active(read_op)
                    {
                        let mut changed = false;
                        for i in 1..data.op(read_op).num_inputs() {
                            if data.op(read_op).input(i) == Some(out_vn) {
                                let cs = data.call_specs.get_mut(&read_op).unwrap();
                                if cs.set_input_bytes_consumed(i, bytes_consumed) {
                                    changed = true;
                                }
                            }
                        }
                        if changed {
                            count += 1;
                        }
                    }
                }
                OpCode::Return => {
                    // Ghidra guards on !getFuncProto().isOutputLocked(); mosura models no output
                    // lock (see consume.rs `gather_consumed_return`), so the guard is vacuous.
                    if data.set_return_bytes_consumed(bytes_consumed) {
                        count += 1;
                    }
                }
                _ => {}
            }
        }
    }
    for op in worklist {
        data.op_mut(op).clear_mark();
    }
    count
}

/// Ghidra `RulePiecePathology` (ruleaction.cc:10454, coreaction.cc:5642): a CONCAT whose upper half
/// is *garbage* — the untouched high bytes of a register that was only partially written — is a
/// pathology, not a value. The rule does not rewrite the concatenation; it records how many bytes
/// are real at each place the value is consumed, so the dead-code sweep can drop the rest.
///
/// Two shapes qualify. A `PIECE(SUBPIECE(v, k≠0), lo)` where `v` traces back to a non-persistent
/// input or an unrecovered call return ([`piece_pathology_is_pathology`]) — the classic "read EAX
/// after a function that only set AL". Or a `PIECE(INDIRECT-creation, lo)` where the low half comes
/// from a real computation (or a call with a locked output) and the two halves are *contiguous
/// storage* — the register pieced back together across a call that clobbered it.
pub struct RulePiecePathology;

impl Rule for RulePiecePathology {
    fn name(&self) -> &str {
        "piecepathology"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(vn) = data.op(op).input(0) else { return 0 };
        if !data.vn(vn).is_written() {
            return 0;
        }
        let sub_op = data.vn(vn).def.unwrap();
        // Make sure we are concatenating the most significant bytes of a truncation.
        match data.op(sub_op).code() {
            OpCode::Subpiece => {
                let Some(off) = data.op(sub_op).input(1) else { return 0 };
                if data.vn(off).constant_value() == 0 {
                    return 0;
                }
                let Some(src) = data.op(sub_op).input(0) else { return 0 };
                if !piece_pathology_is_pathology(data, src) {
                    return 0;
                }
            }
            OpCode::Indirect => {
                // Indirect concatenation.
                let indirect_creation =
                    data.op(sub_op).output.is_some_and(|o| data.vn(o).is_indirect_creation());
                if !indirect_creation {
                    return 0;
                }
                let Some(lsb_vn) = data.op(op).input(1) else { return 0 };
                if !data.vn(lsb_vn).is_written() {
                    return 0;
                }
                let lsb_op = data.vn(lsb_vn).def.unwrap();
                if !data.op(lsb_op).is_unary_or_binary() {
                    // ... or a CALL with a locked output. mosura models no output lock, so no call
                    // qualifies and this arm declines — Ghidra's conservative direction.
                    return 0;
                }
                // Into a contiguous register (little-endian: the low half sits below the high).
                let lsb_loc = data.vn(lsb_vn).loc;
                let expected = Address::new(lsb_loc.space, lsb_loc.offset + data.vn(lsb_vn).size as u64);
                if expected != data.vn(vn).loc {
                    return 0;
                }
            }
            _ => return 0,
        }
        piece_pathology_trace_forward(data, op)
    }
}

/// Ghidra `RulePtrsubCharConstant::pushConstFurther` (ruleaction.cc:7323): give a PTRADD reading
/// the recovered string pointer the folded constant directly, so the constant propagates instead of
/// leaving a pointer variable behind. Returns whether the descendant took it.
fn ptrsub_char_push_const_further(
    data: &mut Funcdata,
    outtype: &super::types::Datatype,
    op: OpId,
    slot: usize,
    val: u64,
) -> bool {
    if data.op(op).code() != OpCode::Ptradd || slot != 0 {
        return false;
    }
    let Some(vn) = data.op(op).input(1) else { return false };
    if !data.vn(vn).is_constant() {
        return false; // that is adding a constant
    }
    let Some(mult) = data.op(op).input(2) else { return false };
    let addval = data.vn(vn).constant_value().wrapping_mul(data.vn(mult).constant_value());
    let val = val.wrapping_add(addval);
    let size = data.vn(vn).size;
    let newconst = data.new_const(size, val);
    data.vn_mut(newconst).update_type(outtype.clone());
    data.op_remove_input(op, 2);
    data.op_remove_input(op, 1);
    data.op_set_opcode(op, OpCode::Copy);
    data.op_set_input(op, 0, newconst);
    true
}

/// Ghidra `RulePtrsubCharConstant` (ruleaction.cc:7342, cleanup slot :5702): a PTRSUB off a
/// spacebase that resolves to a read-only address holding a string is really a pointer CONSTANT —
/// the thing the printer renders as `"..."`. Convert it, propagating the constant into any PTRADD
/// readers ([`ptrsub_char_push_const_further`]) and dropping the PTRSUB entirely when they all take
/// it.
///
/// ⚠️ **Structurally inert on today's targets, and the reason is worth knowing.** The rule needs a
/// PTRSUB whose base points at a `TypeSpacebase`. Ghidra builds that shape for globals in
/// `Funcdata::spacebaseConstant` (funcdata.cc:358), reached from `ActionConstantPtr`
/// (coreaction.cc:1167) once a constant has been matched against a global symbol. mosura has
/// neither, and registers only ONE spacebase — the stack (`space.rs`) — whose addresses are never
/// read-only. So the gate cannot open until global symbol management exists. It is ported anyway,
/// faithfully and wired, on the same principle as `RuleFuncPtrEncoding` (inert because no x86 cspec
/// sets `<funcptr>`): the logic is Ghidra's and is unit-tested against hand-built preconditions, so
/// when the producer lands the rule is already correct rather than absent.
pub struct RulePtrsubCharConstant;

impl Rule for RulePtrsubCharConstant {
    fn name(&self) -> &str {
        "ptrsubcharconstant"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Ptrsub]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        use super::types::Datatype;
        let Some(sb) = data.op(op).input(0) else { return 0 };
        let Datatype::Pointer(_, sb_pointee) = data.vn(sb).get_type() else { return 0 };
        // The pointee must be a spacebase — Ghidra's `TypeSpacebase`.
        let Datatype::Spacebase(space) = *sb_pointee else { return 0 };
        let Some(vn1) = data.op(op).input(1) else { return 0 };
        if !data.vn(vn1).is_constant() {
            return 0;
        }
        let Some(outvn) = data.op(op).output else { return 0 };
        let outtype = data.vn(outvn).get_type();
        let Datatype::Pointer(_, basetype) = outtype.clone() else { return 0 };
        if !basetype.is_char_print() {
            return 0;
        }
        // Ghidra `TypeSpacebase::getAddress(offset, size, point)`: for the spacebase's own space,
        // the offset IS the address.
        let symaddr = data.vn(vn1).constant_value();
        let _ = space;
        if !data.is_read_only(symaddr, 1) {
            return 0;
        }
        // Check whether the data at the address looks like a string.
        if !super::stringmanage::is_string(data, symaddr, basetype.size() as usize) {
            return 0;
        }
        // The PTRSUB becomes a (COPY of a) pointer constant.
        let mut remove_copy = false;
        if !data.vn(outvn).is_addr_force() {
            remove_copy = true; // assume we can remove, unless a descendant declines
            for subop in data.vn(outvn).descend.clone() {
                let Some(slot) = (0..data.op(subop).num_inputs())
                    .find(|&k| data.op(subop).input(k) == Some(outvn))
                else {
                    remove_copy = false;
                    continue;
                };
                if !ptrsub_char_push_const_further(data, &outtype, subop, slot, symaddr) {
                    remove_copy = false;
                }
            }
        }
        if remove_copy {
            data.op_destroy(op);
        } else {
            let size = data.vn(outvn).size;
            let newvn = data.new_const(size, symaddr);
            data.vn_mut(newvn).update_type(outtype);
            data.op_remove_input(op, 1);
            data.op_set_input(op, 0, newvn);
            data.op_set_opcode(op, OpCode::Copy);
        }
        1
    }
}

/// Ghidra `PieceNode` (ruleaction.hh): one edge of a CONCAT tree — the PIECE op, which input slot,
/// the byte offset of that piece within the structured whole, and whether it is a leaf.
#[derive(Clone, Copy)]
struct PieceNode {
    op: OpId,
    slot: usize,
    type_offset: i64,
    leaf: bool,
}

/// Ghidra `PieceNode::isLeaf` (ruleaction.cc): the tree stops here — the value has its own symbol,
/// is not written, is not built by a PIECE, is shared, or sits at the wrong address.
fn piece_node_is_leaf(data: &Funcdata, root_vn: VarnodeId, vn: VarnodeId, rel_offset: i64) -> bool {
    // Ghidra compares SymbolEntries; mosura has no symbol entries for these varnodes, so `isMapped`
    // alone decides — the conservative direction (a mapped value is treated as its own symbol).
    if data.vn(vn).is_mapped() {
        return true;
    }
    if !data.vn(vn).is_written() {
        return true;
    }
    let def = data.vn(vn).def.unwrap();
    if data.op(def).code() != OpCode::Piece {
        return true;
    }
    if data.lone_descend(vn).is_none() {
        return true;
    }
    if data.vn(vn).is_addrtied() {
        let base = data.vn(root_vn).loc;
        let addr = Address::new(base.space, (base.offset as i64 + rel_offset) as u64);
        if data.vn(vn).loc != addr {
            return true;
        }
    }
    false
}

/// Ghidra `PieceNode::gatherPieces` (ruleaction.cc): walk the CONCAT tree depth-first, recording an
/// edge per input with its offset into the whole. Little-endian: input 1 is the LOW half, so it
/// keeps the base offset and input 0 sits above it.
fn piece_node_gather(
    data: &Funcdata,
    stack: &mut Vec<PieceNode>,
    root_vn: VarnodeId,
    op: OpId,
    base_offset: i64,
    root_offset: i64,
) {
    for i in 0..2 {
        let Some(vn) = data.op(op).input(i) else { continue };
        let other = data.op(op).input(1 - i).map_or(0, |v| data.vn(v).size as i64);
        let offset = if i == 1 { base_offset } else { base_offset + other };
        let res = piece_node_is_leaf(data, root_vn, vn, offset - root_offset);
        stack.push(PieceNode { op, slot: i, type_offset: offset, leaf: res });
        if !res {
            let def = data.vn(vn).def.unwrap();
            piece_node_gather(data, stack, root_vn, def, offset, root_offset);
        }
    }
}

/// Ghidra `RulePieceStructure::spanningRange` (ruleaction.cc:7501): does `[offset, offset+size)`
/// cross more than one component of `ct`?
fn piece_structure_spanning_range(
    ct: &super::types::Datatype,
    offset: i64,
    size: u32,
) -> bool {
    if offset + size as i64 > ct.size() as i64 {
        return false;
    }
    let mut ct = ct.clone();
    let mut newoff = offset;
    loop {
        match ct.get_subtype(newoff) {
            None => return true, // don't know what it spans, assume multiple
            Some((sub, off)) => {
                ct = sub;
                newoff = off;
            }
        }
        if newoff + size as i64 > ct.size() as i64 {
            return true; // spans more than one
        }
        if !ct.is_piece_structured() {
            break;
        }
    }
    false
}

/// Ghidra `RulePieceStructure::convertZextToPiece` (ruleaction.cc:7525): a zero extension inside a
/// structured CONCAT tree is really a concatenation with a zero field, so rewrite it as one — that
/// is what lets the tree be split along the structure's own boundaries.
fn piece_structure_convert_zext(
    data: &mut Funcdata,
    zext: OpId,
    ct: &super::types::Datatype,
    offset: i64,
) -> bool {
    let (Some(outvn), Some(invn)) = (data.op(zext).output, data.op(zext).input(0)) else {
        return false;
    };
    if data.vn(invn).is_constant() {
        return false;
    }
    let sz = data.vn(outvn).size - data.vn(invn).size;
    if sz > 8 {
        return false; // Ghidra's sizeof(uintb) precision guard
    }
    // Little-endian: the zero field sits above the extended value.
    let mut newoff = offset + data.vn(invn).size as i64;
    let mut cur = Some(ct.clone());
    while let Some(c) = cur.clone() {
        if c.size() <= sz {
            break;
        }
        match c.get_subtype(newoff) {
            Some((sub, off)) => {
                cur = Some(sub);
                newoff = off;
            }
            None => {
                cur = None;
                break;
            }
        }
    }
    let zerovn = data.new_const(sz, 0);
    if let Some(c) = cur {
        if c.size() == sz {
            data.vn_mut(zerovn).update_type(c);
        }
    }
    data.op_set_opcode(zext, OpCode::Piece);
    data.op_insert_input(zext, 0, zerovn);
    // Ghidra also transfers a union read-resolution here (`inheritResolution`); mosura models no
    // unions, so `needsResolution` is never true and the transfer is unreachable.
    true
}

/// Ghidra `RulePieceStructure::findReplaceZext` (ruleaction.cc:7556).
fn piece_structure_find_replace_zext(
    data: &mut Funcdata,
    stack: &[PieceNode],
    structured_type: &super::types::Datatype,
) -> bool {
    let mut change = false;
    for node in stack {
        if !node.leaf {
            continue;
        }
        let Some(vn) = data.op(node.op).input(node.slot) else { continue };
        if !data.vn(vn).is_written() {
            continue;
        }
        let op = data.vn(vn).def.unwrap();
        if data.op(op).code() != OpCode::IntZext {
            continue;
        }
        if !piece_structure_spanning_range(structured_type, node.type_offset, data.vn(vn).size) {
            continue;
        }
        if piece_structure_convert_zext(data, op, structured_type, node.type_offset) {
            change = true;
        }
    }
    change
}

/// Ghidra `RulePieceStructure::separateSymbol` (ruleaction.cc:7580): would this leaf belong to a
/// different symbol than the root, so that it needs its own storage?
fn piece_structure_separate_symbol(data: &Funcdata, root: VarnodeId, leaf: VarnodeId) -> bool {
    // Ghidra's first test compares SymbolEntries; mosura has none for these varnodes, so the two
    // are never "forced to be different symbols" and the test falls through.
    if data.vn(root).is_addrtied() {
        return false;
    }
    if !data.vn(leaf).is_written() {
        return true; // assume different symbols
    }
    if data.vn(leaf).is_proto_partial() {
        return true; // already in another tree
    }
    let op = data.vn(leaf).def.unwrap();
    if data.op(op).is_marker() {
        return true; // leaf is not defined locally
    }
    if data.op(op).code() != OpCode::Piece {
        return false;
    }
    data.vn(leaf).get_type().is_piece_structured() // would be a separate root
}

/// Ghidra `RulePieceStructure::determineDatatype` (ruleaction.cc:7463): the structured type this
/// CONCAT tree is building, and the offset of `vn` within it.
fn piece_structure_determine_datatype(
    data: &Funcdata,
    vn: VarnodeId,
) -> Option<(super::types::Datatype, i64)> {
    // Ghidra `Varnode::getStructuredType` (varnode.cc): the mapped symbol's type, else the
    // varnode's own — but only if it is piece-structured.
    let ct = data.vn(vn).get_type();
    if !ct.is_piece_structured() {
        return None;
    }
    if ct.size() != data.vn(vn).size {
        // Ghidra resolves the partial through the varnode's SymbolEntry, which mosura does not
        // have; without it the base offset is unknowable, so decline.
        return None;
    }
    Some((ct, 0))
}

/// Ghidra `RulePieceStructure` (ruleaction.cc:7595, cleanup slot :5704): a CONCAT tree that is
/// really building a STRUCTURE gets split along the structure's own field boundaries, so each field
/// lands in its own storage instead of being assembled into one opaque value.
///
/// ⚠️ **Structurally inert on today's targets.** The gate is `determineDatatype` →
/// `Varnode::getStructuredType`, which needs a varnode whose type (or whose mapped symbol's type)
/// is a struct or array. A probe at this rule's own pool slot was invoked 7254 times across the
/// corpus and found ZERO such varnodes: `Datatype::Struct` is constructed nowhere in mosura, and
/// `Array` only ever appears as a POINTEE. So the rule cannot fire until type recovery produces a
/// structured type for a value. It is ported anyway, faithfully and wired, on the
/// `RuleFuncPtrEncoding` principle — unit-tested against hand-built preconditions, so it is correct
/// when the producer lands rather than absent.
///
/// Two of Ghidra's steps are unreachable here rather than omitted: the union read-resolution
/// transfers (`inheritResolution`/`resolveInFlow`), which are gated on `needsResolution` and mosura
/// models no unions; and `Merge::registerProtoPartialRoot`, which feeds a merge-time
/// proto-partial pass mosura does not have.
pub struct RulePieceStructure;

impl Rule for RulePieceStructure {
    fn name(&self) -> &str {
        "piecestructure"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece, OpCode::IntZext]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).is_partial_root() {
            return 0; // this CONCAT tree has already been visited
        }
        let Some(outvn) = data.op(op).output else { return 0 };
        let Some((ct, base_offset)) = piece_structure_determine_datatype(data, outvn) else {
            return 0;
        };
        if data.op(op).code() == OpCode::IntZext {
            return u32::from(piece_structure_convert_zext(data, op, &ct, 0));
        }
        // Check that outvn is really the root of the tree.
        if let Some(zext) = data.lone_descend(outvn) {
            match data.op(zext).code() {
                OpCode::Piece => return 0, // more PIECEs below us, not a root
                OpCode::IntZext => {
                    // An extension of a structured data-type: convert it to a PIECE first.
                    let zt = data.op(zext).output.map(|o| data.vn(o).get_type());
                    let Some(zt) = zt else { return 0 };
                    return u32::from(piece_structure_convert_zext(data, zext, &zt, 0));
                }
                _ => {}
            }
        }
        let mut stack: Vec<PieceNode> = Vec::new();
        loop {
            stack.clear();
            piece_node_gather(data, &mut stack, outvn, op, base_offset, base_offset);
            if !piece_structure_find_replace_zext(data, &stack, &ct) {
                break;
            }
            // If we found some, regenerate the tree.
        }
        data.op_mut(op).set_partial_root();
        let base = data.vn(outvn).loc;
        let base_addr = Address::new(base.space, (base.offset as i64 - base_offset) as u64);
        for node in stack {
            let Some(vn) = data.op(node.op).input(node.slot) else { continue };
            let addr =
                Address::new(base_addr.space, (base_addr.offset as i64 + node.type_offset) as u64);
            if data.vn(vn).loc == addr
                && (!node.leaf || !piece_structure_separate_symbol(data, outvn, vn))
            {
                // Already at the right address and part of the same symbol as the root.
                if !data.vn(vn).is_addrtied() && !data.vn(vn).is_proto_partial() {
                    data.vn_mut(vn).set_proto_partial();
                }
                continue;
            }
            if node.leaf {
                // Insert a COPY into the correctly-addressed storage.
                let pc = data.op(node.op).seqnum.pc;
                let uniq = data.num_ops() as u32;
                let copy_op = data.new_op(OpCode::Copy, SeqNum { pc, uniq }, vec![vn]);
                let size = data.vn(vn).size;
                let new_vn = data.new_output(copy_op, size, addr);
                if let Some(newtype) = ct.get_exact_piece(node.type_offset, size) {
                    data.vn_mut(new_vn).update_type(newtype);
                }
                data.op_set_input(node.op, node.slot, new_vn);
                data.op_insert_before(copy_op, node.op);
                if !data.vn(new_vn).is_addrtied() {
                    data.vn_mut(new_vn).set_proto_partial();
                }
            } else {
                // Not addrtied and has a lone descendant: replace the Varnode outright.
                let (Some(def_op), Some(lone_op)) = (data.vn(vn).def, data.lone_descend(vn)) else {
                    continue;
                };
                let Some(slot) = (0..data.op(lone_op).num_inputs())
                    .find(|&k| data.op(lone_op).input(k) == Some(vn))
                else {
                    continue;
                };
                let size = data.vn(vn).size;
                let ty = data.vn(vn).ty.clone();
                let new_vn = data.new_varnode(size, addr);
                if let Some(t) = ty {
                    data.vn_mut(new_vn).update_type(t);
                }
                data.op_set_output(def_op, new_vn);
                data.op_set_input(lone_op, slot, new_vn);
                data.delete_varnode(vn);
                if !data.vn(new_vn).is_addrtied() {
                    data.vn_mut(new_vn).set_proto_partial();
                }
            }
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::action::{Action, ActionPool};
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::{Funcdata, SeqNum};

    fn fd() -> (Funcdata, Address) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        (Funcdata::new("t", Address::new(ram, 0), spaces), Address::new(ram, 0))
    }

    #[test]
    fn loadvarnode_const_addr_becomes_ram_copy() {
        // `u = LOAD #ram #0x100074` → `u = COPY <ram:0x100074>` (RuleLoadVarnode const-offset branch).
        let (mut f, _) = fd();
        let ram = f.spaces.by_name("ram").unwrap();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let sid = f.new_const(8, ram.0 as u64);
        let ptr = f.new_const(8, 0x100074);
        let load = f.new_op(OpCode::Load, seq, vec![sid, ptr]);
        f.new_output(load, 4, Address::new(reg, 0x40));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![load], ..Default::default() }]);
        f.op_mut(load).parent = Some(BlockId(0));
        assert_eq!(RuleLoadVarnode.apply_op(load, &mut f), 1);
        assert_eq!(f.op(load).code(), OpCode::Copy);
        assert_eq!(f.op(load).num_inputs(), 1);
        let in0 = f.op(load).input(0).unwrap();
        assert_eq!(f.vn(in0).loc, Address::new(ram, 0x100074));
        assert_eq!(f.vn(in0).size, 4);
    }

    #[test]
    fn storevarnode_const_addr_becomes_ram_copy() {
        // `STORE #ram #0x100074 val` → `<ram:0x100074> = COPY val` (RuleStoreVarnode const-offset).
        let (mut f, _) = fd();
        let ram = f.spaces.by_name("ram").unwrap();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let sid = f.new_const(8, ram.0 as u64);
        let ptr = f.new_const(8, 0x100074);
        let val = f.new_input(4, Address::new(reg, 0x10));
        let store = f.new_op(OpCode::Store, seq, vec![sid, ptr, val]);
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![store], ..Default::default() }]);
        f.op_mut(store).parent = Some(BlockId(0));
        assert_eq!(RuleStoreVarnode.apply_op(store, &mut f), 1);
        assert_eq!(f.op(store).code(), OpCode::Copy);
        assert_eq!(f.op(store).num_inputs(), 1);
        assert_eq!(f.op(store).input(0), Some(val));
        let out = f.op(store).output.unwrap();
        assert_eq!(f.vn(out).loc, Address::new(ram, 0x100074));
        assert_eq!(f.vn(out).size, 4);
    }

    #[test]
    fn sub_ext_comm_splits_straddling_piece() {
        // floatcast's return chain (ruleaction.cc:4423-4439): `SUB(ZEXT(diff:8):16, #4):12` straddles
        // the extension boundary at a nonzero offset → split into `ZEXT(SUB(diff, #4):4):12`, the
        // shape RuleConcatZext then collapses.
        let (mut f, _) = fd();
        let ram = f.spaces.by_name("ram").unwrap();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u16| SeqNum { pc: Address::new(ram, 0), uniq: u as u32 };
        let diff = f.new_input(8, Address::new(reg, 0x10));
        let zext = f.new_op(OpCode::IntZext, seq(0), vec![diff]);
        let wide = f.new_output(zext, 16, Address::new(reg, 0x20));
        let four = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq(1), vec![wide, four]);
        f.new_output(sub, 12, Address::new(reg, 0x30));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![zext, sub], ..Default::default() }]);
        f.op_mut(zext).parent = Some(BlockId(0));
        f.op_mut(sub).parent = Some(BlockId(0));

        assert_eq!(RuleSubExtComm.apply_op(sub, &mut f), 1);
        // The SUBPIECE became the commuted ZEXT of a fresh inner SUBPIECE(diff, 4):4.
        assert_eq!(f.op(sub).code(), OpCode::IntZext);
        assert_eq!(f.op(sub).num_inputs(), 1);
        let inner = f.op(sub).input(0).unwrap();
        assert_eq!(f.vn(inner).size, 4, "inner piece is in_size - subcut = 8 - 4");
        let innerop = f.vn(inner).def.expect("inner piece is written");
        assert_eq!(f.op(innerop).code(), OpCode::Subpiece);
        assert_eq!(f.op(innerop).input(0), Some(diff));
        let c = f.op(innerop).input(1).unwrap();
        assert_eq!(f.vn(c).constant_value(), 4);

        // Decline when the cut starts at/past the pre-extension value (`subcut >= in_size`).
        let zext2 = f.new_op(OpCode::IntZext, seq(2), vec![diff]);
        let wide2 = f.new_output(zext2, 16, Address::new(reg, 0x40));
        let eight = f.new_const(4, 8);
        let sub2 = f.new_op(OpCode::Subpiece, seq(3), vec![wide2, eight]);
        f.new_output(sub2, 8, Address::new(reg, 0x50));
        f.block_mut(BlockId(0)).ops.extend([zext2, sub2]);
        f.op_mut(zext2).parent = Some(BlockId(0));
        f.op_mut(sub2).parent = Some(BlockId(0));
        assert_eq!(RuleSubExtComm.apply_op(sub2, &mut f), 0);
        assert_eq!(f.op(sub2).code(), OpCode::Subpiece);
    }

    #[test]
    fn loadvarnode_skips_nonconst_pointer() {
        // A non-constant pointer that is NOT a marked spacebase register is left as a LOAD.
        let (mut f, _) = fd();
        let ram = f.spaces.by_name("ram").unwrap();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let sid = f.new_const(8, ram.0 as u64);
        let ptr = f.new_input(8, Address::new(reg, 0x20)); // RSP input, but NOT spacebase-marked
        let load = f.new_op(OpCode::Load, seq, vec![sid, ptr]);
        f.new_output(load, 4, Address::new(reg, 0x40));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![load], ..Default::default() }]);
        f.op_mut(load).parent = Some(BlockId(0));
        assert_eq!(RuleLoadVarnode.apply_op(load, &mut f), 0);
        assert_eq!(f.op(load).code(), OpCode::Load);
    }

    #[test]
    fn loadvarnode_spacebase_input_becomes_stack_copy() {
        // `u = LOAD #ram RSP_input` (RSP marked spacebase) → `u = COPY <stack:0>`
        // (RuleLoadVarnode spacebase-register branch, correctSpacebase direct-input case).
        let (mut f, _) = fd();
        let ram = f.spaces.by_name("ram").unwrap();
        let reg = f.spaces.by_name("register").unwrap();
        let stack = f.spaces.by_name("stack").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let sid = f.new_const(8, ram.0 as u64);
        let rsp = f.new_input(8, Address::new(reg, 0x20));
        f.vn_mut(rsp).set_spacebase();
        let load = f.new_op(OpCode::Load, seq, vec![sid, rsp]);
        f.new_output(load, 4, Address::new(reg, 0x40));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![load], ..Default::default() }]);
        f.op_mut(load).parent = Some(BlockId(0));
        assert_eq!(RuleLoadVarnode.apply_op(load, &mut f), 1);
        assert_eq!(f.op(load).code(), OpCode::Copy);
        assert_eq!(f.op(load).num_inputs(), 1);
        let in0 = f.op(load).input(0).unwrap();
        assert_eq!(f.vn(in0).loc, Address::new(stack, 0));
        assert_eq!(f.vn(in0).size, 4);
    }

    #[test]
    fn loadvarnode_spacebase_plus_const_becomes_stack_copy() {
        // `u = LOAD #ram (RSP_input + -0x18)` → `u = COPY <stack:-0x18>`
        // (correctSpacebase via vnSpacebase INT_ADD(RSP_input, const) arm).
        let (mut f, _) = fd();
        let ram = f.spaces.by_name("ram").unwrap();
        let reg = f.spaces.by_name("register").unwrap();
        let stack = f.spaces.by_name("stack").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let sid = f.new_const(8, ram.0 as u64);
        let rsp = f.new_input(8, Address::new(reg, 0x20));
        f.vn_mut(rsp).set_spacebase();
        let c = f.new_const(8, 0xffffffffffffffe8); // -0x18
        let add = f.new_op(OpCode::IntAdd, seq, vec![rsp, c]);
        f.new_output(add, 8, Address::new(uniq, 0x100));
        let sum = f.op(add).output.unwrap();
        let load = f.new_op(OpCode::Load, seq, vec![sid, sum]);
        f.new_output(load, 4, Address::new(reg, 0x40));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![add, load], ..Default::default() }]);
        f.op_mut(add).parent = Some(BlockId(0));
        f.op_mut(load).parent = Some(BlockId(0));
        assert_eq!(RuleLoadVarnode.apply_op(load, &mut f), 1);
        assert_eq!(f.op(load).code(), OpCode::Copy);
        let in0 = f.op(load).input(0).unwrap();
        assert_eq!(f.vn(in0).loc, Address::new(stack, 0xffffffffffffffe8));
        assert_eq!(f.vn(in0).size, 4);
    }

    #[test]
    fn storevarnode_spacebase_plus_const_becomes_stack_copy() {
        // `STORE #ram (RSP_input + -0x40) val` → `<stack:-0x40> = COPY val`.
        let (mut f, _) = fd();
        let ram = f.spaces.by_name("ram").unwrap();
        let reg = f.spaces.by_name("register").unwrap();
        let stack = f.spaces.by_name("stack").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let sid = f.new_const(8, ram.0 as u64);
        let rsp = f.new_input(8, Address::new(reg, 0x20));
        f.vn_mut(rsp).set_spacebase();
        let c = f.new_const(8, 0xffffffffffffffc0); // -0x40
        let add = f.new_op(OpCode::IntAdd, seq, vec![rsp, c]);
        f.new_output(add, 8, Address::new(uniq, 0x100));
        let sum = f.op(add).output.unwrap();
        let val = f.new_input(4, Address::new(reg, 0x10));
        let store = f.new_op(OpCode::Store, seq, vec![sid, sum, val]);
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![add, store], ..Default::default() }]);
        f.op_mut(add).parent = Some(BlockId(0));
        f.op_mut(store).parent = Some(BlockId(0));
        assert_eq!(RuleStoreVarnode.apply_op(store, &mut f), 1);
        assert_eq!(f.op(store).code(), OpCode::Copy);
        assert_eq!(f.op(store).num_inputs(), 1);
        assert_eq!(f.op(store).input(0), Some(val));
        let out = f.op(store).output.unwrap();
        assert_eq!(f.vn(out).loc, Address::new(stack, 0xffffffffffffffc0));
        assert_eq!(f.vn(out).size, 4);
    }

    #[test]
    fn loadvarnode_declines_copy_of_spacebase() {
        // The STRICT boundary (correctSpacebase `!vn->isInput()`): a `COPY`-of-RSP is spacebase-marked
        // (ActionSpacebase marks every RSP version) but is NOT the input, so the LOAD off it is left
        // indirect — matching Ghidra keeping `*puVar3` where `puVar3 = COPY(RSP)` (partialsplit).
        let (mut f, _) = fd();
        let ram = f.spaces.by_name("ram").unwrap();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let sid = f.new_const(8, ram.0 as u64);
        let rsp = f.new_input(8, Address::new(reg, 0x20));
        f.vn_mut(rsp).set_spacebase();
        let copy = f.new_op(OpCode::Copy, seq, vec![rsp]);
        f.new_output(copy, 8, Address::new(uniq, 0x200));
        let cpy = f.op(copy).output.unwrap();
        f.vn_mut(cpy).set_spacebase(); // marked spacebase, but written (not input)
        let load = f.new_op(OpCode::Load, seq, vec![sid, cpy]);
        f.new_output(load, 4, Address::new(reg, 0x40));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![copy, load], ..Default::default() }]);
        f.op_mut(copy).parent = Some(BlockId(0));
        f.op_mut(load).parent = Some(BlockId(0));
        assert_eq!(RuleLoadVarnode.apply_op(load, &mut f), 0);
        assert_eq!(f.op(load).code(), OpCode::Load);
    }

    #[test]
    fn subvar_zext_rule_narrows_a_zext_fed_return() {
        // RuleSubvarZext on `RAX:8 = ZEXT(u:4)` feeding a RETURN narrows the return to the 4-byte
        // logical value (via SubvariableFlow::try_return_pull) — the twodim-class int4 return fix.
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let u = f.new_input(4, Address::new(reg, 0x10));
        let op_z = f.new_op(OpCode::IntZext, seq, vec![u]);
        let rax = f.new_output(op_z, 8, Address::new(reg, 0x0));
        let retaddr = f.new_input(8, Address::new(reg, 0x288));
        let ret = f.new_op(OpCode::Return, seq, vec![retaddr, rax]);
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op_z, ret], ..Default::default() }]);
        for op in f.block(BlockId(0)).ops.clone() {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        // Pipeline precondition (fresh varnodes default to fully-consumed, Ghidra varnode.cc:586):
        // nzm(RAX) = 0xffffffff for the ZEXT 4→8 (ActionNonzeroMask), then ActionConsume seeds the
        // RETURN value with minimalmask(nzm) — what makes a ZEXT-padded return narrowable.
        f.vn_mut(rax).nzm = 0xffffffff;
        crate::decompile::consume::calc_consume(&mut f);
        assert_eq!(RuleSubvarZext.apply_op(op_z, &mut f), 1);
        assert_eq!(f.vn(f.op(ret).input(1).unwrap()).size, 4);
    }

    #[test]
    fn subvar_subpiece_rule_dissolves_a_truncation() {
        // p:1 = SUBPIECE(y:4 = a & 0xff, 0), used narrowly (STORE). RuleSubvarSubpiece seeds the flow
        // on y with mask 0xff; the SUBPIECE becomes a COPY of the 1-byte logical value.
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
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
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op0, op1, store], ..Default::default() }]);
        for op in f.block(BlockId(0)).ops.clone() {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        // Pipeline precondition: ActionConsume always precedes the pool (fresh varnodes default to
        // fully-consumed, Ghidra varnode.cc:586); the STORE-seeded backward sweep computes the
        // narrow-use consume the SubVariableFlow gates require.
        crate::decompile::consume::calc_consume(&mut f);
        assert_eq!(RuleSubvarSubpiece.apply_op(op1, &mut f), 1);
        assert_eq!(f.op(op1).code(), OpCode::Copy);
    }

    #[test]
    fn selectcse_hoists_to_common_dominator_when_neither_dominates() {
        // Diamond 0 -> {1,2} -> 3. Blocks 1 and 2 each compute SUBPIECE(RAX,4); neither dominates
        // the other, so Ghidra `cseElimination` (funcdata_op.cc:1374) builds the op at their common
        // dominator (block 0, before its CBRANCH) and merges both. The corpus exercises only the
        // same-block and one-dominates arms — this pins the neither-dominates arm.
        use crate::decompile::BlockBasic;
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let rax = f.new_input(8, Address::new(reg, 0x0));

        // block 0: a terminating CBRANCH (the hoisted op must land before it)
        let cond = f.new_input(1, Address::new(reg, 0x200));
        let target = f.new_const(8, 0x100);
        let br = f.new_op(OpCode::Cbranch, seq, vec![target, cond]);

        // block 1 and block 2: identical SUBPIECE(rax, 4) at distinct output addresses
        let c4a = f.new_const(4, 4);
        let op_a = f.new_op(OpCode::Subpiece, seq, vec![rax, c4a]);
        let out_a = f.new_output(op_a, 4, Address::new(reg, 0x40));
        let c4b = f.new_const(4, 4);
        let op_b = f.new_op(OpCode::Subpiece, seq, vec![rax, c4b]);
        let out_b = f.new_output(op_b, 4, Address::new(reg, 0x48));

        // block 3: join reads BOTH, so the merge is observable
        let add = f.new_op(OpCode::IntAdd, seq, vec![out_a, out_b]);
        f.new_output(add, 4, Address::new(reg, 0x50));

        f.set_blocks(vec![
            BlockBasic { ops: vec![br], out_edges: vec![BlockId(1), BlockId(2)], ..Default::default() },
            BlockBasic {
                ops: vec![op_a],
                in_edges: vec![BlockId(0)],
                out_edges: vec![BlockId(3)],
            },
            BlockBasic {
                ops: vec![op_b],
                in_edges: vec![BlockId(0)],
                out_edges: vec![BlockId(3)],
            },
            BlockBasic { ops: vec![add], in_edges: vec![BlockId(1), BlockId(2)], ..Default::default() },
        ]);
        for b in 0..4u32 {
            for op in f.block(BlockId(b)).ops.clone() {
                f.op_mut(op).parent = Some(BlockId(b));
            }
        }

        assert_eq!(RuleSelectCse.apply_op(op_a, &mut f), 1);
        assert!(f.op(op_a).is_dead());
        assert!(f.op(op_b).is_dead());
        // a single hoisted SUBPIECE now sits in block 0, before the CBRANCH
        let b0 = f.block(BlockId(0)).ops.clone();
        assert_eq!(b0.len(), 2);
        assert_eq!(f.op(b0[0]).code(), OpCode::Subpiece);
        assert_eq!(f.op(b0[1]).code(), OpCode::Cbranch);
        // the join reads that single output for BOTH operands
        let hout = f.op(b0[0]).output.unwrap();
        assert_eq!(f.op(add).input(0), Some(hout));
        assert_eq!(f.op(add).input(1), Some(hout));
    }

    #[test]
    fn selectcse_keeps_dominating_op_across_blocks() {
        // 0 -> 1, both compute SUBPIECE(RAX,4). Block 0 dominates block 1, so the block-0 op is
        // kept and block-1's is repointed to it (Ghidra cseElimination common==op1->parent arm).
        use crate::decompile::BlockBasic;
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let rax = f.new_input(8, Address::new(reg, 0x0));
        let c4a = f.new_const(4, 4);
        let op0 = f.new_op(OpCode::Subpiece, seq, vec![rax, c4a]); // block 0
        let out0 = f.new_output(op0, 4, Address::new(reg, 0x40));
        let c4b = f.new_const(4, 4);
        let op1 = f.new_op(OpCode::Subpiece, seq, vec![rax, c4b]); // block 1
        let out1 = f.new_output(op1, 4, Address::new(reg, 0x48));
        let use1 = f.new_op(OpCode::IntAdd, seq, vec![out1, out0]);
        f.new_output(use1, 4, Address::new(reg, 0x50));
        f.set_blocks(vec![
            BlockBasic { ops: vec![op0], out_edges: vec![BlockId(1)], ..Default::default() },
            BlockBasic { ops: vec![op1, use1], in_edges: vec![BlockId(0)], ..Default::default() },
        ]);
        for b in 0..2u32 {
            for op in f.block(BlockId(b)).ops.clone() {
                f.op_mut(op).parent = Some(BlockId(b));
            }
        }
        assert_eq!(RuleSelectCse.apply_op(op1, &mut f), 1);
        assert!(!f.op(op0).is_dead()); // dominating op kept
        assert!(f.op(op1).is_dead()); // dominated op removed
        assert_eq!(f.op(use1).input(0), Some(out0));
        assert_eq!(f.op(use1).input(1), Some(out0));
    }

    // The firing path of the remaining 3 driving rules is covered end-to-end by the 20 SubvariableFlow
    // trace unit tests + the corpus; here we pin each rule's seed guard (the part unique to the wrapper).

    #[test]
    fn subvar_and_rule_needs_a_constant_mask() {
        // RuleSubvarAnd seeds only on `V & c` (constant mask); a non-constant second operand → no-op.
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18)); // non-constant
        let op = f.new_op(OpCode::IntAnd, seq, vec![a, b]);
        f.new_output(op, 4, Address::new(reg, 0x20));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op], ..Default::default() }]);
        assert_eq!(RuleSubvarAnd.apply_op(op, &mut f), 0);
    }

    #[test]
    fn subvar_compzero_rule_needs_a_single_bit() {
        // RuleSubvarCompZero seeds only when the tested value has a single live bit; a full 4-byte
        // value (nzmask many bits) → no-op.
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let z = f.new_const(4, 0);
        let op = f.new_op(OpCode::IntEqual, seq, vec![v, z]);
        f.new_output(op, 1, Address::new(reg, 0x20));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op], ..Default::default() }]);
        assert_eq!(RuleSubvarCompZero.apply_op(op, &mut f), 0);
    }

    #[test]
    fn subvar_shift_rule_needs_a_byte_source() {
        // RuleSubvarShift seeds only when the shifted value is exactly 1 byte; a 4-byte shift → no-op.
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let sa = f.new_const(4, 2);
        let op = f.new_op(OpCode::IntRight, seq, vec![v, sa]);
        f.new_output(op, 4, Address::new(reg, 0x20));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op], ..Default::default() }]);
        assert_eq!(RuleSubvarShift.apply_op(op, &mut f), 0);
    }

    #[test]
    fn const_fold_basics() {
        assert_eq!(eval_const(OpCode::IntAnd, &[(0x2, 4), (0x1f, 4)], 4), Some(0x2));
        assert_eq!(eval_const(OpCode::IntAdd, &[(40, 4), (2, 4)], 4), Some(42));
        assert_eq!(eval_const(OpCode::IntSext, &[(0xff, 1)], 4), Some(0xffffffff));
        assert_eq!(eval_const(OpCode::IntZext, &[(0xff, 1)], 4), Some(0xff));
        assert_eq!(eval_const(OpCode::Subpiece, &[(0x1122334455667788, 8), (4, 4)], 4), Some(0x11223344));
        assert_eq!(eval_const(OpCode::Load, &[(0, 8)], 4), None);
    }

    #[test]
    fn const_fold_collapses_in_place_then_propagates() {
        let (mut f, ram) = fd();
        // out = INT_AND #2 #0x1f ; user = INT_ADD out #1
        let c2 = f.new_const(4, 2);
        let c1f = f.new_const(4, 0x1f);
        let seq = SeqNum { pc: ram, uniq: 0 };
        let and = f.new_op(OpCode::IntAnd, seq, vec![c2, c1f]);
        let out = f.new_output(and, 4, Address::new(f.spaces.by_name("register").unwrap(), 0));
        let c1 = f.new_const(4, 1);
        let add = f.new_op(OpCode::IntAdd, seq, vec![out, c1]);
        f.new_output(add, 4, Address::new(f.spaces.by_name("register").unwrap(), 8));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![and, add], ..Default::default() }]);

        // Ghidra `RuleCollapseConstants`: the AND is rewritten in place as `out = COPY #2` (not
        // propagated). The ADD still reads `out`; propagation is RulePropagateCopy's job.
        ActionPool::new("p").with(RuleConstFold).apply(&mut f);
        assert_eq!(f.op(and).code(), OpCode::Copy);
        assert_eq!(f.op(and).num_inputs(), 1);
        let and_in0 = f.op(and).input(0).unwrap();
        assert!(f.vn(and_in0).is_constant() && f.vn(and_in0).constant_value() == 2);
        assert_eq!(f.op(add).input(0), Some(out), "ADD still reads the COPY output, not the constant");

        // With RulePropagateCopy the constant reaches the ADD and the now-unused COPY output dies.
        ActionPool::new("p").with(RulePropagateCopy).apply(&mut f);
        let add_in0 = f.op(add).input(0).unwrap();
        assert!(f.vn(add_in0).is_constant() && f.vn(add_in0).constant_value() == 2);
        assert!(f.vn(out).descend.is_empty(), "COPY output no longer used after propagation");
    }

    #[test]
    fn trivial_arith_x_and_x() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x10));
        let seq = SeqNum { pc: ram, uniq: 0 };
        let op = f.new_op(OpCode::IntAnd, seq, vec![x, x]);
        f.new_output(op, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op], ..Default::default() }]);

        let mut pool = ActionPool::new("p").with(RuleTrivialArith);
        pool.apply(&mut f);
        // x & x  →  COPY x
        assert_eq!(f.op(op).code(), OpCode::Copy);
        assert_eq!(f.op(op).num_inputs(), 1);
        assert_eq!(f.op(op).input(0), Some(x));
    }

    #[test]
    fn termorder_then_identity_collapses_zero_add() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x10));
        let zero = f.new_const(4, 0);
        let seq = SeqNum { pc: ram, uniq: 0 };
        let op = f.new_op(OpCode::IntAdd, seq, vec![zero, x]); // 0 + x (const in slot 0)
        f.new_output(op, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op], ..Default::default() }]);

        let mut pool = ActionPool::new("p").with(RuleTermOrder).with(RuleIdentityEl);
        pool.apply(&mut f);
        // 0 + x  →  x + 0  →  COPY x
        assert_eq!(f.op(op).code(), OpCode::Copy);
        assert_eq!(f.op(op).input(0), Some(x));
    }

    #[test]
    fn mult_zero_and_shift_overflow_go_to_zero() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x10));
        let seq = SeqNum { pc: ram, uniq: 0 };
        let z = f.new_const(4, 0);
        let m = f.new_op(OpCode::IntMult, seq, vec![x, z]); // x * 0
        f.new_output(m, 4, Address::new(reg, 0));
        let big = f.new_const(4, 64);
        let s = f.new_op(OpCode::IntLeft, seq, vec![x, big]); // x << 64
        f.new_output(s, 4, Address::new(reg, 8));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![m, s], ..Default::default() }]);

        let mut pool = ActionPool::new("p").with(RuleIdentityEl).with(RuleTrivialShift);
        pool.apply(&mut f);
        for op in [m, s] {
            assert_eq!(f.op(op).code(), OpCode::Copy);
            let in0 = f.op(op).input(0).unwrap();
            assert!(f.vn(in0).is_constant() && f.vn(in0).constant_value() == 0);
        }
    }

    #[test]
    fn collect_terms_a_plus_a2_is_a3() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let a = f.new_input(8, Address::new(reg, 0x38));
        let two = f.new_const(8, 2);
        let seq = SeqNum { pc: ram, uniq: 0 };
        let m = f.new_op(OpCode::IntMult, seq, vec![a, two]); // a * 2
        let mout = f.new_output(m, 8, Address::new(uniq, 0x100));
        let add = f.new_op(OpCode::IntAdd, seq, vec![a, mout]); // a + a*2
        f.new_output(add, 8, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![m, add], ..Default::default() }]);

        // Faithful RuleCollectTerms produces `INT_ADD(#0, a*3)`; RuleIdentityEl drops the `+0`.
        let mut pool =
            ActionPool::new("p").with(RuleTermOrder).with(RuleCollectTerms).with(RuleIdentityEl);
        pool.apply(&mut f);
        // a + a*2  →  a*3
        let result = if f.op(add).code() == OpCode::Copy {
            f.vn(f.op(add).input(0).unwrap()).def.unwrap()
        } else {
            add
        };
        assert_eq!(f.op(result).code(), OpCode::IntMult);
        assert_eq!(f.op(result).input(0), Some(a));
        let c = f.op(result).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 3);
    }

    #[test]
    fn lessequal_collapses_jle_idiom() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let seq = SeqNum { pc: ram, uniq: 0 };
        // ZF: (a - b) == 0   (a distinct zero/constant, as the lifter emits)
        let sub = f.new_op(OpCode::IntSub, seq, vec![a, b]);
        let subout = f.new_output(sub, 4, Address::new(uniq, 0x100));
        let zero = f.new_const(4, 0);
        let eq = f.new_op(OpCode::IntEqual, seq, vec![subout, zero]);
        let eqout = f.new_output(eq, 1, Address::new(uniq, 0x200));
        // SF != OF, already collapsed by RuleSborrow to: a s< b
        let sl = f.new_op(OpCode::IntSless, seq, vec![a, b]);
        let slout = f.new_output(sl, 1, Address::new(uniq, 0x300));
        // jle = ZF || (SF != OF)
        let or = f.new_op(OpCode::BoolOr, seq, vec![eqout, slout]);
        f.new_output(or, 1, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sub, eq, sl, or],
            ..Default::default()
        }]);

        let mut pool = ActionPool::new("p").with(RuleEqual2Zero).with(RuleLessEqual);
        pool.apply(&mut f);
        // (a - b == 0) || (a s< b)  =>  a s<= b
        assert_eq!(f.op(or).code(), OpCode::IntSlessequal);
        assert_eq!(f.op(or).input(0), Some(a));
        assert_eq!(f.op(or).input(1), Some(b));
    }

    #[test]
    fn boolnegate_flips_equal() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let a = f.new_input(4, Address::new(reg, 0x10));
        let nine = f.new_const(4, 9);
        let seq = SeqNum { pc: ram, uniq: 0 };
        let eq = f.new_op(OpCode::IntEqual, seq, vec![a, nine]);
        let eqout = f.new_output(eq, 1, Address::new(uniq, 0x100));
        let neg = f.new_op(OpCode::BoolNegate, seq, vec![eqout]);
        f.new_output(neg, 1, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![eq, neg], ..Default::default() }]);
        ActionPool::new("p").with(RuleBoolNegate).apply(&mut f);
        // !(a == 9)  =>  a != 9
        assert_eq!(f.op(neg).code(), OpCode::IntNotequal);
        assert_eq!(f.op(neg).input(0), Some(a));
    }

    #[test]
    fn logic2bool_converts_int_or_of_booleans() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let nine = f.new_const(4, 9);
        let ten = f.new_const(4, 10);
        // two comparisons (booloutput) feed an INT_OR — nan's `(a==9) | (b==10)` flag web
        let c1 = f.new_op(OpCode::IntEqual, seq, vec![a, nine]);
        let c1o = f.new_output(c1, 1, Address::new(uniq, 0x100));
        let c2 = f.new_op(OpCode::IntEqual, seq, vec![b, ten]);
        let c2o = f.new_output(c2, 1, Address::new(uniq, 0x200));
        let or = f.new_op(OpCode::IntOr, seq, vec![c1o, c2o]);
        f.new_output(or, 1, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![c1, c2, or], ..Default::default() }]);
        ActionPool::new("p").with(RuleLogic2Bool).apply(&mut f);
        assert_eq!(f.op(or).code(), OpCode::BoolOr, "INT_OR of two comparisons becomes BOOL_OR");
    }

    #[test]
    fn logic2bool_leaves_nonboolean_int_or() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // INT_OR of two plain register reads (not booleans) must not be rewritten.
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let or = f.new_op(OpCode::IntOr, seq, vec![a, b]);
        f.new_output(or, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![or], ..Default::default() }]);
        ActionPool::new("p").with(RuleLogic2Bool).apply(&mut f);
        assert_eq!(f.op(or).code(), OpCode::IntOr, "INT_OR of non-booleans is unchanged");
    }

    #[test]
    fn ormask_collapses_or_with_allones() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(8, Address::new(reg, 0x10));
        let allones = f.new_const(8, u64::MAX); // -1
        let or = f.new_op(OpCode::IntOr, seq, vec![a, allones]);
        f.new_output(or, 8, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![or], ..Default::default() }]);
        ActionPool::new("p").with(RuleOrMask).apply(&mut f);
        assert_eq!(f.op(or).code(), OpCode::Copy, "V | -1 collapses to COPY -1");
        assert_eq!(f.op(or).input(0), Some(allones));
    }

    #[test]
    fn ormask_leaves_partial_mask() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(8, Address::new(reg, 0x10));
        let partial = f.new_const(8, 0xff); // not every bit set
        let or = f.new_op(OpCode::IntOr, seq, vec![a, partial]);
        f.new_output(or, 8, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![or], ..Default::default() }]);
        ActionPool::new("p").with(RuleOrMask).apply(&mut f);
        assert_eq!(f.op(or).code(), OpCode::IntOr, "a partial mask does not collapse the OR");
    }

    #[test]
    fn selectcse_merges_duplicate_subpieces() {
        use crate::decompile::{BlockBasic, BlockId};
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let r = f.new_input(8, Address::new(reg, 0x8));
        let seq = SeqNum { pc: ram, uniq: 0 };
        // two distinct SUBPIECE(r, 0):4 — what heritage's read-size normalization produces
        let z1 = f.new_const(8, 0);
        let s1 = f.new_op(OpCode::Subpiece, seq, vec![r, z1]);
        let s1o = f.new_output(s1, 4, Address::new(uniq, 0x100));
        let z2 = f.new_const(8, 0);
        let s2 = f.new_op(OpCode::Subpiece, seq, vec![r, z2]);
        let s2o = f.new_output(s2, 4, Address::new(uniq, 0x200));
        let x = f.new_op(OpCode::IntXor, seq, vec![s1o, s2o]);
        f.new_output(x, 4, Address::new(reg, 0));
        f.set_blocks(vec![BlockBasic { ops: vec![s1, s2, x], ..Default::default() }]);
        for op in [s1, s2, x] {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        ActionPool::new("p").with(RuleSelectCse).with(RuleTrivialArith).apply(&mut f);
        // CSE collapses the duplicate SUBPIECEs, so the xor becomes `s ^ s` → 0
        assert_eq!(f.op(x).code(), OpCode::Copy);
        assert!(f.vn(f.op(x).input(0).unwrap()).is_constant());
    }

    #[test]
    fn rangemeld_merges_disequality_into_strict() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x10));
        let c = f.new_const(4, 9);
        let seq = SeqNum { pc: ram, uniq: 0 };
        let ne = f.new_op(OpCode::IntNotequal, seq, vec![x, c]);
        let neout = f.new_output(ne, 1, Address::new(uniq, 0x100));
        let le = f.new_op(OpCode::IntSlessequal, seq, vec![c, x]); // 9 <= x
        let leout = f.new_output(le, 1, Address::new(uniq, 0x200));
        let and = f.new_op(OpCode::BoolAnd, seq, vec![neout, leout]);
        f.new_output(and, 1, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![ne, le, and], ..Default::default() }]);
        ActionPool::new("p").with(RuleRangeMeld).apply(&mut f);
        // (x != 9) && (9 s<= x)  =>  9 s< x. Ghidra's RuleRangeMeld re-expresses the intersected
        // CircleRange through `translate2_op`, which MINTS the bound as a fresh constant rather
        // than reusing the operand varnode — so assert the value, not varnode identity.
        assert_eq!(f.op(and).code(), OpCode::IntSless);
        let bound = f.op(and).input(0).unwrap();
        assert!(f.vn(bound).is_constant());
        assert_eq!(f.vn(bound).constant_value(), 9);
        assert_eq!(f.op(and).input(1), Some(x));
    }

    #[test]
    fn sborrow_collapses_to_signed_less() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let seq = SeqNum { pc: ram, uniq: 0 };
        let sb = f.new_op(OpCode::IntSborrow, seq, vec![a, b]); // sborrow(a,b)
        let sbout = f.new_output(sb, 1, Address::new(uniq, 0x100));
        // a - b in the canonical additive form `a + b*(-1)` (post-RuleSub2Add), which is what
        // RuleSborrow's AddExpression comparison expects.
        let negone = f.new_const(4, crate::decompile::nzmask::calc_mask(4));
        let negb = f.new_op(OpCode::IntMult, seq, vec![b, negone]);
        let negbout = f.new_output(negb, 4, Address::new(uniq, 0x180));
        let sub = f.new_op(OpCode::IntAdd, seq, vec![a, negbout]); // a + b*(-1)
        let subout = f.new_output(sub, 4, Address::new(uniq, 0x200));
        let zero = f.new_const(4, 0);
        let sl = f.new_op(OpCode::IntSless, seq, vec![subout, zero]); // (a-b) s< 0
        let slout = f.new_output(sl, 1, Address::new(uniq, 0x300));
        let ne = f.new_op(OpCode::IntNotequal, seq, vec![sbout, slout]); // sborrow != (a-b s< 0)
        f.new_output(ne, 1, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sb, negb, sub, sl, ne],
            ..Default::default()
        }]);

        let mut pool = ActionPool::new("p").with(RuleSborrow);
        pool.apply(&mut f);
        // sborrow(a,b) != ((a-b) s< 0)  →  a s< b
        assert_eq!(f.op(ne).code(), OpCode::IntSless);
        assert_eq!(f.op(ne).input(0), Some(a));
        assert_eq!(f.op(ne).input(1), Some(b));
    }

    #[test]
    fn shift_add_collects_to_mult() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let a = f.new_input(8, Address::new(reg, 0x38));
        let two = f.new_const(8, 2);
        let seq = SeqNum { pc: ram, uniq: 0 };
        let sh = f.new_op(OpCode::IntLeft, seq, vec![a, two]); // a << 2  (== a*4)
        let shout = f.new_output(sh, 8, Address::new(uniq, 0x100));
        let add = f.new_op(OpCode::IntAdd, seq, vec![shout, a]); // (a<<2) + a
        f.new_output(add, 8, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![sh, add], ..Default::default() }]);

        // Ghidra's getMultCoeff only reads INT_MULT coefficients, so RuleShift2Mult converts
        // `a<<2` to `a*4` first; RuleCollectTerms then combines to `INT_ADD(#0, a*5)`, cleaned by
        // RuleIdentityEl.
        let mut pool = ActionPool::new("p")
            .with(RuleShift2Mult)
            .with(RuleTermOrder)
            .with(RuleCollectTerms)
            .with(RuleIdentityEl);
        pool.apply(&mut f);
        // (a<<2) + a  →  a*5  (the lea-as-multiply Ghidra recovers)
        let result = if f.op(add).code() == OpCode::Copy {
            f.vn(f.op(add).input(0).unwrap()).def.unwrap()
        } else {
            add
        };
        assert_eq!(f.op(result).code(), OpCode::IntMult);
        assert_eq!(f.op(result).input(0), Some(a));
        let c = f.op(result).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 5);
    }

    #[test]
    fn propagate_copy_threads_through() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let a = f.new_input(4, Address::new(reg, 0x38));
        let seq = SeqNum { pc: ram, uniq: 0 };
        let cp = f.new_op(OpCode::Copy, seq, vec![a]); // c = COPY a
        let c = f.new_output(cp, 4, Address::new(uniq, 0x100));
        let b = f.new_input(4, Address::new(reg, 0x30));
        let add = f.new_op(OpCode::IntAdd, seq, vec![c, b]); // c + b
        f.new_output(add, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![cp, add], ..Default::default() }]);

        let mut pool = ActionPool::new("p").with(RulePropagateCopy);
        pool.apply(&mut f);
        // the ADD now reads `a` directly; the COPY's output is no longer used
        assert_eq!(f.op(add).input(0), Some(a));
        assert!(f.vn(c).descend.is_empty());
    }

    #[test]
    fn addmultcollapse_flattens_nested_constant_add() {
        // `(V + c) + d  =>  V + (c+d)` — the chained stack-frame base collapse.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let v = f.new_input(8, Address::new(reg, 0x20));
        let c = f.new_const(8, 0xfffffffffffffff8); // -8
        let seq = SeqNum { pc: ram, uniq: 0 };
        let inner = f.new_op(OpCode::IntAdd, seq, vec![v, c]); // V + -8
        let iout = f.new_output(inner, 8, Address::new(uniq, 0x100));
        let d = f.new_const(8, 0xffffffffffffff70); // -0x90
        let outer = f.new_op(OpCode::IntAdd, seq, vec![iout, d]); // (V + -8) + -0x90
        f.new_output(outer, 8, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![inner, outer], ..Default::default() }]);

        ActionPool::new("p").with(RuleAddMultCollapse).apply(&mut f);
        // V + -0x98: the two constant offsets are summed and the intermediate add is bypassed
        assert_eq!(f.op(outer).code(), OpCode::IntAdd);
        assert_eq!(f.op(outer).input(0), Some(v));
        let c2 = f.op(outer).input(1).unwrap();
        assert!(f.vn(c2).is_constant());
        assert_eq!(f.vn(c2).constant_value(), 0xffffffffffffff68); // -8 + -0x90 = -0x98
    }

    #[test]
    fn sub2add_canonicalises_then_cleanup_round_trips() {
        // RuleSub2Add turns `V - W` into `V + (W * -1)`; the cleanup pool then restores `V - W`.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let v = f.new_input(4, Address::new(reg, 0x30));
        let w = f.new_input(4, Address::new(reg, 0x38));
        let seq = SeqNum { pc: ram, uniq: 0 };
        let sub = f.new_op(OpCode::IntSub, seq, vec![v, w]); // V - W
        f.new_output(sub, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![sub], ..Default::default() }]);

        ActionPool::new("p").with(RuleSub2Add).apply(&mut f);
        // V + (W * -1): the op is now INT_ADD; input 1 is W * -1
        assert_eq!(f.op(sub).code(), OpCode::IntAdd);
        assert_eq!(f.op(sub).input(0), Some(v));
        let prod = f.op(sub).input(1).unwrap();
        let mul = f.vn(prod).def.unwrap();
        assert_eq!(f.op(mul).code(), OpCode::IntMult);
        assert_eq!(f.op(mul).input(0), Some(w));
        let c = f.op(mul).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0xffffffff);

        // cleanup restores the subtraction
        ActionPool::new("c").with(RuleMultNegOne).with(Rule2Comp2Sub).apply(&mut f);
        assert_eq!(f.op(sub).code(), OpCode::IntSub);
        assert_eq!(f.op(sub).input(0), Some(v));
        assert_eq!(f.op(sub).input(1), Some(w));
    }

    #[test]
    fn multnegone_then_2comp2sub_reconstructs_subtraction() {
        // `V + (W * -1)` — the canonical form RuleSub2Add leaves for a non-constant subtraction —
        // is reduced to `INT_2COMP(W)` then folded into `V - W`.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let v = f.new_input(4, Address::new(reg, 0x30));
        let w = f.new_input(4, Address::new(reg, 0x38));
        let seq = SeqNum { pc: ram, uniq: 0 };
        let neg1 = f.new_const(4, 0xffffffff);
        let mul = f.new_op(OpCode::IntMult, seq, vec![w, neg1]); // W * -1
        let mout = f.new_output(mul, 4, Address::new(uniq, 0x100));
        let add = f.new_op(OpCode::IntAdd, seq, vec![v, mout]); // V + (W*-1)
        f.new_output(add, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![mul, add], ..Default::default() }]);

        let mut pool = ActionPool::new("p").with(RuleMultNegOne).with(Rule2Comp2Sub);
        pool.apply(&mut f);
        // V - W: the INT_MULT became INT_2COMP and was absorbed into the now-INT_SUB
        assert_eq!(f.op(add).code(), OpCode::IntSub);
        assert_eq!(f.op(add).input(0), Some(v));
        assert_eq!(f.op(add).input(1), Some(w));
        assert!(f.op(mul).is_dead());
    }

    // --- RuleMultiCollapse ------------------------------------------------

    /// Two identical branches: `out = MULTIEQUAL(a, a)` collapses to `a` (absolute equality).
    #[test]
    fn multicollapse_absolute_equality() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let a = f.new_input(4, Address::new(reg, 0x10));
        let seq = SeqNum { pc: ram, uniq: u32::MAX };
        let op = f.new_op(OpCode::Multiequal, seq, vec![a, a]);
        let out = f.new_output(op, 4, Address::new(reg, 0x20));
        let user = f.new_op(OpCode::Copy, SeqNum { pc: ram, uniq: 1 }, vec![out]);
        f.new_output(user, 4, Address::new(reg, 0x28));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op, user], ..Default::default() }]);

        assert_eq!(RuleMultiCollapse.apply_op(op, &mut f), 1);
        assert!(f.op(op).is_dead(), "the MULTIEQUAL is destroyed");
        assert_eq!(f.op(user).input(0), Some(a), "the use now reads a directly");
    }

    /// A value that recurs unchanged in a loop — `out = MULTIEQUAL(a, out)` — collapses to `a`:
    /// the self-referential branch is skipped as a recurrence, leaving only `a`.
    #[test]
    fn multicollapse_loop_recurrence() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let a = f.new_input(4, Address::new(reg, 0x10));
        let seq = SeqNum { pc: ram, uniq: u32::MAX };
        let op = f.new_op(OpCode::Multiequal, seq, vec![a, a]); // 2nd input fixed up below
        let out = f.new_output(op, 4, Address::new(reg, 0x20));
        f.op_set_input(op, 1, out); // the phi reaches itself (loop back-edge)
        let user = f.new_op(OpCode::Copy, SeqNum { pc: ram, uniq: 1 }, vec![out]);
        f.new_output(user, 4, Address::new(reg, 0x28));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op, user], ..Default::default() }]);

        assert_eq!(RuleMultiCollapse.apply_op(op, &mut f), 1);
        assert!(f.op(op).is_dead());
        assert_eq!(f.op(user).input(0), Some(a));
    }

    /// CORRECTNESS GUARD: distinct values must NOT be merged. `MULTIEQUAL(a, b)` with two
    /// different inputs returns 0 (no change) and the MULTIEQUAL survives.
    #[test]
    fn multicollapse_keeps_distinct_values() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let seq = SeqNum { pc: ram, uniq: u32::MAX };
        let op = f.new_op(OpCode::Multiequal, seq, vec![a, b]);
        let out = f.new_output(op, 4, Address::new(reg, 0x20));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op], ..Default::default() }]);

        assert_eq!(RuleMultiCollapse.apply_op(op, &mut f), 0, "distinct branches do not collapse");
        assert!(!f.op(op).is_dead());
        assert_eq!(f.op(op).code(), OpCode::Multiequal);
        assert_eq!(f.op(op).input(0), Some(a));
        assert_eq!(f.op(op).input(1), Some(b));
        assert!(!f.vn(out).is_mark(), "the traversal mark is cleared on the failure path");
    }

    // --- RulePullsubMulti / RulePullsubIndirect / RulePushMulti (the pullsub cluster) ----------

    /// RulePullsubMulti: `SUBPIECE(MULTIEQUAL(a, b), 0):4` pulls the truncation up into a narrow
    /// `MULTIEQUAL(SUBPIECE(a,0), SUBPIECE(b,0)):4`, and the reader collapses to a COPY of it.
    #[test]
    fn pullsub_multi_narrows_phi() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let a = f.new_input(8, Address::new(reg, 0x10));
        let b = f.new_input(8, Address::new(reg, 0x18));
        let seq = SeqNum { pc: ram, uniq: u32::MAX };
        let phi = f.new_op(OpCode::Multiequal, seq, vec![a, b]);
        let m = f.new_output(phi, 8, Address::new(reg, 0x20));
        let zero = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, SeqNum { pc: ram, uniq: 1 }, vec![m, zero]);
        let s = f.new_output(sub, 4, Address::new(reg, 0x28));
        let user = f.new_op(OpCode::Copy, SeqNum { pc: ram, uniq: 2 }, vec![s]);
        f.new_output(user, 4, Address::new(reg, 0x30));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![phi, sub, user], ..Default::default() }]);
        for o in [phi, sub, user] {
            f.op_mut(o).parent = Some(BlockId(0));
        }

        // Pipeline precondition: ActionConsume precedes the pool (fresh varnodes default to
        // fully-consumed, Ghidra varnode.cc:586); the gate checks the phi's high bits are unused.
        crate::decompile::consume::calc_consume(&mut f);
        assert_eq!(RulePullsubMulti.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::Copy, "the reader collapses to a COPY");
        let narrow = f.op(sub).input(0).unwrap();
        assert_eq!(f.vn(narrow).size, 4);
        let np = f.vn(narrow).def.unwrap();
        assert_eq!(f.op(np).code(), OpCode::Multiequal, "a new narrow phi is built");
        assert_eq!(f.op(np).num_inputs(), 2);
        for i in 0..2 {
            let inp = f.op(np).input(i).unwrap();
            assert_eq!(f.vn(inp).size, 4);
            assert_eq!(f.op(f.vn(inp).def.unwrap()).code(), OpCode::Subpiece);
        }
    }

    /// RulePullsubMulti declines a loop-header phi (Ghidra's `hasLoopIn` guard): pulling into the
    /// loop back-edge is not allowed. `MULTIEQUAL(a, self)` in a self-looping block is left alone.
    #[test]
    fn pullsub_multi_declines_loop_header() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let a = f.new_input(8, Address::new(reg, 0x10));
        let seq = SeqNum { pc: ram, uniq: u32::MAX };
        let phi = f.new_op(OpCode::Multiequal, seq, vec![a, a]);
        let m = f.new_output(phi, 8, Address::new(reg, 0x20));
        f.op_set_input(phi, 1, m); // back-edge: the phi reaches itself
        let zero = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, SeqNum { pc: ram, uniq: 1 }, vec![m, zero]);
        f.new_output(sub, 4, Address::new(reg, 0x28));
        let mut blk = crate::decompile::BlockBasic { ops: vec![phi, sub], ..Default::default() };
        blk.in_edges = vec![BlockId(0)]; // self-edge => this block dominates its own predecessor
        blk.out_edges = vec![BlockId(0)];
        f.set_blocks(vec![blk]);
        for o in [phi, sub] {
            f.op_mut(o).parent = Some(BlockId(0));
        }
        assert_eq!(RulePullsubMulti.apply_op(sub, &mut f), 0, "a loop-header phi is not pulled");
    }

    /// RulePullsubIndirect: `SUBPIECE(INDIRECT(before), 0):4` becomes a narrow INDIRECT of the same
    /// causing op (mosura's `guarded_op`), and the reader collapses to a COPY.
    #[test]
    fn pullsub_indirect_narrows_indirect() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let call = f.new_op(OpCode::Call, SeqNum { pc: ram, uniq: 0 }, vec![]);
        let before = f.new_input(8, Address::new(reg, 0x10));
        let indir = f.new_op(OpCode::Indirect, SeqNum { pc: ram, uniq: 1 }, vec![before]);
        f.op_mut(indir).guarded_op = Some(call);
        let iout = f.new_output(indir, 8, Address::new(reg, 0x10));
        let zero = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, SeqNum { pc: ram, uniq: 2 }, vec![iout, zero]);
        let s = f.new_output(sub, 4, Address::new(reg, 0x18));
        let user = f.new_op(OpCode::Copy, SeqNum { pc: ram, uniq: 3 }, vec![s]);
        f.new_output(user, 4, Address::new(reg, 0x20));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![call, indir, sub, user], ..Default::default() }]);
        for o in [call, indir, sub, user] {
            f.op_mut(o).parent = Some(BlockId(0));
        }
        // Pipeline precondition: ActionConsume precedes the pool (fresh varnodes default to
        // fully-consumed, Ghidra varnode.cc:586); the gate checks the INDIRECT's high bits are unused.
        crate::decompile::consume::calc_consume(&mut f);
        assert_eq!(RulePullsubIndirect.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::Copy);
        let narrow = f.op(sub).input(0).unwrap();
        assert_eq!(f.vn(narrow).size, 4);
        let ni = f.vn(narrow).def.unwrap();
        assert_eq!(f.op(ni).code(), OpCode::Indirect);
        assert_eq!(f.op(ni).guarded_op(), Some(call), "the narrow INDIRECT keeps the causing op");
    }

    /// RulePushMulti (general path): `MULTIEQUAL(x+1, x+1)` — two functionally-equal ADDs feeding only
    /// the phi — collapses to a single `x+1` producing the phi's output; the phi and the duplicate are
    /// destroyed.
    #[test]
    fn push_multi_pushes_shared_op() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x10));
        let c1 = f.new_const(4, 1);
        let add1 = f.new_op(OpCode::IntAdd, SeqNum { pc: ram, uniq: 0 }, vec![x, c1]);
        let a1 = f.new_output(add1, 4, Address::new(reg, 0x18));
        let c2 = f.new_const(4, 1);
        let add2 = f.new_op(OpCode::IntAdd, SeqNum { pc: ram, uniq: 1 }, vec![x, c2]);
        let a2 = f.new_output(add2, 4, Address::new(reg, 0x20));
        let seq = SeqNum { pc: ram, uniq: u32::MAX };
        let phi = f.new_op(OpCode::Multiequal, seq, vec![a1, a2]);
        let m = f.new_output(phi, 4, Address::new(reg, 0x28));
        let user = f.new_op(OpCode::Copy, SeqNum { pc: ram, uniq: 2 }, vec![m]);
        f.new_output(user, 4, Address::new(reg, 0x30));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![add1, add2, phi, user], ..Default::default() }]);
        for o in [add1, add2, phi, user] {
            f.op_mut(o).parent = Some(BlockId(0));
        }
        assert_eq!(RulePushMulti.apply_op(phi, &mut f), 1);
        assert!(f.op(phi).is_dead(), "the MULTIEQUAL is destroyed");
        assert!(f.op(add2).is_dead(), "the duplicate op is destroyed");
        assert_eq!(f.op(add1).output, Some(m), "the surviving op produces the unified output");
        assert_eq!(f.op(user).input(0), Some(m), "the use reads the unified value");
    }

    /// Functional equality: two branches that each `COPY` the same constant collapse, with the
    /// MULTIEQUAL rewritten in place into that `COPY const` (the recompute path, no `cseFindInBlock`
    /// hit because the operand is constant).
    #[test]
    fn multicollapse_functional_equality_copy_const() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let off = 0x20;
        // Two separate `COPY #5` ops feeding the phi from two predecessor blocks.
        let c5a = f.new_const(4, 5);
        let copy_a = f.new_op(OpCode::Copy, SeqNum { pc: ram, uniq: 1 }, vec![c5a]);
        let va = f.new_output(copy_a, 4, Address::new(reg, off));
        let c5b = f.new_const(4, 5);
        let copy_b = f.new_op(OpCode::Copy, SeqNum { pc: ram, uniq: 2 }, vec![c5b]);
        let vb = f.new_output(copy_b, 4, Address::new(reg, off));
        // Three blocks: the two defs, then the merge holding the MULTIEQUAL.
        f.set_blocks(vec![
            crate::decompile::BlockBasic { ops: vec![copy_a], ..Default::default() },
            crate::decompile::BlockBasic { ops: vec![copy_b], ..Default::default() },
            crate::decompile::BlockBasic::default(),
        ]);
        let merge = crate::decompile::BlockId(2);
        let op = f.new_multiequal(merge, reg, off, 4, 2);
        f.op_set_input(op, 0, va);
        f.op_set_input(op, 1, vb);
        let out = f.op(op).output.unwrap();
        let user = f.new_op(OpCode::Copy, SeqNum { pc: ram, uniq: 3 }, vec![out]);
        f.new_output(user, 4, Address::new(reg, 0x30));
        f.op_insert_begin(user, merge);

        assert_eq!(RuleMultiCollapse.apply_op(op, &mut f), 1);
        // The MULTIEQUAL became `out = COPY #5` (alive, recomputed), and the use still reads it.
        assert!(!f.op(op).is_dead());
        assert_eq!(f.op(op).code(), OpCode::Copy);
        let in0 = f.op(op).input(0).unwrap();
        assert!(f.vn(in0).is_constant() && f.vn(in0).constant_value() == 5);
        assert_eq!(f.op(user).input(0), Some(out), "use still reads the collapsed value");
        // and it now sits after the (now absent) leading MULTIEQUALs, i.e. ahead of the user.
        assert!(f.block(merge).ops.contains(&op));
    }

    // --- RuleSlessToLess (ruleaction.cc:2530) ---------------------------------

    #[test]
    fn sless_to_less_when_both_operands_nonnegative() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // ta = a & 0x7f ; tb = b & 0x7f  → both provably non-negative (nzm has the sign bit clear).
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let m1 = f.new_const(4, 0x7f);
        let and_a = f.new_op(OpCode::IntAnd, seq, vec![a, m1]);
        let ta = f.new_output_unique(and_a, 4);
        let m2 = f.new_const(4, 0x7f);
        let and_b = f.new_op(OpCode::IntAnd, seq, vec![b, m2]);
        let tb = f.new_output_unique(and_b, 4);
        let sless = f.new_op(OpCode::IntSless, seq, vec![ta, tb]);
        f.new_output_unique(sless, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and_a, and_b, sless],
            ..Default::default()
        }]);

        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        assert_eq!(f.vn(ta).get_nzmask(), 0x7f, "masked value proves the sign bit is clear");

        ActionPool::new("p").with(RuleSlessToLess).apply(&mut f);
        // Ghidra RuleSlessToLess: both operands non-negative ⇒ INT_SLESS → INT_LESS.
        assert_eq!(f.op(sless).code(), OpCode::IntLess);
    }

    #[test]
    fn sless_to_less_declines_when_sign_bit_possible() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // Plain 4-byte inputs: nzm is the full mask, so the sign bit may be set → rule must not fire.
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let sless = f.new_op(OpCode::IntSless, seq, vec![a, b]);
        f.new_output_unique(sless, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sless],
            ..Default::default()
        }]);

        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        ActionPool::new("p").with(RuleSlessToLess).apply(&mut f);
        assert_eq!(f.op(sless).code(), OpCode::IntSless, "sign bit may be set ⇒ stays signed");
    }

    // --- RulePopcountBoolXor (ruleaction.cc:10273) ----------------------------

    #[test]
    fn popcount_bool_xor_single_bit_to_copy() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // b1 = (a == b)  → boolean, nzm 1
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let eq = f.new_op(OpCode::IntEqual, seq, vec![a, b]);
        let b1 = f.new_output_unique(eq, 1);
        // s = zext(b1) << 6   → a single set bit at position 6
        let z = f.new_op(OpCode::IntZext, seq, vec![b1]);
        let zo = f.new_output_unique(z, 8);
        let sh6 = f.new_const(4, 6);
        let sh = f.new_op(OpCode::IntLeft, seq, vec![zo, sh6]);
        let so = f.new_output_unique(sh, 8);
        // p = popcount(s) ; and = p & 1   (parity check of the one shifted boolean)
        let pc = f.new_op(OpCode::Popcount, seq, vec![so]);
        let po = f.new_output_unique(pc, 1);
        let one = f.new_const(1, 1);
        let and = f.new_op(OpCode::IntAnd, seq, vec![po, one]);
        f.new_output_unique(and, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![eq, z, sh, pc, and],
            ..Default::default()
        }]);

        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        assert_eq!(f.vn(so).get_nzmask(), 0x40, "single boolean bit at position 6");

        ActionPool::new("p").with(RulePopcountBoolXor).apply(&mut f);
        // Ghidra RulePopcountBoolXor: popcount(b1 << 6) & 1  →  COPY(b1).
        assert_eq!(f.op(and).code(), OpCode::Copy);
        assert_eq!(f.op(and).num_inputs(), 1);
        assert_eq!(f.op(and).input(0), Some(b1));
    }

    #[test]
    fn popcount_bool_xor_two_bits_to_xor() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let c = f.new_input(4, Address::new(reg, 0x20));
        let d = f.new_input(4, Address::new(reg, 0x28));
        // b1 = (a == b) ; b2 = (c == d)
        let eq1 = f.new_op(OpCode::IntEqual, seq, vec![a, b]);
        let b1 = f.new_output_unique(eq1, 1);
        let eq2 = f.new_op(OpCode::IntEqual, seq, vec![c, d]);
        let b2 = f.new_output_unique(eq2, 1);
        // o = (zext(b1) << 6) | (zext(b2) << 2)  → set bits at positions 6 and 2
        let z1 = f.new_op(OpCode::IntZext, seq, vec![b1]);
        let z1o = f.new_output_unique(z1, 8);
        let z2 = f.new_op(OpCode::IntZext, seq, vec![b2]);
        let z2o = f.new_output_unique(z2, 8);
        let sh6 = f.new_const(4, 6);
        let s1 = f.new_op(OpCode::IntLeft, seq, vec![z1o, sh6]);
        let s1o = f.new_output_unique(s1, 8);
        let sh2 = f.new_const(4, 2);
        let s2 = f.new_op(OpCode::IntLeft, seq, vec![z2o, sh2]);
        let s2o = f.new_output_unique(s2, 8);
        let or = f.new_op(OpCode::IntOr, seq, vec![s1o, s2o]);
        let oo = f.new_output_unique(or, 8);
        // p = popcount(o) ; and = p & 1
        let pc = f.new_op(OpCode::Popcount, seq, vec![oo]);
        let po = f.new_output_unique(pc, 1);
        let one = f.new_const(1, 1);
        let and = f.new_op(OpCode::IntAnd, seq, vec![po, one]);
        f.new_output_unique(and, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![eq1, eq2, z1, z2, s1, s2, or, pc, and],
            ..Default::default()
        }]);

        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        assert_eq!(f.vn(oo).get_nzmask(), 0x44, "two boolean bits at positions 2 and 6");

        ActionPool::new("p").with(RulePopcountBoolXor).apply(&mut f);
        // Ghidra RulePopcountBoolXor: popcount((b1 << 6) | (b2 << 2)) & 1  →  b1 ^ b2.
        assert_eq!(f.op(and).code(), OpCode::IntXor);
        let ins = [f.op(and).input(0).unwrap(), f.op(and).input(1).unwrap()];
        assert!(ins.contains(&b1) && ins.contains(&b2), "XOR of the two booleans");
    }

    // --- RuleOrCollapse (ruleaction.cc:384) -----------------------------------

    #[test]
    fn or_collapse_when_operand_bits_subset_of_const() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // t = a & 0x0f  (nzm 0x0f) ; t | 0x0f  →  0x0f  (OR turns on no new bit)
        let a = f.new_input(4, Address::new(reg, 0x10));
        let m = f.new_const(4, 0x0f);
        let and = f.new_op(OpCode::IntAnd, seq, vec![a, m]);
        let t = f.new_output_unique(and, 4);
        let c = f.new_const(4, 0x0f);
        let or = f.new_op(OpCode::IntOr, seq, vec![t, c]);
        f.new_output_unique(or, 4);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and, or],
            ..Default::default()
        }]);
        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        ActionPool::new("p").with(RuleOrCollapse).apply(&mut f);
        assert_eq!(f.op(or).code(), OpCode::Copy);
        assert_eq!(f.op(or).num_inputs(), 1);
        let in0 = f.op(or).input(0).unwrap();
        assert!(f.vn(in0).is_constant() && f.vn(in0).constant_value() == 0x0f);
    }

    // --- RuleXorCollapse (ruleaction.cc:4050) ---------------------------------

    #[test]
    fn xor_collapse_folds_const_into_compare() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (v ^ 5) == 3   →   v == (5 ^ 3 = 6)
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c5 = f.new_const(4, 0x5);
        let xor = f.new_op(OpCode::IntXor, seq, vec![v, c5]);
        let t = f.new_output_unique(xor, 4);
        let d3 = f.new_const(4, 0x3);
        let eq = f.new_op(OpCode::IntEqual, seq, vec![t, d3]);
        f.new_output_unique(eq, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![xor, eq],
            ..Default::default()
        }]);
        ActionPool::new("p").with(RuleXorCollapse).apply(&mut f);
        assert_eq!(f.op(eq).code(), OpCode::IntEqual);
        assert_eq!(f.op(eq).input(0), Some(v));
        let d = f.op(eq).input(1).unwrap();
        assert!(f.vn(d).is_constant() && f.vn(d).constant_value() == 0x6);
    }

    // --- RuleHighOrderAnd (ruleaction.cc:1196) --------------------------------

    #[test]
    fn high_order_and_pushes_mask_into_add_const() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // xalign = b & 0xf0  (nzm 0xf0, low 4 bits clear → unaffected by & 0xfff0)
        let b = f.new_input(2, Address::new(reg, 0x10));
        let m = f.new_const(2, 0xf0);
        let anda = f.new_op(OpCode::IntAnd, seq, vec![b, m]);
        let xalign = f.new_output_unique(anda, 2);
        let c2 = f.new_const(2, 0x1234);
        let add = f.new_op(OpCode::IntAdd, seq, vec![xalign, c2]);
        let addout = f.new_output_unique(add, 2);
        let mask = f.new_const(2, 0xfff0);
        let and = f.new_op(OpCode::IntAnd, seq, vec![addout, mask]);
        f.new_output_unique(and, 2);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![anda, add, and],
            ..Default::default()
        }]);
        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        ActionPool::new("p").with(RuleHighOrderAnd).apply(&mut f);
        // (xalign + 0x1234) & 0xfff0  →  xalign + (0x1234 & 0xfff0 = 0x1230)
        assert_eq!(f.op(and).code(), OpCode::IntAdd);
        assert_eq!(f.op(and).input(0), Some(xalign));
        let c = f.op(and).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0x1230);
    }

    // --- RuleNotDistribute (ruleaction.cc:1147) — ported + held (see the rule's doc comment) --

    #[test]
    fn not_distribute_de_morgan() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // neg = !(v && w)   →   !v || !w
        let v = f.new_input(1, Address::new(reg, 0x10));
        let w = f.new_input(1, Address::new(reg, 0x18));
        let and = f.new_op(OpCode::BoolAnd, seq, vec![v, w]);
        let andout = f.new_output_unique(and, 1);
        let neg = f.new_op(OpCode::BoolNegate, seq, vec![andout]);
        f.new_output_unique(neg, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and, neg],
            ..Default::default()
        }]);
        assert_eq!(RuleNotDistribute.apply_op(neg, &mut f), 1);
        assert_eq!(f.op(neg).code(), OpCode::BoolOr);
        let (i0, i1) = (f.op(neg).input(0).unwrap(), f.op(neg).input(1).unwrap());
        let d0 = f.vn(i0).def.unwrap();
        let d1 = f.vn(i1).def.unwrap();
        assert_eq!(f.op(d0).code(), OpCode::BoolNegate);
        assert_eq!(f.op(d1).code(), OpCode::BoolNegate);
        assert_eq!(f.op(d0).input(0), Some(v));
        assert_eq!(f.op(d1).input(0), Some(w));
    }

    // --- RuleZextShiftZext (ruleaction.cc:4865) — wired -----------------------

    #[test]
    fn zext_shift_zext_collapses_double_zext() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // zext(zext(V:2 -> 4) -> 8)  =>  zext(V:2 -> 8)
        let v = f.new_input(2, Address::new(reg, 0x10));
        let z1 = f.new_op(OpCode::IntZext, seq, vec![v]);
        let z1o = f.new_output_unique(z1, 4);
        let z2 = f.new_op(OpCode::IntZext, seq, vec![z1o]);
        f.new_output_unique(z2, 8);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![z1, z2],
            ..Default::default()
        }]);
        ActionPool::new("p").with(RuleZextShiftZext).apply(&mut f);
        assert_eq!(f.op(z2).code(), OpCode::IntZext);
        assert_eq!(f.op(z2).input(0), Some(v));
    }

    #[test]
    fn zext_shift_zext_pulls_shift_outside() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // zext( zext(V:1 -> 4) << 8 )  =>  zext(V:1 -> 8) << 8   (8 <= 8*(4-1), keeps bits)
        let v = f.new_input(1, Address::new(reg, 0x10));
        let z1 = f.new_op(OpCode::IntZext, seq, vec![v]);
        let z1o = f.new_output_unique(z1, 4);
        let sh = f.new_const(4, 8);
        let shl = f.new_op(OpCode::IntLeft, seq, vec![z1o, sh]);
        let shlo = f.new_output_unique(shl, 4);
        let z2 = f.new_op(OpCode::IntZext, seq, vec![shlo]);
        f.new_output_unique(z2, 8);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![z1, shl, z2],
            ..Default::default()
        }]);
        ActionPool::new("p").with(RuleZextShiftZext).apply(&mut f);
        // z2 is now  ZEXT(v):8 << 8
        assert_eq!(f.op(z2).code(), OpCode::IntLeft);
        let nz = f.op(z2).input(0).unwrap();
        let nzdef = f.vn(nz).def.unwrap();
        assert_eq!(f.op(nzdef).code(), OpCode::IntZext);
        assert_eq!(f.op(nzdef).input(0), Some(v));
        assert_eq!(f.vn(nz).size, 8);
        let c = f.op(z2).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 8);
    }

    // --- RuleAndCompare (ruleaction.cc:1745) — ported + held ------------------

    #[test]
    fn and_compare_widens_mask_through_zext() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (zext(V:2 -> 4) & 0x1ff) == 0   =>   (V & 0x1ff) == 0
        let v = f.new_input(2, Address::new(reg, 0x10));
        let z = f.new_op(OpCode::IntZext, seq, vec![v]);
        let zo = f.new_output_unique(z, 4);
        let c = f.new_const(4, 0x1ff);
        let and = f.new_op(OpCode::IntAnd, seq, vec![zo, c]);
        let ando = f.new_output_unique(and, 4);
        let zero = f.new_const(4, 0);
        let eq = f.new_op(OpCode::IntEqual, seq, vec![ando, zero]);
        f.new_output_unique(eq, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![z, and, eq],
            ..Default::default()
        }]);
        assert_eq!(RuleAndCompare.apply_op(eq, &mut f), 1);
        assert_eq!(f.op(eq).code(), OpCode::IntEqual);
        let a0 = f.op(eq).input(0).unwrap();
        let d = f.vn(a0).def.unwrap();
        assert_eq!(f.op(d).code(), OpCode::IntAnd);
        assert_eq!(f.op(d).input(0), Some(v));
        let dc = f.op(d).input(1).unwrap();
        assert!(f.vn(dc).is_constant() && f.vn(dc).constant_value() == 0x1ff && f.vn(dc).size == 2);
        let z1 = f.op(eq).input(1).unwrap();
        assert!(f.vn(z1).is_constant() && f.vn(z1).constant_value() == 0);
    }

    // --- RuleSubZext (ruleaction.cc:5039) — ported + held ---------------------

    #[test]
    fn sub_zext_low_truncation_becomes_and_mask() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // zext( sub(V:4, 0):2 -> 4 )  =>  V & 0xffff
        let v = f.new_input(4, Address::new(reg, 0x10));
        let off0 = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![v, off0]);
        let subo = f.new_output_unique(sub, 2);
        let z = f.new_op(OpCode::IntZext, seq, vec![subo]);
        f.new_output_unique(z, 4);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sub, z],
            ..Default::default()
        }]);
        assert_eq!(RuleSubZext.apply_op(z, &mut f), 1);
        assert_eq!(f.op(z).code(), OpCode::IntAnd);
        assert_eq!(f.op(z).input(0), Some(v));
        let m = f.op(z).input(1).unwrap();
        assert!(f.vn(m).is_constant() && f.vn(m).constant_value() == 0xffff);
    }

    #[test]
    fn sub_zext_mid_truncation_becomes_shift_and_mask() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // zext( sub(V:4, 2):2 -> 4 )  =>  (V >> 16) & 0xffff
        let v = f.new_input(4, Address::new(reg, 0x10));
        let off2 = f.new_const(4, 2);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![v, off2]);
        let subo = f.new_output_unique(sub, 2);
        let z = f.new_op(OpCode::IntZext, seq, vec![subo]);
        f.new_output_unique(z, 4);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sub, z],
            ..Default::default()
        }]);
        assert_eq!(RuleSubZext.apply_op(z, &mut f), 1);
        assert_eq!(f.op(z).code(), OpCode::IntAnd);
        let sh = f.op(z).input(0).unwrap();
        let shd = f.vn(sh).def.unwrap();
        assert_eq!(f.op(shd).code(), OpCode::IntRight);
        assert_eq!(f.op(shd).input(0), Some(v));
        let sa = f.op(shd).input(1).unwrap();
        assert!(f.vn(sa).is_constant() && f.vn(sa).constant_value() == 16);
        let m = f.op(z).input(1).unwrap();
        assert!(f.vn(m).is_constant() && f.vn(m).constant_value() == 0xffff);
    }

    // --- RulePiece2Zext (ruleaction.cc:219) — ported, wiring pending (see doc comment) --

    #[test]
    fn piece2zext_zero_high_becomes_zext() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // concat(#0:2, W:2) : 4  =>  zext(W)
        let w = f.new_input(2, Address::new(reg, 0x10));
        let hi0 = f.new_const(2, 0);
        let piece = f.new_op(OpCode::Piece, seq, vec![hi0, w]);
        f.new_output_unique(piece, 4);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![piece],
            ..Default::default()
        }]);
        assert_eq!(RulePiece2Zext.apply_op(piece, &mut f), 1);
        assert_eq!(f.op(piece).code(), OpCode::IntZext);
        assert_eq!(f.op(piece).num_inputs(), 1);
        assert_eq!(f.op(piece).input(0), Some(w));
    }

    // --- RulePiece2Sext (ruleaction.cc:232) — wired @104, after RulePiece2Zext --

    #[test]
    fn piece2sext_sign_smear_becomes_sext() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // concat(V s>> 0x1f, V) : 8  =>  sext(V)   (the cdq;idiv dividend)
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c31 = f.new_const(4, 31);
        let sr = f.new_op(OpCode::IntSright, seq, vec![v, c31]);
        let hi = f.new_output_unique(sr, 4);
        let piece = f.new_op(OpCode::Piece, SeqNum { pc: ram, uniq: 1 }, vec![hi, v]);
        f.new_output_unique(piece, 8);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sr, piece],
            ..Default::default()
        }]);
        assert_eq!(RulePiece2Sext.apply_op(piece, &mut f), 1);
        assert_eq!(f.op(piece).code(), OpCode::IntSext);
        assert_eq!(f.op(piece).num_inputs(), 1);
        assert_eq!(f.op(piece).input(0), Some(v));
    }

    #[test]
    fn piece2sext_declines_non_sign_smear() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // Wrong shift amount (not 8*|V|-1): concat(V s>> 16, V) stays a PIECE.
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c16 = f.new_const(4, 16);
        let sr = f.new_op(OpCode::IntSright, seq, vec![v, c16]);
        let hi = f.new_output_unique(sr, 4);
        let piece = f.new_op(OpCode::Piece, SeqNum { pc: ram, uniq: 1 }, vec![hi, v]);
        f.new_output_unique(piece, 8);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sr, piece],
            ..Default::default()
        }]);
        assert_eq!(RulePiece2Sext.apply_op(piece, &mut f), 0);
        assert_eq!(f.op(piece).code(), OpCode::Piece);

        // High half shifts a DIFFERENT varnode than the low half: decline.
        let w = f.new_input(4, Address::new(reg, 0x18));
        let c31 = f.new_const(4, 31);
        let sr2 = f.new_op(OpCode::IntSright, SeqNum { pc: ram, uniq: 2 }, vec![w, c31]);
        let hi2 = f.new_output_unique(sr2, 4);
        let piece2 = f.new_op(OpCode::Piece, SeqNum { pc: ram, uniq: 3 }, vec![hi2, v]);
        f.new_output_unique(piece2, 8);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sr, piece, sr2, piece2],
            ..Default::default()
        }]);
        assert_eq!(RulePiece2Sext.apply_op(piece2, &mut f), 0);
        assert_eq!(f.op(piece2).code(), OpCode::Piece);
    }

    // --- RuleLessEqual2Zero (ruleaction.cc:5601) — wired ----------------------

    #[test]
    fn lessequal2zero_v_le_zero_is_equal() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // V <= 0  =>  V == 0
        let v = f.new_input(4, Address::new(reg, 0x10));
        let zero = f.new_const(4, 0);
        let le = f.new_op(OpCode::IntLessequal, seq, vec![v, zero]);
        f.new_output_unique(le, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![le],
            ..Default::default()
        }]);
        ActionPool::new("p").with(RuleLessEqual2Zero).apply(&mut f);
        assert_eq!(f.op(le).code(), OpCode::IntEqual);
        assert_eq!(f.op(le).input(0), Some(v));
    }

    #[test]
    fn lessequal2zero_zero_le_v_is_true() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // 0 <= V  =>  true  (COPY #1)
        let zero = f.new_const(4, 0);
        let v = f.new_input(4, Address::new(reg, 0x10));
        let le = f.new_op(OpCode::IntLessequal, seq, vec![zero, v]);
        f.new_output_unique(le, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![le],
            ..Default::default()
        }]);
        ActionPool::new("p").with(RuleLessEqual2Zero).apply(&mut f);
        assert_eq!(f.op(le).code(), OpCode::Copy);
        assert_eq!(f.op(le).num_inputs(), 1);
        let c = f.op(le).input(0).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 1);
    }

    // --- RuleShiftBitops (ruleaction.cc:490) — wired --------------------------

    #[test]
    fn shift_bitops_and_shifted_away_becomes_zero() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (V & 0xf000) << 4  in 2 bytes: 0xf000<<4 clears → result 0 → op input(0) = #0
        let v = f.new_input(2, Address::new(reg, 0x10));
        let m = f.new_const(2, 0xf000);
        let and = f.new_op(OpCode::IntAnd, seq, vec![v, m]);
        let ando = f.new_output_unique(and, 2);
        let sh4 = f.new_const(4, 4);
        let shl = f.new_op(OpCode::IntLeft, seq, vec![ando, sh4]);
        f.new_output_unique(shl, 2);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and, shl],
            ..Default::default()
        }]);
        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        ActionPool::new("p").with(RuleShiftBitops).apply(&mut f);
        assert_eq!(f.op(shl).code(), OpCode::IntLeft);
        let in0 = f.op(shl).input(0).unwrap();
        assert!(f.vn(in0).is_constant() && f.vn(in0).constant_value() == 0);
    }

    #[test]
    fn shift_bitops_add_drops_shifted_out_addend() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (V + 0xf000) << 4  in 2 bytes: the 0xf000 addend shifts out → V << 4
        let v = f.new_input(2, Address::new(reg, 0x10));
        let c = f.new_const(2, 0xf000);
        let add = f.new_op(OpCode::IntAdd, seq, vec![v, c]);
        let addo = f.new_output_unique(add, 2);
        let sh4 = f.new_const(4, 4);
        let shl = f.new_op(OpCode::IntLeft, seq, vec![addo, sh4]);
        f.new_output_unique(shl, 2);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![add, shl],
            ..Default::default()
        }]);
        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        ActionPool::new("p").with(RuleShiftBitops).apply(&mut f);
        assert_eq!(f.op(shl).code(), OpCode::IntLeft);
        assert_eq!(f.op(shl).input(0), Some(v));
    }

    // --- RuleHumptyOr (ruleaction.cc:5332) — wired ----------------------------

    #[test]
    fn humpty_or_full_cover_becomes_copy() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (V & 0xff00) | (V & 0x00ff)  =>  V
        let v = f.new_input(2, Address::new(reg, 0x10));
        let m1 = f.new_const(2, 0xff00);
        let and1 = f.new_op(OpCode::IntAnd, seq, vec![v, m1]);
        let a1o = f.new_output_unique(and1, 2);
        let m2 = f.new_const(2, 0x00ff);
        let and2 = f.new_op(OpCode::IntAnd, seq, vec![v, m2]);
        let a2o = f.new_output_unique(and2, 2);
        let or = f.new_op(OpCode::IntOr, seq, vec![a1o, a2o]);
        f.new_output_unique(or, 2);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and1, and2, or],
            ..Default::default()
        }]);
        ActionPool::new("p").with(RuleHumptyOr).apply(&mut f);
        assert_eq!(f.op(or).code(), OpCode::Copy);
        assert_eq!(f.op(or).input(0), Some(v));
    }

    #[test]
    fn humpty_or_partial_cover_becomes_and() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (V & 0xf000) | (V & 0x000f)  =>  V & 0xf00f
        let v = f.new_input(2, Address::new(reg, 0x10));
        let m1 = f.new_const(2, 0xf000);
        let and1 = f.new_op(OpCode::IntAnd, seq, vec![v, m1]);
        let a1o = f.new_output_unique(and1, 2);
        let m2 = f.new_const(2, 0x000f);
        let and2 = f.new_op(OpCode::IntAnd, seq, vec![v, m2]);
        let a2o = f.new_output_unique(and2, 2);
        let or = f.new_op(OpCode::IntOr, seq, vec![a1o, a2o]);
        f.new_output_unique(or, 2);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and1, and2, or],
            ..Default::default()
        }]);
        ActionPool::new("p").with(RuleHumptyOr).apply(&mut f);
        assert_eq!(f.op(or).code(), OpCode::IntAnd);
        assert_eq!(f.op(or).input(0), Some(v));
        let c = f.op(or).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0xf00f);
    }

    // --- RuleAndPiece (ruleaction.cc:1640) — wired ----------------------------

    #[test]
    fn and_piece_high_masked_becomes_zext() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // concat(W:1, X:1) & 0xff : the 0xff masks off the high byte => AND(zext(X), 0xff)
        let high = f.new_input(1, Address::new(reg, 0x10));
        let low = f.new_input(1, Address::new(reg, 0x18));
        let piece = f.new_op(OpCode::Piece, seq, vec![high, low]);
        let pc = f.new_output_unique(piece, 2);
        let mask = f.new_const(2, 0xff);
        let and = f.new_op(OpCode::IntAnd, seq, vec![pc, mask]);
        f.new_output_unique(and, 2);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![piece, and],
            ..Default::default()
        }]);
        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        ActionPool::new("p").with(RuleAndPiece).apply(&mut f);
        // the PIECE input of the AND is now a ZEXT(low)
        assert_eq!(f.op(and).code(), OpCode::IntAnd);
        let in0 = f.op(and).input(0).unwrap();
        let d = f.vn(in0).def.unwrap();
        assert_eq!(f.op(d).code(), OpCode::IntZext);
        assert_eq!(f.op(d).input(0), Some(low));
    }

    // --- RuleAndDistribute (ruleaction.cc:1254) — ported + held (see doc comment) --

    #[test]
    fn and_distribute_when_term_cancels() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (0xff00 | B) & 0x00ff  =>  (0xff00 & 0x00ff) | (B & 0x00ff)   [first term's mask cancels]
        let a = f.new_const(2, 0xff00);
        let b = f.new_input(2, Address::new(reg, 0x10));
        let or = f.new_op(OpCode::IntOr, seq, vec![a, b]);
        let oro = f.new_output_unique(or, 2);
        let c = f.new_const(2, 0x00ff);
        let and = f.new_op(OpCode::IntAnd, seq, vec![oro, c]);
        f.new_output_unique(and, 2);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![or, and],
            ..Default::default()
        }]);
        assert_eq!(RuleAndDistribute.apply_op(and, &mut f), 1);
        assert_eq!(f.op(and).code(), OpCode::IntOr);
        let (i0, i1) = (f.op(and).input(0).unwrap(), f.op(and).input(1).unwrap());
        let d0 = f.vn(i0).def.unwrap();
        let d1 = f.vn(i1).def.unwrap();
        assert_eq!(f.op(d0).code(), OpCode::IntAnd);
        assert_eq!(f.op(d1).code(), OpCode::IntAnd);
        assert_eq!(f.op(d0).input(0), Some(a)); // A & C
        assert_eq!(f.op(d1).input(0), Some(b)); // B & C
    }

    // --- RulePositiveDiv (ruleaction.cc:7799) ---

    #[test]
    fn positive_div_of_nonnegative_becomes_unsigned() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // num = x & 0x7fffffff  (sign bit provably 0 via nz mask) ; den = 3 (positive const)
        let x = f.new_input(4, Address::new(reg, 0x10));
        let m = f.new_const(4, 0x7fffffff);
        let and = f.new_op(OpCode::IntAnd, seq, vec![x, m]);
        let num = f.new_output_unique(and, 4);
        let three = f.new_const(4, 3);
        let sdiv = f.new_op(OpCode::IntSdiv, seq, vec![num, three]);
        f.new_output(sdiv, 4, Address::new(reg, 0));
        let srem = f.new_op(OpCode::IntSrem, seq, vec![num, three]);
        f.new_output(srem, 4, Address::new(reg, 8));
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and, sdiv, srem],
            ..Default::default()
        }]);
        let dom = crate::decompile::dominator::compute(&f);
        crate::decompile::nzmask::calc_nzmask(&mut f, &dom);
        // Both operands provably non-negative  =>  SDIV→DIV, SREM→REM.
        assert_eq!(RulePositiveDiv.apply_op(sdiv, &mut f), 1);
        assert_eq!(f.op(sdiv).code(), OpCode::IntDiv);
        assert_eq!(RulePositiveDiv.apply_op(srem, &mut f), 1);
        assert_eq!(f.op(srem).code(), OpCode::IntRem);
    }

    #[test]
    fn positive_div_skips_possibly_negative() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // Raw 4-byte input has a full nz mask (sign bit may be set)  =>  rule must not fire.
        let x = f.new_input(4, Address::new(reg, 0x10));
        let three = f.new_const(4, 3);
        let sdiv = f.new_op(OpCode::IntSdiv, seq, vec![x, three]);
        f.new_output(sdiv, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sdiv],
            ..Default::default()
        }]);
        let dom = crate::decompile::dominator::compute(&f);
        crate::decompile::nzmask::calc_nzmask(&mut f, &dom);
        assert_eq!(RulePositiveDiv.apply_op(sdiv, &mut f), 0);
        assert_eq!(f.op(sdiv).code(), OpCode::IntSdiv);
    }

    // --- RuleAndCommute (ruleaction.cc:1532) ---

    #[test]
    fn and_commute_left_const_lonedescend() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (V << 8) & 0xff00   =>   (V & (0xff00 >> 8)) << 8   [the INT_LEFT const fast path]
        let v = f.new_input(2, Address::new(reg, 0x10));
        let sa = f.new_const(4, 8);
        let sh = f.new_op(OpCode::IntLeft, seq, vec![v, sa]);
        let shvn = f.new_output_unique(sh, 2);
        let mask = f.new_const(2, 0xff00);
        let and = f.new_op(OpCode::IntAnd, seq, vec![shvn, mask]);
        f.new_output(and, 2, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sh, and],
            ..Default::default()
        }]);

        assert_eq!(RuleAndCommute.apply_op(and, &mut f), 1);
        // The AND op is now the outer INT_LEFT by the same shift amount.
        assert_eq!(f.op(and).code(), OpCode::IntLeft);
        let outer_sa = f.op(and).input(1).unwrap();
        assert!(f.vn(outer_sa).is_constant() && f.vn(outer_sa).constant_value() == 8);
        // Its shifted value is `V & (0xff00 >> 8)`.
        let inner_and = f.vn(f.op(and).input(0).unwrap()).def.unwrap();
        assert_eq!(f.op(inner_and).code(), OpCode::IntAnd);
        assert_eq!(f.op(inner_and).input(0), Some(v));
        let inner_shift = f.vn(f.op(inner_and).input(1).unwrap()).def.unwrap();
        assert_eq!(f.op(inner_shift).code(), OpCode::IntRight);
        let masked_const = f.op(inner_shift).input(0).unwrap();
        assert!(f.vn(masked_const).is_constant() && f.vn(masked_const).constant_value() == 0xff00);
    }

    #[test]
    fn and_commute_skips_plain_and() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // Neither operand is a shift  =>  rule must not fire.
        let v = f.new_input(4, Address::new(reg, 0x10));
        let w = f.new_input(4, Address::new(reg, 0x18));
        let and = f.new_op(OpCode::IntAnd, seq, vec![v, w]);
        f.new_output(and, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and],
            ..Default::default()
        }]);
        assert_eq!(RuleAndCommute.apply_op(and, &mut f), 0);
        assert_eq!(f.op(and).code(), OpCode::IntAnd);
    }

    #[test]
    fn early_removal_destroys_a_dead_output_keeps_live_and_global() {
        // RuleEarlyRemoval: an op whose unique output has no readers is destroyed; one whose output
        // is read is kept; a written `ram` global is kept (the persist live-out guard).
        let (mut f, _) = fd();
        // The rule now carries Ghidra's `deadRemovalAllowedSeen` guard (ruleaction.cc:38), so it
        // declines on any space that has not been heritaged yet. A default `Funcdata` sits at
        // heritage_pass 0, a state the pipeline never runs a rule pool in; pass 2 is the realistic
        // one (every space past its delay) and it keeps this test exercising what it claims — the ram
        // global is then kept by the PERSIST guard, not incidentally by the delay.
        f.heritage_pass = 2;
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x14));

        // dead: unique output with no descendants → removed.
        let dead = f.new_op(OpCode::IntAdd, seq, vec![a, b]);
        let _dead_out = f.new_output(dead, 4, Address::new(uniq, 0x100));
        assert_eq!(RuleEarlyRemoval.apply_op(dead, &mut f), 1);
        assert!(f.op(dead).is_dead());

        // live: output read by a STORE sink → kept.
        let live = f.new_op(OpCode::IntAdd, seq, vec![a, b]);
        let live_out = f.new_output(live, 4, Address::new(uniq, 0x108));
        let sid = f.new_const(8, ram.0 as u64);
        let ptr = f.new_input(8, Address::new(reg, 0x30));
        let _store = f.new_op(OpCode::Store, seq, vec![sid, ptr, live_out]);
        assert_eq!(RuleEarlyRemoval.apply_op(live, &mut f), 0);
        assert!(!f.op(live).is_dead());

        // ram global: written to a global (ram) address, no SSA reader → kept by the persist guard.
        let glob = f.new_op(OpCode::IntAdd, seq, vec![a, b]);
        let _glob_out = f.new_output(glob, 4, Address::new(ram, 0x601030));
        assert_eq!(RuleEarlyRemoval.apply_op(glob, &mut f), 0);
        assert!(!f.op(glob).is_dead());
    }

    #[test]
    fn scarry_trivial_and_comparison_rewrite() {
        // Trivial: SCARRY(a, 0) → COPY 0.
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let c0 = f.new_const(4, 0);
        let triv = f.new_op(OpCode::IntScarry, seq, vec![a, c0]);
        let _to = f.new_output(triv, 1, Address::new(reg, 0x200));
        assert_eq!(RuleScarry.apply_op(triv, &mut f), 1);
        assert_eq!(f.op(triv).code(), OpCode::Copy);

        // Comparison: `scarry(a, 5) != (0 s< (a + 5))` → a signed compare of `a` against `-5`.
        let c5 = f.new_const(4, 5);
        let sc = f.new_op(OpCode::IntScarry, seq, vec![a, c5]);
        let sc_out = f.new_output(sc, 1, Address::new(reg, 0x208));
        let sum = f.new_op(OpCode::IntAdd, seq, vec![a, c5]);
        let sum_out = f.new_output(sum, 4, Address::new(reg, 0x20c));
        let z = f.new_const(4, 0);
        let sless = f.new_op(OpCode::IntSless, seq, vec![z, sum_out]); // 0 s< (a+5)
        let sless_out = f.new_output(sless, 1, Address::new(reg, 0x210));
        let ne = f.new_op(OpCode::IntNotequal, seq, vec![sc_out, sless_out]);
        let _ne_out = f.new_output(ne, 1, Address::new(reg, 0x218));
        assert_eq!(RuleScarry.apply_op(sc, &mut f), 1);
        // The compare is rewritten to INT_SLESS between `a` and the constant `-5` (0xfffffffb).
        assert_eq!(f.op(ne).code(), OpCode::IntSless);
        let (n0, n1) = (f.op(ne).input(0).unwrap(), f.op(ne).input(1).unwrap());
        let has_a = n0 == a || n1 == a;
        let negc = 5u64.wrapping_neg() & 0xffff_ffff;
        let has_negc = f.vn(n0).is_constant() && f.vn(n0).constant_value() == negc
            || f.vn(n1).is_constant() && f.vn(n1).constant_value() == negc;
        assert!(has_a && has_negc, "compare is `a` vs `-5`");
    }

    #[test]
    fn float_cast_collapses_stacked_casts() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // (float)(double)x, exact narrow back to the source size → identity COPY of x.
        let x4 = f.new_input(4, Address::new(r, 0x10));
        let up = f.new_op(OpCode::FloatFloat2float, seq, vec![x4]);
        let up8 = f.new_output(up, 8, Address::new(r, 0x20));
        let down = f.new_op(OpCode::FloatFloat2float, seq, vec![up8]);
        let _d4 = f.new_output(down, 4, Address::new(r, 0x28));
        assert_eq!(RuleFloatCast.apply_op(down, &mut f), 1);
        assert_eq!(f.op(down).code(), OpCode::Copy);
        assert_eq!(f.op(down).input(0).unwrap(), x4);

        // Superfluous narrow but NOT back to the source size → stays FLOAT2FLOAT, skips the middle
        // cast (insize1 > outsize, outsize != insize2). 10-byte x87 long double → 8 here.
        let y4 = f.new_input(4, Address::new(r, 0x30));
        let up10 = f.new_op(OpCode::FloatFloat2float, seq, vec![y4]);
        let up10o = f.new_output(up10, 10, Address::new(r, 0x40));
        let down8 = f.new_op(OpCode::FloatFloat2float, seq, vec![up10o]);
        let _d8 = f.new_output(down8, 8, Address::new(r, 0x50));
        assert_eq!(RuleFloatCast.apply_op(down8, &mut f), 1);
        assert_eq!(f.op(down8).code(), OpCode::FloatFloat2float);
        assert_eq!(f.op(down8).input(0).unwrap(), y4);

        // (float)(double)(int)n → int straight into the final float size: op becomes INT2FLOAT of n.
        let n4 = f.new_input(4, Address::new(r, 0x60));
        let i2f = f.new_op(OpCode::FloatInt2float, seq, vec![n4]);
        let i2f8 = f.new_output(i2f, 8, Address::new(r, 0x68));
        let narrow = f.new_op(OpCode::FloatFloat2float, seq, vec![i2f8]);
        let _nf4 = f.new_output(narrow, 4, Address::new(r, 0x70));
        assert_eq!(RuleFloatCast.apply_op(narrow, &mut f), 1);
        assert_eq!(f.op(narrow).code(), OpCode::FloatInt2float);
        assert_eq!(f.op(narrow).input(0).unwrap(), n4);

        // trunc((double)z) → float straight into the final integer: op stays TRUNC of the small float.
        let z4 = f.new_input(4, Address::new(r, 0x80));
        let zup = f.new_op(OpCode::FloatFloat2float, seq, vec![z4]);
        let zup8 = f.new_output(zup, 8, Address::new(r, 0x88));
        let trunc = f.new_op(OpCode::FloatTrunc, seq, vec![zup8]);
        let _t4 = f.new_output(trunc, 4, Address::new(r, 0x90));
        assert_eq!(RuleFloatCast.apply_op(trunc, &mut f), 1);
        assert_eq!(f.op(trunc).code(), OpCode::FloatTrunc);
        assert_eq!(f.op(trunc).input(0).unwrap(), z4);

        // Input not defined by a float cast (FLOAT_ADD) → no match.
        let a = f.new_input(8, Address::new(r, 0xa0));
        let b = f.new_input(8, Address::new(r, 0xa8));
        let add = f.new_op(OpCode::FloatAdd, seq, vec![a, b]);
        let add8 = f.new_output(add, 8, Address::new(r, 0xb0));
        let nomatch = f.new_op(OpCode::FloatFloat2float, seq, vec![add8]);
        let _nm4 = f.new_output(nomatch, 4, Address::new(r, 0xb8));
        assert_eq!(RuleFloatCast.apply_op(nomatch, &mut f), 0);
        assert_eq!(f.op(nomatch).code(), OpCode::FloatFloat2float);
    }

    #[test]
    fn shift_and_drops_redundant_mask() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // (v & 0xff00) >> 8, with v's non-zero bits confined to 0xff00: after the shift the mask
        // (0xff) covers all of v's possibly-nonzero bits (0xff), so the AND is redundant → COPY.
        let v = f.new_input(4, Address::new(r, 0x10));
        f.vn_mut(v).nzm = 0xff00;
        let m = f.new_const(4, 0xff00);
        let c8 = f.new_const(4, 8);
        let and = f.new_op(OpCode::IntAnd, seq, vec![v, m]);
        let ando = f.new_output(and, 4, Address::new(r, 0x18));
        let sh = f.new_op(OpCode::IntRight, seq, vec![ando, c8]);
        let _o = f.new_output(sh, 4, Address::new(r, 0x20));
        assert_eq!(RuleShiftAnd.apply_op(sh, &mut f), 1);
        assert_eq!(f.op(and).code(), OpCode::Copy);
        assert_eq!(f.op(and).inrefs.len(), 1);

        // INT_MULT by a power of two (16) is treated as a left shift by 4; nzm 0x0f, mask 0x0f →
        // after `<< 4` mask 0xf0 covers nzm 0xf0 → redundant AND → COPY.
        let v2 = f.new_input(4, Address::new(r, 0x30));
        f.vn_mut(v2).nzm = 0x0f;
        let m2 = f.new_const(4, 0x0f);
        let c16 = f.new_const(4, 16);
        let and2 = f.new_op(OpCode::IntAnd, seq, vec![v2, m2]);
        let and2o = f.new_output(and2, 4, Address::new(r, 0x38));
        let mul = f.new_op(OpCode::IntMult, seq, vec![and2o, c16]);
        let _o2 = f.new_output(mul, 4, Address::new(r, 0x40));
        assert_eq!(RuleShiftAnd.apply_op(mul, &mut f), 1);
        assert_eq!(f.op(and2).code(), OpCode::Copy);

        // No fire: mask 0x0f does NOT cover the bits v can set (nzm 0xff) after `<< 4`.
        let v3 = f.new_input(4, Address::new(r, 0x50));
        f.vn_mut(v3).nzm = 0xff;
        let m3 = f.new_const(4, 0x0f);
        let c4 = f.new_const(4, 4);
        let and3 = f.new_op(OpCode::IntAnd, seq, vec![v3, m3]);
        let and3o = f.new_output(and3, 4, Address::new(r, 0x58));
        let shl = f.new_op(OpCode::IntLeft, seq, vec![and3o, c4]);
        let _o3 = f.new_output(shl, 4, Address::new(r, 0x60));
        assert_eq!(RuleShiftAnd.apply_op(shl, &mut f), 0);
        assert_eq!(f.op(and3).code(), OpCode::IntAnd);

        // No fire: INT_MULT by a non-power-of-two (3) is not a shift.
        let v4 = f.new_input(4, Address::new(r, 0x70));
        f.vn_mut(v4).nzm = 0x0f;
        let m4 = f.new_const(4, 0x0f);
        let c3 = f.new_const(4, 3);
        let and4 = f.new_op(OpCode::IntAnd, seq, vec![v4, m4]);
        let and4o = f.new_output(and4, 4, Address::new(r, 0x78));
        let mul3 = f.new_op(OpCode::IntMult, seq, vec![and4o, c3]);
        let _o4 = f.new_output(mul3, 4, Address::new(r, 0x80));
        assert_eq!(RuleShiftAnd.apply_op(mul3, &mut f), 0);
        assert_eq!(f.op(and4).code(), OpCode::IntAnd);
    }

    #[test]
    fn concat_commute_pulls_concat_inside() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // concat(V, W | c)  =>  concat(V,W) | c   (i==1 branch, no shift of the constant).
        let vv = f.new_input(2, Address::new(r, 0x10));
        let ww = f.new_input(2, Address::new(r, 0x18));
        let c = f.new_const(2, 0x0055);
        let orop = f.new_op(OpCode::IntOr, seq, vec![ww, c]);
        let oro = f.new_output(orop, 2, Address::new(r, 0x20));
        let pc = f.new_op(OpCode::Piece, seq, vec![vv, oro]);
        let _po = f.new_output(pc, 4, Address::new(r, 0x28));
        assert_eq!(RuleConcatCommute.apply_op(pc, &mut f), 1);
        assert_eq!(f.op(pc).code(), OpCode::IntOr);
        let inner = f.op(pc).input(0).unwrap();
        let idef = f.vn(inner).def.unwrap();
        assert_eq!(f.op(idef).code(), OpCode::Piece);
        assert_eq!(f.op(idef).input(0).unwrap(), vv);
        assert_eq!(f.op(idef).input(1).unwrap(), ww);
        let cst = f.op(pc).input(1).unwrap();
        assert!(f.vn(cst).is_constant() && f.vn(cst).constant_value() == 0x0055);

        // concat(V & c, W)  =>  concat(V,W) & ((c << 8|W|) | mask(|W|))   (i==0 branch).
        let v2 = f.new_input(1, Address::new(r, 0x30));
        let w2 = f.new_input(1, Address::new(r, 0x38));
        let c2 = f.new_const(1, 0x0f);
        let andop = f.new_op(OpCode::IntAnd, seq, vec![v2, c2]);
        let ando = f.new_output(andop, 1, Address::new(r, 0x40));
        let pc2 = f.new_op(OpCode::Piece, seq, vec![ando, w2]);
        let _po2 = f.new_output(pc2, 2, Address::new(r, 0x48));
        assert_eq!(RuleConcatCommute.apply_op(pc2, &mut f), 1);
        assert_eq!(f.op(pc2).code(), OpCode::IntAnd);
        let cst2 = f.op(pc2).input(1).unwrap();
        // low byte (W) fully kept = 0xff; high byte (V) keeps low nibble = 0x0f << 8 = 0xf00.
        assert!(f.vn(cst2).is_constant() && f.vn(cst2).constant_value() == 0x0fff);
    }

    #[test]
    fn concat_zext_pulls_zext_out() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // concat(zext(V), W)  =>  zext(concat(V,W)).
        let vv = f.new_input(2, Address::new(r, 0x10));
        let ww = f.new_input(2, Address::new(r, 0x18));
        let ze = f.new_op(OpCode::IntZext, seq, vec![vv]);
        let zeo = f.new_output(ze, 4, Address::new(r, 0x20));
        let pc = f.new_op(OpCode::Piece, seq, vec![zeo, ww]);
        let _po = f.new_output(pc, 6, Address::new(r, 0x28));
        assert_eq!(RuleConcatZext.apply_op(pc, &mut f), 1);
        assert_eq!(f.op(pc).code(), OpCode::IntZext);
        assert_eq!(f.op(pc).inrefs.len(), 1);
        let inner = f.op(pc).input(0).unwrap();
        let idef = f.vn(inner).def.unwrap();
        assert_eq!(f.op(idef).code(), OpCode::Piece);
        assert_eq!(f.op(idef).input(0).unwrap(), vv);
        assert_eq!(f.op(idef).input(1).unwrap(), ww);
        // the inner concat is the unextended width |V|+|W| = 4, not the 6-byte output.
        assert_eq!(f.vn(inner).size, 4);

        // No fire: high input not defined by a ZEXT.
        let a = f.new_input(4, Address::new(r, 0x30));
        let b = f.new_input(2, Address::new(r, 0x38));
        let pc2 = f.new_op(OpCode::Piece, seq, vec![a, b]);
        let _po2 = f.new_output(pc2, 6, Address::new(r, 0x40));
        assert_eq!(RuleConcatZext.apply_op(pc2, &mut f), 0);
        assert_eq!(f.op(pc2).code(), OpCode::Piece);
    }

    #[test]
    fn zext_commute_moves_shift_under_zext() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // zext(V) >> 8  =>  zext(V >> 8).
        let vv = f.new_input(2, Address::new(r, 0x10));
        let ze = f.new_op(OpCode::IntZext, seq, vec![vv]);
        let zeo = f.new_output(ze, 4, Address::new(r, 0x18));
        let c8 = f.new_const(4, 8);
        let shr = f.new_op(OpCode::IntRight, seq, vec![zeo, c8]);
        let _o = f.new_output(shr, 4, Address::new(r, 0x20));
        assert_eq!(RuleZextCommute.apply_op(shr, &mut f), 1);
        assert_eq!(f.op(shr).code(), OpCode::IntZext);
        assert_eq!(f.op(shr).inrefs.len(), 1);
        let inner = f.op(shr).input(0).unwrap();
        let idef = f.vn(inner).def.unwrap();
        assert_eq!(f.op(idef).code(), OpCode::IntRight);
        assert_eq!(f.op(idef).input(0).unwrap(), vv);
        assert_eq!(f.vn(inner).size, 2); // shift is on the unextended width
    }

    #[test]
    fn concat_zero_becomes_zext_shift() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // concat(V, 0) => zext(V) << 16  (the zero operand is 2 bytes = 16 bits).
        let vv = f.new_input(2, Address::new(r, 0x10));
        let z = f.new_const(2, 0);
        let pc = f.new_op(OpCode::Piece, seq, vec![vv, z]);
        let _po = f.new_output(pc, 4, Address::new(r, 0x18));
        assert_eq!(RuleConcatZero.apply_op(pc, &mut f), 1);
        assert_eq!(f.op(pc).code(), OpCode::IntLeft);
        let sh = f.op(pc).input(1).unwrap();
        assert!(f.vn(sh).is_constant() && f.vn(sh).constant_value() == 16);
        let zx = f.op(pc).input(0).unwrap();
        assert_eq!(f.op(f.vn(zx).def.unwrap()).code(), OpCode::IntZext);

        // No fire: low part not the zero constant.
        let a = f.new_input(2, Address::new(r, 0x30));
        let b = f.new_const(2, 5);
        let pc2 = f.new_op(OpCode::Piece, seq, vec![a, b]);
        let _po2 = f.new_output(pc2, 4, Address::new(r, 0x38));
        assert_eq!(RuleConcatZero.apply_op(pc2, &mut f), 0);
    }

    #[test]
    fn concat_left_shift_refactors_to_nested_concat() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // concat(V, zext(W) << 16) => concat(concat(V,W), 0), when zext(W)<<16 top-justifies W.
        let vv = f.new_input(2, Address::new(r, 0x10)); // V
        let ww = f.new_input(2, Address::new(r, 0x18)); // W
        let ze = f.new_op(OpCode::IntZext, seq, vec![ww]);
        let zeo = f.new_output(ze, 4, Address::new(r, 0x20)); // zext(W), 4 bytes
        let c16 = f.new_const(4, 16); // 16 bits = 2 bytes; 2 + |W|(2) == 4 = |zext(W)|
        let shl = f.new_op(OpCode::IntLeft, seq, vec![zeo, c16]);
        let shlo = f.new_output(shl, 4, Address::new(r, 0x28));
        let pc = f.new_op(OpCode::Piece, seq, vec![vv, shlo]);
        let _po = f.new_output(pc, 6, Address::new(r, 0x30));
        assert_eq!(RuleConcatLeftShift.apply_op(pc, &mut f), 1);
        assert_eq!(f.op(pc).code(), OpCode::Piece);
        let inner = f.op(pc).input(0).unwrap();
        let idef = f.vn(inner).def.unwrap();
        assert_eq!(f.op(idef).code(), OpCode::Piece);
        assert_eq!(f.op(idef).input(0).unwrap(), vv);
        assert_eq!(f.op(idef).input(1).unwrap(), ww);
        assert_eq!(f.vn(inner).size, 4); // |V|+|W|
        let lo = f.op(pc).input(1).unwrap();
        assert!(f.vn(lo).is_constant() && f.vn(lo).constant_value() == 0 && f.vn(lo).size == 2);
    }

    #[test]
    fn double_sub_collapses_chained_subpiece() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // sub(sub(V, 2), 1) => sub(V, 3).
        let v = f.new_input(8, Address::new(r, 0x10));
        let c2 = f.new_const(4, 2);
        let inner = f.new_op(OpCode::Subpiece, seq, vec![v, c2]);
        let innero = f.new_output(inner, 4, Address::new(r, 0x18));
        let c1 = f.new_const(4, 1);
        let outer = f.new_op(OpCode::Subpiece, seq, vec![innero, c1]);
        let _o = f.new_output(outer, 2, Address::new(r, 0x20));
        assert_eq!(RuleDoubleSub.apply_op(outer, &mut f), 1);
        assert_eq!(f.op(outer).input(0).unwrap(), v);
        let off = f.op(outer).input(1).unwrap();
        assert!(f.vn(off).is_constant() && f.vn(off).constant_value() == 3);
    }

    #[test]
    fn double_shift_combines_cancels_saturates() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // Same direction: (V << 2) << 3 => V << 5.
        let v = f.new_input(4, Address::new(r, 0x10));
        let c2 = f.new_const(4, 2);
        let inner = f.new_op(OpCode::IntLeft, seq, vec![v, c2]);
        let innero = f.new_output(inner, 4, Address::new(r, 0x18));
        let c3 = f.new_const(4, 3);
        let outer = f.new_op(OpCode::IntLeft, seq, vec![innero, c3]);
        let _o = f.new_output(outer, 4, Address::new(r, 0x20));
        assert_eq!(RuleDoubleShift.apply_op(outer, &mut f), 1);
        assert_eq!(f.op(outer).code(), OpCode::IntLeft);
        assert_eq!(f.op(outer).input(0).unwrap(), v);
        assert_eq!(f.vn(f.op(outer).input(1).unwrap()).constant_value(), 5);

        // Opposite equal shifts: (V << 3) >> 3 => V & 0x1fffffff.
        let v2 = f.new_input(4, Address::new(r, 0x30));
        let c3b = f.new_const(4, 3);
        let l = f.new_op(OpCode::IntLeft, seq, vec![v2, c3b]);
        let lo = f.new_output(l, 4, Address::new(r, 0x38));
        let c3c = f.new_const(4, 3);
        let rgt = f.new_op(OpCode::IntRight, seq, vec![lo, c3c]);
        let _ro = f.new_output(rgt, 4, Address::new(r, 0x40));
        assert_eq!(RuleDoubleShift.apply_op(rgt, &mut f), 1);
        assert_eq!(f.op(rgt).code(), OpCode::IntAnd);
        assert_eq!(f.op(rgt).input(0).unwrap(), v2);
        assert_eq!(f.vn(f.op(rgt).input(1).unwrap()).constant_value(), 0x1fff_ffff);

        // Same direction shifting the whole word out: (V << 20) << 20 => COPY 0.
        let v3 = f.new_input(4, Address::new(r, 0x50));
        let c20 = f.new_const(4, 20);
        let s1 = f.new_op(OpCode::IntLeft, seq, vec![v3, c20]);
        let s1o = f.new_output(s1, 4, Address::new(r, 0x58));
        let c20b = f.new_const(4, 20);
        let s2 = f.new_op(OpCode::IntLeft, seq, vec![s1o, c20b]);
        let _s2o = f.new_output(s2, 4, Address::new(r, 0x60));
        assert_eq!(RuleDoubleShift.apply_op(s2, &mut f), 1);
        assert_eq!(f.op(s2).code(), OpCode::Copy);
        assert_eq!(f.vn(f.op(s2).input(0).unwrap()).constant_value(), 0);
    }

    #[test]
    fn double_arith_shift_saturates_signed() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // (x s>> 2) s>> 3 => x s>> 5.
        let x = f.new_input(4, Address::new(r, 0x10));
        let c2 = f.new_const(4, 2);
        let inner = f.new_op(OpCode::IntSright, seq, vec![x, c2]);
        let innero = f.new_output(inner, 4, Address::new(r, 0x18));
        let c3 = f.new_const(4, 3);
        let outer = f.new_op(OpCode::IntSright, seq, vec![innero, c3]);
        let _o = f.new_output(outer, 4, Address::new(r, 0x20));
        assert_eq!(RuleDoubleArithShift.apply_op(outer, &mut f), 1);
        assert_eq!(f.op(outer).input(0).unwrap(), x);
        assert_eq!(f.vn(f.op(outer).input(1).unwrap()).constant_value(), 5);

        // Saturates at |out|*8 - 1 = 31 for a 4-byte result: (x s>> 20) s>> 20 => x s>> 31.
        let y = f.new_input(4, Address::new(r, 0x30));
        let c20 = f.new_const(4, 20);
        let s1 = f.new_op(OpCode::IntSright, seq, vec![y, c20]);
        let s1o = f.new_output(s1, 4, Address::new(r, 0x38));
        let c20b = f.new_const(4, 20);
        let s2 = f.new_op(OpCode::IntSright, seq, vec![s1o, c20b]);
        let _s2o = f.new_output(s2, 4, Address::new(r, 0x40));
        assert_eq!(RuleDoubleArithShift.apply_op(s2, &mut f), 1);
        assert_eq!(f.vn(f.op(s2).input(1).unwrap()).constant_value(), 31);
    }

    #[test]
    fn concat_shift_cancels_least_part() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // Exact cancel: concat(V, W) >> 16 => zext(V)  (|W| = 2 bytes = 16 bits).
        let v = f.new_input(2, Address::new(r, 0x10));
        let w = f.new_input(2, Address::new(r, 0x18));
        let pc = f.new_op(OpCode::Piece, seq, vec![v, w]);
        let pco = f.new_output(pc, 4, Address::new(r, 0x20));
        let c16 = f.new_const(4, 16);
        let sh = f.new_op(OpCode::IntRight, seq, vec![pco, c16]);
        let _o = f.new_output(sh, 4, Address::new(r, 0x28));
        assert_eq!(RuleConcatShift.apply_op(sh, &mut f), 1);
        assert_eq!(f.op(sh).code(), OpCode::IntZext);
        assert_eq!(f.op(sh).inrefs.len(), 1);
        assert_eq!(f.op(sh).input(0).unwrap(), v);

        // Residual: concat(V, W) >> 24 => zext(V) >> 8.
        let v2 = f.new_input(2, Address::new(r, 0x30));
        let w2 = f.new_input(2, Address::new(r, 0x38));
        let pc2 = f.new_op(OpCode::Piece, seq, vec![v2, w2]);
        let pc2o = f.new_output(pc2, 4, Address::new(r, 0x40));
        let c24 = f.new_const(4, 24);
        let sh2 = f.new_op(OpCode::IntRight, seq, vec![pc2o, c24]);
        let _o2 = f.new_output(sh2, 4, Address::new(r, 0x48));
        assert_eq!(RuleConcatShift.apply_op(sh2, &mut f), 1);
        assert_eq!(f.op(sh2).code(), OpCode::IntRight);
        assert_eq!(f.vn(f.op(sh2).input(1).unwrap()).constant_value(), 8);
        let ext = f.op(sh2).input(0).unwrap();
        assert_eq!(f.op(f.vn(ext).def.unwrap()).code(), OpCode::IntZext);
        assert_eq!(f.op(f.vn(ext).def.unwrap()).input(0).unwrap(), v2);

        // Signed shift extends via SEXT: concat(V, W) s>> 16 => sext(V).
        let v3 = f.new_input(2, Address::new(r, 0x50));
        let w3 = f.new_input(2, Address::new(r, 0x58));
        let pc3 = f.new_op(OpCode::Piece, seq, vec![v3, w3]);
        let pc3o = f.new_output(pc3, 4, Address::new(r, 0x60));
        let c16b = f.new_const(4, 16);
        let sh3 = f.new_op(OpCode::IntSright, seq, vec![pc3o, c16b]);
        let _o3 = f.new_output(sh3, 4, Address::new(r, 0x68));
        assert_eq!(RuleConcatShift.apply_op(sh3, &mut f), 1);
        assert_eq!(f.op(sh3).code(), OpCode::IntSext);
        assert_eq!(f.op(sh3).input(0).unwrap(), v3);

        // No fire: shift smaller than the least part (8 < 16) keeps some of W.
        let v4 = f.new_input(2, Address::new(r, 0x70));
        let w4 = f.new_input(2, Address::new(r, 0x78));
        let pc4 = f.new_op(OpCode::Piece, seq, vec![v4, w4]);
        let pc4o = f.new_output(pc4, 4, Address::new(r, 0x80));
        let c8 = f.new_const(4, 8);
        let sh4 = f.new_op(OpCode::IntRight, seq, vec![pc4o, c8]);
        let _o4 = f.new_output(sh4, 4, Address::new(r, 0x88));
        assert_eq!(RuleConcatShift.apply_op(sh4, &mut f), 0);
        assert_eq!(f.op(sh4).code(), OpCode::IntRight);
    }

    #[test]
    fn sign_form_normalizes_sext_subpiece() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // sub(sext(V), 4) => V s>> 31  (V is 4 bytes; the SUBPIECE takes the sign-extension bytes).
        let v = f.new_input(4, Address::new(r, 0x10));
        let sx = f.new_op(OpCode::IntSext, seq, vec![v]);
        let sxo = f.new_output(sx, 8, Address::new(r, 0x18));
        let c4 = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![sxo, c4]);
        let _o = f.new_output(sub, 4, Address::new(r, 0x20));
        assert_eq!(RuleSignForm.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::IntSright);
        assert_eq!(f.op(sub).input(0).unwrap(), v);
        assert_eq!(f.vn(f.op(sub).input(1).unwrap()).constant_value(), 31);

        // No fire: SUBPIECE offset below V's width still lands inside V, not the sign extension.
        let v2 = f.new_input(4, Address::new(r, 0x30));
        let sx2 = f.new_op(OpCode::IntSext, seq, vec![v2]);
        let sx2o = f.new_output(sx2, 8, Address::new(r, 0x38));
        let c2 = f.new_const(4, 2);
        let sub2 = f.new_op(OpCode::Subpiece, seq, vec![sx2o, c2]);
        let _o2 = f.new_output(sub2, 4, Address::new(r, 0x40));
        assert_eq!(RuleSignForm.apply_op(sub2, &mut f), 0);
        assert_eq!(f.op(sub2).code(), OpCode::Subpiece);
    }

    #[test]
    fn sign_shift_converts_logical_to_arithmetic_when_arith_fed() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        // (V >> 63) feeding an INT_ADD  =>  (V s>> 63) * -1
        let v = f.new_input(8, Address::new(r, 0x10));
        let sh = f.new_const(8, 0x3f);
        let op = f.new_op(OpCode::IntRight, seq, vec![v, sh]);
        let opo = f.new_output(op, 8, Address::new(r, 0x18));
        let w = f.new_input(8, Address::new(r, 0x20));
        let add = f.new_op(OpCode::IntAdd, seq, vec![opo, w]);
        let _ = f.new_output(add, 8, Address::new(r, 0x28));

        assert_eq!(RuleSignShift.apply_op(op, &mut f), 1);
        assert_eq!(f.op(op).code(), OpCode::IntMult);
        assert_eq!(f.vn(f.op(op).input(1).unwrap()).constant_value(), super::super::nzmask::calc_mask(8));
        let sr = f.vn(f.op(op).input(0).unwrap()).def.unwrap();
        assert_eq!(f.op(sr).code(), OpCode::IntSright);
        assert_eq!(f.op(sr).input(0), Some(v));
        assert_eq!(f.vn(f.op(sr).input(1).unwrap()).constant_value(), 0x3f);

        // No fire when the sign bit is not fed into arithmetic/comparison.
        let v2 = f.new_input(8, Address::new(r, 0x40));
        let sh2 = f.new_const(8, 0x3f);
        let op2 = f.new_op(OpCode::IntRight, seq, vec![v2, sh2]);
        let _ = f.new_output(op2, 8, Address::new(r, 0x48));
        assert_eq!(RuleSignShift.apply_op(op2, &mut f), 0);
    }

    #[test]
    fn test_sign_rewrites_sign_bit_tests_as_signed_compares() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        // sign = V s>> 63; then  (sign != 0) => V s< 0   and   (sign == 0) => 0 s<= V
        let v = f.new_input(8, Address::new(r, 0x10));
        let sh = f.new_const(8, 0x3f);
        let op = f.new_op(OpCode::IntSright, seq, vec![v, sh]);
        let opo = f.new_output(op, 8, Address::new(r, 0x18));
        let z1 = f.new_const(8, 0);
        let ne = f.new_op(OpCode::IntNotequal, seq, vec![opo, z1]);
        let _ = f.new_output(ne, 1, Address::new(r, 0x20));
        let z2 = f.new_const(8, 0);
        let eq = f.new_op(OpCode::IntEqual, seq, vec![opo, z2]);
        let _ = f.new_output(eq, 1, Address::new(r, 0x28));

        assert_eq!(RuleTestSign.apply_op(op, &mut f), 1);
        // NOTEQUAL vs 0  =>  V s< 0
        assert_eq!(f.op(ne).code(), OpCode::IntSless);
        assert_eq!(f.op(ne).input(0), Some(v));
        assert_eq!(f.vn(f.op(ne).input(1).unwrap()).constant_value(), 0);
        // EQUAL vs 0  =>  0 s<= V
        assert_eq!(f.op(eq).code(), OpCode::IntSlessequal);
        assert_eq!(f.vn(f.op(eq).input(0).unwrap()).constant_value(), 0);
        assert_eq!(f.op(eq).input(1), Some(v));
    }

    #[test]
    fn sign_form2_repoints_through_nonoverflow_mult_and_returns_zero() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        // sub(sext(V) * 3, 4) s>> 31  =>  repoints shift input to V, returns 0 (faithful quirk)
        let v = f.new_input(4, Address::new(r, 0x10));
        let sx = f.new_op(OpCode::IntSext, seq, vec![v]);
        let sxo = f.new_output(sx, 8, Address::new(r, 0x18));
        let small = f.new_const(8, 3);
        let mult = f.new_op(OpCode::IntMult, seq, vec![sxo, small]);
        let multo = f.new_output(mult, 8, Address::new(r, 0x20));
        let c4 = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![multo, c4]);
        let subo = f.new_output(sub, 4, Address::new(r, 0x28));
        let sh31 = f.new_const(4, 31);
        let op = f.new_op(OpCode::IntSright, seq, vec![subo, sh31]);
        let _ = f.new_output(op, 4, Address::new(r, 0x30));

        assert_eq!(RuleSignForm2.apply_op(op, &mut f), 0); // faithful: reports no-change
        assert_eq!(f.op(op).input(0), Some(v)); // but the shift input was repointed to V
        assert_eq!(f.op(op).code(), OpCode::IntSright);
    }

    #[test]
    fn trivial_bool_folds_constant_operand() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let mut addr = 0x10u64;
        // Build `V <bop> const` and return the op id.
        let mut mk = |f: &mut Funcdata, bop: OpCode, k: u64| -> (VarnodeId, OpId) {
            let v = f.new_input(1, Address::new(r, addr));
            let c = f.new_const(1, k);
            let o = f.new_op(bop, seq, vec![v, c]);
            f.new_output(o, 1, Address::new(r, addr + 8));
            addr += 0x10;
            (v, o)
        };

        // V && false => false (COPY 0);  V && true => V.
        let (_v, o) = mk(&mut f, OpCode::BoolAnd, 0);
        assert_eq!(RuleTrivialBool.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::Copy);
        assert!(f.vn(f.op(o).input(0).unwrap()).is_constant() && f.vn(f.op(o).input(0).unwrap()).constant_value() == 0);
        let (v, o) = mk(&mut f, OpCode::BoolAnd, 1);
        assert_eq!(RuleTrivialBool.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::Copy);
        assert_eq!(f.op(o).input(0).unwrap(), v);

        // V || false => V;  V || true => true (COPY 1).
        let (v, o) = mk(&mut f, OpCode::BoolOr, 0);
        assert_eq!(RuleTrivialBool.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::Copy);
        assert_eq!(f.op(o).input(0).unwrap(), v);
        let (_v, o) = mk(&mut f, OpCode::BoolOr, 1);
        assert_eq!(RuleTrivialBool.apply_op(o, &mut f), 1);
        assert!(f.vn(f.op(o).input(0).unwrap()).is_constant() && f.vn(f.op(o).input(0).unwrap()).constant_value() == 1);

        // V ^^ true => !V (BOOL_NEGATE);  V ^^ false => V.
        let (v, o) = mk(&mut f, OpCode::BoolXor, 1);
        assert_eq!(RuleTrivialBool.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::BoolNegate);
        assert_eq!(f.op(o).input(0).unwrap(), v);
        let (v, o) = mk(&mut f, OpCode::BoolXor, 0);
        assert_eq!(RuleTrivialBool.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::Copy);
        assert_eq!(f.op(o).input(0).unwrap(), v);
    }

    #[test]
    fn less2zero_folds_extremal_constants() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let mut a = 0x10u64;
        let mut less = |f: &mut Funcdata, l: Option<u64>, rr: Option<u64>| -> OpId {
            let lv = match l {
                Some(k) => f.new_const(4, k),
                None => f.new_input(4, Address::new(r, a)),
            };
            let rv = match rr {
                Some(k) => f.new_const(4, k),
                None => f.new_input(4, Address::new(r, a + 8)),
            };
            let o = f.new_op(OpCode::IntLess, seq, vec![lv, rv]);
            f.new_output(o, 1, Address::new(r, a + 0x10));
            a += 0x20;
            o
        };
        let max = 0xffff_ffffu64;

        // 0 < V  =>  0 != V
        let o = less(&mut f, Some(0), None);
        assert_eq!(RuleLess2Zero.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::IntNotequal);

        // max < V  =>  false
        let o = less(&mut f, Some(max), None);
        assert_eq!(RuleLess2Zero.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::Copy);
        assert!(f.vn(f.op(o).input(0).unwrap()).is_constant() && f.vn(f.op(o).input(0).unwrap()).constant_value() == 0);

        // V < 0  =>  false
        let o = less(&mut f, None, Some(0));
        assert_eq!(RuleLess2Zero.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::Copy);
        assert!(f.vn(f.op(o).input(0).unwrap()).is_constant() && f.vn(f.op(o).input(0).unwrap()).constant_value() == 0);

        // V < max  =>  V != max
        let o = less(&mut f, None, Some(max));
        assert_eq!(RuleLess2Zero.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::IntNotequal);

        // V < 5  =>  no fire
        let o = less(&mut f, None, Some(5));
        assert_eq!(RuleLess2Zero.apply_op(o, &mut f), 0);
        assert_eq!(f.op(o).code(), OpCode::IntLess);
    }

    #[test]
    fn or_consume_drops_unconsumed_input() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // A|B where A's bits (0xff000000) are never consumed (out consume = 0xff) => COPY B.
        let a = f.new_input(4, Address::new(r, 0x10));
        f.vn_mut(a).nzm = 0xff00_0000;
        let b = f.new_input(4, Address::new(r, 0x18));
        f.vn_mut(b).nzm = 0x0000_00ff;
        let o = f.new_op(OpCode::IntOr, seq, vec![a, b]);
        let out = f.new_output(o, 4, Address::new(r, 0x20));
        f.vn_mut(out).consume = 0x0000_00ff;
        assert_eq!(RuleOrConsume.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::Copy);
        assert_eq!(f.op(o).inrefs.len(), 1);
        assert_eq!(f.op(o).input(0).unwrap(), b);

        // Symmetric: B's bits unconsumed => COPY A (drops input 1).
        let a2 = f.new_input(4, Address::new(r, 0x30));
        f.vn_mut(a2).nzm = 0x0000_00ff;
        let b2 = f.new_input(4, Address::new(r, 0x38));
        f.vn_mut(b2).nzm = 0xff00_0000;
        let o2 = f.new_op(OpCode::IntOr, seq, vec![a2, b2]);
        let out2 = f.new_output(o2, 4, Address::new(r, 0x40));
        f.vn_mut(out2).consume = 0x0000_00ff;
        assert_eq!(RuleOrConsume.apply_op(o2, &mut f), 1);
        assert_eq!(f.op(o2).code(), OpCode::Copy);
        assert_eq!(f.op(o2).input(0).unwrap(), a2);

        // No fire: both inputs have consumed bits.
        let a3 = f.new_input(4, Address::new(r, 0x50));
        f.vn_mut(a3).nzm = 0x0000_000f;
        let b3 = f.new_input(4, Address::new(r, 0x58));
        f.vn_mut(b3).nzm = 0x0000_00f0;
        let o3 = f.new_op(OpCode::IntOr, seq, vec![a3, b3]);
        let out3 = f.new_output(o3, 4, Address::new(r, 0x60));
        f.vn_mut(out3).consume = 0x0000_00ff;
        assert_eq!(RuleOrConsume.apply_op(o3, &mut f), 0);
        assert_eq!(f.op(o3).code(), OpCode::IntOr);
    }

    #[test]
    fn equal2constant_folds_arith_through_compare() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // V + 3 == 10  =>  V == 7
        let v = f.new_input(4, Address::new(r, 0x10));
        let c3 = f.new_const(4, 3);
        let add = f.new_op(OpCode::IntAdd, seq, vec![v, c3]);
        let addo = f.new_output(add, 4, Address::new(r, 0x18));
        let c10 = f.new_const(4, 10);
        let eq = f.new_op(OpCode::IntEqual, seq, vec![addo, c10]);
        let _eo = f.new_output(eq, 1, Address::new(r, 0x20));
        assert_eq!(RuleEqual2Constant.apply_op(eq, &mut f), 1);
        assert_eq!(f.op(eq).input(0).unwrap(), v);
        assert_eq!(f.vn(f.op(eq).input(1).unwrap()).constant_value(), 7);

        // V * -1 == 5  =>  V == -5 (0xfffffffb)
        let v2 = f.new_input(4, Address::new(r, 0x30));
        let cm1 = f.new_const(4, 0xffff_ffff);
        let mul = f.new_op(OpCode::IntMult, seq, vec![v2, cm1]);
        let mulo = f.new_output(mul, 4, Address::new(r, 0x38));
        let c5 = f.new_const(4, 5);
        let eq2 = f.new_op(OpCode::IntEqual, seq, vec![mulo, c5]);
        let _eo2 = f.new_output(eq2, 1, Address::new(r, 0x40));
        assert_eq!(RuleEqual2Constant.apply_op(eq2, &mut f), 1);
        assert_eq!(f.op(eq2).input(0).unwrap(), v2);
        assert_eq!(f.vn(f.op(eq2).input(1).unwrap()).constant_value(), 0xffff_fffb);

        // ~V == 0xf  =>  V == ~0xf (0xfffffff0)
        let v3 = f.new_input(4, Address::new(r, 0x50));
        let neg = f.new_op(OpCode::IntNegate, seq, vec![v3]);
        let nego = f.new_output(neg, 4, Address::new(r, 0x58));
        let cf = f.new_const(4, 0xf);
        let eq3 = f.new_op(OpCode::IntEqual, seq, vec![nego, cf]);
        let _eo3 = f.new_output(eq3, 1, Address::new(r, 0x60));
        assert_eq!(RuleEqual2Constant.apply_op(eq3, &mut f), 1);
        assert_eq!(f.op(eq3).input(0).unwrap(), v3);
        assert_eq!(f.vn(f.op(eq3).input(1).unwrap()).constant_value(), 0xffff_fff0);

        // No fire: the arith result is also used in a non-comparison (INT_ADD).
        let v4 = f.new_input(4, Address::new(r, 0x70));
        let c1 = f.new_const(4, 1);
        let add4 = f.new_op(OpCode::IntAdd, seq, vec![v4, c1]);
        let add4o = f.new_output(add4, 4, Address::new(r, 0x78));
        let c2 = f.new_const(4, 2);
        let eq4 = f.new_op(OpCode::IntEqual, seq, vec![add4o, c2]);
        let _eo4 = f.new_output(eq4, 1, Address::new(r, 0x80));
        let c9 = f.new_const(4, 9);
        let other = f.new_op(OpCode::IntAdd, seq, vec![add4o, c9]); // non-comparison use of add4o
        let _oo = f.new_output(other, 4, Address::new(r, 0x88));
        assert_eq!(RuleEqual2Constant.apply_op(eq4, &mut f), 0);
        assert_eq!(f.op(eq4).input(0).unwrap(), add4o);
    }

    // ---- RuleBoolZext (#62) --------------------------------------------------------------------
    // Builds a `zext(V) * -1` extended-boolean and drives each of the three action forms.

    /// Wire up `zext(V) * -1` where `V` is a real boolean (INT_EQUAL output). Returns
    /// `(zext_op, mult_out_vn, V)` with all ops parented into block 0 alongside `extra`.
    fn ext_bool(
        f: &mut Funcdata,
        v_addr: u64,
    ) -> (OpId, VarnodeId, VarnodeId) {
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_input(4, Address::new(reg, v_addr));
        let b = f.new_input(4, Address::new(reg, v_addr + 4));
        let cmp = f.new_op(OpCode::IntEqual, seq, vec![a, b]);
        let v = f.new_output(cmp, 1, Address::new(reg, v_addr + 8));
        let zop = f.new_op(OpCode::IntZext, seq, vec![v]);
        let zv = f.new_output(zop, 4, Address::new(reg, v_addr + 0x10));
        let negone = f.new_const(4, 0xffff_ffff);
        let mop = f.new_op(OpCode::IntMult, seq, vec![zv, negone]);
        let mout = f.new_output(mop, 4, Address::new(reg, v_addr + 0x18));
        (zop, mout, v)
    }

    fn parent_all(f: &mut Funcdata, ops: Vec<OpId>) {
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: ops.clone(), ..Default::default() }]);
        for op in ops {
            f.op_mut(op).parent = Some(BlockId(0));
        }
    }

    #[test]
    fn boolzext_add_one_becomes_zext_negate() {
        // (zext(V) * -1) + 1  =>  zext(!V) : the ADD collapses to a COPY of zext(!V), the ZEXT feeds !V.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let (zop, mout, v) = ext_bool(&mut f, 0x10);
        let one = f.new_const(4, 1);
        let add = f.new_op(OpCode::IntAdd, seq, vec![mout, one]);
        f.new_output(add, 4, Address::new(reg, 0x100));
        let mop = f.vn(mout).def.unwrap();
        let cmp = f.vn(v).def.unwrap();
        parent_all(&mut f, vec![cmp, zop, mop, add]);

        let zext_out = f.op(zop).output.unwrap();
        assert_eq!(RuleBoolZext.apply_op(zop, &mut f), 1);
        // ADD is now COPY(zext_out)
        assert_eq!(f.op(add).code(), OpCode::Copy);
        assert_eq!(f.op(add).num_inputs(), 1);
        assert_eq!(f.op(add).input(0), Some(zext_out));
        // ZEXT now extends a BOOL_NEGATE of V
        let neg_out = f.op(zop).input(0).unwrap();
        let neg = f.vn(neg_out).def.unwrap();
        assert_eq!(f.op(neg).code(), OpCode::BoolNegate);
        assert_eq!(f.op(neg).input(0), Some(v));
    }

    #[test]
    fn boolzext_compare_neg_one_becomes_compare_true() {
        // (zext(V) * -1) == -1  =>  V == 1
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let (zop, mout, v) = ext_bool(&mut f, 0x10);
        let negone = f.new_const(4, 0xffff_ffff);
        let eq = f.new_op(OpCode::IntEqual, seq, vec![mout, negone]);
        f.new_output(eq, 1, Address::new(reg, 0x100));
        let mop = f.vn(mout).def.unwrap();
        let cmp = f.vn(v).def.unwrap();
        parent_all(&mut f, vec![cmp, zop, mop, eq]);

        assert_eq!(RuleBoolZext.apply_op(zop, &mut f), 1);
        assert_eq!(f.op(eq).code(), OpCode::IntEqual);
        assert_eq!(f.op(eq).input(0), Some(v));
        let c = f.op(eq).input(1).unwrap();
        assert!(f.vn(c).is_constant());
        assert_eq!(f.vn(c).constant_value(), 1);
        assert_eq!(f.vn(c).size, 1);
    }

    #[test]
    fn boolzext_and_of_two_becomes_zext_booland() {
        // (zext(V) * -1) & (zext(W) * -1)  =>  zext(V && W) * -1
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let (zopv, moutv, v) = ext_bool(&mut f, 0x10);
        let (zopw, moutw, w) = ext_bool(&mut f, 0x40);
        let andop = f.new_op(OpCode::IntAnd, seq, vec![moutv, moutw]);
        f.new_output(andop, 4, Address::new(reg, 0x100));
        let mopv = f.vn(moutv).def.unwrap();
        let mopw = f.vn(moutw).def.unwrap();
        let cmpv = f.vn(v).def.unwrap();
        let cmpw = f.vn(w).def.unwrap();
        parent_all(&mut f, vec![cmpv, zopv, mopv, cmpw, zopw, mopw, andop]);

        assert_eq!(RuleBoolZext.apply_op(zopv, &mut f), 1);
        // andop is now INT_MULT(zext(V && W), -1)
        assert_eq!(f.op(andop).code(), OpCode::IntMult);
        let mc = f.op(andop).input(1).unwrap();
        assert!(f.vn(mc).is_constant() && f.vn(mc).constant_value() == 0xffff_ffff);
        let zin = f.op(andop).input(0).unwrap();
        let zext = f.vn(zin).def.unwrap();
        assert_eq!(f.op(zext).code(), OpCode::IntZext);
        let band_out = f.op(zext).input(0).unwrap();
        let band = f.vn(band_out).def.unwrap();
        assert_eq!(f.op(band).code(), OpCode::BoolAnd);
        assert_eq!(f.op(band).input(0), Some(v));
        assert_eq!(f.op(band).input(1), Some(w));
    }

    // ---- RuleSubCommute (#66) ------------------------------------------------------------------

    #[test]
    fn subcommute_pushes_subpiece_into_add() {
        // SUBPIECE(a + b, 0):4  =>  SUBPIECE(a,0):4 + SUBPIECE(b,0):4, the ADD narrowed to 4 bytes.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(8, Address::new(reg, 0x10));
        let b = f.new_input(8, Address::new(reg, 0x18));
        let add = f.new_op(OpCode::IntAdd, seq, vec![a, b]);
        let base = f.new_output(add, 8, Address::new(reg, 0x20));
        let z = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![base, z]);
        let out = f.new_output(sub, 4, Address::new(reg, 0x28));
        parent_all(&mut f, vec![add, sub]);

        assert_eq!(RuleSubCommute.apply_op(sub, &mut f), 1);
        assert!(f.op(sub).is_dead());
        assert_eq!(f.op(add).code(), OpCode::IntAdd);
        assert_eq!(f.op(add).output, Some(out));
        // Both operands are now SUBPIECE(_, 0)
        for slot in 0..2 {
            let s = f.vn(f.op(add).input(slot).unwrap()).def.unwrap();
            assert_eq!(f.op(s).code(), OpCode::Subpiece);
            assert_eq!(f.vn(f.op(s).output.unwrap()).size, 4);
        }
        assert_eq!(f.vn(f.op(f.vn(f.op(add).input(0).unwrap()).def.unwrap()).input(0).unwrap()).size, 8);
    }

    #[test]
    fn subcommute_commutes_div_of_zexts() {
        // SUBPIECE(zext(a:4) / zext(b:4), 0):4  =>  DIV narrowed to 4 bytes over SUBPIECEs
        // (which cancel the ZEXTs downstream). ZEXT input sizes == outsize → the commute path.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let za = f.new_op(OpCode::IntZext, seq, vec![a]);
        let zav = f.new_output(za, 8, Address::new(reg, 0x20));
        let zb = f.new_op(OpCode::IntZext, seq, vec![b]);
        let zbv = f.new_output(zb, 8, Address::new(reg, 0x28));
        let div = f.new_op(OpCode::IntDiv, seq, vec![zav, zbv]);
        let base = f.new_output(div, 8, Address::new(reg, 0x30));
        let z = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![base, z]);
        let out = f.new_output(sub, 4, Address::new(reg, 0x38));
        parent_all(&mut f, vec![za, zb, div, sub]);

        assert_eq!(RuleSubCommute.apply_op(sub, &mut f), 1);
        assert!(f.op(sub).is_dead());
        assert_eq!(f.op(div).code(), OpCode::IntDiv);
        assert_eq!(f.op(div).output, Some(out));
        for slot in 0..2 {
            let s = f.vn(f.op(div).input(slot).unwrap()).def.unwrap();
            assert_eq!(f.op(s).code(), OpCode::Subpiece);
            assert_eq!(f.vn(f.op(s).output.unwrap()).size, 4);
        }
    }

    #[test]
    fn subcommute_partial_cancels_wide_zext_div() {
        // SUBPIECE(zext(a:4) / zext(b:4), 0):2  — the ZEXT inputs (4) are wider than the SUBPIECE
        // output (2), so cancelExtensions removes the ZEXTs, narrows the DIV to 4 bytes over a,b,
        // and leaves a SUBPIECE(div:4, 0):2 in place.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let za = f.new_op(OpCode::IntZext, seq, vec![a]);
        let zav = f.new_output(za, 8, Address::new(reg, 0x20));
        let zb = f.new_op(OpCode::IntZext, seq, vec![b]);
        let zbv = f.new_output(zb, 8, Address::new(reg, 0x28));
        let div = f.new_op(OpCode::IntDiv, seq, vec![zav, zbv]);
        let base = f.new_output(div, 8, Address::new(reg, 0x30));
        let z = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![base, z]);
        let out = f.new_output(sub, 2, Address::new(reg, 0x38));
        parent_all(&mut f, vec![za, zb, div, sub]);

        assert_eq!(RuleSubCommute.apply_op(sub, &mut f), 1);
        // SUBPIECE stays; DIV is now 4-byte over the raw a,b (ZEXTs cancelled)
        assert_eq!(f.op(sub).code(), OpCode::Subpiece);
        assert_eq!(f.op(sub).output, Some(out));
        assert_eq!(f.op(div).code(), OpCode::IntDiv);
        assert_eq!(f.op(div).input(0), Some(a));
        assert_eq!(f.op(div).input(1), Some(b));
        let divout = f.op(div).output.unwrap();
        assert_eq!(f.vn(divout).size, 4);
        assert_eq!(f.op(sub).input(0), Some(divout));
    }

    // ---- RuleZextSless (#58) -------------------------------------------------------------------

    #[test]
    fn zextsless_drops_unnecessary_zext_on_signed_compare() {
        // zext(V:4):8 s< 0x10  =>  V:4 < 0x10  (sign bit of 0x10 within 4 bytes is clear).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let z = f.new_op(OpCode::IntZext, seq, vec![v]);
        let zv = f.new_output(z, 8, Address::new(reg, 0x18));
        let c = f.new_const(8, 0x10);
        let sless = f.new_op(OpCode::IntSless, seq, vec![zv, c]);
        f.new_output(sless, 1, Address::new(reg, 0x20));
        parent_all(&mut f, vec![z, sless]);

        assert_eq!(RuleZextSless.apply_op(sless, &mut f), 1);
        assert_eq!(f.op(sless).code(), OpCode::IntLess);
        assert_eq!(f.op(sless).input(0), Some(v));
        let nc = f.op(sless).input(1).unwrap();
        assert!(f.vn(nc).is_constant() && f.vn(nc).constant_value() == 0x10 && f.vn(nc).size == 4);
    }

    #[test]
    fn zextsless_rejects_when_narrow_sign_bit_set() {
        // zext(V:1):4 s< 0x80 — 0x80's bit 7 (the narrow sign bit) is set, so the zext is load-bearing.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(1, Address::new(reg, 0x10));
        let z = f.new_op(OpCode::IntZext, seq, vec![v]);
        let zv = f.new_output(z, 4, Address::new(reg, 0x18));
        let c = f.new_const(4, 0x80);
        let sless = f.new_op(OpCode::IntSless, seq, vec![zv, c]);
        f.new_output(sless, 1, Address::new(reg, 0x20));
        parent_all(&mut f, vec![z, sless]);

        assert_eq!(RuleZextSless.apply_op(sless, &mut f), 0);
        assert_eq!(f.op(sless).code(), OpCode::IntSless);
    }

    // ---- RuleSLess2Zero (#47) ------------------------------------------------------------------

    #[test]
    fn sless2zero_negate_becomes_sless_zero() {
        // -1 s< ~V  =>  V s< 0
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let neg = f.new_op(OpCode::IntNegate, seq, vec![v]);
        let negv = f.new_output(neg, 4, Address::new(reg, 0x18));
        let negone = f.new_const(4, 0xffff_ffff);
        let sless = f.new_op(OpCode::IntSless, seq, vec![negone, negv]);
        f.new_output(sless, 1, Address::new(reg, 0x20));
        parent_all(&mut f, vec![neg, sless]);

        assert_eq!(RuleSLess2Zero.apply_op(sless, &mut f), 1);
        assert_eq!(f.op(sless).code(), OpCode::IntSless);
        assert_eq!(f.op(sless).input(0), Some(v));
        let c = f.op(sless).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0 && f.vn(c).size == 4);
    }

    #[test]
    fn sless2zero_subpiece_top_becomes_sless_zero() {
        // SUB(V:8, #4):4 s< 0  =>  V:8 s< 0   (the SUBPIECE extracts the sign-bearing top piece)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let off = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![v, off]);
        let subv = f.new_output(sub, 4, Address::new(reg, 0x18));
        let zero = f.new_const(4, 0);
        let sless = f.new_op(OpCode::IntSless, seq, vec![subv, zero]);
        f.new_output(sless, 1, Address::new(reg, 0x20));
        parent_all(&mut f, vec![sub, sless]);

        assert_eq!(RuleSLess2Zero.apply_op(sless, &mut f), 1);
        assert_eq!(f.op(sless).code(), OpCode::IntSless);
        assert_eq!(f.op(sless).input(0), Some(v));
        let c = f.op(sless).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0 && f.vn(c).size == 8);
    }

    #[test]
    fn sless2zero_and_signbit_becomes_sless_zero() {
        // (V & 0x80000000) s< 0  =>  V s< 0   (mask keeps only the sign bit; AND is lone-descended)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let mask = f.new_const(4, 0x8000_0000);
        let and = f.new_op(OpCode::IntAnd, seq, vec![v, mask]);
        let andv = f.new_output(and, 4, Address::new(reg, 0x18));
        let zero = f.new_const(4, 0);
        let sless = f.new_op(OpCode::IntSless, seq, vec![andv, zero]);
        f.new_output(sless, 1, Address::new(reg, 0x20));
        parent_all(&mut f, vec![and, sless]);

        assert_eq!(RuleSLess2Zero.apply_op(sless, &mut f), 1);
        assert_eq!(f.op(sless).code(), OpCode::IntSless);
        assert_eq!(f.op(sless).input(0), Some(v));
    }

    #[test]
    fn sless2zero_concat_becomes_sless_of_top_piece() {
        // -1 s< CONCAT(V:4, W:4)  =>  -1 s< V   (V is the most-significant piece)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let vv = f.new_input(4, Address::new(reg, 0x10));
        let ww = f.new_input(4, Address::new(reg, 0x18));
        let piece = f.new_op(OpCode::Piece, seq, vec![vv, ww]);
        let pv = f.new_output(piece, 8, Address::new(reg, 0x20));
        let negone = f.new_const(8, 0xffff_ffff_ffff_ffff);
        let sless = f.new_op(OpCode::IntSless, seq, vec![negone, pv]);
        f.new_output(sless, 1, Address::new(reg, 0x28));
        parent_all(&mut f, vec![piece, sless]);

        assert_eq!(RuleSLess2Zero.apply_op(sless, &mut f), 1);
        assert_eq!(f.op(sless).code(), OpCode::IntSless);
        assert_eq!(f.op(sless).input(1), Some(vv));
        let c = f.op(sless).input(0).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0xffff_ffff && f.vn(c).size == 4);
    }

    #[test]
    fn sless2zero_bool_shift_becomes_bool_negate() {
        // -1 s< (bool << 7)  =>  !bool   (1-byte boolean smeared to its sign bit)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(1, Address::new(reg, 0x10));
        let b = f.new_input(1, Address::new(reg, 0x11));
        let cmp = f.new_op(OpCode::IntEqual, seq, vec![a, b]);
        let bv = f.new_output(cmp, 1, Address::new(reg, 0x12));
        let c7 = f.new_const(4, 7);
        let shl = f.new_op(OpCode::IntLeft, seq, vec![bv, c7]);
        let shlv = f.new_output(shl, 1, Address::new(reg, 0x18));
        let negone = f.new_const(1, 0xff);
        let sless = f.new_op(OpCode::IntSless, seq, vec![negone, shlv]);
        f.new_output(sless, 1, Address::new(reg, 0x20));
        parent_all(&mut f, vec![cmp, shl, sless]);

        assert_eq!(RuleSLess2Zero.apply_op(sless, &mut f), 1);
        assert_eq!(f.op(sless).code(), OpCode::BoolNegate);
        assert_eq!(f.op(sless).num_inputs(), 1);
        assert_eq!(f.op(sless).input(0), Some(bv));
    }

    #[test]
    fn sless2zero_hibit_xor_becomes_notequal() {
        // (hi ^ lo) s< 0  =>  hi != 0, where only `hi` can set the sign bit (getHiBit).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let hi = f.new_input(4, Address::new(reg, 0x10));
        f.vn_mut(hi).nzm = 0x8000_0000; // only the sign bit
        let lo = f.new_input(4, Address::new(reg, 0x18));
        f.vn_mut(lo).nzm = 0x7fff_ffff; // everything but the sign bit
        let xor = f.new_op(OpCode::IntXor, seq, vec![hi, lo]);
        let sum = f.new_output(xor, 4, Address::new(reg, 0x20));
        let zero = f.new_const(4, 0);
        let sless = f.new_op(OpCode::IntSless, seq, vec![sum, zero]);
        f.new_output(sless, 1, Address::new(reg, 0x28));
        parent_all(&mut f, vec![xor, sless]);

        assert_eq!(RuleSLess2Zero.apply_op(sless, &mut f), 1);
        assert_eq!(f.op(sless).code(), OpCode::IntNotequal);
        assert_eq!(f.op(sless).input(0), Some(hi));
        let c = f.op(sless).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0);
    }

    #[test]
    fn sless2zero_no_fire_on_plain_input() {
        // V s< 0 where V is a plain (unwritten) input — nothing to peel, no fire.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let zero = f.new_const(4, 0);
        let sless = f.new_op(OpCode::IntSless, seq, vec![v, zero]);
        f.new_output(sless, 1, Address::new(reg, 0x20));
        parent_all(&mut f, vec![sless]);

        assert_eq!(RuleSLess2Zero.apply_op(sless, &mut f), 0);
        assert_eq!(f.op(sless).code(), OpCode::IntSless);
    }

    // ---- Rule2Comp2Mult (#41) / RuleCarryElim (#43) / RuleBxor2NotEqual (#44) -------------------

    #[test]
    fn twocomp2mult_rewrites_negate_as_mult_negone() {
        // -V  =>  V * -1
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let neg = f.new_op(OpCode::Int2comp, seq, vec![v]);
        f.new_output(neg, 4, Address::new(reg, 0x18));
        parent_all(&mut f, vec![neg]);

        assert_eq!(Rule2Comp2Mult.apply_op(neg, &mut f), 1);
        assert_eq!(f.op(neg).code(), OpCode::IntMult);
        assert_eq!(f.op(neg).num_inputs(), 2);
        assert_eq!(f.op(neg).input(0), Some(v));
        let c = f.op(neg).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0xffff_ffff && f.vn(c).size == 4);
    }

    #[test]
    fn carryelim_nonzero_becomes_lessequal() {
        // carry(V, 5)  =>  (-5) <= V   (-5 == 0xfffffffb in 4 bytes)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c5 = f.new_const(4, 5);
        let carry = f.new_op(OpCode::IntCarry, seq, vec![v, c5]);
        f.new_output(carry, 1, Address::new(reg, 0x18));
        parent_all(&mut f, vec![carry]);

        assert_eq!(RuleCarryElim.apply_op(carry, &mut f), 1);
        assert_eq!(f.op(carry).code(), OpCode::IntLessequal);
        assert_eq!(f.op(carry).input(1), Some(v));
        let c = f.op(carry).input(0).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0xffff_fffb && f.vn(c).size == 4);
    }

    #[test]
    fn carryelim_zero_becomes_false() {
        // carry(V, 0)  =>  false  (COPY of a 1-byte 0)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c0 = f.new_const(4, 0);
        let carry = f.new_op(OpCode::IntCarry, seq, vec![v, c0]);
        f.new_output(carry, 1, Address::new(reg, 0x18));
        parent_all(&mut f, vec![carry]);

        assert_eq!(RuleCarryElim.apply_op(carry, &mut f), 1);
        assert_eq!(f.op(carry).code(), OpCode::Copy);
        assert_eq!(f.op(carry).num_inputs(), 1);
        let c = f.op(carry).input(0).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0 && f.vn(c).size == 1);
    }

    #[test]
    fn carryelim_no_fire_on_nonconstant() {
        // carry(V, W) with W non-constant — no fire.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let w = f.new_input(4, Address::new(reg, 0x18));
        let carry = f.new_op(OpCode::IntCarry, seq, vec![v, w]);
        f.new_output(carry, 1, Address::new(reg, 0x20));
        parent_all(&mut f, vec![carry]);

        assert_eq!(RuleCarryElim.apply_op(carry, &mut f), 0);
        assert_eq!(f.op(carry).code(), OpCode::IntCarry);
    }

    #[test]
    fn bxor2notequal_rewrites_bool_xor() {
        // V ^^ W  =>  V != W
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(1, Address::new(reg, 0x10));
        let b = f.new_input(1, Address::new(reg, 0x11));
        let bx = f.new_op(OpCode::BoolXor, seq, vec![a, b]);
        f.new_output(bx, 1, Address::new(reg, 0x18));
        parent_all(&mut f, vec![bx]);

        assert_eq!(RuleBxor2NotEqual.apply_op(bx, &mut f), 1);
        assert_eq!(f.op(bx).code(), OpCode::IntNotequal);
        assert_eq!(f.op(bx).input(0), Some(a));
        assert_eq!(f.op(bx).input(1), Some(b));
    }

    // ---- RuleThreeWayCompare (#50) -------------------------------------------------------------

    /// Build a Form-1 three-way `(zext(V s< W) + zext(V s<= W)) - 1` and return
    /// `(threeway_vn, V, W, ops)`. `threeway` is -1/0/1 for V less/equal/greater than W.
    fn build_threeway(
        f: &mut Funcdata,
        ram: Address,
        base: u64,
    ) -> (VarnodeId, VarnodeId, VarnodeId, Vec<OpId>) {
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, base));
        let w = f.new_input(4, Address::new(reg, base + 8));
        let less = f.new_op(OpCode::IntSless, seq, vec![v, w]);
        let lessv = f.new_output(less, 1, Address::new(reg, base + 0x10));
        let le = f.new_op(OpCode::IntSlessequal, seq, vec![v, w]);
        let lev = f.new_output(le, 1, Address::new(reg, base + 0x18));
        let z1 = f.new_op(OpCode::IntZext, seq, vec![lessv]);
        let z1v = f.new_output(z1, 4, Address::new(reg, base + 0x20));
        let z2 = f.new_op(OpCode::IntZext, seq, vec![lev]);
        let z2v = f.new_output(z2, 4, Address::new(reg, base + 0x28));
        let add = f.new_op(OpCode::IntAdd, seq, vec![z1v, z2v]);
        let addv = f.new_output(add, 4, Address::new(reg, base + 0x30));
        let negone = f.new_const(4, 0xffff_ffff);
        let addm1 = f.new_op(OpCode::IntAdd, seq, vec![addv, negone]);
        let threeway = f.new_output(addm1, 4, Address::new(reg, base + 0x38));
        (threeway, v, w, vec![less, le, z1, z2, add, addm1])
    }

    #[test]
    fn threeway_sless_one_becomes_lessequal() {
        // threeway s< 1  =>  W s<= V   (i.e. NOT(V<W), a >= comparison; form 20)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let (threeway, v, w, mut ops) = build_threeway(&mut f, ram, 0x10);
        let one = f.new_const(4, 1);
        let cmp = f.new_op(OpCode::IntSless, seq, vec![threeway, one]);
        f.new_output(cmp, 1, Address::new(reg, 0x100));
        ops.push(cmp);
        parent_all(&mut f, ops);

        assert_eq!(RuleThreeWayCompare.apply_op(cmp, &mut f), 1);
        assert_eq!(f.op(cmp).code(), OpCode::IntSlessequal);
        assert_eq!(f.op(cmp).input(0), Some(w));
        assert_eq!(f.op(cmp).input(1), Some(v));
    }

    #[test]
    fn threeway_equal_zero_becomes_equal() {
        // threeway == 0  =>  W == V   (i.e. V == W; form 14)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let (threeway, v, w, mut ops) = build_threeway(&mut f, ram, 0x10);
        let zero = f.new_const(4, 0);
        let cmp = f.new_op(OpCode::IntEqual, seq, vec![threeway, zero]);
        f.new_output(cmp, 1, Address::new(reg, 0x100));
        ops.push(cmp);
        parent_all(&mut f, ops);

        assert_eq!(RuleThreeWayCompare.apply_op(cmp, &mut f), 1);
        assert_eq!(f.op(cmp).code(), OpCode::IntEqual);
        assert_eq!(f.op(cmp).input(0), Some(w));
        assert_eq!(f.op(cmp).input(1), Some(v));
    }

    #[test]
    fn threeway_no_fire_on_plain_compare() {
        // V s< 1 where V is a plain input (not a three-way sum) — no fire.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let one = f.new_const(4, 1);
        let cmp = f.new_op(OpCode::IntSless, seq, vec![v, one]);
        f.new_output(cmp, 1, Address::new(reg, 0x20));
        parent_all(&mut f, vec![cmp]);

        assert_eq!(RuleThreeWayCompare.apply_op(cmp, &mut f), 0);
        assert_eq!(f.op(cmp).code(), OpCode::IntSless);
    }

    // ---- RuleIntLessEqual (#10) ----------------------------------------------------------------

    #[test]
    fn intlessequal_right_const_becomes_less() {
        // V <= 5  =>  V < 6
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c5 = f.new_const(4, 5);
        let le = f.new_op(OpCode::IntLessequal, seq, vec![v, c5]);
        f.new_output(le, 1, Address::new(reg, 0x18));
        parent_all(&mut f, vec![le]);

        assert_eq!(RuleIntLessEqual.apply_op(le, &mut f), 1);
        assert_eq!(f.op(le).code(), OpCode::IntLess);
        assert_eq!(f.op(le).input(0), Some(v));
        let c = f.op(le).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 6 && f.vn(c).size == 4);
    }

    #[test]
    fn intlessequal_left_const_becomes_less() {
        // 5 <= V  =>  4 < V
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c5 = f.new_const(4, 5);
        let le = f.new_op(OpCode::IntLessequal, seq, vec![c5, v]);
        f.new_output(le, 1, Address::new(reg, 0x18));
        parent_all(&mut f, vec![le]);

        assert_eq!(RuleIntLessEqual.apply_op(le, &mut f), 1);
        assert_eq!(f.op(le).code(), OpCode::IntLess);
        assert_eq!(f.op(le).input(1), Some(v));
        let c = f.op(le).input(0).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 4 && f.vn(c).size == 4);
    }

    #[test]
    fn intlessequal_signed_form() {
        // V s<= 5  =>  V s< 6
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c5 = f.new_const(4, 5);
        let le = f.new_op(OpCode::IntSlessequal, seq, vec![v, c5]);
        f.new_output(le, 1, Address::new(reg, 0x18));
        parent_all(&mut f, vec![le]);

        assert_eq!(RuleIntLessEqual.apply_op(le, &mut f), 1);
        assert_eq!(f.op(le).code(), OpCode::IntSless);
        let c = f.op(le).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 6);
    }

    #[test]
    fn intlessequal_no_fire_on_unsigned_overflow() {
        // V <= 0xffffffff (unsigned max) — always true, can't add 1, no fire.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let cmax = f.new_const(4, 0xffff_ffff);
        let le = f.new_op(OpCode::IntLessequal, seq, vec![v, cmax]);
        f.new_output(le, 1, Address::new(reg, 0x18));
        parent_all(&mut f, vec![le]);

        assert_eq!(RuleIntLessEqual.apply_op(le, &mut f), 0);
        assert_eq!(f.op(le).code(), OpCode::IntLessequal);
    }

    // ---- RuleRangeMeld (#101) ------------------------------------------------------------------

    #[test]
    fn rangemeld_and_collapses_jg_flag_form() {
        // (v != 6) && (5 s< v)  =>  6 s< v   (the x86 `jg` signed-compare flag reconstruction)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c6 = f.new_const(4, 6);
        let ne = f.new_op(OpCode::IntNotequal, seq, vec![v, c6]);
        let neout = f.new_output(ne, 1, Address::new(reg, 0x18));
        let c5 = f.new_const(4, 5);
        let sl = f.new_op(OpCode::IntSless, seq, vec![c5, v]);
        let slout = f.new_output(sl, 1, Address::new(reg, 0x19));
        let and = f.new_op(OpCode::BoolAnd, seq, vec![neout, slout]);
        f.new_output(and, 1, Address::new(reg, 0x1a));
        parent_all(&mut f, vec![ne, sl, and]);

        assert_eq!(RuleRangeMeld.apply_op(and, &mut f), 1);
        assert_eq!(f.op(and).code(), OpCode::IntSless);
        let c = f.op(and).input(0).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 6);
        assert_eq!(f.op(and).input(1), Some(v));
    }

    #[test]
    fn rangemeld_or_collapses_jle_flag_form() {
        // (v == 9) || (v s< 9)  =>  v s< 10   (the x86 `jle` signed-compare flag reconstruction)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c9a = f.new_const(4, 9);
        let eq = f.new_op(OpCode::IntEqual, seq, vec![v, c9a]);
        let eqout = f.new_output(eq, 1, Address::new(reg, 0x18));
        let c9b = f.new_const(4, 9);
        let sl = f.new_op(OpCode::IntSless, seq, vec![v, c9b]);
        let slout = f.new_output(sl, 1, Address::new(reg, 0x19));
        let or = f.new_op(OpCode::BoolOr, seq, vec![eqout, slout]);
        f.new_output(or, 1, Address::new(reg, 0x1a));
        parent_all(&mut f, vec![eq, sl, or]);

        assert_eq!(RuleRangeMeld.apply_op(or, &mut f), 1);
        assert_eq!(f.op(or).code(), OpCode::IntSless);
        assert_eq!(f.op(or).input(0), Some(v));
        let c = f.op(or).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 10);
    }

    #[test]
    fn rangemeld_no_fire_on_distinct_variables() {
        // (v != 6) && (5 s< w) — different base Varnodes of equal size, no meld.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let w = f.new_input(4, Address::new(reg, 0x20));
        let c6 = f.new_const(4, 6);
        let ne = f.new_op(OpCode::IntNotequal, seq, vec![v, c6]);
        let neout = f.new_output(ne, 1, Address::new(reg, 0x18));
        let c5 = f.new_const(4, 5);
        let sl = f.new_op(OpCode::IntSless, seq, vec![c5, w]);
        let slout = f.new_output(sl, 1, Address::new(reg, 0x19));
        let and = f.new_op(OpCode::BoolAnd, seq, vec![neout, slout]);
        f.new_output(and, 1, Address::new(reg, 0x1a));
        parent_all(&mut f, vec![ne, sl, and]);

        assert_eq!(RuleRangeMeld.apply_op(and, &mut f), 0);
        assert_eq!(f.op(and).code(), OpCode::BoolAnd);
    }

    // ---- RuleCondNegate (#condnegate) ----------------------------------------------------------

    /// Build a `CBRANCH(target, cond)` where `cond = INT_SLESS(v, 5)`, all in one block.
    /// Returns (cbranch, cond-varnode, v-input).
    fn cbranch_on_sless(f: &mut Funcdata, ram: Address) -> (OpId, VarnodeId, VarnodeId) {
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c5 = f.new_const(4, 5);
        let cmp = f.new_op(OpCode::IntSless, seq, vec![v, c5]);
        let cond = f.new_output(cmp, 1, Address::new(reg, 0x20));
        let target = f.new_const(8, 0x1000); // coderef target (unread by the rule)
        let cbr = f.new_op(OpCode::Cbranch, seq, vec![target, cond]);
        parent_all(f, vec![cmp, cbr]);
        (cbr, cond, v)
    }

    #[test]
    fn condnegate_materializes_negation_when_flagged() {
        // boolean_flip set => insert BOOL_NEGATE(cond), repoint CBRANCH.in[1] at it, clear the flag.
        let (mut f, ram) = fd();
        let (cbr, cond, _v) = cbranch_on_sless(&mut f, ram);
        f.op_flip_condition(cbr); // structurer's mark: branch taken on the false condition
        assert!(f.op(cbr).is_boolean_flip());

        assert_eq!(RuleCondNegate.apply_op(cbr, &mut f), 1);

        // Flag flipped back off; condition input now the negated value.
        assert!(!f.op(cbr).is_boolean_flip());
        let neg = f.op(cbr).input(1).unwrap();
        assert_ne!(neg, cond);
        let negop = f.vn(neg).def.unwrap();
        assert_eq!(f.op(negop).code(), OpCode::BoolNegate);
        assert_eq!(f.op(negop).input(0), Some(cond));
        // cond now feeds only the BOOL_NEGATE (the CBRANCH was repointed off it).
        assert_eq!(f.vn(cond).descend, vec![negop]);
    }

    #[test]
    fn condnegate_no_fire_without_flag() {
        // No boolean_flip => rule declines and leaves the CBRANCH untouched.
        let (mut f, ram) = fd();
        let (cbr, cond, _v) = cbranch_on_sless(&mut f, ram);
        assert!(!f.op(cbr).is_boolean_flip());

        assert_eq!(RuleCondNegate.apply_op(cbr, &mut f), 0);
        assert_eq!(f.op(cbr).input(1), Some(cond));
        assert_eq!(f.vn(cond).descend, vec![cbr]);
    }

    // ---- opFlipInPlaceTest / opFlipInPlaceExecute (ActionPreferComplement / mechanism A) --------

    /// Build a `CBRANCH(target, cond)` where `cond = <opc>(a, b)`; returns (cbranch, cmp op).
    fn cbranch_on_cmp(f: &mut Funcdata, ram: Address, opc: OpCode, a: VarnodeId, b: VarnodeId) -> (OpId, OpId) {
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let cmp = f.new_op(opc, seq, vec![a, b]);
        let cond = f.new_output(cmp, 1, Address::new(reg, 0x20));
        let target = f.new_const(8, 0x1000);
        let cbr = f.new_op(OpCode::Cbranch, seq, vec![target, cond]);
        let _ = cond;
        parent_all(f, vec![cmp, cbr]);
        (cbr, cmp)
    }

    #[test]
    fn flip_in_place_const_left_less_normalizes_to_strict_lt() {
        // `9 s< v` (const on the left) normalizes (test==0); the flip yields `v s< 10` in place —
        // opFlipInPlaceExecute swaps to `v s<= 9` then replaceLessequal rewrites to `v s< 10`.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c9 = f.new_const(4, 9);
        let (cbr, cmp) = cbranch_on_cmp(&mut f, ram, OpCode::IntSless, c9, v);

        let (result, fliplist) = f.op_flip_in_place_test(cbr);
        assert_eq!(result, 0, "const-left `<` normalizes");
        assert_eq!(fliplist, vec![cmp]);

        f.op_flip_in_place_execute(&fliplist);
        assert_eq!(f.op(cmp).code(), OpCode::IntSless);
        assert_eq!(f.op(cmp).input(0), Some(v));
        let rhs = f.op(cmp).input(1).unwrap();
        assert!(f.vn(rhs).is_constant());
        assert_eq!(f.vn(rhs).constant_value(), 10);
    }

    #[test]
    fn flip_in_place_notequal_becomes_equal() {
        // `v != c` normalizes (test==0); the flip is the plain complement `v == c`, no reorder.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c5 = f.new_const(4, 5);
        let (cbr, cmp) = cbranch_on_cmp(&mut f, ram, OpCode::IntNotequal, v, c5);

        let (result, fliplist) = f.op_flip_in_place_test(cbr);
        assert_eq!(result, 0);
        f.op_flip_in_place_execute(&fliplist);
        assert_eq!(f.op(cmp).code(), OpCode::IntEqual);
        assert_eq!(f.op(cmp).input(0), Some(v));
        assert_eq!(f.op(cmp).input(1), Some(c5));
    }

    #[test]
    fn flip_in_place_nonconst_less_is_ambivalent() {
        // `v s< w` with both non-constant is ambivalent (test==1) — ActionPreferComplement leaves it.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let v = f.new_input(4, Address::new(reg, 0x10));
        let w = f.new_input(4, Address::new(reg, 0x18));
        let (cbr, _cmp) = cbranch_on_cmp(&mut f, ram, OpCode::IntSless, v, w);

        let (result, _fliplist) = f.op_flip_in_place_test(cbr);
        assert_eq!(result, 1);
    }

    #[test]
    fn flip_in_place_execute_flips_fallthru_flag_only() {
        // flip_in_place_execute toggles fallthru_true and leaves boolean_flip clear (the op-code is
        // being changed explicitly, unlike block_negate_condition).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c9 = f.new_const(4, 9);
        let (_cbr, _cmp) = cbranch_on_cmp(&mut f, ram, OpCode::IntSless, c9, v);
        f.flip_in_place_execute(BlockId(0));
        let cbr = *f.block(BlockId(0)).ops.last().unwrap();
        assert!(f.op(cbr).is_fallthru_true());
        assert!(!f.op(cbr).is_boolean_flip());
    }

    // ---- RuleSubNormal (#81) -------------------------------------------------------------------

    #[test]
    fn subnormal_byte_aligned_folds_into_subpiece() {
        // sub(V:8 >> 16, 0):4  =>  sub(V, 2):4   (byte-aligned shift absorbed into the offset)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let sh = f.new_const(4, 16);
        let shr = f.new_op(OpCode::IntRight, seq, vec![v, sh]);
        let shrv = f.new_output(shr, 8, Address::new(reg, 0x18));
        let c0 = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![shrv, c0]);
        f.new_output(sub, 4, Address::new(reg, 0x20));
        parent_all(&mut f, vec![shr, sub]);

        assert_eq!(RuleSubNormal.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::Subpiece);
        assert_eq!(f.op(sub).input(0), Some(v));
        let c = f.op(sub).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 2);
    }

    #[test]
    fn subnormal_past_end_becomes_zext_of_subpiece() {
        // sub(V:4 >> 16, 0):4  =>  zext(sub(V, 2):2)   (window runs past input end, truncSize=2)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let sh = f.new_const(4, 16);
        let shr = f.new_op(OpCode::IntRight, seq, vec![v, sh]);
        let shrv = f.new_output(shr, 4, Address::new(reg, 0x18));
        let c0 = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![shrv, c0]);
        f.new_output(sub, 4, Address::new(reg, 0x20));
        parent_all(&mut f, vec![shr, sub]);

        assert_eq!(RuleSubNormal.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::IntZext);
        assert_eq!(f.op(sub).num_inputs(), 1);
        let inner_out = f.op(sub).input(0).unwrap();
        assert_eq!(f.vn(inner_out).size, 2);
        let inner = f.vn(inner_out).def.unwrap();
        assert_eq!(f.op(inner).code(), OpCode::Subpiece);
        assert_eq!(f.op(inner).input(0), Some(v));
        let ic = f.op(inner).input(1).unwrap();
        assert!(f.vn(ic).is_constant() && f.vn(ic).constant_value() == 2);
    }

    #[test]
    fn subnormal_nonaligned_becomes_shift_of_subpiece() {
        // sub(V:8 >> 36, 0):4  =>  sub(V, 4):4 >> 4   (byte part folds, 4-bit remainder stays)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let sh = f.new_const(4, 36);
        let shr = f.new_op(OpCode::IntRight, seq, vec![v, sh]);
        let shrv = f.new_output(shr, 8, Address::new(reg, 0x18));
        let c0 = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![shrv, c0]);
        f.new_output(sub, 4, Address::new(reg, 0x20));
        parent_all(&mut f, vec![shr, sub]);

        assert_eq!(RuleSubNormal.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::IntRight);
        assert_eq!(f.op(sub).num_inputs(), 2);
        let sh_amt = f.op(sub).input(1).unwrap();
        assert!(f.vn(sh_amt).is_constant() && f.vn(sh_amt).constant_value() == 4);
        let inner_out = f.op(sub).input(0).unwrap();
        assert_eq!(f.vn(inner_out).size, 4);
        let inner = f.vn(inner_out).def.unwrap();
        assert_eq!(f.op(inner).code(), OpCode::Subpiece);
        assert_eq!(f.op(inner).input(0), Some(v));
        let ic = f.op(inner).input(1).unwrap();
        assert!(f.vn(ic).is_constant() && f.vn(ic).constant_value() == 4);
    }

    #[test]
    fn subnormal_no_fire_on_plain_subpiece() {
        // sub(V, 0) where V is a plain input (not a shift) — no fire.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let c0 = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![v, c0]);
        f.new_output(sub, 4, Address::new(reg, 0x18));
        parent_all(&mut f, vec![sub]);

        assert_eq!(RuleSubNormal.apply_op(sub, &mut f), 0);
        assert_eq!(f.op(sub).code(), OpCode::Subpiece);
    }

    // ---- RuleSubRight (cleanup) ------------------------------------------------------------------

    #[test]
    fn subright_converts_truncation_to_shift() {
        // sub(V:8, 4):4  =>  sub(V >> 0x20, 0):4
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let c4 = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![v, c4]);
        f.new_output(sub, 4, Address::new(reg, 0x20));
        parent_all(&mut f, vec![sub]);

        assert_eq!(RuleSubRight.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::Subpiece);
        let off = f.op(sub).input(1).unwrap();
        assert!(f.vn(off).is_constant() && f.vn(off).constant_value() == 0);
        let shifted = f.op(sub).input(0).unwrap();
        let shiftop = f.vn(shifted).def.unwrap();
        assert_eq!(f.op(shiftop).code(), OpCode::IntRight);
        assert_eq!(f.op(shiftop).input(0), Some(v));
        let d = f.op(shiftop).input(1).unwrap();
        assert!(f.vn(d).is_constant() && f.vn(d).constant_value() == 0x20);
        assert_eq!(f.vn(shifted).size, 8);
    }

    #[test]
    fn subright_lumps_lone_sright_descendant() {
        // u = sub(V:8, 4):4;  w = u s>> 0x10   =>   w = sub(V s>> 0x30, 0):4
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let c4 = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![v, c4]);
        let u = f.new_output(sub, 4, Address::new(reg, 0x20));
        let c16 = f.new_const(4, 0x10);
        let shr = f.new_op(OpCode::IntSright, seq, vec![u, c16]);
        f.new_output(shr, 4, Address::new(reg, 0x28));
        parent_all(&mut f, vec![sub, shr]);

        assert_eq!(RuleSubRight.apply_op(sub, &mut f), 1);
        // The lone shift descendant was repurposed as the least-sig SUBPIECE
        assert_eq!(f.op(shr).code(), OpCode::Subpiece);
        let off = f.op(shr).input(1).unwrap();
        assert!(f.vn(off).is_constant() && f.vn(off).constant_value() == 0);
        let shifted = f.op(shr).input(0).unwrap();
        let shiftop = f.vn(shifted).def.unwrap();
        assert_eq!(f.op(shiftop).code(), OpCode::IntSright);
        assert_eq!(f.op(shiftop).input(0), Some(v));
        let d = f.op(shiftop).input(1).unwrap();
        assert!(f.vn(d).is_constant() && f.vn(d).constant_value() == 0x30);
        // The original SUBPIECE is dead and out of the block
        assert!(f.op(sub).is_dead());
    }

    #[test]
    fn subright_sright_overflow_becomes_sign_extraction() {
        // u = sub(V:8, 4):4; w = u s>> 0x20 — total 0x40 >= 64 bits: clamps to 63 (sign extraction).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let c4 = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![v, c4]);
        let u = f.new_output(sub, 4, Address::new(reg, 0x20));
        let c32 = f.new_const(4, 0x20);
        let shr = f.new_op(OpCode::IntSright, seq, vec![u, c32]);
        f.new_output(shr, 4, Address::new(reg, 0x28));
        parent_all(&mut f, vec![sub, shr]);

        assert_eq!(RuleSubRight.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(shr).code(), OpCode::Subpiece);
        let shifted = f.op(shr).input(0).unwrap();
        let shiftop = f.vn(shifted).def.unwrap();
        assert_eq!(f.op(shiftop).code(), OpCode::IntSright);
        let d = f.op(shiftop).input(1).unwrap();
        assert!(f.vn(d).is_constant() && f.vn(d).constant_value() == 63);
    }

    #[test]
    fn subright_no_fire_offset_zero_or_unsigned_overflow() {
        // sub(V, 0) — least sig, no fire. And u = sub(V:8,4):4; w = u >> 0x20 (unsigned, total
        // 64 bits) — result would be 0; Ghidra returns without transforming.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let c0 = f.new_const(4, 0);
        let sub0 = f.new_op(OpCode::Subpiece, seq, vec![v, c0]);
        f.new_output(sub0, 4, Address::new(reg, 0x20));
        let c4 = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![v, c4]);
        let u = f.new_output(sub, 4, Address::new(reg, 0x28));
        let c32 = f.new_const(4, 0x20);
        let shr = f.new_op(OpCode::IntRight, seq, vec![u, c32]);
        f.new_output(shr, 4, Address::new(reg, 0x30));
        parent_all(&mut f, vec![sub0, sub, shr]);

        assert_eq!(RuleSubRight.apply_op(sub0, &mut f), 0);
        assert_eq!(f.op(sub0).code(), OpCode::Subpiece);
        assert_eq!(RuleSubRight.apply_op(sub, &mut f), 0);
        assert_eq!(f.op(sub).code(), OpCode::Subpiece);
        assert_eq!(f.op(shr).code(), OpCode::IntRight);
    }

    // ---- RuleBitUndistribute (#59) -------------------------------------------------------------

    #[test]
    fn bitundistribute_pulls_zext_out_of_and() {
        // zext(V:4):8 & zext(W:4):8  =>  zext(V & W)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let w = f.new_input(4, Address::new(reg, 0x18));
        let zv = f.new_op(OpCode::IntZext, seq, vec![v]);
        let zvv = f.new_output(zv, 8, Address::new(reg, 0x20));
        let zw = f.new_op(OpCode::IntZext, seq, vec![w]);
        let zwv = f.new_output(zw, 8, Address::new(reg, 0x28));
        let and = f.new_op(OpCode::IntAnd, seq, vec![zvv, zwv]);
        f.new_output(and, 8, Address::new(reg, 0x30));
        parent_all(&mut f, vec![zv, zw, and]);

        assert_eq!(RuleBitUndistribute.apply_op(and, &mut f), 1);
        assert_eq!(f.op(and).code(), OpCode::IntZext);
        assert_eq!(f.op(and).num_inputs(), 1);
        let sl = f.op(and).input(0).unwrap();
        assert_eq!(f.vn(sl).size, 4);
        let inner = f.vn(sl).def.unwrap();
        assert_eq!(f.op(inner).code(), OpCode::IntAnd);
        assert_eq!(f.op(inner).input(0), Some(v));
        assert_eq!(f.op(inner).input(1), Some(w));
    }

    #[test]
    fn bitundistribute_pulls_shift_out_of_or() {
        // (V >> 8) | (W >> 8)  =>  (V | W) >> 8
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let w = f.new_input(4, Address::new(reg, 0x18));
        let c8a = f.new_const(4, 8);
        let sv = f.new_op(OpCode::IntRight, seq, vec![v, c8a]);
        let svv = f.new_output(sv, 4, Address::new(reg, 0x20));
        let c8b = f.new_const(4, 8);
        let sw = f.new_op(OpCode::IntRight, seq, vec![w, c8b]);
        let swv = f.new_output(sw, 4, Address::new(reg, 0x28));
        let or = f.new_op(OpCode::IntOr, seq, vec![svv, swv]);
        f.new_output(or, 4, Address::new(reg, 0x30));
        parent_all(&mut f, vec![sv, sw, or]);

        assert_eq!(RuleBitUndistribute.apply_op(or, &mut f), 1);
        assert_eq!(f.op(or).code(), OpCode::IntRight);
        assert_eq!(f.op(or).num_inputs(), 2);
        let sa = f.op(or).input(1).unwrap();
        assert!(f.vn(sa).is_constant() && f.vn(sa).constant_value() == 8);
        let sl = f.op(or).input(0).unwrap();
        let inner = f.vn(sl).def.unwrap();
        assert_eq!(f.op(inner).code(), OpCode::IntOr);
        assert_eq!(f.op(inner).input(0), Some(v));
        assert_eq!(f.op(inner).input(1), Some(w));
    }

    #[test]
    fn bitundistribute_no_fire_on_mismatched_shift() {
        // (V >> 8) | (W >> 4) — shift amounts differ, no fire.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let w = f.new_input(4, Address::new(reg, 0x18));
        let c8 = f.new_const(4, 8);
        let sv = f.new_op(OpCode::IntRight, seq, vec![v, c8]);
        let svv = f.new_output(sv, 4, Address::new(reg, 0x20));
        let c4 = f.new_const(4, 4);
        let sw = f.new_op(OpCode::IntRight, seq, vec![w, c4]);
        let swv = f.new_output(sw, 4, Address::new(reg, 0x28));
        let or = f.new_op(OpCode::IntOr, seq, vec![svv, swv]);
        f.new_output(or, 4, Address::new(reg, 0x30));
        parent_all(&mut f, vec![sv, sw, or]);

        assert_eq!(RuleBitUndistribute.apply_op(or, &mut f), 0);
        assert_eq!(f.op(or).code(), OpCode::IntOr);
    }

    // ---- RuleNegateIdentity (#80) --------------------------------------------------------------

    #[test]
    fn negateidentity_and_becomes_zero() {
        // V & ~V  =>  0   (negation output at slot 1)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let neg = f.new_op(OpCode::IntNegate, seq, vec![v]);
        let negv = f.new_output(neg, 4, Address::new(reg, 0x18));
        let and = f.new_op(OpCode::IntAnd, seq, vec![v, negv]);
        f.new_output(and, 4, Address::new(reg, 0x20));
        parent_all(&mut f, vec![neg, and]);

        assert_eq!(RuleNegateIdentity.apply_op(neg, &mut f), 1);
        assert_eq!(f.op(and).code(), OpCode::Copy);
        assert_eq!(f.op(and).num_inputs(), 1);
        let c = f.op(and).input(0).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0 && f.vn(c).size == 4);
    }

    #[test]
    fn negateidentity_or_becomes_allones() {
        // ~V | V  =>  -1   (negation output at slot 0)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let neg = f.new_op(OpCode::IntNegate, seq, vec![v]);
        let negv = f.new_output(neg, 4, Address::new(reg, 0x18));
        let or = f.new_op(OpCode::IntOr, seq, vec![negv, v]);
        f.new_output(or, 4, Address::new(reg, 0x20));
        parent_all(&mut f, vec![neg, or]);

        assert_eq!(RuleNegateIdentity.apply_op(neg, &mut f), 1);
        assert_eq!(f.op(or).code(), OpCode::Copy);
        assert_eq!(f.op(or).num_inputs(), 1);
        let c = f.op(or).input(0).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0xffff_ffff && f.vn(c).size == 4);
    }

    #[test]
    fn negateidentity_no_fire_on_different_operand() {
        // W & ~V  (other operand is not the negated value) — no fire.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let w = f.new_input(4, Address::new(reg, 0x18));
        let neg = f.new_op(OpCode::IntNegate, seq, vec![v]);
        let negv = f.new_output(neg, 4, Address::new(reg, 0x20));
        let and = f.new_op(OpCode::IntAnd, seq, vec![w, negv]);
        f.new_output(and, 4, Address::new(reg, 0x28));
        parent_all(&mut f, vec![neg, and]);

        assert_eq!(RuleNegateIdentity.apply_op(neg, &mut f), 0);
        assert_eq!(f.op(and).code(), OpCode::IntAnd);
    }

    // ---- BooleanMatch (expression.cc) / RuleBooleanUndistribute (#60) / RuleBooleanDedup (#61) --

    use crate::decompile::expression::{self, BooleanMatch};

    #[test]
    fn booleanmatch_direct_same_flip_uncorrelated() {
        // Two INT_EQUAL(x,y) => same; INT_EQUAL vs INT_NOTEQUAL(x,y) => complementary (booleanflip);
        // INT_EQUAL(x,y) vs INT_EQUAL(x,z) => uncorrelated.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let x = f.new_input(4, Address::new(reg, 0x10));
        let y = f.new_input(4, Address::new(reg, 0x18));
        let z = f.new_input(4, Address::new(reg, 0x20));
        let eq1 = f.new_op(OpCode::IntEqual, seq, vec![x, y]);
        let e1 = f.new_output(eq1, 1, Address::new(reg, 0x30));
        let eq2 = f.new_op(OpCode::IntEqual, seq, vec![x, y]);
        let e2 = f.new_output(eq2, 1, Address::new(reg, 0x31));
        let ne = f.new_op(OpCode::IntNotequal, seq, vec![x, y]);
        let n1 = f.new_output(ne, 1, Address::new(reg, 0x32));
        let eqz = f.new_op(OpCode::IntEqual, seq, vec![x, z]);
        let ez = f.new_output(eqz, 1, Address::new(reg, 0x33));
        parent_all(&mut f, vec![eq1, eq2, ne, eqz]);

        assert_eq!(expression::evaluate(&f, e1, e2, 1), BooleanMatch::Same);
        assert_eq!(expression::evaluate(&f, e1, n1, 1), BooleanMatch::Complementary);
        assert_eq!(expression::evaluate(&f, e1, ez, 1), BooleanMatch::Uncorrelated);
    }

    #[test]
    fn booleanmatch_reorder_and_sameop_complement() {
        // INT_SLESS(x,y) vs INT_SLESSEQUAL(y,x) => complementary (booleanflip with reorder);
        // x < 9 vs 8 < x (INT_LESS) => complementary (sameOpComplement).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let x = f.new_input(4, Address::new(reg, 0x10));
        let y = f.new_input(4, Address::new(reg, 0x18));
        let sl = f.new_op(OpCode::IntSless, seq, vec![x, y]);
        let sl_out = f.new_output(sl, 1, Address::new(reg, 0x30));
        let sle = f.new_op(OpCode::IntSlessequal, seq, vec![y, x]);
        let sle_out = f.new_output(sle, 1, Address::new(reg, 0x31));
        let c9 = f.new_const(4, 9);
        let c8 = f.new_const(4, 8);
        let l1 = f.new_op(OpCode::IntLess, seq, vec![x, c9]);
        let l1_out = f.new_output(l1, 1, Address::new(reg, 0x32));
        let l2 = f.new_op(OpCode::IntLess, seq, vec![c8, x]);
        let l2_out = f.new_output(l2, 1, Address::new(reg, 0x33));
        parent_all(&mut f, vec![sl, sle, l1, l2]);

        assert_eq!(expression::evaluate(&f, sl_out, sle_out, 1), BooleanMatch::Complementary);
        assert_eq!(expression::evaluate(&f, l1_out, l2_out, 1), BooleanMatch::Complementary);
    }

    #[test]
    fn booleanmatch_negate_and_demorgan() {
        // !A vs A => complementary (BOOL_NEGATE unwrap); A&&B vs !A||!B => complementary (De Morgan).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(1, Address::new(reg, 0x10));
        let b = f.new_input(1, Address::new(reg, 0x11));
        let nega = f.new_op(OpCode::BoolNegate, seq, vec![a]);
        let na = f.new_output(nega, 1, Address::new(reg, 0x20));
        let negb = f.new_op(OpCode::BoolNegate, seq, vec![b]);
        let nb = f.new_output(negb, 1, Address::new(reg, 0x21));
        let and = f.new_op(OpCode::BoolAnd, seq, vec![a, b]);
        let and_out = f.new_output(and, 1, Address::new(reg, 0x22));
        let or = f.new_op(OpCode::BoolOr, seq, vec![na, nb]);
        let or_out = f.new_output(or, 1, Address::new(reg, 0x23));
        parent_all(&mut f, vec![nega, negb, and, or]);

        assert_eq!(expression::evaluate(&f, na, a, 1), BooleanMatch::Complementary);
        assert_eq!(expression::evaluate(&f, and_out, or_out, 1), BooleanMatch::Complementary);
        // Depth exhausted: the AND/OR pair requires descending, so depth 0 gives uncorrelated
        assert_eq!(expression::evaluate(&f, and_out, or_out, 0), BooleanMatch::Uncorrelated);
    }

    #[test]
    fn booleanundistribute_notequal_of_ands() {
        // (A && B) != (A && C)  =>  A && (B != C)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(1, Address::new(reg, 0x10));
        let b = f.new_input(1, Address::new(reg, 0x11));
        let c = f.new_input(1, Address::new(reg, 0x12));
        let and0 = f.new_op(OpCode::BoolAnd, seq, vec![a, b]);
        let v0 = f.new_output(and0, 1, Address::new(reg, 0x20));
        let and1 = f.new_op(OpCode::BoolAnd, seq, vec![a, c]);
        let v1 = f.new_output(and1, 1, Address::new(reg, 0x21));
        let ne = f.new_op(OpCode::IntNotequal, seq, vec![v0, v1]);
        f.new_output(ne, 1, Address::new(reg, 0x22));
        parent_all(&mut f, vec![and0, and1, ne]);

        assert_eq!(RuleBooleanUndistribute.apply_op(ne, &mut f), 1);
        assert_eq!(f.op(ne).code(), OpCode::BoolAnd);
        assert_eq!(f.op(ne).input(0), Some(a));
        let tmp = f.op(ne).input(1).unwrap();
        let eq_op = f.vn(tmp).def.unwrap();
        assert_eq!(f.op(eq_op).code(), OpCode::IntNotequal);
        assert_eq!(f.op(eq_op).input(0), Some(b));
        assert_eq!(f.op(eq_op).input(1), Some(c));
    }

    #[test]
    fn booleanundistribute_equal_of_ands_negates() {
        // (A && B) == (A && C)  =>  !A || (B == C)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(1, Address::new(reg, 0x10));
        let b = f.new_input(1, Address::new(reg, 0x11));
        let c = f.new_input(1, Address::new(reg, 0x12));
        let and0 = f.new_op(OpCode::BoolAnd, seq, vec![a, b]);
        let v0 = f.new_output(and0, 1, Address::new(reg, 0x20));
        let and1 = f.new_op(OpCode::BoolAnd, seq, vec![a, c]);
        let v1 = f.new_output(and1, 1, Address::new(reg, 0x21));
        let eq = f.new_op(OpCode::IntEqual, seq, vec![v0, v1]);
        f.new_output(eq, 1, Address::new(reg, 0x22));
        parent_all(&mut f, vec![and0, and1, eq]);

        assert_eq!(RuleBooleanUndistribute.apply_op(eq, &mut f), 1);
        assert_eq!(f.op(eq).code(), OpCode::BoolOr);
        let neg_a = f.op(eq).input(0).unwrap();
        let neg_def = f.vn(neg_a).def.unwrap();
        assert_eq!(f.op(neg_def).code(), OpCode::BoolNegate);
        assert_eq!(f.op(neg_def).input(0), Some(a));
        let tmp = f.op(eq).input(1).unwrap();
        let inner = f.vn(tmp).def.unwrap();
        assert_eq!(f.op(inner).code(), OpCode::IntEqual);
        assert_eq!(f.op(inner).input(0), Some(b));
        assert_eq!(f.op(inner).input(1), Some(c));
    }

    #[test]
    fn booleandedup_or_of_ands_factors() {
        // (A && B) || (A && C)  =>  A && (B || C)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(1, Address::new(reg, 0x10));
        let b = f.new_input(1, Address::new(reg, 0x11));
        let c = f.new_input(1, Address::new(reg, 0x12));
        let and0 = f.new_op(OpCode::BoolAnd, seq, vec![a, b]);
        let v0 = f.new_output(and0, 1, Address::new(reg, 0x20));
        let and1 = f.new_op(OpCode::BoolAnd, seq, vec![a, c]);
        let v1 = f.new_output(and1, 1, Address::new(reg, 0x21));
        let or = f.new_op(OpCode::BoolOr, seq, vec![v0, v1]);
        f.new_output(or, 1, Address::new(reg, 0x22));
        parent_all(&mut f, vec![and0, and1, or]);

        assert_eq!(RuleBooleanDedup.apply_op(or, &mut f), 1);
        assert_eq!(f.op(or).code(), OpCode::BoolAnd);
        assert_eq!(f.op(or).input(0), Some(a));
        let tmp = f.op(or).input(1).unwrap();
        let inner = f.vn(tmp).def.unwrap();
        assert_eq!(f.op(inner).code(), OpCode::BoolOr);
        assert_eq!(f.op(inner).input(0), Some(b));
        assert_eq!(f.op(inner).input(1), Some(c));
    }

    #[test]
    fn booleandedup_contradiction_becomes_false() {
        // (A && B) && (!A && C)  =>  false
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(1, Address::new(reg, 0x10));
        let b = f.new_input(1, Address::new(reg, 0x11));
        let c = f.new_input(1, Address::new(reg, 0x12));
        let nega = f.new_op(OpCode::BoolNegate, seq, vec![a]);
        let na = f.new_output(nega, 1, Address::new(reg, 0x18));
        let and0 = f.new_op(OpCode::BoolAnd, seq, vec![a, b]);
        let v0 = f.new_output(and0, 1, Address::new(reg, 0x20));
        let and1 = f.new_op(OpCode::BoolAnd, seq, vec![na, c]);
        let v1 = f.new_output(and1, 1, Address::new(reg, 0x21));
        let and = f.new_op(OpCode::BoolAnd, seq, vec![v0, v1]);
        f.new_output(and, 1, Address::new(reg, 0x22));
        parent_all(&mut f, vec![nega, and0, and1, and]);

        assert_eq!(RuleBooleanDedup.apply_op(and, &mut f), 1);
        assert_eq!(f.op(and).code(), OpCode::Copy);
        assert_eq!(f.op(and).num_inputs(), 1);
        let k = f.op(and).input(0).unwrap();
        assert!(f.vn(k).is_constant() && f.vn(k).constant_value() == 0 && f.vn(k).size == 1);
    }

    #[test]
    fn booleandedup_no_fire_uncorrelated() {
        // (A && B) || (D && C) with unrelated D — no fire.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(1, Address::new(reg, 0x10));
        let b = f.new_input(1, Address::new(reg, 0x11));
        let c = f.new_input(1, Address::new(reg, 0x12));
        let d = f.new_input(1, Address::new(reg, 0x13));
        let and0 = f.new_op(OpCode::BoolAnd, seq, vec![a, b]);
        let v0 = f.new_output(and0, 1, Address::new(reg, 0x20));
        let and1 = f.new_op(OpCode::BoolAnd, seq, vec![d, c]);
        let v1 = f.new_output(and1, 1, Address::new(reg, 0x21));
        let or = f.new_op(OpCode::BoolOr, seq, vec![v0, v1]);
        f.new_output(or, 1, Address::new(reg, 0x22));
        parent_all(&mut f, vec![and0, and1, or]);

        assert_eq!(RuleBooleanDedup.apply_op(or, &mut f), 0);
        assert_eq!(f.op(or).code(), OpCode::BoolOr);
    }

    // ---- RuleAndOrLump (#21) / RuleRightShiftAnd (#23) -----------------------------------------

    #[test]
    fn andorlump_folds_nested_and_constants() {
        // (V & 0xff) & 0xf0  =>  V & 0xf0
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c1 = f.new_const(4, 0xff);
        let inner = f.new_op(OpCode::IntAnd, seq, vec![v, c1]);
        let iv = f.new_output(inner, 4, Address::new(reg, 0x18));
        let c2 = f.new_const(4, 0xf0);
        let outer = f.new_op(OpCode::IntAnd, seq, vec![iv, c2]);
        f.new_output(outer, 4, Address::new(reg, 0x20));
        parent_all(&mut f, vec![inner, outer]);

        assert_eq!(RuleAndOrLump.apply_op(outer, &mut f), 1);
        assert_eq!(f.op(outer).input(0), Some(v));
        let c = f.op(outer).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0xf0);
    }

    #[test]
    fn andorlump_needs_matching_parent_op() {
        // (V | 0xff) & 0xf0 — parent is OR, this op is AND → no fold.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c1 = f.new_const(4, 0xff);
        let inner = f.new_op(OpCode::IntOr, seq, vec![v, c1]);
        let iv = f.new_output(inner, 4, Address::new(reg, 0x18));
        let c2 = f.new_const(4, 0xf0);
        let outer = f.new_op(OpCode::IntAnd, seq, vec![iv, c2]);
        f.new_output(outer, 4, Address::new(reg, 0x20));
        parent_all(&mut f, vec![inner, outer]);

        assert_eq!(RuleAndOrLump.apply_op(outer, &mut f), 0);
    }

    #[test]
    fn rightshiftand_drops_redundant_mask() {
        // (V:4 & 0xff000000) >> 0x18  =>  V >> 0x18  (mask covers the whole surviving field)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let mask = f.new_const(4, 0xff000000);
        let and = f.new_op(OpCode::IntAnd, seq, vec![v, mask]);
        let av = f.new_output(and, 4, Address::new(reg, 0x18));
        let sa = f.new_const(4, 0x18);
        let shr = f.new_op(OpCode::IntRight, seq, vec![av, sa]);
        f.new_output(shr, 4, Address::new(reg, 0x20));
        parent_all(&mut f, vec![and, shr]);

        assert_eq!(RuleRightShiftAnd.apply_op(shr, &mut f), 1);
        assert_eq!(f.op(shr).input(0), Some(v));
    }

    #[test]
    fn rightshiftand_keeps_load_bearing_mask() {
        // (V:4 & 0xff0000) >> 8 — mask does NOT cover all surviving bits (bits 8..16 are cleared but
        // survive the shift), so the AND stays.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let mask = f.new_const(4, 0xff0000);
        let and = f.new_op(OpCode::IntAnd, seq, vec![v, mask]);
        let av = f.new_output(and, 4, Address::new(reg, 0x18));
        let sa = f.new_const(4, 8);
        let shr = f.new_op(OpCode::IntRight, seq, vec![av, sa]);
        f.new_output(shr, 4, Address::new(reg, 0x20));
        parent_all(&mut f, vec![and, shr]);

        assert_eq!(RuleRightShiftAnd.apply_op(shr, &mut f), 0);
        assert_eq!(f.op(shr).input(0), Some(av));
    }

    // ---- RuleSubCancel (#75) / RuleShiftSub (#76) ----------------------------------------------

    #[test]
    fn subcancel_total_elimination_of_zext() {
        // sub(zext(V:4):8, 0):4  =>  COPY(V)   (outsize == farinsize)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let z = f.new_op(OpCode::IntZext, seq, vec![v]);
        let zv = f.new_output(z, 8, Address::new(reg, 0x18));
        let off = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![zv, off]);
        f.new_output(sub, 4, Address::new(reg, 0x20));
        parent_all(&mut f, vec![z, sub]);

        assert_eq!(RuleSubCancel.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::Copy);
        assert_eq!(f.op(sub).num_inputs(), 1);
        assert_eq!(f.op(sub).input(0), Some(v));
    }

    #[test]
    fn subcancel_partial_extension_stays_zext() {
        // sub(zext(V:2):8, 0):4  =>  zext(V):4   (farinsize 2 < outsize 4 < insize 8)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(2, Address::new(reg, 0x10));
        let z = f.new_op(OpCode::IntZext, seq, vec![v]);
        let zv = f.new_output(z, 8, Address::new(reg, 0x18));
        let off = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![zv, off]);
        f.new_output(sub, 4, Address::new(reg, 0x20));
        parent_all(&mut f, vec![z, sub]);

        assert_eq!(RuleSubCancel.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::IntZext);
        assert_eq!(f.op(sub).num_inputs(), 1);
        assert_eq!(f.op(sub).input(0), Some(v));
    }

    #[test]
    fn subcancel_zext_high_offset_is_zero() {
        // sub(zext(V:2):8, 4):2  =>  COPY(0)   (offset 4 >= farinsize 2)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(2, Address::new(reg, 0x10));
        let z = f.new_op(OpCode::IntZext, seq, vec![v]);
        let zv = f.new_output(z, 8, Address::new(reg, 0x18));
        let off = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![zv, off]);
        f.new_output(sub, 2, Address::new(reg, 0x20));
        parent_all(&mut f, vec![z, sub]);

        assert_eq!(RuleSubCancel.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::Copy);
        let c = f.op(sub).input(0).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0);
    }

    #[test]
    fn subcancel_and_mask_drops_to_subpiece() {
        // sub(V:8 & 0xffffffff, 0):4  =>  sub(V, 0)  (mask == full mask of outsize 4)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let mask = f.new_const(8, 0xffffffff);
        let and = f.new_op(OpCode::IntAnd, seq, vec![v, mask]);
        let av = f.new_output(and, 8, Address::new(reg, 0x18));
        let off = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![av, off]);
        f.new_output(sub, 4, Address::new(reg, 0x20));
        parent_all(&mut f, vec![and, sub]);

        assert_eq!(RuleSubCancel.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::Subpiece);
        assert_eq!(f.op(sub).input(0), Some(v));
    }

    #[test]
    fn shiftsub_folds_byte_shift_into_offset() {
        // sub(V:8 << 0x10, 4):2  =>  sub(V, 4 - 2):2  = sub(V, 2)   (shift 16 bits = 2 bytes)
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let n = f.new_const(4, 0x10);
        let shl = f.new_op(OpCode::IntLeft, seq, vec![v, n]);
        let sv = f.new_output(shl, 8, Address::new(reg, 0x18));
        let off = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![sv, off]);
        f.new_output(sub, 2, Address::new(reg, 0x20));
        parent_all(&mut f, vec![shl, sub]);

        assert_eq!(RuleShiftSub.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).input(0), Some(v));
        assert_eq!(f.vn(f.op(sub).input(1).unwrap()).constant_value(), 2);
    }

    #[test]
    fn shiftsub_rejects_unnatural_truncation() {
        // sub(V:4 << 0x10, 0):4 — window [0-2, 0-2+4) = [-2, 2) escapes V (c-k < 0) → no fire.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let n = f.new_const(4, 0x10);
        let shl = f.new_op(OpCode::IntLeft, seq, vec![v, n]);
        let sv = f.new_output(shl, 4, Address::new(reg, 0x18));
        let off = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![sv, off]);
        f.new_output(sub, 4, Address::new(reg, 0x20));
        parent_all(&mut f, vec![shl, sub]);

        assert_eq!(RuleShiftSub.apply_op(sub, &mut f), 0);
    }

    // ---- batch 1: RuleLessOne / RuleXorSwap / RuleLzcountShiftBool / RuleFloatSign /
    // ---- RuleNegateNegate -----------------------------------------------------------------

    #[test]
    fn lessone_int_less_one_becomes_equal_zero() {
        // `V < 1` => `V == 0`, with the constant replaced by zero (ruleaction.cc:2233).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let one = f.new_const(4, 1);
        let cmp = f.new_op(OpCode::IntLess, seq, vec![v, one]);
        f.new_output_unique(cmp, 1);
        parent_all(&mut f, vec![cmp]);
        assert_eq!(RuleLessOne.apply_op(cmp, &mut f), 1);
        assert_eq!(f.op(cmp).code(), OpCode::IntEqual);
        let c = f.op(cmp).input(1).unwrap();
        assert_eq!(f.vn(c).constant_value(), 0);
        assert_eq!(f.vn(c).size, 4);
    }

    #[test]
    fn lessone_int_lessequal_zero_becomes_equal_keeping_constant() {
        // `V <= 0` => `V == 0`; val is already 0, so the constant is left alone.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let zero = f.new_const(4, 0);
        let cmp = f.new_op(OpCode::IntLessequal, seq, vec![v, zero]);
        f.new_output_unique(cmp, 1);
        parent_all(&mut f, vec![cmp]);
        assert_eq!(RuleLessOne.apply_op(cmp, &mut f), 1);
        assert_eq!(f.op(cmp).code(), OpCode::IntEqual);
        assert_eq!(f.op(cmp).input(1), Some(zero));
    }

    #[test]
    fn lessone_declines_other_bounds() {
        // `V < 2` is not a boundary comparison — declined.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let two = f.new_const(4, 2);
        let cmp = f.new_op(OpCode::IntLess, seq, vec![v, two]);
        f.new_output_unique(cmp, 1);
        parent_all(&mut f, vec![cmp]);
        assert_eq!(RuleLessOne.apply_op(cmp, &mut f), 0);
        assert_eq!(f.op(cmp).code(), OpCode::IntLess);
    }

    #[test]
    fn xorswap_collapses_shared_operand() {
        // `V ^ (V ^ W)` => `COPY W` (ruleaction.cc:6055).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let w = f.new_input(4, Address::new(reg, 0x18));
        let inner = f.new_op(OpCode::IntXor, seq(0), vec![v, w]);
        let inner_out = f.new_output_unique(inner, 4);
        let outer = f.new_op(OpCode::IntXor, seq(1), vec![v, inner_out]);
        f.new_output_unique(outer, 4);
        parent_all(&mut f, vec![inner, outer]);
        assert_eq!(RuleXorSwap.apply_op(outer, &mut f), 1);
        assert_eq!(f.op(outer).code(), OpCode::Copy);
        assert_eq!(f.op(outer).num_inputs(), 1);
        assert_eq!(f.op(outer).input(0), Some(w));
    }

    #[test]
    fn xorswap_declines_unrelated_xor() {
        // No shared operand — declined.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let w = f.new_input(4, Address::new(reg, 0x18));
        let x = f.new_input(4, Address::new(reg, 0x20));
        let inner = f.new_op(OpCode::IntXor, seq(0), vec![w, x]);
        let inner_out = f.new_output_unique(inner, 4);
        let outer = f.new_op(OpCode::IntXor, seq(1), vec![v, inner_out]);
        f.new_output_unique(outer, 4);
        parent_all(&mut f, vec![inner, outer]);
        assert_eq!(RuleXorSwap.apply_op(outer, &mut f), 0);
        assert_eq!(f.op(outer).code(), OpCode::IntXor);
    }

    #[test]
    fn negatenegate_collapses_to_copy() {
        // `~~V` => `COPY V` (ruleaction.cc:9040).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let neg2 = f.new_op(OpCode::IntNegate, seq(0), vec![v]);
        let neg2_out = f.new_output_unique(neg2, 4);
        let neg1 = f.new_op(OpCode::IntNegate, seq(1), vec![neg2_out]);
        f.new_output_unique(neg1, 4);
        parent_all(&mut f, vec![neg2, neg1]);
        assert_eq!(RuleNegateNegate.apply_op(neg1, &mut f), 1);
        assert_eq!(f.op(neg1).code(), OpCode::Copy);
        assert_eq!(f.op(neg1).input(0), Some(v));
    }

    #[test]
    fn floatsign_input_and_mask_becomes_float_abs() {
        // FLOAT_ADD reading `INT_AND(V, 0x7fffffff)` — the operand is really `ABS(V)`
        // (TypeOp::floatSignManipulation, typeop.cc:153).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let w = f.new_input(4, Address::new(reg, 0x18));
        let mask = f.new_const(4, 0x7fff_ffff);
        let and = f.new_op(OpCode::IntAnd, seq(0), vec![v, mask]);
        let and_out = f.new_output_unique(and, 4);
        let add = f.new_op(OpCode::FloatAdd, seq(1), vec![and_out, w]);
        f.new_output_unique(add, 4);
        parent_all(&mut f, vec![and, add]);
        assert_eq!(RuleFloatSign.apply_op(add, &mut f), 1);
        assert_eq!(f.op(and).code(), OpCode::FloatAbs);
        assert_eq!(f.op(and).num_inputs(), 1);
        assert_eq!(f.op(and).input(0), Some(v));
    }

    #[test]
    fn floatsign_output_xor_topbit_becomes_float_neg() {
        // A reader of a float op's output that XORs the top bit is `NEG`.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let w = f.new_input(4, Address::new(reg, 0x18));
        let add = f.new_op(OpCode::FloatAdd, seq(0), vec![v, w]);
        let add_out = f.new_output_unique(add, 4);
        let top = f.new_const(4, 0x8000_0000);
        let xor = f.new_op(OpCode::IntXor, seq(1), vec![add_out, top]);
        f.new_output_unique(xor, 4);
        parent_all(&mut f, vec![add, xor]);
        assert_eq!(RuleFloatSign.apply_op(add, &mut f), 1);
        assert_eq!(f.op(xor).code(), OpCode::FloatNeg);
        assert_eq!(f.op(xor).num_inputs(), 1);
        assert_eq!(f.op(xor).input(0), Some(add_out));
    }

    #[test]
    fn floatsign_declines_int2float_input_side() {
        // FLOAT_INT2FLOAT's input is an INTEGER, so an AND-mask feeding it is not a sign
        // manipulation — Ghidra skips the input side entirely for this opcode.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let mask = f.new_const(4, 0x7fff_ffff);
        let and = f.new_op(OpCode::IntAnd, seq(0), vec![v, mask]);
        let and_out = f.new_output_unique(and, 4);
        let cvt = f.new_op(OpCode::FloatInt2float, seq(1), vec![and_out]);
        f.new_output_unique(cvt, 4);
        parent_all(&mut f, vec![and, cvt]);
        assert_eq!(RuleFloatSign.apply_op(cvt, &mut f), 0);
        assert_eq!(f.op(and).code(), OpCode::IntAnd);
    }

    #[test]
    fn lzcount_shift_bool_becomes_equal_zero() {
        // `LZCOUNT(V:4) >> 5` is 1 exactly when V is zero: 8*4 = 32 is a power of two and
        // 32 >> 5 == 1 (ruleaction.cc:6100). The shift op survives as the width adapter.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let lz = f.new_op(OpCode::Lzcount, seq(0), vec![v]);
        let lz_out = f.new_output_unique(lz, 4);
        let five = f.new_const(4, 5);
        let shift = f.new_op(OpCode::IntRight, seq(1), vec![lz_out, five]);
        f.new_output_unique(shift, 4);
        parent_all(&mut f, vec![lz, shift]);
        assert_eq!(RuleLzcountShiftBool.apply_op(lz, &mut f), 1);
        // The shift became a ZEXT of a fresh `V == 0`.
        assert_eq!(f.op(shift).code(), OpCode::IntZext);
        assert_eq!(f.op(shift).num_inputs(), 1);
        let eq_out = f.op(shift).input(0).unwrap();
        let eq = f.vn(eq_out).def.unwrap();
        assert_eq!(f.op(eq).code(), OpCode::IntEqual);
        assert_eq!(f.op(eq).input(0), Some(v));
        let c = f.op(eq).input(1).unwrap();
        assert_eq!(f.vn(c).constant_value(), 0);
        assert_eq!(f.vn(eq_out).size, 1);
    }

    #[test]
    fn lzcount_shift_bool_declines_wrong_shift() {
        // 32 >> 4 == 2, not 1 — the test would not mean "V is zero".
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let lz = f.new_op(OpCode::Lzcount, seq(0), vec![v]);
        let lz_out = f.new_output_unique(lz, 4);
        let four = f.new_const(4, 4);
        let shift = f.new_op(OpCode::IntRight, seq(1), vec![lz_out, four]);
        f.new_output_unique(shift, 4);
        parent_all(&mut f, vec![lz, shift]);
        assert_eq!(RuleLzcountShiftBool.apply_op(lz, &mut f), 0);
        assert_eq!(f.op(shift).code(), OpCode::IntRight);
    }


    // ---- batch 2: RuleFuncPtrEncoding / RuleUnsigned2Float / RuleInt2FloatCollapse ----------

    #[test]
    fn funcptr_encoding_declines_when_spec_sets_no_alignment() {
        // funcptr_align == 0 (every x86 cspec) — Ghidra's first test, so the rule is inert.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let mask = f.new_const(8, 0xffff_ffff_ffff_fffe);
        let and = f.new_op(OpCode::IntAnd, seq(0), vec![v, mask]);
        let and_out = f.new_output_unique(and, 8);
        let call = f.new_op(OpCode::Callind, seq(1), vec![and_out]);
        parent_all(&mut f, vec![and, call]);
        assert_eq!(f.funcptr_align, 0);
        assert_eq!(RuleFuncPtrEncoding.apply_op(call, &mut f), 0);
        assert_eq!(f.op(and).code(), OpCode::IntAnd);
    }

    #[test]
    fn funcptr_encoding_drops_low_bit_mask_when_aligned() {
        // With `<funcptr align="2"/>` (funcptr_align == 1, the ARM/THUMB case), the mask clearing
        // bit 0 before an indirect call is the encoding, not the address — eliminated.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        f.funcptr_align = 1;
        let v = f.new_input(8, Address::new(reg, 0x10));
        let mask = f.new_const(8, u64::MAX << 1);
        let and = f.new_op(OpCode::IntAnd, seq(0), vec![v, mask]);
        let and_out = f.new_output_unique(and, 8);
        let call = f.new_op(OpCode::Callind, seq(1), vec![and_out]);
        parent_all(&mut f, vec![and, call]);
        assert_eq!(RuleFuncPtrEncoding.apply_op(call, &mut f), 1);
        assert_eq!(f.op(and).code(), OpCode::Copy);
        assert_eq!(f.op(and).num_inputs(), 1);
        assert_eq!(f.op(and).input(0), Some(v));
    }

    #[test]
    fn funcptr_encoding_declines_unrelated_mask() {
        // A mask that is not "all bits above the alignment" is real arithmetic — declined.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        f.funcptr_align = 1;
        let v = f.new_input(8, Address::new(reg, 0x10));
        let mask = f.new_const(8, 0xff);
        let and = f.new_op(OpCode::IntAnd, seq(0), vec![v, mask]);
        let and_out = f.new_output_unique(and, 8);
        let call = f.new_op(OpCode::Callind, seq(1), vec![and_out]);
        parent_all(&mut f, vec![and, call]);
        assert_eq!(RuleFuncPtrEncoding.apply_op(call, &mut f), 0);
        assert_eq!(f.op(and).code(), OpCode::IntAnd);
    }

    #[test]
    fn unsigned2float_collapses_halve_convert_double() {
        // `((V >> 1) | (V & 1))` converted signed, then added to itself, is really the unsigned
        // conversion of V (ruleaction.cc:10554).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let one = f.new_const(8, 1);
        let shift = f.new_op(OpCode::IntRight, seq(0), vec![v, one]);
        let shift_out = f.new_output_unique(shift, 8);
        let one2 = f.new_const(8, 1);
        let and = f.new_op(OpCode::IntAnd, seq(1), vec![v, one2]);
        let and_out = f.new_output_unique(and, 8);
        let or = f.new_op(OpCode::IntOr, seq(2), vec![shift_out, and_out]);
        let or_out = f.new_output_unique(or, 8);
        let cvt = f.new_op(OpCode::FloatInt2float, seq(3), vec![or_out]);
        let cvt_out = f.new_output_unique(cvt, 8);
        let add = f.new_op(OpCode::FloatAdd, seq(4), vec![cvt_out, cvt_out]);
        f.new_output_unique(add, 8);
        parent_all(&mut f, vec![shift, and, or, cvt, add]);
        assert_eq!(RuleUnsigned2Float.apply_op(cvt, &mut f), 1);
        // The doubling FLOAT_ADD became the unsigned conversion of a widened V.
        assert_eq!(f.op(add).code(), OpCode::FloatInt2float);
        assert_eq!(f.op(add).num_inputs(), 1);
        let zext_out = f.op(add).input(0).unwrap();
        let zext = f.vn(zext_out).def.unwrap();
        assert_eq!(f.op(zext).code(), OpCode::IntZext);
        assert_eq!(f.op(zext).input(0), Some(v));
        // preferredZextSize(8) == 9 (typeop.cc:1911).
        assert_eq!(f.vn(zext_out).size, 9);
    }

    #[test]
    fn unsigned2float_declines_without_the_doubling_add() {
        // No `f + f` reader — the idiom is not complete, so nothing is rewritten.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let one = f.new_const(8, 1);
        let shift = f.new_op(OpCode::IntRight, seq(0), vec![v, one]);
        let shift_out = f.new_output_unique(shift, 8);
        let one2 = f.new_const(8, 1);
        let and = f.new_op(OpCode::IntAnd, seq(1), vec![v, one2]);
        let and_out = f.new_output_unique(and, 8);
        let or = f.new_op(OpCode::IntOr, seq(2), vec![shift_out, and_out]);
        let or_out = f.new_output_unique(or, 8);
        let cvt = f.new_op(OpCode::FloatInt2float, seq(3), vec![or_out]);
        f.new_output_unique(cvt, 8);
        parent_all(&mut f, vec![shift, and, or, cvt]);
        assert_eq!(RuleUnsigned2Float.apply_op(cvt, &mut f), 0);
    }

    #[test]
    fn unsigned2float_declines_wrong_shift_amount() {
        // Shifted by 2, not 1 — this is not the halving idiom.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let two = f.new_const(8, 2);
        let shift = f.new_op(OpCode::IntRight, seq(0), vec![v, two]);
        let shift_out = f.new_output_unique(shift, 8);
        let one = f.new_const(8, 1);
        let and = f.new_op(OpCode::IntAnd, seq(1), vec![v, one]);
        let and_out = f.new_output_unique(and, 8);
        let or = f.new_op(OpCode::IntOr, seq(2), vec![shift_out, and_out]);
        let or_out = f.new_output_unique(or, 8);
        let cvt = f.new_op(OpCode::FloatInt2float, seq(3), vec![or_out]);
        let cvt_out = f.new_output_unique(cvt, 8);
        let add = f.new_op(OpCode::FloatAdd, seq(4), vec![cvt_out, cvt_out]);
        f.new_output_unique(add, 8);
        parent_all(&mut f, vec![shift, and, or, cvt, add]);
        assert_eq!(RuleUnsigned2Float.apply_op(cvt, &mut f), 0);
        assert_eq!(f.op(add).code(), OpCode::FloatAdd);
    }

    /// The branching unsigned-conversion shape RuleInt2FloatCollapse folds:
    ///
    /// ```text
    ///          b0:  if (V s< 0) goto b2      <- cond, out_edges [b1(signed), b2(unsigned)]
    ///     b1: f1 = (float)V           b2: f2 = (float)(zext V)
    ///          b3:  phi = MULTIEQUAL(f1, f2)
    /// ```
    fn int2float_branching(sless_form: bool) -> (Funcdata, OpId, OpId, VarnodeId) {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let v = f.new_input(4, Address::new(reg, 0x10));
        // b0: the sign test. `V s< 0` (true => unsigned) or `-1 s< V` (true => signed).
        let cmp = if sless_form {
            let zero = f.new_const(4, 0);
            f.new_op(OpCode::IntSless, seq(0), vec![v, zero])
        } else {
            let minus_one = f.new_const(4, 0xffff_ffff);
            f.new_op(OpCode::IntSless, seq(0), vec![minus_one, v])
        };
        let cmp_out = f.new_output_unique(cmp, 1);
        let dest = f.new_const(8, 0x100);
        let cbr = f.new_op(OpCode::Cbranch, seq(1), vec![dest, cmp_out]);
        // b1: the signed conversion.
        let signed = f.new_op(OpCode::FloatInt2float, seq(2), vec![v]);
        let signed_out = f.new_output_unique(signed, 8);
        // b2: the unsigned conversion, through a ZEXT.
        let zext = f.new_op(OpCode::IntZext, seq(3), vec![v]);
        let zext_out = f.new_output_unique(zext, 8);
        let unsigned = f.new_op(OpCode::FloatInt2float, seq(4), vec![zext_out]);
        let unsigned_out = f.new_output_unique(unsigned, 8);
        // b3: the join. Input order follows in_edges: [b1 (signed), b2 (unsigned)].
        let phi = f.new_op(OpCode::Multiequal, seq(5), vec![signed_out, unsigned_out]);
        f.new_output_unique(phi, 8);
        let blocks = vec![
            crate::decompile::BlockBasic {
                ops: vec![cmp, cbr],
                in_edges: vec![],
                out_edges: vec![BlockId(1), BlockId(2)],
            },
            crate::decompile::BlockBasic {
                ops: vec![signed],
                in_edges: vec![BlockId(0)],
                out_edges: vec![BlockId(3)],
            },
            crate::decompile::BlockBasic {
                ops: vec![zext, unsigned],
                in_edges: vec![BlockId(0)],
                out_edges: vec![BlockId(3)],
            },
            crate::decompile::BlockBasic {
                ops: vec![phi],
                in_edges: vec![BlockId(1), BlockId(2)],
                out_edges: vec![],
            },
        ];
        for (bi, blk) in blocks.iter().enumerate() {
            for &opid in &blk.ops {
                f.op_mut(opid).parent = Some(BlockId(bi as u32));
            }
        }
        f.set_blocks(blocks);
        (f, unsigned, phi, v)
    }

    #[test]
    fn int2float_collapse_folds_the_sign_test_branch() {
        // `(V s< 0) ? (float)(unsigned)V : (float)V` => `(float)(unsigned)V`, the MULTIEQUAL
        // itself redefined as the conversion (ruleaction.cc:10637).
        let (mut f, unsigned, phi, v) = int2float_branching(true);
        assert_eq!(RuleInt2FloatCollapse.apply_op(unsigned, &mut f), 1);
        assert_eq!(f.op(phi).code(), OpCode::FloatInt2float);
        assert_eq!(f.op(phi).num_inputs(), 1);
        let zext_out = f.op(phi).input(0).unwrap();
        let zext = f.vn(zext_out).def.unwrap();
        assert_eq!(f.op(zext).code(), OpCode::IntZext);
        assert_eq!(f.op(zext).input(0), Some(v));
        // preferredZextSize(4) == 8 (typeop.cc:1911).
        assert_eq!(f.vn(zext_out).size, 8);
    }

    #[test]
    fn int2float_collapse_rejects_reversed_branch_direction() {
        // Same shape with the condition written `-1 s< V`, whose TRUE branch must reach the
        // SIGNED conversion. Here it reaches the unsigned one, so the guard declines — this is
        // the arm that keeps the rule from folding a conditional that means the opposite.
        let (mut f, unsigned, phi, _) = int2float_branching(false);
        assert_eq!(RuleInt2FloatCollapse.apply_op(unsigned, &mut f), 0);
        assert_eq!(f.op(phi).code(), OpCode::Multiequal);
    }

    #[test]
    fn int2float_collapse_declines_signed_original() {
        // The op being examined must be the UNSIGNED conversion (input written by INT_ZEXT).
        let (mut f, _, phi, _) = int2float_branching(true);
        let signed = f.vn(f.op(phi).input(0).unwrap()).def.unwrap();
        assert_eq!(RuleInt2FloatCollapse.apply_op(signed, &mut f), 0);
        assert_eq!(f.op(phi).code(), OpCode::Multiequal);
    }


    // ---- batch 3: RuleFloatSignCleanup / RuleDumptyHumpLate / RuleExtensionPush -------------

    #[test]
    fn floatsign_cleanup_typed_float_and_becomes_abs() {
        // Post-type-inference: an INT_AND clearing the sign bit whose OUTPUT IS TYPED FLOAT is
        // FLOAT_ABS on its own, with no neighbouring float op (ruleaction.cc:10771).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let mask = f.new_const(4, 0x7fff_ffff);
        let and = f.new_op(OpCode::IntAnd, seq, vec![v, mask]);
        let out = f.new_output_unique(and, 4);
        f.vn_mut(out).update_type(crate::decompile::types::Datatype::Float(4));
        parent_all(&mut f, vec![and]);
        assert_eq!(RuleFloatSignCleanup.apply_op(and, &mut f), 1);
        assert_eq!(f.op(and).code(), OpCode::FloatAbs);
        assert_eq!(f.op(and).num_inputs(), 1);
    }

    #[test]
    fn floatsign_cleanup_declines_integer_output() {
        // The same bit pattern on an INTEGER-typed result is ordinary masking — the type test is
        // the whole difference between this rule and RuleFloatSign.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let mask = f.new_const(4, 0x7fff_ffff);
        let and = f.new_op(OpCode::IntAnd, seq, vec![v, mask]);
        let out = f.new_output_unique(and, 4);
        f.vn_mut(out).update_type(crate::decompile::types::Datatype::Uint(4));
        parent_all(&mut f, vec![and]);
        assert_eq!(RuleFloatSignCleanup.apply_op(and, &mut f), 0);
        assert_eq!(f.op(and).code(), OpCode::IntAnd);
    }

    #[test]
    fn dumpty_hump_late_reads_the_high_component_directly() {
        // `SUB(PIECE(hi,lo), 4):4` is just `hi` — exact size match with a free output, so the
        // output is replaced outright and the reader now reads `hi` (subflow.cc:3012).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let hi = f.new_input(4, Address::new(reg, 0x10));
        let lo = f.new_input(4, Address::new(reg, 0x18));
        let piece = f.new_op(OpCode::Piece, seq(0), vec![hi, lo]);
        let piece_out = f.new_output_unique(piece, 8);
        let four = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq(1), vec![piece_out, four]);
        let sub_out = f.new_output_unique(sub, 4);
        let reader = f.new_op(OpCode::IntAdd, seq(2), vec![sub_out, lo]);
        f.new_output_unique(reader, 4);
        parent_all(&mut f, vec![piece, sub, reader]);
        assert_eq!(RuleDumptyHumpLate.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(reader).input(0), Some(hi));
    }

    #[test]
    fn dumpty_hump_late_keeps_subpiece_when_component_is_wider() {
        // `SUB(PIECE(hi:4,lo:4), 4):2` lands inside `hi` but is narrower — the SUBPIECE survives,
        // re-rooted onto `hi` with the offset rebased to 0.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let hi = f.new_input(4, Address::new(reg, 0x10));
        let lo = f.new_input(4, Address::new(reg, 0x18));
        let piece = f.new_op(OpCode::Piece, seq(0), vec![hi, lo]);
        let piece_out = f.new_output_unique(piece, 8);
        let four = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq(1), vec![piece_out, four]);
        f.new_output_unique(sub, 2);
        parent_all(&mut f, vec![piece, sub]);
        assert_eq!(RuleDumptyHumpLate.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::Subpiece);
        assert_eq!(f.op(sub).input(0), Some(hi));
        let off = f.op(sub).input(1).unwrap();
        assert_eq!(f.vn(off).constant_value(), 0);
    }

    #[test]
    fn dumpty_hump_late_declines_when_truncation_straddles() {
        // `SUB(PIECE(hi:4,lo:4), 2):4` crosses both components — no component to re-root onto.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let hi = f.new_input(4, Address::new(reg, 0x10));
        let lo = f.new_input(4, Address::new(reg, 0x18));
        let piece = f.new_op(OpCode::Piece, seq(0), vec![hi, lo]);
        let piece_out = f.new_output_unique(piece, 8);
        let two = f.new_const(4, 2);
        let sub = f.new_op(OpCode::Subpiece, seq(1), vec![piece_out, two]);
        f.new_output_unique(sub, 4);
        parent_all(&mut f, vec![piece, sub]);
        assert_eq!(RuleDumptyHumpLate.apply_op(sub, &mut f), 0);
        assert_eq!(f.op(sub).input(0), Some(piece_out));
    }

    #[test]
    fn extension_push_duplicates_into_each_ptradd() {
        // A ZEXT read by two PTRADDs is duplicated into both and the original destroyed, so each
        // index expression can print its own cast (ruleaction.cc:10827).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let idx = f.new_input(4, Address::new(reg, 0x10));
        let base1 = f.new_input(8, Address::new(reg, 0x18));
        let base2 = f.new_input(8, Address::new(reg, 0x20));
        let zext = f.new_op(OpCode::IntZext, seq(0), vec![idx]);
        let zext_out = f.new_output_unique(zext, 8);
        let elem = f.new_const(8, 4);
        let pa1 = f.new_op(OpCode::Ptradd, seq(1), vec![base1, zext_out, elem]);
        f.new_output_unique(pa1, 8);
        let pa2 = f.new_op(OpCode::Ptradd, seq(2), vec![base2, zext_out, elem]);
        f.new_output_unique(pa2, 8);
        parent_all(&mut f, vec![zext, pa1, pa2]);
        assert_eq!(RuleExtensionPush.apply_op(zext, &mut f), 1);
        assert!(f.op(zext).is_dead(), "the shared extension is destroyed");
        // Each PTRADD now reads its OWN zext of the same index.
        let z1 = f.vn(f.op(pa1).input(1).unwrap()).def.unwrap();
        let z2 = f.vn(f.op(pa2).input(1).unwrap()).def.unwrap();
        assert_ne!(z1, z2);
        for z in [z1, z2] {
            assert_eq!(f.op(z).code(), OpCode::IntZext);
            assert_eq!(f.op(z).input(0), Some(idx));
        }
    }

    #[test]
    fn extension_push_declines_single_reader() {
        // One PTRADD reader — nothing is shared, so there is nothing to un-share.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let idx = f.new_input(4, Address::new(reg, 0x10));
        let base = f.new_input(8, Address::new(reg, 0x18));
        let zext = f.new_op(OpCode::IntZext, seq(0), vec![idx]);
        let zext_out = f.new_output_unique(zext, 8);
        let elem = f.new_const(8, 4);
        let pa = f.new_op(OpCode::Ptradd, seq(1), vec![base, zext_out, elem]);
        f.new_output_unique(pa, 8);
        parent_all(&mut f, vec![zext, pa]);
        assert_eq!(RuleExtensionPush.apply_op(zext, &mut f), 0);
        assert!(!f.op(zext).is_dead());
    }

    #[test]
    fn extension_push_declines_non_pointer_reader() {
        // A reader that is neither PTRADD nor an INT_ADD feeding a PTRADD aborts the whole rule —
        // the extension is not about to be hidden, so duplicating it would just add ops.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let idx = f.new_input(4, Address::new(reg, 0x10));
        let base = f.new_input(8, Address::new(reg, 0x18));
        let other = f.new_input(8, Address::new(reg, 0x28));
        let zext = f.new_op(OpCode::IntZext, seq(0), vec![idx]);
        let zext_out = f.new_output_unique(zext, 8);
        let elem = f.new_const(8, 4);
        let pa = f.new_op(OpCode::Ptradd, seq(1), vec![base, zext_out, elem]);
        f.new_output_unique(pa, 8);
        let mul = f.new_op(OpCode::IntMult, seq(2), vec![zext_out, other]);
        f.new_output_unique(mul, 8);
        parent_all(&mut f, vec![zext, pa, mul]);
        assert_eq!(RuleExtensionPush.apply_op(zext, &mut f), 0);
        assert!(!f.op(zext).is_dead());
    }


    // ---- batch 4: RuleConditionalMove -------------------------------------------------------

    /// The conditional-move shape:
    ///
    /// ```text
    ///        b0: if (c) ...            <- out_edges [b1 (false path), b2 (true path)]
    ///   b1: a = COPY #v0        b2: b = COPY #v1
    ///        b3: res = MULTIEQUAL(a, b)
    /// ```
    fn cond_move(v0: u64, v1: u64, sz: u32) -> (Funcdata, OpId, VarnodeId) {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: Address::new(ram.space, ram.offset + u as u64), uniq: u };
        let x = f.new_input(4, Address::new(reg, 0x10));
        let zero = f.new_const(4, 0);
        let cmp = f.new_op(OpCode::IntEqual, seq(0), vec![x, zero]);
        let cond = f.new_output_unique(cmp, 1);
        let dest = f.new_const(8, 0x100);
        let cbr = f.new_op(OpCode::Cbranch, seq(1), vec![dest, cond]);
        let k0 = f.new_const(sz, v0);
        let cp0 = f.new_op(OpCode::Copy, seq(2), vec![k0]);
        let a = f.new_output_unique(cp0, sz);
        let k1 = f.new_const(sz, v1);
        let cp1 = f.new_op(OpCode::Copy, seq(3), vec![k1]);
        let b = f.new_output_unique(cp1, sz);
        let phi = f.new_op(OpCode::Multiequal, seq(4), vec![a, b]);
        f.new_output_unique(phi, sz);
        let blocks = vec![
            crate::decompile::BlockBasic {
                ops: vec![cmp, cbr],
                in_edges: vec![],
                out_edges: vec![BlockId(1), BlockId(2)],
            },
            crate::decompile::BlockBasic {
                ops: vec![cp0],
                in_edges: vec![BlockId(0)],
                out_edges: vec![BlockId(3)],
            },
            crate::decompile::BlockBasic {
                ops: vec![cp1],
                in_edges: vec![BlockId(0)],
                out_edges: vec![BlockId(3)],
            },
            crate::decompile::BlockBasic {
                ops: vec![phi],
                in_edges: vec![BlockId(1), BlockId(2)],
                out_edges: vec![],
            },
        ];
        for (bi, blk) in blocks.iter().enumerate() {
            for &opid in &blk.ops {
                f.op_mut(opid).parent = Some(BlockId(bi as u32));
            }
        }
        f.set_blocks(blocks);
        (f, phi, cond)
    }

    #[test]
    fn conditional_move_two_constants_becomes_zext() {
        // `if (c) res = 0; else res = 1;` at width 4 => `res = zext(!c)`. b1 is the FALSE path
        // (out_edges[1] is the true one), so the condition needs complementing.
        let (mut f, phi, cond) = cond_move(1, 0, 4);
        assert_eq!(RuleConditionalMove.apply_op(phi, &mut f), 1);
        assert_eq!(f.op(phi).code(), OpCode::IntZext);
        assert_eq!(f.op(phi).num_inputs(), 1);
        let neg_out = f.op(phi).input(0).unwrap();
        let neg = f.vn(neg_out).def.unwrap();
        assert_eq!(f.op(neg).code(), OpCode::BoolNegate);
        assert_eq!(f.op(neg).input(0), Some(cond));
    }

    #[test]
    fn conditional_move_equal_constants_becomes_copy() {
        // Both arms supply the same literal — the branch is irrelevant, so it is a plain COPY.
        let (mut f, phi, _) = cond_move(1, 1, 4);
        assert_eq!(RuleConditionalMove.apply_op(phi, &mut f), 1);
        assert_eq!(f.op(phi).code(), OpCode::Copy);
        assert_eq!(f.op(phi).num_inputs(), 1);
        let c = f.op(phi).input(0).unwrap();
        assert!(f.vn(c).is_constant());
        assert_eq!(f.vn(c).constant_value(), 1);
    }

    #[test]
    fn conditional_move_boolean_width_uses_negate_not_zext() {
        // At width 1 there is nothing to extend: the merge becomes BOOL_NEGATE (or COPY) of the
        // condition directly.
        let (mut f, phi, cond) = cond_move(1, 0, 1);
        assert_eq!(RuleConditionalMove.apply_op(phi, &mut f), 1);
        assert_eq!(f.op(phi).code(), OpCode::BoolNegate);
        assert_eq!(f.op(phi).input(0), Some(cond));
    }

    #[test]
    fn conditional_move_declines_non_boolean_arms() {
        // Arms carrying values other than 0/1 are not a conditional move.
        let (mut f, phi, _) = cond_move(7, 0, 4);
        assert_eq!(RuleConditionalMove.apply_op(phi, &mut f), 0);
        assert_eq!(f.op(phi).code(), OpCode::Multiequal);
    }

    #[test]
    fn conditional_move_declines_three_input_multiequal() {
        // Ghidra's first test: exactly 2 inputs.
        let (mut f, phi, _) = cond_move(1, 0, 4);
        let extra = f.op(phi).input(0).unwrap();
        let mut ins: Vec<_> = (0..f.op(phi).num_inputs()).filter_map(|i| f.op(phi).input(i)).collect();
        ins.push(extra);
        f.op_set_all_input(phi, &ins);
        assert_eq!(RuleConditionalMove.apply_op(phi, &mut f), 0);
        assert_eq!(f.op(phi).code(), OpCode::Multiequal);
    }


    // ---- batch 5: RuleSwitchSingle ----------------------------------------------------------

    /// A BRANCHIND whose block has ONE out-edge, with a recovered single-entry jump table.
    fn switch_single(targets: Vec<u64>, labels: Vec<i64>, out_edges: Vec<BlockId>) -> (Funcdata, OpId) {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: Address::new(ram.space, 0x1000), uniq: u };
        let v = f.new_input(8, Address::new(reg, 0x10));
        let bi = f.new_op(OpCode::Branchind, seq(0), vec![v]);
        let blocks = vec![
            crate::decompile::BlockBasic { ops: vec![bi], in_edges: vec![], out_edges },
            crate::decompile::BlockBasic { ops: vec![], in_edges: vec![BlockId(0)], out_edges: vec![] },
        ];
        f.op_mut(bi).parent = Some(BlockId(0));
        f.set_blocks(blocks);
        f.jumptables = vec![crate::decompile::jumptable::JumpTable {
            op_addr: 0x1000,
            targets,
            default: None,
            labels,
            switchvn_loc: None,
            normalized: false,
        }];
        (f, bi)
    }

    #[test]
    fn switch_single_becomes_a_plain_branch() {
        // One out-edge + a labelled table => BRANCH to the single destination, table forgotten.
        let (mut f, bi) = switch_single(vec![0x2000], vec![0], vec![BlockId(1)]);
        assert_eq!(RuleSwitchSingle.apply_op(bi, &mut f), 1);
        assert_eq!(f.op(bi).code(), OpCode::Branch);
        let dest = f.op(bi).input(0).unwrap();
        assert!(f.vn(dest).is_annotation());
        assert_eq!(f.vn(dest).loc.offset, 0x2000);
        assert!(f.jumptables.is_empty(), "the table is removed with the switch");
    }

    #[test]
    fn switch_single_declines_multiway_block() {
        // Two out-edges — a real switch.
        let (mut f, bi) =
            switch_single(vec![0x2000, 0x3000], vec![0, 1], vec![BlockId(1), BlockId(1)]);
        assert_eq!(RuleSwitchSingle.apply_op(bi, &mut f), 0);
        assert_eq!(f.op(bi).code(), OpCode::Branchind);
        assert_eq!(f.jumptables.len(), 1);
    }

    #[test]
    fn switch_single_declines_unlabelled_table() {
        // No recovered labels: Ghidra requires them, because their absence is what signals a
        // multistage recovery problem rather than a genuine one-destination switch.
        let (mut f, bi) = switch_single(vec![0x2000], vec![], vec![BlockId(1)]);
        assert_eq!(RuleSwitchSingle.apply_op(bi, &mut f), 0);
        assert_eq!(f.op(bi).code(), OpCode::Branchind);
    }


    // ---- batch 6: RuleExpandLoad ------------------------------------------------------------

    #[test]
    fn expand_load_widens_to_the_pointee_and_truncates() {
        // `*(int1*)p` where p is `int4*` becomes a full 4-byte LOAD with a SUBPIECE recovering the
        // original byte (ruleaction.cc:10909).
        use crate::decompile::types::Datatype;
        let (mut f, ram_addr) = fd();
        let ram = f.spaces.by_name("ram").unwrap();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram_addr, uniq: 0 };
        let p = f.new_input(8, Address::new(reg, 0x10));
        f.vn_mut(p).update_type(Datatype::Pointer(8, Box::new(Datatype::Int(4))));
        let sid = f.new_const(8, ram.0 as u64);
        let load = f.new_op(OpCode::Load, seq, vec![sid, p]);
        let out = f.new_output_unique(load, 1);
        f.vn_mut(out).update_type(Datatype::Int(1));
        // A reader that is NOT the mask-and-compare shape, so the SUBPIECE path is taken. (With no
        // readers at all, Ghidra's checkAndComparison is vacuously true and the and-compare path
        // runs instead — a LOAD with no readers is dead, so that case does not arise in practice.)
        let other = f.new_input(1, Address::new(reg, 0x20));
        let use_op = f.new_op(OpCode::IntAdd, SeqNum { pc: ram_addr, uniq: 1 }, vec![out, other]);
        f.new_output_unique(use_op, 1);
        parent_all(&mut f, vec![load, use_op]);
        assert_eq!(RuleExpandLoad.apply_op(load, &mut f), 1);
        // The LOAD now produces the whole int4 ...
        let new_out = f.op(load).output.unwrap();
        assert_eq!(f.vn(new_out).size, 4);
        // ... and the original 1-byte value is a SUBPIECE of it at offset 0.
        let sub = f.vn(out).def.unwrap();
        assert_eq!(f.op(sub).code(), OpCode::Subpiece);
        assert_eq!(f.op(sub).input(0), Some(new_out));
        assert_eq!(f.vn(f.op(sub).input(1).unwrap()).constant_value(), 0);
    }

    #[test]
    fn expand_load_shifts_masks_in_the_and_compare_form() {
        // Every reader is `(v & #m) == #c`, and the LOAD sits at byte offset 2 through an INT_ADD:
        // no SUBPIECE is needed — the mask and the comparison constant shift left by 2 bytes, and
        // the INT_ADD folds away.
        use crate::decompile::types::Datatype;
        let (mut f, ram_addr) = fd();
        let ram = f.spaces.by_name("ram").unwrap();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram_addr, uniq: u };
        let p = f.new_input(8, Address::new(reg, 0x10));
        f.vn_mut(p).update_type(Datatype::Pointer(8, Box::new(Datatype::Uint(4))));
        let two = f.new_const(8, 2);
        let add = f.new_op(OpCode::IntAdd, seq(0), vec![p, two]);
        let padd = f.new_output_unique(add, 8);
        let sid = f.new_const(8, ram.0 as u64);
        let load = f.new_op(OpCode::Load, seq(1), vec![sid, padd]);
        let out = f.new_output_unique(load, 1);
        let mask = f.new_const(1, 0x3);
        let and = f.new_op(OpCode::IntAnd, seq(2), vec![out, mask]);
        let and_out = f.new_output_unique(and, 1);
        let k = f.new_const(1, 0x1);
        let cmp = f.new_op(OpCode::IntEqual, seq(3), vec![and_out, k]);
        f.new_output_unique(cmp, 1);
        parent_all(&mut f, vec![add, load, and, cmp]);
        assert_eq!(RuleExpandLoad.apply_op(load, &mut f), 1);
        let new_out = f.op(load).output.unwrap();
        assert_eq!(f.vn(new_out).size, 4);
        // The INT_ADD folded away: the LOAD reads the root pointer.
        assert_eq!(f.op(load).input(1), Some(p));
        assert!(f.op(add).is_dead());
        // Mask and comparison constant both shifted left by 8*2 bits, at the wider size.
        assert_eq!(f.op(and).input(0), Some(new_out));
        let m = f.op(and).input(1).unwrap();
        assert_eq!(f.vn(m).constant_value(), 0x3 << 16);
        assert_eq!(f.vn(m).size, 4);
        let c = f.op(cmp).input(1).unwrap();
        assert_eq!(f.vn(c).constant_value(), 0x1 << 16);
    }

    #[test]
    fn expand_load_declines_unknown_pointee() {
        // Ghidra's TYPE_UNKNOWN guard: an `undefined4*` says nothing about how much is really
        // there, so widening would be a guess. This is why the rule is silent on mosura's corpus,
        // where most pointees are still undefined.
        use crate::decompile::types::Datatype;
        let (mut f, ram_addr) = fd();
        let ram = f.spaces.by_name("ram").unwrap();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram_addr, uniq: 0 };
        let p = f.new_input(8, Address::new(reg, 0x10));
        f.vn_mut(p).update_type(Datatype::Pointer(8, Box::new(Datatype::Unknown(4))));
        let sid = f.new_const(8, ram.0 as u64);
        let load = f.new_op(OpCode::Load, seq, vec![sid, p]);
        f.new_output_unique(load, 1);
        parent_all(&mut f, vec![load]);
        assert_eq!(RuleExpandLoad.apply_op(load, &mut f), 0);
    }


    // ---- batch 7: RulePiecePathology + the bytes-consumed model ------------------------------

    /// `PIECE(SUBPIECE(param, 4), lo)` — the classic "read the whole register after something only
    /// wrote its low half". `param` is a non-persistent function input, which is Ghidra's first
    /// pathology source.
    fn piece_pathology_shape() -> (Funcdata, OpId, VarnodeId) {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let param = f.new_input(8, Address::new(reg, 0x10));
        let four = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq(0), vec![param, four]);
        let hi = f.new_output_unique(sub, 4);
        let lo = f.new_input(4, Address::new(reg, 0x20));
        let piece = f.new_op(OpCode::Piece, seq(1), vec![hi, lo]);
        let whole = f.new_output_unique(piece, 8);
        (f, piece, whole)
    }

    #[test]
    fn piece_pathology_records_the_returned_width() {
        // The pathological value reaches a RETURN, so only its low 4 bytes are really returned.
        let (mut f, piece, whole) = piece_pathology_shape();
        let ret = f.new_op(OpCode::Return, SeqNum { pc: f.op(piece).seqnum.pc, uniq: 2 }, vec![whole]);
        let ops = vec![piece, ret];
        let mut all = vec![f.vn(f.op(piece).input(0).unwrap()).def.unwrap()];
        all.extend(ops);
        parent_all(&mut f, all);
        assert_eq!(f.return_bytes_consumed, 0, "unset before the rule runs");
        assert_eq!(RulePiecePathology.apply_op(piece, &mut f), 1);
        assert_eq!(f.return_bytes_consumed, 4, "only the low half is really returned");
    }

    #[test]
    fn piece_pathology_records_the_argument_width_at_a_call() {
        // The same value passed as a CALL argument records the consumed width on that slot.
        use crate::decompile::fspec::CallSpec;
        let (mut f, piece, whole) = piece_pathology_shape();
        let pc = f.op(piece).seqnum.pc;
        let target = f.new_const(8, 0x2000);
        let call = f.new_op(OpCode::Call, SeqNum { pc, uniq: 2 }, vec![target, whole]);
        f.call_specs.insert(call, CallSpec::default());
        let sub = f.vn(f.op(piece).input(0).unwrap()).def.unwrap();
        parent_all(&mut f, vec![sub, piece, call]);
        assert_eq!(RulePiecePathology.apply_op(piece, &mut f), 1);
        assert_eq!(f.call_specs[&call].input_bytes_consumed(1), 4);
        // The setter only ever shrinks (fspec.cc:5887).
        let cs = f.call_specs.get_mut(&call).unwrap();
        assert!(!cs.set_input_bytes_consumed(1, 8), "a wider claim is discarded");
        assert!(cs.set_input_bytes_consumed(1, 2), "a narrower one is taken");
    }

    #[test]
    fn piece_pathology_declines_zero_offset_truncation() {
        // `SUBPIECE(v, 0)` is the LOW half — concatenating it back is not the pathology.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let param = f.new_input(8, Address::new(reg, 0x10));
        let zero = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, seq(0), vec![param, zero]);
        let hi = f.new_output_unique(sub, 4);
        let lo = f.new_input(4, Address::new(reg, 0x20));
        let piece = f.new_op(OpCode::Piece, seq(1), vec![hi, lo]);
        let whole = f.new_output_unique(piece, 8);
        let ret = f.new_op(OpCode::Return, seq(2), vec![whole]);
        parent_all(&mut f, vec![sub, piece, ret]);
        assert_eq!(RulePiecePathology.apply_op(piece, &mut f), 0);
        assert_eq!(f.return_bytes_consumed, 0);
    }

    #[test]
    fn piece_pathology_declines_a_persistent_input() {
        // A persistent (global) input's high bytes are real data, not garbage.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let param = f.new_input(8, Address::new(reg, 0x10));
        f.vn_mut(param).flags |= crate::decompile::varnode::flags::PERSIST;
        let four = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq(0), vec![param, four]);
        let hi = f.new_output_unique(sub, 4);
        let lo = f.new_input(4, Address::new(reg, 0x20));
        let piece = f.new_op(OpCode::Piece, seq(1), vec![hi, lo]);
        let whole = f.new_output_unique(piece, 8);
        let ret = f.new_op(OpCode::Return, seq(2), vec![whole]);
        parent_all(&mut f, vec![sub, piece, ret]);
        assert_eq!(RulePiecePathology.apply_op(piece, &mut f), 0);
        assert_eq!(f.return_bytes_consumed, 0);
    }

    #[test]
    fn return_bytes_consumed_only_shrinks() {
        // FuncProto::setReturnBytesConsumed (fspec.cc:3954).
        let (mut f, _) = fd();
        assert!(!f.set_return_bytes_consumed(0), "0 means no information");
        assert!(f.set_return_bytes_consumed(4));
        assert!(!f.set_return_bytes_consumed(8), "a wider claim is discarded");
        assert!(f.set_return_bytes_consumed(2));
        assert_eq!(f.return_bytes_consumed, 2);
    }


    // ---- batch 8: RulePtrsubCharConstant -----------------------------------------------------

    /// The shape the rule wants, built by hand because production cannot produce it yet: a PTRSUB
    /// off a pointer-to-spacebase, at a read-only address holding a NUL-terminated string.
    fn ptrsub_char_shape(readonly: bool, string_at: bool) -> (Funcdata, OpId, VarnodeId) {
        use crate::decompile::types::Datatype;
        let (mut f, ram) = fd();
        let ramspc = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let mut bytes = b"hello".to_vec();
        bytes.push(0);
        bytes.resize(64, 0);
        if !string_at {
            bytes[0] = 0x80; // illegal UTF-8 lead
        }
        f.image.push((0x2000, bytes));
        if readonly {
            f.readonly_ranges.push((0x2000, 0x203f));
        }
        // A spacebase-typed base pointer, as Funcdata::spacebaseConstant would build for a global.
        let base = f.new_const(8, 0);
        f.vn_mut(base)
            .update_type(Datatype::Pointer(8, Box::new(Datatype::Spacebase(ramspc))));
        let off = f.new_const(8, 0x2000);
        let sub = f.new_op(OpCode::Ptrsub, seq, vec![base, off]);
        let out = f.new_output_unique(sub, 8);
        f.vn_mut(out).update_type(Datatype::Pointer(8, Box::new(Datatype::Char)));
        parent_all(&mut f, vec![sub]);
        (f, sub, out)
    }

    #[test]
    fn ptrsub_char_constant_converts_a_readonly_string_pointer() {
        // A reader that is NOT a PTRADD cannot take the folded constant, so `removeCopy` stays
        // false and the PTRSUB is rewritten as a COPY of the pointer constant. (With NO readers at
        // all, Ghidra instead destroys the op — covered by the PTRADD test below.)
        let (mut f, sub, out) = ptrsub_char_shape(true, true);
        let other = f.new_input(8, Address::new(f.spaces.by_name("register").unwrap(), 0x10));
        let add = f.new_op(OpCode::IntAdd, SeqNum { pc: f.op(sub).seqnum.pc, uniq: 2 }, vec![out, other]);
        f.new_output_unique(add, 8);
        parent_all(&mut f, vec![sub, add]);
        assert_eq!(RulePtrsubCharConstant.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::Copy);
        assert_eq!(f.op(sub).num_inputs(), 1);
        let c = f.op(sub).input(0).unwrap();
        assert!(f.vn(c).is_constant());
        assert_eq!(f.vn(c).constant_value(), 0x2000);
    }

    #[test]
    fn ptrsub_char_constant_declines_writable_memory() {
        // Ghidra gates on Scope::isReadOnly — a writable address may not hold what it holds now.
        let (mut f, sub, _) = ptrsub_char_shape(false, true);
        assert_eq!(RulePtrsubCharConstant.apply_op(sub, &mut f), 0);
        assert_eq!(f.op(sub).code(), OpCode::Ptrsub);
    }

    #[test]
    fn ptrsub_char_constant_declines_when_the_bytes_are_not_a_string() {
        // Read-only, but the bytes fail the encoding check.
        let (mut f, sub, _) = ptrsub_char_shape(true, false);
        assert_eq!(RulePtrsubCharConstant.apply_op(sub, &mut f), 0);
        assert_eq!(f.op(sub).code(), OpCode::Ptrsub);
    }

    #[test]
    fn ptrsub_char_constant_pushes_the_constant_into_a_ptradd_reader() {
        // A PTRADD reader takes the folded constant, so the PTRSUB is removed entirely.
        let (mut f, sub, out) = ptrsub_char_shape(true, true);
        let idx = f.new_const(8, 3);
        let elem = f.new_const(8, 1);
        let pa = f.new_op(OpCode::Ptradd, SeqNum { pc: f.op(sub).seqnum.pc, uniq: 1 }, vec![out, idx, elem]);
        f.new_output_unique(pa, 8);
        parent_all(&mut f, vec![sub, pa]);
        assert_eq!(RulePtrsubCharConstant.apply_op(sub, &mut f), 1);
        assert!(f.op(sub).is_dead(), "the PTRSUB is destroyed once every reader takes the constant");
        assert_eq!(f.op(pa).code(), OpCode::Copy);
        let c = f.op(pa).input(0).unwrap();
        assert_eq!(f.vn(c).constant_value(), 0x2003, "0x2000 + 3*1 folded in");
    }

    #[test]
    fn ptrsub_char_constant_declines_a_non_spacebase_base() {
        // The stack-relative and ordinary-pointer cases: the pointee must be a spacebase.
        use crate::decompile::types::Datatype;
        let (mut f, sub, _) = ptrsub_char_shape(true, true);
        let base = f.op(sub).input(0).unwrap();
        f.vn_mut(base).update_type(Datatype::Pointer(8, Box::new(Datatype::Char)));
        assert_eq!(RulePtrsubCharConstant.apply_op(sub, &mut f), 0);
    }


    // ---- batch 9: RulePieceStructure ---------------------------------------------------------

    #[test]
    fn piece_structure_splits_a_concat_along_field_boundaries() {
        // The precondition is hand-built, because nothing in mosura yet gives a value a struct
        // type: `PIECE(b, a)` whose OUTPUT is typed as a 2-field struct. Each leaf is moved into
        // the storage its field occupies, via a COPY.
        use crate::decompile::types::Datatype;
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let a = f.new_input(4, Address::new(reg, 0x40)); // low field
        let b = f.new_input(4, Address::new(reg, 0x80)); // high field, at the WRONG address
        let piece = f.new_op(OpCode::Piece, seq(0), vec![b, a]);
        let out = f.new_output(piece, 8, Address::new(reg, 0x40));
        let st = Datatype::Struct(8, vec![(0, Datatype::Uint(4)), (4, Datatype::Uint(4))]);
        f.vn_mut(out).update_type(st);
        parent_all(&mut f, vec![piece]);
        assert_eq!(RulePieceStructure.apply_op(piece, &mut f), 1);
        assert!(f.op(piece).is_partial_root(), "the tree is marked visited");
        // The high field's leaf was at register+0x80 but its field lives at register+0x44, so a
        // COPY into that storage was inserted and the PIECE now reads it.
        let hi_in = f.op(piece).input(0).unwrap();
        assert_eq!(f.vn(hi_in).loc, Address::new(reg, 0x44));
        let copy = f.vn(hi_in).def.unwrap();
        assert_eq!(f.op(copy).code(), OpCode::Copy);
        assert_eq!(f.op(copy).input(0), Some(b));
    }

    #[test]
    fn piece_structure_declines_an_unstructured_output() {
        // The gate: without a structured type on the output there is no field layout to split
        // along. This is why the rule is inert on today's corpus.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x40));
        let b = f.new_input(4, Address::new(reg, 0x80));
        let piece = f.new_op(OpCode::Piece, seq, vec![b, a]);
        f.new_output_unique(piece, 8);
        parent_all(&mut f, vec![piece]);
        assert_eq!(RulePieceStructure.apply_op(piece, &mut f), 0);
        assert!(!f.op(piece).is_partial_root());
    }

    #[test]
    fn piece_structure_declines_a_tree_it_already_visited() {
        // Ghidra's isPartialRoot guard: the CONCAT tree is walked once.
        use crate::decompile::types::Datatype;
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x40));
        let b = f.new_input(4, Address::new(reg, 0x80));
        let piece = f.new_op(OpCode::Piece, seq, vec![b, a]);
        let out = f.new_output(piece, 8, Address::new(reg, 0x40));
        f.vn_mut(out)
            .update_type(Datatype::Struct(8, vec![(0, Datatype::Uint(4)), (4, Datatype::Uint(4))]));
        parent_all(&mut f, vec![piece]);
        f.op_mut(piece).set_partial_root();
        assert_eq!(RulePieceStructure.apply_op(piece, &mut f), 0);
    }

    #[test]
    fn piece_structure_spanning_range_detects_a_straddling_field() {
        // The helper that decides whether a ZEXT leaf needs converting: 4 bytes at offset 2 of a
        // two-4-byte-field struct straddles both fields; 4 bytes at offset 0 does not.
        use crate::decompile::types::Datatype;
        let st = Datatype::Struct(8, vec![(0, Datatype::Uint(4)), (4, Datatype::Uint(4))]);
        assert!(piece_structure_spanning_range(&st, 2, 4), "straddles the field boundary");
        assert!(!piece_structure_spanning_range(&st, 0, 4), "fits field 0 exactly");
    }

}
