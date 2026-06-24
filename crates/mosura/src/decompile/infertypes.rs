//! Type inference — a faithful port of Ghidra's `ActionInferTypes` (`coreaction.cc`).
//!
//! Each varnode is seeded with a *local* type read off the ops that produce and consume it
//! ([`build_localtypes`]/[`get_local_type`] ← Ghidra `buildLocaltypes`/`Varnode::getLocalType`),
//! then [`propagate_one_type`] (Ghidra `propagateOneType`) pushes each seed as far as it will go
//! through the data-flow graph, transforming it across each [`PcodeOp`] edge by the per-op rules
//! ([`propagate_type`] ← `TypeOp::propagateType`). A push is trimmed wherever the incoming type
//! is not strictly *more specific* than the one already on the target varnode, under
//! [`type_order`]. The settled per-varnode types are committed (`writeBack`) and resolved per
//! [`merge`] HighVariable so each C variable gets one type.
//!
//! **Storage-decoupled.** A varnode's type is whatever propagation lands on it, ordered by
//! [`type_order`] (sub-metatype, then width) — it is *not* pinned to `vn.size`. Local seeds are
//! sized to the varnode (a value's local type has the value's width), but propagation carries a
//! type across an edge by the op's rule, not by the target's storage: a COPY/phi/INDIRECT relays
//! the incoming type unchanged, a LOAD/STORE relays pointer↔pointee, a signed compare relays
//! signedness between its operands. The type a varnode ends up with is therefore an independent
//! property of the dataflow, the way Ghidra's `Datatype` is independent of the `Varnode`.
//!
//! Faithfully deferred (Ghidra has them; this port does not yet, pending the aggregate lattice
//! and the cast subsystem): `propagateAcrossReturns`, `propagateSpacebaseRef`/`propagateRef`,
//! SUBPIECE/PIECE propagation into composite (struct/array/union) types, and INT_ADD/PTRADD/
//! PTRSUB pointer arithmetic (`propagateAddIn2Out`/`downChain`/`TypePointerRel`). None of these
//! apply to the primitive lattice modelled here, so omitting them yields *fewer* refinements,
//! never wrong ones.

use std::cmp::Ordering;
use std::collections::HashMap;

use super::funcdata::Funcdata;
use super::merge::merge;
use super::op::OpId;
use super::opcode::OpCode;
use super::types::{meet, type_order, Datatype};
use super::varnode::{flags, VarnodeId};

/// A Ghidra `type_metatype` tag, just enough to size a local-type seed via [`base`].
#[derive(Clone, Copy)]
enum Meta {
    Unknown,
    Int,
    Uint,
    Bool,
    Float,
}

/// Ghidra's `TypeFactory::getBase(size, metatype)` for the metatypes that seed local types.
fn base(meta: Meta, size: u32) -> Datatype {
    match meta {
        Meta::Unknown => Datatype::Unknown(size),
        Meta::Int => Datatype::Int(size),
        Meta::Uint => Datatype::Uint(size),
        Meta::Bool => Datatype::Bool,
        Meta::Float => Datatype::Float(size),
    }
}

/// `(metaout, metain)` for an op — the metatypes its `TypeOp` advertises for its output and its
/// inputs (`TypeOpBinary`/`Unary`/`Func` constructors in `typeop.cc`). Everything unlisted —
/// COPY, LOAD, STORE, MULTIEQUAL, INDIRECT, SUBPIECE, PIECE, calls — uses the `TypeOp` default of
/// `(unknown, unknown)`; those ops carry no metatype of their own (their typing comes from
/// propagation, not a local seed).
fn op_meta(c: OpCode) -> (Meta, Meta) {
    use Meta::*;
    use OpCode::*;
    match c {
        IntEqual | IntNotequal | IntSless | IntSlessequal => (Bool, Int),
        IntLess | IntLessequal | IntCarry => (Bool, Uint),
        IntScarry | IntSborrow => (Bool, Int),
        IntZext => (Uint, Uint),
        IntSext => (Int, Int),
        IntAdd | IntSub | Int2comp | IntLeft | IntSright | IntMult | IntSdiv | IntSrem => (Int, Int),
        IntNegate | IntXor | IntAnd | IntOr | IntRight | IntDiv | IntRem => (Uint, Uint),
        BoolNegate | BoolXor | BoolAnd | BoolOr => (Bool, Bool),
        FloatEqual | FloatNotequal | FloatLess | FloatLessequal | FloatNan => (Bool, Float),
        FloatAdd | FloatDiv | FloatMult | FloatSub | FloatNeg | FloatAbs | FloatSqrt
        | FloatFloat2float | FloatCeil | FloatFloor | FloatRound => (Float, Float),
        FloatInt2float => (Float, Int),
        FloatTrunc => (Int, Float),
        Popcount | Lzcount => (Int, Unknown),
        _ => (Unknown, Unknown),
    }
}

/// The slot at which `vn` is read by `op`, or -1 if it is not an input (Ghidra `PcodeOp::getSlot`).
fn get_slot(f: &Funcdata, op: OpId, vn: VarnodeId) -> i32 {
    f.op(op)
        .inrefs
        .iter()
        .position(|&iv| iv == vn)
        .map(|p| p as i32)
        .unwrap_or(-1)
}

/// Ghidra's `PropagationState` — the edge iterator over a root varnode: first each descendant op
/// (its output, then its other inputs), then the defining op (its inputs). An edge is the triple
/// `(op, inslot, outslot)`, where a slot of -1 denotes the op's output and ≥0 an input index.
struct PropagationState {
    vn: VarnodeId,
    descend: Vec<OpId>,
    di: usize,
    op: Option<OpId>,
    inslot: i32,
    slot: i32,
}

impl PropagationState {
    fn new(f: &Funcdata, vn: VarnodeId) -> Self {
        let descend = f.vn(vn).descend.clone();
        if let Some(&op) = descend.first() {
            let slot = if f.op(op).output.is_some() { -1 } else { 0 };
            let inslot = get_slot(f, op, vn);
            PropagationState { vn, descend, di: 1, op: Some(op), inslot, slot }
        } else {
            let op = f.vn(vn).def;
            PropagationState { vn, descend, di: 0, op, inslot: -1, slot: 0 }
        }
    }

    fn valid(&self) -> bool {
        self.op.is_some()
    }

    fn step(&mut self, f: &Funcdata) {
        self.slot += 1;
        if let Some(op) = self.op {
            if (self.slot as usize) < f.op(op).num_inputs() {
                return;
            }
        }
        if self.di < self.descend.len() {
            let op = self.descend[self.di];
            self.di += 1;
            self.op = Some(op);
            self.slot = if f.op(op).output.is_some() { -1 } else { 0 };
            self.inslot = get_slot(f, op, self.vn);
            return;
        }
        // descendants exhausted: move on to the defining op, unless we are already there
        self.op = if self.inslot == -1 { None } else { f.vn(self.vn).def };
        self.inslot = -1;
        self.slot = 0;
    }
}

/// The running type-inference state: the temporary per-varnode types being propagated plus the
/// DFS `mark` bits (Ghidra keeps both on the `Varnode`; here they are side tables).
struct TypeInfer<'a> {
    f: &'a Funcdata,
    temp: Vec<Datatype>,
    mark: Vec<bool>,
    /// Type-locked varnodes (Ghidra `Varnode::typelock`) — e.g. parameters locked to their
    /// prototype type. A locked varnode keeps its type through `getLocalType`/`propagateTypeEdge`.
    locks: &'a HashMap<VarnodeId, Datatype>,
}

impl<'a> TypeInfer<'a> {
    fn new(f: &'a Funcdata, locks: &'a HashMap<VarnodeId, Datatype>) -> Self {
        let temp = (0..f.num_varnodes() as u32)
            .map(|i| Datatype::Unknown(f.vn(VarnodeId(i)).size))
            .collect();
        TypeInfer { f, temp, mark: vec![false; f.num_varnodes()], locks }
    }

    fn t(&self, v: VarnodeId) -> &Datatype {
        &self.temp[v.0 as usize]
    }

    /// Whether a varnode takes part in type inference (Ghidra skips annotations and varnodes that
    /// are neither written nor read).
    fn active(&self, v: VarnodeId) -> bool {
        let vn = self.f.vn(v);
        if vn.flags & flags::ANNOTATION != 0 {
            return false;
        }
        vn.is_written() || !vn.descend.is_empty()
    }

    /// Ghidra `Varnode::getLocalType`: the most-specific of the def's output local type and each
    /// use's input local type. A type-locked varnode returns its locked type unchanged.
    fn get_local_type(&self, v: VarnodeId) -> Datatype {
        if let Some(t) = self.locks.get(&v) {
            return t.clone(); // Ghidra: `if (isTypeLock()) return type;`
        }
        let vn = self.f.vn(v);
        let mut ct: Option<Datatype> = vn.def.map(|def| self.output_type_local(def));
        for &op in &vn.descend {
            let slot = get_slot(self.f, op, v);
            if slot < 0 {
                continue;
            }
            let newct = self.input_type_local(op, slot as usize);
            match &ct {
                None => ct = Some(newct),
                Some(cur) if type_order(&newct, cur) == Ordering::Less => ct = Some(newct),
                _ => {}
            }
        }
        ct.unwrap_or_else(|| Datatype::Unknown(vn.size))
    }

    fn output_type_local(&self, op: OpId) -> Datatype {
        let o = self.f.op(op);
        let size = o.output.map(|v| self.f.vn(v).size).unwrap_or(1);
        base(op_meta(o.code()).0, size)
    }

    fn input_type_local(&self, op: OpId, slot: usize) -> Datatype {
        let o = self.f.op(op);
        let size = o.input(slot).map(|v| self.f.vn(v).size).unwrap_or(1);
        base(op_meta(o.code()).1, size)
    }

    /// Ghidra `buildLocaltypes`: seed every active varnode with its local type.
    fn build_localtypes(&mut self) {
        for i in 0..self.f.num_varnodes() as u32 {
            let v = VarnodeId(i);
            if self.active(v) {
                self.temp[i as usize] = self.get_local_type(v);
            }
        }
    }

    /// Ghidra `propagateOneType`: push the type on `root` as far as it will go through the graph.
    fn propagate_one_type(&mut self, root: VarnodeId) {
        let mut stack = vec![PropagationState::new(self.f, root)];
        self.mark[root.0 as usize] = true;
        loop {
            let Some(top) = stack.last() else { break };
            if !top.valid() {
                let vn = top.vn;
                stack.pop();
                self.mark[vn.0 as usize] = false;
                continue;
            }
            let (op, inslot, outslot) = (top.op.unwrap(), top.inslot, top.slot);
            let pushed = self.propagate_type_edge(op, inslot, outslot);
            stack.last_mut().unwrap().step(self.f); // step before recursing, as Ghidra does
            if pushed {
                let newvn = self.edge_varnode(op, outslot);
                stack.push(PropagationState::new(self.f, newvn));
                self.mark[newvn.0 as usize] = true;
            }
        }
    }

    /// The varnode on the output end of an edge (-1 ⇒ op output, else the indexed input).
    fn edge_varnode(&self, op: OpId, slot: i32) -> VarnodeId {
        if slot < 0 {
            self.f.op(op).output.unwrap()
        } else {
            self.f.op(op).input(slot as usize).unwrap()
        }
    }

    /// Ghidra `propagateTypeEdge`: transform the incoming type across one op edge and, if the
    /// result is strictly more specific than the target's current type, install it. Returns
    /// whether to recurse into the target (i.e. the type changed and the target is not already on
    /// the DFS stack).
    fn propagate_type_edge(&mut self, op: OpId, inslot: i32, outslot: i32) -> bool {
        if inslot == outslot {
            return false; // never backtrack
        }
        let invn = self.edge_varnode(op, inslot);
        let alttype = self.t(invn).clone();
        let outvn = if outslot < 0 {
            self.f.op(op).output.unwrap()
        } else {
            let ov = self.f.op(op).input(outslot as usize).unwrap();
            if self.f.vn(ov).flags & flags::ANNOTATION != 0 {
                return false;
            }
            ov
        };
        if self.locks.contains_key(&outvn) {
            return false; // Ghidra: can't propagate through a typelock
        }
        // Only propagate a boolean into a value that can hold only 0/1. Ghidra tests the non-zero
        // mask; lacking that here, we approximate with single-byte storage (the bool's own width).
        if matches!(alttype, Datatype::Bool) && self.f.vn(outvn).size > 1 {
            return false;
        }
        let Some(newtype) = self.propagate_type(op, invn, outvn, inslot, outslot, &alttype) else {
            return false;
        };
        if type_order(&newtype, self.t(outvn)) == Ordering::Less {
            self.temp[outvn.0 as usize] = newtype;
            return !self.mark[outvn.0 as usize];
        }
        false
    }

    /// Ghidra `TypeOp::propagateType`: how each op transforms a type flowing across one of its
    /// edges. `None` means the type does not propagate along this edge.
    fn propagate_type(
        &self,
        op: OpId,
        invn: VarnodeId,
        outvn: VarnodeId,
        inslot: i32,
        outslot: i32,
        alttype: &Datatype,
    ) -> Option<Datatype> {
        use OpCode::*;
        match self.f.op(op).code() {
            // COPY / MULTIEQUAL relay the type unchanged between input and output.
            Copy | Multiequal => {
                if inslot != -1 && outslot != -1 {
                    return None;
                }
                Some(self.copy_like(invn, alttype))
            }
            // INDIRECT likewise, but never along the iop-pointer edge (slot 1).
            Indirect => {
                if inslot == 1 || outslot == 1 || (inslot != -1 && outslot != -1) {
                    return None;
                }
                Some(self.copy_like(invn, alttype))
            }
            // A signed compare relays *signedness* between its two operands (input↔input).
            IntSless | IntSlessequal => {
                if inslot == -1 || outslot == -1 || !matches!(alttype, Datatype::Int(_)) {
                    return None;
                }
                Some(alttype.clone())
            }
            // Other compares relay any type between operands (Ghidra `propagateAcrossCompare`).
            IntEqual | IntNotequal | IntLess | IntLessequal => {
                if inslot == -1 || outslot == -1 {
                    return None;
                }
                Some(self.copy_like(invn, alttype))
            }
            Load => self.propagate_load_store(op, invn, outvn, inslot, outslot, alttype, false),
            Store => self.propagate_load_store(op, invn, outvn, inslot, outslot, alttype, true),
            _ => None,
        }
    }

    /// Ghidra's spacebase special-case shared by COPY/MULTIEQUAL/INDIRECT/compare: a value copied
    /// off the stack/spacebase pointer is itself a pointer; otherwise the type relays unchanged.
    fn copy_like(&self, invn: VarnodeId, alttype: &Datatype) -> Datatype {
        if self.f.vn(invn).is_spacebase() {
            Datatype::Pointer(alttype.size(), Box::new(Datatype::Unknown(1)))
        } else {
            alttype.clone()
        }
    }

    /// LOAD/STORE pointer↔value propagation (Ghidra `TypeOpLoad`/`TypeOpStore::propagateType` via
    /// `propagateToPointer`/`propagateFromPointer`). LOAD: in0=space, in1=ptr, out=value. STORE:
    /// in0=space, in1=ptr, in2=value. Slot 0 (the space constant) never participates.
    fn propagate_load_store(
        &self,
        _op: OpId,
        invn: VarnodeId,
        outvn: VarnodeId,
        inslot: i32,
        outslot: i32,
        alttype: &Datatype,
        is_store: bool,
    ) -> Option<Datatype> {
        if inslot == 0 || outslot == 0 || self.f.vn(invn).is_spacebase() {
            return None;
        }
        // value→ptr: from the LOAD output (inslot -1) or the STORE value (inslot 2).
        let value_to_ptr = if is_store { inslot == 2 } else { inslot == -1 };
        if value_to_ptr {
            Some(propagate_to_pointer(alttype, self.f.vn(outvn).size))
        } else {
            propagate_from_pointer(alttype, self.f.vn(outvn).size)
        }
    }

    /// Ghidra `canonicalReturnOp`: the live RETURN whose value input has the most specific type.
    fn canonical_return(&self, returns: &[OpId]) -> Option<OpId> {
        let mut best: Option<(OpId, Datatype)> = None;
        for &r in returns {
            let vn = self.f.op(r).input(1)?;
            let ct = self.t(vn).clone();
            match &best {
                None => best = Some((r, ct)),
                Some((_, b)) if type_order(&ct, b) == Ordering::Less => best = Some((r, ct)),
                _ => {}
            }
        }
        best.map(|(r, _)| r)
    }

    /// Ghidra `propagateAcrossReturns`: a function returns a single data-type, so the type on the
    /// most-specific RETURN's value propagates to the value inputs of the other RETURNs.
    fn propagate_across_returns(&mut self) {
        let returns: Vec<OpId> = self
            .f
            .op_ids()
            .filter(|&op| {
                let o = self.f.op(op);
                !o.is_dead() && o.code() == OpCode::Return && o.num_inputs() > 1
            })
            .collect();
        let Some(canon) = self.canonical_return(&returns) else { return };
        let base = self.f.op(canon).input(1).unwrap();
        let ct = self.t(base).clone();
        let base_size = self.f.vn(base).size;
        let is_bool = matches!(ct, Datatype::Bool);
        for r in returns {
            if r == canon {
                continue;
            }
            let vn = self.f.op(r).input(1).unwrap();
            if self.f.vn(vn).size != base_size {
                continue;
            }
            // Ghidra: don't propagate bool unless the value is provably 0/1; approximate with width.
            if is_bool && self.f.vn(vn).size > 1 {
                continue;
            }
            if *self.t(vn) == ct {
                continue;
            }
            self.temp[vn.0 as usize] = ct.clone();
            self.propagate_one_type(vn);
        }
    }

    /// Ghidra `writeBack`: commit each varnode's settled temporary type (type-locks were honoured
    /// during propagation, and the permanent type starts at `undefined`).
    fn write_back(self) -> Vec<Datatype> {
        self.temp
    }
}

/// Ghidra `TypeOp::propagateToPointer`: build a pointer (of width `sz`) to the value type.
fn propagate_to_pointer(dt: &Datatype, sz: u32) -> Datatype {
    let inner = if matches!(dt, Datatype::Pointer(..)) {
        Datatype::Unknown(dt.size()) // pointer-to-pointer collapses to pointer-to-unknown
    } else {
        dt.clone()
    };
    Datatype::Pointer(sz, Box::new(inner))
}

/// Ghidra `TypeOp::propagateFromPointer`: the dereferenced element type, when the pointee width
/// matches the dereferenced size (the enum/partial-enum size-mismatch cases are deferred).
fn propagate_from_pointer(dt: &Datatype, sz: u32) -> Option<Datatype> {
    if let Datatype::Pointer(_, pointee) = dt {
        if pointee.size() == sz {
            return Some((**pointee).clone());
        }
    }
    None
}

/// Infer a type for every non-constant varnode: run the local-type seeding and per-varnode
/// propagation (Ghidra `ActionInferTypes::apply`), then resolve one type per [`merge`]
/// HighVariable so each emitted C variable is typed consistently across its SSA versions.
pub fn infer(f: &Funcdata, locks: &HashMap<VarnodeId, Datatype>) -> HashMap<VarnodeId, Datatype> {
    let mut ti = TypeInfer::new(f, locks);
    ti.build_localtypes();
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        if ti.active(v) {
            ti.propagate_one_type(v);
        }
    }
    ti.propagate_across_returns();
    let committed = ti.write_back();

    // Resolve to one type per HighVariable (Ghidra commits per-varnode; the C variable's type is
    // the meet of its members), then map every non-constant varnode to its variable's type. A
    // type-locked member wins for the whole variable (Ghidra's symbol type-lock).
    let mut h = merge(f);
    let nonconst: Vec<VarnodeId> = (0..f.num_varnodes() as u32)
        .map(VarnodeId)
        .filter(|&v| !f.vn(v).is_constant())
        .collect();

    let mut locked_hv: HashMap<u32, Datatype> = HashMap::new();
    for (&v, t) in locks {
        if !f.vn(v).is_constant() {
            locked_hv.insert(h.high(v), t.clone());
        }
    }
    let mut hv: HashMap<u32, Datatype> = HashMap::new();
    for &v in &nonconst {
        let id = h.high(v);
        if locked_hv.contains_key(&id) {
            continue;
        }
        let lt = committed[v.0 as usize].clone();
        hv.entry(id).and_modify(|t| *t = meet(t, &lt)).or_insert(lt);
    }

    nonconst
        .into_iter()
        .map(|v| {
            let id = h.high(v);
            let t = locked_hv
                .get(&id)
                .or_else(|| hv.get(&id))
                .cloned()
                .unwrap_or_else(|| committed[v.0 as usize].clone());
            (v, t)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::build::raw_funcdata_flow;
    use crate::decompile::pipeline;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::{Funcdata, OpCode, SeqNum};
    use crate::sleigh::engine::Spec;
    use crate::{datatest, paths};

    fn x86_64() -> Option<(Spec, Vec<u32>)> {
        let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
        if !sla.exists() {
            return None;
        }
        let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).ok()?;
        let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
        Some((spec, ctx))
    }

    #[test]
    fn signed_compare_seeds_a_signed_type() {
        // loopcomment is full of signed `<` bound checks (SBORROW → INT_SLESS). getLocalType
        // reads `int` off those compares, and propagation carries it onto the compared values —
        // exactly the signed `int` types that drive Ghidra's `(int4)param_1` casts.
        let Some((spec, ctx)) = x86_64() else { return };
        let dt = datatest::parse_file(&paths::datatests_dir().join("loopcomment.xml")).unwrap();
        let mut f = raw_funcdata_flow(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
        pipeline::decompile(&mut f);
        let types = infer(&f, &HashMap::new());
        assert!(
            types.values().any(|t| matches!(t, Datatype::Int(_))),
            "a signed comparison should seed a signed int type"
        );
    }

    #[test]
    fn copy_relays_a_type_across_a_unit() {
        // out = COPY(a), with `a` also read by FLOAT_ADD (so its local type is float).
        // Propagation must carry that float across the COPY onto `out`, whose own storage carries
        // no float signal — the storage-decoupled relay.
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_varnode(8, Address::new(reg, 0x100)); // free input, read twice
        let ofa = f.new_op(OpCode::FloatAdd, seq, vec![a, a]);
        let _b = f.new_output(ofa, 8, Address::new(reg, 0x200));
        let oc = f.new_op(OpCode::Copy, seq, vec![a]);
        let out = f.new_output(oc, 8, Address::new(reg, 0x300));

        let locks = HashMap::new();
        let mut ti = TypeInfer::new(&f, &locks);
        ti.build_localtypes();
        assert_eq!(ti.t(a), &Datatype::Float(8), "a FLOAT_ADD use makes `a` float locally");
        ti.propagate_one_type(a);
        assert_eq!(ti.t(out), &Datatype::Float(8), "float relays across the COPY to out");
    }

    #[test]
    fn unsigned_compare_seeds_unsigned_not_signed() {
        // INT_LESS advertises uint inputs; with no stronger signal a compared value stays uint
        // (uint orders fractionally ahead of int under `type_order`, matching Ghidra).
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_varnode(4, Address::new(reg, 0x100));
        let c = f.new_const(4, 10);
        let olt = f.new_op(OpCode::IntLess, seq, vec![a, c]);
        let _b = f.new_output(olt, 1, Address::new(reg, 0x200));

        let locks = HashMap::new();
        let mut ti = TypeInfer::new(&f, &locks);
        ti.build_localtypes();
        assert_eq!(ti.t(a), &Datatype::Uint(4), "INT_LESS seeds an unsigned operand");
    }
}
