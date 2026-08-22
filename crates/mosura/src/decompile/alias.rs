//! Stack-aliasing analysis — a port of Ghidra's `AliasChecker` (`varmap.cc`).
//!
//! Decides which stack slots are *aliased* — a pointer to them escapes — so that heritage's
//! conservative call-guards (`guard_calls`) are applied only to those.
//! A non-aliased local (a spilled loop variable touched only by direct constant-offset load/store)
//! is left untouched, so its loop SSA is undisturbed; an aliased local (one whose address is taken
//! and passed to a call, so the callee can modify it through the pointer) is guarded.
//!
//! `AliasChecker::gatherAdditiveBase` (varmap.cc:741): forward-walk the entry stack-pointer value
//! through *additive* ops only (`COPY`/`INT_ADD`/`INT_SUB`/`PTRADD`/`PTRSUB`, the constant-offset
//! address arithmetic); an SP-derived value used by any *non-additive* op (a CALL argument, a STORE
//! value, a compare, a MULTIEQUAL, …) is a root, and its stack offset has escaped. Dead ops are
//! skipped — Ghidra walks the live graph. A direct constant-offset LOAD/STORE *through* the pointer
//! is discounted (it is the class `RuleLoadVarnode`/`RuleStoreVarnode` resolves to a direct
//! stack-space varnode — Ghidra's checker runs at `aliasyes` passes, after conversion, so it never
//! sees them as pointer uses), so a slot only ever accessed directly is not aliased — the exact
//! discriminator between a spilled loop variable and a call-modified local, with no
//! calling-convention register scan.

use std::collections::HashSet;

use super::fspec::ProtoModel;
use super::funcdata::Funcdata;
use super::space::SpaceId;
use super::opcode::OpCode;
use super::varnode::VarnodeId;

/// Ghidra `AliasChecker::findSpacebaseInput` looks up the spacebase register from the compiler
/// spec; mosura carries it on [`Funcdata::stack_pointer`]. Formerly `const RSP: u64 = 0x20`, an
/// x86-64 constant that silently matched no register on `x86:LE:32` (ESP is `0x10` there) — see
/// [`super::stackvars`].
fn is_stack_pointer_input(f: &Funcdata, v: VarnodeId) -> bool {
    let vn = f.vn(v);
    vn.is_input() && f.stack_pointer.is_some_and(|sp| vn.loc == sp)
}

/// Ghidra `AliasChecker::gatherAdditiveBase`/`gatherOffset`: the entry-stack-relative offsets whose
/// address escapes as a value (a pointer can reach them).
pub fn aliased_stack_offsets(f: &Funcdata) -> HashSet<i64> {
    let mut aliased = HashSet::new();
    // The entry stack-pointer input varnode (Ghidra `findSpacebaseInput`).
    let Some(sp) = (0..f.num_varnodes() as u32).map(VarnodeId).find(|&v| is_stack_pointer_input(f, v))
    else {
        return aliased;
    };

    let mut seen: HashSet<VarnodeId> = HashSet::new();
    let mut queue = vec![(sp, 0i64)]; // (varnode holding entry_sp + off, off)
    while let Some((vn, off)) = queue.pop() {
        if !seen.insert(vn) {
            continue;
        }
        for op in f.vn(vn).descend.clone() {
            if f.op(op).is_dead() {
                continue; // a dead op is not a real use — walk the live graph
            }
            let o = f.op(op);
            match o.code() {
                // additive value movement — propagate the offset to the result
                OpCode::Copy => {
                    if let Some(out) = o.output {
                        queue.push((out, off));
                    }
                }
                OpCode::IntAdd => {
                    let other = if o.input(0) == Some(vn) { o.input(1) } else { o.input(0) };
                    match other.filter(|&x| f.vn(x).is_constant()) {
                        Some(c) => {
                            if let Some(out) = o.output {
                                queue.push((out, off + f.vn(c).loc.offset as i64));
                            }
                        }
                        None => {
                            aliased.insert(off); // a non-constant index ⇒ an indexed (aliased) access
                        }
                    }
                }
                OpCode::IntSub if o.input(0) == Some(vn) => match o.input(1).filter(|&x| f.vn(x).is_constant()) {
                    Some(c) => {
                        if let Some(out) = o.output {
                            queue.push((out, off - f.vn(c).loc.offset as i64));
                        }
                    }
                    None => {
                        aliased.insert(off);
                    }
                },
                // The typed additive forms RulePushPtr/RulePtrArith rewrite the INT_ADDs into
                // (`gatherAdditiveBase` treats PTRADD like INT_ADD and follows PTRSUB, varmap.cc:
                // 783-798): PTRSUB(base, #c) ⇒ base + c; PTRADD(base, idx, #elem) ⇒ base +
                // idx*elem, a non-constant idx being an indexed (aliased) access like INT_ADD's.
                OpCode::Ptrsub if o.input(0) == Some(vn) => {
                    match o.input(1).filter(|&x| f.vn(x).is_constant()) {
                        Some(c) => {
                            if let Some(out) = o.output {
                                queue.push((out, off.wrapping_add(f.vn(c).loc.offset as i64)));
                            }
                        }
                        None => {
                            aliased.insert(off);
                        }
                    }
                }
                OpCode::Ptradd if o.input(0) == Some(vn) => {
                    let idx = o.input(1).filter(|&x| f.vn(x).is_constant());
                    let elem = o.input(2).filter(|&x| f.vn(x).is_constant());
                    match (idx, elem) {
                        (Some(i), Some(e)) => {
                            if let Some(out) = o.output {
                                let c = (f.vn(i).loc.offset as i64).wrapping_mul(f.vn(e).loc.offset as i64);
                                queue.push((out, off.wrapping_add(c)));
                            }
                        }
                        _ => {
                            aliased.insert(off); // a non-constant index ⇒ an indexed (aliased) access
                        }
                    }
                }
                // A LOAD/STORE *through* the SP-derived pointer is a direct access to the slot, not
                // an escape of its address — exactly the class `RuleLoadVarnode`/`RuleStoreVarnode`
                // resolves to a direct stack varnode. Ghidra's checker never sees these: it runs at
                // `aliasyes` passes (`ActionRestructureVarnode`, pass != 0), after the previous
                // iteration's actprop2 already converted them; mosura's probe runs pre-conversion,
                // so the deref must be discounted here or every directly-accessed slot classifies
                // aliased. A STORE of the pointer *as the value* (input 2) still escapes below.
                OpCode::Load if o.input(1) == Some(vn) => {}
                OpCode::Store if o.input(1) == Some(vn) && o.input(2) != Some(vn) => {}
                // any other use ⇒ the SP-derived address escapes here, so the slot is aliased
                _ => {
                    aliased.insert(off);
                }
            }
        }
    }
    aliased
}

/// Ghidra `AliasChecker::aliasBoundary`/`hasLocalAlias`: once a pointer to some stack offset
/// escapes, the callee can reach every slot at or above it (a negative-growth frame), so the whole
/// region from the shallowest escaped offset upward is aliased. Returns that boundary, or `None`
/// when nothing escapes.
pub fn alias_boundary(f: &Funcdata) -> Option<i64> {
    aliased_stack_offsets(f).into_iter().min()
}

/// Ghidra `AliasChecker::AddBase`: a pointer Varnode into the stack and a possible index added to it.
#[derive(Clone, Copy)]
pub struct AddBase {
    pub base: VarnodeId,
    pub index: Option<VarnodeId>,
}

/// Ghidra `AliasChecker::gatherAdditiveBase` (varmap.cc:741): for every \e sum the entry stack
/// pointer is involved in (via the additive ops COPY/INT_ADD/INT_SUB/PTRADD/PTRSUB), collect the
/// root result Varnode of the sum, together with any non-constant index that was added in.  A root
/// is a Varnode that has at least one \e non-additive use (its stack address escapes there).
pub fn gather_additive_base(f: &Funcdata) -> Vec<AddBase> {
    let mut addbase: Vec<AddBase> = Vec::new();
    let Some(startvn) =
        (0..f.num_varnodes() as u32).map(VarnodeId).find(|&v| is_stack_pointer_input(f, v))
    else {
        return addbase;
    };

    // (varnode, index) work queue; `seen` plays the role of Ghidra's Varnode::setMark.
    let mut vnqueue: Vec<AddBase> = vec![AddBase { base: startvn, index: None }];
    let mut seen: HashSet<VarnodeId> = HashSet::from([startvn]);
    let mut i = 0;
    while i < vnqueue.len() {
        let vn = vnqueue[i].base;
        let mut index = vnqueue[i].index;
        i += 1;
        let mut nonadduse = false;
        for op in f.vn(vn).descend.clone() {
            let o = f.op(op);
            let push = |sub: Option<VarnodeId>, idx, q: &mut Vec<AddBase>, seen: &mut HashSet<VarnodeId>| {
                if let Some(sub) = sub {
                    if seen.insert(sub) {
                        q.push(AddBase { base: sub, index: idx });
                    }
                }
            };
            match o.code() {
                OpCode::Copy => {
                    nonadduse = true; // a COPY is both a non-add use and part of the ADD expression
                    push(o.output, index, &mut vnqueue, &mut seen);
                }
                OpCode::IntSub => {
                    if o.input(1) == Some(vn) {
                        nonadduse = true; // subtracting the pointer
                        continue;
                    }
                    let othervn = o.input(1).unwrap();
                    if !f.vn(othervn).is_constant() {
                        index = Some(othervn);
                    }
                    push(o.output, index, &mut vnqueue, &mut seen);
                }
                OpCode::IntAdd | OpCode::Ptradd => {
                    let mut othervn = o.input(1).unwrap();
                    if othervn == vn {
                        othervn = o.input(0).unwrap();
                    }
                    if !f.vn(othervn).is_constant() {
                        index = Some(othervn);
                    }
                    push(o.output, index, &mut vnqueue, &mut seen);
                }
                OpCode::Ptrsub => {
                    push(o.output, index, &mut vnqueue, &mut seen);
                }
                _ => nonadduse = true, // used in a non-additive expression
            }
        }
        if nonadduse {
            addbase.push(AddBase { base: vn, index });
        }
    }
    addbase
}

/// Ghidra `AliasChecker::gatherOffset` (varmap.cc:817): treat `vn` as the result of a series of
/// additive ops and sum the constant terms by walking the def graph backwards.
pub fn gather_offset(f: &Funcdata, vn: VarnodeId) -> u64 {
    let mask = |v: u64, size: u32| if size >= 8 { v } else { v & ((1u64 << (8 * size)) - 1) };
    if f.vn(vn).is_constant() {
        return f.vn(vn).constant_value();
    }
    let Some(def) = f.vn(vn).def else { return 0 };
    let o = f.op(def);
    let retval = match o.code() {
        OpCode::Copy => gather_offset(f, o.input(0).unwrap()),
        OpCode::Ptrsub | OpCode::IntAdd => {
            gather_offset(f, o.input(0).unwrap()).wrapping_add(gather_offset(f, o.input(1).unwrap()))
        }
        OpCode::IntSub => {
            gather_offset(f, o.input(0).unwrap()).wrapping_sub(gather_offset(f, o.input(1).unwrap()))
        }
        OpCode::Ptradd => {
            let othervn = o.input(2).unwrap();
            let base = gather_offset(f, o.input(0).unwrap());
            let in1 = o.input(1).unwrap();
            if f.vn(in1).is_constant() {
                base.wrapping_add(f.vn(in1).constant_value().wrapping_mul(f.vn(othervn).constant_value()))
            } else if f.vn(othervn).constant_value() == 1 {
                base.wrapping_add(gather_offset(f, in1))
            } else {
                base
            }
        }
        _ => 0,
    };
    mask(retval, f.vn(vn).size)
}

/// Ghidra `AliasChecker` (varmap.hh:138, varmap.cc:660-735): the object `ActionActiveParam` gathers
/// once per pass (`aliascheck.gather(&data, stackspace, true)`, coreaction.cc:1731) and
/// `FuncCallSpecs::checkInputTrialUse` asks `hasLocalAlias(vn)` of for every stack trial — a stack
/// slot at or above the shallowest escaped local address may be written by the callee through the
/// pointer, so it is "definitely not a parameter" (fspec.cc:5606). Lazy: the escapes are gathered on
/// the first query, over the graph as it stands then. The boundary arithmetic is UNSIGNED, as in
/// Ghidra: locals sit at the top of the offset space (negative offsets), parameters at the bottom,
/// so a parameter slot never tests as aliased and "after a pointer reference" means "at a higher
/// offset".
pub struct AliasChecker {
    /// The stack space (`space`).
    space: Option<SpaceId>,
    /// Collection of pointers into the address space (`addBase`).
    add_base: Vec<AddBase>,
    /// List of aliased addresses, as offsets (`alias`).
    alias: Vec<u64>,
    /// Have aliases been calculated (`calculated`).
    calculated: bool,
    /// Largest possible offset for a local variable (`localExtreme`).
    local_extreme: u64,
    /// Boundary offset separating locals and parameters (`localBoundary`).
    local_boundary: u64,
    /// Shallowest alias (`aliasBoundary`).
    alias_boundary: u64,
    /// 1 = stack grows negative, -1 = positive (`direction`).
    direction: i32,
}

impl AliasChecker {
    /// Ghidra `AliasChecker::gather` (varmap.cc:692): set up for the given function and stack
    /// space, deriving the local/parameter boundaries from its prototype model; `defer` postpones
    /// the escape gathering to the first query. (`direction` follows `space->stackGrowsNegative()`;
    /// mosura's stack model is negative-growth only — see `ProtoModel::default_local_range` — so it
    /// is 1.)
    pub fn gather(f: &Funcdata, spc: Option<SpaceId>, defer: bool) -> AliasChecker {
        let mut checker = AliasChecker {
            space: spc,
            add_base: Vec::new(),
            alias: Vec::new(),
            calculated: false, // defer calculation
            local_extreme: 0,
            local_boundary: 0,
            alias_boundary: 0,
            direction: 1, // direction == 1 for normal negative stack growth
        };
        checker.derive_boundaries(&f.proto_model);
        if !defer {
            checker.gather_internal(f);
        }
        checker
    }

    /// Ghidra `AliasChecker::deriveBoundaries` (varmap.cc:641): the offset separating locals from
    /// parameters, and the largest possible local offset, from the model's local and parameter
    /// ranges (defaults when the model has none).
    fn derive_boundaries(&mut self, proto: &ProtoModel) {
        self.local_extreme = u64::MAX; // default settings
        self.local_boundary = 0x1000000;
        if self.direction == -1 {
            self.local_extreme = self.local_boundary;
        }
        // (`proto.hasModel()`: mosura's function always carries a model; an empty one has no
        // ranges, which is the same null case.)
        let local = proto.localrange.iter().next();
        let param = proto.paramrange.iter().last();
        if let (Some(_local), Some(param)) = (local, param) {
            self.local_boundary = param.last;
            if self.direction == -1 {
                let first = proto.paramrange.iter().next().expect("a non-empty range list has a first range");
                self.local_boundary = first.first;
                self.local_extreme = self.local_boundary;
            }
        }
    }

    /// Ghidra `AliasChecker::gatherInternal` (varmap.cc:660): if there is a stack-pointer input,
    /// look for additive uses of it; once all those Varnodes are accumulated, calculate the
    /// specific offsets that start a region being aliased.
    fn gather_internal(&mut self, f: &Funcdata) {
        self.calculated = true;
        self.alias_boundary = self.local_extreme;
        // `fd->findSpacebaseInput(space)`: no stack-pointer input ⇒ no possible alias.
        if !(0..f.num_varnodes() as u32).map(VarnodeId).any(|v| is_stack_pointer_input(f, v)) {
            return;
        }
        self.add_base = gather_additive_base(f);
        for i in 0..self.add_base.len() {
            // (`AddrSpace::addressToByte`: mosura's stack space is byte-addressed.)
            let offset = gather_offset(f, self.add_base[i].base);
            if std::env::var_os("MOSURA_ARG_DEBUG").is_some() {
                let base = self.add_base[i].base;
                let uses: Vec<String> = f.vn(base).descend.iter().map(|&o| format!("{:?}@{:#x}{}", f.op(o).code(), f.op(o).seqnum.pc.offset, if f.op(o).is_dead() { "(dead)" } else { "" })).collect();
            }
            self.alias.push(offset);
            if self.direction == 1 {
                if offset < self.local_boundary {
                    continue; // parameter ref
                }
            } else if offset > self.local_boundary {
                continue; // parameter ref
            }
            // Always consider anything AFTER a pointer reference as aliased, regardless of the
            // stack direction
            if offset < self.alias_boundary {
                self.alias_boundary = offset;
            }
        }
    }

    /// Ghidra `AliasChecker::hasLocalAlias` (varmap.cc:711): is the given stack Varnode at or
    /// above the shallowest escaped local address? (For positive stack growth this is not a good
    /// test — values queued for a subfunction always sit a little above ALL locals — so it is
    /// never an alias there.)
    pub fn has_local_alias(&mut self, f: &Funcdata, vn: VarnodeId) -> bool {
        if !self.calculated {
            self.gather_internal(f);
        }
        if Some(f.vn(vn).loc.space) != self.space {
            return false;
        }
        if self.direction == -1 {
            return false;
        }
        f.vn(vn).loc.offset >= self.alias_boundary
    }

    /// Ghidra `AliasChecker::getAlias`: the list of alias starting offsets (unsorted; Ghidra's
    /// `sortAlias` is the caller's).
    pub fn alias(&self) -> &[u64] {
        &self.alias
    }
    /// The shallowest alias offset (`aliasBoundary`), for diagnostics.
    pub fn alias_boundary(&self) -> u64 {
        self.alias_boundary
    }
}
