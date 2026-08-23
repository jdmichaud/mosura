//! Ghidra `ActionConstantPtr` (coreaction.cc:1167, group `typerecovery`, mainloop slot :5665):
//! infer which constants are really pointers into the data space, and rewrite each into
//! `PTRSUB(<ram-spacebase>, #addr)` referencing the global at that address
//! ([`Funcdata::spacebase_constant`]). Gated on type recovery having started, at most 4 passes.
//!
//! The symbol query at the end of `isPointer` (`getScopeLocal()->getParent()->queryContainer`,
//! coreaction.cc:1152) is answered in Ghidra's application by the program database, which
//! resolves a symbol for ANY address inside a loaded memory block — that is why `&DAT_...`
//! references exist for addresses no one ever named. mosura's analog is
//! [`Funcdata::is_loaded`]: an in-image `rampoint` yields a synthesized entry at exactly that
//! address with unknown type (so `needexacthit` is trivially satisfied and the `extra` arm of
//! `spacebaseConstant` is structurally dead — see its notes).
//!
//! Configuration reductions, each cited: `inferPtrSpaces` is the single `ram` space (Ghidra
//! populates the list from the cspec; every mosura target infers into ram only);
//! `infer_pointers` is `true` (the cspec off-switch is not modeled); pointer bounds are
//! `AddrSpace::calcScaleMask`'s defaults (space.cc:33) — `[0x1000, highest-0x1000]` for
//! address sizes >= 3 bytes — with the cspec `<pointerbound>` override not modeled;
//! `Architecture::resolveConstant` is the flat-space arm (wrap into the space), the segmented
//! arm being x86-16 territory.

use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::SpaceId;
use super::types::Datatype;
use super::varnode::VarnodeId;

/// Ghidra `bit_transitions` (address.cc): the number of 0->1 / 1->0 transitions in the bit
/// pattern — a cheap "looks like an address, not a mask or a single bit" test.
fn bit_transitions(val: u64, size: u32) -> u32 {
    let mut count = 0;
    let mut last = val & 1;
    for i in 1..(size as u64 * 8) {
        let bit = (val >> i) & 1;
        if bit != last {
            count += 1;
            last = bit;
        }
    }
    count
}

/// Ghidra `ActionConstantPtr::searchForSpaceAttribute` (coreaction.cc:957): follow the value
/// forward up to 3 ops looking for a LOAD/STORE whose space-id constant names the pointer
/// space; then scan all descendants for the same. Only consulted when more than one space could
/// be inferred — with mosura's single-entry infer list it is unreachable, ported for the day a
/// second inferable space exists.
#[allow(dead_code)]
fn search_for_space_attribute(f: &Funcdata, mut vn: VarnodeId, mut op: OpId) -> Option<SpaceId> {
    for _ in 0..3 {
        if let Some(Datatype::Pointer(psz, inner)) = f.vn(vn).ty.as_ref() {
            if let Datatype::Spacebase(spc) = **inner {
                if f.spaces.get(spc).addr_size == *psz {
                    return Some(spc);
                }
            }
        }
        match f.op(op).code() {
            OpCode::IntAdd | OpCode::Copy | OpCode::Indirect | OpCode::Multiequal => {
                let out = f.op(op).output?;
                vn = out;
                if f.vn(out).descend.len() != 1 {
                    break;
                }
                op = f.vn(out).descend[0];
            }
            OpCode::Load => return space_from_const(f, f.op(op).input(0)?),
            OpCode::Store => {
                if f.op(op).input(1) == Some(vn) {
                    return space_from_const(f, f.op(op).input(0)?);
                }
                return None;
            }
            _ => return None,
        }
    }
    for &d in &f.vn(vn).descend {
        match f.op(d).code() {
            OpCode::Load => return space_from_const(f, f.op(d).input(0)?),
            OpCode::Store if f.op(d).input(1) == Some(vn) => {
                return space_from_const(f, f.op(d).input(0)?)
            }
            _ => {}
        }
    }
    None
}

/// `Varnode::getSpaceFromConst`: a LOAD/STORE's input 0 is a constant whose value is the space id.
fn space_from_const(f: &Funcdata, vn: VarnodeId) -> Option<SpaceId> {
    f.vn(vn).is_constant().then(|| SpaceId(f.vn(vn).loc.offset as u32))
}

/// Ghidra `ActionConstantPtr::selectInferSpace` (coreaction.cc:1005) over the one-element
/// mosura infer list: an explicitly pointer-typed constant selects its own space; otherwise
/// `ram` if the constant is pointer-sized for it.
fn select_infer_space(f: &Funcdata, vn: VarnodeId, ram: SpaceId) -> Option<SpaceId> {
    if let Some(Datatype::Pointer(psz, inner)) = f.vn(vn).ty.as_ref() {
        if let Datatype::Spacebase(spc) = **inner {
            if f.spaces.get(spc).addr_size == *psz {
                return Some(spc);
            }
        }
    }
    // minSize == 0 (no `<inferptrbounds>` sets one): exact pointer-size match required.
    (f.vn(vn).size == f.spaces.get(ram).addr_size).then_some(ram)
}

/// Ghidra `ActionConstantPtr::checkCopy` (coreaction.cc:1041): a COPY feeding a RETURN of a
/// function whose prototype is output-locked to a non-pointer refuses inference. mosura models
/// no prototype output locks, so only the `infer_pointers` default (true) remains — ported for
/// the shape, always permitting today.
fn check_copy(_f: &Funcdata, _op: OpId) -> bool {
    true
}

/// Ghidra `ActionConstantPtr::isPointer` (coreaction.cc:1070). Returns the resolved global
/// address (`rampoint`) when the constant should be treated as a pointer into `spc`.
fn is_pointer(f: &Funcdata, spc: SpaceId, vn: VarnodeId, op: OpId, slot: usize) -> Option<u64> {
    let needexact; // kept for fidelity; always satisfied by the synthesized exact-hit entry
    let v = f.vn(vn);
    if matches!(v.ty, Some(Datatype::Pointer(..))) {
        // Explicitly typed as a pointer (mosura's committed type stands in for
        // `getTypeReadFacing`): resolve without the heuristics.
        needexact = false;
    } else {
        // (Ghidra's `isTypeLock` early-out: type locks are not modeled.)
        needexact = true;
        match f.op(op).code() {
            OpCode::Call | OpCode::Callind => {
                if slot == 0 {
                    return None;
                }
                // Locked input prototypes are not modeled; `infer_pointers` (true) admits.
            }
            OpCode::Copy => {
                if !check_copy(f, op) {
                    return None;
                }
            }
            OpCode::Piece
            | OpCode::IntEqual
            | OpCode::IntNotequal
            | OpCode::IntLess
            | OpCode::IntLessequal => {
                // admitted by `infer_pointers` (true)
            }
            OpCode::IntAdd => {
                let out = f.op(op).output?;
                if matches!(f.vn(out).ty, Some(Datatype::Pointer(..))) {
                    let other = f.op(op).input(1 - slot)?;
                    if matches!(f.vn(other).ty, Some(Datatype::Pointer(..))) {
                        return None; // the other side is already the pointer base
                    }
                    // needexacthit = false in Ghidra; irrelevant under the exact-hit entry
                } // else admitted by `infer_pointers`
            }
            OpCode::Store => {
                if slot != 2 {
                    return None;
                }
            }
            _ => return None,
        }
        // Pointer range: `AddrSpace::calcScaleMask` defaults (space.cc:33).
        let space = f.spaces.get(spc);
        let highest = space.highest();
        let buffer = if space.addr_size < 3 { 0x100 } else { 0x1000 };
        if v.loc.offset < buffer || v.loc.offset > highest - buffer {
            return None;
        }
        if bit_transitions(v.loc.offset, v.size) < 3 {
            return None;
        }
    }
    let _ = needexact;
    // `Architecture::resolveConstant`, flat arm: wrap into the space.
    let rampoint = f.spaces.get(spc).wrap_offset(v.loc.offset);
    // The global-scope query (see the module header): under the APPLICATION scope model an
    // entry exists iff the address is in a loaded image block; under the STANDALONE model no
    // undeclared symbol resolves and the action is silent — matching each context's oracle
    // (`Funcdata::global_scope_all_loaded`). The entry sits exactly at `rampoint`, so
    // `needexacthit` holds.
    (f.global_scope_all_loaded && f.is_loaded(rampoint)).then_some(rampoint)
}

/// The action. `localcount` caps the passes at 4, as Ghidra's member does.
pub struct ActionConstantPtr {
    localcount: u32,
}

impl ActionConstantPtr {
    pub fn new() -> Self {
        ActionConstantPtr { localcount: 0 }
    }
}

impl super::action::Action for ActionConstantPtr {
    fn name(&self) -> &str {
        "constantptr"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        if !data.has_type_recovery_started() {
            return 0;
        }
        if self.localcount >= 4 {
            return 0; // At most 4 passes (once type recovery starts)
        }
        self.localcount += 1;

        let Some(ram) = data.spaces.by_name("ram") else { return 0 };
        let mut count = 0;
        // Ghidra iterates the constant-space location set; new constants created mid-loop are
        // guarded off by its `!isConstant -> break`. mosura snapshots the ids up front — later
        // creations get their turn on the next pass.
        let n = data.num_varnodes();
        for i in 0..n as u32 {
            let vn = VarnodeId(i);
            let v = data.vn(vn);
            if !v.is_constant() || v.loc.offset == 0 || v.is_ptr_check() || v.is_spacebase() {
                continue;
            }
            if v.descend.len() != 1 {
                if std::env::var_os("MOSURA_CONSTPTR_DEBUG").is_some() && v.descend.len() > 1 {
                    let rd: Vec<String> = v.descend.iter().map(|&o| format!("{:?}@{:#x}", data.op(o).code(), data.op(o).seqnum.pc.offset)).collect();
                    eprintln!("[constptr] pass{} #{:#x}/{} SHARED by {} readers [{}]", self.localcount, v.loc.offset, v.size, v.descend.len(), rd.join(" "));
                }
                continue; // loneDescend
            }
            let op = v.descend[0];
            if data.op(op).is_dead() {
                continue;
            }
            let Some(rspc) = select_infer_space(data, vn, ram) else { continue };
            let Some(slot) = (0..data.op(op).num_inputs()).find(|&s| data.op(op).input(s) == Some(vn))
            else {
                continue;
            };
            let opc = data.op(op).code();
            if opc == OpCode::IntAdd {
                let Some(other) = data.op(op).input(1 - slot) else { continue };
                if data.vn(other).is_spacebase() {
                    continue; // other side is already a spacebase
                }
            } else if opc == OpCode::Ptrsub || opc == OpCode::Ptradd {
                continue;
            }
            let hit = is_pointer(data, rspc, vn, op, slot);
            if std::env::var_os("MOSURA_CONSTPTR_DEBUG").is_some() {
                eprintln!(
                    "[constptr] pass{} #{:#x}/{} at {:?}@{:#x} slot{} -> {:?} (loaded={} all_loaded={})",
                    self.localcount, data.vn(vn).loc.offset, data.vn(vn).size, opc, data.op(op).seqnum.pc.offset, slot, hit,
                    data.is_loaded(data.vn(vn).loc.offset), data.global_scope_all_loaded
                );
            }
            data.vn_mut(vn).set_ptr_check(); // AFTER the search, as Ghidra does
            if let Some(rampoint) = hit {
                let (origval, origsize) = (data.vn(vn).loc.offset, data.vn(vn).size);
                data.spacebase_constant(op, slot, rampoint, origval, origsize, rspc);
                if opc == OpCode::IntAdd && slot == 1 {
                    data.op_swap_input(op, 0, 1);
                }
                count += 1;
            }
        }
        count
    }
}
