//! Hidden struct-return recovery — the FACT half, BEYOND GHIDRA, owed to the recompilation goal
//! (docs/struct-return-arm.md). On i386 a function returning a struct by value takes a hidden
//! pointer to the caller's return storage as its first parameter, writes the struct through it and
//! returns the pointer in EAX; a cdecl callee also pops the pointer's slot (`ret $4`, the SysV
//! rule), while gcc's local (regparm) convention keeps the pointer in EAX and pops nothing.
//! Ghidra's decompiler recovers none of it: its hidden-return mechanism is TYPE-driven
//! (`ProtoModel::assignParameterStorage` inserts the hidden input only when the return data type
//! is a struct, fspec.cc:2420/1583-1610/792-805), and with no type it prints exactly the
//! `void f(undefined4 *param_1, ..)` we print (the oracle traces in docs/ground-truth-findings.md).
//!
//! This module observes the SHAPE in the decompiled IR, per function, and the call-site EVIDENCE
//! per call; the decision (the byte witness) is `recompile::recovery::struct_return` and the
//! rendering is the `struct-return` emit arm. Both facts travel through the whole-program
//! prototype pass (`analysis::interface`), so a caller learns its callee's shape and a callee
//! learns its callers' evidence through the same fixpoint that carries prototypes.
use crate::decompile::funcdata::Funcdata;
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::space::Address;
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;

/// The shape of a hidden struct return: parameter slot 0 is a pointer that the body only STORES
/// through, at constant offsets inside `[0, size)`, and returns unchanged. `fields` are the stores
/// — `(offset, size, stored type)`, ascending, non-overlapping; `size` is their extent.
#[derive(Clone, Debug, PartialEq)]
pub struct SretShape {
    /// Parameter slot 0's storage (the cdecl stack slot, or the regparm EAX slot).
    pub slot: Address,
    pub size: u32,
    pub fields: Vec<(u32, u32, Datatype)>,
}

/// The per-function record the prototype pass keeps: the shape, and the bytes the function pops
/// on return (`RET n`, `None` when it has no single answer — `convention::callee_stack_cleanup`).
#[derive(Clone, Debug, PartialEq)]
pub struct SretFact {
    pub shape: Option<SretShape>,
    pub ret_pop: Option<u32>,
}

/// What one call site says about its callee's hidden pointer: the call's own output (EAX, the
/// returned pointer) is dead, and the slot-0 argument is the address of a caller stack local.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallEvidence {
    pub output_dead: bool,
    pub arg0_local_addr: bool,
}

impl CallEvidence {
    /// The evidence a struct-returning callee's every call site shows.
    pub fn supports_sret(&self) -> bool {
        self.output_dead && self.arg0_local_addr
    }
}

/// The largest struct the recovery admits (a store far past the pointer is an array walk, not a
/// return value).
const MAX_SIZE: u32 = 1024;

/// The hidden-return SHAPE of `f`, if its slot-0 parameter is only stored through and returned.
///
/// The walk follows the slot-0 input varnode through COPY/CAST and constant displacements
/// (INT_ADD by a constant, PTRADD by a constant index, PTRSUB by a constant) and admits exactly
/// two kinds of reader: a STORE whose ADDRESS is the walked value (a field write at that
/// displacement) and the RETURN whose value is the undisplaced pointer. Any other reader — a
/// LOAD through the pointer, a call argument, a compare, a phi, the pointer itself being stored
/// — is not this shape and the answer is `None`. At least one store and the return are required.
pub fn sret_shape(f: &Funcdata) -> Option<SretShape> {
    let r = sret_shape_inner(f);
    debug!(crate::debug::Topic::Args, "{:#x}: sret shape {:?}", f.addr.offset, r.as_ref().map(|s| (s.size, s.fields.len())));
    r
}

fn sret_shape_inner(f: &Funcdata) -> Option<SretShape> {
    let slots = crate::decompile::printc::rendered_param_slots(f);
    let Some(slot0) = slots.first() else {
        debug!(crate::debug::Topic::Args, "{:#x}: sret: no parameter slot", f.addr.offset);
        return None;
    };
    let Some(hidden) = slot0.vn else {
        debug!(crate::debug::Topic::Args, "{:#x}: sret: slot 0 unused", f.addr.offset);
        return None;
    };
    let ptr_size = pointer_size(f)?;
    if f.vn(hidden).size != ptr_size {
        debug!(crate::debug::Topic::Args, "{:#x}: sret: slot 0 is {} bytes, pointer {ptr_size}", f.addr.offset, f.vn(hidden).size);
        return None;
    }
    let mut fields: Vec<(u32, u32, Datatype)> = Vec::new();
    let mut returned = false;
    let mut work: Vec<(VarnodeId, i64)> = vec![(hidden, 0)];
    let mut seen: std::collections::HashSet<VarnodeId> = std::collections::HashSet::new();
    while let Some((v, disp)) = work.pop() {
        if !seen.insert(v) {
            continue;
        }
        for &r in &f.vn(v).descend {
            let o = f.op(r);
            if o.is_dead() {
                continue;
            }
            match o.code() {
                OpCode::Store => {
                    // input 1 = the address, input 2 = the value; the pointer itself stored is a leak
                    if o.input(1) != Some(v) || o.input(2) == Some(v) {
                        return None;
                    }
                    let val = o.input(2)?;
                    let sz = f.vn(val).size;
                    if disp < 0 || disp as u64 + sz as u64 > MAX_SIZE as u64 {
                        return None;
                    }
                    fields.push((disp as u32, sz, f.vn(val).get_type()));
                }
                OpCode::Return => {
                    if o.input(1) != Some(v) || disp != 0 {
                        return None;
                    }
                    returned = true;
                }
                OpCode::Copy | OpCode::Cast => {
                    work.push((o.output?, disp));
                }
                OpCode::IntAdd => {
                    let other = if o.input(0) == Some(v) { o.input(1)? } else { o.input(0)? };
                    if other == v || !f.vn(other).is_constant() {
                        return None;
                    }
                    work.push((o.output?, disp + sign_extend(f.vn(other).constant_value(), f.vn(other).size)));
                }
                OpCode::Ptrsub => {
                    if o.input(0) != Some(v) {
                        return None;
                    }
                    let c = o.input(1)?;
                    if !f.vn(c).is_constant() {
                        return None;
                    }
                    work.push((o.output?, disp + sign_extend(f.vn(c).constant_value(), f.vn(c).size)));
                }
                OpCode::Ptradd => {
                    if o.input(0) != Some(v) {
                        return None;
                    }
                    let (idx, elem) = (o.input(1)?, o.input(2)?);
                    if !f.vn(idx).is_constant() || !f.vn(elem).is_constant() {
                        return None;
                    }
                    let i = sign_extend(f.vn(idx).constant_value(), f.vn(idx).size);
                    work.push((o.output?, disp + i * f.vn(elem).constant_value() as i64));
                }
                other => {
                    debug!(crate::debug::Topic::Args, "{:#x}: sret: slot 0 read by {other:?} (op {})", f.addr.offset, r.0);
                    return None;
                }
            }
        }
    }
    // "Returned unchanged" has a second form, the one gcc's local convention produces: slot 0 IS
    // the model's return register (EAX under regparm) and nothing writes it, so every RETURN
    // carries no value at all — the decompiler (Ghidra too: trace A2) recovers `void`, and the
    // register still holds the pointer at the return by construction. A written value reaching a
    // RETURN in that register would have been recovered as the return value, and the walk above
    // would not have matched it.
    if !returned {
        let mut rets = f.op_ids().filter(|&op| !f.op(op).is_dead() && f.op(op).code() == OpCode::Return).peekable();
        let no_value = rets.peek().is_some() && rets.all(|op| f.op(op).num_inputs() <= 1);
        let slot0_is_return_reg = f.proto_model.output.as_ref().is_some_and(|pl| pl.possible_param(slot0.addr, ptr_size));
        returned = no_value && slot0_is_return_reg;
    }
    if fields.is_empty() || !returned {
        debug!(crate::debug::Topic::Args, "{:#x}: sret: {} stores, returned={returned}", f.addr.offset, fields.len());
        return None;
    }
    fields.sort_by_key(|&(off, _, _)| off);
    let mut end = 0u32;
    for &(off, sz, _) in &fields {
        if off < end {
            return None; // overlapping writes: not one field per store
        }
        end = off + sz;
    }
    Some(SretShape { slot: slot0.addr, size: end, fields })
}

/// What the call `call` in `f` says about its callee's slot-0 argument and returned pointer.
pub fn call_evidence(f: &Funcdata, call: OpId) -> CallEvidence {
    let o = f.op(call);
    let output_dead = match o.output {
        None => true,
        Some(out) => f.vn(out).descend.iter().all(|&r| f.op(r).is_dead()),
    };
    let arg0_local_addr = o.input(1).is_some_and(|a| local_address_off(f, a).is_some());
    CallEvidence { output_dead, arg0_local_addr }
}

/// The frame offset of the caller stack local whose address `v` is — a `PTRSUB(<spacebase>, #off)`
/// reached through COPY/CAST — sign-extended from the pointer width (`spacebase_sub_pointer`'s
/// rule: a 32-bit offset varnode holds the wrapped `0xffffffdc`, not `-0x24`).
pub fn local_address_off(f: &Funcdata, v: VarnodeId) -> Option<i64> {
    let mut v = v;
    for _ in 0..8 {
        let def = f.vn(v).def?;
        let o = f.op(def);
        match o.code() {
            OpCode::Copy | OpCode::Cast => v = o.input(0)?,
            OpCode::Ptrsub => {
                let base = o.input(0)?;
                if !f.vn(base).is_spacebase() {
                    return None;
                }
                let c = o.input(1)?;
                if !f.vn(c).is_constant() {
                    return None;
                }
                return Some(sign_extend(f.vn(c).constant_value(), f.vn(c).size));
            }
            _ => return None,
        }
    }
    None
}

fn sign_extend(v: u64, size: u32) -> i64 {
    let bits = (size as u32 * 8).min(64);
    if bits == 64 {
        return v as i64;
    }
    let m = 1u64 << (bits - 1);
    ((v & ((1u64 << bits) - 1)) ^ m).wrapping_sub(m) as i64
}

/// The target's pointer size: the stack pointer register's width (the spacebase entry of the
/// `stack` space, as `analysis::decompiler` reads it for `RET n`).
fn pointer_size(f: &Funcdata) -> Option<u32> {
    let st = f.spaces.by_name("stack")?;
    f.spaces.get(st).spacebase.first().map(|&(_, size)| size)
}

/// The C declaration of the anonymous struct a shape returns: `struct s8 { int4 f0; int4 f4; };`
/// — fields named by their byte offset with the STORED type, gaps `uint1 pad<off>[n]`, the tail
/// padded to `size`. Two shapes with the same layout print the same declaration, so a TU can
/// hold one per layout.
pub fn struct_declaration(shape: &SretShape) -> String {
    let mut s = format!("struct {} {{ ", struct_tag(shape));
    let mut at = 0u32;
    for (off, sz, ty) in &shape.fields {
        if *off > at {
            s += &format!("uint1 pad{at}[{}]; ", off - at);
        }
        s += &format!("{} f{off}; ", ty.name());
        at = off + sz;
    }
    if shape.size > at {
        s += &format!("uint1 pad{at}[{}]; ", shape.size - at);
    }
    s += "};";
    s
}

/// The struct's tag — `Datatype::struct_tag`, the one function of the layout that the
/// declaration and the printer's spelling of `Datatype::Struct` share.
pub fn struct_tag(shape: &SretShape) -> String {
    Datatype::struct_tag(shape.size, &layout(shape))
}

fn layout(shape: &SretShape) -> Vec<(u64, Datatype)> {
    shape.fields.iter().map(|(off, _, ty)| (*off as u64, ty.clone())).collect()
}

/// The shape as the printer's datatype (built at PRINT time only, never in the IR — the
/// `Datatype::Struct` census in cast.rs).
pub fn struct_datatype(shape: &SretShape) -> Datatype {
    Datatype::Struct(shape.size, layout(shape))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::types::Datatype;

    #[test]
    fn sign_extend_wraps_by_width() {
        assert_eq!(sign_extend(0xffffffdc, 4), -0x24);
        assert_eq!(sign_extend(4, 4), 4);
        assert_eq!(sign_extend(0xfffffffffffffff0, 8), -16);
    }

    #[test]
    fn struct_declaration_names_fields_by_offset_and_pads_gaps() {
        let ram = crate::decompile::space::SpaceId(0);
        let shape = SretShape {
            slot: Address::new(ram, 0),
            size: 12,
            fields: vec![(0, 4, Datatype::Int(4)), (8, 2, Datatype::Uint(2))],
        };
        assert_eq!(struct_declaration(&shape), "struct s12_i4p4u2p2 { int4 f0; uint1 pad4[4]; uint2 f8; uint1 pad10[2]; };");
        assert_eq!(struct_datatype(&shape).name(), "struct s12_i4p4u2p2");
    }

    /// The tag is a function of the layout: the contiguous all-int4 layout is `s<size>`, any
    /// other layout of the same size gets its own tag, and the declaration and the datatype's
    /// spelling agree.
    #[test]
    fn same_size_different_layouts_get_different_tags() {
        let ram = crate::decompile::space::SpaceId(0);
        let mk = |fields: Vec<(u32, u32, Datatype)>| SretShape { slot: Address::new(ram, 0), size: 8, fields };
        let ints = mk(vec![(0, 4, Datatype::Int(4)), (4, 4, Datatype::Int(4))]);
        let short_then_int = mk(vec![(0, 2, Datatype::Int(2)), (4, 4, Datatype::Int(4))]);
        let unknowns = mk(vec![(0, 4, Datatype::Unknown(4)), (4, 4, Datatype::Unknown(4))]);
        assert_eq!(struct_tag(&ints), "s8");
        assert_eq!(struct_tag(&short_then_int), "s8_i2p2i4");
        assert_eq!(struct_tag(&unknowns), "s8_x4x4");
        for s in [&ints, &short_then_int, &unknowns] {
            assert!(struct_declaration(s).starts_with(&format!("struct {} {{", struct_tag(s))));
            assert_eq!(struct_datatype(s).name(), format!("struct {}", struct_tag(s)));
        }
    }
}
