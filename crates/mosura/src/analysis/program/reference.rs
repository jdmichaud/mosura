//! `Reference` / `ReferenceManager` / `RefType` — a port of Ghidra's
//! `program/model/symbol/` reference model (A5). A reference is a directed
//! `from → to` edge with a kind ([`RefType`]) and the operand it came from: flow
//! references (call/jump) created during disassembly, and data references created by
//! the constant-propagation analyzer.

use crate::decompile::space::Address;

/// The kind of a reference (Ghidra `RefType`, the subset we create). [`RefType::name`]
/// matches Ghidra's `RefType` string for the snapshot.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum RefType {
    Data,
    Read,
    Write,
    UnconditionalJump,
    ConditionalJump,
    ComputedJump,
    ConditionalComputedJump,
    UnconditionalCall,
    ConditionalCall,
    ComputedCall,
    ConditionalComputedCall,
    CallTerminator,
    ComputedCallTerminator,
    Indirection,
    /// Ghidra `RefType.PARAM` (`__UNKNOWNPARAM`): a constant/pointer argument passed to a
    /// call, recovered by the constant propagator's parameter analysis.
    Param,
}

impl RefType {
    pub fn name(self) -> &'static str {
        match self {
            RefType::Data => "DATA",
            RefType::Read => "READ",
            RefType::Write => "WRITE",
            RefType::UnconditionalJump => "UNCONDITIONAL_JUMP",
            RefType::ConditionalJump => "CONDITIONAL_JUMP",
            RefType::ComputedJump => "COMPUTED_JUMP",
            RefType::ConditionalComputedJump => "CONDITIONAL_COMPUTED_JUMP",
            RefType::UnconditionalCall => "UNCONDITIONAL_CALL",
            RefType::ConditionalCall => "CONDITIONAL_CALL",
            RefType::ComputedCall => "COMPUTED_CALL",
            RefType::ConditionalComputedCall => "CONDITIONAL_COMPUTED_CALL",
            RefType::CallTerminator => "CALL_TERMINATOR",
            RefType::ComputedCallTerminator => "COMPUTED_CALL_TERMINATOR",
            RefType::Indirection => "INDIRECTION",
            RefType::Param => "PARAM",
        }
    }
    pub fn is_call(self) -> bool {
        matches!(
            self,
            RefType::UnconditionalCall
                | RefType::ConditionalCall
                | RefType::ComputedCall
                | RefType::ConditionalComputedCall
                | RefType::CallTerminator
                | RefType::ComputedCallTerminator
        )
    }
    pub fn is_flow(self) -> bool {
        !matches!(self, RefType::Data | RefType::Read | RefType::Write | RefType::Param)
    }
    /// Ghidra `RefType.isJump()` — a jump-class flow (the family `OperandReferenceAnalyzer`
    /// re-types on an external jump).
    pub fn is_jump_like(self) -> bool {
        matches!(
            self,
            RefType::UnconditionalJump
                | RefType::ConditionalJump
                | RefType::ComputedJump
                | RefType::ConditionalComputedJump
        )
    }
}

/// A directed reference (Ghidra `Reference`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reference {
    pub from: Address,
    pub to: Address,
    pub ref_type: RefType,
    /// Operand index the reference came from (Ghidra `getOperandIndex`); `-1` for the
    /// mnemonic / a flow target.
    pub op_index: i32,
}

/// The program's references (Ghidra `ReferenceManager`).
#[derive(Clone, Default, Debug)]
pub struct ReferenceManager {
    refs: Vec<Reference>,
    /// Dedup key set `(from.space, from.off, to.space, to.off, op, type)` for O(1) `add`
    /// (the program can hold tens of thousands of references — a per-add scan/sort is
    /// quadratic). Iteration order is imposed by the snapshot, not maintained here.
    seen: std::collections::HashSet<(u32, u64, u32, u64, i32, i32)>,
}

impl ReferenceManager {
    pub fn new() -> ReferenceManager {
        ReferenceManager { refs: Vec::new(), seen: std::collections::HashSet::new() }
    }

    /// Add a reference, idempotent on `(from, to, op_index, ref_type)`.
    pub fn add(&mut self, from: Address, to: Address, ref_type: RefType, op_index: i32) {
        let key = (from.space.0, from.offset, to.space.0, to.offset, op_index, ref_type as i32);
        if self.seen.insert(key) {
            self.refs.push(Reference { from, to, ref_type, op_index });
        }
    }

    /// Change the type of the reference `from → to` (the effect of a flow override, which
    /// re-types the existing flow reference rather than adding a new one — Ghidra
    /// `Instruction.setFlowOverride` triggers reference fixup). No-op if no such reference
    /// exists. The dedup key set is updated so the re-typed reference round-trips.
    pub fn retype(&mut self, from: Address, to: Address, new_type: RefType) {
        for r in &mut self.refs {
            if r.from == from && r.to == to && r.ref_type != new_type {
                let old_key =
                    (from.space.0, from.offset, to.space.0, to.offset, r.op_index, r.ref_type as i32);
                let new_key =
                    (from.space.0, from.offset, to.space.0, to.offset, r.op_index, new_type as i32);
                self.seen.remove(&old_key);
                self.seen.insert(new_key);
                r.ref_type = new_type;
            }
        }
    }

    /// Remove every reference `from → to` of `ref_type` (any op index). Used when the
    /// parameter analysis claims an operand: Ghidra's `ScalarOperandAnalyzer` skips an
    /// operand that already carries a reference, so a speculative DATA ref must not coexist
    /// with the PARAM the constant propagator created at the same site.
    pub fn remove(&mut self, from: Address, to: Address, ref_type: RefType) {
        self.refs.retain(|r| !(r.from == from && r.to == to && r.ref_type == ref_type));
        self.seen.retain(|k| {
            !(k.0 == from.space.0 && k.1 == from.offset && k.2 == to.space.0 && k.3 == to.offset && k.5 == ref_type as i32)
        });
    }

    /// True if any reference `from → to` exists (any type/op index).
    pub fn has_ref(&self, from: Address, to: Address) -> bool {
        self.refs.iter().any(|r| r.from == from && r.to == to)
    }

    /// All references (unordered; the snapshot sorts). Ghidra `getReferenceIterator`.
    pub fn references(&self) -> impl Iterator<Item = &Reference> {
        self.refs.iter()
    }

    pub fn refs_from(&self, from: Address) -> impl Iterator<Item = &Reference> {
        self.refs.iter().filter(move |r| r.from == from)
    }

    pub fn refs_to(&self, to: Address) -> impl Iterator<Item = &Reference> {
        self.refs.iter().filter(move |r| r.to == to)
    }

    pub fn len(&self) -> usize {
        self.refs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::SpaceId;
    const RAM: SpaceId = SpaceId(1);

    #[test]
    fn add_dedups_and_queries() {
        let mut rm = ReferenceManager::new();
        let call = Address::new(RAM, 0x1042);
        let target = Address::new(RAM, 0x1000);
        rm.add(call, target, RefType::UnconditionalCall, -1);
        rm.add(call, target, RefType::UnconditionalCall, -1); // dup
        rm.add(Address::new(RAM, 0x1050), target, RefType::Data, 1);
        assert_eq!(rm.len(), 2);
        assert_eq!(rm.refs_to(target).count(), 2);
        assert_eq!(rm.refs_from(call).count(), 1);
        assert!(RefType::UnconditionalCall.is_call() && RefType::UnconditionalCall.is_flow());
        assert_eq!(RefType::ComputedJump.name(), "COMPUTED_JUMP");
    }
}
