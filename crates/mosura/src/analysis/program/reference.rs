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
    UnconditionalCall,
    ConditionalCall,
    ComputedCall,
    Indirection,
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
            RefType::UnconditionalCall => "UNCONDITIONAL_CALL",
            RefType::ConditionalCall => "CONDITIONAL_CALL",
            RefType::ComputedCall => "COMPUTED_CALL",
            RefType::Indirection => "INDIRECTION",
        }
    }
    pub fn is_call(self) -> bool {
        matches!(self, RefType::UnconditionalCall | RefType::ConditionalCall | RefType::ComputedCall)
    }
    pub fn is_flow(self) -> bool {
        !matches!(self, RefType::Data | RefType::Read | RefType::Write)
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
}

impl ReferenceManager {
    pub fn new() -> ReferenceManager {
        ReferenceManager { refs: Vec::new() }
    }

    /// Add a reference, idempotent on `(from, to, op_index, ref_type)`.
    pub fn add(&mut self, from: Address, to: Address, ref_type: RefType, op_index: i32) {
        let r = Reference { from, to, ref_type, op_index };
        if self.refs.contains(&r) {
            return;
        }
        self.refs.push(r);
        self.refs.sort_by_key(|r| {
            (r.from.space.0, r.from.offset, r.to.space.0, r.to.offset, r.op_index, r.ref_type as i32)
        });
    }

    /// All references, ordered (Ghidra `getReferenceIterator`).
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
