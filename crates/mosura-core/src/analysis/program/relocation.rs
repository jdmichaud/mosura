//! `Relocation` / `RelocationTable` — a port of Ghidra's
//! `program/model/reloc/RelocationTable.java` + `Relocation.java`.
//!
//! The loader's record of every stored address the image's own relocation/fixup table
//! identifies. Ghidra's analyzers consult it as a **filter**: `AddressTable.getEntry`
//! (AddressTable.java:1131 → `isValidRelocationAddress` :1434) and
//! `OperandReferenceAnalyzer.checkForPointer` (:956) both refuse to treat a word as a pointer
//! when the program is relocatable and that word is not one of the relocations. Ghidra's own
//! comment states the premise: *"if it is relocatable, then there should be no pointers in
//! memory, other than relocatable ones"*.
//!
//! **`is_relocatable` is not "has relocations".** Ghidra's interface doc (RelocationTable.java:116)
//! is explicit: *"Returns true if this relocation table contains relocations for a relocatable
//! binary. Some binaries may contain relocations, but not actually be relocatable. For example,
//! ELF executables."* A table that is empty or not relocatable filters **nothing**, which is why
//! adding this type leaves every ELF/PE/COM program in the corpus bit-identical — they never
//! populate it, so `is_valid_relocation_address` keeps returning true exactly as the stub did.

use std::collections::BTreeSet;

use crate::decompile::space::Address;

/// One relocation record (Ghidra `Relocation`). `value` is the relocated address written into
/// the slot — Ghidra's `getValue()`; mosura's LE loader has it because it computes the value it
/// patches in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Relocation {
    /// The address of the slot the relocation applies to (Ghidra `getAddress`).
    pub address: Address,
    /// The relocated value written into that slot (Ghidra `getValue`).
    pub value: u64,
}

/// The program's relocation table (Ghidra `RelocationTable`).
#[derive(Clone, Default, Debug)]
pub struct RelocationTable {
    relocations: Vec<Relocation>,
    /// Slot-address index for `has_relocation` (Ghidra's table is indexed by address).
    addrs: BTreeSet<(u32, u64)>,
    relocatable: bool,
}

impl RelocationTable {
    /// An empty, non-relocatable table — the state every loader that does not populate one
    /// leaves it in, and the state in which every consumer's filter is inert.
    pub fn new() -> RelocationTable {
        RelocationTable::default()
    }

    /// Ghidra `isRelocatable` — whether these relocations belong to a *relocatable binary*, not
    /// merely whether any exist. Set by the loader.
    pub fn is_relocatable(&self) -> bool {
        self.relocatable
    }

    pub fn set_relocatable(&mut self, relocatable: bool) {
        self.relocatable = relocatable;
    }

    /// Ghidra `getSize` — the number of relocation records.
    pub fn size(&self) -> usize {
        self.relocations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.relocations.is_empty()
    }

    /// Ghidra `hasRelocation(Address)`.
    pub fn has_relocation(&self, addr: Address) -> bool {
        self.addrs.contains(&(addr.space.0, addr.offset))
    }

    /// Ghidra `add(...)` — record a relocation applied at `address` writing `value`.
    pub fn add(&mut self, address: Address, value: u64) {
        if self.addrs.insert((address.space.0, address.offset)) {
            self.relocations.push(Relocation { address, value });
        }
    }

    /// Ghidra `getRelocations()`.
    pub fn relocations(&self) -> impl Iterator<Item = &Relocation> {
        self.relocations.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::SpaceId;
    const RAM: SpaceId = SpaceId(1);

    /// The default table is the inert one: not relocatable, empty — so every consumer's filter
    /// passes. This is the property that keeps ELF/PE behaviour unchanged.
    #[test]
    fn default_table_is_inert() {
        let rt = RelocationTable::new();
        assert!(!rt.is_relocatable());
        assert_eq!(rt.size(), 0);
        assert!(!rt.has_relocation(Address::new(RAM, 0x1000)));
    }

    #[test]
    fn add_indexes_and_dedups() {
        let mut rt = RelocationTable::new();
        rt.set_relocatable(true);
        rt.add(Address::new(RAM, 0x1000), 0x40_1234);
        rt.add(Address::new(RAM, 0x1000), 0x40_1234); // dup
        rt.add(Address::new(RAM, 0x1004), 0x40_5678);
        assert_eq!(rt.size(), 2);
        assert!(rt.has_relocation(Address::new(RAM, 0x1004)));
        assert!(!rt.has_relocation(Address::new(RAM, 0x1008)));
        assert_eq!(rt.relocations().next().unwrap().value, 0x40_1234);
    }
}
