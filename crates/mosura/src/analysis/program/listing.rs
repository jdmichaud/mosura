//! `Listing` / `CodeUnit` — a port of Ghidra's `program/model/listing/` code-unit
//! view: every address is either an `Instruction`, a `Data` item, or undefined.
//!
//! **Minimal in A1** — the container + types exist so analyzers have somewhere to lay
//! down code/data, but it is populated by **A4** (disassembly + function discovery).

use crate::decompile::space::Address;

/// A defined code unit at an address (Ghidra `CodeUnit`: `Instruction` or `Data`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodeUnit {
    /// A disassembled instruction occupying `length` bytes.
    Instruction { length: u32 },
    /// A defined data item of `length` bytes, with its data-type name.
    Data { length: u32, type_name: String },
}

impl CodeUnit {
    pub fn length(&self) -> u32 {
        match self {
            CodeUnit::Instruction { length } | CodeUnit::Data { length, .. } => *length,
        }
    }
}

/// The defined code units of the program, keyed by start address (Ghidra `Listing`).
#[derive(Clone, Default, Debug)]
pub struct Listing {
    units: Vec<(Address, CodeUnit)>,
}

impl Listing {
    pub fn new() -> Listing {
        Listing { units: Vec::new() }
    }

    pub fn define(&mut self, addr: Address, unit: CodeUnit) {
        self.units.push((addr, unit));
        self.units.sort_by_key(|(a, _)| (a.space.0, a.offset));
    }

    pub fn code_unit_at(&self, addr: Address) -> Option<&CodeUnit> {
        self.units.iter().find(|(a, _)| *a == addr).map(|(_, u)| u)
    }

    pub fn code_units(&self) -> impl Iterator<Item = (Address, &CodeUnit)> {
        self.units.iter().map(|(a, u)| (*a, u))
    }

    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }
}
