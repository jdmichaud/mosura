//! `Listing` / `CodeUnit` — a port of Ghidra's `program/model/listing/` code-unit
//! view: every address is either an `Instruction`, a `Data` item, or undefined.
//!
//! **Minimal in A1** — the container + types exist so analyzers have somewhere to lay
//! down code/data, but it is populated by **A4** (disassembly + function discovery).

use std::collections::HashMap;

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
///
/// Hash-keyed by `(space, offset)` so `define`/`code_unit_at` are O(1): the program can
/// hold hundreds of thousands of code units, and the disassembler probes `code_unit_at`
/// once per instruction — a Vec scan/sort made disassembly quadratic. Iteration order is
/// imposed by the snapshot.
#[derive(Clone, Default, Debug)]
pub struct Listing {
    units: HashMap<(u32, u64), (Address, CodeUnit)>,
    /// Ordered index of instruction start addresses — the backing for Ghidra's
    /// `Listing.getInstructionAfter`, which `AddressTable.getEntry` calls once per candidate
    /// table (a scan of the hash map is O(listing) and WAR2 holds >100k instructions).
    instruction_starts: std::collections::BTreeSet<(u32, u64)>,
}

impl Listing {
    pub fn new() -> Listing {
        Listing::default()
    }

    pub fn define(&mut self, addr: Address, unit: CodeUnit) {
        if matches!(unit, CodeUnit::Instruction { .. }) {
            self.instruction_starts.insert((addr.space.0, addr.offset));
        }
        self.units.insert((addr.space.0, addr.offset), (addr, unit));
    }

    /// The first instruction starting strictly after `addr`, in `addr`'s space (Ghidra
    /// `Listing.getInstructionAfter`).
    pub fn instruction_after(&self, addr: Address) -> Option<Address> {
        self.instruction_starts
            .range((addr.space.0, addr.offset + 1)..)
            .next()
            .filter(|(s, _)| *s == addr.space.0)
            .map(|(s, o)| Address::new(crate::decompile::space::SpaceId(*s), *o))
    }

    pub fn code_unit_at(&self, addr: Address) -> Option<&CodeUnit> {
        self.units.get(&(addr.space.0, addr.offset)).map(|(_, u)| u)
    }

    /// The code unit whose `[start, start+length)` range contains `addr` (Ghidra
    /// `Listing.getCodeUnitContaining`), returning its start address and length. Probes
    /// backward within the maximum code-unit length (x86 instructions are ≤ 16 bytes; data
    /// items can be longer, but this is used only for instruction fall-through queries).
    pub fn code_unit_containing(&self, addr: Address, max_len: u64) -> Option<(Address, u64)> {
        for back in 0..=max_len {
            let off = addr.offset.checked_sub(back)?;
            if let Some((start, unit)) = self.units.get(&(addr.space.0, off)) {
                let len = u64::from(unit.length());
                if off + len > addr.offset {
                    return Some((*start, len));
                }
            }
        }
        None
    }

    pub fn code_units(&self) -> impl Iterator<Item = (Address, &CodeUnit)> {
        self.units.values().map(|(a, u)| (*a, u))
    }

    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Number of defined code units (Ghidra `Listing.getNumCodeUnits`). Used as half the
    /// staleness key of the analysis-time body refresh
    /// ([`crate::analysis::analyzers::refresh_function_bodies`]): a body goes stale when code is
    /// laid down, not only when the function set grows.
    pub fn len(&self) -> usize {
        self.units.len()
    }
}
