//! Symbol table — a port of Ghidra's `Scope`/`Symbol`/`SymbolEntry` (`database.hh`/`database.cc`),
//! the layer that maps storage locations to named symbols with data-types and the varnode-like
//! `mapped`/`addrtied`/`typelock` properties.
//!
//! mosura's earlier passes skipped this layer entirely; it is the foundation for prototype/symbol
//! types ([`super::infertypes`] currently approximates it), the heritage `addrtied` flag (which
//! drives the call/store INDIRECT guards), and parameter recovery. This is the core data model:
//! a [`Scope`] owns [`Symbol`]s, each mapped to storage by one or more [`SymbolEntry`]. Ghidra
//! stores the entries in an interval (range) map keyed by space+offset; the semantics modelled
//! here — "find the symbol whose storage contains this address range" — are the same, with a
//! sorted `Vec` standing in for the rangemap.

use super::space::{Address, SpaceId};
use super::types::Datatype;
use super::varnode::flags;

/// A symbol's special category (Ghidra `Symbol::category`).
pub mod category {
    pub const NO_CATEGORY: i32 = -1;
    pub const FUNCTION_PARAMETER: i32 = 0;
    pub const EQUATE: i32 = 1;
}

/// Ghidra `Symbol`: a named entity with a data-type and varnode-like flags.
#[derive(Clone, Debug)]
pub struct Symbol {
    pub name: String,
    pub datatype: Datatype,
    /// `typelock`/`namelock`/`readonly`/`externref` etc. (`varnode::flags` bit values), the
    /// subset Ghidra keeps on the symbol; `addrtied`/`mapped`/`persist` are derived from the scope.
    pub flags: u32,
    pub category: i32,
    pub catindex: u32,
}

/// Ghidra `SymbolEntry`: maps a storage range to a (piece of a) [`Symbol`].
#[derive(Clone, Debug)]
pub struct SymbolEntry {
    pub addr: Address,
    pub size: u32,
    /// Byte offset into the symbol that this entry covers.
    pub offset: u32,
    /// Index of the mapped symbol in [`Scope::symbols`].
    pub symbol: usize,
    /// Varnode flags specific to this storage location (Ghidra `SymbolEntry::extraflags`).
    pub extraflags: u32,
}

impl SymbolEntry {
    /// Ghidra `SymbolEntry::getAllFlags`: the symbol's flags combined with this entry's extras.
    fn all_flags(&self, sym: &Symbol) -> u32 {
        sym.flags | self.extraflags
    }
}

/// Ghidra `Scope` (the local/function scope, `ScopeLocal`): the function's symbol table.
#[derive(Default)]
pub struct Scope {
    symbols: Vec<Symbol>,
    /// Storage→symbol entries (Ghidra's interval map; a `Vec` scanned for containment here).
    entries: Vec<SymbolEntry>,
}

impl Scope {
    pub fn new() -> Scope {
        Scope::default()
    }

    pub fn symbol(&self, idx: usize) -> &Symbol {
        &self.symbols[idx]
    }

    /// Add a symbol mapped to a single contiguous storage location (Ghidra `Scope::addSymbol`
    /// for a whole-symbol entry). Returns the symbol index.
    pub fn add_symbol(&mut self, name: impl Into<String>, datatype: Datatype, addr: Address, size: u32) -> usize {
        self.add_symbol_cat(name, datatype, addr, size, category::NO_CATEGORY, 0)
    }

    /// Add a symbol with a category (e.g. a parameter) and per-entry flags.
    pub fn add_symbol_cat(
        &mut self,
        name: impl Into<String>,
        datatype: Datatype,
        addr: Address,
        size: u32,
        category: i32,
        extraflags: u32,
    ) -> usize {
        let idx = self.symbols.len();
        self.symbols.push(Symbol { name: name.into(), datatype, flags: 0, category, catindex: 0 });
        self.entries.push(SymbolEntry { addr, size, offset: 0, symbol: idx, extraflags });
        idx
    }

    /// Ghidra `Scope::findContainer`: the symbol entry whose storage contains `[addr, addr+size)`,
    /// if any.
    pub fn find_container(&self, addr: Address, size: u32) -> Option<&SymbolEntry> {
        self.entries.iter().find(|e| {
            e.addr.space == addr.space
                && e.addr.offset <= addr.offset
                && addr.offset + size as u64 <= e.addr.offset + e.size as u64
        })
    }

    /// Ghidra `Scope::queryProperties`: the varnode flags for a storage location. A mapped symbol
    /// contributes its flags; an unmapped *memory* location (stack/global) is still `mapped |
    /// addrtied` (and `persist` for globals), which is what makes the heritage guards fire.
    /// `memory` says whether the address's space is memory-like (stack/ram), `global` whether it
    /// is a global (ram) location.
    pub fn query_properties(&self, addr: Address, size: u32, memory: bool, global: bool) -> u32 {
        if let Some(entry) = self.find_container(addr, size) {
            return entry.all_flags(&self.symbols[entry.symbol]);
        }
        if memory {
            let mut fl = flags::MAPPED | flags::ADDRTIED;
            if global {
                fl |= flags::PERSIST;
            }
            fl
        } else {
            0
        }
    }

    /// The data-type recovered for a storage location, if a symbol maps it exactly.
    pub fn type_of(&self, addr: Address, size: u32) -> Option<Datatype> {
        self.find_container(addr, size).and_then(|e| {
            (e.offset == 0 && e.size == size).then(|| self.symbols[e.symbol].datatype.clone())
        })
    }

    /// The name of the symbol mapping a storage location, if any.
    pub fn name_at(&self, addr: Address, size: u32) -> Option<&str> {
        self.find_container(addr, size).map(|e| self.symbols[e.symbol].name.as_str())
    }
}

/// Whether `space` is a memory-like space (stack or ram) — the spaces whose unmapped locations are
/// `addrtied` (Ghidra's spacebase/ram), as opposed to register/unique/const.
pub fn is_memory_space(spaces: &super::space::SpaceManager, space: SpaceId) -> bool {
    [spaces.by_name("stack"), spaces.by_name("ram")].into_iter().flatten().any(|s| s == space)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::{Address, SpaceManager};

    #[test]
    fn maps_storage_to_symbol_and_flags() {
        let spaces = SpaceManager::standard();
        let stack = spaces.by_name("stack").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut scope = Scope::new();
        let p = scope.add_symbol_cat(
            "param_1",
            Datatype::Unknown(4),
            Address::new(reg, 0x38),
            4,
            category::FUNCTION_PARAMETER,
            0,
        );
        assert_eq!(scope.symbol(p).category, category::FUNCTION_PARAMETER);

        // exact storage → that symbol's type/name
        assert_eq!(scope.type_of(Address::new(reg, 0x38), 4), Some(Datatype::Unknown(4)));
        assert_eq!(scope.name_at(Address::new(reg, 0x38), 4), Some("param_1"));
        // a sub-range is still contained
        assert!(scope.find_container(Address::new(reg, 0x38), 2).is_some());
        // a different location is not mapped
        assert!(scope.find_container(Address::new(reg, 0x30), 4).is_none());

        // an unmapped *stack* location is mapped|addrtied even without a symbol
        let fl = scope.query_properties(Address::new(stack, 0xfffffffffffffff0), 8, true, false);
        assert_ne!(fl & flags::ADDRTIED, 0);
        assert_ne!(fl & flags::MAPPED, 0);
        // an unmapped register location is not addrtied
        assert_eq!(scope.query_properties(Address::new(reg, 0x100), 8, false, false), 0);
    }
}
