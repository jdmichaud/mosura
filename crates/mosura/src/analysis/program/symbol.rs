//! `Symbol` / `SymbolTable` — a port of Ghidra's `program/model/symbol/`. Named
//! addresses: function symbols, labels, imported/external names. Accessors mirror
//! `Symbol`: [`Symbol::address`], [`name`](Symbol::name),
//! [`symbol_type`](Symbol::symbol_type), [`is_external`](Symbol::is_external).

use crate::decompile::space::Address;

/// The kind of a symbol (Ghidra `SymbolType`, the subset we model).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SymbolType {
    Label,
    Function,
    /// A defined data symbol (global variable, string, …).
    Data,
}

/// A named address (Ghidra `Symbol`).
#[derive(Clone, Debug)]
pub struct Symbol {
    pub address: Address,
    pub name: String,
    pub symbol_type: SymbolType,
    /// The primary symbol at its address (Ghidra allows several; one is primary).
    pub primary: bool,
    /// An external symbol (an import resolved in the EXTERNAL block / a thunk target).
    pub external: bool,
}

impl Symbol {
    pub fn address(&self) -> Address {
        self.address
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn symbol_type(&self) -> SymbolType {
        self.symbol_type
    }
    pub fn is_external(&self) -> bool {
        self.external
    }
    pub fn is_primary(&self) -> bool {
        self.primary
    }
}

/// The program's symbols (Ghidra `SymbolTable`).
#[derive(Clone, Default, Debug)]
pub struct SymbolTable {
    symbols: Vec<Symbol>,
    /// `(space, offset, name)` dedup set + `(space, offset)` presence set for O(1) `add`
    /// and `has_symbol_at` — a per-add scan/sort is quadratic at thousands of symbols.
    /// Iteration order is imposed by the snapshot.
    seen: std::collections::HashSet<(u32, u64, String)>,
    addrs: std::collections::HashSet<(u32, u64)>,
}

impl SymbolTable {
    pub fn new() -> SymbolTable {
        SymbolTable::default()
    }

    pub fn add(&mut self, sym: Symbol) {
        // Ghidra `createSymbol` is idempotent on (address, name): a same-named symbol
        // already at the address (e.g. `_DYNAMIC` from both `.dynamic` markup and the
        // symbol table) is not duplicated.
        let key = (sym.address.space.0, sym.address.offset, sym.name.clone());
        if !self.seen.insert(key) {
            return;
        }
        self.addrs.insert((sym.address.space.0, sym.address.offset));
        self.symbols.push(sym);
    }

    /// Convenience for the common case of a single primary symbol.
    pub fn add_symbol(&mut self, address: Address, name: &str, symbol_type: SymbolType) {
        self.add(Symbol { address, name: name.to_string(), symbol_type, primary: true, external: false });
    }

    /// Add a symbol with an explicit primary flag (Ghidra's per-symbol `isPrimary`).
    pub fn add_with_primary(&mut self, address: Address, name: &str, symbol_type: SymbolType, primary: bool) {
        self.add(Symbol { address, name: name.to_string(), symbol_type, primary, external: false });
    }

    /// Whether any symbol exists at `addr` (Ghidra `getPrimarySymbol(addr) != null`).
    pub fn has_symbol_at(&self, addr: Address) -> bool {
        self.addrs.contains(&(addr.space.0, addr.offset))
    }

    /// All symbols (unordered; the snapshot sorts).
    pub fn symbols(&self) -> impl Iterator<Item = &Symbol> {
        self.symbols.iter()
    }

    pub fn symbols_at(&self, addr: Address) -> impl Iterator<Item = &Symbol> {
        self.symbols.iter().filter(move |s| s.address == addr)
    }

    /// The primary symbol at `addr`, if any (Ghidra `getPrimarySymbol`).
    pub fn primary_at(&self, addr: Address) -> Option<&Symbol> {
        self.symbols_at(addr).find(|s| s.primary).or_else(|| self.symbols_at(addr).next())
    }

    /// Rename the primary symbol at `addr` to `new_name`, returning its old name (the
    /// demangler's `SetLabelPrimaryCmd` step — the demangled name becomes the primary
    /// symbol). Keeps the `(space, offset, name)` dedup index consistent. The old name is
    /// *not* removed from the table by this call — the caller re-adds it as a non-primary
    /// label (Ghidra retains the original mangled name as a secondary label).
    pub fn rename_primary(&mut self, addr: Address, new_name: &str) -> Option<String> {
        let key = (addr.space.0, addr.offset);
        let idx = self
            .symbols
            .iter()
            .position(|s| (s.address.space.0, s.address.offset) == key && s.primary)
            .or_else(|| self.symbols.iter().position(|s| (s.address.space.0, s.address.offset) == key))?;
        let old = self.symbols[idx].name.clone();
        if old == new_name {
            return Some(old);
        }
        self.seen.remove(&(key.0, key.1, old.clone()));
        self.seen.insert((key.0, key.1, new_name.to_string()));
        self.symbols[idx].name = new_name.to_string();
        Some(old)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::SpaceId;
    const RAM: SpaceId = SpaceId(1);

    #[test]
    fn dedup_and_queryable() {
        let mut t = SymbolTable::new();
        t.add_symbol(Address::new(RAM, 0x1168), "main", SymbolType::Function);
        t.add_symbol(Address::new(RAM, 0x1000), "_init", SymbolType::Function);
        // Iteration is unordered (the snapshot sorts); sort here to assert membership.
        let mut syms: Vec<_> = t.symbols().collect();
        syms.sort_by_key(|s| s.address().offset);
        let names: Vec<_> = syms.iter().map(|s| s.name()).collect();
        assert_eq!(names, vec!["_init", "main"]);
        assert_eq!(t.primary_at(Address::new(RAM, 0x1168)).unwrap().name(), "main");
        assert!(t.primary_at(Address::new(RAM, 0x9999)).is_none());
    }
}
