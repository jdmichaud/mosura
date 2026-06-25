//! `Function` / `FunctionManager` — a port of Ghidra's function model
//! (`program/model/listing/Function`, `FunctionManager`). A function is its entry
//! point, name, and body (the [`AddressSet`] of instructions belonging to it).
//! Accessors mirror `Function`: [`Function::entry_point`], [`name`](Function::name),
//! [`body`](Function::body).

use super::address_set::AddressSet;
use crate::decompile::space::Address;

/// A recovered function (Ghidra `Function`).
#[derive(Clone, Debug)]
pub struct Function {
    pub entry: Address,
    pub name: String,
    /// The instructions belonging to this function (empty until A4 lays down code).
    pub body: AddressSet,
}

impl Function {
    pub fn entry_point(&self) -> Address {
        self.entry
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn body(&self) -> &AddressSet {
        &self.body
    }
}

/// The program's functions (Ghidra `FunctionManager`).
#[derive(Clone, Default, Debug)]
pub struct FunctionManager {
    functions: Vec<Function>,
    /// `(space, offset)` entry set for O(1) existence checks — a per-add scan/sort is
    /// quadratic at thousands of functions. Iteration order is imposed by the snapshot.
    entries: std::collections::HashSet<(u32, u64)>,
}

impl FunctionManager {
    pub fn new() -> FunctionManager {
        FunctionManager::default()
    }

    /// Create a function at `entry`, or return false if one already exists there
    /// (Ghidra `createFunction` is idempotent on an existing entry).
    pub fn create_function(&mut self, entry: Address, name: &str, body: AddressSet) -> bool {
        if !self.entries.insert((entry.space.0, entry.offset)) {
            return false;
        }
        self.functions.push(Function { entry, name: name.to_string(), body });
        true
    }

    /// All functions, ordered by entry (Ghidra `getFunctions(true)`).
    pub fn functions(&self) -> impl Iterator<Item = &Function> {
        self.functions.iter()
    }

    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    pub fn function_at(&self, entry: Address) -> Option<&Function> {
        self.functions.iter().find(|f| f.entry == entry)
    }

    /// The function with the highest entry strictly below `addr` in the same space (Ghidra
    /// `SharedReturnAnalysisCmd.getFunctionBefore` via `listing.getFunctions(rangeBefore)`).
    pub fn function_before(&self, addr: Address) -> Option<&Function> {
        self.functions
            .iter()
            .filter(|f| f.entry.space == addr.space && f.entry.offset < addr.offset)
            .max_by_key(|f| f.entry.offset)
    }

    /// The function with the lowest entry strictly above `addr` in the same space (Ghidra
    /// `SharedReturnAnalysisCmd.getFunctionAfter`).
    pub fn function_after(&self, addr: Address) -> Option<&Function> {
        self.functions
            .iter()
            .filter(|f| f.entry.space == addr.space && f.entry.offset > addr.offset)
            .min_by_key(|f| f.entry.offset)
    }

    /// The function whose body contains `addr` (Ghidra `FunctionManager.getFunctionContaining`).
    pub fn function_containing(&self, addr: Address) -> Option<&Function> {
        self.functions.iter().find(|f| f.body.contains(addr))
    }

    /// Set a function's body (Ghidra `Function.setBody`) — the address set of code units
    /// it owns, computed once disassembly has run.
    pub fn set_body(&mut self, entry: Address, body: AddressSet) {
        if let Some(f) = self.functions.iter_mut().find(|f| f.entry == entry) {
            f.body = body;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::SpaceId;
    const RAM: SpaceId = SpaceId(1);

    #[test]
    fn create_is_idempotent() {
        let mut fm = FunctionManager::new();
        assert!(fm.create_function(Address::new(RAM, 0x1168), "main", AddressSet::new()));
        assert!(fm.create_function(Address::new(RAM, 0x1000), "add", AddressSet::new()));
        assert!(!fm.create_function(Address::new(RAM, 0x1168), "dup", AddressSet::new())); // exists
        // Iteration is unordered (the snapshot sorts); sort here to assert membership.
        let mut fns: Vec<_> = fm.functions().collect();
        fns.sort_by_key(|f| f.entry_point().offset);
        let names: Vec<_> = fns.iter().map(|f| f.name()).collect();
        assert_eq!(names, vec!["add", "main"]);
        assert_eq!(fm.function_count(), 2);
    }
}
