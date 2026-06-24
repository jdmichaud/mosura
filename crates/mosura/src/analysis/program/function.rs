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
}

impl FunctionManager {
    pub fn new() -> FunctionManager {
        FunctionManager { functions: Vec::new() }
    }

    /// Create a function at `entry`, or return false if one already exists there
    /// (Ghidra `createFunction` is idempotent on an existing entry).
    pub fn create_function(&mut self, entry: Address, name: &str, body: AddressSet) -> bool {
        if self.function_at(entry).is_some() {
            return false;
        }
        self.functions.push(Function { entry, name: name.to_string(), body });
        self.functions.sort_by_key(|f| (f.entry.space.0, f.entry.offset));
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::SpaceId;
    const RAM: SpaceId = SpaceId(1);

    #[test]
    fn create_is_idempotent_and_sorted() {
        let mut fm = FunctionManager::new();
        assert!(fm.create_function(Address::new(RAM, 0x1168), "main", AddressSet::new()));
        assert!(fm.create_function(Address::new(RAM, 0x1000), "add", AddressSet::new()));
        assert!(!fm.create_function(Address::new(RAM, 0x1168), "dup", AddressSet::new())); // exists
        let names: Vec<_> = fm.functions().map(|f| f.name()).collect();
        assert_eq!(names, vec!["add", "main"]);
        assert_eq!(fm.function_count(), 2);
    }
}
