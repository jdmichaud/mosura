//! Address spaces — a port of Ghidra's `AddrSpace` / `AddrSpaceManager` (`space.cc`,
//! `translate.cc`). A [`Space`] is registered once per architecture and referenced
//! everywhere by its [`SpaceId`]; an [`Address`] is `(SpaceId, offset)`.

use std::collections::HashMap;

/// The kind of an address space (Ghidra's `spacetype`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SpaceKind {
    /// `IPTR_CONSTANT` — the constant pool; an offset is a literal value.
    Constant,
    /// `IPTR_PROCESSOR` — real memory or registers (`ram`, `register`).
    Processor,
    /// `IPTR_INTERNAL` — the `unique` temporary space.
    Internal,
    /// `IPTR_SPACEBASE` — a register-relative space (the stack).
    Spacebase,
    /// `IPTR_FSPEC` / `IPTR_IOP` / `IPTR_JOIN` — internal annotation spaces.
    Special,
}

/// A handle to a registered [`Space`] — an index into the [`SpaceManager`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SpaceId(pub u32);

/// One registered address space.
#[derive(Clone, Debug)]
pub struct Space {
    pub id: SpaceId,
    pub name: String,
    pub kind: SpaceKind,
    /// Address size in bytes (e.g. 8 for a 64-bit `ram`).
    pub addr_size: u32,
    /// Bytes per addressable unit (1 for byte-addressable spaces).
    pub wordsize: u32,
    /// Number of heritage passes to delay before this space first enters SSA construction
    /// (Ghidra's `AddrSpace::getDelay`). Registers heritage at pass 0; `ram`/`stack` wait a
    /// pass so the stack pointer's reaching def is known first. See [`heritage_delay`].
    pub delay: i32,
    /// Number of passes before dead-code removal is allowed on this space (Ghidra's
    /// `AddrSpace::getDeadcodeDelay`); defaults equal to `delay`.
    pub deadcodedelay: i32,
}

impl Space {
    pub fn is_constant(&self) -> bool {
        self.kind == SpaceKind::Constant
    }

    /// Whether dataflow is traced through this space (Ghidra's `AddrSpace::isHeritaged`).
    /// On by default; the constant and annotation spaces turn it off (`space.cc`).
    pub fn is_heritaged(&self) -> bool {
        matches!(self.kind, SpaceKind::Processor | SpaceKind::Internal | SpaceKind::Spacebase)
    }
}

/// The faithful heritage delay for a space, from Ghidra's space construction. The SLEIGH
/// compiler gives every space `delay = (type == register_space) ? 0 : 1`
/// (`slgh_compile.cc:2708`), and the constant/unique spaces are built with delay 0
/// (`space.cc` `ConstantSpace`/`UniqueSpace`). The stack spacebase is built with
/// `register_delay + 1` (`architecture.cc:565`), which is 1 since registers delay 0.
/// `deadcodedelay` equals `delay` in all these cases.
fn heritage_delay(kind: SpaceKind, name: &str) -> i32 {
    match kind {
        // ConstantSpace/UniqueSpace are constructed with delay 0; annotation spaces too.
        SpaceKind::Constant | SpaceKind::Internal | SpaceKind::Special => 0,
        // register_space → 0, every other processor space (ram) → 1.
        SpaceKind::Processor => i32::from(name != "register"),
        // stack = register_delay + 1 = 1.
        SpaceKind::Spacebase => 1,
    }
}

/// The registry of address spaces for one architecture (Ghidra's `AddrSpaceManager`).
#[derive(Clone, Debug)]
pub struct SpaceManager {
    spaces: Vec<Space>,
    by_name: HashMap<String, SpaceId>,
}

impl SpaceManager {
    /// Construct the standard x86-64 space set (`const`, `register`, `ram`, `unique`,
    /// `stack`). Real specs come from the SLEIGH `.sla`; this is the default for tests
    /// and the initial build-from-lifter path.
    pub fn standard() -> SpaceManager {
        let mut m = SpaceManager { spaces: Vec::new(), by_name: HashMap::new() };
        m.add("const", SpaceKind::Constant, 8, 1);
        m.add("ram", SpaceKind::Processor, 8, 1);
        m.add("register", SpaceKind::Processor, 4, 1);
        m.add("unique", SpaceKind::Internal, 4, 1);
        m.add("stack", SpaceKind::Spacebase, 8, 1);
        m
    }

    /// Register a space, returning its id.
    pub fn add(&mut self, name: &str, kind: SpaceKind, addr_size: u32, wordsize: u32) -> SpaceId {
        if let Some(&id) = self.by_name.get(name) {
            return id;
        }
        let id = SpaceId(self.spaces.len() as u32);
        let delay = heritage_delay(kind, name);
        self.spaces.push(Space {
            id,
            name: name.to_string(),
            kind,
            addr_size,
            wordsize,
            delay,
            deadcodedelay: delay,
        });
        self.by_name.insert(name.to_string(), id);
        id
    }

    pub fn get(&self, id: SpaceId) -> &Space {
        &self.spaces[id.0 as usize]
    }

    /// Number of registered spaces (Ghidra's `AddrSpaceManager::numSpaces`).
    pub fn num_spaces(&self) -> usize {
        self.spaces.len()
    }

    pub fn by_name(&self, name: &str) -> Option<SpaceId> {
        self.by_name.get(name).copied()
    }

    /// The constant space (`const`) — always present.
    pub fn constant(&self) -> SpaceId {
        self.by_name("const").expect("const space registered")
    }
}

/// A storage location or constant value: a space plus an offset (Ghidra's `Address`).
/// A `Constant`-space address holds a literal value in `offset`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Address {
    pub space: SpaceId,
    pub offset: u64,
}

impl Address {
    pub fn new(space: SpaceId, offset: u64) -> Address {
        Address { space, offset }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The standard x86-64 space set carries Ghidra's faithful heritage delays: registers
    /// (and the const/unique spaces) at pass 0, `ram`/`stack` at pass 1, so heritage
    /// processes registers before the stack. `deadcodedelay` mirrors `delay`.
    #[test]
    fn standard_space_delays_match_ghidra() {
        let m = SpaceManager::standard();
        for (name, delay, heritaged) in [
            ("const", 0, false),
            ("register", 0, true),
            ("ram", 1, true),
            ("unique", 0, true),
            ("stack", 1, true),
        ] {
            let s = m.get(m.by_name(name).unwrap());
            assert_eq!(s.delay, delay, "{name} delay");
            assert_eq!(s.deadcodedelay, delay, "{name} deadcodedelay");
            assert_eq!(s.is_heritaged(), heritaged, "{name} heritaged");
        }
    }
}
