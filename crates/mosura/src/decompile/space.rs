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
}

impl Space {
    pub fn is_constant(&self) -> bool {
        self.kind == SpaceKind::Constant
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
        self.spaces.push(Space { id, name: name.to_string(), kind, addr_size, wordsize });
        self.by_name.insert(name.to_string(), id);
        id
    }

    pub fn get(&self, id: SpaceId) -> &Space {
        &self.spaces[id.0 as usize]
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
