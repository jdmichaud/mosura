//! The SSA value node — a port of Ghidra's `Varnode` (`varnode.hh`/`varnode.cc`).
//!
//! Ghidra's SSA *is* the Varnode graph: each `Varnode` is one SSA value with at most one
//! defining op ([`def`](Varnode::def)) and a list of using ops ([`descend`](Varnode::descend)).
//! Ghidra uses raw `Varnode*`; we use arena indices ([`VarnodeId`]/[`OpId`]) owned by the
//! [`Funcdata`](super::funcdata::Funcdata) — the same graph, in safe Rust.

use super::op::OpId;
use super::space::Address;

/// A handle to a [`Varnode`] — an index into the `Funcdata` varnode arena.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct VarnodeId(pub u32);

/// Ghidra's `Varnode::varnode_flags` — the boolean attributes, with Ghidra's bit values.
pub mod flags {
    pub const MARK: u32 = 0x01;
    pub const CONSTANT: u32 = 0x02;
    pub const ANNOTATION: u32 = 0x04;
    pub const INPUT: u32 = 0x08;
    pub const WRITTEN: u32 = 0x10;
    pub const INSERT: u32 = 0x20;
    pub const IMPLIED: u32 = 0x40;
    pub const EXPLICIT: u32 = 0x80;
    pub const TYPELOCK: u32 = 0x100;
    pub const NAMELOCK: u32 = 0x200;
    pub const NOLOCALALIAS: u32 = 0x400;
    pub const VOLATILE: u32 = 0x800;
    pub const EXTERNREF: u32 = 0x1000;
    pub const READONLY: u32 = 0x2000;
    pub const PERSIST: u32 = 0x4000;
    pub const ADDRTIED: u32 = 0x8000;
    pub const UNAFFECTED: u32 = 0x10000;
    pub const SPACEBASE: u32 = 0x20000;
    pub const INDIRECTONLY: u32 = 0x40000;
    pub const DIRECTWRITE: u32 = 0x80000;
    pub const ADDRFORCE: u32 = 0x100000;
    pub const MAPPED: u32 = 0x200000;
    pub const INDIRECT_CREATION: u32 = 0x400000;
    pub const RETURN_ADDRESS: u32 = 0x800000;
    pub const COVERDIRTY: u32 = 0x1000000;
    pub const PRECISLO: u32 = 0x2000000;
    pub const PRECISHI: u32 = 0x4000000;
    pub const INDIRECTSTORAGE: u32 = 0x8000000;
    pub const HIDDENRETPARM: u32 = 0x10000000;
    pub const INCIDENTAL_COPY: u32 = 0x20000000;
    pub const AUTOLIVE_HOLD: u32 = 0x40000000;
    pub const PROTO_PARTIAL: u32 = 0x80000000;
}

/// An SSA value. Created via [`Funcdata`](super::funcdata::Funcdata); never constructed
/// directly elsewhere.
#[derive(Clone, Debug)]
pub struct Varnode {
    /// Storage location, or (in the constant space) the literal value.
    pub loc: Address,
    /// Size in bytes.
    pub size: u32,
    /// Boolean attributes — see [`flags`].
    pub flags: u32,
    /// One-up creation index (Ghidra's `create_index`; ties order the varnode bank).
    pub create_index: u32,
    /// The defining op, if [`WRITTEN`](flags::WRITTEN).
    pub def: Option<OpId>,
    /// The ops that read this varnode (Ghidra's descendant list).
    pub descend: Vec<OpId>,
}

impl Varnode {
    pub fn is_constant(&self) -> bool {
        self.flags & flags::CONSTANT != 0
    }
    pub fn is_input(&self) -> bool {
        self.flags & flags::INPUT != 0
    }
    pub fn is_written(&self) -> bool {
        self.flags & flags::WRITTEN != 0
    }
    pub fn is_free(&self) -> bool {
        self.flags & (flags::INSERT | flags::CONSTANT) == 0
    }
    pub fn is_addrtied(&self) -> bool {
        self.flags & flags::ADDRTIED != 0
    }
    pub fn is_spacebase(&self) -> bool {
        self.flags & flags::SPACEBASE != 0
    }
    /// The literal value of a constant varnode.
    pub fn constant_value(&self) -> u64 {
        self.loc.offset
    }
}
