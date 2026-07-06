//! The SSA value node — a port of Ghidra's `Varnode` (`varnode.hh`/`varnode.cc`).
//!
//! Ghidra's SSA *is* the Varnode graph: each `Varnode` is one SSA value with at most one
//! defining op ([`def`](Varnode::def)) and a list of using ops ([`descend`](Varnode::descend)).
//! Ghidra uses raw `Varnode*`; we use arena indices ([`VarnodeId`]/[`OpId`]) owned by the
//! [`Funcdata`](super::funcdata::Funcdata) — the same graph, in safe Rust.

use super::op::OpId;
use super::space::Address;
use super::types::Datatype;

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
    /// Ghidra's `Varnode::type` — the data-type this value carries. `None` until type inference
    /// commits it (Ghidra leaves it at the factory's `undefined` until then). The cast subsystem
    /// ([`super::actionsetcasts`]) reads and updates this directly, so casts run off persistent
    /// per-varnode types rather than a recomputed-at-print table.
    pub ty: Option<Datatype>,
    /// Ghidra's `Varnode::nzm` — the mask of bits that may be non-zero (every cleared bit is
    /// provably 0). Computed by [`super::nzmask::calc_nzmask`]; defaults to the full mask (the
    /// conservative over-approximation) until then.
    pub nzm: u64,
    /// Ghidra's `Varnode::consume` — the mask of bits actually *used* downstream (the backward
    /// dual of [`nzm`](Self::nzm)). Computed by [`super::consume::calc_consume`]; defaults to 0
    /// (Ghidra clears consume at the start of every `ActionDeadCode`). Read by the SubVariableFlow
    /// driving rules to prove a wide value is only used through a narrow logical sub-value.
    pub consume: u64,
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
    /// Ghidra `Varnode::isHeritageKnown` — the value sits in the SSA tree (`insert`), or is a
    /// constant/annotation. Used by `RuleMultiCollapse` to refuse a MULTIEQUAL whose inputs are
    /// not yet heritaged.
    pub fn is_heritage_known(&self) -> bool {
        self.flags & (flags::INSERT | flags::CONSTANT | flags::ANNOTATION) != 0
    }
    /// Ghidra `Varnode::isMark` / the `mark` traversal bit.
    pub fn is_mark(&self) -> bool {
        self.flags & flags::MARK != 0
    }
    pub fn set_mark(&mut self) {
        self.flags |= flags::MARK;
    }
    pub fn clear_mark(&mut self) {
        self.flags &= !flags::MARK;
    }
    /// Ghidra `Varnode::isAnnotation` — a code-address annotation (e.g. a CALLOTHER selector),
    /// never a real value, so it can never be a switch variable.
    pub fn is_annotation(&self) -> bool {
        self.flags & flags::ANNOTATION != 0
    }
    /// Ghidra `Varnode::isReadOnly` — the value lives in a read-only region of the load image.
    pub fn is_readonly(&self) -> bool {
        self.flags & flags::READONLY != 0
    }
    pub fn is_addrtied(&self) -> bool {
        self.flags & flags::ADDRTIED != 0
    }
    /// Ghidra `Varnode::isAddrForce` — this value is forced into a particular storage location.
    pub fn is_addr_force(&self) -> bool {
        self.flags & flags::ADDRFORCE != 0
    }
    /// Ghidra `Varnode::isAutoLive` — exempt from dead-code removal because the value is forced
    /// into its storage (`addrforce`) or a temporary hold is in place (`autolive_hold`).
    pub fn is_auto_live(&self) -> bool {
        self.flags & (flags::ADDRFORCE | flags::AUTOLIVE_HOLD) != 0
    }
    /// Ghidra `Varnode::setAddrForce` — mark this value as forcing into its storage location.
    pub fn set_addr_force(&mut self) {
        self.flags |= flags::ADDRFORCE;
    }
    pub fn is_spacebase(&self) -> bool {
        self.flags & flags::SPACEBASE != 0
    }
    /// Ghidra `Varnode::isPrecisLo` / `isPrecisHi` — this value is the low / high half of a
    /// double-precision (piece-tracked) quantity. Guards rules (e.g. RuleSubCommute) that must not
    /// commute across a precision boundary.
    pub fn is_precis_lo(&self) -> bool {
        self.flags & flags::PRECISLO != 0
    }
    pub fn is_precis_hi(&self) -> bool {
        self.flags & flags::PRECISHI != 0
    }
    /// Ghidra `Varnode::isPersist` — the value is persistent (a global/`persist` location visible
    /// beyond this function). Used by SubVariableFlow's sign-extension restriction path.
    pub fn is_persist(&self) -> bool {
        self.flags & flags::PERSIST != 0
    }
    /// Ghidra `Varnode::isIndirectCreation` — this value is created out of nothing by an INDIRECT
    /// modeling a call's `killedbycall` clobber (it has no realistic ancestor).
    pub fn is_indirect_creation(&self) -> bool {
        self.flags & flags::INDIRECT_CREATION != 0
    }
    /// Ghidra `Varnode::setIndirectCreation` — mark this INDIRECT output a created (clobbered) value.
    pub fn set_indirect_creation(&mut self) {
        self.flags |= flags::INDIRECT_CREATION;
    }
    /// Ghidra `Varnode::isReturnAddress` — this INDIRECT output carries the call's return address.
    pub fn is_return_address(&self) -> bool {
        self.flags & flags::RETURN_ADDRESS != 0
    }
    /// Ghidra `Varnode::setReturnAddress`.
    pub fn set_return_address(&mut self) {
        self.flags |= flags::RETURN_ADDRESS;
    }
    /// The literal value of a constant varnode.
    pub fn constant_value(&self) -> u64 {
        self.loc.offset
    }
    /// Ghidra `Varnode::getNZMask` — the mask of bits that may be non-zero (see [`Varnode::nzm`]).
    pub fn get_nzmask(&self) -> u64 {
        self.nzm
    }
    /// Ghidra `Varnode::getConsume` — the mask of bits used downstream (see [`Varnode::consume`]).
    pub fn get_consume(&self) -> u64 {
        self.consume
    }
    pub fn is_implied(&self) -> bool {
        self.flags & flags::IMPLIED != 0
    }
    pub fn is_explicit(&self) -> bool {
        self.flags & flags::EXPLICIT != 0
    }
    pub fn is_typelock(&self) -> bool {
        self.flags & flags::TYPELOCK != 0
    }
    /// Ghidra `Varnode::setImplied` — this value is folded into the expression that uses it.
    pub fn set_implied(&mut self) {
        self.flags |= flags::IMPLIED;
        self.flags &= !flags::EXPLICIT;
    }
    /// Ghidra `Varnode::getType` — the committed data-type, or `undefined<size>` if none set yet.
    pub fn get_type(&self) -> Datatype {
        self.ty.clone().unwrap_or_else(|| Datatype::default_for(self.size))
    }
    /// Ghidra `Varnode::updateType(ct)`: install `ct` unless equal or the varnode is type-locked.
    /// Returns whether the type changed.
    pub fn update_type(&mut self, ct: Datatype) -> bool {
        if self.ty.as_ref() == Some(&ct) || self.is_typelock() {
            return false;
        }
        self.ty = Some(ct);
        true
    }
}
