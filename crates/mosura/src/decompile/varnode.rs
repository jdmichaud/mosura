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

/// Ghidra's `Varnode::addl_flags` (varnode.hh:118) — the *additional* attributes, kept in a second
/// field because `varnode_flags` (above) already fills all 32 bits. mosura carries only the subset
/// it uses.
pub mod addlflags {
    /// Ghidra `Varnode::activeheritage` (varnode.hh:119): "The varnode is actively being
    /// heritaged." Set by `Heritage::guard` (heritage.cc:1174/1181) on exactly the reads and
    /// writes it normalized to the current range's width, and consumed+cleared by
    /// `Heritage::renameRecurse` (heritage.cc:2496/2527), which skips every varnode without it.
    /// This — not a location-set membership test — is how Ghidra distinguishes "free access this
    /// round" from "already linked in an earlier pass" at the same address.
    pub const ACTIVEHERITAGE: u32 = 0x01;
    /// Ghidra `Varnode::ptrcheck` (varnode.hh:121): "this constant varnode was already checked
    /// as a possible pointer" — `ActionConstantPtr` sets it after the symbol search so each
    /// constant is evaluated at most once across the action's (up to 4) passes.
    pub const PTRCHECK: u32 = 0x08;
    /// Ghidra `Varnode::writemask` (varnode.hh:120): "Should not be considered a write in heritage
    /// calculation." Set by `Heritage::removeRevisitedMarkers` on the narrow varnode whose defining
    /// MULTIEQUAL/INDIRECT was rewritten to a SUBPIECE of a wider re-heritaged range, so the later
    /// candidate/cover scan does not re-collect it as an independent location.
    pub const WRITEMASK: u32 = 0x02;
    /// Ghidra `Varnode::spacebase_placeholder` (varnode.hh:129): "This varnode is inserted
    /// artificially to track a register." It marks the output of the LOAD that
    /// `FuncCallSpecs::createPlaceholder` (fspec.cc:4849) hangs off a CALL as an extra input. The
    /// flag is a TRIGGER, not a property: `RuleLoadVarnode` (ruleaction.cc:4295) clears it the
    /// moment the LOAD resolves to a concrete stack varnode and calls `resolveSpacebaseRelative`,
    /// which is how the decompiler learns the stack-pointer delta at that call site — the thing
    /// `Heritage::guardCalls` needs before it can express a stack range in the CALLEE's frame and
    /// register it as a parameter trial. Bit value matches Ghidra's.
    pub const SPACEBASE_PLACEHOLDER: u32 = 0x400;
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
    /// Additional attributes — see [`addlflags`] (Ghidra's second flag word). Defaults to 0.
    pub addlflags: u32,
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
    /// Ghidra `Varnode::isWriteMask` (varnode.hh): this varnode should not be treated as a write
    /// during heritage (its defining marker was rewritten to a SUBPIECE of a wider range).
    pub fn is_write_mask(&self) -> bool {
        self.addlflags & addlflags::WRITEMASK != 0
    }
    /// Ghidra `Varnode::setWriteMask`.
    pub fn set_write_mask(&mut self) {
        self.addlflags |= addlflags::WRITEMASK;
    }
    /// Ghidra `Varnode::isSpacebasePlaceholder` (varnode.hh:261): is this varnode the artificial
    /// stack-pointer tracker a CALL carries until `RuleLoadVarnode` resolves it?
    pub fn is_spacebase_placeholder(&self) -> bool {
        self.addlflags & addlflags::SPACEBASE_PLACEHOLDER != 0
    }
    /// Ghidra `Varnode::setSpacebasePlaceholder`.
    pub fn set_spacebase_placeholder(&mut self) {
        self.addlflags |= addlflags::SPACEBASE_PLACEHOLDER;
    }
    /// Ghidra `Varnode::clearSpacebasePlaceholder` (varnode.hh) — the trigger fires exactly once.
    pub fn clear_spacebase_placeholder(&mut self) {
        self.addlflags &= !addlflags::SPACEBASE_PLACEHOLDER;
    }
    /// Ghidra `Varnode::isActiveHeritage` (varnode.hh:264): is this varnode currently being traced
    /// by the Heritage algorithm — i.e. did `guard()` normalize it into the range being renamed?
    pub fn is_active_heritage(&self) -> bool {
        self.addlflags & addlflags::ACTIVEHERITAGE != 0
    }
    /// Ghidra `Varnode::setActiveHeritage` (varnode.hh:301).
    pub fn set_active_heritage(&mut self) {
        self.addlflags |= addlflags::ACTIVEHERITAGE;
    }
    /// Ghidra `Varnode::clearActiveHeritage` (varnode.hh:302).
    pub fn clear_active_heritage(&mut self) {
        self.addlflags &= !addlflags::ACTIVEHERITAGE;
    }
    pub fn is_input(&self) -> bool {
        self.flags & flags::INPUT != 0
    }
    /// Ghidra `Varnode::isUnaffected` (varnode.hh): the value is a callee-saved register that flows
    /// through the function untouched. Read by the heritage cover walk (`heritage.cc:2704`), which
    /// keeps such a register even with no reads and no writes.
    pub fn is_unaffected(&self) -> bool {
        self.flags & flags::UNAFFECTED != 0
    }
    pub fn is_written(&self) -> bool {
        self.flags & flags::WRITTEN != 0
    }
    /// Ghidra `Varnode::isFree` (varnode.hh:238): `(flags & (written|input)) == 0` — not linked
    /// into SSA. **A CONSTANT is free** (it is neither written nor input); Ghidra rule guards
    /// like `if (vn->isFree()) return 0` therefore DECLINE constants, and every faithful
    /// translation must too. The previous definition here — `!(INSERT | CONSTANT)` — inverted
    /// that: constants counted as not-free, so `RuleConcatCommute` commuted `PIECE(#0, x & 3)`
    /// into the wide-mask AND Ghidra never forms (the compgoto jump-table failure). INSERT is
    /// set/cleared in lockstep with WRITTEN/INPUT at every mutation site (and `makeFree` clears
    /// them together), so for NON-constants the two definitions agree; the flip changes behavior
    /// exactly at constants, aligning every translated `isFree()` guard with its original.
    /// Sites needing "free and not a constant" spell it `is_free() && !is_constant()`, exactly
    /// as Ghidra spells `isFree() && !isConstant()`.
    pub fn is_free(&self) -> bool {
        self.flags & (flags::WRITTEN | flags::INPUT) == 0
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
    /// Ghidra `Varnode::clearAddrForce` (varnode.hh) — drop the addr-force. Used by
    /// `Heritage::removeRevisitedMarkers` when an INDIRECT marker is rewritten to a SUBPIECE of a
    /// wider re-heritaged range (the replacement wide varnode holds the address instead).
    pub fn clear_addr_force(&mut self) {
        self.flags &= !flags::ADDRFORCE;
    }
    /// Ghidra `Varnode::isDirectWrite` (varnode.hh:247) — this value is (could be) directly affected
    /// by a legitimate function input. Computed by [`super::directwrite::ActionDirectWrite`] and read
    /// by `ActionDeadCode` to decide whether an `addrforce` varnode stays exempt from removal.
    pub fn is_direct_write(&self) -> bool {
        self.flags & flags::DIRECTWRITE != 0
    }
    /// Ghidra `Varnode::setDirectWrite` (varnode.hh:305).
    pub fn set_direct_write(&mut self) {
        self.flags |= flags::DIRECTWRITE;
    }
    /// Ghidra `Varnode::clearDirectWrite` (varnode.hh:306).
    pub fn clear_direct_write(&mut self) {
        self.flags &= !flags::DIRECTWRITE;
    }
    pub fn is_spacebase(&self) -> bool {
        self.flags & flags::SPACEBASE != 0
    }
    /// Ghidra `Varnode::setFlags(Varnode::spacebase)` (funcdata.cc:262, `Funcdata::spacebase`):
    /// mark this value a spacebase (stack-pointer) register. Set on every SSA version of the base
    /// register, not just the input, so the pointer-arithmetic / nonzero-mask / type-inference rules
    /// that key on `is_spacebase()` recognise stack-relative arithmetic.
    /// Ghidra `Varnode::isPtrCheck` (addl flag `ptrcheck`).
    pub fn is_ptr_check(&self) -> bool {
        self.addlflags & addlflags::PTRCHECK != 0
    }
    /// Ghidra `Varnode::setPtrCheck`.
    pub fn set_ptr_check(&mut self) {
        self.addlflags |= addlflags::PTRCHECK;
    }

    pub fn set_spacebase(&mut self) {
        self.flags |= flags::SPACEBASE;
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
    /// Ghidra `Varnode::hasNoLocalAlias` (varnode.hh:262) — no local pointer can affect this value.
    ///
    /// The flag bit exists ([`flags::NOLOCALALIAS`]) but mosura has no *producer* for it: Ghidra
    /// sets it in `ScopeLocal`'s unaliased-symbol marking (`varmap.cc:1375`), a piece
    /// [`super::varnodeprops`] models only by its net effect on `addrtied`/`addrforce` rather than
    /// by storing the attribute. So this reads `false` everywhere today, which is exactly what
    /// Ghidra's own code does with the attribute unset — it is not an approximation of the
    /// predicate, it is the predicate over the attributes mosura currently produces.
    pub fn has_no_local_alias(&self) -> bool {
        self.flags & flags::NOLOCALALIAS != 0
    }
    /// Ghidra `Varnode::contains` (varnode.cc) — how this Varnode's storage contains `op`'s:
    /// `0` fully contained, `1` `op` starts inside but runs past the end, `2` `op` starts at/after
    /// the end, `-1` `op` starts before, `3` incomparable (different space, or constant).
    pub fn contains(&self, op: &Varnode, is_constant_space: bool) -> i32 {
        if self.loc.space != op.loc.space || is_constant_space {
            return 3;
        }
        let (a, b) = (self.loc.offset, op.loc.offset);
        if b < a {
            return -1;
        }
        if b >= a + self.size as u64 {
            return 2;
        }
        if b + op.size as u64 > a + self.size as u64 {
            return 1;
        }
        0
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
    /// Ghidra `Varnode::updateType(ct, true, true)`'s lock half: the committed type survives
    /// inference (`getLocalType` returns it unchanged, and `update_type` refuses overwrites).
    pub fn set_typelock(&mut self) {
        self.flags |= flags::TYPELOCK;
    }
    /// Ghidra `Varnode::setPrecisLo` — set by `RuleDoubleIn`/`RuleDoubleOut`'s `attemptMarking`
    /// (double.cc), which is what makes the halves of a double-precision value recognizable to the
    /// rest of the double-precision machinery (including `RuleDoubleStore`).
    pub fn set_precis_lo(&mut self) {
        self.flags |= flags::PRECISLO;
    }
    /// Ghidra `Varnode::setPrecisHi`.
    pub fn set_precis_hi(&mut self) {
        self.flags |= flags::PRECISHI;
    }
    /// Ghidra `Varnode::isProtoPartial` (varnode.hh:315): the value is a piece of a larger
    /// structured whole that `RulePieceStructure` has carved out.
    pub fn is_proto_partial(&self) -> bool {
        self.flags & flags::PROTO_PARTIAL != 0
    }
    /// Ghidra `Varnode::setProtoPartial`.
    pub fn set_proto_partial(&mut self) {
        self.flags |= flags::PROTO_PARTIAL;
    }
    /// Ghidra `Varnode::isMapped` (varnode.hh:293): the storage has a symbol mapped over it.
    pub fn is_mapped(&self) -> bool {
        self.flags & flags::MAPPED != 0
    }
    /// Ghidra `Varnode::isNameLock` (varnode.hh:299) — the name attached to this storage is fixed,
    /// so a transform must not redefine or duplicate into it.
    pub fn is_namelock(&self) -> bool {
        self.flags & flags::NAMELOCK != 0
    }
    /// Ghidra `Varnode::setImplied` — this value is folded into the expression that uses it.
    pub fn set_implied(&mut self) {
        self.flags |= flags::IMPLIED;
        self.flags &= !flags::EXPLICIT;
    }
    /// Ghidra `Varnode::setExplicit` — this value is a named variable, not folded inline.
    pub fn set_explicit(&mut self) {
        self.flags |= flags::EXPLICIT;
        self.flags &= !flags::IMPLIED;
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
