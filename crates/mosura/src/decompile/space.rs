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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SpaceId(pub u32);

/// One registered address space.
#[derive(Clone, Debug)]
pub struct Space {
    pub id: SpaceId,
    pub name: String,
    pub kind: SpaceKind,
    /// Address size in bytes (e.g. 8 for a 64-bit `ram`).
    pub addr_size: u32,
    /// Ghidra `AddrSpace::isBigEndian` (space.hh:145) — whether values in this space are
    /// stored most-significant byte first. Per SPACE, not per program: the SLEIGH spec gives
    /// each space its own `bigendian` attribute defaulting to the processor's
    /// ([`crate::sleigh::engine::Spec`] mirrors this), and Ghidra's decompiler branches on it
    /// in 132 places — PIECE operand order, SUBPIECE byte offsets, lane indexing. Set by the
    /// spec-driven builder; `false` on a hand-built manager, matching the x86 tests.
    pub big_endian: bool,
    /// Bytes per addressable unit (1 for byte-addressable spaces).
    pub wordsize: u32,
    /// Number of heritage passes to delay before this space first enters SSA construction
    /// (Ghidra's `AddrSpace::getDelay`). Registers heritage at pass 0; `ram`/`stack` wait a
    /// pass so the stack pointer's reaching def is known first. See [`heritage_delay`].
    pub delay: i32,
    /// Number of passes before dead-code removal is allowed on this space (Ghidra's
    /// `AddrSpace::getDeadcodeDelay`); defaults equal to `delay`.
    pub deadcodedelay: i32,
    /// The base register(s) that make this a virtual `Spacebase` space (Ghidra's
    /// `AddrSpace::numSpacebase`/`getSpacebase`, whose records are `VarnodeData`). For the x86-64
    /// `stack` space this is the single stack-pointer register RSP `(register:0x20, 8)`. Empty for
    /// every non-virtual space. Read by [`SpaceManager::space_by_spacebase`] (Ghidra
    /// `getSpaceBySpacebase`) and by `Funcdata::spacebase` (`ActionSpacebase`) to mark the input
    /// stack pointer `is_spacebase()`.
    pub spacebase: Vec<(Address, u32)>,
    /// For a `Spacebase` (stack) space, the physical space it is a placeholder into (Ghidra
    /// `SpacebaseSpace::getContain`) — `ram` for the x86-64 stack. `None` for every non-virtual
    /// space. Read by the spacebase-register branch of `RuleLoadVarnode::correctSpacebase` to
    /// reject a LOAD/STORE whose data space is not this spacebase's container.
    pub contain: Option<SpaceId>,
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

    /// Ghidra `AddrSpace::highest` (`space.hh:100`, computed in the constructor as
    /// `calcMask(addressSize)`, then scaled to bytes when `wordsize > 1`): the largest byte offset
    /// this space can hold.
    pub fn highest(&self) -> u64 {
        let mask =
            if self.addr_size >= 8 { u64::MAX } else { (1u64 << (self.addr_size * 8)) - 1 };
        if self.wordsize > 1 {
            mask * self.wordsize as u64 + (self.wordsize as u64 - 1)
        } else {
            mask
        }
    }

    /// Ghidra `AddrSpace::wrapOffset` (`space.hh:383`): fold `off` into this space's offset range.
    /// This is how a stack offset stays meaningful after the signed subtraction that translates it
    /// between the caller's and the callee's frame — on a 32-bit space `ESP - 0x10` must wrap to a
    /// 32-bit offset, not sit as a 64-bit near-`u64::MAX` value that matches no stack range.
    pub fn wrap_offset(&self, off: u64) -> u64 {
        let highest = self.highest();
        if off <= highest {
            return off;
        }
        // `highest + 1` is the modulus. It overflows to 0 exactly when the space spans the whole
        // 64-bit range, and then the comparison above has already returned — Ghidra relies on the
        // same thing, but in Rust the unreachable `% 0` would still be a panic, so it is explicit.
        let Some(m) = (highest as i64).checked_add(1) else { return off };
        if m == 0 {
            return off;
        }
        let mut res = (off as i64) % m; // remainder is signed, as in Ghidra
        if res < 0 {
            res += m;
        }
        res as u64
    }
}

/// Ghidra `Range` (`address.hh:181`): a contiguous, inclusive `[first,last]` byte range within one
/// address space. Ordered by `(space, first, last)`, which is the ordering
/// [`RangeList`]'s insert/remove/lookup all rely on.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Range {
    pub spc: SpaceId,
    pub first: u64,
    pub last: u64,
}

/// Ghidra `RangeList` (`address.cc:383/412/468`): a set of address ranges kept as a DISJOINT,
/// non-adjacent cover. Ghidra holds it in a `std::set<Range>`; mosura keeps the same ordering in a
/// sorted `Vec`, so `upper_bound` is a `partition_point` and the algorithms translate line for line.
///
/// It exists here for the prototype model's `<localrange>`/`<paramrange>`
/// ([`super::fspec::ProtoModel`]), which decide which stack offsets `ScopeLocal` may map at all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RangeList {
    tree: Vec<Range>,
}

impl RangeList {
    pub fn new() -> RangeList {
        RangeList { tree: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Range> {
        self.tree.iter()
    }

    /// `tree.upper_bound(Range(spc,off,off))` — the index of the first range ordering strictly after
    /// the probe. Ghidra probes with `last == first == off`, so a range starting at `off` with a
    /// larger `last` orders AFTER the probe and is not skipped.
    /// Ghidra `std::set<Range>::upper_bound(Range(spc,off,off))` under `Range::operator<`
    /// (address.hh): ranges order by `(space, first)` ONLY — `last` never takes part. The derived
    /// `Ord` on [`Range`] (which also compares `last`) placed a probe `(spc, off, off)` BEFORE a
    /// range starting at exactly `off`, so `in_range` denied an address sitting on a range's first
    /// byte (`[0x8, 0x1fb]` did not contain `0x8`: the x86-64 parameter window's first slot).
    fn upper_bound(&self, spc: SpaceId, off: u64) -> usize {
        self.tree.partition_point(|r| (r.spc, r.first) <= (spc, off))
    }

    /// Ghidra `RangeList::insertRange` (address.cc:383): add `[first,last]`, absorbing every range it
    /// touches so the cover stays disjoint.
    pub fn insert_range(&mut self, spc: SpaceId, first: u64, last: u64) {
        let mut first = first;
        let mut last = last;
        let mut iter1 = self.upper_bound(spc, first);
        // Set iter1 to the first range with `range.last >= first` — either the current one or the
        // one before it.
        if iter1 != 0 {
            iter1 -= 1;
            if self.tree[iter1].spc != spc || self.tree[iter1].last < first {
                iter1 += 1;
            }
        }
        let iter2 = self.upper_bound(spc, last);
        for r in &self.tree[iter1..iter2] {
            first = first.min(r.first);
            last = last.max(r.last);
        }
        self.tree.drain(iter1..iter2);
        let ins = Range { spc, first, last };
        let at = self.tree.partition_point(|r| *r < ins);
        self.tree.insert(at, ins);
    }

    /// Ghidra `RangeList::removeRange` (address.cc:412): eliminate `[first,last]`, narrowing or
    /// splitting the ranges it overlaps so the cover stays disjoint.
    pub fn remove_range(&mut self, spc: SpaceId, first: u64, last: u64) {
        if self.tree.is_empty() {
            return;
        }
        let mut iter1 = self.upper_bound(spc, first);
        if iter1 != 0 {
            iter1 -= 1;
            if self.tree[iter1].spc != spc || self.tree[iter1].last < first {
                iter1 += 1;
            }
        }
        let iter2 = self.upper_bound(spc, last);
        let mut replacement = Vec::new();
        for r in &self.tree[iter1..iter2] {
            if r.first < first {
                replacement.push(Range { spc, first: r.first, last: first - 1 });
            }
            if r.last > last {
                replacement.push(Range { spc, first: last + 1, last: r.last });
            }
        }
        self.tree.splice(iter1..iter2, replacement);
        self.tree.sort_unstable();
    }

    /// Ghidra `RangeList::inRange` (address.cc:468): is `[addr, addr+size)` fully contained in a
    /// SINGLE range of this list? An empty list contains nothing.
    pub fn in_range(&self, addr: Address, size: u32) -> bool {
        if self.tree.is_empty() {
            return false;
        }
        let iter = self.upper_bound(addr.space, addr.offset);
        if iter == 0 {
            return false;
        }
        let r = self.tree[iter - 1];
        if r.spc != addr.space {
            return false;
        }
        r.last >= addr.offset.wrapping_add(size as u64).wrapping_sub(1)
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
        let register = m.add("register", SpaceKind::Processor, 4, 1);
        m.add("unique", SpaceKind::Internal, 4, 1);
        let stack = m.add("stack", SpaceKind::Spacebase, 8, 1);
        // The DEFAULT spacebase register for the `stack` space: x86-64's RSP `(register:0x20, 8)`.
        // Ghidra reads this from the compiler spec's `<stackpointer>`, and so does mosura whenever a
        // spec is available — [`Self::set_stack_pointer`] replaces this default from
        // `analysis::cspec::default_stack_pointer`. It stays here as the fallback for a hand-built
        // `SpaceManager` with no spec. This registration is what `ActionSpacebase`
        // (`Funcdata::spacebase`) looks up to mark the input stack pointer `is_spacebase()`, and
        // hence what lets `RuleLoadVarnode`/`RuleStoreVarnode` turn a stack-relative access into a
        // `stack`-space Varnode at all.
        m.set_spacebase(stack, Address::new(register, 0x20), 8);
        // The `stack` spacebase is a placeholder into `ram` (Ghidra `SpacebaseSpace` `contain`),
        // so `correctSpacebase` accepts a stack-relative LOAD/STORE only off the `ram` data space.
        let ram = m.by_name("ram").expect("standard ram space registered");
        m.set_contain(stack, ram);
        m
    }

    /// Register a spacebase (base pointer) register for a virtual space (Ghidra's per-space
    /// `spacebaselist`, populated from the compiler spec). `reg`/`size` describe the register.
    /// Install a delayed dead-code pass for a space (Ghidra's `Override::deadcodedelay` read back
    /// through `AddrSpace::getDeadcodeDelay`).
    pub fn set_deadcode_delay(&mut self, space: SpaceId, delay: i32) {
        self.spaces[space.0 as usize].deadcodedelay = delay;
    }

    pub fn set_spacebase(&mut self, space: SpaceId, reg: Address, size: u32) {
        self.spaces[space.0 as usize].spacebase.push((reg, size));
    }

    /// Replace the `stack` space's spacebase register with the one the compiler spec declares
    /// (`<stackpointer>`), as Ghidra does when it builds the address spaces for a target.
    ///
    /// Without this the default x86-64 `RSP=(register:0x20, 8)` is used on every target. On
    /// `x86:LE:32` the stack pointer is ESP at `0x10` (Ghidra `ia.sinc`'s `@else` register file), so
    /// the default matches no register — `ActionSpacebase` marks nothing, and no stack-relative
    /// access is ever turned into a `stack` Varnode. The failure is silent: not a wrong frame, no
    /// frame at all.
    /// The space's ADDRESS SIZE is set from the same register, because Ghidra creates the space from
    /// it: `Architecture::decodeStackPointer` takes `truncSize = point.size` (the stack-pointer
    /// register's size, architecture.cc:1008) and passes it to `addSpacebase` (:1013), which is the
    /// `sz` argument of `SpacebaseSpace(m,t,nm,ind,sz,base,dl,isFormal)` (translate.hh:181) — the
    /// space's `addressSize`. Leaving it at the x86-64 default 8 on `x86:LE:32` makes every
    /// address-size-derived quantity silently wrong on a 32-bit target: `sign_extend(off,
    /// addrSize*8-1)` (varmap.cc:905) is then the identity, so a frame offset keeps its wrapped
    /// `0xffffffdc` form instead of `-0x24` and the whole `ScopeLocal` cover mis-sorts;
    /// `AddrSpace::wrapOffset` never wraps; and `normalizeWriteSize`'s SUBPIECE offset constants
    /// (heritage.cc:444, `newConstant(addr.getAddrSize(),…)`) come out 8 bytes wide.
    /// Set the `ram` (default data) space's address size from the SLEIGH spec, as Ghidra reads
    /// `getDefaultDataSpace()->getAddrSize()`.
    ///
    /// [`SpaceManager::standard`] seeds `ram` at **8**, which is right for x86-64 and silently wrong
    /// for every 32-bit target. The LOADERS already get this right — `loader/le.rs` registers ram at
    /// 4, `com.rs` at 2, `pe.rs` from the header — but the decompile path builds a FRESH
    /// `SpaceManager::standard()` and discarded that, so nothing downstream ever saw the real size.
    /// This is the third instance of the hardcoded-x86-64 class, after the `<stackpointer>` (RSP 0x20
    /// vs ESP 0x10) and the hardcoded return storage, and it has the same signature: correct by
    /// coincidence on an all-x86-64 corpus, wrong on x86-32, and invisible to that corpus.
    ///
    /// It is not cosmetic. `Space::highest` masks every offset to `addr_size`, `LaneDivide`'s default
    /// lane width branches on `addr_size != 4`, and `ScopeInternal::buildVariableName`'s field width
    /// is `2*addr.getAddrSize()` — so the name of every global on a 32-bit target depends on it.
    /// Set every space's endianness from the processor spec (Ghidra: each `AddrSpace` carries
    /// the `bigendian` attribute of its `<space>` element, defaulting to the language's). The
    /// builder calls this once; `const`/`unique` follow the processor like every other space,
    /// which is what Ghidra does (`AddrSpaceManager` builds them with the same flag).
    pub fn set_big_endian(&mut self, big: bool) {
        for s in &mut self.spaces {
            s.big_endian = big;
        }
    }

    /// Ghidra `Address::justifiedContain` (address.cc:131) — the ENDIAN-AWARE offset of the
    /// range `(op2, sz2)` inside the range `(addr, sz)`, or `None` when it is not properly
    /// contained. Offset 0 means the two ranges' LEAST-significant bytes coincide, which on a
    /// big-endian space is the far end of the container, hence the flip.
    ///
    /// `forceleft` forces the little-endian reading regardless of endianness — Ghidra's own
    /// escape hatch, used where the container is addressed left-to-right by construction
    /// (`ParamEntry`'s `force_left_justify` flag).
    ///
    /// This is the primitive the hand-rolled `offset - base` arithmetic scattered through the
    /// port was standing in for; every such site is little-endian-only until it calls this.
    pub fn justified_contain(
        &self,
        addr: Address,
        sz: u32,
        op2: Address,
        sz2: u32,
        forceleft: bool,
    ) -> Option<u64> {
        if addr.space != op2.space || sz == 0 || sz2 == 0 {
            return None;
        }
        if op2.offset < addr.offset {
            return None;
        }
        let off1 = addr.offset + (sz as u64 - 1);
        let off2 = op2.offset + (sz2 as u64 - 1);
        if off2 > off1 {
            return None;
        }
        if self.is_big_endian(addr.space) && !forceleft {
            return Some(off1 - off2);
        }
        Some(op2.offset - addr.offset)
    }

    /// Ghidra `AddrSpace::isBigEndian` for a space id.
    pub fn is_big_endian(&self, id: SpaceId) -> bool {
        self.spaces[id.0 as usize].big_endian
    }

    pub fn set_ram_addr_size(&mut self, size: u32) {
        let Some(ram) = self.by_name("ram") else { return };
        if size > 0 {
            self.spaces[ram.0 as usize].addr_size = size;
        }
    }

    pub fn set_stack_pointer(&mut self, reg: Address, size: u32) {
        let Some(stack) = self.by_name("stack") else { return };
        self.spaces[stack.0 as usize].spacebase.clear();
        self.spaces[stack.0 as usize].addr_size = size;
        self.set_spacebase(stack, reg, size);
    }

    /// Record the physical space a virtual `Spacebase` space is a placeholder into (Ghidra
    /// `SpacebaseSpace` `contain`, space.cc). For x86-64 the `stack` space is contained in `ram`.
    pub fn set_contain(&mut self, space: SpaceId, contain: SpaceId) {
        self.spaces[space.0 as usize].contain = Some(contain);
    }

    /// Ghidra `Architecture::getSpaceBySpacebase` (architecture.cc:264): the address space whose
    /// spacebase register matches `(loc, size)` — e.g. passing RSP's location returns the `stack`
    /// space. Returns `None` if no space claims the register (Ghidra throws `LowlevelError`). Used by
    /// the spacebase-register branch of `checkSpacebase`/`correctSpacebase` (the stack
    /// `RuleLoadVarnode` case, live since task #22-B Brick 2).
    pub fn space_by_spacebase(&self, loc: Address, size: u32) -> Option<SpaceId> {
        self.spaces
            .iter()
            .find(|s| s.spacebase.iter().any(|&(rl, rs)| rl == loc && rs == size))
            .map(|s| s.id)
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
            big_endian: false,
            wordsize,
            delay,
            deadcodedelay: delay,
            spacebase: Vec::new(),
            contain: None,
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

    /// The standard space set registers RSP `(register:0x20, 8)` as the `stack` space's spacebase
    /// register, and `space_by_spacebase` (Ghidra `getSpaceBySpacebase`) resolves it — the reg→space
    /// lookup the spacebase-register `RuleLoadVarnode` branch uses.
    #[test]
    fn stack_spacebase_register_registered() {
        let m = SpaceManager::standard();
        let register = m.by_name("register").unwrap();
        let stack = m.by_name("stack").unwrap();
        let rsp = Address::new(register, 0x20);
        assert_eq!(m.get(stack).spacebase, vec![(rsp, 8)]);
        assert_eq!(m.space_by_spacebase(rsp, 8), Some(stack));
        // Wrong size or a non-spacebase register resolves to nothing (Ghidra throws; we return None).
        assert_eq!(m.space_by_spacebase(rsp, 4), None);
        assert_eq!(m.space_by_spacebase(Address::new(register, 0), 8), None);
    }
}
