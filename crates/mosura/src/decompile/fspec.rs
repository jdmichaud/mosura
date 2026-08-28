//! Function-prototype recovery — a port of Ghidra's `ParamEntry`/`ParamList`/`ParamActive`/
//! `ParamTrial` (`fspec.{hh,cc}`): the calling-convention description plus the trial machinery
//! that recovers which storage locations are a function's parameters and where it returns.
//!
//! A [`ParamList`] is one direction of a calling convention: an ordered list of [`ParamEntry`]
//! *resources*. For System V x86-64 the input list is the float registers `XMM0..XMM7`
//! (resource section 0) followed by the integer registers `RDI,RSI,RDX,RCX,R8,R9` (section 1)
//! followed by a stack overflow area; the output list is `XMM0/XMM1` and `RAX/RDX`. Recovery
//! builds [`ParamTrial`]s from the function's varnodes and [`ParamList::fillin_map`] decides
//! which become real parameters — matching `ParamListStandard::fillinMap` (fspec.cc:1285).
//!
//! This module is the convention model + trial containers; the dataflow filter
//! (`AncestorRealistic`) and the driving actions live alongside it as they are ported.

use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::{Address, RangeList, SpaceId, SpaceManager};
use super::varnode::VarnodeId;

/// Ghidra `type_class` (fspec.hh): the resource section a parameter draws from. System V keeps
/// the float and integer registers in separate sections so a used XMM and a used integer
/// register never force each other inactive (the `resourceStart` split, fspec.cc:946).
pub mod type_class {
    pub const GENERAL: u8 = 0; // TYPECLASS_GENERAL — integer/pointer registers + stack
    pub const FLOAT: u8 = 1; // TYPECLASS_FLOAT — XMM registers
}

/// Ghidra `ParamEntry` containment codes (fspec.hh:99): how a storage range relates to a
/// convention's parameter/return entries. Drives `guardReturns`/`guardInput` (a range that *is* an
/// entry registers a trial; one that `contained_by` an entry — a wide write covering a narrower
/// output register — is truncated with a SUBPIECE).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Containment {
    /// Range neither contains nor is contained by any entry.
    NoContainment,
    /// An entry contains the range, but not as its least-significant bytes.
    ContainsUnjustified,
    /// An entry contains the range as its least-significant bytes.
    ContainsJustified,
    /// No entry contains the range, but the range contains at least one entry.
    ContainedBy,
}

/// Ghidra `ParamEntry` (fspec.hh:84): one storage resource for a parameter or return value.
/// A register entry has `alignment == 0` — an *exclusion* entry that holds exactly one
/// parameter; the stack entry has `alignment != 0` — a non-exclusion area of many aligned slots.
#[derive(Clone, Debug)]
pub struct ParamEntry {
    /// Resource group index. Exclusion entries sharing a group are mutually exclusive (at most
    /// one is a used parameter); distinct groups are distinct parameter positions.
    pub group: u32,
    pub type_class: u8,
    pub space: SpaceId,
    pub addressbase: u64,
    /// Maximum size this entry handles (a register's full width; the stack area's extent).
    pub size: u32,
    /// Minimum size this entry handles.
    pub minsize: u32,
    /// 0 ⇒ exclusion (a single slot); otherwise the slot stride for the non-exclusion area.
    pub alignment: u32,
}

impl ParamEntry {
    fn is_exclusion(&self) -> bool {
        self.alignment == 0
    }

    /// Public form of [`Self::is_exclusion`]: an entry that is a single dedicated slot (a
    /// register), as opposed to an area many parameters are packed into (the stack overflow).
    /// The distinction decides whether the entry's declared size describes ONE parameter.
    pub fn is_exclusion_slot(&self) -> bool {
        self.is_exclusion()
    }

    /// Ghidra `ParamEntry::justifiedContain` (fspec.cc:248): if `[addr,addr+sz)` lies within
    /// this entry (and `sz` is in `[minsize,size]`), return the endian-justified byte offset of
    /// the parameter within the entry; else `None`. For a register entry a parameter sits at
    /// the base (offset 0) and may be a low sub-register (e.g. `EDI` in `RDI`).
    ///
    /// `spaces` supplies the space's endianness — Ghidra reaches it through the `AddrSpace *`
    /// its `Address` carries, and `isLeftJustified()` (fspec.hh:82) is
    /// `force_left_justify || !spaceid->isBigEndian()`.
    pub fn justified_contain_with(&self, spaces: &SpaceManager, addr: Address, sz: u32) -> Option<u64> {
        // Ghidra's `force_left_justify` flag (fspec.hh:82, set from the `<pentry>`'s
        // `extension="left"`) has no counterpart in mosura's ParamEntry — no cspec this port
        // reads sets it. Revival condition: model the flag, then OR it in here.
        let left = !spaces.is_big_endian(self.space);
        self.justified_contain_impl(addr, sz, left)
    }

    /// The little-endian reading, for callers that have no `SpaceManager` at hand. Every such
    /// caller is a latent big-endian defect — the endianness-aware entry point above is the
    /// one to move to (TODO.md's endianness sweep).
    pub fn justified_contain(&self, addr: Address, sz: u32) -> Option<u64> {
        self.justified_contain_impl(addr, sz, true)
    }

    fn justified_contain_impl(&self, addr: Address, sz: u32, left_justified: bool) -> Option<u64> {
        if addr.space != self.space || sz < self.minsize || sz > self.size {
            return None;
        }
        if addr.offset < self.addressbase {
            return None;
        }
        let end = addr.offset.checked_add(sz as u64)?;
        if end > self.addressbase + self.size as u64 {
            return None;
        }
        if self.alignment != 0 {
            if !left_justified {
                // fspec.cc:277-281 — right-justified (big-endian): measure back from the last
                // alignment boundary the range ends on.
                let endaddr = addr.offset + sz as u64 - 1 - self.addressbase;
                let res = (endaddr + 1) % self.alignment as u64;
                return Some(if res == 0 { 0 } else { self.alignment as u64 - res });
            }
            // An ALIGNED entry (fspec.cc:269-282) is a run of equal-sized slots, not one datum:
            // a parameter is justified within its own slot, so the offset is taken modulo the
            // alignment rather than from the entry base. Little-endian is always left-justified
            // (`isLeftJustified()` is `force_left_justify || !isBigEndian`), which is the
            // `startaddr % alignment` branch. Reading the offset from the base instead reported
            // every stack parameter past the first slot as "unjustified" — harmless while every
            // caller only tested `is_some()`, but `ParamList::unjustified_container` reads the
            // value, and `ActionUnjustifiedParams` then widened the same stack slot forever.
            return Some((addr.offset - self.addressbase) % self.alignment as u64);
        }
        // Ghidra delegates the unaligned case to `Address::justifiedContain` (fspec.cc:252),
        // which flips for a big-endian space unless `force_left_justify`.
        if !left_justified {
            let off1 = self.addressbase + (self.size as u64 - 1);
            let off2 = addr.offset + (sz as u64 - 1);
            return Some(off1 - off2);
        }
        Some(addr.offset - self.addressbase)
    }

    /// Ghidra `ParamEntry::getContainer` (fspec.cc:295): the full storage of the parameter that
    /// contains `[addr, addr+sz)`, as `(address, size)`. Returns `None` when the range is not
    /// contained in this entry at all.
    ///
    /// Ghidra's `joinrec` branch — a parameter split across several pieces — has no counterpart
    /// here: mosura's `ParamEntry` models no join records, so only the single-range case exists.
    pub fn get_container(&self, addr: Address, sz: u32) -> Option<(Address, u32)> {
        if addr.space != self.space || sz == 0 {
            return None;
        }
        let endoff = addr.offset.checked_add(sz as u64 - 1)?;
        let base = self.addressbase;
        let entry_end = base + self.size as u64 - 1;
        if addr.offset > entry_end || endoff < base {
            return None; // Ghidra's two `overlap` tests
        }
        if self.alignment == 0 {
            // Ordinary endian containment: the whole entry is the container.
            return Some((Address::new(self.space, base), self.size));
        }
        let al = (addr.offset - base) % self.alignment as u64;
        let off = addr.offset - al;
        let mut size = (endoff - off) as u32 + 1;
        let al2 = size % self.alignment;
        if al2 != 0 {
            size += self.alignment - al2; // bump up to the nearest alignment
        }
        Some((Address::new(self.space, off), size))
    }

    /// Ghidra `ParamEntry::containedBy` (fspec.cc): is this entry fully contained within the range
    /// `[addr, addr+sz)`? (A range wider than the entry that swallows it — e.g. a `RAX:8` write
    /// covering the `EAX:4` output entry.)
    pub fn contained_by(&self, addr: Address, sz: u32) -> bool {
        if self.space != addr.space || self.addressbase < addr.offset {
            return false;
        }
        let entryoff = self.addressbase + self.size as u64 - 1;
        let rangeoff = addr.offset + sz as u64 - 1;
        entryoff <= rangeoff
    }

    /// Ghidra `ParamEntry::getSlot` (fspec.cc:407): the slot index covering byte `off` of a
    /// parameter at `addr`. Exclusion entries always occupy their `group`; non-exclusion (stack)
    /// entries index by alignment.
    pub fn get_slot(&self, addr: Address, off: u32) -> u32 {
        if self.is_exclusion() {
            self.group
        } else {
            let rel = (addr.offset - self.addressbase) + off as u64;
            self.group + (rel / self.alignment as u64) as u32
        }
    }

    /// Ghidra `ParamEntry::getAddrBySlot` (fspec.cc:450) for the exclusion / aligned-area cases:
    /// the storage address for relative `slot` (0-based within the entry), used to synthesize
    /// hole-filling trials. Exclusion entries only allocate slot 0.
    pub fn get_addr_by_slot(&self, slot: u32, sz: u32) -> Option<Address> {
        if sz < self.minsize {
            return None;
        }
        if self.is_exclusion() {
            if slot != 0 || sz > self.size {
                return None;
            }
            Some(Address::new(self.space, self.addressbase))
        } else {
            Some(Address::new(self.space, self.addressbase + slot as u64 * self.alignment as u64))
        }
    }

    /// Ghidra `ParamEntry::groupOverlap` (fspec.cc:157): whether two entries share a group. With
    /// single-group entries this is group equality.
    pub fn group_overlap(&self, other: &ParamEntry) -> bool {
        self.group == other.group
    }
}

/// Ghidra `ParamListStandard` (fspec.hh:589) / `ParamListStandardOut` (fspec.hh:656): an ordered
/// resource list for one direction of a convention. The `resource_start` group indices mark
/// where each resource *section* (float, then integer, then stack) begins — used to score the
/// sections independently (`separateSections`, fspec.cc:946).
#[derive(Clone, Debug)]
pub struct ParamList {
    pub entry: Vec<ParamEntry>,
    pub resource_start: Vec<u32>,
    /// Output lists choose at most one entry (the return storage); input lists fill a sequence.
    pub is_output: bool,
}

impl ParamList {
    /// Ghidra `ParamListStandard::getRangeList` (fspec.cc:1439): the storage this convention passes
    /// parameters in WITHIN one space, as a [`RangeList`]. `ProtoModel::decode` (fspec.cc:2609) asks
    /// this of the stack space to derive `paramrange` from the stack overflow `<pentry>`, in
    /// preference to [`ProtoModel::default_param_range`].
    pub fn range_list(&self, spc: SpaceId, res: &mut RangeList) {
        for e in &self.entry {
            if e.space != spc {
                continue;
            }
            res.insert_range(spc, e.addressbase, e.addressbase + e.size as u64 - 1);
        }
    }

    /// Ghidra `ParamListStandard::findEntry` (fspec.cc:661): the first entry whose storage
    /// contains `[loc,loc+size)`, with its justified offset. Drives `possibleParam`.
    pub fn find_entry(&self, loc: Address, size: u32) -> Option<(&ParamEntry, u64)> {
        self.entry.iter().find_map(|e| e.justified_contain(loc, size).map(|off| (e, off)))
    }

    /// Ghidra `ParamListStandard::unjustifiedContainer` (fspec.cc:1411): if `[loc,loc+size)` sits
    /// inside one of this list's entries but is NOT justified within it — a sub-range that does
    /// not start where the convention says a parameter of that size starts — return the full
    /// storage of the containing parameter. `None` means either "not contained" or "contained and
    /// properly justified", which are the two cases needing no adjustment.
    ///
    /// mosura's [`ParamEntry::justified_contain`] returns `None` for Ghidra's `just < 0` and
    /// `Some(0)` for its `just == 0`, so the three-way outcome maps directly.
    pub fn unjustified_container(&self, loc: Address, size: u32) -> Option<(Address, u32)> {
        for e in &self.entry {
            if e.minsize > size {
                continue;
            }
            match e.justified_contain(loc, size) {
                None => continue,          // not contained (Ghidra: just < 0)
                Some(0) => return None,    // contained but properly justified
                Some(_) => return e.get_container(loc, size),
            }
        }
        None
    }

    /// Ghidra `ParamListStandard::checkSplit` (fspec.cc:1342): would `[loc,loc+size)`, cut at
    /// `splitpoint`, land on two storage locations this convention actually uses for parameters?
    /// Reached from `FuncCallSpecs::checkInputSplit` (fspec.hh:1524) via the model.
    pub fn check_split(&self, loc: Address, size: u32, splitpoint: u32) -> bool {
        if splitpoint == 0 || splitpoint >= size {
            return false;
        }
        let loc2 = Address::new(loc.space, loc.offset + splitpoint as u64);
        self.find_entry(loc, splitpoint).is_some() && self.find_entry(loc2, size - splitpoint).is_some()
    }

    /// Whether `[loc,loc+size)` could be a parameter under this convention (Ghidra
    /// `ParamList::possibleParam`).
    pub fn possible_param(&self, loc: Address, size: u32) -> bool {
        self.find_entry(loc, size).is_some()
    }

    /// Ghidra `ParamListStandard::characterizeAsParam` (fspec.cc:682): classify how `[loc,loc+size)`
    /// relates to this list's entries — is it one of them (`Contains*`), does it swallow one
    /// (`ContainedBy`), or neither. Reached via `FuncProto::characterizeAsOutput` (unlocked → the
    /// output model, fspec.cc:4336) to decide, for each heritaged write, whether it is a return
    /// value and at what width. mosura scans the linear entry list directly (Ghidra uses a
    /// per-space `ParamEntryResolver` index; the two-pass structure there is just that index's
    /// optimization).
    pub fn characterize_as_param(&self, loc: Address, size: u32) -> Containment {
        let mut res_contains = false;
        let mut res_contained_by = false;
        for e in &self.entry {
            if let Some(off) = e.justified_contain(loc, size) {
                if off == 0 {
                    return Containment::ContainsJustified;
                }
                res_contains = true;
            }
            if e.is_exclusion() && e.contained_by(loc, size) {
                res_contained_by = true;
            }
        }
        if res_contains {
            Containment::ContainsUnjustified
        } else if res_contained_by {
            Containment::ContainedBy
        } else {
            Containment::NoContainment
        }
    }

    /// Ghidra `ParamListStandard::getBiggestContainedParam` (fspec.cc:1375): the LARGEST entry
    /// fully contained within `[loc,loc+size)`, as `(address, size)`. Reached via
    /// `FuncProto::getBiggestContainedOutput` (fspec.cc:4492) from `Heritage::guardReturnsOverlapping`
    /// to truncate an over-wide heritaged range down to the return storage it swallows. (Ghidra
    /// narrows the candidate set with a per-space `ParamEntryResolver` interval index first; the
    /// linear scan here is that index's contents.)
    pub fn get_biggest_contained_param(&self, loc: Address, size: u32) -> Option<(Address, u32)> {
        loc.offset.checked_add(size as u64 - 1)?; // Ghidra's wrapping check (fspec.cc:1385)
        self.entry
            .iter()
            .filter(|e| e.contained_by(loc, size))
            .max_by_key(|e| e.size)
            .map(|e| (Address::new(e.space, e.addressbase), e.size))
    }

    /// Ghidra `ParamListStandard::getSpacebase` (fspec.hh:639): the stack space this convention
    /// passes overflow parameters in, or `None` when it has no stack resource. A non-`None` answer is
    /// exactly Ghidra's "we need a stack-pointer placeholder" signal at each call site
    /// (`ActionFuncLink::funcLinkInput`, coreaction.cc:1479).
    ///
    /// Ghidra caches this during `decode` (fspec.cc:1243-1245: every `<pentry>` whose space is a
    /// spacebase overwrites the field, so the LAST such entry wins); mosura recomputes it from the
    /// entry list, which is the same value — the same way [`Self::max_delay`] recomputes `maxdelay`.
    pub fn get_spacebase(&self, spaces: &SpaceManager) -> Option<SpaceId> {
        self.entry
            .iter()
            .rev()
            .find(|e| spaces.get(e.space).kind == super::space::SpaceKind::Spacebase)
            .map(|e| e.space)
    }

    /// Ghidra `ParamList::getMaxDelay` (fspec.hh:800): the maximum heritage delay across the
    /// entries' address spaces — how many heritage passes must complete before data-flow for every
    /// possible parameter/return location is available. Ghidra caches it during
    /// `ParamListStandard::decode` (fspec.cc:1521, `maxdelay = max(spc->getDelay())`); mosura
    /// recomputes it from the space table, which is the same value.
    pub fn max_delay(&self, spaces: &SpaceManager) -> i32 {
        self.entry.iter().map(|e| spaces.get(e.space).delay).max().unwrap_or(0)
    }

    /// Index into [`Self::entry`] of the entry containing `[loc,loc+size)` (the index form of
    /// `find_entry`, so trials can store a stable handle to their matched entry).
    fn find_entry_index(&self, loc: Address, size: u32) -> Option<usize> {
        self.entry.iter().position(|e| e.justified_contain(loc, size).is_some())
    }

    /// Ghidra `ParamListStandard::selectUnreferenceEntry` (fspec.cc:820): the entry at group
    /// `grp` best matching `pref_type`, to fill a hole with an `unref` trial.
    fn select_unreference_entry(&self, grp: u32, pref_type: u8) -> Option<usize> {
        let mut best: Option<(i32, usize)> = None;
        for (i, e) in self.entry.iter().enumerate() {
            if e.group != grp {
                continue;
            }
            let score = if e.type_class == pref_type {
                2
            } else if pref_type == type_class::GENERAL {
                1
            } else {
                0
            };
            if best.is_none_or(|(bs, _)| score > bs) {
                best = Some((score, i));
            }
        }
        best.map(|(_, i)| i)
    }

    // -- fillinMap and its helpers (fspec.cc:849-1313) ------------------------------------------

    /// Ghidra `ParamListStandard::fillinMap` (fspec.cc:1285): from the accumulated trials, decide
    /// which storage locations are actual parameters — map trials to entries, fill holes, enforce
    /// exclusion/no-hole rules per resource section, and mark the survivors `used`.
    pub fn fillin_map(&self, active: &mut ParamActive) {
        if active.num_trials() == 0 {
            return;
        }
        let dump = |tag: &str, active: &ParamActive| {
            if crate::debug::on(crate::debug::Topic::Args) {
                let v: Vec<String> = active
                    .trial
                    .iter()
                    .map(|t| {
                        format!(
                            "g{:?}o{:#x}{}{}{}",
                            t.entry,
                            t.addr.offset,
                            if t.is_active() { "A" } else { "-" },
                            if t.is_definitely_not_used() { "U" } else { "-" },
                            if t.is_unref() { "r" } else { "-" }
                        )
                    })
                    .collect();
                debug!(crate::debug::Topic::Args, "[fillin:{tag}] {}", v.join(" "));
            }
        };
        self.build_trial_map(active);
        dump("map", active);
        self.force_exclusion_group(active);
        dump("excl", active);
        let starts = self.separate_sections(active);
        let nsec = starts.len() - 1;
        for i in 0..nsec {
            self.force_no_use(active, starts[i], starts[i + 1]);
        }
        dump("nouse", active);
        for i in 0..nsec {
            self.force_inactive_chain(active, 2, starts[i], starts[i + 1], self.resource_start[i]);
        }
        dump("chain", active);
        for t in active.trial.iter_mut() {
            if t.is_active() {
                t.mark_used();
            }
        }
    }

    /// Ghidra `buildTrialMap` (fspec.cc:849): match each trial to a model entry (unmatched →
    /// unused), synthesize `unref` trials for holes that precede a used group, and sort.
    fn build_trial_map(&self, active: &mut ParamActive) {
        let mut hitlist: Vec<Option<usize>> = Vec::new();
        let (mut float_count, mut int_count) = (0i32, 0i32);
        for i in 0..active.num_trials() {
            let (addr, size, is_active) = {
                let t = &active.trial[i];
                (t.addr, t.size, t.is_active())
            };
            match self.find_entry_index(addr, size) {
                None => active.trial[i].mark_no_use(),
                Some(ei) => {
                    let grp = self.entry[ei].group;
                    active.trial[i].set_entry(ei, grp);
                    if is_active {
                        if self.entry[ei].type_class == type_class::FLOAT {
                            float_count += 1;
                        } else {
                            int_count += 1;
                        }
                    }
                    while hitlist.len() <= grp as usize {
                        hitlist.push(None);
                    }
                    if hitlist[grp as usize].is_none() {
                        hitlist[grp as usize] = Some(ei);
                    }
                }
            }
        }
        let pref = if float_count > int_count { type_class::FLOAT } else { type_class::GENERAL };
        // faithful port of Ghidra's group scan; `i` is the group/slot index passed downstream
        #[allow(clippy::needless_range_loop)]
        for i in 0..hitlist.len() {
            match hitlist[i] {
                None => {
                    if let Some(ei) = self.select_unreference_entry(i as u32, pref) {
                        let (sz, addr_opt) = {
                            let e = &self.entry[ei];
                            let sz = if e.is_exclusion() { e.size } else { e.alignment };
                            (sz, e.get_addr_by_slot(0, sz))
                        };
                        if let Some(addr) = addr_opt {
                            let ti = active.register_trial(addr, sz);
                            active.trial[ti].flags |= trial_flags::UNREF;
                            active.trial[ti].set_entry(ei, self.entry[ei].group);
                        }
                    }
                }
                Some(ei) if !self.entry[ei].is_exclusion() => self.fill_nonexclusion_holes(active, ei),
                _ => {}
            }
        }
        active.sort_trials();
    }

    /// The non-exclusion (stack) branch of `buildTrialMap` (fspec.cc:902): fill gaps between
    /// occupied slots of a single non-exclusion group with `unref` trials.
    fn fill_nonexclusion_holes(&self, active: &mut ParamActive, ei: usize) {
        let (group, align) = (self.entry[ei].group, self.entry[ei].alignment);
        let mut slotlist: Vec<u8> = Vec::new();
        for j in 0..active.num_trials() {
            if active.trial[j].entry != Some(ei) {
                continue;
            }
            let (addr, size) = (active.trial[j].addr, active.trial[j].size);
            let mut slot = (self.entry[ei].get_slot(addr, 0) - group) as i64;
            let mut endslot = (self.entry[ei].get_slot(addr, size - 1) - group) as i64;
            if endslot < slot {
                std::mem::swap(&mut slot, &mut endslot);
            }
            while (slotlist.len() as i64) <= endslot {
                slotlist.push(0);
            }
            for s in slot..=endslot {
                slotlist[s as usize] = 1;
            }
        }
        for (j, &filled) in slotlist.iter().enumerate() {
            if filled == 0 {
                if let Some(addr) = self.entry[ei].get_addr_by_slot(j as u32, align) {
                    let ti = active.register_trial(addr, align);
                    active.trial[ti].flags |= trial_flags::UNREF;
                    active.trial[ti].set_entry(ei, group);
                }
            }
        }
    }

    /// Ghidra `separateSections` (fspec.cc:946): the index ranges of each resource section, split
    /// at the `resource_start` group boundaries. Trials must already be group-sorted.
    fn separate_sections(&self, active: &ParamActive) -> Vec<usize> {
        let n = active.num_trials();
        let mut starts = vec![0usize];
        let mut next_group = self.resource_start[1];
        let mut next_section = 2usize;
        for ct in 0..n {
            let Some(ei) = active.trial[ct].entry else { continue };
            if self.entry[ei].group >= next_group {
                next_group = self.resource_start[next_section];
                next_section += 1;
                starts.push(ct);
            }
        }
        starts.push(n);
        starts
    }

    /// Ghidra `markGroupNoUse` (fspec.cc:974): mark every trial sharing `active_trial`'s group
    /// (except it) as definitely-not-used.
    fn mark_group_no_use(&self, active: &mut ParamActive, active_trial: usize, trial_start: usize) {
        let n = active.num_trials();
        let active_group = self.entry[active.trial[active_trial].entry.unwrap()].group;
        for i in trial_start..n {
            if i == active_trial || active.trial[i].is_definitely_not_used() {
                continue;
            }
            if self.entry[active.trial[i].entry.unwrap()].group != active_group {
                break;
            }
            active.trial[i].mark_no_use();
        }
    }

    /// Ghidra `markBestInactive` (fspec.cc:997): among several inactive trials in one exclusion
    /// group, keep the best-scoring and mark the rest not-used.
    fn mark_best_inactive(&self, active: &mut ParamActive, group: u32, group_start: usize, pref_type: u8) {
        let n = active.num_trials();
        let mut best: Option<(i32, usize)> = None;
        for i in group_start..n {
            if active.trial[i].is_definitely_not_used() {
                continue;
            }
            let e = &self.entry[active.trial[i].entry.unwrap()];
            if e.group != group {
                break;
            }
            let mut score = 0;
            if active.trial[i].flags & trial_flags::ANCESTOR_REALISTIC != 0 {
                score += 5;
                if active.trial[i].flags & trial_flags::ANCESTOR_SOLID != 0 {
                    score += 5;
                }
            }
            if e.type_class == pref_type {
                score += 1;
            }
            if best.is_none_or(|(bs, _)| score > bs) {
                best = Some((score, i));
            }
        }
        if let Some((_, bi)) = best {
            self.mark_group_no_use(active, bi, group_start);
        }
    }

    /// Ghidra `forceExclusionGroup` (fspec.cc:1032): at most one active trial survives per
    /// exclusion group; among multiple inactive, keep the best.
    fn force_exclusion_group(&self, active: &mut ParamActive) {
        let n = active.num_trials();
        let mut cur_group: i64 = -1;
        let mut group_start = 0usize;
        let mut inactive_count = 0;
        for i in 0..n {
            let (dnu, entry_opt) = (active.trial[i].is_definitely_not_used(), active.trial[i].entry);
            let Some(ei) = entry_opt else { continue };
            if dnu || !self.entry[ei].is_exclusion() {
                continue;
            }
            let grp = self.entry[ei].group as i64;
            if grp != cur_group {
                if inactive_count > 1 {
                    self.mark_best_inactive(active, cur_group as u32, group_start, type_class::GENERAL);
                }
                cur_group = grp;
                group_start = i;
                inactive_count = 0;
            }
            if active.trial[i].is_active() {
                self.mark_group_no_use(active, i, group_start);
            } else {
                inactive_count += 1;
            }
        }
        if inactive_count > 1 {
            self.mark_best_inactive(active, cur_group as u32, group_start, type_class::GENERAL);
        }
    }

    /// Ghidra `forceNoUse` (fspec.cc:1069): once a whole group is definitely-not-used, force
    /// every later trial in the section inactive ("no holes after a gap").
    fn force_no_use(&self, active: &mut ParamActive, start: usize, stop: usize) {
        let mut seendefnouse = false;
        let mut curgroup: i64 = -1;
        let mut alldefnouse = false;
        for i in start..stop {
            let Some(ei) = active.trial[i].entry else { continue };
            let grp = self.entry[ei].group as i64;
            let exclusion = self.entry[ei].is_exclusion();
            let dnu = active.trial[i].is_definitely_not_used();
            if grp <= curgroup && exclusion {
                if !dnu {
                    alldefnouse = false;
                }
            } else {
                if alldefnouse {
                    seendefnouse = true;
                }
                alldefnouse = dnu;
                curgroup = grp;
            }
            if seendefnouse {
                active.trial[i].mark_inactive();
            }
        }
    }

    /// Ghidra `forceInactiveChain` (fspec.cc:1111): a chain of inactive slots longer than
    /// `maxchain` forces later slots inactive; isolated inactive slots before it become active
    /// (hole-filling between actives). Called per resource section.
    fn force_inactive_chain(&self, active: &mut ParamActive, maxchain: i64, start: usize, stop: usize, groupstart: u32) {
        let is_subcall = active.is_recover_subcall;
        let mut seenchain = false;
        let mut chainlength: i64 = 0;
        let mut max: i64 = -1;
        for i in start..stop {
            if active.trial[i].is_definitely_not_used() {
                continue;
            }
            if !active.trial[i].is_active() {
                let (addr, size, ei, is_unref) = {
                    let t = &active.trial[i];
                    (t.addr, t.size, t.entry.unwrap(), t.is_unref())
                };
                // Ghidra sets `seenchain` from an unref trial ONLY for a STACK location — the inner
                // `if (trial.getAddress().getSpace()->getType() == IPTR_SPACEBASE)`. The reasoning is
                // specific to the stack: an unreferenced REGISTER may be an input the caller passes
                // straight through, whereas a stack slot cannot, since caller and callee stack
                // offsets differ. Entries live in the register space or on the stack, so "not the
                // register space" is that test.
                //
                // Without it, one synthesized REGISTER hole set `seenchain` at the first trial and
                // every later trial in the section was marked inactive regardless of chain length,
                // which discarded real arguments — `FUN_00033370`'s `MOV EBX,0x8ce58` among them.
                let on_stack = Some(addr.space) != active.reg_space;
                if is_unref && is_subcall && on_stack {
                    seenchain = true;
                }
                let slotgroup = self.entry[ei].get_slot(addr, size - 1) as i64;
                if i == start {
                    chainlength += slotgroup - groupstart as i64 + 1;
                } else {
                    let pt = &active.trial[i - 1];
                    let prev_slotgroup =
                        self.entry[pt.entry.unwrap()].get_slot(pt.addr, pt.size - 1) as i64;
                    chainlength += slotgroup - prev_slotgroup;
                }
                if chainlength > maxchain {
                    seenchain = true;
                }
            } else {
                chainlength = 0;
                if !seenchain {
                    max = i as i64;
                }
            }
            if seenchain {
                active.trial[i].mark_inactive();
            }
        }
        if max >= start as i64 {
            for i in start..=(max as usize) {
                if !active.trial[i].is_definitely_not_used() && !active.trial[i].is_active() {
                    active.trial[i].mark_active();
                }
            }
        }
    }
}

// ---- System V x86-64 register offsets (mosura's register space) -------------------------------

const RAX: u64 = 0x0;
const RDX: u64 = 0x10;
const RCX: u64 = 0x8;
const RSI: u64 = 0x30;
const RDI: u64 = 0x38;
const R8: u64 = 0x80;
const R9: u64 = 0x88;
const XMM_BASE: u64 = 0x1200;
const XMM_STRIDE: u64 = 0x40;

/// The System V AMD64 input resource list (Ghidra `x86-64-gcc.cspec` `__stdcall`): float
/// registers `XMM0..XMM7` (section 0, groups 0-7), then integer registers `RDI,RSI,RDX,RCX,R8,R9`
/// (section 1, groups 8-13), then the stack overflow area (section 2, group 14).
pub fn sysv_input(spaces: &SpaceManager) -> Option<ParamList> {
    let reg = spaces.by_name("register")?;
    let stack = spaces.by_name("stack")?;
    let mut entry = Vec::new();
    for i in 0..8u32 {
        entry.push(ParamEntry {
            group: i,
            type_class: type_class::FLOAT,
            space: reg,
            addressbase: XMM_BASE + i as u64 * XMM_STRIDE,
            size: 8,
            minsize: 4,
            alignment: 0,
        });
    }
    for (i, off) in [RDI, RSI, RDX, RCX, R8, R9].into_iter().enumerate() {
        entry.push(ParamEntry {
            group: 8 + i as u32,
            type_class: type_class::GENERAL,
            space: reg,
            addressbase: off,
            size: 8,
            minsize: 1,
            alignment: 0,
        });
    }
    // Stack overflow: a non-exclusion area of 8-byte slots starting just above the return addr.
    entry.push(ParamEntry {
        group: 14,
        type_class: type_class::GENERAL,
        space: stack,
        addressbase: 8,
        size: 500,
        minsize: 1,
        alignment: 8,
    });
    // resource_start: float section starts group 0, general section starts group 8; the trailing
    // value is the sentinel `numgroup` (highest group 14 + 1) so the stack stays in the general
    // section and `separate_sections` never splits past it (Ghidra fspec.cc:1240/1502).
    Some(ParamList { entry, resource_start: vec![0, 8, 15], is_output: false })
}

/// The System V AMD64 output (return) resource list: `XMM0/XMM1` (float) and `RAX/RDX`
/// (integer). The recovery picks the single best-covered entry — effectively `XMM0` for a
/// float return and `RAX` for an integer/pointer return.
pub fn sysv_output(spaces: &SpaceManager) -> Option<ParamList> {
    let reg = spaces.by_name("register")?;
    let entry = vec![
        ParamEntry { group: 0, type_class: type_class::FLOAT, space: reg, addressbase: XMM_BASE, size: 8, minsize: 4, alignment: 0 },
        ParamEntry { group: 1, type_class: type_class::FLOAT, space: reg, addressbase: XMM_BASE + XMM_STRIDE, size: 8, minsize: 4, alignment: 0 },
        ParamEntry { group: 2, type_class: type_class::GENERAL, space: reg, addressbase: RAX, size: 8, minsize: 1, alignment: 0 },
        ParamEntry { group: 3, type_class: type_class::GENERAL, space: reg, addressbase: RDX, size: 8, minsize: 1, alignment: 0 },
    ];
    Some(ParamList { entry, resource_start: vec![0, 2, 4], is_output: true })
}

// ---- Side-effects (EffectRecord / ProtoModel.effectlist) --------------------------------------

/// Ghidra `EffectRecord` effect types (fspec.hh:393): the side-effect a sub-function has on a
/// storage range, seen from the caller across a call to it.
pub mod effect {
    /// The sub-function does not change the value at all (a callee-saved register).
    pub const UNAFFECTED: u8 = 1;
    /// The memory is changed, unrelated to its original value (a caller-saved/clobbered register).
    pub const KILLEDBYCALL: u8 = 2;
    /// The memory holds the return address.
    pub const RETURN_ADDRESS: u8 = 3;
    /// No EffectRecord covers the range — the effect is unknown (value may flow through).
    pub const UNKNOWN_EFFECT: u8 = 4;
}

/// Ghidra `EffectRecord` (fspec.hh:391): the indirect effect a sub-function has on one memory
/// range. The range is given in the caller's address space (registers, or the stack-relative
/// return-address slot).
#[derive(Clone, Copy, Debug)]
pub struct EffectRecord {
    pub space: SpaceId,
    pub offset: u64,
    pub size: u32,
    pub effect: u8,
}

/// The System V AMD64 effect list — Ghidra's `ProtoModel::effectlist` for the `__stdcall`
/// prototype of `x86-64-gcc.cspec`. Each input-parameter register is `killedbycall`
/// (`ParamListStandard::parsePentry`, fspec.cc:1247) — `RDI,RSI,RDX,RCX,R8,R9` and `XMM0..7` —
/// joined with the explicit `<killedbycall>` set (`RAX,RDX,XMM0`) and the output registers
/// (`RAX,RDX,XMM0,XMM1`); the `<unaffected>` callee-saved registers (`RBX,RSP,RBP,R12..R15`) are
/// `unaffected`; the stack slot at offset 0 holds the `return_address`. `R10/R11` and the flags
/// are absent ⇒ `unknown_effect`.
pub fn sysv_effect_list(spaces: &SpaceManager) -> Vec<EffectRecord> {
    let Some(reg) = spaces.by_name("register") else { return Vec::new() };
    let mut list = Vec::new();
    let mut kill = |off: u64| list.push(EffectRecord { space: reg, offset: off, size: 8, effect: effect::KILLEDBYCALL });
    // killedbycall: the volatile integer registers (params + RAX) ...
    for off in [RAX, RCX, RDX, RSI, RDI, R8, R9] {
        kill(off);
    }
    // ... and the float registers XMM0..7 (which also cover the XMM0/XMM1 outputs).
    for i in 0..8u64 {
        kill(XMM_BASE + i * XMM_STRIDE);
    }
    // unaffected: the callee-saved registers RBX, RSP, RBP, R12..R15.
    for off in [0x18u64, 0x20, 0x28, 0xa0, 0xa8, 0xb0, 0xb8] {
        list.push(EffectRecord { space: reg, offset: off, size: 8, effect: effect::UNAFFECTED });
    }
    if let Some(stack) = spaces.by_name("stack") {
        list.push(EffectRecord { space: stack, offset: 0, size: 8, effect: effect::RETURN_ADDRESS });
    }
    list.sort_by(|a, b| a.space.0.cmp(&b.space.0).then(a.offset.cmp(&b.offset)));
    list
}

/// Ghidra `ProtoModel::lookupEffect` (fspec.cc:2472): the effect type covering `[addr,addr+size)`
/// — the first record at or before `addr` whose range fully contains it, else `unknown_effect`.
/// (Constants / unique-space ranges are local to the function and always `unaffected`.)
pub fn lookup_effect(efflist: &[EffectRecord], addr: Address, size: u32) -> u8 {
    // `efflist` is sorted by (space, offset); find the last record at or before `addr`.
    let mut hit: Option<&EffectRecord> = None;
    for e in efflist {
        if e.space.0 < addr.space.0 || (e.space.0 == addr.space.0 && e.offset <= addr.offset) {
            hit = Some(e);
        } else {
            break;
        }
    }
    let Some(e) = hit else { return effect::UNKNOWN_EFFECT };
    if e.space != addr.space {
        return effect::UNKNOWN_EFFECT;
    }
    let end = addr.offset.saturating_add(size as u64);
    if addr.offset >= e.offset && end <= e.offset + e.size as u64 {
        e.effect
    } else {
        effect::UNKNOWN_EFFECT
    }
}

// ---- ProtoModel (the default calling convention) ----------------------------------------------

/// Ghidra `ProtoModel` (fspec.hh:1039) reduced to the surface mosura's prototype recovery and
/// heritage call-guarding consume: the input & output parameter [`ParamList`]s and the sorted
/// [`EffectRecord`] list. It is decoded once, at function-build time, from the compiler spec's
/// `<default_proto>` — the faithful `ParamListStandard::decode`/`ProtoModel::decode` port in
/// [`crate::analysis::cspec::default_proto_model`] — and carried on [`Funcdata`], replacing the old
/// hardcoded SysV `sysv_input`/`sysv_output`/`sysv_effect_list` literals. A hand-built `Funcdata`
/// (no compiler spec resolved) carries the [`ProtoModel::empty`] model: no parameter storage and no
/// side effects (every range reads back `unknown_effect`).
#[derive(Clone, Debug, Default)]
pub struct ProtoModel {
    pub input: Option<ParamList>,
    pub output: Option<ParamList>,
    pub effectlist: Vec<EffectRecord>,
    /// Ghidra `ProtoModel::localrange` (fspec.hh:1050): the stack window a function's LOCALS may
    /// occupy. `ScopeLocal` maps nothing outside it and names nothing outside it, so it is what makes
    /// a frame offset a local at all. From the model's `<localrange>` when the compiler spec supplies
    /// one, else [`Self::default_local_range`].
    pub localrange: RangeList,
    /// Ghidra `ProtoModel::paramrange` (fspec.hh:1051): the stack window INPUT PARAMETERS occupy.
    /// `ScopeLocal`'s range is `localrange ∪ paramrange`, but `MapState` then removes `paramrange`
    /// from it (varmap.cc:870-875) so parameter slots never become locals.
    pub paramrange: RangeList,
    /// Ghidra `ProtoModel::extrapop` (fspec.hh:752): bytes the CALLEE pops from the stack beyond
    /// what the caller pushed — the stack pointer's change across a call.
    ///
    /// [`EXTRAPOP_UNKNOWN`] is NOT the same as zero: an unknown extrapop makes the stack pointer
    /// after the call indeterminate, which `ActionExtraPopSetup` models with an INDIRECT rather
    /// than an add. WAR2's `__watcall` is exactly that (`extrapop="unknown"`); x86-64-gcc's
    /// `__stdcall` is `8`.
    pub extrapop: i32,
    /// Ghidra `ProtoModel::likelytrash` (fspec.hh:757), decoded from the cspec's `<likelytrash>`
    /// element: registers a caller is likely to leave garbage in, reached through
    /// `FuncProto::trashBegin()..trashEnd()`. `ActionLikelyTrash` traces each one and, if every
    /// path from it is a trash sink, cuts the data flow. Empty for a model that declares none —
    /// x86-32-watcom and x86-64-gcc both do, so this is empty on both of mosura's targets; x86win,
    /// x86gcc, x86borland, x86delphi and x86-32-golang declare it.
    pub likelytrash: Vec<(Address, u32)>,
    /// BEYOND GHIDRA. Does the compiler this model describes let a FUNCTION declare its own
    /// register convention (Watcom's `#pragma aux <name> parm [..] value [..] modify [..]`, High
    /// C's equivalent)? When it does, a body that reads or returns through registers the model
    /// does not name is evidence of such a declaration, and mosura recovers it (the custom
    /// register parameters in [`recover_input_params`], the self-evidence prototype in
    /// `analysis::decompiler`). When it does not — gcc's SysV, where the ABI is fixed and only the
    /// CLOBBER set varies (`-fipa-ra`) — those readings are wrong by construction: the ground-truth
    /// corpus' `structval` read `mk`'s parameters in instruction order (RSI before EDI) and `dot`'s
    /// 8-byte inputs at the width of their first 4-byte read, so neither matched a trial and both
    /// became uninitialized locals. Set from the compiler spec id in `build::resolve_proto_model`.
    pub custom_conventions: bool,
}

/// Ghidra `ProtoModel::extrapop_unknown` (fspec.hh:772).
pub const EXTRAPOP_UNKNOWN: i32 = 0x8000;

impl ProtoModel {
    /// The empty model — no parameter storage, no declared side effects. Ghidra's `ProtoModel`
    /// CONSTRUCTOR still installs the default stack windows (fspec.cc:2353-2354), so prefer
    /// [`Self::with_default_ranges`] wherever a [`SpaceManager`] is in hand; a model with no
    /// `localrange` maps no stack locals at all.
    pub fn empty() -> ProtoModel {
        ProtoModel::default()
    }

    /// Ghidra `ProtoModel::ProtoModel(Architecture*)` (fspec.cc:2340): a model carrying nothing but
    /// the two default stack windows, which every `ProtoModel` has from construction.
    pub fn with_default_ranges(spaces: &SpaceManager) -> ProtoModel {
        ProtoModel {
            localrange: Self::default_local_range(spaces, true),
            paramrange: Self::default_param_range(spaces, true),
            ..ProtoModel::default()
        }
    }

    /// Ghidra `ProtoModel::defaultLocalRange` (fspec.cc:2263): with the normal negative-growing
    /// stack, locals live at NEGATIVE offsets — the top `999999` bytes of the stack space (`9999` /
    /// `99` for a 2-byte / 1-byte space). The window is expressed in the space's own wrapped offsets,
    /// so on a 4-byte stack it is `[0xfff0bdc1, 0xffffffff]` and every non-negative frame offset
    /// falls OUTSIDE it. That is why Ghidra emits no `StackX_` name over WAR2's 1286 functions: the
    /// caller-allocated marker in `ScopeLocal::buildVariableName` (varmap.cc:566) sits behind an
    /// `inRange` test this window cannot pass.
    pub fn default_local_range(spaces: &SpaceManager, stack_grows_negative: bool) -> RangeList {
        let mut rl = RangeList::new();
        let Some(stack) = spaces.by_name("stack") else { return rl };
        let spc = spaces.get(stack);
        let span = match spc.addr_size {
            n if n >= 4 => 999999,
            n if n >= 2 => 9999,
            _ => 99,
        };
        if stack_grows_negative {
            let last = spc.highest();
            rl.insert_range(stack, last - span, last);
        } else {
            rl.insert_range(stack, 0, span);
        }
        rl
    }

    /// Ghidra `ProtoModel::defaultParamRange` (fspec.cc:2292): with the normal negative-growing
    /// stack, stack parameters live at the POSITIVE offsets `[0, 511]` (`[0,255]` / `[0,15]` for a
    /// 2-byte / 1-byte space).
    pub fn default_param_range(spaces: &SpaceManager, stack_grows_negative: bool) -> RangeList {
        let mut rl = RangeList::new();
        let Some(stack) = spaces.by_name("stack") else { return rl };
        let spc = spaces.get(stack);
        let span = match spc.addr_size {
            n if n >= 4 => 511,
            n if n >= 2 => 255,
            _ => 15,
        };
        if stack_grows_negative {
            rl.insert_range(stack, 0, span);
        } else {
            let last = spc.highest();
            rl.insert_range(stack, last - span, last);
        }
        rl
    }

    /// Ghidra `FuncProto::possibleInputParam` (fspec.cc:4310 → `ParamList::possibleParam`): whether
    /// `[loc,loc+size)` is storage the convention could pass an input parameter in.
    pub fn possible_input_param(&self, loc: Address, size: u32) -> bool {
        self.input.as_ref().is_some_and(|pl| pl.possible_param(loc, size))
    }

    /// Ghidra `FuncProto::hasEffect` (fspec.cc:2540 → [`lookup_effect`], `ProtoModel::lookupEffect`,
    /// fspec.cc:2472): the effect type a call under this model has on the range `[addr,addr+size)`.
    pub fn has_effect(&self, addr: Address, size: u32) -> u8 {
        lookup_effect(&self.effectlist, addr, size)
    }

    /// Ghidra `FuncProto::characterizeAsInputParam` (fspec.cc:4289 →
    /// `ProtoModel::characterizeAsInputParam`, fspec.hh:858 → `input->characterizeAsParam`): how
    /// `[loc,loc+size)` relates to this convention's parameter storage. The input-side twin of
    /// [`Self::characterize_as_output`], asked by `Heritage::guardCalls` (heritage.cc:1495) of every
    /// heritaged range at every call site.
    pub fn characterize_as_input_param(&self, loc: Address, size: u32) -> Containment {
        match self.input.as_ref() {
            Some(pl) => pl.characterize_as_param(loc, size),
            None => Containment::NoContainment,
        }
    }

    /// Ghidra `FuncProto::getBiggestContainedInputParam` (fspec.cc:4470): the largest parameter
    /// storage contained within an over-wide range, for `guardCallOverlappingInput`'s SUBPIECE.
    pub fn get_biggest_contained_input_param(&self, loc: Address, size: u32) -> Option<(Address, u32)> {
        self.input.as_ref()?.get_biggest_contained_param(loc, size)
    }

    /// Ghidra `FuncProto::getMaxInputDelay` (fspec.hh:1571 → `ProtoModel::getMaxInputDelay`,
    /// fspec.hh:990): heritage passes to wait before every possible parameter location has
    /// data-flow. Feeds `FuncCallSpecs::initActiveInput`'s `setMaxPass` (fspec.cc:5335).
    pub fn max_input_delay(&self, spaces: &SpaceManager) -> i32 {
        self.input.as_ref().map_or(0, |pl| pl.max_delay(spaces))
    }

    /// Ghidra `FuncProto::characterizeAsOutput` (fspec.cc:4336 → `ProtoModel::characterizeAsOutput`,
    /// fspec.hh:873 → `output->characterizeAsParam`): how `[loc,loc+size)` relates to this
    /// convention's return storage. This is the query `Heritage::guardReturns` (heritage.cc:1660)
    /// makes of EVERY heritaged range — the return-value candidates arise BY QUERY FROM THE COMPILER
    /// SPEC, never from a fixed register list. mosura's prototypes are never output-locked (the
    /// locked branch, fspec.cc:4338-4353, has no counterpart yet), so this is the unlocked path.
    pub fn characterize_as_output(&self, loc: Address, size: u32) -> Containment {
        match self.output.as_ref() {
            Some(pl) => pl.characterize_as_param(loc, size),
            None => Containment::NoContainment,
        }
    }

    /// Ghidra `FuncProto::getBiggestContainedOutput` (fspec.cc:4492 →
    /// `ProtoModel::getBiggestContainedOutput`, fspec.hh:973): the largest return storage contained
    /// within an over-wide range, for `Heritage::guardReturnsOverlapping`'s SUBPIECE truncation.
    pub fn get_biggest_contained_output(&self, loc: Address, size: u32) -> Option<(Address, u32)> {
        self.output.as_ref()?.get_biggest_contained_param(loc, size)
    }

    /// Ghidra `FuncProto::getMaxOutputDelay` (fspec.hh:1572 → `ProtoModel::getMaxOutputDelay`,
    /// fspec.hh:998): heritage passes to wait before every possible return location has data-flow.
    /// Feeds `Funcdata::initActiveOutput`'s `setMaxPass` (funcdata_varnode.cc:585).
    pub fn max_output_delay(&self, spaces: &SpaceManager) -> i32 {
        self.output.as_ref().map_or(0, |pl| pl.max_delay(spaces))
    }
}

// ---- Trials -----------------------------------------------------------------------------------

/// Ghidra `ParamTrial` flag bits (fspec.hh:212). The subset the faithful recovery needs.
pub mod trial_flags {
    pub const CHECKED: u32 = 1; // the trial has been investigated
    pub const USED: u32 = 2; // final verdict: a real parameter
    pub const DEFNOUSE: u32 = 4; // definitely not used
    pub const ACTIVE: u32 = 8; // hint: written/used in dataflow (a likely parameter)
    pub const UNREF: u32 = 0x10; // synthesized to fill a hole — no backing varnode
    pub const KILLEDBYCALL: u32 = 0x20; // storage is overwritten by a call
    pub const REM_FORMED: u32 = 0x40; // the trial is built out of a remainder operation
    pub const INDCREATE_FORMED: u32 = 0x80; // the trial is built out of an indirect creation
    pub const CONDEXE_EFFECT: u32 = 0x100; // this trial may be affected by conditional execution
    pub const ANCESTOR_REALISTIC: u32 = 0x200; // trial has a realistic ancestor
    pub const ANCESTOR_SOLID: u32 = 0x400; // solid movement into the Varnode
}

/// Ghidra `ParamTrial` (fspec.hh:210): one candidate parameter at a storage location.
#[derive(Clone, Debug)]
pub struct ParamTrial {
    pub addr: Address,
    pub size: u32,
    /// Formal slot for ordering (filled by `fillin_map`); the matched entry's group.
    pub slot: u32,
    /// The CALL/RETURN input-varnode index this trial corresponds to — Ghidra's `ParamTrial::slot`
    /// (fspec.hh:229, assigned by `ParamActive::registerTrial` from `slotbase`). Set by the
    /// call/return trial recovery in `recover.rs`; the `recover_input_params` path (which maps input
    /// varnodes, not op slots) leaves it 0 and orders by `slot`/group instead.
    pub op_slot: u32,
    /// Index of the matched [`ParamEntry`] in the list, once `find_entry` succeeds.
    pub entry: Option<usize>,
    pub flags: u32,
}

impl ParamTrial {
    pub fn new(addr: Address, size: u32) -> ParamTrial {
        ParamTrial { addr, size, slot: 0, op_slot: 0, entry: None, flags: 0 }
    }
    pub fn is_active(&self) -> bool {
        self.flags & trial_flags::ACTIVE != 0
    }
    pub fn is_used(&self) -> bool {
        self.flags & trial_flags::USED != 0
    }
    pub fn is_unref(&self) -> bool {
        self.flags & trial_flags::UNREF != 0
    }
    /// Ghidra `ParamTrial::isChecked` (fspec.hh:243): has this trial been investigated?
    pub fn is_checked(&self) -> bool {
        self.flags & trial_flags::CHECKED != 0
    }

    /// Ghidra `ParamTrial::splitHi` (fspec.cc:1845): a trial covering the FIRST `sz` bytes of this
    /// trial's range, keeping its slot and flags.
    pub fn split_hi(&self, sz: u32) -> ParamTrial {
        ParamTrial { size: sz, ..self.clone() }
    }

    /// Ghidra `ParamTrial::splitLo` (fspec.cc:1856): a trial covering the LAST `sz` bytes of this
    /// trial's range, taking the next slot and keeping the flags.
    pub fn split_lo(&self, sz: u32) -> ParamTrial {
        ParamTrial {
            addr: Address::new(self.addr.space, self.addr.offset + (self.size - sz) as u64),
            size: sz,
            slot: self.slot + 1,
            ..self.clone()
        }
    }

    pub fn is_definitely_not_used(&self) -> bool {
        self.flags & trial_flags::DEFNOUSE != 0
    }
    /// Ghidra `ParamTrial::isKilledByCall` (fspec.hh:254).
    pub fn is_killed_by_call(&self) -> bool {
        self.flags & trial_flags::KILLEDBYCALL != 0
    }
    /// Ghidra `ParamTrial::setIndCreateFormed` (fspec.hh:257): formed by indirect creation.
    pub fn set_ind_create_formed(&mut self) {
        self.flags |= trial_flags::INDCREATE_FORMED;
    }
    /// Ghidra `ParamTrial::setCondExeEffect` / `hasCondExeEffect` (fspec.hh:259-260): possibly
    /// affected by conditional execution.
    pub fn set_cond_exe_effect(&mut self) {
        self.flags |= trial_flags::CONDEXE_EFFECT;
    }
    pub fn has_cond_exe_effect(&self) -> bool {
        self.flags & trial_flags::CONDEXE_EFFECT != 0
    }
    /// Ghidra `ParamTrial::setAncestorRealistic` (fspec.hh:261): has a realistic ancestor.
    pub fn set_ancestor_realistic(&mut self) {
        self.flags |= trial_flags::ANCESTOR_REALISTIC;
    }
    /// Ghidra `ParamTrial::setAncestorSolid` (fspec.hh:263): solid movement into the Varnode.
    pub fn set_ancestor_solid(&mut self) {
        self.flags |= trial_flags::ANCESTOR_SOLID;
    }
    /// Record the matched entry (index into [`ParamList::entry`]) and its group (the sort key) —
    /// Ghidra `ParamTrial::setEntry` (fspec.hh:242).
    pub(super) fn set_entry(&mut self, idx: usize, group: u32) {
        self.entry = Some(idx);
        self.slot = group;
    }
    /// Ghidra `ParamTrial::setEntry(0, 0)` (fspec.hh:242): the trial matches no entry. This is the
    /// sort key that sinks it BELOW every matched trial (`ParamTrial::operator<`, fspec.cc:1893
    /// returns entry-less last), which is what lets a consumer stop at the first unmatched trial.
    pub(super) fn clear_entry(&mut self) {
        self.entry = None;
        self.slot = 0;
    }
    pub fn mark_active(&mut self) {
        self.flags |= trial_flags::ACTIVE | trial_flags::CHECKED;
    }
    pub fn mark_inactive(&mut self) {
        self.flags &= !trial_flags::ACTIVE;
        self.flags |= trial_flags::CHECKED;
    }
    pub fn mark_no_use(&mut self) {
        self.flags |= trial_flags::DEFNOUSE | trial_flags::CHECKED;
        self.flags &= !trial_flags::ACTIVE;
    }
    /// Withdraw a `used` verdict (the A6 over-call clamp): the trial stays checked, it just does
    /// not become an argument.
    pub fn mark_unused(&mut self) {
        self.flags &= !trial_flags::USED;
    }
    pub fn mark_used(&mut self) {
        self.flags |= trial_flags::USED;
    }
}

/// The per-CALL state Ghidra keeps on `FuncCallSpecs` (fspec.hh:1651-1652) that must OUTLIVE the
/// trial container. mosura has no `FuncCallSpecs` object — a call's trials live in
/// [`Funcdata::active_inputs`](super::funcdata::Funcdata::active_inputs), keyed by the CALL op, and
/// that entry is REMOVED when the arguments commit (`clearActiveInput`). The stack offset must
/// survive that: `Heritage::guardCalls` reads it on every later heritage pass, and `hasEffect`
/// (fspec.cc:5940) reads it too. So it gets its own map, keyed the same way.
#[derive(Clone, Debug, Default)]
pub struct CallSpec {
    /// Ghidra `FuncCallSpecs::stackoffset` (fspec.hh:1651): "Relative offset of stack-pointer at
    /// time of this call". `None` is Ghidra's `offset_unknown` (fspec.hh:1677, the 0xBADBEEF
    /// sentinel) — the state in which `guardCalls` refuses to register a spacebase range as a
    /// parameter trial, because it cannot express the range in the callee's frame.
    pub stackoffset: Option<u64>,
    /// Ghidra `FuncCallSpecs::extrapop` (fspec.hh:1362): this call site's stack-pointer change
    /// across the call, RECOVERED from the callee's own return instruction (`RET` vs `RET n`,
    /// [`crate::recompile::convention::callee_stack_cleanup`]) plus the return-address slot.
    /// `None` when the callee's returns are unknown or disagree -- the model's (usually unknown)
    /// extrapop then applies, which is what `ActionExtraPopSetup` models as an INDIRECT.
    pub extrapop: Option<i32>,
    /// Ghidra `FuncCallSpecs::effectiveExtraPop` (fspec.hh:1656): the extrapop as modelled --
    /// `None` until `ActionExtraPopSetup` (known case) or the stack solver has set it.
    pub effective_extrapop: Option<i32>,
    /// Evidence for PER-CALL prototype-model selection — Ghidra's architecture carries this
    /// natively (`FuncCallSpecs` IS-a `FuncProto` with its OWN model, fspec.hh:1640, filled from
    /// the database's per-function prototype; mosura's whole-program pass recovers it from bytes
    /// instead). `Some(n)`: the ORIGINAL caller pops `n > 0` argument bytes itself (`ADD ESP,n`
    /// at this call's fallthrough, [`crate::recompile::convention::caller_stack_cleanup`]) while
    /// the callee's own `RET` pops none — the `__cdecl`/vararg convention at this ONE call.
    /// Consumers ([`super::funcdata::Funcdata::input_list_for_call`]) then characterize the
    /// call's inputs against the cspec's named `__cdecl` stack-only list, so `__watcall`'s
    /// register pentries stop manufacturing trials (and the killing chain) at a call that takes
    /// no register arguments.
    pub caller_cleans: Option<u32>,
    /// The caller-cleaned callee's own recovered MODIFY set (register offsets, sub-registers
    /// normalized to their containing 32-bit register): what its body visibly clobbers at
    /// return — writes minus saved-and-restored, nested calls counted as clobbering the
    /// convention's kill set (`callee_writes_cfg(_, calls_clobber=true)`). Recovered ONLY for
    /// `caller_cleans` callees; the emitter renders it as the callee pragma's `modify [..]`
    /// clause, because Watcom emits the caller's prologue saves only when the callee's declared
    /// contract kills a register the caller's own contract must preserve. `None` = the walk
    /// could not complete (indirect flow, budget) — the declaration then omits the clause and
    /// the default (preserves-all) assumption stands.
    pub cdecl_modify: Option<Vec<u64>>,
    /// Increment 2 of the contract design: was this callee declared `modify EXACT` in this
    /// TU? OW `CallZap` (i86reg.c:263) adds `state->parm.used` — the call's own argument
    /// registers — to the scheduler-visible kill set UNLESS the declaration carried
    /// `ROUTINE_MODIFY_EXACT`. The observable signature (the 12c58 pass-through class): a
    /// register that IS one of the call's own argument registers and provably SURVIVES that
    /// call in the caller's CFG was compiled under an `exact` declaration — a non-exact one
    /// would have zapped it. Recovered per (TU, callee) like the kill set itself; `false`
    /// (no testimony) emits the plain `modify [..]`, whose parm.used behavior matches the
    /// baseline.
    pub cdecl_exact: bool,
    /// BEYOND-GHIDRA bookkeeping for `stackvars::recover_stack`'s call-mechanism model: the
    /// return-address push amount it already CANCELLED at this call (the push rewritten to an
    /// identity COPY, the retaddr store materialized at its slot). Ghidra keeps the push in the
    /// IR, so its extrapop machinery restores the whole `+4`; mosura's pre-model has already
    /// restored it, and every later extrapop consumer must subtract this or the ret-pop is
    /// counted twice — measured on WAR2 FUN_0003495c, where the unknown-extrapop solver's `+4`
    /// guess on top of the neutralized push shifted every post-call stack resolution by +4,
    /// landing a call's return address inside the (correctly) aliased locals as
    /// `aiStack_18[0] = 0x34a6d;` and breaking the structure into gotos (the E1082 family).
    pub push_neutralized: Option<i64>,
    /// Ghidra `FuncCallSpecs::inputConsume` (fspec.hh:1660): per input slot, how many BYTES of the
    /// argument this callee actually consumes — 0 meaning "no information". Written only by
    /// `RulePiecePathology` (ruleaction.cc:10521), which discovers that a wide argument's high
    /// bytes are pathological garbage, and read by the dead-code consume sweep
    /// (coreaction.cc:3857) to clamp what the argument is considered to consume.
    ///
    /// Indexed by CALL input slot, so slot 0 (the call target) is never used.
    pub input_consume: Vec<u32>,
    /// Ghidra `FuncCallSpecs::stackPlaceholderSlot` (fspec.hh:1652): which CALL input slot holds the
    /// artificial stack-pointer tracker. `None` is Ghidra's `-1` (unused/released).
    pub stack_placeholder_slot: Option<usize>,
    /// Whether [`reads`](Self::reads) came from the callee's own DECOMPILE (the whole-program
    /// prototype pass) rather than from the straight-line scan. The two are different grades of
    /// evidence and one consumer must tell them apart: the stack-placeholder anchor
    /// ([`create_placeholder`]) corrects the placeholder's binding only where a recovered
    /// prototype will consume the resolved offset, because there the prototype itself caps the
    /// argument list and a spurious saved-slot trial stays unused. Scan-grade reads get the
    /// historical geometry, whose non-resolving placeholder is what the measured baseline is
    /// built on.
    pub reads_recovered: bool,
    /// Registers this callee OVERWRITES that the default convention calls `<unaffected>` —
    /// recovered from the callee's own body, per call site.
    ///
    /// `<unaffected>` is a property of the DEFAULT model, and in this binary it is a per-function
    /// property: Watcom's `modify` list is set per translation unit by `#pragma aux`, and hand
    /// written assembly obeys whatever contract its callers were built against. 264 functions
    /// across 245 measured on WAR2 write EBX/ESI/EDI/EBP and never restore them.
    ///
    /// Believing the default model at such a call site is wrong code, not a cosmetic difference:
    /// `guardCalls` emits no guard for an unaffected register, so the caller's PRE-call value
    /// flows across untouched and every later use reads a stale value. Measured on WAR2
    /// FUN_000748fd, whose callee returns a new pointer in EBX:
    ///
    /// ```text
    ///   original   call FUN_00074744 ; mov BYTE PTR [ebx],al   <- stores through the RESULT
    ///   mosura     func_0x00074744(...); *pxStack00000004 = ... <- stores through the STALE ptr
    /// ```
    ///
    /// Ghidra has the same defect and cannot fix it: it recovers a prototype from one function in
    /// isolation, so nothing inside the callee is visible while the caller is decompiled. Asked
    /// through the whole-image wrapper it emits the same truncated callee. This is therefore a
    /// deliberate `beyond-ghidra` extension, licensed by that measurement — see
    /// war2-survey/PLAN-register-effects.md.
    pub overwrites: Vec<(Address, u32)>,

    /// Every register offset the callee writes anywhere in its reachable body, or `None` when that
    /// could not be established (`analysis::decompiler::callee_writes_cfg`). Unlike
    /// [`Self::overwrites`] — a straight-line UPGRADE list — this is complete over the callee's
    /// CFG, so absence from it is sound evidence the callee NEVER writes the register.
    pub writes_all: Option<Vec<u64>>,
    /// The registers this callee READS BEFORE WRITING — its actual input storage, recovered from
    /// its own body. The input-side twin of [`Self::overwrites`], and the other half of the
    /// per-call prototype: Ghidra's `FuncCallSpecs` extends `FuncProto`, which owns BOTH parameter
    /// lists, so a callee whose convention differs from the model is describable rather than
    /// patchable one query at a time.
    ///
    /// `None` means NO EVIDENCE — the body scan hit a branch or call and stopped, so nothing is
    /// claimed and the default convention decides alone. `Some` is a closed list: a register
    /// outside it is not an argument however live it looks at the call site, which is what stops
    /// every caller-live register in the convention's parameter set becoming a spurious argument.
    pub reads: Option<Vec<(Address, u32)>>,
    /// The callee's ACTUAL read widths per recovered parameter (`FuncProto::params[i].size`),
    /// PARALLEL to `reads` but UN-widened: `reads` rounds a register param up to the entry width
    /// (the caller writes the whole register), while this keeps the byte/word the callee's own TU
    /// declares. Consumed by printc's N1 (declare a constant-join local at its consumer's width).
    pub param_widths: Option<Vec<u32>>,
}

impl CallSpec {
    /// Ghidra `FuncCallSpecs::getInputBytesConsumed` (fspec.cc:5870): bytes consumed at this slot,
    /// or 0 for "unknown" (including any slot past what has been recorded).
    pub fn input_bytes_consumed(&self, slot: usize) -> u32 {
        self.input_consume.get(slot).copied().unwrap_or(0)
    }

    /// Ghidra `FuncCallSpecs::setInputBytesConsumed` (fspec.cc:5887): record that only `val` bytes
    /// of this slot are consumed. **Only ever shrinks** — a wider claim than one already recorded is
    /// discarded — and returns whether anything changed, which is what lets the rule count a change
    /// and the pool re-run.
    pub fn set_input_bytes_consumed(&mut self, slot: usize, val: u32) -> bool {
        if self.input_consume.len() <= slot {
            self.input_consume.resize(slot + 1, 0);
        }
        let old = self.input_consume[slot];
        if old == 0 || val < old {
            self.input_consume[slot] = val;
            return true;
        }
        false
    }
}

/// Ghidra `ParamActive` (fspec.hh:285): the set of trials accumulated while recovering one
/// direction's parameters, plus the pass bookkeeping.
#[derive(Clone, Debug, Default)]
pub struct ParamActive {
    /// Ghidra `FuncCallSpecs::isinputactive` (fspec.hh:1658): is input-parameter recovery still
    /// running for this call?
    ///
    /// It is a FLAG, not the container's existence, and that distinction is load-bearing. Ghidra's
    /// `clearActiveInput` (fspec.hh:1696) sets `isinputactive = false` and leaves the trials in
    /// place, so a call can be re-opened later with everything it learned. mosura used to DELETE
    /// the container on commit, which made re-opening impossible — see
    /// [`Funcdata::reopen_input`](super::funcdata::Funcdata::reopen_input).
    pub active: bool,
    pub trial: Vec<ParamTrial>,
    /// The register space (so `register_trial` can auto-mark register trials killedbycall).
    reg_space: Option<SpaceId>,
    /// True when recovering a sub-function CALL's parameters (vs. this function's own inputs);
    /// gates the stack-reuse special case in `force_inactive_chain`.
    pub is_recover_subcall: bool,
    /// Ghidra `ParamActive::numpasses` (fspec.hh:289): how many evaluation passes have completed.
    numpasses: i32,
    /// Ghidra `ParamActive::maxpass` (fspec.hh:290): passes to make before assuming all trials are
    /// seen. The structural commit (`build_*_from_trials`) is deferred until `numpasses > maxpass`,
    /// so trials accumulate across heritage/simplification passes instead of being pruned greedily.
    maxpass: i32,
    /// Ghidra `ParamActive::isfullychecked` (fspec.hh:291): all trials examined, no new ones expected.
    isfullychecked: bool,
    /// Ghidra `ParamActive::needsfinalcheck` (fspec.hh:292): should a final pass be made on trials
    /// (to take into account control-flow changes).
    needsfinalcheck: bool,
    /// Ghidra `ParamActive::stackplaceholder` (fspec.hh:288): which CALL input slot holds the stack
    /// placeholder. `-1` = none yet, `-2` = it has been found and released (Ghidra's
    /// `freePlaceholderSlot` sentinel). Ghidra's companion `slotbase` is deliberately NOT ported:
    /// it exists to PREDICT the input index a trial will land on, and mosura's callers read the
    /// index back off the op after appending, which is the same number by construction.
    stackplaceholder: i32,
}

impl ParamActive {
    /// Ghidra `ParamActive::splitTrial` (fspec.cc:2033): replace trial `i` with two trials — the
    /// first `sz` bytes and the remainder — and push every later slot up by one.
    ///
    /// Panics where Ghidra throws: the stack placeholder must have been recovered first, because
    /// splitting renumbers the slots the placeholder is tracked by.
    ///
    /// Ghidra also bumps its `slotbase` here; mosura deliberately does not carry `slotbase` (it
    /// exists to PREDICT the input index a trial lands on, and mosura's callers read the index
    /// back off the op instead — the same number by construction).
    pub fn split_trial(&mut self, i: usize, sz: u32) {
        assert!(
            self.stackplaceholder < 0,
            "cannot split parameter when the placeholder has not been recovered"
        );
        let slot = self.trial[i].slot;
        let mut newtrials: Vec<ParamTrial> = Vec::with_capacity(self.trial.len() + 1);
        let bump = |t: &ParamTrial| {
            let mut t = t.clone();
            if t.slot > slot {
                t.slot += 1;
            }
            t
        };
        for t in &self.trial[..i] {
            newtrials.push(bump(t));
        }
        newtrials.push(self.trial[i].split_hi(sz));
        newtrials.push(self.trial[i].split_lo(self.trial[i].size - sz));
        for t in &self.trial[i + 1..] {
            newtrials.push(bump(t));
        }
        self.trial = newtrials;
    }

    pub fn new(reg_space: Option<SpaceId>) -> ParamActive {
        ParamActive {
            active: true,
            trial: Vec::new(),
            reg_space,
            is_recover_subcall: false,
            numpasses: 0,
            maxpass: 0,
            isfullychecked: false,
            needsfinalcheck: false,
            stackplaceholder: -1,
        }
    }

    /// Ghidra `ParamActive::setPlaceholderSlot` (fspec.hh:310): record which CALL input slot the
    /// artificial stack-pointer tracker occupies.
    pub fn set_placeholder_slot(&mut self, slot: usize) {
        self.stackplaceholder = slot as i32;
    }

    /// Ghidra `ParamActive::freePlaceholderSlot` (fspec.cc:1995): the placeholder input has been
    /// removed from the CALL, so every trial sitting at a HIGHER input slot shifts down one.
    ///
    /// ⭐ AND `maxpass = 0`, which is not bookkeeping — it is the point of the whole mechanism.
    /// Ghidra's comment: "If we've found the placeholder, then the -next- time we analyze
    /// parameters, we will have given all locations the chance to show up, so we prevent any
    /// analysis after -next-." Resolving the placeholder is what tells the decompiler the stack
    /// offset, which is what lets `guardCalls` register the STACK trials; once those exist there is
    /// nothing further to wait for, so the argument list commits on the very next
    /// `ActionActiveParam` instead of burning the remaining passes. That is what keeps the commit
    /// EARLY ENOUGH for the narrowing rules to still have something to narrow (task #9).
    pub fn free_placeholder_slot(&mut self) {
        for t in &mut self.trial {
            if t.op_slot as i32 > self.stackplaceholder {
                t.op_slot -= 1;
            }
        }
        self.stackplaceholder = -2;
        self.maxpass = 0;
    }

    pub fn num_trials(&self) -> usize {
        self.trial.len()
    }

    /// Ghidra `ParamActive::getNumPasses` (fspec.hh:312).
    pub fn get_num_passes(&self) -> i32 {
        self.numpasses
    }
    /// Ghidra `ParamActive::getMaxPass` (fspec.hh:313).
    pub fn get_max_pass(&self) -> i32 {
        self.maxpass
    }
    /// Ghidra `ParamActive::setMaxPass` (fspec.hh:314).
    pub fn set_max_pass(&mut self, val: i32) {
        self.maxpass = val;
    }
    /// Ghidra `ParamActive::finishPass` (fspec.hh:315): record that an evaluation pass completed.
    pub fn finish_pass(&mut self) {
        self.numpasses += 1;
    }
    /// Ghidra `ParamActive::isFullyChecked` (fspec.hh:308).
    pub fn is_fully_checked(&self) -> bool {
        self.isfullychecked
    }
    /// Ghidra `ParamActive::needsFinalCheck` / `markNeedsFinalCheck` (fspec.hh:303-304).
    pub fn needs_final_check(&self) -> bool {
        self.needsfinalcheck
    }
    pub fn mark_needs_final_check(&mut self) {
        self.needsfinalcheck = true;
    }
    /// Ghidra `ParamActive::markFullyChecked` (fspec.hh:309).
    pub fn mark_fully_checked(&mut self) {
        self.isfullychecked = true;
    }

    /// Ghidra `ParamActive::registerTrial` (fspec.cc:1963): add a trial, returning its index. A
    /// *register* trial is auto-marked `killedbycall` (a call would overwrite it); a stack trial
    /// is not.
    pub fn register_trial(&mut self, addr: Address, size: u32) -> usize {
        let mut t = ParamTrial::new(addr, size);
        if Some(addr.space) == self.reg_space {
            t.flags |= trial_flags::KILLEDBYCALL;
        }
        self.trial.push(t);
        self.trial.len() - 1
    }

    /// Ghidra `ParamActive::whichTrial` (fspec.cc:1982): the index of the first trial overlapping
    /// `[addr,addr+sz)`, or `None`. Used by `Heritage::guardCalls` to avoid registering a second
    /// trial for a range some earlier heritage pass already registered (heritage.cc:1499).
    pub fn which_trial(&self, addr: Address, sz: u32) -> Option<usize> {
        self.trial.iter().position(|t| {
            t.addr.space == addr.space
                && addr.offset < t.addr.offset + t.size as u64
                && t.addr.offset < addr.offset + sz as u64
        })
    }

    /// Ghidra `ParamActive::deleteUnusedTrials` (fspec.cc:2013): drop every trial that `fillin_map`
    /// did not mark `used` and renumber the survivors' slots 1, 2, … — the trial list is now the
    /// committed argument list, so a trial's slot again names where its varnode sits on the op.
    pub fn delete_unused_trials(&mut self) {
        self.trial.retain(|t| t.is_used());
        for (i, t) in self.trial.iter_mut().enumerate() {
            t.op_slot = (i + 1) as u32;
        }
    }

    /// Ghidra `ParamActive::sortTrials`: order trials into formal-parameter order — a trial that
    /// matched NO entry sinks below every matched one (`ParamTrial::operator<`, fspec.cc:1894-1895),
    /// then by matched group, then by entry, then by address (fspec.cc:1896-1912). The entry-less
    /// rule is load-bearing: it is what lets `buildReturnOutput`/`buildOutputFromTrials` stop at the
    /// first not-used trial and still see every used one.
    pub fn sort_trials(&mut self) {
        self.trial.sort_by(|a, b| {
            a.entry
                .is_none()
                .cmp(&b.entry.is_none())
                .then(a.slot.cmp(&b.slot))
                .then(a.entry.cmp(&b.entry))
                .then(a.addr.space.0.cmp(&b.addr.space.0))
                .then(a.addr.offset.cmp(&b.addr.offset))
                .then(a.size.cmp(&b.size))
        });
    }
}

// ---- Recovered prototype + drivers ------------------------------------------------------------

/// One recovered parameter or return slot: its storage and size. (Types are recovered separately
/// by the type-inference pass; a storage slot defaults to `undefined<size>`.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtoSlot {
    pub addr: Address,
    pub size: u32,
}

/// Ghidra `FuncProto` (fspec.hh:1343) — the recovered function prototype, reduced to the storage
/// surface A6's parameter-ID consumes: the ordered input parameters and the return storage.
#[derive(Clone, Debug, Default)]
pub struct FuncProto {
    pub params: Vec<ProtoSlot>,
    /// Return storage; `None` is a void return.
    pub output: Option<ProtoSlot>,
}

/// Ghidra `ActionInputPrototype` (coreaction.cc:4707): recover the function's input parameters
/// from its input varnodes — a trial per input varnode whose storage is a possible parameter,
/// marked active when the varnode is used (`!hasNoDescend()`), resolved by the convention's
/// `fillin_map`. A used-but-never-written input register (a pure pass-through parameter) is kept,
/// which the older realism heuristic dropped.
pub fn recover_input_params(f: &Funcdata) -> Vec<ProtoSlot> {
    let Some(reg) = f.spaces.by_name("register") else { return Vec::new() };
    let Some(pl) = f.proto_model.input.as_ref() else { return Vec::new() };
    let mut active = ParamActive::new(Some(reg));
    for i in 0..f.num_varnodes() as u32 {
        let vn = f.vn(VarnodeId(i));
        if !vn.is_input() {
            continue;
        }
        let size = vn.size;
        if !pl.possible_param(vn.loc, size) {
            continue;
        }
        let ti = active.register_trial(vn.loc, size);
        if !vn.descend.is_empty() {
            active.trial[ti].mark_active();
        }
    }
    // A STACK-BASED function has no register arguments at all, and under a register convention the
    // empty register slots ahead of the stack entry read as HOLES: `build_trial_map` synthesizes
    // unref trials for them and `force_inactive_chain` (maxchain=2) latches on the run and marks
    // every later trial inactive — the real stack trial included. That chain rule is a faithful
    // port of Ghidra's `fspec.cc:1111` and must not be weakened.
    //
    // The holes are an artefact of asking the WRONG LIST. When the evidence says this function
    // takes no register arguments (no register input is even a possible parameter) but does take a
    // stack one, the convention in force is the stack-based variant — Watcom spells it
    // `#pragma aux ... parm []`, and warcraft2-re's proven sources use exactly that for these
    // functions. Ask that list instead and there is no hole for the rule to fire on.
    //
    // Measured on the `stackarg` MVE (`mov eax,[esp+4] ; inc eax ; ret 4`), which came back
    // `(void)` with the parameter rendered as an unassigned local.
    // STRICTLY ADDITIVE. This is beyond-Ghidra evidence, so it may only ADD a prototype where the
    // convention found none — never re-decide one it already recovered. Without that guard it also
    // fired on SysV functions whose parameters are legitimately on the stack (`long double` is
    // passed there), and the `longdouble` corpus fixture dropped 1.000 -> 0.976.
    // A CUSTOM REGISTER CONVENTION, collected once and APPENDED to whatever the convention itself
    // recovers. The body reads these registers without ever writing them, so their values come from
    // the caller and they are parameters, whatever list the model holds. Watcom spells it
    // `#pragma aux <name> parm [<regs>]`, the same mechanism the stack-only branch below uses.
    //
    // FUN_00010ac2 takes BOTH its arguments this way (ESI and EDI) and came back `void f(void)`
    // with both pointers left as declared-but-never-assigned locals that the body then
    // dereferenced. FUN_00010010 is the mixed case: EAX and EDX by the convention, plus ESI/EDI as
    // the operands of its `rep movs`, which the caller must have set. 603 emitted WAR2 TUs carry
    // such a local and none are byte-clean.
    //
    // STRICTLY ADDITIVE: it only ever ADDS storage the convention did not claim, never re-decides
    // what it did. Ordered by register offset so the result is deterministic.
    let mut custom: Vec<ProtoSlot> = Vec::new();
    for i in 0..f.num_varnodes() as u32 {
        // Only a compiler with per-function conventions can have put a parameter there
        // (`ProtoModel::custom_conventions`). Under SysV the same read is the varargs `AL`
        // count or a stale scratch register, never an argument.
        if !f.proto_model.custom_conventions {
            break;
        }
        let vn = f.vn(VarnodeId(i));
        if !vn.is_input() || vn.loc.space != reg || vn.descend.is_empty() {
            continue;
        }
        if f.spaces.space_by_spacebase(vn.loc, vn.size).is_some() || pl.possible_param(vn.loc, vn.size) {
            continue;
        }
        // Is this register's incoming value used for ANYTHING other than being saved? A register
        // that is merely preserved has exactly one use — the COPY into its stack slot — while a
        // parameter is used in real computation.
        //
        // "Saved and restored" alone is NOT a disqualifier, which is what the earlier version of
        // this got wrong: a parameter that arrives in a callee-saved register is saved too, because
        // the convention says preserve it. FUN_00010bb1 takes EDI and ESI, saves both, and computes
        // `*(int2 *)(edi + 4) = si - …`; excluding on the save alone left it `void f(void)` with two
        // undefined locals. The dataflow separates the cases cleanly and needs no walk, so it also
        // covers the functions where `callee_writes_cfg` bails (any indirect call).
        let only_saved = !vn.descend.is_empty()
            && vn.descend.iter().all(|&d| {
                f.op(d).code() == OpCode::Copy
                    && f.op(d).output.is_some_and(|o| {
                        f.spaces.get(f.vn(o).loc.space).kind == super::space::SpaceKind::Spacebase
                    })
            });
        if only_saved {
            continue;
        }
        // When the save/restore walk could not run (`own_saved` is None — an indirect branch, an
        // unresolvable target, budget), there is NO evidence either way, and admitting a
        // conventionally callee-saved register on no evidence is how EBP became a "parameter".
        // Watcom rejects it outright: `E1122: Illegal register modified by '<name>' #pragma`, which
        // fails the whole translation unit. Two TUs still hit that after the modify-list fix,
        // because the frame pointer was in their `parm` list rather than their `modify` list.
        //
        // The frame and stack pointers are never argument storage under any Watcom convention, so
        // they are excluded unconditionally; the other callee-saved registers are excluded only
        // when there is no evidence to the contrary.
        let callee_saved = f
            .proto_model
            .effectlist
            .iter()
            .any(|e| e.space == reg && e.offset == vn.loc.offset && e.effect == effect::UNAFFECTED);
        let _ = callee_saved;

        // Flags and other status bits are not argument storage.
        if vn.size > 4 || pl.entry.iter().all(|e| e.space != vn.loc.space || vn.loc.offset >= 0x100) {
            continue;
        }
        if !custom.iter().any(|p| p.addr == vn.loc) {
            custom.push(ProtoSlot { addr: vn.loc, size: vn.size });
        }
    }
    custom.sort_by_key(|p| p.addr.offset);

    let mut default_run = active.clone();
    pl.fillin_map(&mut default_run);
    // INSTRUMENT (`MOSURA_PROTO=1`): 579 emitted WAR2 TUs declare a local that is never assigned
    // and none are byte-clean; several are DROPPED PARAMETERS (FUN_0004d95c uses EDX and EBX,
    // recovers only EAX). Which rule drops a trial is a measurement, not a guess.
    if crate::debug::on(crate::debug::Topic::Args) {
        for t in &default_run.trial {
            debug!(crate::debug::Topic::Args,
                "trial {:#x}/{} active={} used={} unref={} dnu={} entry={:?}",
                t.addr.offset, t.size, t.is_active(), t.is_used(), t.is_unref(),
                t.is_definitely_not_used(), t.entry
            );
        }
    }
    if default_run.trial.iter().any(|t| t.is_used()) {
        let mut out: Vec<ProtoSlot> = default_run
            .trial
            .iter()
            .filter(|t| t.is_used())
            .map(|t| ProtoSlot { addr: t.addr, size: t.size })
            .collect();
        out.extend(custom);
        return out;
    }
    // A register trial disqualifies the stack-based reading only when it is ACTIVE -- an input
    // varnode with actual reads. A present-but-inactive trial is an input varnode NOBODY READS:
    // heritage's call guards manufacture entry-value varnodes (a passthrough INDIRECT's `before`
    // at the first call IS the entry value), and a later-deleted chain leaves them floating with
    // no descend. That is not evidence of a register argument. Measured on WAR2's FUN_0006c6f0
    // (1,963 B): its two stack arguments read throughout the body, its four register trials all
    // inactive -- and their mere presence kept this branch from firing, so the prototype came out
    // `void(void)` with the arguments declared as uninitialized locals (`iStack00000004`).
    let any_reg_param = active.trial.iter().any(|t| t.addr.space == reg && t.is_active());
    let stack_only = !any_reg_param && active.num_trials() > 0;
    if stack_only {
        let entries: Vec<ParamEntry> = pl.entry.iter().filter(|e| e.space != reg).cloned().collect();
        // The kept entries retain their ORIGINAL group numbers (the stack overflow slot is group 4
        // in the watcom list), and `separate_sections` indexes `resource_start[1]` as the sentinel
        // for "past the last group" — so it must exceed the largest group present, not the entry
        // count. A `[0, 1]` sentinel indexes off the end of the section table.
        let sentinel = entries.iter().map(|e| e.group).max().map_or(1, |g| g + 1);
        let stack_list = ParamList {
            entry: entries,
            resource_start: vec![0, sentinel],
            is_output: false,
        };
        if !stack_list.entry.is_empty() {
            let mut restaged = active.clone();
            stack_list.fillin_map(&mut restaged);
            if restaged.trial.iter().any(|t| t.is_used()) {
                return restaged
                    .trial
                    .iter()
                    .filter(|t| t.is_used())
                    .map(|t| ProtoSlot { addr: t.addr, size: t.size })
                    .collect();
            }
        }
    }
    pl.fillin_map(&mut active);
    let by_model: Vec<ProtoSlot> =
        active.trial.iter().filter(|t| t.is_used()).map(|t| ProtoSlot { addr: t.addr, size: t.size }).collect();

    // A CUSTOM REGISTER CONVENTION. The convention found nothing, yet the body reads registers it
    // never wrote — those values come from the caller and are parameters, whatever list the model
    // holds. Watcom spells it `#pragma aux <name> parm [<regs>]`, the same mechanism the stack-only
    // branch above uses.
    //
    // FUN_00010ac2 is the specimen: its arguments arrive in ESI and EDI, neither of which is in
    // watcall's `<input>` list (EAX/EDX/EBX/ECX/stack), so it came back `void f(void)` with both
    // pointers left as declared-but-never-assigned locals whose garbage values the body then
    // dereferenced. 603 emitted WAR2 TUs carry such a local and none are byte-clean.
    //
    // STRICTLY ADDITIVE, exactly like the stack-only branch: it may only ADD a prototype where the
    // convention recovered none, never re-decide one it already found. Ordered by register offset
    // so the recovered list is deterministic.
    // APPENDED, not substituted: the convention's own parameters keep their positions and order,
    // and the custom registers follow. A function can have both — FUN_00010010 takes EAX and EDX
    // by the convention AND reads ESI/EDI as the source/destination of its `rep movs`, which the
    // caller must have set; recovering only the first two left five undefined locals in its body.
    let mut out = by_model;
    out.extend(custom);
    out
}

/// Ghidra `ActionOutputPrototype` (coreaction.cc:4765): the return storage, read from the
/// realistic return value that return-recovery (`recover::resolve_return`) left on the RETURN ops.
/// `None` when every RETURN is void.
pub fn recover_output(f: &Funcdata) -> Option<ProtoSlot> {
    for op in f.op_ids() {
        let o = f.op(op);
        if o.code() == OpCode::Return && o.num_inputs() > 1 {
            let v = o.input(1)?;
            return Some(ProtoSlot { addr: f.vn(v).loc, size: f.vn(v).size });
        }
    }
    None
}

/// Ghidra `Funcdata::getFuncProto`: the recovered prototype (input params + return storage).
pub fn recover_func_proto(f: &Funcdata) -> FuncProto {
    FuncProto { params: recover_input_params(f), output: recover_output(f) }
}

// -------------------------------------------------------------------------------------------------
// The stack-pointer placeholder (Ghidra `FuncCallSpecs`, fspec.cc:4844-4920)
//
// A call site cannot register a STACK location as a parameter trial until it knows the stack
// pointer's offset AT THAT CALL, because a trial's address is expressed in the CALLEE's frame while
// heritage hands it the CALLER's (`Heritage::guardCalls`, heritage.cc:1461-1466). Ghidra measures
// that offset with an artificial extra CALL input: a 1-byte LOAD off a FREE reference to the
// spacebase register. Heritage links the free reference to whatever stack-pointer value reaches the
// call; the constant-folding rules collapse it to `<sp_input> + delta`; then `RuleLoadVarnode`
// recognises the spacebase form, converts the LOAD to a COPY of a fixed stack slot, and the
// `spacebase_placeholder` flag on its output fires this subsystem, whose whole job is to read
// `delta` back out and then delete the machinery it rode in on.
//
// mosura has no `FuncCallSpecs` object, so the per-call state lives in
// [`Funcdata::call_specs`](super::funcdata::Funcdata::call_specs) keyed by the CALL op, and these
// are free functions rather than methods. See [`CallSpec`].
// -------------------------------------------------------------------------------------------------

/// TEMPORARY INSTRUMENT (`MOSURA_PLACEHOLDER=1`): report each placeholder's fate, so the resolution
/// rate is measured rather than assumed. The whole subsystem is inert if the placeholders never
/// resolve, and that depends on the folding rules collapsing `(sp_input + delta) + 0` before the
/// stack pass clears them — a claim only the running pipeline can settle.
fn ph_log(ev: &str, call: OpId, extra: &str) {
    debug!(crate::debug::Topic::Args, "PH {ev} call={} {extra}", call.0);
}

/// Ghidra `FuncCallSpecs::getSpacebaseOffset` (fspec.hh:1689): the stack-pointer offset at `call`
/// relative to the incoming stack pointer, or `None` for Ghidra's `offset_unknown` — the state in
/// which `guardCalls` refuses to register a spacebase range as a trial.
pub fn spacebase_offset(f: &Funcdata, call: OpId) -> Option<u64> {
    f.call_specs.get(&call).and_then(|c| c.stackoffset)
}

/// Ghidra `FuncCallSpecs::setStackPlaceholderSlot` (fspec.hh:1671): record the slot, and tell the
/// trial container to reserve it so no trial claims that input index.
fn set_stack_placeholder_slot(f: &mut Funcdata, call: OpId, slot: usize) {
    f.call_specs.entry(call).or_default().stack_placeholder_slot = Some(slot);
    // Ghidra's `if (isinputactive)`; mosura's `isInputActive` is the presence of the call's entry.
    if let Some(active) = f.active_inputs.get_mut(&call) {
        active.set_placeholder_slot(slot);
    }
}

/// Ghidra `FuncCallSpecs::clearStackPlaceholderSlot` (fspec.hh:1673): release the slot and let the
/// trial container shift every higher trial down one (and reset its pass budget — see
/// [`ParamActive::free_placeholder_slot`], where that reset is the point).
fn clear_stack_placeholder_slot(f: &mut Funcdata, call: OpId) {
    if let Some(c) = f.call_specs.get_mut(&call) {
        c.stack_placeholder_slot = None;
    }
    if let Some(active) = f.active_inputs.get_mut(&call) {
        active.free_placeholder_slot();
    }
}

/// The extrapop INDIRECT `ActionExtraPopSetup` planted for `call`, if one exists: the nearest op
/// before `call` in its block, at the call's own address, that is an INDIRECT guarded by this call
/// and defines the stack-pointer spacebase register. `None` when extrapop modelling did not cover
/// this call.
fn extrapop_indirect_before(f: &Funcdata, call: OpId) -> Option<OpId> {
    let block = f.op(call).parent?;
    let ops = f.block(block).ops.clone();
    let pos = ops.iter().position(|&o| o == call)?;
    let pc = f.op(call).seqnum.pc;
    // The spacebase register (ESP) this function's stack space is based on.
    let stack = f.spaces.by_name("stack")?;
    let &(sb_addr, sb_size) = f.spaces.get(stack).spacebase.first()?;
    for i in (0..pos).rev() {
        let op = ops[i];
        if f.op(op).seqnum.pc != pc {
            break; // left the call instruction's op cluster
        }
        if f.op(op).code() == super::opcode::OpCode::Indirect
            && f.op(op).guarded_op() == Some(call)
            && f.op(op).output.is_some_and(|o| f.vn(o).loc == sb_addr && f.vn(o).size == sb_size)
        {
            return Some(op);
        }
    }
    None
}

/// Ghidra `FuncCallSpecs::createPlaceholder` (fspec.cc:4849): hang the artificial stack-pointer
/// tracker off `call` as an extra input — a 1-byte LOAD from offset 0 of `spacebase`, built off a
/// FREE spacebase-register reference so heritage resolves it to the value reaching this call site.
pub fn create_placeholder(f: &mut Funcdata, call: OpId, spacebase: SpaceId) {
    let slot = f.op(call).num_inputs();
    // The placeholder must bind the stack pointer BEFORE the call's extrapop INDIRECT, when
    // `ActionExtraPopSetup` has planted one (extrapop unknown -- watcall). Both are manufactured
    // ops inserted directly before the CALL, so whichever is created later sits closer to the call;
    // the INDIRECT is created first (pipeline setup), the placeholder after (and again on every
    // re-open round), so the placeholder's free stack-pointer read renames to the INDIRECT's
    // OUTPUT -- the post-call value the stack solver later resolves. The offset convention here
    // (`resolve_spacebase_relative`: pre-push binding, corrected by the return-address slot) was
    // derived on a graph with NO such INDIRECT, so a post-call binding records the offset one or
    // more slots high, every caller stack range translates below the parameter area, and the
    // trailing stack argument is silently dropped.
    //
    // Measured on WAR2's `FUN_00023514` under the prototype pass: with the INDIRECT present the
    // placeholder resolved off=-16 and recorded -20 (truth: -24); its 5th argument `PUSH 9`
    // vanished from the emitted call. Anchoring the placeholder before the INDIRECT restores the
    // same binding the no-INDIRECT graph produces, making the recorded offset invariant to whether
    // extrapop modelling covered the call -- which is what lets the recovered-prototype
    // configuration coexist with the placeholder machinery.
    //
    // Ghidra's geometry differs and is internally consistent the other way: its placeholder also
    // reads through the INDIRECT, but its stackoffset semantics are defined relative to that same
    // graph. mosura's binding rule already deviates (the placeholder is not ordered against the
    // call instruction's own push -- see `resolve_spacebase_relative`), and this keeps that
    // documented deviation SELF-consistent rather than coverage-dependent.
    // The corrected binding applies exactly where Ghidra's locked-prototype branch would need a
    // stack offset: a recovered prototype that NAMES STACK STORAGE (funcLinkInput's "Param is
    // stack relative" arm, coreaction.cc:1498). A register-only callee's arguments never touch
    // the stack, so resolving the offset at its calls buys nothing -- and it costs: resolution
    // enables stack-range trials at the call, and the caller's own saved-register slots translate
    // into the parameter window and survive realism (they are written, and they trace to real
    // inputs). Measured on WAR2's FUN_0001fdbc under the prototype pass: with the anchor applied
    // at its 63 register-only memset calls, 59 of them grew phantom stack arguments from the
    // caller's save slots, EXACT -> 0.522.
    // The corrected binding applies where a recovered prototype names STACK storage (Ghidra's
    // locked-branch condition, coreaction.cc:1498). The unconditional form was tried twice --
    // thread 4's endgame -- and both times cost the default configuration the same two functions
    // (FUN_000121e8, FUN_000485a0): with resolution live at every call, solver-guessed extrapop
    // deltas at multi-call functions drift the recorded offsets, and mis-windowed stack slots
    // become trials. Recovered per-call extrapop (CallSpec::extrapop) removes the INDIRECT at
    // known-cleanup calls entirely, which is the road to retiring this gate.
    let stack_param = f.call_specs.get(&call).is_some_and(|c| {
        c.reads_recovered
            && c.reads.as_ref().is_some_and(|r| {
                r.iter().any(|(a, _)| f.spaces.get(a.space).kind == super::space::SpaceKind::Spacebase)
            })
    });
    let anchor = if stack_param { extrapop_indirect_before(f, call).unwrap_or(call) } else { call };
    // Ghidra passes `(Varnode *)0` for the stack reference and `false` for insertafter.
    let Some(loadval) = f.op_stack_load(spacebase, 0, 1, anchor, None, false) else { return };
    f.op_append_input(call, loadval); // Ghidra `opInsertInput(op,loadval,slot)` with slot == numInput
    set_stack_placeholder_slot(f, call, slot);
    f.vn_mut(loadval).set_spacebase_placeholder();
    ph_log("create", call, &format!("slot={slot}"));
}

/// Ghidra `FuncCallSpecs::resolveSpacebaseRelative` (fspec.cc:4870): read the stack-pointer offset
/// at `call` off the now-resolved placeholder. `phvn` is the placeholder varnode, which
/// `RuleLoadVarnode` has just turned into the output of a COPY from a fixed stack varnode — so the
/// COPY's input names the offset directly.
///
/// Ghidra's two branches after recording the offset are: the placeholder is still in its own slot ⇒
/// [`abort_spacebase_relative`] tears it down (the offset is all it was for); or the prototype is
/// input-locked and a locked STACK parameter carried the flag instead, in which case the offset is
/// taken relative to that parameter's address. mosura's call prototypes are never input-locked
/// (`build_input_from_trials` documents the same gap), so only the first branch is reachable and the
/// locked branch is not ported — Ghidra's fall-through there is a `LowlevelError` throw, and
/// reaching it would mean locked prototypes had appeared without this being revisited.
pub fn resolve_spacebase_relative(f: &mut Funcdata, call: OpId, phvn: VarnodeId) {
    let Some(def) = f.vn(phvn).def else { return };
    let Some(refvn) = f.op(def).input(0) else { return };
    let loc = f.vn(refvn).loc;
    // Ghidra warns "This function may have set the stack pointer" when the resolved reference is not
    // in a spacebase space; mosura models no warning header, so the diagnostic is dropped (the
    // offset is still recorded, exactly as Ghidra does after warning).
    // Ghidra's `stackoffset` is the stack pointer AT THE CALL OP. On x86 the call instruction
    // pushes its own return address first — the p-code is `INT_SUB ESP,4 ; STORE ; CALL` — so the
    // value Ghidra records already includes that push, and a stack argument then translates into
    // the callee's frame at the convention's stack `<pentry>` offset (`+4` for `__watcall`, i.e.
    // just past the return address).
    //
    // mosura's placeholder binds its free spacebase reference to the PRE-push stack pointer: the
    // manufactured ops take the CALL's own `SeqNum`, so they are not ordered against the same
    // instruction's `INT_SUB`. Every stack range therefore translated one slot too high and matched
    // no entry, so no stack argument was ever registered as a trial.
    //
    // Worked example, `FUN_000190bc`. Its prologue pushes EBX, ECX, EDX, EBP and then the argument
    // `PUSH 0x2c8c4`, so the stack pointer at the call is -24 and the argument sits at -20. We
    // recorded -20, translating the argument to +0 — below the parameter area — and dropped it.
    // Ghidra, asked about the same function, emits `FUN_0004245c(0x2c8c4)`.
    //
    // Correcting the recorded offset by the return address restores Ghidra's semantics for every
    // consumer at once, rather than each of them compensating. The size comes from the space's own
    // address size, not from the `stackshift` cspec attribute — Ghidra parses that attribute and
    // deliberately ignores it ("Allow this attribute for backward compatibility", fspec.cc:2580),
    // so keying on it would diverge from the reference.
    let return_address = f.spaces.get(loc.space).addr_size as u64;
    let at_call_op = loc.offset.wrapping_sub(return_address);
    f.call_specs.entry(call).or_default().stackoffset = Some(at_call_op);
    ph_log("resolve", call, &format!("off={:#x} at_call_op={at_call_op:#x}", loc.offset));

    if let Some(slot) = f.call_specs.get(&call).and_then(|c| c.stack_placeholder_slot) {
        if f.op(call).input(slot) == Some(phvn) {
            abort_spacebase_relative(f, call);
        }
    }
}

/// Ghidra `FuncCallSpecs::abortSpacebaseRelative` (fspec.cc:4911): remove the placeholder input from
/// `call` and destroy the op that produced it. Called both on success (the offset has been read, the
/// tracker has served its purpose) and from [`super::heritage::clear_stack_placeholders`] when the
/// stack space is about to be heritaged with the placeholder still unresolved.
pub fn abort_spacebase_relative(f: &mut Funcdata, call: OpId) {
    let Some(slot) = f.call_specs.get(&call).and_then(|c| c.stack_placeholder_slot) else { return };
    ph_log(
        if spacebase_offset(f, call).is_some() { "abort-resolved" } else { "abort-UNRESOLVED" },
        call,
        "",
    );
    let vn = f.op(call).input(slot);
    f.op_remove_input(call, slot);
    clear_stack_placeholder_slot(f, call);
    // Ghidra: remove the op producing the placeholder as well, but only if nothing else reads it and
    // it is a `unique`-space written value (i.e. really the manufactured LOAD/COPY, not a varnode the
    // rest of the graph depends on).
    if let Some(vn) = vn {
        let v = f.vn(vn);
        if v.descend.is_empty()
            && f.spaces.get(v.loc.space).kind == super::space::SpaceKind::Internal
            && v.is_written()
        {
            if let Some(def) = v.def {
                f.op_destroy(def);
            }
        }
    }
}

#[cfg(test)]
mod tests {

    /// `ParamTrial::splitHi`/`splitLo` carve a trial in two: the first `sz` bytes keep the slot,
    /// the remainder takes the next slot, and both inherit the flags (Ghidra fspec.cc:1845/1856).
    #[test]
    fn param_trial_splits_into_hi_and_lo() {
        let spaces = crate::decompile::space::SpaceManager::standard();
        let stack = spaces.by_name("stack").unwrap();
        let mut t = ParamTrial::new(Address::new(stack, 0x10), 8);
        t.slot = 3;
        t.flags |= trial_flags::ACTIVE;

        let hi = t.split_hi(4);
        assert_eq!((hi.addr.offset, hi.size, hi.slot), (0x10, 4, 3));
        let lo = t.split_lo(4);
        assert_eq!((lo.addr.offset, lo.size, lo.slot), (0x14, 4, 4), "lo starts past the hi part");
        assert_eq!(lo.flags & trial_flags::ACTIVE, trial_flags::ACTIVE, "flags are inherited");
    }

    /// `ParamActive::splitTrial` replaces the trial in place and pushes every LATER slot up by one,
    /// leaving earlier slots alone (Ghidra fspec.cc:2033).
    #[test]
    fn split_trial_renumbers_later_slots_only() {
        let spaces = crate::decompile::space::SpaceManager::standard();
        let stack = spaces.by_name("stack").unwrap();
        let mut a = ParamActive::new(None);
        for (off, slot) in [(0x08u64, 1u32), (0x10, 2), (0x18, 3)] {
            let mut t = ParamTrial::new(Address::new(stack, off), 8);
            t.slot = slot;
            a.trial.push(t);
        }
        a.split_trial(1, 4); // split the middle trial (slot 2)

        let slots: Vec<u32> = a.trial.iter().map(|t| t.slot).collect();
        assert_eq!(slots, vec![1, 2, 3, 4], "the split adds a slot and later trials shift up");
        let sizes: Vec<u32> = a.trial.iter().map(|t| t.size).collect();
        assert_eq!(sizes, vec![8, 4, 4, 8]);
        assert_eq!(a.trial[1].addr.offset, 0x10);
        assert_eq!(a.trial[2].addr.offset, 0x14);
    }

    /// `checkSplit` asks whether BOTH halves land on storage the convention uses; a cut at 0 or at
    /// the full size is not a split at all.
    #[test]
    fn check_split_requires_both_halves_to_be_parameters() {
        let spaces = crate::decompile::space::SpaceManager::standard();
        let stack = spaces.by_name("stack").unwrap();
        let mut pl = ParamList { entry: Vec::new(), resource_start: vec![0], is_output: false };
        pl.entry.push(ParamEntry {
            group: 0,
            type_class: 0,
            space: stack,
            addressbase: 0x10,
            size: 0x40,
            minsize: 1,
            alignment: 4,
        });
        let at = Address::new(stack, 0x10);
        assert!(pl.check_split(at, 8, 4), "two 4-byte halves both land in the stack entry");
        assert!(!pl.check_split(at, 8, 0), "a cut at 0 is not a split");
        assert!(!pl.check_split(at, 8, 8), "a cut at the full size is not a split");
    }

    /// `unjustifiedContainer` distinguishes Ghidra's three outcomes: not contained, contained and
    /// properly justified, contained but improperly justified (the only one needing adjustment).
    #[test]
    fn unjustified_container_three_outcomes() {
        let spaces = crate::decompile::space::SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let mut pl = ParamList { entry: Vec::new(), resource_start: vec![0], is_output: false };
        // One 8-byte register entry at register+0x20, accepting parameters of 1..=8 bytes.
        pl.entry.push(ParamEntry {
            group: 0,
            type_class: 0,
            space: reg,
            addressbase: 0x20,
            size: 8,
            minsize: 1,
            alignment: 0,
        });
        let at = |off: u64| Address::new(reg, off);

        // Outside the entry entirely.
        assert_eq!(pl.unjustified_container(at(0x40), 4), None, "not contained");
        // At the base — properly justified for little-endian, so nothing to do.
        assert_eq!(pl.unjustified_container(at(0x20), 4), None, "justified");
        // Partway in — improperly justified, so the whole entry is the container.
        assert_eq!(
            pl.unjustified_container(at(0x22), 2),
            Some((at(0x20), 8)),
            "unjustified sub-range returns the containing parameter storage"
        );
    }

    /// `minsize` gates the scan exactly as Ghidra's `getMinSize() > size` continue does.
    #[test]
    fn unjustified_container_respects_minsize() {
        let spaces = crate::decompile::space::SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let mut pl = ParamList { entry: Vec::new(), resource_start: vec![0], is_output: false };
        pl.entry.push(ParamEntry {
            group: 0,
            type_class: 0,
            space: reg,
            addressbase: 0x20,
            size: 8,
            minsize: 4,
            alignment: 0,
        });
        // A 2-byte range is below the entry's minimum, so the entry is skipped entirely.
        assert_eq!(pl.unjustified_container(Address::new(reg, 0x22), 2), None);
    }
    use super::*;
    use crate::decompile::space::SpaceManager;
    use crate::decompile::{OpCode, SeqNum};

    #[test]
    fn sysv_input_maps_registers_to_groups() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let pl = sysv_input(&spaces).unwrap();

        // RDI (int arg 0) → integer section, group 8.
        let (e, off) = pl.find_entry(Address::new(reg, RDI), 8).expect("RDI is a param");
        assert_eq!(e.group, 8);
        assert_eq!(e.type_class, type_class::GENERAL);
        assert_eq!(off, 0);

        // EDI: the low 4 bytes of RDI → same entry, justified offset 0 (little-endian).
        let (e4, off4) = pl.find_entry(Address::new(reg, RDI), 4).expect("EDI is a param");
        assert_eq!(e4.group, 8);
        assert_eq!(off4, 0);

        // XMM0 (float arg 0) → float section, group 0.
        let (xe, _) = pl.find_entry(Address::new(reg, XMM_BASE), 8).expect("XMM0 is a param");
        assert_eq!(xe.group, 0);
        assert_eq!(xe.type_class, type_class::FLOAT);

        // R9 → group 13 (last integer register).
        assert_eq!(pl.find_entry(Address::new(reg, R9), 8).unwrap().0.group, 13);
    }

    #[test]
    fn characterize_as_output_classifies_return_registers() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let out = sysv_output(&spaces).unwrap();
        // RAX:8 is exactly the integer return entry; EAX (its low 4) is justified within it.
        assert_eq!(out.characterize_as_param(Address::new(reg, RAX), 8), Containment::ContainsJustified);
        assert_eq!(out.characterize_as_param(Address::new(reg, RAX), 4), Containment::ContainsJustified);
        // RDX:8 is the second integer return entry.
        assert_eq!(out.characterize_as_param(Address::new(reg, RDX), 8), Containment::ContainsJustified);
        // RCX is volatile but not a return location.
        assert_eq!(out.characterize_as_param(Address::new(reg, RCX), 8), Containment::NoContainment);
    }

    #[test]
    fn sysv_input_maps_stack_overflow() {
        let spaces = SpaceManager::standard();
        let stack = spaces.by_name("stack").unwrap();
        let pl = sysv_input(&spaces).unwrap();
        // A 7th integer argument spills to the stack overflow area (group 14, non-exclusion).
        let (e, _) = pl.find_entry(Address::new(stack, 8), 8).expect("stack arg");
        assert_eq!(e.group, 14);
        assert_eq!(e.alignment, 8);
        // and the next slot indexes by alignment.
        assert_eq!(e.get_slot(Address::new(stack, 16), 0), 15);
    }

    #[test]
    fn non_param_storage_finds_no_entry() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let pl = sysv_input(&spaces).unwrap();
        // RBX (callee-saved, offset 0x18) is not a parameter register.
        assert!(pl.find_entry(Address::new(reg, 0x18), 8).is_none());
    }

    #[test]
    fn output_picks_rax_and_xmm0() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let pl = sysv_output(&spaces).unwrap();
        assert_eq!(pl.find_entry(Address::new(reg, RAX), 8).unwrap().0.group, 2);
        assert_eq!(pl.find_entry(Address::new(reg, XMM_BASE), 8).unwrap().0.group, 0);
    }

    #[test]
    fn sysv_effects_classify_registers() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let efflist = sysv_effect_list(&spaces);
        // caller-saved (killedbycall): RAX, RCX, RDX, RSI, RDI, XMM0 — clobbered across a call.
        for off in [RAX, RCX, RDX, RSI, RDI, XMM_BASE] {
            assert_eq!(lookup_effect(&efflist, Address::new(reg, off), 8), effect::KILLEDBYCALL, "off {off:#x}");
        }
        // a narrow sub-register read (EAX) is still within RAX's killedbycall record.
        assert_eq!(lookup_effect(&efflist, Address::new(reg, RAX), 4), effect::KILLEDBYCALL);
        // callee-saved (unaffected): RBX (0x18), RSP (0x20), RBP (0x28), R12 (0xa0).
        for off in [0x18u64, 0x20, 0x28, 0xa0] {
            assert_eq!(lookup_effect(&efflist, Address::new(reg, off), 8), effect::UNAFFECTED, "off {off:#x}");
        }
        // R10 (0x90) is neither a parameter nor explicitly listed ⇒ unknown.
        assert_eq!(lookup_effect(&efflist, Address::new(reg, 0x90), 8), effect::UNKNOWN_EFFECT);
        // the stack slot at offset 0 holds the return address.
        assert_eq!(lookup_effect(&efflist, Address::new(stack, 0), 8), effect::RETURN_ADDRESS);
    }

    #[test]
    fn register_trial_is_killed_by_call() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let mut active = ParamActive::new(Some(reg));
        active.register_trial(Address::new(reg, RDI), 8);
        active.register_trial(Address::new(stack, 8), 8);
        assert_ne!(active.trial[0].flags & trial_flags::KILLEDBYCALL, 0, "register trial killed by call");
        assert_eq!(active.trial[1].flags & trial_flags::KILLEDBYCALL, 0, "stack trial not killed by call");
    }

    /// Run `fillin_map` over a set of active register trials and return the offsets recovered as
    /// real (used) parameters, sorted.
    fn recover_params(offs: &[u64]) -> Vec<u64> {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let pl = sysv_input(&spaces).unwrap();
        let mut active = ParamActive::new(Some(reg));
        for &off in offs {
            let i = active.register_trial(Address::new(reg, off), 8);
            active.trial[i].mark_active();
        }
        pl.fillin_map(&mut active);
        let mut used: Vec<u64> =
            active.trial.iter().filter(|t| t.is_used()).map(|t| t.addr.offset).collect();
        used.sort_unstable();
        used
    }

    #[test]
    fn contiguous_int_params_all_used() {
        assert_eq!(recover_params(&[RDI, RSI]), vec![RSI, RDI]); // 0x30, 0x38
        assert_eq!(recover_params(&[RDI]), vec![RDI]);
        // float and integer sections are independent — both survive.
        assert_eq!(recover_params(&[RDI, XMM_BASE]), vec![RDI, XMM_BASE]);
    }

    #[test]
    fn interior_hole_is_filled() {
        // RDI + RDX used, RSI never referenced: Ghidra fills the hole (RSI becomes a param) so the
        // parameter list has no gap.
        assert_eq!(recover_params(&[RDI, RDX]), vec![RDX, RSI, RDI]); // 0x10, 0x30, 0x38
    }

    #[test]
    fn distant_lone_param_is_dropped() {
        // RDI used and R9 used with the whole RSI..R8 run absent: the inactive chain exceeds
        // maxchain=2, so R9 is dropped and only RDI remains.
        assert_eq!(recover_params(&[RDI, R9]), vec![RDI]);
    }

    /// A function with input varnodes at the given register offsets, each optionally given a use
    /// (a descendant op) so it counts as an active parameter. Carries the SysV `proto_model`
    /// [`recover_input_params`] reads; `None` (caller skips) when the Ghidra tree is absent.
    fn func_with_inputs(specs: &[(u64, bool)]) -> Option<Funcdata> {
        let pm = crate::decompile::build::test_sysv_proto_model()?;
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        f.proto_model = pm;
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        for &(off, used) in specs {
            let v = f.new_input(8, Address::new(reg, off));
            if used {
                let c = f.new_const(8, 1);
                f.new_op(OpCode::IntAdd, seq, vec![v, c]);
            }
        }
        Some(f)
    }

    #[test]
    fn recovers_used_input_params_in_order() {
        // RDI and RSI used → two params, in formal (group) order RDI then RSI.
        let Some(f) = func_with_inputs(&[(RDI, true), (RSI, true)]) else { return };
        let p = recover_input_params(&f);
        assert_eq!(p.iter().map(|s| s.addr.offset).collect::<Vec<_>>(), vec![RDI, RSI]);
    }

    #[test]
    fn pure_passthrough_param_is_recovered() {
        // An input register read (used) but never written is still a parameter — the case the
        // realism heuristic dropped (it required a real write).
        let Some(f) = func_with_inputs(&[(RDI, true)]) else { return };
        assert_eq!(recover_input_params(&f).len(), 1);
    }

    #[test]
    fn unused_trailing_input_is_not_a_param() {
        let Some(f) = func_with_inputs(&[(RDI, true), (RSI, false)]) else { return };
        let p = recover_input_params(&f);
        assert_eq!(p.iter().map(|s| s.addr.offset).collect::<Vec<_>>(), vec![RDI]);
    }

    #[test]
    fn recovers_return_storage() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let retaddr = f.new_input(8, Address::new(reg, 0x20));
        let rax = f.new_input(8, Address::new(reg, RAX));
        f.new_op(OpCode::Return, seq, vec![retaddr, rax]);
        assert_eq!(recover_output(&f).unwrap().addr.offset, RAX);
    }
}
