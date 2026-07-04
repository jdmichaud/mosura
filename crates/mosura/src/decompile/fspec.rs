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
use super::opcode::OpCode;
use super::space::{Address, SpaceId, SpaceManager};
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

    /// Ghidra `ParamEntry::justifiedContain` (fspec.cc:248): if `[addr,addr+sz)` lies within
    /// this entry (and `sz` is in `[minsize,size]`), return the little-endian-justified byte
    /// offset of the parameter within the entry; else `None`. For a register entry a parameter
    /// sits at the base (offset 0) and may be a low sub-register (e.g. `EDI` in `RDI`).
    pub fn justified_contain(&self, addr: Address, sz: u32) -> Option<u64> {
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
        // little-endian: justify to the least-significant bytes, i.e. offset from the base.
        Some(addr.offset - self.addressbase)
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
    /// Ghidra `ParamListStandard::findEntry` (fspec.cc:661): the first entry whose storage
    /// contains `[loc,loc+size)`, with its justified offset. Drives `possibleParam`.
    pub fn find_entry(&self, loc: Address, size: u32) -> Option<(&ParamEntry, u64)> {
        self.entry.iter().find_map(|e| e.justified_contain(loc, size).map(|off| (e, off)))
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
        self.build_trial_map(active);
        self.force_exclusion_group(active);
        let starts = self.separate_sections(active);
        let nsec = starts.len() - 1;
        for i in 0..nsec {
            self.force_no_use(active, starts[i], starts[i + 1]);
        }
        for i in 0..nsec {
            self.force_inactive_chain(active, 2, starts[i], starts[i + 1], self.resource_start[i]);
        }
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
                // Ghidra restricts this to stack (IPTR_SPACEBASE) params; only reached during
                // sub-call recovery, which isn't wired yet (is_recover_subcall == false here).
                if is_unref && is_subcall {
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

// ---- Trials -----------------------------------------------------------------------------------

/// Ghidra `ParamTrial` flag bits (fspec.hh:212). The subset the faithful recovery needs.
pub mod trial_flags {
    pub const CHECKED: u32 = 1; // the trial has been investigated
    pub const USED: u32 = 2; // final verdict: a real parameter
    pub const DEFNOUSE: u32 = 4; // definitely not used
    pub const ACTIVE: u32 = 8; // hint: written/used in dataflow (a likely parameter)
    pub const UNREF: u32 = 0x10; // synthesized to fill a hole — no backing varnode
    pub const KILLEDBYCALL: u32 = 0x20; // storage is overwritten by a call
    pub const ANCESTOR_REALISTIC: u32 = 0x100; // AncestorRealistic accepted it
    pub const ANCESTOR_SOLID: u32 = 0x200; // ...via a solid (real-movement) path
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
    pub fn is_definitely_not_used(&self) -> bool {
        self.flags & trial_flags::DEFNOUSE != 0
    }
    /// Record the matched entry (index into [`ParamList::entry`]) and its group (the sort key).
    fn set_entry(&mut self, idx: usize, group: u32) {
        self.entry = Some(idx);
        self.slot = group;
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
    pub fn mark_used(&mut self) {
        self.flags |= trial_flags::USED;
    }
}

/// Ghidra `ParamActive` (fspec.hh:285): the set of trials accumulated while recovering one
/// direction's parameters, plus the pass bookkeeping.
#[derive(Clone, Debug, Default)]
pub struct ParamActive {
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
}

impl ParamActive {
    pub fn new(reg_space: Option<SpaceId>) -> ParamActive {
        ParamActive { trial: Vec::new(), reg_space, is_recover_subcall: false, numpasses: 0, maxpass: 0, isfullychecked: false }
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

    /// Ghidra `ParamActive::sortTrials`: order trials into formal-parameter order — by matched
    /// group, then by address (`ParamTrial::operator<`, fspec.cc:1893).
    pub fn sort_trials(&mut self) {
        self.trial.sort_by(|a, b| {
            a.slot.cmp(&b.slot).then(a.addr.space.0.cmp(&b.addr.space.0)).then(a.addr.offset.cmp(&b.addr.offset))
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
    let Some(pl) = sysv_input(&f.spaces) else { return Vec::new() };
    let mut active = ParamActive::new(Some(reg));
    for i in 0..f.num_varnodes() as u32 {
        let vn = f.vn(VarnodeId(i));
        if !vn.is_input() {
            continue;
        }
        let size = vn.size as u32;
        if !pl.possible_param(vn.loc, size) {
            continue;
        }
        let ti = active.register_trial(vn.loc, size);
        if !vn.descend.is_empty() {
            active.trial[ti].mark_active();
        }
    }
    pl.fillin_map(&mut active);
    active.trial.iter().filter(|t| t.is_used()).map(|t| ProtoSlot { addr: t.addr, size: t.size }).collect()
}

/// Ghidra `ActionOutputPrototype` (coreaction.cc:4765): the return storage, read from the
/// realistic return value that return-recovery (`recover::resolve_return`) left on the RETURN ops.
/// `None` when every RETURN is void.
pub fn recover_output(f: &Funcdata) -> Option<ProtoSlot> {
    for op in f.op_ids() {
        let o = f.op(op);
        if o.code() == OpCode::Return && o.num_inputs() > 1 {
            let v = o.input(1)?;
            return Some(ProtoSlot { addr: f.vn(v).loc, size: f.vn(v).size as u32 });
        }
    }
    None
}

/// Ghidra `Funcdata::getFuncProto`: the recovered prototype (input params + return storage).
pub fn recover_func_proto(f: &Funcdata) -> FuncProto {
    FuncProto { params: recover_input_params(f), output: recover_output(f) }
}

#[cfg(test)]
mod tests {
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
    /// (a descendant op) so it counts as an active parameter.
    fn func_with_inputs(specs: &[(u64, bool)]) -> Funcdata {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        for &(off, used) in specs {
            let v = f.new_input(8, Address::new(reg, off));
            if used {
                let c = f.new_const(8, 1);
                f.new_op(OpCode::IntAdd, seq, vec![v, c]);
            }
        }
        f
    }

    #[test]
    fn recovers_used_input_params_in_order() {
        // RDI and RSI used → two params, in formal (group) order RDI then RSI.
        let f = func_with_inputs(&[(RDI, true), (RSI, true)]);
        let p = recover_input_params(&f);
        assert_eq!(p.iter().map(|s| s.addr.offset).collect::<Vec<_>>(), vec![RDI, RSI]);
    }

    #[test]
    fn pure_passthrough_param_is_recovered() {
        // An input register read (used) but never written is still a parameter — the case the
        // realism heuristic dropped (it required a real write).
        let f = func_with_inputs(&[(RDI, true)]);
        assert_eq!(recover_input_params(&f).len(), 1);
    }

    #[test]
    fn unused_trailing_input_is_not_a_param() {
        let f = func_with_inputs(&[(RDI, true), (RSI, false)]);
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
