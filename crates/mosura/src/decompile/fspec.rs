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

use super::space::{Address, SpaceId, SpaceManager};

/// Ghidra `type_class` (fspec.hh): the resource section a parameter draws from. System V keeps
/// the float and integer registers in separate sections so a used XMM and a used integer
/// register never force each other inactive (the `resourceStart` split, fspec.cc:946).
pub mod type_class {
    pub const GENERAL: u8 = 0; // TYPECLASS_GENERAL — integer/pointer registers + stack
    pub const FLOAT: u8 = 1; // TYPECLASS_FLOAT — XMM registers
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

    /// Ghidra `ParamEntry::getSlot` (fspec.cc:407): the slot index covering `addr`. Exclusion
    /// entries occupy exactly their `group`; non-exclusion (stack) entries index by alignment.
    pub fn get_slot(&self, addr: Address) -> u32 {
        if self.is_exclusion() {
            self.group
        } else {
            self.group + ((addr.offset - self.addressbase) / self.alignment as u64) as u32
        }
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
    Some(ParamList { entry, resource_start: vec![0, 8, 14], is_output: false })
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
    /// Index of the matched [`ParamEntry`] in the list, once `find_entry` succeeds.
    pub entry: Option<usize>,
    pub flags: u32,
}

impl ParamTrial {
    pub fn new(addr: Address, size: u32) -> ParamTrial {
        ParamTrial { addr, size, slot: 0, entry: None, flags: 0 }
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
}

impl ParamActive {
    pub fn new() -> ParamActive {
        ParamActive::default()
    }

    /// Ghidra `ParamActive::registerTrial` (fspec.cc:1963): add a trial. A *register* trial is
    /// auto-marked `killedbycall` (a call would overwrite it); a stack trial is not.
    pub fn register_trial(&mut self, addr: Address, size: u32, reg_space: Option<SpaceId>) {
        let mut t = ParamTrial::new(addr, size);
        if Some(addr.space) == reg_space {
            t.flags |= trial_flags::KILLEDBYCALL;
        }
        self.trial.push(t);
    }

    /// Ghidra `ParamActive::sortTrials`: order trials into formal-parameter order — by matched
    /// group, then by address (`ParamTrial::operator<`, fspec.cc:1893).
    pub fn sort_trials(&mut self) {
        self.trial.sort_by(|a, b| {
            a.slot.cmp(&b.slot).then(a.addr.space.0.cmp(&b.addr.space.0)).then(a.addr.offset.cmp(&b.addr.offset))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::SpaceManager;

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
    fn sysv_input_maps_stack_overflow() {
        let spaces = SpaceManager::standard();
        let stack = spaces.by_name("stack").unwrap();
        let pl = sysv_input(&spaces).unwrap();
        // A 7th integer argument spills to the stack overflow area (group 14, non-exclusion).
        let (e, _) = pl.find_entry(Address::new(stack, 8), 8).expect("stack arg");
        assert_eq!(e.group, 14);
        assert_eq!(e.alignment, 8);
        // and the next slot indexes by alignment.
        assert_eq!(e.get_slot(Address::new(stack, 16)), 15);
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
    fn register_trial_is_killed_by_call() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let mut active = ParamActive::new();
        active.register_trial(Address::new(reg, RDI), 8, Some(reg));
        active.register_trial(Address::new(stack, 8), 8, Some(reg));
        assert_ne!(active.trial[0].flags & trial_flags::KILLEDBYCALL, 0, "register trial killed by call");
        assert_eq!(active.trial[1].flags & trial_flags::KILLEDBYCALL, 0, "stack trial not killed by call");
    }
}
