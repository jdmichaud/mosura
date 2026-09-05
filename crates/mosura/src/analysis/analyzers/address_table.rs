//! `AddressTable` + `AddressTableAnalyzer` — a port of Ghidra's
//! `Features/Base/.../ghidra/app/plugin/core/disassembler/AddressTable.java` and
//! `.../AddressTableAnalyzer.java` ("Create Address Tables").
//!
//! # What this recovers
//!
//! A **run of consecutive pointers** stored in data. the subject reaches large parts of its code
//! through such tables: `<subject-survey>/analysis-gap/REPORT.md` §7 measured that mosura never
//! disassembles 24.7% of the code object (109,338 bytes in 23 regions >2KB), that 783 of the
//! 815 missing functions have no reference in mosura's reference set at all, and that the only
//! edges into those regions from outside are `DATA` (region `00039bd4` is entered by DATA×11).
//! Without a data-side analyzer those subgraphs are simply unreachable — which is why fixing
//! five flow-side seeds recovered exactly five functions.
//!
//! # What it does NOT do — and this is the point
//!
//! **It never creates a function.** `AddressTableAnalyzer.processAddressTable`
//! (AddressTableAnalyzer.java:282-297) builds `validFuncSet` and then leaves the
//! `mgr.createFunction` call commented out: *"For Now, Never make functions from address
//! tables"*. Its siblings agree — `OperandReferenceAnalyzer.createFunctions`
//! (OperandReferenceAnalyzer.java:614) and `DataOperandReferenceAnalyzer.createFunctions`
//! (:39) are both empty bodies, *"don't ever create functions from pointed to code"*.
//!
//! What it does is lay down the pointers and **disassemble** their targets. Functions then
//! appear the ordinary way: `FunctionAnalyzer` ("Subroutine References",
//! `plugin/core/function/FunctionAnalyzer.java:49`) creates one at every direct-call target
//! inside the newly decoded code — in mosura, [`Disassembler`](super::Disassembler) scheduling
//! `function_defined` for its call targets. Verified against Ghidra on
//! `oracle/ground-truth/datafnptr.watcom-x86-32`: Ghidra decodes all four handlers behind the
//! pointer table, creates **no** function at any of them, and does create `FUN_08048106` — the
//! helper one of them calls.
//!
//! # The guards that stop over-creation
//!
//! 1. `getEntry` accepts a run only if **every** value in it is a plausible pointer: non-zero,
//!    `>= MINIMUM_SAFE_ADDRESS`, inside mapped memory, not colliding with existing code, with
//!    no reference landing mid-table — and the run must reach `minimumTableSize`, which is
//!    derived from the image size by `getThresholdRunOfValidPointers` (a 1-in-a-billion
//!    false-positive budget), never chosen by hand.
//! 2. `checkTable` trims the table at the first entry that looks like a unicode string, sits
//!    below `minPointerAddress`, jumps further than `maxPointerDistance` from its neighbour, or
//!    points *offcut* into an existing code unit.
//! 3. `getFunctionEntries` + `processAddressTable`'s `validCodeList.size() >=
//!    getNumberAddressEntries()` (:267) — **all** targets must be valid code, judged by
//!    [`PseudoDisassembler::is_valid_code`], or nothing at all is disassembled.

use std::cell::Cell;

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::manager::Scheduling;
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, CodeUnit, Program, RefType};
use crate::analysis::pseudo_disassembler::PseudoDisassembler;
use crate::decompile::space::{Address, SpaceId};

/// `AddressTable.BILLION_CASES` (AddressTable.java:44).
const BILLION_CASES: f64 = (1024 * 1024 * 1024) as f64;
/// `AddressTable.TOO_MANY_ENTRIES` (:45).
const TOO_MANY_ENTRIES: i32 = 1024 * 1024;
/// `AddressTable.MINIMUM_SAFE_ADDRESS` (:46) — "default minimum address that should be
/// considered an address".
const MINIMUM_SAFE_ADDRESS: u64 = 1024;

/// `AddressTableAnalyzer.OPTION_DEFAULT_TABLE_ALIGNMENT` (AddressTableAnalyzer.java:69).
const OPTION_DEFAULT_TABLE_ALIGNMENT: u64 = 4;
/// `OPTION_DEFAULT_PTR_ALIGNMENT` (:70).
const OPTION_DEFAULT_PTR_ALIGNMENT: u64 = 1;
/// `OPTION_DEFAULT_MIN_POINTER_ADDR` (:74).
const OPTION_DEFAULT_MIN_POINTER_ADDR: u64 = 0x1024;
/// `OPTION_DEFAULT_MAX_POINTER_DIFF` (:75).
const OPTION_DEFAULT_MAX_POINTER_DIFF: u64 = 0xffffff;
/// `OPTION_DEFAULT_AUTO_LABEL_TABLE` (:71).
const OPTION_DEFAULT_AUTO_LABEL_TABLE: bool = false;
/// `OPTION_DEFAULT_RELOCATION_GUIDE_ENABLED` (:72).
const OPTION_DEFAULT_RELOCATION_GUIDE_ENABLED: bool = true;
/// `OPTION_DEFAULT_ALLOW_OFFCUT_REFERENCES` (:73).
const OPTION_DEFAULT_ALLOW_OFFCUT_REFERENCES: bool = false;

/// Longest x86-64 instruction — the `getCodeUnitContaining` back-probe window.
const MAX_INSN_LEN: u64 = 16;

/// Ghidra's `PointerDataType(DataType.DEFAULT, dtm).getName()` — the data type
/// `AddressTable.makeTable` lays on each entry. Confirmed against Ghidra's own dump of
/// `datafnptr.watcom-x86-32` (`DATA 08049000 undefined * len=4`).
const POINTER_TYPE_NAME: &str = "undefined *";

/// A run of consecutive pointers found in memory (Ghidra `AddressTable`). The secondary
/// index-table variant (`topIndexAddress`/`indexLen`) is not modelled: `AddressTableAnalyzer`
/// calls `getEntry` through the 9-argument overload (AddressTable.java:1004), which passes
/// `checkForIndex = false` (:1007), so that whole branch (:1267-1328) is unreachable from here.
#[derive(Clone, Debug)]
pub struct AddressTable {
    top_address: Address,
    table_elements: Vec<Address>,
    addr_size: u64,
    skip_amount: u64,
}

impl AddressTable {
    /// `getTopAddress` (:127).
    pub fn top_address(&self) -> Address {
        self.top_address
    }

    /// `getNumberAddressEntries` (:160).
    pub fn number_address_entries(&self) -> usize {
        self.table_elements.len()
    }

    /// `getTableElements` (:167).
    pub fn table_elements(&self) -> &[Address] {
        &self.table_elements
    }

    /// `getByteLength()` (:134).
    pub fn byte_length(&self) -> u64 {
        self.table_elements.len() as u64 * self.addr_size
    }

    /// `getByteLength(start, end, includeIndex)` (:147).
    fn byte_length_range(&self, start: usize, end: usize) -> u64 {
        ((end as i64 - start as i64) + 1).max(0) as u64 * self.addr_size
    }

    /// `getTableBody` (:1452).
    fn table_body(&self) -> AddressSet {
        let mut set = AddressSet::new();
        let len = self.byte_length();
        if len > 0 {
            set.add_range(self.top_address.space, self.top_address.offset, self.top_address.offset + len - 1);
        }
        set
    }

    /// `newRemainingAddressTable(startPos)` (:108) — a new table from whatever entries remain
    /// after `start_pos`, or `None` if none do.
    fn new_remaining_address_table(&self, start_pos: usize) -> Option<AddressTable> {
        if start_pos == 0 || start_pos >= self.table_elements.len() {
            return None;
        }
        let byte_length = self.byte_length_range(0, start_pos - 1);
        Some(AddressTable {
            top_address: Address::new(self.top_address.space, self.top_address.offset + byte_length),
            table_elements: self.table_elements[start_pos..].to_vec(),
            addr_size: self.addr_size,
            skip_amount: self.skip_amount,
        })
    }

    /// `getEntry(program, topAddr, monitor, checkExisting, minimumTableSize, alignment,
    /// skipAmount, minAddressOffset, useRelocationTable)` (:1030, entered through the
    /// 9-argument overload at :1004 so `useShiftedAddressesIfNecessary=true`,
    /// `checkForIndex=false`).
    ///
    /// `shiftedAddresses` is the data organization's pointer shift, which is 0 for every
    /// architecture in mosura's corpus (it is a Harvard-architecture feature), so the shift
    /// arithmetic at :1090 collapses to the plain read.
    #[allow(clippy::too_many_arguments)]
    pub fn get_entry(
        program: &Program,
        top_addr: Address,
        check_existing: bool,
        minimum_table_size: usize,
        alignment: u64,
        skip_amount: u64,
        min_address_offset: u64,
        use_relocation_table: bool,
    ) -> Option<AddressTable> {
        // :1051 — "if the address doesn't start on the processor's instruction alignment it
        // shouldn't be the start of a table". Every caller here passes alignment >= 1, so the
        // `alignment < 1` fallback to the language's instruction alignment is unreachable.
        let alignment = if !(1..=8).contains(&alignment) { 1 } else { alignment };
        if !top_addr.offset.is_multiple_of(alignment) {
            return None;
        }

        // :1064 — the memory range containing topAddr bounds the scan.
        let block = program.memory.block_at(top_addr)?;
        let (range_min, range_max) = (block.start().offset, block.end().offset);

        let mut array_elements: Vec<Address> = Vec::new();
        let mut array_entries: Vec<u64> = Vec::new();
        let mut pointer_set = AddressSet::new();

        let mut count: usize = 0;
        let mut current = top_addr.offset;
        let addr_size = u64::from(program.addr_size_bits / 8);

        while current >= range_min && current <= range_max {
            // :1080 — get the value in address form of the bytes at the current address.
            let Some(addr_long) = read_uint_le(program, Address::new(top_addr.space, current), addr_size)
            else {
                break; // MemoryAccessException
            };

            // :1107 — too low in memory to be an address.
            if addr_long > 0 && addr_long < min_address_offset {
                break;
            }
            // :1112 — "test that the value isn't 0 … better to be conservative".
            if addr_long == 0 {
                break;
            }
            // :1119 — the value must satisfy the processor's alignment.
            if addr_long % alignment != 0 {
                break;
            }
            let test_addr = Address::new(top_addr.space, addr_long);
            // :1124 — the tested address must be contained in memory.
            if !program.memory.contains(test_addr) {
                break;
            }
            // :1129 — a relocatable program's pointers must all be relocations.
            if use_relocation_table
                && !is_valid_relocation_address(program, Address::new(top_addr.space, current))
            {
                break;
            }
            // :1135 — "if there is a ref in the middle of the table, then isn't a table".
            if count > 1
                && program.reference_manager.has_reference_to(Address::new(top_addr.space, current))
            {
                break;
            }
            // :1141 — "also check what the address pointer points to; if the thing existing
            // there doesn't jibe with the pointer, don't do it".
            if check_existing && check_for_collision_at_target(program, test_addr) {
                break;
            }

            array_elements.push(test_addr);
            array_entries.push(current);
            pointer_set.add_range(top_addr.space, current, current + addr_size - 1);
            let Some(next) = current.checked_add(addr_size + skip_amount) else { break };
            current = next;
            count += 1;
        }

        // :1163 — "if table too small, don't even check later".
        if count < minimum_table_size {
            return None;
        }

        // :1168 — "Any reference or symbol breaks the address table." Find the next reference
        // destination after the top and shrink the table to it.
        let next_sym_addr = program
            .reference_manager
            .next_destination_from(Address::new(top_addr.space, top_addr.offset + 1));
        let end_addr = top_addr.offset + (count as u64 * (addr_size + skip_amount));
        if let Some(next) = next_sym_addr {
            if next.space == top_addr.space && next.offset < end_addr {
                count = ((next.offset - top_addr.offset) / (addr_size + skip_amount)) as usize;
            }
        }
        if count < minimum_table_size {
            return None;
        }

        if check_existing {
            // :1194 — an existing code unit must start exactly at the top, and must not be an
            // instruction ("data is OK").
            if let Some((start, _)) = program.listing.code_unit_containing(top_addr, MAX_INSN_LEN) {
                if start != top_addr {
                    return None;
                }
                if matches!(program.listing.code_unit_at(top_addr), Some(CodeUnit::Instruction { .. })) {
                    return None;
                }
            }

            // :1205 — "get next instruction, restrict table to before instruction".
            let end_addr = top_addr.offset + (count as u64 * (addr_size + skip_amount));
            if let Some(instr) = program.listing.instruction_after(top_addr) {
                if instr.space == top_addr.space && instr.offset < end_addr {
                    count = ((instr.offset - top_addr.offset) / (addr_size + skip_amount)) as usize;
                }
            }
            if count < minimum_table_size {
                return None;
            }

            // :1218 — "look for defined data that isn't already a pointer that doesn't align
            // with the table's pointer starts".
            let end_addr = top_addr.offset + (count as u64 * (addr_size + skip_amount)) - 1;
            let mut defined: Vec<&(Address, String, u32)> = program
                .defined_data
                .iter()
                .filter(|(a, _, _)| a.space == top_addr.space && a.offset >= top_addr.offset)
                .collect();
            defined.sort_by_key(|(a, _, _)| a.offset);
            for (a, type_name, len) in defined {
                if a.offset > end_addr {
                    break;
                }
                // data found at the start of a pointer: if it is a pointer, OK.
                if array_entries.contains(&a.offset) && type_name.ends_with('*') {
                    continue;
                }
                // undefined data is OK, could be a pointer.
                if type_name.starts_with("undefined") && !type_name.ends_with('*') {
                    continue;
                }
                let last = a.offset + u64::from((*len).max(1)) - 1;
                if pointer_set.ranges().any(|r| a.offset <= r.max && last >= r.min) {
                    count = ((a.offset - top_addr.offset) / (addr_size + skip_amount)) as usize;
                    break;
                }
            }
        }

        if count < minimum_table_size {
            return None;
        }

        array_elements.truncate(count);
        Some(AddressTable {
            top_address: top_addr,
            table_elements: array_elements,
            addr_size,
            skip_amount,
        })
    }

    /// `makeTable(program, start, end, createIndex, autoLabel)` (:247) — lay a pointer data
    /// unit on each entry. `createIndex` is false (no index table is ever found here) and
    /// `autoLabel` is the analyzer's `OPTION_DEFAULT_AUTO_LABEL_TABLE` (false), so `setLabels`
    /// (:311) is not reached.
    fn make_table(&self, program: &mut Program, start: usize, end: usize) -> bool {
        let end = end.min(self.table_elements.len().saturating_sub(1)).max(start);
        let len = end - start + 1;
        let current_address = self.top_address.offset + start as u64 * self.addr_size;

        // :278 — "check to make sure there is no existing things overlapping the table".
        let total_len = len as u64 * self.addr_size + self.skip_amount;
        if !is_undefined(program, self.top_address.space, current_address, current_address + total_len - 1) {
            for k in 0..total_len {
                let a = Address::new(self.top_address.space, current_address + k);
                match defined_data_containing(program, a) {
                    // a pointer or Undefined data unit is fine; anything else defined is not
                    Some((_, type_name, _)) if type_name.ends_with('*') || type_name.starts_with("undefined") => {}
                    Some(_) => return false,
                    // `data == null` in Ghidra means "not inside a Data code unit at all",
                    // which for a listing holding instructions means an instruction is there.
                    None if program.listing.code_unit_containing(a, MAX_INSN_LEN).is_some() => {
                        return false
                    }
                    None => {}
                }
            }
        }

        // :295 — make the pointers.
        let mut new_address = current_address;
        for j in 0..len {
            let at = Address::new(self.top_address.space, new_address);
            let target = self.table_elements[start + j];
            program.listing.define(
                at,
                CodeUnit::Data { length: self.addr_size as u32, type_name: POINTER_TYPE_NAME.to_string() },
            );
            program.defined_data.push((at, POINTER_TYPE_NAME.to_string(), self.addr_size as u32));
            // Creating a Pointer data unit creates its outbound memory reference (Ghidra
            // `DataDB.getReferencesFrom` synthesizes it from the pointer's value; the dump of
            // `datafnptr.watcom-x86-32` shows `REF 08049000 -> 08048110 DATA op=0 src=DEFAULT`).
            program.reference_manager.add(at, target, RefType::Data, 0);
            new_address += self.addr_size + self.skip_amount;
        }
        true
    }

    /// `getFunctionEntries(program, offset)` (:753) — the table entries that are (or plausibly
    /// start) code. **This is the over-creation guard**: an entry that is not valid code is
    /// simply absent from the list, and the caller requires the list to cover the whole table.
    fn function_entries(
        &self,
        program: &Program,
        pdis: &PseudoDisassembler,
        offset: usize,
    ) -> Vec<Address> {
        let mut list = Vec::new();
        let exec_set = execute_set(program);
        for test_addr in self.table_elements.iter().skip(offset).copied() {
            // :769 — outside executable memory, skip (never disqualifies the table).
            if !exec_set.is_empty() && !exec_set.contains(test_addr) {
                continue;
            }
            // :772 — "if it is already an instruction, assume it is valid" (but only at its start).
            if let Some((start, _)) = instruction_containing(program, test_addr) {
                if start == test_addr {
                    list.push(test_addr);
                }
                continue;
            }
            // :782 — defined data there is not code.
            if defined_data_containing(program, test_addr).is_some() {
                continue;
            }
            // :785 — the pseudo-disassembler's verdict.
            if pdis.is_valid_code(program, test_addr) {
                list.push(test_addr);
            }
        }
        list
    }

    /// `getThresholdRunOfValidPointers(program, oneInNumberOfCases)` (:1397) — "the number of
    /// valid runs of pointers to achieve a (1 in numberOfCases)" false-positive rate. This is
    /// where the minimum table size comes from; it is never a hand-picked constant.
    pub fn threshold_run_of_valid_pointers(program: &Program, one_in_number_of_cases: f64) -> i32 {
        let byte_count: f64 = program.memory.blocks().map(|b| b.size() as f64).sum();
        let bit_size = f64::from(program.addr_size_bits);
        let byte_size = 2f64.powf(bit_size).ceil();
        if byte_count >= byte_size {
            return TOO_MANY_ENTRIES; // "Need many in a row!"
        }
        let threshold = 1.0 / one_in_number_of_cases;
        (threshold.ln() / (byte_count / byte_size).ln()).ceil() as i32
    }
}

/// `isValidRelocationAddress(program, target)` (AddressTable.java:1434) — *"If the program is
/// relocatable, and this address is not one of the relocations, [it] can't be a pointer"*.
///
/// This was STUBBED to always-true when the address table was first ported, because no mosura
/// loader populated a relocation table. The LE loader now does, from the binary's own fixup
/// records, so the real check runs. For every other format the table is empty and
/// non-relocatable, so this returns true exactly as the stub did — Ghidra's own semantics
/// (RelocationTable.java:116) and the reason ELF/PE behaviour is unchanged.
fn is_valid_relocation_address(program: &Program, target: Address) -> bool {
    let table = &program.relocation_table;
    if table.is_relocatable() && table.size() != 0 && !table.has_relocation(target) {
        return false;
    }
    true
}

/// `checkForCollisionAtTarget(program, testAddr)` (:1339) — "check for collision or
/// inconsistencies at the target address". `allowOffcutCode`
/// (`hasLowBitCodeModeInAddrValues`) is the ARM/Thumb low-bit mode and is false here.
fn check_for_collision_at_target(program: &Program, test_addr: Address) -> bool {
    // :1342 — if the pointer is into the middle of code.
    let Some((instr_min, _)) = instruction_containing(program, test_addr) else {
        return false;
    };
    // :1347 — in the middle of an instruction.
    if instr_min != test_addr {
        return true;
    }
    // :1351 — the instruction has a fall-from (something falls into it).
    if instruction_falls_into(program, test_addr) {
        return true;
    }
    // :1355 — in the middle of a function.
    if let Some(func) = program.function_manager.function_containing(test_addr) {
        if func.entry_point() != test_addr {
            // :1358 — "check all the references to this place. If they are all data ptrs and
            // non-computed jump references then it could be a shared return routine."
            for r in program.reference_manager.refs_to(test_addr) {
                if matches!(r.ref_type, RefType::Data | RefType::Read | RefType::Write) {
                    return false;
                }
                if r.ref_type.is_jump_like() && r.ref_type != RefType::ComputedJump {
                    return false;
                }
            }
            return true;
        }
    }
    false
}

/// `Instruction.getFallFrom() != null` — whether the instruction immediately before `addr`
/// falls through into it. mosura models fall-through by decoding the predecessor, the same way
/// `SharedReturnAnalyzer` does; here the cheap listing-only test suffices, because any decoded
/// predecessor that ends exactly at `addr` and is not a code unit boundary implies a
/// fall-through candidate. A predecessor that does NOT fall through (a `ret`/`jmp`) leaves the
/// instruction with no fall-from, so only the flow type decides.
fn instruction_falls_into(program: &Program, addr: Address) -> bool {
    let Some((prev, len)) = (1..=MAX_INSN_LEN).find_map(|back| {
        let off = addr.offset.checked_sub(back)?;
        let a = Address::new(addr.space, off);
        match program.listing.code_unit_at(a) {
            Some(CodeUnit::Instruction { length, .. }) => Some((a, u64::from(*length))),
            _ => None,
        }
    }) else {
        return false;
    };
    if prev.offset + len != addr.offset {
        return false;
    }
    // A flow reference out of `prev` to somewhere other than `addr` does not preclude
    // fall-through; Ghidra's `getFallFrom` is decided by the predecessor's fall-through, which
    // is exactly "there is no terminating flow that removes it".
    !program.reference_manager.refs_from(prev).any(|r| {
        matches!(r.ref_type, RefType::UnconditionalJump | RefType::ComputedJump) && r.to != addr
    })
}

/// `Listing.getInstructionContaining` restricted to real instructions.
fn instruction_containing(program: &Program, addr: Address) -> Option<(Address, u64)> {
    let (start, len) = program.listing.code_unit_containing(addr, MAX_INSN_LEN)?;
    match program.listing.code_unit_at(start) {
        Some(CodeUnit::Instruction { .. }) => Some((start, len)),
        _ => None,
    }
}

/// `Listing.getDefinedDataContaining`.
fn defined_data_containing(program: &Program, addr: Address) -> Option<&(Address, String, u32)> {
    program.defined_data.iter().find(|(a, _, len)| {
        a.space == addr.space && a.offset <= addr.offset && addr.offset < a.offset + u64::from((*len).max(1))
    })
}

/// `Listing.isUndefined(min, max)` — no instruction and no defined data in the range.
fn is_undefined(program: &Program, space: SpaceId, min: u64, max: u64) -> bool {
    if program.defined_data.iter().any(|(a, _, len)| {
        a.space == space && a.offset <= max && a.offset + u64::from((*len).max(1)) > min
    }) {
        return false;
    }
    (min..=max).all(|o| instruction_containing(program, Address::new(space, o)).is_none())
}

/// The union of the executable memory blocks (Ghidra `Memory.getExecuteSet` /
/// `AddressTable.getExecuteSet`, :793 — `null` when empty, modelled here as the empty set).
fn execute_set(program: &Program) -> AddressSet {
    let mut set = AddressSet::new();
    for b in program.memory.blocks().filter(|b| b.is_execute()) {
        set.add_range(b.start().space, b.start().offset, b.end().offset);
    }
    set
}

/// Read an unsigned little-endian integer of `size` bytes (`Memory.getInt`/`getLong`).
/// Returns `None` on a short/uninitialized read (Ghidra's `MemoryAccessException`).
fn read_uint_le(program: &Program, addr: Address, size: u64) -> Option<u64> {
    let bytes = program.memory.read_window(addr, size as usize);
    if bytes.len() < size as usize {
        return None;
    }
    let mut v = 0u64;
    if program.big_endian {
        for b in bytes.iter().take(size as usize) {
            v = (v << 8) | u64::from(*b);
        }
    } else {
        for (i, b) in bytes.iter().take(size as usize).enumerate() {
            v |= u64::from(*b) << (8 * i);
        }
    }
    Some(v)
}

/// The "Create Address Tables" analyzer (Ghidra `AddressTableAnalyzer`), a BYTE_ANALYZER at
/// `DATA_TYPE_PROPOGATION.before()` — i.e. after ordinary flow disassembly and function
/// discovery have converged, so it only ever looks at bytes nothing else claimed.
pub struct AddressTableAnalyzer {
    ram: SpaceId,
    pdis: PseudoDisassembler,
    minimum_table_size: usize,
    table_alignment: u64,
    ptr_alignment: u64,
    auto_label_table: bool,
    min_pointer_address: u64,
    max_pointer_distance: u64,
    relocation_guide_enabled: bool,
    allow_offcut_references: bool,
    /// Ghidra guards `removeDefined` with `id != lastID` (AddressTableAnalyzer.java:132), the
    /// current transaction id — in a headless run the whole analysis is one transaction, so it
    /// happens on the first entry only. This is that latch.
    did_remove_defined: Cell<bool>,
    /// The `Address Table` analysis bookmarks (`processAddressTable`:234-263). Ghidra reads
    /// them back to avoid re-making a table it already made; they are not part of mosura's
    /// `Program`, so they live here.
    bookmarks: std::cell::RefCell<std::collections::HashSet<(u32, u64)>>,
}

impl AddressTableAnalyzer {
    /// Build the analyzer, or `None` if the SLEIGH tables for the program's language are
    /// unavailable (the pseudo-disassembler needs them).
    pub fn for_program(program: &Program) -> Option<AddressTableAnalyzer> {
        let pdis = PseudoDisassembler::for_program(program)?;
        // `calculateMinimumTableSize` (:522).
        let mut minimum_table_size =
            AddressTable::threshold_run_of_valid_pointers(program, BILLION_CASES);
        if minimum_table_size < 2 {
            minimum_table_size = 2;
        }
        Some(AddressTableAnalyzer {
            ram: program.default_space,
            pdis,
            minimum_table_size: minimum_table_size as usize,
            table_alignment: OPTION_DEFAULT_TABLE_ALIGNMENT,
            ptr_alignment: OPTION_DEFAULT_PTR_ALIGNMENT,
            auto_label_table: OPTION_DEFAULT_AUTO_LABEL_TABLE,
            min_pointer_address: OPTION_DEFAULT_MIN_POINTER_ADDR,
            max_pointer_distance: OPTION_DEFAULT_MAX_POINTER_DIFF,
            relocation_guide_enabled: OPTION_DEFAULT_RELOCATION_GUIDE_ENABLED,
            allow_offcut_references: OPTION_DEFAULT_ALLOW_OFFCUT_REFERENCES,
            did_remove_defined: Cell::new(false),
            bookmarks: std::cell::RefCell::new(std::collections::HashSet::new()),
        })
    }

    /// `getDefaultEnablement` (:511) — note it *overrides* the `setDefaultEnablement(false)` in
    /// the constructor (:104), so the analyzer is on by default unless the image is so large
    /// that a run of pointers carries no information.
    pub fn default_enablement(&self) -> bool {
        self.minimum_table_size as i32 != TOO_MANY_ENTRIES
    }

    /// `removeNonSearchableMemory` (:347) — keep only loaded+initialized bytes, and drop blocks
    /// with no read/write/execute permission at all.
    fn remove_non_searchable_memory(&self, program: &Program, set: &AddressSet) -> AddressSet {
        let mut keep = AddressSet::new();
        for b in program.memory.blocks() {
            if !b.is_initialized() {
                continue;
            }
            if !(b.is_write() || b.is_read() || b.is_execute()) {
                continue;
            }
            keep.add_range(b.start().space, b.start().offset, b.end().offset);
        }
        set.intersect(&keep)
    }

    /// `removeDefined` (:316) — remove defined data that cannot be part of an address table
    /// (anything not `Undefined` and not a pointer), and every defined instruction.
    fn remove_defined(&self, program: &Program, set: &AddressSet) -> AddressSet {
        let mut sub = AddressSet::new();
        for (a, type_name, len) in &program.defined_data {
            if type_name.starts_with("undefined") && !type_name.ends_with('*') {
                continue;
            }
            if type_name.ends_with('*') {
                continue; // data.isPointer()
            }
            sub.add_range(a.space, a.offset, a.offset + u64::from((*len).max(1)) - 1);
        }
        let mut out = set.subtract(&sub);
        let mut sub = AddressSet::new();
        for (a, u) in program.listing.code_units() {
            if let CodeUnit::Instruction { length, .. } = u {
                sub.add_range(a.space, a.offset, a.offset + u64::from(*length) - 1);
            }
        }
        out = out.subtract(&sub);
        out
    }

    /// `checkTable(tableEntry, program, monitor)` (:386) — "check the table for consistency and
    /// return the number of good entries before a bad entry is found".
    fn check_table(&self, program: &Program, table: &AddressTable) -> usize {
        let possible_strings = find_possible_strings(program, &table.table_body());
        let start = table.top_address;
        let table_len = table.number_address_entries();
        let addrs = table.table_elements();
        for i in 0..table_len {
            // NOTE Ghidra hardcodes `i * 4` here even though the table's pointer size is a
            // field (:398); faithful, and identical for the 4-byte pointers this runs on.
            let table_entry_addr = Address::new(start.space, start.offset + i as u64 * 4);
            let target_addr = addrs[i];
            if possible_strings.contains(table_entry_addr) {
                return i;
            }
            if possible_strings.contains(Address::new(start.space, table_entry_addr.offset + 3)) {
                return i;
            }
            // :406 — again the TABLE ENTRY's own address, not the target's (faithful).
            if table_entry_addr.offset > 0 && table_entry_addr.offset < self.min_pointer_address {
                return i;
            }
            // :410 — "check that the table entries are not all over the place".
            if i > 0 {
                let diff = addrs[i - 1].offset.abs_diff(addrs[i].offset);
                if diff > self.max_pointer_distance {
                    return i;
                }
            }
            let Some((cu_min, _)) = program.listing.code_unit_containing(target_addr, MAX_INSN_LEN)
            else {
                continue;
            };
            // :423 — an offcut pointer into an existing code unit breaks the table.
            if !self.allow_offcut_references && cu_min != target_addr {
                return i;
            }
        }
        table_len
    }

    /// `processAddressTable(addressTable, program, mgr, monitor)` (:224). Returns
    /// `(did_table, disassemble_set)` — the addresses to hand to the disassembler.
    fn process_address_table(
        &self,
        program: &mut Program,
        mut table: Option<AddressTable>,
        dis_set: &mut AddressSet,
    ) -> bool {
        let mut did_table = false;
        while let Some(t) = table {
            let table_len = self.check_table(program, &t);

            // :233 — an existing Address Table bookmark here means it was already made.
            let has_bookmark =
                self.bookmarks.borrow().contains(&(t.top_address.space.0, t.top_address.offset));

            if has_bookmark || table_len < self.minimum_table_size {
                // :241 — skip the entry assumed to have broken the table and continue.
                table = t.new_remaining_address_table(table_len + 1);
                continue;
            }

            // :252 — make the table.
            t.make_table(program, 0, table_len - 1);

            if self.auto_label_table {
                // `setLabels` (:311) — unreachable: OPTION_DEFAULT_AUTO_LABEL_TABLE is false.
            }
            self.bookmarks.borrow_mut().insert((t.top_address.space.0, t.top_address.offset));

            // :265 — "if all are valid code, disassemble".
            let valid_code_list = t.function_entries(program, &self.pdis, 0);
            if valid_code_list.len() >= t.number_address_entries() {
                for addr in valid_code_list {
                    // :277 — "even though they are valid code, don't do them if there is
                    // already code there".
                    if program.listing.code_unit_containing(addr, MAX_INSN_LEN).is_none() {
                        dis_set.add_range(addr.space, addr.offset, addr.offset);
                    }
                    // :282-296 — `validFuncSet` is built and then NOT used: "For Now, Never
                    // make functions from address tables". No function is created here.
                }
            }

            table = t.new_remaining_address_table(table_len + 1);
            did_table = true;
        }
        did_table
    }
}

impl Analyzer for AddressTableAnalyzer {
    fn name(&self) -> &str {
        "Create Address Tables"
    }
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Byte
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::DATA_TYPE_PROPAGATION.before()
    }
    /// `canAnalyze` (:108) — "only analyze programs with address spaces > 16 bits", plus
    /// `getDefaultEnablement` (:511).
    fn can_analyze(&self, program: &Program) -> bool {
        matches!(program.addr_size_bits, 32 | 64) && self.default_enablement()
    }

    fn added(&self, program: &mut Program, set: &AddressSet, sched: &mut Scheduling) -> bool {
        let mut addr_set = self.remove_non_searchable_memory(program, set);
        if !self.did_remove_defined.get() {
            self.did_remove_defined.set(true);
            addr_set = self.remove_defined(program, &addr_set);
        }
        if addr_set.is_empty() {
            return true;
        }

        let Some(min_addr) = addr_set.min_address() else { return true };
        let mut max_addr = min_addr;
        let mut dis_set = AddressSet::new();

        // :159 — iterate the set until ONE table is made, then yield to the other analyzers.
        let mut did_table = false;
        'outer: for r in addr_set.ranges().map(|r| (r.space, r.min, r.max)).collect::<Vec<_>>() {
            let mut off = r.1;
            while off <= r.2 {
                let start = Address::new(r.0, off);
                max_addr = start;
                if off % self.table_alignment != 0 {
                    off += 1;
                    continue;
                }
                let table = AddressTable::get_entry(
                    program,
                    start,
                    true,
                    self.minimum_table_size,
                    self.ptr_alignment,
                    0,
                    MINIMUM_SAFE_ADDRESS,
                    self.relocation_guide_enabled,
                );
                let Some(table) = table else {
                    off += 1;
                    continue;
                };
                // :186 — the whole table found is assumed processed; skip past its bytes.
                let table_byte_len = table.byte_length();
                did_table = self.process_address_table(program, Some(table), &mut dis_set);
                max_addr = Address::new(r.0, off + table_byte_len.saturating_sub(1));
                off += table_byte_len.max(1);
                if did_table {
                    break 'outer;
                }
            }
        }

        // :199 — "set up a one time analysis to get us back into here if there are still
        // addresses on the set".
        let mut consumed = AddressSet::new();
        consumed.add_range(self.ram, min_addr.offset, max_addr.offset);
        let left = addr_set.subtract(&consumed);
        if !left.is_empty() && did_table {
            sched.block_added(&left);
        }

        // :288 — "disassemble valid code" (`mgr.disassemble`) — a COMMAND, which is what the
        // Ghidra line already says; it was routed through the `codeDefined` notification.
        if !dis_set.is_empty() {
            sched.disassemble(&dis_set);
        }
        true
    }
}

/// `findPossibleStrings(program, addrSet, monitor)` (:435) — "skip over anything that smells
/// like a unicode string", so a table is never laid over one.
fn find_possible_strings(program: &Program, addr_set: &AddressSet) -> AddressSet {
    let mut out = AddressSet::new();
    let max_bytes = addr_set.num_addresses();
    for r in addr_set.ranges() {
        let mut off = r.min;
        while off <= r.max {
            let str_len = get_wstr_len(program, Address::new(r.space, off), (max_bytes / 2) as usize);
            if str_len > 4 {
                let num_bytes = (str_len * 2) as u64;
                out.add_range(r.space, off, off + num_bytes);
                off = off.saturating_add(num_bytes);
                continue;
            }
            off += 1;
        }
    }
    out
}

/// `getWStrLen(memory, ad, max)` (:482) — the length in UTF-16 code units of the English
/// unicode string at `ad`, or how far it got before a non-printable value.
fn get_wstr_len(program: &Program, ad: Address, max: usize) -> usize {
    let mut i = 0usize;
    while i < max {
        let Some(v) = read_uint_le(program, Address::new(ad.space, ad.offset + 2 * i as u64), 2)
        else {
            return i;
        };
        let value = v as u16 as i16;
        if value == 0 {
            return i + 1;
        }
        // allow tab, carriage return, and linefeed
        if value != 0x09 && value != 0x0a && value != 0x0d && !(0x20..0x7f).contains(&value) {
            return i;
        }
        i += 1;
    }
    i
}
