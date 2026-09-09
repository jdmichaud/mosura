//! Ghidra's **"Switch Table References"** — the half of `OperandReferenceAnalyzer`
//! (`app/plugin/core/analysis/OperandReferenceAnalyzer.java`) that starts from the INSTRUCTION
//! naming a table of code pointers, together with `AddressTable.createSwitchTable`
//! (`app/plugin/core/disassembler/AddressTable.java:331`) that it drives. Ghidra ships it
//! DISABLED (`OPTION_DEFAULT_SWITCH_TABLE_ENABLED = false`, :108; the option is registered at
//! :1271 under the name at :70); mosura turns it on with
//! [`Knobs::switch_table_refs`](crate::switches::Knobs) (`analysis.switch-table-refs`) and keeps
//! Ghidra's default. The blind scan in [`address_table`](super::address_table) is the OTHER
//! address-table path — a byte analyzer that guesses table tops from alignment; this one is told
//! the top by the instruction that indexes it.
//!
//! WHAT IT DOES. For every newly decoded instruction whose flow is a COMPUTED call or jump (:713,
//! :734 — `(ftype.isJump() || ftype.isCall()) && ftype.isComputed()`), each DATA reference it
//! carries names a candidate table top: `AddressTable.getEntry` is asked for a run of pointers
//! there with `switchTableAlignment = 1` (:109, :719), so the blind scan's alignment-4 filter
//! (`OPTION_DEFAULT_TABLE_ALIGNMENT`, AddressTableAnalyzer.java:69) never applies — a top named by
//! an instruction is not a blind guess. A run of at least the program's minimum table size (:397;
//! `calculateMinimumAddressTableSize`, :167) goes to `createSwitchTable` (:331), which walks the
//! entries ONE BY ONE: a pointer datum at each slot, the target's block and spread checked
//! (:446-:467), a reference FROM THE INSTRUCTION to the entry typed as the instruction's own flow
//! (`addMnemonicReference`, :480), the target disassembled (:484), and for a jump the function body
//! extended over the arms (:489 — [`get_function_body`](super::get_function_body) follows
//! `COMPUTED_JUMP` references, so mosura's bodies take the arms in at their next refresh). A bad
//! entry ENDS the walk and keeps the good ones before it (the `break`s at :405, :449, :456, :466):
//! the all-or-nothing verdict of the blind scan (`processAddressTable`, :265) is not this path's.
//!
//! THE TWO-PASS PROTOCOL (AddressTable.java:469-:475, :502-:511; OperandReferenceAnalyzer.java
//! :401-:407, :523). The first time a table with undecoded targets is met, the walk only
//! disassembles them, strips any reference it had placed, marks the table IN PROGRESS and answers
//! "new code found"; the analyzer then yields — re-scheduling itself once on what was left of its
//! set, the naming instruction included — so the new code is analyzed before the table is
//! finished. The second visit finds the table in progress, places every reference, labels the
//! table (`callTable` / `switchTable`, the cases `case_0x<i>`; :343, :477, `labelTable` :560) and
//! clears the mark. Ghidra disassembles inside the walk and the re-run is queued behind the code
//! that produced; mosura queues the disassembly ahead of its own re-run
//! ([`Scheduling::disassemble`] runs before a one-shot at this analyzer's priority), which orders
//! the two the same way.
//!
//! ONE DEVIATION, OWNED HERE — FUNCTIONS AT A CALL TABLE'S ENTRIES. Ghidra's analyzer holds the
//! rule that a computed-call reference whose target is not a function sends the Subroutine
//! References analyzer there to make one (OperandReferenceAnalyzer.java:275-:283 →
//! `plugin/core/function/FunctionAnalyzer.java:80-:86`, :139); but it applies the rule to the
//! references an instruction carries WHEN IT IS VISITED (the snapshot at :267), and the references
//! this path creates are placed after the last visit's snapshot was taken, so on a call table
//! Ghidra's own rule never fires: the entries are disassembled and referenced, and become functions
//! only if something else calls them. mosura applies the rule where the reference is made
//! ([`Scheduling::create_function`]). The "never make functions from address tables" policy is the
//! BLIND scan's (AddressTableAnalyzer.java:281,294), for tables no instruction vouches for; here
//! the instruction calls through the table, and a routine that is called is a function. On the
//! second subject that is the difference between its mode and key handlers being functions or
//! anonymous code (docs/tasklist-2026-09-08.md item 12). Under the default option nothing here
//! runs, so the first subject's identity gate and `analysis_parity`'s Ghidra goldens are untouched
//! by construction.
//!
//! NOT PORTED, stated: the negative-offset table search (:734-:792 — a table indexed from its
//! bottom, `jmp [T - k + reg*4]`, found by walking `MAX_NEG_ENTRIES` entries backwards and recorded
//! through an OFFSET reference mosura does not model), and `createTableIndex` (:493 — this path's
//! `getEntry` runs with `checkForIndex = false`, :719, so no table here ever has one). Neither
//! subject shows either shape. The C printed for a switch this path bounds is a separate matter:
//! the decompiler's own jump-table recovery still decides what `switch` it prints, as in Ghidra.
//!
//! Gated by `ground_truth_parity.rs::switch_table_references` on the self-compiled `codetable`
//! fixture (both directions), and by `ground_truth_parity` itself under the option the fixture
//! declares.

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::analyzers::address_table::{
    defined_data_containing, AddressTable, BILLION_CASES, MAX_INSN_LEN, MINIMUM_SAFE_ADDRESS, POINTER_TYPE_NAME,
};
use crate::analysis::analyzers::refresh_function_bodies;
use crate::analysis::flowtype::{modified_flow_type, FlowKind, FlowOverride};
use crate::analysis::manager::Scheduling;
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, CodeUnit, Program, RefType, SymbolType};
use crate::decompile::opcode::OpCode;
use crate::decompile::space::{Address, SpaceId};
use crate::sleigh::engine::Spec;
use crate::sleigh::pcode::PArg;

/// `MINIMUM_POTENTIAL_TABLE_SIZE` (OperandReferenceAnalyzer.java:111): the run `getEntry` is asked
/// for at a named top.
const MINIMUM_POTENTIAL_TABLE_SIZE: usize = 3;
/// `OPTION_DEFAULT_SWITCH_TABLE_ALIGNMENT` (:109).
const OPTION_DEFAULT_SWITCH_TABLE_ALIGNMENT: u64 = 1;
/// `OPTION_DEFAULT_RELOCATION_GUIDE_ENABLED` (:103).
const OPTION_DEFAULT_RELOCATION_GUIDE_ENABLED: bool = true;
/// "Don't allow the targets of the switch to vary widely" (AddressTable.java:447): `1024 * 128`.
const MAX_TARGET_SPREAD: i64 = 1024 * 128;

pub struct SwitchTableAnalyzer {
    ram: SpaceId,
    spec: &'static Spec,
    ctx: &'static [u32],
    /// `minimumAddressTableSize` (:397; `calculateMinimumAddressTableSize` :167-:174): the run
    /// length for one false positive in a billion cases on this image, never below 2.
    minimum_address_table_size: usize,
    /// `TABLE_IN_PROGRESS_PROPERTY_NAME` (AddressTable.java:517-:556): the tops whose first visit
    /// found new code. Shared with the one-shot re-run this analyzer schedules for itself.
    in_progress: Rc<RefCell<HashSet<u64>>>,
}

impl SwitchTableAnalyzer {
    pub fn for_program(program: &Program) -> Option<SwitchTableAnalyzer> {
        // `canAnalyze` (:141-:163): only address spaces wider than 16 bits.
        if program.addr_size_bits <= 16 {
            return None;
        }
        let (spec, ctx) = crate::lang::load_cached(&program.language_id)?;
        let minimum_address_table_size =
            AddressTable::threshold_run_of_valid_pointers(program, BILLION_CASES).max(2) as usize;
        Some(SwitchTableAnalyzer {
            ram: program.default_space,
            spec,
            ctx,
            minimum_address_table_size,
            in_progress: Rc::new(RefCell::new(HashSet::new())),
        })
    }

    /// The instance a one-shot re-run gets: the same table-in-progress marks.
    fn share(&self) -> SwitchTableAnalyzer {
        SwitchTableAnalyzer {
            ram: self.ram,
            spec: self.spec,
            ctx: self.ctx,
            minimum_address_table_size: self.minimum_address_table_size,
            in_progress: Rc::clone(&self.in_progress),
        }
    }

    /// `instr.getFlowType()` — the prototype flow type with the instruction's flow override applied
    /// (InstructionDB.java:321), which is what :713 and :734 test.
    fn flow_type(&self, program: &Program, a: Address) -> Option<RefType> {
        let (_, flow) = program.listing.instruction_at(a)?;
        let FlowKind::Ref(r) = flow.kind else { return None };
        let ov = program.flow_override_at(a);
        Some(if ov == FlowOverride::None { r } else { modified_flow_type(r, ov) })
    }

    /// The instructions of `set` whose flow is a computed jump or call, in address order — the
    /// reference SOURCES of `added()`'s loop (:250) that :734 admits.
    fn computed_flow_sites(&self, program: &Program, set: &AddressSet) -> Vec<Address> {
        let mut out = Vec::new();
        for r in set.ranges() {
            if r.space != self.ram {
                continue;
            }
            let mut off = r.min;
            while off <= r.max {
                let a = Address::new(self.ram, off);
                match program.listing.instruction_at(a) {
                    Some((len, _)) => {
                        if self.flow_type(program, a).is_some_and(is_computed_flow) {
                            out.push(a);
                        }
                        off += u64::from(len.max(1));
                    }
                    None => match program.listing.instruction_after(a) {
                        Some(n) if n.offset <= r.max => off = n.offset,
                        _ => break,
                    },
                }
            }
        }
        out
    }

    /// ":713-:717 — if this is a computed jump or call, with just 1 address operand, it can't be a
    /// jump/call table": `call [0x45218]` reads its target straight out of ONE memory address — its
    /// `CALLIND`/`BRANCHIND` input is a `ram` varnode — where a table call computes the location
    /// from an index (a `unique`).
    fn single_address_operand(&self, program: &Program, a: Address) -> bool {
        let window = program.memory.read_window(a, MAX_INSN_LEN as usize);
        let Some(insn) = self.spec.disassemble_ctx(&window, a.offset, self.ctx).into_iter().next() else {
            return false;
        };
        insn.ops.iter().any(|op| {
            matches!(OpCode::from_u32(op.opcode), Some(OpCode::Callind | OpCode::Branchind))
                && matches!(op.ins.first(), Some(PArg::Var(v)) if v.space == "ram")
        })
    }

    /// `getAddressTable(program, instr, opIndex, target, monitor)` (:709-:792) — the positive
    /// half: the run of pointers at the named top, alignment 1, existing units respected.
    fn get_address_table(&self, program: &Program, instr: Address, target: Address) -> Option<AddressTable> {
        if self.single_address_operand(program, instr) {
            return None;
        }
        // :719. (:721-:731 flags a NEGATIVE table off an OFFSET reference; mosura has no offset
        // references, so a table found here is always positive. :734-:792, the negative-offset
        // search, is not ported — module doc.)
        AddressTable::get_entry(
            program,
            target,
            true,
            MINIMUM_POTENTIAL_TABLE_SIZE,
            OPTION_DEFAULT_SWITCH_TABLE_ALIGNMENT,
            0,
            MINIMUM_SAFE_ADDRESS,
            OPTION_DEFAULT_RELOCATION_GUIDE_ENABLED,
        )
    }

    /// `AddressTable.createSwitchTable(program, start_inst, opindex, flagNewCode, monitor)`
    /// (AddressTable.java:331-:513). Returns Ghidra's "new code found". The targets to
    /// disassemble and the entries to make functions of are collected for the caller to schedule.
    #[allow(clippy::too_many_arguments)]
    fn create_switch_table(
        &self,
        program: &mut Program,
        start: Address,
        ftype: RefType,
        table: &AddressTable,
        flag_new_code: bool,
        dis: &mut AddressSet,
        make_functions: &mut AddressSet,
    ) -> bool {
        let addr_size = u64::from(program.addr_size_bits / 8);
        let top = table.top_address();
        let is_call = ftype.is_call();
        // :343
        let table_name = if is_call { "callTable" } else { "switchTable" };

        // :349 — "if there are already mnemonic references, then the switch stmt is already done."
        if program.reference_manager.refs_from(start).any(|r| r.op_index == -1 && r.ref_type.is_flow()) {
            return false;
        }
        // :355 — is the instruction's block executable?
        let instr_block_executable = program.memory.block_at(start).is_some_and(|b| b.is_execute());
        // :368 — "we prefer switch tables to already be in a function": a body question.
        refresh_function_bodies(program);
        let not_in_a_function = program.function_manager.function_containing(start).is_none();
        // :375
        let table_in_progress = self.in_progress.borrow().contains(&top.offset);

        let mut new_code_found = false;
        let mut last: Option<Address> = None;
        let mut placed: Vec<Address> = Vec::new();
        let mut case_labels: Vec<(Address, String)> = Vec::new();
        let elements: Vec<Address> = table.table_elements().to_vec();
        for (i, &target) in elements.iter().enumerate() {
            let loc = Address::new(top.space, top.offset + i as u64 * addr_size);
            // :398-:428 — the pointer datum at the slot; an INSTRUCTION over the slot ends the table.
            if !define_pointer_slot(program, loc, target, addr_size) {
                break;
            }
            // :446-:461 — "Don't allow the targets of the switch to vary widely", nor to change block.
            let this_block = program.memory.block_at(target).map(|b| b.start());
            if let Some(l) = last {
                if l.offset as i64 - target.offset as i64 > MAX_TARGET_SPREAD {
                    break;
                }
                let last_block = program.memory.block_at(l).map(|b| b.start());
                if last_block.is_none() || last_block != this_block {
                    break;
                }
            }
            last = Some(target);
            // :465 — code in an executable block does not switch into a non-executable one.
            if instr_block_executable && program.memory.block_at(target).is_some_and(|b| !b.is_execute()) {
                break;
            }
            // :469-:475 — an undecoded target (or a table outside any function) is NEW CODE, unless
            // this table is already in progress.
            if (program.listing.instruction_at(target).is_none() || not_in_a_function) && !table_in_progress {
                new_code_found = true;
            }
            if !flag_new_code || !new_code_found {
                // :477-:480 — the case label, and the reference from the instruction's mnemonic.
                if !is_call {
                    case_labels.push((target, format!("case_0x{i:x}")));
                }
                program.reference_manager.add(start, target, ftype, -1);
                placed.push(target);
            }
            // :484 — `disassembleTarget`.
            dis.add(target);
        }
        // :488 `fixupFunctionBody` — bodies follow the references (`get_function_body`); nothing to do.
        // :492 `createTableIndex` — no index (module doc).

        if flag_new_code && new_code_found {
            // :502-:510 — strip what was placed before the new code was met: more code must be
            // found first, and the re-run places everything.
            for t in &placed {
                program.reference_manager.remove(start, *t, ftype);
            }
            self.in_progress.borrow_mut().insert(top.offset);
            crate::debug!(
                crate::debug::Topic::Analysis,
                "switchtable {:#x} -> {:#x}: {} entries, new code — disassembling, table in progress",
                start.offset,
                top.offset,
                elements.len()
            );
            return true;
        }
        self.in_progress.borrow_mut().remove(&top.offset);
        crate::debug!(
            crate::debug::Topic::Analysis,
            "switchtable {:#x} -> {:#x}: {} entries, {} referenced as {} ({table_name})",
            start.offset,
            top.offset,
            elements.len(),
            placed.len(),
            ftype.name()
        );
        label_table(program, top, table_name, &case_labels);
        // The one deviation (module doc): a call table's entries are functions.
        if is_call {
            for t in &placed {
                if program.function_manager.function_at(*t).is_none() {
                    make_functions.add(*t);
                }
            }
        }
        false
    }
}

/// `FlowType.isComputed()` over the flow types that are also a jump or a call.
fn is_computed_flow(r: RefType) -> bool {
    matches!(
        r,
        RefType::ComputedJump
            | RefType::ConditionalComputedJump
            | RefType::ComputedCall
            | RefType::ConditionalComputedCall
            | RefType::ComputedCallTerminator
    )
}

/// `createData(loc, ptrDT)` with its `CodeUnitInsertionException` arms (AddressTable.java
/// :398-:428): an instruction over the slot ends the table (`false`); data that is not already the
/// pointer is cleared for it; the pointer datum carries its DATA reference to the target, laid
/// down the way `AddressTable::make_table` lays the blind scan's.
fn define_pointer_slot(program: &mut Program, loc: Address, target: Address, addr_size: u64) -> bool {
    if let Some((start, _)) = program.listing.code_unit_containing(loc, MAX_INSN_LEN) {
        match program.listing.code_unit_at(start) {
            Some(CodeUnit::Instruction { .. }) => return false,
            Some(CodeUnit::Data { type_name, .. }) if start == loc && type_name.ends_with('*') => return true,
            Some(CodeUnit::Data { .. }) => {
                // :424 — clear the unit here and make the pointer.
                program.listing.undefine(start);
                program.defined_data.retain(|(a, _, _)| *a != start);
            }
            None => {}
        }
    }
    program.listing.define(
        loc,
        CodeUnit::Data { length: addr_size as u32, type_name: POINTER_TYPE_NAME.to_string() },
    );
    program.defined_data.push((loc, POINTER_TYPE_NAME.to_string(), addr_size as u32));
    program.reference_manager.add(loc, target, RefType::Data, 0);
    true
}

/// `labelTable` (AddressTable.java:560-:640): the table's name at its top and a `case_0x<i>` at
/// each jump target — unless the top already carries a symbol by that name (:562-:567). Ghidra
/// files them in a `switch_<addr>` namespace of their own (:577); mosura's symbol table has no
/// namespaces, so the names are flat and the table number Ghidra appends on a namespace collision
/// (:598-:611) never applies. An ANALYSIS `Addr…` label at the top is superseded (:590-:594);
/// mosura's blind scan sets none (`OPTION_DEFAULT_AUTO_LABEL_TABLE` is false), so there is nothing
/// to supersede. A label is primary only where the address has no primary symbol yet.
fn label_table(program: &mut Program, top: Address, name: &str, case_labels: &[(Address, String)]) {
    if program.symbol_table.symbols_at(top).any(|s| s.name().starts_with(name)) {
        return;
    }
    let primary = program.symbol_table.primary_at(top).is_none();
    program.symbol_table.add_with_primary(top, name, SymbolType::Label, primary);
    for (a, l) in case_labels {
        let primary = program.symbol_table.primary_at(*a).is_none();
        program.symbol_table.add_with_primary(*a, l, SymbolType::Label, primary);
    }
}

impl Analyzer for SwitchTableAnalyzer {
    fn name(&self) -> &str {
        "Switch Table References"
    }
    /// `INSTRUCTION_ANALYZER` (OperandReferenceAnalyzer.java:133): the newly decoded extent.
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Instruction
    }
    /// `setPriority(AnalysisPriority.REFERENCE_ANALYSIS)` (:138) — after the constant propagator
    /// that records the DATA reference to the table (`REFERENCE.before()` ×4), on the same channel.
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::REFERENCE
    }
    fn added(&self, program: &mut Program, set: &AddressSet, sched: &mut Scheduling) -> bool {
        let mut dis = AddressSet::new();
        let mut make_functions = AddressSet::new();
        let mut left = AddressSet::new();
        let mut new_code_found = false;
        'sites: for site in self.computed_flow_sites(program, set) {
            let Some(ftype) = self.flow_type(program, site) else { continue };
            // :267 — the references this instruction carries, as of now: the snapshot the loop
            // iterates.
            let refs: Vec<(Address, RefType)> =
                program.reference_manager.refs_from(site).map(|r| (r.to, r.ref_type)).collect();
            let mut checked: HashSet<u64> = HashSet::new();
            for (target, rt) in refs {
                // :274-:305 — flow references have their own arms (the external jump and the thunk
                // check live in their own analyzers; the computed-call arm: module doc).
                if rt.is_flow() {
                    continue;
                }
                // :311 `checkedTargets`; :317-:323 a memory reference into mapped memory.
                if !checked.insert(target.offset) || !program.memory.contains(target) {
                    continue;
                }
                // :328-:341 — defined data at the target that is neither a string, a pointer nor
                // undefined is not a table top.
                if let Some((_, ty, _)) = defined_data_containing(program, target) {
                    if !(ty.ends_with('*') || ty.starts_with("undefined") || ty.contains("string")) {
                        continue;
                    }
                }
                // :391-:396
                let Some(table) = self.get_address_table(program, site, target) else {
                    crate::debug!(
                        crate::debug::Topic::Analysis,
                        "switchtable {:#x} -> {:#x}: no pointer run at the named top",
                        site.offset,
                        target.offset
                    );
                    continue;
                };
                if table.number_address_entries() < self.minimum_address_table_size {
                    crate::debug!(
                        crate::debug::Topic::Analysis,
                        "switchtable {:#x} -> {:#x}: run of {} < minimum {}",
                        site.offset,
                        target.offset,
                        table.number_address_entries(),
                        self.minimum_address_table_size
                    );
                    continue;
                }
                if self.create_switch_table(program, site, ftype, &table, true, &mut dis, &mut make_functions) {
                    // :401-:407 — "if new code found, must yield analysis elsewhere": what is left
                    // of the set, this instruction included, is re-run once the code is in.
                    new_code_found = true;
                    left = set.clone();
                    if let Some(min) = set.min_address() {
                        if min.offset < site.offset {
                            let mut done = AddressSet::new();
                            done.add_range(self.ram, min.offset, site.offset - 1);
                            left = left.subtract(&done);
                        }
                    }
                    left.add(site);
                    break 'sites;
                }
            }
        }
        sched.disassemble(&dis);
        sched.create_function(&make_functions);
        // :523 — `scheduleOneTimeAnalysis(this, leftSet)`.
        if new_code_found && !left.is_empty() {
            sched.schedule_one_shot(Box::new(self.share()), &left);
        }
        true
    }
}
