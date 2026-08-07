//! `SharedReturnAnalyzer` (A7) — a port of Ghidra's
//! `app/plugin/core/function/SharedReturnAnalyzer.java` +
//! `SharedReturnJumpAnalyzer.java`, driven by
//! `app/cmd/analysis/SharedReturnAnalysisCmd.java`.
//!
//! A shared-return tail call is an (unconditional) **jump** to the entry of a function:
//! the callee shares the caller's return, so the jump is logically a call that does not
//! return. Ghidra's `SharedReturnAnalysisCmd.applyTo` has two parts:
//!
//! 1. `processFunctionJumpReferences` — for each destination function, find the JUMP
//!    references to its entry; for each whose source is a single-flow jump that is neither
//!    a function entry (a thunk) nor an internal jump within the same function, apply a
//!    `FlowOverride.CALL_RETURN` to the source instruction. The override re-types the flow
//!    reference (`InstructionDB.setFlowOverride` → `RefTypeFactory.getDefaultMemoryRefType`
//!    → `getDefaultJumpOrCallFlowType`): a plain `UNCONDITIONAL_JUMP` becomes a
//!    `CALL_TERMINATOR` *instruction* flow, whose *reference* type is `UNCONDITIONAL_CALL`
//!    (Ghidra `RefType.CALL_TERMINATOR` doc).
//! 2. `assumeContiguousFunctions` (default `true`, the x86 pspec default) — an unconditional
//!    jump that crosses a neighbouring function's boundary (forward past the next function's
//!    entry, or backward before the previous function's entry) is treated as a shared-return
//!    tail call into a *new* function: `createFunction(destAddr)`. On `basic.elf` this is
//!    what recovers `FUN_00401020` (PLT[0]) from the resolve-tail `jmp 0x401020` at
//!    `0x40103b`, which jumps backward before `printf@plt`.
//!
//! Priority: Ghidra runs at `CODE_ANALYSIS.before().before()` (functions already exist,
//! created by `CreateFunctionCmd` during disassembly flow). mosura creates functions in a
//! dedicated `FunctionCreator` analyzer (priority FUNCTION) and lays down flow references
//! during disassembly, so this analyzer runs after both (`REFERENCE.after()`), the same
//! accommodation the switch/external-jump analyzers make — the precondition Ghidra relies
//! on (functions + flow refs present) holds there. New functions it creates are scheduled
//! via `function_defined`, re-triggering disassembly + reference recovery to a fixpoint.

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::flowtype::{
    default_jump_or_call_flow_type, has_fallthrough, is_terminator_flow, modified_flow_type,
    FlowOverride,
};
use crate::analysis::manager::Scheduling;
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, Program, RefType, SymbolType};
use crate::decompile::space::{Address, SpaceId};
use crate::sleigh::engine::Spec;

/// Max x86-64 instruction length — the back-probe window for `getCodeUnitContaining`.
const MAX_INSN_LEN: u64 = 16;

pub struct SharedReturnAnalyzer {
    ram: SpaceId,
    /// `assumeContiguousFunctions` — Ghidra's x86 pspec default is `true`.
    assume_contiguous_functions: bool,
    /// `considerConditionalBranches` — Ghidra default `false`.
    consider_conditional_branches: bool,
    spec: Spec,
    ctx: Vec<u32>,
}

impl SharedReturnAnalyzer {
    /// Build the analyzer, or `None` if the SLEIGH tables for the program's language are
    /// unavailable (the fall-through guard needs to decode the predecessor instruction).
    pub fn for_program(program: &Program) -> Option<SharedReturnAnalyzer> {
        let (spec, ctx) = crate::lang::load(&program.language_id)?;
        Some(SharedReturnAnalyzer {
            ram: program.default_space,
            assume_contiguous_functions: true,
            consider_conditional_branches: false,
            spec,
            ctx,
        })
    }

    /// `getSingleFlowReferenceFrom` — the lone memory **flow** reference out of the
    /// instruction at `from`, or `None` if there is not exactly one.
    fn single_flow_reference_from(&self, program: &Program, from: Address) -> Option<(Address, RefType)> {
        let mut found: Option<(Address, RefType)> = None;
        let mut count = 0;
        for r in program.reference_manager.refs_from(from) {
            if !r.ref_type.is_flow() {
                continue;
            }
            count += 1;
            if count > 1 {
                return None; // only change if single flow
            }
            found = Some((r.to, r.ref_type));
        }
        found
    }

    /// The flow reference `applyTo`'s contiguous-function scan reads out of an instruction
    /// (SharedReturnAnalysisCmd.java:100-110). It is deliberately NOT
    /// [`single_flow_reference_from`]: its "ignore points with multiple flows" `break` fires
    /// *after* `flow`/`destAddr` have been assigned and never clears them, so a second flow
    /// reference stops the scan but leaves the **first** one in play. Kept as its own method so
    /// the difference from the helper Ghidra uses in `processFunctionJumpReferences` is
    /// explicit rather than accidental.
    fn first_flow_reference_from(&self, program: &Program, from: Address) -> Option<(Address, RefType)> {
        program
            .reference_manager
            .refs_from(from)
            .find(|r| r.ref_type.is_flow())
            .map(|r| (r.to, r.ref_type))
    }

    /// `SharedReturnAnalysisCmd.processFunctionJumpReferences` — apply `CALL_RETURN` to the
    /// single-flow jump sources that jump to function `entry`. Collects the instructions to
    /// override and the reference retypes to apply, rather than mutating as it goes, mirroring
    /// Ghidra's own reason: "since reference fixup will occur when flow override is done, avoid
    /// concurrent modification during reference iterator use by building list of jump
    /// references" (SharedReturnAnalysisCmd.java:379).
    fn process_function_jump_references(
        &self,
        program: &Program,
        entry: Address,
        overrides: &mut Vec<Address>,
        retypes: &mut Vec<(Address, Address, RefType)>,
    ) {
        // getJumpRefsToFunction: JUMP references to `entry` (skipping conditional ones unless
        // considerConditionalBranches).
        let jump_refs: Vec<(Address, Address, RefType)> = program
            .reference_manager
            .refs_to(entry)
            .filter(|r| r.ref_type.is_jump_like())
            .filter(|r| {
                self.consider_conditional_branches
                    || !matches!(
                        r.ref_type,
                        RefType::ConditionalJump | RefType::ConditionalComputedJump
                    )
            })
            .map(|r| (r.from, r.to, r.ref_type))
            .collect();

        for (from, to, _) in jump_refs {
            // The source instruction must exist (getInstructionAt).
            if program.listing.code_unit_at(from).is_none() {
                continue;
            }
            // getSingleFlowReferenceFrom: only a single flow out of the source.
            let Some((check_to, check_type)) = self.single_flow_reference_from(program, from) else {
                continue;
            };
            // "if there is a function at this address, this is a thunk" — handle differently.
            if program.function_manager.function_at(from).is_some() {
                continue;
            }
            // "if this instruction is contained in the body of the function then it is just
            // an internal jump reference to the top of the function".
            if let Some(containing) = program.function_manager.function_containing(from) {
                if containing.entry_point() == entry {
                    continue;
                }
            }
            // checkRef.getToAddress().equals(ref.getToAddress()): the single flow goes to the
            // same target (and is a jump, i.e. would actually be overridden).
            if check_to != to {
                continue;
            }
            // "if (instr.getFlowOverride() != FlowOverride.NONE) continue;"
            // (SharedReturnAnalysisCmd.java:417) — an instruction analysis has already
            // overridden is left alone. This guard used to be absent because the override was
            // modelled *solely* by the resulting reference type, which made re-application
            // accidentally idempotent; now that the override is carried on the instruction
            // (`Program::flow_overrides`) the real guard applies.
            if program.flow_override_at(from) != FlowOverride::None {
                continue;
            }
            // SetFlowOverrideCmd(refInstrAddr, FlowOverride.CALL_RETURN) (:420). The override is
            // the primary effect — it is what makes the instruction's flow CALL_TERMINATOR and
            // therefore stops it falling through. The reference retype is the *consequence*:
            // `InstructionDB.setFlowOverride` runs a reference fixup that re-derives the flow
            // reference's type from the new flow via getDefaultJumpOrCallFlowType —
            // UNCONDITIONAL_CALL for a plain jump.
            overrides.push(from);
            let overridden_flow = modified_flow_type(check_type, FlowOverride::CallReturn);
            if let Some(new_ref_type) = default_jump_or_call_flow_type(overridden_flow) {
                if new_ref_type != check_type {
                    retypes.push((from, to, new_ref_type));
                }
            }
        }
    }

    /// `SharedReturnAnalysisCmd`'s `checkAboveFunction` + `checkBelowFunction`
    /// (SharedReturnAnalysisCmd.java:297,312), applied to each destination function in
    /// ASCENDING address order — Ghidra drives them from `symbolTable.getSymbols(set,
    /// FUNCTION, true)`, and the order matters because `checkBelowFunction` **deletes** a
    /// single-range body from the set that earlier iterations may have added.
    ///
    /// - above: `[prevFunction.entry, fnAddr]`, or `[space.min, fnAddr]` when there is none.
    /// - below: the body first, but only if it is discontiguous (`numAddressRanges > 1`);
    ///   then `[fnAddr, nextFunction.entry - 1]` (or `[fnAddr, space.max]`); then, if the body
    ///   IS a single range, that body is deleted again — a contiguous function's own
    ///   instructions are not scanned on its own account (a later function's `checkAbove` may
    ///   still bring them back).
    fn build_jump_scan_set(&self, program: &Program, entries: &[Address]) -> AddressSet {
        let mut scan = AddressSet::new();
        let mut sorted: Vec<Address> = entries.to_vec();
        sorted.sort_by_key(|a| a.offset);
        for entry in sorted {
            // checkAboveFunction
            let above_lo = program
                .function_manager
                .function_before(entry)
                .map(|f| f.entry_point().offset)
                .unwrap_or(0);
            scan.add_range(self.ram, above_lo, entry.offset);

            // checkBelowFunction
            let body = program
                .function_manager
                .function_at(entry)
                .map(|f| f.body().clone())
                .unwrap_or_default();
            let body_ranges = body.ranges().count();
            if body_ranges > 1 {
                scan = scan.union(&body);
            }
            let below_hi = program
                .function_manager
                .function_after(entry)
                .map(|f| f.entry_point().offset - 1)
                .unwrap_or(u64::MAX);
            if below_hi >= entry.offset {
                scan.add_range(self.ram, entry.offset, below_hi);
            }
            if body_ranges <= 1 {
                scan = scan.subtract(&body);
            }
        }
        scan
    }

    /// `SharedReturnAnalysisCmd.createFunction` — if a function already exists at `entry`,
    /// (re-)process its jump references; otherwise create it. Ghidra's
    /// `checkIfCouldHaveFallThruTo` guard (do not create if the entry has a real
    /// fall-through predecessor, or is a lone terminator) is ported to avoid splitting a
    /// function that flow would reach by fall-through.
    fn create_function(
        &self,
        program: &mut Program,
        entry: Address,
        new_functions: &mut AddressSet,
        overrides: &mut Vec<Address>,
        retypes: &mut Vec<(Address, Address, RefType)>,
    ) {
        if program.function_manager.function_at(entry).is_some() {
            self.process_function_jump_references(program, entry, overrides, retypes);
            return;
        }
        if self.could_have_fall_thru_to(program, entry) {
            return;
        }
        // analysisMgr.createFunction: create the function + its default symbol, and schedule
        // it (function_defined re-triggers FunctionCreator → disassembly → reference recovery).
        let name = format!("FUN_{:08x}", entry.offset);
        if program.function_manager.create_function(entry, &name, AddressSet::new()) {
            if !program.symbol_table.has_symbol_at(entry) {
                program.symbol_table.add_with_primary(entry, &name, SymbolType::Function, true);
            }
            new_functions.add_range(entry.space, entry.offset, entry.offset);
            // The newly created function is itself a shared-return destination — process its
            // jump references now (Ghidra re-enters via the FUNCTION_ANALYZER event).
            self.process_function_jump_references(program, entry, overrides, retypes);
        }
    }

    /// `SharedReturnAnalysisCmd.checkIfCouldHaveFallThruTo` (SharedReturnAnalysisCmd.java:275)
    /// — true if `location` has (or could later have) a real fall-through predecessor, or is
    /// itself a terminator instruction. Ghidra's three arms, in order:
    ///
    /// 1. `getInstructionAt(location) == null` → true ("if there is no instruction yet,
    ///    function may not be created yet").
    /// 2. `instr.getFallFrom()`'s instruction falls through to `location` → true.
    ///    `InstructionDB.getFallFrom` (InstructionDB.java:211) is `getInstructionContaining
    ///    (location - alignment)` (x86 has no delay slots, alignment 1) filtered by
    ///    `fallThrough == location`; Ghidra then re-checks that same instruction's
    ///    fall-through, so the two tests collapse into one.
    /// 3. `instr.getFlowType() == RefType.TERMINATOR` → true ("a single instruction that is
    ///    terminal consider as having a possible future fallthru to").
    ///
    /// **Nothing else.** In particular there is no "location lies inside some function's
    /// body" arm: a tail-call destination is *always* inside the jumping function's body
    /// (flow follows the `jmp` into it), so such a gate vetoes every shared-return
    /// destination — which is precisely what kept WAR2's `FUN_00067f40` / `FUN_00072301` /
    /// `FUN_00079330` (and 28 more) from being created. `oracle/ground-truth/src/tailjmp.c`
    /// is the self-compiled repro.
    fn could_have_fall_thru_to(&self, program: &Program, location: Address) -> bool {
        if program.listing.code_unit_at(location).is_none() {
            return true;
        }
        // getFallFrom(): the instruction abutting `location` from below whose fall-through is
        // `location`.
        if location.offset > 0 {
            if let Some((prev_addr, prev_len)) = program
                .listing
                .code_unit_containing(Address::new(location.space, location.offset - 1), MAX_INSN_LEN)
            {
                if prev_addr.offset + prev_len == location.offset
                    && self.instruction_falls_through(program, prev_addr)
                {
                    return true;
                }
            }
        }
        self.instruction_is_terminator(program, location)
    }

    /// Decode the instruction at `addr` with the SLEIGH engine (same as `Disassembler`).
    fn decode(&self, program: &Program, addr: Address) -> Option<crate::sleigh::Instruction> {
        let window = program.memory.read_window(addr, MAX_INSN_LEN as usize);
        self.spec.disassemble_ctx(&window, addr.offset, &self.ctx).into_iter().next()
    }

    /// `Instruction.getFallThrough() != null` for the instruction at `addr` — Ghidra reads it
    /// off the instruction's prototype flow type, so this goes through
    /// [`crate::analysis::flowtype::has_fallthrough`] rather than looking at the last p-code
    /// op. The difference is not cosmetic: `rep movs` lifts to an internal loop whose LAST op
    /// is a p-code-relative `BRANCH`, so the last-op reading calls it an unconditional jump
    /// and reports no fall-through — which made `checkIfCouldHaveFallThruTo` miss the veto and
    /// split WAR2's `FUN_00012e68` at the `rep movsw` boundary.
    fn instruction_falls_through(&self, program: &Program, addr: Address) -> bool {
        let Some(insn) = self.decode(program, addr) else {
            return false;
        };
        has_fallthrough(&insn.ops, addr.offset, addr.offset + insn.bytes.len() as u64)
    }

    /// Whether the instruction at `addr` has Ghidra flow type `RefType.TERMINATOR`
    /// (`crate::analysis::flowtype::is_terminator_flow`) — a `ret`, or a no-fall-through
    /// instruction with no real destination (`hlt`).
    fn instruction_is_terminator(&self, program: &Program, addr: Address) -> bool {
        self.decode(program, addr).is_some_and(|insn| {
            is_terminator_flow(&insn.ops, addr.offset, addr.offset + insn.bytes.len() as u64)
        })
    }
}

impl Analyzer for SharedReturnAnalyzer {
    fn name(&self) -> &str {
        "Shared Return Calls"
    }
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Function
    }
    fn priority(&self) -> AnalysisPriority {
        // See the module note: after FunctionCreator (FUNCTION) and reference recovery
        // (REFERENCE), where Ghidra's precondition (functions + flow refs present) holds.
        AnalysisPriority::REFERENCE.after()
    }
    fn added(&self, program: &mut Program, set: &AddressSet, sched: &mut Scheduling) -> bool {
        // The trigger set is newly-created functions. Ghidra (SharedReturnJumpAnalyzer +
        // SharedReturnAnalysisCmd) processes the destination functions in `set` plus the
        // contiguous-function jump scan.
        //
        // `symbolTable.getSymbols(set, SymbolType.FUNCTION, true)` (SharedReturnAnalysisCmd.java:66
        // and again at :80) — **every** FUNCTION symbol whose address lies in `set`, ASCENDING;
        // that is exactly the function entries contained in the set. It is NOT one per range:
        // an `AddressSet` coalesces adjacent ranges, so functions at consecutive entries
        // (`08048110 sink_` / `08048111 __CHK` / `08048112 p_leaf_` on `wprobe.watcom-x86-32`)
        // collapse into a single range and reading `r.min` kept only the first
        // (`docs/function-discovery-backlog.md`, CAUSE B).
        let new_function_entries: Vec<Address> = {
            let mut entries: Vec<u64> = program
                .function_manager
                .functions()
                .map(|f| f.entry_point())
                .filter(|e| e.space == self.ram && set.contains(*e))
                .map(|e| e.offset)
                .collect();
            entries.sort_unstable(); // getSymbols(..., true) — ascending
            entries.into_iter().map(|off| Address::new(self.ram, off)).collect()
        };
        if new_function_entries.is_empty() {
            return false;
        }

        let mut overrides: Vec<Address> = Vec::new();
        let mut retypes: Vec<(Address, Address, RefType)> = Vec::new();
        let mut new_functions = AddressSet::new();

        // Part 1 — processFunctionJumpReferences for each destination function in `set`.
        for entry in &new_function_entries {
            self.process_function_jump_references(program, *entry, &mut overrides, &mut retypes);
        }

        // Part 2 — assumeContiguousFunctions: scan the unconditional jumps around each
        // destination function's boundaries; a jump crossing a neighbouring function's entry
        // is a shared-return tail call into a new function at the destination.
        if self.assume_contiguous_functions {
            let scan = self.build_jump_scan_set(program, &new_function_entries);

            // getReferenceSourceIterator(jumpScanSet, true) — every reference SOURCE address in
            // the scan set, ASCENDING. The order is load-bearing: the two cursors below are
            // carried across iterations, so a source's verdict depends on the ones before it.
            let mut src_offsets: Vec<u64> = program
                .reference_manager
                .references()
                .map(|r| r.from)
                .filter(|a| a.space == self.ram && scan.contains(*a))
                .map(|a| a.offset)
                .collect();
            src_offsets.sort_unstable();
            src_offsets.dedup();

            // `functionAfterSrc` / `functionBeforeSrc`, with Java's three states modelled as
            // `None` (null — never queried), `Some(None)` (Address.NO_ADDRESS — queried, no
            // such function) and `Some(Some(a))` (an entry point). These are **caches that
            // change the answer**, not an optimisation: `functionBeforeSrc` is re-queried only
            // once the walk has passed `functionAfterSrc`, so while it is frozen it holds the
            // function-before of an EARLIER address — always lower than a fresh query — and
            // `destAddr < functionBeforeSrc` therefore fails where a fresh query would pass.
            // Re-querying both on every source (which is what a "cleaned-up" version does)
            // over-creates: on WAR2 it invents functions at three shared epilogues
            // (0x51e12 / 0x53254 / 0x78039) that Ghidra's own
            // `SharedReturnAnalysisCmd`, run one-shot over the whole program, does not create.
            let mut function_after_src: Option<Option<u64>> = None;
            let mut function_before_src: Option<Option<u64>> = None;

            for off in src_offsets {
                let src = Address::new(self.ram, off);
                let Some((dest, flow)) = self.first_flow_reference_from(program, src) else {
                    continue; // destAddr == null || flow == null
                };
                if !flow.is_jump_like()
                    || matches!(flow, RefType::ConditionalJump | RefType::ConditionalComputedJump)
                {
                    continue; // !flow.isJump() || !flow.isUnConditional()
                }
                if src.space != dest.space {
                    continue; // can't handle flows between different spaces/overlays
                }
                let fn_after = |p: &Program, a: Address| {
                    p.function_manager.function_after(a).map(|f| f.entry_point().offset)
                };
                let fn_before = |p: &Program, a: Address| {
                    p.function_manager.function_before(a).map(|f| f.entry_point().offset)
                };

                if src.offset < dest.offset {
                    // ---- forward jump ----
                    if function_after_src == Some(None) {
                        continue; // no function after srcAddr
                    }
                    if function_after_src.is_none()
                        || function_after_src.unwrap().unwrap() <= src.offset
                    {
                        match fn_after(program, src) {
                            Some(e) => function_after_src = Some(Some(e)),
                            None => {
                                function_after_src = Some(None);
                                continue; // no function after srcAddr
                            }
                        }
                    }
                    if dest.offset >= function_after_src.unwrap().unwrap() {
                        self.create_function(program, dest, &mut new_functions, &mut overrides, &mut retypes);
                    }
                } else {
                    // ---- backward jump ----
                    // prime lastFunctionAfterSrc if not previously set
                    if function_after_src.is_none() {
                        function_after_src = Some(fn_after(program, src));
                    }
                    if function_before_src == Some(None) {
                        if function_after_src == Some(None) {
                            continue; // no functions exist - rare
                        }
                        if src.offset < function_after_src.unwrap().unwrap() {
                            continue; // we have not passed next function - no function before
                        }
                        function_before_src = None; // must re-query
                        function_after_src = Some(fn_after(program, src));
                    }
                    // if we have not passed lastFunctionAfter then no change to
                    // lastFunctionBefore
                    let keep = function_before_src.is_some()
                        && (function_after_src == Some(None)
                            || src.offset < function_after_src.unwrap().unwrap());
                    if !keep {
                        match fn_before(program, src) {
                            Some(e) => function_before_src = Some(Some(e)),
                            None => {
                                function_before_src = Some(None);
                                continue; // no function before srcAddr
                            }
                        }
                    }
                    if dest.offset < function_before_src.unwrap().unwrap() {
                        self.create_function(program, dest, &mut new_functions, &mut overrides, &mut retypes);
                    }
                }
            }
        }

        // Apply the collected flow overrides, then the reference retypes they imply (Ghidra
        // does both inside `InstructionDB.setFlowOverride`; here the override is stored on the
        // instruction and the reference fixup follows it).
        for from in &overrides {
            program.set_flow_override(*from, FlowOverride::CallReturn);
        }
        for (from, to, new_type) in &retypes {
            program.reference_manager.retype(*from, *to, *new_type);
        }
        // Schedule the new functions for disassembly + reference recovery.
        if !new_functions.is_empty() {
            sched.function_defined(&new_functions);
        }
        !overrides.is_empty() || !retypes.is_empty() || !new_functions.is_empty()
    }
}

#[cfg(test)]
mod destination_set_tests {
    use super::*;
    use crate::analysis::manager::Scheduling;
    use crate::analysis::program::CodeUnit;
    use crate::decompile::space::{SpaceKind, SpaceManager};

    fn program() -> Program {
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
        let base = Address::new(ram, 0x40_1000);
        let mut p = Program::new(spaces, ram, "x86:LE:64:default", "gcc", base, false, 64);
        p.memory.add_block(".text", base, 0x1000, true, false, true, Some(vec![0; 0x1000]));
        p
    }

    fn make_function(p: &mut Program, off: u64) {
        let ram = p.default_space;
        p.function_manager.create_function(
            Address::new(ram, off),
            &format!("FUN_{off:08x}"),
            AddressSet::new(),
        );
    }

    /// CAUSE B (`docs/function-discovery-backlog.md`): `SharedReturnAnalysisCmd.applyTo` drives
    /// `symbolTable.getSymbols(set, SymbolType.FUNCTION, true)` (SharedReturnAnalysisCmd.java:66)
    /// — **every** function symbol in the set. Reading one entry per `AddressSet` range instead
    /// drops all but the first of any run of adjacent entries, because the set coalesces them
    /// (`wprobe.watcom-x86-32`: `08048110` / `08048111` / `08048112`).
    ///
    /// Here the shared-return jump targets the THIRD of three adjacent entries, so under the
    /// range-minimum reading `processFunctionJumpReferences` is never run for it and the
    /// `UNCONDITIONAL_JUMP` is never re-typed to `UNCONDITIONAL_CALL`.
    ///
    /// `assume_contiguous_functions` is off so part 2 cannot supply the same effect by another
    /// route — the assertion measures the destination-set iteration and nothing else.
    #[test]
    fn every_function_entry_in_the_set_is_a_destination_not_just_the_range_minimum() {
        let Some((spec, ctx)) = crate::lang::load("x86:LE:64:default") else {
            return; // SLEIGH tables unavailable
        };
        let mut p = program();
        let ram = p.default_space;
        for off in [0x40_1010, 0x40_1011, 0x40_1012] {
            make_function(&mut p, off);
        }
        // A `jmp 0x401012` at 0x401000: a code unit with exactly one flow reference out, in no
        // function of its own (so it is neither a thunk nor an internal jump).
        let src = Address::new(ram, 0x40_1000);
        let dest = Address::new(ram, 0x40_1012);
        p.listing.define(src, CodeUnit::Instruction { length: 5 });
        p.reference_manager.add(src, dest, RefType::UnconditionalJump, -1);

        let a = SharedReturnAnalyzer {
            ram,
            assume_contiguous_functions: false,
            consider_conditional_branches: false,
            spec,
            ctx,
        };
        let mut set = AddressSet::new();
        for off in [0x40_1010, 0x40_1011, 0x40_1012] {
            set.add_range(ram, off, off);
        }
        assert_eq!(set.ranges().count(), 1, "the three entries must coalesce for this to bite");

        a.added(&mut p, &set, &mut Scheduling::default());

        let types: Vec<RefType> =
            p.reference_manager.refs_from(src).map(|r| r.ref_type).collect();
        assert_eq!(
            types,
            vec![RefType::UnconditionalCall],
            "the jump to the function at 0x401012 is a shared-return tail call and must be \
             re-typed; taking only the range minimum processes 0x401010 and stops"
        );
    }
}
