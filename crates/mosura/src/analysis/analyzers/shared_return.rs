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
    spec: &'static Spec,
    ctx: &'static [u32],
}

impl SharedReturnAnalyzer {
    /// Build the analyzer, or `None` if the SLEIGH tables for the program's language are
    /// unavailable (the fall-through guard needs to decode the predecessor instruction).
    pub fn for_program(program: &Program) -> Option<SharedReturnAnalyzer> {
        let (spec, ctx) = crate::lang::load_cached(&program.language_id)?;
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
        crate::analysis::analyzers::decode_listed(program, self.spec, self.ctx, addr)
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

/// The two lookup cursors `SharedReturnAnalysisCmd.applyTo` carries across its ascending walk
/// (SharedReturnAnalysisCmd.java:88-89), with Java's three states modelled as `None` (null —
/// never queried), `Some(None)` (`Address.NO_ADDRESS` — queried, no such function) and
/// `Some(Some(a))` (an entry point).
///
/// These are **caches that change the answer**, not an optimisation: `functionBeforeSrc` is
/// re-queried only once the walk has passed `functionAfterSrc`, so while it is frozen it holds the
/// function-before of an EARLIER address — never higher than a fresh query — and
/// `destAddr < functionBeforeSrc` therefore fails where a fresh query would pass. Re-querying both
/// on every source (which is what a "cleaned-up" version does) over-creates: on WAR2 it invents
/// functions at three shared epilogues (0x51e12 / 0x53254 / 0x78039) that Ghidra's own
/// `SharedReturnAnalysisCmd`, run one-shot over the whole program, does not create.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Cursors {
    /// `functionAfterSrc`.
    pub after: Option<Option<u64>>,
    /// `functionBeforeSrc`.
    pub before: Option<Option<u64>>,
}

impl SharedReturnAnalyzer {
    /// One iteration of `applyTo`'s `refSrcIter` loop (SharedReturnAnalysisCmd.java:92-193):
    /// decide what the source at `src` does, advancing the carried cursors. `Some(dest)` means
    /// Ghidra would call `createFunction(destAddr)`.
    ///
    /// Extracted so that [`Self::report_scan`] runs **this** code rather than a second copy of
    /// it — a re-implementation would measure itself, not the port.
    fn scan_step(&self, program: &Program, cur: &mut Cursors, src: Address) -> Option<Address> {
        let (dest, flow) = self.first_flow_reference_from(program, src)?; // destAddr/flow == null
        if !flow.is_jump_like()
            || matches!(flow, RefType::ConditionalJump | RefType::ConditionalComputedJump)
        {
            return None; // !flow.isJump() || !flow.isUnConditional()
        }
        if src.space != dest.space {
            return None; // can't handle flows between different spaces/overlays
        }
        let fn_after = |p: &Program, a: Address| {
            p.function_manager.function_after(a).map(|f| f.entry_point().offset)
        };
        let fn_before = |p: &Program, a: Address| {
            p.function_manager.function_before(a).map(|f| f.entry_point().offset)
        };

        if src.offset < dest.offset {
            // ---- forward jump ----
            if cur.after == Some(None) {
                return None; // no function after srcAddr
            }
            if cur.after.is_none() || cur.after.unwrap().unwrap() <= src.offset {
                match fn_after(program, src) {
                    Some(e) => cur.after = Some(Some(e)),
                    None => {
                        cur.after = Some(None);
                        return None; // no function after srcAddr
                    }
                }
            }
            (dest.offset >= cur.after.unwrap().unwrap()).then_some(dest)
        } else {
            // ---- backward jump ----
            // prime lastFunctionAfterSrc if not previously set
            if cur.after.is_none() {
                cur.after = Some(fn_after(program, src));
            }
            if cur.before == Some(None) {
                if cur.after == Some(None) {
                    return None; // no functions exist - rare
                }
                if src.offset < cur.after.unwrap().unwrap() {
                    return None; // we have not passed next function - no function before
                }
                cur.before = None; // must re-query
                cur.after = Some(fn_after(program, src));
            }
            // if we have not passed lastFunctionAfter then no change to lastFunctionBefore
            let keep = cur.before.is_some()
                && (cur.after == Some(None) || src.offset < cur.after.unwrap().unwrap());
            if !keep {
                match fn_before(program, src) {
                    Some(e) => cur.before = Some(Some(e)),
                    None => {
                        cur.before = Some(None);
                        return None; // no function before srcAddr
                    }
                }
            }
            (dest.offset < cur.before.unwrap().unwrap()).then_some(dest)
        }
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

            // The carried cursors — see [`Cursors`] for why they are semantic, not a cache.
            let mut cursors = Cursors::default();

            for off in src_offsets {
                let src = Address::new(self.ram, off);
                if let Some(dest) = self.scan_step(program, &mut cursors, src) {
                    self.create_function(program, dest, &mut new_functions, &mut overrides, &mut retypes);
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

// ---------------------------------------------------------------------------------------------
// The instrument (task #3). Not part of the port: it replays the scan above read-only and puts
// the CARRIED verdict beside the FRESH one, so "the cursors declined it" is measured rather than
// assumed. Creations are suppressed, so it answers "with this function set held fixed, what does
// each source decide" — see [`SharedReturnAnalyzer::report_scan`].
// ---------------------------------------------------------------------------------------------

/// One reference source as the contiguous-function scan sees it.
#[derive(Debug, Clone, Copy)]
pub struct SourceDecision {
    pub src: Address,
    pub dest: Address,
    pub ref_type: RefType,
    /// Cursor state as the source was reached (i.e. carried in from the sources before it).
    pub carried_in: Cursors,
    /// Would `createFunction(dest)` run, with the carried cursors?
    pub carried_creates: bool,
    /// ...and with cursors primed from nothing at this source — Ghidra's state on the first
    /// source of a fresh `SharedReturnAnalysisCmd`, which is what a finer invocation gives it.
    pub fresh_creates: bool,
    /// Is there already a function at `dest`?
    pub dest_is_function: bool,
    /// Would `createFunction` then decline anyway? `checkIfCouldHaveFallThruTo`
    /// (SharedReturnAnalysisCmd.java:275) is applied AFTER the cursor test, so a create verdict
    /// is not yet a created function — without this column a guarded decline reads as work the
    /// pass failed to do.
    pub blocked_by_fallthru_guard: bool,
}

impl SourceDecision {
    /// The only rows that bear on invocation granularity: the carried cursors and a fresh pair
    /// disagree about this source.
    pub fn diverges(&self) -> bool {
        self.carried_creates != self.fresh_creates
    }
}

/// What one invocation of the contiguous-function scan would do, with creations suppressed.
pub struct ScanReport {
    /// The function entries in the invocation's `set` (`getSymbols(set, FUNCTION, true)`).
    pub set_entries: usize,
    /// `jumpScanSet` — what `checkAboveFunction`/`checkBelowFunction` built.
    pub scan: AddressSet,
    pub decisions: Vec<SourceDecision>,
}

impl SharedReturnAnalyzer {
    /// Replay [`Self::added`]'s `assumeContiguousFunctions` scan over `set` **read-only**,
    /// recording each source's verdict under the carried cursors and under a fresh pair.
    ///
    /// ⚠️ **WHAT THIS CAN AND CANNOT SAY.** It runs the same [`Self::scan_step`] the port runs, so
    /// the carried column is the real one. But the live scan CREATES functions as it goes and this
    /// one does not, so the two diverge after the live scan's first creation: this is the answer
    /// for the function set **held fixed**, which is the right question for "was the set missing
    /// something when this source was scanned?" and the wrong one for "what did round 1 actually
    /// do end to end". Take it on a converged program, where the set is the final one.
    ///
    /// A source that does not appear in [`ScanReport::decisions`] was never scanned at all —
    /// check [`ScanReport::scan`] for whether the address was in `jumpScanSet`. That is a real and
    /// separate reason for a missing function: `checkBelowFunction` DELETES a contiguous
    /// function's own body from the scan on its own account (SharedReturnAnalysisCmd.java:326-337),
    /// and only another function's `checkAboveFunction` puts it back.
    pub fn report_scan(&self, program: &Program, set: &AddressSet) -> ScanReport {
        let entries: Vec<Address> = {
            let mut v: Vec<u64> = program
                .function_manager
                .functions()
                .map(|f| f.entry_point())
                .filter(|e| e.space == self.ram && set.contains(*e))
                .map(|e| e.offset)
                .collect();
            v.sort_unstable();
            v.into_iter().map(|off| Address::new(self.ram, off)).collect()
        };
        let scan = self.build_jump_scan_set(program, &entries);

        let mut src_offsets: Vec<u64> = program
            .reference_manager
            .references()
            .map(|r| r.from)
            .filter(|a| a.space == self.ram && scan.contains(*a))
            .map(|a| a.offset)
            .collect();
        src_offsets.sort_unstable();
        src_offsets.dedup();

        let mut cursors = Cursors::default();
        let mut decisions = Vec::new();
        for off in src_offsets {
            let src = Address::new(self.ram, off);
            let carried_in = cursors;
            let carried = self.scan_step(program, &mut cursors, src);
            // The same step from a standing start — one source is all a fresh command sees before
            // it reaches this one when the invocation is finer.
            let fresh = self.scan_step(program, &mut Cursors::default(), src);
            // A row for every source the scan EVALUATES, not only the ones it acts on: a decline
            // is the whole question here, so recording only `Some(dest)` would drop exactly the
            // rows being asked about.
            let Some((dest, ref_type)) = self.first_flow_reference_from(program, src) else {
                continue;
            };
            if !ref_type.is_jump_like()
                || matches!(ref_type, RefType::ConditionalJump | RefType::ConditionalComputedJump)
                || src.space != dest.space
            {
                continue; // `!flow.isJump() || !flow.isUnConditional()`, or a cross-space flow
            }
            decisions.push(SourceDecision {
                src,
                dest,
                ref_type,
                carried_in,
                carried_creates: carried.is_some(),
                fresh_creates: fresh.is_some(),
                dest_is_function: program.function_manager.function_at(dest).is_some(),
                blocked_by_fallthru_guard: self.could_have_fall_thru_to(program, dest),
            });
        }
        ScanReport { set_entries: entries.len(), scan, decisions }
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
        let Some((spec, ctx)) = crate::lang::load_cached("x86:LE:64:default") else {
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
        p.listing.define(src, CodeUnit::instruction(5));
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

    /// ⭐ **THE MVE for task #3: the invocation SET is semantic.** The same program, the same
    /// analyzer, the same final function set — two invocation granularities, two different
    /// answers. That is the claim "mosura calls the command once with every function, Ghidra calls
    /// it per creation round" rests on, and it is measured here rather than argued.
    ///
    /// ```text
    /// 0x400800  E: a function                      }
    /// 0x400900  D: the tail-call DESTINATION       }  no function here yet
    /// 0x401000  F: a function, body [0x401000, 0x4010ff] — ONE range
    /// 0x401080  S:   jmp 0x400900                  }  inside F's body
    /// 0x401200  G: a function
    /// ```
    ///
    /// `S` is a backward jump and `getFunctionBefore(S) = F`, so `destAddr < functionBeforeSrc`
    /// holds and the cursor test says *create a function at D*. Whether that test is ever reached
    /// depends entirely on `jumpScanSet`:
    ///
    /// - **set = {E, F, G}** (mosura's whole-program pass): `checkBelowFunction(F)` deletes F's
    ///   single-range body — with `S` in it — but `checkAboveFunction(G)` then re-adds
    ///   `[F.entry, G.entry]` (SharedReturnAnalysisCmd.java:297-305), so `S` **is** scanned and D
    ///   is created.
    /// - **set = {F}** (the per-round invocation Ghidra makes when F is created): nothing re-adds
    ///   the body, so `S` is never scanned and D is **not** created.
    ///
    /// ⚠️ Note the DIRECTION, because it contradicts the intuitive story: the finer invocation
    /// sees *less* here, not more. Granularity does not monotonically buy recall, so "make it
    /// per-round" cannot be justified as a recall argument — only as a faithfulness one.
    #[test]
    fn the_invocation_set_decides_whether_a_tail_call_destination_is_created() {
        let Some((spec, ctx)) = crate::lang::load_cached("x86:LE:64:default") else {
            return; // SLEIGH tables unavailable
        };
        let build = || {
            let mut p = program();
            let ram = p.default_space;
            // E and G: plain functions with a one-instruction body.
            for off in [0x40_0800u64, 0x40_1200] {
                let mut body = AddressSet::new();
                body.add_range(ram, off, off);
                p.function_manager.create_function(
                    Address::new(ram, off),
                    &format!("FUN_{off:08x}"),
                    body,
                );
            }
            // F, with ONE contiguous body range that contains the jump source.
            let mut f_body = AddressSet::new();
            f_body.add_range(ram, 0x40_1000, 0x40_10ff);
            p.function_manager.create_function(
                Address::new(ram, 0x40_1000),
                "FUN_00401000",
                f_body,
            );
            // S: `jmp 0x400900`, one flow reference out, inside F's body.
            let src = Address::new(ram, 0x40_1080);
            let dest = Address::new(ram, 0x40_0900);
            p.listing.define(src, CodeUnit::instruction(5));
            p.reference_manager.add(src, dest, RefType::UnconditionalJump, -1);
            // D: decoded, with no fall-through predecessor, so `checkIfCouldHaveFallThruTo` lets
            // the creation through — otherwise this fixture would measure that guard instead.
            p.listing.define(dest, CodeUnit::instruction(2));
            p
        };
        let analyzer = |p: &Program| SharedReturnAnalyzer {
            ram: p.default_space,
            assume_contiguous_functions: true,
            consider_conditional_branches: false,
            spec,
            ctx,
        };
        let entry_set = |p: &Program, offs: &[u64]| {
            let mut s = AddressSet::new();
            for &off in offs {
                s.add_range(p.default_space, off, off);
            }
            s
        };

        // --- whole-program invocation: G's checkAbove re-adds F's body, so S is scanned ---
        let mut whole = build();
        let ram = whole.default_space;
        let dest = Address::new(ram, 0x40_0900);
        let a = analyzer(&whole);
        let set = entry_set(&whole, &[0x40_0800, 0x40_1000, 0x40_1200]);
        assert!(
            a.report_scan(&whole, &set).scan.contains(Address::new(ram, 0x40_1080)),
            "fixture broken: the whole-program jumpScanSet must contain the jump source"
        );
        a.added(&mut whole, &set, &mut Scheduling::default());
        assert!(
            whole.function_manager.function_at(dest).is_some(),
            "the whole-program invocation scans S and must create the tail-call destination"
        );

        // --- per-round invocation for F alone: its own body is deleted and never restored ---
        let mut round = build();
        let a = analyzer(&round);
        let set = entry_set(&round, &[0x40_1000]);
        let r = a.report_scan(&round, &set);
        assert!(
            !r.scan.contains(Address::new(ram, 0x40_1080)),
            "checkBelowFunction deletes F's single-range body, and with only F in the set nothing \
             re-adds it — the source must be outside jumpScanSet"
        );
        assert!(
            r.decisions.is_empty(),
            "and therefore no source is evaluated at all: {:x?}",
            r.decisions.iter().map(|d| d.src.offset).collect::<Vec<_>>()
        );
        a.added(&mut round, &set, &mut Scheduling::default());
        assert!(
            round.function_manager.function_at(dest).is_none(),
            "the per-round invocation never reaches S, so it creates nothing — the two \
             granularities disagree, which is the whole of task #3's premise"
        );
    }

    /// ⭐ **HOW THE CARRIED CURSOR GOES STALE — with the function set held completely FIXED.**
    ///
    /// I told the lead that `keep == true` implies the carried `before` equals a fresh query
    /// whenever the set is static, reasoning that the cursor can only freeze an answer from an
    /// address with no intervening function entry. That is WRONG, and this fixture is the
    /// counter-example. The flaw: the **forward** branch updates `functionAfterSrc` and never
    /// touches `functionBeforeSrc` (SharedReturnAnalysisCmd.java:127-141). So a forward source can
    /// push `after` PAST later entries while `before` stays frozen at an answer from far below —
    /// and every backward source that follows, up to the new `after`, keeps that frozen value.
    ///
    /// ```text
    /// 0x401000  A                     }
    /// 0x401500     jmp 0x401400       } backward: before := A(0x401000), after := B(0x402000)
    /// 0x402000  B                     }
    /// 0x402500     jmp 0x402600       } FORWARD: after is stale-low, so re-query -> C(0x403000)
    /// 0x402800     jmp 0x401800       } backward: 0x402800 < after(0x403000) => KEEP
    /// 0x403000  C                     }
    /// ```
    ///
    /// At `0x402800` the carried `before` is still `0x401000`, while `getFunctionBefore` freshly
    /// answers `0x402000` — no function was created, nothing changed, the walk simply never
    /// re-asked. `destAddr < functionBeforeSrc` is then `0x401800 < 0x401000` (false) where a
    /// fresh pair gives `0x401800 < 0x402000` (true).
    ///
    /// ⚠️ **THE CONSEQUENCE FOR ANY PROPOSED FIX.** This is a property of the WALK, not of the
    /// function set, so re-running the same whole-program invocation later reproduces it exactly:
    /// the second pass starts from the bottom and arrives here with the same stale cursor. Only an
    /// invocation whose scan set STARTS near the source — Ghidra's per-round granularity — primes
    /// the cursors close enough to decide it freshly. WAR2's `0x69032` is this shape, measured:
    /// carried `before` = `0x67d45`, fresh = `0x68f25`.
    #[test]
    fn a_forward_source_leaves_the_before_cursor_stale_with_the_function_set_unchanged() {
        let Some((spec, ctx)) = crate::lang::load_cached("x86:LE:64:default") else {
            return; // SLEIGH tables unavailable
        };
        let mut p = program();
        let ram = p.default_space;
        for off in [0x40_1000u64, 0x40_2000, 0x40_3000] {
            let mut body = AddressSet::new();
            body.add_range(ram, off, off);
            p.function_manager.create_function(
                Address::new(ram, off),
                &format!("FUN_{off:08x}"),
                body,
            );
        }
        // Three jump sources, none of them a function entry.
        for (from, to) in [
            (0x40_1500u64, 0x40_1400u64), // backward — primes both cursors
            (0x40_2500, 0x40_2600),       // FORWARD — pushes `after` to C, leaves `before` alone
            (0x40_2800, 0x40_1800),       // backward — keeps the frozen `before`
        ] {
            let src = Address::new(ram, from);
            p.listing.define(src, CodeUnit::instruction(5));
            p.reference_manager.add(src, Address::new(ram, to), RefType::UnconditionalJump, -1);
        }

        let a = SharedReturnAnalyzer {
            ram,
            assume_contiguous_functions: true,
            consider_conditional_branches: false,
            spec,
            ctx,
        };
        let mut set = AddressSet::new();
        for off in [0x40_1000u64, 0x40_2000, 0x40_3000] {
            set.add_range(ram, off, off);
        }
        let r = a.report_scan(&p, &set);
        let row = r
            .decisions
            .iter()
            .find(|d| d.src.offset == 0x40_2800)
            .expect("the last source must be evaluated — otherwise this measures the scan set");

        assert_eq!(
            row.carried_in.before,
            Some(Some(0x40_1000)),
            "the carried `before` must still be A, frozen since 0x401500"
        );
        assert_eq!(
            p.function_manager.function_before(row.src).map(|f| f.entry_point().offset),
            Some(0x40_2000),
            "...while a fresh getFunctionBefore answers B — the set never changed"
        );
        assert!(
            !row.carried_creates && row.fresh_creates,
            "and the two disagree about creating 0x401800: carried={} fresh={}",
            row.carried_creates,
            row.fresh_creates
        );
        // The walk is deterministic in the set, so a SECOND identical invocation decides
        // identically — which is why "run the whole-program pass again at the end" cannot fix it.
        let again = a.report_scan(&p, &set);
        assert_eq!(
            again.decisions.iter().find(|d| d.src.offset == 0x40_2800).map(|d| d.carried_creates),
            Some(false),
            "a repeated whole-program invocation reproduces the same stale cursor"
        );
    }
}
