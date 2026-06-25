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
use crate::analysis::flowtype::{default_jump_or_call_flow_type, modified_flow_type, FlowOverride};
use crate::analysis::manager::Scheduling;
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, Program, RefType, SymbolType};
use crate::decompile::opcode::OpCode;
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

    /// `SharedReturnAnalysisCmd.processFunctionJumpReferences` — apply `CALL_RETURN` to the
    /// single-flow jump sources that jump to function `entry`. Returns the retypes to apply
    /// (collected to avoid mutating the reference manager mid-iteration, mirroring Ghidra's
    /// "build list of jump references" comment).
    fn process_function_jump_references(
        &self,
        program: &Program,
        entry: Address,
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
            // Apply FlowOverride.CALL_RETURN: the instruction's flow becomes CALL_TERMINATOR
            // (modified_flow_type), and the reference fixup re-derives the *reference* type
            // from that flow via getDefaultJumpOrCallFlowType — UNCONDITIONAL_CALL for a
            // plain jump. (Ghidra checks getFlowOverride() != NONE first; we model the
            // override solely by the resulting reference type, so re-applying is idempotent.)
            let overridden_flow = modified_flow_type(check_type, FlowOverride::CallReturn);
            if let Some(new_ref_type) = default_jump_or_call_flow_type(overridden_flow) {
                if new_ref_type != check_type {
                    retypes.push((from, to, new_ref_type));
                }
            }
        }
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
        retypes: &mut Vec<(Address, Address, RefType)>,
    ) {
        if program.function_manager.function_at(entry).is_some() {
            self.process_function_jump_references(program, entry, retypes);
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
            self.process_function_jump_references(program, entry, retypes);
        }
    }

    /// `SharedReturnAnalysisCmd.checkIfCouldHaveFallThruTo` — true if `location` has (or
    /// could later have) a real fall-through predecessor, or is a lone terminator
    /// instruction. We approximate `getFallFrom`/`getFallThrough` with the previous
    /// instruction: if the instruction immediately before `location` falls through to it,
    /// it must not be split into a new function.
    fn could_have_fall_thru_to(&self, program: &Program, location: Address) -> bool {
        if program.listing.code_unit_at(location).is_none() {
            // "if there is no instruction yet, function may not be created yet" → true.
            return true;
        }
        // A location strictly inside an existing function's (contiguous) body necessarily has
        // a real fall-through predecessor — that fall-through is what made the body
        // contiguous in the first place. This is the structural form of Ghidra's
        // getFallFrom→getFallThrough check: Ghidra's CreateFunctionCmd keeps functions
        // contiguous (subtractBodyFromExisting), and SharedReturnAnalysisCmd's
        // checkIfCouldHaveFallThruTo refuses to split such an interior point. (Reading it off
        // the body rather than re-decoding the predecessor is also robust to languages whose
        // single-instruction relift differs from the in-context disassembly.)
        if let Some(containing) = program.function_manager.function_containing(location) {
            if containing.entry_point() != location {
                return true;
            }
        }
        // Otherwise, fall back to decoding the predecessor: if the instruction immediately
        // before `location` abuts it and falls through, it must not be split into a function.
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
        false
    }

    /// Whether the instruction at `addr` falls through to its next address — the
    /// disassembler's flow classification (a terminal `RETURN`/`BRANCH`/`BRANCHIND` does
    /// not). Decodes the instruction with the SLEIGH engine (same as `Disassembler`).
    fn instruction_falls_through(&self, program: &Program, addr: Address) -> bool {
        let window = program.memory.read_window(addr, MAX_INSN_LEN as usize);
        let Some(insn) = self.spec.disassemble_ctx(&window, addr.offset, &self.ctx).into_iter().next()
        else {
            return false;
        };
        let last = insn.ops.last().and_then(|o| OpCode::from_u32(o.opcode));
        !matches!(last, Some(OpCode::Return | OpCode::Branch | OpCode::Branchind))
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
        let new_function_entries: Vec<Address> = {
            let entries: std::collections::BTreeSet<u64> =
                program.function_manager.functions().map(|f| f.entry_point().offset).collect();
            set.ranges()
                .filter(|r| entries.contains(&r.min))
                .map(|r| Address::new(self.ram, r.min))
                .collect()
        };
        if new_function_entries.is_empty() {
            return false;
        }

        let mut retypes: Vec<(Address, Address, RefType)> = Vec::new();
        let mut new_functions = AddressSet::new();

        // Part 1 — processFunctionJumpReferences for each destination function in `set`.
        for entry in &new_function_entries {
            self.process_function_jump_references(program, *entry, &mut retypes);
        }

        // Part 2 — assumeContiguousFunctions: for each new function, scan the unconditional
        // jumps around its boundaries; a jump crossing a neighbouring function's entry is a
        // shared-return tail call into a new function at the destination.
        if self.assume_contiguous_functions {
            // Build the jump-scan set: the gaps above/below each new function (Ghidra
            // checkAboveFunction/checkBelowFunction). We then examine every jump-reference
            // source in that set.
            let mut scan = AddressSet::new();
            for entry in &new_function_entries {
                // checkAboveFunction: [prevFunction.entry, entry] (or [min, entry]).
                let above_lo = program
                    .function_manager
                    .function_before(*entry)
                    .map(|f| f.entry_point().offset)
                    .unwrap_or(0);
                scan.add_range(self.ram, above_lo, entry.offset);
                // checkBelowFunction: [entry, nextFunction.entry - 1] (or [entry, max]).
                let below_hi = program
                    .function_manager
                    .function_after(*entry)
                    .map(|f| f.entry_point().offset - 1)
                    .unwrap_or(u64::MAX);
                if below_hi >= entry.offset {
                    scan.add_range(self.ram, entry.offset, below_hi);
                }
            }

            // For each source instruction in the scan set with a single unconditional jump
            // flow, apply the forward/backward boundary-crossing test.
            let mut src_offsets: Vec<u64> = program
                .reference_manager
                .references()
                .filter(|r| r.ref_type.is_flow())
                .map(|r| r.from)
                .filter(|a| a.space == self.ram && scan.contains(*a))
                .map(|a| a.offset)
                .collect();
            src_offsets.sort_unstable();
            src_offsets.dedup();
            let sources: Vec<Address> = src_offsets.into_iter().map(|o| Address::new(self.ram, o)).collect();

            for src in sources {
                // A single flow out of src that is an UNCONDITIONAL jump.
                let Some((dest, flow)) = self.single_flow_reference_from(program, src) else {
                    continue;
                };
                if !flow.is_jump_like()
                    || matches!(flow, RefType::ConditionalJump | RefType::ConditionalComputedJump)
                {
                    continue; // !flow.isJump() || !flow.isUnConditional()
                }
                if src.space != dest.space {
                    continue;
                }
                if src.offset < dest.offset {
                    // forward jump: createFunction if destAddr >= function-after(src).
                    if let Some(next) = program.function_manager.function_after(src) {
                        if dest.offset >= next.entry_point().offset {
                            self.create_function(program, dest, &mut new_functions, &mut retypes);
                        }
                    }
                } else {
                    // backward jump: createFunction if destAddr < function-before(src).
                    if let Some(prev) = program.function_manager.function_before(src) {
                        if dest.offset < prev.entry_point().offset {
                            self.create_function(program, dest, &mut new_functions, &mut retypes);
                        }
                    }
                }
            }
        }

        // Apply the collected reference retypes (the observable effect of the flow override).
        for (from, to, new_type) in &retypes {
            program.reference_manager.retype(*from, *to, *new_type);
        }
        // Schedule the new functions for disassembly + reference recovery.
        if !new_functions.is_empty() {
            sched.function_defined(&new_functions);
        }
        !retypes.is_empty() || !new_functions.is_empty()
    }
}
